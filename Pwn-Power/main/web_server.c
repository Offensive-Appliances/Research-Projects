#include "esp_http_server.h"
#include "esp_log.h"
#include "http_parser.h"
#include "wifi_scan.h"
#include "cJSON.h"
#include "deauth.h"
#include "handshake.h"
#include "ota.h"
#include "esp_http_client.h"
#include "esp_timer.h"
#include "scan_storage.h"
#include "background_scan.h"
#include "ap_config.h"
#include "sta_config.h"
#include "idle_scanner.h"
#include "ouis.h"
#include "device_db.h"
#include "device_lifecycle.h"
#include "webhook.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "driver/gpio.h"
#include "monitor_uptime.h"
#include <stddef.h>
#include <time.h>

extern const uint8_t _binary_web_content_gz_h_start[] asm("_binary_web_content_gz_h_start");
extern const uint8_t _binary_web_content_gz_h_end[] asm("_binary_web_content_gz_h_end");

#define WEB_UI_GZ         ((const char *)_binary_web_content_gz_h_start)
#define WEB_UI_GZ_SIZE    ((size_t)(_binary_web_content_gz_h_end - _binary_web_content_gz_h_start))

extern bool pwnpower_time_is_synced(void);
// some SDK versions expose gpio_pad_select_gpio as esp_rom_gpio_pad_select_gpio
#ifndef gpio_pad_select_gpio
#define gpio_pad_select_gpio esp_rom_gpio_pad_select_gpio
#endif

#define TAG "WebServer"

#define SMARTPLUG_GPIO 4
static int s_smartplug_level = 0;
static bool s_smartplug_inited = false;

// Add missing HTTP status code if not defined
#ifndef HTTPD_503_SERVICE_UNAVAILABLE
#define HTTPD_503_SERVICE_UNAVAILABLE 503
#endif

#define MAX_HS_STA 10
typedef struct { uint8_t bssid[6]; int channel; int duration; uint8_t stas[MAX_HS_STA][6]; int sta_count; } hs_args_t;
static TaskHandle_t hs_task_handle = NULL;
static hs_args_t hs_args;

// simple STA connection helpers used by the web UI
static volatile bool g_sta_connected = false;
static bool g_ip_handler_registered = false;
static bool g_wifi_handler_registered = false;
static bool s_wifi_inited = false;
static volatile uint32_t g_last_request_time = 0;

void webserver_set_sta_connected(bool connected) {
    g_sta_connected = connected;
}

bool webserver_get_sta_connected(void) {
    return g_sta_connected;
}

uint32_t webserver_get_last_request_time(void) {
    return g_last_request_time;
}

static void update_last_request_time(void) {
    g_last_request_time = (uint32_t)(esp_timer_get_time() / 1000000ULL);
}

static void ip_event_handler(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data) {
    if (event_id == IP_EVENT_STA_GOT_IP) {
        g_sta_connected = true;
        ESP_LOGI(TAG, "STA got IP");
    }
}

static void wifi_event_handler(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data) {
    if (event_id == WIFI_EVENT_STA_DISCONNECTED) {
        g_sta_connected = false;
        ESP_LOGI(TAG, "STA disconnected");
    }
}

static bool attempt_sta_connect(const char *ssid, const char *password,
                                wifi_auth_mode_t threshold_mode,
                                bool pmf_required,
                                uint32_t wait_ms) {
    if (!s_wifi_inited) {
        wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
        if (esp_wifi_init(&cfg) != ESP_OK) {
            ESP_LOGE(TAG, "esp_wifi_init failed");
            return false;
        }
        s_wifi_inited = true;
    }

    // ensure netif + event loop
    esp_netif_init();
    esp_event_loop_create_default();
    // avoid creating duplicate default STA netif
    if (esp_netif_get_handle_from_ifkey("WIFI_STA_DEF") == NULL) {
        esp_netif_create_default_wifi_sta();
    }

    // register handlers once
    if (!g_ip_handler_registered) {
        if (esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &ip_event_handler, NULL) == ESP_OK) g_ip_handler_registered = true;
    }
    if (!g_wifi_handler_registered) {
        if (esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, &wifi_event_handler, NULL) == ESP_OK) g_wifi_handler_registered = true;
    }

    // keep AP running while adding STA - use APSTA mode so AP continues to host
    // do not stop wifi here (that would tear down the AP)
    esp_wifi_set_mode(WIFI_MODE_APSTA);

    wifi_config_t sta_cfg = {0};
    if (ssid) strncpy((char*)sta_cfg.sta.ssid, ssid, sizeof(sta_cfg.sta.ssid));
    if (password) strncpy((char*)sta_cfg.sta.password, password, sizeof(sta_cfg.sta.password));
    sta_cfg.sta.threshold.authmode = threshold_mode;
    sta_cfg.sta.pmf_cfg.capable = true;
    sta_cfg.sta.pmf_cfg.required = pmf_required;
#ifdef WPA3_SAE_PWE_BOTH
    sta_cfg.sta.sae_pwe_h2e = WPA3_SAE_PWE_BOTH;
#endif
    esp_wifi_set_config(WIFI_IF_STA, &sta_cfg);
    esp_wifi_start();
    vTaskDelay(pdMS_TO_TICKS(100));
    esp_wifi_set_ps(WIFI_PS_NONE);

    ESP_LOGI(TAG, "Attempting STA connect ssid=\"%s\" threshold=%d pmf_required=%s wait_ms=%u", ssid, threshold_mode, pmf_required ? "true" : "false", wait_ms);

    g_sta_connected = false;
    esp_err_t e = esp_wifi_connect();
    if (e != ESP_OK) {
        ESP_LOGE(TAG, "esp_wifi_connect err=%d", e);
        return false;
    }

    uint32_t waited = 0;
    while (!g_sta_connected && waited < wait_ms) {
        vTaskDelay(pdMS_TO_TICKS(100));
        waited += 100;
    }
    return g_sta_connected;
}
static void hs_task(void *arg) {
	hs_args_t *a = (hs_args_t*)arg;
	ESP_LOGI(TAG, "hs_task start: bssid=%02X:%02X:%02X:%02X:%02X:%02X channel=%d duration=%d sta_count=%d",
			a->bssid[0], a->bssid[1], a->bssid[2], a->bssid[3], a->bssid[4], a->bssid[5], a->channel, a->duration, a->sta_count);
	vTaskDelay(pdMS_TO_TICKS(300));
	int e = 0;
	start_handshake_capture(a->bssid, a->channel, a->duration, a->stas, a->sta_count, &e);
	ESP_LOGI(TAG, "Handshake capture done: eapol=%d", e);
	hs_task_handle = NULL;
	vTaskDelete(NULL);
}

static esp_err_t index_handler(httpd_req_t *req) {
    update_last_request_time();
    httpd_resp_set_type(req, "text/html");
    httpd_resp_set_hdr(req, "Content-Encoding", "gzip");
    httpd_resp_send(req, (const char *)WEB_UI_GZ, WEB_UI_GZ_SIZE);
    return ESP_OK;
}
// Handler for scanning Wi-Fi networks
static esp_err_t wifi_scan_handler(httpd_req_t *req) {
    update_last_request_time();
    ESP_LOGI(TAG, "Received Wi-Fi scan request");

    // check if deauth is running
    if(deauth_task_handle != NULL) {
        httpd_resp_send_err(req, HTTPD_503_SERVICE_UNAVAILABLE, "Cannot scan during active attack");
        return ESP_FAIL;
    }

    const char *cached_results = wifi_scan_get_results();
    if(cached_results && strlen(cached_results) > 2) {
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req, cached_results, strlen(cached_results));
        return ESP_OK;
    }

    // no cached results, start initial scan
    if(wifi_scan_is_complete()) {
        wifi_scan();
    }

    // return empty json while scan runs
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"rows\":[]}");
    return ESP_OK;
}

static esp_err_t startattack_handler(httpd_req_t *req) {
    ESP_LOGI(TAG, "Received attack command");
    
    char query_str[200] = {0};
    char mac_str[18] = {0};
    char state_str[8] = {0};
    
    // Log request type and size
    size_t query_len = httpd_req_get_url_query_len(req);
    ESP_LOGD(TAG, "Incoming request: %s, query_len=%d", 
             query_len > 0 ? "GET" : "POST", query_len);

    // First try to get URL query string
    if(query_len > 0) {
        if(httpd_req_get_url_query_str(req, query_str, sizeof(query_str)) != ESP_OK) {
            httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid query params");
            return ESP_FAIL;
        }
    } else {
        // check POST body
        int ret = httpd_req_recv(req, query_str, sizeof(query_str)-1);
        if(ret <= 0) {
            httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing params");
            return ESP_FAIL;
        }
        query_str[ret] = '\0';  // Null-terminate
    }
    
    // Add raw data logging
    ESP_LOGD(TAG, "Raw input: %s", query_str);

    cJSON *root = cJSON_Parse(query_str);
    if (!root) {
        ESP_LOGE(TAG, "Failed to parse JSON: %s", query_str);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
        return ESP_FAIL;
    }

    // Log extracted values
    cJSON *mac_json = cJSON_GetObjectItem(root, "mac");
    cJSON *state_json = cJSON_GetObjectItem(root, "state");
    cJSON *channel_json = cJSON_GetObjectItem(root, "channel");
    ESP_LOGI(TAG, "Parsed MAC: %s, State: %s, Channel: %s", 
            mac_json ? mac_json->valuestring : "NULL",
            state_json ? state_json->valuestring : "NULL",
            channel_json ? channel_json->valuestring : "NULL");

    if (!cJSON_IsString(mac_json) || !cJSON_IsString(state_json) || !cJSON_IsString(channel_json)) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing/invalid fields");
        return ESP_FAIL;
    }

    strlcpy(mac_str, mac_json->valuestring, sizeof(mac_str));
    strlcpy(state_str, state_json->valuestring, sizeof(state_str));
    int target_channel = atoi(channel_json->valuestring);
    
    // new sta field parsing
    cJSON *sta_json = cJSON_GetObjectItem(root, "sta");
    bool has_specific_targets = false;
    
    // Store up to 10 target stations
    #define MAX_TARGET_STATIONS 10
    uint8_t target_stas[MAX_TARGET_STATIONS][6];
    int target_sta_count = 0;
    
    // First clear all entries
    memset(target_stas, 0, sizeof(target_stas));

    if (sta_json) {
        // Check if it's a string (single MAC) or an array (multiple MACs)
        if (cJSON_IsString(sta_json)) {
            // Single MAC address
            sscanf(sta_json->valuestring, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                &target_stas[0][0], &target_stas[0][1], &target_stas[0][2],
                &target_stas[0][3], &target_stas[0][4], &target_stas[0][5]);
            target_sta_count = 1;
            has_specific_targets = true;
            ESP_LOGI(TAG, "Single target client: %s", sta_json->valuestring);
        } 
        else if (cJSON_IsArray(sta_json)) {
            // Array of MAC addresses
            int size = cJSON_GetArraySize(sta_json);
            ESP_LOGI(TAG, "Found %d target clients", size);
            
            for (int i = 0; i < size && i < MAX_TARGET_STATIONS; i++) {
                cJSON *item = cJSON_GetArrayItem(sta_json, i);
                if (cJSON_IsString(item)) {
                    int converted = sscanf(item->valuestring, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                        &target_stas[i][0], &target_stas[i][1], &target_stas[i][2],
                        &target_stas[i][3], &target_stas[i][4], &target_stas[i][5]);
                    
                    if (converted == 6) {
                        // Check if this MAC is the same as the AP MAC - can't deauth yourself
                        if (mac_json && item->valuestring && strcmp(item->valuestring, mac_json->valuestring) == 0) {
                            ESP_LOGW(TAG, "Ignoring client MAC that matches AP MAC: %s", item->valuestring);
                        } else {
                            target_sta_count++;
                            has_specific_targets = true;
                            ESP_LOGI(TAG, "Target client %d: %s", i, item->valuestring);
                        }
                    } else {
                        ESP_LOGE(TAG, "Invalid MAC format for client %d: %s", i, item->valuestring);
                    }
                }
            }
        }
    }

    cJSON_Delete(root);

    // Log MAC conversion attempt
    ESP_LOGD(TAG, "Converting MAC: %s", mac_str);
    uint8_t target_bssid[6];
    int mac_conversion = sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
        &target_bssid[0], &target_bssid[1], &target_bssid[2],
        &target_bssid[3], &target_bssid[4], &target_bssid[5]);
    
    if(mac_conversion != 6) {
        ESP_LOGE(TAG, "Invalid MAC format: %s (converted %d/6 octets)", mac_str, mac_conversion);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Bad MAC");
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "Converted BSSID: %02X:%02X:%02X:%02X:%02X:%02X",
             target_bssid[0], target_bssid[1], target_bssid[2], target_bssid[3],
             target_bssid[4], target_bssid[5]);

    // 5Ghz: if(target_channel < 1 || target_channel > 165) {
    // 2.4Ghz: if(target_channel < 1 || target_channel > 14) {
    if(target_channel < 1 || target_channel > 165) {
        ESP_LOGE(TAG, "Invalid channel number: %d", target_channel);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid channel");
        return ESP_FAIL;
    }

    if(memcmp(target_bssid, "\xFF\xFF\xFF\xFF\xFF\xFF", 6) == 0) {
        ESP_LOGE(TAG, "Attempted broadcast DEAUTH attack!");
        httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "Broadcast not allowed");
        return ESP_FAIL;
    }

    // Log attack state change
    if(strcmp(state_str, "started") == 0) {
        if(!has_specific_targets) {
            // no sta provided - scan and attack all + broadcast
            wifi_scan_stations();
            const char *station_json = wifi_scan_get_station_results();
            cJSON *root = cJSON_Parse(station_json);
            
            // FIND AP'S STATIONS
            char ap_mac_str[18];
            snprintf(ap_mac_str, sizeof(ap_mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                    target_bssid[0], target_bssid[1], target_bssid[2],
                    target_bssid[3], target_bssid[4], target_bssid[5]);
            
            cJSON *ap_entry = cJSON_GetObjectItemCaseSensitive(root, ap_mac_str);
            if(ap_entry) {
                cJSON *stations = cJSON_GetObjectItem(ap_entry, "stations");
                cJSON *station;
                cJSON_ArrayForEach(station, stations) {
                    // ADD TARGETED ATTACK FOR EACH STA
                    cJSON *sta_mac_json = cJSON_GetObjectItem(station, "mac");
                    uint8_t sta_mac[6];
                    sscanf(sta_mac_json->valuestring, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                        &sta_mac[0], &sta_mac[1], &sta_mac[2],
                        &sta_mac[3], &sta_mac[4], &sta_mac[5]);
                        
                    wifi_manager_start_deauth(target_bssid, target_channel, sta_mac);
                }
            }
            // ADD BROADCAST ATTACK
            wifi_manager_start_deauth(target_bssid, target_channel, NULL);
            cJSON_Delete(root);
        } else {
            // direct targeted attack to specific clients + broadcast
            for (int i = 0; i < target_sta_count; i++) {
                // Skip if client MAC matches AP MAC - can't deauth yourself
                if (memcmp(target_stas[i], target_bssid, 6) == 0) {
                    ESP_LOGW(TAG, "Skipping client that matches AP MAC: %02X:%02X:%02X:%02X:%02X:%02X", 
                        target_stas[i][0], target_stas[i][1], target_stas[i][2],
                        target_stas[i][3], target_stas[i][4], target_stas[i][5]);
                    continue;
                }
                
                ESP_LOGI(TAG, "Sending deauth to client %d: %02X:%02X:%02X:%02X:%02X:%02X", 
                    i, target_stas[i][0], target_stas[i][1], target_stas[i][2],
                    target_stas[i][3], target_stas[i][4], target_stas[i][5]);
                    
                wifi_manager_start_deauth(target_bssid, target_channel, target_stas[i]);
            }
            // Also add broadcast attack
            wifi_manager_start_deauth(target_bssid, target_channel, NULL);
        }
    } else if(strcmp(state_str, "stopped") == 0) {
        ESP_LOGI(TAG, "STOPPING attack on %s", mac_str);
        wifi_manager_stop_deauth(target_bssid);
    } else {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid state");
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "Attack command processed successfully");
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"status\":\"success\"}");
    return ESP_OK;
}


static esp_err_t station_scan_handler(httpd_req_t *req) {
    if(deauth_task_handle != NULL) {
        httpd_resp_send_err(req, HTTPD_503_SERVICE_UNAVAILABLE, "scan blocked during attack");
        return ESP_FAIL;
    }
    
    wifi_scan_stations();
    const char *json = wifi_scan_get_station_results();
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, json, strlen(json));
    return ESP_OK;
}

// New handler that ONLY returns cached results without triggering a scan
static esp_err_t cached_scan_handler(httpd_req_t *req) {
    ESP_LOGI(TAG, "Received cached-only scan request");
    
    // Return cached results if we have them
    const char *cached_results = wifi_scan_get_results();
    if(cached_results && strlen(cached_results) > 2) { // Check if we have valid JSON (more than just {})
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req, cached_results, strlen(cached_results));
        return ESP_OK;
    }
    
    // Return empty JSON if we have no cached results
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"rows\":[]}");
    return ESP_OK;
}

static esp_err_t handshake_handler(httpd_req_t *req) {
    if(deauth_task_handle != NULL) {
        httpd_resp_send_err(req, HTTPD_503_SERVICE_UNAVAILABLE, "attack in progress");
        return ESP_FAIL;
    }

    char body[256] = {0};
    int ret = httpd_req_recv(req, body, sizeof(body)-1);
    if(ret <= 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "missing body");
        return ESP_FAIL;
    }
    body[ret] = '\0';
    ESP_LOGI(TAG, "Handshake request body: %s", body);

    cJSON *root = cJSON_Parse(body);
    if(!root) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad json");
        return ESP_FAIL;
    }

    cJSON *mac_json = cJSON_GetObjectItem(root, "mac");
    cJSON *channel_json = cJSON_GetObjectItem(root, "channel");
    cJSON *duration_json = cJSON_GetObjectItem(root, "duration");
    cJSON *sta_json = cJSON_GetObjectItem(root, "sta");
    if(!cJSON_IsString(mac_json) || !(cJSON_IsString(channel_json) || cJSON_IsNumber(channel_json)) || !cJSON_IsNumber(duration_json)) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "missing fields");
        return ESP_FAIL;
    }

    uint8_t bssid[6];
    if(sscanf(mac_json->valuestring, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &bssid[0], &bssid[1], &bssid[2], &bssid[3], &bssid[4], &bssid[5]) != 6) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad mac");
        return ESP_FAIL;
    }

    int channel = 0;
    if(cJSON_IsString(channel_json)) {
        channel = atoi(channel_json->valuestring);
    } else if(cJSON_IsNumber(channel_json)) {
        channel = channel_json->valueint;
    }
    int duration = duration_json->valueint;
    if(channel < 1 || channel > 165 || duration <= 0) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad params");
        return ESP_FAIL;
    }

    uint8_t stas[MAX_HS_STA][6];
    int sta_count = 0;
    memset(stas, 0, sizeof(stas));
    if(sta_json) {
        if(cJSON_IsString(sta_json)) {
            if(sscanf(sta_json->valuestring, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &stas[0][0], &stas[0][1], &stas[0][2], &stas[0][3], &stas[0][4], &stas[0][5]) == 6) {
                sta_count = 1;
            }
        } else if(cJSON_IsArray(sta_json)) {
            int n = cJSON_GetArraySize(sta_json);
            for(int i=0;i<n && i<MAX_HS_STA;i++) {
                cJSON *it = cJSON_GetArrayItem(sta_json, i);
                if(cJSON_IsString(it)) {
                    if(sscanf(it->valuestring, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &stas[i][0], &stas[i][1], &stas[i][2], &stas[i][3], &stas[i][4], &stas[i][5]) == 6) {
                        sta_count++;
                    }
                }
            }
        }
    }

    if(hs_task_handle != NULL) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_503_SERVICE_UNAVAILABLE, "handshake busy");
        return ESP_FAIL;
    }
    memcpy(hs_args.bssid, bssid, 6);
    hs_args.channel = channel;
    hs_args.duration = duration;
    memcpy(hs_args.stas, stas, sizeof(stas));
    hs_args.sta_count = sta_count;
    ESP_LOGI(TAG, "Handshake capture start: bssid=%s, channel=%d, duration=%d, sta_count=%d", mac_json->valuestring, channel, duration, sta_count);
    cJSON *res = cJSON_CreateObject();
    cJSON_AddStringToObject(res, "status", "started");
    char *out = cJSON_PrintUnformatted(res);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, out);
    cJSON_free(out);
    cJSON_Delete(res);
    ESP_LOGI(TAG, "Handshake response sent, starting capture task");
    cJSON_Delete(root);
    xTaskCreate(hs_task, "hs_task", 4096, &hs_args, 5, &hs_task_handle);
    return ESP_OK;
}

static esp_err_t handshake_pcap_handler(httpd_req_t *req) {
    size_t sz = 0;
    const uint8_t *data = handshake_pcap_data(&sz);
    if(sz == 0) {
        ESP_LOGW(TAG, "PCAP requested but empty");
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "no pcap");
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "PCAP request size=%u", (unsigned)sz);
    httpd_resp_set_type(req, "application/vnd.tcpdump.pcap");
    char disp[64];
    snprintf(disp, sizeof(disp), "attachment; filename=\"%s\"", handshake_pcap_filename());
    httpd_resp_set_hdr(req, "Content-Disposition", disp);
    httpd_resp_send(req, (const char*)data, sz);
    return ESP_OK;
}

static esp_err_t ota_upload_handler(httpd_req_t *req) {
	if(deauth_task_handle != NULL) {
		httpd_resp_send_err(req, HTTPD_503_SERVICE_UNAVAILABLE, "Cannot update during active attack");
		return ESP_FAIL;
	}
	if(hs_task_handle != NULL) {
		httpd_resp_send_err(req, HTTPD_503_SERVICE_UNAVAILABLE, "Cannot update during handshake capture");
		return ESP_FAIL;
	}

	ESP_LOGI(TAG, "OTA upload start, len=%d", (int)req->content_len);

	esp_ota_handle_t handle = 0;
	const esp_partition_t *part = NULL;
	if (ota_begin(req->content_len, &handle, &part) != ESP_OK) {
		// begin failed, probably no ota partition
		ESP_LOGE(TAG, "ota begin failed");
		httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "OTA begin failed (no OTA partition?)");
		return ESP_FAIL;
	}

	char *buf = malloc(4096);
	if (!buf) {
		ESP_LOGE(TAG, "malloc failed");
		httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "malloc failed");
		return ESP_FAIL;
	}

	size_t remaining = req->content_len;
	while (remaining > 0) {
		int to_read = remaining > 4096 ? 4096 : (int)remaining;
		int r = httpd_req_recv(req, buf, to_read);
		if (r <= 0) {
			ESP_LOGE(TAG, "recv failed r=%d", r);
			free(buf);
			httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Receive failed");
			return ESP_FAIL;
		}
		if (ota_write(handle, buf, (size_t)r) != ESP_OK) {
			ESP_LOGE(TAG, "ota write failed");
			free(buf);
			httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "OTA write failed");
			return ESP_FAIL;
		}
		remaining -= (size_t)r;
	}

	if (ota_finish_and_set_boot(handle, part) != ESP_OK) {
		free(buf);
		ESP_LOGE(TAG, "ota finish failed");
		httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "OTA finish failed");
		return ESP_FAIL;
	}

	ESP_LOGI(TAG, "OTA upload complete, rebooting soon");
	httpd_resp_set_type(req, "application/json");
	httpd_resp_sendstr(req, "{\"status\":\"ok\",\"message\":\"Firmware uploaded. Rebooting in 3 seconds...\"}");
	free(buf);
	ota_schedule_reboot_ms(3000);
	return ESP_OK;
}

static esp_err_t ota_fetch_handler(httpd_req_t *req) {
	char body[256] = {0};
	int ret = httpd_req_recv(req, body, sizeof(body)-1);
	if (ret <= 0) {
		httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "missing body");
		return ESP_FAIL;
	}
	body[ret] = '\0';
	cJSON *root = cJSON_Parse(body);
	if (!root) {
		httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad json");
		return ESP_FAIL;
	}
	cJSON *urlj = cJSON_GetObjectItem(root, "url");
	if (!cJSON_IsString(urlj)) {
		cJSON_Delete(root);
		httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "missing url");
		return ESP_FAIL;
	}

	ESP_LOGI(TAG, "OTA fetch: %s", urlj->valuestring);

	esp_ota_handle_t handle = 0;
	const esp_partition_t *part = NULL;
	if (ota_begin(0, &handle, &part) != ESP_OK) {
		cJSON_Delete(root);
		httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "OTA begin failed");
		return ESP_FAIL;
	}

	esp_http_client_config_t cfg = { .url = urlj->valuestring, .timeout_ms = 10000 };
	esp_http_client_handle_t client = esp_http_client_init(&cfg);
	if (!client) {
		cJSON_Delete(root);
		httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "client init failed");
		return ESP_FAIL;
	}
	esp_err_t err = esp_http_client_open(client, 0);
	if (err != ESP_OK) {
		esp_http_client_cleanup(client);
		cJSON_Delete(root);
		httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "open failed");
		return ESP_FAIL;
	}

	char *buf = malloc(4096);
	if (!buf) {
		esp_http_client_close(client);
		esp_http_client_cleanup(client);
		cJSON_Delete(root);
		httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "malloc failed");
		return ESP_FAIL;
	}
	while (1) {
		int r = esp_http_client_read(client, buf, 4096);
		if (r < 0) { err = ESP_FAIL; break; }
		if (r == 0) break;
		if (ota_write(handle, buf, (size_t)r) != ESP_OK) { err = ESP_FAIL; break; }
	}
	free(buf);
	esp_http_client_close(client);
	esp_http_client_cleanup(client);
	cJSON_Delete(root);

	if (err != ESP_OK) {
		httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "download failed");
		return ESP_FAIL;
	}
	if (ota_finish_and_set_boot(handle, part) != ESP_OK) {
		httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "OTA finish failed");
		return ESP_FAIL;
	}
	httpd_resp_set_type(req, "application/json");
	httpd_resp_sendstr(req, "{\"status\":\"ok\",\"message\":\"Update downloaded. Rebooting...\"}");
	ota_schedule_reboot_ms(3000);
	return ESP_OK;
}

httpd_uri_t uri_get = {
    .uri = "/",
    .method = HTTP_GET,
    .handler = index_handler,
    .user_ctx = NULL
};

httpd_uri_t uri_scan = {
    .uri = "/scan",
    .method = HTTP_GET,
    .handler = wifi_scan_handler,
    .user_ctx = NULL
};

httpd_uri_t uri_cached_scan = {
    .uri = "/cached-scan",
    .method = HTTP_GET,
    .handler = cached_scan_handler,
    .user_ctx = NULL
};

httpd_uri_t uri_attack = {
    .uri = "/start-attack",
    .method = HTTP_POST,
    .handler = startattack_handler,
    .user_ctx = NULL
};

httpd_uri_t uri_attack_alt = {
    .uri = "/attack",
    .method = HTTP_POST,
    .handler = startattack_handler,
    .user_ctx = NULL
};

httpd_uri_t uri_stations = {
    .uri = "/scan-stations",
    .method = HTTP_GET,
    .handler = station_scan_handler
};

httpd_uri_t uri_handshake = {
    .uri = "/handshake-capture",
    .method = HTTP_POST,
    .handler = handshake_handler,
    .user_ctx = NULL
};

httpd_uri_t uri_handshake_alt = {
    .uri = "/handshake",
    .method = HTTP_POST,
    .handler = handshake_handler,
    .user_ctx = NULL
};

typedef struct { int channel; int duration; } gc_args_t;
static void gc_task(void *arg) {
    gc_args_t *a = (gc_args_t*)arg;
    vTaskDelay(pdMS_TO_TICKS(200));
    start_general_capture(a->channel, a->duration);
    vTaskDelete(NULL);
}

static esp_err_t general_capture_handler(httpd_req_t *req) {
    if(deauth_task_handle != NULL) {
        httpd_resp_send_err(req, HTTPD_503_SERVICE_UNAVAILABLE, "attack in progress");
        return ESP_FAIL;
    }
    char body[128] = {0};
    int ret = httpd_req_recv(req, body, sizeof(body)-1);
    if(ret <= 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "missing body");
        return ESP_FAIL;
    }
    body[ret] = '\0';
    cJSON *root = cJSON_Parse(body);
    if(!root) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad json");
        return ESP_FAIL;
    }
    cJSON *channel_json = cJSON_GetObjectItem(root, "channel");
    cJSON *duration_json = cJSON_GetObjectItem(root, "duration");
    if(!cJSON_IsString(channel_json) || !cJSON_IsNumber(duration_json)) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "missing fields");
        return ESP_FAIL;
    }
    int channel = atoi(channel_json->valuestring);
    int duration = duration_json->valueint;
    if(channel < 1 || channel > 165 || duration <= 0) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad params");
        return ESP_FAIL;
    }
    cJSON_Delete(root);
    TaskHandle_t gc_task_handle = NULL;
    typedef struct { int channel; int duration; } gc_args_t;
    static gc_args_t gc_args;
    gc_args.channel = channel;
    gc_args.duration = duration;
    cJSON *res = cJSON_CreateObject();
    cJSON_AddStringToObject(res, "status", "started");
    char *out = cJSON_PrintUnformatted(res);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, out);
    cJSON_free(out);
    cJSON_Delete(res);
    xTaskCreate(gc_task, "gc_task", 4096, &gc_args, 5, &gc_task_handle);
    return ESP_OK;
}

httpd_uri_t uri_hs_pcap = {
    .uri = "/handshake.pcap",
    .method = HTTP_GET,
    .handler = handshake_pcap_handler,
    .user_ctx = NULL
};

static esp_err_t capture_history_handler(httpd_req_t *req) {
    update_last_request_time();
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, handshake_get_history_json());
    return ESP_OK;
}

httpd_uri_t uri_capture_history = {
    .uri = "/captures",
    .method = HTTP_GET,
    .handler = capture_history_handler,
    .user_ctx = NULL
};

static esp_err_t security_stats_handler(httpd_req_t *req) {
    update_last_request_time();
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, wifi_scan_get_security_stats_json());
    return ESP_OK;
}

httpd_uri_t uri_security_stats = {
    .uri = "/security/stats",
    .method = HTTP_GET,
    .handler = security_stats_handler,
    .user_ctx = NULL
};

httpd_uri_t uri_general_capture = {
    .uri = "/capture",
    .method = HTTP_POST,
    .handler = general_capture_handler,
    .user_ctx = NULL
};

httpd_uri_t uri_ota = {
	.uri = "/ota",
	.method = HTTP_POST,
	.handler = ota_upload_handler,
	.user_ctx = NULL
};

httpd_uri_t uri_ota_fetch = {
	.uri = "/ota/fetch",
	.method = HTTP_POST,
	.handler = ota_fetch_handler,
	.user_ctx = NULL
};

static esp_err_t wifi_connect_handler(httpd_req_t *req) {
    char buf[256] = {0};
    int ret = httpd_req_recv(req, buf, sizeof(buf)-1);
    if (ret <= 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "missing body");
        return ESP_FAIL;
    }
    buf[ret] = '\0';
    cJSON *root = cJSON_Parse(buf);
    if (!root) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad json");
        return ESP_FAIL;
    }
    cJSON *ssid = cJSON_GetObjectItem(root, "ssid");
    cJSON *pass = cJSON_GetObjectItem(root, "password");
    if (!cJSON_IsString(ssid)) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "missing ssid");
        return ESP_FAIL;
    }

    const char *ssid_str = ssid->valuestring;
    const char *pass_str = cJSON_IsString(pass) ? pass->valuestring : "";
    
    bool ok = attempt_sta_connect(ssid_str, pass_str, WIFI_AUTH_WPA2_PSK, false, 10000);
    
    if (ok) {
        esp_err_t err = sta_config_set(ssid_str, pass_str);
        if (err == ESP_OK) {
            ESP_LOGI(TAG, "Saved STA credentials for auto-reconnect");
        } else {
            ESP_LOGW(TAG, "Failed to save STA credentials: %s", esp_err_to_name(err));
        }
    }
    
    cJSON_Delete(root);

    cJSON *res = cJSON_CreateObject();
    if (ok) {
        cJSON_AddStringToObject(res, "message", "Connected and saved for auto-reconnect");
        cJSON_AddStringToObject(res, "status", "ok");
    } else {
        cJSON_AddStringToObject(res, "message", "Connection failed");
        cJSON_AddStringToObject(res, "status", "error");
    }
    char *out = cJSON_PrintUnformatted(res);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, out);
    cJSON_free(out);
    cJSON_Delete(res);
    return ESP_OK;
}

// handler to report STA connection status
static esp_err_t wifi_status_handler(httpd_req_t *req) {
    cJSON *res = cJSON_CreateObject();
    if (g_sta_connected) {
        cJSON_AddStringToObject(res, "status", "connected");
    } else {
        cJSON_AddStringToObject(res, "status", "disconnected");
    }
    
    sta_config_t sta_cfg;
    if (sta_config_get(&sta_cfg) == ESP_OK && strlen(sta_cfg.ssid) > 0) {
        cJSON_AddStringToObject(res, "saved_ssid", sta_cfg.ssid);
        cJSON_AddBoolToObject(res, "has_saved", true);
        cJSON_AddBoolToObject(res, "auto_connect", sta_cfg.auto_connect);
        cJSON_AddBoolToObject(res, "ap_while_connected", sta_cfg.ap_while_connected);
    } else {
        cJSON_AddBoolToObject(res, "has_saved", false);
        cJSON_AddBoolToObject(res, "auto_connect", true);
        cJSON_AddBoolToObject(res, "ap_while_connected", true);
    }
    
    uint32_t uptime = monitor_uptime_get();
    uint32_t boot_uptime = monitor_uptime_get_boot_uptime();
    cJSON_AddNumberToObject(res, "uptime", uptime);
    cJSON_AddNumberToObject(res, "boot_uptime", boot_uptime);
    cJSON_AddBoolToObject(res, "time_synced", pwnpower_time_is_synced());
    if (pwnpower_time_is_synced()) {
        time_t now;
        time(&now);
        cJSON_AddNumberToObject(res, "timestamp", (double)now);
    }
    
    char *out = cJSON_PrintUnformatted(res);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, out);
    cJSON_free(out);
    cJSON_Delete(res);
    return ESP_OK;
}

static esp_err_t wifi_settings_handler(httpd_req_t *req) {
    char buf[128] = {0};
    int ret = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (ret <= 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing body");
        return ESP_FAIL;
    }
    buf[ret] = '\0';
    
    cJSON *root = cJSON_Parse(buf);
    if (!root) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
        return ESP_FAIL;
    }
    
    cJSON *auto_conn = cJSON_GetObjectItem(root, "auto_connect");
    if (auto_conn && cJSON_IsBool(auto_conn)) {
        sta_config_set_auto_connect(cJSON_IsTrue(auto_conn));
    }
    
    cJSON *ap_while = cJSON_GetObjectItem(root, "ap_while_connected");
    if (ap_while && cJSON_IsBool(ap_while)) {
        sta_config_set_ap_while_connected(cJSON_IsTrue(ap_while));
    }
    
    cJSON_Delete(root);
    
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"status\":\"ok\"}");
    return ESP_OK;
}

static esp_err_t wifi_disconnect_handler(httpd_req_t *req) {
    sta_config_clear();
    esp_wifi_disconnect();
    
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"status\":\"ok\",\"message\":\"Disconnected and cleared saved network\"}");
    return ESP_OK;
}

// Handler to set GPIO value for smart plug
static esp_err_t gpio_set_handler(httpd_req_t *req) {
    char body[128] = {0};
    int ret = httpd_req_recv(req, body, sizeof(body)-1);
    if (ret <= 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "missing body");
        return ESP_FAIL;
    }
    body[ret] = '\0';
    cJSON *root = cJSON_Parse(body);
    if (!root) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad json");
        return ESP_FAIL;
    }
    cJSON *pinj = cJSON_GetObjectItem(root, "pin");
    cJSON *valj = cJSON_GetObjectItem(root, "value");
    if (!cJSON_IsNumber(pinj) || !cJSON_IsNumber(valj)) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "missing fields");
        return ESP_FAIL;
    }
    int pin = pinj->valueint;
    int val = valj->valueint ? 1 : 0;
    cJSON_Delete(root);

    if (pin != SMARTPLUG_GPIO) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid pin");
        return ESP_FAIL;
    }

    // init once
    if (!s_smartplug_inited) {
        gpio_pad_select_gpio(pin);
        gpio_set_direction(pin, GPIO_MODE_OUTPUT);
        s_smartplug_inited = true;
    }
    gpio_set_level(pin, val);
    s_smartplug_level = val;

    cJSON *res = cJSON_CreateObject();
    cJSON_AddStringToObject(res, "status", "ok");
    cJSON_AddNumberToObject(res, "value", s_smartplug_level);
    char *out = cJSON_PrintUnformatted(res);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, out);
    cJSON_free(out);
    cJSON_Delete(res);
    return ESP_OK;
}

// Handler to get GPIO status for smart plug
static esp_err_t gpio_status_handler(httpd_req_t *req) {
    char buf[32];
    const char *pin_q = httpd_req_get_url_query_str(req, buf, sizeof(buf)) == ESP_OK ? buf : NULL;
    int pin = SMARTPLUG_GPIO;
    if (pin_q) {
        // parse pin param if provided
        char *p = strstr(pin_q, "pin=");
        if (p) pin = atoi(p+4);
    }

    if (pin != SMARTPLUG_GPIO) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid pin");
        return ESP_FAIL;
    }

    // report last set level; initialize if not yet
    if (!s_smartplug_inited) {
        gpio_pad_select_gpio(pin);
        gpio_set_direction(pin, GPIO_MODE_OUTPUT);
        gpio_set_level(pin, s_smartplug_level);
        s_smartplug_inited = true;
    }
    int level = s_smartplug_level;

    cJSON *res = cJSON_CreateObject();
    cJSON_AddNumberToObject(res, "pin", pin);
    cJSON_AddNumberToObject(res, "value", level);
    char *out = cJSON_PrintUnformatted(res);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, out);
    cJSON_free(out);
    cJSON_Delete(res);
    return ESP_OK;
}

httpd_uri_t uri_wifi_status = {
    .uri = "/wifi/status",
    .method = HTTP_GET,
    .handler = wifi_status_handler,
    .user_ctx = NULL
};

static esp_err_t scan_report_handler(httpd_req_t *req) {
    cJSON *root = cJSON_CreateObject();
    
    network_stats_t stats;
    scan_storage_get_stats(&stats);
    
    cJSON *summary = cJSON_AddObjectToObject(root, "summary");
    cJSON_AddNumberToObject(summary, "total_scans", stats.scan_count);
    cJSON_AddNumberToObject(summary, "unique_aps", stats.total_aps_seen);
    cJSON_AddNumberToObject(summary, "unique_stations", stats.total_stations_seen);
    cJSON_AddNumberToObject(summary, "monitoring_hours", stats.monitoring_duration_sec / 3600.0);
    cJSON_AddNumberToObject(summary, "deauth_events_last_hour", stats.deauth_events_last_hour);
    cJSON_AddNumberToObject(summary, "rogue_aps_detected", stats.rogue_aps_detected);
    cJSON_AddNumberToObject(summary, "known_devices_present", stats.known_devices_present);
    
    // Add intelligence data to report
    const char *intel_json = scan_storage_get_intelligence_json();
    if (intel_json) {
        cJSON *intel_obj = cJSON_Parse(intel_json);
        if (intel_obj) {
            cJSON_AddItemToObject(root, "intelligence", intel_obj);
        }
    }
    
    scan_record_t *latest = malloc(sizeof(scan_record_t));
    if (latest && scan_storage_get_latest(latest) == ESP_OK) {
        uint8_t channel_usage[14] = {0};
        uint8_t security_counts[6] = {0};
        uint8_t total_stations = 0;
        
        for (uint8_t i = 0; i < latest->header.ap_count; i++) {
            stored_ap_t *ap = &latest->aps[i];
            if (ap->channel > 0 && ap->channel <= 14) {
                channel_usage[ap->channel - 1]++;
            }
            if (ap->auth_mode < 6) {
                security_counts[ap->auth_mode]++;
            }
            total_stations += ap->station_count;
        }
        
        cJSON *channels = cJSON_AddObjectToObject(root, "channel_analysis");
        cJSON *channel_data = cJSON_AddArrayToObject(channels, "channels");
        uint8_t most_congested = 0;
        uint8_t max_aps = 0;
        
        for (uint8_t i = 0; i < 14; i++) {
            if (channel_usage[i] > 0) {
                cJSON *ch = cJSON_CreateObject();
                cJSON_AddNumberToObject(ch, "channel", i + 1);
                cJSON_AddNumberToObject(ch, "ap_count", channel_usage[i]);
                cJSON_AddItemToArray(channel_data, ch);
                
                if (channel_usage[i] > max_aps) {
                    max_aps = channel_usage[i];
                    most_congested = i + 1;
                }
            }
        }
        cJSON_AddNumberToObject(channels, "most_congested", most_congested);
        cJSON_AddNumberToObject(channels, "max_ap_count", max_aps);
        
        cJSON *security = cJSON_AddObjectToObject(root, "security_analysis");
        cJSON_AddNumberToObject(security, "open", security_counts[0]);
        cJSON_AddNumberToObject(security, "wep", security_counts[1]);
        cJSON_AddNumberToObject(security, "wpa2", security_counts[2] + security_counts[3]);
        cJSON_AddNumberToObject(security, "wpa3", security_counts[4]);
        cJSON_AddNumberToObject(security, "wpa2_wpa3", security_counts[5]);
        
        float open_percent = latest->header.ap_count > 0 ? 
            (security_counts[0] * 100.0f / latest->header.ap_count) : 0;
        cJSON_AddNumberToObject(security, "open_percent", open_percent);
        
        cJSON *activity = cJSON_AddObjectToObject(root, "network_activity");
        cJSON_AddNumberToObject(activity, "current_aps", latest->header.ap_count);
        cJSON_AddNumberToObject(activity, "total_stations", total_stations);
        cJSON_AddNumberToObject(activity, "avg_stations_per_ap", 
            latest->header.ap_count > 0 ? (float)total_stations / latest->header.ap_count : 0);
        
        cJSON *networks = cJSON_AddArrayToObject(root, "networks");
        for (uint8_t i = 0; i < latest->header.ap_count; i++) {
            stored_ap_t *ap = &latest->aps[i];
            cJSON *net = cJSON_CreateObject();
            
            char mac[18];
            snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
                    ap->bssid[0], ap->bssid[1], ap->bssid[2],
                    ap->bssid[3], ap->bssid[4], ap->bssid[5]);
            
            cJSON_AddStringToObject(net, "bssid", mac);
            cJSON_AddStringToObject(net, "ssid", (char*)ap->ssid);
            cJSON_AddNumberToObject(net, "channel", ap->channel);
            cJSON_AddNumberToObject(net, "rssi", ap->rssi);
            cJSON_AddNumberToObject(net, "stations", ap->station_count);
            cJSON_AddNumberToObject(net, "last_seen", ap->last_seen);
            
            const char *auth;
            switch (ap->auth_mode) {
                case 0: auth = "Open"; break;
                case 1: auth = "WEP"; break;
                case 2: case 3: auth = "WPA2"; break;
                case 4: auth = "WPA3"; break;
                case 5: auth = "WPA2/WPA3"; break;
                default: auth = "Unknown"; break;
            }
            cJSON_AddStringToObject(net, "security", auth);
            
            char ap_vendor[48] = "Unknown";
            ouis_lookup_vendor(ap->bssid, ap_vendor, sizeof(ap_vendor));
            cJSON_AddStringToObject(net, "vendor", ap_vendor);
            
            if (ap->station_count > 0) {
                cJSON *stas = cJSON_AddArrayToObject(net, "clients");
                for (uint8_t s = 0; s < ap->station_count && s < MAX_STATIONS_PER_AP; s++) {
                    cJSON *sta = cJSON_CreateObject();
                    char sta_mac[18];
                    snprintf(sta_mac, sizeof(sta_mac), "%02X:%02X:%02X:%02X:%02X:%02X",
                            ap->stations[s].mac[0], ap->stations[s].mac[1], ap->stations[s].mac[2],
                            ap->stations[s].mac[3], ap->stations[s].mac[4], ap->stations[s].mac[5]);
                    cJSON_AddStringToObject(sta, "mac", sta_mac);
                    cJSON_AddNumberToObject(sta, "rssi", ap->stations[s].rssi);
                    cJSON_AddNumberToObject(sta, "last_seen", ap->stations[s].last_seen);
                    
                    char sta_vendor[48] = "Unknown";
                    ouis_lookup_vendor(ap->stations[s].mac, sta_vendor, sizeof(sta_vendor));
                    cJSON_AddStringToObject(sta, "vendor", sta_vendor);
                    
                    cJSON_AddItemToArray(stas, sta);
                }
            }
            
            cJSON_AddItemToArray(networks, net);
        }
    }
    if (latest) free(latest);
    
    char *json = cJSON_PrintUnformatted(root);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, json);
    free(json);
    cJSON_Delete(root);
    return ESP_OK;
}

static esp_err_t scan_timeline_handler(httpd_req_t *req) {
    httpd_resp_set_type(req, "application/json");
    const char *json = scan_storage_get_timeline_json(24);
    httpd_resp_sendstr(req, json);
    return ESP_OK;
}

static esp_err_t scan_trigger_handler(httpd_req_t *req) {
    background_scan_trigger();
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"status\":\"triggered\"}");
    return ESP_OK;
}

static esp_err_t intelligence_handler(httpd_req_t *req) {
    update_last_request_time();
    httpd_resp_set_type(req, "application/json");
    const char *json = scan_storage_get_intelligence_json();
    httpd_resp_sendstr(req, json);
    return ESP_OK;
}

static esp_err_t device_presence_handler(httpd_req_t *req) {
    update_last_request_time();
    httpd_resp_set_type(req, "application/json");
    const char *json = scan_storage_get_device_presence_json();
    httpd_resp_sendstr(req, json);
    return ESP_OK;
}

static esp_err_t unified_intelligence_handler(httpd_req_t *req) {
    update_last_request_time();
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    const char *json = scan_storage_get_unified_intelligence_json();
    httpd_resp_sendstr(req, json);
    return ESP_OK;
}

static esp_err_t scan_status_handler(httpd_req_t *req) {
    cJSON *root = cJSON_CreateObject();
    
    bg_scan_state_t state = background_scan_get_state();
    const char *state_str;
    switch (state) {
        case BG_SCAN_IDLE: state_str = "idle"; break;
        case BG_SCAN_WAITING: state_str = "waiting"; break;
        case BG_SCAN_RUNNING: state_str = "running"; break;
        case BG_SCAN_PAUSED: state_str = "paused"; break;
        default: state_str = "unknown"; break;
    }
    
    cJSON_AddStringToObject(root, "state", state_str);
    cJSON_AddNumberToObject(root, "last_scan", background_scan_get_last_time());
    cJSON_AddNumberToObject(root, "record_count", scan_storage_get_count());
    
    const bg_scan_config_t *cfg = background_scan_get_config();
    cJSON_AddNumberToObject(root, "interval_sec", cfg->interval_sec);
    cJSON_AddBoolToObject(root, "auto_scan", cfg->auto_scan);
    
    char *json = cJSON_PrintUnformatted(root);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, json);
    free(json);
    cJSON_Delete(root);
    return ESP_OK;
}

static esp_err_t scan_config_get_handler(httpd_req_t *req) {
    const bg_scan_config_t *bg_cfg = background_scan_get_config();
    const idle_scan_config_t *idle_cfg = idle_scanner_get_config();
    
    cJSON *root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "bg_interval", bg_cfg->interval_sec);
    cJSON_AddBoolToObject(root, "bg_enabled", bg_cfg->auto_scan);
    cJSON_AddNumberToObject(root, "idle_threshold", idle_cfg->idle_threshold_sec);
    cJSON_AddBoolToObject(root, "auto_handshake", idle_cfg->auto_handshake);
    cJSON_AddNumberToObject(root, "handshake_duration", idle_cfg->handshake_duration_sec);
    
    char *json = cJSON_PrintUnformatted(root);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, json);
    free(json);
    cJSON_Delete(root);
    return ESP_OK;
}

static esp_err_t scan_config_handler(httpd_req_t *req) {
    char buf[256];
    int ret = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (ret <= 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing body");
        return ESP_FAIL;
    }
    buf[ret] = '\0';
    
    cJSON *root = cJSON_Parse(buf);
    if (!root) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
        return ESP_FAIL;
    }
    
    cJSON *interval = cJSON_GetObjectItem(root, "bg_interval");
    if (interval && cJSON_IsNumber(interval)) {
        background_scan_set_interval((uint16_t)interval->valueint);
    }
    
    cJSON *bg_enabled = cJSON_GetObjectItem(root, "bg_enabled");
    if (bg_enabled && cJSON_IsBool(bg_enabled)) {
        background_scan_set_enabled(cJSON_IsTrue(bg_enabled));
    }
    
    cJSON *idle_thresh = cJSON_GetObjectItem(root, "idle_threshold");
    if (idle_thresh && cJSON_IsNumber(idle_thresh)) {
        idle_scanner_set_idle_threshold((uint32_t)idle_thresh->valueint);
    }
    
    cJSON *auto_hs = cJSON_GetObjectItem(root, "auto_handshake");
    if (auto_hs && cJSON_IsBool(auto_hs)) {
        idle_scanner_set_auto_handshake(cJSON_IsTrue(auto_hs));
    }
    
    cJSON *hs_dur = cJSON_GetObjectItem(root, "handshake_duration");
    if (hs_dur && cJSON_IsNumber(hs_dur)) {
        idle_scanner_set_handshake_duration((uint8_t)hs_dur->valueint);
    }
    
    cJSON_Delete(root);
    
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"status\":\"ok\"}");
    return ESP_OK;
}

static esp_err_t scan_clear_handler(httpd_req_t *req) {
    scan_storage_clear();
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"status\":\"cleared\"}");
    return ESP_OK;
}

static esp_err_t ap_config_get_handler(httpd_req_t *req) {
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, ap_config_get_json());
    return ESP_OK;
}

static esp_err_t ap_config_set_handler(httpd_req_t *req) {
    char buf[256];
    int ret = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (ret <= 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing body");
        return ESP_FAIL;
    }
    buf[ret] = '\0';
    
    cJSON *root = cJSON_Parse(buf);
    if (!root) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
        return ESP_FAIL;
    }
    
    cJSON *ssid = cJSON_GetObjectItem(root, "ssid");
    cJSON *password = cJSON_GetObjectItem(root, "password");
    
    if (!ssid || !cJSON_IsString(ssid) || strlen(ssid->valuestring) == 0) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "SSID required");
        return ESP_FAIL;
    }
    
    const char *pass_str = (password && cJSON_IsString(password)) ? password->valuestring : "";
    
    if (strlen(pass_str) > 0 && strlen(pass_str) < 8) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Password must be 8+ chars or empty");
        return ESP_FAIL;
    }
    
    esp_err_t err = ap_config_set(ssid->valuestring, pass_str);
    cJSON_Delete(root);
    
    if (err != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to save");
        return ESP_FAIL;
    }
    
    ap_config_apply();
    
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"status\":\"ok\",\"message\":\"Settings saved. Reconnect to new AP.\"}");
    return ESP_OK;
}

static esp_err_t history_samples_handler(httpd_req_t *req) {
    update_last_request_time();
    
    // parse days parameter (default 7, max 30, min 0.1)
    float days = 7.0f;
    char query[64];
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK) {
        char days_str[16];
        if (httpd_query_key_value(query, "days", days_str, sizeof(days_str)) == ESP_OK) {
            days = atof(days_str);
            if (days < 0.1f) days = 0.1f;
            if (days > 30.0f) days = 30.0f;
        }
    }
    
    // limit samples to prevent oom (process in chunks)
    uint32_t max_samples = (uint32_t)(days * 24.0f * 30.0f);  // 30 samples per hour
    if (max_samples > 5040) max_samples = 5040;  // limit to 7 days worth
    
    uint32_t history_count = scan_storage_get_history_count();
    ESP_LOGI(TAG, "history_samples_handler: total_count=%u, max_samples=%u", history_count, max_samples);
    uint32_t remaining = (history_count > max_samples) ? max_samples : history_count;
    uint32_t start_idx = (history_count > max_samples) ? (history_count - max_samples) : 0;
    ESP_LOGI(TAG, "history_samples_handler: start_idx=%u, remaining=%u", start_idx, remaining);
    
    #define HISTORY_CHUNK_SIZE 100
    history_sample_t *chunk = malloc(sizeof(history_sample_t) * HISTORY_CHUNK_SIZE);
    if (!chunk) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Out of memory");
        return ESP_FAIL;
    }
    
    // start json response manually to avoid large cjson tree
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr_chunk(req, "{\"samples\":[");
    
    bool first = true;
    while (remaining > 0) {
        uint32_t request_count = remaining > HISTORY_CHUNK_SIZE ? HISTORY_CHUNK_SIZE : remaining;
        uint32_t actual = 0;
        esp_err_t err = scan_storage_get_history_samples_window(start_idx, request_count, chunk, &actual);
        ESP_LOGI(TAG, "history_samples_handler: requested=%u, actual=%u", request_count, actual);
        if (err != ESP_OK) {
            free(chunk);
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to read samples");
            return ESP_FAIL;
        }
        
        for (uint32_t i = 0; i < actual; i++) {
            // Optimize: Build entire JSON object in one buffer to reduce httpd_resp_sendstr_chunk calls
            // This reduces 15+ calls per sample to just 1 call per sample
            char buf[300];
            int len = snprintf(buf, sizeof(buf),
                "%s{\"epoch_ts\":%lu,\"uptime_sec\":%lu,\"time_valid\":%s,\"ap_count\":%u,\"client_count\":%u,\"channel_counts\":[%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u]}",
                first ? "" : ",",
                (unsigned long)chunk[i].epoch_ts,
                (unsigned long)chunk[i].uptime_sec,
                chunk[i].time_valid ? "true" : "false",
                chunk[i].ap_count,
                chunk[i].client_count,
                chunk[i].channel_counts[0], chunk[i].channel_counts[1], chunk[i].channel_counts[2],
                chunk[i].channel_counts[3], chunk[i].channel_counts[4], chunk[i].channel_counts[5],
                chunk[i].channel_counts[6], chunk[i].channel_counts[7], chunk[i].channel_counts[8],
                chunk[i].channel_counts[9], chunk[i].channel_counts[10], chunk[i].channel_counts[11],
                chunk[i].channel_counts[12]);
            first = false;

            httpd_resp_sendstr_chunk(req, buf);
        }
        
        // advance by request_count (items read from flash), not actual (items after sanitize)
        start_idx += request_count;
        remaining -= request_count;
    }
    
    free(chunk);
    httpd_resp_sendstr_chunk(req, "]}");
    httpd_resp_sendstr_chunk(req, NULL);  // finish chunked response
    
    return ESP_OK;
}

static esp_err_t devices_list_handler(httpd_req_t *req) {
    update_last_request_time();
    
    // get device presence data from scan_storage
    const char *presence_json = scan_storage_get_device_presence_json();
    
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, presence_json);
    return ESP_OK;
}

static esp_err_t devices_update_handler(httpd_req_t *req) {
    char buf[512];
    int ret = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (ret <= 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing body");
        return ESP_FAIL;
    }
    buf[ret] = '\0';
    
    cJSON *root = cJSON_Parse(buf);
    if (!root) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
        return ESP_FAIL;
    }
    
    cJSON *mac_json = cJSON_GetObjectItem(root, "mac");
    if (!mac_json || !cJSON_IsString(mac_json)) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "MAC required");
        return ESP_FAIL;
    }
    
    device_settings_t settings;
    memset(&settings, 0, sizeof(settings));
    
    // parse mac
    if (sscanf(mac_json->valuestring, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &settings.mac[0], &settings.mac[1], &settings.mac[2],
               &settings.mac[3], &settings.mac[4], &settings.mac[5]) != 6) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid MAC format");
        return ESP_FAIL;
    }
    
    // get existing settings or use defaults
    if (device_db_get(settings.mac, &settings) != ESP_OK) {
        settings.trust_score = 50;
        settings.tracked = false;
        settings.name[0] = '\0';
    }
    
    // update fields if provided
    cJSON *name_json = cJSON_GetObjectItem(root, "name");
    if (name_json && cJSON_IsString(name_json)) {
        strncpy(settings.name, name_json->valuestring, DEVICE_NAME_MAX_LEN - 1);
        settings.name[DEVICE_NAME_MAX_LEN - 1] = '\0';
    }
    
    cJSON *trust_json = cJSON_GetObjectItem(root, "trust_score");
    if (trust_json && cJSON_IsNumber(trust_json)) {
        int trust = trust_json->valueint;
        if (trust < 0) trust = 0;
        if (trust > 100) trust = 100;
        settings.trust_score = (uint8_t)trust;
    }
    
    cJSON *tracked_json = cJSON_GetObjectItem(root, "tracked");
    if (tracked_json && cJSON_IsBool(tracked_json)) {
        settings.tracked = cJSON_IsTrue(tracked_json);
    }
    
    cJSON *home_json = cJSON_GetObjectItem(root, "home_device");
    bool set_home = false;
    bool home_value = false;
    if (home_json && cJSON_IsBool(home_json)) {
        set_home = true;
        home_value = cJSON_IsTrue(home_json);
    }
    
    cJSON_Delete(root);
    
    // save to db
    esp_err_t err = device_db_set(&settings);
    if (err != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to save device");
        return ESP_FAIL;
    }
    
    // set home flag in presence storage if requested
    if (set_home) {
        scan_storage_set_device_home(settings.mac, home_value);
    }
    
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"status\":\"ok\"}");
    return ESP_OK;
}

static esp_err_t webhook_config_get_handler(httpd_req_t *req) {
    webhook_config_t config;
    webhook_get_config(&config);
    
    cJSON *root = cJSON_CreateObject();
    cJSON_AddBoolToObject(root, "enabled", config.enabled);
    cJSON_AddStringToObject(root, "url", config.url);
    cJSON_AddBoolToObject(root, "tracked_only", config.tracked_only);
    cJSON_AddBoolToObject(root, "home_departure_alert", config.home_departure_alert);
    cJSON_AddBoolToObject(root, "home_arrival_alert", config.home_arrival_alert);
    cJSON_AddBoolToObject(root, "new_device_alert", config.new_device_alert);
    cJSON_AddBoolToObject(root, "all_events", config.all_events);
    cJSON_AddNumberToObject(root, "send_cursor", webhook_get_send_cursor());
    cJSON_AddNumberToObject(root, "total_events", scan_storage_get_event_count());
    
    char *json_str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, json_str);
    free(json_str);
    
    return ESP_OK;
}

static esp_err_t webhook_config_set_handler(httpd_req_t *req) {
    char buf[512];
    int ret = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (ret <= 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing body");
        return ESP_FAIL;
    }
    buf[ret] = '\0';
    
    cJSON *root = cJSON_Parse(buf);
    if (!root) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
        return ESP_FAIL;
    }
    
    webhook_config_t config;
    webhook_get_config(&config);
    
    cJSON *enabled_json = cJSON_GetObjectItem(root, "enabled");
    if (enabled_json && cJSON_IsBool(enabled_json)) {
        config.enabled = cJSON_IsTrue(enabled_json);
    }
    
    cJSON *url_json = cJSON_GetObjectItem(root, "url");
    if (url_json && cJSON_IsString(url_json)) {
        strncpy(config.url, url_json->valuestring, WEBHOOK_URL_MAX_LEN - 1);
        config.url[WEBHOOK_URL_MAX_LEN - 1] = '\0';
    }
    
    cJSON *tracked_only_json = cJSON_GetObjectItem(root, "tracked_only");
    if (tracked_only_json && cJSON_IsBool(tracked_only_json)) {
        config.tracked_only = cJSON_IsTrue(tracked_only_json);
    }
    
    cJSON *home_departure_json = cJSON_GetObjectItem(root, "home_departure_alert");
    if (home_departure_json && cJSON_IsBool(home_departure_json)) {
        config.home_departure_alert = cJSON_IsTrue(home_departure_json);
    }
    
    cJSON *home_arrival_json = cJSON_GetObjectItem(root, "home_arrival_alert");
    if (home_arrival_json && cJSON_IsBool(home_arrival_json)) {
        config.home_arrival_alert = cJSON_IsTrue(home_arrival_json);
    }
    
    cJSON *new_device_json = cJSON_GetObjectItem(root, "new_device_alert");
    if (new_device_json && cJSON_IsBool(new_device_json)) {
        config.new_device_alert = cJSON_IsTrue(new_device_json);
    }
    
    cJSON *all_events_json = cJSON_GetObjectItem(root, "all_events");
    if (all_events_json && cJSON_IsBool(all_events_json)) {
        config.all_events = cJSON_IsTrue(all_events_json);
    }
    
    cJSON_Delete(root);
    
    esp_err_t err = webhook_set_config(&config);
    if (err != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to save config");
        return ESP_FAIL;
    }
    
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"status\":\"ok\"}");
    return ESP_OK;
}

static esp_err_t webhook_test_handler(httpd_req_t *req) {
    esp_err_t err = webhook_send_test();
    
    cJSON *root = cJSON_CreateObject();
    if (err == ESP_OK) {
        cJSON_AddStringToObject(root, "status", "ok");
        cJSON_AddStringToObject(root, "message", "Test webhook sent successfully");
    } else {
        cJSON_AddStringToObject(root, "status", "error");
        cJSON_AddStringToObject(root, "message", "Failed to send test webhook");
    }
    
    char *json_str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, json_str);
    free(json_str);
    
    return ESP_OK;
}

static esp_err_t home_ssids_get_handler(httpd_req_t *req) {
    cJSON *root = cJSON_CreateObject();
    const char *connected = scan_storage_get_home_ssid();
    cJSON_AddStringToObject(root, "connected", connected ? connected : "");
    cJSON_AddRawToObject(root, "extra", scan_storage_get_extra_home_ssids_json());
    
    char *json_str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, json_str);
    free(json_str);
    return ESP_OK;
}

static esp_err_t home_ssids_add_handler(httpd_req_t *req) {
    char buf[128];
    int ret = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (ret <= 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing body");
        return ESP_FAIL;
    }
    buf[ret] = '\0';
    
    cJSON *root = cJSON_Parse(buf);
    if (!root) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
        return ESP_FAIL;
    }
    
    cJSON *ssid_json = cJSON_GetObjectItem(root, "ssid");
    if (!ssid_json || !cJSON_IsString(ssid_json)) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "SSID required");
        return ESP_FAIL;
    }
    
    esp_err_t err = scan_storage_add_extra_home_ssid(ssid_json->valuestring);
    cJSON_Delete(root);
    
    if (err == ESP_OK) {
        httpd_resp_set_type(req, "application/json");
        httpd_resp_sendstr(req, "{\"status\":\"ok\"}");
    } else if (err == ESP_ERR_NO_MEM) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Max 3 extra SSIDs allowed");
        return ESP_FAIL;
    } else {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to add SSID");
        return ESP_FAIL;
    }
    return ESP_OK;
}

static esp_err_t home_ssids_refresh_handler(httpd_req_t *req) {
    scan_storage_refresh_home_flags();
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"status\":\"ok\"}");
    return ESP_OK;
}

static esp_err_t home_ssids_remove_handler(httpd_req_t *req) {
    char buf[128];
    int ret = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (ret <= 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing body");
        return ESP_FAIL;
    }
    buf[ret] = '\0';
    
    cJSON *root = cJSON_Parse(buf);
    if (!root) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
        return ESP_FAIL;
    }
    
    cJSON *ssid_json = cJSON_GetObjectItem(root, "ssid");
    if (!ssid_json || !cJSON_IsString(ssid_json)) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "SSID required");
        return ESP_FAIL;
    }
    
    esp_err_t err = scan_storage_remove_extra_home_ssid(ssid_json->valuestring);
    cJSON_Delete(root);
    
    if (err == ESP_OK) {
        httpd_resp_set_type(req, "application/json");
        httpd_resp_sendstr(req, "{\"status\":\"ok\"}");
    } else {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "SSID not found");
        return ESP_FAIL;
    }
    return ESP_OK;
}

// Start the web server and register URI handlers
httpd_handle_t start_webserver(void) {
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    /* increase available URI handler slots to allow additional routes (OTA, fetch, etc) */
    config.max_uri_handlers = 48;
    httpd_handle_t server = NULL;

    if (httpd_start(&server, &config) == ESP_OK) {
        httpd_register_uri_handler(server, &uri_get);
        httpd_register_uri_handler(server, &uri_scan);
        httpd_register_uri_handler(server, &uri_cached_scan);
        httpd_register_uri_handler(server, &uri_attack);
        httpd_register_uri_handler(server, &uri_attack_alt);
        httpd_register_uri_handler(server, &uri_stations);
        httpd_register_uri_handler(server, &uri_handshake);
        httpd_register_uri_handler(server, &uri_handshake_alt);
        httpd_register_uri_handler(server, &uri_hs_pcap);
        httpd_register_uri_handler(server, &uri_capture_history);
        httpd_register_uri_handler(server, &uri_security_stats);
        httpd_register_uri_handler(server, &uri_general_capture);
        httpd_register_uri_handler(server, &uri_ota);
        httpd_register_uri_handler(server, &uri_ota_fetch);
        // register wifi status endpoint
        httpd_register_uri_handler(server, &uri_wifi_status);
        // register gpio endpoints for smart plug
        httpd_uri_t uri_gpio_set = {
            .uri = "/gpio",
            .method = HTTP_POST,
            .handler = gpio_set_handler,
            .user_ctx = NULL
        };
        httpd_uri_t uri_gpio_status = {
            .uri = "/gpio/status",
            .method = HTTP_GET,
            .handler = gpio_status_handler,
            .user_ctx = NULL
        };
        httpd_register_uri_handler(server, &uri_gpio_set);
        httpd_register_uri_handler(server, &uri_gpio_status);
        // wifi connect endpoint for providing internet during OTA
        httpd_uri_t uri_wifi_connect = {
            .uri = "/wifi/connect",
            .method = HTTP_POST,
            .handler = wifi_connect_handler,
            .user_ctx = NULL
        };
        httpd_register_uri_handler(server, &uri_wifi_connect);
        
        httpd_uri_t uri_wifi_settings = { .uri = "/wifi/settings", .method = HTTP_POST, .handler = wifi_settings_handler, .user_ctx = NULL };
        httpd_uri_t uri_wifi_disconnect = { .uri = "/wifi/disconnect", .method = HTTP_POST, .handler = wifi_disconnect_handler, .user_ctx = NULL };
        httpd_register_uri_handler(server, &uri_wifi_settings);
        httpd_register_uri_handler(server, &uri_wifi_disconnect);
        
        httpd_uri_t uri_scan_report = { .uri = "/scan/report", .method = HTTP_GET, .handler = scan_report_handler, .user_ctx = NULL };
        httpd_uri_t uri_scan_timeline = { .uri = "/scan/timeline", .method = HTTP_GET, .handler = scan_timeline_handler, .user_ctx = NULL };
        httpd_uri_t uri_scan_trigger = { .uri = "/scan/trigger", .method = HTTP_POST, .handler = scan_trigger_handler, .user_ctx = NULL };
        httpd_uri_t uri_scan_status = { .uri = "/scan/status", .method = HTTP_GET, .handler = scan_status_handler, .user_ctx = NULL };
        httpd_uri_t uri_scan_config_get = { .uri = "/scan/settings", .method = HTTP_GET, .handler = scan_config_get_handler, .user_ctx = NULL };
        httpd_uri_t uri_scan_config = { .uri = "/scan/settings", .method = HTTP_POST, .handler = scan_config_handler, .user_ctx = NULL };
        httpd_uri_t uri_scan_clear = { .uri = "/scan/clear", .method = HTTP_POST, .handler = scan_clear_handler, .user_ctx = NULL };
        httpd_uri_t uri_intelligence = { .uri = "/intelligence", .method = HTTP_GET, .handler = intelligence_handler, .user_ctx = NULL };
        httpd_uri_t uri_device_presence = { .uri = "/devices/presence", .method = HTTP_GET, .handler = device_presence_handler, .user_ctx = NULL };
        httpd_uri_t uri_unified_intelligence = { .uri = "/intelligence/unified", .method = HTTP_GET, .handler = unified_intelligence_handler, .user_ctx = NULL };
        httpd_register_uri_handler(server, &uri_scan_report);
        httpd_register_uri_handler(server, &uri_scan_timeline);
        httpd_register_uri_handler(server, &uri_scan_trigger);
        httpd_register_uri_handler(server, &uri_scan_status);
        httpd_register_uri_handler(server, &uri_scan_config_get);
        httpd_register_uri_handler(server, &uri_scan_config);
        httpd_register_uri_handler(server, &uri_scan_clear);
        httpd_register_uri_handler(server, &uri_intelligence);
        httpd_register_uri_handler(server, &uri_device_presence);
        httpd_register_uri_handler(server, &uri_unified_intelligence);
        
        httpd_uri_t uri_ap_config_get = { .uri = "/ap/config", .method = HTTP_GET, .handler = ap_config_get_handler, .user_ctx = NULL };
        httpd_uri_t uri_ap_config_set = { .uri = "/ap/config", .method = HTTP_POST, .handler = ap_config_set_handler, .user_ctx = NULL };
        httpd_register_uri_handler(server, &uri_ap_config_get);
        httpd_register_uri_handler(server, &uri_ap_config_set);
        
        httpd_uri_t uri_history_samples = { .uri = "/history/samples", .method = HTTP_GET, .handler = history_samples_handler, .user_ctx = NULL };
        httpd_uri_t uri_devices_list = { .uri = "/devices/list", .method = HTTP_GET, .handler = devices_list_handler, .user_ctx = NULL };
        httpd_uri_t uri_devices_update = { .uri = "/devices/update", .method = HTTP_POST, .handler = devices_update_handler, .user_ctx = NULL };
        httpd_uri_t uri_webhook_config_get = { .uri = "/webhook/config", .method = HTTP_GET, .handler = webhook_config_get_handler, .user_ctx = NULL };
        httpd_uri_t uri_webhook_config_set = { .uri = "/webhook/config", .method = HTTP_POST, .handler = webhook_config_set_handler, .user_ctx = NULL };
        httpd_uri_t uri_webhook_test = { .uri = "/webhook/test", .method = HTTP_POST, .handler = webhook_test_handler, .user_ctx = NULL };
        httpd_uri_t uri_home_ssids_get = { .uri = "/home-ssids", .method = HTTP_GET, .handler = home_ssids_get_handler, .user_ctx = NULL };
        httpd_uri_t uri_home_ssids_add = { .uri = "/home-ssids/add", .method = HTTP_POST, .handler = home_ssids_add_handler, .user_ctx = NULL };
        httpd_uri_t uri_home_ssids_remove = { .uri = "/home-ssids/remove", .method = HTTP_POST, .handler = home_ssids_remove_handler, .user_ctx = NULL };
        httpd_uri_t uri_home_ssids_refresh = { .uri = "/home-ssids/refresh", .method = HTTP_POST, .handler = home_ssids_refresh_handler, .user_ctx = NULL };
        httpd_register_uri_handler(server, &uri_history_samples);
        httpd_register_uri_handler(server, &uri_devices_list);
        httpd_register_uri_handler(server, &uri_devices_update);
        httpd_register_uri_handler(server, &uri_webhook_config_get);
        httpd_register_uri_handler(server, &uri_webhook_config_set);
        httpd_register_uri_handler(server, &uri_webhook_test);
        httpd_register_uri_handler(server, &uri_home_ssids_get);
        httpd_register_uri_handler(server, &uri_home_ssids_add);
        httpd_register_uri_handler(server, &uri_home_ssids_remove);
        httpd_register_uri_handler(server, &uri_home_ssids_refresh);
        
        ESP_LOGI(TAG, "Web Server started");
    } else {
        ESP_LOGE(TAG, "Failed to start web server");
    }

    return server;
}
