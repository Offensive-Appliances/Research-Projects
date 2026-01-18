#include "webhook.h"
#include "scan_storage.h"
#include "web_server.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_log.h"
#include "esp_http_client.h"
#include "esp_crt_bundle.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "cJSON.h"
#include "device_lifecycle.h"
#include <string.h>
#include <time.h>
#include <ctype.h>

#define TAG "Webhook"
#define NVS_NAMESPACE "webhook"
#define NVS_KEY_CONFIG "config"
#define NVS_KEY_CURSOR "cursor"
#define NVS_KEY_WRITE_IDX "write_idx"
#define WEBHOOK_TASK_STACK 16384
#define CHECK_INTERVAL_MS 10000

static webhook_config_t current_config;
static uint32_t send_cursor = 0;
static uint32_t last_write_idx = 0;
static TaskHandle_t webhook_task_handle = NULL;
static volatile bool task_running = false;
static esp_http_client_handle_t webhook_client = NULL;
static char webhook_client_url[WEBHOOK_URL_MAX_LEN] = {0};
static const uint32_t max_events_per_cycle = 5;

esp_err_t webhook_init(void) {
    // load config from nvs
    nvs_handle_t handle;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READONLY, &handle);
    if (err == ESP_OK) {
        size_t len = sizeof(webhook_config_t);
        err = nvs_get_blob(handle, NVS_KEY_CONFIG, &current_config, &len);
        if (err != ESP_OK) {
            memset(&current_config, 0, sizeof(current_config));
            current_config.enabled = false;
            current_config.tracked_only = false;
            current_config.home_departure_alert = true;
            current_config.home_arrival_alert = false;
            current_config.new_device_alert = true;
            current_config.all_events = false;
        }
        
        // load send cursor
        nvs_get_u32(handle, NVS_KEY_CURSOR, &send_cursor);
        nvs_get_u32(handle, NVS_KEY_WRITE_IDX, &last_write_idx);
        
        nvs_close(handle);
    } else {
        memset(&current_config, 0, sizeof(current_config));
        current_config.enabled = false;
        current_config.tracked_only = false;
        current_config.home_departure_alert = true;
        current_config.home_arrival_alert = false;
        current_config.new_device_alert = true;
        current_config.all_events = false;
        send_cursor = 0;
        last_write_idx = 0;
    }
    
    ESP_LOGI(TAG, "Webhook initialized (enabled=%d, tracked_only=%d, cursor=%lu)",
             current_config.enabled, current_config.tracked_only, (unsigned long)send_cursor);
    return ESP_OK;
}

static void persist_cursor_state(void) {
    nvs_handle_t handle;
    if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &handle) == ESP_OK) {
        nvs_set_u32(handle, NVS_KEY_CURSOR, send_cursor);
        nvs_set_u32(handle, NVS_KEY_WRITE_IDX, last_write_idx);
        nvs_commit(handle);
        nvs_close(handle);
    }
}

static esp_http_client_handle_t get_webhook_client(void) {
    if (!current_config.url[0]) {
        return NULL;
    }

    if (webhook_client && strcmp(webhook_client_url, current_config.url) == 0) {
        return webhook_client;
    }

    if (webhook_client) {
        esp_http_client_cleanup(webhook_client);
        webhook_client = NULL;
        webhook_client_url[0] = '\0';
    }

    esp_http_client_config_t config = {
        .url = current_config.url,
        .method = HTTP_METHOD_POST,
        .timeout_ms = 10000,
        .crt_bundle_attach = esp_crt_bundle_attach,
        .keep_alive_enable = true,
    };

    webhook_client = esp_http_client_init(&config);
    if (webhook_client) {
        strncpy(webhook_client_url, current_config.url, sizeof(webhook_client_url) - 1);
        webhook_client_url[sizeof(webhook_client_url) - 1] = '\0';
    }

    return webhook_client;
}

static void reset_webhook_client(void) {
    if (webhook_client) {
        esp_http_client_cleanup(webhook_client);
        webhook_client = NULL;
        webhook_client_url[0] = '\0';
    }
}

static void sanitize_text(char *out, size_t out_size, const char *in) {
    if (!out || out_size == 0) return;
    size_t pos = 0;
    bool last_space = false;
    if (!in) {
        out[0] = '\0';
        return;
    }
    while (*in && pos < out_size - 1) {
        unsigned char c = (unsigned char)*in++;
        // Filter out control characters, high-bit characters, and invalid UTF-8
        if (c < 32 || c == 127 || c > 127) {
            if (!last_space && pos > 0) {
                out[pos++] = ' ';
                last_space = true;
            }
            continue;
        }
        if (isspace(c)) {
            if (!last_space && pos > 0) {
                out[pos++] = ' ';
                last_space = true;
            }
            continue;
        }
        out[pos++] = (char)c;
        last_space = false;
    }
    if (pos > 0 && out[pos - 1] == ' ') {
        pos--;
    }
    out[pos] = '\0';
}

esp_err_t webhook_get_config(webhook_config_t *config) {
    if (!config) return ESP_ERR_INVALID_ARG;
    memcpy(config, &current_config, sizeof(webhook_config_t));
    return ESP_OK;
}

esp_err_t webhook_set_config(const webhook_config_t *config) {
    if (!config) return ESP_ERR_INVALID_ARG;
    
    // save to nvs
    nvs_handle_t handle;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to open NVS: %s", esp_err_to_name(err));
        return err;
    }
    
    err = nvs_set_blob(handle, NVS_KEY_CONFIG, config, sizeof(webhook_config_t));
    if (err == ESP_OK) {
        err = nvs_commit(handle);
    }
    
    nvs_close(handle);
    
    if (err == ESP_OK) {
        memcpy(&current_config, config, sizeof(webhook_config_t));
        ESP_LOGI(TAG, "Webhook config saved (enabled=%d, url=%s)", 
                 current_config.enabled, current_config.url);
    }
    
    return err;
}

static esp_err_t send_event(const device_event_t *event) {
    if (!event || !current_config.url[0]) return ESP_ERR_INVALID_ARG;
    
    cJSON *root = cJSON_CreateObject();
    
    const char *event_names[] = {"first_seen", "arrived", "left", "returned"};
    const char *event_labels[] = {"First Seen", "Arrived", "Left", "Returned"};
    
    char mac_str[18];
    snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
             event->mac[0], event->mac[1], event->mac[2],
             event->mac[3], event->mac[4], event->mac[5]);
    
    bool is_discord = (strstr(current_config.url, "discord.com/api/webhooks") != NULL) ||
                      (strstr(current_config.url, "discordapp.com/api/webhooks") != NULL);
    
    if (is_discord) {
        char vendor_clean[32];
        const char *vendor_raw = event->vendor[0] ? event->vendor : "Unknown";
        sanitize_text(vendor_clean, sizeof(vendor_clean), vendor_raw);
        if (!vendor_clean[0]) {
            strncpy(vendor_clean, "Unknown", sizeof(vendor_clean) - 1);
            vendor_clean[sizeof(vendor_clean) - 1] = '\0';
        }

        char ap_clean[40];
        const char *ap_raw = "Unknown";
        device_presence_t presence;
        if (scan_storage_get_device_presence(event->mac, &presence) == ESP_OK && presence.last_ap_ssid[0]) {
            ap_raw = presence.last_ap_ssid;
        }
        sanitize_text(ap_clean, sizeof(ap_clean), ap_raw);
        if (!ap_clean[0]) {
            strncpy(ap_clean, "Unknown", sizeof(ap_clean) - 1);
            ap_clean[sizeof(ap_clean) - 1] = '\0';
        }

        char timestamp[32];
        bool has_timestamp = false;
        if (event->time_valid && event->epoch_ts > 0) {
            time_t ts = (time_t)event->epoch_ts;
            struct tm tm_buf;
            if (gmtime_r(&ts, &tm_buf)) {
                if (strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", &tm_buf) > 0) {
                    has_timestamp = true;
                }
            }
        }

        const char *title = "Device Event";
        int color = 0x5865F2;
        if (event->event_type == DEVICE_EVENT_FIRST_SEEN) {
            title = "Device First Seen";
            color = 0x57F287;
        } else if (event->event_type == DEVICE_EVENT_ARRIVED) {
            title = "Device Arrived";
            color = 0x57F287;
        } else if (event->event_type == DEVICE_EVENT_LEFT) {
            title = "Device Left";
            color = 0xED4245;
        } else if (event->event_type == DEVICE_EVENT_RETURNED) {
            title = "Device Returned";
            color = 0x57F287;
        }

        const char *event_label = event_labels[event->event_type];

        cJSON *embeds = cJSON_CreateArray();
        cJSON *embed = cJSON_CreateObject();

        cJSON_AddStringToObject(embed, "title", title);
        cJSON_AddNumberToObject(embed, "color", color);

        char description[192];
        snprintf(description, sizeof(description), "**Event:** %s\n**MAC:** `%s`\n**Vendor:** %s",
                 event_label, mac_str, vendor_clean);
        cJSON_AddStringToObject(embed, "description", description);

        cJSON *fields = cJSON_CreateArray();

        const char *trust_label = "New";
        if (event->trust_score > 70) {
            trust_label = "Trusted";
        } else if (event->trust_score > 50) {
            trust_label = "Known";
        } else if (event->trust_score > 30) {
            trust_label = "Familiar";
        }
        cJSON *f_trust = cJSON_CreateObject();
        cJSON_AddStringToObject(f_trust, "name", "Trust");
        cJSON_AddStringToObject(f_trust, "value", trust_label);
        cJSON_AddBoolToObject(f_trust, "inline", true);
        cJSON_AddItemToArray(fields, f_trust);

        char rssi_str[16];
        snprintf(rssi_str, sizeof(rssi_str), "%d", (int)event->rssi);
        cJSON *f_rssi = cJSON_CreateObject();
        cJSON_AddStringToObject(f_rssi, "name", "RSSI");
        cJSON_AddStringToObject(f_rssi, "value", rssi_str);
        cJSON_AddBoolToObject(f_rssi, "inline", true);
        cJSON_AddItemToArray(fields, f_rssi);

        const char *tracked_str = event->tracked ? "Yes" : "No";
        cJSON *f_tracked = cJSON_CreateObject();
        cJSON_AddStringToObject(f_tracked, "name", "Tracked");
        cJSON_AddStringToObject(f_tracked, "value", tracked_str);
        cJSON_AddBoolToObject(f_tracked, "inline", true);
        cJSON_AddItemToArray(fields, f_tracked);

        const char *home_str = (event->device_flags & 0x04) ? "Yes" : "No";
        cJSON *f_home = cJSON_CreateObject();
        cJSON_AddStringToObject(f_home, "name", "Home");
        cJSON_AddStringToObject(f_home, "value", home_str);
        cJSON_AddBoolToObject(f_home, "inline", true);
        cJSON_AddItemToArray(fields, f_home);

        cJSON *f_ap = cJSON_CreateObject();
        cJSON_AddStringToObject(f_ap, "name", "Last AP");
        cJSON_AddStringToObject(f_ap, "value", ap_clean);
        cJSON_AddBoolToObject(f_ap, "inline", true);
        cJSON_AddItemToArray(fields, f_ap);

        cJSON_AddItemToObject(embed, "fields", fields);

        cJSON *footer = cJSON_CreateObject();
        if (has_timestamp) {
            cJSON_AddStringToObject(embed, "timestamp", timestamp);
            cJSON_AddStringToObject(footer, "text", "PwnPower");
        } else {
            char footer_text[64];
            snprintf(footer_text, sizeof(footer_text), "PwnPower • Uptime: %lus", (unsigned long)event->uptime_sec);
            cJSON_AddStringToObject(footer, "text", footer_text);
        }
        cJSON_AddItemToObject(embed, "footer", footer);

        cJSON_AddItemToArray(embeds, embed);
        cJSON_AddItemToObject(root, "embeds", embeds);
    } else {
        cJSON_AddStringToObject(root, "event_type", event_names[event->event_type]);
        cJSON_AddStringToObject(root, "mac", mac_str);
        cJSON_AddStringToObject(root, "vendor", event->vendor);
        cJSON_AddNumberToObject(root, "trust_score", event->trust_score);
        cJSON_AddBoolToObject(root, "tracked", event->tracked != 0);
        cJSON_AddNumberToObject(root, "rssi", event->rssi);
        
        if (event->time_valid) {
            cJSON_AddNumberToObject(root, "epoch_ts", event->epoch_ts);
            cJSON_AddBoolToObject(root, "time_valid", true);
        } else {
            cJSON_AddNumberToObject(root, "uptime_sec", event->uptime_sec);
            cJSON_AddBoolToObject(root, "time_valid", false);
        }
    }
    
    char *json_str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    
    if (!json_str) return ESP_ERR_NO_MEM;
    
    if (is_discord) {
        ESP_LOGI(TAG, "Discord payload length: %d", (int)strlen(json_str));
        if (strlen(json_str) > 6000) {
            ESP_LOGW(TAG, "Discord payload may be too long for Discord (6000+ chars)");
        }
        ESP_LOGI(TAG, "Discord payload: %s", json_str);
    }
    
    // send http post
    esp_http_client_handle_t client = get_webhook_client();
    if (!client) {
        free(json_str);
        return ESP_FAIL;
    }
    
    esp_http_client_set_header(client, "Content-Type", "application/json");
    esp_http_client_set_post_field(client, json_str, strlen(json_str));
    
    esp_err_t err = esp_http_client_perform(client);
    int status_code = esp_http_client_get_status_code(client);
    int content_length = esp_http_client_get_content_length(client);

    ESP_LOGI(TAG, "HTTP response: status=%d, content_length=%d, err=%d", status_code, content_length, err);

    // Read response body if available
    char resp[256] = {0};
    if (content_length > 0 && content_length < sizeof(resp)) {
        int rlen = esp_http_client_read(client, resp, sizeof(resp) - 1);
        if (rlen > 0) {
            resp[rlen] = '\0';
        }
    }

    if (err == ESP_OK && status_code == 400) {
        if (strlen(resp) > 0) {
            ESP_LOGW(TAG, "Webhook 400 response body: %s", resp);
        } else {
            ESP_LOGW(TAG, "Webhook 400 response body: empty (content_length=%d)", content_length);
        }
    } else if (err == ESP_OK && (status_code < 200 || status_code >= 300)) {
        if (strlen(resp) > 0) {
            ESP_LOGW(TAG, "Webhook response body: %s", resp);
        }
    }
    
    free(json_str);
    
    vTaskDelay(pdMS_TO_TICKS(100));
    
    if (err == ESP_OK && status_code >= 200 && status_code < 300) {
        ESP_LOGI(TAG, "Webhook sent successfully (status=%d)", status_code);
        return ESP_OK;
    } else {
        ESP_LOGW(TAG, "Webhook failed (err=%d, status=%d)", err, status_code);
        reset_webhook_client();
        return ESP_FAIL;
    }
}

static void webhook_dispatcher_task(void *arg) {
    ESP_LOGI(TAG, "Webhook dispatcher task started");
    
    while (task_running) {
        // check every 10 seconds
        for (int i = 0; i < (CHECK_INTERVAL_MS / 100) && task_running; i++) {
            vTaskDelay(pdMS_TO_TICKS(100));
        }
        
        if (!task_running) break;
        
        // skip if not enabled or not connected
        if (!current_config.enabled || !current_config.url[0]) {
            continue;
        }
        
        if (!webserver_get_sta_connected()) {
            continue;
        }
        
        // try to send pending events
        uint32_t total_events = scan_storage_get_event_count();
        uint32_t write_idx = scan_storage_get_event_write_idx();

        if (total_events == 0) {
            send_cursor = 0;
            last_write_idx = write_idx;
            persist_cursor_state();
            continue;
        }

        if (total_events < MAX_DEVICE_EVENTS) {
            if (send_cursor > total_events) {
                send_cursor = total_events;
                persist_cursor_state();
            }
            last_write_idx = write_idx;
        } else if (send_cursor >= total_events) {
            uint32_t delta = (write_idx + MAX_DEVICE_EVENTS - last_write_idx) % MAX_DEVICE_EVENTS;
            if (delta == 0) {
                continue;
            }
            send_cursor = total_events - delta;
        }
        
        uint32_t sent_this_cycle = 0;
        while (send_cursor < total_events && task_running && sent_this_cycle < max_events_per_cycle) {
            device_event_t event;
            uint32_t actual_count = 0;
            
            esp_err_t err = scan_storage_get_device_events(send_cursor, 1, &event, &actual_count);
            if (err != ESP_OK || actual_count == 0) {
                break;
            }
            
            if (!current_config.all_events) {
                bool should_send = false;
                bool is_home_device = (event.device_flags & 0x04) != 0;  // DEVICE_FLAG_HOME_DEVICE
                bool is_new_device = (event.trust_score < 30);
                bool is_known_device = (event.trust_score > 50);
                
                if (current_config.home_departure_alert && is_home_device && 
                    event.event_type == DEVICE_EVENT_LEFT) {
                    should_send = true;
                }
                
                if (current_config.home_arrival_alert && is_home_device && 
                    (event.event_type == DEVICE_EVENT_ARRIVED || event.event_type == DEVICE_EVENT_RETURNED)) {
                    should_send = true;
                }
                
                if (current_config.new_device_alert && is_new_device) {
                    should_send = true;
                }
                
                if (current_config.tracked_only && is_known_device && 
                    (event.event_type == DEVICE_EVENT_FIRST_SEEN || 
                     event.event_type == DEVICE_EVENT_ARRIVED ||
                     event.event_type == DEVICE_EVENT_LEFT)) {
                    should_send = true;
                }
                
                if (!should_send) {
                    send_cursor++;
                    continue;
                }
            }
            
            // attempt send
            err = send_event(&event);
            if (err == ESP_OK) {
                send_cursor++;
                if (total_events >= MAX_DEVICE_EVENTS && send_cursor >= total_events) {
                    last_write_idx = write_idx;
                }
                persist_cursor_state();
                sent_this_cycle++;
            } else {
                // failed, will retry later
                break;
            }
            
            // small delay between sends to avoid flooding
            vTaskDelay(pdMS_TO_TICKS(500));
        }
    }
    
    webhook_task_handle = NULL;
    vTaskDelete(NULL);
}

esp_err_t webhook_start(void) {
    if (webhook_task_handle != NULL) {
        return ESP_ERR_INVALID_STATE;
    }
    
    task_running = true;
    
    BaseType_t ret = xTaskCreate(webhook_dispatcher_task, "webhook_dispatch", 
                                  WEBHOOK_TASK_STACK, NULL, 2, &webhook_task_handle);
    
    if (ret != pdPASS) {
        task_running = false;
        return ESP_ERR_NO_MEM;
    }
    
    ESP_LOGI(TAG, "Webhook dispatcher started");
    return ESP_OK;
}

void webhook_stop(void) {
    task_running = false;
    if (webhook_task_handle) {
        for (int i = 0; i < 50 && webhook_task_handle; i++) {
            vTaskDelay(pdMS_TO_TICKS(100));
        }
    }
    ESP_LOGI(TAG, "Webhook dispatcher stopped");
}

esp_err_t webhook_send_test(void) {
    if (!current_config.url[0]) {
        return ESP_ERR_INVALID_STATE;
    }
    
    // create a test event
    device_event_t test_event;
    memset(&test_event, 0, sizeof(test_event));
    
    // dummy mac
    test_event.mac[0] = 0xDE;
    test_event.mac[1] = 0xAD;
    test_event.mac[2] = 0xBE;
    test_event.mac[3] = 0xEF;
    test_event.mac[4] = 0xCA;
    test_event.mac[5] = 0xFE;
    
    test_event.event_type = DEVICE_EVENT_FIRST_SEEN;
    test_event.trust_score = 50;
    test_event.tracked = 0;
    test_event.rssi = -65;
    strncpy(test_event.vendor, "Test Vendor", sizeof(test_event.vendor) - 1);
    
    time_t now;
    time(&now);
    test_event.epoch_ts = (uint32_t)now;
    test_event.time_valid = 1;
    
    return send_event(&test_event);
}

uint32_t webhook_get_send_cursor(void) {
    return send_cursor;
}
