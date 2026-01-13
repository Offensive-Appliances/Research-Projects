#include "freertos/FreeRTOS.h"
#include "wifi_scan.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_timer.h"
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "esp_wifi_types.h"
#include "freertos/semphr.h"
#include "cJSON.h"
#include "sdkconfig.h"
#include "ouis.h"
#include "scan_storage.h"

#define TAG "WiFi_Scan"
#define MAX_JSON_SIZE 8192  // Increased size to accommodate the new JSON structure
#define MAX_STATIONS 50

static char scan_results_json[MAX_JSON_SIZE]; // Buffer for JSON results
static station_info_t stations[MAX_STATIONS];
static SemaphoreHandle_t stations_mutex = NULL;
static volatile size_t stations_count = 0;
static bool scan_in_progress = false;
static bool new_results_available = false;
static volatile bool station_scan_active = false;
static SemaphoreHandle_t scan_mutex = NULL;
static uint8_t known_ap_bssids[100][6];
static uint8_t known_ap_channels[64];
static int known_ap_count = 0;
static int known_channel_count = 0;

static volatile uint32_t s_deauth_count = 0;
static volatile uint32_t s_deauth_last_seen = 0;
static volatile uint32_t s_hidden_ap_count = 0;

#define MAX_HIDDEN_APS 16
typedef struct {
    uint8_t bssid[6];
    uint8_t channel;
    char ssid[33];
    uint32_t first_seen;
    uint8_t probe_attempts;
    bool revealed;
} hidden_ap_t;
static hidden_ap_t s_hidden_aps[MAX_HIDDEN_APS];
static int s_hidden_ap_idx = 0;

// Define 2.4 GHz and 5 GHz channels
const uint8_t dual_band_channels[] = {
    // 2.4 GHz channels: 1-13 (commonly used)
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
/*     // 5GHz channels below - comment out for C6 testing
    // UNII-1 (36-48)
    36, 40, 44, 48,
    // UNII-2 (52-64)
    52, 56, 60, 64,
    // UNII-2 Extended (100-144)
    100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
    // UNII-3 (149-165)
    149, 153, 157, 161, 165 */
};

const size_t dual_band_channels_size = sizeof(dual_band_channels)/sizeof(dual_band_channels[0]);

// Helper function to get the security type from the encryption mode
const char* get_security_type(uint8_t encryption) {
    switch (encryption) {
        case WIFI_AUTH_OPEN:
            return "Open";
        case WIFI_AUTH_WEP:
            return "WEP";
        case WIFI_AUTH_WPA_PSK:
            return "WPA2";
        case WIFI_AUTH_WPA2_PSK:
            return "WPA2";
        case WIFI_AUTH_WPA3_PSK:
            return "WPA3";
        case WIFI_AUTH_WPA2_WPA3_PSK:
            return "WPA2/WPA3";
        default:
            return "UNKNOWN";
    }
}


const char* get_band(uint8_t channel) {
    if (channel >= 1 && channel <= 13) {
        return "2.4ghz";
    }
    if ((channel >= 36 && channel <= 144) || (channel >= 149 && channel <= 165)) {
        return "5ghz";
    }
    return "Unknown Band";
}

void wifi_scan() {
    if(!scan_mutex) {
        scan_mutex = xSemaphoreCreateMutex();
    }

    scan_in_progress = true;
    
    // calculate estimate first
    const uint32_t ap_dwell_ms = 120;  // ap scan time per channel
    const uint32_t station_dwell_ms = 500;  // increased from 250
    const uint32_t total_estimate_ms = (ap_dwell_ms + station_dwell_ms) * dual_band_channels_size;
    
    ESP_LOGI(TAG, "Starting scan - estimated %.1f seconds (%d channels)", 
            total_estimate_ms / 1000.0f, dual_band_channels_size);

    cJSON *root = cJSON_CreateObject();
    cJSON *rows = cJSON_AddArrayToObject(root, "rows");
    
    wifi_scan_config_t scan_config = {
        .ssid = NULL,       
        .bssid = NULL,    
        .channel = 0,        // 0 means scan all channels in the list
        .show_hidden = true  
    };

    for (size_t i = 0; i < sizeof(dual_band_channels) / sizeof(dual_band_channels[0]); i++) {
        scan_config.channel = dual_band_channels[i];
        esp_err_t err = esp_wifi_scan_start(&scan_config, true);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "Wi-Fi scan failed on channel %d: %s", scan_config.channel, esp_err_to_name(err));
            cJSON_AddItemToArray(rows, cJSON_CreateObject());
            continue;
        }
        uint16_t ap_count = 0;
        esp_wifi_scan_get_ap_num(&ap_count);

        if (ap_count == 0) {
            continue;  // Skip silently if no APs
        }
        ESP_LOGI(TAG, "Found %d Wi-Fi networks on channel %d", ap_count, scan_config.channel);
        wifi_ap_record_t *ap_records = (wifi_ap_record_t *)malloc(sizeof(wifi_ap_record_t) * ap_count);
        if (!ap_records) {
            ESP_LOGE(TAG, "Memory allocation failed!");
            cJSON_AddItemToArray(rows, cJSON_CreateObject());
            continue;
        }
        err = esp_wifi_scan_get_ap_records(&ap_count, ap_records);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "Failed to get scan results on channel %d: %s", scan_config.channel, esp_err_to_name(err));
            free(ap_records);
            cJSON_AddItemToArray(rows, cJSON_CreateObject());
            continue;
        }
        uint32_t now_sec = (uint32_t)(esp_timer_get_time() / 1000000ULL);
        for (int j = 0; j < ap_count; j++) {
            bool is_hidden = (ap_records[j].ssid[0] == '\0');
            if (is_hidden) {
                s_hidden_ap_count++;
                bool found = false;
                for (int h = 0; h < s_hidden_ap_idx && h < MAX_HIDDEN_APS; h++) {
                    if (memcmp(s_hidden_aps[h].bssid, ap_records[j].bssid, 6) == 0) {
                        found = true;
                        break;
                    }
                }
                if (!found && s_hidden_ap_idx < MAX_HIDDEN_APS) {
                    memcpy(s_hidden_aps[s_hidden_ap_idx].bssid, ap_records[j].bssid, 6);
                    s_hidden_aps[s_hidden_ap_idx].channel = scan_config.channel;
                    s_hidden_aps[s_hidden_ap_idx].ssid[0] = '\0';
                    s_hidden_aps[s_hidden_ap_idx].first_seen = now_sec;
                    s_hidden_aps[s_hidden_ap_idx].probe_attempts = 0;
                    s_hidden_aps[s_hidden_ap_idx].revealed = false;
                    s_hidden_ap_idx++;
                }
            }
            
            cJSON *ap_entry = cJSON_CreateObject();
            cJSON_AddStringToObject(ap_entry, "SSID", (char*)ap_records[j].ssid);
            cJSON_AddStringToObject(ap_entry, "MAC", mac_to_str(ap_records[j].bssid));
            cJSON_AddNumberToObject(ap_entry, "Channel", scan_config.channel);
            cJSON_AddNumberToObject(ap_entry, "RSSI", ap_records[j].rssi);
            cJSON_AddStringToObject(ap_entry, "Security", get_security_type(ap_records[j].authmode));
            cJSON_AddStringToObject(ap_entry, "Band", get_band(scan_config.channel));
            cJSON_AddNumberToObject(ap_entry, "last_seen", now_sec);
            cJSON_AddBoolToObject(ap_entry, "hidden", is_hidden);
            
            char vendor[48] = "Unknown";
            ouis_lookup_vendor(ap_records[j].bssid, vendor, sizeof(vendor));
            cJSON_AddStringToObject(ap_entry, "Vendor", vendor);
            
            cJSON_AddItemToArray(rows, ap_entry);
            bool exists = false;
            for(int k=0;k<known_ap_count;k++){ if(memcmp(known_ap_bssids[k], ap_records[j].bssid, 6)==0){ exists=true; break; } }
            if(!exists && known_ap_count < (int)(sizeof(known_ap_bssids)/sizeof(known_ap_bssids[0]))){ memcpy(known_ap_bssids[known_ap_count], ap_records[j].bssid, 6); known_ap_count++; }
            uint8_t ch = scan_config.channel;
            bool ch_exists = false;
            for(int k=0;k<known_channel_count;k++){ if(known_ap_channels[k]==ch){ ch_exists=true; break; } }
            if(!ch_exists && known_channel_count < (int)(sizeof(known_ap_channels))){ known_ap_channels[known_channel_count++] = ch; }
        }
        free(ap_records);
    }

    // NOW DO STATION SCAN
    wifi_scan_stations();
    const char *station_json = wifi_scan_get_station_results();
    cJSON *station_root = cJSON_Parse(station_json);
    if (!station_root) {
        station_root = cJSON_CreateObject();
    }

    // Update device presence tracking for all found stations
    cJSON *station_ap_entry = NULL;
    cJSON_ArrayForEach(station_ap_entry, station_root) {
        cJSON *stations = cJSON_GetObjectItem(station_ap_entry, "stations");
        if (stations && cJSON_IsArray(stations)) {
            cJSON *station = NULL;
            cJSON_ArrayForEach(station, stations) {
                cJSON *mac_item = cJSON_GetObjectItem(station, "mac");
                cJSON *rssi_item = cJSON_GetObjectItem(station, "rssi");
                if (mac_item && rssi_item) {
                    // Parse MAC address
                    uint8_t mac[6];
                    if (sscanf(mac_item->valuestring, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                              &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) == 6) {
                        // Find the corresponding AP entry to get SSID
                        cJSON *ap_mac_item = cJSON_GetObjectItem(station_ap_entry, "bssid");
                        if (ap_mac_item) {
                            // Find AP SSID from the main scan results
                            cJSON *scan_ap_entry = NULL;
                            cJSON_ArrayForEach(scan_ap_entry, rows) {
                                cJSON *scan_mac_item = cJSON_GetObjectItem(scan_ap_entry, "MAC");
                                if (scan_mac_item && strcmp(scan_mac_item->valuestring, ap_mac_item->valuestring) == 0) {
                                    cJSON *ssid_item = cJSON_GetObjectItem(scan_ap_entry, "SSID");
                                    if (ssid_item) {
                                        scan_storage_update_device_presence(mac, rssi_item->valueint, ssid_item->valuestring);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // merge station data into AP entries
    cJSON *ap_entry = NULL;
    cJSON_ArrayForEach(ap_entry, rows) {
        cJSON *mac_item = cJSON_GetObjectItem(ap_entry, "MAC");
        if(mac_item) {
            // convert to uppercase for key matching
            char upper_mac[18];
            strncpy(upper_mac, mac_item->valuestring, sizeof(upper_mac));
            for(int i=0; upper_mac[i]; i++) upper_mac[i] = toupper(upper_mac[i]);
            
            cJSON *station_data = cJSON_GetObjectItem(station_root, upper_mac);
            if(station_data) {
                cJSON *stations = cJSON_DetachItemFromObject(station_data, "stations");
                cJSON_AddItemToObject(ap_entry, "stations", stations);
            }
        }
    }

    // Store results in buffer with mutex protection
    xSemaphoreTake(scan_mutex, portMAX_DELAY);
    char *json_str = cJSON_PrintUnformatted(root);
    if (json_str) {
        size_t json_len = strlen(json_str);
        if (json_len >= MAX_JSON_SIZE) {
            ESP_LOGW(TAG, "Scan JSON too large (%u bytes), returning empty result", (unsigned)json_len);
            strncpy(scan_results_json, "{\"rows\":[]}", MAX_JSON_SIZE - 1);
            scan_results_json[MAX_JSON_SIZE - 1] = '\0';
        } else {
            memcpy(scan_results_json, json_str, json_len + 1);
        }
        free(json_str);
    } else {
        strncpy(scan_results_json, "{\"rows\":[]}", MAX_JSON_SIZE - 1);
        scan_results_json[MAX_JSON_SIZE - 1] = '\0';
    }
    
    scan_in_progress = false;
    new_results_available = true;
    xSemaphoreGive(scan_mutex);
    
    // cleanup
    cJSON_Delete(root);
    cJSON_Delete(station_root);
    
    // Sync deauth detection results to intelligence system
    scan_storage_update_security_events(wifi_scan_get_deauth_count());
    
    ESP_LOGI(TAG, "Wi-Fi Scan Completed. Results cached.");
}

const char* wifi_scan_get_results() {
    if(!scan_mutex) return "{}";  // Return empty JSON if not initialized
    
    xSemaphoreTake(scan_mutex, portMAX_DELAY);
    // If scan is in progress, return previous results
    if(scan_in_progress) {
        xSemaphoreGive(scan_mutex);
        return scan_results_json;
    }
    new_results_available = false;  // Mark results as read
    xSemaphoreGive(scan_mutex);
    return scan_results_json;
}

bool wifi_scan_is_complete() {
    if(!scan_mutex) return true;  // Assume complete if not initialized
    
    xSemaphoreTake(scan_mutex, portMAX_DELAY);
    bool complete = !scan_in_progress;
    xSemaphoreGive(scan_mutex);
    return complete;
}

bool wifi_scan_has_new_results() {
    if(!scan_mutex) return false;
    
    xSemaphoreTake(scan_mutex, portMAX_DELAY);
    bool has_new = new_results_available;
    xSemaphoreGive(scan_mutex);
    return has_new;
}

static void stations_sniffer(void* buf, wifi_promiscuous_pkt_type_t type) {
    if(type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA) return;

    wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
    wifi_pkt_rx_ctrl_t *rx_ctrl = &pkt->rx_ctrl;
    uint8_t *payload = pkt->payload;
    uint8_t fc0 = payload[0];
    uint8_t fc1 = payload[1];
    uint8_t frame_type = (fc0 >> 2) & 0x03;
    uint8_t frame_subtype = (fc0 >> 4) & 0x0F;
    
    if (frame_type == 0 && (frame_subtype == 0x0C || frame_subtype == 0x0A)) {
        s_deauth_count++;
        s_deauth_last_seen = (uint32_t)(esp_timer_get_time() / 1000000ULL);
        return;
    }
    
    // Monitor for probe responses (0x0B) that might reveal hidden SSIDs
    if (frame_type == 0 && frame_subtype == 0x0B) {
        uint8_t *bssid = payload + 16;
        uint8_t *frame_body = payload + 24;
        
        // Skip fixed parameters (timestamp: 8, beacon interval: 2, capabilities: 2)
        frame_body += 12;
        
        // Parse parameters - look for SSID parameter (ID 0x00)
        while (frame_body[0] != 0x00 && frame_body[0] != 0xFF && frame_body < payload + pkt->rx_ctrl.sig_len) {
            uint8_t param_len = frame_body[1];
            frame_body += 2 + param_len;
        }
        
        if (frame_body[0] == 0x00) {
            uint8_t ssid_len = frame_body[1];
            if (ssid_len > 0 && ssid_len < 33) {
                // Check if this matches any of our hidden APs
                for (int h = 0; h < s_hidden_ap_idx && h < MAX_HIDDEN_APS; h++) {
                    if (!s_hidden_aps[h].revealed && memcmp(s_hidden_aps[h].bssid, bssid, 6) == 0) {
                        memcpy(s_hidden_aps[h].ssid, frame_body + 2, ssid_len);
                        s_hidden_aps[h].ssid[ssid_len] = '\0';
                        s_hidden_aps[h].revealed = true;
                        ESP_LOGI(TAG, "Revealed hidden SSID from client probe: %s", s_hidden_aps[h].ssid);
                        break;
                    }
                }
            }
        }
    }
    
    // Monitor for association requests (0x00) that reveal hidden SSIDs
    if (frame_type == 0 && frame_subtype == 0x00) {
        uint8_t *bssid = payload + 16;
        uint8_t *frame_body = payload + 24;
        
        // Skip fixed parameters
        frame_body += 2; // Capability info
        
        // Parse parameters - look for SSID parameter (ID 0x00)
        while (frame_body[0] != 0x00 && frame_body[0] != 0xFF && frame_body < payload + pkt->rx_ctrl.sig_len) {
            uint8_t param_len = frame_body[1];
            frame_body += 2 + param_len;
        }
        
        if (frame_body[0] == 0x00) {
            uint8_t ssid_len = frame_body[1];
            if (ssid_len > 0 && ssid_len < 33) {
                // Check if this matches any of our hidden APs
                for (int h = 0; h < s_hidden_ap_idx && h < MAX_HIDDEN_APS; h++) {
                    if (!s_hidden_aps[h].revealed && memcmp(s_hidden_aps[h].bssid, bssid, 6) == 0) {
                        memcpy(s_hidden_aps[h].ssid, frame_body + 2, ssid_len);
                        s_hidden_aps[h].ssid[ssid_len] = '\0';
                        s_hidden_aps[h].revealed = true;
                        ESP_LOGI(TAG, "Revealed hidden SSID from client association: %s", s_hidden_aps[h].ssid);
                        break;
                    }
                }
            }
        }
    }
    
    bool to_ds = (fc1 & 0x01) != 0;
    bool from_ds = (fc1 & 0x02) != 0;
    uint8_t *addr1 = payload + 4;
    uint8_t *addr2 = payload + 10;
    uint8_t *addr3 = payload + 16;
    uint8_t station_mac[6];
    uint8_t ap_bssid[6];
    bool found = false;
    if(frame_type == 2){
        if(to_ds && !from_ds){ memcpy(station_mac, addr2, 6); memcpy(ap_bssid, addr1, 6); found = true; }
        else if(!to_ds && from_ds){ memcpy(station_mac, addr1, 6); memcpy(ap_bssid, addr2, 6); found = true; }
        else { memcpy(station_mac, addr2, 6); memcpy(ap_bssid, addr3, 6); found = true; }
    } else if(frame_type == 0){
        if(frame_subtype == 8) return;
        memcpy(station_mac, addr2, 6);
        memcpy(ap_bssid, addr3, 6);
        if(memcmp(station_mac, ap_bssid, 6) != 0) found = true;
    } else {
        return;
    }
    if(!found) return;
    bool ap_ok = false;
    for(int k=0;k<known_ap_count;k++){ if(memcmp(known_ap_bssids[k], ap_bssid, 6)==0){ ap_ok = true; break; } }
    if(!ap_ok) return;
    const uint8_t bcast[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
    if(memcmp(station_mac, bcast, 6)==0) return;
    if((station_mac[0] & 0x01) != 0) return;
    if(memcmp(station_mac, ap_bssid, 6)==0) return;
    station_info_t candidate = { .channel = rx_ctrl->channel, .rssi = rx_ctrl->rssi };
    memcpy(candidate.station_mac, station_mac, 6);
    memcpy(candidate.ap_bssid, ap_bssid, 6);
    xSemaphoreTake(stations_mutex, portMAX_DELAY);
    bool exists = false;
    for(int i=0; i<stations_count; i++) {
        if(memcmp(stations[i].station_mac, candidate.station_mac, 6) == 0 && memcmp(stations[i].ap_bssid, candidate.ap_bssid, 6) == 0) { exists = true; break; }
    }
    if(!exists && stations_count < MAX_STATIONS) { stations[stations_count++] = candidate; }
    xSemaphoreGive(stations_mutex);
}

bool wifi_scan_is_station_scan_active(void) {
    return station_scan_active;
}

void wifi_scan_set_station_scan_active(bool active) {
    station_scan_active = active;
}

static void probe_hidden_aps_internal(void);

void wifi_scan_stations() {
    if(!stations_mutex) stations_mutex = xSemaphoreCreateMutex();
    
    station_scan_active = true;
    
    // store original wifi mode and connection state
    wifi_mode_t original_mode;
    esp_wifi_get_mode(&original_mode);
    
    bool was_sta_connected = false;
    wifi_ap_record_t ap_info;
    if(original_mode == WIFI_MODE_STA || original_mode == WIFI_MODE_APSTA) {
        was_sta_connected = (esp_wifi_sta_get_ap_info(&ap_info) == ESP_OK);
    }
    
    // disconnect STA and disable AP to allow free channel switching
    if(was_sta_connected) {
        ESP_LOGI(TAG, "Disconnecting STA for station scan");
        esp_wifi_disconnect();
        vTaskDelay(pdMS_TO_TICKS(300));
    }
    
    if(original_mode == WIFI_MODE_APSTA || original_mode == WIFI_MODE_AP) {
        ESP_LOGI(TAG, "Temporarily disabling AP for station scan");
        esp_wifi_deauth_sta(0);
        vTaskDelay(pdMS_TO_TICKS(200));
    }
    
    esp_wifi_set_mode(WIFI_MODE_STA);
    vTaskDelay(pdMS_TO_TICKS(300));
    
    xSemaphoreTake(stations_mutex, portMAX_DELAY);
    stations_count = 0; // reset for new scan
    xSemaphoreGive(stations_mutex);

    if(known_ap_count == 0) {
        wifi_scan_config_t scan_config = { .ssid = NULL, .bssid = NULL, .channel = 0, .show_hidden = true, .scan_type = WIFI_SCAN_TYPE_ACTIVE, .scan_time.active.min = 150, .scan_time.active.max = 300 };
        if(esp_wifi_scan_start(&scan_config, true) == ESP_OK){
            uint16_t ap_num = 0; esp_wifi_scan_get_ap_num(&ap_num);
            if(ap_num > 0){
                wifi_ap_record_t *ap_records = malloc(sizeof(wifi_ap_record_t)*ap_num);
                if(ap_records){
                    if(esp_wifi_scan_get_ap_records(&ap_num, ap_records) == ESP_OK){
                        known_ap_count = 0; known_channel_count = 0;
                        for(int i=0;i<ap_num;i++){
                            bool exists=false; for(int k=0;k<known_ap_count;k++){ if(memcmp(known_ap_bssids[k], ap_records[i].bssid,6)==0){ exists=true; break; }}
                            if(!exists && known_ap_count < (int)(sizeof(known_ap_bssids)/sizeof(known_ap_bssids[0]))){ memcpy(known_ap_bssids[known_ap_count], ap_records[i].bssid,6); known_ap_count++; }
                            uint8_t ch = ap_records[i].primary; bool ch_exists=false; for(int k=0;k<known_channel_count;k++){ if(known_ap_channels[k]==ch){ ch_exists=true; break; } }
                            if(!ch_exists && known_channel_count < (int)(sizeof(known_ap_channels))){ known_ap_channels[known_channel_count++] = ch; }
                        }
                    }
                    free(ap_records);
                }
            }
        }
    }

    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(stations_sniffer);

    uint32_t scan_time_ms = 8000;
    uint32_t dwell_time_ms = 300;
    int ch_count = known_channel_count > 0 ? known_channel_count : (int)dual_band_channels_size;
    uint32_t iterations = scan_time_ms / (dwell_time_ms * (uint32_t)ch_count);
    if (iterations == 0) iterations = 1;
    if (iterations > 8) iterations = 8;
    for (uint32_t iter = 0; iter < iterations; iter++) {
        for (int i = 0; i < ch_count; i++) {
            uint8_t ch = (known_channel_count > 0) ? known_ap_channels[i] : dual_band_channels[i];
            esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
            vTaskDelay(pdMS_TO_TICKS(dwell_time_ms));
        }
    }

    esp_wifi_set_promiscuous(false);
    
    probe_hidden_aps_internal();
    
    // restore original mode and reconnect if needed
    if(original_mode != WIFI_MODE_STA) {
        ESP_LOGI(TAG, "Restoring original mode");
        esp_wifi_set_mode(original_mode);
        vTaskDelay(pdMS_TO_TICKS(500));
    }
    
    station_scan_active = false;
    
    if(was_sta_connected) {
        ESP_LOGI(TAG, "Reconnecting STA");
        esp_wifi_connect();
    }
}

const char* wifi_scan_get_station_results() {
    static char json_output[4096];
    cJSON *root = cJSON_CreateObject();
    
    xSemaphoreTake(stations_mutex, portMAX_DELAY);
    for(int i=0; i<stations_count; i++) {
        // Get/Create AP entry
        char ap_key[18];
        snprintf(ap_key, sizeof(ap_key), "%02X:%02X:%02X:%02X:%02X:%02X",
                stations[i].ap_bssid[0], stations[i].ap_bssid[1],
                stations[i].ap_bssid[2], stations[i].ap_bssid[3],
                stations[i].ap_bssid[4], stations[i].ap_bssid[5]);
        
        cJSON *ap_entry = cJSON_GetObjectItemCaseSensitive(root, ap_key);
        if(!ap_entry) {
            ap_entry = cJSON_AddObjectToObject(root, ap_key);
            cJSON_AddStringToObject(ap_entry, "bssid", ap_key);
            cJSON_AddNumberToObject(ap_entry, "channel", stations[i].channel);
            cJSON_AddArrayToObject(ap_entry, "stations");
        }

        // Add station to AP's list
        uint32_t now_sec = (uint32_t)(esp_timer_get_time() / 1000000ULL);
        cJSON *station = cJSON_CreateObject();
        cJSON_AddStringToObject(station, "mac", 
            (char*)mac_to_str(stations[i].station_mac));
        cJSON_AddNumberToObject(station, "rssi", stations[i].rssi);
        cJSON_AddNumberToObject(station, "last_seen", now_sec);
        
        char sta_vendor[48] = "Unknown";
        ouis_lookup_vendor(stations[i].station_mac, sta_vendor, sizeof(sta_vendor));
        cJSON_AddStringToObject(station, "vendor", sta_vendor);
        
        cJSON_AddItemToArray(cJSON_GetObjectItem(ap_entry, "stations"), station);
    }
    xSemaphoreGive(stations_mutex);
    
    char *json = cJSON_PrintUnformatted(root);
    if (json) {
        size_t json_len = strlen(json);
        if (json_len >= sizeof(json_output)) {
            ESP_LOGW(TAG, "Station JSON too large (%u bytes), returning empty result", (unsigned)json_len);
            strncpy(json_output, "{}", sizeof(json_output) - 1);
            json_output[sizeof(json_output) - 1] = '\0';
        } else {
            memcpy(json_output, json, json_len + 1);
        }
        free(json);
    } else {
        strncpy(json_output, "{}", sizeof(json_output) - 1);
        json_output[sizeof(json_output) - 1] = '\0';
    }
    cJSON_Delete(root);
    
    return json_output;
}

const char* mac_to_str(const uint8_t *mac) {
    static char mac_str[18];
    snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return mac_str;
}

uint32_t wifi_scan_get_deauth_count(void) {
    return s_deauth_count;
}

uint32_t wifi_scan_get_deauth_last_seen(void) {
    return s_deauth_last_seen;
}

void wifi_scan_reset_deauth_count(void) {
    s_deauth_count = 0;
}

void wifi_scan_register_hidden_ap(const uint8_t *bssid, uint8_t channel) {
    if (!bssid || s_hidden_ap_idx >= MAX_HIDDEN_APS) return;
    
    for (int h = 0; h < s_hidden_ap_idx; h++) {
        if (memcmp(s_hidden_aps[h].bssid, bssid, 6) == 0) {
            return;
        }
    }
    
    memcpy(s_hidden_aps[s_hidden_ap_idx].bssid, bssid, 6);
    s_hidden_aps[s_hidden_ap_idx].channel = channel;
    s_hidden_aps[s_hidden_ap_idx].ssid[0] = '\0';
    s_hidden_aps[s_hidden_ap_idx].first_seen = (uint32_t)(esp_timer_get_time() / 1000000ULL);
    s_hidden_aps[s_hidden_ap_idx].probe_attempts = 0;
    s_hidden_aps[s_hidden_ap_idx].revealed = false;
    s_hidden_ap_idx++;
}

const char* wifi_scan_get_security_stats_json(void) {
    static char buf[512];
    uint32_t now = (uint32_t)(esp_timer_get_time() / 1000000ULL);
    int pos = 0;
    pos += snprintf(buf + pos, sizeof(buf) - pos, 
        "{\"deauth_count\":%lu,\"deauth_last_seen\":%lu,\"hidden_aps\":[",
        (unsigned long)s_deauth_count, 
        s_deauth_last_seen > 0 ? (unsigned long)(now - s_deauth_last_seen) : 0);
    
    for (int i = 0; i < s_hidden_ap_idx && i < MAX_HIDDEN_APS; i++) {
        if (i > 0) pos += snprintf(buf + pos, sizeof(buf) - pos, ",");
        pos += snprintf(buf + pos, sizeof(buf) - pos,
            "{\"bssid\":\"%02X:%02X:%02X:%02X:%02X:%02X\",\"first_seen\":%lu,\"revealed\":%s,\"ssid\":\"%s\"}",
            s_hidden_aps[i].bssid[0], s_hidden_aps[i].bssid[1], s_hidden_aps[i].bssid[2],
            s_hidden_aps[i].bssid[3], s_hidden_aps[i].bssid[4], s_hidden_aps[i].bssid[5],
            (unsigned long)s_hidden_aps[i].first_seen,
            s_hidden_aps[i].revealed ? "true" : "false",
            s_hidden_aps[i].revealed ? s_hidden_aps[i].ssid : "");
    }
    pos += snprintf(buf + pos, sizeof(buf) - pos, "],\"hidden_count\":%d}", s_hidden_ap_idx);
    return buf;
}

static void probe_hidden_aps_internal(void) {
    int unrevealed_count = 0;
    for (int i = 0; i < s_hidden_ap_idx && i < MAX_HIDDEN_APS; i++) {
        if (!s_hidden_aps[i].revealed && s_hidden_aps[i].probe_attempts < 20) {
            unrevealed_count++;
        }
    }
    
    if (unrevealed_count == 0) return;
    
    ESP_LOGI(TAG, "Monitoring %d hidden APs for client activity", unrevealed_count);
    
    // Enable promiscuous mode to monitor for client activity
    wifi_promiscuous_filter_t filt = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT
    };
    esp_wifi_set_promiscuous_filter(&filt);
    esp_wifi_set_promiscuous_rx_cb(stations_sniffer);
    esp_wifi_set_promiscuous(true);
    
    // Monitor for 10 seconds to catch client activity
    vTaskDelay(pdMS_TO_TICKS(10000));
    
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(NULL);
    
    ESP_LOGI(TAG, "Hidden AP monitoring complete");
}

int wifi_scan_probe_hidden_aps(void) {
    int revealed_count = 0;
    int unrevealed_count = 0;
    
    for (int i = 0; i < s_hidden_ap_idx && i < MAX_HIDDEN_APS; i++) {
        if (!s_hidden_aps[i].revealed && s_hidden_aps[i].probe_attempts < 20) {
            unrevealed_count++;
        }
    }
    
    if (unrevealed_count == 0) return revealed_count;
    
    ESP_LOGI(TAG, "Monitoring %d hidden APs for client activity", unrevealed_count);
    
    // Enable promiscuous mode to monitor for client activity
    wifi_promiscuous_filter_t filt = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT
    };
    esp_wifi_set_promiscuous_filter(&filt);
    esp_wifi_set_promiscuous_rx_cb(stations_sniffer);
    esp_wifi_set_promiscuous(true);
    
    // Monitor for 10 seconds to catch client activity
    vTaskDelay(pdMS_TO_TICKS(10000));
    
    // Count revealed APs and increment monitoring attempts
    for (int i = 0; i < s_hidden_ap_idx && i < MAX_HIDDEN_APS; i++) {
        if (s_hidden_aps[i].revealed) {
            revealed_count++;
        }
        // Increment probe attempts to track monitoring attempts
        if (!s_hidden_aps[i].revealed && s_hidden_aps[i].probe_attempts < 20) {
            s_hidden_aps[i].probe_attempts++;
        }
    }
    
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(NULL);
    
    ESP_LOGI(TAG, "Hidden AP monitoring complete: %d/%d revealed", revealed_count, unrevealed_count);
    return revealed_count;
}
