#include "freertos/FreeRTOS.h"  // ADD THIS FIRST TO SATISFY DEPENDENCIES
#include "wifi_scan.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "esp_wifi_types.h"  // contains wifi_ieee80211_mac_hdr_t
#include "freertos/semphr.h"
#include "cJSON.h"
#include "sdkconfig.h"  // add this FIRST before freertos

#define TAG "WiFi_Scan"
#define MAX_JSON_SIZE 2048  // Increased size to accommodate the new JSON structure
#define MAX_STATIONS 50

static char scan_results_json[MAX_JSON_SIZE]; // Buffer for JSON results
static station_info_t stations[MAX_STATIONS];
static SemaphoreHandle_t stations_mutex = NULL;
static volatile size_t stations_count = 0;
static bool scan_in_progress = false;
static bool new_results_available = false;
static SemaphoreHandle_t scan_mutex = NULL;
static uint8_t known_ap_bssids[100][6];
static uint8_t known_ap_channels[64];
static int known_ap_count = 0;
static int known_channel_count = 0;

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
        for (int j = 0; j < ap_count; j++) {
            cJSON *ap_entry = cJSON_CreateObject();
            cJSON_AddStringToObject(ap_entry, "SSID", (char*)ap_records[j].ssid);
            cJSON_AddStringToObject(ap_entry, "MAC", mac_to_str(ap_records[j].bssid));
            cJSON_AddNumberToObject(ap_entry, "Channel", scan_config.channel);
            cJSON_AddStringToObject(ap_entry, "Security", get_security_type(ap_records[j].authmode));
            cJSON_AddStringToObject(ap_entry, "Band", get_band(scan_config.channel));
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
    strncpy(scan_results_json, json_str, MAX_JSON_SIZE-1);
    scan_results_json[MAX_JSON_SIZE-1] = '\0';
    free(json_str);
    
    scan_in_progress = false;
    new_results_available = true;
    xSemaphoreGive(scan_mutex);
    
    // cleanup
    cJSON_Delete(root);
    cJSON_Delete(station_root);
    
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

void wifi_scan_stations() {
    if(!stations_mutex) stations_mutex = xSemaphoreCreateMutex();
    
    // store original wifi mode
    wifi_mode_t original_mode;
    esp_wifi_get_mode(&original_mode);
    
    // disable AP if it was active
    if(original_mode == WIFI_MODE_APSTA) {
        esp_wifi_set_mode(WIFI_MODE_STA);
        vTaskDelay(pdMS_TO_TICKS(100)); // let wifi stack adjust
    }
    
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
    
    // restore original mode
    esp_wifi_set_mode(original_mode);
    vTaskDelay(pdMS_TO_TICKS(100)); // let AP restart
}

const char* wifi_scan_get_station_results() {
    static char json_output[2048];
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
        cJSON *station = cJSON_CreateObject();
        cJSON_AddStringToObject(station, "mac", 
            (char*)mac_to_str(stations[i].station_mac));
        cJSON_AddNumberToObject(station, "rssi", stations[i].rssi);
        cJSON_AddItemToArray(cJSON_GetObjectItem(ap_entry, "stations"), station);
    }
    xSemaphoreGive(stations_mutex);
    
    char *json = cJSON_PrintUnformatted(root);
    strncpy(json_output, json, sizeof(json_output)-1);
    free(json);
    cJSON_Delete(root);
    
    return json_output;
}

const char* mac_to_str(const uint8_t *mac) {
    static char mac_str[18]; // 6 octets * 2 + 5 colons + null
    snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return mac_str;
}
