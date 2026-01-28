#include "freertos/FreeRTOS.h"
#include "wifi_scan.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_timer.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>
#include "esp_wifi_types.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "cJSON.h"
#include "esp_netif.h"
#include "sdkconfig.h"
#include "ouis.h"
#include "scan_storage.h"
#include "json_utils.h"
#include "device_lifecycle.h"

// Forward declarations
extern bool pwnpower_time_is_synced(void);
static uint32_t get_current_timestamp(void);
static void stations_sniffer(void* buf, wifi_promiscuous_pkt_type_t type);
static esp_err_t update_scan_results_json(cJSON *root);

#define TAG "WiFi_Scan"
#define MAX_JSON_SIZE 8192  // Increased size to accommodate the new JSON structure
#define MAX_STATIONS 50

static char *scan_results_json = NULL; // Dynamic buffer for JSON results
static size_t scan_results_size = MAX_JSON_SIZE;
static char *station_json_buffer = NULL; // Dynamic buffer for station results
static station_info_t stations[MAX_STATIONS];
static SemaphoreHandle_t stations_mutex = NULL;
static volatile size_t stations_count = 0;
static bool scan_in_progress = false;
static bool new_results_available = false;
static uint32_t scan_results_timestamp = 0;  // Timestamp when results were generated
static bool scan_was_truncated = false;      // Flag if results were truncated due to size
static volatile bool station_scan_active = false;
static volatile bool station_scan_background = false;
// static TaskHandle_t s_station_scan_task = NULL;
// static cJSON *s_pending_ap_data = NULL;
static SemaphoreHandle_t scan_mutex = NULL;
static TaskHandle_t s_wifi_scan_task_handle = NULL;
static void wifi_scan_task(void *arg);
static uint8_t known_ap_bssids[100][6];
static uint8_t known_ap_channels[64];
static int known_ap_count = 0;
static int known_channel_count = 0;

static volatile uint32_t s_deauth_count = 0;
static volatile uint32_t s_deauth_last_seen = 0;
static volatile uint32_t s_hidden_ap_count = 0;
static volatile uint32_t s_probe_request_count = 0;

// Smart channel weighting system
uint32_t channel_scan_counts[14] = {0};     // Times each channel was scanned
uint32_t channel_discovery_counts[14] = {0}; // Devices found per channel
uint32_t last_channel_update = 0;

#define CHANNEL_LEARNING_RATE 0.2f
#define MIN_SCANS_FOR_LEARNING 5
#define MAX_CHANNEL_WEIGHT 2.0f
#define MIN_CHANNEL_WEIGHT 0.5f
#define RSSI_CUTOFF_THRESHOLD -85  // Ignore networks weaker than -85 dBm

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

// WPS tracking
#define MAX_WPS_APS 100
typedef struct {
    uint8_t bssid[6];
    bool wps_enabled;
} wps_ap_t;
static wps_ap_t s_wps_aps[MAX_WPS_APS];
static int s_wps_ap_count = 0;

// Dynamic channel selection based on configured Wi-Fi country
typedef struct {
    const char code[3];
    const uint8_t *channels;
    size_t count;
} country_channels_t;

static const uint8_t channels_world[] = {
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
    36, 40, 44, 48, 52, 56, 60, 64,
    100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
    149, 153, 157, 161, 165
};

static const uint8_t channels_us[] = {
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
    36, 40, 44, 48, 52, 56, 60, 64,
    100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
    149, 153, 157, 161
};

static const uint8_t channels_cn[] = {
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
    36, 40, 44, 48, 52, 56, 60, 64,
    149, 153, 157, 161, 165
};

static const uint8_t channels_eu[] = {
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
    36, 40, 44, 48, 52, 56, 60, 64,
    100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140
};

static const uint8_t channels_jp[] = {
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
    34, 38, 42, 46,
    52, 56, 60, 64,
    100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140
};

static const country_channels_t country_map[] = {
    {"US", channels_us, sizeof(channels_us) / sizeof(channels_us[0])},
    {"CN", channels_cn, sizeof(channels_cn) / sizeof(channels_cn[0])},
    {"EU", channels_eu, sizeof(channels_eu) / sizeof(channels_eu[0])},
    {"JP", channels_jp, sizeof(channels_jp) / sizeof(channels_jp[0])},
};

static uint8_t dynamic_channels[64];
static size_t dynamic_channels_count = 0;

static bool target_is_dual_band(void) {
#if CONFIG_IDF_TARGET_ESP32C5
    return true;
#else
    return false;
#endif
}

static void init_country_channels(void) {
    if (dynamic_channels_count) {
        return;
    }

    wifi_country_t country = {0};
    if (esp_wifi_get_country(&country) != ESP_OK) {
        country.cc[0] = 'W';
        country.cc[1] = 'O';
        country.cc[2] = 'R';
    }

    const uint8_t *selected = channels_world;
    size_t selected_count = sizeof(channels_world) / sizeof(channels_world[0]);

    for (size_t i = 0; i < sizeof(country_map) / sizeof(country_map[0]); i++) {
        if (country.cc[0] == country_map[i].code[0] && country.cc[1] == country_map[i].code[1]) {
            selected = country_map[i].channels;
            selected_count = country_map[i].count;
            break;
        }
    }

    bool dual_band = target_is_dual_band();
    for (size_t i = 0; i < selected_count && dynamic_channels_count < sizeof(dynamic_channels); i++) {
        uint8_t ch = selected[i];
        if (!dual_band && ch > 14) {
            continue;
        }
        dynamic_channels[dynamic_channels_count++] = ch;
    }
}

const uint8_t* get_scan_channels(void) {
    init_country_channels();
    return dynamic_channels;
}

size_t get_scan_channels_size(void) {
    init_country_channels();
    return dynamic_channels_count;
}


static esp_err_t update_scan_results_json(cJSON *root) {
    if (!root) return ESP_ERR_INVALID_ARG;
    
    // Free existing buffer
    if (scan_results_json) {
        free(scan_results_json);
        scan_results_json = NULL;
    }
    
    // Create new JSON string
    size_t json_len;
    char *new_json = json_print_sized(root, scan_results_size, &json_len);
    if (!new_json) {
        ESP_LOGE(TAG, "Failed to create scan results JSON");
        return ESP_ERR_NO_MEM;
    }
    
    scan_results_json = new_json;
    return ESP_OK;
}

void wifi_scan_cleanup(void) {
    if (scan_results_json) {
        free(scan_results_json);
        scan_results_json = NULL;
    }
    
    // Clean up station JSON buffer
    wifi_scan_cleanup_station_json();
}

// Initialize memory for wifi scan
void wifi_scan_init_memory(void) {
    scan_results_json = NULL;
    scan_results_size = MAX_JSON_SIZE;
    ESP_LOGI(TAG, "WiFi scan memory initialized");
}

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

static bool detect_wps(const uint8_t *bssid) {
    for (int i = 0; i < s_wps_ap_count; i++) {
        if (memcmp(s_wps_aps[i].bssid, bssid, 6) == 0) {
            return s_wps_aps[i].wps_enabled;
        }
    }
    return false;
}

// Update WPS status for an AP
static void update_wps_status(const uint8_t *bssid, bool wps_enabled) {
    // Check if already exists
    for (int i = 0; i < s_wps_ap_count; i++) {
        if (memcmp(s_wps_aps[i].bssid, bssid, 6) == 0) {
            if (wps_enabled && !s_wps_aps[i].wps_enabled) {
                ESP_LOGI(TAG, "WPS detected on %02X:%02X:%02X:%02X:%02X:%02X",
                         bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
            }
            s_wps_aps[i].wps_enabled = wps_enabled;
            return;
        }
    }
    if (s_wps_ap_count < MAX_WPS_APS) {
        memcpy(s_wps_aps[s_wps_ap_count].bssid, bssid, 6);
        s_wps_aps[s_wps_ap_count].wps_enabled = wps_enabled;
        if (wps_enabled) {
            ESP_LOGI(TAG, "WPS detected on %02X:%02X:%02X:%02X:%02X:%02X",
                     bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
        }
        s_wps_ap_count++;
    }
}

// Parse beacon/probe response for WPS Information Element
static bool parse_wps_ie(const uint8_t *frame_body, int body_len) {
    const uint8_t *ptr = frame_body;
    const uint8_t *end = frame_body + body_len;

    // WPS uses vendor-specific IE (0xDD) with OUI 0x0050F204 and type 0x04
    while (ptr + 2 <= end) {
        uint8_t ie_id = ptr[0];
        uint8_t ie_len = ptr[1];

        if (ptr + 2 + ie_len > end) break;

        // Check for vendor-specific IE
        if (ie_id == 0xDD && ie_len >= 4) {
            // Check WPS OUI: 0x0050F204
            if (ptr[2] == 0x00 && ptr[3] == 0x50 && ptr[4] == 0xF2 && ptr[5] == 0x04) {
                return true;  // WPS detected
            }
        }

        ptr += 2 + ie_len;
    }

    return false;
}

uint32_t get_channel_dwell_time(uint8_t channel, bool is_background_scan) {
    uint32_t base_ap_dwell = is_background_scan ? 80 : 120;
    uint32_t base_station_dwell = is_background_scan ? 200 : 500;

#if CONFIG_IDF_TARGET_ESP32C5
    // 25% more dwell time for extra channels
    base_ap_dwell = (base_ap_dwell * 5) / 4;
    base_station_dwell = (base_station_dwell * 5) / 4;
#endif
    
    // Only apply weighting after we have enough data
    if (channel_scan_counts[channel] >= MIN_SCANS_FOR_LEARNING) {
        // Calculate discovery rate (devices per scan)
        float discovery_rate = channel_scan_counts[channel] > 0 ? 
            (float)channel_discovery_counts[channel] / channel_scan_counts[channel] : 0;
        
        // Calculate weight multiplier based on discovery rate
        float weight_multiplier = MIN_CHANNEL_WEIGHT + (discovery_rate * (MAX_CHANNEL_WEIGHT - MIN_CHANNEL_WEIGHT));
        if (weight_multiplier > MAX_CHANNEL_WEIGHT) weight_multiplier = MAX_CHANNEL_WEIGHT;
        if (weight_multiplier < MIN_CHANNEL_WEIGHT) weight_multiplier = MIN_CHANNEL_WEIGHT;
        
        // Apply weighting
        base_ap_dwell = (uint32_t)(base_ap_dwell * weight_multiplier);
        base_station_dwell = (uint32_t)(base_station_dwell * weight_multiplier);
        
        // Ensure reasonable bounds
        if (base_ap_dwell < 60) base_ap_dwell = 60;
        if (base_ap_dwell > 240) base_ap_dwell = 240;
        if (base_station_dwell < 150) base_station_dwell = 150;
        if (base_station_dwell > 1000) base_station_dwell = 1000;
        
        ESP_LOGD(TAG, "Channel %d: discovery_rate=%.2f, multiplier=%.2f, dwell=%d ms", 
                 channel, discovery_rate, weight_multiplier, base_ap_dwell);
    }
    
    return base_ap_dwell;
}

void update_channel_activity(uint8_t channel, uint32_t devices_found, int8_t *rssi_values, uint32_t rssi_count) {
    if (channel < 1 || channel > 13) return;
    
    // Apply RSSI cutoff threshold - only count devices within useful range
    uint32_t valid_devices = 0;
    if (rssi_values && rssi_count > 0) {
        for (uint32_t i = 0; i < rssi_count && i < devices_found; i++) {
            if (rssi_values[i] >= RSSI_CUTOFF_THRESHOLD) {
                valid_devices++;
            }
        }
    } else {
        // Fallback if no RSSI data provided
        valid_devices = devices_found;
    }
    
    // Update discovery counts with filtered results
    channel_discovery_counts[channel] += valid_devices;
    
    ESP_LOGD(TAG, "Channel %d: %d valid devices (RSSI>=%d), %d total filtered, %d discoveries in %d scans", 
             channel, valid_devices, RSSI_CUTOFF_THRESHOLD, devices_found, 
             channel_discovery_counts[channel], channel_scan_counts[channel]);
}

static void maintain_channel_learning(void) {
    uint32_t now = get_current_timestamp();
    
    // Reset counters if they get too old (every 24 hours)
    if (now - last_channel_update > 86400) {
        // Decay the discovery counts slightly to adapt to changes
        for (int ch = 1; ch <= 13; ch++) {
            channel_discovery_counts[ch] = (uint32_t)(channel_discovery_counts[ch] * 0.8);
            channel_scan_counts[ch] = (uint32_t)(channel_scan_counts[ch] * 0.8);
        }
        last_channel_update = now;
        
        ESP_LOGI(TAG, "Channel learning data decayed for adaptation");
    }
}

static uint32_t last_scan_complete_time = 0;

void wifi_scan() {
    if(!scan_mutex) {
        scan_mutex = xSemaphoreCreateMutex();
    }
    if(!stations_mutex) {
        stations_mutex = xSemaphoreCreateMutex();
    }

    uint32_t scan_start_time = (uint32_t)(esp_timer_get_time() / 1000); // milliseconds

    // Prevent rapid-fire scans (debounce within 30 seconds)
    if (last_scan_complete_time > 0) {
        uint32_t time_since_last = scan_start_time - last_scan_complete_time;
        if (time_since_last < 30000) {
            ESP_LOGW(TAG, "=== SCAN BLOCKED === Too soon after last scan (only %lu ms ago), ignoring request",
                     (unsigned long)time_since_last);
            return;
        }
    }

    ESP_LOGI(TAG, "=== SCAN START === at %lu ms, setting scan_in_progress=true", (unsigned long)scan_start_time);
    scan_in_progress = true;
    
    // Run maintenance to adapt to changing conditions
    maintain_channel_learning();
    
    const uint8_t* channels = get_scan_channels();
    size_t channels_size = get_scan_channels_size();
    
    // Calculate estimate using adaptive timing
    uint32_t total_estimate_ms = 0;
    for (size_t i = 0; i < channels_size; i++) {
        uint8_t channel = channels[i];
        uint32_t ap_dwell = get_channel_dwell_time(channel, false);
        uint32_t station_dwell = (uint32_t)(ap_dwell * 4.17); // Maintain 500/120 ratio
        total_estimate_ms += ap_dwell + station_dwell;
    }
    
    ESP_LOGI(TAG, "Starting smart scan - estimated %.1f seconds (%d channels)", 
            total_estimate_ms / 1000.0f, channels_size);

    cJSON *root = cJSON_CreateObject();
    cJSON *rows = cJSON_AddArrayToObject(root, "rows");
    
    wifi_scan_config_t scan_config = {
        .ssid = NULL,       
        .bssid = NULL,    
        .channel = 0,        // 0 means scan all channels in the list
        .show_hidden = true  
    };

    for (size_t i = 0; i < channels_size; i++) {
        uint8_t channel = channels[i];
        
        // Get smart dwell time for this channel
        uint32_t ap_dwell = get_channel_dwell_time(channel, false);
        
        // Track that we're scanning this channel
        channel_scan_counts[channel]++;
        
        scan_config.channel = channel;
        esp_err_t err = esp_wifi_scan_start(&scan_config, true);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "Wi-Fi scan failed on channel %d: %s", channel, esp_err_to_name(err));
            cJSON_AddItemToArray(rows, cJSON_CreateObject());
            continue;
        }
        uint16_t ap_count = 0;
        esp_wifi_scan_get_ap_num(&ap_count);

        if (ap_count == 0) {
            // Update channel activity with zero results
            update_channel_activity(channel, 0, NULL, 0);
            continue;  // Skip silently if no APs
        }
        
        ESP_LOGI(TAG, "Found %d Wi-Fi networks on channel %d (dwell: %d ms)", ap_count, channel, ap_dwell);
        wifi_ap_record_t *ap_records = (wifi_ap_record_t *)malloc(sizeof(wifi_ap_record_t) * ap_count);
        if (!ap_records) {
            ESP_LOGE(TAG, "Memory allocation failed!");
            // Update channel activity with count but no RSSI data
            update_channel_activity(channel, ap_count, NULL, 0);
            cJSON_AddItemToArray(rows, cJSON_CreateObject());
            continue;
        }
        err = esp_wifi_scan_get_ap_records(&ap_count, ap_records);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "Failed to get scan results on channel %d: %s", channel, esp_err_to_name(err));
            free(ap_records);
            // Update channel activity with count but no RSSI data
            update_channel_activity(channel, ap_count, NULL, 0);
            cJSON_AddItemToArray(rows, cJSON_CreateObject());
            continue;
        }
        
        // Collect RSSI values for filtering
        int8_t *rssi_values = malloc(sizeof(int8_t) * ap_count);
        if (rssi_values) {
            for (int j = 0; j < ap_count; j++) {
                rssi_values[j] = ap_records[j].rssi;
            }
        }
        
        // Update channel activity with RSSI filtering
        update_channel_activity(channel, ap_count, rssi_values, ap_count);

        if (rssi_values) {
            free(rssi_values);
        }

        uint32_t now_sec = get_current_timestamp();
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
            
            char vendor[64] = "Unknown";
            ouis_lookup_vendor(ap_records[j].bssid, vendor, sizeof(vendor));
            cJSON_AddStringToObject(ap_entry, "Vendor", vendor);

            // Add WPS status
            bool wps = detect_wps(ap_records[j].bssid);
            cJSON_AddBoolToObject(ap_entry, "wps", wps);

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

    // SAVE AP-ONLY RESULTS FIRST for fast UX feedback
    xSemaphoreTake(scan_mutex, portMAX_DELAY);
    esp_err_t ap_err = update_scan_results_json(root);
    if (ap_err == ESP_OK) {
        scan_results_timestamp = get_current_timestamp();
        new_results_available = true;
        ESP_LOGI(TAG, "AP scan complete - initial results available (%d APs)", cJSON_GetArraySize(rows));
    }
    scan_in_progress = false;
    station_scan_background = true;
    xSemaphoreGive(scan_mutex);

    // NOW DO STATION SCAN (runs while UI can already show AP results)
    wifi_scan_stations();
    const char *station_json = wifi_scan_get_station_results();
    ESP_LOGI(TAG, "Station scan complete. Station JSON: %s", station_json);
    cJSON *station_root = cJSON_Parse(station_json);
    if (!station_root) {
        ESP_LOGE(TAG, "Failed to parse station JSON");
        station_root = cJSON_CreateObject();
    } else {
        ESP_LOGI(TAG, "Station JSON parsed successfully, merging with AP data");
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
                        cJSON *ap_mac_item = cJSON_GetObjectItem(station_ap_entry, "bssid");
                        if (ap_mac_item) {
                            cJSON *scan_ap_entry = NULL;
                            cJSON_ArrayForEach(scan_ap_entry, rows) {
                                cJSON *scan_mac_item = cJSON_GetObjectItem(scan_ap_entry, "MAC");
                                if (scan_mac_item && scan_mac_item->valuestring && ap_mac_item->valuestring) {
                                    char scan_mac_upper[18];
                                    char ap_mac_upper[18];
                                    strncpy(scan_mac_upper, scan_mac_item->valuestring, sizeof(scan_mac_upper));
                                    scan_mac_upper[sizeof(scan_mac_upper) - 1] = '\0';
                                    strncpy(ap_mac_upper, ap_mac_item->valuestring, sizeof(ap_mac_upper));
                                    ap_mac_upper[sizeof(ap_mac_upper) - 1] = '\0';

                                    for (int m = 0; scan_mac_upper[m]; m++) scan_mac_upper[m] = toupper((unsigned char)scan_mac_upper[m]);
                                    for (int m = 0; ap_mac_upper[m]; m++) ap_mac_upper[m] = toupper((unsigned char)ap_mac_upper[m]);

                                    if (strcmp(scan_mac_upper, ap_mac_upper) != 0) {
                                        continue;
                                    }
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
    ESP_LOGI(TAG, "Merging station data into AP entries...");
    int merge_count = 0;
    cJSON *ap_entry = NULL;
    cJSON_ArrayForEach(ap_entry, rows) {
        cJSON *mac_item = cJSON_GetObjectItem(ap_entry, "MAC");
        if(mac_item) {
            // convert to uppercase for key matching
            char upper_mac[18];
            strncpy(upper_mac, mac_item->valuestring, sizeof(upper_mac));
            upper_mac[sizeof(upper_mac) - 1] = '\0';
            for(int i=0; upper_mac[i]; i++) upper_mac[i] = toupper(upper_mac[i]);
            
            ESP_LOGI(TAG, "Looking for stations for AP: %s", upper_mac);
            cJSON *station_data = cJSON_GetObjectItem(station_root, upper_mac);
            if(station_data) {
                cJSON *stations = cJSON_DetachItemFromObject(station_data, "stations");
                if (stations) {
                    int station_count = cJSON_GetArraySize(stations);
                    ESP_LOGI(TAG, "Found %d stations for AP %s", station_count, upper_mac);
                    cJSON_AddItemToObject(ap_entry, "stations", stations);
                    merge_count++;
                } else {
                    ESP_LOGW(TAG, "No stations array in station_data for %s", upper_mac);
                }
            }
        }
    }
    ESP_LOGI(TAG, "Merged stations for %d APs", merge_count);

    // Update WPS status for all APs now that station scan has detected WPS
    ESP_LOGI(TAG, "Updating WPS status for APs...");
    cJSON_ArrayForEach(ap_entry, rows) {
        cJSON *mac_item = cJSON_GetObjectItem(ap_entry, "MAC");
        if (mac_item && mac_item->valuestring) {
            // Parse MAC address
            uint8_t bssid[6];
            if (sscanf(mac_item->valuestring, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                      &bssid[0], &bssid[1], &bssid[2], &bssid[3], &bssid[4], &bssid[5]) == 6) {
                bool wps = detect_wps(bssid);
                cJSON *wps_item = cJSON_GetObjectItem(ap_entry, "wps");
                if (wps_item) {
                    cJSON_SetBoolValue(wps_item, wps);
                } else {
                    cJSON_AddBoolToObject(ap_entry, "wps", wps);
                }
            }
        }
    }

    // Store results in buffer with mutex protection
    xSemaphoreTake(scan_mutex, portMAX_DELAY);
    scan_was_truncated = false;

    // Use dynamic allocation for JSON
    esp_err_t err = update_scan_results_json(root);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to update scan results JSON");
        scan_was_truncated = true;
        // Set fallback JSON
        if (scan_results_json) {
            free(scan_results_json);
        }
        scan_results_json = strdup("{\"rows\":[]}");
    }

    scan_results_timestamp = get_current_timestamp();
    uint32_t scan_end_time = (uint32_t)(esp_timer_get_time() / 1000); // milliseconds
    uint32_t scan_duration = scan_end_time - scan_start_time;

    new_results_available = true;
    station_scan_background = false;
    last_scan_complete_time = scan_end_time; // Track when scan completed for debouncing
    ESP_LOGI(TAG, "=== SCAN COMPLETE (with stations) === at %lu ms, duration=%lu ms",
             (unsigned long)scan_end_time, (unsigned long)scan_duration);
    xSemaphoreGive(scan_mutex);

    // Check if there's a pending background scan update to apply
    extern scan_record_t pending_background_record;
    if (pending_background_record.header.magic == SCAN_MAGIC) {
        ESP_LOGI(TAG, "Applying pending background scan update");
        wifi_scan_update_ui_cache_from_record(&pending_background_record);
        memset(&pending_background_record, 0, sizeof(scan_record_t));
    }

    // cleanup
    cJSON_Delete(root);
    cJSON_Delete(station_root);

    // Sync deauth detection results to intelligence system
    scan_storage_update_security_events(wifi_scan_get_deauth_count());

    // Send batched deauth webhook alert if frames were detected
    if (wifi_scan_get_deauth_count() > 0) {
        device_lifecycle_generate_batched_deauth_alert(wifi_scan_get_deauth_count(), 30); // Station scans typically ~30 seconds
        // Reset count after sending alert to prevent duplicate notifications
        wifi_scan_reset_deauth_count();
    }

    ESP_LOGI(TAG, "Wi-Fi Scan Completed. Results cached.");
    
    wifi_scan_cleanup_station_json();
    
    // Log heap status after cleanup
    uint32_t free_heap = esp_get_free_heap_size();
    ESP_LOGI(TAG, "Heap after scan cleanup: %lu bytes", (unsigned long)free_heap);
}

bool wifi_scan_start_async(void) {
    if(!scan_mutex) {
        scan_mutex = xSemaphoreCreateMutex();
    }

    if(!stations_mutex) {
        stations_mutex = xSemaphoreCreateMutex();
    }

    if(!scan_mutex || !stations_mutex) {
        ESP_LOGE(TAG, "Failed to create scan mutexes");
        return false;
    }

    xSemaphoreTake(scan_mutex, portMAX_DELAY);
    if(scan_in_progress || s_wifi_scan_task_handle != NULL) {
        xSemaphoreGive(scan_mutex);
        ESP_LOGW(TAG, "Scan already running; ignoring async start");
        return false;
    }
    scan_in_progress = true;
    xSemaphoreGive(scan_mutex);

    BaseType_t rc = xTaskCreate(wifi_scan_task, "wifi_scan_task", 8192, NULL, 5, &s_wifi_scan_task_handle);
    if(rc != pdPASS) {
        ESP_LOGE(TAG, "Failed to create wifi_scan_task: %d", rc);
        xSemaphoreTake(scan_mutex, portMAX_DELAY);
        scan_in_progress = false;
        xSemaphoreGive(scan_mutex);
        s_wifi_scan_task_handle = NULL;
        return false;
    }

    return true;
}

static void wifi_scan_task(void *arg) {
    ESP_LOGI(TAG, "Wi-Fi scan task started");
    wifi_scan();
    s_wifi_scan_task_handle = NULL;
    ESP_LOGI(TAG, "Wi-Fi scan task finished");
    vTaskDelete(NULL);
}

// update ui cache from background scan record
void wifi_scan_update_ui_cache_from_record(const scan_record_t *record) {
    if (!record) return;
    if (!scan_mutex) scan_mutex = xSemaphoreCreateMutex();
    
    // Check heap before allocating - UI cache is optional, save memory for critical operations
    uint32_t free_heap = esp_get_free_heap_size();
    if (free_heap < 10000) {
        ESP_LOGW(TAG, "Skipping UI cache update - low heap (%lu bytes)", (unsigned long)free_heap);
        return;
    }
    
    cJSON *root = cJSON_CreateObject();
    cJSON *rows = cJSON_AddArrayToObject(root, "rows");
    
    uint32_t now_sec = record->header.time_valid ? record->header.epoch_ts : record->header.uptime_sec;
    
    // Determine safe AP limit based on heap
    // Each AP entry in JSON DOM takes approx 1KB of heap
    int max_aps = record->header.ap_count;
    if (free_heap < 20000) {
        max_aps = 10; // Restrict to top 10 if heap is low < 20KB
        ESP_LOGW(TAG, "Low heap during UI update (%lu), limiting to %d/%d APs", (unsigned long)free_heap, max_aps, record->header.ap_count);
    } else if (free_heap < 30000) {
        max_aps = 20; // Restrict to top 20 if heap < 30KB
    }
    
    for (int i = 0; i < record->header.ap_count && i < max_aps; i++) {
        const stored_ap_t *ap = &record->aps[i];
        
        cJSON *ap_entry = cJSON_CreateObject();
        cJSON_AddStringToObject(ap_entry, "SSID", (char*)ap->ssid);
        cJSON_AddStringToObject(ap_entry, "MAC", mac_to_str(ap->bssid));
        cJSON_AddNumberToObject(ap_entry, "Channel", ap->channel);
        cJSON_AddNumberToObject(ap_entry, "RSSI", ap->rssi);
        cJSON_AddStringToObject(ap_entry, "Security", get_security_type(ap->auth_mode));
        cJSON_AddStringToObject(ap_entry, "Band", get_band(ap->channel));
        cJSON_AddNumberToObject(ap_entry, "last_seen", now_sec);
        cJSON_AddBoolToObject(ap_entry, "hidden", ap->hidden);
        
        // Skip vendor lookup if memory is very low within the loop
        if (esp_get_free_heap_size() > 8000) {
            char vendor[64] = "Unknown";
            ouis_lookup_vendor(ap->bssid, vendor, sizeof(vendor));
            cJSON_AddStringToObject(ap_entry, "Vendor", vendor);
        } else {
            cJSON_AddStringToObject(ap_entry, "Vendor", "");
        }
        
        // add stations if present - limit stations if low memory
        if (ap->station_count > 0 && esp_get_free_heap_size() > 10000) {
            cJSON *stations_array = cJSON_AddArrayToObject(ap_entry, "stations");
            for (int s = 0; s < ap->station_count; s++) {
                const stored_station_t *sta = &ap->stations[s];
                cJSON *sta_obj = cJSON_CreateObject();
                cJSON_AddStringToObject(sta_obj, "mac", mac_to_str(sta->mac));
                cJSON_AddNumberToObject(sta_obj, "rssi", sta->rssi);
                cJSON_AddNumberToObject(sta_obj, "last_seen", now_sec);
                
                if (esp_get_free_heap_size() > 8000) {
                    char sta_vendor[64] = "Unknown";
                    ouis_lookup_vendor(sta->mac, sta_vendor, sizeof(sta_vendor));
                    cJSON_AddStringToObject(sta_obj, "vendor", sta_vendor);
                }
                
                cJSON_AddItemToArray(stations_array, sta_obj);
            }
        }
        
        cJSON_AddItemToArray(rows, ap_entry);
    }
    
    // update cache with mutex protection
    xSemaphoreTake(scan_mutex, portMAX_DELAY);

    // Don't overwrite if manual scan is in progress, but queue update for after scan completes
    if (scan_in_progress) {
        ESP_LOGW(TAG, "Manual scan in progress, queuing background scan cache update");
        xSemaphoreGive(scan_mutex);
        if (root) cJSON_Delete(root);
        
        // Store record for later update when scan completes
        extern scan_record_t pending_background_record;
        memcpy(&pending_background_record, record, sizeof(scan_record_t));
        return;
    }

    scan_was_truncated = false;
    
    esp_err_t err = update_scan_results_json(root);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to update scan results JSON from background scan");
        scan_was_truncated = true;
        // Set fallback JSON
        if (scan_results_json) {
            free(scan_results_json);
        }
        scan_results_json = strdup("{\"rows\":[]}");
    }
    
    scan_results_timestamp = now_sec;
    new_results_available = true;
    xSemaphoreGive(scan_mutex);
    
    if (root) cJSON_Delete(root);
    ESP_LOGI(TAG, "UI cache updated from background scan (%u APs, %u stations)", 
             record->header.ap_count, record->header.total_stations);
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

bool wifi_scan_is_in_progress() {
    if(!scan_mutex) return false;

    xSemaphoreTake(scan_mutex, portMAX_DELAY);
    bool in_progress = scan_in_progress;
    xSemaphoreGive(scan_mutex);
    return in_progress;
}

bool wifi_scan_station_scan_running() {
    return station_scan_background;
}

uint32_t wifi_scan_get_results_timestamp() {
    if(!scan_mutex) return 0;

    xSemaphoreTake(scan_mutex, portMAX_DELAY);
    uint32_t ts = scan_results_timestamp;
    xSemaphoreGive(scan_mutex);
    return ts;
}

bool wifi_scan_was_truncated() {
    if(!scan_mutex) return false;

    xSemaphoreTake(scan_mutex, portMAX_DELAY);
    bool truncated = scan_was_truncated;
    xSemaphoreGive(scan_mutex);
    return truncated;
}

bool wifi_scan_has_new_results() {
    if(!scan_mutex) return false;
    
    xSemaphoreTake(scan_mutex, portMAX_DELAY);
    bool has_new = new_results_available;
    xSemaphoreGive(scan_mutex);
    return has_new;
}

static void parse_probe_request_fingerprint(const uint8_t *frame_body, int frame_len, station_info_t *station);
static void extract_device_capabilities(const uint8_t *ie_data, uint8_t ie_len, char *fingerprint, size_t fp_len);
static const char* get_vendor_from_oui(const uint8_t *mac);
static bool fingerprints_match(const char *fp1, const char *fp2, int channel1, int channel2);
static bool try_group_with_existing_station(station_info_t *new_station);

static uint32_t get_current_timestamp(void) {
    if (pwnpower_time_is_synced()) {
        time_t now;
        time(&now);
        return (uint32_t)now;
    }
    return (uint32_t)(esp_timer_get_time() / 1000000ULL);
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
    
    if (frame_type == 0) {
        s_probe_request_count++;
        if (frame_subtype == 0x04 && s_probe_request_count % 50 == 0) {
            ESP_LOGI(TAG, "PROBE_DEBUG: Probe request detected! Total probe requests seen: %lu", (unsigned long)s_probe_request_count);
        } else if (s_probe_request_count % 200 == 0) {
            ESP_LOGI(TAG, "PROBE_DEBUG: Management frames seen: %lu, subtype: 0x%02X", (unsigned long)s_probe_request_count, frame_subtype);
        }
    }
    
    if (frame_type == 0 && (frame_subtype == 0x0C || frame_subtype == 0x0A)) {
        s_deauth_count++;
        s_deauth_last_seen = get_current_timestamp();
        
        ESP_LOGI(TAG, "Deauth frame detected, total: %lu", (unsigned long)s_deauth_count);
        
        return;
    }

    // Parse beacons (0x08) and probe responses (0x0B) for WPS
    if (frame_type == 0 && (frame_subtype == 0x08 || frame_subtype == 0x0B)) {
        uint8_t *bssid = payload + 16;
        uint8_t *frame_body = payload + 24;

        // Skip fixed parameters (timestamp: 8, beacon interval: 2, capabilities: 2)
        int fixed_params_len = 12;
        if (rx_ctrl->sig_len > 24 + fixed_params_len) {
            bool wps_found = parse_wps_ie(frame_body + fixed_params_len,
                                          rx_ctrl->sig_len - 24 - fixed_params_len);
            update_wps_status(bssid, wps_found);
        }
    }

    // Monitor for probe responses (0x0B) that might reveal hidden SSIDs
    if (frame_type == 0 && frame_subtype == 0x0B) {
        if (rx_ctrl->sig_len < 36) return; // Need at least header + fixed params
        uint8_t *bssid = payload + 16;
        uint8_t *frame_body = payload + 24;
        uint8_t *frame_end = payload + rx_ctrl->sig_len;
        
        // Skip fixed parameters (timestamp: 8, beacon interval: 2, capabilities: 2)
        frame_body += 12;
        
        // Parse parameters - look for SSID parameter (ID 0x00)
        while (frame_body + 2 <= frame_end && frame_body[0] != 0x00 && frame_body[0] != 0xFF) {
            uint8_t param_len = frame_body[1];
            if (frame_body + 2 + param_len > frame_end) break;
            frame_body += 2 + param_len;
        }
        
        if (frame_body + 2 <= frame_end && frame_body[0] == 0x00) {
            uint8_t ssid_len = frame_body[1];
            if (ssid_len > 0 && ssid_len < 33 && frame_body + 2 + ssid_len <= frame_end) {
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
        if (rx_ctrl->sig_len < 26) return; // Need at least header + capability info
        uint8_t *bssid = payload + 16;
        uint8_t *frame_body = payload + 24;
        uint8_t *frame_end = payload + rx_ctrl->sig_len;
        
        // Skip fixed parameters
        frame_body += 2; // Capability info
        
        // Parse parameters - look for SSID parameter (ID 0x00) with proper bounds checking
        while (frame_body + 2 <= frame_end && frame_body[0] != 0x00 && frame_body[0] != 0xFF) {
            uint8_t param_len = frame_body[1];
            if (frame_body + 2 + param_len > frame_end) break; // Prevent overflow
            frame_body += 2 + param_len;
        }
        
        if (frame_body + 2 <= frame_end && frame_body[0] == 0x00) {
            uint8_t ssid_len = frame_body[1];
            if (ssid_len > 0 && ssid_len < 33 && frame_body + 2 + ssid_len <= frame_end) {
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
    
    // Enhanced probe request fingerprinting for management frames
    if (frame_type == 0 && frame_subtype == 0x04) { // Probe Request
        // Extract source MAC from probe request frame
        uint8_t probe_mac[6];
        memcpy(probe_mac, addr2, 6); // Source address is addr2 in management frames
        
        ESP_LOGD(TAG, "PROBE_FINGERPRINT: Capturing probe request from %02X:%02X:%02X:%02X:%02X:%02X on channel %d, RSSI %d",
                 probe_mac[0], probe_mac[1], probe_mac[2], probe_mac[3], probe_mac[4], probe_mac[5],
                 rx_ctrl->channel, rx_ctrl->rssi);
        
        // Parse probe request for fingerprinting
        uint8_t *frame_body = payload + 24;
        int body_len = rx_ctrl->sig_len - 24;
        if (body_len > 0) {
            station_info_t temp_station = {0};
            memcpy(temp_station.station_mac, probe_mac, 6);
            temp_station.channel = rx_ctrl->channel;
            temp_station.rssi = rx_ctrl->rssi;
            temp_station.last_seen = get_current_timestamp();
            
            parse_probe_request_fingerprint(frame_body, body_len, &temp_station);
            
            ESP_LOGD(TAG, "PROBE_FINGERPRINT: Vendor: %s, Fingerprint: %s",
                     temp_station.device_vendor, temp_station.device_fingerprint);
                     
            // Update existing station record or create new one (with timeout to avoid blocking callback)
            if (xSemaphoreTake(stations_mutex, pdMS_TO_TICKS(10)) != pdTRUE) {
                // Mutex busy, skip this update to avoid blocking the sniffer callback
                return;
            }
            bool station_exists = false;
            for(int i=0; i<stations_count; i++) {
                if(memcmp(stations[i].station_mac, probe_mac, 6) == 0) {
                    // Update fingerprinting data
                    station_exists = true;
                    stations[i].probe_count++;
                    stations[i].last_seen = temp_station.last_seen;
                    stations[i].rssi = temp_station.rssi;
                    if (temp_station.has_fingerprint) {
                        stations[i].has_fingerprint = true;
                        if (strlen(temp_station.device_vendor) > 0) {
                            strncpy(stations[i].device_vendor, temp_station.device_vendor, sizeof(stations[i].device_vendor) - 1);
                            stations[i].device_vendor[sizeof(stations[i].device_vendor) - 1] = '\0';
                        }
                        if (strlen(temp_station.device_fingerprint) > 0) {
                            strncpy(stations[i].device_fingerprint, temp_station.device_fingerprint, sizeof(stations[i].device_fingerprint) - 1);
                            stations[i].device_fingerprint[sizeof(stations[i].device_fingerprint) - 1] = '\0';
                        }
                    }
                    ESP_LOGD(TAG, "PROBE_FINGERPRINT: Updated existing station %s, probe count: %d", 
                             mac_to_str(probe_mac), stations[i].probe_count);
                    break;
                }
            }
            
            // Create new station record if not found and we have space
            if (!station_exists && stations_count < MAX_STATIONS) {
                // For probe requests, try to find a known AP on the same channel
                bool ap_found = false;
                for(int k=0; k<known_ap_count; k++) {
                    if(known_ap_channels[k] == rx_ctrl->channel) {
                        memcpy(temp_station.ap_bssid, known_ap_bssids[k], 6);
                        ap_found = true;
                        break;
                    }
                }
                
                // If no known AP on this channel, use broadcast
                if (!ap_found) {
                    uint8_t broadcast_bssid[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
                    memcpy(temp_station.ap_bssid, broadcast_bssid, 6);
                }
                
                temp_station.probe_count = 1;
                temp_station.last_seen = get_current_timestamp();
                temp_station.is_grouped = false;
                temp_station.grouped_mac_count = 0;
                
                // Create station if we have any useful fingerprint data
                if (strlen(temp_station.device_fingerprint) > 4 || strlen(temp_station.device_vendor) > 0) {
                    temp_station.has_fingerprint = true;
                    
                    // Try to group with existing station if we have fingerprint
                    if (try_group_with_existing_station(&temp_station)) {
                        ESP_LOGI(TAG, "PROBE_FINGERPRINT: Grouped station %s with existing device based on fingerprint match",
                                 mac_to_str(probe_mac));
                    } else {
                        memcpy(&stations[stations_count], &temp_station, sizeof(station_info_t));
                        stations[stations_count].is_grouped = false;
                        stations[stations_count].grouped_mac_count = 0;
                        ESP_LOGD(TAG, "PROBE_FINGERPRINT: Created new station from probe - %s, Vendor: %s, Channel: %d, RSSI: %d",
                                 mac_to_str(temp_station.station_mac), temp_station.device_vendor, temp_station.channel, temp_station.rssi);
                        stations_count++;
                    }
                } else {
                    ESP_LOGD(TAG, "PROBE_FINGERPRINT: Skipping station creation - insufficient fingerprint data");
                }
            } else if (!station_exists) {
                ESP_LOGW(TAG, "PROBE_FINGERPRINT: Station array full, cannot add new station %s", mac_to_str(probe_mac));
            }
            xSemaphoreGive(stations_mutex);
        }
    }
    
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
    station_info_t candidate = { 
        .channel = rx_ctrl->channel, 
        .rssi = rx_ctrl->rssi,
        .probe_count = 1,
        .last_seen = get_current_timestamp(),
        .has_fingerprint = false
    };
    memcpy(candidate.station_mac, station_mac, 6);
    memcpy(candidate.ap_bssid, ap_bssid, 6);
    
    // Skip vendor lookup during sniffer processing for performance
    // Vendor will be filled later during fingerprint processing
    candidate.device_vendor[0] = '\0';
    
    // Acquire mutex with timeout to avoid blocking the sniffer callback
    if (xSemaphoreTake(stations_mutex, pdMS_TO_TICKS(10)) != pdTRUE) {
        // Mutex busy, skip this update
        return;
    }
    bool exists = false;
    for(int i=0; i<stations_count; i++) {
        if(memcmp(stations[i].station_mac, candidate.station_mac, 6) == 0 && memcmp(stations[i].ap_bssid, candidate.ap_bssid, 6) == 0) { 
            exists = true;
            stations[i].probe_count++;
            stations[i].last_seen = candidate.last_seen;
            stations[i].rssi = candidate.rssi;
            break;
        }
    }
    if(!exists && stations_count < MAX_STATIONS) { 
        stations[stations_count++] = candidate;
        ESP_LOGD(TAG, "PROBE_FINGERPRINT: New station added - %s, Vendor: %s, Channel: %d, RSSI: %d",
                 mac_to_str(candidate.station_mac), candidate.device_vendor, candidate.channel, candidate.rssi);
    }
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
    ESP_LOGI(TAG, "PROBE_DEBUG: Starting station scan, reset probe counter to 0");

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

    uint32_t scan_time_ms = 4000;
    uint32_t dwell_time_ms = 200;
    int ch_count = known_channel_count > 0 ? known_channel_count : (int)get_scan_channels_size();
    const uint8_t* channels = get_scan_channels();
    uint32_t iterations = scan_time_ms / (dwell_time_ms * (uint32_t)ch_count);
    if (iterations == 0) iterations = 1;
    if (iterations > 8) iterations = 8;
    for (uint32_t iter = 0; iter < iterations; iter++) {
        for (int i = 0; i < ch_count; i++) {
            uint8_t ch = (known_channel_count > 0) ? known_ap_channels[i] : channels[i];
            esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
            vTaskDelay(pdMS_TO_TICKS(dwell_time_ms));
        }
    }

    esp_wifi_set_promiscuous(false);
    
    ESP_LOGI(TAG, "PROBE_DEBUG: Station scan completed, total probe requests processed: %lu", (unsigned long)s_probe_request_count);
    
    probe_hidden_aps_internal();
    
    // restore original mode and reconnect if needed
    if(original_mode != WIFI_MODE_STA) {
        ESP_LOGI(TAG, "Restoring original mode (APSTA)");
        esp_wifi_set_mode(original_mode);
        vTaskDelay(pdMS_TO_TICKS(500));
    }
    
    // Keep station_scan_active=true during reconnection to prevent
    // the disconnect handler from interfering with our reconnect attempt
    if(was_sta_connected) {
        ESP_LOGI(TAG, "Reconnecting STA after station scan");
        
        // Give WiFi stack time to fully restore mode
        vTaskDelay(pdMS_TO_TICKS(300));
        
        esp_wifi_connect();
        
        // Wait for connection to fully stabilize (including DHCP)
        // This prevents the disconnect handler from racing with us
        // esp_wifi_sta_get_ap_info only checks WiFi association, not DHCP
        // We wait up to 10 seconds for stability
        bool connected = false;
        for (int wait = 0; wait < 100; wait++) {  // 10 seconds max
            vTaskDelay(pdMS_TO_TICKS(100));
            
            wifi_ap_record_t ap_check;
            esp_err_t ap_err = esp_wifi_sta_get_ap_info(&ap_check);
            if (ap_err == ESP_OK) {
                if (!connected) {
                    ESP_LOGI(TAG, "STA associated after station scan, waiting for DHCP...");
                    connected = true;
                }
                // Continue waiting a bit more for DHCP/stability
                // The IP event will reset retry counters
                if (wait > 30) {  // After 3s of being associated, assume stable enough
                    ESP_LOGI(TAG, "STA connection stabilized after station scan");
                    break;
                }
            } else {
                connected = false;  // Re-check if we need to reconnect
            }
        }
        
        if (!connected) {
            ESP_LOGW(TAG, "STA reconnection after station scan timed out - disconnect handler will retry");
        } else {
            // Explicitly force DHCP client restart to ensure IP assignment
            // This fixes an issue where the device reconnects but fails to get an IP address
            esp_netif_t *netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
            if (netif) {
                ESP_LOGI(TAG, "Explicitly starting DHCP client after scan reconnect (netif=%p)", netif);
                esp_netif_dhcpc_stop(netif); // Ensure clean state
                esp_netif_dhcpc_start(netif);
            } else {
                ESP_LOGE(TAG, "Failed to get WIFI_STA_DEF netif handle - cannot restart DHCP");
            }
        }
    }
    
    // Now safe to clear - either connected or disconnect handler will take over
    station_scan_active = false;
    ESP_LOGI(TAG, "Station scan complete, cleared scan_active flag");
}

const char* wifi_scan_get_station_results() {
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
        cJSON_AddNumberToObject(station, "last_seen", stations[i].last_seen);
        cJSON_AddNumberToObject(station, "probe_count", stations[i].probe_count);
        
        // Add fingerprinting data
        if (stations[i].has_fingerprint) {
            cJSON_AddBoolToObject(station, "has_fingerprint", true);
            if (strlen(stations[i].device_vendor) > 0) {
                cJSON_AddStringToObject(station, "device_vendor", stations[i].device_vendor);
            } else {
                cJSON_AddStringToObject(station, "device_vendor", "Unknown");
            }
            if (strlen(stations[i].device_fingerprint) > 0) {
                cJSON_AddStringToObject(station, "device_fingerprint", stations[i].device_fingerprint);
            }
        } else {
            cJSON_AddBoolToObject(station, "has_fingerprint", false);
            // Fallback to basic OUI lookup
            char sta_vendor[64] = "Unknown";
            ouis_lookup_vendor(stations[i].station_mac, sta_vendor, sizeof(sta_vendor));
            cJSON_AddStringToObject(station, "device_vendor", sta_vendor);
        }
        
        // Add grouped MAC addresses if this device has multiple MACs
        if (stations[i].is_grouped && stations[i].grouped_mac_count > 0) {
            cJSON *grouped_macs_array = cJSON_AddArrayToObject(station, "grouped_macs");
            for (int g = 0; g < stations[i].grouped_mac_count && g < 5; g++) {
                cJSON_AddItemToArray(grouped_macs_array, cJSON_CreateString(mac_to_str(stations[i].grouped_macs[g])));
            }
            cJSON_AddNumberToObject(station, "grouped_count", stations[i].grouped_mac_count + 1);
        }
        
        cJSON_AddItemToArray(cJSON_GetObjectItem(ap_entry, "stations"), station);
    }
    xSemaphoreGive(stations_mutex);
    
    // Use dynamic allocation for JSON
    char *json = json_create_string(root);
    cJSON_Delete(root);
    
    if (!json) {
        ESP_LOGE(TAG, "Failed to create station results JSON");
        return "{}";
    }
    
    // Store in global buffer for compatibility (caller expects const char*)
    if (station_json_buffer) {
        free(station_json_buffer);
    }
    station_json_buffer = json;
    
    return station_json_buffer;
}

void wifi_scan_cleanup_station_json(void) {
    if (station_json_buffer) {
        free(station_json_buffer);
        station_json_buffer = NULL;
    }
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

void wifi_scan_increment_deauth_count(void) {
    s_deauth_count++;
    s_deauth_last_seen = get_current_timestamp();
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
    s_hidden_aps[s_hidden_ap_idx].first_seen = get_current_timestamp();
    s_hidden_aps[s_hidden_ap_idx].probe_attempts = 0;
    s_hidden_aps[s_hidden_ap_idx].revealed = false;
    s_hidden_ap_idx++;
}

const char* wifi_scan_get_security_stats_json(void) {
    static char buf[512];
    uint32_t now = get_current_timestamp();
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
    
    // Monitor for 5 seconds to catch client activity
    vTaskDelay(pdMS_TO_TICKS(5000));
    
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

static const char* get_vendor_from_oui(const uint8_t *mac) {
    static char vendor_buffer[64];
    if (ouis_lookup_vendor(mac, vendor_buffer, sizeof(vendor_buffer))) {
        return vendor_buffer;
    }
    return "Unknown";
}

static void extract_device_capabilities(const uint8_t *ie_data, uint8_t ie_len, char *fingerprint, size_t fp_len) {
    int pos = 0;
    fingerprint[0] = '\0';
    
    // Parse supported rates (IE 0x01)
    if (ie_data[0] == 0x01 && ie_len >= 1) {
        pos += snprintf(fingerprint + pos, fp_len - pos, "Rates:");
        for (int i = 1; i <= ie_len && i < 9; i++) {
            uint8_t rate = ie_data[i];
            if (rate & 0x80) {
                pos += snprintf(fingerprint + pos, fp_len - pos, "%.1fM ", (rate & 0x7F) / 2.0);
            } else {
                pos += snprintf(fingerprint + pos, fp_len - pos, "%.1fM ", rate / 2.0);
            }
        }
    }
    
    // Parse extended capabilities (IE 0x7F)
    if (ie_data[0] == 0x7F && ie_len >= 1) {
        pos += snprintf(fingerprint + pos, fp_len - pos, "ExtCaps:");
        for (int i = 1; i <= ie_len && i < 9; i++) {
            pos += snprintf(fingerprint + pos, fp_len - pos, "%02X", ie_data[i]);
        }
    }
    
    // Parse VHT capabilities (IE 0xBF) for 802.11ac devices
    if (ie_data[0] == 0xBF && ie_len >= 1) {
        pos += snprintf(fingerprint + pos, fp_len - pos, "VHT:");
        // Extract key VHT capability fields for fingerprinting
        if (ie_len >= 4) {
            uint32_t vht_cap_info = (ie_data[1] << 24) | (ie_data[2] << 16) | (ie_data[3] << 8) | ie_data[4];
            pos += snprintf(fingerprint + pos, fp_len - pos, "%08lX", (unsigned long)vht_cap_info);
        }
        if (ie_len >= 6) {
            pos += snprintf(fingerprint + pos, fp_len - pos, "MCS:%02X%02X", ie_data[5], ie_data[6]);
        }
    }
    
    // Parse HT capabilities (IE 0x45) for 802.11n devices
    if (ie_data[0] == 0x45 && ie_len >= 1) {
        pos += snprintf(fingerprint + pos, fp_len - pos, "HT:");
        if (ie_len >= 2) {
            pos += snprintf(fingerprint + pos, fp_len - pos, "%04X", (ie_data[1] << 8) | ie_data[2]);
        }
    }
    
    ESP_LOGD(TAG, "PROBE_FINGERPRINT: Extracted capabilities - %s", fingerprint);
}

static void parse_probe_request_fingerprint(const uint8_t *frame_body, int frame_len, station_info_t *station) {
    ESP_LOGD(TAG, "PROBE_FINGERPRINT: Parsing probe request, frame length: %d", frame_len);
    
    // Initialize fingerprint
    station->device_fingerprint[0] = '\0';
    station->device_vendor[0] = '\0';
    station->has_fingerprint = false;
    
    int fp_pos = 0;
    fp_pos += snprintf(station->device_fingerprint + fp_pos, sizeof(station->device_fingerprint) - fp_pos, "FP:");
    
    // Parse Information Elements (IEs) in probe request
    int ie_offset = 0;
    
    // Skip SSID IE (0x00) if present
    if (frame_len > 0 && frame_body[0] == 0x00) {
        uint8_t ssid_len = frame_body[1];
        ie_offset += 2 + ssid_len;
        ESP_LOGD(TAG, "PROBE_FINGERPRINT: SSID length: %d", ssid_len);
    }
    
    while (ie_offset + 1 < frame_len) {
        uint8_t ie_id = frame_body[ie_offset];
        uint8_t ie_len = frame_body[ie_offset + 1];
        
        ESP_LOGD(TAG, "PROBE_FINGERPRINT: Found IE 0x%02X, length %d at offset %d", ie_id, ie_len, ie_offset);
        
        if (ie_offset + 2 + ie_len > frame_len) {
            ESP_LOGW(TAG, "PROBE_FINGERPRINT: IE 0x%02X extends beyond frame boundary", ie_id);
            break;
        }
        
        char ie_fingerprint[64] = {0};
        extract_device_capabilities(&frame_body[ie_offset], ie_len + 2, ie_fingerprint, sizeof(ie_fingerprint));
        
        if (strlen(ie_fingerprint) > 0) {
            fp_pos += snprintf(station->device_fingerprint + fp_pos, sizeof(station->device_fingerprint) - fp_pos, "%s ", ie_fingerprint);
        }
        
        if (ie_id == 0xDD && ie_len >= 3) {
            uint8_t vendor_oui[3];
            memcpy(vendor_oui, &frame_body[ie_offset + 2], 3);
            const char* vendor = get_vendor_from_oui(vendor_oui);
            if (vendor && strlen(vendor) > 0) {
                strncpy(station->device_vendor, vendor, sizeof(station->device_vendor) - 1);
                station->device_vendor[sizeof(station->device_vendor) - 1] = '\0';
                fp_pos += snprintf(station->device_fingerprint + fp_pos, sizeof(station->device_fingerprint) - fp_pos, "VENDOR:%s ", vendor);
            }
        }
        
        ie_offset += 2 + ie_len;
        
        // Prevent buffer overflow
        if (fp_pos >= sizeof(station->device_fingerprint) - 20) {
            break;
        }
    }
    
    // Get vendor from MAC address OUI as fallback
    if (strlen(station->device_vendor) == 0) {
        const char* vendor = get_vendor_from_oui(station->station_mac);
        if (vendor) {
            strncpy(station->device_vendor, vendor, sizeof(station->device_vendor) - 1);
            station->device_vendor[sizeof(station->device_vendor) - 1] = '\0';
        }
    }
    
    // Mark as having fingerprint if we collected any useful data
    if (strlen(station->device_fingerprint) > 4 || strlen(station->device_vendor) > 0) {
        station->has_fingerprint = true;
        ESP_LOGD(TAG, "PROBE_FINGERPRINT: Complete fingerprint generated - Vendor: %s, Data: %s", 
                 station->device_vendor, station->device_fingerprint);
    } else {
        ESP_LOGD(TAG, "PROBE_FINGERPRINT: Limited fingerprint data available");
    }
}

// Compare two fingerprints to determine if they're from the same device
static bool fingerprints_match(const char *fp1, const char *fp2, int channel1, int channel2) {
    // Must be on same or nearby channel
    if (abs(channel1 - channel2) > 2) {
        return false;
    }
    
    // Both must have fingerprints
    if (!fp1 || !fp2 || strlen(fp1) < 10 || strlen(fp2) < 10) {
        return false;
    }
    
    // Extract key parts of fingerprint for comparison
    // Look for VHT capabilities (most unique identifier)
    const char *vht1 = strstr(fp1, "VHT:");
    const char *vht2 = strstr(fp2, "VHT:");
    
    if (vht1 && vht2) {
        // Compare VHT capability info (first 8 hex chars after "VHT:")
        if (strncmp(vht1, vht2, 12) == 0) {
            ESP_LOGI(TAG, "FINGERPRINT_MATCH: VHT capabilities match");
            return true;
        }
    }
    
    // Look for ExtCaps (extended capabilities)
    const char *ext1 = strstr(fp1, "ExtCaps:");
    const char *ext2 = strstr(fp2, "ExtCaps:");
    
    if (ext1 && ext2) {
        // Compare ExtCaps (first 16 hex chars)
        if (strncmp(ext1, ext2, 24) == 0) {
            ESP_LOGI(TAG, "FINGERPRINT_MATCH: Extended capabilities match");
            return true;
        }
    }
    
    // Look for supported rates pattern
    const char *rates1 = strstr(fp1, "Rates:");
    const char *rates2 = strstr(fp2, "Rates:");
    
    if (rates1 && rates2) {
        // Extract rate string (up to next space or 50 chars)
        char rate_str1[60] = {0};
        char rate_str2[60] = {0};
        const char *end1 = strchr(rates1 + 6, ' ');
        const char *end2 = strchr(rates2 + 6, ' ');
        
        int len1 = end1 ? (end1 - rates1) : strlen(rates1);
        int len2 = end2 ? (end2 - rates2) : strlen(rates2);
        
        if (len1 > 0 && len1 < 60) strncpy(rate_str1, rates1, len1);
        if (len2 > 0 && len2 < 60) strncpy(rate_str2, rates2, len2);
        
        // If rates match exactly
        if (strlen(rate_str1) > 10 && strcmp(rate_str1, rate_str2) == 0) {
            ESP_LOGI(TAG, "FINGERPRINT_MATCH: Supported rates match exactly");
            return true;
        }
    }
    
    return false;
}

// Try to group new station with existing station based on fingerprint
static bool try_group_with_existing_station(station_info_t *new_station) {
    // Only group if it's a randomized MAC
    if ((new_station->station_mac[0] & 0x02) == 0) {
        return false;
    }
    
    // Must have fingerprint
    if (!new_station->has_fingerprint) {
        return false;
    }
    
    // Search for matching fingerprint in existing stations
    for (int i = 0; i < stations_count; i++) {
        // Skip if same MAC
        if (memcmp(stations[i].station_mac, new_station->station_mac, 6) == 0) {
            continue;
        }
        
        // Must have fingerprint
        if (!stations[i].has_fingerprint) {
            continue;
        }
        
        // Check if fingerprints match
        if (fingerprints_match(stations[i].device_fingerprint, new_station->device_fingerprint,
                               stations[i].channel, new_station->channel)) {
            
            ESP_LOGI(TAG, "FINGERPRINT_GROUP: Grouping %s with %s based on matching fingerprint",
                     mac_to_str(new_station->station_mac), mac_to_str(stations[i].station_mac));
            
            // Add to grouped MACs if we have space
            if (stations[i].grouped_mac_count < 5) {
                memcpy(stations[i].grouped_macs[stations[i].grouped_mac_count], new_station->station_mac, 6);
                stations[i].grouped_mac_count++;
                stations[i].is_grouped = true;
                
                // Update probe count and RSSI
                stations[i].probe_count += new_station->probe_count;
                if (new_station->rssi > stations[i].rssi) {
                    stations[i].rssi = new_station->rssi;
                }
                stations[i].last_seen = new_station->last_seen;
                
                ESP_LOGI(TAG, "FINGERPRINT_GROUP: Device now has %d MAC addresses, total probes: %d",
                         stations[i].grouped_mac_count + 1, stations[i].probe_count);
                
                return true;
            }
        }
    }
    
    return false;
}
