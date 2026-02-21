#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "background_scan.h"
#include "scan_storage.h"
#include "device_lifecycle.h"
#include "wifi_scan.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "monitor_uptime.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "peer_discovery.h"


// External variables for channel tracking

extern void update_channel_activity(uint8_t channel, uint32_t devices_found, int8_t *rssi_values, uint32_t rssi_count);

extern bool pwnpower_time_is_synced(void);
extern uint32_t scan_storage_get_history_base_epoch(void);
extern void scan_storage_set_history_base_epoch(uint32_t epoch);

extern uint32_t wifi_scan_get_deauth_count(void);
extern void wifi_scan_increment_deauth_count(void);
extern uint32_t webserver_get_last_request_time(void);

#define TAG "BgScan"
#define CLIENT_ACTIVITY_DEFER_SEC 8
#define BG_SCAN_TASK_STACK 6144  // Reduced from 8192 to save memory
#define BG_SCAN_TASK_PRIO 5

static bg_scan_state_t scan_state = BG_SCAN_IDLE;
static bg_scan_config_t config = {
    .interval_sec = 120,
    .ap_pause_ms = 3000,
    .auto_scan = true,
    .scan_while_ap = true,
    .quick_scan_channels = 0
};

static TaskHandle_t scan_task_handle = NULL;
static SemaphoreHandle_t scan_sem = NULL;
static uint32_t last_scan_time = 0;
static bool task_running = false;
static bool trigger_pending = false;

static uint32_t get_uptime_sec(void) {
    return (uint32_t)(esp_timer_get_time() / 1000000ULL);
}

static uint32_t hash_ssid(const uint8_t *ssid, size_t len) {
    uint32_t hash = 5381;
    for (size_t i = 0; i < len && ssid[i] != 0; i++) {
        hash = ((hash << 5) + hash) + ssid[i];
    }
    return hash;
}

uint32_t get_background_channel_dwell_time(uint8_t channel) {
    return get_channel_dwell_time(channel, true);
}

typedef struct {
    uint8_t bssid[6];
    uint8_t mac[6];
    int8_t rssi;
} temp_station_t;

static temp_station_t temp_stations[128];
static volatile int temp_station_count = 0;

static void promisc_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_DATA && type != WIFI_PKT_MGMT) return;
    if (temp_station_count >= 128) return;
    
    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    if (pkt->rx_ctrl.sig_len < 24) return;
    
    uint8_t *frame = pkt->payload;
    uint8_t frame_ctrl = frame[0];
    uint8_t fc1 = frame[1];
    uint8_t frame_type = (frame_ctrl >> 2) & 0x03;
    uint8_t frame_subtype = (frame_ctrl >> 4) & 0x0F;
    
    // Check for deauthentication frames (same logic as stations_sniffer)
    if (frame_type == 0 && (frame_subtype == 0x0C || frame_subtype == 0x0A)) {
        wifi_scan_increment_deauth_count();
        ESP_LOGI(TAG, "Deauth frame detected during background scan, total: %lu", (unsigned long)wifi_scan_get_deauth_count());
        return; // Don't process as regular station data
    }
    
    uint8_t to_ds = (fc1 >> 0) & 1;
    uint8_t from_ds = (fc1 >> 1) & 1;
    
    uint8_t *bssid = NULL;
    uint8_t *sta_mac = NULL;
    
    if (to_ds && !from_ds) {
        bssid = &frame[4];
        sta_mac = &frame[10];
    } else if (!to_ds && from_ds) {
        sta_mac = &frame[4];
        bssid = &frame[10];
    } else {
        return;
    }
    
    if (sta_mac[0] & 0x01) return;
    
    for (int i = 0; i < temp_station_count; i++) {
        if (memcmp(temp_stations[i].mac, sta_mac, 6) == 0 &&
            memcmp(temp_stations[i].bssid, bssid, 6) == 0) {
            return;
        }
    }
    
    memcpy(temp_stations[temp_station_count].bssid, bssid, 6);
    memcpy(temp_stations[temp_station_count].mac, sta_mac, 6);
    temp_stations[temp_station_count].rssi = pkt->rx_ctrl.rssi;
    temp_station_count++;
}

static void populate_scan_record(scan_record_t *record) {
    memset(record, 0, sizeof(scan_record_t));
    
    record->header.timestamp = get_uptime_sec();
    record->header.uptime_sec = get_uptime_sec();
    record->header.scan_type = 0;
    
    uint32_t start_time = get_uptime_sec();
    
    wifi_scan_config_t scan_cfg = {
        .ssid = NULL,
        .bssid = NULL,
        .channel = 0,
        .show_hidden = true,
        .scan_type = WIFI_SCAN_TYPE_ACTIVE,
        .scan_time.active.min = 120,
        .scan_time.active.max = 400
    };

    uint8_t ap_idx = 0;
    
    // Use dynamic channel list
    const uint8_t *channels = get_scan_channels();
    size_t channel_count = get_scan_channels_size();
    
    for (size_t i = 0; i < channel_count && ap_idx < MAX_APS_PER_SCAN; i++) {
        uint8_t ch = channels[i];
        // Get smart dwell time for this channel
        uint32_t dwell_time = get_background_channel_dwell_time(ch);
        
        // Track that we're scanning this channel
        channel_scan_counts[ch]++;
        
        scan_cfg.channel = ch;
        scan_cfg.scan_time.active.min = dwell_time / 2;
        scan_cfg.scan_time.active.max = dwell_time;
        
        if (esp_wifi_scan_start(&scan_cfg, true) != ESP_OK) continue;
        
        uint16_t ap_count = 0;
        esp_wifi_scan_get_ap_num(&ap_count);
        
        if (ap_count == 0) {
            // Update channel activity with zero results
            update_channel_activity(ch, 0, NULL, 0);
            continue;
        }
        
        wifi_ap_record_t *ap_list = malloc(sizeof(wifi_ap_record_t) * ap_count);
        if (!ap_list) {
            // Update channel activity with count but no RSSI data
            update_channel_activity(ch, ap_count, NULL, 0);
            continue;
        }
        
        if (esp_wifi_scan_get_ap_records(&ap_count, ap_list) == ESP_OK) {
            // Process scan results for Peer Discovery
            peer_discovery_process_scan_results(ap_list, ap_count);

            // Collect RSSI values for filtering
            int8_t *rssi_values = malloc(sizeof(int8_t) * ap_count);
            if (rssi_values) {
                for (uint16_t i = 0; i < ap_count; i++) {
                    rssi_values[i] = ap_list[i].rssi;
                }
            }
            
            // Update channel activity with RSSI filtering
            update_channel_activity(ch, ap_count, rssi_values, ap_count);
            
            if (rssi_values) {
                free(rssi_values);
            }
            
            for (uint16_t i = 0; i < ap_count && ap_idx < MAX_APS_PER_SCAN; i++) {
                bool exists = false;
                for (uint8_t j = 0; j < ap_idx; j++) {
                    if (memcmp(record->aps[j].bssid, ap_list[i].bssid, 6) == 0) {
                        exists = true;
                        if (ap_list[i].rssi > record->aps[j].rssi) {
                            record->aps[j].rssi = ap_list[i].rssi;
                        }
                        if (ap_list[i].rssi < record->aps[j].rssi_min) {
                            record->aps[j].rssi_min = ap_list[i].rssi;
                        }
                        if (ap_list[i].rssi > record->aps[j].rssi_max) {
                            record->aps[j].rssi_max = ap_list[i].rssi;
                        }
                        record->aps[j].beacon_count++;
                        break;
                    }
                }
                
                if (!exists) {
                    stored_ap_t *ap = &record->aps[ap_idx];
                    memcpy(ap->bssid, ap_list[i].bssid, 6);
                    strncpy((char*)ap->ssid, (char*)ap_list[i].ssid, 32);
                    ap->channel = ap_list[i].primary;
                    ap->auth_mode = ap_list[i].authmode;
                    ap->rssi = ap_list[i].rssi;
                    ap->rssi_min = ap_list[i].rssi;
                    ap->rssi_max = ap_list[i].rssi;
                    ap->hidden = (ap_list[i].ssid[0] == '\0');
                    if (ap->hidden) {
                        wifi_scan_register_hidden_ap(ap_list[i].bssid, ap_list[i].primary);
                    }
                    ap->first_seen = get_uptime_sec();
                    ap->last_seen = get_uptime_sec();
                    ap->beacon_count = 1;
                    ap->station_count = 0;
                    ap_idx++;
                }
            }
        }
        free(ap_list);
    }

    record->header.ap_count = ap_idx;

    temp_station_count = 0;
    
    wifi_scan_set_station_scan_active(true);
    
    wifi_mode_t original_mode;
    esp_wifi_get_mode(&original_mode);
    
    bool was_sta_connected = false;
    wifi_ap_record_t ap_info;
    if (original_mode == WIFI_MODE_STA || original_mode == WIFI_MODE_APSTA) {
        was_sta_connected = (esp_wifi_sta_get_ap_info(&ap_info) == ESP_OK);
    }
    
    if (was_sta_connected) {
        ESP_LOGI(TAG, "Disconnecting STA for station scan");
        esp_wifi_disconnect();
        vTaskDelay(pdMS_TO_TICKS(300));
    }
    
    if (original_mode == WIFI_MODE_APSTA || original_mode == WIFI_MODE_AP) {
        ESP_LOGI(TAG, "Temporarily switching to STA mode for channel hopping");
        ESP_LOGI(TAG, "Deauthenticating all AP clients...");
        esp_wifi_deauth_sta(0);
        vTaskDelay(pdMS_TO_TICKS(200));
    }

    ESP_LOGI(TAG, "Setting WiFi mode to STA (AP will be destroyed temporarily)");
    esp_wifi_set_mode(WIFI_MODE_STA);
    vTaskDelay(pdMS_TO_TICKS(300));
    ESP_LOGI(TAG, "Now in STA-only mode for promiscuous scanning");
    
    wifi_promiscuous_filter_t filt = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA
    };
    esp_wifi_set_promiscuous_filter(&filt);
    esp_wifi_set_promiscuous_rx_cb(promisc_cb);
    esp_wifi_set_promiscuous(true);
    
    // Use dynamic channel list for promiscuous hopping
    channels = get_scan_channels();
    channel_count = get_scan_channels_size();
    
    // Safety timeout
    uint32_t scan_start_sec = get_uptime_sec();
    
    for (size_t i = 0; i < channel_count; i++) {
        // Watchdog check
        if ((get_uptime_sec() - scan_start_sec) > 45) {
            ESP_LOGW(TAG, "Background scan station phase timed out - aborting");
            break;
        }

        esp_wifi_set_channel(channels[i], WIFI_SECOND_CHAN_NONE);
        vTaskDelay(pdMS_TO_TICKS(250)); 
    }
    
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(NULL);
    
    if (original_mode != WIFI_MODE_STA) {
        ESP_LOGI(TAG, "Restoring original WiFi mode (AP will restart)");
        esp_wifi_set_mode(original_mode);
        vTaskDelay(pdMS_TO_TICKS(500));
        ESP_LOGI(TAG, "WiFi mode restored, AP should be available again");
    }

    if (was_sta_connected) {
        ESP_LOGI(TAG, "Reconnecting STA after background scan");
        
        // Give WiFi stack time to fully restore mode
        vTaskDelay(pdMS_TO_TICKS(300));
        
        esp_wifi_connect();
        
        // Wait for connection to stabilize before clearing scan flag
        // This prevents the disconnect handler from racing with us
        bool connected = false;
        // Reduced wait time since we're not blocking the whole system as hard
        for (int wait = 0; wait < 60; wait++) {  // 6 seconds max
            vTaskDelay(pdMS_TO_TICKS(100));
            
            wifi_ap_record_t ap_check;
            esp_err_t ap_err = esp_wifi_sta_get_ap_info(&ap_check);
            if (ap_err == ESP_OK) {
                if (!connected) {
                    ESP_LOGI(TAG, "STA associated after background scan, waiting for DHCP...");
                    connected = true;
                }
                // After 2s of being associated, assume stable enough
                if (wait > 20) {
                    ESP_LOGI(TAG, "STA connection stabilized after background scan");
                    break;
                }
            } else {
                connected = false;
            }
        }
        
        if (!connected) {
            ESP_LOGW(TAG, "STA reconnection after background scan timed out - disconnect handler will retry");
        }
    }
    
    wifi_scan_set_station_scan_active(false);
    ESP_LOGI(TAG, "Background scan station phase complete, cleared scan_active flag");

    for (int s = 0; s < temp_station_count; s++) {
        for (uint8_t a = 0; a < record->header.ap_count; a++) {
            if (memcmp(record->aps[a].bssid, temp_stations[s].bssid, 6) == 0) {
                if (record->aps[a].station_count < MAX_STATIONS_PER_AP) {
                    stored_station_t *sta = &record->aps[a].stations[record->aps[a].station_count];
                    memcpy(sta->mac, temp_stations[s].mac, 6);
                    sta->rssi = temp_stations[s].rssi;
                    sta->first_seen = get_uptime_sec();
                    sta->last_seen = get_uptime_sec();
                    sta->frame_count = 1;
                    record->aps[a].station_count++;
                    record->header.total_stations++;
                    
                    // Update device presence tracking
                    scan_storage_update_device_presence(temp_stations[s].mac, temp_stations[s].rssi, (char*)record->aps[a].ssid);
                }
                break;
            }
        }
    }
    
    // check for device departures
    device_lifecycle_check_departures();
    
    // run analytics after each scan
    scan_storage_detect_rogue_aps();

    record->header.scan_duration_sec = get_uptime_sec() - start_time;
    
    // add epoch timestamp if time is synced
    if (pwnpower_time_is_synced()) {
        time_t now;
        time(&now);
        record->header.epoch_ts = (uint32_t)now;
        record->header.time_valid = 1;
    } else {
        record->header.epoch_ts = 0;
        record->header.time_valid = 0;
    }
}

static void background_scan_task(void *arg) {
    ESP_LOGI(TAG, "Background scan task started");
    ESP_LOGI(TAG, "Initial free heap: %lu bytes", (unsigned long)esp_get_free_heap_size());

    while (task_running) {
        scan_state = BG_SCAN_WAITING;

        // Periodic heap monitoring while waiting
        ESP_LOGI(TAG, "Free heap (waiting): %lu bytes, Min ever: %lu bytes",
                 (unsigned long)esp_get_free_heap_size(),
                 (unsigned long)esp_get_minimum_free_heap_size());
        
        uint32_t remaining_ms = config.interval_sec * 1000;
        const uint32_t check_interval_ms = 1000;
        
        while (remaining_ms > 0 && task_running && !trigger_pending) {
            uint32_t delay = (remaining_ms > check_interval_ms) ? check_interval_ms : remaining_ms;
            vTaskDelay(pdMS_TO_TICKS(delay));
            remaining_ms -= delay;
        }
        
        if (!task_running) break;
        
        bool was_triggered = trigger_pending;
        trigger_pending = false;
        
        if (!config.auto_scan && !was_triggered) continue;
        
        uint32_t now = get_uptime_sec();
        uint32_t last_req = webserver_get_last_request_time();
        if (!was_triggered && last_req > 0 && (now - last_req) < CLIENT_ACTIVITY_DEFER_SEC) {
            ESP_LOGI(TAG, "Deferring scan - recent client activity (%lus ago)", (unsigned long)(now - last_req));
            continue;
        }
        
        // Don't start background scan if manual scan is running
        if (wifi_scan_is_in_progress() || wifi_scan_is_station_scan_active()) {
            ESP_LOGI(TAG, "Deferring scan - manual scan in progress");
            continue;
        }
        
        // Defer if a scan just completed (give user time to view results)
        uint32_t last_scan_ts = wifi_scan_get_results_timestamp();
        if (!was_triggered && last_scan_ts > 0) {
            time_t now_epoch;
            time(&now_epoch);
            if ((uint32_t)now_epoch - last_scan_ts < 15) {  // 15 second grace period after scan
                ESP_LOGI(TAG, "Deferring scan - recent scan completed (%lus ago)", (unsigned long)((uint32_t)now_epoch - last_scan_ts));
                continue;
            }
        }
        
        scan_state = BG_SCAN_RUNNING;
        ESP_LOGI(TAG, "=== BACKGROUND SCAN START ===");
        ESP_LOGI(TAG, "Free heap before scan: %lu bytes", (unsigned long)esp_get_free_heap_size());

        // Use shared buffer instead of malloc
        scan_record_t *record = &shared_scan_buffer;

        populate_scan_record(record);
        
        history_sample_t sample;
        memset(&sample, 0, sizeof(sample));
        


        bool save_history = (record->header.time_valid && record->header.epoch_ts > 0);
        if (save_history) {
            sample.timestamp = record->header.epoch_ts;
            sample.flags = HISTORY_FLAG_TIME_VALID;
        }
        sample.ap_count = record->header.ap_count;
        sample.client_count = record->header.total_stations > 255 ? 255 : record->header.total_stations;
        if (sample.client_count >= 250) {
            ESP_LOGW(TAG, "history sample client_count=%u looks corrupt; treating as 0", sample.client_count);
            sample.client_count = 0;
        }
        
        uint8_t ch_counts[MAX_CHANNEL_ID + 1] = {0};
        for (uint8_t i = 0; i < record->header.ap_count; i++) {
            uint8_t ch = record->aps[i].channel;
            if (ch <= MAX_CHANNEL_ID) {
                ch_counts[ch]++;
            }
        }

        typedef struct { uint8_t ch; uint8_t count; } ch_count_t;
        ch_count_t sorted_ch[MAX_CHANNEL_ID + 1];
        int ch_idx = 0;
        
        for (int c = 1; c <= MAX_CHANNEL_ID; c++) {
             if (ch_counts[c] > 0) {
                 sorted_ch[ch_idx].ch = c;
                 sorted_ch[ch_idx].count = ch_counts[c];
                 ch_idx++;
             }
        }
        
        // Sort by count descending
        for (int i = 0; i < ch_idx - 1; i++) {
            for (int j = i + 1; j < ch_idx; j++) {
                if (sorted_ch[j].count > sorted_ch[i].count) {
                    ch_count_t tmp = sorted_ch[i];
                    sorted_ch[i] = sorted_ch[j];
                    sorted_ch[j] = tmp;
                }
            }
        }
        
        // Store top 7
        for (int i = 0; i < 7; i++) {
            if (i < ch_idx) {
                sample.top_channels[i] = sorted_ch[i].ch;
                sample.top_counts[i] = sorted_ch[i].count;
            } else {
                sample.top_channels[i] = 0;
                sample.top_counts[i] = 0;
            }
        }
        
        typedef struct {
            uint32_t hash;
            uint8_t count;
        } ssid_temp_t;
        ssid_temp_t ssid_temps[MAX_APS_PER_SCAN];
        uint8_t temp_count = 0;
        
        for (uint8_t i = 0; i < record->header.ap_count && temp_count < MAX_APS_PER_SCAN; i++) {
            if (record->aps[i].station_count > 0) {
                // Clamp individual AP client counts to prevent overflow
                uint8_t client_count = record->aps[i].station_count > 50 ? 50 : record->aps[i].station_count;
                ssid_temps[temp_count].hash = hash_ssid(record->aps[i].ssid, 33);
                ssid_temps[temp_count].count = client_count;
                temp_count++;
            }
        }
        
        // Deduplicate SSIDs by hash and sum client counts
        for (uint8_t i = 0; i < temp_count; i++) {
            for (uint8_t j = i + 1; j < temp_count; j++) {
                if (ssid_temps[i].hash == ssid_temps[j].hash) {
                    // Sum client counts for duplicate SSIDs
                    ssid_temps[i].count += ssid_temps[j].count;
                    // Clamp to reasonable maximum to prevent overflow
                    if (ssid_temps[i].count > 50) {
                        ssid_temps[i].count = 50;
                    }
                    // Remove duplicate entry
                    ssid_temps[j] = ssid_temps[--temp_count];
                    j--;
                }
            }
        }
        
        // Sort by total client count (descending)
        for (uint8_t i = 0; i < temp_count - 1; i++) {
            for (uint8_t j = i + 1; j < temp_count; j++) {
                if (ssid_temps[j].count > ssid_temps[i].count) {
                    ssid_temp_t tmp = ssid_temps[i];
                    ssid_temps[i] = ssid_temps[j];
                    ssid_temps[j] = tmp;
                }
            }
        }
        
        uint8_t ssid_count = temp_count > MAX_SSID_CLIENTS_PER_SAMPLE ? MAX_SSID_CLIENTS_PER_SAMPLE : temp_count;
        HISTORY_SET_SSID_COUNT(sample.flags, ssid_count);
        for (uint8_t i = 0; i < ssid_count; i++) {
            sample.ssid_clients[i].ssid_hash = ssid_temps[i].hash;
            sample.ssid_clients[i].client_count = ssid_temps[i].count;
        }
        
        ESP_LOGI(TAG, "Free heap before storage save: %lu bytes", (unsigned long)esp_get_free_heap_size());

        esp_err_t err = scan_storage_save(record);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "Failed to save scan: %s", esp_err_to_name(err));
        } else {
            ESP_LOGI(TAG, "Background scan saved successfully (%u APs, %u stations)", 
                     record->header.ap_count, record->header.total_stations);
            
            // Only update UI cache if save was successful
            wifi_scan_update_ui_cache_from_record(record);
        }

        ESP_LOGI(TAG, "Free heap after storage save: %lu bytes", (unsigned long)esp_get_free_heap_size());
        
        if (save_history) {
            sample.crc8 = history_sample_crc8(&sample);
            err = scan_storage_append_history_sample(&sample);
            if (err != ESP_OK) {
                ESP_LOGE(TAG, "Failed to save history sample: %s", esp_err_to_name(err));
            }
        } else {
            ESP_LOGW(TAG, "Skipping history sample: Time not synced (SNTP/Internet required)");
        }
        
        // flush tracked devices to nvs after each scan
        scan_storage_flush_devices();
        
        // Sync deauth detection results to intelligence system
        scan_storage_update_security_events(wifi_scan_get_deauth_count());
        
        // Send batched deauth webhook alert if frames were detected
        if (wifi_scan_get_deauth_count() > 0) {
            device_lifecycle_generate_batched_deauth_alert(wifi_scan_get_deauth_count(), record->header.scan_duration_sec);
            // Reset count after sending alert to prevent duplicate notifications
            wifi_scan_reset_deauth_count();
        }

        last_scan_time = get_uptime_sec();

        ESP_LOGI(TAG, "Free heap at scan end: %lu bytes, Min ever: %lu bytes",
                 (unsigned long)esp_get_free_heap_size(),
                 (unsigned long)esp_get_minimum_free_heap_size());
        ESP_LOGI(TAG, "=== BACKGROUND SCAN END ===");
    }
    
    scan_state = BG_SCAN_IDLE;
    scan_task_handle = NULL;
    vTaskDelete(NULL);
}

esp_err_t background_scan_init(void) {
    if (scan_sem == NULL) {
        scan_sem = xSemaphoreCreateBinary();
        xSemaphoreGive(scan_sem);
    }
    
    esp_err_t err = scan_storage_init();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to init storage: %s", esp_err_to_name(err));
        return err;
    }
    
    ESP_LOGI(TAG, "Background scan initialized (interval: %us)", config.interval_sec);
    return ESP_OK;
}

esp_err_t background_scan_start(void) {
    if (scan_task_handle != NULL) {
        return ESP_ERR_INVALID_STATE;
    }
    
    task_running = true;
    
    BaseType_t ret = xTaskCreate(
        background_scan_task,
        "bg_scan",
        BG_SCAN_TASK_STACK,
        NULL,
        BG_SCAN_TASK_PRIO,
        &scan_task_handle
    );
    
    if (ret != pdPASS) {
        task_running = false;
        return ESP_ERR_NO_MEM;
    }
    
    ESP_LOGI(TAG, "Background scanning started");
    return ESP_OK;
}

esp_err_t background_scan_stop(void) {
    if (!task_running) return ESP_OK;
    
    task_running = false;
    
    if (scan_task_handle) {
        for (int i = 0; i < 50 && scan_task_handle != NULL; i++) {
            vTaskDelay(pdMS_TO_TICKS(100));
        }
    }
    
    scan_state = BG_SCAN_IDLE;
    ESP_LOGI(TAG, "Background scanning stopped");
    return ESP_OK;
}

esp_err_t background_scan_trigger(void) {
    trigger_pending = true;
    ESP_LOGI(TAG, "Manual scan triggered - will start within 1 second");
    return ESP_OK;
}

esp_err_t background_scan_set_interval(uint16_t seconds) {
    if (seconds < 60) seconds = 60;
    if (seconds > 3600) seconds = 3600;
    config.interval_sec = seconds;
    ESP_LOGI(TAG, "Scan interval set to %u seconds", seconds);
    return ESP_OK;
}

void background_scan_set_enabled(bool enabled) {
    config.auto_scan = enabled;
    ESP_LOGI(TAG, "Auto scan %s", enabled ? "enabled" : "disabled");
}

bg_scan_state_t background_scan_get_state(void) {
    return scan_state;
}

uint32_t background_scan_get_last_time(void) {
    return last_scan_time;
}

const bg_scan_config_t* background_scan_get_config(void) {
    return &config;
}
