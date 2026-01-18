#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "scan_storage.h"
#include "device_lifecycle.h"
#include "flash_manager.h"
#include "esp_partition.h"
#include "nvs.h"
#include "esp_log.h"
#include "esp_crc.h"
#include "esp_timer.h"
#include "cJSON.h"
#include "ouis.h"
#include "esp_http_server.h"
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <time.h>

#define TAG "ScanStorage"
#define NVS_NAMESPACE "scan_idx"
#define MAX_TRACKED_DEVICES 64
#define RECORD_SIZE sizeof(scan_record_t)
#define INDEX_OFFSET 0
#define INDEX_SIZE 4096
#define DATA_OFFSET 4096
#define FLASH_SECTOR_SIZE 4096
#define HISTORY_OFFSET (((DATA_OFFSET + RECORD_SIZE + FLASH_SECTOR_SIZE - 1) / FLASH_SECTOR_SIZE) * FLASH_SECTOR_SIZE)
#define HISTORY_SIZE (sizeof(history_sample_t) * MAX_HISTORY_SAMPLES)
#define EVENTS_OFFSET (HISTORY_OFFSET + HISTORY_SIZE)
#define EVENTS_SIZE (sizeof(device_event_t) * MAX_DEVICE_EVENTS)
#define DEVICES_OFFSET (EVENTS_OFFSET + EVENTS_SIZE)
#define DEVICES_SIZE (sizeof(device_presence_t) * MAX_TRACKED_DEVICES)

static flash_manager_t flash_mgr;
static storage_index_t storage_index;
static char report_json[4096];
static char intelligence_json[2048];
static ring_buffer_ctx_t history_ring;
static ring_buffer_ctx_t events_ring;

static device_presence_t tracked_devices[MAX_TRACKED_DEVICES];
static int tracked_device_count = 0;
static bool devices_loaded_from_flash = false;

static uint32_t deauth_events_hour = 0;
static uint32_t rogue_ap_count = 0;
static char connected_ssid[33] = {0};
static char extra_home_ssids[3][33] = {{0}};  // up to 3 additional home SSIDs
#define MAX_EXTRA_HOME_SSIDS 3
static uint32_t device_updates_since_save = 0;
#define DEVICE_SAVE_INTERVAL 20

// Counter caps to prevent overflow
#define MAX_BEACON_COUNT 65000
#define MAX_FRAME_COUNT 100000
#define STALE_AP_THRESHOLD_SEC (24 * 3600)      // 24 hours
#define STALE_STATION_THRESHOLD_SEC 3600         // 1 hour
#define STALE_DEVICE_THRESHOLD_SEC (7 * 86400)   // 7 days

// Device prioritization thresholds
#define HOME_DEVICE_PRIORITY_MULTIPLIER 10  // Home devices get 10x priority score
#define MIN_SIGHTINGS_FOR_PROTECTION 5      // Devices with 5+ sightings harder to evict

// forward declarations
static uint32_t get_uptime_sec(void);
static void device_cleanup_task(void *arg);

extern bool pwnpower_time_is_synced(void);

static uint32_t calc_record_crc(const scan_record_t *rec) {
    uint32_t crc = 0;
    size_t crc_offset = offsetof(scan_record_t, header) + offsetof(scan_header_t, crc32);
    crc = esp_crc32_le(crc, (const uint8_t*)rec, crc_offset);
    crc = esp_crc32_le(crc, (const uint8_t*)rec + crc_offset + sizeof(uint32_t), 
                       sizeof(scan_record_t) - crc_offset - sizeof(uint32_t));
    return crc;
}

// nvs-based index persistence to avoid flash erase cycles
static esp_err_t write_storage_index(void) {
    nvs_handle_t handle;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) return err;
    
    err = nvs_set_blob(handle, "index", &storage_index, sizeof(storage_index_t));
    if (err == ESP_OK) {
        err = nvs_commit(handle);
    }
    nvs_close(handle);
    return err;
}

static esp_err_t read_storage_index(void) {
    nvs_handle_t handle;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READONLY, &handle);
    if (err != ESP_OK) return err;
    
    size_t required_size = sizeof(storage_index_t);
    err = nvs_get_blob(handle, "index", &storage_index, &required_size);
    nvs_close(handle);
    return err;
}

static esp_err_t save_tracked_devices(void) {
    if (!flash_mgr.partition) {
        ESP_LOGE(TAG, "flash manager not initialized");
        return ESP_ERR_INVALID_STATE;
    }

    if (tracked_device_count == 0) {
        ESP_LOGD(TAG, "no devices to save");
        return ESP_OK;
    }

    size_t data_size = sizeof(device_presence_t) * tracked_device_count;
    size_t total_size = sizeof(uint32_t) + data_size;
    
    uint8_t *write_buf = malloc(total_size);
    if (!write_buf) {
        ESP_LOGE(TAG, "failed to allocate write buffer");
        return ESP_ERR_NO_MEM;
    }
    
    uint32_t count_header = tracked_device_count;
    memcpy(write_buf, &count_header, sizeof(uint32_t));
    memcpy(write_buf + sizeof(uint32_t), tracked_devices, data_size);
    
    esp_err_t err = flash_manager_write(&flash_mgr, DEVICES_OFFSET, write_buf, total_size);
    free(write_buf);
    
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "failed to write devices: %s", esp_err_to_name(err));
        return err;
    }

    ESP_LOGI(TAG, "saved %d devices to flash (%zu bytes)", tracked_device_count, data_size);
    return ESP_OK;
}

static esp_err_t load_tracked_devices(void) {
    if (!flash_mgr.partition) {
        return ESP_ERR_INVALID_STATE;
    }

    uint32_t count_header = 0;
    esp_err_t err = flash_manager_read(&flash_mgr, DEVICES_OFFSET, &count_header, sizeof(uint32_t));
    if (err != ESP_OK) {
        return err;
    }

    if (count_header == 0 || count_header > MAX_TRACKED_DEVICES || count_header == 0xFFFFFFFF) {
        ESP_LOGD(TAG, "no valid devices in flash (count=%lu)", (unsigned long)count_header);
        return ESP_ERR_NOT_FOUND;
    }

    size_t data_size = sizeof(device_presence_t) * count_header;
    err = flash_manager_read(&flash_mgr, DEVICES_OFFSET + sizeof(uint32_t), tracked_devices, data_size);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "failed to read devices: %s", esp_err_to_name(err));
        return err;
    }

    tracked_device_count = count_header;
    devices_loaded_from_flash = true;

    time_t epoch_now = time(NULL);
    bool epoch_now_valid = (epoch_now > 0 && epoch_now != (time_t)-1);
    uint32_t uptime_now = get_uptime_sec();

    for (int i = 0; i < tracked_device_count; i++) {
        device_presence_t *dev = &tracked_devices[i];

        if (epoch_now_valid && DEVICE_EPOCH_VALID(dev->flags)) {
            if (dev->first_seen_epoch > 0 && dev->first_seen_epoch <= (uint32_t)epoch_now) {
                uint32_t age = (uint32_t)epoch_now - dev->first_seen_epoch;
                dev->first_seen = (age < uptime_now) ? (uptime_now - age) : 0;
            } else {
                dev->first_seen = 0;
            }

            if (dev->last_seen_epoch > 0 && dev->last_seen_epoch <= (uint32_t)epoch_now) {
                uint32_t age = (uint32_t)epoch_now - dev->last_seen_epoch;
                dev->last_seen = (age < uptime_now) ? (uptime_now - age) : 0;
            } else {
                dev->last_seen = 0;
            }
        } else {
            dev->first_seen = 0;
            dev->last_seen = 0;
        }

        device_lifecycle_restore_device(dev->mac);
    }

    ESP_LOGI(TAG, "loaded %d devices from flash (restored lifecycle state)", tracked_device_count);
    return ESP_OK;
}

esp_err_t scan_storage_init(void) {
    // initialize flash manager for scan data partition
    esp_err_t err = flash_manager_init(&flash_mgr, SCAN_STORAGE_PARTITION, TAG);
    if (err != ESP_OK) {
        return err;
    }

    // initialize ring buffer contexts
    history_ring.base_offset = HISTORY_OFFSET;
    history_ring.item_size = sizeof(history_sample_t);
    history_ring.max_items = MAX_HISTORY_SAMPLES;
    history_ring.write_idx = 0;
    history_ring.count = 0;
    
    events_ring.base_offset = EVENTS_OFFSET;
    events_ring.item_size = sizeof(device_event_t);
    events_ring.max_items = MAX_DEVICE_EVENTS;
    events_ring.write_idx = 0;
    events_ring.count = 0;

    // Load tracked devices from flash FIRST (before any potential erase)
    load_tracked_devices();
    int devices_before_init = tracked_device_count;
    
    // Load extra home SSIDs from NVS
    nvs_handle_t handle;
    if (nvs_open(NVS_NAMESPACE, NVS_READONLY, &handle) == ESP_OK) {
        for (int i = 0; i < MAX_EXTRA_HOME_SSIDS; i++) {
            char key[16];
            snprintf(key, sizeof(key), "home_ssid_%d", i);
            size_t len = sizeof(extra_home_ssids[i]);
            if (nvs_get_str(handle, key, extra_home_ssids[i], &len) == ESP_OK) {
                ESP_LOGI(TAG, "Loaded extra home SSID[%d]: %s", i, extra_home_ssids[i]);
            }
        }
        nvs_close(handle);
    }

    // try to load index from nvs (persists across reboots)
    err = read_storage_index();
    if (err != ESP_OK || storage_index.magic != SCAN_MAGIC || storage_index.version != SCAN_VERSION) {
        ESP_LOGI(TAG, "initializing fresh scan storage (version upgrade or fresh boot)");
        memset(&storage_index, 0, sizeof(storage_index_t));
        storage_index.magic = SCAN_MAGIC;
        storage_index.version = SCAN_VERSION;
        storage_index.first_boot = 0;
        storage_index.history_write_idx = 0;
        storage_index.history_count = 0;
        storage_index.event_write_idx = 0;
        storage_index.event_count = 0;
        storage_index.history_base_epoch = 0;
        
        // erase data partition on fresh init
        err = flash_manager_erase_range(&flash_mgr, DATA_OFFSET, flash_mgr.partition->size - DATA_OFFSET);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "failed to erase data partition: %s", esp_err_to_name(err));
            return err;
        }
        
        // save fresh index to nvs
        err = write_storage_index();
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "failed to write index to nvs: %s", esp_err_to_name(err));
            return err;
        }

        // Re-save devices that were loaded before erase
        if (devices_before_init > 0) {
            ESP_LOGI(TAG, "restoring %d devices after partition init", devices_before_init);
            save_tracked_devices();
        }
    } else {
        ESP_LOGI(TAG, "loaded storage index from nvs: %lu total scans, %u records, %lu history samples, %lu events", 
                 (unsigned long)storage_index.total_scans, storage_index.record_count,
                 (unsigned long)storage_index.history_count, (unsigned long)storage_index.event_count);
        
        // restore ring buffer state from index
        history_ring.write_idx = storage_index.history_write_idx;
        history_ring.count = storage_index.history_count;
        events_ring.write_idx = storage_index.event_write_idx;
        events_ring.count = storage_index.event_count;
        
        // validate history ring by checking oldest sample (index 0 if ring hasn't wrapped)
        if (history_ring.count > 0) {
            uint32_t oldest_idx = (history_ring.count < history_ring.max_items) ? 0 : history_ring.write_idx;
            history_sample_t test_sample;
            uint32_t offset = history_ring.base_offset + (oldest_idx * history_ring.item_size);
            if (flash_manager_read(&flash_mgr, offset, &test_sample, sizeof(test_sample)) == ESP_OK) {
                if (test_sample.ap_count == 255 || test_sample.client_count == 255 ||
                    test_sample.timestamp_delta_sec == 0xFFFF) {
                    ESP_LOGW(TAG, "history ring oldest sample invalid (flash erased?), resetting count from %lu to 0",
                             (unsigned long)history_ring.count);
                    history_ring.count = 0;
                    history_ring.write_idx = 0;
                    storage_index.history_count = 0;
                    storage_index.history_write_idx = 0;
                    write_storage_index();
                }
            }
        }
    }

    // Start device cleanup task
    xTaskCreate(device_cleanup_task, "device_cleanup", 2048, NULL, 3, NULL);
    ESP_LOGI(TAG, "Started device cleanup task");

    return ESP_OK;
}

static void device_cleanup_task(void *arg) {
    ESP_LOGI(TAG, "Device cleanup task started");
    while (1) {
        // Wait 1 hour between cleanup cycles
        vTaskDelay(pdMS_TO_TICKS(3600000));

        time_t epoch_now = time(NULL);
        bool epoch_valid = (epoch_now > 0 && epoch_now != (time_t)-1);
        uint32_t uptime_now = get_uptime_sec();

        int removed_count = 0;
        for (int i = 0; i < tracked_device_count; ) {
            device_presence_t *dev = &tracked_devices[i];
            bool stale = false;

            if (epoch_valid && DEVICE_EPOCH_VALID(dev->flags) &&
                dev->last_seen_epoch > 0 && dev->last_seen_epoch <= (uint32_t)epoch_now) {
                uint32_t age = (uint32_t)epoch_now - dev->last_seen_epoch;
                stale = (age > STALE_DEVICE_THRESHOLD_SEC);
            } else if (dev->last_seen > 0 && dev->last_seen <= uptime_now) {
                uint32_t age = uptime_now - dev->last_seen;
                stale = (age > STALE_DEVICE_THRESHOLD_SEC);
            }

            if (!stale) {
                i++;
                continue;
            }

            // Device is stale (not seen in threshold), remove it
            if (i < tracked_device_count - 1) {
                memmove(&tracked_devices[i], &tracked_devices[i + 1],
                        (tracked_device_count - i - 1) * sizeof(device_presence_t));
            }
            tracked_device_count--;
            removed_count++;
            // Don't increment i, check the new device at this position
        }

        if (removed_count > 0) {
            ESP_LOGI(TAG, "Device cleanup: removed %d stale devices (threshold: %d days)",
                     removed_count, STALE_DEVICE_THRESHOLD_SEC / 86400);
            scan_storage_flush_devices();
        }
    }
}

static void prune_stale_data(scan_record_t *record, time_t current_time) {
    if (!record || current_time == 0) return;

    // Remove stale APs
    for (uint8_t i = 0; i < record->header.ap_count; ) {
        if ((current_time - record->aps[i].last_seen) > STALE_AP_THRESHOLD_SEC) {
            // AP is stale, shift remaining APs down
            if (i < record->header.ap_count - 1) {
                memmove(&record->aps[i], &record->aps[i + 1],
                        (record->header.ap_count - i - 1) * sizeof(stored_ap_t));
            }
            record->header.ap_count--;
            // Don't increment i, check the new AP at this position
        } else {
            // Remove stale stations within this AP
            for (uint8_t s = 0; s < record->aps[i].station_count; ) {
                if ((current_time - record->aps[i].stations[s].last_seen) > STALE_STATION_THRESHOLD_SEC) {
                    // Station is stale, shift remaining stations down
                    if (s < record->aps[i].station_count - 1) {
                        memmove(&record->aps[i].stations[s], &record->aps[i].stations[s + 1],
                                (record->aps[i].station_count - s - 1) * sizeof(stored_station_t));
                    }
                    record->aps[i].station_count--;
                    // Don't increment s, check the new station at this position
                } else {
                    s++;
                }
            }
            i++;
        }
    }

    // Recalculate total_stations after pruning
    record->header.total_stations = 0;
    for (uint8_t i = 0; i < record->header.ap_count; i++) {
        record->header.total_stations += record->aps[i].station_count;
    }
}

esp_err_t scan_storage_save(scan_record_t *record) {
    if (!flash_mgr.partition || !record) return ESP_ERR_INVALID_ARG;

    scan_record_t *existing = malloc(sizeof(scan_record_t));
    bool has_existing = false;
    
    if (existing && storage_index.record_count > 0) {
        uint32_t read_offset = DATA_OFFSET;
        if (flash_manager_read(&flash_mgr, read_offset, existing, sizeof(scan_record_t)) == ESP_OK) {
            if (existing->header.magic == SCAN_MAGIC) {
                uint32_t expected_crc = calc_record_crc(existing);
                if (existing->header.crc32 == expected_crc) {
                    has_existing = true;
                }
            }
        }
    }

    if (has_existing) {
        // Prune stale data before merging
        prune_stale_data(existing, record->header.timestamp);

        for (uint8_t i = 0; i < record->header.ap_count; i++) {
            stored_ap_t *new_ap = &record->aps[i];
            bool found = false;
            
            for (uint8_t j = 0; j < existing->header.ap_count; j++) {
                if (memcmp(existing->aps[j].bssid, new_ap->bssid, 6) == 0) {
                    found = true;
                    existing->aps[j].last_seen = new_ap->last_seen;

                    // Cap beacon_count to prevent overflow
                    uint32_t new_beacon_count = existing->aps[j].beacon_count + new_ap->beacon_count;
                    existing->aps[j].beacon_count = (new_beacon_count > MAX_BEACON_COUNT) ?
                                                      MAX_BEACON_COUNT : new_beacon_count;

                    if (new_ap->rssi > existing->aps[j].rssi_max) {
                        existing->aps[j].rssi_max = new_ap->rssi;
                    }
                    if (new_ap->rssi < existing->aps[j].rssi_min) {
                        existing->aps[j].rssi_min = new_ap->rssi;
                    }
                    existing->aps[j].rssi = new_ap->rssi;
                    
                    for (uint8_t s = 0; s < new_ap->station_count; s++) {
                        bool sta_found = false;
                        for (uint8_t t = 0; t < existing->aps[j].station_count; t++) {
                            if (memcmp(existing->aps[j].stations[t].mac, new_ap->stations[s].mac, 6) == 0) {
                                sta_found = true;
                                existing->aps[j].stations[t].last_seen = new_ap->stations[s].last_seen;
                                existing->aps[j].stations[t].rssi = new_ap->stations[s].rssi;

                                // Cap frame_count to prevent overflow
                                uint32_t new_frame_count = existing->aps[j].stations[t].frame_count +
                                                           new_ap->stations[s].frame_count;
                                existing->aps[j].stations[t].frame_count = (new_frame_count > MAX_FRAME_COUNT) ?
                                                                            MAX_FRAME_COUNT : new_frame_count;
                                break;
                            }
                        }
                        if (!sta_found && existing->aps[j].station_count < MAX_STATIONS_PER_AP) {
                            memcpy(&existing->aps[j].stations[existing->aps[j].station_count], 
                                   &new_ap->stations[s], sizeof(stored_station_t));
                            existing->aps[j].station_count++;
                        }
                    }
                    break;
                }
            }
            
            if (!found && existing->header.ap_count < MAX_APS_PER_SCAN) {
                memcpy(&existing->aps[existing->header.ap_count], new_ap, sizeof(stored_ap_t));
                existing->header.ap_count++;
            }
        }
        
        // recalculate total_stations from scratch to avoid accumulation bug
        existing->header.total_stations = 0;
        for (uint8_t i = 0; i < existing->header.ap_count; i++) {
            existing->header.total_stations += existing->aps[i].station_count;
        }
        
        existing->header.timestamp = record->header.timestamp;
        existing->header.uptime_sec = record->header.uptime_sec;
        existing->header.epoch_ts = record->header.epoch_ts;
        existing->header.time_valid = record->header.time_valid;
        memcpy(record, existing, sizeof(scan_record_t));
    }
    
    if (existing) free(existing);

    record->header.magic = SCAN_MAGIC;
    record->header.version = SCAN_VERSION;
    record->header.crc32 = calc_record_crc(record);

    uint32_t offset = DATA_OFFSET;
    
    // use flash manager for auto-erase write (thread-safe)
    esp_err_t err = flash_manager_write(&flash_mgr, offset, record, sizeof(scan_record_t));
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "write failed: %s", esp_err_to_name(err));
        return err;
    }

    storage_index.record_count = 1;
    storage_index.total_scans++;
    storage_index.last_scan = record->header.timestamp;
    
    if (storage_index.first_boot == 0) {
        storage_index.first_boot = record->header.timestamp;
    }

    // persist index to nvs (handles wear-leveling automatically)
    err = write_storage_index();
    
    ESP_LOGI(TAG, "saved scan record %lu (%u aps, %u stations)", 
             (unsigned long)storage_index.total_scans,
             record->header.ap_count,
             record->header.total_stations);

    return err;
}

esp_err_t scan_storage_get_latest(scan_record_t *record) {
    if (!flash_mgr.partition || !record || storage_index.record_count == 0) {
        return ESP_ERR_NOT_FOUND;
    }

    uint8_t idx = (storage_index.write_index == 0) ? 
                  (storage_index.record_count - 1) : 
                  (storage_index.write_index - 1);
    
    return scan_storage_get_record(idx, record);
}

esp_err_t scan_storage_get_record(uint8_t index, scan_record_t *record) {
    if (!flash_mgr.partition || !record || index >= storage_index.record_count) {
        return ESP_ERR_INVALID_ARG;
    }

    uint32_t offset = DATA_OFFSET + (index * RECORD_SIZE);
    esp_err_t err = flash_manager_read(&flash_mgr, offset, record, sizeof(scan_record_t));

    if (err != ESP_OK) return err;

    if (record->header.magic != SCAN_MAGIC) {
        return ESP_ERR_INVALID_CRC;
    }

    uint32_t expected_crc = calc_record_crc(record);
    if (record->header.crc32 != expected_crc) {
        ESP_LOGW(TAG, "CRC mismatch for record %u", index);
        return ESP_ERR_INVALID_CRC;
    }

    return ESP_OK;
}

esp_err_t scan_storage_get_stats(network_stats_t *stats) {
    if (!stats) return ESP_ERR_INVALID_ARG;

    memset(stats, 0, sizeof(network_stats_t));
    stats->scan_count = storage_index.total_scans;

    if (storage_index.record_count == 0) return ESP_OK;

    scan_record_t *rec = malloc(sizeof(scan_record_t));
    if (!rec) return ESP_ERR_NO_MEM;

    if (scan_storage_get_latest(rec) == ESP_OK) {
        stats->total_aps_seen = rec->header.ap_count;
        stats->current_aps = rec->header.ap_count;
        stats->total_stations_seen = rec->header.total_stations;
        stats->current_stations = rec->header.total_stations;
    }

    free(rec);

    if (storage_index.first_boot > 0 && storage_index.last_scan > storage_index.first_boot) {
        stats->monitoring_duration_sec = storage_index.last_scan - storage_index.first_boot;
    }

    stats->deauth_events_last_hour = deauth_events_hour;
    stats->rogue_aps_detected = rogue_ap_count;
    
    uint32_t now = (uint32_t)(esp_timer_get_time() / 1000000ULL);
    bool time_ok = pwnpower_time_is_synced();
    uint32_t epoch_now = 0;
    if (time_ok) {
        time_t t;
        time(&t);
        if (t > 0) epoch_now = (uint32_t)t;
        else time_ok = false;
    }
    int present = 0;
    for (int i = 0; i < tracked_device_count; i++) {
        device_presence_t *dev = &tracked_devices[i];
        if (time_ok && DEVICE_EPOCH_VALID(dev->flags) && dev->last_seen_epoch > 0 && dev->last_seen_epoch <= epoch_now) {
            if ((epoch_now - dev->last_seen_epoch) < 300) present++;
        } else if (dev->last_seen > 0 && dev->last_seen <= now) {
            if ((now - dev->last_seen) < 300) present++;
        }
    }
    stats->known_devices_present = present;

    return ESP_OK;
}

esp_err_t scan_storage_clear(void) {
    if (!flash_mgr.partition) return ESP_ERR_INVALID_STATE;

    esp_err_t err = flash_manager_erase_all(&flash_mgr);
    if (err == ESP_OK) {
        memset(&storage_index, 0, sizeof(storage_index_t));
        storage_index.magic = SCAN_MAGIC;
        storage_index.version = SCAN_VERSION;
        
        // reset ring buffers
        history_ring.write_idx = 0;
        history_ring.count = 0;
        events_ring.write_idx = 0;
        events_ring.count = 0;
        
        err = write_storage_index();
    }

    return err;
}

uint8_t scan_storage_get_count(void) {
    return storage_index.record_count;
}

const char* scan_storage_get_report_json(void) {
    cJSON *root = cJSON_CreateObject();
    
    network_stats_t stats;
    scan_storage_get_stats(&stats);
    
    cJSON *summary = cJSON_AddObjectToObject(root, "summary");
    cJSON_AddNumberToObject(summary, "total_scans", stats.scan_count);
    cJSON_AddNumberToObject(summary, "unique_aps", stats.total_aps_seen);
    cJSON_AddNumberToObject(summary, "unique_stations", stats.total_stations_seen);
    cJSON_AddNumberToObject(summary, "current_aps", stats.current_aps);
    cJSON_AddNumberToObject(summary, "current_stations", stats.current_stations);
    cJSON_AddNumberToObject(summary, "monitoring_hours", stats.monitoring_duration_sec / 3600.0);

    cJSON *networks = cJSON_AddArrayToObject(root, "networks");
    
    scan_record_t *latest = malloc(sizeof(scan_record_t));
    if (latest && scan_storage_get_latest(latest) == ESP_OK) {
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
            cJSON_AddNumberToObject(net, "rssi_min", ap->rssi_min);
            cJSON_AddNumberToObject(net, "rssi_max", ap->rssi_max);
            cJSON_AddNumberToObject(net, "stations", ap->station_count);
            cJSON_AddNumberToObject(net, "beacons", ap->beacon_count);
            cJSON_AddBoolToObject(net, "hidden", ap->hidden);
            
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

            if (ap->station_count > 0) {
                cJSON *clients = cJSON_AddArrayToObject(net, "clients");
                for (uint8_t j = 0; j < ap->station_count && j < MAX_STATIONS_PER_AP; j++) {
                    stored_station_t *sta = &ap->stations[j];
                    cJSON *client = cJSON_CreateObject();
                    
                    snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
                            sta->mac[0], sta->mac[1], sta->mac[2],
                            sta->mac[3], sta->mac[4], sta->mac[5]);
                    
                    cJSON_AddStringToObject(client, "mac", mac);
                    cJSON_AddNumberToObject(client, "rssi", sta->rssi);
                    cJSON_AddNumberToObject(client, "frames", sta->frame_count);
                    cJSON_AddItemToArray(clients, client);
                }
            }
            
            cJSON_AddItemToArray(networks, net);
        }
    }
    if (latest) free(latest);

    char *json = cJSON_PrintUnformatted(root);
    strncpy(report_json, json, sizeof(report_json) - 1);
    report_json[sizeof(report_json) - 1] = '\0';
    free(json);
    cJSON_Delete(root);

    return report_json;
}

const char* scan_storage_get_timeline_json(uint8_t hours) {
    cJSON *root = cJSON_CreateObject();
    cJSON *timeline = cJSON_AddArrayToObject(root, "timeline");
    
    scan_record_t *rec = malloc(sizeof(scan_record_t));
    if (rec) {
        for (uint8_t i = 0; i < storage_index.record_count; i++) {
            if (scan_storage_get_record(i, rec) != ESP_OK) continue;
            
            cJSON *entry = cJSON_CreateObject();
            cJSON_AddNumberToObject(entry, "timestamp", rec->header.timestamp);
            cJSON_AddNumberToObject(entry, "uptime", rec->header.uptime_sec);
            cJSON_AddNumberToObject(entry, "aps", rec->header.ap_count);
            cJSON_AddNumberToObject(entry, "stations", rec->header.total_stations);
            cJSON_AddNumberToObject(entry, "duration", rec->header.scan_duration_sec);
            cJSON_AddItemToArray(timeline, entry);
        }
        free(rec);
    }

    char *json = cJSON_PrintUnformatted(root);
    strncpy(report_json, json, sizeof(report_json) - 1);
    free(json);
    cJSON_Delete(root);

    return report_json;
}

esp_err_t scan_storage_get_ap_history(const uint8_t *bssid, ap_summary_t *summary) {
    if (!bssid || !summary) return ESP_ERR_INVALID_ARG;
    
    memset(summary, 0, sizeof(ap_summary_t));
    memcpy(summary->bssid, bssid, 6);
    
    scan_record_t *rec = malloc(sizeof(scan_record_t));
    if (!rec) return ESP_ERR_NO_MEM;
    
    int rssi_sum = 0;
    int rssi_count = 0;
    int8_t first_rssi = 0;
    int8_t last_rssi = 0;
    uint8_t presence_count = 0;
    
    for (uint8_t i = 0; i < storage_index.record_count; i++) {
        if (scan_storage_get_record(i, rec) != ESP_OK) continue;
        
        for (uint8_t j = 0; j < rec->header.ap_count; j++) {
            if (memcmp(rec->aps[j].bssid, bssid, 6) == 0) {
                presence_count++;
                rssi_sum += rec->aps[j].rssi;
                rssi_count++;
                
                if (first_rssi == 0) first_rssi = rec->aps[j].rssi;
                last_rssi = rec->aps[j].rssi;
                
                strncpy(summary->ssid, (char*)rec->aps[j].ssid, 32);
                summary->channel = rec->aps[j].channel;
                summary->station_count = rec->aps[j].station_count;
                break;
            }
        }
    }
    
    free(rec);
    
    if (rssi_count > 0) {
        summary->rssi_avg = rssi_sum / rssi_count;
        summary->rssi_trend = last_rssi - first_rssi;
    }
    
    summary->stability = (storage_index.record_count > 0) ? 
                         (presence_count * 100 / storage_index.record_count) : 0;
    
    return ESP_OK;
}

static uint32_t get_uptime_sec(void) {
    return (uint32_t)(esp_timer_get_time() / 1000000ULL);
}

static uint32_t calculate_device_priority(const device_presence_t *dev, uint32_t now, uint32_t epoch_now, bool time_ok) {
    uint32_t priority = 0;

    uint32_t sightings = (dev->total_sightings > 100) ? 100 : dev->total_sightings;
    priority += sightings * 10;

    if (DEVICE_IS_HOME(dev->flags)) {
        priority += 10000;
    }

    if (DEVICE_IS_KNOWN(dev->flags)) {
        priority += 500;
    }

    uint32_t last_seen_ago = UINT32_MAX;
    if (time_ok && DEVICE_EPOCH_VALID(dev->flags) && dev->last_seen_epoch > 0 && dev->last_seen_epoch <= epoch_now) {
        last_seen_ago = epoch_now - dev->last_seen_epoch;
    } else if (dev->last_seen > 0 && dev->last_seen <= now) {
        last_seen_ago = now - dev->last_seen;
    }

    if (last_seen_ago < 300) {
        priority += 500;
    } else if (last_seen_ago < 3600) {
        priority += 300;
    } else if (last_seen_ago < 86400) {
        priority += 100;
    }

    if (dev->first_seen > 0 && dev->first_seen <= now) {
        uint32_t age_days = (now - dev->first_seen) / 86400;
        priority += (age_days > 20) ? 200 : (age_days * 10);
    }

    return priority;
}

// Find and evict the lowest priority device to make room for a new one
// Returns true if eviction was successful
static bool evict_lowest_priority_device(void) {
    if (tracked_device_count < MAX_TRACKED_DEVICES) {
        return true; // No eviction needed
    }

    uint32_t now = get_uptime_sec();
    bool time_ok = pwnpower_time_is_synced();
    uint32_t epoch_now = 0;
    if (time_ok) {
        time_t t;
        time(&t);
        if (t > 0) epoch_now = (uint32_t)t;
        else time_ok = false;
    }

    int lowest_idx = -1;
    uint32_t lowest_priority = UINT32_MAX;

    // Find device with lowest priority score
    for (int i = 0; i < tracked_device_count; i++) {
        uint32_t priority = calculate_device_priority(&tracked_devices[i], now, epoch_now, time_ok);

        if (priority < lowest_priority) {
            lowest_priority = priority;
            lowest_idx = i;
        }
    }

    if (lowest_idx < 0) {
        ESP_LOGW(TAG, "failed to find device to evict");
        return false;
    }

    // Log eviction for debugging
    ESP_LOGI(TAG, "evicting device %02X:%02X:%02X:%02X:%02X:%02X (priority=%lu, sightings=%u, home=%d) to make room",
             tracked_devices[lowest_idx].mac[0], tracked_devices[lowest_idx].mac[1],
             tracked_devices[lowest_idx].mac[2], tracked_devices[lowest_idx].mac[3],
             tracked_devices[lowest_idx].mac[4], tracked_devices[lowest_idx].mac[5],
             (unsigned long)lowest_priority,
             tracked_devices[lowest_idx].total_sightings,
             DEVICE_IS_HOME(tracked_devices[lowest_idx].flags) ? 1 : 0);

    // Shift array to remove evicted device
    if (lowest_idx < tracked_device_count - 1) {
        memmove(&tracked_devices[lowest_idx],
                &tracked_devices[lowest_idx + 1],
                sizeof(device_presence_t) * (tracked_device_count - lowest_idx - 1));
    }

    tracked_device_count--;
    return true;
}

esp_err_t scan_storage_update_device_presence(const uint8_t *mac, int8_t rssi, const char *ap_ssid) {
    if (!mac) return ESP_ERR_INVALID_ARG;

    uint32_t now = get_uptime_sec();
    uint8_t hour = (now / 3600) % 24;

    bool time_ok = pwnpower_time_is_synced();
    uint32_t epoch_now = 0;
    if (time_ok) {
        time_t t;
        time(&t);
        if (t > 0) epoch_now = (uint32_t)t;
        else time_ok = false;
    }

    // Check if device is on home network (connected SSID or any extra home SSID)
    bool is_home_device = false;
    if (ap_ssid && ap_ssid[0]) {
        if (connected_ssid[0] && strcmp(ap_ssid, connected_ssid) == 0) {
            is_home_device = true;
            ESP_LOGD(TAG, "Device matched connected_ssid: '%s'", ap_ssid);
        }
        for (int i = 0; i < MAX_EXTRA_HOME_SSIDS && !is_home_device; i++) {
            if (extra_home_ssids[i][0] && strcmp(ap_ssid, extra_home_ssids[i]) == 0) {
                is_home_device = true;
                ESP_LOGD(TAG, "Device matched extra_home_ssid[%d]: '%s'", i, ap_ssid);
            }
        }
        if (!is_home_device && (connected_ssid[0] || extra_home_ssids[0][0])) {
            ESP_LOGD(TAG, "SSID mismatch - ap_ssid:'%s' (len=%zu) vs connected:'%s' (len=%zu)",
                     ap_ssid, strlen(ap_ssid), connected_ssid, strlen(connected_ssid));
        }
    }

    // get vendor for lifecycle
    char vendor[48] = "Unknown";
    ouis_lookup_vendor(mac, vendor, sizeof(vendor));

    // update lifecycle tracking (generates events as needed)
    device_lifecycle_update(mac, rssi, ap_ssid, vendor);

    bool device_modified = false;
    bool new_device_added = false;

    // Update existing device
    for (int i = 0; i < tracked_device_count; i++) {
        if (memcmp(tracked_devices[i].mac, mac, 6) == 0) {
            tracked_devices[i].last_seen = now;
            if (tracked_devices[i].total_sightings < UINT16_MAX) {
                tracked_devices[i].total_sightings++;
            }
            tracked_devices[i].rssi_avg = (tracked_devices[i].rssi_avg + rssi) / 2;
            device_set_presence_hour(tracked_devices[i].presence_hours, hour);

            // Update epoch timestamps
            if (time_ok) {
                tracked_devices[i].last_seen_epoch = epoch_now;
                if (tracked_devices[i].first_seen_epoch == 0 && tracked_devices[i].first_seen > 0 && tracked_devices[i].first_seen <= now) {
                    tracked_devices[i].first_seen_epoch = epoch_now - (now - tracked_devices[i].first_seen);
                }
                tracked_devices[i].flags |= DEVICE_FLAG_EPOCH_VALID;
            }

            // Mark as home device if on home network, clear if not
            if (is_home_device) {
                tracked_devices[i].flags |= DEVICE_FLAG_HOME_DEVICE;
            } else if (ap_ssid && ap_ssid[0]) {
                tracked_devices[i].flags &= ~DEVICE_FLAG_HOME_DEVICE;
            }

            // Update AP association if provided
            if (ap_ssid && ap_ssid[0]) {
                strncpy(tracked_devices[i].last_ap_ssid, ap_ssid, sizeof(tracked_devices[i].last_ap_ssid) - 1);
                tracked_devices[i].last_ap_ssid[sizeof(tracked_devices[i].last_ap_ssid) - 1] = '\0';
            }

            device_modified = true;
            break;
        }
    }

    // Add new device (with smart eviction if needed)
    if (!device_modified) {
        // Make room if needed
        if (tracked_device_count >= MAX_TRACKED_DEVICES) {
            if (!evict_lowest_priority_device()) {
                ESP_LOGW(TAG, "failed to evict device, cannot track new device");
                return ESP_ERR_NO_MEM;
            }
        }

        device_presence_t *dev = &tracked_devices[tracked_device_count];
        memset(dev, 0, sizeof(device_presence_t));

        memcpy(dev->mac, mac, 6);
        dev->first_seen = now;
        dev->last_seen = now;
        dev->total_sightings = 1;
        dev->rssi_avg = rssi;

        // Initialize flags
        dev->flags = 0;
        DEVICE_SET_TYPE(dev->flags, 0);  // Unknown device type
        if (time_ok) {
            dev->flags |= DEVICE_FLAG_EPOCH_VALID;
        }
        if (is_home_device) {
            dev->flags |= DEVICE_FLAG_HOME_DEVICE;
            ESP_LOGI(TAG, "new home device detected: %02X:%02X:%02X:%02X:%02X:%02X on %s",
                     mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ap_ssid);
        }

        dev->first_seen_epoch = time_ok ? epoch_now : 0;
        dev->last_seen_epoch = time_ok ? epoch_now : 0;

        device_clear_presence_hours(dev->presence_hours);
        device_set_presence_hour(dev->presence_hours, hour);

        strncpy(dev->vendor, vendor, sizeof(dev->vendor) - 1);
        dev->vendor[sizeof(dev->vendor) - 1] = '\0';

        dev->associated_ap_count = 0;
        memset(dev->associated_aps, 0, sizeof(dev->associated_aps));

        // Set AP SSID if provided
        if (ap_ssid && ap_ssid[0]) {
            strncpy(dev->last_ap_ssid, ap_ssid, sizeof(dev->last_ap_ssid) - 1);
            dev->last_ap_ssid[sizeof(dev->last_ap_ssid) - 1] = '\0';
        } else {
            dev->last_ap_ssid[0] = '\0';
        }

        tracked_device_count++;
        device_modified = true;
        new_device_added = true;
    }

    // periodically save tracked devices to flash to persist across reboots
    if (device_modified) {
        device_updates_since_save++;
        if (new_device_added || device_updates_since_save >= DEVICE_SAVE_INTERVAL) {
            save_tracked_devices();
            device_updates_since_save = 0;
        }
    }

    return ESP_OK;
}

esp_err_t scan_storage_get_device_presence(const uint8_t *mac, device_presence_t *out) {
    if (!mac || !out) return ESP_ERR_INVALID_ARG;
    
    for (int i = 0; i < tracked_device_count; i++) {
        if (memcmp(tracked_devices[i].mac, mac, 6) == 0) {
            memcpy(out, &tracked_devices[i], sizeof(device_presence_t));
            return ESP_OK;
        }
    }
    return ESP_ERR_NOT_FOUND;
}

const char* scan_storage_get_device_presence_json(void) {
    static char buf[6144];
    int pos = 0;
    uint32_t now = get_uptime_sec();

    bool time_ok = pwnpower_time_is_synced();
    uint32_t epoch_now = 0;
    if (time_ok) {
        time_t t;
        time(&t);
        if (t > 0) epoch_now = (uint32_t)t;
        else time_ok = false;
    }
    
    pos += snprintf(buf + pos, sizeof(buf) - pos, "{\"devices\":[");
    
    for (int i = 0; i < tracked_device_count && pos < (int)sizeof(buf) - 400; i++) {
        device_presence_t *dev = &tracked_devices[i];
        
        uint32_t last_seen_ago;
        bool is_present;
        if (time_ok && DEVICE_EPOCH_VALID(dev->flags) && dev->last_seen_epoch > 0 && dev->last_seen_epoch <= epoch_now) {
            last_seen_ago = epoch_now - dev->last_seen_epoch;
            is_present = (last_seen_ago < 300);
        } else if (dev->last_seen > 0 && dev->last_seen <= now) {
            last_seen_ago = now - dev->last_seen;
            is_present = (last_seen_ago < 300);
        } else {
            last_seen_ago = UINT32_MAX;
            is_present = false;
        }
        
        if (i > 0) pos += snprintf(buf + pos, sizeof(buf) - pos, ",");
        pos += snprintf(buf + pos, sizeof(buf) - pos,
            "{\"mac\":\"%02X:%02X:%02X:%02X:%02X:%02X\","
            "\"rssi\":%d,\"first_seen\":%lu,\"last_seen_ago\":%lu,"
            "\"last_seen_epoch\":%lu,\"epoch_valid\":%lu,"
            "\"sightings\":%lu,\"present\":%s,\"known\":%s,"
            "\"vendor\":\"%s\",\"last_ap\":\"%s\"}",
            dev->mac[0], dev->mac[1], dev->mac[2],
            dev->mac[3], dev->mac[4], dev->mac[5],
            dev->rssi_avg, (unsigned long)dev->first_seen,
            (unsigned long)last_seen_ago, (unsigned long)dev->total_sightings,
            (unsigned long)dev->last_seen_epoch, (unsigned long)DEVICE_EPOCH_VALID(dev->flags),
            is_present ? "true" : "false",
            DEVICE_IS_KNOWN(dev->flags) ? "true" : "false",
            dev->vendor,
            dev->last_ap_ssid[0] ? dev->last_ap_ssid : "Unknown");
    }
    
    int present_count = 0;
    for (int i = 0; i < tracked_device_count; i++) {
        device_presence_t *dev = &tracked_devices[i];
        if (time_ok && DEVICE_EPOCH_VALID(dev->flags) && dev->last_seen_epoch > 0 && dev->last_seen_epoch <= epoch_now) {
            if ((epoch_now - dev->last_seen_epoch) < 300) present_count++;
        } else if (dev->last_seen > 0 && dev->last_seen <= now) {
            if ((now - dev->last_seen) < 300) present_count++;
        }
    }
    
    pos += snprintf(buf + pos, sizeof(buf) - pos, 
        "],\"total_tracked\":%d,\"currently_present\":%d}",
        tracked_device_count, present_count);
    
    return buf;
}

void scan_storage_set_home_ssid(const char *ssid) {
    if (!ssid || ssid[0] == '\0') {
        ESP_LOGW(TAG, "attempted to set empty home SSID");
        return;
    }

    if (strcmp(connected_ssid, ssid) != 0) {
        strncpy(connected_ssid, ssid, sizeof(connected_ssid) - 1);
        connected_ssid[sizeof(connected_ssid) - 1] = '\0';
        ESP_LOGI(TAG, "Connected home network set to: %s", connected_ssid);
    }
}

const char* scan_storage_get_home_ssid(void) {
    return connected_ssid[0] ? connected_ssid : NULL;
}

static void recalculate_all_home_device_flags(void) {
    int updated_count = 0;
    int cleared_count = 0;
    
    ESP_LOGI(TAG, "Recalculating home flags for %d devices", tracked_device_count);
    ESP_LOGI(TAG, "Connected SSID: '%s'", connected_ssid[0] ? connected_ssid : "(none)");
    for (int j = 0; j < MAX_EXTRA_HOME_SSIDS; j++) {
        if (extra_home_ssids[j][0]) {
            ESP_LOGI(TAG, "Extra home SSID[%d]: '%s'", j, extra_home_ssids[j]);
        }
    }
    
    for (int i = 0; i < tracked_device_count; i++) {
        if (!tracked_devices[i].last_ap_ssid[0]) continue;
        
        bool should_be_home = false;
        if (connected_ssid[0] && strcmp(tracked_devices[i].last_ap_ssid, connected_ssid) == 0) {
            should_be_home = true;
        }
        for (int j = 0; j < MAX_EXTRA_HOME_SSIDS && !should_be_home; j++) {
            if (extra_home_ssids[j][0] && strcmp(tracked_devices[i].last_ap_ssid, extra_home_ssids[j]) == 0) {
                should_be_home = true;
            }
        }
        
        bool currently_home = (tracked_devices[i].flags & DEVICE_FLAG_HOME_DEVICE) != 0;
        
        if (should_be_home && !currently_home) {
            tracked_devices[i].flags |= DEVICE_FLAG_HOME_DEVICE;
            updated_count++;
            ESP_LOGI(TAG, "SET home flag for %02X:%02X:%02X:%02X:%02X:%02X (AP: %s)",
                     tracked_devices[i].mac[0], tracked_devices[i].mac[1], tracked_devices[i].mac[2],
                     tracked_devices[i].mac[3], tracked_devices[i].mac[4], tracked_devices[i].mac[5],
                     tracked_devices[i].last_ap_ssid);
        } else if (!should_be_home && currently_home) {
            tracked_devices[i].flags &= ~DEVICE_FLAG_HOME_DEVICE;
            cleared_count++;
            ESP_LOGI(TAG, "CLEARED home flag for %02X:%02X:%02X:%02X:%02X:%02X (AP: %s)",
                     tracked_devices[i].mac[0], tracked_devices[i].mac[1], tracked_devices[i].mac[2],
                     tracked_devices[i].mac[3], tracked_devices[i].mac[4], tracked_devices[i].mac[5],
                     tracked_devices[i].last_ap_ssid);
        }
    }
    
    if (updated_count > 0 || cleared_count > 0) {
        save_tracked_devices();
        ESP_LOGI(TAG, "Recalculated home flags: %d set, %d cleared", updated_count, cleared_count);
    } else {
        ESP_LOGI(TAG, "No home flag changes needed");
    }
}

esp_err_t scan_storage_add_extra_home_ssid(const char *ssid) {
    if (!ssid || ssid[0] == '\0') return ESP_ERR_INVALID_ARG;
    
    // check if already exists
    for (int i = 0; i < MAX_EXTRA_HOME_SSIDS; i++) {
        if (extra_home_ssids[i][0] && strcmp(extra_home_ssids[i], ssid) == 0) {
            return ESP_OK;  // already in list
        }
    }
    
    // find empty slot
    for (int i = 0; i < MAX_EXTRA_HOME_SSIDS; i++) {
        if (extra_home_ssids[i][0] == '\0') {
            strncpy(extra_home_ssids[i], ssid, 32);
            extra_home_ssids[i][32] = '\0';
            ESP_LOGI(TAG, "Added extra home SSID: %s", ssid);
            
            // persist to NVS
            nvs_handle_t handle;
            esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &handle);
            if (err == ESP_OK) {
                char key[16];
                snprintf(key, sizeof(key), "home_ssid_%d", i);
                nvs_set_str(handle, key, ssid);
                nvs_commit(handle);
                nvs_close(handle);
            }
            
            recalculate_all_home_device_flags();
            return ESP_OK;
        }
    }
    
    return ESP_ERR_NO_MEM;  // no free slots
}

esp_err_t scan_storage_remove_extra_home_ssid(const char *ssid) {
    if (!ssid || ssid[0] == '\0') return ESP_ERR_INVALID_ARG;
    
    for (int i = 0; i < MAX_EXTRA_HOME_SSIDS; i++) {
        if (extra_home_ssids[i][0] && strcmp(extra_home_ssids[i], ssid) == 0) {
            extra_home_ssids[i][0] = '\0';
            ESP_LOGI(TAG, "Removed extra home SSID: %s", ssid);
            
            // clear from NVS
            nvs_handle_t handle;
            esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &handle);
            if (err == ESP_OK) {
                char key[16];
                snprintf(key, sizeof(key), "home_ssid_%d", i);
                nvs_erase_key(handle, key);
                nvs_commit(handle);
                nvs_close(handle);
            }
            
            recalculate_all_home_device_flags();
            return ESP_OK;
        }
    }
    
    return ESP_ERR_NOT_FOUND;
}

const char* scan_storage_get_extra_home_ssids_json(void) {
    static char buf[256];
    int pos = snprintf(buf, sizeof(buf), "[");
    bool first = true;
    
    for (int i = 0; i < MAX_EXTRA_HOME_SSIDS; i++) {
        if (extra_home_ssids[i][0]) {
            pos += snprintf(buf + pos, sizeof(buf) - pos, "%s\"%s\"", first ? "" : ",", extra_home_ssids[i]);
            first = false;
        }
    }
    
    snprintf(buf + pos, sizeof(buf) - pos, "]");
    return buf;
}

void scan_storage_refresh_home_flags(void) {
    recalculate_all_home_device_flags();
}

esp_err_t scan_storage_set_device_home(const uint8_t *mac, bool is_home) {
    if (!mac) return ESP_ERR_INVALID_ARG;
    
    for (int i = 0; i < tracked_device_count; i++) {
        if (memcmp(tracked_devices[i].mac, mac, 6) == 0) {
            if (is_home) {
                tracked_devices[i].flags |= DEVICE_FLAG_HOME_DEVICE;
            } else {
                tracked_devices[i].flags &= ~DEVICE_FLAG_HOME_DEVICE;
            }
            save_tracked_devices();
            return ESP_OK;
        }
    }
    return ESP_ERR_NOT_FOUND;
}

esp_err_t scan_storage_detect_rogue_aps(void) {
    scan_record_t *rec = malloc(sizeof(scan_record_t));
    if (!rec) return ESP_ERR_NO_MEM;

    if (scan_storage_get_latest(rec) != ESP_OK) {
        free(rec);
        return ESP_FAIL;
    }

    rogue_ap_count = 0;

    // Only auto-detect if home SSID not set (no connected network)
    // Prefer connected network set via scan_storage_set_home_ssid()
    if (connected_ssid[0] == '\0' && rec->header.ap_count > 0) {
        int8_t strongest_rssi = -127;
        int strongest_idx = -1;
        for (uint8_t i = 0; i < rec->header.ap_count; i++) {
            if (rec->aps[i].rssi > strongest_rssi && rec->aps[i].ssid[0] != '\0') {
                strongest_rssi = rec->aps[i].rssi;
                strongest_idx = i;
            }
        }
        if (strongest_idx >= 0) {
            strncpy(connected_ssid, (char*)rec->aps[strongest_idx].ssid, 32);
            ESP_LOGI(TAG, "Auto-detected home SSID: %s (fallback - strongest signal)", connected_ssid);
        }
    }
    
    if (connected_ssid[0] != '\0') {
        uint8_t home_bssid[6] = {0};
        bool found_home = false;
        
        for (uint8_t i = 0; i < rec->header.ap_count; i++) {
            if (strcmp((char*)rec->aps[i].ssid, connected_ssid) == 0) {
                if (!found_home) {
                    memcpy(home_bssid, rec->aps[i].bssid, 6);
                    found_home = true;
                } else {
                    if (memcmp(rec->aps[i].bssid, home_bssid, 6) != 0) {
                        rogue_ap_count++;
                        ESP_LOGW(TAG, "Potential rogue AP detected: %s with different BSSID", connected_ssid);
                    }
                }
            }
        }
    }
    
    free(rec);
    return ESP_OK;
}

esp_err_t scan_storage_update_security_events(uint32_t deauth_count) {
    deauth_events_hour = deauth_count;
    return ESP_OK;
}

const char* scan_storage_get_intelligence_json(void) {
    uint32_t now = get_uptime_sec();
    
    int devices_present = 0;
    int devices_away = 0;
    int new_devices_today = 0;
    bool time_ok = pwnpower_time_is_synced();
    uint32_t epoch_now = 0;
    uint32_t today_start = 0;
    if (time_ok) {
        time_t t;
        time(&t);
        if (t > 0) epoch_now = (uint32_t)t;
        else time_ok = false;
    }
    if (time_ok) {
        today_start = (epoch_now / 86400) * 86400;
    } else {
        today_start = (now / 86400) * 86400;
    }
    
    for (int i = 0; i < tracked_device_count; i++) {
        device_presence_t *dev = &tracked_devices[i];

        if (time_ok && DEVICE_EPOCH_VALID(dev->flags) && dev->last_seen_epoch > 0 && dev->last_seen_epoch <= epoch_now) {
            if ((epoch_now - dev->last_seen_epoch) < 300) devices_present++;
            else devices_away++;
        } else if (dev->last_seen > 0 && dev->last_seen <= now) {
            if ((now - dev->last_seen) < 300) devices_present++;
            else devices_away++;
        } else {
            devices_away++;
        }

        if (time_ok && DEVICE_EPOCH_VALID(dev->flags) && dev->first_seen_epoch > 0 && dev->first_seen_epoch <= epoch_now) {
            if (dev->first_seen_epoch >= today_start) new_devices_today++;
        } else if (!time_ok && dev->first_seen > 0 && dev->first_seen <= now) {
            if (dev->first_seen >= today_start) new_devices_today++;
        }
    }
    
    scan_record_t *rec = malloc(sizeof(scan_record_t));
    int hidden_count = 0;
    int open_count = 0;
    int strongest_signal = -127;
    char strongest_ap[33] = "N/A";
    
    if (rec && scan_storage_get_latest(rec) == ESP_OK) {
        for (uint8_t i = 0; i < rec->header.ap_count; i++) {
            if (rec->aps[i].hidden) hidden_count++;
            if (rec->aps[i].auth_mode == 0) open_count++;
            if (rec->aps[i].rssi > strongest_signal) {
                strongest_signal = rec->aps[i].rssi;
                strncpy(strongest_ap, (char*)rec->aps[i].ssid, 32);
            }
        }
    }
    if (rec) free(rec);
    
    snprintf(intelligence_json, sizeof(intelligence_json),
        "{"
        "\"presence\":{\"devices_present\":%d,\"devices_away\":%d,\"new_today\":%d},"
        "\"security\":{\"deauth_events\":%lu,\"rogue_aps\":%lu,\"open_networks\":%d,\"hidden_networks\":%d},"
        "\"network\":{\"home_ssid\":\"%s\",\"strongest_ap\":\"%s\",\"strongest_rssi\":%d},"
        "\"uptime_hours\":%.1f"
        "}",
        devices_present, devices_away, new_devices_today,
        (unsigned long)deauth_events_hour, (unsigned long)rogue_ap_count, open_count, hidden_count,
        connected_ssid[0] ? connected_ssid : "Not set", strongest_ap, strongest_signal,
        now / 3600.0);
    
    return intelligence_json;
}

esp_err_t scan_storage_send_unified_intelligence_chunked(httpd_req_t *req) {
    char chunk[512];
    uint32_t now = get_uptime_sec();
    
    // Calculate presence stats
    int devices_present = 0, devices_away = 0, new_devices_today = 0;
    bool time_ok = pwnpower_time_is_synced();
    uint32_t epoch_now = 0, today_start = 0;
    
    if (time_ok) {
        time_t t;
        time(&t);
        if (t > 0) epoch_now = (uint32_t)t;
        else time_ok = false;
    }
    if (time_ok) today_start = (epoch_now / 86400) * 86400;
    else today_start = (now / 86400) * 86400;
    
    for (int i = 0; i < tracked_device_count; i++) {
        device_presence_t *dev = &tracked_devices[i];
        if (time_ok && DEVICE_EPOCH_VALID(dev->flags) && dev->last_seen_epoch > 0 && dev->last_seen_epoch <= epoch_now) {
            if ((epoch_now - dev->last_seen_epoch) < 300) devices_present++;
            else devices_away++;
        } else if (dev->last_seen > 0 && dev->last_seen <= now) {
            if ((now - dev->last_seen) < 300) devices_present++;
            else devices_away++;
        } else devices_away++;
        
        if (time_ok && DEVICE_EPOCH_VALID(dev->flags) && dev->first_seen_epoch > 0 && dev->first_seen_epoch <= epoch_now) {
            if (dev->first_seen_epoch >= today_start) new_devices_today++;
        } else if (!time_ok && dev->first_seen > 0 && dev->first_seen <= now) {
            if (dev->first_seen >= today_start) new_devices_today++;
        }
    }
    
    // Get network stats
    scan_record_t *rec = malloc(sizeof(scan_record_t));
    int hidden_count = 0, open_count = 0, unique_aps = 0, unique_stations = 0, active_channels = 0;
    
    if (rec && scan_storage_get_latest(rec) == ESP_OK) {
        unique_aps = rec->header.ap_count;
        unique_stations = rec->header.total_stations;
        bool channels[14] = {false};
        for (uint8_t i = 0; i < rec->header.ap_count; i++) {
            if (rec->aps[i].hidden) hidden_count++;
            if (rec->aps[i].auth_mode == 0) open_count++;
            if (rec->aps[i].channel > 0 && rec->aps[i].channel < 14) channels[rec->aps[i].channel] = true;
        }
        for (int i = 1; i < 14; i++) if (channels[i]) active_channels++;
    }
    if (rec) free(rec);
    
    // Send summary
    int len = snprintf(chunk, sizeof(chunk),
        "{\"summary\":{\"presence\":{\"devices_present\":%d,\"devices_away\":%d,\"new_today\":%d},"
        "\"security\":{\"deauth_events\":%lu,\"rogue_aps\":%lu,\"open_networks\":%d,\"hidden_networks\":%d},"
        "\"network\":{\"unique_aps\":%d,\"unique_stations\":%d,\"active_channels\":%d},"
        "\"uptime_hours\":%.1f,\"time_synced\":%s,\"epoch_now\":%lu},\"devices\":[",
        devices_present, devices_away, new_devices_today,
        (unsigned long)deauth_events_hour, (unsigned long)rogue_ap_count, open_count, hidden_count,
        unique_aps, unique_stations, active_channels, now / 3600.0,
        time_ok ? "true" : "false", (unsigned long)epoch_now);
    if (httpd_resp_send_chunk(req, chunk, len) != ESP_OK) return ESP_FAIL;
    
    // Stream devices one at a time
    scan_record_t *ap_rec = malloc(sizeof(scan_record_t));
    bool has_aps = (ap_rec && scan_storage_get_latest(ap_rec) == ESP_OK);
    
    for (int i = 0; i < tracked_device_count; i++) {
        device_presence_t *dev = &tracked_devices[i];
        
        uint32_t last_seen_ago;
        bool is_present;
        if (time_ok && DEVICE_EPOCH_VALID(dev->flags) && dev->last_seen_epoch > 0 && dev->last_seen_epoch <= epoch_now) {
            last_seen_ago = epoch_now - dev->last_seen_epoch;
            is_present = (last_seen_ago < 300);
        } else if (dev->last_seen > 0 && dev->last_seen <= now) {
            last_seen_ago = now - dev->last_seen;
            is_present = (last_seen_ago < 300);
        } else {
            last_seen_ago = UINT32_MAX;
            is_present = false;
        }
        
        uint8_t trust_score = 10;
        if (dev->total_sightings > 100) trust_score += 40;
        else if (dev->total_sightings > 50) trust_score += 30;
        else if (dev->total_sightings > 20) trust_score += 20;
        else if (dev->total_sightings > 10) trust_score += 10;
        if (dev->total_sightings >= 2 && trust_score <= 30) trust_score = 35;
        if (DEVICE_IS_KNOWN(dev->flags)) trust_score += 30;
        if (dev->first_seen > 0 && dev->first_seen <= now) {
            uint32_t days = (now - dev->first_seen) / 86400;
            if (days >= 7) trust_score += 20;
            else if (days >= 3) trust_score += 10;
        }
        if (trust_score > 100) trust_score = 100;
        
        uint32_t days_tracked = 1;
        if (dev->first_seen > 0 && dev->first_seen <= now) days_tracked = ((now - dev->first_seen) / 86400) + 1;
        
        len = snprintf(chunk, sizeof(chunk),
            "%s{\"mac\":\"%02X:%02X:%02X:%02X:%02X:%02X\",\"vendor\":\"%s\",\"trust_score\":%u,"
            "\"present\":%s,\"rssi\":%d,\"sightings\":%lu,\"last_seen_ago\":%lu,\"last_seen_epoch\":%lu,"
            "\"epoch_valid\":%u,\"last_ap\":\"%s\",\"tracked\":%s,\"home_device\":%s,\"days_tracked\":%lu,"
            "\"presence_hours\":[%u,%u,%u],\"associated_ap_count\":%u,\"associated_aps\":[",
            i > 0 ? "," : "",
            dev->mac[0], dev->mac[1], dev->mac[2], dev->mac[3], dev->mac[4], dev->mac[5],
            dev->vendor, trust_score, is_present ? "true" : "false", dev->rssi_avg,
            (unsigned long)dev->total_sightings, (unsigned long)last_seen_ago, (unsigned long)dev->last_seen_epoch,
            (unsigned)DEVICE_EPOCH_VALID(dev->flags), dev->last_ap_ssid[0] ? dev->last_ap_ssid : "unknown",
            DEVICE_IS_KNOWN(dev->flags) ? "true" : "false", DEVICE_IS_HOME(dev->flags) ? "true" : "false",
            (unsigned long)days_tracked, dev->presence_hours[0], dev->presence_hours[1], dev->presence_hours[2],
            dev->associated_ap_count);
        if (httpd_resp_send_chunk(req, chunk, len) != ESP_OK) { if (ap_rec) free(ap_rec); return ESP_FAIL; }
        
        // Send associated APs
        for (uint8_t ap_idx = 0; ap_idx < dev->associated_ap_count && ap_idx < 8; ap_idx++) {
            char ssid[33] = "Unknown";
            if (has_aps) {
                for (uint8_t s = 0; s < ap_rec->header.ap_count; s++) {
                    if (memcmp(ap_rec->aps[s].bssid, dev->associated_aps[ap_idx], 6) == 0) {
                        strncpy(ssid, (char*)ap_rec->aps[s].ssid, 32);
                        ssid[32] = '\0';
                        break;
                    }
                }
            }
            len = snprintf(chunk, sizeof(chunk), "%s{\"ssid\":\"%s\",\"bssid\":\"%02X:%02X:%02X:%02X:%02X:%02X\"}",
                ap_idx > 0 ? "," : "", ssid,
                dev->associated_aps[ap_idx][0], dev->associated_aps[ap_idx][1], dev->associated_aps[ap_idx][2],
                dev->associated_aps[ap_idx][3], dev->associated_aps[ap_idx][4], dev->associated_aps[ap_idx][5]);
            if (httpd_resp_send_chunk(req, chunk, len) != ESP_OK) { if (ap_rec) free(ap_rec); return ESP_FAIL; }
        }
        
        if (httpd_resp_send_chunk(req, "]}", 2) != ESP_OK) { if (ap_rec) free(ap_rec); return ESP_FAIL; }
    }
    if (ap_rec) free(ap_rec);
    
    // Close JSON
    if (httpd_resp_send_chunk(req, "]}", 2) != ESP_OK) return ESP_FAIL;
    if (httpd_resp_send_chunk(req, NULL, 0) != ESP_OK) return ESP_FAIL;
    
    return ESP_OK;
}

const char* scan_storage_get_unified_intelligence_json(void) {
    static char unified_buf[6144];
    snprintf(unified_buf, sizeof(unified_buf), "{\"error\":\"deprecated - use chunked endpoint\"}");
    return unified_buf;
}

// history sample ring buffer implementation
static uint32_t last_history_epoch = 0;
static uint32_t last_history_uptime = 0;

uint32_t scan_storage_get_history_base_epoch(void) {
    return storage_index.history_base_epoch;
}

void scan_storage_set_history_base_epoch(uint32_t epoch) {
    storage_index.history_base_epoch = epoch;
    write_storage_index();
}

esp_err_t scan_storage_append_history_sample(const history_sample_t *sample) {
    if (!sample) return ESP_ERR_INVALID_ARG;
    
    uint32_t current_epoch = 0;
    if (HISTORY_IS_TIME_VALID(sample->flags) && storage_index.history_base_epoch > 0) {
        current_epoch = storage_index.history_base_epoch + sample->timestamp_delta_sec;
    }
    
    if (current_epoch > 0 && current_epoch == last_history_epoch) {
        ESP_LOGD(TAG, "skipping duplicate history sample epoch=%lu", (unsigned long)current_epoch);
        return ESP_OK;
    }
    if (current_epoch == 0 && sample->timestamp_delta_sec == last_history_uptime && sample->timestamp_delta_sec != 0) {
        ESP_LOGD(TAG, "skipping duplicate history sample delta=%u", sample->timestamp_delta_sec);
        return ESP_OK;
    }
    
    ESP_LOGI(TAG, "writing history sample: delta=%u aps=%u clients=%u flags=0x%02x",
             sample->timestamp_delta_sec, sample->ap_count, sample->client_count, sample->flags);
    
    esp_err_t err = flash_manager_ring_write(&flash_mgr, &history_ring, sample);
    if (err != ESP_OK) {
        return err;
    }
    
    last_history_epoch = current_epoch;
    last_history_uptime = sample->timestamp_delta_sec;
    
    storage_index.history_write_idx = history_ring.write_idx;
    storage_index.history_count = history_ring.count;
    err = write_storage_index();
    
    return err;
}


static uint32_t sanitize_history_samples(history_sample_t *samples, uint32_t count) {
    ESP_LOGI(TAG, "sanitize_history_samples: input count=%u", count);
    if (count == 0) return 0;

    uint32_t valid_count = 0;
    uint32_t last_epoch = 0;
    uint32_t last_uptime = 0;
    bool last_time_valid = false;
    bool have_prev = false;
    uint32_t base_epoch = storage_index.history_base_epoch;

    for (uint32_t i = 0; i < count; i++) {
        history_sample_t *src = &samples[i];

        if (src->ap_count >= 200 || src->client_count >= 250) {
            ESP_LOGD(TAG, "filter sample %u: garbage data (ap=%u, clients=%u)", i, src->ap_count, src->client_count);
            continue;
        }
        if (src->timestamp_delta_sec == 0 && !HISTORY_IS_TIME_VALID(src->flags)) {
            ESP_LOGD(TAG, "filter sample %u: zero timestamp delta", i);
            continue;
        }
        if (src->timestamp_delta_sec == 0xFFFF) {
            ESP_LOGD(TAG, "filter sample %u: FF timestamp delta", i);
            continue;
        }

        bool channel_corrupted = false;
        for (int ch = 0; ch < 13; ch++) {
            if (src->channel_counts[ch] == 255) {
                channel_corrupted = true;
                break;
            }
        }
        if (channel_corrupted) {
            ESP_LOGD(TAG, "filter sample %u: corrupted channel_counts", i);
            continue;
        }

        uint32_t epoch_ts = 0;
        bool time_valid = HISTORY_IS_TIME_VALID(src->flags);
        if (time_valid && base_epoch > 0) {
            epoch_ts = base_epoch + src->timestamp_delta_sec;
        }
        if (time_valid && epoch_ts > 0 && epoch_ts < 1700000000) {
            ESP_LOGD(TAG, "filter sample %u: stale epoch %lu", i, (unsigned long)epoch_ts);
            src->flags &= ~HISTORY_FLAG_TIME_VALID;
            time_valid = false;
        }

        bool is_dup = false;
        if (have_prev) {
            if (time_valid && last_time_valid && epoch_ts == last_epoch) {
                is_dup = true;
            } else if (!time_valid && !last_time_valid && src->timestamp_delta_sec == last_uptime) {
                is_dup = true;
            }
        }
        if (is_dup) {
            ESP_LOGD(TAG, "dedup sample %u", i);
            continue;
        }

        if (valid_count != i) {
            memcpy(&samples[valid_count], src, sizeof(history_sample_t));
            src = &samples[valid_count];
        }

        last_epoch = epoch_ts;
        last_uptime = src->timestamp_delta_sec;
        last_time_valid = time_valid;
        have_prev = true;
        valid_count++;
    }

    ESP_LOGI(TAG, "sanitize_history_samples: final count=%u", valid_count);
    return valid_count;
}

esp_err_t scan_storage_get_history_samples_window(uint32_t start_idx, uint32_t max_count, history_sample_t *samples, uint32_t *actual_count) {
    if (!samples || !actual_count) return ESP_ERR_INVALID_ARG;
    
    uint32_t total = history_ring.count;
    if (start_idx >= total || max_count == 0) {
        *actual_count = 0;
        return ESP_OK;
    }
    
    uint32_t count = max_count;
    if (start_idx + count > total) {
        count = total - start_idx;
    }
    
    esp_err_t err = flash_manager_ring_read(&flash_mgr, &history_ring, start_idx, count, samples, actual_count);
    if (err != ESP_OK) return err;
    
    *actual_count = sanitize_history_samples(samples, *actual_count);
    return ESP_OK;
}

esp_err_t scan_storage_get_history_samples(uint32_t max_count, history_sample_t *samples, uint32_t *actual_count) {
    if (!samples || !actual_count) return ESP_ERR_INVALID_ARG;
    uint32_t total = history_ring.count;
    uint32_t start_idx = (total > max_count) ? (total - max_count) : 0;
    return scan_storage_get_history_samples_window(start_idx, max_count, samples, actual_count);
}

uint32_t scan_storage_get_history_count(void) {
    return history_ring.count;
}

// device event ring buffer implementation
esp_err_t scan_storage_append_device_event(const device_event_t *event) {
    if (!event) return ESP_ERR_INVALID_ARG;
    
    // use flash manager ring buffer helper
    esp_err_t err = flash_manager_ring_write(&flash_mgr, &events_ring, event);
    if (err != ESP_OK) {
        return err;
    }
    
    // update index and persist
    storage_index.event_write_idx = events_ring.write_idx;
    storage_index.event_count = events_ring.count;
    err = write_storage_index();
    
    return err;
}

esp_err_t scan_storage_get_device_events(uint32_t start_idx, uint32_t max_count, device_event_t *events, uint32_t *actual_count) {
    if (!events || !actual_count) return ESP_ERR_INVALID_ARG;
    
    // use flash manager ring buffer helper
    return flash_manager_ring_read(&flash_mgr, &events_ring, start_idx, max_count, events, actual_count);
}

uint32_t scan_storage_get_event_count(void) {
    return events_ring.count;
}

uint32_t scan_storage_get_event_write_idx(void) {
    return events_ring.write_idx;
}

esp_err_t scan_storage_flush_devices(void) {
    return save_tracked_devices();
}
