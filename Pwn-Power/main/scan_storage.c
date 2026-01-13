#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "scan_storage.h"
#include "esp_partition.h"
#include "esp_log.h"
#include "esp_crc.h"
#include "esp_timer.h"
#include "cJSON.h"
#include "ouis.h"
#include <string.h>
#include <stddef.h>

#define TAG "ScanStorage"
#define RECORD_SIZE sizeof(scan_record_t)
#define INDEX_OFFSET 0
#define DATA_OFFSET 4096

static const esp_partition_t *scan_partition = NULL;
static SemaphoreHandle_t storage_mutex = NULL;
static storage_index_t storage_index;
static char report_json[4096];
static char intelligence_json[2048];

#define MAX_TRACKED_DEVICES 32
static device_presence_t tracked_devices[MAX_TRACKED_DEVICES];
static int tracked_device_count = 0;

static uint32_t deauth_events_hour = 0;
static uint32_t rogue_ap_count = 0;
static char home_ssid[33] = {0};

static uint32_t calc_record_crc(const scan_record_t *rec) {
    uint32_t crc = 0;
    size_t crc_offset = offsetof(scan_record_t, header) + offsetof(scan_header_t, crc32);
    crc = esp_crc32_le(crc, (const uint8_t*)rec, crc_offset);
    crc = esp_crc32_le(crc, (const uint8_t*)rec + crc_offset + sizeof(uint32_t), 
                       sizeof(scan_record_t) - crc_offset - sizeof(uint32_t));
    return crc;
}

esp_err_t scan_storage_init(void) {
    if (storage_mutex == NULL) {
        storage_mutex = xSemaphoreCreateMutex();
    }

    scan_partition = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, 0x99, SCAN_STORAGE_PARTITION);
    if (!scan_partition) {
        ESP_LOGE(TAG, "Scan data partition not found");
        return ESP_ERR_NOT_FOUND;
    }

    ESP_LOGI(TAG, "Found partition '%s' at 0x%lx, size %lu KB", 
             scan_partition->label, 
             (unsigned long)scan_partition->address,
             (unsigned long)scan_partition->size / 1024);

    esp_err_t err = esp_partition_read(scan_partition, INDEX_OFFSET, &storage_index, sizeof(storage_index_t));
    if (err != ESP_OK || storage_index.magic != SCAN_MAGIC) {
        ESP_LOGI(TAG, "Initializing fresh scan storage");
        memset(&storage_index, 0, sizeof(storage_index_t));
        storage_index.magic = SCAN_MAGIC;
        storage_index.version = SCAN_VERSION;
        storage_index.first_boot = 0;
        
        err = esp_partition_erase_range(scan_partition, 0, scan_partition->size);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "Failed to erase partition: %s", esp_err_to_name(err));
            return err;
        }
        
        err = esp_partition_write(scan_partition, INDEX_OFFSET, &storage_index, sizeof(storage_index_t));
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "Failed to write index: %s", esp_err_to_name(err));
            return err;
        }
    } else {
        ESP_LOGI(TAG, "Loaded storage index: %lu total scans, %u records", 
                 (unsigned long)storage_index.total_scans, storage_index.record_count);
    }

    return ESP_OK;
}

esp_err_t scan_storage_save(scan_record_t *record) {
    if (!scan_partition || !record) return ESP_ERR_INVALID_ARG;

    xSemaphoreTake(storage_mutex, portMAX_DELAY);

    scan_record_t *existing = malloc(sizeof(scan_record_t));
    bool has_existing = false;
    
    if (existing && storage_index.record_count > 0) {
        uint32_t read_offset = DATA_OFFSET;
        if (esp_partition_read(scan_partition, read_offset, existing, sizeof(scan_record_t)) == ESP_OK) {
            if (existing->header.magic == SCAN_MAGIC) {
                uint32_t expected_crc = calc_record_crc(existing);
                if (existing->header.crc32 == expected_crc) {
                    has_existing = true;
                }
            }
        }
    }
    
    if (has_existing) {
        for (uint8_t i = 0; i < record->header.ap_count; i++) {
            stored_ap_t *new_ap = &record->aps[i];
            bool found = false;
            
            for (uint8_t j = 0; j < existing->header.ap_count; j++) {
                if (memcmp(existing->aps[j].bssid, new_ap->bssid, 6) == 0) {
                    found = true;
                    existing->aps[j].last_seen = new_ap->last_seen;
                    existing->aps[j].beacon_count += new_ap->beacon_count;
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
                                existing->aps[j].stations[t].frame_count += new_ap->stations[s].frame_count;
                                break;
                            }
                        }
                        if (!sta_found && existing->aps[j].station_count < MAX_STATIONS_PER_AP) {
                            memcpy(&existing->aps[j].stations[existing->aps[j].station_count], 
                                   &new_ap->stations[s], sizeof(stored_station_t));
                            existing->aps[j].station_count++;
                            existing->header.total_stations++;
                        }
                    }
                    break;
                }
            }
            
            if (!found && existing->header.ap_count < MAX_APS_PER_SCAN) {
                memcpy(&existing->aps[existing->header.ap_count], new_ap, sizeof(stored_ap_t));
                existing->header.ap_count++;
                existing->header.total_stations += new_ap->station_count;
            }
        }
        
        existing->header.timestamp = record->header.timestamp;
        existing->header.uptime_sec = record->header.uptime_sec;
        memcpy(record, existing, sizeof(scan_record_t));
    }
    
    if (existing) free(existing);

    record->header.magic = SCAN_MAGIC;
    record->header.version = SCAN_VERSION;
    record->header.crc32 = calc_record_crc(record);

    uint32_t offset = DATA_OFFSET;
    uint32_t sector_start = (offset / 4096) * 4096;
    uint32_t sectors_needed = ((offset + RECORD_SIZE - sector_start) + 4095) / 4096;
    
    esp_err_t err = esp_partition_erase_range(scan_partition, sector_start, sectors_needed * 4096);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Erase failed: %s", esp_err_to_name(err));
        xSemaphoreGive(storage_mutex);
        return err;
    }

    err = esp_partition_write(scan_partition, offset, record, sizeof(scan_record_t));
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Write failed: %s", esp_err_to_name(err));
        xSemaphoreGive(storage_mutex);
        return err;
    }

    storage_index.record_count = 1;
    storage_index.total_scans++;
    storage_index.last_scan = record->header.timestamp;
    
    if (storage_index.first_boot == 0) {
        storage_index.first_boot = record->header.timestamp;
    }

    err = esp_partition_erase_range(scan_partition, 0, 4096);
    if (err == ESP_OK) {
        err = esp_partition_write(scan_partition, INDEX_OFFSET, &storage_index, sizeof(storage_index_t));
    }

    xSemaphoreGive(storage_mutex);
    
    ESP_LOGI(TAG, "Saved scan record %lu (%u APs, %u stations)", 
             (unsigned long)storage_index.total_scans,
             record->header.ap_count,
             record->header.total_stations);

    return err;
}

esp_err_t scan_storage_get_latest(scan_record_t *record) {
    if (!scan_partition || !record || storage_index.record_count == 0) {
        return ESP_ERR_NOT_FOUND;
    }

    uint8_t idx = (storage_index.write_index == 0) ? 
                  (storage_index.record_count - 1) : 
                  (storage_index.write_index - 1);
    
    return scan_storage_get_record(idx, record);
}

esp_err_t scan_storage_get_record(uint8_t index, scan_record_t *record) {
    if (!scan_partition || !record || index >= storage_index.record_count) {
        return ESP_ERR_INVALID_ARG;
    }

    xSemaphoreTake(storage_mutex, portMAX_DELAY);

    uint32_t offset = DATA_OFFSET + (index * RECORD_SIZE);
    esp_err_t err = esp_partition_read(scan_partition, offset, record, sizeof(scan_record_t));
    
    xSemaphoreGive(storage_mutex);

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
    int present = 0;
    for (int i = 0; i < tracked_device_count; i++) {
        if ((now - tracked_devices[i].last_seen) < 300) present++;
    }
    stats->known_devices_present = present;

    return ESP_OK;
}

esp_err_t scan_storage_clear(void) {
    if (!scan_partition) return ESP_ERR_INVALID_STATE;

    xSemaphoreTake(storage_mutex, portMAX_DELAY);

    esp_err_t err = esp_partition_erase_range(scan_partition, 0, scan_partition->size);
    if (err == ESP_OK) {
        memset(&storage_index, 0, sizeof(storage_index_t));
        storage_index.magic = SCAN_MAGIC;
        storage_index.version = SCAN_VERSION;
        err = esp_partition_write(scan_partition, INDEX_OFFSET, &storage_index, sizeof(storage_index_t));
    }

    xSemaphoreGive(storage_mutex);
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

esp_err_t scan_storage_update_device_presence(const uint8_t *mac, int8_t rssi, const char *ap_ssid) {
    if (!mac) return ESP_ERR_INVALID_ARG;
    
    uint32_t now = get_uptime_sec();
    uint8_t hour = (now / 3600) % 24;
    
    for (int i = 0; i < tracked_device_count; i++) {
        if (memcmp(tracked_devices[i].mac, mac, 6) == 0) {
            tracked_devices[i].last_seen = now;
            tracked_devices[i].total_sightings++;
            tracked_devices[i].rssi_avg = (tracked_devices[i].rssi_avg + rssi) / 2;
            tracked_devices[i].presence_hours[hour]++;
            // Update AP association if provided
            if (ap_ssid && ap_ssid[0]) {
                strncpy(tracked_devices[i].last_ap_ssid, ap_ssid, sizeof(tracked_devices[i].last_ap_ssid) - 1);
                tracked_devices[i].last_ap_ssid[sizeof(tracked_devices[i].last_ap_ssid) - 1] = '\0';
            }
            return ESP_OK;
        }
    }
    
    if (tracked_device_count < MAX_TRACKED_DEVICES) {
        device_presence_t *dev = &tracked_devices[tracked_device_count];
        memcpy(dev->mac, mac, 6);
        dev->first_seen = now;
        dev->last_seen = now;
        dev->total_sightings = 1;
        dev->rssi_avg = rssi;
        dev->device_type = 0;
        dev->is_known = false;
        memset(dev->presence_hours, 0, sizeof(dev->presence_hours));
        dev->presence_hours[hour] = 1;
        
        // Vendor lookup
        char vendor[48] = "Unknown";
        ouis_lookup_vendor(mac, vendor, sizeof(vendor));
        strncpy(dev->vendor, vendor, sizeof(dev->vendor) - 1);
        
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
    }
    
    return ESP_OK;
}

const char* scan_storage_get_device_presence_json(void) {
    static char buf[4096];
    int pos = 0;
    uint32_t now = get_uptime_sec();
    
    pos += snprintf(buf + pos, sizeof(buf) - pos, "{\"devices\":[");
    
    for (int i = 0; i < tracked_device_count && pos < (int)sizeof(buf) - 400; i++) {
        device_presence_t *dev = &tracked_devices[i];
        uint32_t last_seen_ago = now - dev->last_seen;
        bool is_present = (last_seen_ago < 300);
        
        if (i > 0) pos += snprintf(buf + pos, sizeof(buf) - pos, ",");
        pos += snprintf(buf + pos, sizeof(buf) - pos,
            "{\"mac\":\"%02X:%02X:%02X:%02X:%02X:%02X\","
            "\"rssi\":%d,\"first_seen\":%lu,\"last_seen_ago\":%lu,"
            "\"sightings\":%lu,\"present\":%s,\"known\":%s,"
            "\"vendor\":\"%s\",\"last_ap\":\"%s\"}",
            dev->mac[0], dev->mac[1], dev->mac[2],
            dev->mac[3], dev->mac[4], dev->mac[5],
            dev->rssi_avg, (unsigned long)dev->first_seen,
            (unsigned long)last_seen_ago, (unsigned long)dev->total_sightings,
            is_present ? "true" : "false",
            dev->is_known ? "true" : "false",
            dev->vendor,
            dev->last_ap_ssid[0] ? dev->last_ap_ssid : "Unknown");
    }
    
    int present_count = 0;
    for (int i = 0; i < tracked_device_count; i++) {
        if ((now - tracked_devices[i].last_seen) < 300) present_count++;
    }
    
    pos += snprintf(buf + pos, sizeof(buf) - pos, 
        "],\"total_tracked\":%d,\"currently_present\":%d}",
        tracked_device_count, present_count);
    
    return buf;
}

esp_err_t scan_storage_detect_rogue_aps(void) {
    scan_record_t *rec = malloc(sizeof(scan_record_t));
    if (!rec) return ESP_ERR_NO_MEM;
    
    if (scan_storage_get_latest(rec) != ESP_OK) {
        free(rec);
        return ESP_FAIL;
    }
    
    rogue_ap_count = 0;
    
    if (home_ssid[0] == '\0' && rec->header.ap_count > 0) {
        int8_t strongest_rssi = -127;
        int strongest_idx = -1;
        for (uint8_t i = 0; i < rec->header.ap_count; i++) {
            if (rec->aps[i].rssi > strongest_rssi && rec->aps[i].ssid[0] != '\0') {
                strongest_rssi = rec->aps[i].rssi;
                strongest_idx = i;
            }
        }
        if (strongest_idx >= 0) {
            strncpy(home_ssid, (char*)rec->aps[strongest_idx].ssid, 32);
            ESP_LOGI(TAG, "Auto-detected home SSID: %s", home_ssid);
        }
    }
    
    if (home_ssid[0] != '\0') {
        uint8_t home_bssid[6] = {0};
        bool found_home = false;
        
        for (uint8_t i = 0; i < rec->header.ap_count; i++) {
            if (strcmp((char*)rec->aps[i].ssid, home_ssid) == 0) {
                if (!found_home) {
                    memcpy(home_bssid, rec->aps[i].bssid, 6);
                    found_home = true;
                } else {
                    if (memcmp(rec->aps[i].bssid, home_bssid, 6) != 0) {
                        rogue_ap_count++;
                        ESP_LOGW(TAG, "Potential rogue AP detected: %s with different BSSID", home_ssid);
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
    uint32_t today_start = (now / 86400) * 86400;
    
    for (int i = 0; i < tracked_device_count; i++) {
        if ((now - tracked_devices[i].last_seen) < 300) {
            devices_present++;
        } else {
            devices_away++;
        }
        if (tracked_devices[i].first_seen >= today_start) {
            new_devices_today++;
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
        home_ssid[0] ? home_ssid : "Not set", strongest_ap, strongest_signal,
        now / 3600.0);
    
    return intelligence_json;
}
