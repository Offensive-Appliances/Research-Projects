#ifndef SCAN_STORAGE_H
#define SCAN_STORAGE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define SCAN_STORAGE_PARTITION "scandata"
#define SCAN_MAGIC 0x50574E53  // "PWNS"
#define SCAN_VERSION 1
#define MAX_APS_PER_SCAN 16
#define MAX_STATIONS_PER_AP 8
#define MAX_SCAN_HISTORY 1

typedef struct __attribute__((packed)) {
    uint8_t mac[6];
    int8_t rssi;
    int8_t last_rssi;
    uint32_t first_seen;
    uint32_t last_seen;
    uint16_t frame_count;
} stored_station_t;

typedef struct __attribute__((packed)) {
    uint8_t bssid[6];
    uint8_t ssid[33];
    uint8_t channel;
    uint8_t auth_mode;
    int8_t rssi;
    int8_t rssi_min;
    int8_t rssi_max;
    uint8_t station_count;
    uint32_t first_seen;
    uint32_t last_seen;
    uint16_t beacon_count;
    uint8_t hidden;
    stored_station_t stations[MAX_STATIONS_PER_AP];
} stored_ap_t;

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint8_t version;
    uint8_t ap_count;
    uint16_t scan_duration_sec;
    uint32_t timestamp;
    uint32_t uptime_sec;
    uint8_t scan_type;      // 0=full, 1=quick, 2=targeted
    uint8_t channel_mask;   // which channels were scanned
    uint16_t total_stations;
    uint16_t total_frames;
    uint32_t crc32;
} scan_header_t;

typedef struct __attribute__((packed)) {
    scan_header_t header;
    stored_ap_t aps[MAX_APS_PER_SCAN];
} scan_record_t;

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint8_t version;
    uint8_t record_count;
    uint16_t write_index;
    uint32_t total_scans;
    uint32_t first_boot;
    uint32_t last_scan;
} storage_index_t;

typedef struct {
    uint8_t bssid[6];
    char ssid[33];
    uint8_t channel;
    int8_t rssi_avg;
    int8_t rssi_trend;      // positive = improving, negative = degrading
    uint32_t uptime_sec;    // how long this AP has been seen
    uint8_t stability;      // 0-100 score based on presence consistency
    uint8_t station_count;
    bool is_new;
    bool is_gone;
    uint32_t last_seen_sec;
    uint8_t device_type;    // 0=unknown, 1=phone, 2=laptop, 3=iot
} ap_summary_t;

typedef struct {
    uint8_t mac[6];
    uint32_t first_seen;
    uint32_t last_seen;
    uint32_t total_sightings;
    int8_t rssi_avg;
    uint8_t device_type;
    char vendor[24];
    bool is_known;
    uint32_t presence_hours[24];  // Hourly presence pattern
    uint8_t associated_ap_count;
    uint8_t associated_aps[8][6]; // Up to 8 APs this device connects to
    char last_ap_ssid[33];        // Last seen AP SSID
} device_presence_t;

typedef struct {
    uint32_t scan_count;
    uint32_t total_aps_seen;
    uint32_t total_stations_seen;
    uint32_t current_aps;
    uint32_t current_stations;
    uint32_t new_aps_last_hour;
    uint32_t gone_aps_last_hour;
    uint32_t monitoring_duration_sec;
    uint32_t deauth_events_last_hour;
    uint32_t rogue_aps_detected;
    uint32_t known_devices_present;
} network_stats_t;

esp_err_t scan_storage_init(void);
esp_err_t scan_storage_save(scan_record_t *record);
esp_err_t scan_storage_get_latest(scan_record_t *record);
esp_err_t scan_storage_get_record(uint8_t index, scan_record_t *record);
esp_err_t scan_storage_get_stats(network_stats_t *stats);
esp_err_t scan_storage_clear(void);
uint8_t scan_storage_get_count(void);
const char* scan_storage_get_report_json(void);
const char* scan_storage_get_timeline_json(uint8_t hours);
esp_err_t scan_storage_get_ap_history(const uint8_t *bssid, ap_summary_t *summary);

// Analytics functions
esp_err_t scan_storage_update_device_presence(const uint8_t *mac, int8_t rssi, const char *ap_ssid);
const char* scan_storage_get_device_presence_json(void);
esp_err_t scan_storage_detect_rogue_aps(void);
esp_err_t scan_storage_update_security_events(uint32_t deauth_count);
const char* scan_storage_get_intelligence_json(void);

#endif
