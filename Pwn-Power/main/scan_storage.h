#ifndef SCAN_STORAGE_H
#define SCAN_STORAGE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "esp_err.h"

#define SCAN_STORAGE_PARTITION "scandata"
#define SCAN_MAGIC 0x50574E53  // "PWNS"
#define SCAN_VERSION 2
#define MAX_APS_PER_SCAN 16
#define MAX_STATIONS_PER_AP 8
#define MAX_SCAN_HISTORY 1

// Optimized storage allocation in 896KB scandata partition:
// - Scan record: ~11KB (reusable)
// - History samples: 30 days at 2-min cadence = ~21600 samples × 32 bytes = ~691KB
// - Device events: 512 events × 44 bytes = ~22KB
// - Device tracking: Moved to dedicated offset for better flash utilization
// Total: ~724KB used, ~172KB free
#define MAX_HISTORY_SAMPLES 21600
#define MAX_DEVICE_EVENTS 512

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
    uint32_t epoch_ts;      // unix epoch timestamp (if time_valid)
    uint8_t time_valid;     // 1 if epoch_ts is valid
    uint8_t _reserved[3];
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
    uint32_t history_write_idx;
    uint32_t history_count;
    uint32_t event_write_idx;
    uint32_t event_count;
} storage_index_t;

// compact history sample for charts (fixed size ring buffer)
typedef struct __attribute__((packed)) {
    uint32_t epoch_ts;      // unix epoch timestamp
    uint32_t uptime_sec;    // uptime in seconds
    uint8_t time_valid;     // 1 if epoch_ts is valid
    uint8_t ap_count;
    uint16_t client_count;
    uint8_t channel_counts[13];  // ap count per channel 1-13
    uint8_t _reserved[3];
} history_sample_t;

// device lifecycle event (fixed size ring buffer)
typedef struct __attribute__((packed)) {
    uint32_t epoch_ts;      // unix epoch timestamp
    uint32_t uptime_sec;    // uptime in seconds
    uint8_t time_valid;     // 1 if epoch_ts is valid
    uint8_t event_type;     // 0=first_seen, 1=arrived, 2=left, 3=returned
    uint8_t mac[6];
    int8_t rssi;
    uint8_t trust_score;    // 0-100
    uint8_t tracked;        // 1 if tracked
    uint8_t device_flags;   // DEVICE_FLAG_* from device_presence_t
    char vendor[24];
    uint8_t _reserved[2];
} device_event_t;

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
} device_presence_v1_t;

// Optimized device presence tracking structure
// Reduced from 235 bytes to 131 bytes per device (44% smaller!)
typedef struct __attribute__((packed)) {
    uint8_t mac[6];                     // 6 bytes - Device MAC address
    uint32_t first_seen;                // 4 bytes - First seen uptime
    uint32_t last_seen;                 // 4 bytes - Last seen uptime
    uint16_t total_sightings;           // 2 bytes - Total sightings (was 4, max 65k is plenty)
    int8_t rssi_avg;                    // 1 byte - Average RSSI
    uint8_t flags;                      // 1 byte - Packed: device_type(4bit) | is_known(1bit) | epoch_valid(1bit) | reserved(2bit)
    char vendor[16];                    // 16 bytes - Vendor string (reduced from 24)
    uint8_t presence_hours[3];          // 3 bytes - Bit-packed hourly presence (1 bit per hour, 0-23)
    uint8_t associated_ap_count;        // 1 byte - Number of associated APs
    uint8_t associated_aps[8][6];       // 48 bytes - Up to 8 APs this device connects to
    char last_ap_ssid[33];              // 33 bytes - Last seen AP SSID
    uint32_t first_seen_epoch;          // 4 bytes - First seen epoch timestamp
    uint32_t last_seen_epoch;           // 4 bytes - Last seen epoch timestamp
} device_presence_t;                    // Total: 131 bytes (was 235)

// Flag bit positions
#define DEVICE_FLAG_IS_KNOWN        (1 << 0)
#define DEVICE_FLAG_EPOCH_VALID     (1 << 1)
#define DEVICE_FLAG_HOME_DEVICE     (1 << 2)  // Device belongs to home network
#define DEVICE_FLAG_DEVICE_TYPE_MASK 0xF0
#define DEVICE_FLAG_DEVICE_TYPE_SHIFT 4

// Helper macros for flag manipulation
#define DEVICE_GET_TYPE(flags)      (((flags) & DEVICE_FLAG_DEVICE_TYPE_MASK) >> DEVICE_FLAG_DEVICE_TYPE_SHIFT)
#define DEVICE_SET_TYPE(flags, type) ((flags) = ((flags) & ~DEVICE_FLAG_DEVICE_TYPE_MASK) | (((type) & 0x0F) << DEVICE_FLAG_DEVICE_TYPE_SHIFT))
#define DEVICE_IS_KNOWN(flags)      ((flags) & DEVICE_FLAG_IS_KNOWN)
#define DEVICE_EPOCH_VALID(flags)   ((flags) & DEVICE_FLAG_EPOCH_VALID)
#define DEVICE_IS_HOME(flags)       ((flags) & DEVICE_FLAG_HOME_DEVICE)

// Helper functions for presence_hours bit packing
static inline void device_set_presence_hour(uint8_t *hours, uint8_t hour) {
    if (hour < 24) hours[hour / 8] |= (1 << (hour % 8));
}
static inline bool device_get_presence_hour(const uint8_t *hours, uint8_t hour) {
    if (hour >= 24) return false;
    return (hours[hour / 8] & (1 << (hour % 8))) != 0;
}
static inline void device_clear_presence_hours(uint8_t *hours) {
    hours[0] = hours[1] = hours[2] = 0;
}

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
esp_err_t scan_storage_get_device_presence(const uint8_t *mac, device_presence_t *out);
const char* scan_storage_get_device_presence_json(void);
esp_err_t scan_storage_detect_rogue_aps(void);
esp_err_t scan_storage_update_security_events(uint32_t deauth_count);
const char* scan_storage_get_intelligence_json(void);
const char* scan_storage_get_unified_intelligence_json(void);

// history sample ring buffer
esp_err_t scan_storage_append_history_sample(const history_sample_t *sample);
esp_err_t scan_storage_get_history_samples(uint32_t max_count, history_sample_t *samples, uint32_t *actual_count);
esp_err_t scan_storage_get_history_samples_window(uint32_t start_idx, uint32_t max_count, history_sample_t *samples, uint32_t *actual_count);
uint32_t scan_storage_get_history_count(void);

// device event ring buffer
esp_err_t scan_storage_append_device_event(const device_event_t *event);
esp_err_t scan_storage_get_device_events(uint32_t start_idx, uint32_t max_count, device_event_t *events, uint32_t *actual_count);
uint32_t scan_storage_get_event_count(void);
uint32_t scan_storage_get_event_write_idx(void);

// device persistence
esp_err_t scan_storage_flush_devices(void);

// home network management
void scan_storage_set_home_ssid(const char *ssid);
const char* scan_storage_get_home_ssid(void);
esp_err_t scan_storage_add_extra_home_ssid(const char *ssid);
esp_err_t scan_storage_remove_extra_home_ssid(const char *ssid);
const char* scan_storage_get_extra_home_ssids_json(void);
void scan_storage_refresh_home_flags(void);

// device flag management
esp_err_t scan_storage_set_device_home(const uint8_t *mac, bool is_home);

#endif
