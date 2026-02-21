#ifndef SCAN_STORAGE_H
#define SCAN_STORAGE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "esp_err.h"

// Forward declaration to avoid including web server headers
struct httpd_req;
typedef struct httpd_req httpd_req_t;

#define SCAN_STORAGE_PARTITION "scandata"
#define SCAN_MAGIC 0x50574E53  // "PWNS"
#define SCAN_VERSION 5
#define MAX_APS_PER_SCAN 32
#define MAX_STATIONS_PER_AP 8
#define MAX_SCAN_HISTORY 1
#define MAX_HISTORY_SAMPLES 13500
#define MAX_DEVICE_EVENTS 512
#define MAX_SSID_CLIENTS_PER_SAMPLE 6

typedef struct __attribute__((packed)) {
    uint32_t ssid_hash;
    uint8_t client_count;
} ssid_client_entry_t;

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
    uint8_t wps_enabled;
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
// Optimized to ~50 bytes per sample for ~5 days in 768KB partition
// UPDATED: Now using 32-bit absolute timestamp (SCAN_VERSION 3)
typedef struct __attribute__((packed)) {
    uint32_t timestamp;            // absolute unix epoch timestamp
    uint8_t flags;                 // bit0=time_valid, bits1-3=ssid_count (0-6), bits4-7=reserved
    uint8_t ap_count;
    uint8_t client_count;          // clamped to 255
    uint8_t top_channels[7];       // Channel IDs of the top 7 most congested channels
    uint8_t top_counts[7];         // Device counts for the top 7 channels
    ssid_client_entry_t ssid_clients[MAX_SSID_CLIENTS_PER_SAMPLE];
    uint8_t crc8;                  // CRC8 integrity check (computed over all preceding fields)
} history_sample_t;

// Helper macros for history_sample_t flags
#define HISTORY_FLAG_TIME_VALID     (1 << 0)
#define HISTORY_FLAG_SSID_COUNT_MASK 0x0E
#define HISTORY_FLAG_SSID_COUNT_SHIFT 1
#define HISTORY_GET_SSID_COUNT(flags) (((flags) & HISTORY_FLAG_SSID_COUNT_MASK) >> HISTORY_FLAG_SSID_COUNT_SHIFT)
#define HISTORY_SET_SSID_COUNT(flags, count) ((flags) = ((flags) & ~HISTORY_FLAG_SSID_COUNT_MASK) | (((count) & 0x07) << HISTORY_FLAG_SSID_COUNT_SHIFT))
#define HISTORY_IS_TIME_VALID(flags) ((flags) & HISTORY_FLAG_TIME_VALID)

// CRC8 integrity check for history samples
uint8_t history_sample_crc8(const history_sample_t *sample);

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
    char vendor[64];
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
    char vendor[64];
    bool is_known;
    uint32_t presence_hours[24];  // Hourly presence pattern
    uint8_t associated_ap_count;
    uint8_t associated_aps[8][6]; // Up to 8 APs this device connects to
    char last_ap_ssid[33];        // Last seen AP SSID
} device_presence_v1_t;

typedef struct __attribute__((packed)) {
    uint8_t mac[6];
    uint32_t first_seen;
    uint32_t last_seen;
    uint16_t total_sightings;
    int8_t rssi_avg;
    uint8_t flags;
    char vendor[64];
    uint8_t presence_hours[3];
    uint8_t associated_ap_count;
    uint8_t associated_aps[8][6];
    char last_ap_ssid[33];
    uint32_t first_seen_epoch;
    uint32_t last_seen_epoch;
} device_presence_t;

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

// Shared scan record buffer (defined in scan_storage.c, used across multiple files)
extern scan_record_t shared_scan_buffer;

// Pending background scan record for queuing updates during manual scans
extern scan_record_t pending_background_record;

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
esp_err_t scan_storage_send_unified_intelligence_chunked(httpd_req_t *req);

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
