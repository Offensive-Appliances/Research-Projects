#ifndef WIFI_SCAN_H
#define WIFI_SCAN_H

#include <stdint.h>   // Needed for uint8_t
#include <stddef.h>   // Needed for size_t
#include <stdbool.h>  // Needed for bool
#include "esp_wifi_types.h"
#include "freertos/semphr.h"
#include "scan_storage.h"

void wifi_scan();
bool wifi_scan_start_async(void);
const char* wifi_scan_get_results();
bool wifi_scan_is_complete();
bool wifi_scan_is_in_progress();
bool wifi_scan_station_scan_running();
uint32_t wifi_scan_get_results_timestamp();
bool wifi_scan_was_truncated();
bool wifi_scan_has_new_results();
void wifi_scan_update_ui_cache_from_record(const scan_record_t *record);
extern const uint8_t* get_scan_channels(void);
extern const size_t get_scan_channels_size(void);

typedef struct {
    uint8_t station_mac[6];
    uint8_t ap_bssid[6];
    int channel;
    int rssi;
    char device_vendor[64];
    char device_fingerprint[128];
    uint32_t probe_count;
    uint32_t last_seen;
    bool has_fingerprint;
    bool is_grouped;
    uint8_t grouped_mac_count;
    uint8_t grouped_macs[5][6];
} station_info_t;

void wifi_scan_stations();
const char* wifi_scan_get_station_results();

const char* mac_to_str(const uint8_t *mac);

bool wifi_scan_is_station_scan_active(void);
void wifi_scan_set_station_scan_active(bool active);

uint32_t wifi_scan_get_deauth_count(void);
uint32_t wifi_scan_get_deauth_last_seen(void);
void wifi_scan_reset_deauth_count(void);
void wifi_scan_increment_deauth_count(void);
const char* wifi_scan_get_security_stats_json(void);
int wifi_scan_probe_hidden_aps(void);
void wifi_scan_register_hidden_ap(const uint8_t *bssid, uint8_t channel);

// Smart channel weighting functions
uint32_t get_channel_dwell_time(uint8_t channel, bool is_background_scan);
void update_channel_activity(uint8_t channel, uint32_t devices_found, int8_t *rssi_values, uint32_t rssi_count);

// Channel weighting constants
#define RSSI_CUTOFF_THRESHOLD -85  // Ignore networks weaker than -85 dBm

// Channel tracking variables (shared with background_scan)
extern uint32_t channel_scan_counts[14];
extern uint32_t channel_discovery_counts[14];
extern uint32_t last_channel_update;

// Memory management
void wifi_scan_cleanup(void);
void wifi_scan_init_memory(void);
void wifi_scan_cleanup_station_json(void);

#endif
