#ifndef WIFI_SCAN_H
#define WIFI_SCAN_H

#include <stdint.h>   // Needed for uint8_t
#include <stddef.h>   // Needed for size_t
#include <stdbool.h>  // Needed for bool
#include "esp_wifi_types.h"
#include "freertos/semphr.h"
#include "scan_storage.h"

void wifi_scan();
const char* wifi_scan_get_results();
bool wifi_scan_is_complete();
bool wifi_scan_has_new_results();
void wifi_scan_update_ui_cache_from_record(const scan_record_t *record);
extern const uint8_t dual_band_channels[];
extern const size_t dual_band_channels_size;

typedef struct {
    uint8_t station_mac[6];
    uint8_t ap_bssid[6];
    int channel;
    int rssi;
} station_info_t;

void wifi_scan_stations();
const char* wifi_scan_get_station_results();

const char* mac_to_str(const uint8_t *mac);

bool wifi_scan_is_station_scan_active(void);
void wifi_scan_set_station_scan_active(bool active);

uint32_t wifi_scan_get_deauth_count(void);
uint32_t wifi_scan_get_deauth_last_seen(void);
void wifi_scan_reset_deauth_count(void);
const char* wifi_scan_get_security_stats_json(void);
int wifi_scan_probe_hidden_aps(void);
void wifi_scan_register_hidden_ap(const uint8_t *bssid, uint8_t channel);

#endif
