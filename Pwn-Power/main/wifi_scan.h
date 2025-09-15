#ifndef WIFI_SCAN_H
#define WIFI_SCAN_H

#include <stdint.h>   // Needed for uint8_t
#include <stddef.h>   // Needed for size_t
#include <stdbool.h>  // Needed for bool
#include "esp_wifi_types.h"
#include "freertos/semphr.h"

void wifi_scan();
const char* wifi_scan_get_results();
bool wifi_scan_is_complete();
bool wifi_scan_has_new_results();
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

#endif
