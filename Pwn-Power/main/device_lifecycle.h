#ifndef DEVICE_LIFECYCLE_H
#define DEVICE_LIFECYCLE_H

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

#define PRESENCE_TIMEOUT_SEC 300

typedef enum {
    DEVICE_EVENT_FIRST_SEEN = 0,
    DEVICE_EVENT_ARRIVED = 1,
    DEVICE_EVENT_LEFT = 2,
    DEVICE_EVENT_RETURNED = 3,
    DEVICE_EVENT_DEAUTH_DETECTED = 4,
    DEVICE_EVENT_HANDSHAKE_CAPTURED = 5
} device_event_type_t;

// trust score ranges (auto-calculated)
// 0-30:   new/unknown device
// 31-50:  familiar device (seen a few times)
// 51-70:  known device (regular visitor)
// 71-100: trusted device (long-term regular)

// initialize device lifecycle tracking
esp_err_t device_lifecycle_init(void);

// update device presence (called when device is seen in scan)
// generates events as needed and stores them in scan_storage
esp_err_t device_lifecycle_update(const uint8_t *mac, int8_t rssi, const char *ap_ssid, const char *vendor);

// periodic check for devices that left (called by background task)
esp_err_t device_lifecycle_check_departures(void);

// get current presence status
bool device_lifecycle_is_present(const uint8_t *mac);

// restore device history from persisted storage (prevents first_seen events on reboot)
esp_err_t device_lifecycle_restore_device(const uint8_t *mac);

// generate security event alerts
void device_lifecycle_generate_deauth_event(const uint8_t *mac, uint32_t deauth_count);
void device_lifecycle_generate_batched_deauth_alert(uint32_t total_deauth_count, uint32_t scan_duration_sec);
void device_lifecycle_generate_handshake_event(const uint8_t *bssid, const uint8_t *client_mac, int eapol_count);

#endif
