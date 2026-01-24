#include "device_lifecycle.h"
#include "device_db.h"
#include "scan_storage.h"
#include "webhook.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include <string.h>
#include <time.h>

#define TAG "DeviceLifecycle"
#define MAX_TRACKED_DEVICES 64

extern bool pwnpower_time_is_synced(void);

typedef struct {
    uint8_t mac[6];
    uint32_t last_seen_uptime;
    bool is_present;
    bool has_history;
} device_state_t;

static device_state_t device_states[MAX_TRACKED_DEVICES];
static int device_state_count = 0;
static SemaphoreHandle_t lifecycle_mutex = NULL;

static uint32_t get_uptime_sec(void) {
    return (uint32_t)(esp_timer_get_time() / 1000000ULL);
}

esp_err_t device_lifecycle_init(void) {
    if (lifecycle_mutex == NULL) {
        lifecycle_mutex = xSemaphoreCreateMutex();
    }
    memset(device_states, 0, sizeof(device_states));
    device_state_count = 0;
    ESP_LOGI(TAG, "Device lifecycle tracking initialized");
    return ESP_OK;
}

static device_state_t* find_or_create_state(const uint8_t *mac) {
    // find existing
    for (int i = 0; i < device_state_count; i++) {
        if (memcmp(device_states[i].mac, mac, 6) == 0) {
            return &device_states[i];
        }
    }
    
    // create new if space available
    if (device_state_count < MAX_TRACKED_DEVICES) {
        device_state_t *state = &device_states[device_state_count];
        memcpy(state->mac, mac, 6);
        state->last_seen_uptime = 0;
        state->is_present = false;
        state->has_history = false;
        device_state_count++;
        return state;
    }
    
    return NULL;
}

// calculate automatic trust score based on device behavior
static uint8_t calculate_trust_score(const device_state_t *state, uint32_t days_known) {
    // base score starts at 10 (unknown)
    uint8_t score = 10;
    
    // increase trust based on how long we've known the device
    if (days_known >= 30) score += 40;       // known for a month
    else if (days_known >= 14) score += 30;  // known for 2 weeks
    else if (days_known >= 7) score += 20;   // known for a week
    else if (days_known >= 3) score += 10;   // known for 3 days
    
    // increase trust if device has regular pattern (has been seen multiple times)
    if (state->has_history) {
        score += 20;  // returning device
    }
    
    // additional scoring could be added:
    // - consistent rssi location (not moving around)
    // - regular time patterns
    // - known vendor (not randomized mac)
    
    // cap at 100
    if (score > 100) score = 100;
    
    return score;
}

static void generate_event(const uint8_t *mac, device_event_type_t event_type, int8_t rssi, const char *vendor) {
    webhook_config_t webhook_config;
    if (webhook_get_config(&webhook_config) != ESP_OK || !webhook_config.enabled) {
        return;
    }
    
    device_event_t event;
    memset(&event, 0, sizeof(event));
    
    // set timestamp
    event.uptime_sec = get_uptime_sec();
    if (pwnpower_time_is_synced()) {
        time_t now;
        time(&now);
        event.epoch_ts = (uint32_t)now;
        event.time_valid = 1;
    } else {
        event.epoch_ts = 0;
        event.time_valid = 0;
    }
    
    // set event data
    memcpy(event.mac, mac, 6);
    event.event_type = event_type;
    event.rssi = rssi;
    
    // auto-calculate trust score based on device history
    device_settings_t settings;
    bool has_settings = (device_db_get(mac, &settings) == ESP_OK);
    
    // find device state for trust calculation
    device_state_t *state = NULL;
    for (int i = 0; i < device_state_count; i++) {
        if (memcmp(device_states[i].mac, mac, 6) == 0) {
            state = &device_states[i];
            break;
        }
    }
    
    // calculate days known (simplified - could be more accurate with real timestamps)
    uint32_t now_uptime = get_uptime_sec();
    uint32_t days_known = 0;
    if (state && state->has_history) {
        days_known = (now_uptime - state->last_seen_uptime) / 86400;
    }
    
    if (state) {
        event.trust_score = calculate_trust_score(state, days_known);
    } else {
        event.trust_score = 10;  // brand new device
    }
    
    // auto-track devices with trust > 50 (known devices)
    event.tracked = (event.trust_score > 50) ? 1 : 0;
    
    // look up device flags from presence data (home device status etc)
    device_presence_t presence;
    if (scan_storage_get_device_presence(mac, &presence) == ESP_OK) {
        event.device_flags = presence.flags;
    } else {
        event.device_flags = 0;
    }
    
    // save/update trust score in db
    if (!has_settings) {
        memcpy(settings.mac, mac, 6);
        settings.name[0] = '\0';
    }
    settings.trust_score = event.trust_score;
    settings.tracked = (event.trust_score > 50);
    device_db_set(&settings);
    
    // copy vendor
    if (vendor) {
        strncpy(event.vendor, vendor, sizeof(event.vendor) - 1);
    }
    
    // append to storage
    esp_err_t err = scan_storage_append_device_event(&event);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to append event: %s", esp_err_to_name(err));
    } else {
        const char *event_names[] = {"first_seen", "arrived", "left", "returned"};
        const char *trust_label = (event.trust_score > 70) ? "trusted" : 
                                  (event.trust_score > 50) ? "known" : 
                                  (event.trust_score > 30) ? "familiar" : "new";
        ESP_LOGI(TAG, "Event: %s for %02X:%02X:%02X:%02X:%02X:%02X (trust=%u/%s)",
                 event_names[event_type],
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
                 event.trust_score, trust_label);
    }
}

esp_err_t device_lifecycle_update(const uint8_t *mac, int8_t rssi, const char *ap_ssid, const char *vendor) {
    if (!mac) return ESP_ERR_INVALID_ARG;
    
    xSemaphoreTake(lifecycle_mutex, portMAX_DELAY);
    
    device_state_t *state = find_or_create_state(mac);
    if (!state) {
        xSemaphoreGive(lifecycle_mutex);
        ESP_LOGW(TAG, "Device state table full");
        return ESP_ERR_NO_MEM;
    }
    
    uint32_t now = get_uptime_sec();
    bool was_present = state->is_present;
    bool was_recently_seen = (now - state->last_seen_uptime) < PRESENCE_TIMEOUT_SEC;
    
    // update state
    state->last_seen_uptime = now;
    state->is_present = true;
    
    // determine event type
    if (!state->has_history) {
        // first time seeing this device
        generate_event(mac, DEVICE_EVENT_FIRST_SEEN, rssi, vendor);
        state->has_history = true;
    } else if (!was_present && !was_recently_seen) {
        // device returned after being away
        generate_event(mac, DEVICE_EVENT_RETURNED, rssi, vendor);
    } else if (!was_present && was_recently_seen) {
        // Device transitioned to present (was temporarily absent)
        generate_event(mac, DEVICE_EVENT_ARRIVED, rssi, vendor);
    }
    // else: still present, no event needed
    
    xSemaphoreGive(lifecycle_mutex);
    return ESP_OK;
}

esp_err_t device_lifecycle_check_departures(void) {
    xSemaphoreTake(lifecycle_mutex, portMAX_DELAY);
    
    uint32_t now = get_uptime_sec();
    
    for (int i = 0; i < device_state_count; i++) {
        device_state_t *state = &device_states[i];
        
        if (state->is_present) {
            // check if device has left (not seen within timeout)
            if ((now - state->last_seen_uptime) >= PRESENCE_TIMEOUT_SEC) {
                state->is_present = false;
                generate_event(state->mac, DEVICE_EVENT_LEFT, 0, NULL);
            }
        }
    }
    
    xSemaphoreGive(lifecycle_mutex);
    return ESP_OK;
}

bool device_lifecycle_is_present(const uint8_t *mac) {
    if (!mac) return false;
    
    xSemaphoreTake(lifecycle_mutex, portMAX_DELAY);
    
    uint32_t now = get_uptime_sec();
    
    for (int i = 0; i < device_state_count; i++) {
        if (memcmp(device_states[i].mac, mac, 6) == 0) {
            bool present = (now - device_states[i].last_seen_uptime) < PRESENCE_TIMEOUT_SEC;
            xSemaphoreGive(lifecycle_mutex);
            return present;
        }
    }
    
    xSemaphoreGive(lifecycle_mutex);
    return false;
}

esp_err_t device_lifecycle_restore_device(const uint8_t *mac) {
    if (!mac) return ESP_ERR_INVALID_ARG;
    
    xSemaphoreTake(lifecycle_mutex, portMAX_DELAY);
    
    device_state_t *state = find_or_create_state(mac);
    if (!state) {
        xSemaphoreGive(lifecycle_mutex);
        return ESP_ERR_NO_MEM;
    }
    
    state->has_history = true;
    state->is_present = false;
    state->last_seen_uptime = 0;
    
    xSemaphoreGive(lifecycle_mutex);
    return ESP_OK;
}

void device_lifecycle_generate_deauth_event(const uint8_t *mac, uint32_t deauth_count) {
    webhook_config_t webhook_config;
    if (webhook_get_config(&webhook_config) != ESP_OK || !webhook_config.enabled || !webhook_config.deauth_alert) {
        return;
    }
    
    device_event_t event;
    memset(&event, 0, sizeof(event));
    
    // set timestamp
    event.uptime_sec = get_uptime_sec();
    if (pwnpower_time_is_synced()) {
        time_t now;
        time(&now);
        event.epoch_ts = (uint32_t)now;
        event.time_valid = 1;
    } else {
        event.epoch_ts = 0;
        event.time_valid = 0;
    }
    
    // set event data
    memcpy(event.mac, mac, 6);
    event.event_type = DEVICE_EVENT_DEAUTH_DETECTED;
    event.rssi = 0; // deauth frames don't have RSSI context
    
    // use default trust score for security events
    event.trust_score = 50;
    event.tracked = 0;
    
    // look up device flags from presence data
    device_presence_t presence;
    if (scan_storage_get_device_presence(mac, &presence) == ESP_OK) {
        event.device_flags = presence.flags;
        strncpy(event.vendor, presence.vendor, sizeof(event.vendor) - 1);
    } else {
        event.device_flags = 0;
        strncpy(event.vendor, "Unknown", sizeof(event.vendor) - 1);
    }
    
    // append to storage
    esp_err_t err = scan_storage_append_device_event(&event);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to append deauth event: %s", esp_err_to_name(err));
    } else {
        ESP_LOGI(TAG, "Deauth event generated for %02X:%02X:%02X:%02X:%02X:%02X (count=%lu)",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], (unsigned long)deauth_count);
    }
}

void device_lifecycle_generate_batched_deauth_alert(uint32_t total_deauth_count, uint32_t scan_duration_sec) {
    static uint32_t last_deauth_count = 0;
    static uint32_t last_event_time = 0;

    webhook_config_t webhook_config;
    if (webhook_get_config(&webhook_config) != ESP_OK || !webhook_config.enabled || !webhook_config.deauth_alert) {
        return;
    }

    if (total_deauth_count == 0) {
        return; // Don't send alert for zero deauth frames
    }

    // Deduplication: prevent duplicate events within 60 seconds with same count
    uint32_t current_time = get_uptime_sec();
    if (last_deauth_count == total_deauth_count &&
        (current_time - last_event_time) < 60) {
        ESP_LOGW(TAG, "Skipping duplicate deauth alert (count=%lu, time_delta=%lu sec)",
                 (unsigned long)total_deauth_count, (unsigned long)(current_time - last_event_time));
        return;
    }

    last_deauth_count = total_deauth_count;
    last_event_time = current_time;
    
    device_event_t event;
    memset(&event, 0, sizeof(event));
    
    // set timestamp
    event.uptime_sec = get_uptime_sec();
    if (pwnpower_time_is_synced()) {
        time_t now;
        time(&now);
        event.epoch_ts = (uint32_t)now;
        event.time_valid = 1;
    } else {
        event.epoch_ts = 0;
        event.time_valid = 0;
    }
    
    // set event data for batched alert
    memset(event.mac, 0, 6); // Use zero MAC for batched events
    event.event_type = DEVICE_EVENT_DEAUTH_DETECTED;
    event.rssi = (int8_t)(total_deauth_count > 255 ? 255 : total_deauth_count); // Store count in RSSI field
    
    // use default trust score for security events
    event.trust_score = 50;
    event.tracked = 0;
    event.device_flags = 0;
    strncpy(event.vendor, "Security Monitor", sizeof(event.vendor) - 1);
    
    // Create custom event message for batched alert
    char event_message[256];
    snprintf(event_message, sizeof(event_message), 
             "🚨 **Deauth Attack Detected**\n"
             "**%lu** deauth frames detected in %lu seconds\n"
             "This may indicate an active attack on the network",
             (unsigned long)total_deauth_count, (unsigned long)scan_duration_sec);
    
    // append to storage with custom message
    esp_err_t err = scan_storage_append_device_event(&event);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to append batched deauth event: %s", esp_err_to_name(err));
    } else {
        ESP_LOGI(TAG, "Batched deauth alert generated: %lu frames in %lu seconds", 
                 (unsigned long)total_deauth_count, (unsigned long)scan_duration_sec);
    }
}

void device_lifecycle_generate_handshake_event(const uint8_t *bssid, const uint8_t *client_mac, int eapol_count) {
    webhook_config_t webhook_config;
    if (webhook_get_config(&webhook_config) != ESP_OK || !webhook_config.enabled || !webhook_config.handshake_alert) {
        return;
    }
    
    device_event_t event;
    memset(&event, 0, sizeof(event));
    
    // set timestamp
    event.uptime_sec = get_uptime_sec();
    if (pwnpower_time_is_synced()) {
        time_t now;
        time(&now);
        event.epoch_ts = (uint32_t)now;
        event.time_valid = 1;
    } else {
        event.epoch_ts = 0;
        event.time_valid = 0;
    }
    
    // set event data - use client MAC if available, otherwise BSSID
    if (client_mac && memcmp(client_mac, "\x00\x00\x00\x00\x00\x00", 6) != 0) {
        memcpy(event.mac, client_mac, 6);
    } else {
        memcpy(event.mac, bssid, 6);
    }
    event.event_type = DEVICE_EVENT_HANDSHAKE_CAPTURED;
    event.rssi = -70; // typical RSSI for handshake capture
    
    // use higher trust score for successful handshake captures
    event.trust_score = 60;
    event.tracked = 1;
    
    // look up device flags from presence data
    device_presence_t presence;
    if (scan_storage_get_device_presence(event.mac, &presence) == ESP_OK) {
        event.device_flags = presence.flags;
        strncpy(event.vendor, presence.vendor, sizeof(event.vendor) - 1);
    } else {
        event.device_flags = 0;
        strncpy(event.vendor, "Unknown", sizeof(event.vendor) - 1);
    }
    
    // append to storage
    esp_err_t err = scan_storage_append_device_event(&event);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to append handshake event: %s", esp_err_to_name(err));
    } else {
        ESP_LOGI(TAG, "Handshake event generated for %02X:%02X:%02X:%02X:%02X:%02X (EAPOL=%d)",
                 event.mac[0], event.mac[1], event.mac[2], event.mac[3], event.mac[4], event.mac[5], eapol_count);
    }
}
