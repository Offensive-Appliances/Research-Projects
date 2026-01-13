#ifndef IDLE_SCANNER_H
#define IDLE_SCANNER_H

#include "esp_err.h"
#include <stdbool.h>

typedef enum {
    IDLE_SCAN_OFF,
    IDLE_SCAN_WAITING,
    IDLE_SCAN_DEEP_SCAN,
    IDLE_SCAN_HANDSHAKE
} idle_scan_state_t;

typedef struct {
    uint32_t idle_threshold_sec;
    uint32_t deep_scan_interval_sec;
    bool auto_handshake;
    uint8_t handshake_duration_sec;
} idle_scan_config_t;

esp_err_t idle_scanner_init(void);
esp_err_t idle_scanner_start(void);
void idle_scanner_stop(void);
idle_scan_state_t idle_scanner_get_state(void);
const idle_scan_config_t* idle_scanner_get_config(void);
void idle_scanner_set_config(const idle_scan_config_t *config);
void idle_scanner_set_auto_handshake(bool enabled);
void idle_scanner_set_idle_threshold(uint32_t seconds);
void idle_scanner_set_handshake_duration(uint8_t seconds);
bool idle_scanner_is_device_idle(void);

#endif
