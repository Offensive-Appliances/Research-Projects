#ifndef BACKGROUND_SCAN_H
#define BACKGROUND_SCAN_H

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

typedef enum {
    BG_SCAN_IDLE,
    BG_SCAN_WAITING,
    BG_SCAN_RUNNING,
    BG_SCAN_PAUSED
} bg_scan_state_t;

typedef struct {
    uint16_t interval_sec;
    uint16_t ap_pause_ms;
    bool auto_scan;
    bool scan_while_ap;
    uint8_t quick_scan_channels;
} bg_scan_config_t;

esp_err_t background_scan_init(void);
esp_err_t background_scan_start(void);
esp_err_t background_scan_stop(void);
esp_err_t background_scan_trigger(void);
esp_err_t background_scan_set_interval(uint16_t seconds);
void background_scan_set_enabled(bool enabled);
bg_scan_state_t background_scan_get_state(void);
uint32_t background_scan_get_last_time(void);
const bg_scan_config_t* background_scan_get_config(void);

// Smart channel weighting support
uint32_t get_background_channel_dwell_time(uint8_t channel);

#endif
