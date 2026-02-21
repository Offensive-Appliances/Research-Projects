#ifndef MONITOR_UPTIME_H
#define MONITOR_UPTIME_H

#include "esp_err.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Initialize the monitor uptime system
// Loads the saved uptime from NVS and starts periodic save task
esp_err_t monitor_uptime_init(void);

// Get the total monitor uptime in seconds (including previous boot cycles)
uint32_t monitor_uptime_get(void);

// Save the current uptime to NVS immediately (normally done automatically)
esp_err_t monitor_uptime_save(void);

// Get the current boot uptime (time since last power-on)
uint32_t monitor_uptime_get_boot_uptime(void);

#ifdef __cplusplus
}
#endif

#endif // MONITOR_UPTIME_H
