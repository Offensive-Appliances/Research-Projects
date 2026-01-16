#ifndef WEBHOOK_H
#define WEBHOOK_H

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

#define WEBHOOK_URL_MAX_LEN 256

typedef struct {
    bool enabled;
    char url[WEBHOOK_URL_MAX_LEN];
    bool tracked_only;          // smart filter for tracked devices
    bool home_departure_alert;  // alert when home device leaves
    bool home_arrival_alert;    // alert when home device arrives
    bool new_device_alert;      // alert on unknown devices (trust < 30)
    bool all_events;            // send all events (overrides filters)
} webhook_config_t;

// initialize webhook system
esp_err_t webhook_init(void);

// start webhook dispatcher task
esp_err_t webhook_start(void);

// stop webhook dispatcher task
void webhook_stop(void);

// get webhook configuration
esp_err_t webhook_get_config(webhook_config_t *config);

// set webhook configuration
esp_err_t webhook_set_config(const webhook_config_t *config);

// manually trigger a test webhook
esp_err_t webhook_send_test(void);

// get send cursor (for status display)
uint32_t webhook_get_send_cursor(void);

#endif
