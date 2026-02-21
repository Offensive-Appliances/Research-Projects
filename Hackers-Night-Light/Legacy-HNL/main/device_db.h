#ifndef DEVICE_DB_H
#define DEVICE_DB_H

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

#define DEVICE_NAME_MAX_LEN 32

typedef struct {
    uint8_t mac[6];
    char name[DEVICE_NAME_MAX_LEN];
    uint8_t trust_score;  // 0-100
    bool tracked;         // user wants to track this device
} device_settings_t;

// initialize device database
esp_err_t device_db_init(void);

// get device settings (returns ESP_ERR_NOT_FOUND if not in DB)
esp_err_t device_db_get(const uint8_t *mac, device_settings_t *settings);

// set/update device settings
esp_err_t device_db_set(const device_settings_t *settings);

// check if device exists in database
bool device_db_exists(const uint8_t *mac);

// get all tracked devices (returns count)
int device_db_get_all_tracked(device_settings_t *devices, int max_count);

// get all devices (returns count)
int device_db_get_all(device_settings_t *devices, int max_count);

#endif
