#ifndef AP_CONFIG_H
#define AP_CONFIG_H

#include "esp_err.h"
#include <stdbool.h>

#define AP_SSID_MAX_LEN 32
#define AP_PASS_MAX_LEN 64

typedef struct {
    char ssid[AP_SSID_MAX_LEN + 1];
    char password[AP_PASS_MAX_LEN + 1];
} ap_config_t;

esp_err_t ap_config_init(void);
esp_err_t ap_config_get(ap_config_t *config);
esp_err_t ap_config_set(const char *ssid, const char *password);
esp_err_t ap_config_apply(void);
const char* ap_config_get_json(void);

#endif
