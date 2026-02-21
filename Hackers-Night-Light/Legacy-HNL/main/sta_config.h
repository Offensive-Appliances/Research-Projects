#ifndef STA_CONFIG_H
#define STA_CONFIG_H

#include "esp_err.h"
#include <stdbool.h>

typedef struct {
    char ssid[32];
    char password[64];
    bool auto_connect;
    bool ap_while_connected;
} sta_config_t;

esp_err_t sta_config_init(void);
esp_err_t sta_config_get(sta_config_t *config);
esp_err_t sta_config_set(const char *ssid, const char *password);
esp_err_t sta_config_clear(void);
bool sta_config_exists(void);
bool sta_config_get_auto_connect(void);
void sta_config_set_auto_connect(bool enabled);
bool sta_config_get_ap_while_connected(void);
void sta_config_set_ap_while_connected(bool enabled);

#endif
