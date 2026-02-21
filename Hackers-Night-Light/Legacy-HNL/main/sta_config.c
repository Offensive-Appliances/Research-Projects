#include "sta_config.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_log.h"
#include <string.h>

#define TAG "STA_CONFIG"
#define NVS_NAMESPACE "sta_config"
#define NVS_KEY_SSID "ssid"
#define NVS_KEY_PASS "password"
#define NVS_KEY_AUTO "auto_conn"
#define NVS_KEY_AP_WHILE "ap_while"

esp_err_t sta_config_init(void) {
    return ESP_OK;
}

esp_err_t sta_config_get(sta_config_t *config) {
    if (!config) return ESP_ERR_INVALID_ARG;
    
    memset(config, 0, sizeof(sta_config_t));
    
    nvs_handle_t handle;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READONLY, &handle);
    if (err != ESP_OK) {
        return err;
    }
    
    size_t ssid_len = sizeof(config->ssid);
    err = nvs_get_str(handle, NVS_KEY_SSID, config->ssid, &ssid_len);
    if (err == ESP_OK) {
        size_t pass_len = sizeof(config->password);
        nvs_get_str(handle, NVS_KEY_PASS, config->password, &pass_len);
    }
    
    uint8_t auto_val = 1;
    nvs_get_u8(handle, NVS_KEY_AUTO, &auto_val);
    config->auto_connect = (auto_val != 0);
    
    uint8_t ap_val = 1;
    nvs_get_u8(handle, NVS_KEY_AP_WHILE, &ap_val);
    config->ap_while_connected = (ap_val != 0);
    
    nvs_close(handle);
    return err;
}

esp_err_t sta_config_set(const char *ssid, const char *password) {
    if (!ssid) return ESP_ERR_INVALID_ARG;
    
    nvs_handle_t handle;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to open NVS: %s", esp_err_to_name(err));
        return err;
    }
    
    err = nvs_set_str(handle, NVS_KEY_SSID, ssid);
    if (err == ESP_OK) {
        err = nvs_set_str(handle, NVS_KEY_PASS, password ? password : "");
    }
    
    if (err == ESP_OK) {
        err = nvs_commit(handle);
    }
    
    nvs_close(handle);
    
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "Saved STA config: %s", ssid);
    } else {
        ESP_LOGE(TAG, "Failed to save STA config: %s", esp_err_to_name(err));
    }
    
    return err;
}

esp_err_t sta_config_clear(void) {
    nvs_handle_t handle;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) return err;
    
    nvs_erase_all(handle);
    err = nvs_commit(handle);
    nvs_close(handle);
    
    ESP_LOGI(TAG, "Cleared STA config");
    return err;
}

bool sta_config_exists(void) {
    sta_config_t config;
    return (sta_config_get(&config) == ESP_OK && strlen(config.ssid) > 0);
}

bool sta_config_get_auto_connect(void) {
    nvs_handle_t handle;
    if (nvs_open(NVS_NAMESPACE, NVS_READONLY, &handle) != ESP_OK) return true;
    uint8_t val = 1;
    nvs_get_u8(handle, NVS_KEY_AUTO, &val);
    nvs_close(handle);
    return (val != 0);
}

void sta_config_set_auto_connect(bool enabled) {
    nvs_handle_t handle;
    if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &handle) != ESP_OK) return;
    nvs_set_u8(handle, NVS_KEY_AUTO, enabled ? 1 : 0);
    nvs_commit(handle);
    nvs_close(handle);
    ESP_LOGI(TAG, "Auto-connect set to %s", enabled ? "enabled" : "disabled");
}

bool sta_config_get_ap_while_connected(void) {
    nvs_handle_t handle;
    if (nvs_open(NVS_NAMESPACE, NVS_READONLY, &handle) != ESP_OK) return true;
    uint8_t val = 1;
    nvs_get_u8(handle, NVS_KEY_AP_WHILE, &val);
    nvs_close(handle);
    return (val != 0);
}

void sta_config_set_ap_while_connected(bool enabled) {
    nvs_handle_t handle;
    if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &handle) != ESP_OK) return;
    nvs_set_u8(handle, NVS_KEY_AP_WHILE, enabled ? 1 : 0);
    nvs_commit(handle);
    nvs_close(handle);
    ESP_LOGI(TAG, "AP while connected set to %s", enabled ? "enabled" : "disabled");
}
