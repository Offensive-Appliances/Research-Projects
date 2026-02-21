#include "ap_config.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include "cJSON.h"
#include <string.h>

#define TAG "APConfig"
#define NVS_NAMESPACE "ap_cfg"
#define NVS_KEY_SSID "ssid"
#define NVS_KEY_PASS "pass"
#define DEFAULT_SSID "Legacy-HNL"
#define DEFAULT_PASS "password"

static ap_config_t current_config;
static char config_json[256];

esp_err_t ap_config_init(void) {
    nvs_handle_t handle;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to open NVS: %s", esp_err_to_name(err));
        strncpy(current_config.ssid, DEFAULT_SSID, AP_SSID_MAX_LEN);
        strncpy(current_config.password, DEFAULT_PASS, AP_PASS_MAX_LEN);
        return err;
    }

    size_t ssid_len = AP_SSID_MAX_LEN + 1;
    size_t pass_len = AP_PASS_MAX_LEN + 1;

    err = nvs_get_str(handle, NVS_KEY_SSID, current_config.ssid, &ssid_len);
    if (err != ESP_OK) {
        strncpy(current_config.ssid, DEFAULT_SSID, AP_SSID_MAX_LEN);
    }

    err = nvs_get_str(handle, NVS_KEY_PASS, current_config.password, &pass_len);
    if (err != ESP_OK) {
        strncpy(current_config.password, DEFAULT_PASS, AP_PASS_MAX_LEN);
    }

    nvs_close(handle);
    ESP_LOGI(TAG, "Loaded AP config: SSID=%s", current_config.ssid);
    return ESP_OK;
}

esp_err_t ap_config_get(ap_config_t *config) {
    if (!config) return ESP_ERR_INVALID_ARG;
    memcpy(config, &current_config, sizeof(ap_config_t));
    return ESP_OK;
}

esp_err_t ap_config_set(const char *ssid, const char *password) {
    if (!ssid || strlen(ssid) == 0 || strlen(ssid) > AP_SSID_MAX_LEN) {
        return ESP_ERR_INVALID_ARG;
    }
    if (password && strlen(password) > AP_PASS_MAX_LEN) {
        return ESP_ERR_INVALID_ARG;
    }
    if (password && strlen(password) > 0 && strlen(password) < 8) {
        return ESP_ERR_INVALID_ARG;
    }

    nvs_handle_t handle;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to open NVS: %s", esp_err_to_name(err));
        return err;
    }

    err = nvs_set_str(handle, NVS_KEY_SSID, ssid);
    if (err != ESP_OK) {
        nvs_close(handle);
        return err;
    }

    const char *pass_to_store = (password && strlen(password) > 0) ? password : "";
    err = nvs_set_str(handle, NVS_KEY_PASS, pass_to_store);
    if (err != ESP_OK) {
        nvs_close(handle);
        return err;
    }

    err = nvs_commit(handle);
    nvs_close(handle);

    if (err == ESP_OK) {
        strncpy(current_config.ssid, ssid, AP_SSID_MAX_LEN);
        current_config.ssid[AP_SSID_MAX_LEN] = '\0';
        if (password && strlen(password) > 0) {
            strncpy(current_config.password, password, AP_PASS_MAX_LEN);
        } else {
            current_config.password[0] = '\0';
        }
        current_config.password[AP_PASS_MAX_LEN] = '\0';
        ESP_LOGI(TAG, "Saved AP config: SSID=%s", current_config.ssid);
    }

    return err;
}

esp_err_t ap_config_apply(void) {
    wifi_config_t wifi_config = {0};
    
    strncpy((char*)wifi_config.ap.ssid, current_config.ssid, sizeof(wifi_config.ap.ssid) - 1);
    wifi_config.ap.ssid_len = strlen(current_config.ssid);
    
    if (strlen(current_config.password) >= 8) {
        strncpy((char*)wifi_config.ap.password, current_config.password, sizeof(wifi_config.ap.password) - 1);
        wifi_config.ap.authmode = WIFI_AUTH_WPA2_WPA3_PSK;
    } else {
        wifi_config.ap.password[0] = '\0';
        wifi_config.ap.authmode = WIFI_AUTH_OPEN;
    }
    
    wifi_config.ap.channel = 6;
    wifi_config.ap.max_connection = 4;
    wifi_config.ap.pmf_cfg.required = true;

    esp_err_t err = esp_wifi_set_config(WIFI_IF_AP, &wifi_config);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "Applied AP config: SSID=%s", current_config.ssid);
    } else {
        ESP_LOGE(TAG, "Failed to apply AP config: %s", esp_err_to_name(err));
    }
    return err;
}

const char* ap_config_get_json(void) {
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "ssid", current_config.ssid);
    cJSON_AddBoolToObject(root, "has_password", strlen(current_config.password) > 0);
    
    char *json = cJSON_PrintUnformatted(root);
    strncpy(config_json, json, sizeof(config_json) - 1);
    config_json[sizeof(config_json) - 1] = '\0';
    free(json);
    cJSON_Delete(root);
    
    return config_json;
}
