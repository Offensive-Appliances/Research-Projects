#include "device_db.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include <string.h>

#define TAG "DeviceDB"
#define NVS_NAMESPACE "device_db"
#define MAX_DEVICES 64

static SemaphoreHandle_t db_mutex = NULL;

esp_err_t device_db_init(void) {
    if (db_mutex == NULL) {
        db_mutex = xSemaphoreCreateMutex();
    }
    ESP_LOGI(TAG, "Device DB initialized");
    return ESP_OK;
}

static void mac_to_key(const uint8_t *mac, char *key) {
    snprintf(key, 18, "%02x%02x%02x%02x%02x%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

esp_err_t device_db_get(const uint8_t *mac, device_settings_t *settings) {
    if (!mac || !settings) return ESP_ERR_INVALID_ARG;
    
    if (db_mutex) xSemaphoreTake(db_mutex, portMAX_DELAY);
    
    nvs_handle_t handle;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READONLY, &handle);
    if (err != ESP_OK) {
        if (db_mutex) xSemaphoreGive(db_mutex);
        return err;
    }
    
    char key[18];
    mac_to_key(mac, key);
    
    size_t len = sizeof(device_settings_t);
    err = nvs_get_blob(handle, key, settings, &len);
    
    nvs_close(handle);
    
    if (db_mutex) xSemaphoreGive(db_mutex);
    return err;
}

esp_err_t device_db_set(const device_settings_t *settings) {
    if (!settings) return ESP_ERR_INVALID_ARG;
    
    if (db_mutex) xSemaphoreTake(db_mutex, portMAX_DELAY);
    
    nvs_handle_t handle;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        if (db_mutex) xSemaphoreGive(db_mutex);
        ESP_LOGE(TAG, "Failed to open NVS: %s", esp_err_to_name(err));
        return err;
    }
    
    char key[18];
    mac_to_key(settings->mac, key);
    
    err = nvs_set_blob(handle, key, settings, sizeof(device_settings_t));
    if (err == ESP_OK) {
        err = nvs_commit(handle);
    }
    
    nvs_close(handle);
    
    if (db_mutex) xSemaphoreGive(db_mutex);
    
    if (err == ESP_OK) {
        const char *trust_label = (settings->trust_score > 70) ? "trusted" : 
                                  (settings->trust_score > 50) ? "known" : 
                                  (settings->trust_score > 30) ? "familiar" : "new";
        ESP_LOGD(TAG, "Updated device: %s (trust=%u/%s, auto-tracked=%d)", 
                 settings->name[0] ? settings->name : key, 
                 settings->trust_score, trust_label, settings->tracked);
    }
    
    return err;
}

bool device_db_exists(const uint8_t *mac) {
    device_settings_t settings;
    return (device_db_get(mac, &settings) == ESP_OK);
}

int device_db_get_all_tracked(device_settings_t *devices, int max_count) {
    if (!devices || max_count <= 0) return 0;
    
    // NVS doesn't provide easy iteration, iterate through known keys
    return 0;
}

int device_db_get_all(device_settings_t *devices, int max_count) {
    if (!devices || max_count <= 0) return 0;
    
    // Simplified implementation - would maintain device index in production
    return 0;
}
