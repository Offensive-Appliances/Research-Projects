#include "mdns_service.h"
#include "mdns.h"
#include "esp_log.h"

#define TAG "mDNS"

static bool mdns_initialized = false;

esp_err_t mdns_service_init(const char *hostname) {
    if (mdns_initialized) {
        return ESP_OK;
    }

    esp_err_t err = mdns_init();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "mDNS init failed: %s", esp_err_to_name(err));
        return err;
    }

    err = mdns_hostname_set(hostname);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "mDNS hostname set failed: %s", esp_err_to_name(err));
        return err;
    }

    err = mdns_instance_name_set("PwnPower WiFi Scanner");
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "mDNS instance name set failed: %s", esp_err_to_name(err));
    }

    err = mdns_service_add("PwnPower Web", "_http", "_tcp", 80, NULL, 0);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "mDNS service add failed: %s", esp_err_to_name(err));
    }

    mdns_initialized = true;
    ESP_LOGI(TAG, "mDNS initialized: %s.local", hostname);
    return ESP_OK;
}

esp_err_t mdns_service_update_hostname(const char *hostname) {
    if (!mdns_initialized) {
        return mdns_service_init(hostname);
    }

    esp_err_t err = mdns_hostname_set(hostname);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "mDNS hostname update failed: %s", esp_err_to_name(err));
    }
    return err;
}
