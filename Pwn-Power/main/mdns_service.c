#include "mdns_service.h"
#include "mdns.h"
#include "esp_log.h"
#include <string.h>

#define TAG "mDNS"

static bool mdns_initialized = false;
static char current_hostname[33] = "pwnpower";

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

    strncpy(current_hostname, hostname, sizeof(current_hostname) - 1);
    current_hostname[sizeof(current_hostname) - 1] = '\0';

    err = mdns_instance_name_set("PwnPower WiFi Scanner");
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "mDNS instance name set failed: %s", esp_err_to_name(err));
    }

    // Advertise HTTPS on port 443; HTTP now only redirects
    err = mdns_service_add("PwnPower Web", "_https", "_tcp", 443, NULL, 0);
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
    } else {
        strncpy(current_hostname, hostname, sizeof(current_hostname) - 1);
        current_hostname[sizeof(current_hostname) - 1] = '\0';
        ESP_LOGI(TAG, "mDNS hostname updated to: %s.local", hostname);
    }
    return err;
}

const char* mdns_service_get_hostname(void) {
    return current_hostname;
}

bool mdns_service_is_initialized(void) {
    return mdns_initialized;
}
