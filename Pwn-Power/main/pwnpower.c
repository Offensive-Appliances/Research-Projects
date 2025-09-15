#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "web_server.h"
#include "wifi_scan.h"
#include "esp_netif.h"
#include <string.h>
#include "deauth.h"
#include "esp_ota_ops.h"

#define TAG "PwnPower"
#define WIFI_SSID "PwnPower"
#define WIFI_PASS "password"
#define MAX_STA_CONN 4

void wifi_init_softap() {
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();
    esp_netif_t *ap_netif = esp_netif_create_default_wifi_ap();
    esp_netif_ip_info_t ip_info;
    ESP_ERROR_CHECK(esp_netif_get_ip_info(ap_netif, &ip_info));
    ESP_LOGI(TAG, "AP IP Address: " IPSTR, IP2STR(&ip_info.ip));
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    
    // enable raw 802.11 frame transmission
    wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT
    };
    
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(NULL));  // we don't need rx callback
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_filter(&filter)); // set proper filter
    
    wifi_config_t wifi_config = {
        .ap = {
            .ssid = WIFI_SSID,
            .password = WIFI_PASS,
            .ssid_len = strlen(WIFI_SSID),
            .channel = 6, //40 for 5Ghz, 6 for 2.4Ghz
            .authmode = WIFI_AUTH_WPA2_WPA3_PSK,
            .max_connection = MAX_STA_CONN,
            .pmf_cfg = {
                .required = true,
            },
        }
    };
    if (strlen(WIFI_PASS) == 0) {
        wifi_config.ap.authmode = WIFI_AUTH_OPEN;
    }
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_LOGI(TAG, "Wi-Fi AP+STA Started: SSID=%s", WIFI_SSID);
}

void app_main() {
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    // mark app valid so rollback doesn't screw us after ota
    esp_ota_mark_app_valid_cancel_rollback();
    attack_mutex = xSemaphoreCreateMutex();
    wifi_init_softap();
    
    // wait for any ongoing deauth to complete
    while(deauth_active) {
        ESP_LOGI(TAG, "waiting for deauth operations to complete...");
        vTaskDelay(pdMS_TO_TICKS(1000)); // check every second
    }
    
    start_webserver();
}