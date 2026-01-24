#include "monitor_uptime.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "nvs.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#define TAG "MonitorUptime"
#define NVS_NAMESPACE "uptime"
#define NVS_KEY_ACCUMULATED "accumulated"
#define NVS_KEY_BOOT_TIME "boot_time"
#define SAVE_INTERVAL_SEC 3600  // Save every hour

static uint32_t accumulated_uptime_sec = 0;  // Uptime from previous boot cycles
static uint32_t boot_start_time_sec = 0;     // When this boot cycle started
static TaskHandle_t save_task_handle = NULL;
static bool task_running = false;

// Get current uptime from ESP timer
static uint32_t get_current_boot_uptime(void) {
    return (uint32_t)(esp_timer_get_time() / 1000000ULL);
}

esp_err_t monitor_uptime_save(void) {
    nvs_handle_t handle;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to open NVS: %s", esp_err_to_name(err));
        return err;
    }

    // Calculate total uptime at this moment
    uint32_t current_boot_uptime = get_current_boot_uptime();
    uint32_t total_uptime = accumulated_uptime_sec + current_boot_uptime;

    err = nvs_set_u32(handle, NVS_KEY_ACCUMULATED, total_uptime);
    if (err == ESP_OK) {
        err = nvs_set_u32(handle, NVS_KEY_BOOT_TIME, current_boot_uptime);
    }

    if (err == ESP_OK) {
        err = nvs_commit(handle);
    }

    nvs_close(handle);

    if (err == ESP_OK) {
        ESP_LOGI(TAG, "Saved uptime: %lu sec (boot: %lu sec)",
                 (unsigned long)total_uptime, (unsigned long)current_boot_uptime);
    } else {
        ESP_LOGE(TAG, "Failed to save uptime: %s", esp_err_to_name(err));
    }

    return err;
}

static esp_err_t load_uptime(void) {
    nvs_handle_t handle;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READONLY, &handle);
    if (err != ESP_OK) {
        if (err == ESP_ERR_NVS_NOT_FOUND) {
            ESP_LOGI(TAG, "No saved uptime found, starting fresh");
            accumulated_uptime_sec = 0;
            return ESP_OK;
        }
        ESP_LOGE(TAG, "Failed to open NVS: %s", esp_err_to_name(err));
        return err;
    }

    uint32_t saved_accumulated = 0;
    uint32_t saved_boot_time = 0;

    err = nvs_get_u32(handle, NVS_KEY_ACCUMULATED, &saved_accumulated);
    if (err == ESP_OK) {
        nvs_get_u32(handle, NVS_KEY_BOOT_TIME, &saved_boot_time);
    }

    nvs_close(handle);

    if (err == ESP_OK || err == ESP_ERR_NVS_NOT_FOUND) {
        accumulated_uptime_sec = saved_accumulated;
        ESP_LOGI(TAG, "Loaded uptime: %lu sec (previous boot: %lu sec)",
                 (unsigned long)saved_accumulated, (unsigned long)saved_boot_time);
        return ESP_OK;
    }

    ESP_LOGE(TAG, "Failed to load uptime: %s", esp_err_to_name(err));
    return err;
}

static void uptime_save_task(void *arg) {
    ESP_LOGI(TAG, "Uptime save task started (saving every %d seconds)", SAVE_INTERVAL_SEC);

    while (task_running) {
        vTaskDelay(pdMS_TO_TICKS(SAVE_INTERVAL_SEC * 1000));

        if (!task_running) break;

        monitor_uptime_save();
    }

    save_task_handle = NULL;
    vTaskDelete(NULL);
}

esp_err_t monitor_uptime_init(void) {
    esp_err_t err = load_uptime();
    if (err != ESP_OK) {
        return err;
    }

    boot_start_time_sec = get_current_boot_uptime();

    // Start periodic save task
    task_running = true;
    BaseType_t ret = xTaskCreate(uptime_save_task, "uptime_save", 2048, NULL, 5, &save_task_handle);
    if (ret != pdPASS) {
        task_running = false;
        ESP_LOGE(TAG, "Failed to create save task");
        return ESP_ERR_NO_MEM;
    }

    ESP_LOGI(TAG, "Monitor uptime initialized: %lu sec total",
             (unsigned long)(accumulated_uptime_sec + boot_start_time_sec));

    return ESP_OK;
}

uint32_t monitor_uptime_get(void) {
    uint32_t current_boot_uptime = get_current_boot_uptime();
    return accumulated_uptime_sec + current_boot_uptime;
}

uint32_t monitor_uptime_get_boot_uptime(void) {
    return get_current_boot_uptime();
}
