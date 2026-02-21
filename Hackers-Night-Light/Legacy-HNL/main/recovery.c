#include "recovery.h"
#include "esp_log.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "esp_partition.h"

#define RECOVERY_POWER_CYCLE_THRESHOLD 5
#define RECOVERY_CLEAR_WINDOW_MS 10000
#define RECOVERY_NVS_NS "recovery"
#define RECOVERY_NVS_KEY "power_cycles"

static const char *TAG = "Recovery";
static esp_timer_handle_t s_recovery_clear_timer = NULL;

static uint32_t recovery_load_counter(void) {
    nvs_handle_t handle;
    uint32_t count = 0;
    esp_err_t err = nvs_open(RECOVERY_NVS_NS, NVS_READONLY, &handle);
    if (err == ESP_OK) {
        nvs_get_u32(handle, RECOVERY_NVS_KEY, &count);
        nvs_close(handle);
    }
    return count;
}

static void recovery_store_counter(uint32_t count) {
    nvs_handle_t handle;
    esp_err_t err = nvs_open(RECOVERY_NVS_NS, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Recovery NVS open failed: %s", esp_err_to_name(err));
        return;
    }

    err = nvs_set_u32(handle, RECOVERY_NVS_KEY, count);
    if (err == ESP_OK) {
        err = nvs_commit(handle);
    }

    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Recovery counter store failed: %s", esp_err_to_name(err));
    }
    nvs_close(handle);
}

static void recovery_clear_cb(void *arg) {
    recovery_store_counter(0);
    ESP_LOGI(TAG, "Power-cycle recovery window expired; counter cleared");
}

static void recovery_erase_scan_partition(void) {
    const esp_partition_t *part = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, 0x99, "scandata");
    if (!part) {
        ESP_LOGW(TAG, "Scan data partition not found; skipping erase");
        return;
    }
    esp_err_t err = esp_partition_erase_range(part, 0, part->size);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Failed to erase scan data partition: %s", esp_err_to_name(err));
    } else {
        ESP_LOGI(TAG, "Erased scan data partition (%lu KB)", (unsigned long)(part->size / 1024));
    }
}

esp_err_t recovery_init(void) {
    // Create timer used for clearing the counter after a stable boot window
    if (!s_recovery_clear_timer) {
        const esp_timer_create_args_t args = {
            .callback = &recovery_clear_cb,
            .name = "recovery_clear"
        };
        esp_err_t err = esp_timer_create(&args, &s_recovery_clear_timer);
        if (err != ESP_OK) {
            ESP_LOGW(TAG, "Failed to create recovery clear timer: %s", esp_err_to_name(err));
            return err;
        }
    }
    return ESP_OK;
}

void recovery_schedule_clear_timer(void) {
    if (!s_recovery_clear_timer) return;
    esp_timer_stop(s_recovery_clear_timer);
    esp_err_t err = esp_timer_start_once(s_recovery_clear_timer, RECOVERY_CLEAR_WINDOW_MS * 1000ULL);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Failed to start recovery clear timer: %s", esp_err_to_name(err));
    }
}

void recovery_handle_power_cycle_reset(void) {
    uint32_t count = recovery_load_counter();
    count++;
    recovery_store_counter(count);

    ESP_LOGI(TAG, "Recovery counter: %lu/%d", (unsigned long)count, RECOVERY_POWER_CYCLE_THRESHOLD);

    if (count >= RECOVERY_POWER_CYCLE_THRESHOLD) {
        ESP_LOGW(TAG, "Power-cycle recovery threshold reached (%d); erasing NVS and restarting", RECOVERY_POWER_CYCLE_THRESHOLD);
        if (s_recovery_clear_timer) {
            esp_timer_stop(s_recovery_clear_timer);
        }
        recovery_erase_scan_partition();
        esp_err_t nvs_err = nvs_flash_erase();
        if (nvs_err != ESP_OK) {
            ESP_LOGE(TAG, "Failed to erase NVS during recovery: %s", esp_err_to_name(nvs_err));
        }
        // Do not touch NVS after erase; restart to re-init clean state
        esp_restart();
    }

    // Clear counter if we stay powered for long enough (normal boot)
    recovery_schedule_clear_timer();
}
