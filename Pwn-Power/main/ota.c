#include "ota.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "OTA";

esp_err_t ota_begin(esp_ota_handle_t *out_handle, const esp_partition_t **out_part) {
	if(!out_handle || !out_part) return ESP_ERR_INVALID_ARG;
	const esp_partition_t *update_part = esp_ota_get_next_update_partition(NULL);
	if (!update_part) {
		ESP_LOGE(TAG, "no update partition, go fix your damn partitions");
		return ESP_ERR_NOT_FOUND;
	}
	ESP_LOGI(TAG, "writing to partition subtype %d at offset 0x%lx size=0x%lx",
		update_part->subtype, (unsigned long)update_part->address, (unsigned long)update_part->size);
	esp_ota_handle_t h = 0;
	// OTA_WITH_SEQUENTIAL_WRITES erases one flash sector (4KB) just before each write,
	// instead of erasing the entire partition (~1.6MB = ~12 seconds) upfront.
	// Without this, esp_ota_begin blocks for ~12s erasing flash, the TCP receive window
	// fills (~524KB), and the browser closes the connection before recv is ever called.
	esp_err_t err = esp_ota_begin(update_part, OTA_WITH_SEQUENTIAL_WRITES, &h);
	if (err != ESP_OK) {
		ESP_LOGE(TAG, "esp_ota_begin failed: %s", esp_err_to_name(err));
		return err;
	}
	*out_handle = h;
	*out_part = update_part;
	return ESP_OK;
}

esp_err_t ota_write(esp_ota_handle_t handle, const void *data, size_t len) {
	if (!data || len == 0) return ESP_OK;
	return esp_ota_write(handle, data, len);
}

esp_err_t ota_finish_and_set_boot(esp_ota_handle_t handle, const esp_partition_t *part) {
	esp_err_t err = esp_ota_end(handle);
	if (err != ESP_OK) {
		ESP_LOGE(TAG, "esp_ota_end failed: %s", esp_err_to_name(err));
		return err;
	}
	err = esp_ota_set_boot_partition(part);
	if (err != ESP_OK) {
		ESP_LOGE(TAG, "set_boot_partition failed: %s", esp_err_to_name(err));
		return err;
	}
	ESP_LOGI(TAG, "boot partition set, ready to reboot");
	return ESP_OK;
}

static void reboot_task(void *arg) {
	int delay_ms = (int)(intptr_t)arg;
	vTaskDelay(pdMS_TO_TICKS(delay_ms));
	ESP_LOGI(TAG, "restarting to apply update");
	esp_restart();
}

void ota_schedule_reboot_ms(int delay_ms) {
	TaskHandle_t t = NULL;
	xTaskCreate(reboot_task, "ota_reboot", 2048, (void*)(intptr_t)delay_ms, 5, &t);
}


