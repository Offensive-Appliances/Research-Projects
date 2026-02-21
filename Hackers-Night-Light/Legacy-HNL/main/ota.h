#pragma once
#include "esp_err.h"
#include "esp_ota_ops.h"
#include "esp_partition.h"

esp_err_t ota_begin(size_t expected_size, esp_ota_handle_t *out_handle, const esp_partition_t **out_part);
esp_err_t ota_write(esp_ota_handle_t handle, const void *data, size_t len);
esp_err_t ota_finish_and_set_boot(esp_ota_handle_t handle, const esp_partition_t *part);
void ota_schedule_reboot_ms(int delay_ms);


