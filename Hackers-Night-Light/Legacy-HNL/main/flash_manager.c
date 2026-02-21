#include "flash_manager.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include <string.h>

esp_err_t flash_manager_init(flash_manager_t *mgr, const char *partition_label, const char *tag) {
    if (!mgr || !partition_label) return ESP_ERR_INVALID_ARG;
    
    mgr->partition = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, 0x99, partition_label);
    if (!mgr->partition) {
        ESP_LOGE(tag, "partition '%s' not found", partition_label);
        return ESP_ERR_NOT_FOUND;
    }
    
    mgr->mutex = xSemaphoreCreateMutex();
    if (!mgr->mutex) {
        ESP_LOGE(tag, "failed to create mutex");
        return ESP_ERR_NO_MEM;
    }
    
    mgr->tag = tag;
    
    ESP_LOGI(tag, "initialized partition '%s' at 0x%lx, size %lu KB",
             partition_label,
             (unsigned long)mgr->partition->address,
             (unsigned long)mgr->partition->size / 1024);
    
    return ESP_OK;
}

esp_err_t flash_manager_write(flash_manager_t *mgr, uint32_t offset, const void *data, size_t size) {
    if (!mgr || !mgr->partition || !data) return ESP_ERR_INVALID_ARG;
    if (!mgr->mutex) return ESP_ERR_INVALID_STATE;
    
    xSemaphoreTake((SemaphoreHandle_t)mgr->mutex, portMAX_DELAY);
    
    // calculate sector range to erase
    uint32_t sector_start = (offset / FLASH_SECTOR_SIZE) * FLASH_SECTOR_SIZE;
    uint32_t sector_end = ((offset + size + FLASH_SECTOR_SIZE - 1) / FLASH_SECTOR_SIZE) * FLASH_SECTOR_SIZE;
    uint32_t erase_size = sector_end - sector_start;
    
    // erase sectors
    esp_err_t err = esp_partition_erase_range(mgr->partition, sector_start, erase_size);
    if (err != ESP_OK) {
        ESP_LOGE(mgr->tag, "erase failed at 0x%lx size %lu: %s", 
                 (unsigned long)sector_start, (unsigned long)erase_size, esp_err_to_name(err));
        xSemaphoreGive((SemaphoreHandle_t)mgr->mutex);
        return err;
    }
    
    // write data
    err = esp_partition_write(mgr->partition, offset, data, size);
    if (err != ESP_OK) {
        ESP_LOGE(mgr->tag, "write failed at 0x%lx size %lu: %s",
                 (unsigned long)offset, (unsigned long)size, esp_err_to_name(err));
    }
    
    xSemaphoreGive((SemaphoreHandle_t)mgr->mutex);
    return err;
}

esp_err_t flash_manager_read(flash_manager_t *mgr, uint32_t offset, void *data, size_t size) {
    if (!mgr || !mgr->partition || !data) return ESP_ERR_INVALID_ARG;
    if (!mgr->mutex) return ESP_ERR_INVALID_STATE;
    
    xSemaphoreTake((SemaphoreHandle_t)mgr->mutex, portMAX_DELAY);
    
    esp_err_t err = esp_partition_read(mgr->partition, offset, data, size);
    if (err != ESP_OK) {
        ESP_LOGW(mgr->tag, "read failed at 0x%lx size %lu: %s",
                 (unsigned long)offset, (unsigned long)size, esp_err_to_name(err));
    }
    
    xSemaphoreGive((SemaphoreHandle_t)mgr->mutex);
    return err;
}

esp_err_t flash_manager_erase_range(flash_manager_t *mgr, uint32_t offset, size_t size) {
    if (!mgr || !mgr->partition) return ESP_ERR_INVALID_ARG;
    if (!mgr->mutex) return ESP_ERR_INVALID_STATE;
    
    // align to sector boundaries
    uint32_t sector_start = (offset / FLASH_SECTOR_SIZE) * FLASH_SECTOR_SIZE;
    uint32_t sector_end = ((offset + size + FLASH_SECTOR_SIZE - 1) / FLASH_SECTOR_SIZE) * FLASH_SECTOR_SIZE;
    uint32_t erase_size = sector_end - sector_start;
    
    xSemaphoreTake((SemaphoreHandle_t)mgr->mutex, portMAX_DELAY);
    
    esp_err_t err = esp_partition_erase_range(mgr->partition, sector_start, erase_size);
    if (err != ESP_OK) {
        ESP_LOGE(mgr->tag, "erase range failed at 0x%lx size %lu: %s",
                 (unsigned long)sector_start, (unsigned long)erase_size, esp_err_to_name(err));
    }
    
    xSemaphoreGive((SemaphoreHandle_t)mgr->mutex);
    return err;
}

esp_err_t flash_manager_erase_all(flash_manager_t *mgr) {
    if (!mgr || !mgr->partition) return ESP_ERR_INVALID_ARG;
    if (!mgr->mutex) return ESP_ERR_INVALID_STATE;
    
    xSemaphoreTake((SemaphoreHandle_t)mgr->mutex, portMAX_DELAY);
    
    esp_err_t err = esp_partition_erase_range(mgr->partition, 0, mgr->partition->size);
    if (err != ESP_OK) {
        ESP_LOGE(mgr->tag, "erase all failed: %s", esp_err_to_name(err));
    } else {
        ESP_LOGI(mgr->tag, "erased entire partition (%lu KB)", 
                 (unsigned long)mgr->partition->size / 1024);
    }
    
    xSemaphoreGive((SemaphoreHandle_t)mgr->mutex);
    return err;
}

esp_err_t flash_manager_ring_write(flash_manager_t *mgr, ring_buffer_ctx_t *ctx, const void *data) {
    if (!mgr || !mgr->partition || !ctx || !data) return ESP_ERR_INVALID_ARG;
    if (!mgr->mutex) return ESP_ERR_INVALID_STATE;
    
    xSemaphoreTake((SemaphoreHandle_t)mgr->mutex, portMAX_DELAY);
    
    uint32_t write_idx = ctx->write_idx;
    uint32_t offset = ctx->base_offset + (write_idx * ctx->item_size);
    
    // check if we need to erase a new sector
    // erase when crossing sector boundary or wrapping to start
    uint32_t current_sector = offset / FLASH_SECTOR_SIZE;
    uint32_t prev_offset = ctx->base_offset + 
                           (((write_idx == 0) ? (ctx->max_items - 1) : (write_idx - 1)) * ctx->item_size);
    uint32_t prev_sector = prev_offset / FLASH_SECTOR_SIZE;
    
    if (current_sector != prev_sector || write_idx == 0) {
        // erase the sector this item will be written to
        uint32_t sector_start = (offset / FLASH_SECTOR_SIZE) * FLASH_SECTOR_SIZE;
        esp_err_t erase_err = esp_partition_erase_range(mgr->partition, sector_start, FLASH_SECTOR_SIZE);
        if (erase_err != ESP_OK) {
            ESP_LOGW(mgr->tag, "ring buffer erase failed at 0x%lx: %s",
                     (unsigned long)sector_start, esp_err_to_name(erase_err));
            xSemaphoreGive((SemaphoreHandle_t)mgr->mutex);
            return erase_err;
        }
    }
    
    // write the item
    esp_err_t err = esp_partition_write(mgr->partition, offset, data, ctx->item_size);
    if (err != ESP_OK) {
        ESP_LOGE(mgr->tag, "ring buffer write failed at 0x%lx: %s",
                 (unsigned long)offset, esp_err_to_name(err));
        xSemaphoreGive((SemaphoreHandle_t)mgr->mutex);
        return err;
    }
    
    // update ring buffer pointers
    ctx->write_idx = (write_idx + 1) % ctx->max_items;
    if (ctx->count < ctx->max_items) {
        ctx->count++;
    }
    
    xSemaphoreGive((SemaphoreHandle_t)mgr->mutex);
    return ESP_OK;
}

esp_err_t flash_manager_ring_read(flash_manager_t *mgr, ring_buffer_ctx_t *ctx,
                                   uint32_t start_idx, uint32_t count, void *out_data, uint32_t *actual_count) {
    if (!mgr || !mgr->partition || !ctx || !out_data || !actual_count) return ESP_ERR_INVALID_ARG;
    if (!mgr->mutex) return ESP_ERR_INVALID_STATE;
    
    xSemaphoreTake((SemaphoreHandle_t)mgr->mutex, portMAX_DELAY);
    
    uint32_t total = ctx->count;
    
    // safety check: if count is 0, return immediately
    if (total == 0) {
        *actual_count = 0;
        xSemaphoreGive((SemaphoreHandle_t)mgr->mutex);
        return ESP_OK;
    }
    
    if (start_idx >= total) {
        *actual_count = 0;
        xSemaphoreGive((SemaphoreHandle_t)mgr->mutex);
        return ESP_OK;
    }
    
    uint32_t read_count = total - start_idx;
    if (read_count > count) read_count = count;
    *actual_count = read_count;
    
    // calculate oldest item index in ring buffer
    uint32_t oldest_idx = flash_manager_ring_get_oldest_idx(ctx);
    
    // read items in order
    uint8_t *output = (uint8_t *)out_data;
    for (uint32_t i = 0; i < read_count; i++) {
        uint32_t read_idx = (oldest_idx + start_idx + i) % ctx->max_items;
        uint32_t offset = ctx->base_offset + (read_idx * ctx->item_size);
        
        esp_err_t err = esp_partition_read(mgr->partition, offset, 
                                            output + (i * ctx->item_size), ctx->item_size);
        if (err != ESP_OK) {
            ESP_LOGE(mgr->tag, "ring buffer read failed at 0x%lx: %s",
                     (unsigned long)offset, esp_err_to_name(err));
            xSemaphoreGive((SemaphoreHandle_t)mgr->mutex);
            return err;
        }
    }
    
    xSemaphoreGive((SemaphoreHandle_t)mgr->mutex);
    return ESP_OK;
}
