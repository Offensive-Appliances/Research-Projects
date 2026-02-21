#ifndef FLASH_MANAGER_H
#define FLASH_MANAGER_H

#include "esp_partition.h"
#include "esp_err.h"
#include <stdint.h>
#include <stddef.h>

#define FLASH_SECTOR_SIZE 4096

// flash manager context for a partition
typedef struct {
    const esp_partition_t *partition;
    void *mutex;  // SemaphoreHandle_t but void* to avoid including freertos headers
    const char *tag;  // for logging
} flash_manager_t;

// initialize a flash manager for a partition
esp_err_t flash_manager_init(flash_manager_t *mgr, const char *partition_label, const char *tag);

// smart write with auto-erase (handles sector boundaries automatically)
esp_err_t flash_manager_write(flash_manager_t *mgr, uint32_t offset, const void *data, size_t size);

// read from partition (mutex protected)
esp_err_t flash_manager_read(flash_manager_t *mgr, uint32_t offset, void *data, size_t size);

// erase a range (mutex protected)
esp_err_t flash_manager_erase_range(flash_manager_t *mgr, uint32_t offset, size_t size);

// erase entire partition
esp_err_t flash_manager_erase_all(flash_manager_t *mgr);

// ring buffer helpers
typedef struct {
    uint32_t base_offset;    // start of ring buffer in partition
    uint32_t item_size;      // size of each item
    uint32_t max_items;      // max number of items in ring
    uint32_t write_idx;      // current write index (0 to max_items-1)
    uint32_t count;          // number of items written (up to max_items)
} ring_buffer_ctx_t;

// write to ring buffer (handles wrap-around and sector erasing)
esp_err_t flash_manager_ring_write(flash_manager_t *mgr, ring_buffer_ctx_t *ctx, const void *data);

// read from ring buffer (handles chronological order)
esp_err_t flash_manager_ring_read(flash_manager_t *mgr, ring_buffer_ctx_t *ctx, 
                                   uint32_t start_idx, uint32_t count, void *out_data, uint32_t *actual_count);

// get ring buffer stats
static inline uint32_t flash_manager_ring_get_count(const ring_buffer_ctx_t *ctx) {
    return ctx->count;
}

static inline uint32_t flash_manager_ring_get_oldest_idx(const ring_buffer_ctx_t *ctx) {
    if (ctx->count < ctx->max_items) {
        return 0;
    }
    return ctx->write_idx;
}

#endif // FLASH_MANAGER_H
