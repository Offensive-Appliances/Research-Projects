#ifndef MDNS_SERVICE_H
#define MDNS_SERVICE_H

#include "esp_err.h"
#include <stdbool.h>

/**
 * @brief Initialize mDNS service
 * 
 * @param hostname Hostname to set (e.g. "pwnpower")
 * @return esp_err_t ESP_OK on success
 */
esp_err_t mdns_service_init(const char *hostname);

/**
 * @brief Update mDNS hostname
 * 
 * @param hostname New hostname
 * @return esp_err_t ESP_OK on success
 */
esp_err_t mdns_service_update_hostname(const char *hostname);

/**
 * @brief Get current hostname
 * 
 * @return const char* Current hostname
 */
const char* mdns_service_get_hostname(void);

/**
 * @brief Check if mDNS is initialized
 * 
 * @return true if initialized
 */
bool mdns_service_is_initialized(void);

#endif // MDNS_SERVICE_H
