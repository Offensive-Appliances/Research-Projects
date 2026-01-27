#ifndef MDNS_SERVICE_H
#define MDNS_SERVICE_H

#include "esp_err.h"
#include <stdbool.h>

esp_err_t mdns_service_init(const char *hostname);
esp_err_t mdns_service_update_hostname(const char *hostname);
const char* mdns_service_get_hostname(void);
bool mdns_service_is_initialized(void);

#endif
