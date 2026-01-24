#ifndef JSON_UTILS_H
#define JSON_UTILS_H

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"
#include "cJSON.h"

// Forward declaration to avoid including web server headers
struct httpd_req;
typedef struct httpd_req httpd_req_t;

/**
 * Send JSON response with proper memory management
 * Handles client disconnect detection and automatic cleanup
 * 
 * @param req HTTP request handle
 * @param root cJSON object to send (will be deleted)
 * @return ESP_OK on success, error code on failure
 */
esp_err_t json_send_response(httpd_req_t *req, cJSON *root);

/**
 * Create JSON string with memory allocation
 * Returns dynamically allocated string that must be freed
 * 
 * @param root cJSON object to serialize
 * @return Allocated JSON string or NULL on failure
 */
char* json_create_string(cJSON *root);

/**
 * Safe cJSON printing with size limit
 * Uses dynamic allocation with fallback handling
 * 
 * @param root cJSON object to serialize
 * @param max_size Maximum allowed size
 * @param out_len Output length (optional)
 * @return Allocated JSON string or NULL on failure
 */
char* json_print_sized(cJSON *root, size_t max_size, size_t *out_len);

/**
 * Check if HTTP client is still connected
 * Helps avoid sending data to disconnected clients
 * 
 * @param req HTTP request handle
 * @return true if client is connected, false otherwise
 */
bool json_client_connected(httpd_req_t *req);

#endif // JSON_UTILS_H
