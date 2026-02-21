#include "json_utils.h"
#include "esp_log.h"
#include "esp_http_server.h"
#include "esp_heap_trace.h"
#include <string.h>
#include <stdlib.h>

static const char *TAG = "json_utils";

esp_err_t json_send_response(httpd_req_t *req, cJSON *root) {
    if (!req || !root) {
        if (root) cJSON_Delete(root);
        return ESP_ERR_INVALID_ARG;
    }
    
    // Check heap health before processing
    uint32_t free_heap = esp_get_free_heap_size();
    if (free_heap < 4096) {
        ESP_LOGE(TAG, "Critical heap exhaustion: %lu bytes", (unsigned long)free_heap);
        cJSON_Delete(root);
        return ESP_ERR_NO_MEM;
    }
    
    // Check if client is still connected
    if (!json_client_connected(req)) {
        ESP_LOGD(TAG, "Client disconnected, skipping JSON response");
        cJSON_Delete(root);
        return ESP_ERR_TIMEOUT; // Use timeout for connection issues
    }
    
    // Create JSON string
    char *json_str = json_create_string(root);
    cJSON_Delete(root);
    
    if (!json_str) {
        ESP_LOGE(TAG, "Failed to create JSON string");
        return ESP_ERR_NO_MEM;
    }
    
    // Set content type and send
    esp_err_t err = httpd_resp_set_type(req, "application/json");
    if (err != ESP_OK) {
        free(json_str);
        return err;
    }
    
    err = httpd_resp_sendstr(req, json_str);
    free(json_str);
    
    if (err != ESP_OK) {
        ESP_LOGD(TAG, "Failed to send JSON response: %s", esp_err_to_name(err));
    }
    
    return err;
}

char* json_create_string(cJSON *root) {
    if (!root) return NULL;
    
    return cJSON_PrintUnformatted(root);
}

char* json_print_sized(cJSON *root, size_t max_size, size_t *out_len) {
    if (!root) return NULL;
    
    char *json_str = cJSON_PrintUnformatted(root);
    if (!json_str) return NULL;
    
    size_t len = strlen(json_str);
    
    if (len >= max_size) {
        ESP_LOGW(TAG, "JSON too large (%zu bytes), limit is %zu", len, max_size);
        free(json_str);
        return NULL;
    }
    
    if (out_len) *out_len = len;
    return json_str;
}

bool json_client_connected(httpd_req_t *req) {
    if (!req) return false;
    
    // Try to get socket descriptor to check connection
    int sockfd = httpd_req_to_sockfd(req);
    if (sockfd < 0) return false;
    
    // Simple check - if we can get the socket, assume connected
    // More sophisticated checks could be added if needed
    return true;
}
