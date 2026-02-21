#include "esp_http_server.h"
#include "esp_https_server.h"
#include "esp_log.h"
#include "http_parser.h"
#include "wifi_scan.h"
#include "cJSON.h"
#include "deauth.h"
#include "handshake.h"
#include "ota.h"
#include "esp_http_client.h"
#include "esp_timer.h"
#include "scan_storage.h"
#include "background_scan.h"
#include "ap_config.h"
#include "sta_config.h"
#include "idle_scanner.h"
#include "nvs_flash.h"
#include "ouis.h"
#include "device_db.h"
#include "device_lifecycle.h"
#include "webhook.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "driver/gpio.h"
#include "monitor_uptime.h"
#include "json_utils.h"
#include "tls_cert.h"
#include "nvs.h"
#include "esp_random.h"
#include <stddef.h>
#include <time.h>
#include <string.h>
#include "peer_discovery.h"
#include "firmware_info.h"
#include "esp_chip_info.h"
#include "esp_ota_ops.h"
#include "esp_system.h"

extern const uint8_t _binary_web_content_gz_h_start[] asm("_binary_web_content_gz_h_start");
extern const uint8_t _binary_web_content_gz_h_end[] asm("_binary_web_content_gz_h_end");
extern const uint8_t _binary_login_content_gz_h_start[] asm("_binary_login_content_gz_h_start");
extern const uint8_t _binary_login_content_gz_h_end[] asm("_binary_login_content_gz_h_end");

#define WEB_UI_GZ         ((const char *)_binary_web_content_gz_h_start)
#define WEB_UI_GZ_SIZE    ((size_t)(_binary_web_content_gz_h_end - _binary_web_content_gz_h_start))
#define LOGIN_UI_GZ       ((const char *)_binary_login_content_gz_h_start)
#define LOGIN_UI_GZ_SIZE  ((size_t)(_binary_login_content_gz_h_end - _binary_login_content_gz_h_start))

extern bool pwnpower_time_is_synced(void);
// some SDK versions expose gpio_pad_select_gpio as esp_rom_gpio_pad_select_gpio
#ifndef gpio_pad_select_gpio
#define gpio_pad_select_gpio esp_rom_gpio_pad_select_gpio
#endif

#define TAG "WebServer"

#define SMARTPLUG_GPIO 4
static int s_smartplug_level = 0;
static bool s_smartplug_inited = false;

#ifndef HTTPD_503_SERVICE_UNAVAILABLE
#define HTTPD_503_SERVICE_UNAVAILABLE 503
#endif

#define MAX_HS_STA 10
typedef struct { uint8_t bssid[6]; int channel; int duration; uint8_t stas[MAX_HS_STA][6]; int sta_count; } hs_args_t;
static TaskHandle_t hs_task_handle = NULL;
static hs_args_t hs_args;

static httpd_handle_t s_https_server = NULL;
static httpd_handle_t s_http_redirect_server = NULL; // http->https redirect server
static tls_cert_bundle_t s_tls_bundle;

static char s_ui_password[65] = {0};
static char s_auth_token[65] = {0};

static esp_err_t register_routes(httpd_handle_t server);
static httpd_handle_t start_https_server(void);
static httpd_handle_t start_http_redirect_server(void);
static esp_err_t wifi_status_handler(httpd_req_t *req);
static bool wizard_is_completed(void);
static bool auth_is_authorized(httpd_req_t *req);

static volatile bool g_sta_connected = false;
static bool g_ip_handler_registered = false;
static bool g_wifi_handler_registered = false;
static bool s_wifi_inited = false;
static volatile uint32_t g_last_request_time = 0;

void webserver_set_sta_connected(bool connected) {
    g_sta_connected = connected;
}

bool webserver_get_sta_connected(void) {
    return g_sta_connected;
}

uint32_t webserver_get_last_request_time(void) {
    return g_last_request_time;
}

static void update_last_request_time(void) {
    g_last_request_time = (uint32_t)(esp_timer_get_time() / 1000000ULL);
}

static void auth_generate_token(void) {
    for (int i = 0; i < 32; i++) {
        uint8_t b = (uint8_t)(esp_random() & 0xFF);
        snprintf(&s_auth_token[i * 2], 3, "%02x", b);
    }
    s_auth_token[64] = '\0';
}

static void auth_load_password(void) {
    nvs_handle_t handle;
    esp_err_t err = nvs_open("ui_auth", NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to open NVS for auth: %s", esp_err_to_name(err));
        s_ui_password[0] = '\0';
        return;
    }

    size_t len = sizeof(s_ui_password);
    err = nvs_get_str(handle, "password", s_ui_password, &len);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        s_ui_password[0] = '\0';
        ESP_LOGI(TAG, "No UI password set - auth disabled");
    } else if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to read auth password: %s", esp_err_to_name(err));
        s_ui_password[0] = '\0';
    }

    nvs_close(handle);
}

static bool auth_is_authorized(httpd_req_t *req) {
    // If password is unset/empty, auth is effectively disabled
    if (s_ui_password[0] == '\0') {
        return true;
    }

    // 1) Bearer header
    char auth_hdr[128] = {0};
    if (httpd_req_get_hdr_value_str(req, "Authorization", auth_hdr, sizeof(auth_hdr)) != ESP_OK) {
        auth_hdr[0] = '\0';
    }

    const char prefix[] = "Bearer ";
    size_t prefix_len = strlen(prefix);
    if (strncmp(auth_hdr, prefix, prefix_len) == 0) {
        const char *token = auth_hdr + prefix_len;
        if (strlen(token) == strlen(s_auth_token) && s_auth_token[0] != '\0' && strcmp(token, s_auth_token) == 0) {
            return true;
        }
    }

    // 2) Cookie fallback
    char cookie_hdr[256] = {0};
    if (httpd_req_get_hdr_value_str(req, "Cookie", cookie_hdr, sizeof(cookie_hdr)) == ESP_OK) {
        const char *p = strstr(cookie_hdr, "auth_token=");
        if (p) {
            p += strlen("auth_token=");
            char token_buf[65] = {0};
            int i = 0;
            while (*p && *p != ';' && i < (int)sizeof(token_buf) - 1) {
                token_buf[i++] = *p++;
            }
            token_buf[i] = '\0';
            if (strlen(token_buf) == strlen(s_auth_token) && strcmp(token_buf, s_auth_token) == 0) {
                return true;
            }
        }
    }

    return false;
}

static bool auth_require(httpd_req_t *req) {
    if (auth_is_authorized(req)) return true;

    ESP_LOGW(TAG, "Auth rejected uri=%s", req->uri);
    httpd_resp_set_status(req, "401 Unauthorized");
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "WWW-Authenticate", "Bearer");
    httpd_resp_sendstr(req, "{\"error\":\"unauthorized\"}");
    return false;
}

static esp_err_t auth_status_handler(httpd_req_t *req) {
    update_last_request_time();
    bool ok = auth_is_authorized(req);

    cJSON *root = cJSON_CreateObject();
    cJSON_AddBoolToObject(root, "authorized", ok);
    cJSON_AddBoolToObject(root, "has_password", strlen(s_ui_password) > 0);
    char *json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, json);
    cJSON_free(json);
    return ESP_OK;
}

static esp_err_t system_info_handler(httpd_req_t *req) {
    update_last_request_time();

    cJSON *root = cJSON_CreateObject();
    
    // Firmware Info
    cJSON_AddStringToObject(root, "app_name", firmware_get_name());
    cJSON_AddStringToObject(root, "version", firmware_get_version());
    cJSON_AddStringToObject(root, "build_date", firmware_get_build_date());
    cJSON_AddStringToObject(root, "target", firmware_get_target());

    // Hardware/System Info
    esp_chip_info_t chip_info;
    esp_chip_info(&chip_info);
    cJSON_AddStringToObject(root, "idf_version", esp_get_idf_version());
    cJSON_AddNumberToObject(root, "chip_revision", (double)chip_info.revision);
    cJSON_AddNumberToObject(root, "cpu_cores", (double)chip_info.cores);
    
    // Memory Info
    cJSON_AddNumberToObject(root, "heap_free", (double)esp_get_free_heap_size());
    cJSON_AddNumberToObject(root, "heap_min_free", (double)esp_get_minimum_free_heap_size());
    
    // Uptime
    cJSON_AddNumberToObject(root, "uptime_sec", (double)(esp_timer_get_time() / 1000000ULL));

    char *json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, json);
    cJSON_free(json);
    return ESP_OK;
}

static esp_err_t auth_login_handler(httpd_req_t *req) {
    update_last_request_time();
    char buf[96];
    int ret = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (ret <= 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing body");
        return ESP_FAIL;
    }
    buf[ret] = '\0';

    cJSON *root = cJSON_Parse(buf);
    if (!root) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
        return ESP_FAIL;
    }

    cJSON *pass = cJSON_GetObjectItem(root, "password");
    if (!cJSON_IsString(pass)) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "password required");
        return ESP_FAIL;
    }

    if (s_ui_password[0] != '\0' && strcmp(pass->valuestring, s_ui_password) != 0) {
        cJSON_Delete(root);
        httpd_resp_set_status(req, "401 Unauthorized");
        httpd_resp_sendstr(req, "{\"error\":\"invalid\"}");
        return ESP_FAIL;
    }

    auth_generate_token();
    cJSON_Delete(root);

    cJSON *res = cJSON_CreateObject();
    cJSON_AddStringToObject(res, "token", s_auth_token);
    char *json = cJSON_PrintUnformatted(res);
    cJSON_Delete(res);

    // also set cookie for browsers to auto-send
    httpd_resp_set_hdr(req, "Set-Cookie", "auth_token=");
    char cookie_val[96];
    snprintf(cookie_val, sizeof(cookie_val), "auth_token=%s; Path=/; HttpOnly", s_auth_token);
    httpd_resp_set_hdr(req, "Set-Cookie", cookie_val);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, json);
    cJSON_free(json);
    return ESP_OK;
}

static esp_err_t auth_logout_handler(httpd_req_t *req) {
    update_last_request_time();
    s_auth_token[0] = '\0';
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Set-Cookie", "auth_token=; Path=/; Max-Age=0");
    httpd_resp_sendstr(req, "{\"status\":\"logged_out\"}");
    return ESP_OK;
}

static esp_err_t auth_password_handler(httpd_req_t *req) {
    update_last_request_time();
    bool authed = auth_is_authorized(req);

    char buf[160];
    int ret = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (ret <= 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing body");
        return ESP_FAIL;
    }
    buf[ret] = '\0';

    cJSON *root = cJSON_Parse(buf);
    if (!root) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
        return ESP_FAIL;
    }

    cJSON *current = cJSON_GetObjectItem(root, "current_password");
    cJSON *next = cJSON_GetObjectItem(root, "new_password");
    if (!cJSON_IsString(next) || strlen(next->valuestring) >= sizeof(s_ui_password)) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Password must be 0-64 chars");
        return ESP_FAIL;
    }

    size_t new_len = strlen(next->valuestring);
    bool disabling = new_len == 0;
    if (!disabling && new_len < 8) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Password must be 8-64 chars or empty to disable");
        return ESP_FAIL;
    }

    if (!authed) {
        if (s_ui_password[0] != '\0') {
            if (!cJSON_IsString(current) || strcmp(current->valuestring, s_ui_password) != 0) {
                cJSON_Delete(root);
                httpd_resp_set_status(req, "401 Unauthorized");
                httpd_resp_sendstr(req, "{\"error\":\"invalid\"}");
                return ESP_FAIL;
            }
        }
    }

    nvs_handle_t handle;
    if (nvs_open("ui_auth", NVS_READWRITE, &handle) != ESP_OK) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "NVS error");
        return ESP_FAIL;
    }
    esp_err_t err = nvs_set_str(handle, "password", next->valuestring);
    if (err == ESP_OK) err = nvs_commit(handle);
    nvs_close(handle);

    if (err != ESP_OK) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to save password");
        return ESP_FAIL;
    }

    strncpy(s_ui_password, next->valuestring, sizeof(s_ui_password) - 1);
    s_ui_password[sizeof(s_ui_password) - 1] = '\0';
    s_auth_token[0] = '\0';

    cJSON_Delete(root);

    httpd_resp_set_hdr(req, "Set-Cookie", "auth_token=; Path=/; Max-Age=0");

    cJSON *res = cJSON_CreateObject();
    cJSON_AddStringToObject(res, "status", "updated");
    cJSON_AddBoolToObject(res, "disabled", disabling);
    char *json = cJSON_PrintUnformatted(res);
    cJSON_Delete(res);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, json);
    cJSON_free(json);
    return ESP_OK;
}

typedef esp_err_t (*route_handler_fn)(httpd_req_t *req);

static esp_err_t authed_handler(httpd_req_t *req) {
    route_handler_fn fn = (route_handler_fn)req->user_ctx;
    if (!fn) return ESP_FAIL;
    if (!auth_require(req)) return ESP_OK; // already responded 401
    return fn(req);
}

static httpd_uri_t uri_auth_status = { .uri = "/auth/status", .method = HTTP_GET, .handler = auth_status_handler, .user_ctx = NULL };
static httpd_uri_t uri_auth_login = { .uri = "/auth/login", .method = HTTP_POST, .handler = auth_login_handler, .user_ctx = NULL };
static httpd_uri_t uri_auth_logout = { .uri = "/auth/logout", .method = HTTP_POST, .handler = auth_logout_handler, .user_ctx = NULL };
static httpd_uri_t uri_auth_password = { .uri = "/auth/password", .method = HTTP_POST, .handler = auth_password_handler, .user_ctx = NULL };

#define NVS_WIZARD_NAMESPACE "wizard"
#define NVS_WIZARD_KEY "completed"

static bool wizard_is_completed(void) {
    nvs_handle_t handle;
    if (nvs_open(NVS_WIZARD_NAMESPACE, NVS_READONLY, &handle) != ESP_OK) {
        return false;
    }
    uint8_t val = 0;
    nvs_get_u8(handle, NVS_WIZARD_KEY, &val);
    nvs_close(handle);
    return val != 0;
}

static esp_err_t wizard_set_completed(bool completed) {
    nvs_handle_t handle;
    esp_err_t err = nvs_open(NVS_WIZARD_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) return err;
    err = nvs_set_u8(handle, NVS_WIZARD_KEY, completed ? 1 : 0);
    if (err == ESP_OK) err = nvs_commit(handle);
    nvs_close(handle);
    return err;
}

static esp_err_t wizard_status_handler(httpd_req_t *req) {
    update_last_request_time();
    bool completed = wizard_is_completed();
    
    cJSON *root = cJSON_CreateObject();
    cJSON_AddBoolToObject(root, "completed", completed);
    char *json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, json);
    cJSON_free(json);
    return ESP_OK;
}

static esp_err_t wizard_complete_handler(httpd_req_t *req) {
    update_last_request_time();
    
    esp_err_t err = wizard_set_completed(true);
    if (err != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to save wizard state");
        return ESP_FAIL;
    }
    
    ESP_LOGI(TAG, "Setup wizard completed");
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"status\":\"ok\"}");
    return ESP_OK;
}

static esp_err_t wizard_reset_handler(httpd_req_t *req) {
    update_last_request_time();
    
    esp_err_t err = wizard_set_completed(false);
    if (err != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to reset wizard state");
        return ESP_FAIL;
    }
    
    ESP_LOGI(TAG, "Setup wizard reset");
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"status\":\"ok\"}");
    return ESP_OK;
}

static httpd_uri_t uri_wizard_status = { .uri = "/wizard/status", .method = HTTP_GET, .handler = wizard_status_handler, .user_ctx = NULL };
static httpd_uri_t uri_wizard_complete = { .uri = "/wizard/complete", .method = HTTP_POST, .handler = wizard_complete_handler, .user_ctx = NULL };

static void register_authed(httpd_handle_t server, const char *uri, httpd_method_t method, route_handler_fn fn) {
    httpd_uri_t cfg = { .uri = uri, .method = method, .handler = authed_handler, .user_ctx = fn };
    httpd_register_uri_handler(server, &cfg);
}

static void ip_event_handler(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data) {
    if (event_id == IP_EVENT_STA_GOT_IP) {
        g_sta_connected = true;
        ESP_LOGI(TAG, "STA got IP");
    }
}

static void wifi_event_handler(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data) {
    if (event_id == WIFI_EVENT_STA_DISCONNECTED) {
        g_sta_connected = false;
        ESP_LOGI(TAG, "STA disconnected");
    }
}

static bool attempt_sta_connect(const char *ssid, const char *password,
                                wifi_auth_mode_t threshold_mode,
                                bool pmf_required,
                                uint32_t wait_ms) {
    if (!s_wifi_inited) {
        wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
        if (esp_wifi_init(&cfg) != ESP_OK) {
            ESP_LOGE(TAG, "esp_wifi_init failed");
            return false;
        }
        s_wifi_inited = true;
    }

    // ensure netif + event loop
    esp_netif_init();
    esp_event_loop_create_default();
    // avoid creating duplicate default STA netif
    if (esp_netif_get_handle_from_ifkey("WIFI_STA_DEF") == NULL) {
        esp_netif_create_default_wifi_sta();
    }

    // register handlers once
    if (!g_ip_handler_registered) {
        if (esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &ip_event_handler, NULL) == ESP_OK) g_ip_handler_registered = true;
    }
    if (!g_wifi_handler_registered) {
        if (esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, &wifi_event_handler, NULL) == ESP_OK) g_wifi_handler_registered = true;
    }

    // keep AP running while adding STA - use APSTA mode so AP continues to host
    // do not stop wifi here (that would tear down the AP)
    esp_wifi_set_mode(WIFI_MODE_APSTA);

    wifi_config_t sta_cfg = {0};
    if (ssid) strncpy((char*)sta_cfg.sta.ssid, ssid, sizeof(sta_cfg.sta.ssid));
    if (password) strncpy((char*)sta_cfg.sta.password, password, sizeof(sta_cfg.sta.password));
    sta_cfg.sta.threshold.authmode = threshold_mode;
    sta_cfg.sta.pmf_cfg.capable = true;
    sta_cfg.sta.pmf_cfg.required = pmf_required;
#ifdef WPA3_SAE_PWE_BOTH
    sta_cfg.sta.sae_pwe_h2e = WPA3_SAE_PWE_BOTH;
#endif
    esp_wifi_set_config(WIFI_IF_STA, &sta_cfg);
    esp_wifi_start();
    vTaskDelay(pdMS_TO_TICKS(100));
    esp_wifi_set_ps(WIFI_PS_NONE);

    ESP_LOGI(TAG, "Attempting STA connect ssid=\"%s\" threshold=%d pmf_required=%s wait_ms=%u", ssid, threshold_mode, pmf_required ? "true" : "false", wait_ms);

    g_sta_connected = false;
    esp_err_t e = esp_wifi_connect();
    if (e != ESP_OK) {
        ESP_LOGE(TAG, "esp_wifi_connect err=%d", e);
        return false;
    }

    uint32_t waited = 0;
    while (!g_sta_connected && waited < wait_ms) {
        vTaskDelay(pdMS_TO_TICKS(100));
        waited += 100;
    }
    return g_sta_connected;
}
static void hs_task(void *arg) {
	hs_args_t *a = (hs_args_t*)arg;
	ESP_LOGI(TAG, "hs_task start: bssid=%02X:%02X:%02X:%02X:%02X:%02X channel=%d duration=%d sta_count=%d",
			a->bssid[0], a->bssid[1], a->bssid[2], a->bssid[3], a->bssid[4], a->bssid[5], a->channel, a->duration, a->sta_count);
	vTaskDelay(pdMS_TO_TICKS(300));
	int e = 0;
	start_handshake_capture(a->bssid, a->channel, a->duration, a->stas, a->sta_count, &e);
	ESP_LOGI(TAG, "Handshake capture done: eapol=%d", e);
	hs_task_handle = NULL;
	vTaskDelete(NULL);
}

static esp_err_t index_handler(httpd_req_t *req) {
    update_last_request_time();

    ESP_LOGI(TAG, "index_handler called, heap=%lu", (unsigned long)esp_get_free_heap_size());

    bool wizard_done = wizard_is_completed();
    ESP_LOGI(TAG, "Wizard completed: %s", wizard_done ? "yes" : "no");
    
    if (wizard_done && !auth_is_authorized(req)) {
        ESP_LOGI(TAG, "Redirecting to login page");
        httpd_resp_set_status(req, "302 Found");
        httpd_resp_set_hdr(req, "Location", "/login");
        httpd_resp_send(req, NULL, 0);
        return ESP_OK;
    }

    char etag_buf[64];
    size_t buf_len = sizeof(etag_buf);
    if (httpd_req_get_hdr_value_str(req, "If-None-Match", etag_buf, buf_len) == ESP_OK) {
        if (strcmp(etag_buf, "\"pwn-v1\"") == 0) {
            ESP_LOGD(TAG, "Cached UI 304");
            httpd_resp_set_status(req, "304 Not Modified");
            httpd_resp_send(req, NULL, 0);
            return ESP_OK;
        }
    }

    ESP_LOGD(TAG, "Sending UI (%u bytes)", (unsigned int)WEB_UI_GZ_SIZE);

    httpd_resp_set_type(req, "text/html");
    httpd_resp_set_hdr(req, "Content-Encoding", "gzip");
    httpd_resp_set_hdr(req, "Cache-Control", "no-cache");
    httpd_resp_set_hdr(req, "ETag", "\"pwn-v1\"");

    // Send UI in 4KB chunks to reduce memory pressure
    const size_t chunk_size = 4096;
    size_t sent = 0;
    esp_err_t ret = ESP_OK;

    while (sent < WEB_UI_GZ_SIZE) {
        size_t len = WEB_UI_GZ_SIZE - sent;
        if (len > chunk_size) len = chunk_size;
        ret = httpd_resp_send_chunk(req, WEB_UI_GZ + sent, len);
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "UI chunk send failed: %s", esp_err_to_name(ret));
            return ret;
        }
        sent += len;
    }

    // Terminate chunked response
    httpd_resp_send_chunk(req, NULL, 0);
    ESP_LOGD(TAG, "ROOT end heap=%lu", (unsigned long)esp_get_free_heap_size());

    return ret;
}

static esp_err_t login_page_handler(httpd_req_t *req) {
    update_last_request_time();
    
    httpd_resp_set_type(req, "text/html");
    httpd_resp_set_hdr(req, "Content-Encoding", "gzip");
    httpd_resp_set_hdr(req, "Cache-Control", "no-cache");
    
    // Send Login UI in 4KB chunks
    const size_t chunk_size = 4096;
    size_t sent = 0;
    esp_err_t ret = ESP_OK;

    while (sent < LOGIN_UI_GZ_SIZE) {
        size_t len = LOGIN_UI_GZ_SIZE - sent;
        if (len > chunk_size) len = chunk_size;
        ret = httpd_resp_send_chunk(req, LOGIN_UI_GZ + sent, len);
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "Login UI chunk send failed: %s", esp_err_to_name(ret));
            return ret;
        }
        sent += len;
    }

    // Terminate chunked response
    httpd_resp_send_chunk(req, NULL, 0);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Login page send failed: %s", esp_err_to_name(ret));
    }
    return ret;
}

// Handler for scanning Wi-Fi networks
static uint32_t last_scan_request_time = 0;
static uint32_t scan_request_count = 0;
static char last_client_ip[INET6_ADDRSTRLEN] = {0};

static esp_err_t wifi_scan_handler(httpd_req_t *req) {
    update_last_request_time();

    ESP_LOGD(TAG, "scan req heap=%lu", (unsigned long)esp_get_free_heap_size());

    // Get timing information
    uint32_t current_time = (uint32_t)(esp_timer_get_time() / 1000); // milliseconds
    uint32_t time_since_last = current_time - last_scan_request_time;
    scan_request_count++;

    // Get connection info
    int sockfd = httpd_req_to_sockfd(req);
    struct sockaddr_in6 addr;
    socklen_t addr_size = sizeof(addr);
    char addr_str[INET6_ADDRSTRLEN] = "unknown";
    bool same_client = false;

    if (getpeername(sockfd, (struct sockaddr *)&addr, &addr_size) == 0) {
        inet_ntop(AF_INET6, &addr.sin6_addr, addr_str, sizeof(addr_str));
        same_client = (last_client_ip[0] != '\0' && strcmp(addr_str, last_client_ip) == 0);
        strncpy(last_client_ip, addr_str, sizeof(last_client_ip) - 1);
        last_client_ip[sizeof(last_client_ip) - 1] = '\0';

        ESP_LOGD(TAG, "SCAN #%lu from %s%s fd=%d dt=%lums",
                 (unsigned long)scan_request_count, addr_str,
                 same_client ? " (same)" : " (new)",
                 sockfd, (unsigned long)time_since_last);
    } else {
        ESP_LOGD(TAG, "SCAN #%lu fd=%d dt=%lums",
                 (unsigned long)scan_request_count, sockfd, (unsigned long)time_since_last);
    }

    last_scan_request_time = current_time;

    // check if deauth is running
    if(deauth_task_handle != NULL) {
        ESP_LOGW(TAG, "Cannot scan during active attack, returning 503");
        httpd_resp_send_err(req, HTTPD_503_SERVICE_UNAVAILABLE, "Cannot scan during active attack");
        return ESP_FAIL;
    }

    const char *cached_results = wifi_scan_get_results();
    size_t cached_len = cached_results ? strlen(cached_results) : 0;

    if(!wifi_scan_is_complete()) {
        ESP_LOGW(TAG, "Scan already in progress, returning cached results (scan_in_progress=true)");
        httpd_resp_set_type(req, "application/json");
        if(cached_len > 2) {
            httpd_resp_send(req, cached_results, cached_len);
        } else {
            httpd_resp_sendstr(req, "{\"rows\":[]}");
        }
        return ESP_OK;
    }

    ESP_LOGI(TAG, "No active scan detected (scan_in_progress=false), STARTING NEW SCAN NOW");
    wifi_scan();

    const char *latest_results = wifi_scan_get_results();
    size_t latest_len = latest_results ? strlen(latest_results) : 0;

    httpd_resp_set_type(req, "application/json");
    if(latest_len > 2) {
        httpd_resp_send(req, latest_results, latest_len);
    } else {
        httpd_resp_sendstr(req, "{\"rows\":[]}");
    }
    return ESP_OK;
}

static esp_err_t startattack_handler(httpd_req_t *req) {
    ESP_LOGI(TAG, "Received attack command");
    
    char query_str[200] = {0};
    char mac_str[18] = {0};
    char state_str[8] = {0};
    
    // Log request type and size
    size_t query_len = httpd_req_get_url_query_len(req);
    ESP_LOGD(TAG, "Incoming request: %s, query_len=%d", 
             query_len > 0 ? "GET" : "POST", query_len);

    // First try to get URL query string
    if(query_len > 0) {
        if(httpd_req_get_url_query_str(req, query_str, sizeof(query_str)) != ESP_OK) {
            httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid query params");
            return ESP_FAIL;
        }
    } else {
        // check POST body
        int ret = httpd_req_recv(req, query_str, sizeof(query_str)-1);
        if(ret <= 0) {
            httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing params");
            return ESP_FAIL;
        }
        query_str[ret] = '\0';  // Null-terminate
    }
    
    // Add raw data logging
    ESP_LOGD(TAG, "Raw input: %s", query_str);

    cJSON *root = cJSON_Parse(query_str);
    if (!root) {
        ESP_LOGE(TAG, "Failed to parse JSON: %s", query_str);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
        return ESP_FAIL;
    }

    // Log extracted values
    cJSON *mac_json = cJSON_GetObjectItem(root, "mac");
    cJSON *state_json = cJSON_GetObjectItem(root, "state");
    cJSON *channel_json = cJSON_GetObjectItem(root, "channel");
    ESP_LOGI(TAG, "Parsed MAC: %s, State: %s, Channel: %s", 
            mac_json ? mac_json->valuestring : "NULL",
            state_json ? state_json->valuestring : "NULL",
            channel_json ? channel_json->valuestring : "NULL");

    if (!cJSON_IsString(mac_json) || !cJSON_IsString(state_json) || !cJSON_IsString(channel_json)) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing/invalid fields");
        return ESP_FAIL;
    }

    strlcpy(mac_str, mac_json->valuestring, sizeof(mac_str));
    strlcpy(state_str, state_json->valuestring, sizeof(state_str));
    int target_channel = atoi(channel_json->valuestring);
    
    // new sta field parsing
    cJSON *sta_json = cJSON_GetObjectItem(root, "sta");
    bool has_specific_targets = false;
    
    // Store up to 10 target stations
    #define MAX_TARGET_STATIONS 10
    uint8_t target_stas[MAX_TARGET_STATIONS][6];
    int target_sta_count = 0;
    
    // First clear all entries
    memset(target_stas, 0, sizeof(target_stas));

    if (sta_json) {
        // Check if it's a string (single MAC) or an array (multiple MACs)
        if (cJSON_IsString(sta_json)) {
            // Single MAC address
            sscanf(sta_json->valuestring, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                &target_stas[0][0], &target_stas[0][1], &target_stas[0][2],
                &target_stas[0][3], &target_stas[0][4], &target_stas[0][5]);
            target_sta_count = 1;
            has_specific_targets = true;
            ESP_LOGI(TAG, "Single target client: %s", sta_json->valuestring);
        } 
        else if (cJSON_IsArray(sta_json)) {
            // Array of MAC addresses
            int size = cJSON_GetArraySize(sta_json);
            ESP_LOGI(TAG, "Found %d target clients", size);
            
            for (int i = 0; i < size && i < MAX_TARGET_STATIONS; i++) {
                cJSON *item = cJSON_GetArrayItem(sta_json, i);
                if (cJSON_IsString(item)) {
                    int converted = sscanf(item->valuestring, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                        &target_stas[i][0], &target_stas[i][1], &target_stas[i][2],
                        &target_stas[i][3], &target_stas[i][4], &target_stas[i][5]);
                    
                    if (converted == 6) {
                        // Check if this MAC is the same as the AP MAC - can't deauth yourself
                        if (mac_json && item->valuestring && strcmp(item->valuestring, mac_json->valuestring) == 0) {
                            ESP_LOGW(TAG, "Ignoring client MAC that matches AP MAC: %s", item->valuestring);
                        } else {
                            target_sta_count++;
                            has_specific_targets = true;
                            ESP_LOGI(TAG, "Target client %d: %s", i, item->valuestring);
                        }
                    } else {
                        ESP_LOGE(TAG, "Invalid MAC format for client %d: %s", i, item->valuestring);
                    }
                }
            }
        }
    }

    cJSON_Delete(root);

    ESP_LOGD(TAG, "Converting MAC: %s", mac_str);
    uint8_t target_bssid[6];
    int mac_conversion = sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
        &target_bssid[0], &target_bssid[1], &target_bssid[2],
        &target_bssid[3], &target_bssid[4], &target_bssid[5]);
    
    if(mac_conversion != 6) {
        ESP_LOGE(TAG, "Invalid MAC format: %s (converted %d/6 octets)", mac_str, mac_conversion);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Bad MAC");
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "Converted BSSID: %02X:%02X:%02X:%02X:%02X:%02X",
             target_bssid[0], target_bssid[1], target_bssid[2], target_bssid[3],
             target_bssid[4], target_bssid[5]);

    // 5Ghz: if(target_channel < 1 || target_channel > 165) {
    // 2.4Ghz: if(target_channel < 1 || target_channel > 14) {
    if(target_channel < 1 || target_channel > 165) {
        ESP_LOGE(TAG, "Invalid channel number: %d", target_channel);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid channel");
        return ESP_FAIL;
    }

    if(memcmp(target_bssid, "\xFF\xFF\xFF\xFF\xFF\xFF", 6) == 0) {
        ESP_LOGE(TAG, "Attempted broadcast DEAUTH attack!");
        httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "Broadcast not allowed");
        return ESP_FAIL;
    }

    // Log attack state change
    if(strcmp(state_str, "started") == 0) {
        if(!has_specific_targets) {
            // no sta provided - scan and attack all + broadcast
            wifi_scan_stations();
            const char *station_json = wifi_scan_get_station_results();
            cJSON *root = cJSON_Parse(station_json);
            
            // FIND AP'S STATIONS
            char ap_mac_str[18];
            snprintf(ap_mac_str, sizeof(ap_mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                    target_bssid[0], target_bssid[1], target_bssid[2],
                    target_bssid[3], target_bssid[4], target_bssid[5]);
            
            cJSON *ap_entry = cJSON_GetObjectItemCaseSensitive(root, ap_mac_str);
            if(ap_entry) {
                cJSON *stations = cJSON_GetObjectItem(ap_entry, "stations");
                cJSON *station;
                cJSON_ArrayForEach(station, stations) {
                    // ADD TARGETED ATTACK FOR EACH STA
                    cJSON *sta_mac_json = cJSON_GetObjectItem(station, "mac");
                    uint8_t sta_mac[6];
                    sscanf(sta_mac_json->valuestring, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                        &sta_mac[0], &sta_mac[1], &sta_mac[2],
                        &sta_mac[3], &sta_mac[4], &sta_mac[5]);
                        
                    wifi_manager_start_deauth(target_bssid, target_channel, sta_mac);
                }
            }
            // ADD BROADCAST ATTACK
            wifi_manager_start_deauth(target_bssid, target_channel, NULL);
            cJSON_Delete(root);
        } else {
            // direct targeted attack to specific clients + broadcast
            for (int i = 0; i < target_sta_count; i++) {
                // Skip if client MAC matches AP MAC - can't deauth yourself
                if (memcmp(target_stas[i], target_bssid, 6) == 0) {
                    ESP_LOGW(TAG, "Skipping client that matches AP MAC: %02X:%02X:%02X:%02X:%02X:%02X", 
                        target_stas[i][0], target_stas[i][1], target_stas[i][2],
                        target_stas[i][3], target_stas[i][4], target_stas[i][5]);
                    continue;
                }
                
                ESP_LOGI(TAG, "Sending deauth to client %d: %02X:%02X:%02X:%02X:%02X:%02X", 
                    i, target_stas[i][0], target_stas[i][1], target_stas[i][2],
                    target_stas[i][3], target_stas[i][4], target_stas[i][5]);
                    
                wifi_manager_start_deauth(target_bssid, target_channel, target_stas[i]);
            }
            // Also add broadcast attack
            wifi_manager_start_deauth(target_bssid, target_channel, NULL);
        }
    } else if(strcmp(state_str, "stopped") == 0) {
        ESP_LOGI(TAG, "STOPPING attack on %s", mac_str);
        wifi_manager_stop_deauth(target_bssid);
    } else {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid state");
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "Attack command processed successfully");
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"status\":\"success\"}");
    return ESP_OK;
}


static esp_err_t station_scan_handler(httpd_req_t *req) {
    if(deauth_task_handle != NULL) {
        httpd_resp_send_err(req, HTTPD_503_SERVICE_UNAVAILABLE, "scan blocked during attack");
        return ESP_FAIL;
    }
    
    wifi_scan_stations();
    const char *json = wifi_scan_get_station_results();
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, json, strlen(json));
    return ESP_OK;
}

// New handler that ONLY returns cached results without triggering a scan
static esp_err_t cached_scan_handler(httpd_req_t *req) {
    ESP_LOGD(TAG, "cached-scan heap=%lu", (unsigned long)esp_get_free_heap_size());

    // Get cached results with metadata
    const char *cached_results = wifi_scan_get_results();
    uint32_t timestamp = wifi_scan_get_results_timestamp();
    bool truncated = wifi_scan_was_truncated();
    bool in_progress = wifi_scan_is_in_progress();
    bool station_scan = wifi_scan_station_scan_running();

    httpd_resp_set_type(req, "application/json");

    // Build metadata string on stack (no malloc!)
    char metadata[160];
    snprintf(metadata, sizeof(metadata),
            ",\"timestamp\":%lu,\"truncated\":%s,\"scan_in_progress\":%s,\"station_scan_running\":%s}",
            (unsigned long)timestamp,
            truncated ? "true" : "false",
            in_progress ? "true" : "false",
            station_scan ? "true" : "false");

    if(cached_results && strlen(cached_results) > 2) {
        size_t cached_len = strlen(cached_results);

        // Use chunked sending - zero heap allocation!
        if (cached_results[cached_len - 1] == '}') {
            // Send everything except closing brace
            if (httpd_resp_send_chunk(req, cached_results, cached_len - 1) != ESP_OK) {
                return ESP_FAIL;
            }
            // Send metadata with closing brace
            if (httpd_resp_send_chunk(req, metadata, strlen(metadata)) != ESP_OK) {
                return ESP_FAIL;
            }
            // End chunked response
            httpd_resp_send_chunk(req, NULL, 0);
            return ESP_OK;
        }

        // Fallback: just send cached results as-is
        httpd_resp_send(req, cached_results, cached_len);
        return ESP_OK;
    }

    // Return empty JSON with metadata if we have no cached results
    char empty_response[192];
    snprintf(empty_response, sizeof(empty_response),
            "{\"rows\":[],\"timestamp\":%lu,\"truncated\":false,\"scan_in_progress\":%s,\"station_scan_running\":%s}",
            (unsigned long)timestamp,
            in_progress ? "true" : "false",
            station_scan ? "true" : "false");
    httpd_resp_sendstr(req, empty_response);
    return ESP_OK;
}

static esp_err_t handshake_handler(httpd_req_t *req) {
    if(deauth_task_handle != NULL) {
        httpd_resp_send_err(req, HTTPD_503_SERVICE_UNAVAILABLE, "attack in progress");
        return ESP_FAIL;
    }

    char body[256] = {0};
    int ret = httpd_req_recv(req, body, sizeof(body)-1);
    if(ret <= 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "missing body");
        return ESP_FAIL;
    }
    body[ret] = '\0';
    ESP_LOGI(TAG, "Handshake request body: %s", body);

    cJSON *root = cJSON_Parse(body);
    if(!root) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad json");
        return ESP_FAIL;
    }

    cJSON *mac_json = cJSON_GetObjectItem(root, "mac");
    cJSON *channel_json = cJSON_GetObjectItem(root, "channel");
    cJSON *duration_json = cJSON_GetObjectItem(root, "duration");
    cJSON *sta_json = cJSON_GetObjectItem(root, "sta");
    if(!cJSON_IsString(mac_json) || !(cJSON_IsString(channel_json) || cJSON_IsNumber(channel_json)) || !cJSON_IsNumber(duration_json)) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "missing fields");
        return ESP_FAIL;
    }

    uint8_t bssid[6];
    if(sscanf(mac_json->valuestring, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &bssid[0], &bssid[1], &bssid[2], &bssid[3], &bssid[4], &bssid[5]) != 6) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad mac");
        return ESP_FAIL;
    }

    int channel = 0;
    if(cJSON_IsString(channel_json)) {
        channel = atoi(channel_json->valuestring);
    } else if(cJSON_IsNumber(channel_json)) {
        channel = channel_json->valueint;
    }
    int duration = duration_json->valueint;
    if(channel < 1 || channel > 165 || duration <= 0) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad params");
        return ESP_FAIL;
    }

    uint8_t stas[MAX_HS_STA][6];
    int sta_count = 0;
    memset(stas, 0, sizeof(stas));
    if(sta_json) {
        if(cJSON_IsString(sta_json)) {
            if(sscanf(sta_json->valuestring, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &stas[0][0], &stas[0][1], &stas[0][2], &stas[0][3], &stas[0][4], &stas[0][5]) == 6) {
                sta_count = 1;
            }
        } else if(cJSON_IsArray(sta_json)) {
            int n = cJSON_GetArraySize(sta_json);
            for(int i=0;i<n && i<MAX_HS_STA;i++) {
                cJSON *it = cJSON_GetArrayItem(sta_json, i);
                if(cJSON_IsString(it)) {
                    if(sscanf(it->valuestring, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &stas[i][0], &stas[i][1], &stas[i][2], &stas[i][3], &stas[i][4], &stas[i][5]) == 6) {
                        sta_count++;
                    }
                }
            }
        }
    }

    if(hs_task_handle != NULL) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_503_SERVICE_UNAVAILABLE, "handshake busy");
        return ESP_FAIL;
    }
    memcpy(hs_args.bssid, bssid, 6);
    hs_args.channel = channel;
    hs_args.duration = duration;
    memcpy(hs_args.stas, stas, sizeof(stas));
    hs_args.sta_count = sta_count;
    ESP_LOGI(TAG, "Handshake capture start: bssid=%s, channel=%d, duration=%d, sta_count=%d", mac_json->valuestring, channel, duration, sta_count);
    cJSON *res = cJSON_CreateObject();
    cJSON_AddStringToObject(res, "status", "started");
    json_send_response(req, res);
    ESP_LOGI(TAG, "Handshake response sent, starting capture task");
    cJSON_Delete(root);
    xTaskCreate(hs_task, "hs_task", 4096, &hs_args, 5, &hs_task_handle);
    return ESP_OK;
}

static esp_err_t handshake_pcap_handler(httpd_req_t *req) {
    size_t sz = 0;
    const uint8_t *data = handshake_pcap_data(&sz);
    if(sz == 0) {
        ESP_LOGW(TAG, "PCAP requested but empty");
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "no pcap");
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "PCAP request size=%u", (unsigned)sz);
    httpd_resp_set_type(req, "application/vnd.tcpdump.pcap");
    char disp[64];
    snprintf(disp, sizeof(disp), "attachment; filename=\"%s\"", handshake_pcap_filename());
    httpd_resp_set_hdr(req, "Content-Disposition", disp);
    httpd_resp_send(req, (const char*)data, sz);
    return ESP_OK;
}

static esp_err_t ota_upload_handler(httpd_req_t *req) {
	if(deauth_task_handle != NULL) {
		httpd_resp_send_err(req, HTTPD_503_SERVICE_UNAVAILABLE, "Cannot update during active attack");
		return ESP_FAIL;
	}
	if(hs_task_handle != NULL) {
		httpd_resp_send_err(req, HTTPD_503_SERVICE_UNAVAILABLE, "Cannot update during handshake capture");
		return ESP_FAIL;
	}

	ESP_LOGI(TAG, "OTA upload start, len=%d", (int)req->content_len);

	esp_ota_handle_t handle = 0;
	const esp_partition_t *part = NULL;
	if (ota_begin(req->content_len, &handle, &part) != ESP_OK) {
		ESP_LOGE(TAG, "ota begin failed");
		httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "OTA begin failed (no OTA partition?)");
		return ESP_FAIL;
	}

	esp_err_t status = ESP_FAIL;
	char *buf = malloc(4096);
	if (!buf) {
		ESP_LOGE(TAG, "malloc failed");
		httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "malloc failed");
		goto ota_upload_cleanup;
	}

	size_t remaining = req->content_len;
	while (remaining > 0) {
		int to_read = remaining > 4096 ? 4096 : (int)remaining;
		int r = httpd_req_recv(req, buf, to_read);
		if (r <= 0) {
			ESP_LOGE(TAG, "recv failed r=%d", r);
			httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Receive failed");
			goto ota_upload_cleanup;
		}
		if (ota_write(handle, buf, (size_t)r) != ESP_OK) {
			ESP_LOGE(TAG, "ota write failed");
			httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "OTA write failed");
			goto ota_upload_cleanup;
		}
		remaining -= (size_t)r;
	}

	if (ota_finish_and_set_boot(handle, part) != ESP_OK) {
		ESP_LOGE(TAG, "ota finish failed");
		httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "OTA finish failed");
		goto ota_upload_cleanup;
	}

	ESP_LOGI(TAG, "OTA upload complete, erasing data and rebooting soon");
	
	esp_err_t scan_clear_err = scan_storage_clear();
	if (scan_clear_err != ESP_OK) {
		ESP_LOGE(TAG, "Failed to clear scan data: %s", esp_err_to_name(scan_clear_err));
	}
	
	esp_err_t nvs_err = nvs_flash_erase();
	if (nvs_err != ESP_OK) {
		ESP_LOGE(TAG, "Failed to erase NVS: %s", esp_err_to_name(nvs_err));
	}
	
	httpd_resp_set_type(req, "application/json");
	httpd_resp_sendstr(req, "{\"status\":\"ok\",\"message\":\"Firmware uploaded. Data erased. Rebooting in 3 seconds...\"}");
	status = ESP_OK;

ota_upload_cleanup:
	if (buf) {
		free(buf);
	}
	if (status != ESP_OK) {
		return ESP_FAIL;
	}
	ota_schedule_reboot_ms(3000);
	return ESP_OK;
}

static esp_err_t ota_fetch_handler(httpd_req_t *req) {
	char body[256] = {0};
	int ret = httpd_req_recv(req, body, sizeof(body)-1);
	if (ret <= 0) {
		httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "missing body");
		return ESP_FAIL;
	}
	body[ret] = '\0';
	cJSON *root = cJSON_Parse(body);
	if (!root) {
		httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad json");
		return ESP_FAIL;
	}
	cJSON *urlj = cJSON_GetObjectItem(root, "url");
	if (!cJSON_IsString(urlj)) {
		cJSON_Delete(root);
		httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "missing url");
		return ESP_FAIL;
	}

	ESP_LOGI(TAG, "OTA fetch: %s", urlj->valuestring);

	esp_ota_handle_t handle = 0;
	const esp_partition_t *part = NULL;
	if (ota_begin(0, &handle, &part) != ESP_OK) {
		cJSON_Delete(root);
		httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "OTA begin failed");
		return ESP_FAIL;
	}

	esp_http_client_config_t cfg = { .url = urlj->valuestring, .timeout_ms = 10000 };
	esp_http_client_handle_t client = esp_http_client_init(&cfg);
	if (!client) {
		cJSON_Delete(root);
		httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "client init failed");
		return ESP_FAIL;
	}
	esp_err_t err = esp_http_client_open(client, 0);
	if (err != ESP_OK) {
		esp_http_client_cleanup(client);
		cJSON_Delete(root);
		httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "open failed");
		return ESP_FAIL;
	}

	char *buf = malloc(4096);
	if (!buf) {
		esp_http_client_close(client);
		esp_http_client_cleanup(client);
		cJSON_Delete(root);
		httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "malloc failed");
		return ESP_FAIL;
	}
	while (1) {
		int r = esp_http_client_read(client, buf, 4096);
		if (r < 0) { err = ESP_FAIL; break; }
		if (r == 0) break;
		if (ota_write(handle, buf, (size_t)r) != ESP_OK) { err = ESP_FAIL; break; }
	}
	free(buf);
	esp_http_client_close(client);
	esp_http_client_cleanup(client);
	cJSON_Delete(root);

	if (err != ESP_OK) {
		httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "download failed");
		return ESP_FAIL;
	}
	if (ota_finish_and_set_boot(handle, part) != ESP_OK) {
		httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "OTA finish failed");
		return ESP_FAIL;
	}
	
	ESP_LOGI(TAG, "OTA fetch complete, erasing data and rebooting soon");
	
	esp_err_t scan_clear_err = scan_storage_clear();
	if (scan_clear_err != ESP_OK) {
		ESP_LOGE(TAG, "Failed to clear scan data: %s", esp_err_to_name(scan_clear_err));
	}
	
	esp_err_t nvs_err = nvs_flash_erase();
	if (nvs_err != ESP_OK) {
		ESP_LOGE(TAG, "Failed to erase NVS: %s", esp_err_to_name(nvs_err));
	}
	
	httpd_resp_set_type(req, "application/json");
	httpd_resp_sendstr(req, "{\"status\":\"ok\",\"message\":\"Update downloaded. Data erased. Rebooting...\"}");
	ota_schedule_reboot_ms(3000);
	return ESP_OK;
}

httpd_uri_t uri_get = {
    .uri = "/",
    .method = HTTP_GET,
    .handler = index_handler,
    .user_ctx = NULL
};

httpd_uri_t uri_login_page = {
    .uri = "/login",
    .method = HTTP_GET,
    .handler = login_page_handler,
    .user_ctx = NULL
};

#define AUTHE_URI(name, path, verb, fn) \
    httpd_uri_t name = { .uri = path, .method = verb, .handler = authed_handler, .user_ctx = fn }

AUTHE_URI(uri_scan, "/scan", HTTP_GET, wifi_scan_handler);
AUTHE_URI(uri_cached_scan, "/cached-scan", HTTP_GET, cached_scan_handler);
AUTHE_URI(uri_wifi_status, "/wifi/status", HTTP_GET, wifi_status_handler);

static esp_err_t wifi_scan_status_handler(httpd_req_t *req) {
    update_last_request_time();
    ESP_LOGI(TAG, "Received scan status request");

    bool in_progress = wifi_scan_is_in_progress();
    bool station_scan = wifi_scan_station_scan_running();
    uint32_t timestamp = wifi_scan_get_results_timestamp();
    bool truncated = wifi_scan_was_truncated();

    char response[256];
    snprintf(response, sizeof(response),
            "{\"scan_in_progress\":%s,\"station_scan_running\":%s,\"last_scan_timestamp\":%lu,\"truncated\":%s}",
            in_progress ? "true" : "false",
            station_scan ? "true" : "false",
            (unsigned long)timestamp,
            truncated ? "true" : "false");

    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, response);
    return ESP_OK;
}

AUTHE_URI(uri_wifi_scan_status, "/wifi/scan-status", HTTP_GET, wifi_scan_status_handler);

AUTHE_URI(uri_attack, "/start-attack", HTTP_POST, startattack_handler);
AUTHE_URI(uri_attack_alt, "/attack", HTTP_POST, startattack_handler);

AUTHE_URI(uri_stations, "/scan-stations", HTTP_GET, station_scan_handler);

AUTHE_URI(uri_handshake, "/handshake-capture", HTTP_POST, handshake_handler);

AUTHE_URI(uri_handshake_alt, "/handshake", HTTP_POST, handshake_handler);

typedef struct { int channel; int duration; } gc_args_t;
static void gc_task(void *arg) {
    gc_args_t *a = (gc_args_t*)arg;
    vTaskDelay(pdMS_TO_TICKS(200));
    start_general_capture(a->channel, a->duration);
    vTaskDelete(NULL);
}

static esp_err_t general_capture_handler(httpd_req_t *req) {
    if(deauth_task_handle != NULL) {
        httpd_resp_send_err(req, HTTPD_503_SERVICE_UNAVAILABLE, "attack in progress");
        return ESP_FAIL;
    }
    char body[128] = {0};
    int ret = httpd_req_recv(req, body, sizeof(body)-1);
    if(ret <= 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "missing body");
        return ESP_FAIL;
    }
    body[ret] = '\0';
    cJSON *root = cJSON_Parse(body);
    if(!root) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad json");
        return ESP_FAIL;
    }
    cJSON *channel_json = cJSON_GetObjectItem(root, "channel");
    cJSON *duration_json = cJSON_GetObjectItem(root, "duration");
    if(!cJSON_IsString(channel_json) || !cJSON_IsNumber(duration_json)) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "missing fields");
        return ESP_FAIL;
    }
    int channel = atoi(channel_json->valuestring);
    int duration = duration_json->valueint;
    if(channel < 1 || channel > 165 || duration <= 0) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad params");
        return ESP_FAIL;
    }
    cJSON_Delete(root);
    TaskHandle_t gc_task_handle = NULL;
    typedef struct { int channel; int duration; } gc_args_t;
    static gc_args_t gc_args;
    gc_args.channel = channel;
    gc_args.duration = duration;
    cJSON *res = cJSON_CreateObject();
    cJSON_AddStringToObject(res, "status", "started");
    char *out = cJSON_PrintUnformatted(res);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, out);
    cJSON_free(out);
    cJSON_Delete(res);
    xTaskCreate(gc_task, "gc_task", 4096, &gc_args, 5, &gc_task_handle);
    return ESP_OK;
}

AUTHE_URI(uri_hs_pcap, "/handshake.pcap", HTTP_GET, handshake_pcap_handler);

static esp_err_t capture_history_handler(httpd_req_t *req) {
    update_last_request_time();
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, handshake_get_history_json());
    return ESP_OK;
}

AUTHE_URI(uri_capture_history, "/captures", HTTP_GET, capture_history_handler);

static esp_err_t security_stats_handler(httpd_req_t *req) {
    update_last_request_time();
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, wifi_scan_get_security_stats_json());
    return ESP_OK;
}

AUTHE_URI(uri_security_stats, "/security/stats", HTTP_GET, security_stats_handler);

AUTHE_URI(uri_general_capture, "/capture", HTTP_POST, general_capture_handler);

AUTHE_URI(uri_ota, "/ota", HTTP_POST, ota_upload_handler);

AUTHE_URI(uri_ota_fetch, "/ota/fetch", HTTP_POST, ota_fetch_handler);

static esp_err_t wifi_connect_handler(httpd_req_t *req) {
    char buf[256] = {0};
    int ret = httpd_req_recv(req, buf, sizeof(buf)-1);
    if (ret <= 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "missing body");
        return ESP_FAIL;
    }
    buf[ret] = '\0';
    cJSON *root = cJSON_Parse(buf);
    if (!root) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad json");
        return ESP_FAIL;
    }
    cJSON *ssid = cJSON_GetObjectItem(root, "ssid");
    cJSON *pass = cJSON_GetObjectItem(root, "password");
    if (!cJSON_IsString(ssid)) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "missing ssid");
        return ESP_FAIL;
    }

    const char *ssid_str = ssid->valuestring;
    const char *pass_str = cJSON_IsString(pass) ? pass->valuestring : "";
    
    bool ok = attempt_sta_connect(ssid_str, pass_str, WIFI_AUTH_WPA2_PSK, false, 10000);
    
    if (ok) {
        esp_err_t err = sta_config_set(ssid_str, pass_str);
        if (err == ESP_OK) {
            ESP_LOGI(TAG, "Saved STA credentials for auto-reconnect");
        } else {
            ESP_LOGW(TAG, "Failed to save STA credentials: %s", esp_err_to_name(err));
        }
    }
    
    cJSON_Delete(root);

    cJSON *res = cJSON_CreateObject();
    if (ok) {
        cJSON_AddStringToObject(res, "message", "Connected and saved for auto-reconnect");
        cJSON_AddStringToObject(res, "status", "ok");
    } else {
        cJSON_AddStringToObject(res, "message", "Connection failed");
        cJSON_AddStringToObject(res, "status", "error");
    }
    char *out = cJSON_PrintUnformatted(res);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, out);
    cJSON_free(out);
    cJSON_Delete(res);
    return ESP_OK;
}

// handler to report STA connection status
static esp_err_t wifi_status_handler(httpd_req_t *req) {
    cJSON *res = cJSON_CreateObject();
    if (g_sta_connected) {
        cJSON_AddStringToObject(res, "status", "connected");
    } else {
        cJSON_AddStringToObject(res, "status", "disconnected");
    }
    
    sta_config_t sta_cfg;
    if (sta_config_get(&sta_cfg) == ESP_OK && strlen(sta_cfg.ssid) > 0) {
        cJSON_AddStringToObject(res, "saved_ssid", sta_cfg.ssid);
        cJSON_AddBoolToObject(res, "has_saved", true);
        cJSON_AddBoolToObject(res, "auto_connect", sta_cfg.auto_connect);
        cJSON_AddBoolToObject(res, "ap_while_connected", sta_cfg.ap_while_connected);
    } else {
        cJSON_AddBoolToObject(res, "has_saved", false);
        cJSON_AddBoolToObject(res, "auto_connect", true);
        cJSON_AddBoolToObject(res, "ap_while_connected", true);
    }
    
    uint32_t uptime = monitor_uptime_get_boot_uptime();
    uint32_t boot_uptime = monitor_uptime_get_boot_uptime();
    cJSON_AddNumberToObject(res, "uptime", uptime);
    cJSON_AddNumberToObject(res, "boot_uptime", boot_uptime);
    cJSON_AddBoolToObject(res, "time_synced", pwnpower_time_is_synced());
    if (pwnpower_time_is_synced()) {
        time_t now;
        time(&now);
        cJSON_AddNumberToObject(res, "timestamp", (double)now);
    }
    
    char *out = cJSON_PrintUnformatted(res);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, out);
    cJSON_free(out);
    cJSON_Delete(res);
    return ESP_OK;
}

static esp_err_t wifi_settings_handler(httpd_req_t *req) {
    char buf[128] = {0};
    int ret = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (ret <= 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing body");
        return ESP_FAIL;
    }
    buf[ret] = '\0';
    
    cJSON *root = cJSON_Parse(buf);
    if (!root) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
        return ESP_FAIL;
    }
    
    cJSON *auto_conn = cJSON_GetObjectItem(root, "auto_connect");
    if (auto_conn && cJSON_IsBool(auto_conn)) {
        sta_config_set_auto_connect(cJSON_IsTrue(auto_conn));
    }
    
    cJSON *ap_while = cJSON_GetObjectItem(root, "ap_while_connected");
    if (ap_while && cJSON_IsBool(ap_while)) {
        sta_config_set_ap_while_connected(cJSON_IsTrue(ap_while));
    }
    
    cJSON_Delete(root);
    
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"status\":\"ok\"}");
    return ESP_OK;
}

static esp_err_t wifi_disconnect_handler(httpd_req_t *req) {
    sta_config_clear();
    esp_wifi_disconnect();
    
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"status\":\"ok\",\"message\":\"Disconnected and cleared saved network\"}");
    return ESP_OK;
}

// Handler to set GPIO value for smart plug
static esp_err_t gpio_set_handler(httpd_req_t *req) {
    char body[128] = {0};
    int ret = httpd_req_recv(req, body, sizeof(body)-1);
    if (ret <= 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "missing body");
        return ESP_FAIL;
    }
    body[ret] = '\0';
    cJSON *root = cJSON_Parse(body);
    if (!root) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad json");
        return ESP_FAIL;
    }
    cJSON *pinj = cJSON_GetObjectItem(root, "pin");
    cJSON *valj = cJSON_GetObjectItem(root, "value");
    if (!cJSON_IsNumber(pinj) || !cJSON_IsNumber(valj)) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "missing fields");
        return ESP_FAIL;
    }
    int pin = pinj->valueint;
    int val = valj->valueint ? 1 : 0;
    cJSON_Delete(root);

    if (pin != SMARTPLUG_GPIO) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid pin");
        return ESP_FAIL;
    }

    // init once
    if (!s_smartplug_inited) {
        gpio_pad_select_gpio(pin);
        gpio_set_direction(pin, GPIO_MODE_OUTPUT);
        s_smartplug_inited = true;
    }
    gpio_set_level(pin, val);
    s_smartplug_level = val;

    cJSON *res = cJSON_CreateObject();
    cJSON_AddStringToObject(res, "status", "ok");
    cJSON_AddNumberToObject(res, "value", s_smartplug_level);
    char *out = cJSON_PrintUnformatted(res);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, out);
    cJSON_free(out);
    cJSON_Delete(res);
    return ESP_OK;
}

// Handler to get GPIO status for smart plug
static esp_err_t gpio_status_handler(httpd_req_t *req) {
    update_last_request_time();
    char buf[32];
    const char *pin_q = httpd_req_get_url_query_str(req, buf, sizeof(buf)) == ESP_OK ? buf : NULL;
    int pin = SMARTPLUG_GPIO;
    if (pin_q) {
        // parse pin param if provided
        char *p = strstr(pin_q, "pin=");
        if (p) pin = atoi(p+4);
    }

    if (pin != SMARTPLUG_GPIO) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid pin");
        return ESP_FAIL;
    }

    // report last set level; initialize if not yet
    if (!s_smartplug_inited) {
        gpio_pad_select_gpio(pin);
        gpio_set_direction(pin, GPIO_MODE_OUTPUT);
        gpio_set_level(pin, s_smartplug_level);
        s_smartplug_inited = true;
    }
    int level = s_smartplug_level;

    cJSON *res = cJSON_CreateObject();
    cJSON_AddNumberToObject(res, "pin", pin);
    cJSON_AddNumberToObject(res, "value", level);
    char *out = cJSON_PrintUnformatted(res);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, out);
    cJSON_free(out);
    cJSON_Delete(res);
    return ESP_OK;
}

static esp_err_t scan_report_handler(httpd_req_t *req) {
    update_last_request_time();
    char chunk[512];
    int len;
    
    network_stats_t stats;
    scan_storage_get_stats(&stats);
    
    httpd_resp_set_type(req, "application/json");
    
    // Send summary
    len = snprintf(chunk, sizeof(chunk),
        "{\"summary\":{\"total_scans\":%lu,\"unique_aps\":%lu,\"unique_stations\":%lu,"
        "\"monitoring_hours\":%.1f,\"deauth_events_last_hour\":%lu,"
        "\"rogue_aps_detected\":%lu,\"known_devices_present\":%lu},",
        (unsigned long)stats.scan_count, (unsigned long)stats.total_aps_seen,
        (unsigned long)stats.total_stations_seen, stats.monitoring_duration_sec / 3600.0,
        (unsigned long)stats.deauth_events_last_hour, (unsigned long)stats.rogue_aps_detected,
        (unsigned long)stats.known_devices_present);
    if (httpd_resp_send_chunk(req, chunk, len) != ESP_OK) return ESP_FAIL;
    
    const char *intel_json = scan_storage_get_intelligence_json();
    if (intel_json && strlen(intel_json) > 2) {
        len = snprintf(chunk, sizeof(chunk), "\"intelligence\":");
        if (httpd_resp_send_chunk(req, chunk, len) != ESP_OK) return ESP_FAIL;
        if (httpd_resp_send_chunk(req, intel_json, strlen(intel_json)) != ESP_OK) return ESP_FAIL;
        if (httpd_resp_send_chunk(req, ",", 1) != ESP_OK) return ESP_FAIL;
    }
    
    // Use shared buffer instead of malloc
    scan_record_t *latest = &shared_scan_buffer;
    
    if (latest && scan_storage_get_latest(latest) == ESP_OK) {
        uint8_t channel_usage[14] = {0};
        uint8_t security_counts[6] = {0};
        uint8_t total_stations = 0;
        
        for (uint8_t i = 0; i < latest->header.ap_count; i++) {
            stored_ap_t *ap = &latest->aps[i];
            if (ap->channel > 0 && ap->channel <= 14) channel_usage[ap->channel - 1]++;
            if (ap->auth_mode < 6) security_counts[ap->auth_mode]++;
            total_stations += ap->station_count;
        }
        
        // Send channel analysis
        len = snprintf(chunk, sizeof(chunk), "\"channel_analysis\":{\"channels\":[");
        if (httpd_resp_send_chunk(req, chunk, len) != ESP_OK) { return ESP_FAIL; }
        
        uint8_t most_congested = 0, max_aps = 0;
        bool first_ch = true;
        for (uint8_t i = 0; i < 14; i++) {
            if (channel_usage[i] > 0) {
                len = snprintf(chunk, sizeof(chunk), "%s{\"channel\":%d,\"ap_count\":%d}",
                    first_ch ? "" : ",", i + 1, channel_usage[i]);
                if (httpd_resp_send_chunk(req, chunk, len) != ESP_OK) { return ESP_FAIL; }
                first_ch = false;
                if (channel_usage[i] > max_aps) { max_aps = channel_usage[i]; most_congested = i + 1; }
            }
        }
        
        float open_percent = latest->header.ap_count > 0 ? (security_counts[0] * 100.0f / latest->header.ap_count) : 0;
        float avg_stations = latest->header.ap_count > 0 ? (float)total_stations / latest->header.ap_count : 0;
        
        len = snprintf(chunk, sizeof(chunk),
            "],\"most_congested\":%d,\"max_ap_count\":%d},"
            "\"security_analysis\":{\"open\":%d,\"wep\":%d,\"wpa2\":%d,\"wpa3\":%d,\"wpa2_wpa3\":%d,\"open_percent\":%.1f},"
            "\"network_activity\":{\"current_aps\":%d,\"total_stations\":%d,\"avg_stations_per_ap\":%.1f},\"networks\":[",
            most_congested, max_aps, security_counts[0], security_counts[1], 
            security_counts[2] + security_counts[3], security_counts[4], security_counts[5], open_percent,
            latest->header.ap_count, total_stations, avg_stations);
        if (httpd_resp_send_chunk(req, chunk, len) != ESP_OK) { return ESP_FAIL; }
        
        // Stream networks
        for (uint8_t i = 0; i < latest->header.ap_count; i++) {
            stored_ap_t *ap = &latest->aps[i];
            const char *auth = "Unknown";
            switch (ap->auth_mode) {
                case 0: auth = "Open"; break;
                case 1: auth = "WEP"; break;
                case 2: case 3: auth = "WPA2"; break;
                case 4: auth = "WPA3"; break;
                case 5: auth = "WPA2/WPA3"; break;
            }
            
            char ap_vendor[64] = "Unknown";
            ouis_lookup_vendor(ap->bssid, ap_vendor, sizeof(ap_vendor));
            
            len = snprintf(chunk, sizeof(chunk),
                "%s{\"bssid\":\"%02X:%02X:%02X:%02X:%02X:%02X\",\"ssid\":\"%s\",\"channel\":%d,"
                "\"rssi\":%d,\"stations\":%d,\"last_seen\":%lu,\"security\":\"%s\",\"vendor\":\"%s\",\"clients\":[",
                i > 0 ? "," : "", ap->bssid[0], ap->bssid[1], ap->bssid[2], ap->bssid[3], ap->bssid[4], ap->bssid[5],
                ap->ssid, ap->channel, ap->rssi, ap->station_count, (unsigned long)ap->last_seen, auth, ap_vendor);
            if (httpd_resp_send_chunk(req, chunk, len) != ESP_OK) { return ESP_FAIL; }
            
            // Stream clients
            for (uint8_t s = 0; s < ap->station_count && s < MAX_STATIONS_PER_AP; s++) {
                char sta_vendor[64] = "Unknown";
                ouis_lookup_vendor(ap->stations[s].mac, sta_vendor, sizeof(sta_vendor));
                
                len = snprintf(chunk, sizeof(chunk),
                    "%s{\"mac\":\"%02X:%02X:%02X:%02X:%02X:%02X\",\"rssi\":%d,\"last_seen\":%lu,\"vendor\":\"%s\"}",
                    s > 0 ? "," : "", ap->stations[s].mac[0], ap->stations[s].mac[1], ap->stations[s].mac[2],
                    ap->stations[s].mac[3], ap->stations[s].mac[4], ap->stations[s].mac[5],
                    ap->stations[s].rssi, (unsigned long)ap->stations[s].last_seen, sta_vendor);
                if (httpd_resp_send_chunk(req, chunk, len) != ESP_OK) { return ESP_FAIL; }
            }
            
            if (httpd_resp_send_chunk(req, "]}", 2) != ESP_OK) { return ESP_FAIL; }
        }
        
        if (httpd_resp_send_chunk(req, "]}", 2) != ESP_OK) { return ESP_FAIL; }
    } else {
        // No scan data - send empty defaults
        const char *empty = "\"channel_analysis\":{\"channels\":[],\"most_congested\":0,\"max_ap_count\":0},"
            "\"security_analysis\":{\"open\":0,\"wep\":0,\"wpa2\":0,\"wpa3\":0,\"wpa2_wpa3\":0,\"open_percent\":0},"
            "\"network_activity\":{\"current_aps\":0,\"total_stations\":0,\"avg_stations_per_ap\":0},\"networks\":[]}";
        if (httpd_resp_send_chunk(req, empty, strlen(empty)) != ESP_OK) { 
            if (latest)             return ESP_FAIL;
        }
    }
    
    if (latest)     
    // End chunked response
    if (httpd_resp_send_chunk(req, NULL, 0) != ESP_OK) return ESP_FAIL;
    
    ESP_LOGI(TAG, "Streamed scan report: %lu APs, %lu stations", 
             (unsigned long)stats.total_aps_seen, (unsigned long)stats.total_stations_seen);
    
    return ESP_OK;
}

static esp_err_t scan_timeline_handler(httpd_req_t *req) {
    httpd_resp_set_type(req, "application/json");
    const char *json = scan_storage_get_timeline_json(24);
    httpd_resp_sendstr(req, json);
    return ESP_OK;
}

static esp_err_t scan_trigger_handler(httpd_req_t *req) {
    background_scan_trigger();
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"status\":\"triggered\"}");
    return ESP_OK;
}

static esp_err_t intelligence_handler(httpd_req_t *req) {
    update_last_request_time();
    httpd_resp_set_type(req, "application/json");
    const char *json = scan_storage_get_intelligence_json();
    httpd_resp_sendstr(req, json);
    return ESP_OK;
}

static esp_err_t device_presence_handler(httpd_req_t *req) {
    update_last_request_time();
    httpd_resp_set_type(req, "application/json");
    const char *json = scan_storage_get_device_presence_json();
    httpd_resp_sendstr(req, json);
    return ESP_OK;
}

static esp_err_t unified_intelligence_handler(httpd_req_t *req) {
    update_last_request_time();
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    
    // Use chunked encoding to stream response without large buffers
    esp_err_t ret = scan_storage_send_unified_intelligence_chunked(req);
    if (ret != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to generate response");
        return ESP_FAIL;
    }
    
    return ESP_OK;
}

static esp_err_t scan_status_handler(httpd_req_t *req) {
    update_last_request_time();
    cJSON *root = cJSON_CreateObject();
    
    bg_scan_state_t state = background_scan_get_state();
    const char *state_str;
    switch (state) {
        case BG_SCAN_IDLE: state_str = "idle"; break;
        case BG_SCAN_WAITING: state_str = "waiting"; break;
        case BG_SCAN_RUNNING: state_str = "running"; break;
        case BG_SCAN_PAUSED: state_str = "paused"; break;
        default: state_str = "unknown"; break;
    }
    
    cJSON_AddStringToObject(root, "state", state_str);
    cJSON_AddNumberToObject(root, "last_scan", background_scan_get_last_time());
    cJSON_AddNumberToObject(root, "record_count", scan_storage_get_count());
    
    const bg_scan_config_t *cfg = background_scan_get_config();
    cJSON_AddNumberToObject(root, "interval_sec", cfg->interval_sec);
    cJSON_AddBoolToObject(root, "auto_scan", cfg->auto_scan);
    
    char *json = cJSON_PrintUnformatted(root);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, json);
    free(json);
    cJSON_Delete(root);
    return ESP_OK;
}

static esp_err_t scan_config_get_handler(httpd_req_t *req) {
    update_last_request_time();
    const bg_scan_config_t *bg_cfg = background_scan_get_config();
    const idle_scan_config_t *idle_cfg = idle_scanner_get_config();
    
    cJSON *root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "bg_interval", bg_cfg->interval_sec);
    cJSON_AddBoolToObject(root, "bg_enabled", bg_cfg->auto_scan);
    cJSON_AddNumberToObject(root, "idle_threshold", idle_cfg->idle_threshold_sec);
    cJSON_AddBoolToObject(root, "auto_handshake", idle_cfg->auto_handshake);
    cJSON_AddNumberToObject(root, "handshake_duration", idle_cfg->handshake_duration_sec);
    
    char *json = cJSON_PrintUnformatted(root);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, json);
    free(json);
    cJSON_Delete(root);
    return ESP_OK;
}

static esp_err_t scan_config_handler(httpd_req_t *req) {
    char buf[256];
    int ret = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (ret <= 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing body");
        return ESP_FAIL;
    }
    buf[ret] = '\0';
    
    cJSON *root = cJSON_Parse(buf);
    if (!root) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
        return ESP_FAIL;
    }
    
    cJSON *interval = cJSON_GetObjectItem(root, "bg_interval");
    if (interval && cJSON_IsNumber(interval)) {
        background_scan_set_interval((uint16_t)interval->valueint);
    }
    
    cJSON *bg_enabled = cJSON_GetObjectItem(root, "bg_enabled");
    if (bg_enabled && cJSON_IsBool(bg_enabled)) {
        background_scan_set_enabled(cJSON_IsTrue(bg_enabled));
    }
    
    cJSON *idle_thresh = cJSON_GetObjectItem(root, "idle_threshold");
    if (idle_thresh && cJSON_IsNumber(idle_thresh)) {
        idle_scanner_set_idle_threshold((uint32_t)idle_thresh->valueint);
    }
    
    cJSON *auto_hs = cJSON_GetObjectItem(root, "auto_handshake");
    if (auto_hs && cJSON_IsBool(auto_hs)) {
        idle_scanner_set_auto_handshake(cJSON_IsTrue(auto_hs));
    }
    
    cJSON *hs_dur = cJSON_GetObjectItem(root, "handshake_duration");
    if (hs_dur && cJSON_IsNumber(hs_dur)) {
        idle_scanner_set_handshake_duration((uint8_t)hs_dur->valueint);
    }
    
    cJSON_Delete(root);
    
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"status\":\"ok\"}");
    return ESP_OK;
}

static esp_err_t scan_clear_handler(httpd_req_t *req) {
    scan_storage_clear();
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"status\":\"cleared\"}");
    return ESP_OK;
}

static esp_err_t ap_config_get_handler(httpd_req_t *req) {
    update_last_request_time();
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, ap_config_get_json());
    return ESP_OK;
}

static esp_err_t ap_config_set_handler(httpd_req_t *req) {
    char buf[256];
    int ret = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (ret <= 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing body");
        return ESP_FAIL;
    }
    buf[ret] = '\0';
    
    cJSON *root = cJSON_Parse(buf);
    if (!root) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
        return ESP_FAIL;
    }
    
    cJSON *ssid = cJSON_GetObjectItem(root, "ssid");
    cJSON *password = cJSON_GetObjectItem(root, "password");
    
    if (!ssid || !cJSON_IsString(ssid) || strlen(ssid->valuestring) == 0) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "SSID required");
        return ESP_FAIL;
    }
    
    const char *pass_str = (password && cJSON_IsString(password)) ? password->valuestring : "";
    
    if (strlen(pass_str) > 0 && strlen(pass_str) < 8) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Password must be 8+ chars or empty");
        return ESP_FAIL;
    }
    
    esp_err_t err = ap_config_set(ssid->valuestring, pass_str);
    cJSON_Delete(root);
    
    if (err != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to save");
        return ESP_FAIL;
    }
    
    ap_config_apply();
    
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"status\":\"ok\",\"message\":\"Settings saved. Reconnect to new AP.\"}");
    return ESP_OK;
}

static esp_err_t history_samples_handler(httpd_req_t *req) {
    update_last_request_time();

    // parse query parameters
    float days = 7.0f;
    uint32_t since_ts = 0;  // incremental update support
    char query[128];
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK) {
        char days_str[16];
        if (httpd_query_key_value(query, "days", days_str, sizeof(days_str)) == ESP_OK) {
            days = atof(days_str);
            if (days < 0.1f) days = 0.1f;
            if (days > 30.0f) days = 30.0f;
        }

        // incremental updates: only return samples after since_ts
        char since_str[16];
        if (httpd_query_key_value(query, "since_ts", since_str, sizeof(since_str)) == ESP_OK) {
            since_ts = (uint32_t)atoi(since_str);
            ESP_LOGI(TAG, "Incremental update requested: since_ts=%lu", (unsigned long)since_ts);
        }
    }

    // limit samples to prevent oom (process in chunks)
    uint32_t max_samples = MIN(5040, (uint32_t)(days * 720.0f));  // 30 samples per hour, cap at 7 days

    uint32_t history_count = scan_storage_get_history_count();
    ESP_LOGD(TAG, "history_samples_handler: total_count=%u, max_samples=%u, since_ts=%lu",
             history_count, max_samples, (unsigned long)since_ts);
    uint32_t remaining = (history_count > max_samples) ? max_samples : history_count;
    uint32_t start_idx = (history_count > max_samples) ? (history_count - max_samples) : 0;
    ESP_LOGD(TAG, "history_samples_handler: start_idx=%u, remaining=%u", start_idx, remaining);
    
    // Chunk size for flash read operations (48 bytes * 200 = 9.6KB, fits in fragmented heap)
    #define HISTORY_CHUNK_SIZE 150
    history_sample_t *chunk = malloc(sizeof(history_sample_t) * HISTORY_CHUNK_SIZE);
    if (!chunk) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Out of memory");
        return ESP_FAIL;
    }
    
    // extern uint32_t scan_storage_get_history_base_epoch(void);
    // uint32_t base_epoch = scan_storage_get_history_base_epoch();
    
    httpd_resp_set_type(req, "application/json");
    // Compact format: {"s":[[epoch,ap,cli,[ch0-12],[[hash,cnt],...]],...]}
    // Field order: [0]=epoch_ts, [1]=ap_count, [2]=client_count, [3]=channel_counts[13], [4]=ssid_clients[[hash,count],...]
    httpd_resp_sendstr_chunk(req, "{\"s\":[");
    
    bool first = true;
    while (remaining > 0) {
        uint32_t request_count = remaining > HISTORY_CHUNK_SIZE ? HISTORY_CHUNK_SIZE : remaining;
        uint32_t actual = 0;
        esp_err_t err = scan_storage_get_history_samples_window(start_idx, request_count, chunk, &actual);
        ESP_LOGD(TAG, "history_samples_handler: requested=%u, actual=%u", request_count, actual);
        if (err != ESP_OK) {
            free(chunk);
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to read samples");
            return ESP_FAIL;
        }
        
        for (uint32_t i = 0; i < actual; i++) {
            uint32_t epoch_ts = 0;
            bool time_valid = HISTORY_IS_TIME_VALID(chunk[i].flags);

            if (time_valid) {
                epoch_ts = chunk[i].timestamp;
            }

            // incremental update: skip samples older than or equal to since_ts
            if (since_ts > 0 && epoch_ts > 0 && epoch_ts <= since_ts) {
                continue;
            }

            // Channel data: [[ids],[counts]]
            char ch_buf[128];
            int p = 0;
            p += snprintf(ch_buf + p, sizeof(ch_buf) - p, "[[");
            int count = 0;
            for(int k=0; k<7; k++) {
                if(chunk[i].top_channels[k] == 0) break;
                count++;
                p += snprintf(ch_buf + p, sizeof(ch_buf) - p, "%s%u", k==0?"":",", chunk[i].top_channels[k]);
            }
            p += snprintf(ch_buf + p, sizeof(ch_buf) - p, "],[");
            for(int k=0; k<count; k++) {
                p += snprintf(ch_buf + p, sizeof(ch_buf) - p, "%s%u", k==0?"":",", chunk[i].top_counts[k]);
            }
            p += snprintf(ch_buf + p, sizeof(ch_buf) - p, "]]");

            static char buf[300];
            int written = snprintf(buf, sizeof(buf),
                "%s[%lu,%u,%u,%s,[",
                first ? "" : ",",
                (unsigned long)epoch_ts,
                chunk[i].ap_count,
                chunk[i].client_count,
                ch_buf);
            if (written <= 0 || written >= (int)sizeof(buf)) {
                free(chunk);
                httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "History JSON buffer overflow");
                return ESP_FAIL;
            }

            if (httpd_resp_send_chunk(req, buf, (size_t)written) != ESP_OK) {
                free(chunk);
                ESP_LOGW(TAG, "Client disconnected during history stream");
                return ESP_FAIL;
            }
            first = false;

            // SSID clients as compact arrays: [[hash,count],[hash,count],...]
            uint8_t ssid_count = HISTORY_GET_SSID_COUNT(chunk[i].flags);
            for (uint8_t j = 0; j < ssid_count; j++) {
                char ssid_buf[48];
                int ssid_written = snprintf(ssid_buf, sizeof(ssid_buf), "%s[%lu,%u]",
                    j == 0 ? "" : ",",
                    (unsigned long)chunk[i].ssid_clients[j].ssid_hash,
                    chunk[i].ssid_clients[j].client_count);
                if (ssid_written > 0) {
                    size_t len = (ssid_written < (int)sizeof(ssid_buf)) ? (size_t)ssid_written : sizeof(ssid_buf);
                    if (httpd_resp_send_chunk(req, ssid_buf, len) != ESP_OK) {
                        free(chunk);
                        ESP_LOGW(TAG, "Client disconnected during history stream");
                        return ESP_FAIL;
                    }
                }
            }
            if (httpd_resp_sendstr_chunk(req, "]]") != ESP_OK) {
                free(chunk);
                ESP_LOGW(TAG, "Client disconnected during history stream");
                return ESP_FAIL;
            }

            if ((i & 0x1F) == 0) {
                vTaskDelay(1);
            }
        }
        
        start_idx += request_count;
        remaining -= request_count;
    }
    
    free(chunk);
    httpd_resp_sendstr_chunk(req, "]}");
    httpd_resp_sendstr_chunk(req, NULL);
    
    return ESP_OK;
}

static esp_err_t devices_list_handler(httpd_req_t *req) {
    update_last_request_time();
    
    // get device presence data from scan_storage
    const char *presence_json = scan_storage_get_device_presence_json();
    
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, presence_json);
    return ESP_OK;
}

static esp_err_t devices_update_handler(httpd_req_t *req) {
    char buf[512];
    int ret = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (ret <= 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing body");
        return ESP_FAIL;
    }
    buf[ret] = '\0';
    
    cJSON *root = cJSON_Parse(buf);
    if (!root) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
        return ESP_FAIL;
    }
    
    cJSON *mac_json = cJSON_GetObjectItem(root, "mac");
    if (!mac_json || !cJSON_IsString(mac_json)) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "MAC required");
        return ESP_FAIL;
    }
    
    device_settings_t settings;
    memset(&settings, 0, sizeof(settings));
    
    // parse mac
    if (sscanf(mac_json->valuestring, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &settings.mac[0], &settings.mac[1], &settings.mac[2],
               &settings.mac[3], &settings.mac[4], &settings.mac[5]) != 6) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid MAC format");
        return ESP_FAIL;
    }
    
    // get existing settings or use defaults
    if (device_db_get(settings.mac, &settings) != ESP_OK) {
        settings.trust_score = 50;
        settings.tracked = false;
        settings.name[0] = '\0';
    }
    
    // update fields if provided
    cJSON *name_json = cJSON_GetObjectItem(root, "name");
    if (name_json && cJSON_IsString(name_json)) {
        strncpy(settings.name, name_json->valuestring, DEVICE_NAME_MAX_LEN - 1);
        settings.name[DEVICE_NAME_MAX_LEN - 1] = '\0';
    }
    
    cJSON *trust_json = cJSON_GetObjectItem(root, "trust_score");
    if (trust_json && cJSON_IsNumber(trust_json)) {
        int trust = trust_json->valueint;
        if (trust < 0) trust = 0;
        if (trust > 100) trust = 100;
        settings.trust_score = (uint8_t)trust;
    }
    
    cJSON *tracked_json = cJSON_GetObjectItem(root, "tracked");
    if (tracked_json && cJSON_IsBool(tracked_json)) {
        settings.tracked = cJSON_IsTrue(tracked_json);
    }
    
    cJSON *home_json = cJSON_GetObjectItem(root, "home_device");
    bool set_home = false;
    bool home_value = false;
    if (home_json && cJSON_IsBool(home_json)) {
        set_home = true;
        home_value = cJSON_IsTrue(home_json);
    }
    
    cJSON_Delete(root);
    
    // save to db
    esp_err_t err = device_db_set(&settings);
    if (err != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to save device");
        return ESP_FAIL;
    }
    
    // set home flag in presence storage if requested
    if (set_home) {
        scan_storage_set_device_home(settings.mac, home_value);
    }
    
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"status\":\"ok\"}");
    return ESP_OK;
}

static esp_err_t webhook_config_get_handler(httpd_req_t *req) {
    update_last_request_time();
    webhook_config_t config;
    webhook_get_config(&config);
    
    cJSON *root = cJSON_CreateObject();
    cJSON_AddBoolToObject(root, "enabled", config.enabled);
    cJSON_AddStringToObject(root, "url", config.url);
    cJSON_AddBoolToObject(root, "tracked_only", config.tracked_only);
    cJSON_AddBoolToObject(root, "home_departure_alert", config.home_departure_alert);
    cJSON_AddBoolToObject(root, "home_arrival_alert", config.home_arrival_alert);
    cJSON_AddBoolToObject(root, "new_device_alert", config.new_device_alert);
    cJSON_AddBoolToObject(root, "deauth_alert", config.deauth_alert);
    cJSON_AddBoolToObject(root, "handshake_alert", config.handshake_alert);
    cJSON_AddBoolToObject(root, "all_events", config.all_events);
    cJSON_AddNumberToObject(root, "send_cursor", webhook_get_send_cursor());
    cJSON_AddNumberToObject(root, "total_events", scan_storage_get_event_count());
    
    char *json_str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, json_str);
    free(json_str);
    
    return ESP_OK;
}

static esp_err_t webhook_config_set_handler(httpd_req_t *req) {
    char buf[512];
    int ret = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (ret <= 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing body");
        return ESP_FAIL;
    }
    buf[ret] = '\0';
    
    cJSON *root = cJSON_Parse(buf);
    if (!root) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
        return ESP_FAIL;
    }
    
    webhook_config_t config;
    webhook_get_config(&config);
    
    cJSON *enabled_json = cJSON_GetObjectItem(root, "enabled");
    if (enabled_json && cJSON_IsBool(enabled_json)) {
        config.enabled = cJSON_IsTrue(enabled_json);
    }
    
    cJSON *url_json = cJSON_GetObjectItem(root, "url");
    if (url_json && cJSON_IsString(url_json)) {
        strncpy(config.url, url_json->valuestring, WEBHOOK_URL_MAX_LEN - 1);
        config.url[WEBHOOK_URL_MAX_LEN - 1] = '\0';
    }
    
    cJSON *tracked_only_json = cJSON_GetObjectItem(root, "tracked_only");
    if (tracked_only_json && cJSON_IsBool(tracked_only_json)) {
        config.tracked_only = cJSON_IsTrue(tracked_only_json);
    }
    
    cJSON *home_departure_json = cJSON_GetObjectItem(root, "home_departure_alert");
    if (home_departure_json && cJSON_IsBool(home_departure_json)) {
        config.home_departure_alert = cJSON_IsTrue(home_departure_json);
    }
    
    cJSON *home_arrival_json = cJSON_GetObjectItem(root, "home_arrival_alert");
    if (home_arrival_json && cJSON_IsBool(home_arrival_json)) {
        config.home_arrival_alert = cJSON_IsTrue(home_arrival_json);
    }
    
    cJSON *new_device_json = cJSON_GetObjectItem(root, "new_device_alert");
    if (new_device_json && cJSON_IsBool(new_device_json)) {
        config.new_device_alert = cJSON_IsTrue(new_device_json);
    }
    
    cJSON *deauth_alert_json = cJSON_GetObjectItem(root, "deauth_alert");
    if (deauth_alert_json && cJSON_IsBool(deauth_alert_json)) {
        config.deauth_alert = cJSON_IsTrue(deauth_alert_json);
    }
    
    cJSON *handshake_alert_json = cJSON_GetObjectItem(root, "handshake_alert");
    if (handshake_alert_json && cJSON_IsBool(handshake_alert_json)) {
        config.handshake_alert = cJSON_IsTrue(handshake_alert_json);
    }
    
    cJSON *all_events_json = cJSON_GetObjectItem(root, "all_events");
    if (all_events_json && cJSON_IsBool(all_events_json)) {
        config.all_events = cJSON_IsTrue(all_events_json);
    }
    
    cJSON_Delete(root);
    
    esp_err_t err = webhook_set_config(&config);
    if (err != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to save config");
        return ESP_FAIL;
    }
    
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"status\":\"ok\"}");
    return ESP_OK;
}

static esp_err_t webhook_test_handler(httpd_req_t *req) {
    esp_err_t err = webhook_send_test();
    
    cJSON *root = cJSON_CreateObject();
    if (err == ESP_OK) {
        cJSON_AddStringToObject(root, "status", "ok");
        cJSON_AddStringToObject(root, "message", "Test webhook sent successfully");
    } else {
        cJSON_AddStringToObject(root, "status", "error");
        cJSON_AddStringToObject(root, "message", "Failed to send test webhook");
    }
    
    char *json_str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, json_str);
    free(json_str);
    
    return ESP_OK;
}

static esp_err_t home_ssids_get_handler(httpd_req_t *req) {
    update_last_request_time();
    cJSON *root = cJSON_CreateObject();
    const char *connected = scan_storage_get_home_ssid();
    cJSON_AddStringToObject(root, "connected", connected ? connected : "");
    cJSON_AddRawToObject(root, "extra", scan_storage_get_extra_home_ssids_json());
    
    char *json_str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, json_str);
    free(json_str);
    return ESP_OK;
}

static esp_err_t home_ssids_add_handler(httpd_req_t *req) {
    char buf[128];
    int ret = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (ret <= 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing body");
        return ESP_FAIL;
    }
    buf[ret] = '\0';
    
    cJSON *root = cJSON_Parse(buf);
    if (!root) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
        return ESP_FAIL;
    }
    
    cJSON *ssid_json = cJSON_GetObjectItem(root, "ssid");
    if (!ssid_json || !cJSON_IsString(ssid_json)) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "SSID required");
        return ESP_FAIL;
    }
    
    esp_err_t err = scan_storage_add_extra_home_ssid(ssid_json->valuestring);
    cJSON_Delete(root);
    
    if (err == ESP_OK) {
        httpd_resp_set_type(req, "application/json");
        httpd_resp_sendstr(req, "{\"status\":\"ok\"}");
    } else if (err == ESP_ERR_NO_MEM) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Max 3 extra SSIDs allowed");
        return ESP_FAIL;
    } else {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to add SSID");
        return ESP_FAIL;
    }
    return ESP_OK;
}

static esp_err_t home_ssids_refresh_handler(httpd_req_t *req) {
    scan_storage_refresh_home_flags();
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"status\":\"ok\"}");
    return ESP_OK;
}

static esp_err_t home_ssids_remove_handler(httpd_req_t *req) {
    char buf[128];
    int ret = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (ret <= 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing body");
        return ESP_FAIL;
    }
    buf[ret] = '\0';
    
    cJSON *root = cJSON_Parse(buf);
    if (!root) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
        return ESP_FAIL;
    }
    
    cJSON *ssid_json = cJSON_GetObjectItem(root, "ssid");
    if (!ssid_json || !cJSON_IsString(ssid_json)) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "SSID required");
        return ESP_FAIL;
    }
    
    esp_err_t err = scan_storage_remove_extra_home_ssid(ssid_json->valuestring);
    cJSON_Delete(root);
    
    if (err == ESP_OK) {
        httpd_resp_set_type(req, "application/json");
        httpd_resp_sendstr(req, "{\"status\":\"ok\"}");
    } else {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "SSID not found");
        return ESP_FAIL;
    }
    return ESP_OK;
}

// ------ Peer Discovery API Handlers ------

static esp_err_t peers_list_handler(httpd_req_t *req) {
    update_last_request_time();
    
    peer_info_t peers[PEER_MAX_DEVICES];
    size_t count = 0;
    peer_discovery_get_peers(peers, PEER_MAX_DEVICES, &count);
    
    cJSON *root = cJSON_CreateObject();
    cJSON *peers_array = cJSON_AddArrayToObject(root, "peers");
    
    for (size_t i = 0; i < count; i++) {
        cJSON *peer = cJSON_CreateObject();
        
        // MAC address as string
        char mac_str[18];
        snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
                 peers[i].mac[0], peers[i].mac[1], peers[i].mac[2],
                 peers[i].mac[3], peers[i].mac[4], peers[i].mac[5]);
        cJSON_AddStringToObject(peer, "mac", mac_str);
        
        // IP address as string
        char ip_str[16];
        uint32_t ip = peers[i].ip_addr;
        snprintf(ip_str, sizeof(ip_str), "%lu.%lu.%lu.%lu",
                 (unsigned long)(ip & 0xFF),
                 (unsigned long)((ip >> 8) & 0xFF),
                 (unsigned long)((ip >> 16) & 0xFF),
                 (unsigned long)((ip >> 24) & 0xFF));
        cJSON_AddStringToObject(peer, "ip", ip_str);
        
        cJSON_AddStringToObject(peer, "hostname", peers[i].hostname);
        cJSON_AddStringToObject(peer, "role", peers[i].role == PEER_ROLE_LEADER ? "leader" : "follower");
        cJSON_AddBoolToObject(peer, "ap_active", peers[i].ap_active);
        cJSON_AddBoolToObject(peer, "is_self", peers[i].is_self);
        cJSON_AddNumberToObject(peer, "last_seen", peers[i].last_seen);
        
        cJSON_AddItemToArray(peers_array, peer);
    }
    
    cJSON_AddNumberToObject(root, "count", count);
    
    char *json_str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, json_str);
    free(json_str);
    
    return ESP_OK;
}

static esp_err_t peers_status_handler(httpd_req_t *req) {
    update_last_request_time();
    
    peer_info_t self;
    peer_discovery_get_self(&self);
    
    cJSON *root = cJSON_CreateObject();
    
    // Self info
    char mac_str[18];
    snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
             self.mac[0], self.mac[1], self.mac[2],
             self.mac[3], self.mac[4], self.mac[5]);
    cJSON_AddStringToObject(root, "mac", mac_str);
    cJSON_AddStringToObject(root, "hostname", peer_discovery_get_hostname());
    cJSON_AddStringToObject(root, "role", peer_discovery_get_role() == PEER_ROLE_LEADER ? "leader" : "follower");
    cJSON_AddBoolToObject(root, "ap_active", self.ap_active);
    
    // AP coordination mode
    peer_ap_mode_t mode = peer_discovery_get_ap_mode();
    const char *mode_str = "auto";
    if (mode == PEER_AP_MODE_ALWAYS_ON) mode_str = "always_on";
    else if (mode == PEER_AP_MODE_LEADER_ONLY) mode_str = "leader_only";
    cJSON_AddStringToObject(root, "ap_mode", mode_str);
    
    // Peer count
    peer_info_t peers[PEER_MAX_DEVICES];
    size_t count = 0;
    peer_discovery_get_peers(peers, PEER_MAX_DEVICES, &count);
    cJSON_AddNumberToObject(root, "peer_count", count);
    
    char *json_str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, json_str);
    free(json_str);
    
    return ESP_OK;
}

static esp_err_t peers_elect_handler(httpd_req_t *req) {
    update_last_request_time();
    
    ESP_LOGI(TAG, "Manual peer election triggered via API");
    peer_discovery_trigger_election();
    
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"status\":\"ok\",\"message\":\"election triggered\"}");
    return ESP_OK;
}

// Register all application routes on the given server (HTTPS)
static esp_err_t register_routes(httpd_handle_t server) {
    httpd_register_uri_handler(server, &uri_get);
    httpd_register_uri_handler(server, &uri_login_page);
    httpd_register_uri_handler(server, &uri_scan);
    httpd_register_uri_handler(server, &uri_cached_scan);
    httpd_register_uri_handler(server, &uri_wifi_scan_status);
    httpd_register_uri_handler(server, &uri_attack);
    httpd_register_uri_handler(server, &uri_attack_alt);
    httpd_register_uri_handler(server, &uri_stations);
    httpd_register_uri_handler(server, &uri_handshake);
    httpd_register_uri_handler(server, &uri_handshake_alt);
    httpd_register_uri_handler(server, &uri_hs_pcap);
    httpd_register_uri_handler(server, &uri_capture_history);
    httpd_register_uri_handler(server, &uri_security_stats);
    httpd_register_uri_handler(server, &uri_general_capture);
    httpd_register_uri_handler(server, &uri_ota);
    httpd_register_uri_handler(server, &uri_ota_fetch);
    httpd_register_uri_handler(server, &uri_auth_status);
    httpd_register_uri_handler(server, &uri_auth_login);
    httpd_register_uri_handler(server, &uri_auth_logout);
    httpd_register_uri_handler(server, &uri_auth_password);
    httpd_register_uri_handler(server, &uri_wifi_status);
    httpd_register_uri_handler(server, &uri_wizard_status);
    httpd_register_uri_handler(server, &uri_wizard_complete);
    register_authed(server, "/wizard/reset", HTTP_POST, wizard_reset_handler);

    register_authed(server, "/gpio", HTTP_POST, gpio_set_handler);
    register_authed(server, "/gpio/status", HTTP_GET, gpio_status_handler);

    register_authed(server, "/wifi/connect", HTTP_POST, wifi_connect_handler);
    register_authed(server, "/wifi/settings", HTTP_POST, wifi_settings_handler);
    register_authed(server, "/wifi/disconnect", HTTP_POST, wifi_disconnect_handler);

    register_authed(server, "/scan/report", HTTP_GET, scan_report_handler);
    register_authed(server, "/scan/timeline", HTTP_GET, scan_timeline_handler);
    register_authed(server, "/scan/trigger", HTTP_POST, scan_trigger_handler);
    register_authed(server, "/scan/status", HTTP_GET, scan_status_handler);
    register_authed(server, "/scan/settings", HTTP_GET, scan_config_get_handler);
    register_authed(server, "/scan/settings", HTTP_POST, scan_config_handler);
    register_authed(server, "/scan/clear", HTTP_POST, scan_clear_handler);
    register_authed(server, "/intelligence", HTTP_GET, intelligence_handler);
    register_authed(server, "/devices/presence", HTTP_GET, device_presence_handler);
    register_authed(server, "/intelligence/unified", HTTP_GET, unified_intelligence_handler);
    register_authed(server, "/system/info", HTTP_GET, system_info_handler);

    register_authed(server, "/ap/config", HTTP_GET, ap_config_get_handler);
    register_authed(server, "/ap/config", HTTP_POST, ap_config_set_handler);

    register_authed(server, "/history/samples", HTTP_GET, history_samples_handler);
    register_authed(server, "/devices/list", HTTP_GET, devices_list_handler);
    register_authed(server, "/devices/update", HTTP_POST, devices_update_handler);
    register_authed(server, "/webhook/config", HTTP_GET, webhook_config_get_handler);
    register_authed(server, "/webhook/config", HTTP_POST, webhook_config_set_handler);
    register_authed(server, "/webhook/test", HTTP_POST, webhook_test_handler);
    register_authed(server, "/home-ssids", HTTP_GET, home_ssids_get_handler);
    register_authed(server, "/home-ssids/add", HTTP_POST, home_ssids_add_handler);
    register_authed(server, "/home-ssids/remove", HTTP_POST, home_ssids_remove_handler);
    register_authed(server, "/home-ssids/refresh", HTTP_POST, home_ssids_refresh_handler);

    // Peer discovery routes for multi-device coordination
    register_authed(server, "/peers", HTTP_GET, peers_list_handler);
    register_authed(server, "/peers/status", HTTP_GET, peers_status_handler);
    register_authed(server, "/peers/elect", HTTP_POST, peers_elect_handler);

    ESP_LOGI(TAG, "All URI handlers registered successfully");
    ESP_LOGI(TAG, "Free heap after registration: %lu bytes", (unsigned long)esp_get_free_heap_size());
    return ESP_OK;
}

static esp_err_t redirect_handler(httpd_req_t *req) {
    char host[128] = {0};
    if (httpd_req_get_hdr_value_str(req, "Host", host, sizeof(host)) != ESP_OK) {
        strlcpy(host, "192.168.66.1", sizeof(host));
    }

    char location[192];
    int written = snprintf(location, sizeof(location), "https://%s/", host);
    if (written <= 0 || written >= (int)sizeof(location)) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Redirect failed");
        return ESP_FAIL;
    }

    httpd_resp_set_status(req, "301 Moved Permanently");
    httpd_resp_set_hdr(req, "Location", location);
    httpd_resp_send(req, NULL, 0);
    return ESP_OK;
}

static httpd_handle_t start_http_redirect_server(void) {
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.server_port = 80;
    config.lru_purge_enable = true;
    config.max_uri_handlers = 2;
    config.max_open_sockets = 1;
    config.backlog_conn = 1;
    config.uri_match_fn = httpd_uri_match_wildcard;
#ifdef CONFIG_IDF_TARGET_ESP32C5
    config.stack_size = 3072;
#endif

    httpd_uri_t redirect_uri = {
        .uri = "/*",
        .method = HTTP_GET,
        .handler = redirect_handler,
        .user_ctx = NULL,
    };

    httpd_handle_t server = NULL;
    if (httpd_start(&server, &config) == ESP_OK) {
        httpd_register_uri_handler(server, &redirect_uri);
        ESP_LOGI(TAG, "HTTP redirect server started on :80");
    } else {
        ESP_LOGW(TAG, "Failed to start HTTP redirect server");
    }

    return server;
}

// Connection open handler - checks heap health before accepting HTTPS connections
static esp_err_t https_open_fn(httpd_handle_t hd, int sockfd) {
    uint32_t free_heap = esp_get_free_heap_size();

    // Reject connections if heap is critically low
    // TLS handshakes need ~6-8KB for crypto buffers
    if (free_heap < 10000) {
        ESP_LOGW(TAG, "Rejecting connection: low heap (%lu bytes)", (unsigned long)free_heap);
        return ESP_FAIL;
    }

    return ESP_OK;
}

static httpd_handle_t start_https_server(void) {
    if (!tls_cert_load_or_generate(&s_tls_bundle)) {
        ESP_LOGE(TAG, "TLS certificate generation failed");
        return NULL;
    }

    auth_load_password();
    auth_generate_token();

    httpd_ssl_config_t conf = HTTPD_SSL_CONFIG_DEFAULT();
    conf.port_secure = 443;
    conf.servercert = (const uint8_t *)s_tls_bundle.cert_pem;
    conf.servercert_len = strlen(s_tls_bundle.cert_pem) + 1;
    conf.prvtkey_pem = (const uint8_t *)s_tls_bundle.key_pem;
    conf.prvtkey_len = strlen(s_tls_bundle.key_pem) + 1;
    conf.httpd.max_uri_handlers = 58;  // Increased for peer discovery routes
#ifdef CONFIG_IDF_TARGET_ESP32C5
    conf.httpd.max_open_sockets = 2;
    conf.httpd.backlog_conn = 1;
    conf.httpd.stack_size = 4096;
#else
    conf.httpd.max_open_sockets = 4;
    conf.httpd.backlog_conn = 1;
    conf.httpd.stack_size = 6144;
#endif
    conf.httpd.lru_purge_enable = true;
    conf.httpd.send_wait_timeout = 5;
    conf.httpd.recv_wait_timeout = 5;
    conf.httpd.keep_alive_enable = false;
    conf.httpd.keep_alive_idle = 5;
    conf.httpd.keep_alive_interval = 2;
    conf.httpd.keep_alive_count = 3;
    conf.httpd.open_fn = https_open_fn; // check heap health before accepting connections

    httpd_handle_t server = NULL;
    esp_err_t err = httpd_ssl_start(&server, &conf);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "HTTPS server started on :443");
        register_routes(server);
    } else {
        ESP_LOGE(TAG, "Failed to start HTTPS server: %s", esp_err_to_name(err));
    }
    return server;
}

httpd_handle_t start_webserver(void) {
    ESP_LOGI(TAG, "=== WEB SERVER INITIALIZATION (HTTPS + redirect) ===");
    ESP_LOGI(TAG, "Free heap before start: %lu bytes", (unsigned long)esp_get_free_heap_size());
    ESP_LOGI(TAG, "Min free heap ever: %lu bytes", (unsigned long)esp_get_minimum_free_heap_size());

    s_https_server = start_https_server();
    if (!s_https_server) {
        ESP_LOGE(TAG, "HTTPS server failed to start");
        return NULL;
    }

    // Optional HTTP redirect server (best-effort, non-fatal)
    if (!s_http_redirect_server) {
        s_http_redirect_server = start_http_redirect_server();
    }

    ESP_LOGI(TAG, "=== WEB SERVER READY (HTTPS only) ===");
    return s_https_server;
}
