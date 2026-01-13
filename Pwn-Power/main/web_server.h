#ifndef WEB_SERVER_H
#define WEB_SERVER_H

#include <esp_http_server.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

httpd_handle_t start_webserver(void);
void webserver_set_sta_connected(bool connected);
bool webserver_get_sta_connected(void);
uint32_t webserver_get_last_request_time(void);

#ifdef __cplusplus
}
#endif

#endif
