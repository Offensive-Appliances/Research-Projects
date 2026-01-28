#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "web_server.h"
#include "wifi_scan.h"
#include "esp_netif.h"
#include <string.h>
#include "deauth.h"
#include "esp_ota_ops.h"
#include "background_scan.h"
#include "ap_config.h"
#include "mdns_service.h"
#include "sta_config.h"
#include "idle_scanner.h"
#include "device_db.h"
#include "device_lifecycle.h"
#include "webhook.h"
#include "scan_storage.h"
#include "esp_sntp.h"
#include "esp_timer.h"
#include "esp_system.h"
#include "esp_sleep.h"
#include "monitor_uptime.h"
#include "recovery.h"
#include <time.h>
#include "lwip/ip4_addr.h"
#include "lwip/netdb.h"
#include "lwip/dns.h"
#include "peer_discovery.h"

#define TAG "PwnPower"
#define MAX_STA_CONN 4
#define MAX_RETRY 5

static int s_retry_num = 0;
static bool s_time_synced = false;
static bool s_sntp_started = false;

static void pwnpower_time_sync_cb(struct timeval *tv) {
    s_time_synced = true;
    time_t now = 0;
    time(&now);
    struct tm tm_info;
    localtime_r(&now, &tm_info);
    ESP_LOGI(TAG, "Time synchronized: %04d-%02d-%02d %02d:%02d:%02d", tm_info.tm_year + 1900, tm_info.tm_mon + 1, tm_info.tm_mday, tm_info.tm_hour, tm_info.tm_min, tm_info.tm_sec);
}

// AP reconnect system state
static uint32_t s_last_disconnect_time = 0;
static uint32_t s_next_retry_time = 0;
static const uint32_t RETRY_INTERVALS[] = {30, 60, 120, 300, 600}; // 30s, 1m, 2m, 5m, 10m
static const int RETRY_INTERVAL_COUNT = 5;
static int s_current_retry_interval = 0;

static void pwnpower_sntp_sync_time(void) {
    // Debug DNS resolution for NTP
    struct addrinfo hints = {0}, *res;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    int err = getaddrinfo("pool.ntp.org", "123", &hints, &res);
    if (err != 0) {
        ESP_LOGE(TAG, "DNS lookup for pool.ntp.org failed: %d", err);
    } else {
        struct sockaddr_in *addr = (struct sockaddr_in *)res->ai_addr;
        uint32_t ip = addr->sin_addr.s_addr;
        ESP_LOGI(TAG, "DNS lookup for pool.ntp.org success: %d.%d.%d.%d",
                 (int)(ip & 0xFF), (int)((ip >> 8) & 0xFF),
                 (int)((ip >> 16) & 0xFF), (int)((ip >> 24) & 0xFF));
        freeaddrinfo(res);
    }

    if (!esp_sntp_enabled()) {
        esp_sntp_setoperatingmode(SNTP_OPMODE_POLL);
        esp_sntp_setservername(0, "pool.ntp.org");
        esp_sntp_setservername(1, "time.google.com");
        esp_sntp_setservername(2, "time.windows.com");
        esp_sntp_set_time_sync_notification_cb(pwnpower_time_sync_cb);
        esp_sntp_init();
        s_sntp_started = true;
        ESP_LOGI(TAG, "SNTP started with 3 servers (pool.ntp.org, time.google.com, time.windows.com)");
    } else {
        s_time_synced = false; // Reset to force re-check
        esp_sntp_stop(); 
        esp_sntp_setoperatingmode(SNTP_OPMODE_POLL); // Ensure mode is set
        esp_sntp_setservername(0, "pool.ntp.org");
        esp_sntp_setservername(1, "time.google.com");
        esp_sntp_setservername(2, "time.windows.com");
        esp_sntp_set_time_sync_notification_cb(pwnpower_time_sync_cb);
        esp_sntp_init();
        ESP_LOGI(TAG, "SNTP restarted - checking for time sync...");
    }
}

bool pwnpower_time_is_synced(void) {
    if (s_time_synced) return true;
    if (!s_sntp_started) return false;
    time_t now = 0;
    time(&now);
    s_time_synced = (now > 1704067200);
    return s_time_synced;
}

static void wifi_event_handler(void* arg, esp_event_base_t event_base,
                                int32_t event_id, void* event_data) {
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        sta_config_t sta_cfg;
        if (sta_config_get(&sta_cfg) == ESP_OK && strlen(sta_cfg.ssid) > 0 && sta_cfg.auto_connect) {
            ESP_LOGI(TAG, "STA started, attempting connection...");
            esp_wifi_connect();
        }
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        webserver_set_sta_connected(false);
        s_time_synced = false;
        
        // Record disconnect time for periodic retry system
        s_last_disconnect_time = (uint32_t)(esp_timer_get_time() / 1000000ULL);
        
        if (wifi_scan_is_station_scan_active()) {
            ESP_LOGI(TAG, "Station scan in progress, skipping auto-reconnect");
            return;
        }
        
        // NOTE: We no longer re-enable AP here immediately.
        // Instead, we stay in STA mode during reconnect attempts to avoid channel conflicts.
        // The AP will be re-enabled:
        // 1. After successful STA connection (in IP_EVENT_STA_GOT_IP)
        // 2. After all retry attempts exhausted (below)
        // 3. By the periodic reconnect task
        
        sta_config_t sta_cfg;
        bool should_retry = (sta_config_get(&sta_cfg) == ESP_OK && sta_cfg.auto_connect);
        if (should_retry && s_retry_num < MAX_RETRY) {
            // Keep STA mode during reconnect attempts for cleaner channel handling
            wifi_mode_t current_mode;
            esp_wifi_get_mode(&current_mode);
            if (current_mode == WIFI_MODE_APSTA) {
                ESP_LOGI(TAG, "Temporarily switching to STA mode for reconnect");
                esp_wifi_set_mode(WIFI_MODE_STA);
                vTaskDelay(pdMS_TO_TICKS(100));
            }
            
            vTaskDelay(pdMS_TO_TICKS(2000));  // Increased delay to allow driver to settle
            esp_wifi_disconnect(); // Ensure clean state before retrying
            vTaskDelay(pdMS_TO_TICKS(100)); 
            esp_wifi_connect();
            s_retry_num++;
            ESP_LOGI(TAG, "Retry connecting to STA (%d/%d)", s_retry_num, MAX_RETRY);
        } else if (s_retry_num >= MAX_RETRY) {
            ESP_LOGW(TAG, "Failed to connect to STA after %d retries", MAX_RETRY);
            
            // Re-enable AP after all retries exhausted so device is accessible
            // BUT only if we have enough heap - AP creation needs ~8KB
            wifi_mode_t current_mode;
            esp_wifi_get_mode(&current_mode);
            uint32_t free_heap = esp_get_free_heap_size();
            if (current_mode == WIFI_MODE_STA) {
                if (free_heap > 15000) {  // Need at least 15KB free to safely enable AP
                    ESP_LOGI(TAG, "Re-enabling AP after connection failure (heap: %lu)", (unsigned long)free_heap);
                    esp_wifi_set_mode(WIFI_MODE_APSTA);
                } else {
                    ESP_LOGW(TAG, "Skipping AP re-enable - low heap (%lu bytes), would crash", (unsigned long)free_heap);
                    // Stay in STA mode to conserve memory, will try again on next periodic retry
                }
            }
            
            // Schedule next retry with exponential backoff
            uint32_t interval = RETRY_INTERVALS[s_current_retry_interval];
            s_next_retry_time = s_last_disconnect_time + interval;
            ESP_LOGI(TAG, "Scheduling next retry in %lu seconds", (unsigned long)interval);
            if (s_current_retry_interval < RETRY_INTERVAL_COUNT - 1) {
                s_current_retry_interval++;
            }
        }
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
        ESP_LOGI(TAG, "Got IP: " IPSTR, IP2STR(&event->ip_info.ip));
        s_retry_num = 0;
        
        // Reset periodic retry state on successful connection
        s_current_retry_interval = 0;
        s_next_retry_time = 0;
        webserver_set_sta_connected(true);
        // Update mDNS hostname based on peer discovery role
        mdns_service_update_hostname(peer_discovery_get_hostname());
        pwnpower_sntp_sync_time();

        // Set home network to the connected SSID for device prioritization
        sta_config_t sta_cfg;
        if (sta_config_get(&sta_cfg) == ESP_OK && strlen(sta_cfg.ssid) > 0) {
            scan_storage_set_home_ssid(sta_cfg.ssid);

            if (!sta_cfg.ap_while_connected) {
                // If user EXPLICITLY disabled AP-while-connected, respect that
                ESP_LOGI(TAG, "Disabling AP (ap_while_connected=false)");
                esp_wifi_set_mode(WIFI_MODE_STA);
            } else {
                // Default: Keep AP running
                ESP_LOGI(TAG, "Keeping AP active (ap_while_connected=true)");
                // No mode change needed, we are already in APSTA
            }
                // Re-enable AP if it was disabled during reconnect attempts
                wifi_mode_t current_mode;
                esp_wifi_get_mode(&current_mode);
                if (current_mode == WIFI_MODE_STA) {
                    uint32_t free_heap = esp_get_free_heap_size();
                    if (free_heap > 15000) {  // Need at least 15KB free to safely enable AP
                        ESP_LOGI(TAG, "Re-enabling AP after successful connection (heap: %lu)", (unsigned long)free_heap);
                        esp_wifi_set_mode(WIFI_MODE_APSTA);
                    } else {
                        ESP_LOGW(TAG, "Skipping AP re-enable - low heap (%lu bytes)", (unsigned long)free_heap);
                    }
                }
            }
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_AP_STAIPASSIGNED) {
        ip_event_ap_staipassigned_t *event = (ip_event_ap_staipassigned_t *)event_data;
        ESP_LOGI(TAG, "DHCP assigned IP to station: " IPSTR, IP2STR(&event->ip));
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_AP_STACONNECTED) {
        wifi_event_ap_staconnected_t *event = (wifi_event_ap_staconnected_t *)event_data;
        ESP_LOGI(TAG, "Station connected: %02x:%02x:%02x:%02x:%02x:%02x, AID=%d", event->mac[0], event->mac[1], event->mac[2], event->mac[3], event->mac[4], event->mac[5], event->aid);
    }
}

// Peer discovery event callback - handle role changes and peer events
static void peer_event_handler(peer_event_type_t event, const peer_info_t *peer) {
    switch (event) {
        case PEER_EVENT_ROLE_CHANGED:
            ESP_LOGI(TAG, "Peer role changed to: %s", 
                     peer_discovery_get_role() == PEER_ROLE_LEADER ? "leader" : "follower");
            // Update mDNS hostname to reflect new role
            mdns_service_update_hostname(peer_discovery_get_hostname());
            
            // Update AP SSID to reflect new role
            {
                const char *new_ssid = peer_discovery_get_ap_ssid();
                wifi_config_t wifi_config = {0};
                esp_wifi_get_config(WIFI_IF_AP, &wifi_config);
                
                // Only update if SSID actually changed
                if (strcmp((char*)wifi_config.ap.ssid, new_ssid) != 0) {
                    strncpy((char*)wifi_config.ap.ssid, new_ssid, sizeof(wifi_config.ap.ssid) - 1);
                    wifi_config.ap.ssid_len = strlen(new_ssid);
                    esp_wifi_set_config(WIFI_IF_AP, &wifi_config);
                    ESP_LOGI(TAG, "AP SSID updated to: %s", new_ssid);
                }
            }
            break;
        case PEER_EVENT_DISCOVERED:
            if (peer) {
                ESP_LOGI(TAG, "New PwnPower peer discovered: %s (%02x:%02x:%02x:%02x:%02x:%02x)",
                         peer->hostname, peer->mac[0], peer->mac[1], peer->mac[2],
                         peer->mac[3], peer->mac[4], peer->mac[5]);
            }
            break;
        case PEER_EVENT_LOST:
            if (peer) {
                ESP_LOGI(TAG, "PwnPower peer lost: %02x:%02x:%02x:%02x:%02x:%02x",
                         peer->mac[0], peer->mac[1], peer->mac[2],
                         peer->mac[3], peer->mac[4], peer->mac[5]);
            }
            break;
        case PEER_EVENT_LEADER_CHANGED:
            if (peer) {
                ESP_LOGI(TAG, "New leader elected: %s", peer->hostname);
            }
            break;
    }
}

void wifi_init_softap() {
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();
    esp_netif_t *ap_netif = esp_netif_create_default_wifi_ap();
    esp_netif_ip_info_t ip_info = {0};
    IP4_ADDR(&ip_info.ip, 192, 168, 66, 1);
    IP4_ADDR(&ip_info.gw, 192, 168, 66, 1);
    IP4_ADDR(&ip_info.netmask, 255, 255, 255, 0);
    ESP_ERROR_CHECK(esp_netif_dhcps_stop(ap_netif));
    ESP_ERROR_CHECK(esp_netif_set_ip_info(ap_netif, &ip_info));
    esp_netif_dns_info_t dns_main = {0};
    dns_main.ip.u_addr.ip4 = ip_info.ip;
    dns_main.ip.type = IPADDR_TYPE_V4;
    ESP_ERROR_CHECK(esp_netif_set_dns_info(ap_netif, ESP_NETIF_DNS_MAIN, &dns_main));
    ESP_ERROR_CHECK(esp_netif_dhcps_start(ap_netif));
    esp_netif_set_hostname(ap_netif, "pwnpower");
    mdns_service_init("pwnpower");

    ESP_ERROR_CHECK(esp_netif_get_ip_info(ap_netif, &ip_info));
    ESP_LOGI(TAG, "AP IP Address: " IPSTR, IP2STR(&ip_info.ip));

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    
    wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT
    };
    
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(NULL));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_filter(&filter));
    
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_AP_STAIPASSIGNED, &wifi_event_handler, NULL));
    
    ap_config_init();
    sta_config_init();
    
    ap_config_t ap_cfg;
    ap_config_get(&ap_cfg);
    
    wifi_config_t wifi_config = {0};
    strncpy((char*)wifi_config.ap.ssid, ap_cfg.ssid, sizeof(wifi_config.ap.ssid) - 1);
    wifi_config.ap.ssid_len = strlen(ap_cfg.ssid);
    wifi_config.ap.channel = 6;
    wifi_config.ap.max_connection = MAX_STA_CONN;
    wifi_config.ap.pmf_cfg.required = true;
    
    if (strlen(ap_cfg.password) >= 8) {
        strncpy((char*)wifi_config.ap.password, ap_cfg.password, sizeof(wifi_config.ap.password) - 1);
        wifi_config.ap.authmode = WIFI_AUTH_WPA2_WPA3_PSK;
    } else {
        wifi_config.ap.authmode = WIFI_AUTH_OPEN;
    }
    
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &wifi_config));
    
    sta_config_t sta_cfg;
    if (sta_config_get(&sta_cfg) == ESP_OK && strlen(sta_cfg.ssid) > 0) {
        wifi_config_t sta_wifi_config = {0};
        strncpy((char*)sta_wifi_config.sta.ssid, sta_cfg.ssid, sizeof(sta_wifi_config.sta.ssid) - 1);
        strncpy((char*)sta_wifi_config.sta.password, sta_cfg.password, sizeof(sta_wifi_config.sta.password) - 1);
        sta_wifi_config.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;
        sta_wifi_config.sta.pmf_cfg.capable = true;
        sta_wifi_config.sta.pmf_cfg.required = false;
        
        ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &sta_wifi_config));
        ESP_LOGI(TAG, "Auto-connecting to saved network: %s", sta_cfg.ssid);
    }
    
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_LOGI(TAG, "Wi-Fi AP+STA Started: SSID=%s", ap_cfg.ssid);
}

static void sta_reconnect_task(void *arg) {
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(30000)); // Check every 30 seconds
        
        sta_config_t sta_cfg;
        if (!sta_config_get(&sta_cfg) || !sta_cfg.auto_connect || strlen(sta_cfg.ssid) == 0) {
            continue;
        }
        
        // Only attempt periodic retry if we've exhausted immediate retries
        if (s_retry_num < MAX_RETRY) {
            continue;
        }
        
        uint32_t now = (uint32_t)(esp_timer_get_time() / 1000000ULL);
        
        // Check if it's time to retry
        if (now >= s_next_retry_time && s_next_retry_time > 0) {
            ESP_LOGI(TAG, "Attempting periodic reconnect to %s", sta_cfg.ssid);
            
            // Reset retry counter for this attempt
            s_retry_num = 0;
            
            // Attempt connection
            esp_wifi_connect();
            
            // Update next retry time
            uint32_t interval = RETRY_INTERVALS[s_current_retry_interval];
            s_next_retry_time = now + interval;
            ESP_LOGI(TAG, "Next periodic retry in %lu seconds", (unsigned long)interval);
            
            // Move to next interval if not at max
            if (s_current_retry_interval < RETRY_INTERVAL_COUNT - 1) {
                s_current_retry_interval++;
            }
        }
    }
}

// Periodic heap monitor task
static void heap_monitor_task(void *arg) {
    ESP_LOGI(TAG, "Heap monitor task started");

    while (1) {
        // Log heap stats every 30 seconds
        vTaskDelay(pdMS_TO_TICKS(30000));

        bool synced = pwnpower_time_is_synced();
        time_t now;
        time(&now);
        struct tm tm_info;
        localtime_r(&now, &tm_info);

        uint32_t free_heap = esp_get_free_heap_size();
        uint32_t min_free_heap = esp_get_minimum_free_heap_size();
        uint32_t largest_block = heap_caps_get_largest_free_block(MALLOC_CAP_DEFAULT);

        ESP_LOGI(TAG, "=== HEAP STATS ===");
        ESP_LOGI(TAG, "Time Sync: %s (Year: %d)", synced ? "OK" : "NOT SYNCED", tm_info.tm_year + 1900);
        ESP_LOGI(TAG, "Free heap: %lu bytes (%.1f KB)",
                 (unsigned long)free_heap, free_heap / 1024.0f);
        ESP_LOGI(TAG, "Min free ever: %lu bytes (%.1f KB)",
                 (unsigned long)min_free_heap, min_free_heap / 1024.0f);
        ESP_LOGI(TAG, "Largest free block: %lu bytes (%.1f KB)",
                 (unsigned long)largest_block, largest_block / 1024.0f);

        // Warn if heap is getting low
        if (free_heap < 20000) {
            ESP_LOGW(TAG, "WARNING: Low heap detected! Free: %lu bytes", (unsigned long)free_heap);
        }

        // Periodic cleanup every 5 minutes (10 cycles)
        static int cleanup_counter = 0;
        if (++cleanup_counter >= 10) {
            cleanup_counter = 0;
            ESP_LOGI(TAG, "Performing periodic memory cleanup...");

            // Clean up WiFi scan memory
            extern void wifi_scan_cleanup_station_json(void);
            wifi_scan_cleanup_station_json();

            // Force garbage collection
            void *temp = malloc(1024);
            if (temp) {
                free(temp);
                ESP_LOGI(TAG, "Memory cleanup completed. Heap: %lu bytes", (unsigned long)esp_get_free_heap_size());
            }
        }
    }
}

void app_main() {
    ESP_LOGI(TAG, "=== BOOT: app_main START ===");
    ESP_LOGI(TAG, "Heap at app_main entry: %lu bytes", (unsigned long)esp_get_free_heap_size());

    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    ESP_ERROR_CHECK(recovery_init());

    // Track rapid power cycles using NVS counter to allow factory reset
    recovery_handle_power_cycle_reset();

    // initialize monitor uptime tracking (early to capture boot time)
    monitor_uptime_init();
    ESP_LOGI(TAG, "Heap after monitor_uptime_init: %lu bytes", (unsigned long)esp_get_free_heap_size());

    // mark app valid so rollback doesn't screw us after ota
    esp_ota_mark_app_valid_cancel_rollback();
    attack_mutex = xSemaphoreCreateMutex();
    ESP_LOGI(TAG, "Heap before WiFi init: %lu bytes", (unsigned long)esp_get_free_heap_size());

    wifi_init_softap();
    ESP_LOGI(TAG, "Heap after WiFi init (MAJOR): %lu bytes (-%lu)",
             (unsigned long)esp_get_free_heap_size(),
             (unsigned long)(esp_get_minimum_free_heap_size()));

    // wait for any ongoing deauth to complete
    while(deauth_active) {
        ESP_LOGI(TAG, "waiting for deauth operations to complete...");
        vTaskDelay(pdMS_TO_TICKS(1000)); // check every second
    }

    start_webserver();
    ESP_LOGI(TAG, "Heap after web server: %lu bytes", (unsigned long)esp_get_free_heap_size());

    mdns_service_init("pwnpower");
    ESP_LOGI(TAG, "Heap after mDNS: %lu bytes", (unsigned long)esp_get_free_heap_size());

    // Initialize and start peer discovery for multi-device coordination
    if (peer_discovery_init() == ESP_OK) {
        // Register callback to update mDNS hostname when role changes
        peer_discovery_register_callback(peer_event_handler);
        peer_discovery_start();
        ESP_LOGI(TAG, "Peer discovery started. Role: %s, Hostname: %s",
                 peer_discovery_get_role() == PEER_ROLE_LEADER ? "leader" : "follower",
                 peer_discovery_get_hostname());
    }
    ESP_LOGI(TAG, "Heap after peer discovery: %lu bytes", (unsigned long)esp_get_free_heap_size());

    // initialize device tracking
    device_db_init();
    ESP_LOGI(TAG, "Heap after DeviceDB: %lu bytes", (unsigned long)esp_get_free_heap_size());

    device_lifecycle_init();
    ESP_LOGI(TAG, "Heap after DeviceLifecycle: %lu bytes", (unsigned long)esp_get_free_heap_size());

    // initialize and start webhook dispatcher
    webhook_init();
    ESP_LOGI(TAG, "Heap after webhook_init: %lu bytes", (unsigned long)esp_get_free_heap_size());

    // initialize wifi scan memory
    extern void wifi_scan_init_memory(void);
    wifi_scan_init_memory();
    ESP_LOGI(TAG, "Heap after wifi_scan_init_memory: %lu bytes", (unsigned long)esp_get_free_heap_size());

    webhook_start();
    ESP_LOGI(TAG, "Heap after webhook_start (task): %lu bytes", (unsigned long)esp_get_free_heap_size());

    if (background_scan_init() == ESP_OK) {
        ESP_LOGI(TAG, "Heap after background_scan_init: %lu bytes", (unsigned long)esp_get_free_heap_size());
        background_scan_start();
        ESP_LOGI(TAG, "Heap after background_scan_start (task): %lu bytes", (unsigned long)esp_get_free_heap_size());
    }

    if (idle_scanner_init() == ESP_OK) {
        ESP_LOGI(TAG, "Heap after idle_scanner_init: %lu bytes", (unsigned long)esp_get_free_heap_size());
        idle_scanner_start();
        ESP_LOGI(TAG, "Heap after idle_scanner_start (task): %lu bytes", (unsigned long)esp_get_free_heap_size());
    }

    // start periodic sta reconnect task
    ESP_LOGI(TAG, "Heap before sta_reconnect task: %lu bytes", (unsigned long)esp_get_free_heap_size());
    xTaskCreate(sta_reconnect_task, "sta_reconnect", 2048, NULL, 5, NULL);
    ESP_LOGI(TAG, "Started STA reconnect task");
    ESP_LOGI(TAG, "Heap after sta_reconnect task: %lu bytes", (unsigned long)esp_get_free_heap_size());

    // start periodic heap monitor task
    xTaskCreate(heap_monitor_task, "heap_monitor", 4096, NULL, 1, NULL);
    ESP_LOGI(TAG, "Started heap monitor task");

    ESP_LOGI(TAG, "=== APP INITIALIZATION COMPLETE ===");
    ESP_LOGI(TAG, "Initial free heap: %lu bytes (%.1f KB)",
             (unsigned long)esp_get_free_heap_size(),
             esp_get_free_heap_size() / 1024.0f);
}