#include "peer_discovery.h"
#include "mdns.h"
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_timer.h"
#include "esp_netif.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "wifi_scan.h"
#include <string.h>

#define TAG "PeerDiscovery"

// Discovery configuration
#define PEER_DISCOVERY_PORT 51337
#define PEER_ANNOUNCE_INTERVAL_MS 5000
#define PEER_QUERY_INTERVAL_MS 10000
#define PEER_TIMEOUT_MS 30000
#define PEER_SERVICE_TYPE "_legacyhnl"
#define PEER_SERVICE_PROTO "_udp"

// NVS storage
#define NVS_NAMESPACE "peer_cfg"
#define NVS_KEY_AP_MODE "ap_mode"

// AP scanning
#define PEER_AP_SCAN_INTERVAL_MS 60000  // Scan for other Legacy-HNL APs every 60 seconds
#define LEGACYHNL_SSID_PREFIX "Legacy-HNL"

// Message types for UDP protocol
typedef enum {
    MSG_TYPE_ANNOUNCE = 0x01,
    MSG_TYPE_QUERY = 0x02,
    MSG_TYPE_RESPONSE = 0x03,
    MSG_TYPE_ELECTION = 0x04
} msg_type_t;

// UDP message structure (packed for network transmission)
typedef struct __attribute__((packed)) {
    uint8_t type;
    uint8_t mac[6];
    uint32_t boot_time;
    uint32_t ip_addr;
    uint8_t role;
    uint8_t ap_active;
    char hostname[PEER_HOSTNAME_MAX_LEN];
} peer_message_t;

// Module state
static bool s_initialized = false;
static bool s_running = false;
static peer_role_t s_current_role = PEER_ROLE_UNKNOWN;
static peer_ap_mode_t s_ap_mode = PEER_AP_MODE_AUTO;
static peer_info_t s_self = {0};
static peer_info_t s_peers[PEER_MAX_DEVICES] = {0};
static size_t s_peer_count = 0;
static SemaphoreHandle_t s_peer_mutex = NULL;
static TaskHandle_t s_discovery_task = NULL;
static int s_udp_socket = -1;
static peer_event_callback_t s_event_callback = NULL;
static char s_hostname[PEER_HOSTNAME_MAX_LEN] = "legacyhnl";
static char s_ap_ssid[PEER_HOSTNAME_MAX_LEN] = "Legacy-HNL";  // AP SSID (different from mDNS hostname)
static uint32_t s_boot_time = 0;
static bool s_found_other_aps = false;  // True if we detected other Legacy-HNL APs via WiFi scan
static uint32_t s_last_legacyhnl_ap_seen = 0;
#define LEGACYHNL_AP_TIMEOUT_SEC 300 // 5 minutes without seeing AP -> revert to Leader


// Forward declarations
static void discovery_task(void *arg);
static void handle_incoming_message(peer_message_t *msg, uint32_t sender_ip);
static void send_announce(void);
static void run_election(void);
static void update_hostname(void);
static void update_ap_ssid(void);
static int compare_peers(const peer_info_t *a, const peer_info_t *b);
static void cleanup_stale_peers(void);
static void notify_event(peer_event_type_t event, const peer_info_t *peer);

// Get device MAC address
static void get_device_mac(uint8_t *mac) {
    esp_wifi_get_mac(WIFI_IF_STA, mac);
}

// Get device IP address
// Get device IP address
static uint32_t get_device_ip(void) {
    esp_netif_t *netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (netif) {
        if (esp_netif_is_netif_up(netif)) {
            esp_netif_ip_info_t ip_info;
            if (esp_netif_get_ip_info(netif, &ip_info) == ESP_OK && ip_info.ip.addr != 0) {
                return ip_info.ip.addr;
            }
        }
    }
    
    netif = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
    if (netif) {
        if (esp_netif_is_netif_up(netif)) {
            esp_netif_ip_info_t ip_info;
            if (esp_netif_get_ip_info(netif, &ip_info) == ESP_OK && ip_info.ip.addr != 0) {
                return ip_info.ip.addr;
            }
        }
    }
    return 0;
}

// Initialize self info
static void init_self_info(void) {
    memset(&s_self, 0, sizeof(s_self));
    get_device_mac(s_self.mac);
    s_self.ip_addr = get_device_ip();
    s_self.boot_time = s_boot_time;
    s_self.role = s_current_role;
    s_self.ap_active = true;  // Will be updated based on actual AP state
    s_self.is_self = true;
    s_self.last_seen = (uint32_t)(esp_timer_get_time() / 1000);
    strncpy(s_self.hostname, s_hostname, PEER_HOSTNAME_MAX_LEN - 1);
}

// Load settings from NVS
static void load_settings(void) {
    nvs_handle_t handle;
    if (nvs_open(NVS_NAMESPACE, NVS_READONLY, &handle) == ESP_OK) {
        uint8_t mode = 0;
        if (nvs_get_u8(handle, NVS_KEY_AP_MODE, &mode) == ESP_OK) {
            s_ap_mode = (peer_ap_mode_t)mode;
        }
        nvs_close(handle);
    }
}

// Save settings to NVS
static void save_settings(void) {
    nvs_handle_t handle;
    if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &handle) == ESP_OK) {
        nvs_set_u8(handle, NVS_KEY_AP_MODE, (uint8_t)s_ap_mode);
        nvs_commit(handle);
        nvs_close(handle);
    }
}

// Compare two peers for leader election (lower MAC wins)
static int compare_peers(const peer_info_t *a, const peer_info_t *b) {
    return memcmp(a->mac, b->mac, PEER_ID_LEN);
}

// Generate hostname based on role
static void update_hostname(void) {
    if (s_current_role == PEER_ROLE_LEADER) {
        strncpy(s_hostname, "legacyhnl", PEER_HOSTNAME_MAX_LEN - 1);
    } else {
        // Use last 4 hex digits of MAC for uniqueness
        snprintf(s_hostname, PEER_HOSTNAME_MAX_LEN, "legacyhnl-%02x%02x",
                 s_self.mac[4], s_self.mac[5]);
    }
    s_hostname[PEER_HOSTNAME_MAX_LEN - 1] = '\0';
    strncpy(s_self.hostname, s_hostname, PEER_HOSTNAME_MAX_LEN - 1);
    
    // Sync hostname to peer list (s_peers[0] is always self)
    xSemaphoreTake(s_peer_mutex, portMAX_DELAY);
    if (s_peer_count > 0 && s_peers[0].is_self) {
        strncpy(s_peers[0].hostname, s_hostname, PEER_HOSTNAME_MAX_LEN - 1);
        s_peers[0].hostname[PEER_HOSTNAME_MAX_LEN - 1] = '\0';
    }
    xSemaphoreGive(s_peer_mutex);
    
    ESP_LOGI(TAG, "Hostname updated to: %s", s_hostname);
}

// Run leader election
static void run_election(void) {
    if (!s_initialized || s_peer_count == 0) {
        // No peers, we're the leader
        if (s_current_role != PEER_ROLE_LEADER) {
            s_current_role = PEER_ROLE_LEADER;
            s_self.role = PEER_ROLE_LEADER;
            
            // Update self in peer list
            xSemaphoreTake(s_peer_mutex, portMAX_DELAY);
            if (s_peer_count > 0 && s_peers[0].is_self) {
                s_peers[0].role = PEER_ROLE_LEADER;
            }
            xSemaphoreGive(s_peer_mutex);
            
            update_hostname();
            notify_event(PEER_EVENT_ROLE_CHANGED, &s_self);
            ESP_LOGI(TAG, "No peers found, becoming leader");
        }
        return;
    }
    
    xSemaphoreTake(s_peer_mutex, portMAX_DELAY);
    
    // Find the peer with lowest MAC (including self)
    peer_info_t *leader = &s_self;
    
    for (size_t i = 0; i < s_peer_count; i++) {
        if (!s_peers[i].is_self && compare_peers(&s_peers[i], leader) < 0) {
            leader = &s_peers[i];
        }
    }
    
    peer_role_t old_role = s_current_role;
    
    if (leader->is_self) {
        s_current_role = PEER_ROLE_LEADER;
        s_self.role = PEER_ROLE_LEADER;
        ESP_LOGI(TAG, "Election result: We are the leader");
    } else {
        s_current_role = PEER_ROLE_FOLLOWER;
        s_self.role = PEER_ROLE_FOLLOWER;
        ESP_LOGI(TAG, "Election result: Leader is %02x:%02x:%02x:%02x:%02x:%02x",
                 leader->mac[0], leader->mac[1], leader->mac[2],
                 leader->mac[3], leader->mac[4], leader->mac[5]);
    }
    
    // Update self in peer list (s_peers[0] is always self)
    if (s_peer_count > 0 && s_peers[0].is_self) {
        s_peers[0].role = s_current_role;
    }
    
    xSemaphoreGive(s_peer_mutex);
    
    update_hostname();
    
    if (old_role != s_current_role) {
        notify_event(PEER_EVENT_ROLE_CHANGED, &s_self);
    }
}

// Clean up peers that haven't been seen recently
static void cleanup_stale_peers(void) {
    uint32_t now = (uint32_t)(esp_timer_get_time() / 1000);
    bool need_election = false;
    
    xSemaphoreTake(s_peer_mutex, portMAX_DELAY);
    
    for (size_t i = 0; i < s_peer_count; ) {
        if (!s_peers[i].is_self && (now - s_peers[i].last_seen) > PEER_TIMEOUT_MS) {
            ESP_LOGI(TAG, "Peer timed out: %02x:%02x:%02x:%02x:%02x:%02x",
                     s_peers[i].mac[0], s_peers[i].mac[1], s_peers[i].mac[2],
                     s_peers[i].mac[3], s_peers[i].mac[4], s_peers[i].mac[5]);
            
            peer_info_t lost_peer = s_peers[i];
            
            // Remove peer by shifting array
            memmove(&s_peers[i], &s_peers[i + 1], 
                    (s_peer_count - i - 1) * sizeof(peer_info_t));
            s_peer_count--;
            
            xSemaphoreGive(s_peer_mutex);
            notify_event(PEER_EVENT_LOST, &lost_peer);
            xSemaphoreTake(s_peer_mutex, portMAX_DELAY);
            
            need_election = true;
        } else {
            i++;
        }
    }
    
    xSemaphoreGive(s_peer_mutex);
    
    if (need_election) {
        run_election();
    }
}

// Send announcement message
static void send_announce(void) {
    if (s_udp_socket < 0) return;
    
    // Update self info
    s_self.ip_addr = get_device_ip();
    s_self.last_seen = (uint32_t)(esp_timer_get_time() / 1000);
    
    // Skip announce if we don't have a valid IP (not connected to network)
    if (s_self.ip_addr == 0) {
        return;
    }
    
    // Sync self to peer list (s_peers[0] is always self)
    xSemaphoreTake(s_peer_mutex, portMAX_DELAY);
    if (s_peer_count > 0 && s_peers[0].is_self) {
        s_peers[0].ip_addr = s_self.ip_addr;
        s_peers[0].last_seen = s_self.last_seen;
        strncpy(s_peers[0].hostname, s_hostname, PEER_HOSTNAME_MAX_LEN - 1);
    }
    xSemaphoreGive(s_peer_mutex);
    
    peer_message_t msg = {0};
    msg.type = MSG_TYPE_ANNOUNCE;
    memcpy(msg.mac, s_self.mac, 6);
    msg.boot_time = htonl(s_boot_time);
    msg.ip_addr = s_self.ip_addr;
    msg.role = (uint8_t)s_current_role;
    msg.ap_active = s_self.ap_active ? 1 : 0;
    strncpy(msg.hostname, s_hostname, PEER_HOSTNAME_MAX_LEN - 1);
    
    // Broadcast to local network
    struct sockaddr_in dest_addr = {0};
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(PEER_DISCOVERY_PORT);
    dest_addr.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    
    int err = sendto(s_udp_socket, &msg, sizeof(msg), 0,
                     (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    if (err < 0) {
        // Only log occasionally to avoid spam
        static uint32_t last_warn = 0;
        uint32_t now = (uint32_t)(esp_timer_get_time() / 1000);
        if (now - last_warn > 30000) {  // Log at most once per 30 seconds
            ESP_LOGW(TAG, "Failed to send announce: %d", errno);
            last_warn = now;
        }
    }
}

// Handle incoming peer message
static void handle_incoming_message(peer_message_t *msg, uint32_t sender_ip) {
    // Ignore messages from self
    if (memcmp(msg->mac, s_self.mac, 6) == 0) {
        return;
    }
    
    xSemaphoreTake(s_peer_mutex, portMAX_DELAY);
    
    // Find existing peer or add new one
    peer_info_t *peer = NULL;
    for (size_t i = 0; i < s_peer_count; i++) {
        if (memcmp(s_peers[i].mac, msg->mac, 6) == 0) {
            peer = &s_peers[i];
            break;
        }
    }
    
    bool is_new_peer = (peer == NULL);
    
    if (is_new_peer && s_peer_count < PEER_MAX_DEVICES) {
        peer = &s_peers[s_peer_count++];
        memset(peer, 0, sizeof(peer_info_t));
        memcpy(peer->mac, msg->mac, 6);
        ESP_LOGI(TAG, "New peer discovered: %02x:%02x:%02x:%02x:%02x:%02x",
                 msg->mac[0], msg->mac[1], msg->mac[2],
                 msg->mac[3], msg->mac[4], msg->mac[5]);
    }
    
    if (peer) {
        peer->ip_addr = sender_ip;
        peer->boot_time = ntohl(msg->boot_time);
        peer->role = (peer_role_t)msg->role;
        peer->ap_active = msg->ap_active != 0;
        peer->last_seen = (uint32_t)(esp_timer_get_time() / 1000);
        peer->is_self = false;
        strncpy(peer->hostname, msg->hostname, PEER_HOSTNAME_MAX_LEN - 1);
    }
    
    xSemaphoreGive(s_peer_mutex);
    
    if (is_new_peer && peer) {
        notify_event(PEER_EVENT_DISCOVERED, peer);
        run_election();
    }
}

// Notify registered callback of events
static void notify_event(peer_event_type_t event, const peer_info_t *peer) {
    if (s_event_callback) {
        s_event_callback(event, peer);
    }
}

// Discovery task - handles announcements and incoming messages
static void discovery_task(void *arg) {
    uint32_t last_announce = 0;
    uint32_t last_cleanup = 0;
    
    while (s_running) {
        uint32_t now = (uint32_t)(esp_timer_get_time() / 1000);
        
        // Periodic announce (skip if station scan is in progress to avoid interference)
        if (now - last_announce >= PEER_ANNOUNCE_INTERVAL_MS) {
            if (!wifi_scan_is_in_progress() && !wifi_scan_is_station_scan_active()) {
                send_announce();
            }
            last_announce = now;
        }
        
        // Periodic cleanup of stale peers
        if (now - last_cleanup >= PEER_TIMEOUT_MS / 2) {
            cleanup_stale_peers();
            last_cleanup = now;
        }
        
        // Periodic scan for other Legacy-HNL APs is now handled by system background scans
        // We just check for timeout here
        if (s_found_other_aps) {
            if (now - s_last_legacyhnl_ap_seen > LEGACYHNL_AP_TIMEOUT_SEC) {
                ESP_LOGI(TAG, "No Legacy-HNL AP seen for %d seconds - reverting to Leader", LEGACYHNL_AP_TIMEOUT_SEC);
                s_found_other_aps = false;
                if (s_peer_count <= 1) {
                    s_current_role = PEER_ROLE_LEADER;
                    s_self.role = PEER_ROLE_LEADER;
                    update_hostname();
                    update_ap_ssid();
                    notify_event(PEER_EVENT_ROLE_CHANGED, &s_self);
                }
            }
        }
        
        // Check for incoming messages
        if (s_udp_socket >= 0) {
            struct sockaddr_in source_addr;
            socklen_t addr_len = sizeof(source_addr);
            peer_message_t msg;
            
            // Non-blocking receive
            int len = recvfrom(s_udp_socket, &msg, sizeof(msg), MSG_DONTWAIT,
                              (struct sockaddr *)&source_addr, &addr_len);
            
            if (len == sizeof(peer_message_t)) {
                handle_incoming_message(&msg, source_addr.sin_addr.s_addr);
            }
        }
        
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    
    vTaskDelete(NULL);
}

// Create and bind UDP socket
static esp_err_t create_socket(void) {
    s_udp_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s_udp_socket < 0) {
        ESP_LOGE(TAG, "Failed to create socket: %d", errno);
        return ESP_FAIL;
    }
    
    // Enable broadcast
    int broadcast = 1;
    setsockopt(s_udp_socket, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast));
    
    // Allow address reuse
    int reuse = 1;
    setsockopt(s_udp_socket, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    
    // Bind to port
    struct sockaddr_in bind_addr = {0};
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = htons(PEER_DISCOVERY_PORT);
    bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    
    if (bind(s_udp_socket, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
        ESP_LOGE(TAG, "Failed to bind socket: %d", errno);
        close(s_udp_socket);
        s_udp_socket = -1;
        return ESP_FAIL;
    }
    
    ESP_LOGI(TAG, "UDP socket bound to port %d", PEER_DISCOVERY_PORT);
    return ESP_OK;
}

// Register mDNS service for discovery
static esp_err_t register_mdns_service(void) {
    // Add TXT records with device info
    mdns_txt_item_t txt[] = {
        {"mac", ""},
        {"role", "unknown"}
    };
    
    char mac_str[18];
    snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
             s_self.mac[0], s_self.mac[1], s_self.mac[2],
             s_self.mac[3], s_self.mac[4], s_self.mac[5]);
    txt[0].value = mac_str;
    txt[1].value = (s_current_role == PEER_ROLE_LEADER) ? "leader" : "follower";
    
    esp_err_t err = mdns_service_add("Legacy-HNL Peer", PEER_SERVICE_TYPE, 
                                      PEER_SERVICE_PROTO, PEER_DISCOVERY_PORT, txt, 2);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Failed to add mDNS service: %s", esp_err_to_name(err));
    }
    
    return err;
}

// Public API implementations

esp_err_t peer_discovery_init(void) {
    if (s_initialized) {
        return ESP_OK;
    }
    
    s_peer_mutex = xSemaphoreCreateMutex();
    if (!s_peer_mutex) {
        ESP_LOGE(TAG, "Failed to create mutex");
        return ESP_ERR_NO_MEM;
    }
    
    // Record boot time
    s_boot_time = (uint32_t)(esp_timer_get_time() / 1000000ULL);
    
    load_settings();
    init_self_info();
    
    // Start as leader (will update after discovery)
    s_current_role = PEER_ROLE_LEADER;
    s_self.role = PEER_ROLE_LEADER;
    update_hostname();
    
    s_initialized = true;
    ESP_LOGI(TAG, "Peer discovery initialized. MAC: %02x:%02x:%02x:%02x:%02x:%02x",
             s_self.mac[0], s_self.mac[1], s_self.mac[2],
             s_self.mac[3], s_self.mac[4], s_self.mac[5]);
    
    return ESP_OK;
}

esp_err_t peer_discovery_start(void) {
    if (!s_initialized) {
        return ESP_ERR_INVALID_STATE;
    }
    
    if (s_running) {
        return ESP_OK;
    }
    
    // Create UDP socket
    esp_err_t err = create_socket();
    if (err != ESP_OK) {
        return err;
    }
    
    // Register mDNS service
    register_mdns_service();
    
    // Add self to peer list
    xSemaphoreTake(s_peer_mutex, portMAX_DELAY);
    memcpy(&s_peers[0], &s_self, sizeof(peer_info_t));
    s_peer_count = 1;
    xSemaphoreGive(s_peer_mutex);
    
    s_running = true;
    
    // Start discovery task
    xTaskCreate(discovery_task, "peer_discovery", 4096, NULL, 5, &s_discovery_task);
    
    ESP_LOGI(TAG, "Peer discovery started");
    return ESP_OK;
}

esp_err_t peer_discovery_stop(void) {
    if (!s_running) {
        return ESP_OK;
    }
    
    s_running = false;
    
    // Wait for task to exit
    vTaskDelay(pdMS_TO_TICKS(200));
    
    if (s_udp_socket >= 0) {
        close(s_udp_socket);
        s_udp_socket = -1;
    }
    
    ESP_LOGI(TAG, "Peer discovery stopped");
    return ESP_OK;
}

peer_role_t peer_discovery_get_role(void) {
    return s_current_role;
}

esp_err_t peer_discovery_get_self(peer_info_t *info) {
    if (!info) return ESP_ERR_INVALID_ARG;
    memcpy(info, &s_self, sizeof(peer_info_t));
    return ESP_OK;
}

esp_err_t peer_discovery_get_peers(peer_info_t *peers, size_t max_peers, size_t *count) {
    if (!peers || !count) return ESP_ERR_INVALID_ARG;
    
    xSemaphoreTake(s_peer_mutex, portMAX_DELAY);
    
    size_t copy_count = (s_peer_count < max_peers) ? s_peer_count : max_peers;
    memcpy(peers, s_peers, copy_count * sizeof(peer_info_t));
    *count = copy_count;
    
    xSemaphoreGive(s_peer_mutex);
    
    return ESP_OK;
}

esp_err_t peer_discovery_get_leader(peer_info_t *leader) {
    if (!leader) return ESP_ERR_INVALID_ARG;
    
    xSemaphoreTake(s_peer_mutex, portMAX_DELAY);
    
    for (size_t i = 0; i < s_peer_count; i++) {
        if (s_peers[i].role == PEER_ROLE_LEADER) {
            memcpy(leader, &s_peers[i], sizeof(peer_info_t));
            xSemaphoreGive(s_peer_mutex);
            return ESP_OK;
        }
    }
    
    xSemaphoreGive(s_peer_mutex);
    return ESP_ERR_NOT_FOUND;
}

void peer_discovery_register_callback(peer_event_callback_t callback) {
    s_event_callback = callback;
}

void peer_discovery_set_ap_mode(peer_ap_mode_t mode) {
    s_ap_mode = mode;
    save_settings();
    ESP_LOGI(TAG, "AP mode set to: %d", mode);
}

peer_ap_mode_t peer_discovery_get_ap_mode(void) {
    return s_ap_mode;
}

void peer_discovery_trigger_election(void) {
    ESP_LOGI(TAG, "Manual election triggered");
    run_election();
}

const char* peer_discovery_get_hostname(void) {
    return s_hostname;
}

const char* peer_discovery_get_ap_ssid(void) {
    return s_ap_ssid;
}

bool peer_discovery_found_other_aps(void) {
    return s_found_other_aps;
}

// Update AP SSID based on role
static void update_ap_ssid(void) {
    if (s_current_role == PEER_ROLE_LEADER && !s_found_other_aps) {
        strncpy(s_ap_ssid, "Legacy-HNL", PEER_HOSTNAME_MAX_LEN - 1);
    } else {
        // Use last 4 hex digits of MAC for uniqueness (uppercase for SSID)
        snprintf(s_ap_ssid, PEER_HOSTNAME_MAX_LEN, "Legacy-HNL-%02X%02X",
                 s_self.mac[4], s_self.mac[5]);
    }
    s_ap_ssid[PEER_HOSTNAME_MAX_LEN - 1] = '\0';
    ESP_LOGI(TAG, "AP SSID updated to: %s", s_ap_ssid);
}

void peer_discovery_process_scan_results(const void *aps, uint16_t count) {
    const wifi_ap_record_t *ap_records = (const wifi_ap_record_t *)aps;
    bool found_other = false;
    
    for (int i = 0; i < count; i++) {
        const char *ssid = (const char *)ap_records[i].ssid;
        
        // Check if SSID starts with "Legacy-HNL"
        if (strncmp(ssid, LEGACYHNL_SSID_PREFIX, strlen(LEGACYHNL_SSID_PREFIX)) == 0) {
            // Check if it's not our own AP (compare BSSID with our MAC)
            uint8_t our_ap_mac[6];
            esp_wifi_get_mac(WIFI_IF_AP, our_ap_mac);
            
            if (memcmp(ap_records[i].bssid, our_ap_mac, 6) != 0) {
                // Determine if this is a leader or follower AP
                bool is_leader_ap = (strcmp(ssid, "Legacy-HNL") == 0);
                
                ESP_LOGD(TAG, "Found Legacy-HNL AP (%s): %s (BSSID: %02x:%02x:%02x:%02x:%02x:%02x)",
                         is_leader_ap ? "Leader" : "Follower",
                         ssid,
                         ap_records[i].bssid[0], ap_records[i].bssid[1],
                         ap_records[i].bssid[2], ap_records[i].bssid[3],
                         ap_records[i].bssid[4], ap_records[i].bssid[5]);
                         
                found_other = true;
                break;
            }
        }
    }

    if (found_other) {
        uint32_t now = (uint32_t)(esp_timer_get_time() / 1000);
        s_last_legacyhnl_ap_seen = now;
        
        if (!s_found_other_aps) {
            ESP_LOGI(TAG, "External scan found Legacy-HNL AP - switching to follower SSID");
            s_found_other_aps = true;
            s_current_role = PEER_ROLE_FOLLOWER;
            s_self.role = PEER_ROLE_FOLLOWER;
            update_hostname();
            update_ap_ssid();
            notify_event(PEER_EVENT_ROLE_CHANGED, &s_self);
        }
    }
}

void peer_discovery_scan_for_aps(void) {
    // Manual scan deprecated in favor of system background scans
    // This function now just triggers a background scan if possible
    #include "background_scan.h"
    ESP_LOGI(TAG, "Triggering background scan for peer discovery");
    background_scan_trigger();
}
