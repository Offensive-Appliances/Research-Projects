#ifndef PEER_DISCOVERY_H
#define PEER_DISCOVERY_H

#include "esp_err.h"
#include <stdbool.h>
#include <stdint.h>

#define PEER_MAX_DEVICES 8
#define PEER_HOSTNAME_MAX_LEN 32
#define PEER_ID_LEN 6  // MAC address length

// Peer roles in the network
typedef enum {
    PEER_ROLE_UNKNOWN = 0,
    PEER_ROLE_LEADER,    // Owns pwnpower.local
    PEER_ROLE_FOLLOWER   // Uses pwnpower-XXXX.local
} peer_role_t;

// AP coordination modes
typedef enum {
    PEER_AP_MODE_AUTO = 0,       // Auto-disable AP when not leader
    PEER_AP_MODE_ALWAYS_ON,      // Always keep AP active (different SSID)
    PEER_AP_MODE_LEADER_ONLY     // Only leader runs AP
} peer_ap_mode_t;

// Information about a discovered peer
typedef struct {
    uint8_t mac[PEER_ID_LEN];           // MAC address (unique ID)
    uint32_t ip_addr;                    // IPv4 address
    char hostname[PEER_HOSTNAME_MAX_LEN]; // Current mDNS hostname
    peer_role_t role;                    // Leader or follower
    bool ap_active;                      // Is AP currently active
    uint32_t boot_time;                  // Uptime in seconds (for tiebreaker)
    uint32_t last_seen;                  // Timestamp of last discovery
    bool is_self;                        // True if this is the local device
} peer_info_t;

// Callback for peer events
typedef enum {
    PEER_EVENT_DISCOVERED,    // New peer found
    PEER_EVENT_LOST,          // Peer went offline
    PEER_EVENT_ROLE_CHANGED,  // Our role changed (leader<->follower)
    PEER_EVENT_LEADER_CHANGED // Different device became leader
} peer_event_type_t;

typedef void (*peer_event_callback_t)(peer_event_type_t event, const peer_info_t *peer);

/**
 * @brief Initialize the peer discovery system
 * @return ESP_OK on success
 */
esp_err_t peer_discovery_init(void);

/**
 * @brief Start peer discovery (begin announcements and queries)
 * @return ESP_OK on success
 */
esp_err_t peer_discovery_start(void);

/**
 * @brief Stop peer discovery
 * @return ESP_OK on success
 */
esp_err_t peer_discovery_stop(void);

/**
 * @brief Get the current role of this device
 * @return Current peer role
 */
peer_role_t peer_discovery_get_role(void);

/**
 * @brief Get information about this device
 * @param info Output parameter for device info
 * @return ESP_OK on success
 */
esp_err_t peer_discovery_get_self(peer_info_t *info);

/**
 * @brief Get list of all discovered peers (including self)
 * @param peers Array to fill with peer info
 * @param max_peers Size of the peers array
 * @param count Output parameter for actual count
 * @return ESP_OK on success
 */
esp_err_t peer_discovery_get_peers(peer_info_t *peers, size_t max_peers, size_t *count);

/**
 * @brief Get the current leader device
 * @param leader Output parameter for leader info
 * @return ESP_OK if leader exists, ESP_ERR_NOT_FOUND if no leader
 */
esp_err_t peer_discovery_get_leader(peer_info_t *leader);

/**
 * @brief Register callback for peer events
 * @param callback Function to call on events
 */
void peer_discovery_register_callback(peer_event_callback_t callback);

/**
 * @brief Set AP coordination mode
 * @param mode The AP coordination mode to use
 */
void peer_discovery_set_ap_mode(peer_ap_mode_t mode);

/**
 * @brief Get current AP coordination mode
 * @return Current AP mode
 */
peer_ap_mode_t peer_discovery_get_ap_mode(void);

/**
 * @brief Force a leader re-election
 */
void peer_discovery_trigger_election(void);

/**
 * @brief Get this device's unique hostname (pwnpower or pwnpower-XXXX)
 * @return Pointer to hostname string
 */
const char* peer_discovery_get_hostname(void);

/**
 * @brief Get this device's AP SSID (PwnPower or PwnPower-XXXX)
 * @return Pointer to AP SSID string
 */
const char* peer_discovery_get_ap_ssid(void);

/**
 * @brief Scan for other PwnPower APs and update role if needed
 * Called periodically when not connected to a home network
 */
/**
 * @brief Scan for other PwnPower APs and update role if needed
 * Called periodically when not connected to a home network
 */
void peer_discovery_scan_for_aps(void);

/**
 * @brief Process scan results from external modules (wifi_scan, background_scan)
 * Used to detect other PwnPower APs without initiating a dedicated scan
 * @param aps Array of found AP records
 * @param count Number of AP records
 */
void peer_discovery_process_scan_results(const void *aps, uint16_t count);

/**
 * @brief Check if we detected other PwnPower APs via WiFi scanning
 * @return true if other PwnPower APs were found
 */
bool peer_discovery_found_other_aps(void);

#endif // PEER_DISCOVERY_H
