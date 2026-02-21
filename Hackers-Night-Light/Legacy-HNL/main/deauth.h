#pragma once
#include <stdint.h>
#include <stdbool.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

// Attack control functions
void wifi_manager_start_deauth(uint8_t bssid[6], int channel, uint8_t *target_sta);
void wifi_manager_stop_deauth(uint8_t bssid[6]);

// Mutex for thread safety
extern SemaphoreHandle_t attack_mutex;

// Task handle for checking attack status
extern TaskHandle_t deauth_task_handle;

extern volatile bool deauth_active;

typedef struct {
    uint8_t bssid[6];
    uint8_t target_sta[6];  // ADD TARGET STA FIELD
    int channel;
    bool active;
    bool is_broadcast;      // FLAG FOR BROADCAST TYPE
} active_attack_t; 