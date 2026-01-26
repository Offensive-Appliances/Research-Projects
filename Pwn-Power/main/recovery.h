// Recovery logic for power-cycle based factory reset
#pragma once

#include <stdint.h>
#include "esp_err.h"

esp_err_t recovery_init(void);
void recovery_handle_power_cycle_reset(void);
void recovery_schedule_clear_timer(void);
