#ifndef HANDSHAKE_H
#define HANDSHAKE_H

#include "esp_err.h"
#include <stdint.h>
#include <stddef.h>

esp_err_t start_handshake_capture(uint8_t bssid[6], int channel, int duration_seconds, uint8_t (*stas)[6], int sta_count, int *eapol_count_out);

const uint8_t* handshake_pcap_data(size_t *out_size);
void handshake_clear_pcap(void);

esp_err_t start_general_capture(int channel, int duration_seconds);

const char* handshake_pcap_filename(void);

#endif

