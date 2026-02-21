#ifndef HANDSHAKE_H
#define HANDSHAKE_H

#include "esp_err.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

esp_err_t start_handshake_capture(uint8_t bssid[6], int channel, int duration_seconds, uint8_t (*stas)[6], int sta_count, int *eapol_count_out);
esp_err_t start_handshake_capture_preserve(uint8_t bssid[6], int channel, int duration_seconds, uint8_t (*stas)[6], int sta_count, int *eapol_count_out, bool preserve_eapol);

const uint8_t* handshake_pcap_data(size_t *out_size);
void handshake_clear_pcap(void);
bool handshake_has_eapol_frames(void);

esp_err_t start_general_capture(int channel, int duration_seconds);

const char* handshake_pcap_filename(void);

const char* handshake_get_history_json(void);
void handshake_record_auto_capture(uint8_t bssid[6], int channel, int eapol_count);

#endif

