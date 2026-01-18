#include "handshake.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include <string.h>
#include "deauth.h"

static const char *TAG = "Handshake";

static volatile int s_eapol_count = 0;
static wifi_promiscuous_filter_t s_prev_filter;
static bool s_prev_filter_valid = false;
static wifi_promiscuous_cb_t s_prev_cb = NULL;

#define HS_PCAP_MAX_BYTES (64*1024)
static uint8_t s_pcap_buf[HS_PCAP_MAX_BYTES];
static size_t s_pcap_len = 0;
static char s_pcap_name[32] = "handshake.pcap";

static uint32_t s_wifi_callback_count = 0;
static uint32_t s_mgmt_written = 0;
typedef struct { uint8_t ap[6]; uint8_t sta[6]; uint16_t replay; bool have_ap_frame; bool have_sta_frame; } hs_entry_t;
#define HS_MAX_ENTRIES 16
static hs_entry_t s_hs_table[HS_MAX_ENTRIES];
static uint8_t s_hs_count = 0;
static uint8_t s_hs_insert_idx = 0;
static uint32_t s_handshake_pairs = 0;
static bool s_capture_all = false;

typedef struct {
    uint8_t bssid[6];
    int channel;
    uint32_t timestamp;
    int eapol_count;
    bool is_auto;
    bool valid;
} capture_record_t;
static capture_record_t s_current_capture = {0};
static bool hs_addr_eq(const uint8_t *a, const uint8_t *b){ return memcmp(a,b,6)==0; }
static void hs_process_candidate(const uint8_t *ap,const uint8_t *sta,uint16_t replay,bool from_ap){
    for(uint8_t i=0;i<s_hs_count;i++){
        hs_entry_t *e=&s_hs_table[i];
        if(hs_addr_eq(e->ap,ap)&&hs_addr_eq(e->sta,sta)&&e->replay==replay){
            if(from_ap) e->have_ap_frame=true; else e->have_sta_frame=true;
            if(e->have_ap_frame && e->have_sta_frame){
                s_handshake_pairs++;
                e->have_ap_frame=false;
                e->have_sta_frame=false;
            }
            return;
        }
    }
    uint8_t idx;
    if(s_hs_count<HS_MAX_ENTRIES){ idx=s_hs_count++; }
    else { idx=s_hs_insert_idx; s_hs_insert_idx=(s_hs_insert_idx+1)%HS_MAX_ENTRIES; }
    hs_entry_t *ne=&s_hs_table[idx];
    memcpy(ne->ap,ap,6);
    memcpy(ne->sta,sta,6);
    ne->replay=replay;
    ne->have_ap_frame=from_ap;
    ne->have_sta_frame=!from_ap;
}

typedef struct { uint8_t bssid[6]; bool ssid_nonempty; } beacon_entry_t;
#define HS_MAX_BEACONS 32
static beacon_entry_t s_beacon_table[HS_MAX_BEACONS];
static uint8_t s_beacon_count = 0;
static uint8_t s_beacon_insert_idx = 0;
static bool hs_beacon_should_write(const uint8_t *bssid, bool ssid_has_text){
    for(uint8_t i=0;i<s_beacon_count;i++){
        if(memcmp(s_beacon_table[i].bssid,bssid,6)==0){
            if(!s_beacon_table[i].ssid_nonempty && ssid_has_text){
                s_beacon_table[i].ssid_nonempty=ssid_has_text;
                return true;
            }
            return false;
        }
    }
    uint8_t idx;
    if(s_beacon_count<HS_MAX_BEACONS){ idx=s_beacon_count++; }
    else { idx=s_beacon_insert_idx; s_beacon_insert_idx=(s_beacon_insert_idx+1)%HS_MAX_BEACONS; }
    memcpy(s_beacon_table[idx].bssid,bssid,6);
    s_beacon_table[idx].ssid_nonempty=ssid_has_text;
    return true;
}

static void pcap_write_global_header(void) {
    if (s_pcap_len != 0) return;
    const uint8_t gh[] = { 0xd4,0xc3,0xb2,0xa1, 0x02,0x00,0x04,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0xff,0xff,0x00,0x00, 0x69,0x00,0x00,0x00 };
    memcpy(s_pcap_buf, gh, sizeof(gh));
    s_pcap_len = sizeof(gh);
    ESP_LOGD(TAG, "pcap header written");
}

static void pcap_write_packet(const uint8_t *data, uint32_t caplen) {
    if (!data || caplen == 0) return;
    if (s_pcap_len == 0) pcap_write_global_header();
    struct __attribute__((packed)) hdr { uint32_t ts_sec, ts_usec, incl_len, orig_len; } h;
    uint64_t us = esp_timer_get_time();
    h.ts_sec = (uint32_t)(us / 1000000ULL);
    h.ts_usec = (uint32_t)(us % 1000000ULL);
    h.incl_len = caplen;
    h.orig_len = caplen;
    size_t need = sizeof(h) + caplen;
    if (s_pcap_len + need > HS_PCAP_MAX_BYTES) return;
    memcpy(s_pcap_buf + s_pcap_len, &h, sizeof(h));
    s_pcap_len += sizeof(h);
    memcpy(s_pcap_buf + s_pcap_len, data, caplen);
    s_pcap_len += caplen;
    if ((s_pcap_len & 0xFFF) == 0) {
        ESP_LOGD(TAG, "pcap bytes=%u", (unsigned)s_pcap_len);
    }
}

const uint8_t* handshake_pcap_data(size_t *out_size) {
    if (out_size) *out_size = s_pcap_len;
    return s_pcap_buf;
}

void handshake_clear_pcap(void) {
    s_pcap_len = 0;
}

bool handshake_has_eapol_frames(void) {
    return s_eapol_count > 0;
}

const char* handshake_pcap_filename(void) {
    return s_pcap_name;
}

static void sniff_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    const wifi_promiscuous_pkt_t *ppkt = (const wifi_promiscuous_pkt_t *)buf;
    if (!ppkt) return;
    s_wifi_callback_count++;
    const uint8_t *d = ppkt->payload;
    int len = ppkt->rx_ctrl.sig_len;
    if (len < 24) return;
    uint8_t fc0 = d[0];
    uint8_t frame_type = (uint8_t)((fc0 >> 2) & 0x03);
    uint8_t subtype = (uint8_t)((fc0 >> 4) & 0x0F);

    if (frame_type == 0) {
        if (subtype == 8 || subtype == 5) {
            if (len >= 38) {
                uint8_t ssid_len = d[37];
                if (36 + 2 + ssid_len <= len) {
                    const uint8_t *bssid_ptr = d + 16;
                    bool ssid_nonempty = ssid_len > 0;
                    if (hs_beacon_should_write(bssid_ptr, ssid_nonempty)) {
                        pcap_write_packet(d, (uint32_t)len);
                        s_mgmt_written++;
                        if ((s_mgmt_written % 50) == 0) {
                            ESP_LOGD(TAG, "mgmt written=%lu", (unsigned long)s_mgmt_written);
                        }
                    }
                }
            }
        } else {
            pcap_write_packet(d, (uint32_t)len);
            s_mgmt_written++;
            if ((s_mgmt_written % 50) == 0) {
                ESP_LOGD(TAG, "mgmt written=%lu", (unsigned long)s_mgmt_written);
            }
        }
        return;
    }

    if (frame_type != 2) return;
    int hdr_len = 24;
    if ((subtype & 0x08) != 0) hdr_len += 2;
    if (s_capture_all) {
        pcap_write_packet(d, (uint32_t)len);
        return;
    }
    if (len < hdr_len + 8) return;
    if (d[hdr_len + 0] == 0xAA && d[hdr_len + 1] == 0xAA && d[hdr_len + 2] == 0x03) {
        uint16_t ethertype = (uint16_t)(d[hdr_len + 6] << 8 | d[hdr_len + 7]);
        if (ethertype == 0x888E) {
            const uint8_t *eapol = d + hdr_len + 8;
            if (len < hdr_len + 8 + 4) return;
            uint8_t eapol_type = eapol[1];
            if (eapol_type == 3) {
                pcap_write_packet(d, (uint32_t)len);
                s_eapol_count++;
                if (len >= hdr_len + 8 + 4 + 95) {
                    const uint8_t *key_data = eapol + 4;
                    uint8_t key_descriptor_type = key_data[0];
                    uint16_t key_info = (uint16_t)(key_data[1] << 8 | key_data[2]);
                    if (key_descriptor_type == 2) {
                        bool has_mic = (key_info & 0x0100) != 0;
                        bool is_pairwise = (key_info & 0x0008) != 0;
                        bool is_install = (key_info & 0x0040) != 0;
                        bool is_ack = (key_info & 0x0080) != 0;
                        bool crackable = is_pairwise && has_mic && ((is_ack && is_install) || (!is_ack && !is_install));
                        const uint8_t *addr1 = d + 4;
                        const uint8_t *addr2 = d + 10;
                        bool from_ap = is_ack;
                        const uint8_t *ap_mac = from_ap ? addr2 : addr1;
                        const uint8_t *sta_mac = from_ap ? addr1 : addr2;
                        uint16_t replaycnt = (uint16_t)(eapol[13] << 8 | eapol[12]);
                        if (crackable) {
                            hs_process_candidate(ap_mac, sta_mac, replaycnt, from_ap);
                            ESP_LOGI(TAG, "EAPOL key crackable ap=%02X:%02X:%02X:%02X:%02X:%02X sta=%02X:%02X:%02X:%02X:%02X:%02X replay=%u from_ap=%d",
                                     ap_mac[0],ap_mac[1],ap_mac[2],ap_mac[3],ap_mac[4],ap_mac[5],
                                     sta_mac[0],sta_mac[1],sta_mac[2],sta_mac[3],sta_mac[4],sta_mac[5],
                                     (unsigned)replaycnt, (int)from_ap);
                        }
                    }
                }
            }
        }
    }
}

esp_err_t start_handshake_capture(uint8_t bssid[6], int channel, int duration_seconds, uint8_t (*stas)[6], int sta_count, int *eapol_count_out) {
    strncpy(s_pcap_name, "handshake.pcap", sizeof(s_pcap_name)-1);
    s_pcap_name[sizeof(s_pcap_name)-1] = '\0';
    if (!bssid || channel < 1 || channel > 165 || duration_seconds <= 0) return ESP_ERR_INVALID_ARG;
    if (eapol_count_out) *eapol_count_out = 0;

    ESP_LOGI(TAG, "start: channel=%d duration=%ds sta_count=%d", channel, duration_seconds, sta_count);

    wifi_mode_t original_mode;
    esp_wifi_get_mode(&original_mode);
    ESP_LOGI(TAG, "original mode=%d", (int)original_mode);
    if (original_mode == WIFI_MODE_APSTA) {
        ESP_LOGI(TAG, "switching to STA for capture");
        esp_wifi_set_mode(WIFI_MODE_STA);
        vTaskDelay(pdMS_TO_TICKS(100));
    }

    s_eapol_count = 0;
    handshake_clear_pcap();
    s_mgmt_written = 0;
    wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA
    };
    s_hs_count = 0;
    s_hs_insert_idx = 0;
    s_handshake_pairs = 0;
    s_beacon_count = 0;
    s_beacon_insert_idx = 0;
    wifi_promiscuous_filter_t cur_filter;
    if (esp_wifi_get_promiscuous_filter(&cur_filter) == ESP_OK) {
        s_prev_filter = cur_filter;
        s_prev_filter_valid = true;
    }
    s_prev_cb = NULL; // not retrievable; track only our set

    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(sniff_cb);
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    ESP_LOGI(TAG, "promisc enabled on ch %d", channel);

    // passive capture only; do not trigger deauth during handshake capture

    int ms = duration_seconds * 1000;
    const int step = 50;
    for (int t = 0; t < ms; t += step) {
        vTaskDelay(pdMS_TO_TICKS(step));
    }

    // end passive capture window

    esp_wifi_set_promiscuous(false);
    if (s_prev_filter_valid) {
        esp_wifi_set_promiscuous_filter(&s_prev_filter);
    }
    esp_wifi_set_promiscuous_rx_cb(NULL);
    ESP_LOGI(TAG, "promisc disabled");

    esp_wifi_set_mode(original_mode);
    vTaskDelay(pdMS_TO_TICKS(100));

    if (eapol_count_out) *eapol_count_out = s_eapol_count;
    ESP_LOGI(TAG, "Captured %d EAPOL frames, mgmt written %lu, pcap bytes %u", s_eapol_count, (unsigned long)s_mgmt_written, (unsigned int)s_pcap_len);
    
    if (s_eapol_count > 0 || s_pcap_len > 100) {
        memcpy(s_current_capture.bssid, bssid, 6);
        s_current_capture.channel = channel;
        s_current_capture.timestamp = (uint32_t)(esp_timer_get_time() / 1000000ULL);
        s_current_capture.eapol_count = s_eapol_count;
        s_current_capture.is_auto = false;
        s_current_capture.valid = true;
    }
    
    return ESP_OK;
}

esp_err_t start_handshake_capture_preserve(uint8_t bssid[6], int channel, int duration_seconds, uint8_t (*stas)[6], int sta_count, int *eapol_count_out, bool preserve_eapol) {
    strncpy(s_pcap_name, "handshake.pcap", sizeof(s_pcap_name)-1);
    s_pcap_name[sizeof(s_pcap_name)-1] = '\0';
    if (!bssid || channel < 1 || channel > 165 || duration_seconds <= 0) return ESP_ERR_INVALID_ARG;
    if (eapol_count_out) *eapol_count_out = 0;

    ESP_LOGI(TAG, "start_preserve: channel=%d duration=%ds sta_count=%d preserve_eapol=%s", 
             channel, duration_seconds, sta_count, preserve_eapol ? "true" : "false");

    wifi_mode_t original_mode;
    esp_wifi_get_mode(&original_mode);
    ESP_LOGI(TAG, "original mode=%d", (int)original_mode);
    if (original_mode == WIFI_MODE_APSTA) {
        ESP_LOGI(TAG, "switching to STA for capture");
        esp_wifi_set_mode(WIFI_MODE_STA);
        vTaskDelay(pdMS_TO_TICKS(100));
    }

    // Check if we should preserve existing EAPOL frames
    bool had_eapol = preserve_eapol && handshake_has_eapol_frames();
    uint32_t prev_eapol_count = s_eapol_count;
    
    if (!preserve_eapol || !had_eapol) {
        s_eapol_count = 0;
        handshake_clear_pcap();
    } else {
        ESP_LOGI(TAG, "Preserving existing %d EAPOL frames and %u PCAP bytes", 
                 (int)s_eapol_count, (unsigned int)s_pcap_len);
    }
    
    s_mgmt_written = 0;
    wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA
    };
    
    if (!preserve_eapol || !had_eapol) {
        s_hs_count = 0;
        s_hs_insert_idx = 0;
        s_handshake_pairs = 0;
        s_beacon_count = 0;
        s_beacon_insert_idx = 0;
    }
    
    wifi_promiscuous_filter_t cur_filter;
    if (esp_wifi_get_promiscuous_filter(&cur_filter) == ESP_OK) {
        s_prev_filter = cur_filter;
        s_prev_filter_valid = true;
    }
    s_prev_cb = NULL; // not retrievable; track only our set

    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(sniff_cb);
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    ESP_LOGI(TAG, "promisc enabled on ch %d", channel);

    // passive capture only; do not trigger deauth during handshake capture

    int ms = duration_seconds * 1000;
    const int step = 50;
    for (int t = 0; t < ms; t += step) {
        vTaskDelay(pdMS_TO_TICKS(step));
    }

    // end passive capture window

    esp_wifi_set_promiscuous(false);
    if (s_prev_filter_valid) {
        esp_wifi_set_promiscuous_filter(&s_prev_filter);
    }
    esp_wifi_set_promiscuous_rx_cb(NULL);
    ESP_LOGI(TAG, "promisc disabled");

    esp_wifi_set_mode(original_mode);
    vTaskDelay(pdMS_TO_TICKS(100));

    if (eapol_count_out) *eapol_count_out = s_eapol_count;
    
    uint32_t new_eapol_count = s_eapol_count - prev_eapol_count;
    ESP_LOGI(TAG, "Capture complete: %d total EAPOL frames (%d new), mgmt written %lu, pcap bytes %u", 
             s_eapol_count, (int)new_eapol_count, (unsigned long)s_mgmt_written, (unsigned int)s_pcap_len);
    
    if (s_eapol_count > 0 || s_pcap_len > 100) {
        memcpy(s_current_capture.bssid, bssid, 6);
        s_current_capture.channel = channel;
        s_current_capture.timestamp = (uint32_t)(esp_timer_get_time() / 1000000ULL);
        s_current_capture.eapol_count = s_eapol_count;
        s_current_capture.is_auto = false;
        s_current_capture.valid = true;
    }
    
    return ESP_OK;
}

esp_err_t start_general_capture(int channel, int duration_seconds) {
    strncpy(s_pcap_name, "capture.pcap", sizeof(s_pcap_name)-1);
    s_pcap_name[sizeof(s_pcap_name)-1] = '\0';
    if (channel < 1 || channel > 165 || duration_seconds <= 0) return ESP_ERR_INVALID_ARG;
    wifi_mode_t original_mode;
    esp_wifi_get_mode(&original_mode);
    if (original_mode == WIFI_MODE_APSTA) {
        esp_wifi_set_mode(WIFI_MODE_STA);
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    handshake_clear_pcap();
    s_capture_all = true;
    wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA | WIFI_PROMIS_FILTER_MASK_CTRL
    };
    wifi_promiscuous_filter_t cur_filter;
    if (esp_wifi_get_promiscuous_filter(&cur_filter) == ESP_OK) {
        s_prev_filter = cur_filter;
        s_prev_filter_valid = true;
    }
    s_prev_cb = NULL;
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(sniff_cb);
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    int ms = duration_seconds * 1000;
    const int step = 50;
    for (int t = 0; t < ms; t += step) {
        vTaskDelay(pdMS_TO_TICKS(step));
    }
    esp_wifi_set_promiscuous(false);
    if (s_prev_filter_valid) {
        esp_wifi_set_promiscuous_filter(&s_prev_filter);
    }
    esp_wifi_set_promiscuous_rx_cb(NULL);
    s_capture_all = false;
    esp_wifi_set_mode(original_mode);
    vTaskDelay(pdMS_TO_TICKS(100));
    return ESP_OK;
}

const char* handshake_get_history_json(void) {
    static char json_buf[256];
    
    if (!s_current_capture.valid) {
        snprintf(json_buf, sizeof(json_buf), "[]");
        return json_buf;
    }
    
    capture_record_t *r = &s_current_capture;
    snprintf(json_buf, sizeof(json_buf),
        "[{\"bssid\":\"%02X:%02X:%02X:%02X:%02X:%02X\",\"channel\":%d,\"timestamp\":%lu,\"eapol\":%d,\"auto\":%s}]",
        r->bssid[0], r->bssid[1], r->bssid[2], r->bssid[3], r->bssid[4], r->bssid[5],
        r->channel, (unsigned long)r->timestamp, r->eapol_count, r->is_auto ? "true" : "false");
    return json_buf;
}

void handshake_record_auto_capture(uint8_t bssid[6], int channel, int eapol_count) {
    if (eapol_count <= 0) return;
    
    memcpy(s_current_capture.bssid, bssid, 6);
    s_current_capture.channel = channel;
    s_current_capture.timestamp = (uint32_t)(esp_timer_get_time() / 1000000ULL);
    s_current_capture.eapol_count = eapol_count;
    s_current_capture.is_auto = true;
    s_current_capture.valid = true;
}
