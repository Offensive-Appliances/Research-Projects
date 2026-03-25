#include "handshake.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "sdkconfig.h"
#include "esp_http_server.h"
#include <stdio.h>
#include <string.h>
#include "deauth.h"
#include "device_lifecycle.h"

static const char *TAG = "Handshake";

static void restore_wifi_mode_with_retry(wifi_mode_t target_mode, const char *context) {
    esp_err_t err = ESP_FAIL;
    for (int i = 0; i < 3; i++) {
        err = esp_wifi_set_mode(target_mode);
        if (err == ESP_OK) {
            return;
        }
        ESP_LOGW(TAG, "%s: esp_wifi_set_mode(%d) failed (%s), retry %d/3",
                 context,
                 (int)target_mode,
                 esp_err_to_name(err),
                 i + 1);
        vTaskDelay(pdMS_TO_TICKS(100));
    }

    ESP_LOGW(TAG, "%s: mode restore failed, attempting wifi restart fallback", context);
    esp_wifi_stop();
    vTaskDelay(pdMS_TO_TICKS(100));
    err = esp_wifi_set_mode(target_mode);
    if (err == ESP_OK) {
        err = esp_wifi_start();
    }
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "%s: fallback restore failed: %s", context, esp_err_to_name(err));
    }
}

static volatile int s_eapol_count = 0;
static wifi_promiscuous_filter_t s_prev_filter;
static bool s_prev_filter_valid = false;
static wifi_promiscuous_cb_t s_prev_cb = NULL;

#if CONFIG_IDF_TARGET_ESP32C5 && CONFIG_PWNPOWER_HISTORY_STORAGE_SDMMC
#define HS_PCAP_FILE_BACKED 1
#else
#define HS_PCAP_FILE_BACKED 0
#endif

#if CONFIG_IDF_TARGET_ESP32C5
#define HS_PCAP_MAX_BYTES (16*1024)
#elif CONFIG_IDF_TARGET_ESP32C3
#define HS_PCAP_MAX_BYTES (16*1024)
#else
#define HS_PCAP_MAX_BYTES (32*1024)
#endif

#if HS_PCAP_FILE_BACKED
#define HS_PCAP_QUEUE_DEPTH 4
#define HS_PCAP_PACKET_MAX_BYTES 2048

typedef struct {
    size_t len;
    uint8_t data[HS_PCAP_PACKET_MAX_BYTES];
} hs_pcap_slot_t;

static hs_pcap_slot_t s_pcap_queue[HS_PCAP_QUEUE_DEPTH];
static uint8_t s_pcap_queue_head = 0;
static uint8_t s_pcap_queue_tail = 0;
static uint8_t s_pcap_queue_count = 0;
static uint32_t s_pcap_queue_drops = 0;
static portMUX_TYPE s_pcap_queue_lock = portMUX_INITIALIZER_UNLOCKED;
static FILE *s_pcap_file = NULL;
static char s_pcap_path[96] = {0};
static uint8_t s_pcap_drain_buf[HS_PCAP_PACKET_MAX_BYTES];
#else
static uint8_t s_pcap_buf[HS_PCAP_MAX_BYTES];
#endif
static size_t s_pcap_len = 0;
static char s_pcap_name[32] = "handshake.pcap";
static char s_pcap_storage_name[16] = "HS.CAP";

static uint32_t s_wifi_callback_count = 0;
static uint32_t s_mgmt_written = 0;
typedef struct { uint8_t ap[6]; uint8_t sta[6]; uint16_t replay; bool have_ap_frame; bool have_sta_frame; } hs_entry_t;
#define HS_MAX_ENTRIES 16
static hs_entry_t s_hs_table[HS_MAX_ENTRIES];
static uint8_t s_hs_count = 0;
static uint8_t s_hs_insert_idx = 0;
static uint32_t s_handshake_pairs = 0;
static bool s_capture_all = false;

static void pcap_write_global_header(void);
static void pcap_write_packet(const uint8_t *data, uint32_t caplen);
static esp_err_t pcap_prepare_storage(bool truncate_file);
static esp_err_t pcap_flush_pending_packets(void);
static void pcap_close_storage(void);

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
#if HS_PCAP_FILE_BACKED
    if (!s_pcap_file) {
        return;
    }
    if (fwrite(gh, 1, sizeof(gh), s_pcap_file) != sizeof(gh)) {
        ESP_LOGW(TAG, "failed to write pcap header to %s", s_pcap_path);
        return;
    }
    fflush(s_pcap_file);
#else
    memcpy(s_pcap_buf, gh, sizeof(gh));
#endif
    s_pcap_len = sizeof(gh);
    ESP_LOGD(TAG, "pcap header written");
}

static void pcap_write_packet(const uint8_t *data, uint32_t caplen) {
    if (!data || caplen == 0) return;
    if (s_pcap_len == 0) pcap_write_global_header();
#if HS_PCAP_FILE_BACKED
    if (!s_pcap_file) return;
    if (caplen > HS_PCAP_PACKET_MAX_BYTES) {
        s_pcap_queue_drops++;
        return;
    }

    portENTER_CRITICAL(&s_pcap_queue_lock);
    if (s_pcap_queue_count >= HS_PCAP_QUEUE_DEPTH) {
        s_pcap_queue_drops++;
        portEXIT_CRITICAL(&s_pcap_queue_lock);
        return;
    }
    hs_pcap_slot_t *slot = &s_pcap_queue[s_pcap_queue_head];
    slot->len = caplen;
    memcpy(slot->data, data, caplen);
    s_pcap_queue_head = (uint8_t)((s_pcap_queue_head + 1) % HS_PCAP_QUEUE_DEPTH);
    s_pcap_queue_count++;
    portEXIT_CRITICAL(&s_pcap_queue_lock);
#else
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
#endif
}

const uint8_t* handshake_pcap_data(size_t *out_size) {
    if (out_size) *out_size = s_pcap_len;
#if HS_PCAP_FILE_BACKED
    return NULL;
#else
    return s_pcap_buf;
#endif
}

void handshake_clear_pcap(void) {
#if HS_PCAP_FILE_BACKED
    pcap_close_storage();
    if (s_pcap_path[0] != '\0') {
        remove(s_pcap_path);
    }
    portENTER_CRITICAL(&s_pcap_queue_lock);
    s_pcap_queue_head = 0;
    s_pcap_queue_tail = 0;
    s_pcap_queue_count = 0;
    s_pcap_queue_drops = 0;
    portEXIT_CRITICAL(&s_pcap_queue_lock);
#endif
    s_pcap_len = 0;
}

bool handshake_has_eapol_frames(void) {
    return s_eapol_count > 0;
}

const char* handshake_pcap_filename(void) {
    return s_pcap_name;
}

static esp_err_t pcap_prepare_storage(bool truncate_file) {
#if HS_PCAP_FILE_BACKED
    snprintf(s_pcap_path, sizeof(s_pcap_path), "%s/%s", CONFIG_PWNPOWER_SDMMC_MOUNT_POINT, s_pcap_storage_name);

    if (s_pcap_file) {
        fclose(s_pcap_file);
        s_pcap_file = NULL;
    }

    const char *mode = truncate_file ? "wb" : "ab";
    s_pcap_file = fopen(s_pcap_path, mode);
    if (!s_pcap_file) {
        ESP_LOGE(TAG, "failed to open pcap storage: %s", s_pcap_path);
        return ESP_FAIL;
    }

    if (truncate_file || s_pcap_len == 0) {
        s_pcap_len = 0;
        pcap_write_global_header();
    }
#else
    (void)truncate_file;
#endif
    return ESP_OK;
}

static esp_err_t pcap_flush_pending_packets(void) {
#if HS_PCAP_FILE_BACKED
    if (!s_pcap_file) {
        return ESP_OK;
    }

    while (true) {
        size_t packet_len = 0;
        portENTER_CRITICAL(&s_pcap_queue_lock);
        if (s_pcap_queue_count == 0) {
            portEXIT_CRITICAL(&s_pcap_queue_lock);
            break;
        }
        hs_pcap_slot_t *slot = &s_pcap_queue[s_pcap_queue_tail];
        packet_len = slot->len;
        memcpy(s_pcap_drain_buf, slot->data, packet_len);
        s_pcap_queue_tail = (uint8_t)((s_pcap_queue_tail + 1) % HS_PCAP_QUEUE_DEPTH);
        s_pcap_queue_count--;
        portEXIT_CRITICAL(&s_pcap_queue_lock);

        struct __attribute__((packed)) hdr { uint32_t ts_sec, ts_usec, incl_len, orig_len; } h;
        uint64_t us = esp_timer_get_time();
        h.ts_sec = (uint32_t)(us / 1000000ULL);
        h.ts_usec = (uint32_t)(us % 1000000ULL);
        h.incl_len = packet_len;
        h.orig_len = packet_len;

        if (fwrite(&h, 1, sizeof(h), s_pcap_file) != sizeof(h) ||
            fwrite(s_pcap_drain_buf, 1, packet_len, s_pcap_file) != packet_len) {
            ESP_LOGE(TAG, "failed writing packet to %s", s_pcap_path);
            return ESP_FAIL;
        }

        s_pcap_len += sizeof(h) + packet_len;
    }

    fflush(s_pcap_file);
#endif
    return ESP_OK;
}

static void pcap_close_storage(void) {
#if HS_PCAP_FILE_BACKED
    if (s_pcap_file) {
        fclose(s_pcap_file);
        s_pcap_file = NULL;
    }
#endif
}

esp_err_t handshake_pcap_http_send(httpd_req_t *req) {
    if (s_pcap_len == 0) {
        ESP_LOGW(TAG, "PCAP requested but empty");
        return httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "no pcap");
    }

    ESP_LOGI(TAG, "PCAP request size=%u", (unsigned)s_pcap_len);
    httpd_resp_set_type(req, "application/vnd.tcpdump.pcap");
    char disp[64];
    snprintf(disp, sizeof(disp), "attachment; filename=\"%s\"", handshake_pcap_filename());
    httpd_resp_set_hdr(req, "Content-Disposition", disp);

#if HS_PCAP_FILE_BACKED
    FILE *fp = fopen(s_pcap_path, "rb");
    if (!fp) {
        ESP_LOGE(TAG, "failed to open pcap for download: %s", s_pcap_path);
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "pcap unavailable");
    }

    char chunk[1024];
    size_t nread = 0;
    while ((nread = fread(chunk, 1, sizeof(chunk), fp)) > 0) {
        esp_err_t err = httpd_resp_send_chunk(req, chunk, nread);
        if (err != ESP_OK) {
            fclose(fp);
            return err;
        }
    }
    fclose(fp);
    return httpd_resp_send_chunk(req, NULL, 0);
#else
    return httpd_resp_send(req, (const char *)s_pcap_buf, s_pcap_len);
#endif
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
    strncpy(s_pcap_storage_name, "HS.CAP", sizeof(s_pcap_storage_name)-1);
    s_pcap_storage_name[sizeof(s_pcap_storage_name)-1] = '\0';
    if (!bssid || channel < 1 || channel > 165 || duration_seconds <= 0) return ESP_ERR_INVALID_ARG;
    if (eapol_count_out) *eapol_count_out = 0;

    ESP_LOGI(TAG, "start: channel=%d duration=%ds sta_count=%d", channel, duration_seconds, sta_count);

    wifi_mode_t original_mode;
    esp_wifi_get_mode(&original_mode);
    ESP_LOGI(TAG, "original mode=%d", (int)original_mode);
    if (original_mode == WIFI_MODE_APSTA) {
        ESP_LOGI(TAG, "switching to STA for capture");
        esp_err_t mode_err = esp_wifi_set_mode(WIFI_MODE_STA);
        if (mode_err == ESP_OK) {
            vTaskDelay(pdMS_TO_TICKS(100));
        } else {
            ESP_LOGW(TAG, "Failed to switch to STA for capture: %s", esp_err_to_name(mode_err));
        }
    }

    s_eapol_count = 0;
    handshake_clear_pcap();
    if (pcap_prepare_storage(true) != ESP_OK) {
        restore_wifi_mode_with_retry(original_mode, "start_handshake_capture_open");
        return ESP_FAIL;
    }
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
    const int step = HS_PCAP_FILE_BACKED ? 10 : 50;
    for (int t = 0; t < ms; t += step) {
        vTaskDelay(pdMS_TO_TICKS(step));
        if (pcap_flush_pending_packets() != ESP_OK) {
            break;
        }
    }

    // end passive capture window

    esp_wifi_set_promiscuous(false);
    if (s_prev_filter_valid) {
        esp_wifi_set_promiscuous_filter(&s_prev_filter);
    }
    esp_wifi_set_promiscuous_rx_cb(NULL);
    ESP_LOGI(TAG, "promisc disabled");

    pcap_flush_pending_packets();
    pcap_close_storage();
    if (s_pcap_queue_drops > 0) {
        ESP_LOGW(TAG, "pcap queue dropped %lu packets during capture", (unsigned long)s_pcap_queue_drops);
    }

    restore_wifi_mode_with_retry(original_mode, "start_handshake_capture");
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
        
        device_lifecycle_generate_handshake_event(bssid, NULL, s_eapol_count);
    }
    
    return ESP_OK;
}

esp_err_t start_handshake_capture_preserve(uint8_t bssid[6], int channel, int duration_seconds, uint8_t (*stas)[6], int sta_count, int *eapol_count_out, bool preserve_eapol) {
    strncpy(s_pcap_name, "handshake.pcap", sizeof(s_pcap_name)-1);
    s_pcap_name[sizeof(s_pcap_name)-1] = '\0';
    strncpy(s_pcap_storage_name, "HS.CAP", sizeof(s_pcap_storage_name)-1);
    s_pcap_storage_name[sizeof(s_pcap_storage_name)-1] = '\0';
    if (!bssid || channel < 1 || channel > 165 || duration_seconds <= 0) return ESP_ERR_INVALID_ARG;
    if (eapol_count_out) *eapol_count_out = 0;

    ESP_LOGI(TAG, "start_preserve: channel=%d duration=%ds sta_count=%d preserve_eapol=%s", 
             channel, duration_seconds, sta_count, preserve_eapol ? "true" : "false");

    wifi_mode_t original_mode;
    esp_wifi_get_mode(&original_mode);
    ESP_LOGI(TAG, "original mode=%d", (int)original_mode);
    if (original_mode == WIFI_MODE_APSTA) {
        ESP_LOGI(TAG, "switching to STA for capture");
        esp_err_t mode_err = esp_wifi_set_mode(WIFI_MODE_STA);
        if (mode_err == ESP_OK) {
            vTaskDelay(pdMS_TO_TICKS(100));
        } else {
            ESP_LOGW(TAG, "Failed to switch to STA for preserve capture: %s", esp_err_to_name(mode_err));
        }
    }

    // Check if we should preserve existing EAPOL frames
    bool had_eapol = preserve_eapol && handshake_has_eapol_frames();
    uint32_t prev_eapol_count = s_eapol_count;
    
    if (!preserve_eapol || !had_eapol) {
        s_eapol_count = 0;
        handshake_clear_pcap();
        if (pcap_prepare_storage(true) != ESP_OK) {
            restore_wifi_mode_with_retry(original_mode, "start_handshake_capture_preserve_open");
            return ESP_FAIL;
        }
    } else {
        ESP_LOGI(TAG, "Preserving existing %d EAPOL frames and %u PCAP bytes", 
                 (int)s_eapol_count, (unsigned int)s_pcap_len);
        if (pcap_prepare_storage(false) != ESP_OK) {
            restore_wifi_mode_with_retry(original_mode, "start_handshake_capture_preserve_append");
            return ESP_FAIL;
        }
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
    const int step = HS_PCAP_FILE_BACKED ? 10 : 50;
    for (int t = 0; t < ms; t += step) {
        vTaskDelay(pdMS_TO_TICKS(step));
        if (pcap_flush_pending_packets() != ESP_OK) {
            break;
        }
    }

    // end passive capture window

    esp_wifi_set_promiscuous(false);
    if (s_prev_filter_valid) {
        esp_wifi_set_promiscuous_filter(&s_prev_filter);
    }
    esp_wifi_set_promiscuous_rx_cb(NULL);
    ESP_LOGI(TAG, "promisc disabled");

    pcap_flush_pending_packets();
    pcap_close_storage();
    if (s_pcap_queue_drops > 0) {
        ESP_LOGW(TAG, "pcap queue dropped %lu packets during preserve capture", (unsigned long)s_pcap_queue_drops);
    }

    restore_wifi_mode_with_retry(original_mode, "start_handshake_capture_preserve");
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
        
        device_lifecycle_generate_handshake_event(bssid, NULL, new_eapol_count);
    }
    
    return ESP_OK;
}

esp_err_t start_general_capture(int channel, int duration_seconds) {
    strncpy(s_pcap_name, "capture.pcap", sizeof(s_pcap_name)-1);
    s_pcap_name[sizeof(s_pcap_name)-1] = '\0';
    strncpy(s_pcap_storage_name, "CAP.CAP", sizeof(s_pcap_storage_name)-1);
    s_pcap_storage_name[sizeof(s_pcap_storage_name)-1] = '\0';
    if (channel < 1 || channel > 165 || duration_seconds <= 0) return ESP_ERR_INVALID_ARG;
    wifi_mode_t original_mode;
    esp_wifi_get_mode(&original_mode);
    if (original_mode == WIFI_MODE_APSTA) {
        esp_err_t mode_err = esp_wifi_set_mode(WIFI_MODE_STA);
        if (mode_err == ESP_OK) {
            vTaskDelay(pdMS_TO_TICKS(100));
        } else {
            ESP_LOGW(TAG, "Failed to switch to STA for general capture: %s", esp_err_to_name(mode_err));
        }
    }
    handshake_clear_pcap();
    if (pcap_prepare_storage(true) != ESP_OK) {
        restore_wifi_mode_with_retry(original_mode, "start_general_capture_open");
        return ESP_FAIL;
    }
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
    const int step = HS_PCAP_FILE_BACKED ? 10 : 50;
    for (int t = 0; t < ms; t += step) {
        vTaskDelay(pdMS_TO_TICKS(step));
        if (pcap_flush_pending_packets() != ESP_OK) {
            break;
        }
    }
    esp_wifi_set_promiscuous(false);
    if (s_prev_filter_valid) {
        esp_wifi_set_promiscuous_filter(&s_prev_filter);
    }
    esp_wifi_set_promiscuous_rx_cb(NULL);
    pcap_flush_pending_packets();
    pcap_close_storage();
    if (s_pcap_queue_drops > 0) {
        ESP_LOGW(TAG, "pcap queue dropped %lu packets during general capture", (unsigned long)s_pcap_queue_drops);
    }
    s_capture_all = false;
    restore_wifi_mode_with_retry(original_mode, "start_general_capture");
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
