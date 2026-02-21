#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

extern const uint8_t ouis_json_start[] asm("_binary_ouis_json_start");
extern const uint8_t ouis_json_end[]   asm("_binary_ouis_json_end");


static void normalize_prefix(const char *mac, char *out6) {
    int oi = 0;
    for (const char *p = mac; *p && oi < 6; ++p) {
        if ((*p >= '0' && *p <= '9') || (*p >= 'A' && *p <= 'F') || (*p >= 'a' && *p <= 'f')) {
            out6[oi++] = (char)toupper((unsigned char)*p);
        }
    }
    while (oi < 6) out6[oi++] = '\0';
    out6[6] = '\0';
}

static bool is_locally_administered(const char *mac) {
    // check LAA bit: second least significant bit of first octet
    int hi = 0, lo = 0;
    if (!isxdigit((int)mac[0]) || !isxdigit((int)mac[1])) return false;
    hi = (mac[0] <= '9' ? mac[0]-'0' : toupper(mac[0])-'A'+10);
    lo = (mac[1] <= '9' ? mac[1]-'0' : toupper(mac[1])-'A'+10);
    int first_octet = (hi<<4) | lo;
    return (first_octet & 0x02) != 0;
}

static void to_proper_caps(char *s) {
    // Properly capitalise: first letter upper, rest lower for each token split by space or hyphen
    bool new_word = true;
    for (size_t i = 0; s[i]; ++i) {
        if (s[i] == ' ' || s[i] == '-' || s[i] == '_' ) { new_word = true; continue; }
        if (new_word) { s[i] = (char)toupper((unsigned char)s[i]); new_word = false; }
        else { s[i] = (char)tolower((unsigned char)s[i]); }
    }
}

// naive streaming scan of embedded JSON: {"FC3497":"espressif",...}
static bool lookup_vendor(const char *prefix6, char *out_vendor, size_t out_sz) {
    const char *buf = (const char*)ouis_json_start;
    const char *end = (const char*)ouis_json_end;
    const size_t len = (size_t)(end - buf);
    if (len == 0) return false;
    // search for "PREFIX"
    char keypat[16];
    // pattern like "FC3497"
    snprintf(keypat, sizeof(keypat), "\"%s\"", prefix6);
    const char *p = buf;
    while (p && p < end) {
        const char *k = strstr(p, keypat);
        if (!k || k >= end) break;
        const char *colon = strchr(k + strlen(keypat), ':');
        if (!colon || colon >= end) break;
        const char *q1 = strchr(colon + 1, '"');
        if (!q1 || q1 >= end) break;
        const char *q2 = strchr(q1 + 1, '"');
        if (!q2 || q2 >= end) break;
        size_t vlen = (size_t)(q2 - (q1 + 1));
        if (vlen >= out_sz) vlen = out_sz - 1;
        memcpy(out_vendor, q1 + 1, vlen);
        out_vendor[vlen] = '\0';
        to_proper_caps(out_vendor);
        return true;
    
        // move forward
        p = k + 1;
    }
    return false;
}

bool ouis_lookup_vendor(const uint8_t *mac, char *out_vendor, size_t out_sz) {
    if (!mac || !out_vendor || out_sz < 2) return false;
    
    char mac_str[13];
    snprintf(mac_str, sizeof(mac_str), "%02X%02X%02X%02X%02X%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    
    char p6[8];
    normalize_prefix(mac_str, p6);
    
    if (is_locally_administered(p6)) {
        strncpy(out_vendor, "Random MAC", out_sz - 1);
        out_vendor[out_sz - 1] = '\0';
        return true;
    }
    
    return lookup_vendor(p6, out_vendor, out_sz);
}


