#pragma once
#include <stdbool.h>
#include <stddef.h>

typedef struct {
    char cert_pem[1200];
    char key_pem[600];
} tls_cert_bundle_t;

/**
 * Load server cert/key from NVS or generate a new self-signed RSA-2048 cert for
 * hosts: pwnpower.local and 192.168.4.1. Results are cached in NVS.
 * Returns true on success and fills out bundle.
 */
bool tls_cert_load_or_generate(tls_cert_bundle_t *bundle);
