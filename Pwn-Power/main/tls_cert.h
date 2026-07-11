#pragma once
#include <stdbool.h>
#include <stddef.h>

typedef struct {
    char cert_pem[1200];
    char key_pem[600];
} tls_cert_bundle_t;

/**
 * Load a server cert/key from NVS or generate a self-signed ECDSA P-256 cert.
 * Results are cached in NVS.
 * Returns true on success and fills out bundle.
 */
bool tls_cert_load_or_generate(tls_cert_bundle_t *bundle);
