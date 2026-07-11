#include "tls_cert.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_system.h"
#include "mbedtls/pk.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/oid.h"
#include "psa/crypto.h"
#include <string.h>

#define TAG "TLSCERT"
#define NVS_NAMESPACE "tls"
#define NVS_KEY_CERT "cert"
#define NVS_KEY_KEY  "key"

static void clear_nvs_tls_namespace(void) {
    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h) != ESP_OK) {
        return;
    }
    nvs_erase_all(h);
    nvs_commit(h);
    nvs_close(h);
    ESP_LOGW(TAG, "Cleared cached TLS material in NVS");
}

static bool validate_bundle(const tls_cert_bundle_t *bundle) {
    mbedtls_x509_crt crt;
    mbedtls_pk_context key;
    mbedtls_x509_crt_init(&crt);
    mbedtls_pk_init(&key);

    int ret = mbedtls_x509_crt_parse(&crt, (const unsigned char *)bundle->cert_pem, strlen(bundle->cert_pem) + 1);
    if (ret != 0) {
        ESP_LOGW(TAG, "Cached cert parse failed: -0x%04x", -ret);
        goto fail;
    }

    ret = mbedtls_pk_parse_key(&key, (const unsigned char *)bundle->key_pem, strlen(bundle->key_pem) + 1, NULL, 0);
    if (ret != 0) {
        ESP_LOGW(TAG, "Cached key parse failed: -0x%04x", -ret);
        goto fail;
    }

    ret = mbedtls_pk_check_pair(&crt.pk, &key);
    if (ret != 0) {
        ESP_LOGW(TAG, "Cached cert/key mismatch: -0x%04x", -ret);
        goto fail;
    }

    mbedtls_x509_crt_free(&crt);
    mbedtls_pk_free(&key);
    return true;

fail:
    mbedtls_x509_crt_free(&crt);
    mbedtls_pk_free(&key);
    return false;
}

static bool load_from_nvs(tls_cert_bundle_t *bundle) {
    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READONLY, &h) != ESP_OK) {
        return false;
    }

    size_t cert_len = sizeof(bundle->cert_pem);
    size_t key_len = sizeof(bundle->key_pem);
    esp_err_t e1 = nvs_get_blob(h, NVS_KEY_CERT, bundle->cert_pem, &cert_len);
    esp_err_t e2 = nvs_get_blob(h, NVS_KEY_KEY, bundle->key_pem, &key_len);
    nvs_close(h);

    if (e1 != ESP_OK || e2 != ESP_OK) {
        return false;
    }

    /* Ensure null-terminated strings */
    if (cert_len >= sizeof(bundle->cert_pem) || key_len >= sizeof(bundle->key_pem)) {
        return false;
    }
    bundle->cert_pem[cert_len] = '\0';
    bundle->key_pem[key_len] = '\0';
    if (!validate_bundle(bundle)) {
        ESP_LOGW(TAG, "Cached TLS material invalid; regenerating");
        clear_nvs_tls_namespace();
        return false;
    }
    ESP_LOGI(TAG, "Loaded TLS cert+key from NVS (cert %u bytes, key %u bytes)", (unsigned)cert_len, (unsigned)key_len);
    return true;
}

static bool save_to_nvs(const tls_cert_bundle_t *bundle) {
    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h) != ESP_OK) {
        ESP_LOGE(TAG, "nvs_open failed for namespace '%s'", NVS_NAMESPACE);
        return false;
    }
    esp_err_t e1 = nvs_set_blob(h, NVS_KEY_CERT, bundle->cert_pem, strlen(bundle->cert_pem) + 1);
    esp_err_t e2 = nvs_set_blob(h, NVS_KEY_KEY, bundle->key_pem, strlen(bundle->key_pem) + 1);
    esp_err_t ec = nvs_commit(h);
    nvs_close(h);
    if (e1 != ESP_OK || e2 != ESP_OK || ec != ESP_OK) {
        ESP_LOGE(TAG, "Failed to store TLS material: cert=%d key=%d commit=%d", e1, e2, ec);
        return false;
    }
    ESP_LOGI(TAG, "Stored TLS cert+key into NVS");
    return true;
}

static bool generate_cert(tls_cert_bundle_t *bundle) {
    bool ok = false;
    mbedtls_pk_context key;
    mbedtls_x509write_cert crt;
    psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    unsigned char serial_raw[8];

    mbedtls_pk_init(&key);
    mbedtls_x509write_crt_init(&crt);
    memset(serial_raw, 0, sizeof(serial_raw));

    psa_set_key_type(&key_attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&key_attributes, 256);
    psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&key_attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_status_t status = psa_generate_key(&key_attributes, &key_id);
    if (status != PSA_SUCCESS) {
        ESP_LOGE(TAG, "psa_generate_key failed: %d", status);
        goto cleanup;
    }

    int ret = mbedtls_pk_wrap_psa(&key, key_id);
    if (ret != 0) {
        ESP_LOGE(TAG, "pk_wrap_psa failed: -0x%04x", -ret);
        goto cleanup;
    }

    status = psa_generate_random(serial_raw, sizeof(serial_raw));
    if (status != PSA_SUCCESS) {
        ESP_LOGE(TAG, "psa_generate_random failed: %d", status);
        goto cleanup;
    }

    mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA256);
    mbedtls_x509write_crt_set_version(&crt, MBEDTLS_X509_CRT_VERSION_3);
    mbedtls_x509write_crt_set_subject_key(&crt, &key);
    mbedtls_x509write_crt_set_issuer_key(&crt, &key);
    ret = mbedtls_x509write_crt_set_serial_raw(&crt, serial_raw, sizeof(serial_raw));
    if (ret != 0) {
        ESP_LOGE(TAG, "set_serial_raw failed: -0x%04x", -ret);
        goto cleanup;
    }

    const char *subject = "CN=pwnpower.local";
    ret = mbedtls_x509write_crt_set_subject_name(&crt, subject);
    if (ret != 0) {
        ESP_LOGE(TAG, "set_subject_name failed: -0x%04x", -ret);
        goto cleanup;
    }
    ret = mbedtls_x509write_crt_set_issuer_name(&crt, subject);
    if (ret != 0) {
        ESP_LOGE(TAG, "set_issuer_name failed: -0x%04x", -ret);
        goto cleanup;
    }

    /* Valid for 10 years */
    ret = mbedtls_x509write_crt_set_validity(&crt, "20240101000000", "20340101000000");
    if (ret != 0) {
        ESP_LOGE(TAG, "set_validity failed: -0x%04x", -ret);
        goto cleanup;
    }

    /* Basic Constraints: CA=false, pathlen=0 */
    ret = mbedtls_x509write_crt_set_basic_constraints(&crt, 0, -1);
    if (ret != 0) {
        ESP_LOGE(TAG, "set_basic_constraints failed: -0x%04x", -ret);
        goto cleanup;
    }

    /* Key Usage: digitalSignature | keyEncipherment */
    ret = mbedtls_x509write_crt_set_key_usage(&crt, MBEDTLS_X509_KU_DIGITAL_SIGNATURE | MBEDTLS_X509_KU_KEY_ENCIPHERMENT);
    if (ret != 0) {
        ESP_LOGE(TAG, "set_key_usage failed: -0x%04x", -ret);
        goto cleanup;
    }

    memset(bundle->cert_pem, 0, sizeof(bundle->cert_pem));
    memset(bundle->key_pem, 0, sizeof(bundle->key_pem));

    ret = mbedtls_pk_write_key_pem(&key, (unsigned char *)bundle->key_pem, sizeof(bundle->key_pem));
    if (ret != 0) {
        ESP_LOGE(TAG, "write_key_pem failed: -0x%04x", -ret);
        goto cleanup;
    }

    ret = mbedtls_x509write_crt_pem(&crt, (unsigned char *)bundle->cert_pem, sizeof(bundle->cert_pem));
    if (ret != 0) {
        ESP_LOGE(TAG, "write_crt_pem failed: -0x%04x", -ret);
        goto cleanup;
    }

    ESP_LOGI(TAG, "Generated new self-signed ECDSA P-256 cert");
    ok = true;

cleanup:
    mbedtls_x509write_crt_free(&crt);
    mbedtls_pk_free(&key);
    psa_reset_key_attributes(&key_attributes);
    if (key_id != PSA_KEY_ID_NULL) {
        psa_destroy_key(key_id);
    }
    return ok;
}

bool tls_cert_load_or_generate(tls_cert_bundle_t *bundle) {
    if (!bundle) return false;
    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        ESP_LOGE(TAG, "psa_crypto_init failed: %d", status);
        return false;
    }
    if (load_from_nvs(bundle)) {
        return true;
    }
    if (!generate_cert(bundle)) {
        return false;
    }
    save_to_nvs(bundle);
    return true;
}
