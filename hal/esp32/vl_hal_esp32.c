/*
 * VectiLicense HAL — Espressif ESP32 family. See vl_hal_esp32.h.
 * (c) 2026 VectiVolt — Apache-2.0 License
 *
 * The API calls are esp_efuse_mac_get_default, esp_chip_info,
 * esp_efuse_read_field_blob(ESP_EFUSE_OPTIONAL_UNIQUE_ID), the nvs_* family,
 * esp_secure_boot_enabled and esp_flash_encryption_enabled — all present in
 * ESP-IDF 4.4 (Arduino-ESP32 2.0.x) and 5.x.
 */

#include "vl_hal_esp32.h"

#if defined(ARDUINO_ARCH_ESP32) || defined(ESP_PLATFORM)

#include <string.h>
#include <time.h>

#include <sdkconfig.h>                /* CONFIG_IDF_TARGET_* */

#if defined(__has_include) && __has_include(<esp_mac.h>)
#  include <esp_mac.h>            /* IDF 4.4 and 5.x */
#else
#  include <esp_system.h>         /* older IDF 4.x */
#endif

#include <esp_chip_info.h>

#include <nvs.h>

#if defined(__has_include) && __has_include(<esp_secure_boot.h>)
#  include <esp_secure_boot.h>
#  define VL_HAVE_SECURE_BOOT_API 1
#endif
#if defined(__has_include) && __has_include(<esp_flash_encrypt.h>)
#  include <esp_flash_encrypt.h>
#  define VL_HAVE_FLASH_ENCRYPT_API 1
#endif

#define VL_NVS_NAMESPACE  "vectilicense"     /* 12 chars, NVS limit is 15 */
#define VL_NVS_KEY_HWM    "hwm"
#define VL_NVS_KEY_BLOB   "blob"

/* Any wall clock reading below 2020-01-01 means "never set", not "1970". */
#define VL_EPOCH_SANE_MIN 1577836800u

#define VL_SEG_MAC_LEN    6u
#define VL_SEG_MODEL_LEN  1u
#define VL_SEG_UID_LEN    16u

/* Targets whose eFuse table has OPTIONAL_UNIQUE_ID (a 128-bit per-die id in BLOCK2).
 * The classic ESP32 has no such field; a target not listed here simply yields two
 * segments. Adding a target to this list later changes the fingerprint of every chip of
 * that target that carries the field — do it before the first licence for it is minted. */
#if defined(CONFIG_IDF_TARGET_ESP32S2) || defined(CONFIG_IDF_TARGET_ESP32S3) || \
    defined(CONFIG_IDF_TARGET_ESP32C3) || defined(CONFIG_IDF_TARGET_ESP32C6) || \
    defined(CONFIG_IDF_TARGET_ESP32H2)
#  include <esp_efuse.h>
#  include <esp_efuse_table.h>
#  define VL_HAVE_UNIQUE_ID 1
#endif

/* -------------------------------------------------------------------------- */
/* Identity                                                                    */
/*                                                                             */
/* Only facts burned into THIS die's eFuses by Espressif, read raw. The first  */
/* version also hashed esp_chip_info()'s revision and feature bits and the SPI */
/* flash JEDEC id. None of those identify a die: every chip of a batch shares  */
/* them. Worse, they are not stable — `revision` is encoded differently by     */
/* IDF 4 and IDF 5, the feature flags gained bits between releases, and the    */
/* JEDEC id belongs to whichever flash part a module batch was built with and  */
/* needs a live flash transaction to read — so an SDK upgrade or a transient    */
/* read would have unlicensed devices that never changed. The chip model stays: */
/* it is one stable enum byte that keeps an S3 licence off a C3.               */
/* -------------------------------------------------------------------------- */
#ifdef VL_HAVE_UNIQUE_ID
/* Returns 1 and fills `uid` when the die carries a non-zero OPTIONAL_UNIQUE_ID. A die
 * whose field reads all zero (never programmed) yields no segment, so its fingerprint is
 * MAC + model — still unique, because the factory MAC is. */
static int read_unique_id(uint8_t uid[VL_SEG_UID_LEN])
{
    size_t i;
    uint8_t any = 0u;
    memset(uid, 0, VL_SEG_UID_LEN);
    if (esp_efuse_read_field_blob(ESP_EFUSE_OPTIONAL_UNIQUE_ID, uid,
                                  VL_SEG_UID_LEN * 8u) != ESP_OK) {
        return -1;
    }
    for (i = 0u; i < VL_SEG_UID_LEN; i++) any |= uid[i];
    return any != 0u ? 1 : 0;
}
#endif

static vl_status_t read_id_segment(void *ctx, uint32_t idx,
                                   uint8_t *out, size_t cap, size_t *out_len)
{
    (void)ctx;
    if (out == NULL || out_len == NULL) return VL_ERR_INVALID_ARG;

    switch (idx) {
    case 0: {
        uint8_t mac[VL_SEG_MAC_LEN];
        if (cap < VL_SEG_MAC_LEN) return VL_ERR_BUFFER_TOO_SMALL;
        if (esp_efuse_mac_get_default(mac) != ESP_OK) return VL_ERR_PLATFORM;
        memcpy(out, mac, VL_SEG_MAC_LEN);
        *out_len = VL_SEG_MAC_LEN;
        return VL_OK;
    }
    case 1: {
        esp_chip_info_t info;
        if (cap < VL_SEG_MODEL_LEN) return VL_ERR_BUFFER_TOO_SMALL;
        memset(&info, 0, sizeof info);
        esp_chip_info(&info);
        out[0] = (uint8_t)info.model;    /* esp_chip_model_t: ESP32-S3 = 9 */
        *out_len = VL_SEG_MODEL_LEN;
        return VL_OK;
    }
#ifdef VL_HAVE_UNIQUE_ID
    case 2: {
        uint8_t uid[VL_SEG_UID_LEN];
        int have;
        if (cap < VL_SEG_UID_LEN) return VL_ERR_BUFFER_TOO_SMALL;
        have = read_unique_id(uid);
        if (have < 0) return VL_ERR_PLATFORM;
        if (have == 0) return VL_ERR_NO_MORE_SEGMENTS;
        memcpy(out, uid, VL_SEG_UID_LEN);
        *out_len = VL_SEG_UID_LEN;
        return VL_OK;
    }
#endif
    default:
        return VL_ERR_NO_MORE_SEGMENTS;
    }
}

/* -------------------------------------------------------------------------- */
/* Clock                                                                       */
/* -------------------------------------------------------------------------- */
static vl_status_t now_epoch(void *ctx, uint32_t *out_epoch)
{
    time_t t;
    (void)ctx;
    if (out_epoch == NULL) return VL_ERR_INVALID_ARG;
    t = time(NULL);
    if (t < 0 || (uint64_t)t < VL_EPOCH_SANE_MIN) return VL_ERR_NO_CLOCK;
    if ((uint64_t)t > 0xFFFFFFFFull) return VL_ERR_PLATFORM;
    *out_epoch = (uint32_t)t;
    return VL_OK;
}

/* -------------------------------------------------------------------------- */
/* NVS-backed storage                                                          */
/* -------------------------------------------------------------------------- */
static vl_status_t nvs_begin(nvs_open_mode_t mode, nvs_handle_t *h)
{
    return (nvs_open(VL_NVS_NAMESPACE, mode, h) == ESP_OK) ? VL_OK : VL_ERR_PLATFORM;
}

static vl_status_t hwm_load(void *ctx, uint32_t *out)
{
    nvs_handle_t h;
    esp_err_t err;
    (void)ctx;
    if (out == NULL) return VL_ERR_INVALID_ARG;
    if (nvs_begin(NVS_READONLY, &h) != VL_OK) {
        /* A namespace that has never been written does not exist yet. That is
         * "no mark recorded", not a failure. */
        *out = 0u;
        return VL_OK;
    }
    err = nvs_get_u32(h, VL_NVS_KEY_HWM, out);
    nvs_close(h);
    if (err == ESP_ERR_NVS_NOT_FOUND) { *out = 0u; return VL_OK; }
    return (err == ESP_OK) ? VL_OK : VL_ERR_PLATFORM;
}

static vl_status_t hwm_store(void *ctx, uint32_t value)
{
    nvs_handle_t h;
    esp_err_t err;
    (void)ctx;
    if (nvs_begin(NVS_READWRITE, &h) != VL_OK) return VL_ERR_PLATFORM;
    err = nvs_set_u32(h, VL_NVS_KEY_HWM, value);
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);
    return (err == ESP_OK) ? VL_OK : VL_ERR_PLATFORM;
}

static vl_status_t blob_load(void *ctx, char *out, size_t cap, size_t *out_len)
{
    nvs_handle_t h;
    esp_err_t err;
    size_t len;
    (void)ctx;
    if (out == NULL || out_len == NULL || cap == 0u) return VL_ERR_INVALID_ARG;
    if (nvs_begin(NVS_READONLY, &h) != VL_OK) return VL_ERR_NOT_FOUND;
    len = cap;                                   /* in/out, includes the NUL */
    err = nvs_get_str(h, VL_NVS_KEY_BLOB, out, &len);
    nvs_close(h);
    if (err == ESP_ERR_NVS_NOT_FOUND) return VL_ERR_NOT_FOUND;
    if (err == ESP_ERR_NVS_INVALID_LENGTH) return VL_ERR_BUFFER_TOO_SMALL;
    if (err != ESP_OK || len == 0u) return VL_ERR_PLATFORM;
    *out_len = len - 1u;                         /* report without the NUL */
    return VL_OK;
}

static vl_status_t blob_store(void *ctx, const char *blob, size_t len)
{
    nvs_handle_t h;
    esp_err_t err;
    char tmp[VL_BLOB_STR_BUF_LEN];
    (void)ctx;
    if (blob == NULL) return VL_ERR_INVALID_ARG;
    if (len > VL_BLOB_STR_LEN) return VL_ERR_BUFFER_TOO_SMALL;
    /* nvs_set_str needs a NUL-terminated string; the caller gives us a
     * pointer and a length and need not have terminated it. */
    memcpy(tmp, blob, len);
    tmp[len] = '\0';
    if (nvs_begin(NVS_READWRITE, &h) != VL_OK) return VL_ERR_PLATFORM;
    err = nvs_set_str(h, VL_NVS_KEY_BLOB, tmp);
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);
    memset(tmp, 0, sizeof tmp);
    return (err == ESP_OK) ? VL_OK : VL_ERR_PLATFORM;
}

/* -------------------------------------------------------------------------- */
/* Posture — reported, never enforced here.                                    */
/* -------------------------------------------------------------------------- */
static vl_status_t secure_posture(void *ctx, vl_posture_t *out)
{
    (void)ctx;
    if (out == NULL) return VL_ERR_INVALID_ARG;
    out->secure_boot      = VL_POSTURE_UNKNOWN;
    out->flash_encryption = VL_POSTURE_UNKNOWN;
#ifdef VL_HAVE_SECURE_BOOT_API
    out->secure_boot = esp_secure_boot_enabled() ? VL_POSTURE_ON : VL_POSTURE_OFF;
#endif
#ifdef VL_HAVE_FLASH_ENCRYPT_API
    out->flash_encryption =
        esp_flash_encryption_enabled() ? VL_POSTURE_ON : VL_POSTURE_OFF;
#endif
    return VL_OK;
}

static const vl_hal_t g_hal = {
    read_id_segment,
    now_epoch,
    hwm_load, hwm_store,
    blob_load, blob_store,
    secure_posture,
    NULL
};

const vl_hal_t *vl_hal_esp32(void) { return &g_hal; }

#else  /* not an ESP32 target */

const vl_hal_t *vl_hal_esp32(void) { return NULL; }

#endif
