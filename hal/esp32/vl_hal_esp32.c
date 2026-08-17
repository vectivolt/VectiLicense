/*
 * VectiLicense HAL — Espressif ESP32 family. See vl_hal_esp32.h.
 * (c) 2026 VectiVolt — Apache-2.0 License
 *
 * NEVER BUILT WITH A REAL ESP-IDF OR ARDUINO-ESP32 TOOLCHAIN. There is no ESP
 * toolchain on the machine this was written on, and no stand-in IDF headers
 * are checked in, so nothing in this repository has ever type-checked a single
 * call below. The API calls are the documented ones (esp_efuse_mac_get_default,
 * esp_chip_info, esp_flash_read_id, the nvs_* family, esp_secure_boot_enabled,
 * esp_flash_encryption_enabled) and the logic is the part worth reading; your
 * first build on real hardware is the first build there has ever been.
 */

#include "vl_hal_esp32.h"

#if defined(ARDUINO_ARCH_ESP32) || defined(ESP_PLATFORM)

#include <string.h>
#include <time.h>

#if defined(__has_include) && __has_include(<esp_mac.h>)
#  include <esp_mac.h>            /* IDF 5.x */
#else
#  include <esp_system.h>         /* IDF 4.x */
#endif

#include <esp_chip_info.h>

#if defined(__has_include) && !__has_include(<esp_flash.h>)
#  error "VectiLicense ESP32 HAL needs <esp_flash.h> (IDF >= 4.0 / Arduino-ESP32 >= 2.0)."
#endif
#include <esp_flash.h>

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
#define VL_SEG_CHIP_LEN   8u
#define VL_SEG_FLASH_LEN  4u

/* -------------------------------------------------------------------------- */
/* Identity                                                                    */
/* -------------------------------------------------------------------------- */
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
        uint16_t rev;
        uint32_t feat;
        if (cap < VL_SEG_CHIP_LEN) return VL_ERR_BUFFER_TOO_SMALL;
        memset(&info, 0, sizeof info);
        esp_chip_info(&info);
        /* `revision` is uint8_t on IDF 4 and uint16_t (major*100+minor) on
         * IDF 5. Widen to 16 bits so both encode without collapsing revs. */
        rev  = (uint16_t)info.revision;
        feat = (uint32_t)info.features;
        out[0] = (uint8_t)info.model;
        out[1] = (uint8_t)info.cores;
        out[2] = (uint8_t)(rev & 0xFFu);
        out[3] = (uint8_t)((rev >> 8) & 0xFFu);
        out[4] = (uint8_t)(feat & 0xFFu);
        out[5] = (uint8_t)((feat >> 8) & 0xFFu);
        out[6] = (uint8_t)((feat >> 16) & 0xFFu);
        out[7] = (uint8_t)((feat >> 24) & 0xFFu);
        *out_len = VL_SEG_CHIP_LEN;
        return VL_OK;
    }
    case 2: {
        uint32_t id = 0;
        if (cap < VL_SEG_FLASH_LEN) return VL_ERR_BUFFER_TOO_SMALL;
        /* NULL selects the default (bootstrapped) flash chip. */
        if (esp_flash_read_id(NULL, &id) != ESP_OK) return VL_ERR_PLATFORM;
        if (id == 0u || id == 0x00FFFFFFu) return VL_ERR_PLATFORM;  /* bus stuck */
        out[0] = (uint8_t)((id >> 24) & 0xFFu);
        out[1] = (uint8_t)((id >> 16) & 0xFFu);
        out[2] = (uint8_t)((id >> 8) & 0xFFu);
        out[3] = (uint8_t)(id & 0xFFu);
        *out_len = VL_SEG_FLASH_LEN;
        return VL_OK;
    }
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
