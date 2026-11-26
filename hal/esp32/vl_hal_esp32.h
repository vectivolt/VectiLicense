/*
 * VectiLicense HAL — Espressif ESP32 family (ESP-IDF 4.x / 5.x, Arduino-ESP32).
 * (c) 2026 VectiVolt — Apache-2.0 License
 *
 * See the README's "What has actually been built and run" for which toolchains
 * have compiled this file.
 *
 * Identity segments, in fingerprint order. THIS ORDER IS PART OF THE ON-WIRE
 * FORMAT — changing it invalidates every licence already issued.
 *
 *   0   6 bytes  factory MAC, eFuse BLOCK1      (esp_efuse_mac_get_default),
 *                first octet first, as `espefuse.py summary` prints it
 *   1   1 byte   chip model                     (esp_chip_info().model;
 *                                                ESP32-S3 = 9)
 *   2  16 bytes  eFuse OPTIONAL_UNIQUE_ID       (ESP32-S2/S3/C3/C6/H2 only, and
 *                                                only when not all zero), byte
 *                [0] first, as summary prints it
 *
 * The MAC and the unique id are burned into the die by Espressif and read raw.
 * The model byte is not read from the die: it is the esp_chip_model_t the IDF
 * reports for the target the image was built for, which is the chip it runs
 * on, and it keeps an S3 licence off a C3. So the fingerprint survives an SDK
 * upgrade, a reflash and a flash-part change, and a flash image copied to
 * another board yields that board's fingerprint. eFuse bits can only be set,
 * never cleared; matching another die's MAC AND 128-bit unique id by setting
 * bits needs a donor die whose bits are a subset of both.
 *
 * `vl_mint.py device-id --esp32 --mac .. --model .. [--uid ..]` computes the
 * same id on the host from what `espefuse.py summary` prints, and
 * tests/test_vl_hal_esp32.c holds the two in step. The bench board (MAC
 * d0:cf:13:73:b7:38, ESP32-S3, UID 7b9f020ba13575a5299f6e75e66e665a) is
 * 19PPVWEP2AD037V5ZMQV3S3XH8.
 *
 * Optional callbacks provided:
 *   now_epoch       time(NULL), rejected as unset below 2020-01-01
 *   hwm_load/store  NVS u32, namespace "vectilicense", key "hwm"
 *   blob_load/store NVS str, namespace "vectilicense", key "blob"
 *   secure_posture  esp_secure_boot_enabled() / esp_flash_encryption_enabled()
 *
 * The NVS callbacks require nvs_flash_init() to have succeeded already; this
 * HAL will not initialise the partition for you, because deciding what to do
 * about ESP_ERR_NVS_NO_FREE_PAGES (erase? refuse to boot?) is your call.
 *
 * CLOCK POLICY. now_epoch is non-NULL here, so a device whose clock has never
 * been set fails vl_verify() closed with VL_ERR_PLATFORM rather than silently
 * honouring an expired licence. If you would rather ship a device that boots
 * and runs before SNTP has synced, copy the struct and NULL the field out:
 *
 *     vl_hal_t hal = *vl_hal_esp32();
 *     hal.now_epoch = NULL;          // windows unenforced, VL_CHECKED_TIME clear
 *
 * Build: add this one .c file to your component/library. It compiles to a stub
 * returning NULL on any non-ESP32 target, so it is safe to leave in a
 * multi-target source tree.
 */

#ifndef VL_HAL_ESP32_H
#define VL_HAL_ESP32_H

#include "vectilicense/vectilicense.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Returns a HAL bound to this chip, or NULL when built for a non-ESP32 target.
 * The returned struct is static and const; copy it if you want to disable a
 * callback. Never returns a HAL that would produce a constant fingerprint. */
const vl_hal_t *vl_hal_esp32(void);

#ifdef __cplusplus
}
#endif

#endif /* VL_HAL_ESP32_H */
