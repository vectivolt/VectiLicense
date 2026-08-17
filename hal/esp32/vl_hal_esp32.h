/*
 * VectiLicense HAL — Espressif ESP32 family (ESP-IDF 4.x / 5.x, Arduino-ESP32).
 * (c) 2026 VectiVolt — Apache-2.0 License
 *
 * NEVER BUILT WITH A REAL ESP-IDF OR ARDUINO-ESP32 TOOLCHAIN. Written to the
 * documented IDF API; no build here has ever seen an esp_* header. See the
 * README's "What has actually been built and run".
 *
 * Identity segments, in fingerprint order. THIS ORDER IS PART OF THE ON-WIRE
 * FORMAT — changing it invalidates every licence already issued.
 *
 *   0  6 bytes  efuse base MAC          (esp_efuse_mac_get_default)
 *   1  8 bytes  chip model/cores/rev/features, little-endian (esp_chip_info)
 *   2  4 bytes  SPI flash JEDEC id, big-endian (esp_flash_read_id)
 *
 * Segment 0 alone would be forgeable by an integrator who overrides the MAC;
 * segment 1 pins the silicon and segment 2 the flash part, so a flash image
 * copied onto a different board yields a different fingerprint.
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
