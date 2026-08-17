/*
 * VectiLicense HAL — STMicroelectronics STM32 (STM32Cube HAL).
 * (c) 2026 VectiVolt — Apache-2.0 License
 *
 * WRITTEN TO THE DOCUMENTED CUBE HAL API AND NOT COMPILE-VERIFIED. No STM32
 * SDK was installed on the machine that produced this file.
 *
 * Identity segment, the only one:
 *   0  12 bytes  96-bit unique device ID, HAL_GetUIDw0/1/2(), each word
 *                little-endian, in the order w0, w1, w2
 *
 * Families: every family whose Cube HAL defines UID_BASE and therefore
 * HAL_GetUIDw0/1/2 — F0, F1, F2, F3, F4, F7, G0, G4, H7, L0, L1, L4, L5, U5,
 * WB, WL. The ID is factory-programmed and read-only, so it survives
 * reflashing and cannot be spoofed without replacing the MCU.
 *
 * Compiled only when USE_HAL_DRIVER is defined (every CubeMX project defines
 * it) or when you define VL_HAL_STM32 yourself. On any other target this file
 * compiles to a stub returning NULL.
 *
 * NOT USING THE CUBE HAL? Point the file straight at the UID registers and no
 * vendor header is needed at all:
 *
 *     -DVL_HAL_STM32 -DVL_HAL_STM32_UID_BASE=0x1FFF7A10   // F4
 *
 * The UID base is family-specific — F2/F4 0x1FFF7A10, F7 0x1FF0F420,
 * H7 0x1FF1E800, L4 0x1FFF7590, G0 0x1FFF7590, G4 0x1FFF7590, WB 0x1FFF7590.
 * Check your reference manual; a wrong address usually reads back as zeros,
 * which this HAL rejects rather than turning into a shared fingerprint.
 *
 * ALL OPTIONAL CALLBACKS ARE NULL, on purpose:
 *   now_epoch       an RTC needs an RTC_HandleTypeDef this file cannot know
 *                   about. Wire it yourself if you have one.
 *   hwm_*, blob_*   flash geometry differs per family and your linker script
 *                   already owns the layout. Point them at your EEPROM
 *                   emulation, a backup-domain register, or an external FRAM.
 *
 *     vl_hal_t hal = *vl_hal_stm32();
 *     hal.now_epoch = my_rtc_epoch;
 *     hal.blob_load = my_eeprom_load;
 *     hal.blob_store = my_eeprom_store;
 *
 * With now_epoch NULL, vl_verify() does not enforce not_before/not_after and
 * leaves VL_CHECKED_TIME clear. That is deliberate: read lic.checked, or set
 * VL_FLAG_REQUIRE_CLOCK to make the absence a hard failure.
 */

#ifndef VL_HAL_STM32_H
#define VL_HAL_STM32_H

#include "vectilicense/vectilicense.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Returns a HAL bound to this MCU, or NULL when built for another target.
 * The returned struct is static and const; copy it to add callbacks. */
const vl_hal_t *vl_hal_stm32(void);

#ifdef __cplusplus
}
#endif

#endif /* VL_HAL_STM32_H */
