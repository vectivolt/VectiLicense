/*
 * VectiLicense HAL — Raspberry Pi RP2040 / RP2350 (pico-sdk).
 * (c) 2026 VectiVolt — Apache-2.0 License
 *
 * WRITTEN TO THE DOCUMENTED pico-sdk API AND NOT COMPILE-VERIFIED. No pico-sdk
 * was installed on the machine that produced this file. Expect to fix a
 * header path or two on your first build; the logic is the part worth reading.
 *
 * Identity segment, the only one:
 *   0  8 bytes  pico_get_unique_board_id() — the QSPI flash chip's unique id
 *
 * That id lives in the flash part, not the RP2040. Reflashing the same board
 * keeps the fingerprint; moving the flash chip to another board moves the
 * licence with it. For an RP2040 that is the strongest identity available.
 *
 * Optional callbacks provided:
 *   hwm_load/store, blob_load/store — one dedicated flash sector, by default
 *   the last sector of PICO_FLASH_SIZE_BYTES. Override with
 *   -DVL_HAL_RP2040_FLASH_OFFSET=<byte offset from the start of flash>.
 *
 *   now_epoch is NULL. The RP2040 has no battery-backed clock, so anything it
 *   reports after a power cycle is fiction, and fiction that silently expires
 *   a customer's licence is worse than no clock at all. Wire your own
 *   now_epoch if you have an external RTC:
 *
 *       vl_hal_t hal = *vl_hal_rp2040();
 *       hal.now_epoch = my_ds3231_epoch;
 *
 *   secure_posture is NULL: the RP2040 has no secure boot. On RP2350 you can
 *   report the boot signing state yourself the same way.
 *
 * FLASH WRITE SAFETY. The store callbacks erase and program flash with
 * interrupts disabled. That is sufficient on a single-core program. If core1
 * is running and may execute from XIP, park it first, or replace the two
 * calls with flash_safe_execute() (pico-sdk >= 1.5.1). Do not call the store
 * callbacks from an interrupt handler.
 */

#ifndef VL_HAL_RP2040_H
#define VL_HAL_RP2040_H

#include "vectilicense/vectilicense.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Returns a HAL bound to this board, or NULL when built without the pico-sdk.
 * The returned struct is static and const; copy it to add a clock. */
const vl_hal_t *vl_hal_rp2040(void);

#ifdef __cplusplus
}
#endif

#endif /* VL_HAL_RP2040_H */
