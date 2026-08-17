/*
 * VectiLicense HAL — NXP Kinetis and i.MX RT (MCUXpresso SDK).
 * (c) 2026 VectiVolt — Apache-2.0 License
 *
 * WRITTEN TO THE DOCUMENTED MCUXpresso REGISTER API AND NOT COMPILE-VERIFIED.
 * No NXP SDK was installed on the machine that produced this file.
 *
 * Identity segment, the only one, selected at compile time by which registers
 * your device header defines:
 *
 *   Kinetis (SIM UID)     16 bytes  UIDH, UIDMH, UIDML, UIDL, each big-endian
 *                         12 bytes  on parts without UIDH (KL, KE, some KV)
 *   i.MX RT (OCOTP)        8 bytes  CFG0, CFG1, each big-endian — the 64-bit
 *                                   factory-programmed unique id
 *
 * Both are factory-programmed and read-only: they survive reflashing and
 * cannot be changed without replacing the chip.
 *
 * This file needs "fsl_device_registers.h" on the include path — the standard
 * MCUXpresso umbrella header that pulls in your part's register definitions.
 * It is located with __has_include, so on any other target, or in a build
 * without the SDK, this file compiles to a stub returning NULL.
 *
 * i.MX RT1170 and later keep the unique id in OCOTP->FUSE[] rather than
 * CFG0/CFG1 and are NOT handled here; vl_hal_nxp() returns NULL there rather
 * than inventing an id. Add the branch, using the fuse indices from your
 * reference manual, before shipping one.
 *
 * ALL OPTIONAL CALLBACKS ARE NULL, on purpose: the RTC needs a handle and the
 * flash/FlexNVM layout belongs to your linker script. Copy the struct and
 * fill in what you have:
 *
 *     vl_hal_t hal = *vl_hal_nxp();
 *     hal.now_epoch  = my_rtc_epoch;
 *     hal.blob_load  = my_flexnvm_load;
 *     hal.blob_store = my_flexnvm_store;
 *
 * With now_epoch NULL, vl_verify() does not enforce not_before/not_after and
 * leaves VL_CHECKED_TIME clear. Read lic.checked, or set
 * VL_FLAG_REQUIRE_CLOCK to make the absence a hard failure.
 */

#ifndef VL_HAL_NXP_H
#define VL_HAL_NXP_H

#include "vectilicense/vectilicense.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Returns a HAL bound to this MCU, or NULL when built without a recognised
 * NXP device header. The returned struct is static and const. */
const vl_hal_t *vl_hal_nxp(void);

#ifdef __cplusplus
}
#endif

#endif /* VL_HAL_NXP_H */
