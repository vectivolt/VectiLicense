/*
 * VectiLicense HAL — the unported stub. Copy this pair into hal/<yourboard>/
 * and fill in read_id_segment.
 * (c) 2026 VectiVolt — Apache-2.0 License
 *
 * This HAL compiles everywhere and works nowhere. read_id_segment returns
 * VL_ERR_PLATFORM, so vl_compute_fingerprint() and vl_verify() fail closed on
 * the first call and you find out at bring-up instead of in the field.
 *
 * WHY IT DOES NOT JUST RETURN SOME BYTES. A stub that returned a fixed array
 * would give every unit you ship the same fingerprint, so one licence would
 * unlock the entire production run and no licence would ever be revocable.
 * That failure is silent — everything works, all the way to the customer who
 * pastes their friend's blob and gets VL_OK. Failing loudly is the only safe
 * default, so DO NOT "fix" this file by returning a constant.
 *
 * WHAT MAKES A GOOD IDENTITY SEGMENT, in preference order:
 *   1. a factory-programmed, read-only die id (MCU UID, efuse, OTP)
 *   2. a unique id in a soldered-down peripheral (flash chip, secure element,
 *      Ethernet PHY MAC)
 *   3. a serial number written once at manufacture into OTP or a protected
 *      flash page
 *
 * NOT acceptable: a value from a writable config file, a build-time constant,
 * a random number generated at first boot and stored in plain flash, or
 * anything a user can edit. Each of those means an attacker copies the value
 * along with the flash image and the licence follows it.
 *
 * Return several segments if you have several sources — they are hashed in
 * order with a one-byte length prefix, so the set and its order are part of
 * the on-wire format. Decide on them BEFORE issuing your first licence:
 * adding a segment later invalidates every licence already in the field.
 */

#ifndef VL_HAL_NONE_H
#define VL_HAL_NONE_H

#include "vectilicense/vectilicense.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Never NULL — it returns a real, correctly shaped HAL whose every operation
 * fails. Define VL_HAL_NONE_ACKNOWLEDGED to silence the build warning once
 * you have consciously decided to ship with an unported board. */
const vl_hal_t *vl_hal_none(void);

#ifdef __cplusplus
}
#endif

#endif /* VL_HAL_NONE_H */
