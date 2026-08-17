/*
 * VectiLicense HAL — POSIX hosts: Linux (including Raspberry Pi) and macOS.
 * (c) 2026 VectiVolt — Apache-2.0 License
 *
 * Identity segments, in fingerprint order. THIS ORDER IS PART OF THE ON-WIRE
 * FORMAT — changing it invalidates every licence already issued. The two
 * operating systems deliberately have different segment sets; a fingerprint is
 * only ever compared against itself on the same machine.
 *
 * Linux:
 *   0  primary interface MAC, lowercase text, "b8:27:eb:12:34:56"
 *   1  /etc/machine-id, or /var/lib/dbus/machine-id
 *   2  board serial: /proc/cpuinfo "Serial" (Pi), else
 *      /sys/class/dmi/id/product_uuid (PC, usually root-only), else empty
 *
 * macOS:
 *   0  primary en* interface MAC, lowercase text
 *   1  IOPlatformUUID from IOKit
 *
 * Segment 2 on Linux is legitimately empty on hosts that expose neither
 * source — it is hashed as a zero length byte, so the fingerprint stays
 * stable. Segments 0 and 1 carry the identity there.
 *
 * LINK REQUIREMENTS. Linux: none. macOS: -framework IOKit -framework
 * CoreFoundation. Building macOS with -DVL_HAL_POSIX_NO_IOKIT drops segment 1
 * and needs no frameworks, but PRODUCES A DIFFERENT FINGERPRINT — pick one
 * before you issue your first licence and never change it.
 *
 * Optional callbacks provided: now_epoch (time(3)), and hwm/blob storage in
 * two small files, "<state_path>.hwm" and "<state_path>.blob". secure_posture
 * is NULL: there is nothing cheap and honest to report on a general-purpose
 * OS, so vl_posture() answers VL_POSTURE_UNKNOWN.
 */

#ifndef VL_HAL_POSIX_H
#define VL_HAL_POSIX_H

#include "vectilicense/vectilicense.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Build the POSIX HAL. Returns NULL on a non-POSIX target, or if an argument
 * is too long to store.
 *
 *   iface       network interface to fingerprint, or NULL to auto-pick
 *               (prefers eth* / en* over wlan*, skips lo/docker/veth/awdl).
 *               Pin this on a multi-NIC machine: which interface "wins" can
 *               otherwise change when hardware is added, and the fingerprint
 *               changes with it.
 *   state_path  base path for the two state files, or NULL for the default
 *               "/var/lib/vectilicense/state". The directory must exist and
 *               be writable; this HAL does not create it. Storage is only
 *               used if you call the callbacks or set VL_FLAG_ENFORCE_HWM.
 *
 * The returned HAL points at file-static state, so the last call wins. One
 * process fingerprints one machine; that is the whole use case.
 */
const vl_hal_t *vl_hal_posix(const char *iface, const char *state_path);

#ifdef __cplusplus
}
#endif

#endif /* VL_HAL_POSIX_H */
