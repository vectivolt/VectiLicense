// ---------------------------------------------------------------------------
// VectiLicense × VectiOTA — refuse updates on an unlicensed device
// (c) 2026 VectiVolt — Apache-2.0 License
// ---------------------------------------------------------------------------
//
// Usage:
//
//     #include <VectiOTA.h>
//     #include <VectiLicense.h>
//     void loop() {
//       license.pump();
//       vecti::licenseGateOta(license);   // cheap: three bool stores
//       VectiOTA.loop();
//     }
//
// READ THIS BEFORE GATING FIRMWARE UPDATES. If an expiring licence can turn
// off firmware updates, then the device that most needs a fix — the one in the
// field, out of support, with a bug — is the one that cannot receive it, and
// the only way back in is a serial cable and a technician. That is a support
// cost, not a piracy control.
//
// The default gates all three modes because that is what "unlicensed devices
// do not get updates" means. Pass gateFirmware = false to keep the push-OTA
// door open for recovery while still refusing filesystem and pull updates —
// which is the combination most vendors actually want.
//
// And the usual caveat: this is a business control, not a security boundary.
// Whoever can flash the device over USB never asked VectiOTA's permission.
//
// This file compiles to nothing when VectiOTA is not installed.
//
// NEVER COMPILED AGAINST THE REAL VectiOTA — not in CI, not on a bench, not
// once. It is written to VectiOTA's documented API, and because the whole
// body is behind __has_include(<VectiOTA.h>), every build in this repository
// has skipped it entirely. Expect to fix a name or an include path on your
// first real build. What IS compiled and tested here is vecti::License in
// vl_bridge.h, which is where this file's actual logic lives.
// See the README's "What has actually been built and run".

#ifndef VL_BRIDGE_OTA_H
#define VL_BRIDGE_OTA_H

#if defined(__has_include)
#if __has_include(<VectiOTA.h>)
#define VL_HAVE_VECTIOTA 1
#endif
#endif

#ifdef VL_HAVE_VECTIOTA

#include <VectiOTA.h>

#include "vl_bridge.h"

namespace vecti {

// featureBit >= 0 additionally requires that feature bit, so "updates" can be
// something a customer buys rather than something every licence includes.
// Call from loop(), after license.pump().
inline void licenseGateOta(License &lic, int featureBit = -1,
                           bool gateFirmware = true) {
    bool allow = lic.ok();
    if (allow && featureBit >= 0) {
        allow = lic.feature((unsigned)featureBit);
    }
    if (gateFirmware) { VectiOTA.allowFirmwareUpdates(allow); }
    VectiOTA.allowFilesystemUpdates(allow);
    VectiOTA.allowPullMode(allow);
}

}  // namespace vecti

#endif  // VL_HAVE_VECTIOTA
#endif  // VL_BRIDGE_OTA_H
