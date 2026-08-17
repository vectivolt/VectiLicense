// ---------------------------------------------------------------------------
// VectiLicense × VectiSerial — `license` console command
// (c) 2026 VectiVolt — Apache-2.0 License
// ---------------------------------------------------------------------------
//
//   license                → same as `license status`
//   license status         → verdict, serial, features, expiry, what was checked
//   license id             → the 26-character device id
//   license <blob>         → queue an activation (applied by license.pump())
//
// Usage — VectiSerial has one onMessage slot, so the sketch keeps it and asks
// this to look first:
//
//     VectiSerial.onMessage([](const String &cmd) {
//       if (vecti::licenseSerialCommand(license, cmd)) { return; }
//       ... the sketch's own commands ...
//     });
//
//     void loop() { vecti::licenseSerialLoop(license); VectiSerial.loop(); }
//
// licenseSerialCommand() runs on the AsyncTCP task, which is why it only ever
// queues: no Ed25519, no NVS write, nothing that blocks the socket task.
// licenseSerialLoop() does the work on the loop task and reports the outcome.
//
// This file compiles to nothing when VectiSerial is not installed.
//
// NEVER COMPILED AGAINST THE REAL VectiSerial — not in CI, not on a bench,
// not once. It is written to VectiSerial's documented API, and because the
// whole body is behind __has_include(<VectiSerial.h>), every build in this
// repository has skipped it entirely. Expect to fix a name or an include
// path on your first real build. What IS compiled and tested here is
// vecti::License in vl_bridge.h, which is where this file's actual logic
// lives. See the README's "What has actually been built and run".

#ifndef VL_BRIDGE_SERIAL_H
#define VL_BRIDGE_SERIAL_H

#if defined(__has_include)
#if __has_include(<VectiSerial.h>)
#define VL_HAVE_VECTISERIAL 1
#endif
#endif

#ifdef VL_HAVE_VECTISERIAL

#include <VectiSerial.h>

#include "vl_bridge.h"

namespace vecti {

inline void licenseSerialStatus(License &lic) {
    char summary[96];
    VectiSerial.inf("license: %s", licenseSummary(lic, summary, sizeof(summary)));
    VectiSerial.inf("license: device id %s", lic.deviceId());
    const vl_license_t *l = lic.license();
    if (!l) { return; }
    VectiSerial.inf("license: serial %lu  family %u  features 0x%08lx",
                    (unsigned long)l->serial, (unsigned)l->family,
                    (unsigned long)l->features);
    VectiSerial.inf("license: not_before %lu  not_after %lu%s",
                    (unsigned long)l->not_before, (unsigned long)l->not_after,
                    l->not_after == 0 ? "  (perpetual)" : "");
    // The honest part: a licence can be cryptographically valid and never have
    // had its dates looked at, because the device has no clock.
    if (!(l->checked & VL_CHECKED_TIME)) {
        VectiSerial.warn("license: validity window NOT checked — no clock on this device");
    }
    if (!(l->checked & VL_CHECKED_HWM)) {
        VectiSerial.debug("license: rollback high-water mark not enforced");
    }
}

// Returns true if `cmd` was a licence command and has been handled.
// AsyncTCP task: queues only.
inline bool licenseSerialCommand(License &lic, const String &cmd) {
    String c = cmd;
    c.trim();
    if (!c.startsWith("license")) { return false; }

    String arg = c.substring(7);
    arg.trim();

    if (arg.length() == 0 || arg == "status") {
        licenseSerialStatus(lic);
        return true;
    }
    if (arg == "id") {
        VectiSerial.inf("license: device id %s", lic.deviceId());
        return true;
    }
    if (arg == "help") {
        VectiSerial.info("license: usage — license [status|id|<160-char key>]");
        return true;
    }
    if (!lic.submit(arg.c_str(), arg.length())) {
        VectiSerial.error("license: rejected — too long, or one is already queued");
        return true;
    }
    VectiSerial.info("license: queued, verifying on the next loop()");
    return true;
}

// Call from loop(). Applies a queued blob and reports the verdict.
inline void licenseSerialLoop(License &lic) {
    if (!lic.pump()) { return; }
    if (lic.ok()) {
        licenseSerialStatus(lic);
    } else {
        VectiSerial.err("license: rejected — %s", lic.statusText());
    }
}

}  // namespace vecti

#endif  // VL_HAVE_VECTISERIAL
#endif  // VL_BRIDGE_SERIAL_H
