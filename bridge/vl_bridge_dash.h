// ---------------------------------------------------------------------------
// VectiLicense × VectiDash — status card, QR of the device id, paste box
// (c) 2026 VectiVolt — Apache-2.0 License
// ---------------------------------------------------------------------------
//
// Three cards:
//   * Status   — licensed / why not, recoloured as the verdict changes
//   * QrCode   — the 26-character device id, so the customer photographs it
//                instead of transcribing it
//   * Textarea — paste the licence back in; onChange hands it to License
//
// Usage:
//
//     #include <VectiDash.h>
//     #include <VectiLicense.h>
//     static vecti::License        license(&CFG, &hal);
//     static vecti::DashLicenseCard card(license);
//
//     void setup() {
//       license.begin();
//       card.attach();                      // before or after VectiDash.begin()
//       VectiDash.begin(&server, "admin", "vecti");
//     }
//     void loop() {
//       license.pump();                     // verify + store, on this task
//       card.loop();                        // repaint when the verdict changes
//       VectiDash.tick();
//     }
//
// This file compiles to nothing when VectiDash is not installed.
//
// NEVER COMPILED AGAINST THE REAL VectiDash — not in CI, not on a bench, not
// once. It is written to VectiDash's documented API, and because the whole
// body is behind __has_include(<VectiDash.h>), every build in this repository
// has skipped it entirely. Expect to fix a name or an include path on your
// first real build. What IS compiled and tested here is vecti::License in
// vl_bridge.h, which is where this file's actual logic lives.
// See the README's "What has actually been built and run".

#ifndef VL_BRIDGE_DASH_H
#define VL_BRIDGE_DASH_H

#if defined(__has_include)
#if __has_include(<VectiDash.h>)
#define VL_HAVE_VECTIDASH 1
#endif
#endif

#ifdef VL_HAVE_VECTIDASH

#include <VectiDash.h>

#include "vl_bridge.h"

namespace vecti {

class DashLicenseCard {
public:
    // `tab` is a VectiDash tab name, or "" to leave the cards on the default
    // page. Card ids are prefixed so they cannot collide with a sketch's own.
    explicit DashLicenseCard(License &lic, const char *tab = "")
        : _lic(lic),
          _state(DashType::Status,   "vl_state", "Licence"),
          _id   (DashType::QrCode,   "vl_id",    "Device ID"),
          _paste(DashType::Textarea, "vl_key",   "Activate"),
          _tab(tab), _shown(VL_ERR_INTERNAL) {}

    void attach() {
        if (_tab.length()) {
            _state.setTab(_tab);
            _id.setTab(_tab);
            _paste.setTab(_tab);
        }
        _id.setValue(_lic.deviceId());
        _paste.setValue("");

        // onChange runs on the loop task, from VectiDash.tick() — so calling
        // activate() here would be legal. It goes through submit() anyway so
        // that every path into License looks the same, and so a 30 ms Ed25519
        // verify plus an NVS write does not happen inside the tick() that is
        // also trying to push updates to every open tab.
        License *lic = &_lic;
        _paste.onChange([lic](const String &payload) {
            lic->submit(payload.c_str(), payload.length());
        });

        _repaint();
        VectiDash.add(&_state);
        VectiDash.add(&_id);
        VectiDash.add(&_paste);
    }

    // Call from loop(), after license.pump(). Repaints only when the verdict
    // actually moved, so it does not mark the cards dirty every pass.
    void loop() {
        if (_shown != _lic.status()) { _repaint(); }
    }

    // The cards, if a sketch wants to retitle or hide one.
    DashCard &stateCard() { return _state; }
    DashCard &idCard()    { return _id; }
    DashCard &pasteCard() { return _paste; }

private:
    void _repaint() {
        char summary[96];
        _state.setValue(licenseSummary(_lic, summary, sizeof(summary)));
        _state.setColor(_lic.ok() ? DashColor::Success : DashColor::Danger);
        _id.setValue(_lic.deviceId());
        if (_lic.ok()) { _paste.setValue(""); }   // don't leave the key sitting there
        _shown = _lic.status();
    }

    License  &_lic;
    DashCard  _state, _id, _paste;
    String    _tab;
    vl_status_t _shown;
};

}  // namespace vecti

#endif  // VL_HAVE_VECTIDASH
#endif  // VL_BRIDGE_DASH_H
