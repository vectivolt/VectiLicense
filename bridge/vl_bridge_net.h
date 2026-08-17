// ---------------------------------------------------------------------------
// VectiLicense × VectiNet — activation in the captive portal
// (c) 2026 VectiVolt — Apache-2.0 License
// ---------------------------------------------------------------------------
//
// The flagship story: a sealed box with no internet and no app. The operator
// joins the device's own SoftAP from a phone, the portal pops up, and the setup
// form already carries
//
//   * a read-only Display field with the 26-character device id and a
//     copy-to-clipboard button — that is what they send you, and
//   * a Textarea to paste the 160-character licence back into.
//
// Activation happens before the device has ever joined a network.
//
// Usage:
//
//     #include <VectiNet.h>
//     #include <VectiLicense.h>
//     static vecti::License          license(&CFG, &hal);
//     static vecti::NetLicensePortal portal(license);
//
//     void setup() {
//       license.begin();
//       portal.attach();            // MUST be before VectiNet.begin()
//       VectiNet.begin(&server);
//       VectiNet.autoConnect();
//     }
//     void loop() {
//       VectiNet.loop();
//       portal.loop();              // notices a paste, hands it to license
//       license.pump();             // verifies + stores it, on this task
//     }
//
// This file compiles to nothing when VectiNet is not installed.
//
// NEVER COMPILED AGAINST THE REAL VectiNet — not in CI, not on a bench, not
// once. It is written to VectiNet's documented API, and because the whole
// body is behind __has_include(<VectiNet.h>), every build in this repository
// has skipped it entirely. Expect to fix a name or an include path on your
// first real build. What IS compiled and tested here is vecti::License in
// vl_bridge.h, which is where this file's actual logic lives.
// See the README's "What has actually been built and run".

#ifndef VL_BRIDGE_NET_H
#define VL_BRIDGE_NET_H

#if defined(__has_include)
#if __has_include(<VectiNet.h>)
#define VL_HAVE_VECTINET 1
#endif
#endif

#ifdef VL_HAVE_VECTINET

#include <VectiNet.h>

#include "vl_bridge.h"

namespace vecti {

class NetLicensePortal {
public:
    // `prefix` namespaces the three NVS keys, in case a sketch already owns
    // something called "vl_key".
    explicit NetLicensePortal(License &lic, const char *prefix = "vl")
        : _lic(lic), _prefix(prefix) {}

    // Adds the parameters. Must run BEFORE VectiNet.begin(), which is when
    // VectiNet freezes the form.
    //
    // The two Display fields are snapshots taken now: VectiNet has no API to
    // rewrite a parameter after begin(), so the status line shows the verdict
    // as of boot. After an activation the operator sees the result on the
    // console / dashboard, or on the next reboot here.
    void attach() {
        NetParam id;
        id.key = _prefix + "_id";
        id.label = "Device ID";
        id.type = NetParamType::Display;
        id.value = _lic.deviceId();
        id.hint = "Send this to your supplier to get a licence key.";
        VectiNet.addParameter(id);

        char summary[96];
        NetParam st;
        st.key = _prefix + "_state";
        st.label = "Licence";
        st.type = NetParamType::Display;
        st.value = licenseSummary(_lic, summary, sizeof(summary));
        st.hint = "As of the last restart.";
        VectiNet.addParameter(st);

        NetParam key;
        key.key = _prefix + "_key";
        key.label = "Licence key";
        key.type = NetParamType::Textarea;
        key.hint = "Paste the 160-character key here and press Save.";
        VectiNet.addParameter(key);
    }

    // Call from loop(). Notices a newly saved key and hands it to License;
    // license.pump() does the verifying. Returns true on the pass where a
    // paste was picked up.
    //
    // Polling rather than hijacking VectiNet.onConfig(), which is a single
    // callback slot the sketch probably wants for itself. paramValue() copies
    // under VectiNet's own mutex, so this is safe while the portal POST is
    // still running on the AsyncTCP task.
    bool loop() {
        String v = VectiNet.paramValue(_prefix + "_key");
        if (v.length() == 0 || v == _last) { return false; }
        _last = v;
        return _lic.submit(v.c_str(), v.length());
    }

private:
    License &_lic;
    String   _prefix;
    String   _last;
};

}  // namespace vecti

#endif  // VL_HAVE_VECTINET
#endif  // VL_BRIDGE_NET_H
