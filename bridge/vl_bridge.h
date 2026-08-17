// ---------------------------------------------------------------------------
// VectiLicense — bridge facade
// (c) 2026 VectiVolt — Apache-2.0 License
// ---------------------------------------------------------------------------
//
// vecti::License — the small amount of state the four VectiSuite bridges all
// need: this device's id string, the current verdict, and a one-slot inbox for
// a blob that arrived on some task where verifying it would be a bad idea.
//
// It is header-only, plain C++11, and does NOT include Arduino.h — so it
// compiles on a host for testing, and so a bridge is the only thing that pulls
// in a sibling library.
//
// Threading, which is the whole reason submit()/pump() exist:
//
//   * VectiSerial's onMessage() and VectiNet's portal POST run on the AsyncTCP
//     task. Verifying there means an Ed25519 verify (~30 ms on an ESP32) and,
//     worse, an NVS write inside blob_store() — a blocking flash erase on the
//     task that is servicing every other socket.
//   * So those paths call submit(), which only memcpy's into one slot and sets
//     a flag. The sketch calls pump() from loop(), which does the verify and
//     the store on the loop task.
//   * VectiDash's onChange already runs on the loop task (from tick()), but it
//     uses the same path so there is one story rather than two.
//
// One slot, one writer: while a blob is pending, submit() returns false rather
// than overwriting a buffer pump() may be reading.
//
// Usage:
//
//     static const vl_pubkey_t KEYS[] = { { .key_id = 1, .key = { ... } } };
//     static const vl_config_t CFG = { KEYS, 1, /*family*/ 2, nullptr, 0, 0 };
//     static vl_hal_t hal = vl_hal_esp32();          // or your own
//     static vecti::License license(&CFG, &hal);
//
//     void setup() { license.begin(); }               // re-verify what's stored
//     void loop()  { license.pump(); }                // apply anything pasted
//
// This gate is a business control, not a security boundary: whoever can
// reflash the device can delete the call to license.ok(). See the header
// comment in include/vectilicense/vectilicense.h.

#ifndef VL_BRIDGE_H
#define VL_BRIDGE_H

#include <stddef.h>
#include <string.h>

#include "vectilicense/vectilicense.h"

// Reached by relative path the same way src/VectiLicense.h reaches bridge/, so
// it resolves with no -I of its own under Arduino, PlatformIO and CMake alike.
// The bridge needs the core's non-elidable wipe: a plain memset() on a buffer
// that is dead afterwards is removed outright by clang -O2 (verified with
// objdump), which would undo the hygiene every core/ buffer gets.
#include "../core/vl_util.h"

// 160 significant characters, plus the dashes/newlines a human paste carries,
// plus the NUL. Anything longer than this is not a licence blob.
#ifndef VL_BRIDGE_BLOB_MAX
#define VL_BRIDGE_BLOB_MAX 224
#endif

namespace vecti {

class License {
public:
    // cfg and hal must outlive this object. Neither is copied: cfg is the
    // firmware's const key set, hal is live hardware.
    License(const vl_config_t *cfg, const vl_hal_t *hal)
        : _cfg(cfg), _hal(hal), _status(VL_ERR_NOT_FOUND),
          _pending_flag(false), _onResult(0), _onResultCtx(0) {
        _devid[0] = '\0';
        _blob[0] = '\0';
        memset(&_lic, 0, sizeof(_lic));
        memset(_pending, 0, sizeof(_pending));
    }

    // ---- identity ---------------------------------------------------------

    // The 26-character device id the customer reads off the screen and sends
    // you, and what you pass to `vl_mint.py issue --device-id`. Computed once
    // and cached — the fingerprint does not change while the device is on.
    // Returns "" if the HAL could not produce one; check idStatus() then.
    const char *deviceId() {
        if (_devid[0] == '\0') {
            uint8_t fp[VL_FINGERPRINT_LEN];
            _idStatus = vl_compute_fingerprint(_hal, fp);
            if (_idStatus == VL_OK) {
                _idStatus = vl_encode_device_id(fp, _devid, sizeof(_devid));
            }
            if (_idStatus != VL_OK) { _devid[0] = '\0'; }
            vl_secure_wipe(fp, sizeof(fp));   // never a plain memset: elided at -O2
        }
        return _devid;
    }
    vl_status_t idStatus() const { return _idStatus; }

    // ---- verdict ----------------------------------------------------------

    bool        ok()         const { return _status == VL_OK; }
    vl_status_t status()     const { return _status; }
    const char *statusText() const { return vl_status_str(_status); }

    // Valid only while ok(). Zeroed otherwise, so a caller that ignores ok()
    // sees no features rather than stale ones.
    const vl_license_t *license() const { return ok() ? &_lic : 0; }
    bool feature(unsigned bit) const { return ok() && vl_has_feature(&_lic, bit) != 0; }

    // Which optional checks actually ran — VL_CHECKED_*. A licence can be
    // cryptographically valid with VL_CHECKED_TIME clear because the device
    // has no clock; if that matters, read this, not just ok().
    uint32_t checked() const { return ok() ? _lic.checked : 0u; }

    // The blob currently in force, or "". Handy for a status page. Always the
    // canonical 160 characters — upper case, Crockford aliases folded, no
    // grouping — not whatever the operator happened to paste, so this string
    // is safe to compare or store as a key.
    const char *blob() const { return _blob; }

    // ---- lifecycle --------------------------------------------------------

    // Load the stored blob (hal->blob_load) and verify it. Call from setup().
    // VL_ERR_NOT_FOUND means "never activated", which is not an error worth
    // logging as one.
    vl_status_t begin() {
        if (!_hal || !_hal->blob_load) { return (_status = VL_ERR_NOT_FOUND); }
        char buf[VL_BLOB_STR_BUF_LEN];
        size_t len = 0;
        vl_status_t st = _hal->blob_load(_hal->ctx, buf, sizeof(buf), &len);
        if (st != VL_OK) { return (_status = st); }
        if (len >= sizeof(buf)) { return (_status = VL_ERR_PLATFORM); }
        buf[len] = '\0';
        return _apply(buf, false);
    }

    // Verify a blob and, if it verifies, persist it. Runs Ed25519 and possibly
    // a flash write: loop task only, never from an AsyncTCP callback.
    //
    // Returns the verify status, except that a licence which verified but
    // could not be stored returns VL_ERR_PLATFORM while ok() stays true — it
    // is in force now and will be gone after the next reboot, and the operator
    // needs to be told that.
    vl_status_t activate(const char *blob) { return _apply(blob, true); }

    // Copy a blob in from any task. Cheap and non-blocking; pump() does the
    // work. false = too long, or a blob is already waiting.
    bool submit(const char *blob, size_t len) {
        if (!blob || len == 0 || len >= sizeof(_pending)) { return false; }
        if (_pending_flag) { return false; }
        memcpy(_pending, blob, len);
        _pending[len] = '\0';
        _pending_flag = true;      // written last: the flag publishes the buffer
        return true;
    }
    bool submit(const char *blob) { return blob ? submit(blob, strlen(blob)) : false; }
    bool pendingSubmission() const { return _pending_flag; }

    // Apply a submitted blob, if there is one. Call from loop(). Returns true
    // when it did something, so a caller can refresh its UI.
    bool pump() {
        if (!_pending_flag) { return false; }
        vl_status_t st = activate(_pending);
        memset(_pending, 0, sizeof(_pending));
        _pending_flag = false;
        if (_onResult) { _onResult(_onResultCtx, st); }
        return true;
    }

    // Called from pump(), on the loop task, with the activation result. One
    // slot, and it belongs to the sketch — the bridges never take it, they
    // poll status() instead.
    void onResult(void (*cb)(void *ctx, vl_status_t st), void *ctx) {
        _onResultCtx = ctx;
        _onResult = cb;
    }

    // Forget the stored licence. Only clears what this object holds plus the
    // HAL slot; it cannot un-sign anything.
    vl_status_t clear() {
        _status = VL_ERR_NOT_FOUND;
        memset(&_lic, 0, sizeof(_lic));
        _blob[0] = '\0';
        if (_hal && _hal->blob_store) { return _hal->blob_store(_hal->ctx, "", 0); }
        return VL_OK;
    }

    // Reported, never enforced. Always populated, even with no HAL support.
    vl_posture_t posture() const {
        vl_posture_t p;
        if (vl_posture(_hal, &p) != VL_OK) {
            p.secure_boot = VL_POSTURE_UNKNOWN;
            p.flash_encryption = VL_POSTURE_UNKNOWN;
        }
        return p;
    }

private:
    vl_status_t _apply(const char *blob, bool persist) {
        vl_license_t lic;
        memset(&lic, 0, sizeof(lic));
        vl_status_t st = vl_verify(blob, _cfg, _hal, &lic);
        if (st != VL_OK) {
            _status = st;
            memset(&_lic, 0, sizeof(_lic));
            _blob[0] = '\0';
            vl_secure_wipe(&lic, sizeof(lic));
            return st;
        }
        _lic = lic;
        // vl_verify wipes its own copy; wiping ours too keeps that meaningful.
        vl_secure_wipe(&lic, sizeof(lic));
        _status = VL_OK;

        // Keep the canonical 160 characters, not the operator's spelling.
        // Stripping the grouping characters is not enough: the decoder is
        // case-insensitive and honours the Crockford aliases I/L->1 and O->0,
        // so one licence has many accepted strings. Anything that keys on
        // blob() — a redeemed-blob list, an activation de-duplicator — would
        // be trivially bypassed by a respelling. Fold them here, which yields
        // exactly what vl_base32_encode() would emit for these 100 bytes.
        size_t n = 0;
        for (const char *p = blob; *p && n < VL_BLOB_STR_LEN; ++p) {
            char c = *p;
            if (c == '-' || c == ' ' || c == '\t' || c == '\r' || c == '\n') { continue; }
            if (c >= 'a' && c <= 'z') { c = (char)(c - 'a' + 'A'); }
            if (c == 'I' || c == 'L') { c = '1'; }
            else if (c == 'O')        { c = '0'; }
            _blob[n++] = c;
        }
        _blob[n] = '\0';

        if (persist && _hal && _hal->blob_store) {
            if (_hal->blob_store(_hal->ctx, _blob, n) != VL_OK) {
                return VL_ERR_PLATFORM;   // in force now, gone after a reboot
            }
        }
        return VL_OK;
    }

    const vl_config_t *_cfg;
    const vl_hal_t    *_hal;

    vl_status_t   _status;
    vl_status_t   _idStatus = VL_OK;
    vl_license_t  _lic;
    char          _devid[VL_DEVICE_ID_STR_BUF_LEN];
    char          _blob[VL_BLOB_STR_BUF_LEN];

    char           _pending[VL_BRIDGE_BLOB_MAX];
    volatile bool  _pending_flag;

    void (*_onResult)(void *, vl_status_t);
    void  *_onResultCtx;
};

// A one-line summary for a status card / console line. Writes into `out` and
// returns it, so it can be used inline.
inline const char *licenseSummary(License &lic, char *out, size_t cap) {
    if (!out || cap == 0) { return ""; }
    const char *state = lic.ok() ? "licensed" : "not licensed";
    const char *why = lic.ok() ? "" : lic.statusText();
    size_t n = 0;
    for (const char *s = state; *s && n + 1 < cap; ++s) { out[n++] = *s; }
    if (*why && n + 3 < cap) {
        out[n++] = ' '; out[n++] = '(';
        for (const char *s = why; *s && n + 2 < cap; ++s) { out[n++] = *s; }
        out[n++] = ')';
    }
    out[n] = '\0';
    return out;
}

}  // namespace vecti

#endif  // VL_BRIDGE_H
