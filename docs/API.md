# VectiLicense API reference

Everything public lives in one header:

```c
#include "vectilicense/vectilicense.h"
```

C99, `extern "C"`-guarded so it links into C and C++ alike. Nothing here allocates,
recurses, blocks, or touches a file. The header itself is the normative source; this
document is the same contract with more room to explain why.

**Contents:** [Constants](#constants) · [Status codes](#status-codes) ·
[`vl_hal_t`](#vl_hal_t) · [`vl_config_t`](#vl_config_t) ·
[`vl_license_t`](#vl_license_t) · [`vl_verify`](#vl_verify) ·
[`vl_compute_fingerprint`](#vl_compute_fingerprint) ·
[`vl_encode_device_id`](#vl_encode_device_id) · [`vl_has_feature`](#vl_has_feature) ·
[`vl_posture`](#vl_posture) · [`vl_status_str`](#vl_status_str) ·
[Core internals](#core-internals) · [Transport helpers](#transport-helpers) ·
[Threading, stack and timing](#threading-stack-and-timing)

---

## Constants

| Macro | Value | Meaning |
|---|---|---|
| `VL_MAGIC` | `0x56` | first payload byte, `'V'` |
| `VL_FORMAT_VERSION` | `0x01` | second payload byte |
| `VL_PAYLOAD_LEN` | 36 | signed payload |
| `VL_SIG_LEN` | 64 | Ed25519 signature |
| `VL_BLOB_BIN_LEN` | 100 | payload + signature |
| `VL_BLOB_STR_LEN` | 160 | significant base32 characters |
| `VL_BLOB_STR_BUF_LEN` | 161 | …plus the NUL. **Size blob buffers with this.** |
| `VL_FINGERPRINT_LEN` | 32 | full SHA-256 of the identity segments |
| `VL_DEVICE_ID_LEN` | 16 | the first half of it, which goes in the payload |
| `VL_DEVICE_ID_STR_LEN` | 26 | device id as base32 |
| `VL_DEVICE_ID_STR_BUF_LEN` | 27 | …plus the NUL |
| `VL_PUBKEY_LEN` | 32 | Ed25519 public key |
| `VL_ID_SEGMENT_MAX` | 255 | largest single identity segment a HAL may return |
| `VL_ID_SEGMENT_COUNT_MAX` | 64 | most segments the fingerprint will read |
| `VECTILICENSE_VERSION_MAJOR/MINOR/PATCH` | 1 / 0 / 0 | |

---

## Status codes

`vl_status_t`. `VL_OK` is 0; **every failure is negative, and no function in this
library returns `VL_OK` on any error path.**

| Code | Value | Meaning | Usually means |
|---|---|---|---|
| `VL_OK` | 0 | success | |
| `VL_ERR_INVALID_ARG` | −1 | NULL or nonsensical argument | a programming error in the integration, not a bad licence |
| `VL_ERR_BUFFER_TOO_SMALL` | −2 | output buffer too small | you passed fewer than `VL_DEVICE_ID_STR_BUF_LEN` bytes |
| `VL_ERR_BAD_FORMAT` | −3 | wrong length, or a byte outside the alphabet | truncated paste, extra characters, a `U`, a smart-quote from a word processor |
| `VL_ERR_BAD_MAGIC` | −4 | not a VectiLicense blob at all | the customer pasted a Wi-Fi password |
| `VL_ERR_BAD_VERSION` | −5 | format newer than this firmware understands | a licence minted by a newer tool; upgrade the firmware |
| `VL_ERR_BAD_FAMILY` | −6 | minted for a different product | right customer, wrong SKU |
| `VL_ERR_UNKNOWN_KEY` | −7 | `key_id` is not in the embedded key set | the key was rotated out, or the firmware predates the key |
| `VL_ERR_BAD_SIGNATURE` | −8 | the signature did not verify | forgery, corruption, or the wrong vendor key in the build |
| `VL_ERR_DEVICE_MISMATCH` | −9 | minted for a different device | a copied licence — or a repaired board whose identity changed |
| `VL_ERR_NOT_YET_VALID` | −10 | `now < not_before` | the clock is wrong, or the licence starts later |
| `VL_ERR_EXPIRED` | −11 | `now > not_after` | genuinely expired, or the clock is wrong |
| `VL_ERR_REVOKED` | −12 | the serial is on the deny-list | you revoked it; check your records before telling the customer |
| `VL_ERR_CLOCK_ROLLBACK` | −13 | `now` is below the stored high-water mark | the clock moved backwards; also what a dead RTC battery looks like |
| `VL_ERR_NO_CLOCK` | −14 | a time check was required and there is no clock | you set `VL_FLAG_REQUIRE_CLOCK` on a device with no `now_epoch` |
| `VL_ERR_PLATFORM` | −15 | a HAL callback failed | the hardware could not answer; never treat as "unlicensed" without logging it |
| `VL_ERR_NO_MORE_SEGMENTS` | −16 | **HAL sentinel**: end of the identity list | never returned to the application from `vl_verify()` |
| `VL_ERR_NOT_FOUND` | −17 | `blob_load`: nothing is stored | "never activated", which is not an error worth logging as one |
| `VL_ERR_INTERNAL` | −18 | an invariant broke | should not happen; please report it |

Pass any of these to `vl_status_str()` for a human-readable string.

---

## `vl_hal_t`

One struct of function pointers. It is the entire platform boundary: everything the
core needs from the outside world arrives through it, and the core reads nothing else.

```c
typedef struct vl_hal {
    vl_status_t (*read_id_segment)(void *ctx, uint32_t idx,
                                   uint8_t *out, size_t cap, size_t *out_len);
    vl_status_t (*now_epoch)(void *ctx, uint32_t *out_epoch);
    vl_status_t (*hwm_load)(void *ctx, uint32_t *out);
    vl_status_t (*hwm_store)(void *ctx, uint32_t value);
    vl_status_t (*blob_load)(void *ctx, char *out, size_t cap, size_t *out_len);
    vl_status_t (*blob_store)(void *ctx, const char *blob, size_t len);
    vl_status_t (*secure_posture)(void *ctx, vl_posture_t *out);
    void *ctx;
} vl_hal_t;
```

**Only `read_id_segment` is required.** Every other member may be NULL, and the core
behaves correctly in all 64 combinations — there is a test matrix asserting exactly
that. Callbacks must not allocate and must not block indefinitely. Anything other than
`VL_OK` (or the documented sentinel) is a hard failure and `vl_verify()` fails closed.

### `read_id_segment` — required

Enumerate this device's hardware identity, `idx` = 0, 1, 2, …

| Return | Meaning |
|---|---|
| `VL_OK` | wrote `*out_len` bytes to `out`; `*out_len` **must** be ≤ `cap` |
| `VL_ERR_NO_MORE_SEGMENTS` | the list ends here. This, not `VL_ERR_INVALID_ARG` |
| anything else | a read failed; the fingerprint fails closed with that status |

A zero-length segment is legal and hashes as a single `0x00` length byte. A HAL that
sets `*out_len > cap` gets `VL_ERR_PLATFORM` rather than causing an overread.

Segments are hashed **in order, each with a one-byte length prefix**, so `{"AB","C"}`
and `{"A","BC"}` differ. The set and the order are part of the on-wire format; changing
either invalidates every licence already issued. See [`PORTING.md`](PORTING.md).

### `now_epoch` — optional

Wall-clock seconds since the Unix epoch. **NULL is a supported, documented state:**
validity windows are not enforced and `vl_verify()` reports that it could not check them
by leaving `VL_CHECKED_TIME` clear. Set `VL_FLAG_REQUIRE_CLOCK` to get `VL_ERR_NO_CLOCK`
instead.

Return an error rather than a plausible value if the clock was never set. A `now_epoch`
that answers 0 is worse than no `now_epoch` at all.

### `hwm_load` / `hwm_store` — optional, both or neither

Monotonic high-water mark for clock-rollback protection, in non-volatile storage.
Only consulted when `VL_FLAG_ENFORCE_HWM` is set; setting that flag without **all
three** of `now_epoch`, `hwm_load` and `hwm_store` is `VL_ERR_INVALID_ARG`, never a
silent downgrade. `hwm_store` is called only when the clock has actually advanced past
the stored mark.

`now_epoch` is part of that requirement because a mark is only ever compared against a
clock: with `now_epoch` NULL the whole time step is skipped, so the flag would buy
nothing *and* an expired licence would return `VL_OK`. On a clockless board, rollback
protection is not available in a weaker form — it is not available.

### `blob_load` / `blob_store` — optional

Persist the activated blob. **`vl_verify()` never calls either** — it is handed a blob;
storage is the application's business. They live in the HAL so that the bridges and
examples have one place to find them. `blob_load` returns `VL_ERR_NOT_FOUND` when
nothing is stored. Give `blob_load` at least `VL_BLOB_STR_BUF_LEN` of capacity.

### `secure_posture` — optional

Report whether the platform has a verified boot chain. Reporting only; the core never
enforces it. See [`vl_posture`](#vl_posture).

### `ctx`

Passed to every callback, never inspected by the core.

---

## `vl_config_t`

Everything static about a firmware image. Build one `const` instance and pass its
address; it is never written to.

```c
typedef struct {
    const vl_pubkey_t *keys;
    size_t             key_count;
    uint8_t            family;
    const uint32_t    *revoked_serials;
    size_t             revoked_count;
    uint32_t           flags;
} vl_config_t;

typedef struct { uint8_t key_id; uint8_t key[VL_PUBKEY_LEN]; } vl_pubkey_t;
```

| Field | Contract |
|---|---|
| `keys`, `key_count` | Required, non-NULL, non-zero. Looked up by `key_id`; order is irrelevant. Carrying more than one is how rotation works. |
| `family` | Must equal the payload's family byte or the licence is refused before any crypto runs. |
| `revoked_serials`, `revoked_count` | Optional. NULL **or** count 0 disables the check, and `VL_CHECKED_REVOCATION` then stays clear. Order irrelevant — the scan is linear on purpose. |
| `flags` | `VL_FLAG_REQUIRE_CLOCK` (0x1), `VL_FLAG_ENFORCE_HWM` (0x2), OR-ed. |

---

## `vl_license_t`

Populated **only** on `VL_OK`. On any failure the output struct is zeroed, so a caller
that ignores the return code sees no features rather than stale ones.

```c
typedef struct {
    uint8_t  version, key_id, family;
    uint32_t features;
    uint8_t  device_id[VL_DEVICE_ID_LEN];
    uint32_t not_before, not_after, serial;
    uint32_t checked;
} vl_license_t;
```

`checked` is a bitmask of which optional checks actually ran:

| Bit | Set when |
|---|---|
| `VL_CHECKED_SIGNATURE` | always, on `VL_OK` |
| `VL_CHECKED_DEVICE` | always, on `VL_OK` |
| `VL_CHECKED_TIME` | the HAL had a clock and the window was enforced |
| `VL_CHECKED_REVOCATION` | a non-empty deny-list was configured and consulted |
| `VL_CHECKED_HWM` | `VL_FLAG_ENFORCE_HWM` was set — which now implies a clock, since the flag is refused without `now_epoch` |

**Read this, not just the return code.** A licence can be cryptographically perfect and
have had its expiry entirely unchecked because the device has no RTC. `VL_OK` means
"every applicable check passed", and `checked` is what tells you which were applicable.

---

## `vl_verify`

```c
vl_status_t vl_verify(const char *blob,
                      const vl_config_t *cfg,
                      const vl_hal_t *hal,
                      vl_license_t *out);
```

The whole library. `out` may be NULL if you only want the verdict.

`blob` is NUL-terminated Crockford base32 with 160 significant characters. `-`, space,
tab, CR and LF may appear anywhere as grouping and are ignored; the input is
case-insensitive and the Crockford aliases `I`/`l` → `1` and `O` → `0` are accepted.
Decoding is strict about everything else: exactly 100 bytes out, canonical trailing pad
bits. Input is bounded — a hostile or unterminated buffer is rejected, not scanned
forever.

**The decoded bytes are canonical; the string is not.** Those aliases, plus case and
grouping characters, mean one licence has many accepted spellings — a blob with *k*
characters from `{0,1}` has at least 2^*k* of them, all decoding to the same 100 bytes
and all verifying. No forgery follows: the payload and the signature are fixed, and
revocation is by serial. But **anything that keys on the string** — a redeemed-blob
list, an activation de-duplicator — must canonicalise first by decoding and re-encoding
with `vl_base32_encode()`, not by stripping dashes, or it is trivially bypassed.

**Checks run in this order and stop at the first failure:**

1. Arguments — `VL_ERR_INVALID_ARG`
2. Length and alphabet — `VL_ERR_BAD_FORMAT`
3. Magic, version, family, key lookup — `VL_ERR_BAD_MAGIC` / `_BAD_VERSION` /
   `_BAD_FAMILY` / `_UNKNOWN_KEY`
4. **Ed25519 signature** over `"vectilicense:v1" || 0x00 || payload[0..35]` —
   `VL_ERR_BAD_SIGNATURE`
5. Device fingerprint, compared in constant time — `VL_ERR_DEVICE_MISMATCH`, or
   `VL_ERR_PLATFORM` if the HAL could not answer
6. Revocation — `VL_ERR_REVOKED`
7. Validity window — `VL_ERR_NOT_YET_VALID` / `VL_ERR_EXPIRED` / `VL_ERR_NO_CLOCK` /
   `VL_ERR_PLATFORM`
8. Clock high-water mark — `VL_ERR_CLOCK_ROLLBACK` / `VL_ERR_PLATFORM`

Steps 1–3 are the cheap ones and run **before any crypto**, which is what stops a
hostile blob from costing a full signature verification per attempt. Step 4 before step 5 is deliberate:
a forged blob and a foreign device are indistinguishable from the status code, so there
is no oracle to walk.

Every buffer that held a fingerprint or a decoded payload is wiped before return
through a construct the optimiser may not elide.

```c
vl_license_t lic;
vl_status_t st = vl_verify(blob, &CFG, hal, &lic);
if (st != VL_OK) {
    log_warn("unlicensed: %s", vl_status_str(st));
} else if (vl_has_feature(&lic, FEATURE_MODBUS)) {
    enable_modbus();
}
```

---

## `vl_compute_fingerprint`

```c
vl_status_t vl_compute_fingerprint(const vl_hal_t *hal,
                                   uint8_t out_fingerprint[VL_FINGERPRINT_LEN]);
```

`SHA-256("vectilicense:fingerprint:v1" || (len_u8 || segment)*)` over every segment the
HAL yields, in order. The domain prefix means a bare SHA-256 of a MAC address computed
elsewhere can never collide with a device id.

Returns `VL_ERR_INVALID_ARG` for a NULL `hal`, a NULL `read_id_segment` or a NULL
output; `VL_ERR_PLATFORM` if the HAL yields no segments at all, or claims to have
written more than `cap`; otherwise whatever error the HAL returned. On any failure the
output buffer is wiped, not left half-written.

`vl_verify()` calls this itself. You call it directly to show the customer their device
id.

---

## `vl_encode_device_id`

```c
vl_status_t vl_encode_device_id(const uint8_t fingerprint[VL_FINGERPRINT_LEN],
                                char *out, size_t out_capacity);
```

Encodes the first 16 bytes of a fingerprint as 26 Crockford base32 characters — what the
customer reads off the screen and what you pass to `vl_mint.py issue --device-id`.

`out_capacity` must be at least `VL_DEVICE_ID_STR_BUF_LEN` (27) or you get
`VL_ERR_BUFFER_TOO_SMALL`. NULL arguments give `VL_ERR_INVALID_ARG`.

---

## `vl_has_feature`

```c
int vl_has_feature(const vl_license_t *lic, unsigned bit);
```

Is feature bit 0…31 set? Returns 0 for a NULL licence, for `bit > 31`, and for a clear
bit. There is deliberately no error return: an unreadable licence has no features.

Only meaningful on a `vl_license_t` that `vl_verify()` filled in on a `VL_OK` — which is
safe by construction, because a failed verify zeroes the struct.

---

## `vl_posture`

```c
typedef enum { VL_POSTURE_UNKNOWN = 0, VL_POSTURE_OFF = 1, VL_POSTURE_ON = 2 }
    vl_posture_state_t;
typedef struct { vl_posture_state_t secure_boot, flash_encryption; } vl_posture_t;

vl_status_t vl_posture(const vl_hal_t *hal, vl_posture_t *out);
```

Reports whether the platform has a hardware root of trust. **Information, never
enforcement.**

Fails soft: with a NULL `hal`, or a HAL with no `secure_posture`, both fields are
`VL_POSTURE_UNKNOWN` and the return is `VL_OK` — "unknown" is a truthful answer, not a
failure. `VL_ERR_INVALID_ARG` only for a NULL `out`; `VL_ERR_PLATFORM` if the callback
itself failed, in which case both fields are reset to `UNKNOWN` rather than left
half-filled.

Deciding that an unprotected device should not honour a licence is your call, and a
defensible one: without Secure Boot and Flash Encryption an attacker can simply patch
the branch that reads `vl_verify()`'s result. See
[`THREAT_MODEL.md`](THREAT_MODEL.md).

---

## `vl_status_str`

```c
const char *vl_status_str(vl_status_t status);
const char *vl_version_str(void);
```

`vl_status_str()` never returns NULL — not for a valid code, not for a garbage int
(`"unknown status"`). Safe to call directly inside a log format string.
`vl_version_str()` returns e.g. `"vectilicense/1.0.0"`.

---

## Core internals

Not in the public header, but available if you add `core/` to your include path. Stable
enough to use; documented here because the test suite does.

```c
#include "vl_ed25519.h"
int vl_ed25519_verify(const uint8_t sig[64], const uint8_t *msg, size_t len,
                      const uint8_t pk[32]);   /* 1 = valid, 0 = everything else */
```

Verification only. There is no signing function in this translation unit and none
anywhere in the device build — that code was deleted, not disabled. Returns 0 for NULL
arguments, for a public key that is not a point on the curve, and for an unreduced
scalar `S`; there is no third state.

```c
#include "vl_util.h"
void vl_secure_wipe(void *p, size_t len);        /* not elided at -O2 */
int  vl_ct_eq(const void *a, const void *b, size_t len);  /* 1 iff equal */
```

`vl_ct_eq` returns 0 — "not equal" — for a NULL pointer or a zero length: it fails
closed rather than matching vacuously.

`vl_base32.h`, `vl_sha256.h` and `vl_sha512.h` are likewise available and likewise
freestanding.

---

## Transport helpers

Optional, and needed for exactly two situations. `vl_verify()` takes a string, so HTTP,
MQTT, BLE, files and QR scans need no helper at all. Full detail in
[`transport/README.md`](../transport/README.md) and the headers.

```c
#include "vl_line.h"          /* UART / USB-CDC / telnet: bytes in, one line out */
void        vl_line_reset(vl_line_t *l);
vl_status_t vl_line_push(vl_line_t *l, char ch);   /* VL_OK = a line is ready */

#include "vl_chunk.h"         /* CAN / ISO-TP / BLE GATT: MTU-limited reassembly */
vl_status_t vl_chunk_reset(vl_chunk_t *c, size_t chunk_size, size_t total_len);
vl_status_t vl_chunk_feed(vl_chunk_t *c, uint32_t seq, const void *data, size_t len);
vl_status_t vl_chunk_complete(const vl_chunk_t *c, char *out, size_t cap, size_t *n);
```

Both follow core rules: no allocation, bounded, tolerant of duplicates and gaps.

---

## Threading, stack and timing

**Reentrancy.** `core/` has no writable static state. `vl_verify()` is reentrant as
long as your HAL callbacks are; the `vl_config_t` is const and never written. Two
threads may verify different blobs simultaneously.

**Stack.** Measured with `-fstack-usage` on Cortex-M0+ at `-Os`, the deepest chain
through `vl_verify()` is **4,376 bytes**: `vl_verify` 264 → `vl_ed25519_verify` 2,544 →
`scalarmult` 32 → `add` 1,184 → `M` 304 → `car25519` 48. Give the calling task at least
5 KB.

**Time.** One `vl_verify()` measures **2.8 ms on an Apple M1 Pro at -O2** (1,000
iterations, wall clock / 1,000). On a 240 MHz ESP32 expect tens of milliseconds and on a Cortex-M0+
hundreds; those two are estimates, not measurements. Call `vl_verify()` at boot or from
a work task — **never from an interrupt handler, and never from a network stack's
callback.** The bridges enforce this split: paste handlers only queue, and `pump()` on
the loop task does the verify and the flash write.

**Constant time.** The device-id comparison is constant-time and the vendored field
arithmetic is constant-time. There is nothing secret on the device to leak — the key is
public — so this is defence in depth rather than the main event.
