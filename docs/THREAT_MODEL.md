# VectiLicense threat model

**Read this before shipping.** VectiLicense is a small piece of crypto inside a much
bigger system. It can only help you if you understand exactly what it does and — more
importantly — what it does not do.

This document does not use the words "unbreakable", "uncrackable", or "military-grade",
because none of them would be true.

---

## The one thing v1 changes

VectiLicense v1 replaces a **symmetric** scheme with an **asymmetric** one. That single
change eliminates the class of attack that made the previous version, v0.1, unfit
for revenue-critical features: the keygen.

### Why v0.1 had a keygen

v0.1 verified a licence by *recomputing it*:

```
expected = HMAC-SHA256(vendor_salt, "<product>\x00v1" || family || device_id)
accept if expected[0..9] == truncate(base32_decode(user_typed))
```

The device cannot recompute `expected` without `vendor_salt`. So `vendor_salt` — all 32
bytes of it — had to be present in every firmware image the vendor ever shipped. And
the minting function derived a code from exactly the same three inputs with exactly the
same call.

**The value that checks a licence and the value that mints one are the same value.**

In practice that means:

```bash
esptool.py --port /dev/ttyUSB0 read_flash 0x0 0x400000 dump.bin
# high-entropy 32-byte run in a sea of low-entropy firmware — trivially findable
strings/binwalk/entropy scan → vendor_salt
```

One flash dump, from one device, from one customer, and the attacker can mint a valid
code for **every device in that family that the vendor will ever ship**. Not a
per-device bypass — a universal keygen. Posting the salt on a forum ends licensing for
that product line permanently, and the only fix is a salt rotation that invalidates
every licence already in the field.

Obfuscating the salt does not fix this. Splitting it across the image, XOR-masking it,
deriving it at boot — all of it is recoverable by anyone who can single-step the
verification, because the verification must reconstruct the real salt to work at all.
It is a structural property of symmetric MACs, not an implementation defect.

### Why v1 cannot have a keygen

v1 verifies a licence by **checking an Ed25519 signature**:

```
signed_message = "vectilicense:v1" || 0x00 || payload[0..35]
accept if Ed25519_Verify(vendor_public_key, signed_message, signature[0..63])
```

The firmware holds `vendor_public_key` — 32 bytes that are *not a secret*. The private
key that produces signatures never enters the firmware, never enters this repository,
and never leaves the vendor's key store.

Dump the flash and you get the public key. Recovering the private key from it is the
Ed25519 discrete-log problem on Curve25519 (~2^128 work). No amount of firmware
reverse-engineering shortens that, because **the secret is not in the firmware to
begin with.** There is nothing to extract.

Concretely, after a full flash dump an attacker still cannot:

| Attack | Why it fails |
|---|---|
| Mint a licence for their own device | Requires a signature over their `device_id`; requires the private key. |
| Turn on features they did not buy | `features` is inside the signed payload. Change a bit, the signature fails. |
| Extend an expiry | `not_after` is inside the signed payload. Same. |
| Reuse a friend's licence | `device_id` is bound to the local fingerprint and compared in constant time. |
| Replay a licence from a different product | `family` is inside the signed payload and checked against the caller's family. |
| Replay a VectiLicense signature into another protocol using the same vendor key | The domain-separation prefix `"vectilicense:v1"\|\|0x00` is part of every signed message. |
| Truncate/pad/mutate the blob to slip past parsing | Length, alphabet, magic, version and key id are validated **before** any crypto runs; every failure path returns an error, never `VL_OK`. |
| Time the comparison to learn the expected value | There is no expected value to learn — verification is a signature check, and the device-id compare is constant-time. |

That is the whole of what v1 buys you. It is a real, structural improvement, and it is
also not the same thing as "uncrackable".

---

## What v1 does NOT defend against

### 1. Firmware patching — the honest limit

An attacker who can rewrite the firmware can delete the check.

```c
if (vl_verify(blob, &CFG, hal, &lic) == VL_OK) {
    unlock();          /*  ← attacker patches the branch, or NOPs the call, */
}                      /*    or flips the compare, and unlock() runs always. */
```

This is not a weakness in Ed25519, in this library, or in its implementation. It is
what "the attacker owns the hardware" means. **Every** software licensing scheme ever
written has this property — FlexLM, Sentinel, Denuvo, and this library alike. If the
code that decides runs on a machine the attacker controls, the attacker can change the
decision.

Do not let anyone tell you otherwise, and do not price a product on the assumption
that this is solved.

What v1 does change is the *economics*. Bypassing v0.1 was: dump one device, publish 32
bytes, everyone else copy-pastes a code. Bypassing v1 is: reverse-engineer this
specific firmware build, locate the call site, patch it, re-flash — per firmware
version, and per person who lacks the skill to do it themselves. That is a materially
higher bar and a much smaller blast radius, but it is a speed bump, not a wall.

### 2. Fingerprint spoofing

The device id is the first 16 bytes of a SHA-256 over whatever hardware identity
segments the HAL yields. How forgeable that is depends entirely on the platform, and it
is the single biggest variable in how much this library is worth to you:

| HAL | Identity | Forgeable by |
|---|---|---|
| `hal/esp32` | eFuse base MAC + chip model/revision + SPI flash JEDEC id | burning eFuses on the target board, which is one-way, and matching the flash part. Strong. |
| `hal/stm32` | 96-bit factory UID, read-only | replacing the MCU. Strong. |
| `hal/nxp` | Kinetis `SIM->UIDx` (128/96-bit) or i.MX RT OCOTP (64-bit), read-only | replacing the MCU. Strong. |
| `hal/rp2040` | QSPI flash chip unique id | moving the flash chip — which also moves the licence, correctly. Note the id lives in the flash part, not the RP2040. |
| `hal/posix` | interface MAC + `/etc/machine-id` (+ Pi/DMI serial) | `ip link set dev eth0 address ...` plus a cloned filesystem. **Weak.** |
| `hal/none` | nothing — it fails closed on purpose | n/a, and do not "fix" it by returning a constant |

The ESP32 HAL reads `esp_efuse_mac_get_default()`, the eFuse MAC, not the
runtime-overridable `esp_wifi_set_mac()` copy — that distinction is the difference
between a fingerprint and a suggestion.

On a general-purpose OS, be honest with yourself: **a cloned SD card image with a
spoofed MAC reproduces the fingerprint,** and there is nothing userspace can do about
it. On Linux, treat the device id as a deterrent, not a boundary.

If your device id can be forged, one purchased licence replays across a fleet. That is
a fleet-wide loss but still not a keygen: the attacker can only clone a device they
have already bought a licence for, and the serial on that licence identifies whose it
was — which is what the revocation list is for.

**The segment set is part of the on-wire format.** Adding, removing or reordering a
segment changes every fingerprint and invalidates every licence already issued. Decide
before your first shipment.

### 3. Clock rollback, and having no clock at all

`not_after` is compared against whatever `hal->now_epoch` reports. Set the clock back,
and an expired licence works again.

Two knobs, both off by default, both documented loudly because both can bite:

- `VL_FLAG_ENFORCE_HWM` — the device remembers the highest timestamp it has ever seen
  (`hwm_load`/`hwm_store`, NVS on ESP32) and refuses anything earlier. It makes rollback
  annoying, not impossible, for an attacker who can also write that storage. It can also
  strand a unit whose RTC battery died, which is why it is opt-in. Asking for it without
  supplying `now_epoch`, `hwm_load` **and** `hwm_store` is `VL_ERR_INVALID_ARG`, never a
  silent downgrade to "no protection" — a mark with no clock to compare it against is
  not weaker rollback protection, it is none.
- `VL_FLAG_REQUIRE_CLOCK` — refuse outright when there is no clock.

**The default with no clock is the one to understand.** If `hal->now_epoch` is NULL,
`vl_verify()` does *not* enforce the validity window, returns `VL_OK` for an expired
licence, and reports that it could not check by leaving `VL_CHECKED_TIME` clear in
`lic.checked`. That is the documented contract, not an oversight — a device with no RTC
would otherwise have to reject every time-limited licence it was ever issued. If you
sell subscriptions, either read `lic.checked` or set `VL_FLAG_REQUIRE_CLOCK`. Reading
only the return code is how an expiry quietly stops being enforced.

If expiry matters commercially, back it with something the device cannot lie about: a
server check-in at renewal time, or a hardware RTC the user cannot reach.

### 4. Denial of service against your own customers

The failure mode that will actually cost you money is not piracy. It is a legitimate
customer whose device stops working because the RTC drifted, or the eFuse MAC changed
after a board repair, or a NIC was swapped. **Fail closed on the crypto; fail open on
the business policy.** Warn, grace-period, and log — do not brick. See
[`INTEGRATION.md`](INTEGRATION.md#enforcement-policy).

### 5. Side channels beyond timing

The vendored Ed25519 verify uses constant-time field arithmetic and the device-id
compare is constant-time, so straightforward timing attacks are covered. Power
analysis, EM, fault injection and glitching against a device physically in the
attacker's hands are **not** in scope. They also would not help much here: the only
secret involved is on the vendor's machine, not the device's.

### 6. Supply-chain compromise of the vendor's key

If the Ed25519 private key leaks, the attacker becomes you. This is now the single
point of failure for the whole scheme — v1 concentrates all the risk into one file
that lives in exactly one place, which is a much better position than v0.1's "every
firmware image contains the mint key", but it means key hygiene is not optional:

- Generate on an offline or at least non-shared machine.
- `chmod 0600`. `tools/vl_mint.py` refuses to run on a group- or world-readable key.
- Never commit it. Never put it in CI unless CI is the signing service and the key is
  in a secrets manager or an HSM.
- Provision multiple `key_id`s from day one so rotation is a config change, not a
  recall. See [`INTEGRATION.md`](INTEGRATION.md#key-rotation).

---

## What the implementation is, precisely

Claims about a licensing scheme are worth what its implementation is worth, so:

**The vendored crypto.** TweetNaCl 20140427, public domain, with signing, key
generation, `randombytes`, Salsa20, Poly1305 and Curve25519 **deleted** — not
`#ifdef`ed out. There is no signing code in the device build to re-enable. Two
deliberate divergences from upstream, both in `core/vl_ed25519.c`'s header:

- **Added:** an unreduced signature scalar `S` is rejected, closing signature
  malleability. Upstream accepts it.
- **Added:** the message is streamed into SHA-512 instead of being copied into a
  message-sized scratch buffer. That is what makes verification fit in 4 KB of stack.
- **Not changed:** like upstream, non-canonical encodings of `A` and `R` are accepted
  and there is no cofactor-cleared check. This is RFC 8032 "verify", not ZIP-215. With
  one vendor key and no consensus protocol, that distinction has no effect here — but
  do not lift this file into a blockchain.

**Fail-closed discipline.** No function returns `VL_OK` on any error path. Length,
alphabet, magic, version, family and key id are all validated *before* any crypto runs.
Every buffer that held a fingerprint is wiped through a `volatile` function pointer that
`-O2` cannot elide. A HAL that claims it wrote more bytes than the buffer holds gets
`VL_ERR_PLATFORM`, not an overread.

**What the test suite actually proves.** Not "the tests pass" — these specific things:

- Ed25519 verify matches the RFC 8032 §7.1 vectors, including the 1023-octet case that
  spans several SHA-512 blocks; SHA-256/512 match FIPS 180-4 including the 1,000,000-`a`
  cases.
- Every one of the **800 single-bit mutations** of a valid blob is refused. This is the
  test that proves the signature is genuinely being checked rather than the payload
  merely parsed.
- A signature that is perfectly valid *for a different payload* is refused, in both
  directions — genuine vendor output, forged only in the pairing.
- Every truncation and every over-long extension, every position poisoned with every
  class of out-of-alphabet byte, and a licence signed over the payload *without* the
  domain-separation prefix: all refused.
- All 64 combinations of the optional HAL callbacks being present or absent, against
  three flag settings, produce a documented status and no crash.
- A mutation fuzzer under AddressSanitizer and UndefinedBehaviorSanitizer asserts the
  strong form of "no false accept": anything that returns `VL_OK` must decode to
  *exactly* the 100 bytes the vendor signed. Counting `VL_OK`s would be too weak, since
  a licence respelled in lowercase or split into hyphenated groups is the same licence.

None of that says the scheme cannot be bypassed by patching the firmware. It says the
crypto does what it claims, which is a smaller and more checkable statement.

---

## The only real mitigation: Secure Boot v2 + Flash Encryption

Section 1 above — firmware patching — has exactly one genuine answer on ESP32, and it
is not in this library. It is in the silicon.

- **Secure Boot v2** puts the RSA-PSS public-key digest in eFuses. The ROM bootloader
  refuses to run any image not signed by your key. A patched image does not boot.
- **Flash Encryption** encrypts the flash contents with a key in eFuses that software
  cannot read. A flash dump yields ciphertext; the attacker cannot even *read* your
  firmware to find the call site, let alone modify it.

Together they move the root of trust from "bytes in a flash chip anyone can rewrite" to
"eFuses that are physically one-way". **Without them, VectiLicense is a speed bump
against casual copying. With them, defeating it requires an attack on the ESP32 silicon
itself.**

### Enabling it

Both are irreversible. Burning eFuses on a production board cannot be undone; a mistake
bricks the unit. Test the whole flow on a sacrificial devkit first, and keep the signing
key backed up — losing it means you can never OTA that fleet again.

```bash
# 1. Generate a Secure Boot v2 signing key. Back this up. Losing it is terminal.
espsecure.py generate_signing_key --version 2 secure_boot_signing_key.pem

# 2. Enable both in the project config.
idf.py menuconfig
#   Security features →
#     [*] Enable hardware Secure Boot in bootloader        (Secure Boot V2)
#         (secure_boot_signing_key.pem)  Secure boot private signing key
#     [*] Enable flash encryption on boot
#         Enable usage mode → Release        # Development mode allows re-flashing
#                                            # with a plaintext image; Release does not.

# 3. Build and flash once over USB. This burns the eFuses on first boot.
idf.py bootloader
idf.py build
idf.py -p /dev/ttyUSB0 flash monitor

# 4. Confirm from the firmware itself (VectiLicense exposes this — report it, do not
#    silently enforce it):
#      esp_secure_boot_enabled()        -> true
#      esp_flash_encryption_enabled()   -> true
```

Read the vendor docs end to end before you burn anything:
<https://docs.espressif.com/projects/esp-idf/en/stable/esp32/security/secure-boot-v2.html>
and
<https://docs.espressif.com/projects/esp-idf/en/stable/esp32/security/flash-encryption.html>

On Linux/Raspberry Pi the equivalent posture is verified boot plus a signed, read-only
root filesystem (e.g. RAUC or dm-verity). A stock Raspberry Pi OS image on a removable
SD card offers no such guarantee, and no amount of userspace licensing changes that.

---

## Risk-tier guidance

| Situation | What is appropriate |
|---|---|
| Free / no revenue at stake | Do not license. The support burden exceeds the benefit. |
| Sub-$1k unit, casual copying is the concern | v1 alone. Honest, cheap, effective against the actual threat. |
| $1k–$10k unit, or any expiring / tiered SKU | v1 + Flash Encryption, and think hard about clock rollback. |
| $10k+ unit, or a competitor with a real reverse-engineering budget | v1 + Secure Boot v2 + Flash Encryption (Release mode). Nothing less is meaningful. |
| Safety-critical or regulated (medical, automotive, grid) | None of this is a substitute for a security review by someone qualified. Hire one. |

---

## Reporting a vulnerability

Email <team@vectivolt.com>. If you have found a way to make `vl_verify()` return
`VL_OK` for a blob the vendor key did not sign, that is a genuine break of this
library's stated guarantee and we want to know immediately. If you have found that
patching out the call site bypasses the check — that is documented above, on purpose,
and is not a vulnerability in this library.
