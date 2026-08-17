# Porting VectiLicense to a new MCU

You write **one function**. Everything else in this document is either optional or a
warning about a mistake that is expensive to discover later.

`core/` is freestanding C99 — `<stdint.h>` and `<stddef.h>` and nothing else. **No
`<string.h>`**: that is a *hosted* header (C99 §4p6 lists exactly seven freestanding
headers and string.h is not one of them), and real bare-metal toolchains do not ship
it — `arm-none-eabi-gcc` installs `stddef.h` and `stdint.h` but no libc at all. Core
declares the three functions it needs (`memcpy`, `memset`, `memcmp`) itself, in
`core/vl_libc.h`, and includes `<string.h>` only when `__STDC_HOSTED__` says a libc
is actually there. Your runtime still has to *provide* those three symbols — every
bare-metal runtime does, and the compiler emits calls to them from ordinary struct
assignment whether or not this library asks for them.

No `malloc`, no `stdio`, no `time.h`, no floats, no VLAs, no recursion, no RTOS call,
no vendor header. If your compiler is conforming, the core already builds. The port is
the HAL.

Budget: 20 minutes if your part has a documented unique ID, an hour if you have to go
find one.

---

## 0. Check the core builds for your target first

Two minutes, and it tells you whether anything else is worth doing.

```bash
arm-none-eabi-gcc -std=c99 -Os -ffreestanding -mcpu=cortex-m0plus -mthumb \
    -nostdinc -isystem "$(arm-none-eabi-gcc -print-file-name=include)" \
    -Wall -Wextra -Werror -Wpedantic -Wconversion -Wsign-conversion \
    -Iinclude -Icore -c core/vl_*.c
```

Swap the `-mcpu` for your part. The `-nostdinc -isystem …` pair is what makes this an
honest test: it removes the libc search path and puts back exactly the headers a
freestanding implementation is *required* to provide, so a stray hosted `#include`
fails here instead of on your bench. Without it the check passes on any toolchain that
happens to bundle newlib, which is most of them and none of the interesting ones.

That exact command is run in this repository for Cortex-M4 and Cortex-M0+ and produces
zero diagnostics. It is not a claim in a document — it is `ctest` cases
`freestanding_cortex-m4` and `freestanding_cortex-m0plus`, which run automatically
whenever `arm-none-eabi-gcc` is on `PATH` and cover `transport/` as well as `core/`.

Budget 9 KB of flash, 0 bytes of static RAM, and 5 KB of stack for whatever task calls
`vl_verify()`.

---

## 1. Copy the stub

```bash
cp -r hal/none hal/myboard
mv hal/myboard/vl_hal_none.c hal/myboard/vl_hal_myboard.c
mv hal/myboard/vl_hal_none.h hal/myboard/vl_hal_myboard.h
# then s/none/myboard/ in the include guard, the include, and the function name
```

`hal/none/` is not a placeholder that returns fake data — it is a HAL whose
`read_id_segment` returns `VL_ERR_PLATFORM`, so every licence check fails closed and
you find out at bring-up. Read its header comment before you change anything; it is
the short version of this document.

---

## 2. Implement `read_id_segment`

This is the port.

```c
static vl_status_t read_id_segment(void *ctx, uint32_t idx,
                                   uint8_t *out, size_t cap, size_t *out_len)
{
    (void)ctx;
    if (idx != 0u)  return VL_ERR_NO_MORE_SEGMENTS;
    if (cap < 12u)  return VL_ERR_BUFFER_TOO_SMALL;
    memcpy(out, (const void *)MY_UID_BASE, 12u);
    if (all_same(out, 12u, 0x00u) || all_same(out, 12u, 0xFFu)) {
        return VL_ERR_PLATFORM;      /* the bus answered with nothing */
    }
    *out_len = 12u;
    return VL_OK;
}
```

The core calls this with `idx` = 0, 1, 2, … and hashes each segment with a one-byte
length prefix, so `{"AB","C"}` and `{"A","BC"}` produce different fingerprints.

**The contract, in full:**

| Rule | Why |
|---|---|
| End the list with `VL_ERR_NO_MORE_SEGMENTS` (−16) | Any other error is treated as a hard failure and `vl_verify()` fails closed. Do not end the list by returning zero bytes forever. |
| Never set `*out_len` greater than `cap` | The core checks and returns `VL_ERR_PLATFORM` rather than hashing past the buffer, but do not rely on that. |
| A zero-length segment is legal | It hashes as a single `0x00` length byte. Useful for "this optional source is absent on this unit" while keeping the fingerprint stable. |
| Return `VL_ERR_PLATFORM` if a read failed | Never a placeholder, never zeros, never a default. |
| At most 64 segments, at most 255 bytes each | `VL_ID_SEGMENT_COUNT_MAX`, `VL_ID_SEGMENT_MAX`. |
| `ctx` is whatever you put in `hal.ctx` | The core never looks inside it. |

### What makes a good identity segment

In preference order:

1. A factory-programmed, read-only die ID — MCU UID, eFuse, OTP.
2. A unique ID in a soldered-down peripheral — flash chip id, secure element, Ethernet
   PHY MAC.
3. A serial number written once at manufacture into OTP or a write-protected flash page.

**Not acceptable, ever:** a value from a writable config file, a build-time constant, a
random number generated at first boot and stored in plain flash, or anything a user can
edit. Each of those means an attacker copies the value along with the flash image and
the licence follows it — and worse, a build-time constant gives your entire production
run the same fingerprint, so one licence unlocks every unit and no licence is
revocable. That failure is completely silent right up to the customer who pastes their
friend's blob and gets `VL_OK`.

This is the single most consequential decision in the port. Two independent sources
beat one: a die ID alone survives a board swap, and a serial number alone is only as
trustworthy as the page it lives in.

### Freeze the segment set before you ship

The segment list, its order, and each segment's content are **part of the on-wire
format**. Adding a segment, reordering two, or switching a value from big-endian to
little-endian changes every fingerprint on every unit and invalidates every licence
already issued. There is no migration path short of re-issuing the fleet.

Write the segment list into your HAL's header comment, the way `hal/esp32` and
`hal/posix` do, and treat it as frozen from your first shipment.

---

## 3. Prove the fingerprint before you issue a licence against it

Three properties, in this order. Skipping this step is how a vendor discovers in month
four that half the fleet shares an id.

```c
uint8_t fp[VL_FINGERPRINT_LEN];
char id[VL_DEVICE_ID_STR_BUF_LEN];
if (vl_compute_fingerprint(vl_hal_myboard(), fp) == VL_OK) {
    vl_encode_device_id(fp, id, sizeof id);
    print(id);                      /* 26 characters */
}
```

1. **Stable** — same value across power cycles, across a reflash, across a firmware
   version bump, and after an erase of every user data partition. Print it in a boot
   banner and watch it for a day.
2. **Unique** — different on every board you have. Two boards is enough to catch the
   catastrophic case (a constant); if you have ten, check all ten. If two agree, stop
   and find a better source.
3. **Not something the customer can change.** Try to change it. Rewrite the config,
   swap the SD card, override the MAC in software. If the id moves, an attacker can
   move it too.

`tests/test_vl_hal.c` in this repository does the mechanical half of this against a
fake HAL; the parts above need real boards.

---

## 4. Add the optional callbacks — one at a time, only if you have the hardware

Every member of `vl_hal_t` except `read_id_segment` may be NULL, and the core behaves
correctly in every combination (there is a 64-cell test matrix asserting exactly that).
Adding a callback you cannot back with real hardware is worse than leaving it NULL.

| Callback | Add it when | Leaving it NULL means |
|---|---|---|
| `now_epoch` | you have an RTC or SNTP whose value you trust | validity windows are **not enforced**; `vl_verify()` returns `VL_OK` for an expired licence and leaves `VL_CHECKED_TIME` clear so the caller can tell. Set `VL_FLAG_REQUIRE_CLOCK` to refuse instead. |
| `hwm_load` + `hwm_store` | you have byte-addressable non-volatile storage, a clock, and you sell expiring licences | no clock-rollback protection. All three or none: `VL_FLAG_ENFORCE_HWM` without `now_epoch`, `hwm_load` **and** `hwm_store` is `VL_ERR_INVALID_ARG`. A mark is only ever compared against a clock, so on a clockless board there is no weaker form of this to fall back to. |
| `blob_load` + `blob_store` | you want the library to own the 161 bytes | you store the blob yourself, wherever you keep settings. Perfectly normal. |
| `secure_posture` | your part can report a verified-boot state | `vl_posture()` reports `VL_POSTURE_UNKNOWN`, which is a truthful answer and not an error. |

Return a real error from a callback rather than a plausible value. A `now_epoch` that
returns 0 because the RTC was never set is worse than no `now_epoch` at all: it silently
makes every `not_before` fail. `hal/esp32` rejects any clock reading before 2020-01-01
for exactly this reason; copy that idea.

---

## 5. Guard it for your target

Every shipped HAL compiles to a stub returning NULL on any other target, so a
multi-target source tree can carry all of them:

```c
#if defined(MYBOARD_SDK) || defined(VL_HAL_MYBOARD)
    /* the real thing */
#else
const vl_hal_t *vl_hal_myboard(void) { return NULL; }
#endif
```

Prefer a symbol the SDK itself defines (`USE_HAL_DRIVER` for STM32Cube, `PICO_SDK` for
pico-sdk, `ESP_PLATFORM` for ESP-IDF) with a manual `-DVL_HAL_MYBOARD` escape hatch for
people not using that SDK.

Locate vendor headers with `__has_include` rather than assuming a path. `hal/nxp` does
this for `fsl_device_registers.h`.

---

## 6. Wire it up

```c
#include "vl_hal_myboard.h"

static const vl_pubkey_t VENDOR_KEYS[] = { { .key_id = 1, .key = { /* keygen */ } } };
static const vl_config_t CFG = {
    .keys = VENDOR_KEYS, .key_count = 1, .family = 7,
    .revoked_serials = NULL, .revoked_count = 0, .flags = 0
};

vl_license_t lic;
vl_status_t st = vl_verify(blob, &CFG, vl_hal_myboard(), &lic);
```

That is the whole integration. `examples/baremetal/vl_gate.c` is this, complete, with
no OS and no libc header at all — it is `hal/none/` filled in for a Cortex-M with a
96-bit die ID. It compiles, and these two commands are the evidence:

```bash
cc -std=c99 -ffreestanding -Wall -Wextra -Werror -Iinclude -Itransport \
   -c examples/baremetal/vl_gate.c -o /dev/null
arm-none-eabi-gcc -std=c99 -Os -ffreestanding -mcpu=cortex-m0plus -mthumb \
   -Wall -Wextra -Werror -Iinclude -Itransport \
   -c examples/baremetal/vl_gate.c -o /dev/null
```

Both produce zero diagnostics. Neither is a ctest case, and the file has never been
linked into a firmware image or run on a board — see
[What has actually been built and run](../README.md#what-has-actually-been-built-and-run).

---

## Checklist before your first shipment

- [ ] `core/` compiles for the target with `-Wall -Wextra -Werror -Wpedantic`
- [ ] The fingerprint is stable across reflash, erase and power cycle
- [ ] The fingerprint differs on every board you own
- [ ] You have tried and failed to change it from userspace / a config file
- [ ] The segment list is written down in the HAL header and treated as frozen
- [ ] `read_id_segment` returns `VL_ERR_PLATFORM` on a failed read, never a placeholder
- [ ] The list ends with `VL_ERR_NO_MORE_SEGMENTS`
- [ ] Optional callbacks are NULL unless backed by real hardware
- [ ] If `now_epoch` is NULL and you sell expiring licences, the application reads
      `lic.checked & VL_CHECKED_TIME` — or sets `VL_FLAG_REQUIRE_CLOCK`
- [ ] The task that calls `vl_verify()` has at least 5 KB of stack
- [ ] `vl_verify()` is not called from an interrupt or a network stack's callback

---

## Contributing a HAL back

Match the shape of the existing ones: one `.c` and one `.h` under `hal/<name>/`,
independently deletable, no dependency on any other HAL, a header comment that lists
the identity segments in order and states plainly which optional callbacks are provided
and why the rest are not. If you could not compile it — say so in the header, the way
`hal/stm32`, `hal/nxp` and `hal/rp2040` do. An untested claim is worse than an honest
gap.

Questions: <team@vectivolt.com>.
