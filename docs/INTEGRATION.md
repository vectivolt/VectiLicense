# Integrating VectiLicense

Two workflows — yours and your customer's — and then the parts nobody thinks about
until they matter: rotation, revocation, and what happens when a licence is refused for
a reason that is your fault.

---

## The vendor workflow

### One time, ever

```bash
python3 tools/vl_mint.py keygen --key vendor.key --key-id 1
```

This is the only command in the project that creates a private key, and
`tools/vl_mint.py` is the only file that ever touches one. It writes `vendor.key` with
mode 0600 and refuses to load a key file that is group- or world-readable.

It prints your public key as a ready-to-paste C block:

```c
static const vl_pubkey_t VENDOR_KEYS[] = {
    { .key_id = 1, .key = {
        0x02, 0x1a, 0x03, 0x7f, /* ...28 more... */
    } },
};
```

Key hygiene is not optional, because v1 concentrates all of the risk here. If this key
leaks, the attacker becomes you — and unlike v0.1, where the secret was in every
firmware image, this one lives in exactly one place, which is a much better position to
defend:

- Generate it on an offline or at least non-shared machine.
- Back it up offline. Losing it means you can never issue another licence for the
  fleets that trust it.
- Never commit it. Add `*.key` to `.gitignore` and mean it.
- Never put it in CI unless CI *is* your signing service and the key is in a secrets
  manager or an HSM.
- Provision a second and third `key_id` from day one. Rotation is then a config change
  rather than a recall — see [Key rotation](#key-rotation).

### Per order

The customer sends you 26 characters. You send back 160. There is no database, no
pre-generation, no per-device state, and no server that has to stay up.

```bash
python3 tools/vl_mint.py issue --key vendor.key \
        --device-id 7V3VAR49YVAVNKKRJT0FR2RAE0 \
        --family 2 \
        --features 0x0d \
        --serial 1002 \
        --expires 2027-01-01 \
        --qr licence.png
```

```
device id : 7V3VAR49YVAVNKKRJT0FR2RAE0
family    : 2    key_id: 1    serial: 1002
features  : 0x0000000d
not_before: 0 (unbounded)
not_after : 1798847999 (2027-01-01 23:59:59 UTC)

licence blob (160 characters, case-insensitive, dashes optional):

  AR0G208D-00000FP7-PNG8KXPN-QB77H5M0-ZG5GMW00
  00001ZSX-71NYM0R0-006CZNR6-BZ7D10H9-T7V5QQCP
  ...
```

Signing is O(1) and stateless, so this fits behind a web form, a Zapier hook, or a
support engineer's terminal equally well. `--raw` prints only the blob, for scripting.

Keep your own record of `serial → customer, device id, date, what they bought`. The
library does not need it; your support desk does, and revocation needs it.

`vl_mint.py inspect <blob>` decodes any blob without a key — useful on a support call
to see what a customer actually pasted. It says plainly that decoding proves nothing
about authenticity; only the device's `vl_verify()` does that.

### Choosing the fields

| Field | Advice |
|---|---|
| `--family` | One byte per product line. A licence for family 2 is refused on family 3 before any crypto runs. Assign these once and write them down. |
| `--features` | A 32-bit bitmap. Define the bits in a header shared by firmware and your order system, and never reuse a retired bit number. Bit 0 = "the product runs at all" is a common and useful convention. |
| `--serial` | Monotonic, per issued licence, never reused. It is your only handle for revocation and your only handle on a support call. |
| `--expires` | Omit for perpetual, which is the honest default for a device that may have no clock. Read [Clock reality](#clock-reality) before you sell a subscription. |
| `--not-before` | Rarely needed. Useful for a licence emailed ahead of a scheduled upgrade. |

---

## The device workflow

Four things happen, in this order, and only the third involves a human.

**1. Compute and show the device id.** At boot, or on demand from a menu.

```c
uint8_t fp[VL_FINGERPRINT_LEN];
char id[VL_DEVICE_ID_STR_BUF_LEN];              /* 27 bytes */
if (vl_compute_fingerprint(hal, fp) == VL_OK &&
    vl_encode_device_id(fp, id, sizeof id) == VL_OK) {
    show(id);                                    /* 26 chars, Crockford base32 */
}
```

Crockford base32 has no `I`, `L`, `O` or `U`, and the decoder folds `I`/`l` to `1` and
`O` to `0`, so a customer reading it aloud over the phone still works.

**2. Get the 160 characters onto the device.** See [Delivery paths](#delivery-paths).
This is the only part that differs between products.

**3. Verify, then store — in that order.**

```c
vl_license_t lic;
vl_status_t st = vl_verify(blob, &CFG, hal, &lic);
if (st == VL_OK && hal->blob_store) {
    hal->blob_store(hal->ctx, blob, strlen(blob));
}
```

Storing first and verifying at the next boot means a mistyped blob survives a power
cycle and the customer's next message is "it says invalid and I can't clear it".

**4. Re-verify at every boot.** A licence that was good at the factory is not evidence
about this boot: the flash may have been swapped since, the board repaired, the clock
moved.

```c
char blob[VL_BLOB_STR_BUF_LEN];
size_t len;
if (hal->blob_load(hal->ctx, blob, sizeof blob, &len) == VL_OK) {
    g_status = vl_verify(blob, &CFG, hal, &g_license);
}
```

### Enforcement policy

This is your decision, not the library's, and it is worth more thought than the crypto.

The failure that will actually cost you money is **not piracy**. It is a paying
customer whose board was repaired, whose eFuse MAC therefore changed, whose RTC battery
died, or whose NIC was swapped — and whose device now refuses to run on a Saturday
night. Every field-return you cause costs more than the licence you protected.

**Fail closed on the crypto. Fail open on the business policy.**

| Tier | Behaviour | Fits |
|---|---|---|
| Nag | Everything works; a banner says unlicensed | pilots, evaluation units, anything safety-adjacent |
| Degrade | Core function runs; the paid features are off | most products, most of the time |
| Grace | Full function for N days after the first refusal, then degrade | fleets where a support round-trip takes days |
| Hard stop | Refuses to run | almost never. Reserve it for the case where running unlicensed is itself the harm |

Whatever you pick, always log `vl_status_str(st)`. "Refused" is not a support ticket;
"licence is for a different device" is a two-minute fix.

And read `lic.checked`, not just the return code:

```c
if (st == VL_OK && lic.not_after != 0u && !(lic.checked & VL_CHECKED_TIME)) {
    /* This licence has an expiry that nobody enforced, because this device
     * has no clock. Decide what that means to you — do not assume it was
     * checked. */
}
```

---

## Delivery paths

`vl_verify()` takes a NUL-terminated string. That is the entire transport contract:
anything that can move 160 characters works, and most paths need no helper code at all.
Grouping characters (`-`, space, tab, CR, LF) may appear anywhere and are ignored, and
the input is case-insensitive, so a human paste with line breaks is fine as-is.

> **Before you copy any of the four bridge snippets below:** `bridge/vl_bridge_net.h`,
> `vl_bridge_dash.h`, `vl_bridge_serial.h` and `vl_bridge_ota.h` have **never been
> compiled against the real VectiNet, VectiDash, VectiSerial or VectiOTA** — not in CI,
> not on a bench, not once. They are written to those libraries' documented APIs and
> guarded by `__has_include`, so an uninstalled sibling compiles to nothing and nothing
> here has ever type-checked them. Expect to fix a name or an include path on your first
> build. What *is* compiled and tested on the host is `vecti::License` in
> `bridge/vl_bridge.h`, which is where all four bridges' logic actually lives. See
> [What has actually been built and run](../README.md#what-has-actually-been-built-and-run).

### QR code — the default for anything with a screen or a printer

The vendor side is `--qr licence.png`. The device side is a phone: the operator scans
the code and pastes into whatever form the device offers. In the other direction, show
the **device id** as a QR so the customer photographs 26 characters instead of
transcribing them — `bridge/vl_bridge_dash.h` does exactly this with VectiDash's
`QrCode` card.

No helper needed. A QR scanner hands you a string.

### Captive portal — the strongest story: a sealed box, no internet, no app

`bridge/vl_bridge_net.h` adds three fields to VectiNet's setup portal: a read-only
Display with the device id and a copy button, a Display with the current verdict, and a
Textarea to paste the licence into. The operator joins the device's own SoftAP from a
phone, the portal pops up, and activation happens **before the device has ever joined a
network**.

```c
static vecti::License          license(&CFG, hal);
static vecti::NetLicensePortal portal(license);

void setup() { license.begin(); portal.attach(); VectiNet.begin(&server); }
void loop()  { VectiNet.loop(); portal.loop(); license.pump(); }
```

`portal.attach()` must run before `VectiNet.begin()`, which is when the form is frozen.

Note the split: the portal POST runs on the AsyncTCP task, where an Ed25519 verify of
tens of milliseconds and a blocking NVS write would starve every other socket. `portal.loop()` only queues;
`license.pump()`, on the loop task, does the work.

### Serial console

`bridge/vl_bridge_serial.h` adds a `license` command to VectiSerial:

```
license                → same as `license status`
license status         → verdict, serial, features, expiry, what was checked
license id             → the 26-character device id
license <blob>         → queue an activation
```

Without VectiSerial, `transport/vl_line.c` is the two-function version: push received
bytes, get a NUL-terminated line back, bounded and whitespace-stripped.

```c
static vl_line_t rx;
for (i = 0; i < n; i++) {
    if (vl_line_push(&rx, buf[i]) == VL_OK) {
        st = vl_verify(rx.buf, &CFG, hal, &lic);
        vl_line_reset(&rx);
    }
}
```

### CAN, ISO-TP, BLE GATT — the one that needs a helper

A classic CAN frame carries 8 bytes; a BLE GATT write, 20. `transport/vl_chunk.c`
reassembles the blob from numbered pieces and tolerates out-of-order delivery,
duplicates and gaps:

```c
vl_chunk_t rx;
vl_chunk_reset(&rx, 8, VL_BLOB_STR_LEN);        /* 8-byte frames, 160 characters */

/* per frame: */
vl_chunk_feed(&rx, frame.seq, frame.data, frame.dlc);

char blob[VL_BLOB_STR_BUF_LEN];
size_t n;
if (vl_chunk_complete(&rx, blob, sizeof blob, &n) == VL_OK) {
    st = vl_verify(blob, &CFG, hal, &lic);
}
```

The wire format — how you carry `seq` — is yours. The helper only bounds and orders
bytes; magic, alphabet and signature are `vl_verify()`'s job and it rejects everything
malformed before any crypto runs. State is ~250 bytes and nothing allocates.

### File, USB stick, SD card

Read the bytes, NUL-terminate, call `vl_verify()`. No helper. A trailing newline is
ignored, so `licence.txt` straight from your email works.

```c
char blob[VL_BLOB_STR_BUF_LEN + 8];
size_t n = fread(blob, 1, sizeof blob - 1, f);
blob[n] = '\0';
```

### HTTP, MQTT, BLE with a big enough characteristic

No helper. The payload *is* the blob. Worth stating explicitly because it is the
question people ask first: there is no VectiLicense server, no activation endpoint, and
no protocol. If your fleet-management system can push a string to a device, it can
deliver a licence.

---

## Key rotation

`key_id` is one byte in the payload, and the config holds a set of keys rather than one.
Rotation is therefore a firmware config change, not a recall.

**To rotate:**

1. `python3 tools/vl_mint.py keygen --key vendor2.key --key-id 2`
2. Ship a firmware release whose `VENDOR_KEYS` contains **both** keys:

   ```c
   static const vl_pubkey_t VENDOR_KEYS[] = {
       { .key_id = 1, .key = { /* old */ } },
       { .key_id = 2, .key = { /* new */ } },
   };
   ```
3. Wait until that release has reached the fleet.
4. Start issuing with `--key vendor2.key --key-id 2`. Old licences keep working.
5. A release or two later, drop `key_id` 1 from the array. Every licence signed with it
   now returns `VL_ERR_UNKNOWN_KEY` — which is how you retire a whole generation of
   licences deliberately, and also what happens accidentally if you drop it too early.

**If the private key has actually leaked,** steps 3–5 collapse into one emergency
release that ships only the new key, and every licence ever issued under the old one
stops working. That is the whole reason to provision multiple key ids up front: the
difference between a planned rotation and an outage is whether the new key was already
in the field.

Order does not matter; the lookup is by `key_id`. Ship at most a handful — each key is
33 bytes of flash and one more thing to get wrong.

---

## Revocation

A compiled-in deny-list of serials. No network, so no online revocation — this ships
with your next firmware image.

```c
static const uint32_t REVOKED[] = { 4242, 4243, 9001 };

static const vl_config_t CFG = {
    .keys = VENDOR_KEYS, .key_count = 2,
    .family = 2,
    .revoked_serials = REVOKED,
    .revoked_count   = sizeof REVOKED / sizeof REVOKED[0],
    .flags = 0,
};
```

- `revoked_count = 0`, or `revoked_serials = NULL`, disables the check entirely, and
  `VL_CHECKED_REVOCATION` stays clear in `lic.checked` so a caller can tell the
  difference between "not revoked" and "not checked".
- Order does not matter — the scan is linear on purpose, so there is no sorted-array
  invariant for an integrator to break. If your list ever runs to thousands, sort it and
  switch to a binary search; the comment in `core/vl_core.c` says so.
- Revocation is checked **after** the signature and the device binding, so a refused
  licence returns `VL_ERR_REVOKED` only when it was otherwise genuine.

**What this is for:** a chargeback, a returned unit, a licence issued to the wrong
device id, a reseller dispute. It is a business tool. An attacker who has already
patched out the check does not consult your deny-list.

Keep the list short by keeping serials meaningful. If you find yourself revoking
hundreds, the problem is upstream in how licences are issued.

---

## Clock reality

Before you sell anything time-limited, decide which of these you are:

| Your hardware | `now_epoch` | What `not_after` means |
|---|---|---|
| Battery-backed RTC, or SNTP that has definitely synced | provided | enforced. `VL_CHECKED_TIME` set. |
| No RTC, no network | NULL | **not enforced.** `vl_verify()` returns `VL_OK` for an expired licence and leaves `VL_CHECKED_TIME` clear. Read that bit. |
| No RTC, and you refuse to ship unenforced expiry | NULL + `VL_FLAG_REQUIRE_CLOCK` | `VL_ERR_NO_CLOCK`, always. The device will not run without a clock. |
| RTC the customer can set | provided + `VL_FLAG_ENFORCE_HWM` | enforced, plus rollback is refused below the highest timestamp ever seen |

`VL_FLAG_ENFORCE_HWM` needs `now_epoch`, `hwm_load` and `hwm_store`; setting it without
all three is `VL_ERR_INVALID_ARG` rather than a silent downgrade to no protection — the
clock is part of the requirement because the mark is only ever compared against it. It writes a
new mark only when the clock has actually advanced, so it does not burn a flash sector
on every boot — but it can still strand a unit whose RTC battery died, which is why it
is opt-in.

The perpetual licence (`not_after = 0`) exists because on a lot of embedded hardware it
is the only honest option.

---

## A checklist for the day before launch

- [ ] The private key is backed up offline and is not in the repository, the firmware,
      or CI
- [ ] At least two `key_id`s are in the shipping firmware
- [ ] The `family` byte is assigned and written down
- [ ] Feature bits are defined in a header shared with your order system
- [ ] The HAL's identity segments are frozen — see [`PORTING.md`](PORTING.md)
- [ ] Enforcement is degrade or grace, not hard stop, unless you can defend hard stop
- [ ] `vl_status_str()` output reaches a log the support desk can read
- [ ] Someone has run through the full loop on real hardware: device id → mint →
      paste → reboot → still licensed
- [ ] Someone has tried the failure paths on real hardware: wrong device's blob, a
      typo, an empty paste, and an expired licence
- [ ] You have read [`THREAT_MODEL.md`](THREAT_MODEL.md) and decided about Secure Boot
