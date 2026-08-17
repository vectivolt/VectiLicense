# tools — the vendor side

One script. `vl_mint.py` is the only thing in this repository that holds a
private key, and the only thing that can produce a licence.

That asymmetry is the point of v1. The firmware carries a 32-byte **public**
key; there is no signing code in the device build to re-enable, no shared salt
to extract, and therefore no keygen to build from a flash dump. What an
attacker gets from `esptool.py read_flash` is a public key, which they were
welcome to anyway.

```
vl_mint.py keygen   --key vendor.key --key-id 1
vl_mint.py pubkey   --key vendor.key --key-id 1
vl_mint.py issue    --key vendor.key --device-id <26 chars> --family 2 \
                    --features 0x0d --expires 2027-12-31 --serial 1001
vl_mint.py inspect  <blob> [--pubkey <64 hex>]
vl_mint.py selftest
```

Needs Python 3.8+ and `cryptography` (or `pynacl`). Ed25519 is not hand-rolled
here and must not be. `qrcode` + `pillow` are optional; without them `--qr`
prints a note and everything else still works.

```bash
pip install cryptography            # required
pip install qrcode pillow           # optional, for --qr
```

## First time

```bash
$ ./tools/vl_mint.py keygen --key ~/vendor.key --key-id 1
private key -> /Users/you/vendor.key (mode 0600). Back it up offline. Never commit it.

/* VectiLicense vendor public key — safe to publish, safe to ship. */
static const vl_pubkey_t VENDOR_KEYS[] = {
    { .key_id = 1, .key = {
        0xf2, 0x6f, 0x9d, 0x99, ...
    } },
};
static const vl_config_t LICENSE_CFG = { ... };
```

Paste that block into your firmware. `pubkey` reprints it later, so you never
need to keep the paste around.

The key file is written 0600 and every subcommand re-checks that before using
it — a key file another user on the build machine can read is a key file that
has already leaked, and the script refuses rather than pretending otherwise.

**Losing the key** means every future licence needs a firmware update carrying
a new `key_id`. **Leaking it** means a keygen. Back it up offline; if your
threat model justifies it, keep it in an HSM or a KMS and adapt `_crypto()` —
it is a three-function interface (`sign`, `pub`, `verify`).

## Day to day

The customer reads a 26-character device id off the portal, the dashboard QR or
the serial console, and sends it to you:

```bash
$ ./tools/vl_mint.py issue --key ~/vendor.key \
      --device-id 3V4QMWA9WZVVWTZ7DY1W0BXG48 \
      --family 2 --features 0x0d --expires 2027-12-31 --serial 1001 \
      --qr acme-4421.png
```

You get 160 base32 characters, printed both grouped for a human and as one
line for a script, plus a QR PNG if `qrcode` is installed. Send it back by any
channel that can carry text. The device pastes it into the captive portal, the
dashboard, or `license <blob>` on the console; nothing needs to be online.

Notes on the flags:

| Flag | |
|---|---|
| `--device-id` | the 26 characters the customer reported. Dashes, spaces and case are all ignored; `--device-id-hex` takes the raw 32 hex characters instead. |
| `--family` | 0..255, must match `cfg.family` in the firmware. A licence for one product does not open another. |
| `--features` | 32-bit bitmap, `int(x, 0)` — `0x0d` means bits 0, 2 and 3. Read on the device with `vl_has_feature()`. |
| `--expires` | `YYYY-MM-DD` inclusive (encoded as 23:59:59 UTC that day) or a raw epoch. Omit for perpetual. |
| `--not-before` | same formats. Omit for "valid immediately". |
| `--serial` | your licence number. It is what a revocation deny-list matches on, so keep them unique and keep a record. |
| `--key-id` | which embedded public key signs this. Rotation: ship the new key alongside the old, sign new licences with the new one, drop the old a release later. |

**A device with no clock cannot enforce `--expires`.** That is not a bug in the
minter; it is what `hal->now_epoch == NULL` means, and `vl_verify()` reports it
by leaving `VL_CHECKED_TIME` clear rather than by failing. If a subscription is
the business model, either give the device an RTC or an SNTP source, or set
`VL_FLAG_REQUIRE_CLOCK` and accept that an offline device then refuses to run.

## Reading a blob back

`inspect` decodes without any key at all — useful when a customer sends you a
licence that "does not work" and you want to see which device and which family
it was actually minted for.

```bash
$ ./tools/vl_mint.py inspect ARQG80GD-000007P9-... --pubkey 4f5c...
```

Decoding proves nothing about authenticity: the fields are readable by anyone.
Pass `--pubkey` to also check the signature, which is the same check the device
makes and exits non-zero when it fails.

## Testing it

```bash
$ ./tools/vl_mint.py selftest
selftest: ok
```

That asserts the payload layout, the base32 codec (including that the grouping
characters a human pastes decode identically), that the domain-separation
prefix is really covered by the signature, that all 288 single-bit flips of a
payload break it, and that the key-file permission gate fires.

The stronger check is cross-implementation: `tests/gen_fixtures.py` is an
independent implementation of the same format that mints the blobs the C test
suite verifies. `vl_mint.py` reproduces those fixtures byte for byte. If a
change makes the two disagree, the C tests fail — which is exactly what you
want a format change to do.

## What is not here

There is no C minting tool. v0.1 shipped one; it needed the shared salt, and
that is the vulnerability this version exists to remove. If you want minting in
a CI pipeline, call this script.

There is no batch mode, no audit log and no GUI. Minting is one signature over
36 bytes with no per-device state, so a shell loop over a CSV is the whole
feature:

```bash
while IFS=, read -r devid serial; do
  ./tools/vl_mint.py issue --key ~/vendor.key --device-id "$devid" \
      --family 2 --serial "$serial" --raw > "licences/$serial.txt"
done < devices.csv
```
