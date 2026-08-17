#!/usr/bin/env python3
# (c) 2026 VectiVolt — Apache-2.0 License
"""vl_mint.py — VectiLicense vendor tool. The ONLY place a private key exists.

The device holds a 32-byte Ed25519 public key and can verify. This script holds
the private key and can sign. Nothing in the firmware build can mint, because
the code to mint is here and the key is here.

    vl_mint.py keygen  --key vendor.key --key-id 1
    vl_mint.py pubkey  --key vendor.key --key-id 1
    vl_mint.py issue   --key vendor.key --device-id <26 chars> --family 2 \
                       --features 0x0d --expires 2027-12-31 --serial 1001
    vl_mint.py inspect  <blob>            # decode without any key
    vl_mint.py selftest                   # mint -> inspect -> tamper, all asserted

Key handling:
  * the key file is 64 hex characters, mode 0600, and this script refuses to
    read one that is group- or world-readable;
  * keygen will not overwrite an existing key without --force;
  * back the key up somewhere offline. Losing it means every future licence
    needs a firmware update to add a new key_id. Leaking it is a keygen.

Needs `cryptography` or `pynacl`. Ed25519 is not hand-rolled here.
"""

import argparse
import datetime as dt
import hashlib
import os
import stat
import struct
import sys

# ---------------------------------------------------------------------------
# On-wire format. These four functions are the format; keep them in step with
# core/vl_core.c and tests/gen_fixtures.py (which is the independent reference
# implementation the C is tested against).
# ---------------------------------------------------------------------------

ALPHA = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"          # Crockford, no I L O U
SIGN_PREFIX = b"vectilicense:v1"
FP_DOMAIN = b"vectilicense:fingerprint:v1"

MAGIC = 0x56
FORMAT_VERSION = 0x01
PAYLOAD_LEN = 36
SIG_LEN = 64
BLOB_BIN_LEN = PAYLOAD_LEN + SIG_LEN                # 100
BLOB_STR_LEN = 160
DEVICE_ID_LEN = 16
DEVICE_ID_STR_LEN = 26


def b32(data: bytes) -> str:
    bits = "".join(f"{b:08b}" for b in data)
    bits += "0" * ((-len(bits)) % 5)
    return "".join(ALPHA[int(bits[i:i + 5], 2)] for i in range(0, len(bits), 5))


def b32_decode(text: str, expect_bytes: int) -> bytes:
    """Crockford base32 -> bytes. Tolerates the grouping characters vl_verify()
    tolerates, and the Crockford aliases O->0 and I/L->1."""
    cleaned = []
    for ch in text:
        if ch in "- \t\r\n":
            continue
        ch = ch.upper()
        ch = {"O": "0", "I": "1", "L": "1"}.get(ch, ch)
        if ch not in ALPHA:
            raise ValueError(f"character {ch!r} is not in the base32 alphabet")
        cleaned.append(ch)
    want_chars = (expect_bytes * 8 + 4) // 5
    if len(cleaned) != want_chars:
        raise ValueError(f"expected {want_chars} base32 characters, got {len(cleaned)}")
    bits = "".join(f"{ALPHA.index(c):05b}" for c in cleaned)
    out = bytes(int(bits[i:i + 8], 2) for i in range(0, expect_bytes * 8, 8))
    # Reject a non-canonical encoding: the padding bits must be zero, otherwise
    # two different strings would decode to the same licence.
    if bits[expect_bytes * 8:].strip("0"):
        raise ValueError("non-canonical encoding (padding bits are not zero)")
    return out


def payload(key_id, family, features, device_id16, not_before, not_after, serial) -> bytes:
    assert len(device_id16) == DEVICE_ID_LEN
    return (bytes([MAGIC, FORMAT_VERSION, key_id, family])
            + struct.pack("<I", features)
            + device_id16
            + struct.pack("<I", not_before)
            + struct.pack("<I", not_after)
            + struct.pack("<I", serial))


def fingerprint(segments) -> bytes:
    """SHA-256 over the domain string and every HAL id segment, each with a
    one-byte length prefix. Here for reference and for selftest; the device
    computes its own and the customer reports the first 16 bytes."""
    h = hashlib.sha256()
    h.update(FP_DOMAIN)
    for s in segments:
        if len(s) > 255:
            raise ValueError("id segment longer than 255 bytes")
        h.update(bytes([len(s)]))
        h.update(s)
    return h.digest()


# ---------------------------------------------------------------------------
# Ed25519, from a maintained library. Never hand-rolled.
# ---------------------------------------------------------------------------

def _crypto():
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives import serialization
        raw = dict(encoding=serialization.Encoding.Raw,
                   format=serialization.PublicFormat.Raw)

        def pub(seed):
            return ed25519.Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(**raw)

        def sign(seed, msg):
            return ed25519.Ed25519PrivateKey.from_private_bytes(seed).sign(msg)

        def verify(pk, sig, msg):
            try:
                ed25519.Ed25519PublicKey.from_public_bytes(pk).verify(sig, msg)
                return True
            except Exception:
                return False

        return sign, pub, verify
    except ImportError:
        pass
    try:
        from nacl.signing import SigningKey, VerifyKey
        from nacl.exceptions import BadSignatureError

        def pub(seed):
            return bytes(SigningKey(seed).verify_key)

        def sign(seed, msg):
            return bytes(SigningKey(seed).sign(msg).signature)

        def verify(pk, sig, msg):
            try:
                VerifyKey(pk).verify(msg, sig)
                return True
            except BadSignatureError:
                return False

        return sign, pub, verify
    except ImportError:
        sys.exit("error: needs `cryptography` or `pynacl`.\n"
                 "       pip install cryptography")


SIGN, PUBKEY_OF, VERIFY = None, None, None   # bound lazily in main()


# ---------------------------------------------------------------------------
# Key file
# ---------------------------------------------------------------------------

def read_key(path: str) -> bytes:
    try:
        st = os.stat(path)
    except OSError as e:
        sys.exit(f"error: cannot read key file {path}: {e}")
    if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        sys.exit(f"error: {path} is mode {st.st_mode & 0o777:04o}; it is readable by\n"
                 f"       other users on this machine. Refusing to use it.\n"
                 f"       chmod 600 {path}")
    text = open(path).read().strip()
    try:
        seed = bytes.fromhex(text)
    except ValueError:
        sys.exit(f"error: {path} is not 64 hex characters")
    if len(seed) != 32:
        sys.exit(f"error: {path} holds {len(seed)} bytes, expected 32")
    return seed


def c_array(key_id: int, pk: bytes) -> str:
    rows = []
    for i in range(0, len(pk), 8):
        rows.append("        " + " ".join(f"0x{b:02x}," for b in pk[i:i + 8]))
    return ("/* VectiLicense vendor public key — safe to publish, safe to ship. */\n"
            "static const vl_pubkey_t VENDOR_KEYS[] = {{\n"
            "    {{ .key_id = {kid}, .key = {{\n{body}\n    }} }},\n"
            "}};\n"
            "static const vl_config_t LICENSE_CFG = {{\n"
            "    .keys = VENDOR_KEYS, .key_count = 1,\n"
            "    .family = 1,                 /* your product family byte */\n"
            "    .revoked_serials = NULL, .revoked_count = 0,\n"
            "    .flags = 0,\n"
            "}};\n").format(kid=key_id, body="\n".join(rows))


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------

def cmd_keygen(a):
    if os.path.exists(a.key) and not a.force:
        sys.exit(f"error: {a.key} exists. Use --force only if you are certain — every\n"
                 f"       licence already issued with it stops verifying on firmware\n"
                 f"       that ships only the new key.")
    seed = os.urandom(32)
    # O_CREAT's mode argument applies ONLY when the call creates the file, so
    # reusing a pre-existing inode (the --force / key-rotation path) would put
    # the new signing key on disk at that file's OLD mode -- 0644 if it ever
    # was -- and the trailing chmod would narrow it only after the bytes were
    # already readable. Unlink first and demand O_EXCL, so the key can land
    # only in an inode this process just created at 0600. O_NOFOLLOW closes the
    # symlink-swap window between the unlink and the open.
    try:
        os.unlink(a.key)
    except FileNotFoundError:
        pass
    fd = os.open(a.key, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(seed.hex() + "\n")
    print(f"private key -> {a.key} (mode 0600). Back it up offline. Never commit it.\n")
    print(c_array(a.key_id, PUBKEY_OF(seed)))


def cmd_pubkey(a):
    print(c_array(a.key_id, PUBKEY_OF(read_key(a.key))))


def parse_when(s: str, end_of_day: bool) -> int:
    """YYYY-MM-DD (UTC, inclusive) or a raw epoch. 0 means unbounded."""
    if s is None:
        return 0
    if s.isdigit():
        return int(s)
    try:
        d = dt.datetime.strptime(s, "%Y-%m-%d").replace(tzinfo=dt.timezone.utc)
    except ValueError:
        sys.exit(f"error: {s!r} is not YYYY-MM-DD or an epoch")
    if end_of_day:
        d += dt.timedelta(hours=23, minutes=59, seconds=59)
    return int(d.timestamp())


def cmd_issue(a):
    seed = read_key(a.key)
    try:
        dev = b32_decode(a.device_id, DEVICE_ID_LEN) if not a.device_id_hex \
            else bytes.fromhex(a.device_id_hex)[:DEVICE_ID_LEN]
    except ValueError as e:
        sys.exit(f"error: bad --device-id: {e}")
    if len(dev) != DEVICE_ID_LEN:
        sys.exit("error: device id must be 16 bytes")

    for name, val in (("--family", a.family), ("--key-id", a.key_id)):
        if not 0 <= val <= 255:
            sys.exit(f"error: {name} must be 0..255")
    if not 0 <= a.features <= 0xFFFFFFFF:
        sys.exit("error: --features must fit in 32 bits")

    nb = parse_when(a.not_before, end_of_day=False)
    na = parse_when(a.expires, end_of_day=True)
    if nb and na and na < nb:
        sys.exit("error: --expires is before --not-before")

    p = payload(a.key_id, a.family, a.features, dev, nb, na, a.serial)
    sig = SIGN(seed, SIGN_PREFIX + b"\x00" + p)
    if not VERIFY(PUBKEY_OF(seed), sig, SIGN_PREFIX + b"\x00" + p):
        sys.exit("internal error: freshly minted signature does not verify")
    blob = b32(p + sig)
    assert len(blob) == BLOB_STR_LEN

    if a.raw:
        print(blob)
    else:
        print(f"device id : {a.device_id or a.device_id_hex}")
        print(f"family    : {a.family}    key_id: {a.key_id}    serial: {a.serial}")
        print(f"features  : 0x{a.features:08x}")
        print(f"not_before: {fmt_epoch(nb)}")
        print(f"not_after : {fmt_epoch(na)}")
        print("\nlicence blob (160 characters, case-insensitive, dashes optional):\n")
        for i in range(0, BLOB_STR_LEN, 40):
            print("  " + "-".join(blob[j:j + 8] for j in range(i, i + 40, 8)))
        print(f"\n  {blob}")

    if a.out:
        open(a.out, "w").write(blob + "\n")
        print(f"\nwritten to {a.out}")
    if a.qr:
        write_qr(blob, a.qr)


def fmt_epoch(e: int) -> str:
    if e == 0:
        return "0 (unbounded)"
    return f"{e} ({dt.datetime.fromtimestamp(e, dt.timezone.utc):%Y-%m-%d %H:%M:%S} UTC)"


def write_qr(blob: str, path: str):
    try:
        import qrcode                       # needs pillow for PNG output
    except ImportError:
        print(f"\nnote: no QR written to {path} — `pip install qrcode pillow` for that.\n"
              f"      The blob above is the whole licence; a file or a paste works\n"
              f"      just as well.")
        return
    try:
        qrcode.make(blob).save(path)
    except Exception as e:                  # pillow missing shows up here
        print(f"\nnote: no QR written to {path} ({e}). `pip install pillow`.")
        return
    print(f"\nQR code -> {path}")


def cmd_inspect(a):
    blob = a.blob if a.blob != "-" else sys.stdin.read()
    try:
        raw = b32_decode(blob, BLOB_BIN_LEN)
    except ValueError as e:
        sys.exit(f"error: not a VectiLicense blob: {e}")
    p, sig = raw[:PAYLOAD_LEN], raw[PAYLOAD_LEN:]
    magic, version, key_id, family = p[0], p[1], p[2], p[3]
    features, = struct.unpack("<I", p[4:8])
    dev = p[8:24]
    nb, na, serial = struct.unpack("<III", p[24:36])

    print(f"magic     : 0x{magic:02x} {'(ok)' if magic == MAGIC else '(NOT a VectiLicense blob)'}")
    print(f"version   : {version} {'(ok)' if version == FORMAT_VERSION else '(unsupported)'}")
    print(f"key_id    : {key_id}")
    print(f"family    : {family}")
    print(f"features  : 0x{features:08x}  bits: "
          + (", ".join(str(b) for b in range(32) if features >> b & 1) or "none"))
    print(f"device id : {b32(dev)}")
    print(f"not_before: {fmt_epoch(nb)}")
    print(f"not_after : {fmt_epoch(na)}")
    print(f"serial    : {serial}")
    print(f"signature : {sig.hex()}")

    if a.pubkey:
        # Two bugs lived on this line. read_key() returns the 32-byte PRIVATE
        # seed, which is NOT the public key derived from it, so handing it
        # straight to VERIFY() reported every genuine licence as forged.
        # Derive the public key instead. And discriminate hex-vs-path by
        # whether the string IS hex, not merely by its length: a 64-character
        # path used to take the fromhex branch and raise a bare ValueError.
        if len(a.pubkey) == 64 and all(ch in "0123456789abcdefABCDEF" for ch in a.pubkey):
            pk = bytes.fromhex(a.pubkey)
        else:
            pk = PUBKEY_OF(read_key(a.pubkey))
        ok = VERIFY(pk, sig, SIGN_PREFIX + b"\x00" + p)
        print(f"\nsignature : {'VALID' if ok else 'DOES NOT VERIFY'} against the given public key")
        if not ok:
            sys.exit(1)
    else:
        print("\nsignature not checked (no --pubkey given). Decoding proves nothing about\n"
              "authenticity; only the device's vl_verify() does.")


def cmd_selftest(_a):
    """One runnable check for the format code above."""
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        seed = os.urandom(32)
        pk = PUBKEY_OF(seed)
        dev = fingerprint([b"\xde\xad\xbe\xef", b"board", b""])[:16]

        p = payload(3, 2, 0x0d, dev, 0, 1893456000, 77)
        assert len(p) == PAYLOAD_LEN
        msg = SIGN_PREFIX + b"\x00" + p
        sig = SIGN(seed, msg)
        blob = b32(p + sig)
        assert len(blob) == BLOB_STR_LEN, len(blob)

        # base32 round-trips, and the grouping characters the device tolerates
        # decode to the same bytes.
        assert b32_decode(blob, BLOB_BIN_LEN) == p + sig
        grouped = "-".join(blob[i:i + 8] for i in range(0, BLOB_STR_LEN, 8))
        assert b32_decode(grouped.lower(), BLOB_BIN_LEN) == p + sig
        assert b32_decode(b32(dev), DEVICE_ID_LEN) == dev

        # a signature over the payload WITHOUT the domain prefix must not verify
        assert VERIFY(pk, sig, msg)
        assert not VERIFY(pk, SIGN(seed, p), msg)

        # every single-bit flip in the payload breaks the signature
        for byte in range(PAYLOAD_LEN):
            for bit in range(8):
                bad = bytearray(p)
                bad[byte] ^= 1 << bit
                assert not VERIFY(pk, sig, SIGN_PREFIX + b"\x00" + bytes(bad))

        # the key file permission gate actually fires
        kp = os.path.join(d, "k.key")
        open(kp, "w").write(seed.hex())
        os.chmod(kp, 0o644)
        try:
            read_key(kp)
        except SystemExit:
            pass
        else:
            raise AssertionError("read_key accepted a world-readable key file")
        os.chmod(kp, 0o600)
        assert read_key(kp) == seed

        # REGRESSION: `keygen --force` over a pre-existing world-readable key
        # file must not put the new private key into that file's OLD mode.
        # O_CREAT's mode applies only on creation, so the old code opened the
        # existing 0644 inode, wrote the seed, and only then chmod'ed to 0600 --
        # world-readable for the length of the write. Check the mode of the fd
        # AT open time, before any byte is written; that is the same stat-based
        # check that demonstrated the bug, minus the race.
        fk = os.path.join(d, "vendor.key")
        open(fk, "w").write("00" * 32 + "\n")
        os.chmod(fk, 0o644)
        modes, real_open = [], os.open

        def spy_open(path, flags, *rest):
            fd = real_open(path, flags, *rest)
            modes.append((stat.S_IMODE(os.fstat(fd).st_mode), flags))
            return fd

        os.open = spy_open
        try:
            cmd_keygen(argparse.Namespace(key=fk, key_id=1, force=True))
        finally:
            os.open = real_open
        assert len(modes) == 1, modes
        mode_at_open, flags_at_open = modes[0]
        assert mode_at_open == 0o600, \
            f"private key was created at mode {mode_at_open:04o}, not 0600"
        assert flags_at_open & os.O_EXCL, "key file inode was reused rather than created"
        assert stat.S_IMODE(os.stat(fk).st_mode) == 0o600
        assert read_key(fk) != bytes(32), "keygen --force did not replace the key"

        # REGRESSION: `inspect --pubkey <keyfile>` must DERIVE the public key
        # from the private seed. Passing the seed itself to VERIFY() made every
        # genuine licence report "DOES NOT VERIFY" and exit 1.
        assert pk != seed, "an Ed25519 seed is not its own public key"
        cmd_inspect(argparse.Namespace(blob=blob, pubkey=kp))     # exits 1 on the old code
        cmd_inspect(argparse.Namespace(blob=blob, pubkey=pk.hex()))

        # ...and a 64-CHARACTER PATH must be treated as a path, not as hex.
        long_path = os.path.join(d, "k" * (63 - len(d)))
        assert len(long_path) == 64, len(long_path)
        open(long_path, "w").write(seed.hex())
        os.chmod(long_path, 0o600)
        cmd_inspect(argparse.Namespace(blob=blob, pubkey=long_path))  # ValueError on the old code
    print("selftest: ok")


# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="VectiLicense vendor minting tool (holds the private key).")
    sub = ap.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("keygen", help="create a private key, print the public key as C")
    g.add_argument("--key", default="vendor.key")
    g.add_argument("--key-id", type=int, default=1)
    g.add_argument("--force", action="store_true", help="overwrite an existing key file")
    g.set_defaults(fn=cmd_keygen)

    g = sub.add_parser("pubkey", help="re-print the C array for an existing key")
    g.add_argument("--key", default="vendor.key")
    g.add_argument("--key-id", type=int, default=1)
    g.set_defaults(fn=cmd_pubkey)

    g = sub.add_parser("issue", help="mint a licence for one device")
    g.add_argument("--key", default="vendor.key")
    g.add_argument("--device-id", help="26-character device id the customer reported")
    g.add_argument("--device-id-hex", help="the same thing as 32 hex characters")
    g.add_argument("--family", type=int, required=True)
    g.add_argument("--features", type=lambda s: int(s, 0), default=0,
                   help="32-bit bitmap, e.g. 0x0d")
    g.add_argument("--not-before", help="YYYY-MM-DD or epoch; omit for immediate")
    g.add_argument("--expires", help="YYYY-MM-DD (inclusive) or epoch; omit for perpetual")
    g.add_argument("--serial", type=int, default=0)
    g.add_argument("--key-id", type=int, default=1)
    g.add_argument("--qr", help="also write a QR PNG here")
    g.add_argument("--out", help="also write the blob to this file")
    g.add_argument("--raw", action="store_true", help="print only the blob")
    g.set_defaults(fn=cmd_issue)

    g = sub.add_parser("inspect", help="decode a blob (no private key needed)")
    g.add_argument("blob", help="the blob, or - to read stdin")
    g.add_argument("--pubkey", help="64 hex chars of a PUBLIC key, or the path to a "
                                    "private key file (the public key is derived from it), "
                                    "to also check the signature")
    g.set_defaults(fn=cmd_inspect)

    sub.add_parser("selftest", help="assert the format code against itself"
                   ).set_defaults(fn=cmd_selftest)

    a = ap.parse_args()
    if a.cmd == "issue" and not (a.device_id or a.device_id_hex):
        ap.error("issue needs --device-id or --device-id-hex")

    global SIGN, PUBKEY_OF, VERIFY
    SIGN, PUBKEY_OF, VERIFY = _crypto()
    a.fn(a)


if __name__ == "__main__":
    main()
