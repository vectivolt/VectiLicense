# transport/ — optional framing helpers

`vl_verify()` takes a NUL-terminated Crockford base32 string. That is the entire
transport contract. Anything that can deliver 160 characters into a `char[161]`
already works, with no code from this directory.

**Most transports need nothing here.** Read the bytes, NUL-terminate them, call
`vl_verify()`:

| Transport | What you write |
|---|---|
| HTTP / HTTPS POST | copy the body into `char blob[VL_BLOB_STR_BUF_LEN]`, verify |
| MQTT | the payload of one message is the whole blob, verify |
| BLE — one long write / a 160-byte characteristic | verify the value |
| File (SD card, LittleFS, USB mass storage) | read the file, verify |
| QR code | the decoder hands you a string, verify |
| Technician pasting into a web form or captive portal | verify the field |
| VectiNet captive portal `Textarea`, VectiDash `input` widget | verify the value |

Two transports genuinely need framing, and only those two are here. Both are
optional, independently deletable, and built to core rules: pure C99, no
allocation, no stdio, no recursion. Together they are **462 bytes of Thumb code
on a Cortex-M0+** (`-Os`), 240 bytes of RAM for a chunk reassembler and 224 for a
line buffer, at the default limits.

## `vl_chunk.[ch]` — MTU-limited links

A classic CAN frame carries 8 bytes; a default BLE GATT write carries 20. A
160-character blob does not fit either, so it arrives as numbered pieces that
may be reordered, repeated, or lost.

```c
vl_chunk_t rx;
vl_chunk_reset(&rx, 8, VL_BLOB_STR_LEN);          /* chunk size, total length */

/* for every frame received, in any order, repeated as often as the link likes */
vl_chunk_feed(&rx, seq, frame.data, frame.dlc);

char blob[VL_BLOB_STR_BUF_LEN];
size_t n;
if (vl_chunk_complete(&rx, blob, sizeof blob, &n) == VL_OK)
    status = vl_verify(blob, &cfg, &hal, &lic);
```

- Coverage is tracked as a **bitmap, one bit per chunk**. `complete()` succeeds
  only when every chunk 0..n-1 was individually seen — the same chunk arriving
  twenty times does not stand in for the neighbour that never came.
- Out-of-order and duplicate frames are fine. A duplicate whose bytes *differ*
  from the copy already held is rejected and the first copy kept.
- Sequence numbers are bounded before any arithmetic uses them, so no `seq`,
  length, or repetition can write outside the buffer. `0xFFFFFFFF` is just
  `VL_ERR_BAD_FORMAT`.
- It defines no wire format. Frame IDs, headers and how the receiver learns the
  total length are yours; hardcode `VL_BLOB_STR_LEN`, or send a header frame, or
  take it from the ISO-TP First Frame.
- It has no opinion on the content. Alphabet, magic, version and signature are
  `vl_verify()`'s job, and it rejects everything malformed before any crypto
  runs.

Works over raw CAN, ISO-TP, BLE GATT writes, LoRa, 802.15.4 — any link where you
can number the pieces.

## `vl_line.[ch]` — UART, USB-CDC, telnet

A byte stream has no message boundaries.

```c
static vl_line_t ln;
for (i = 0; i < n; i++)
    if (vl_line_push(&ln, rx[i]) == VL_OK)
        status = vl_verify(ln.buf, &cfg, &hal, &lic);
```

- Both `\r` and `\n` terminate a line — a terminal's Enter key sends `\r`,
  telnet sends both — and an empty line is skipped, so CRLF yields exactly one
  line.
- Whitespace is dropped rather than stored, so padding disappears. `-` grouping
  is kept, because `vl_verify()` ignores it anyway:
  `AR0GE0GD-00000... ` verifies as-is.
- A line that never ends cannot overflow anything. Past `VL_LINE_MAX_LEN` the
  line is abandoned and discarded; the terminator that eventually arrives
  returns `VL_ERR_BAD_FORMAT` once, and the next line starts clean.

## Limits

Both are compile-time, and both are RAM you can trade away:

```
-DVL_CHUNK_MAX_LEN=192   /* longest message reassembled */
-DVL_LINE_MAX_LEN=200    /* longest line accepted, whitespace excluded */
```

The defaults leave room above the 160-character blob for `-` grouping. Set them
to 160 if your framing carries nothing else.

## Tests

`tests/test_vl_transport.c` — shuffled, duplicated, conflicting, missing and
adversarially-numbered chunks; a 1-byte MTU; split writes, CRLF, bare CR,
overlong lines and a 100 kB line with no terminator; guard bytes around both
state structs; and a real minted blob pushed through each helper and then
through `vl_verify()`.

```
cc -std=c99 -Wall -Wextra -Werror -Icore -Iinclude -Itests -Itransport \
   core/vl_*.c transport/vl_*.c tests/test_vl_transport.c \
   -o /tmp/test_vl_transport && /tmp/test_vl_transport
```

(c) 2026 VectiVolt — Apache-2.0 License
