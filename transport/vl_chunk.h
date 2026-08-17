/* vl_chunk.h — reassemble a licence blob that arrives in MTU-sized pieces.
 *
 * (c) 2026 VectiVolt — Apache-2.0 License
 *
 * transport/ layer: OPTIONAL, and built to core rules — pure C99, no malloc,
 * no stdio, no recursion, no floats. Delete this file if you do not need it.
 *
 * WHEN YOU NEED THIS
 *   A licence blob is 160 characters. A classic CAN frame carries 8 bytes and
 *   a BLE GATT write 20. This reassembles the blob from numbered pieces and
 *   tolerates the things a real link does: out-of-order delivery, duplicate
 *   retransmissions, and pieces that never arrive.
 *
 * WHEN YOU DO NOT
 *   HTTP, MQTT, a BLE characteristic that takes the whole blob, a file, a QR
 *   scan, a technician pasting into a terminal: none of them need this. Read
 *   the bytes, NUL-terminate them, call vl_verify(). See transport/README.md.
 *
 * THE WIRE FORMAT IS YOURS, NOT OURS
 *   This does not define frames, headers or IDs. You tell it the chunk size
 *   and the total length up front — hardcode 160, or send a header frame, or
 *   read it from your ISO-TP first frame — and then hand it (seq, bytes) for
 *   each piece you receive. Chunk `seq` occupies bytes [seq*chunk_size ...],
 *   so every chunk but the last must be exactly chunk_size bytes.
 *
 * IT HAS NO OPINION ON THE CONTENT
 *   Base32 alphabet, magic, version and signature are vl_verify()'s job, and
 *   it already rejects everything malformed before any crypto runs. This layer
 *   only bounds and orders bytes.
 *
 * TYPICAL USE, over 8-byte CAN frames:
 *
 *     vl_chunk_t rx;
 *     vl_chunk_reset(&rx, 8, VL_BLOB_STR_LEN);
 *     ... for each frame: vl_chunk_feed(&rx, frame.id_seq, frame.data, frame.dlc);
 *
 *     char blob[VL_BLOB_STR_BUF_LEN];
 *     size_t n;
 *     if (vl_chunk_complete(&rx, blob, sizeof blob, &n) == VL_OK)
 *         status = vl_verify(blob, &cfg, &hal, &lic);
 *
 * The state is ~250 bytes and lives wherever you put it — static, stack, or a
 * member of your own struct. Nothing here allocates.
 */

#ifndef VL_CHUNK_H
#define VL_CHUNK_H

#include <stddef.h>
#include <stdint.h>

#include "vectilicense/vectilicense.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Largest message this will reassemble. 160 for a bare blob; the default
 * leaves room for '-' grouping, which vl_verify() ignores anyway. Override at
 * build time (-DVL_CHUNK_MAX_LEN=...) if your framing carries something
 * bigger; it costs one byte of RAM per byte plus one bit of bitmap. */
#ifndef VL_CHUNK_MAX_LEN
#define VL_CHUNK_MAX_LEN 192u
#endif

#define VL_CHUNK_BITMAP_LEN ((VL_CHUNK_MAX_LEN + 7u) / 8u)

/* Treat as opaque. Fields are exposed only so you can size and place it. */
typedef struct {
    char     buf[VL_CHUNK_MAX_LEN + 1u];   /* +1 for the NUL complete() adds */
    uint8_t  seen[VL_CHUNK_BITMAP_LEN];    /* one bit per chunk actually received */
    uint32_t chunk_size;
    uint32_t total_len;
    uint32_t expect;                       /* chunks needed */
    uint32_t have;                         /* distinct chunks received */
    uint8_t  armed;                        /* 0 until a valid reset(); feed() fails closed */
} vl_chunk_t;

/*
 * Start (or restart) a reassembly. Discards anything already collected.
 *
 *   chunk_size  bytes per chunk, >= 1. The last chunk may be shorter.
 *   total_len   total bytes expected, 1..VL_CHUNK_MAX_LEN. Usually
 *               VL_BLOB_STR_LEN (160).
 *
 * Returns VL_ERR_INVALID_ARG for a NULL state or out-of-range sizes, and in
 * that case leaves the state disarmed so every later feed()/complete() also
 * fails rather than reassembling into a half-configured buffer.
 */
vl_status_t vl_chunk_reset(vl_chunk_t *c, size_t chunk_size, size_t total_len);

/*
 * Absorb one received chunk. `seq` is 0-based.
 *
 *   VL_OK               stored (or an identical duplicate, which is a no-op)
 *   VL_ERR_INVALID_ARG  NULL state, state never reset, or NULL data with len > 0
 *   VL_ERR_BAD_FORMAT   seq past the end of the message, wrong length for that
 *                       seq, or a duplicate whose bytes differ from the copy
 *                       already held — the earlier copy is kept
 *
 * A rejected chunk changes nothing. There is no sequence number, length or
 * repetition that can write outside the buffer.
 */
vl_status_t vl_chunk_feed(vl_chunk_t *c, uint32_t seq,
                          const void *data, size_t len);

/*
 * Hand up the reassembled message, NUL-terminated, ready for vl_verify().
 *
 *   VL_OK                    complete; *out_len is the length without the NUL
 *   VL_ERR_NOT_FOUND         not yet — at least one chunk has not arrived
 *   VL_ERR_BUFFER_TOO_SMALL  cap < total_len + 1
 *   VL_ERR_INVALID_ARG       NULL argument, or the state was never reset
 *
 * "Complete" means every chunk 0..expect-1 was individually seen. Receiving
 * the right *number* of chunks is not enough; the same chunk twice does not
 * fill in for its missing neighbour.
 */
vl_status_t vl_chunk_complete(const vl_chunk_t *c,
                              char *out, size_t cap, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* VL_CHUNK_H */
