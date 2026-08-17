/* vl_chunk.c — see vl_chunk.h.
 *
 * (c) 2026 VectiVolt — Apache-2.0 License
 *
 * transport/ layer, built to core rules: <stdint.h> <stddef.h> and core/vl_libc.h
 * only, no allocation, no recursion, no stdio.
 */

#include "vl_chunk.h"

#include "vl_libc.h"

/* A licence blob is public, signed data — there is nothing secret in this
 * buffer, so plain memcmp is correct here and constant time buys nothing. The
 * signature check inside vl_verify() is where timing matters. */

vl_status_t vl_chunk_reset(vl_chunk_t *c, size_t chunk_size, size_t total_len)
{
    uint32_t cs;

    if (c == NULL) return VL_ERR_INVALID_ARG;

    /* Zero first: a rejected reset leaves armed == 0, so feed() and
     * complete() fail closed instead of running with stale sizes. */
    memset(c, 0, sizeof *c);

    /* Validate the value that actually gets STORED, not the one passed in.
     * chunk_size is a size_t but the state holds a uint32_t, so on a 64-bit
     * host a chunk_size of 2^32 used to pass the "!= 0" test and then be
     * stored as 0 — the one value this line exists to refuse — while `expect`
     * was computed from the untruncated size. Round-tripping the cast is the
     * whole check: it is exactly "the truncation lost nothing", and it is not
     * a tautology on targets where size_t is 32 bits. */
    cs = (uint32_t)chunk_size;
    if (cs == 0u || (size_t)cs != chunk_size) return VL_ERR_INVALID_ARG;
    if (total_len == 0u || total_len > (size_t)VL_CHUNK_MAX_LEN) return VL_ERR_INVALID_ARG;

    c->chunk_size = cs;
    c->total_len  = (uint32_t)total_len;
    /* Ceiling division spelled so it cannot overflow: total_len >= 1 and
     * cs >= 1 are both established above, and `total_len + cs - 1` would wrap
     * for a chunk_size near SIZE_MAX (giving expect == 0, i.e. "complete"
     * before any chunk arrives). A chunk_size larger than total_len is legal
     * and means "one chunk" -- that is what the CAN/BLE caller gets when the
     * MTU happens to exceed the blob. */
    c->expect     = (uint32_t)(((total_len - 1u) / (size_t)cs) + 1u);
    c->armed      = 1u;
    return VL_OK;
}

vl_status_t vl_chunk_feed(vl_chunk_t *c, uint32_t seq,
                          const void *data, size_t len)
{
    uint32_t off, want;
    uint8_t  mask;

    if (c == NULL || c->armed == 0u) return VL_ERR_INVALID_ARG;
    if (data == NULL && len != 0u)   return VL_ERR_INVALID_ARG;

    /* Bound the sequence number before it is used in any arithmetic. expect
     * is at most VL_CHUNK_MAX_LEN, so off and off+want cannot overflow or
     * leave the buffer. */
    if (seq >= c->expect) return VL_ERR_BAD_FORMAT;

    off  = seq * c->chunk_size;
    want = c->total_len - off;                 /* off < total_len, so want >= 1 */
    if (want > c->chunk_size) want = c->chunk_size;

    /* Exact length per position. Anything else would leave a hole we would
     * then mark as filled. Pad-stripping is the caller's job (CAN DLC, or
     * trailing zeros in a fixed 8-byte frame). */
    if (len != (size_t)want) return VL_ERR_BAD_FORMAT;

    mask = (uint8_t)(1u << (seq & 7u));
    if ((c->seen[seq >> 3] & mask) != 0u) {
        /* Retransmission. Identical is a no-op; different means the link or
         * the sender is lying, so reject the new copy and keep the old. */
        return (memcmp(c->buf + off, data, len) == 0) ? VL_OK : VL_ERR_BAD_FORMAT;
    }

    memcpy(c->buf + off, data, len);
    c->seen[seq >> 3] |= mask;
    c->have++;
    return VL_OK;
}

vl_status_t vl_chunk_complete(const vl_chunk_t *c,
                              char *out, size_t cap, size_t *out_len)
{
    if (c == NULL || out == NULL || out_len == NULL) return VL_ERR_INVALID_ARG;

    *out_len = 0u;

    if (c->armed == 0u)          return VL_ERR_INVALID_ARG;
    if (c->have != c->expect)    return VL_ERR_NOT_FOUND;
    if (cap < (size_t)c->total_len + 1u) return VL_ERR_BUFFER_TOO_SMALL;

    memcpy(out, c->buf, (size_t)c->total_len);
    out[c->total_len] = '\0';
    *out_len = (size_t)c->total_len;
    return VL_OK;
}
