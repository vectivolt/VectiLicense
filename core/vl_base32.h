/* vl_base32.h — Crockford base32. http://www.crockford.com/base32.html
 *
 * Part of VectiLicense. Apache-2.0.
 * core/ layer: pure C99, freestanding. */

#ifndef VL_BASE32_H
#define VL_BASE32_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Hard cap on how many input characters vl_base32_decode() will scan before
 * giving up. Bounds the work done on a hostile / unterminated buffer. */
#define VL_BASE32_MAX_INPUT  1024u

/* Number of base32 characters needed for n bytes. */
#define VL_BASE32_CHARS(n)   (((n) * 8u + 4u) / 5u)

/* Encode `in_len` bytes as uppercase Crockford base32, NUL-terminated.
 * Returns the character count (excluding NUL), or -1 if the arguments are
 * bad or `out_capacity` is too small. */
int vl_base32_encode(const uint8_t *in, size_t in_len,
                     char *out, size_t out_capacity);

/* Decode a NUL-terminated Crockford base32 string.
 *
 * Accepts: 0-9 A-Z a-z, with the Crockford aliases I/i/L/l -> 1 and O/o -> 0.
 * Ignores '-', ' ', '\t', '\r' and '\n' as grouping characters.
 * Rejects: U/u (excluded from the alphabet), any other byte, an input longer
 * than VL_BASE32_MAX_INPUT, and anything that would write past out_capacity.
 *
 * `expect_bytes` is the strict-length contract and should always be used for
 * anything security-relevant. When non-zero the decode additionally requires:
 *   - exactly VL_BASE32_CHARS(expect_bytes) significant characters
 *   - exactly expect_bytes bytes of output
 *   - the trailing pad bits to be zero, so no two distinct byte strings share
 *     an encoding and no accepted string decodes to a short payload
 * Pass 0 to decode whatever is there (used by tests only).
 *
 * CANONICALITY, PRECISELY: the DECODED BYTES are canonical; the STRING is
 * not. Crockford's aliases (I/i/L/l -> 1, O/o -> 0), lowercase, and the
 * ignored grouping characters give one payload many distinct strings that all
 * decode to the same bytes and all verify. That is deliberate — the aliases
 * exist so a human reading a licence off a label cannot mistype it — and it
 * costs nothing here, because vl_verify() checks the signature over the
 * decoded bytes and never looks at the string again.
 *
 * It does mean a string is not an identity. Anything that dedupes activations
 * or keeps a redeemed-blob list MUST NOT key on the operator's spelling:
 * either key on the payload serial, or re-encode the decoded bytes with
 * vl_base32_encode() and key on that. Stripping grouping characters is not
 * enough. No canonicality check is provided because nothing in core needs
 * one; re-encoding is the check, and it is one call.
 *
 * Returns the byte count on success, -1 on any failure. Never reads past the
 * terminating NUL and never writes past out_capacity. */
int vl_base32_decode(const char *in,
                     uint8_t *out, size_t out_capacity,
                     size_t expect_bytes);

#ifdef __cplusplus
}
#endif

#endif /* VL_BASE32_H */
