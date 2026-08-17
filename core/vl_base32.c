/* vl_base32.c — Crockford base32.
 *
 * Ported from the v0.1 base32 codec and hardened:
 *   - no lazily-initialised mutable global table (the v0.1 decoder had a
 *     `static uint8_t DEC_TABLE[256]` built on first use, which is neither
 *     thread-safe nor ROM-able); the alphabet is now a const table
 *   - 'U' is rejected rather than silently accepted as an alias
 *   - the input scan is bounded by VL_BASE32_MAX_INPUT
 *   - non-zero trailing pad bits are rejected, so the encoding is canonical
 *   - the output-capacity check happens before every write
 *
 * Not constant-time, and it does not need to be: the licence blob is public
 * data supplied by the attacker, and nothing secret flows through here.
 *
 * Part of VectiLicense. Apache-2.0. */

#include "vl_base32.h"

static const char ENC_ALPHA[32] = {
    '0','1','2','3','4','5','6','7','8','9',
    'A','B','C','D','E','F','G','H','J','K',
    'M','N','P','Q','R','S','T','V','W','X',
    'Y','Z'
};

/* Value of 'A'..'Z'. -1 = not in the alphabet. I and L alias to 1, O to 0,
 * U is excluded outright (Crockford drops it to avoid accidental obscenities
 * and it is not an alias for anything). */
static const signed char A2V[26] = {
    10, 11, 12, 13, 14, 15, 16, 17,  1, 18, 19,  1, 20,
    21,  0, 22, 23, 24, 25, 26, -1, 27, 28, 29, 30, 31
};

/* Returns 0..31 for a value character, -2 for an ignorable grouping
 * character, -1 for anything else. */
static int b32_val(char ch)
{
    unsigned char c = (unsigned char)ch;

    if (c == '-' || c == ' ' || c == '\t' || c == '\r' || c == '\n') {
        return -2;
    }
    if (c >= '0' && c <= '9') {
        return (int)(c - '0');
    }
    if (c >= 'a' && c <= 'z') {
        c = (unsigned char)(c - 32u);
    }
    if (c >= 'A' && c <= 'Z') {
        return (int)A2V[c - 'A'];
    }
    return -1;
}

int vl_base32_encode(const uint8_t *in, size_t in_len,
                     char *out, size_t out_capacity)
{
    uint32_t buffer = 0;
    unsigned bits = 0;
    size_t out_idx = 0;
    size_t out_chars;
    size_t i;

    if (in == NULL || out == NULL) {
        return -1;
    }
    if (in_len > (VL_BASE32_MAX_INPUT / 2u)) {
        return -1;   /* would exceed what the decoder will ever accept back */
    }
    out_chars = VL_BASE32_CHARS(in_len);
    if (out_capacity < out_chars + 1u) {
        return -1;
    }

    for (i = 0; i < in_len; i++) {
        buffer = (buffer << 8) | (uint32_t)in[i];
        bits  += 8u;
        while (bits >= 5u) {
            bits -= 5u;
            out[out_idx++] = ENC_ALPHA[(buffer >> bits) & 0x1Fu];
        }
    }
    if (bits > 0u) {
        out[out_idx++] = ENC_ALPHA[(buffer << (5u - bits)) & 0x1Fu];
    }
    out[out_idx] = '\0';
    return (int)out_idx;
}

int vl_base32_decode(const char *in,
                     uint8_t *out, size_t out_capacity,
                     size_t expect_bytes)
{
    uint32_t buffer = 0;
    unsigned bits = 0;
    size_t out_idx = 0;
    size_t chars = 0;
    size_t scanned;

    if (in == NULL || out == NULL) {
        return -1;
    }
    if (expect_bytes != 0u && out_capacity < expect_bytes) {
        return -1;
    }

    for (scanned = 0; in[scanned] != '\0'; scanned++) {
        int v;
        if (scanned >= VL_BASE32_MAX_INPUT) {
            return -1;                      /* absurdly long / unterminated */
        }
        v = b32_val(in[scanned]);
        if (v == -2) {
            continue;                       /* grouping character */
        }
        if (v < 0) {
            return -1;                      /* out of alphabet */
        }
        buffer = (buffer << 5) | (uint32_t)v;
        bits  += 5u;
        chars++;
        if (bits >= 8u) {
            bits -= 8u;
            if (out_idx >= out_capacity) {
                return -1;                  /* checked before every write */
            }
            out[out_idx++] = (uint8_t)((buffer >> bits) & 0xFFu);
        }
    }

    /* Leftover bits are encoder padding and must be zero, otherwise the same
     * byte string has more than one spelling. */
    if (bits > 0u && (buffer & ((1u << bits) - 1u)) != 0u) {
        return -1;
    }

    if (expect_bytes != 0u) {
        if (chars != VL_BASE32_CHARS(expect_bytes)) {
            return -1;
        }
        if (out_idx != expect_bytes) {
            return -1;
        }
    }
    return (int)out_idx;
}
