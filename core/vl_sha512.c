/* vl_sha512.c — SHA-512, FIPS 180-4 reference implementation.
 *
 * Same shape as vl_sha256.c: 64-bit words, 128-byte blocks, 80 rounds, a
 * 128-bit length field. No data-dependent branches, no allocation.
 *
 * Part of VectiLicense. Apache-2.0. */

#include "vl_sha512.h"
#include "vl_util.h"

#include "vl_libc.h"

static const uint64_t K512[80] = {
    0x428a2f98d728ae22ull, 0x7137449123ef65cdull, 0xb5c0fbcfec4d3b2full,
    0xe9b5dba58189dbbcull, 0x3956c25bf348b538ull, 0x59f111f1b605d019ull,
    0x923f82a4af194f9bull, 0xab1c5ed5da6d8118ull, 0xd807aa98a3030242ull,
    0x12835b0145706fbeull, 0x243185be4ee4b28cull, 0x550c7dc3d5ffb4e2ull,
    0x72be5d74f27b896full, 0x80deb1fe3b1696b1ull, 0x9bdc06a725c71235ull,
    0xc19bf174cf692694ull, 0xe49b69c19ef14ad2ull, 0xefbe4786384f25e3ull,
    0x0fc19dc68b8cd5b5ull, 0x240ca1cc77ac9c65ull, 0x2de92c6f592b0275ull,
    0x4a7484aa6ea6e483ull, 0x5cb0a9dcbd41fbd4ull, 0x76f988da831153b5ull,
    0x983e5152ee66dfabull, 0xa831c66d2db43210ull, 0xb00327c898fb213full,
    0xbf597fc7beef0ee4ull, 0xc6e00bf33da88fc2ull, 0xd5a79147930aa725ull,
    0x06ca6351e003826full, 0x142929670a0e6e70ull, 0x27b70a8546d22ffcull,
    0x2e1b21385c26c926ull, 0x4d2c6dfc5ac42aedull, 0x53380d139d95b3dfull,
    0x650a73548baf63deull, 0x766a0abb3c77b2a8ull, 0x81c2c92e47edaee6ull,
    0x92722c851482353bull, 0xa2bfe8a14cf10364ull, 0xa81a664bbc423001ull,
    0xc24b8b70d0f89791ull, 0xc76c51a30654be30ull, 0xd192e819d6ef5218ull,
    0xd69906245565a910ull, 0xf40e35855771202aull, 0x106aa07032bbd1b8ull,
    0x19a4c116b8d2d0c8ull, 0x1e376c085141ab53ull, 0x2748774cdf8eeb99ull,
    0x34b0bcb5e19b48a8ull, 0x391c0cb3c5c95a63ull, 0x4ed8aa4ae3418acbull,
    0x5b9cca4f7763e373ull, 0x682e6ff3d6b2b8a3ull, 0x748f82ee5defb2fcull,
    0x78a5636f43172f60ull, 0x84c87814a1f0ab72ull, 0x8cc702081a6439ecull,
    0x90befffa23631e28ull, 0xa4506cebde82bde9ull, 0xbef9a3f7b2c67915ull,
    0xc67178f2e372532bull, 0xca273eceea26619cull, 0xd186b8c721c0c207ull,
    0xeada7dd6cde0eb1eull, 0xf57d4f7fee6ed178ull, 0x06f067aa72176fbaull,
    0x0a637dc5a2c898a6ull, 0x113f9804bef90daeull, 0x1b710b35131c471bull,
    0x28db77f523047d84ull, 0x32caab7b40c72493ull, 0x3c9ebe0a15c9bebcull,
    0x431d67c49c100d4cull, 0x4cc5d4becb3e42b6ull, 0x597f299cfc657e2aull,
    0x5fcb6fab3ad6faecull, 0x6c44198c4a475817ull
};

static uint64_t rotr64(uint64_t x, unsigned n)
{
    return (uint64_t)((x >> n) | (x << (64u - n)));
}

static void sha512_compress(uint64_t state[8], const uint8_t block[VL_SHA512_BLOCK_LEN])
{
    uint64_t w[80];
    uint64_t a, b, c, d, e, f, g, h;
    unsigned i, j;

    for (i = 0; i < 16u; i++) {
        uint64_t v = 0;
        for (j = 0; j < 8u; j++) {
            v = (v << 8) | (uint64_t)block[i * 8u + j];
        }
        w[i] = v;
    }
    for (i = 16u; i < 80u; i++) {
        uint64_t s0 = rotr64(w[i - 15u], 1) ^ rotr64(w[i - 15u],  8) ^ (w[i - 15u] >> 7);
        uint64_t s1 = rotr64(w[i -  2u], 19) ^ rotr64(w[i - 2u], 61) ^ (w[i -  2u] >> 6);
        w[i] = w[i - 16u] + s0 + w[i - 7u] + s1;
    }

    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];

    for (i = 0; i < 80u; i++) {
        uint64_t S1  = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41);
        uint64_t ch  = (uint64_t)((e & f) ^ ((~e) & g));
        uint64_t t1  = h + S1 + ch + K512[i] + w[i];
        uint64_t S0  = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39);
        uint64_t maj = (uint64_t)((a & b) ^ (a & c) ^ (b & c));
        uint64_t t2  = S0 + maj;
        h = g; g = f; f = e;
        e = d + t1;
        d = c; c = b; b = a;
        a = t1 + t2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;

    vl_secure_wipe(w, sizeof w);
}

void vl_sha512_init(vl_sha512_ctx_t *ctx)
{
    if (ctx == NULL) {
        return;
    }
    ctx->state[0] = 0x6a09e667f3bcc908ull;
    ctx->state[1] = 0xbb67ae8584caa73bull;
    ctx->state[2] = 0x3c6ef372fe94f82bull;
    ctx->state[3] = 0xa54ff53a5f1d36f1ull;
    ctx->state[4] = 0x510e527fade682d1ull;
    ctx->state[5] = 0x9b05688c2b3e6c1full;
    ctx->state[6] = 0x1f83d9abfb41bd6bull;
    ctx->state[7] = 0x5be0cd19137e2179ull;
    ctx->byte_count = 0;
    ctx->buffer_len = 0;
}

void vl_sha512_update(vl_sha512_ctx_t *ctx, const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;

    if (ctx == NULL || (p == NULL && len != 0u)) {
        return;
    }
    if (len == 0u) {
        /* Absorbing nothing is a no-op, and taking the normal path would run
         * `p += 0` on a possibly-NULL p, which C99 6.5.6p8 leaves undefined.
         * Reachable from vl_ed25519_verify(sig, NULL, 0, pk) — the empty
         * signed message of RFC 8032 test 1. */
        return;
    }
    ctx->byte_count += (uint64_t)len;

    if (ctx->buffer_len > 0u) {
        size_t take = VL_SHA512_BLOCK_LEN - ctx->buffer_len;
        if (take > len) {
            take = len;
        }
        memcpy(ctx->buffer + ctx->buffer_len, p, take);
        ctx->buffer_len += take;
        p   += take;
        len -= take;
        if (ctx->buffer_len == VL_SHA512_BLOCK_LEN) {
            sha512_compress(ctx->state, ctx->buffer);
            ctx->buffer_len = 0;
        }
    }
    while (len >= VL_SHA512_BLOCK_LEN) {
        sha512_compress(ctx->state, p);
        p   += VL_SHA512_BLOCK_LEN;
        len -= VL_SHA512_BLOCK_LEN;
    }
    if (len > 0u) {
        memcpy(ctx->buffer, p, len);
        ctx->buffer_len = len;
    }
}

void vl_sha512_final(vl_sha512_ctx_t *ctx, uint8_t out[VL_SHA512_DIGEST_LEN])
{
    uint64_t lo, hi;
    unsigned i;

    if (ctx == NULL || out == NULL) {
        return;
    }
    /* 128-bit big-endian bit length. Message sizes here never come close to
     * 2^61 bytes, but split it properly rather than assume. */
    lo = ctx->byte_count << 3;
    hi = ctx->byte_count >> 61;

    ctx->buffer[ctx->buffer_len++] = 0x80u;
    if (ctx->buffer_len > 112u) {
        memset(ctx->buffer + ctx->buffer_len, 0, VL_SHA512_BLOCK_LEN - ctx->buffer_len);
        sha512_compress(ctx->state, ctx->buffer);
        ctx->buffer_len = 0;
    }
    memset(ctx->buffer + ctx->buffer_len, 0, 112u - ctx->buffer_len);
    for (i = 0; i < 8u; i++) {
        ctx->buffer[119u - i] = (uint8_t)(hi & 0xFFu);
        hi >>= 8;
        ctx->buffer[127u - i] = (uint8_t)(lo & 0xFFu);
        lo >>= 8;
    }
    sha512_compress(ctx->state, ctx->buffer);

    for (i = 0; i < 8u; i++) {
        unsigned j;
        for (j = 0; j < 8u; j++) {
            out[i * 8u + j] = (uint8_t)(ctx->state[i] >> (56u - 8u * j));
        }
    }
    vl_secure_wipe(ctx, sizeof *ctx);
}

void vl_sha512(const void *data, size_t len, uint8_t out[VL_SHA512_DIGEST_LEN])
{
    vl_sha512_ctx_t ctx;
    vl_sha512_init(&ctx);
    vl_sha512_update(&ctx, data, len);
    vl_sha512_final(&ctx, out);
}
