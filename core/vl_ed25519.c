/* vl_ed25519.c — Ed25519 verification, vendored from TweetNaCl.
 *
 * ===========================================================================
 * VENDORED SOURCE
 *
 *   Upstream name : TweetNaCl
 *   Version       : 20140427
 *   Source file   : https://tweetnacl.cr.yp.to/20140427/tweetnacl.c
 *   Project page  : https://tweetnacl.cr.yp.to/
 *   SHA-256 of the upstream tweetnacl.c as fetched:
 *     02e65bc3013ff2168983365e55906bc783c4c7e0a60d8100f17bb303a17175c4
 *   Authors (alphabetical, per the project page): Daniel J. Bernstein,
 *     Bernard van Gastel, Wesley Janssen, Tanja Lange, Peter Schwabe,
 *     Sjaak Smetsers.
 *
 * LICENCE
 *
 *   TweetNaCl ships no LICENSE file; the licence is stated on the project's
 *   own introduction page (https://tweetnacl.cr.yp.to/, "version 2017.01.22
 *   of the index.html web page"). Verbatim:
 *
 *     "TweetNaCl is the world's first auditable high-security cryptographic
 *      library. TweetNaCl fits into just 100 tweets while supporting all 25
 *      of the C NaCl functions used by applications. TweetNaCl is a
 *      self-contained public-domain C library, so it can easily be
 *      integrated into applications."
 *
 *   Public domain imposes no conditions, so it is compatible with the
 *   Apache-2.0 licence of the rest of VectiLicense. Nothing here is
 *   copyrightable by us; the modifications below are contributed under
 *   Apache-2.0 along with the rest of the repository.
 *
 * WHAT WAS CHANGED
 *
 *   - Kept ONLY the verification path. crypto_sign(), crypto_sign_keypair(),
 *     randombytes(), Salsa20, Poly1305, Curve25519 scalarmult, SHA-512's
 *     TweetNaCl implementation and everything else were deleted, not
 *     ifdef'd out. There is no signing code in this file to patch back in.
 *   - `typedef unsigned long u32; typedef unsigned long long u64;` replaced
 *     with the exact-width types from <stdint.h>. `unsigned long` is 32 bits
 *     on most of our targets and 64 on LP64 hosts; TweetNaCl works either
 *     way, but exact widths remove the question.
 *   - crypto_sign_open() replaced by vl_ed25519_verify(), which takes a
 *     detached signature and streams R || A || M into vl_sha512 instead of
 *     copying the whole signed message into a caller-provided buffer.
 *     Upstream's API required a scratch buffer the size of the message; ours
 *     requires none, which is what makes it usable on a small MCU.
 *   - The final 32-byte comparison uses vl_ct_eq() rather than TweetNaCl's
 *     vn(); both are constant-time, ours returns 1/0 instead of 0/-1.
 *   - Added a check that the signature scalar S is fully reduced (S < L).
 *     Upstream accepts unreduced S, which makes signatures malleable. Not a
 *     forgery, but we have no use for two spellings of one licence.
 *   - Added public-key validation to unpackneg(): the encoding must be
 *     canonical (y < 2^255-19), and A must not lie in the 8-torsion
 *     subgroup. Upstream checks only that A is on the curve, which accepts
 *     the 14 small-order encodings — including 32 zero bytes. Against any of
 *     those, S = 0 plus a search over the few multiples of A forges a
 *     signature for any message with no private key at all, so a device that
 *     had not yet had the real vendor key pasted in would have verified
 *     every licence instead of none. See test_ed25519_small_order().
 *   - The field arithmetic (car25519, sel25519, pack25519, unpack25519,
 *     A, Z, M, S, inv25519, pow2523, add, cswap, pack, scalarmult,
 *     scalarbase, unpackneg, modL, reduce) is byte-for-byte the upstream
 *     algorithm, reformatted and retyped only.
 *
 * NOT CHANGED, AND WORTH KNOWING
 *
 *   A is now canonical-encoded and low-order-rejected (see above). R is not:
 *   like upstream, a non-canonical R is accepted, and the group equation is
 *   checked without clearing the cofactor. That is RFC 8032 "verify" rather
 *   than a stricter variant such as ZIP-215, and for this library's job — one
 *   vendor key, one signature per licence, no consensus protocol — the
 *   remaining difference has no effect. The key checks are not optional the
 *   way those are: a bad A forges, a re-spelled R does not.
 * ===========================================================================
 *
 * Part of VectiLicense. Apache-2.0. */

#include "vl_ed25519.h"

#include "vl_sha512.h"
#include "vl_util.h"

typedef uint8_t  u8;
typedef uint64_t u64;
typedef int64_t  i64;
typedef i64      gf[16];

#define FOR(i, n) for ((i) = 0; (i) < (n); ++(i))

static const gf
    gf0,
    gf1 = { 1 },
    D  = { 0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070,
           0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203 },
    D2 = { 0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0,
           0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406 },
    X  = { 0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c,
           0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169 },
    Y  = { 0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
           0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666 },
    I  = { 0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43,
           0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83 };

/* The group order L = 2^252 + 27742317777372353535851937790883648493,
 * little-endian, as used by modL(). */
static const i64 L[32] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0x10
};

/* ------------------------------------------------------------------ field */

static void set25519(gf r, const gf a)
{
    int i;
    FOR(i, 16) r[i] = a[i];
}

static void car25519(gf o)
{
    int i;
    i64 c;
    FOR(i, 16) {
        o[i] += (1LL << 16);
        c = o[i] >> 16;
        o[(i + 1) * (i < 15)] += c - 1 + 37 * (c - 1) * (i == 15);
        o[i] -= c * 65536;   /* upstream `c << 16`; c goes negative — see modL() */
    }
}

static void sel25519(gf p, gf q, int b)
{
    i64 t, c = ~((i64)b - 1);
    int i;
    FOR(i, 16) {
        t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

static void pack25519(u8 *o, const gf n)
{
    int i, j, b;
    gf m, t;
    FOR(i, 16) t[i] = n[i];
    car25519(t);
    car25519(t);
    car25519(t);
    FOR(j, 2) {
        m[0] = t[0] - 0xffed;
        for (i = 1; i < 15; i++) {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        b = (int)((m[15] >> 16) & 1);
        m[14] &= 0xffff;
        sel25519(t, m, 1 - b);
    }
    FOR(i, 16) {
        o[2 * i]     = (u8)(t[i] & 0xff);
        o[2 * i + 1] = (u8)(t[i] >> 8);
    }
}

static int neq25519(const gf a, const gf b)
{
    u8 c[32], d[32];
    int eq;
    pack25519(c, a);
    pack25519(d, b);
    eq = vl_ct_eq(c, d, 32);
    return eq ? 0 : 1;
}

static u8 par25519(const gf a)
{
    u8 d[32];
    pack25519(d, a);
    return (u8)(d[0] & 1u);
}

static void unpack25519(gf o, const u8 *n)
{
    int i;
    FOR(i, 16) o[i] = n[2 * i] + ((i64)n[2 * i + 1] << 8);
    o[15] &= 0x7fff;
}

static void A(gf o, const gf a, const gf b)
{
    int i;
    FOR(i, 16) o[i] = a[i] + b[i];
}

static void Z(gf o, const gf a, const gf b)
{
    int i;
    FOR(i, 16) o[i] = a[i] - b[i];
}

static void M(gf o, const gf a, const gf b)
{
    i64 t[31];
    int i, j;
    FOR(i, 31) t[i] = 0;
    FOR(i, 16) FOR(j, 16) t[i + j] += a[i] * b[j];
    FOR(i, 15) t[i] += 38 * t[i + 16];
    FOR(i, 16) o[i] = t[i];
    car25519(o);
    car25519(o);
}

static void S(gf o, const gf a)
{
    M(o, a, a);
}

static void inv25519(gf o, const gf i)
{
    gf c;
    int a;
    FOR(a, 16) c[a] = i[a];
    for (a = 253; a >= 0; a--) {
        S(c, c);
        if (a != 2 && a != 4) M(c, c, i);
    }
    FOR(a, 16) o[a] = c[a];
}

static void pow2523(gf o, const gf i)
{
    gf c;
    int a;
    FOR(a, 16) c[a] = i[a];
    for (a = 250; a >= 0; a--) {
        S(c, c);
        if (a != 1) M(c, c, i);
    }
    FOR(a, 16) o[a] = c[a];
}

/* ------------------------------------------------------------------ group */

static void add(gf p[4], gf q[4])
{
    gf a, b, c, d, t, e, f, g, h;

    Z(a, p[1], p[0]);
    Z(t, q[1], q[0]);
    M(a, a, t);
    A(b, p[0], p[1]);
    A(t, q[0], q[1]);
    M(b, b, t);
    M(c, p[3], q[3]);
    M(c, c, D2);
    M(d, p[2], q[2]);
    A(d, d, d);
    Z(e, b, a);
    Z(f, d, c);
    A(g, d, c);
    A(h, b, a);

    M(p[0], e, f);
    M(p[1], h, g);
    M(p[2], g, f);
    M(p[3], e, h);
}

static void cswap(gf p[4], gf q[4], u8 b)
{
    int i;
    FOR(i, 4) sel25519(p[i], q[i], (int)b);
}

static void pack(u8 *r, gf p[4])
{
    gf tx, ty, zi;
    inv25519(zi, p[2]);
    M(tx, p[0], zi);
    M(ty, p[1], zi);
    pack25519(r, ty);
    r[31] = (u8)(r[31] ^ (u8)(par25519(tx) << 7));
}

static void scalarmult(gf p[4], gf q[4], const u8 *s)
{
    int i;
    set25519(p[0], gf0);
    set25519(p[1], gf1);
    set25519(p[2], gf1);
    set25519(p[3], gf0);
    for (i = 255; i >= 0; --i) {
        u8 b = (u8)((s[i / 8] >> (i & 7)) & 1u);
        cswap(p, q, b);
        add(q, p);
        add(p, p);
        cswap(p, q, b);
    }
}

static void scalarbase(gf p[4], const u8 *s)
{
    gf q[4];
    set25519(q[0], X);
    set25519(q[1], Y);
    set25519(q[2], gf1);
    M(q[3], X, Y);
    scalarmult(p, q, s);
}

static void modL(u8 *r, i64 x[64])
{
    i64 carry;
    int i, j;
    for (i = 63; i >= 32; --i) {
        carry = 0;
        for (j = i - 32; j < i - 12; ++j) {
            x[j] += carry - 16 * x[i] * L[j - (i - 32)];
            carry = (x[j] + 128) >> 8;
            /* Upstream writes `carry << 8`. carry is routinely negative here,
             * and left-shifting a negative value is undefined behaviour in
             * C99 6.5.7p4 — UBSan flags it on the first signature checked.
             * Multiplying by 256 is the same arithmetic with defined
             * semantics, and every compiler emits the same shift. */
            x[j] -= carry * 256;
        }
        x[j] += carry;
        x[i] = 0;
    }
    carry = 0;
    FOR(j, 32) {
        x[j] += carry - (x[31] >> 4) * L[j];
        carry = x[j] >> 8;
        x[j] &= 255;
    }
    FOR(j, 32) x[j] -= carry * L[j];
    FOR(i, 32) {
        x[i + 1] += x[i] >> 8;
        r[i] = (u8)(x[i] & 255);
    }
}

static void reduce(u8 *r)
{
    i64 x[64];
    int i;
    FOR(i, 64) x[i] = (i64)r[i];
    FOR(i, 64) r[i] = 0;
    modL(r, x);
    vl_secure_wipe(x, sizeof x);
}

/* Is this point in the 8-torsion subgroup, i.e. does it have order 1, 2, 4
 * or 8? Such a key is a universal forgery: h*A depends only on h mod ord(A),
 * so an attacker with no private key sets S = 0 and searches the ord(A)
 * multiples of A for an R satisfying S*B - h*A == R. Rejecting the identity
 * after three doublings catches every one of them, including the 32 zero
 * bytes a copy-paste integrator ships as a placeholder key. */
static int is_low_order(gf p[4])
{
    static const u8 identity[32] = { 1, 0, 0, 0, 0, 0, 0, 0,
                                     0, 0, 0, 0, 0, 0, 0, 0,
                                     0, 0, 0, 0, 0, 0, 0, 0,
                                     0, 0, 0, 0, 0, 0, 0, 0 };
    gf t[4];
    u8 e[32];
    int i, low;
    FOR(i, 4) set25519(t[i], p[i]);
    add(t, t);   /* 2A */
    add(t, t);   /* 4A */
    add(t, t);   /* 8A */
    pack(e, t);
    low = vl_ct_eq(e, identity, 32);
    vl_secure_wipe(e, sizeof e);
    return low;
}

static int unpackneg(gf r[4], const u8 p[32])
{
    gf t, chk, num, den, den2, den4, den6;
    u8 canon[32];
    set25519(r[2], gf1);
    unpack25519(r[1], p);

    /* unpack25519() reduces modulo nothing, so y and y + (2^255-19) decode to
     * the same point under two different 32-byte strings. One key, one
     * spelling: reject the non-canonical one. */
    pack25519(canon, r[1]);
    canon[31] = (u8)(canon[31] | (u8)(p[31] & 0x80u));
    if (!vl_ct_eq(canon, p, 32)) return -1;

    S(num, r[1]);
    M(den, num, D);
    Z(num, num, r[2]);
    A(den, r[2], den);

    S(den2, den);
    S(den4, den2);
    M(den6, den4, den2);
    M(t, den6, num);
    M(t, t, den);

    pow2523(t, t);
    M(t, t, num);
    M(t, t, den);
    M(t, t, den);
    M(r[0], t, den);

    S(chk, r[0]);
    M(chk, chk, den);
    if (neq25519(chk, num)) M(r[0], r[0], I);

    S(chk, r[0]);
    M(chk, chk, den);
    if (neq25519(chk, num)) return -1;

    if (par25519(r[0]) == (p[31] >> 7)) Z(r[0], gf0, r[0]);

    M(r[3], r[0], r[1]);

    if (is_low_order(r)) return -1;
    return 0;
}

/* Is the signature scalar S strictly less than the group order?
 * S is public (it is half the signature), so a branching compare leaks
 * nothing an attacker does not already hold. */
static int scalar_is_reduced(const u8 s[32])
{
    int i;
    for (i = 31; i >= 0; --i) {
        if ((i64)s[i] < L[i]) return 1;
        if ((i64)s[i] > L[i]) return 0;
    }
    return 0;   /* S == L is not less than L */
}

/* ----------------------------------------------------------------- public */

int vl_ed25519_verify(const uint8_t sig[VL_ED25519_SIG_LEN],
                      const uint8_t *msg, size_t msg_len,
                      const uint8_t pk[VL_ED25519_PUBKEY_LEN])
{
    gf p[4], q[4];
    u8 t[32], h[64];
    vl_sha512_ctx_t sh;
    int ok;

    if (sig == NULL || pk == NULL || (msg == NULL && msg_len != 0u)) {
        return 0;
    }
    if (!scalar_is_reduced(sig + 32)) {
        return 0;
    }
    if (unpackneg(q, pk) != 0) {
        return 0;   /* A is off-curve, non-canonically encoded, or low order */
    }

    /* h = SHA-512(R || A || M), streamed. Upstream copied R || A || M into a
     * message-sized buffer first; we do not have one to spare. */
    vl_sha512_init(&sh);
    vl_sha512_update(&sh, sig, 32);
    vl_sha512_update(&sh, pk, 32);
    vl_sha512_update(&sh, msg, msg_len);
    vl_sha512_final(&sh, h);
    reduce(h);

    scalarmult(p, q, h);      /* p = h * (-A) */
    scalarbase(q, sig + 32);  /* q = S * B    */
    add(p, q);                /* p = S*B - h*A, which must equal R */
    pack(t, p);

    ok = vl_ct_eq(sig, t, 32);

    vl_secure_wipe(h, sizeof h);
    vl_secure_wipe(t, sizeof t);
    return ok;
}
