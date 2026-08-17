/* test_vl_core.c — known-answer tests for the VectiLicense core.
 *
 * Covers:
 *   - NIST SHA-256 and SHA-512 known-answer vectors (incl. the 1,000,000 'a'
 *     cases, which exercise the multi-block and length-encoding paths)
 *   - RFC 8032 section 7.1 Ed25519 vectors, positive and mutated
 *   - Crockford base32 round-trip, aliases, and every rejection case
 *   - vl_verify() end to end against blobs minted by tools/vl_mint.py's
 *     algorithm, plus every rejection path and a flip-every-bit sweep
 *
 * This file is a host test. It is NOT part of the core build and is the only
 * place in the repo that is allowed to use stdio.
 *
 * Build:
 *   cc -std=c99 -Wall -Wextra -Icore -Iinclude -Itests \
 *      core/vl_*.c tests/test_vl_core.c -o /tmp/test_vl_core && /tmp/test_vl_core
 *
 * Part of VectiLicense. Apache-2.0. */

#include "vectilicense/vectilicense.h"

#include "vl_base32.h"
#include "vl_ed25519.h"
#include "vl_sha256.h"
#include "vl_sha512.h"
#include "vl_util.h"

#include "vl_test_fixtures.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond, ...)                                       \
    do {                                                       \
        if (cond) { g_pass++; }                                \
        else {                                                 \
            g_fail++;                                          \
            printf("  FAIL %s:%d: ", __FILE__, __LINE__);      \
            printf(__VA_ARGS__);                               \
            printf("\n");                                      \
        }                                                      \
    } while (0)

static int hexeq(const uint8_t *got, const char *want_hex, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++) {
        char b[3];
        unsigned v;
        b[0] = want_hex[i * 2];
        b[1] = want_hex[i * 2 + 1];
        b[2] = 0;
        v = (unsigned)strtoul(b, NULL, 16);
        if (got[i] != (uint8_t)v) return 0;
    }
    return 1;
}

static void unhex(const char *hex, uint8_t *out, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++) {
        char b[3];
        b[0] = hex[i * 2];
        b[1] = hex[i * 2 + 1];
        b[2] = 0;
        out[i] = (uint8_t)strtoul(b, NULL, 16);
    }
}

/* ========================================================================== */
/* SHA-256 / SHA-512 — NIST FIPS 180-4 examples                               */
/* ========================================================================== */
static void test_sha(void)
{
    uint8_t d32[32], d64[64];
    vl_sha256_ctx_t c2;
    vl_sha512_ctx_t c5;
    int i;

    puts("SHA-256 / SHA-512 known-answer vectors");

    vl_sha256("abc", 3, d32);
    CHECK(hexeq(d32, "ba7816bf8f01cfea414140de5dae2223"
                     "b00361a396177a9cb410ff61f20015ad", 32), "sha256(abc)");

    vl_sha256("", 0, d32);
    CHECK(hexeq(d32, "e3b0c44298fc1c149afbf4c8996fb924"
                     "27ae41e4649b934ca495991b7852b855", 32), "sha256(empty)");

    vl_sha256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56, d32);
    CHECK(hexeq(d32, "248d6a61d20638b8e5c026930c3e6039"
                     "a33ce45964ff2167f6ecedd419db06c1", 32), "sha256(448-bit)");

    vl_sha256_init(&c2);
    for (i = 0; i < 1000; i++) {
        vl_sha256_update(&c2, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1000);
    }
    vl_sha256_final(&c2, d32);
    CHECK(hexeq(d32, "cdc76e5c9914fb9281a1c7e284d73e67"
                     "f1809a48a497200e046d39ccc7112cd0", 32), "sha256(1M 'a')");

    /* A zero-length update must be a no-op, and must not do `p += 0` on a
     * NULL p — C99 6.5.6p8 leaves that undefined and UBSan aborts on it.
     * Reachable in production from vl_ed25519_verify(sig, NULL, 0, pk).
     * Both orderings matter: with an empty buffer, and with a partial block
     * buffered so the `take` clamp is what produces the zero. */
    vl_sha256_init(&c2);
    vl_sha256_update(&c2, NULL, 0);
    vl_sha256_update(&c2, "a", 1);
    vl_sha256_update(&c2, NULL, 0);
    vl_sha256_update(&c2, "bc", 2);
    vl_sha256_update(&c2, NULL, 0);
    vl_sha256_final(&c2, d32);
    CHECK(hexeq(d32, "ba7816bf8f01cfea414140de5dae2223"
                     "b00361a396177a9cb410ff61f20015ad", 32),
          "sha256: NULL/0 updates around a partial block are no-ops");

    vl_sha512("abc", 3, d64);
    CHECK(hexeq(d64, "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea2"
                     "0a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd"
                     "454d4423643ce80e2a9ac94fa54ca49f", 64), "sha512(abc)");

    vl_sha512("", 0, d64);
    CHECK(hexeq(d64, "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc"
                     "83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f"
                     "63b931bd47417a81a538327af927da3e", 64), "sha512(empty)");

    vl_sha512("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
              "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", 112, d64);
    CHECK(hexeq(d64, "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa1"
                     "7299aeadb6889018501d289e4900f7e4331b99dec4b5433a"
                     "c7d329eeb6dd26545e96e55b874be909", 64), "sha512(896-bit)");

    vl_sha512_init(&c5);
    for (i = 0; i < 1000; i++) {
        char buf[1000];
        memset(buf, 'a', sizeof buf);
        vl_sha512_update(&c5, buf, sizeof buf);
    }
    vl_sha512_final(&c5, d64);
    CHECK(hexeq(d64, "e718483d0ce769644e2e42c7bc15b4638e1f98b13b204428"
                     "5632a803afa973ebde0ff244877ea60a4cb0432ce577c31b"
                     "eb009c5c2c49aa2e4eadb217ad8cc09b", 64), "sha512(1M 'a')");

    /* Same NULL+0 regression for SHA-512 — this is the one vl_ed25519_verify
     * hits, because R || A are already buffered when an empty message
     * arrives. */
    vl_sha512_init(&c5);
    vl_sha512_update(&c5, NULL, 0);
    vl_sha512_update(&c5, "a", 1);
    vl_sha512_update(&c5, NULL, 0);
    vl_sha512_update(&c5, "bc", 2);
    vl_sha512_update(&c5, NULL, 0);
    vl_sha512_final(&c5, d64);
    CHECK(hexeq(d64, "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea2"
                     "0a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd"
                     "454d4423643ce80e2a9ac94fa54ca49f", 64),
          "sha512: NULL/0 updates around a partial block are no-ops");

    /* Streaming in awkward chunk sizes must equal the one-shot digest. */
    {
        static const char m[] = "The quick brown fox jumps over the lazy dog";
        uint8_t a[64], b[64];
        size_t chunk;
        vl_sha512(m, sizeof m - 1, a);
        for (chunk = 1; chunk <= 13; chunk++) {
            size_t off = 0;
            vl_sha512_init(&c5);
            while (off < sizeof m - 1) {
                size_t n = (sizeof m - 1 - off < chunk) ? (sizeof m - 1 - off) : chunk;
                vl_sha512_update(&c5, m + off, n);
                off += n;
            }
            vl_sha512_final(&c5, b);
            CHECK(memcmp(a, b, 64) == 0, "sha512 streaming chunk=%u", (unsigned)chunk);
        }
    }
}

/* ========================================================================== */
/* Ed25519 — RFC 8032 section 7.1                                             */
/* ========================================================================== */
struct rfc8032_case {
    const char *name;
    const char *pk_hex;
    const char *sig_hex;
    const char *msg_hex;   /* "" for the empty message */
    size_t      msg_len;
};

static const struct rfc8032_case RFC8032[] = {
    { "TEST 1 (empty message)",
      "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
      "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f"
      "b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
      "", 0 },
    { "TEST 2 (1 octet)",
      "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
      "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da08"
      "5ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
      "72", 1 },
    { "TEST 3 (2 octets)",
      "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
      "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18"
      "ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
      "af82", 2 },
    { "TEST SHA(abc) (64 octets)",
      "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
      "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909"
      "351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
      "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a21"
      "92992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
      64 }
};

/* RFC 8032 "TEST 1024" — 1023 octets. The only vector whose message spans
 * several SHA-512 blocks, so it is the one that exercises the streaming
 * update path inside vl_ed25519_verify(). */
static const char TEST1024_PK[] =
    "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e";
static const char TEST1024_SIG[] =
    "0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350aa"
    "5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03";
static const char TEST1024_MSG[] =
    "08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98fa"
    "6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d879de"
    "7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d658675"
    "fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc1a858efc"
    "b8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4feba15452f80"
    "288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e06203b33890c"
    "c9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbefefd75499da96bd"
    "68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7aff6f6c94fcd7204"
    "ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed185ce81bd84359d4425"
    "4d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2d17ba70eb6248e594e1a"
    "2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24554119a831a9aad6079cad"
    "88425de6bde1a9187ebb6092cf67bf2b13fd65f27088d78b7e883c8759d2c4f5c6"
    "5adb7553878ad575f9fad878e80a0c9ba63bcbcc2732e69485bbc9c90bfbd62481"
    "d9089beccf80cfe2df16a2cf65bd92dd597b0707e0917af48bbb75fed413d238f5"
    "555a7a569d80c3414a8d0859dc65a46128bab27af87a71314f318c782b23ebfe80"
    "8b82b0ce26401d2e22f04d83d1255dc51addd3b75a2b1ae0784504df543af8969b"
    "e3ea7082ff7fc9888c144da2af58429ec96031dbcad3dad9af0dcbaaaf268cb8fc"
    "ffead94f3c7ca495e056a9b47acdb751fb73e666c6c655ade8297297d07ad1ba5e"
    "43f1bca32301651339e22904cc8c42f58c30c04aafdb038dda0847dd988dcda6f3"
    "bfd15c4b4c4525004aa06eeff8ca61783aacec57fb3d1f92b0fe2fd1a85f672451"
    "7b65e614ad6808d6f6ee34dff7310fdc82aebfd904b01e1dc54b2927094b2db68d"
    "6f903b68401adebf5a7e08d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145"
    "986780fc0b16ac451649de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c1"
    "7a3ca8e1b939ae49e488acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d"
    "5011fd2dcc5600a32ef5b52a1ecc820e308aa342721aac0943bf6686b64b257937"
    "6504ccc493d97e6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f25665616"
    "8e6c496afc5fb93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff35"
    "7876e506b50d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa9"
    "33a15ef1369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb686069"
    "37380db2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86ab"
    "a41c0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0";

static void test_ed25519_small_order(void);

static void test_ed25519(void)
{
    size_t i;
    uint8_t pk[32], sig[64];
    uint8_t msg[64];

    puts("Ed25519 verify — RFC 8032 section 7.1");

    for (i = 0; i < sizeof RFC8032 / sizeof RFC8032[0]; i++) {
        const struct rfc8032_case *tc = &RFC8032[i];
        unhex(tc->pk_hex, pk, 32);
        unhex(tc->sig_hex, sig, 64);
        if (tc->msg_len) unhex(tc->msg_hex, msg, tc->msg_len);

        CHECK(vl_ed25519_verify(sig, msg, tc->msg_len, pk) == 1,
              "%s should verify", tc->name);

        /* Mutate the signature: every one of the 64 bytes must matter. */
        {
            size_t b;
            int accepted = 0;
            for (b = 0; b < 64; b++) {
                sig[b] ^= 0x01u;
                if (vl_ed25519_verify(sig, msg, tc->msg_len, pk)) accepted++;
                sig[b] ^= 0x01u;
            }
            CHECK(accepted == 0, "%s: %d mutated signatures accepted",
                  tc->name, accepted);
        }
        /* Mutate the public key. */
        {
            size_t b;
            int accepted = 0;
            for (b = 0; b < 32; b++) {
                pk[b] ^= 0x80u;
                if (vl_ed25519_verify(sig, msg, tc->msg_len, pk)) accepted++;
                pk[b] ^= 0x80u;
            }
            CHECK(accepted == 0, "%s: %d mutated public keys accepted",
                  tc->name, accepted);
        }
        /* Mutate the message. */
        if (tc->msg_len) {
            msg[0] ^= 0x01u;
            CHECK(vl_ed25519_verify(sig, msg, tc->msg_len, pk) == 0,
                  "%s: mutated message accepted", tc->name);
            msg[0] ^= 0x01u;
        }
    }

    /* TEST 1024 — 1023 octets, several SHA-512 blocks. */
    {
        static uint8_t m1023[1023];
        CHECK(strlen(TEST1024_MSG) == 2046u, "TEST 1024 message is 1023 octets");
        unhex(TEST1024_PK, pk, 32);
        unhex(TEST1024_SIG, sig, 64);
        unhex(TEST1024_MSG, m1023, sizeof m1023);
        CHECK(vl_ed25519_verify(sig, m1023, sizeof m1023, pk) == 1,
              "TEST 1024 should verify");
        m1023[512] ^= 0x01u;
        CHECK(vl_ed25519_verify(sig, m1023, sizeof m1023, pk) == 0,
              "TEST 1024 with a mutated middle byte rejected");
        m1023[512] ^= 0x01u;
        CHECK(vl_ed25519_verify(sig, m1023, sizeof m1023 - 1u, pk) == 0,
              "TEST 1024 truncated by one byte rejected");
    }

    /* NULL arguments must fail, not crash. */
    unhex(RFC8032[0].pk_hex, pk, 32);
    unhex(RFC8032[0].sig_hex, sig, 64);
    CHECK(vl_ed25519_verify(NULL, msg, 0, pk) == 0, "NULL sig rejected");
    CHECK(vl_ed25519_verify(sig, NULL, 0, pk) == 1, "NULL msg with len 0 is the empty message");
    CHECK(vl_ed25519_verify(sig, NULL, 5, pk) == 0, "NULL msg with len > 0 rejected");
    CHECK(vl_ed25519_verify(sig, msg, 0, NULL) == 0, "NULL pk rejected");

    /* An unreduced scalar S (S += L) must be rejected even though the
     * underlying group equation still holds. */
    {
        static const uint8_t Lb[32] = {
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
            0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10
        };
        unsigned carry = 0;
        size_t b;
        for (b = 0; b < 32; b++) {
            unsigned v = (unsigned)sig[32 + b] + Lb[b] + carry;
            sig[32 + b] = (uint8_t)(v & 0xFFu);
            carry = v >> 8;
        }
        CHECK(vl_ed25519_verify(sig, msg, 0, pk) == 0,
              "malleable (unreduced) S rejected");
    }

    test_ed25519_small_order();
}

/* ========================================================================== */
/* Low-order public keys — the universal-forgery case                         */
/*                                                                            */
/* If A lies in the 8-torsion subgroup then h*A depends only on h mod ord(A),  */
/* with ord(A) <= 8. An attacker holding no private key of any kind sets S = 0 */
/* and tries the ord(A) multiples of A as R until S*B - h*A == R, where        */
/* h = SHA-512(R || A || M) reduced. That succeeds in a handful of tries for   */
/* ANY message, so such a key verifies everything rather than nothing — which  */
/* matters because all three examples/ files ship 32 zero bytes as a           */
/* placeholder, and 32 zero bytes decode to a point of order 4.                */
/*                                                                            */
/* The table below is the canonical 14 small-order encodings, each paired with */
/* a signature forged offline against it by tests/gen_small_order.py, which    */
/* regenerates it from independent pure-Python curve arithmetic. Before the    */
/* low-order and canonical-encoding checks were added to unpackneg(), all 14   */
/* of these returned 1.                                                        */
/* ========================================================================== */
static void test_ed25519_small_order(void)
{
    /* pk, forged sig, and the message-suffix byte that made the search hit. */
    static const struct { const char *pk; const char *sig; uint8_t n; } SO[] = {
    { "0000000000000000000000000000000000000000000000000000000000000000",
      "0000000000000000000000000000000000000000000000000000000000000000"
      "0000000000000000000000000000000000000000000000000000000000000000", 0 },
    { "0100000000000000000000000000000000000000000000000000000000000000",
      "0100000000000000000000000000000000000000000000000000000000000000"
      "0000000000000000000000000000000000000000000000000000000000000000", 0 },
    { "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
      "0100000000000000000000000000000000000000000000000000000000000000"
      "0000000000000000000000000000000000000000000000000000000000000000", 1 },
    { "0000000000000000000000000000000000000000000000000000000000000080",
      "0000000000000000000000000000000000000000000000000000000000000080"
      "0000000000000000000000000000000000000000000000000000000000000000", 1 },
    { "0100000000000000000000000000000000000000000000000000000000000080",
      "0100000000000000000000000000000000000000000000000000000000000000"
      "0000000000000000000000000000000000000000000000000000000000000000", 0 },
    { "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      "0100000000000000000000000000000000000000000000000000000000000000"
      "0000000000000000000000000000000000000000000000000000000000000000", 2 },
    { "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
      "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
      "0000000000000000000000000000000000000000000000000000000000000000", 0 },
    { "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
      "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"
      "0000000000000000000000000000000000000000000000000000000000000000", 0 },
    { "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
      "0100000000000000000000000000000000000000000000000000000000000000"
      "0000000000000000000000000000000000000000000000000000000000000000", 0 },
    { "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
      "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"
      "0000000000000000000000000000000000000000000000000000000000000000", 0 },
    { "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
      "0000000000000000000000000000000000000000000000000000000000000080"
      "0000000000000000000000000000000000000000000000000000000000000000", 1 },
    { "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      "0100000000000000000000000000000000000000000000000000000000000000"
      "0000000000000000000000000000000000000000000000000000000000000000", 1 },
    { "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
      "0100000000000000000000000000000000000000000000000000000000000000"
      "0000000000000000000000000000000000000000000000000000000000000000", 0 },
    { "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      "0100000000000000000000000000000000000000000000000000000000000000"
      "0000000000000000000000000000000000000000000000000000000000000000", 0 },
    };
    uint8_t pk[32], sig[64], msg[33];
    size_t i;
    int forged_accepted = 0;

    puts("Ed25519 low-order public keys");

    for (i = 0; i < sizeof SO / sizeof SO[0]; i++) {
        memcpy(msg, "VectiLicense small-order forgery", 32);
        msg[32] = SO[i].n;
        unhex(SO[i].pk, pk, 32);
        unhex(SO[i].sig, sig, 64);
        if (vl_ed25519_verify(sig, msg, sizeof msg, pk)) {
            forged_accepted++;
            printf("  FORGED signature accepted under pk %s\n", SO[i].pk);
        }
        /* And nothing else verifies under such a key either — the key itself
         * must be refused, not just this one forgery. */
        sig[0] ^= 0x40u;
        CHECK(vl_ed25519_verify(sig, msg, sizeof msg, pk) == 0,
              "low-order key %.16s...: perturbed signature rejected", SO[i].pk);
    }
    CHECK(forged_accepted == 0,
          "%d/%d forged signatures accepted against a low-order public key",
          forged_accepted, (int)(sizeof SO / sizeof SO[0]));

    /* The all-zero placeholder key that examples/ ships, spelled out on its
     * own so the failure message names the thing an integrator would copy. */
    memset(pk, 0, sizeof pk);
    memset(sig, 0, sizeof sig);
    CHECK(vl_ed25519_verify(sig, (const uint8_t *)"any message", 11u, pk) == 0,
          "the all-zero placeholder public key verifies NOTHING");

    /* Non-canonical encodings of A. unpack25519() reduces modulo nothing, so
     * y and y + (2^255-19) are two 32-byte strings for one key. That only
     * happens for y < 19, and four of the fourteen entries above (the ed../ee..
     * rows, y = 0 and y = 1 respelled) are exactly that case — those are the
     * regression proof, since they were accepted before.
     *
     * y = 3 is the same aliasing on a point that is NOT low order, so only the
     * canonical-encoding check can reject it. No forgery is possible against
     * it and its private key is unknown, so all this can assert is the
     * rejection itself; it is here to pin the rule "one key, one spelling". */
    {
        unhex("f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
              pk, 32);   /* == 3 + (2^255-19), i.e. a second spelling of y = 3 */
        CHECK(vl_ed25519_verify(sig, (const uint8_t *)"any message", 11u, pk) == 0,
              "non-canonically encoded public key rejected");
    }

    /* Positive control: the low-order rejection must not have made the
     * verifier reject honest keys. RFC 8032 test 1 still verifies. */
    unhex(RFC8032[0].pk_hex, pk, 32);
    unhex(RFC8032[0].sig_hex, sig, 64);
    CHECK(vl_ed25519_verify(sig, NULL, 0, pk) == 1,
          "a full-order key still verifies (RFC 8032 test 1)");
}

/* ========================================================================== */
/* base32                                                                     */
/* ========================================================================== */
static void test_base32(void)
{
    uint8_t buf[128], back[128];
    char enc[256];
    size_t len;
    int n;

    puts("Crockford base32");

    /* Round-trip every length up to 100 bytes with a deterministic pattern. */
    for (len = 1; len <= 100; len++) {
        size_t i;
        for (i = 0; i < len; i++) buf[i] = (uint8_t)(i * 37u + len);
        n = vl_base32_encode(buf, len, enc, sizeof enc);
        CHECK(n == (int)VL_BASE32_CHARS(len), "encode len %u -> %d chars",
              (unsigned)len, n);
        n = vl_base32_decode(enc, back, sizeof back, len);
        CHECK(n == (int)len && memcmp(buf, back, len) == 0,
              "round-trip len %u", (unsigned)len);
    }

    /* Known vector: the 100-byte blob decodes to exactly 100 bytes. */
    n = vl_base32_decode(FIX_BLOB_PERPETUAL, buf, sizeof buf, VL_BLOB_BIN_LEN);
    CHECK(n == (int)VL_BLOB_BIN_LEN, "fixture blob decodes to 100 bytes (got %d)", n);
    CHECK(buf[0] == VL_MAGIC && buf[1] == VL_FORMAT_VERSION, "fixture magic/version");

    /* Crockford aliases and case-insensitivity. */
    {
        uint8_t a[8], b[8];
        CHECK(vl_base32_decode("01234567", a, sizeof a, 5) == 5, "plain digits decode");
        CHECK(vl_base32_decode("1111", a, sizeof a, 0) ==
              vl_base32_decode("ILil", b, sizeof b, 0), "I/L alias char count");
        CHECK(memcmp(a, b, 2) == 0, "I/L decode as 1");
        CHECK(vl_base32_decode("0000", a, sizeof a, 0) ==
              vl_base32_decode("OoOo", b, sizeof b, 0), "O alias char count");
        CHECK(memcmp(a, b, 2) == 0, "O decodes as 0");
        CHECK(vl_base32_decode("ABCDEFGH", a, sizeof a, 5) == 5, "uppercase decodes");
        CHECK(vl_base32_decode("abcdefgh", b, sizeof b, 5) == 5, "lowercase decodes");
        CHECK(memcmp(a, b, 5) == 0, "case-insensitive");
    }

    /* Grouping characters are ignored, anywhere. */
    {
        char grouped[VL_BLOB_STR_LEN + 64];
        size_t i, o = 0;
        for (i = 0; i < VL_BLOB_STR_LEN; i++) {
            grouped[o++] = FIX_BLOB_PERPETUAL[i];
            if ((i % 8u) == 7u) grouped[o++] = '-';
        }
        grouped[o] = '\0';
        CHECK(vl_base32_decode(grouped, buf, sizeof buf, VL_BLOB_BIN_LEN) ==
              (int)VL_BLOB_BIN_LEN, "hyphen-grouped blob decodes");
    }

    /* --- rejection cases -------------------------------------------------- */
    CHECK(vl_base32_decode(NULL, buf, sizeof buf, 4) == -1, "NULL input rejected");
    CHECK(vl_base32_decode("ABCDEFGH", NULL, 8, 4) == -1, "NULL output rejected");
    CHECK(vl_base32_decode("ABCDEFGU", buf, sizeof buf, 5) == -1, "'U' rejected");
    CHECK(vl_base32_decode("ABCDEFG!", buf, sizeof buf, 5) == -1, "punctuation rejected");
    CHECK(vl_base32_decode("ABCDEFG\x80", buf, sizeof buf, 5) == -1, "high byte rejected");
    CHECK(vl_base32_decode("ABCDEFG", buf, sizeof buf, 5) == -1, "short input rejected");
    CHECK(vl_base32_decode("ABCDEFGHJ", buf, sizeof buf, 5) == -1, "long input rejected");
    CHECK(vl_base32_decode("", buf, sizeof buf, 5) == -1, "empty input rejected");
    CHECK(vl_base32_decode("ABCDEFGH", buf, 3, 0) == -1, "capacity overflow rejected");
    {
        /* 4 chars = 20 bits = 2 bytes + 4 pad bits. Non-zero pad must fail. */
        CHECK(vl_base32_decode("0001", buf, sizeof buf, 2) == -1,
              "non-canonical trailing pad bits rejected");
        CHECK(vl_base32_decode("0000", buf, sizeof buf, 2) == 2,
              "canonical trailing pad bits accepted");
    }
    {
        /* Bounded scan: a huge run of grouping characters must not hang. */
        static char big[VL_BASE32_MAX_INPUT + 64];
        memset(big, '-', sizeof big - 1);
        big[sizeof big - 1] = '\0';
        CHECK(vl_base32_decode(big, buf, sizeof buf, 0) == -1,
              "over-long input rejected");
    }

    /* Encode capacity checks. */
    CHECK(vl_base32_encode(buf, 10, enc, 16) == -1, "encode into 16 bytes rejected");
    CHECK(vl_base32_encode(buf, 10, enc, 17) == 16, "encode into 17 bytes accepted");
    CHECK(vl_base32_encode(NULL, 10, enc, 64) == -1, "encode NULL input rejected");
    CHECK(vl_base32_encode(buf, 10, NULL, 64) == -1, "encode NULL output rejected");
}

/* ========================================================================== */
/* A fake HAL                                                                 */
/* ========================================================================== */
struct fake_ctx {
    int      wrong_device;
    uint32_t now;
    int      have_clock;
    uint32_t hwm;
    int      have_hwm;
    int      hwm_stores;
    int      fail_segment;
};

static vl_status_t fake_read_segment(void *vctx, uint32_t idx,
                                     uint8_t *out, size_t cap, size_t *out_len)
{
    static const uint8_t s0[6] = { 0xde, 0xad, 0xbe, 0xef, 0x00, 0x11 };
    static const char s1[] = "vecti-test-board";
    struct fake_ctx *c = (struct fake_ctx *)vctx;

    if (c->fail_segment) return VL_ERR_PLATFORM;

    switch (idx) {
    case 0:
        if (cap < sizeof s0) return VL_ERR_BUFFER_TOO_SMALL;
        memcpy(out, s0, sizeof s0);
        if (c->wrong_device) out[0] ^= 0xFFu;
        *out_len = sizeof s0;
        return VL_OK;
    case 1:
        if (cap < sizeof s1 - 1) return VL_ERR_BUFFER_TOO_SMALL;
        memcpy(out, s1, sizeof s1 - 1);
        *out_len = sizeof s1 - 1;
        return VL_OK;
    case 2:
        *out_len = 0;              /* a zero-length segment is legal */
        return VL_OK;
    default:
        return VL_ERR_NO_MORE_SEGMENTS;
    }
}

static vl_status_t fake_now(void *vctx, uint32_t *out)
{
    struct fake_ctx *c = (struct fake_ctx *)vctx;
    if (!c->have_clock) return VL_ERR_PLATFORM;
    *out = c->now;
    return VL_OK;
}

static vl_status_t fake_hwm_load(void *vctx, uint32_t *out)
{
    struct fake_ctx *c = (struct fake_ctx *)vctx;
    if (!c->have_hwm) return VL_ERR_PLATFORM;
    *out = c->hwm;
    return VL_OK;
}

static vl_status_t fake_hwm_store(void *vctx, uint32_t value)
{
    struct fake_ctx *c = (struct fake_ctx *)vctx;
    if (!c->have_hwm) return VL_ERR_PLATFORM;
    c->hwm = value;
    c->hwm_stores++;
    return VL_OK;
}

static vl_status_t fake_posture(void *vctx, vl_posture_t *out)
{
    (void)vctx;
    out->secure_boot      = VL_POSTURE_ON;
    out->flash_encryption = VL_POSTURE_OFF;
    return VL_OK;
}

/* ========================================================================== */
/* Fingerprint + device id                                                    */
/* ========================================================================== */
static void test_fingerprint(void)
{
    struct fake_ctx ctx;
    vl_hal_t hal;
    uint8_t fp[VL_FINGERPRINT_LEN];
    char id[VL_DEVICE_ID_STR_BUF_LEN];

    puts("Fingerprint + device id");

    memset(&ctx, 0, sizeof ctx);
    memset(&hal, 0, sizeof hal);
    hal.read_id_segment = fake_read_segment;
    hal.ctx = &ctx;

    CHECK(vl_compute_fingerprint(&hal, fp) == VL_OK, "fingerprint computes");
    CHECK(memcmp(fp, FIX_FINGERPRINT, sizeof fp) == 0,
          "fingerprint matches the independent Python implementation");

    CHECK(vl_encode_device_id(fp, id, sizeof id) == VL_OK, "device id encodes");
    CHECK(strcmp(id, FIX_DEVICE_ID_STR) == 0,
          "device id string is '%s', expected '%s'", id, FIX_DEVICE_ID_STR);
    CHECK(strlen(id) == VL_DEVICE_ID_STR_LEN, "device id is 26 chars");

    CHECK(vl_encode_device_id(fp, id, VL_DEVICE_ID_STR_LEN) == VL_ERR_BUFFER_TOO_SMALL,
          "short device id buffer rejected");
    CHECK(vl_encode_device_id(NULL, id, sizeof id) == VL_ERR_INVALID_ARG,
          "NULL fingerprint rejected");
    CHECK(vl_compute_fingerprint(NULL, fp) == VL_ERR_INVALID_ARG, "NULL hal rejected");

    ctx.fail_segment = 1;
    CHECK(vl_compute_fingerprint(&hal, fp) == VL_ERR_PLATFORM,
          "a failing segment read fails closed");
    ctx.fail_segment = 0;

    /* A different device gives a different fingerprint. */
    ctx.wrong_device = 1;
    CHECK(vl_compute_fingerprint(&hal, fp) == VL_OK, "other-device fingerprint computes");
    CHECK(memcmp(fp, FIX_FINGERPRINT, sizeof fp) != 0, "other device differs");
}

/* ========================================================================== */
/* vl_verify                                                                  */
/* ========================================================================== */
static const vl_pubkey_t KEYS[1] = { { 7, { 0 } } };

static void test_verify(void)
{
    struct fake_ctx ctx;
    vl_hal_t hal;
    vl_pubkey_t keys[1];
    vl_config_t cfg;
    vl_license_t lic;
    static const uint32_t revoked[] = { 99, 4242, 100000 };
    vl_status_t st;

    puts("vl_verify");

    memcpy(keys, KEYS, sizeof keys);
    keys[0].key_id = 7;
    memcpy(keys[0].key, FIX_PUBKEY, VL_PUBKEY_LEN);

    memset(&ctx, 0, sizeof ctx);
    memset(&hal, 0, sizeof hal);
    hal.read_id_segment = fake_read_segment;
    hal.secure_posture  = fake_posture;
    hal.ctx = &ctx;

    memset(&cfg, 0, sizeof cfg);
    cfg.keys      = keys;
    cfg.key_count = 1;
    cfg.family    = 0x02;

    /* --- the happy path --------------------------------------------------- */
    st = vl_verify(FIX_BLOB_PERPETUAL, &cfg, &hal, &lic);
    CHECK(st == VL_OK, "perpetual licence verifies (got %s)", vl_status_str(st));
    CHECK(lic.serial == 1001u, "serial parsed: %u", lic.serial);
    CHECK(lic.features == 0x0000000du, "features parsed: 0x%08x", lic.features);
    CHECK(lic.key_id == 7u && lic.family == 0x02u, "key_id/family parsed");
    CHECK(lic.not_before == 0u && lic.not_after == 0u, "perpetual window parsed");
    CHECK((lic.checked & VL_CHECKED_SIGNATURE) != 0u, "signature marked checked");
    CHECK((lic.checked & VL_CHECKED_DEVICE) != 0u, "device marked checked");
    CHECK((lic.checked & VL_CHECKED_TIME) == 0u, "no clock => time not marked checked");
    CHECK(vl_has_feature(&lic, 0) == 1, "feature 0 set");
    CHECK(vl_has_feature(&lic, 1) == 0, "feature 1 clear");
    CHECK(vl_has_feature(&lic, 2) == 1, "feature 2 set");
    CHECK(vl_has_feature(&lic, 3) == 1, "feature 3 set");
    CHECK(vl_has_feature(&lic, 31) == 0, "feature 31 clear");
    CHECK(vl_has_feature(&lic, 32) == 0, "feature 32 out of range");
    CHECK(vl_has_feature(NULL, 0) == 0, "NULL licence has no features");

    CHECK(vl_verify(FIX_BLOB_PERPETUAL, &cfg, &hal, NULL) == VL_OK,
          "NULL out is allowed");

    /* --- argument rejection ----------------------------------------------- */
    CHECK(vl_verify(NULL, &cfg, &hal, &lic) == VL_ERR_INVALID_ARG, "NULL blob");
    CHECK(vl_verify(FIX_BLOB_PERPETUAL, NULL, &hal, &lic) == VL_ERR_INVALID_ARG, "NULL cfg");
    CHECK(vl_verify(FIX_BLOB_PERPETUAL, &cfg, NULL, &lic) == VL_ERR_INVALID_ARG, "NULL hal");
    {
        vl_config_t bad = cfg;
        bad.key_count = 0;
        CHECK(vl_verify(FIX_BLOB_PERPETUAL, &bad, &hal, &lic) == VL_ERR_INVALID_ARG,
              "empty key set");
        bad = cfg;
        bad.keys = NULL;
        CHECK(vl_verify(FIX_BLOB_PERPETUAL, &bad, &hal, &lic) == VL_ERR_INVALID_ARG,
              "NULL key array");
        bad = cfg;
        bad.flags = VL_FLAG_ENFORCE_HWM;
        CHECK(vl_verify(FIX_BLOB_PERPETUAL, &bad, &hal, &lic) == VL_ERR_INVALID_ARG,
              "ENFORCE_HWM without hwm callbacks");
    }
    /* ENFORCE_HWM with the hwm pair wired but NO clock. The mark is only ever
     * compared against and advanced by the clock, so this used to be accepted
     * and then silently do nothing at all: no rollback check, and — because
     * the validity window lives in the same branch — no expiry check either,
     * so an expired licence returned VL_OK. That is the shape of the shipped
     * RP2040 HAL. It must be refused at the argument check, like the other
     * half of the same flag. */
    {
        vl_hal_t noclock = hal;
        vl_config_t c2 = cfg;
        noclock.now_epoch = NULL;
        noclock.hwm_load  = fake_hwm_load;
        noclock.hwm_store = fake_hwm_store;
        ctx.have_hwm   = 1;
        ctx.hwm        = 0xFFFFFFFFu;
        ctx.hwm_stores = 0;
        c2.flags = VL_FLAG_ENFORCE_HWM;

        CHECK(vl_verify(FIX_BLOB_PERPETUAL, &c2, &noclock, &lic) == VL_ERR_INVALID_ARG,
              "ENFORCE_HWM without a clock is refused, not silently downgraded");
        CHECK(vl_verify(FIX_BLOB_EXPIRED, &c2, &noclock, &lic) == VL_ERR_INVALID_ARG,
              "...and an expired licence does not sneak through that door");
        CHECK(ctx.hwm_stores == 0, "a refused config touches no flash");
        CHECK(lic.checked == 0u, "a refused config reports no checks run");

        /* Same flag, same missing clock, but the hwm pair missing too: one
         * error code for one broken request. */
        noclock.hwm_load = NULL;
        noclock.hwm_store = NULL;
        CHECK(vl_verify(FIX_BLOB_PERPETUAL, &c2, &noclock, &lic) == VL_ERR_INVALID_ARG,
              "ENFORCE_HWM with neither clock nor hwm callbacks");
        ctx.hwm = 0;
    }
    /* A forged licence blob built against an ALL-ZERO public key — the
     * placeholder every examples/ file ships — with no private key of any
     * kind. Serial 2, every feature bit set, bound to this test HAL's own
     * fingerprint. Before unpackneg() rejected low-order keys this returned
     * VL_OK, so any image flashed before the real vendor key was pasted in
     * was a universal keygen. */
    {
        static const char FORGED_ZEROKEY[] =
            "AR0G20QZZZZZY7P9F9RMKSZQQSNYEVW3R0QV08G00000000000004000"
            "000G0000000000000000000000000000000000000000000000000000"
            "000000000000000000000000000000000000000000000000";
        static const vl_pubkey_t zerokeys[1] = { { 1, { 0 } } };
        vl_config_t c2 = cfg;
        c2.keys = zerokeys;
        c2.key_count = 1;
        memset(&lic, 0, sizeof lic);
        CHECK(strlen(FORGED_ZEROKEY) == VL_BLOB_STR_LEN,
              "forged blob is a well-formed %u-char blob (%u)",
              (unsigned)VL_BLOB_STR_LEN, (unsigned)strlen(FORGED_ZEROKEY));
        st = vl_verify(FORGED_ZEROKEY, &c2, &hal, &lic);
        CHECK(st == VL_ERR_BAD_SIGNATURE,
              "forged blob against the all-zero key rejected (got %s)",
              vl_status_str(st));
        CHECK(lic.features == 0u,
              "...and hands back no features (got 0x%08x)", lic.features);
    }
    {
        vl_hal_t bad = hal;
        bad.read_id_segment = NULL;
        CHECK(vl_verify(FIX_BLOB_PERPETUAL, &cfg, &bad, &lic) == VL_ERR_INVALID_ARG,
              "HAL with no fingerprint callback");
    }

    /* --- format rejection -------------------------------------------------- */
    CHECK(vl_verify("", &cfg, &hal, &lic) == VL_ERR_BAD_FORMAT, "empty blob");
    CHECK(vl_verify("ABC", &cfg, &hal, &lic) == VL_ERR_BAD_FORMAT, "short blob");
    {
        char b[VL_BLOB_STR_BUF_LEN + 4];
        memcpy(b, FIX_BLOB_PERPETUAL, VL_BLOB_STR_LEN);
        b[VL_BLOB_STR_LEN]     = 'A';
        b[VL_BLOB_STR_LEN + 1] = '\0';
        CHECK(vl_verify(b, &cfg, &hal, &lic) == VL_ERR_BAD_FORMAT, "one char too long");

        memcpy(b, FIX_BLOB_PERPETUAL, VL_BLOB_STR_LEN + 1);
        b[10] = 'U';
        CHECK(vl_verify(b, &cfg, &hal, &lic) == VL_ERR_BAD_FORMAT, "out-of-alphabet char");
        b[10] = '\x01';
        CHECK(vl_verify(b, &cfg, &hal, &lic) == VL_ERR_BAD_FORMAT, "control char");

        /* Magic byte: 0x56 -> anything else. First base32 char covers bits
         * 7..3 of byte 0, so changing it changes the magic. */
        memcpy(b, FIX_BLOB_PERPETUAL, VL_BLOB_STR_LEN + 1);
        b[0] = (char)((b[0] == '0') ? '1' : '0');
        st = vl_verify(b, &cfg, &hal, &lic);
        CHECK(st == VL_ERR_BAD_MAGIC || st == VL_ERR_BAD_VERSION,
              "corrupt first byte -> magic/version error, got %s", vl_status_str(st));
    }

    /* --- family / key id --------------------------------------------------- */
    CHECK(vl_verify(FIX_BLOB_WRONGFAMILY, &cfg, &hal, &lic) == VL_ERR_BAD_FAMILY,
          "wrong family rejected");
    CHECK(vl_verify(FIX_BLOB_UNKNOWNKEY, &cfg, &hal, &lic) == VL_ERR_UNKNOWN_KEY,
          "unknown key id rejected");

    /* --- signature / domain separation ------------------------------------- */
    CHECK(vl_verify(FIX_BLOB_NODOMAIN, &cfg, &hal, &lic) == VL_ERR_BAD_SIGNATURE,
          "signature over the bare payload (no domain prefix) rejected");
    {
        vl_pubkey_t other[1];
        vl_config_t c2 = cfg;
        memcpy(other, keys, sizeof other);
        other[0].key[0] ^= 0x01u;
        c2.keys = other;
        CHECK(vl_verify(FIX_BLOB_PERPETUAL, &c2, &hal, &lic) == VL_ERR_BAD_SIGNATURE,
              "wrong public key rejected");
    }

    /* --- device binding ----------------------------------------------------- */
    CHECK(vl_verify(FIX_BLOB_OTHERDEV, &cfg, &hal, &lic) == VL_ERR_DEVICE_MISMATCH,
          "licence for another device rejected");
    ctx.wrong_device = 1;
    CHECK(vl_verify(FIX_BLOB_PERPETUAL, &cfg, &hal, &lic) == VL_ERR_DEVICE_MISMATCH,
          "same licence on a different device rejected");
    ctx.wrong_device = 0;
    ctx.fail_segment = 1;
    CHECK(vl_verify(FIX_BLOB_PERPETUAL, &cfg, &hal, &lic) == VL_ERR_PLATFORM,
          "unreadable fingerprint fails closed");
    ctx.fail_segment = 0;

    /* --- revocation ---------------------------------------------------------- */
    {
        vl_config_t c2 = cfg;
        c2.revoked_serials = revoked;
        c2.revoked_count   = sizeof revoked / sizeof revoked[0];
        CHECK(vl_verify(FIX_BLOB_REVOKED, &c2, &hal, &lic) == VL_ERR_REVOKED,
              "revoked serial rejected");
        CHECK(vl_verify(FIX_BLOB_PERPETUAL, &c2, &hal, &lic) == VL_OK,
              "non-revoked serial still passes");
        CHECK((lic.checked & VL_CHECKED_REVOCATION) != 0u, "revocation marked checked");
        /* Without the list, the same blob is fine. */
        CHECK(vl_verify(FIX_BLOB_REVOKED, &cfg, &hal, &lic) == VL_OK,
              "no deny-list means no revocation");
    }

    /* --- time --------------------------------------------------------------- */
    hal.now_epoch  = fake_now;
    ctx.have_clock = 1;

    ctx.now = 1750000000u;
    st = vl_verify(FIX_BLOB_WINDOWED, &cfg, &hal, &lic);
    CHECK(st == VL_OK, "in-window licence verifies (got %s)", vl_status_str(st));
    CHECK((lic.checked & VL_CHECKED_TIME) != 0u, "time marked checked");

    ctx.now = 1650000000u;
    CHECK(vl_verify(FIX_BLOB_WINDOWED, &cfg, &hal, &lic) == VL_ERR_NOT_YET_VALID,
          "before not_before rejected");
    ctx.now = 1850000000u;
    CHECK(vl_verify(FIX_BLOB_WINDOWED, &cfg, &hal, &lic) == VL_ERR_EXPIRED,
          "after not_after rejected");

    ctx.now = 1750000000u;
    CHECK(vl_verify(FIX_BLOB_EXPIRED, &cfg, &hal, &lic) == VL_ERR_EXPIRED,
          "expired licence rejected");
    CHECK(vl_verify(FIX_BLOB_FUTURE, &cfg, &hal, &lic) == VL_ERR_NOT_YET_VALID,
          "not-yet-valid licence rejected");
    CHECK(vl_verify(FIX_BLOB_PERPETUAL, &cfg, &hal, &lic) == VL_OK,
          "perpetual licence ignores the clock");

    ctx.have_clock = 0;
    CHECK(vl_verify(FIX_BLOB_PERPETUAL, &cfg, &hal, &lic) == VL_ERR_PLATFORM,
          "a broken clock callback fails closed");
    ctx.have_clock = 1;

    /* No clock at all: default is to report, not enforce. */
    {
        vl_hal_t noclock = hal;
        vl_config_t strict = cfg;
        noclock.now_epoch = NULL;
        CHECK(vl_verify(FIX_BLOB_EXPIRED, &cfg, &noclock, &lic) == VL_OK,
              "clockless device accepts an expired licence by default");
        CHECK((lic.checked & VL_CHECKED_TIME) == 0u,
              "...and says so via VL_CHECKED_TIME");
        strict.flags = VL_FLAG_REQUIRE_CLOCK;
        CHECK(vl_verify(FIX_BLOB_EXPIRED, &strict, &noclock, &lic) == VL_ERR_NO_CLOCK,
              "VL_FLAG_REQUIRE_CLOCK turns that into a refusal");
    }

    /* --- clock high-water mark ----------------------------------------------- */
    {
        vl_config_t c2 = cfg;
        hal.hwm_load  = fake_hwm_load;
        hal.hwm_store = fake_hwm_store;
        ctx.have_hwm  = 1;
        ctx.hwm       = 0;
        ctx.hwm_stores = 0;
        c2.flags = VL_FLAG_ENFORCE_HWM;

        ctx.now = 1750000000u;
        CHECK(vl_verify(FIX_BLOB_PERPETUAL, &c2, &hal, &lic) == VL_OK,
              "first verify sets the high-water mark");
        CHECK(ctx.hwm == 1750000000u, "mark stored: %u", ctx.hwm);
        CHECK((lic.checked & VL_CHECKED_HWM) != 0u, "hwm marked checked");

        ctx.now = 1750000001u;
        CHECK(vl_verify(FIX_BLOB_PERPETUAL, &c2, &hal, &lic) == VL_OK,
              "clock moving forward is fine");
        CHECK(ctx.hwm == 1750000001u, "mark advanced");

        ctx.now = 1700000000u;
        CHECK(vl_verify(FIX_BLOB_PERPETUAL, &c2, &hal, &lic) == VL_ERR_CLOCK_ROLLBACK,
              "clock rolled back is refused");
        CHECK(ctx.hwm == 1750000001u, "a refused verify does not move the mark back");

        ctx.now = 1750000001u;
        ctx.hwm_stores = 0;
        CHECK(vl_verify(FIX_BLOB_PERPETUAL, &c2, &hal, &lic) == VL_OK, "equal to mark is fine");
        CHECK(ctx.hwm_stores == 0, "equal to mark does not rewrite flash");

        ctx.have_hwm = 0;
        CHECK(vl_verify(FIX_BLOB_PERPETUAL, &c2, &hal, &lic) == VL_ERR_PLATFORM,
              "a broken hwm store fails closed");
        ctx.have_hwm = 1;

        hal.hwm_load = NULL;
        hal.hwm_store = NULL;
    }

    /* --- posture -------------------------------------------------------------- */
    {
        vl_posture_t p;
        vl_hal_t bare;
        CHECK(vl_posture(&hal, &p) == VL_OK, "posture reads");
        CHECK(p.secure_boot == VL_POSTURE_ON, "secure boot reported");
        CHECK(p.flash_encryption == VL_POSTURE_OFF, "flash encryption reported");
        memset(&bare, 0, sizeof bare);
        CHECK(vl_posture(&bare, &p) == VL_OK, "posture with no callback is not an error");
        CHECK(p.secure_boot == VL_POSTURE_UNKNOWN &&
              p.flash_encryption == VL_POSTURE_UNKNOWN, "...it reports unknown");
        CHECK(vl_posture(NULL, &p) == VL_OK, "NULL hal reports unknown");
        CHECK(vl_posture(&hal, NULL) == VL_ERR_INVALID_ARG, "NULL out rejected");
    }
}

/* ========================================================================== */
/* Flip every bit of a valid blob; nothing may verify.                        */
/* ========================================================================== */
static void test_bitflip_sweep(void)
{
    struct fake_ctx ctx;
    vl_hal_t hal;
    vl_pubkey_t keys[1];
    vl_config_t cfg;
    uint8_t bin[VL_BLOB_BIN_LEN];
    char blob[VL_BLOB_STR_BUF_LEN];
    size_t byte, bit;
    int accepted = 0;
    int tried = 0;

    puts("Bit-flip sweep over a valid blob");

    keys[0].key_id = 7;
    memcpy(keys[0].key, FIX_PUBKEY, VL_PUBKEY_LEN);
    memset(&ctx, 0, sizeof ctx);
    memset(&hal, 0, sizeof hal);
    hal.read_id_segment = fake_read_segment;
    hal.ctx = &ctx;
    memset(&cfg, 0, sizeof cfg);
    cfg.keys = keys;
    cfg.key_count = 1;
    cfg.family = 0x02;

    CHECK(vl_base32_decode(FIX_BLOB_PERPETUAL, bin, sizeof bin, VL_BLOB_BIN_LEN) ==
          (int)VL_BLOB_BIN_LEN, "sweep base decodes");

    for (byte = 0; byte < VL_BLOB_BIN_LEN; byte++) {
        for (bit = 0; bit < 8u; bit++) {
            bin[byte] ^= (uint8_t)(1u << bit);
            if (vl_base32_encode(bin, VL_BLOB_BIN_LEN, blob, sizeof blob) ==
                (int)VL_BLOB_STR_LEN) {
                tried++;
                if (vl_verify(blob, &cfg, &hal, NULL) == VL_OK) accepted++;
            }
            bin[byte] ^= (uint8_t)(1u << bit);
        }
    }
    CHECK(tried == 800, "800 single-bit mutations tried (got %d)", tried);
    CHECK(accepted == 0, "%d mutated blobs were accepted", accepted);

    /* And the unmutated blob still passes, so the sweep was not vacuous. */
    CHECK(vl_base32_encode(bin, VL_BLOB_BIN_LEN, blob, sizeof blob) ==
          (int)VL_BLOB_STR_LEN, "re-encode");
    CHECK(vl_verify(blob, &cfg, &hal, NULL) == VL_OK, "the control blob still verifies");
}

/* ========================================================================== */
/* Random / mutated garbage: no crash, no false accept.                       */
/* ========================================================================== */
static void test_fuzzish(void)
{
    struct fake_ctx ctx;
    vl_hal_t hal;
    vl_pubkey_t keys[1];
    vl_config_t cfg;
    uint8_t bin[VL_BLOB_BIN_LEN];
    char blob[512];
    uint32_t rng = 0x12345678u;
    int i;
    int accepted = 0;

    puts("Fuzz-ish sweep (20000 random and mutated blobs)");

    keys[0].key_id = 7;
    memcpy(keys[0].key, FIX_PUBKEY, VL_PUBKEY_LEN);
    memset(&ctx, 0, sizeof ctx);
    memset(&hal, 0, sizeof hal);
    hal.read_id_segment = fake_read_segment;
    hal.ctx = &ctx;
    memset(&cfg, 0, sizeof cfg);
    cfg.keys = keys;
    cfg.key_count = 1;
    cfg.family = 0x02;

    for (i = 0; i < 20000; i++) {
        size_t len, j;
        rng = rng * 1103515245u + 12345u;
        if ((rng >> 16) & 1u) {
            /* Random string of a random length, arbitrary bytes. */
            len = (size_t)((rng >> 8) % (sizeof blob - 1u));
            for (j = 0; j < len; j++) {
                rng = rng * 1103515245u + 12345u;
                blob[j] = (char)(((rng >> 16) & 0x7Fu) | 1u);  /* never NUL */
            }
            blob[len] = '\0';
        } else {
            /* A valid blob with a handful of random bytes corrupted. */
            int k;
            (void)vl_base32_decode(FIX_BLOB_PERPETUAL, bin, sizeof bin, VL_BLOB_BIN_LEN);
            for (k = 0; k < 3; k++) {
                rng = rng * 1103515245u + 12345u;
                bin[(rng >> 8) % VL_BLOB_BIN_LEN] ^= (uint8_t)(rng >> 24);
            }
            (void)vl_base32_encode(bin, VL_BLOB_BIN_LEN, blob, sizeof blob);
        }
        if (vl_verify(blob, &cfg, &hal, NULL) == VL_OK) accepted++;
    }
    CHECK(accepted == 0, "%d fuzz inputs were accepted", accepted);
}

/* ========================================================================== */
static void test_util(void)
{
    uint8_t a[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    uint8_t b[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };

    puts("vl_util");
    CHECK(vl_ct_eq(a, b, 8) == 1, "equal buffers compare equal");
    b[7] = 9;
    CHECK(vl_ct_eq(a, b, 8) == 0, "differing last byte");
    b[7] = 8; b[0] = 9;
    CHECK(vl_ct_eq(a, b, 8) == 0, "differing first byte");
    CHECK(vl_ct_eq(NULL, b, 8) == 0, "NULL a fails closed");
    CHECK(vl_ct_eq(a, NULL, 8) == 0, "NULL b fails closed");
    CHECK(vl_ct_eq(a, a, 0) == 0, "zero length fails closed");

    vl_secure_wipe(a, sizeof a);
    CHECK(a[0] == 0 && a[7] == 0, "secure wipe zeroes");
    vl_secure_wipe(NULL, 8);          /* must not crash */
    vl_secure_wipe(a, 0);

    CHECK(strcmp(vl_status_str(VL_OK), "ok") == 0, "status_str(VL_OK)");
    CHECK(vl_status_str((vl_status_t)-999) != NULL, "status_str of a bogus value is non-NULL");
    CHECK(strcmp(vl_status_str((vl_status_t)-999), "unknown status") == 0,
          "status_str of a bogus value");
    CHECK(vl_version_str() != NULL, "version_str");
}

int main(void)
{
    printf("%s\n\n", vl_version_str());
    test_util();
    test_sha();
    test_ed25519();
    test_base32();
    test_fingerprint();
    test_verify();
    test_bitflip_sweep();
    test_fuzzish();

    printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
