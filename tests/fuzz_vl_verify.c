/* fuzz_vl_verify.c — random and mutated input, run under AddressSanitizer and
 * UndefinedBehaviorSanitizer.
 *
 * Two properties, asserted on every iteration:
 *
 *   1. No crash, no out-of-bounds access, no undefined behaviour. That part is
 *      the sanitizers' job; this file just supplies the traffic. Build it
 *      WITHOUT them and it still runs, it just stops proving anything about
 *      memory safety.
 *   2. No false accept — and stated precisely: if vl_verify() returns VL_OK,
 *      the input must decode to exactly the 100 bytes the vendor signed.
 *      Simply counting VL_OK is too weak, because a licence respelled in
 *      lowercase or split into hyphenated groups is genuinely the same licence
 *      and must still be accepted.
 *
 * Also fuzzes vl_compute_fingerprint() against a HAL that returns arbitrary
 * segment lengths and arbitrary failures, and the base32 codec against
 * arbitrary buffers and capacities.
 *
 * Deterministic: the same seed gives the same run. Take a failing seed from
 * the output and re-run just it.
 *
 *   ./fuzz_vl_verify [iterations] [seed]
 *
 * (c) 2026 VectiVolt — Apache-2.0 License */

#include "vectilicense/vectilicense.h"

#include "vl_base32.h"

#include "vl_test_fixtures.h"
#include "vl_test_hal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FIX_FAMILY  0x02u
#define FIX_KEY_ID  7u

#define MAX_BLOB    600u

static const char ALPHA[] = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
static const char GROUP[] = "- \t\r\n";

/* xorshift32: tiny, deterministic, and not remotely a CSPRNG — which is fine,
 * nothing here is a secret. */
static uint32_t g_rng;
static uint32_t rnd(void)
{
    g_rng ^= g_rng << 13;
    g_rng ^= g_rng >> 17;
    g_rng ^= g_rng << 5;
    return g_rng;
}
static uint32_t rnd_below(uint32_t n) { return n ? rnd() % n : 0u; }

static int g_fail = 0;
static void fail(const char *what, unsigned iter, const char *blob)
{
    g_fail++;
    printf("  FAIL iter %u: %s\n    blob: %.200s\n", iter, what, blob);
}

/* ========================================================================== */
/* A HAL whose identity segments are whatever the RNG says today.             */
/* ========================================================================== */
static vl_status_t chaos_read_id_segment(void *ctx, uint32_t idx,
                                         uint8_t *out, size_t cap, size_t *out_len)
{
    uint32_t roll = rnd();
    size_t n;
    (void)ctx;

    if ((roll & 0x3fu) == 0u) return VL_ERR_PLATFORM;
    if ((roll & 0x0fu) == 0u) return VL_ERR_NO_MORE_SEGMENTS;
    if (idx > 200u)           return VL_ERR_NO_MORE_SEGMENTS;

    for (n = 0; n < cap; n++) out[n] = (uint8_t)rnd();
    /* Deliberately allowed to exceed cap: the core must refuse that, not
     * hash whatever is past the end of the buffer. */
    *out_len = (size_t)(rnd() % (cap + 4u));
    return VL_OK;
}

/* ========================================================================== */
static void mutate_from_valid(char *dst, size_t dst_cap)
{
    size_t len = VL_BLOB_STR_LEN;
    size_t i;
    uint32_t edits;

    memcpy(dst, FIX_BLOB_PERPETUAL, VL_BLOB_STR_LEN + 1u);

    edits = 1u + rnd_below(4u);
    while (edits--) {
        switch (rnd_below(6u)) {
        case 0:   /* substitute a character with another alphabet character */
            if (len) dst[rnd_below((uint32_t)len)] = ALPHA[rnd_below(32u)];
            break;
        case 1:   /* substitute with an arbitrary byte, never NUL */
            if (len) dst[rnd_below((uint32_t)len)] = (char)((rnd() & 0xFFu) | 1u);
            break;
        case 2:   /* delete a character */
            if (len) {
                i = rnd_below((uint32_t)len);
                memmove(dst + i, dst + i + 1, len - i);
                len--;
            }
            break;
        case 3:   /* insert a character */
            if (len + 2u < dst_cap) {
                i = rnd_below((uint32_t)len + 1u);
                memmove(dst + i + 1, dst + i, len - i + 1u);
                dst[i] = ALPHA[rnd_below(32u)];
                len++;
            }
            break;
        case 4:   /* insert a grouping character — must be ignored, not fatal */
            if (len + 2u < dst_cap) {
                i = rnd_below((uint32_t)len + 1u);
                memmove(dst + i + 1, dst + i, len - i + 1u);
                dst[i] = GROUP[rnd_below(sizeof GROUP - 1u)];
                len++;
            }
            break;
        default:  /* recase */
            if (len) {
                i = rnd_below((uint32_t)len);
                if (dst[i] >= 'A' && dst[i] <= 'Z') dst[i] = (char)(dst[i] + 32);
                else if (dst[i] >= 'a' && dst[i] <= 'z') dst[i] = (char)(dst[i] - 32);
            }
            break;
        }
    }
    dst[len] = '\0';
}

static void random_bytes_blob(char *dst, size_t dst_cap)
{
    size_t len = (size_t)rnd_below((uint32_t)dst_cap - 1u);
    size_t i;
    for (i = 0; i < len; i++) dst[i] = (char)((rnd() & 0xFFu) | 1u);
    dst[len] = '\0';
}

static void random_alphabet_blob(char *dst, size_t dst_cap)
{
    /* Well-formed base32 of a length near the real one, so parsing gets past
     * the cheap checks and the payload/crypto path is actually exercised. */
    size_t len = (size_t)(VL_BLOB_STR_LEN + rnd_below(5u)) - 2u;
    size_t i;
    if (len >= dst_cap) len = dst_cap - 1u;
    for (i = 0; i < len; i++) dst[i] = ALPHA[rnd_below(32u)];
    dst[len] = '\0';
}

/* A structurally perfect blob: right magic, version, family, key id, right
 * device id — and a signature made of noise. This is the shape an attacker
 * with a hex editor produces, and the one that reaches Ed25519 every time. */
static void forged_blob(char *dst, size_t dst_cap, int keep_device)
{
    uint8_t bin[VL_BLOB_BIN_LEN];
    uint8_t device[VL_DEVICE_ID_LEN];
    size_t i;

    (void)vl_base32_decode(FIX_BLOB_PERPETUAL, bin, sizeof bin, VL_BLOB_BIN_LEN);
    memcpy(device, bin + 8, sizeof device);

    switch (rnd_below(4u)) {
    case 0:                                     /* noise signature */
        for (i = VL_PAYLOAD_LEN; i < VL_BLOB_BIN_LEN; i++) bin[i] = (uint8_t)rnd();
        break;
    case 1:                                     /* upgraded features */
        for (i = 4; i < 8; i++) bin[i] = (uint8_t)rnd();
        break;
    case 2:                                     /* extended expiry */
        bin[28] = 0xFFu; bin[29] = 0xFFu; bin[30] = 0xFFu; bin[31] = 0x7Fu;
        break;
    default:                                    /* noise payload */
        for (i = 2; i < VL_PAYLOAD_LEN; i++) bin[i] = (uint8_t)rnd();
        break;
    }
    if (keep_device) {
        /* Keep magic, version, key id, family and device id intact so the only
         * thing wrong with the blob is that nobody signed it. */
        bin[0] = VL_MAGIC;
        bin[1] = VL_FORMAT_VERSION;
        bin[2] = (uint8_t)FIX_KEY_ID;
        bin[3] = (uint8_t)FIX_FAMILY;
        memcpy(bin + 8, device, sizeof device);
    }
    if (vl_base32_encode(bin, VL_BLOB_BIN_LEN, dst, dst_cap) != (int)VL_BLOB_STR_LEN) {
        dst[0] = '\0';
    }
}

/* The one thing an accepted blob must satisfy. */
static int decodes_to_the_signed_bytes(const char *blob, const uint8_t *expect)
{
    uint8_t bin[VL_BLOB_BIN_LEN];
    if (vl_base32_decode(blob, bin, sizeof bin, VL_BLOB_BIN_LEN) != (int)VL_BLOB_BIN_LEN) {
        return 0;
    }
    return memcmp(bin, expect, VL_BLOB_BIN_LEN) == 0;
}

/* ========================================================================== */
static void fuzz_fingerprint(unsigned iterations)
{
    vl_hal_t hal;
    uint8_t fp[VL_FINGERPRINT_LEN];
    unsigned i;

    memset(&hal, 0, sizeof hal);
    hal.read_id_segment = chaos_read_id_segment;

    for (i = 0; i < iterations; i++) {
        vl_status_t st = vl_compute_fingerprint(&hal, fp);
        if (st != VL_OK && st != VL_ERR_PLATFORM) {
            g_fail++;
            printf("  FAIL fingerprint iter %u: unexpected %s\n", i, vl_status_str(st));
        }
    }
}

static void fuzz_base32(unsigned iterations)
{
    unsigned i;
    for (i = 0; i < iterations; i++) {
        uint8_t in[64], out[64];
        char enc[256];
        size_t in_len   = (size_t)rnd_below(sizeof in + 1u);
        size_t out_cap  = (size_t)rnd_below(sizeof out + 1u);
        size_t enc_cap  = (size_t)rnd_below(sizeof enc + 1u);
        size_t expect   = (size_t)rnd_below(70u);
        size_t j;
        int n;

        for (j = 0; j < in_len; j++) in[j] = (uint8_t)rnd();
        n = vl_base32_encode(in, in_len, enc, enc_cap);
        if (n >= 0) {
            if ((size_t)n != VL_BASE32_CHARS(in_len)) {
                g_fail++;
                printf("  FAIL base32 encode length: %d for %u bytes\n",
                       n, (unsigned)in_len);
            }
            /* A successful encode must round-trip, given room. */
            if (vl_base32_decode(enc, out, sizeof out, in_len) == (int)in_len &&
                in_len > 0u && memcmp(in, out, in_len) != 0) {
                g_fail++;
                printf("  FAIL base32 round-trip at %u bytes\n", (unsigned)in_len);
            }
        }
        /* Arbitrary garbage in, arbitrary capacity: never a write past out. */
        for (j = 0; j + 1u < sizeof enc; j++) enc[j] = (char)((rnd() & 0x7Fu) | 1u);
        enc[sizeof enc - 1u] = '\0';
        n = vl_base32_decode(enc, out, out_cap, expect);
        if (n > 0 && (size_t)n > out_cap) {
            g_fail++;
            printf("  FAIL base32 decode wrote %d bytes into %u\n",
                   n, (unsigned)out_cap);
        }
        if (expect != 0u && n > 0 && (size_t)n != expect) {
            g_fail++;
            printf("  FAIL base32 decode ignored expect_bytes\n");
        }
    }
}

/* ========================================================================== */
int main(int argc, char **argv)
{
    vl_test_ctx_t ctx;
    vl_hal_t hal, full;
    vl_test_ctx_t full_ctx;
    vl_pubkey_t keys[1];
    vl_config_t cfg;
    uint8_t signed_bytes[VL_BLOB_BIN_LEN];
    char blob[MAX_BLOB];
    unsigned iterations = (argc > 1) ? (unsigned)strtoul(argv[1], NULL, 0) : 1500u;
    unsigned seed       = (argc > 2) ? (unsigned)strtoul(argv[2], NULL, 0) : 0xC0FFEEu;
    unsigned i;
    unsigned accepted = 0;

    g_rng = seed ? seed : 1u;

    printf("%s — fuzz\n", vl_version_str());
    printf("iterations=%u seed=0x%x\n\n", iterations, seed);

    keys[0].key_id = FIX_KEY_ID;
    memcpy(keys[0].key, FIX_PUBKEY, VL_PUBKEY_LEN);
    memset(&cfg, 0, sizeof cfg);
    cfg.keys      = keys;
    cfg.key_count = 1;
    cfg.family    = FIX_FAMILY;

    vlt_hal_init(&hal, &ctx);
    vlt_hal_full(&full, &full_ctx);
    full_ctx.now = 1750000000u;

    if (vl_base32_decode(FIX_BLOB_PERPETUAL, signed_bytes, sizeof signed_bytes,
                         VL_BLOB_BIN_LEN) != (int)VL_BLOB_BIN_LEN) {
        puts("fixture blob does not decode — fixtures are broken");
        return 1;
    }

    for (i = 0; i < iterations; i++) {
        const vl_hal_t *h = ((rnd() & 7u) == 0u) ? &full : &hal;
        vl_license_t lic;
        vl_status_t st;

        switch (rnd_below(5u)) {
        case 0:  random_bytes_blob(blob, sizeof blob);    break;
        case 1:  random_alphabet_blob(blob, sizeof blob); break;
        case 2:  forged_blob(blob, sizeof blob, 0);       break;
        case 3:  forged_blob(blob, sizeof blob, 1);       break;
        default: mutate_from_valid(blob, sizeof blob);    break;
        }

        st = vl_verify(blob, &cfg, h, &lic);
        if (st == VL_OK) {
            accepted++;
            if (!decodes_to_the_signed_bytes(blob, signed_bytes)) {
                fail("accepted a blob that is not the signed licence", i, blob);
            }
            if ((lic.checked & VL_CHECKED_SIGNATURE) == 0u ||
                (lic.checked & VL_CHECKED_DEVICE) == 0u) {
                fail("accepted without marking signature+device checked", i, blob);
            }
        } else if (st > 0) {
            fail("a positive status code is not in the API", i, blob);
        } else {
            /* Failure must not leak a partially-filled licence. */
            static const vl_license_t zero;
            if (memcmp(&lic, &zero, sizeof lic) != 0) {
                fail("failure path left data in the output licence", i, blob);
            }
        }
    }

    /* The same traffic against the other two entry points. */
    fuzz_fingerprint(iterations / 10u + 1u);
    fuzz_base32(iterations / 4u + 1u);

    printf("%u iterations, %u accepted (all of them the genuine licence), "
           "%d failures\n", iterations, accepted, g_fail);

    if (accepted == 0u) {
        /* The mutation strategy is supposed to produce the identity blob and
         * harmless respellings sometimes. Never doing so means the harness is
         * only testing the cheap rejection path. */
        puts("WARNING: nothing was accepted — is the harness reaching the "
             "crypto at all?");
    }
    return g_fail == 0 ? 0 : 1;
}
