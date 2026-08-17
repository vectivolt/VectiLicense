/* test_vl_robustness.c — the tests that are about what vl_verify() does when
 * the world is not cooperating.
 *
 *   1. the NULL-callback matrix: all 64 combinations of the six optional
 *      vl_hal_t members present/absent, against three flag settings. No crash,
 *      and a documented status for every cell.
 *   2. a signature that is perfectly valid — for a different payload.
 *   3. length sweep: every prefix and every over-long extension of a valid blob.
 *   4. alphabet sweep: every position poisoned with every kind of bad byte.
 *   5. HALs that misbehave: failing, lying about how much they wrote, never
 *      ending the segment list, or yielding nothing at all.
 *
 * Host test. Build:
 *   cc -std=c99 -Wall -Wextra -Werror -Icore -Iinclude -Itests \
 *      core/vl_*.c tests/test_vl_robustness.c -o /tmp/t && /tmp/t
 *
 * (c) 2026 VectiVolt — Apache-2.0 License */

#include "vectilicense/vectilicense.h"

#include "vl_base32.h"

#include "vl_test_fixtures.h"
#include "vl_test_hal.h"

#include <stdio.h>
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

/* The fixture family and key id, from tests/gen_fixtures.py. */
#define FIX_FAMILY  0x02u
#define FIX_KEY_ID  7u

static void cfg_init(vl_config_t *cfg, vl_pubkey_t *keys)
{
    keys[0].key_id = FIX_KEY_ID;
    memcpy(keys[0].key, FIX_PUBKEY, VL_PUBKEY_LEN);
    memset(cfg, 0, sizeof *cfg);
    cfg->keys      = keys;
    cfg->key_count = 1;
    cfg->family    = FIX_FAMILY;
}

/* ========================================================================== */
/* 1. NULL-callback matrix                                                     */
/*                                                                             */
/* read_id_segment is the only required member. Every other combination of the */
/* six optional ones must produce a defined result, and none of them may make  */
/* the core reach through a NULL pointer.                                      */
/* ========================================================================== */
#define CB_NOW      0x01u
#define CB_HWM_LOAD 0x02u
#define CB_HWM_STOR 0x04u
#define CB_BLOB_LD  0x08u
#define CB_BLOB_ST  0x10u
#define CB_POSTURE  0x20u

static void test_null_matrix(void)
{
    unsigned mask;

    puts("NULL-callback matrix (64 combinations x 3 flag settings)");

    for (mask = 0; mask < 64u; mask++) {
        vl_test_ctx_t ctx;
        vl_hal_t hal;
        vl_pubkey_t keys[1];
        vl_config_t cfg;
        vl_license_t lic;
        vl_posture_t posture;
        vl_status_t st;
        int has_clock = (mask & CB_NOW)      != 0u;
        int has_hwm   = (mask & CB_HWM_LOAD) != 0u && (mask & CB_HWM_STOR) != 0u;

        vlt_hal_init(&hal, &ctx);
        ctx.now = 1750000000u;                    /* inside FIX_BLOB_WINDOWED */
        if (mask & CB_NOW)      hal.now_epoch      = vlt_now_epoch;
        if (mask & CB_HWM_LOAD) hal.hwm_load       = vlt_hwm_load;
        if (mask & CB_HWM_STOR) hal.hwm_store      = vlt_hwm_store;
        if (mask & CB_BLOB_LD)  hal.blob_load      = vlt_blob_load;
        if (mask & CB_BLOB_ST)  hal.blob_store     = vlt_blob_store;
        if (mask & CB_POSTURE)  hal.secure_posture = vlt_secure_posture;

        cfg_init(&cfg, keys);

        /* --- default flags ------------------------------------------------ */
        st = vl_verify(FIX_BLOB_PERPETUAL, &cfg, &hal, &lic);
        CHECK(st == VL_OK, "mask 0x%02x: perpetual should verify, got %s",
              mask, vl_status_str(st));
        CHECK((lic.checked & VL_CHECKED_SIGNATURE) != 0u &&
              (lic.checked & VL_CHECKED_DEVICE) != 0u,
              "mask 0x%02x: signature and device always checked", mask);
        CHECK(((lic.checked & VL_CHECKED_TIME) != 0u) == has_clock,
              "mask 0x%02x: VL_CHECKED_TIME iff a clock exists", mask);
        CHECK((lic.checked & VL_CHECKED_HWM) == 0u,
              "mask 0x%02x: HWM not checked unless asked for", mask);

        /* An expired licence: enforced only when there is a clock. This is
         * the documented clockless contract, not an oversight. */
        st = vl_verify(FIX_BLOB_EXPIRED, &cfg, &hal, &lic);
        CHECK(st == (has_clock ? VL_ERR_EXPIRED : VL_OK),
              "mask 0x%02x: expired blob -> %s", mask, vl_status_str(st));

        /* --- VL_FLAG_REQUIRE_CLOCK ---------------------------------------- */
        cfg.flags = VL_FLAG_REQUIRE_CLOCK;
        st = vl_verify(FIX_BLOB_PERPETUAL, &cfg, &hal, &lic);
        CHECK(st == (has_clock ? VL_OK : VL_ERR_NO_CLOCK),
              "mask 0x%02x: REQUIRE_CLOCK -> %s", mask, vl_status_str(st));

        /* --- VL_FLAG_ENFORCE_HWM ------------------------------------------ */
        cfg.flags = VL_FLAG_ENFORCE_HWM;
        st = vl_verify(FIX_BLOB_PERPETUAL, &cfg, &hal, &lic);
        /* Rollback protection is a clock compared against a stored mark. A HAL
         * missing either half cannot provide it, so asking for it must be
         * refused outright — including the clockless case, which used to
         * return VL_OK having enforced nothing at all (not the mark, and not
         * the validity window that shares the same branch). */
        if (!has_hwm || !has_clock) {
            CHECK(st == VL_ERR_INVALID_ARG,
                  "mask 0x%02x: ENFORCE_HWM with half a HWM implementation must "
                  "be refused, not silently downgraded (got %s)",
                  mask, vl_status_str(st));
            CHECK(lic.checked == 0u,
                  "mask 0x%02x: a refused config reports no checks run", mask);
            CHECK(ctx.hwm == 0u,
                  "mask 0x%02x: a refused config stores no mark", mask);
            /* And it must not be a door around expiry either. */
            CHECK(vl_verify(FIX_BLOB_EXPIRED, &cfg, &hal, &lic) == VL_ERR_INVALID_ARG,
                  "mask 0x%02x: ENFORCE_HWM refusal covers an expired blob too",
                  mask);
        } else {
            CHECK(st == VL_OK, "mask 0x%02x: ENFORCE_HWM -> %s",
                  mask, vl_status_str(st));
            CHECK((lic.checked & VL_CHECKED_HWM) != 0u,
                  "mask 0x%02x: HWM marked checked", mask);
            CHECK(ctx.hwm == 1750000000u,
                  "mask 0x%02x: mark stored", mask);
        }

        /* --- posture ------------------------------------------------------- */
        CHECK(vl_posture(&hal, &posture) == VL_OK,
              "mask 0x%02x: posture never fails on a well-behaved HAL", mask);
        CHECK(posture.secure_boot ==
              ((mask & CB_POSTURE) ? VL_POSTURE_ON : VL_POSTURE_UNKNOWN),
              "mask 0x%02x: posture reports what it knows", mask);

        /* --- blob storage is none of vl_verify()'s business ----------------- */
        CHECK(ctx.blob_loads == 0 && ctx.blob_stores == 0,
              "mask 0x%02x: vl_verify must not touch blob storage", mask);
    }
}

/* ========================================================================== */
/* 2. A valid signature over the wrong payload                                 */
/* ========================================================================== */
static void test_cross_payload_signature(void)
{
    vl_test_ctx_t ctx;
    vl_hal_t hal;
    vl_pubkey_t keys[1];
    vl_config_t cfg;
    uint8_t a[VL_BLOB_BIN_LEN], b[VL_BLOB_BIN_LEN];
    char blob[VL_BLOB_STR_BUF_LEN];
    vl_status_t st;

    puts("A signature that is valid, but for a different payload");

    vlt_hal_init(&hal, &ctx);
    cfg_init(&cfg, keys);

    CHECK(vl_base32_decode(FIX_BLOB_PERPETUAL, a, sizeof a, VL_BLOB_BIN_LEN) ==
          (int)VL_BLOB_BIN_LEN, "decode perpetual");
    CHECK(vl_base32_decode(FIX_BLOB_WINDOWED, b, sizeof b, VL_BLOB_BIN_LEN) ==
          (int)VL_BLOB_BIN_LEN, "decode windowed");

    /* Both halves are genuine vendor output; only the pairing is forged. */
    memcpy(a + VL_PAYLOAD_LEN, b + VL_PAYLOAD_LEN, VL_SIG_LEN);
    CHECK(vl_base32_encode(a, VL_BLOB_BIN_LEN, blob, sizeof blob) ==
          (int)VL_BLOB_STR_LEN, "re-encode spliced blob");
    st = vl_verify(blob, &cfg, &hal, NULL);
    CHECK(st == VL_ERR_BAD_SIGNATURE,
          "perpetual payload + windowed signature rejected (got %s)",
          vl_status_str(st));

    /* And the other way round. */
    CHECK(vl_base32_decode(FIX_BLOB_PERPETUAL, a, sizeof a, VL_BLOB_BIN_LEN) ==
          (int)VL_BLOB_BIN_LEN, "re-decode perpetual");
    memcpy(b + VL_PAYLOAD_LEN, a + VL_PAYLOAD_LEN, VL_SIG_LEN);
    CHECK(vl_base32_encode(b, VL_BLOB_BIN_LEN, blob, sizeof blob) ==
          (int)VL_BLOB_STR_LEN, "re-encode spliced blob 2");
    st = vl_verify(blob, &cfg, &hal, NULL);
    CHECK(st == VL_ERR_BAD_SIGNATURE,
          "windowed payload + perpetual signature rejected (got %s)",
          vl_status_str(st));

    /* The signature is checked before the device is even looked at, so a
     * forged pairing cannot be distinguished from a foreign device by the
     * status code — which is what we want: no oracle. */
    ctx.wrong_device = 1;
    CHECK(vl_verify(blob, &cfg, &hal, NULL) == VL_ERR_BAD_SIGNATURE,
          "still a signature error on the wrong device");
}

/* ========================================================================== */
/* 3. Length sweep — truncated and over-long                                   */
/* ========================================================================== */
static void test_length_sweep(void)
{
    vl_test_ctx_t ctx;
    vl_hal_t hal;
    vl_pubkey_t keys[1];
    vl_config_t cfg;
    char blob[VL_BLOB_STR_LEN + 64];
    size_t n;
    int wrong = 0;

    puts("Length sweep: every truncation and every over-long extension");

    vlt_hal_init(&hal, &ctx);
    cfg_init(&cfg, keys);

    for (n = 0; n <= VL_BLOB_STR_LEN + 32u; n++) {
        vl_status_t st;
        size_t i;
        for (i = 0; i < n; i++) {
            blob[i] = (i < VL_BLOB_STR_LEN) ? FIX_BLOB_PERPETUAL[i] : '0';
        }
        blob[n] = '\0';
        st = vl_verify(blob, &cfg, &hal, NULL);
        if (n == VL_BLOB_STR_LEN) {
            if (st != VL_OK) {
                wrong++;
                printf("  full-length blob returned %s\n", vl_status_str(st));
            }
        } else if (st != VL_ERR_BAD_FORMAT) {
            wrong++;
            printf("  length %u returned %s\n", (unsigned)n, vl_status_str(st));
        }
    }
    CHECK(wrong == 0, "%d lengths gave the wrong status", wrong);

    /* Grouping characters are free, but they are not significant characters:
     * a blob padded out to 160 characters with hyphens is still short. */
    memcpy(blob, FIX_BLOB_PERPETUAL, VL_BLOB_STR_LEN + 1u);
    blob[VL_BLOB_STR_LEN - 1u] = '-';
    CHECK(vl_verify(blob, &cfg, &hal, NULL) == VL_ERR_BAD_FORMAT,
          "a significant character replaced by a hyphen is a short blob");
}

/* ========================================================================== */
/* 4. Alphabet sweep — every position, every kind of bad byte                   */
/* ========================================================================== */
static void test_alphabet_sweep(void)
{
    static const char POISON[] = { 'U', 'u', '!', '=', '\x01', '\x7f',
                                   (char)0x80, (char)0xff, '+', '/' };
    vl_test_ctx_t ctx;
    vl_hal_t hal;
    vl_pubkey_t keys[1];
    vl_config_t cfg;
    char blob[VL_BLOB_STR_BUF_LEN];
    size_t pos, p;
    int accepted = 0;
    int wrong_status = 0;

    puts("Alphabet sweep: 160 positions x 10 out-of-alphabet bytes");

    vlt_hal_init(&hal, &ctx);
    cfg_init(&cfg, keys);

    for (pos = 0; pos < VL_BLOB_STR_LEN; pos++) {
        for (p = 0; p < sizeof POISON; p++) {
            vl_status_t st;
            memcpy(blob, FIX_BLOB_PERPETUAL, VL_BLOB_STR_LEN + 1u);
            blob[pos] = POISON[p];
            st = vl_verify(blob, &cfg, &hal, NULL);
            if (st == VL_OK) accepted++;
            if (st != VL_ERR_BAD_FORMAT) wrong_status++;
        }
    }
    CHECK(accepted == 0, "%d poisoned blobs were accepted", accepted);
    CHECK(wrong_status == 0,
          "%d poisoned blobs failed for a reason other than BAD_FORMAT",
          wrong_status);

    /* An embedded NUL truncates, which the length check already catches. */
    memcpy(blob, FIX_BLOB_PERPETUAL, VL_BLOB_STR_LEN + 1u);
    blob[80] = '\0';
    CHECK(vl_verify(blob, &cfg, &hal, NULL) == VL_ERR_BAD_FORMAT,
          "embedded NUL rejected");

    /* Case and Crockford aliases are not errors: the same bytes, respelled,
     * are the same licence. Nothing else in the alphabet may be. */
    {
        size_t i;
        int changed = 0;
        memcpy(blob, FIX_BLOB_PERPETUAL, VL_BLOB_STR_LEN + 1u);
        for (i = 0; i < VL_BLOB_STR_LEN; i++) {
            if (blob[i] >= 'A' && blob[i] <= 'Z') {
                blob[i] = (char)(blob[i] - 'A' + 'a');
                changed++;
            }
        }
        CHECK(changed > 0, "the fixture has letters to lowercase");
        CHECK(vl_verify(blob, &cfg, &hal, NULL) == VL_OK,
              "a lowercased blob is the same licence");
    }
}

/* ========================================================================== */
/* 5. HALs that misbehave                                                      */
/* ========================================================================== */
static void test_bad_hal(void)
{
    vl_test_ctx_t ctx;
    vl_hal_t hal;
    vl_pubkey_t keys[1];
    vl_config_t cfg;
    uint8_t fp[VL_FINGERPRINT_LEN];
    vl_status_t st;

    puts("HALs that misbehave");

    vlt_hal_init(&hal, &ctx);
    cfg_init(&cfg, keys);

    ctx.lying_segment = 1;
    st = vl_compute_fingerprint(&hal, fp);
    CHECK(st == VL_ERR_PLATFORM,
          "a HAL claiming it wrote more than cap is refused, not trusted "
          "(got %s)", vl_status_str(st));
    CHECK(vl_verify(FIX_BLOB_PERPETUAL, &cfg, &hal, NULL) == VL_ERR_PLATFORM,
          "...and vl_verify fails closed");
    ctx.lying_segment = 0;

    ctx.no_segments = 1;
    CHECK(vl_compute_fingerprint(&hal, fp) == VL_ERR_PLATFORM,
          "a HAL with no identity at all is a platform error, not an empty hash");
    ctx.no_segments = 0;

    /* An endless segment list must terminate at VL_ID_SEGMENT_COUNT_MAX and
     * produce a fingerprint, not spin. If this test hangs, that bound is gone. */
    ctx.endless_segments = 1;
    CHECK(vl_compute_fingerprint(&hal, fp) == VL_OK,
          "an endless segment list is bounded, not fatal");
    CHECK(vl_verify(FIX_BLOB_PERPETUAL, &cfg, &hal, NULL) == VL_ERR_DEVICE_MISMATCH,
          "...and yields some other device's fingerprint");
    ctx.endless_segments = 0;

    ctx.fail_segment = 1;
    CHECK(vl_verify(FIX_BLOB_PERPETUAL, &cfg, &hal, NULL) == VL_ERR_PLATFORM,
          "a failing segment read fails closed");
    ctx.fail_segment = 0;

    /* A broken clock is a platform error, never a silently skipped check. */
    hal.now_epoch   = vlt_now_epoch;
    ctx.clock_fails = 1;
    CHECK(vl_verify(FIX_BLOB_PERPETUAL, &cfg, &hal, NULL) == VL_ERR_PLATFORM,
          "a failing clock fails closed even for a perpetual licence");
    ctx.clock_fails = 0;

    /* A broken high-water store, likewise. */
    {
        vl_hal_t full;
        vl_test_ctx_t fctx;
        vl_config_t c2;
        vlt_hal_full(&full, &fctx);
        cfg_init(&c2, keys);
        c2.flags   = VL_FLAG_ENFORCE_HWM;
        fctx.now   = 1750000000u;
        CHECK(vl_verify(FIX_BLOB_PERPETUAL, &c2, &full, NULL) == VL_OK,
              "the full HAL verifies");
        CHECK(fctx.blob_loads == 0 && fctx.blob_stores == 0,
              "the full HAL's blob callbacks stay untouched");
        fctx.hwm_fails = 1;
        CHECK(vl_verify(FIX_BLOB_PERPETUAL, &c2, &full, NULL) == VL_ERR_PLATFORM,
              "a failing high-water mark fails closed");
    }
}

/* ========================================================================== */
/* 6. Deny-list edges                                                          */
/* ========================================================================== */
static void test_denylist_edges(void)
{
    vl_test_ctx_t ctx;
    vl_hal_t hal;
    vl_pubkey_t keys[1];
    vl_config_t cfg;
    vl_license_t lic;
    static const uint32_t only_zero[]  = { 0u };
    static const uint32_t has_target[] = { 0u, 1u, 1001u, 0xFFFFFFFFu };

    puts("Deny-list edges");

    vlt_hal_init(&hal, &ctx);
    cfg_init(&cfg, keys);

    /* count > 0 with a NULL pointer must not be dereferenced. */
    cfg.revoked_serials = NULL;
    cfg.revoked_count   = 4;
    CHECK(vl_verify(FIX_BLOB_PERPETUAL, &cfg, &hal, &lic) == VL_OK,
          "a NULL deny-list with a non-zero count is treated as absent");
    CHECK((lic.checked & VL_CHECKED_REVOCATION) == 0u,
          "...and says the check did not run");

    /* A non-NULL list with count 0, likewise. */
    cfg.revoked_serials = only_zero;
    cfg.revoked_count   = 0;
    CHECK(vl_verify(FIX_BLOB_PERPETUAL, &cfg, &hal, &lic) == VL_OK,
          "an empty deny-list is treated as absent");

    /* Serial 0 in the list must not accidentally match serial 1001. */
    cfg.revoked_count = 1;
    CHECK(vl_verify(FIX_BLOB_PERPETUAL, &cfg, &hal, &lic) == VL_OK,
          "a deny-list containing only 0 does not revoke serial 1001");
    CHECK((lic.checked & VL_CHECKED_REVOCATION) != 0u,
          "...and the check is marked as having run");

    cfg.revoked_serials = has_target;
    cfg.revoked_count   = sizeof has_target / sizeof has_target[0];
    CHECK(vl_verify(FIX_BLOB_PERPETUAL, &cfg, &hal, &lic) == VL_ERR_REVOKED,
          "a serial in the middle of the list is found");
}

/* ========================================================================== */
/* 7. Key-set edges                                                            */
/* ========================================================================== */
static void test_keyset_edges(void)
{
    vl_test_ctx_t ctx;
    vl_hal_t hal;
    vl_pubkey_t keys[3];
    vl_config_t cfg;

    puts("Key-set edges");

    vlt_hal_init(&hal, &ctx);
    memset(&cfg, 0, sizeof cfg);
    cfg.family    = FIX_FAMILY;
    cfg.keys      = keys;
    cfg.key_count = 3;

    /* Rotation shape: the real key sits behind two decoys. */
    memset(keys, 0, sizeof keys);
    keys[0].key_id = 1;
    keys[1].key_id = 2;
    keys[2].key_id = FIX_KEY_ID;
    memcpy(keys[2].key, FIX_PUBKEY, VL_PUBKEY_LEN);
    CHECK(vl_verify(FIX_BLOB_PERPETUAL, &cfg, &hal, NULL) == VL_OK,
          "the right key is found at the end of the set");

    /* An all-zero key with the right key_id must not verify anything. */
    keys[2].key_id = FIX_KEY_ID;
    memset(keys[2].key, 0, VL_PUBKEY_LEN);
    CHECK(vl_verify(FIX_BLOB_PERPETUAL, &cfg, &hal, NULL) == VL_ERR_BAD_SIGNATURE,
          "an all-zero public key verifies nothing");

    /* Retiring the key id is how a whole generation of licences is dropped. */
    keys[2].key_id = 8;
    memcpy(keys[2].key, FIX_PUBKEY, VL_PUBKEY_LEN);
    CHECK(vl_verify(FIX_BLOB_PERPETUAL, &cfg, &hal, NULL) == VL_ERR_UNKNOWN_KEY,
          "dropping a key id retires every licence signed with it");
}

int main(void)
{
    printf("%s — robustness\n\n", vl_version_str());
    test_null_matrix();
    test_cross_payload_signature();
    test_length_sweep();
    test_alphabet_sweep();
    test_bad_hal();
    test_denylist_edges();
    test_keyset_edges();

    printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
