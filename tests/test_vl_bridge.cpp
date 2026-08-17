/* test_vl_bridge.cpp — host test for the bridge facade, bridge/vl_bridge.h.
 *
 * The four VectiSuite bridges cannot be compiled here (they need Arduino,
 * ESPAsyncWebServer and the sibling libraries), but everything they actually
 * do lives in vecti::License, which is deliberately free of Arduino — so it is
 * testable, and this is the test.
 *
 * Uses the same fake HAL segments and the same minted blobs as
 * tests/test_vl_core.c, via tests/gen_fixtures.py.
 *
 * Build (CMake does this for you):
 *   c++ -std=c++11 -Iinclude -Ibridge -Itests -Icore tests/test_vl_bridge.cpp \
 *       core/vl_*.c -o /tmp/test_vl_bridge && /tmp/test_vl_bridge
 *
 * Part of VectiLicense. Apache-2.0. */

#include "vl_bridge.h"

#include "vl_test_fixtures.h"

#include <stdio.h>
#include <string.h>

static int g_pass = 0, g_fail = 0;

#define CHECK(cond)                                                       \
    do {                                                                  \
        if (cond) { g_pass++; }                                           \
        else { g_fail++; printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); } \
    } while (0)

/* ------------------------------------------------------------------ */
/* A fake HAL: the three id segments gen_fixtures.py signed against, an
 * in-memory blob slot, and no clock — which is the interesting default,
 * because it is what a bare board without an RTC looks like.            */
/* ------------------------------------------------------------------ */

static const unsigned char SEG0[] = { 0xde, 0xad, 0xbe, 0xef, 0x00, 0x11 };
static const char SEG1[] = "vecti-test-board";

static char g_store[VL_BLOB_STR_BUF_LEN];
static size_t g_store_len = 0;
static int g_store_fails = 0;

static vl_status_t fake_segments(void *ctx, uint32_t idx,
                                 uint8_t *out, size_t cap, size_t *out_len) {
    (void)ctx;
    switch (idx) {
    case 0:
        if (cap < sizeof(SEG0)) { return VL_ERR_BUFFER_TOO_SMALL; }
        memcpy(out, SEG0, sizeof(SEG0));
        *out_len = sizeof(SEG0);
        return VL_OK;
    case 1:
        if (cap < sizeof(SEG1) - 1) { return VL_ERR_BUFFER_TOO_SMALL; }
        memcpy(out, SEG1, sizeof(SEG1) - 1);
        *out_len = sizeof(SEG1) - 1;
        return VL_OK;
    case 2:
        *out_len = 0;            /* a zero-length segment is legal */
        return VL_OK;
    default:
        return VL_ERR_NO_MORE_SEGMENTS;
    }
}

static vl_status_t fake_blob_load(void *ctx, char *out, size_t cap, size_t *out_len) {
    (void)ctx;
    if (g_store_len == 0) { return VL_ERR_NOT_FOUND; }
    if (g_store_len >= cap) { return VL_ERR_BUFFER_TOO_SMALL; }
    memcpy(out, g_store, g_store_len);
    *out_len = g_store_len;
    return VL_OK;
}

static vl_status_t fake_blob_store(void *ctx, const char *blob, size_t len) {
    (void)ctx;
    if (g_store_fails) { return VL_ERR_PLATFORM; }
    if (len >= sizeof(g_store)) { return VL_ERR_BUFFER_TOO_SMALL; }
    memcpy(g_store, blob, len);
    g_store[len] = '\0';
    g_store_len = len;
    return VL_OK;
}

static vl_hal_t make_hal(int with_storage) {
    vl_hal_t h;
    memset(&h, 0, sizeof(h));
    h.read_id_segment = fake_segments;
    if (with_storage) {
        h.blob_load = fake_blob_load;
        h.blob_store = fake_blob_store;
    }
    return h;
}

static const vl_pubkey_t KEYS[] = { { 7, { 0 } } };

static vl_config_t make_cfg(void) {
    static vl_pubkey_t keys[1];
    keys[0].key_id = 7;
    memcpy(keys[0].key, FIX_PUBKEY, VL_PUBKEY_LEN);
    vl_config_t c;
    memset(&c, 0, sizeof(c));
    c.keys = keys;
    c.key_count = 1;
    c.family = 0x02;
    return c;
}

/* ------------------------------------------------------------------ */
/* Regression: deviceId() must not leave the 32-byte fingerprint on the
 * stack. It used to clear it with a plain memset(), which clang -O2
 * deletes outright (the buffer is dead afterwards — verified against
 * the old header with objdump); it now goes through vl_secure_wipe(),
 * which the optimiser may not remove.
 *
 * The check: poison a slab of stack, run deviceId() so its frame lands
 * in that slab, then read the slab back and look for the fingerprint.
 * Only meaningful in an optimised build — at -O0 even the old memset
 * was emitted. The documented build (Release) is optimised, and the
 * -O2 command in this file's header is the one that catches it.       */

#define VL_STACK_PIT 8192
static unsigned char g_stack_copy[VL_STACK_PIT];

#if defined(__GNUC__)
#define VL_NOINLINE __attribute__((noinline))
#else
#define VL_NOINLINE
#endif

VL_NOINLINE static void poison_stack(void) {
    volatile unsigned char pit[VL_STACK_PIT];
    for (size_t i = 0; i < VL_STACK_PIT; i++) { pit[i] = 0x5a; }
}

VL_NOINLINE static void snapshot_stack(void) {
    volatile unsigned char pit[VL_STACK_PIT];
    /* Deliberately reading what the frames above left behind. */
    for (size_t i = 0; i < VL_STACK_PIT; i++) { g_stack_copy[i] = pit[i]; }
}

VL_NOINLINE static void make_device_id(const vl_config_t *cfg, const vl_hal_t *hal,
                                       char *out, size_t cap) {
    vecti::License lic(cfg, hal);
    const char *id = lic.deviceId();
    size_t n = 0;
    while (id[n] && n + 1 < cap) { out[n] = id[n]; n++; }
    out[n] = '\0';
}

static int stack_holds(const unsigned char *needle, size_t n) {
    for (size_t i = 0; i + n <= VL_STACK_PIT; i++) {
        if (memcmp(g_stack_copy + i, needle, n) == 0) { return 1; }
    }
    return 0;
}

/* pump() reports through a plain callback; prove it fires exactly once. */
static int g_cb_calls = 0;
static vl_status_t g_cb_status = VL_ERR_INTERNAL;
static void on_result(void *ctx, vl_status_t st) {
    *(int *)ctx += 1;
    g_cb_status = st;
}

int main(void) {
    (void)KEYS;
    const vl_config_t cfg = make_cfg();
    vl_hal_t hal = make_hal(1);

    /* ---- identity ------------------------------------------------- */
    {
        vecti::License lic(&cfg, &hal);
        CHECK(strcmp(lic.deviceId(), FIX_DEVICE_ID_STR) == 0);
        CHECK(lic.idStatus() == VL_OK);
        CHECK(strcmp(lic.deviceId(), FIX_DEVICE_ID_STR) == 0);   /* cached */
        CHECK(!lic.ok());
        CHECK(lic.license() == NULL);
        CHECK(lic.checked() == 0);
    }

    /* A HAL with no read_id_segment cannot produce an id, and must say so
     * rather than hand back a plausible-looking empty string as if it worked. */
    {
        vl_hal_t broken;
        memset(&broken, 0, sizeof(broken));
        vecti::License lic(&cfg, &broken);
        CHECK(lic.deviceId()[0] == '\0');
        CHECK(lic.idStatus() != VL_OK);
    }

    /* ---- nothing stored yet --------------------------------------- */
    g_store_len = 0;
    {
        vecti::License lic(&cfg, &hal);
        CHECK(lic.begin() == VL_ERR_NOT_FOUND);
        CHECK(!lic.ok());
    }

    /* ---- activate, persist, survive a reboot ----------------------- */
    {
        vecti::License lic(&cfg, &hal);
        CHECK(lic.activate(FIX_BLOB_PERPETUAL) == VL_OK);
        CHECK(lic.ok());
        CHECK(lic.license() != NULL);
        CHECK(lic.license()->serial == 1001);
        CHECK(lic.feature(0) && lic.feature(2) && lic.feature(3));
        CHECK(!lic.feature(1));
        CHECK(!lic.feature(31));
        CHECK(strcmp(lic.blob(), FIX_BLOB_PERPETUAL) == 0);
        CHECK(g_store_len == VL_BLOB_STR_LEN);

        /* no clock in this HAL: the signature was checked, the dates were not,
         * and checked() is the only place that difference is visible. */
        CHECK((lic.checked() & VL_CHECKED_SIGNATURE) != 0);
        CHECK((lic.checked() & VL_CHECKED_DEVICE) != 0);
        CHECK((lic.checked() & VL_CHECKED_TIME) == 0);
    }
    {
        vecti::License rebooted(&cfg, &hal);
        CHECK(rebooted.begin() == VL_OK);
        CHECK(rebooted.ok());
        CHECK(rebooted.license()->serial == 1001);
    }

    /* ---- grouping characters, and what gets stored ------------------ */
    {
        char grouped[256];
        size_t n = 0;
        for (size_t i = 0; i < VL_BLOB_STR_LEN; i += 8) {
            if (i) { grouped[n++] = '-'; }
            memcpy(grouped + n, FIX_BLOB_PERPETUAL + i, 8);
            n += 8;
        }
        grouped[n++] = '\n';
        grouped[n] = '\0';

        g_store_len = 0;
        vecti::License lic(&cfg, &hal);
        CHECK(lic.activate(grouped) == VL_OK);
        /* the dashes the operator pasted are not what gets written to flash */
        CHECK(strcmp(lic.blob(), FIX_BLOB_PERPETUAL) == 0);
        CHECK(g_store_len == VL_BLOB_STR_LEN);
    }

    /* Regression: one licence has many accepted spellings — lower case, and
     * the Crockford aliases I/L -> 1 and O -> 0. blob() used to hand back
     * whichever one the operator pasted, so any check keyed on that string
     * (a redeemed-blob list, an activation de-dupe) was bypassed by typing
     * an I for a 1. It must come back canonical whatever went in.        */
    {
        char respelled[256];
        size_t n = 0;
        for (size_t i = 0; i < VL_BLOB_STR_LEN; i++) {
            char c = FIX_BLOB_PERPETUAL[i];
            if (c == '1')      { c = (i & 1) ? 'I' : 'l'; }
            else if (c == '0') { c = 'O'; }
            else if (c >= 'A' && c <= 'Z' && (i & 1)) { c = (char)(c - 'A' + 'a'); }
            respelled[n++] = c;
        }
        respelled[n] = '\0';
        CHECK(strcmp(respelled, FIX_BLOB_PERPETUAL) != 0);   /* really different */

        g_store_len = 0;
        vecti::License lic(&cfg, &hal);
        CHECK(lic.activate(respelled) == VL_OK);             /* still a valid licence */
        CHECK(strcmp(lic.blob(), FIX_BLOB_PERPETUAL) == 0);  /* stored canonical */
        CHECK(strncmp(g_store, FIX_BLOB_PERPETUAL, VL_BLOB_STR_LEN) == 0);
    }

    /* ---- submit / pump, which is how every bridge feeds it ---------- */
    {
        g_store_len = 0;
        g_cb_calls = 0;
        vecti::License lic(&cfg, &hal);
        lic.onResult(on_result, &g_cb_calls);

        CHECK(!lic.pump());                       /* nothing queued */
        CHECK(lic.submit(FIX_BLOB_PERPETUAL));
        CHECK(lic.pendingSubmission());
        CHECK(!lic.submit(FIX_BLOB_WINDOWED));    /* one slot, one writer */
        CHECK(lic.pump());
        CHECK(g_cb_calls == 1);
        CHECK(g_cb_status == VL_OK);
        CHECK(lic.ok());
        CHECK(!lic.pendingSubmission());
        CHECK(!lic.pump());

        CHECK(!lic.submit(NULL));
        CHECK(!lic.submit("", 0));
        char huge[VL_BRIDGE_BLOB_MAX + 8];
        memset(huge, 'A', sizeof(huge) - 1);
        huge[sizeof(huge) - 1] = '\0';
        CHECK(!lic.submit(huge));                 /* bounded, never overflows */
    }

    /* ---- rejections all fail closed -------------------------------- */
    {
        struct { const char *blob; vl_status_t want; } cases[] = {
            { FIX_BLOB_OTHERDEV,   VL_ERR_DEVICE_MISMATCH },
            { FIX_BLOB_WRONGFAMILY, VL_ERR_BAD_FAMILY },
            { FIX_BLOB_UNKNOWNKEY, VL_ERR_UNKNOWN_KEY },
            { FIX_BLOB_NODOMAIN,   VL_ERR_BAD_SIGNATURE },
            { "not a licence",     VL_ERR_BAD_FORMAT },
            { "",                  VL_ERR_BAD_FORMAT },
        };
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
            g_store_len = 0;
            vecti::License lic(&cfg, &hal);
            CHECK(lic.activate(cases[i].blob) == cases[i].want);
            CHECK(!lic.ok());
            CHECK(lic.license() == NULL);
            CHECK(lic.blob()[0] == '\0');
            CHECK(g_store_len == 0);              /* a bad blob is never stored */
        }
    }

    /* A good licence that follows a bad one must not leave the bad verdict,
     * and a bad one after a good one must not leave the good licence readable. */
    {
        g_store_len = 0;
        vecti::License lic(&cfg, &hal);
        CHECK(lic.activate(FIX_BLOB_PERPETUAL) == VL_OK);
        CHECK(lic.activate(FIX_BLOB_OTHERDEV) == VL_ERR_DEVICE_MISMATCH);
        CHECK(!lic.ok());
        CHECK(lic.license() == NULL);
        CHECK(!lic.feature(0));
        CHECK(lic.checked() == 0);
    }

    /* ---- a store that fails is reported, not swallowed -------------- */
    {
        g_store_len = 0;
        g_store_fails = 1;
        vecti::License lic(&cfg, &hal);
        vl_status_t st = lic.activate(FIX_BLOB_PERPETUAL);
        g_store_fails = 0;
        CHECK(st == VL_ERR_PLATFORM);   /* in force now... */
        CHECK(lic.ok());                /* ...but gone after a reboot */
        CHECK(g_store_len == 0);
    }

    /* ---- a HAL with no storage still verifies ---------------------- */
    {
        vl_hal_t no_store = make_hal(0);
        vecti::License lic(&cfg, &no_store);
        CHECK(lic.begin() == VL_ERR_NOT_FOUND);
        CHECK(lic.activate(FIX_BLOB_PERPETUAL) == VL_OK);
        CHECK(lic.ok());
    }

    /* ---- clear ------------------------------------------------------ */
    {
        g_store_len = 0;
        vecti::License lic(&cfg, &hal);
        CHECK(lic.activate(FIX_BLOB_PERPETUAL) == VL_OK);
        CHECK(lic.clear() == VL_OK);
        CHECK(!lic.ok());
        CHECK(lic.blob()[0] == '\0');
        CHECK(g_store_len == 0);
    }

    /* ---- posture is always populated ------------------------------- */
    {
        vecti::License lic(&cfg, &hal);
        vl_posture_t p = lic.posture();
        CHECK(p.secure_boot == VL_POSTURE_UNKNOWN);
        CHECK(p.flash_encryption == VL_POSTURE_UNKNOWN);
    }

    /* ---- licenseSummary never overruns its buffer ------------------- */
    {
        g_store_len = 0;
        vecti::License lic(&cfg, &hal);
        char big[128], tiny[6], one[1];
        CHECK(strstr(vecti::licenseSummary(lic, big, sizeof(big)), "not licensed") == big);
        CHECK(strchr(big, '(') != NULL);                 /* carries the reason */
        CHECK(strlen(vecti::licenseSummary(lic, tiny, sizeof(tiny))) < sizeof(tiny));
        CHECK(vecti::licenseSummary(lic, one, sizeof(one))[0] == '\0');
        CHECK(vecti::licenseSummary(lic, NULL, 0)[0] == '\0');

        CHECK(lic.activate(FIX_BLOB_PERPETUAL) == VL_OK);
        CHECK(strcmp(vecti::licenseSummary(lic, big, sizeof(big)), "licensed") == 0);
    }

    /* ---- deviceId() leaves no fingerprint on the stack -------------- */
    {
        char id[VL_DEVICE_ID_STR_BUF_LEN];

        /* Sanity first: the poisoned slab really is the region the call
         * runs in, so a "not found" below means wiped, not missed. */
        poison_stack();
        snapshot_stack();
        CHECK(stack_holds((const unsigned char *)"\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a", 8));

        poison_stack();
        make_device_id(&cfg, &hal, id, sizeof(id));
        snapshot_stack();
        CHECK(strcmp(id, FIX_DEVICE_ID_STR) == 0);      /* it really ran */
        CHECK(!stack_holds(FIX_FINGERPRINT, sizeof(FIX_FINGERPRINT)));
    }

    /* Fixtures this test does not use are exercised by test_vl_core.c. */
    (void)FIX_BLOB_EXPIRED; (void)FIX_BLOB_FUTURE; (void)FIX_BLOB_REVOKED;

    printf("%s: %d passed, %d failed\n", g_fail ? "FAIL" : "ok", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
