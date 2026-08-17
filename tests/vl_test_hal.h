/* vl_test_hal.h — the fake HAL shared by the robustness and fuzz harnesses.
 *
 * Header-only and `static`, so each test binary gets its own copy and there is
 * no test support library to build. The segment list here is byte-identical to
 * the one in tests/gen_fixtures.py, which is what makes the fixture blobs
 * verify against it.
 *
 * (c) 2026 VectiVolt — Apache-2.0 License */

#ifndef VL_TEST_HAL_H
#define VL_TEST_HAL_H

#include "vectilicense/vectilicense.h"

#include <string.h>

typedef struct {
    int      wrong_device;     /* perturb segment 0 -> a different device */
    int      fail_segment;     /* read_id_segment returns VL_ERR_PLATFORM */
    int      lying_segment;    /* read_id_segment sets *out_len > cap */
    int      endless_segments; /* never return NO_MORE_SEGMENTS */
    int      no_segments;      /* return NO_MORE_SEGMENTS at idx 0 */

    uint32_t now;
    int      clock_fails;

    uint32_t hwm;
    int      hwm_fails;
    int      hwm_stores;

    int      blob_loads;       /* the core must never call these */
    int      blob_stores;
    int      posture_calls;
} vl_test_ctx_t;

static vl_status_t vlt_read_id_segment(void *vctx, uint32_t idx,
                                       uint8_t *out, size_t cap, size_t *out_len)
{
    static const uint8_t s0[6] = { 0xde, 0xad, 0xbe, 0xef, 0x00, 0x11 };
    static const char    s1[]  = "vecti-test-board";
    vl_test_ctx_t *c = (vl_test_ctx_t *)vctx;

    if (c->fail_segment)  return VL_ERR_PLATFORM;
    if (c->no_segments)   return VL_ERR_NO_MORE_SEGMENTS;
    if (c->lying_segment) { *out_len = cap + 1u; return VL_OK; }

    if (c->endless_segments) {
        if (cap < 1u) return VL_ERR_BUFFER_TOO_SMALL;
        out[0]   = (uint8_t)idx;
        *out_len = 1u;
        return VL_OK;
    }

    switch (idx) {
    case 0:
        if (cap < sizeof s0) return VL_ERR_BUFFER_TOO_SMALL;
        memcpy(out, s0, sizeof s0);
        if (c->wrong_device) out[0] ^= 0xFFu;
        *out_len = sizeof s0;
        return VL_OK;
    case 1:
        if (cap < sizeof s1 - 1u) return VL_ERR_BUFFER_TOO_SMALL;
        memcpy(out, s1, sizeof s1 - 1u);
        *out_len = sizeof s1 - 1u;
        return VL_OK;
    case 2:
        *out_len = 0u;                    /* a zero-length segment is legal */
        return VL_OK;
    default:
        return VL_ERR_NO_MORE_SEGMENTS;
    }
}

static vl_status_t vlt_now_epoch(void *vctx, uint32_t *out)
{
    vl_test_ctx_t *c = (vl_test_ctx_t *)vctx;
    if (c->clock_fails) return VL_ERR_PLATFORM;
    *out = c->now;
    return VL_OK;
}

static vl_status_t vlt_hwm_load(void *vctx, uint32_t *out)
{
    vl_test_ctx_t *c = (vl_test_ctx_t *)vctx;
    if (c->hwm_fails) return VL_ERR_PLATFORM;
    *out = c->hwm;
    return VL_OK;
}

static vl_status_t vlt_hwm_store(void *vctx, uint32_t value)
{
    vl_test_ctx_t *c = (vl_test_ctx_t *)vctx;
    if (c->hwm_fails) return VL_ERR_PLATFORM;
    c->hwm = value;
    c->hwm_stores++;
    return VL_OK;
}

/* vl_verify() must never touch blob storage — it is handed a blob. These two
 * exist purely so the matrix can prove the call count stays at zero. */
static vl_status_t vlt_blob_load(void *vctx, char *out, size_t cap, size_t *out_len)
{
    vl_test_ctx_t *c = (vl_test_ctx_t *)vctx;
    (void)out; (void)cap; (void)out_len;
    c->blob_loads++;
    return VL_ERR_NOT_FOUND;
}

static vl_status_t vlt_blob_store(void *vctx, const char *blob, size_t len)
{
    vl_test_ctx_t *c = (vl_test_ctx_t *)vctx;
    (void)blob; (void)len;
    c->blob_stores++;
    return VL_OK;
}

static vl_status_t vlt_secure_posture(void *vctx, vl_posture_t *out)
{
    vl_test_ctx_t *c = (vl_test_ctx_t *)vctx;
    c->posture_calls++;
    out->secure_boot      = VL_POSTURE_ON;
    out->flash_encryption = VL_POSTURE_OFF;
    return VL_OK;
}

/* A HAL with the required callback and nothing else. */
static void vlt_hal_init(vl_hal_t *hal, vl_test_ctx_t *ctx)
{
    memset(ctx, 0, sizeof *ctx);
    memset(hal, 0, sizeof *hal);
    hal->read_id_segment = vlt_read_id_segment;
    hal->ctx             = ctx;
}

/* Every callback populated. */
static void vlt_hal_full(vl_hal_t *hal, vl_test_ctx_t *ctx)
{
    vlt_hal_init(hal, ctx);
    hal->now_epoch      = vlt_now_epoch;
    hal->hwm_load       = vlt_hwm_load;
    hal->hwm_store      = vlt_hwm_store;
    hal->blob_load      = vlt_blob_load;
    hal->blob_store     = vlt_blob_store;
    hal->secure_posture = vlt_secure_posture;
}

#endif /* VL_TEST_HAL_H */
