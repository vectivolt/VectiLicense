/*
 * VectiLicense HAL — the unported stub. See vl_hal_none.h.
 * (c) 2026 VectiVolt — Apache-2.0 License
 */

#include "vl_hal_none.h"

#if defined(__GNUC__) && !defined(VL_HAL_NONE_ACKNOWLEDGED)
#warning "VectiLicense: building hal/none. Every licence check will fail until you implement read_id_segment. Define VL_HAL_NONE_ACKNOWLEDGED to silence."
#endif

/*
 * TODO(you): replace the body with your board's hardware identity.
 *
 * A worked example, for an MCU with a 96-bit die id at a known address:
 *
 *     if (idx != 0u) return VL_ERR_NO_MORE_SEGMENTS;
 *     if (cap < 12u) return VL_ERR_BUFFER_TOO_SMALL;
 *     memcpy(out, (const void *)MY_UID_BASE, 12u);
 *     if (is_all_zero_or_all_ones(out, 12u)) return VL_ERR_PLATFORM;
 *     *out_len = 12u;
 *     return VL_OK;
 *
 * Rules the core relies on:
 *   - end the list with VL_ERR_NO_MORE_SEGMENTS, not with an error code and
 *     not by returning zero bytes forever
 *   - never set *out_len larger than cap
 *   - a zero-length segment is legal and hashes as a single 0x00 byte
 *   - return VL_ERR_PLATFORM if the read failed, never a placeholder value
 */
static vl_status_t read_id_segment(void *ctx, uint32_t idx,
                                   uint8_t *out, size_t cap, size_t *out_len)
{
    (void)ctx; (void)idx; (void)out; (void)cap; (void)out_len;
    return VL_ERR_PLATFORM;
}

/* Everything optional is NULL. The core handles that: validity windows go
 * unenforced and VL_CHECKED_TIME stays clear, rollback protection is off, and
 * vl_posture() reports VL_POSTURE_UNKNOWN. Add callbacks as you gain the
 * hardware to back them. */
static const vl_hal_t g_hal = {
    read_id_segment,
    NULL,
    NULL, NULL,
    NULL, NULL,
    NULL,
    NULL
};

const vl_hal_t *vl_hal_none(void) { return &g_hal; }
