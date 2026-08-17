/*
 * VectiLicense HAL — NXP Kinetis / i.MX RT. See vl_hal_nxp.h.
 * (c) 2026 VectiVolt — Apache-2.0 License
 *
 * WRITTEN TO THE DOCUMENTED MCUXpresso REGISTER API, NOT COMPILE-VERIFIED
 * against a real SDK. The logic below was compiled for arm-none-eabi with
 * stand-in SIM and OCOTP register definitions, which proves the C is valid
 * but not that your part's header spells the fields the same way.
 */

#include "vl_hal_nxp.h"

#if defined(__has_include)
#  if __has_include("fsl_device_registers.h")
#    include "fsl_device_registers.h"
#    define VL_NXP_HAVE_SDK 1
#  endif
#endif

#if defined(VL_NXP_HAVE_SDK) && defined(SIM_UIDL_UID_MASK)
#  define VL_NXP_KINETIS 1
#elif defined(VL_NXP_HAVE_SDK) && defined(OCOTP) && defined(OCOTP_CFG0_BITS_MASK)
#  define VL_NXP_IMXRT 1
#endif

#if defined(VL_NXP_KINETIS) || defined(VL_NXP_IMXRT)

#include <string.h>

/* Big-endian so a UID printed from the debugger reads the same way round as
 * the fingerprint's input. Order is part of the on-wire format. */
static size_t put_be32(uint8_t *out, uint32_t w)
{
    out[0] = (uint8_t)((w >> 24) & 0xFFu);
    out[1] = (uint8_t)((w >> 16) & 0xFFu);
    out[2] = (uint8_t)((w >> 8) & 0xFFu);
    out[3] = (uint8_t)(w & 0xFFu);
    return 4u;
}

#if defined(VL_NXP_KINETIS)
#  if defined(SIM_UIDH_UID_MASK)
#    define VL_NXP_ID_LEN 16u
#  else
#    define VL_NXP_ID_LEN 12u   /* KL / KE / some KV have no UIDH */
#  endif
#else
#  define VL_NXP_ID_LEN 8u
#endif

static vl_status_t read_id_segment(void *ctx, uint32_t idx,
                                   uint8_t *out, size_t cap, size_t *out_len)
{
    size_t n = 0;
    size_t i;
    uint8_t any = 0u;
    uint8_t all = 0xFFu;

    (void)ctx;
    if (out == NULL || out_len == NULL) return VL_ERR_INVALID_ARG;
    if (idx != 0u) return VL_ERR_NO_MORE_SEGMENTS;
    if (cap < VL_NXP_ID_LEN) return VL_ERR_BUFFER_TOO_SMALL;

#if defined(VL_NXP_KINETIS)
#  if defined(SIM_UIDH_UID_MASK)
    n += put_be32(out + n, (uint32_t)SIM->UIDH);
#  endif
    n += put_be32(out + n, (uint32_t)SIM->UIDMH);
    n += put_be32(out + n, (uint32_t)SIM->UIDML);
    n += put_be32(out + n, (uint32_t)SIM->UIDL);
#else
    n += put_be32(out + n, (uint32_t)OCOTP->CFG0);
    n += put_be32(out + n, (uint32_t)OCOTP->CFG1);
#endif

    /* All zeros or all ones means the read did not reach the fuses. Hashing
     * that would give every affected board one shared fingerprint, and one
     * licence would unlock all of them. */
    for (i = 0; i < n; i++) { any |= out[i]; all &= out[i]; }
    if (any == 0u || all == 0xFFu) {
        memset(out, 0, n);
        return VL_ERR_PLATFORM;
    }

    *out_len = n;
    return VL_OK;
}

static const vl_hal_t g_hal = {
    read_id_segment,
    NULL,               /* now_epoch:      supply your RTC               */
    NULL, NULL,         /* hwm_load/store: supply your FlexNVM/EEPROM    */
    NULL, NULL,         /* blob_load/store                               */
    NULL,               /* secure_posture                                */
    NULL
};

const vl_hal_t *vl_hal_nxp(void) { return &g_hal; }

#else  /* no recognised NXP device header */

const vl_hal_t *vl_hal_nxp(void) { return NULL; }

#endif
