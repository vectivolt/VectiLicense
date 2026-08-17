/*
 * VectiLicense HAL — STM32. See vl_hal_stm32.h.
 * (c) 2026 VectiVolt — Apache-2.0 License
 *
 * WRITTEN TO THE DOCUMENTED CUBE HAL API, NOT COMPILE-VERIFIED against a real
 * STM32Cube installation. The logic below was compiled for arm-none-eabi with
 * stand-in declarations of HAL_GetUIDw0/1/2, which proves the C is valid but
 * not that it links against your family's HAL.
 */

#include "vl_hal_stm32.h"

#if defined(USE_HAL_DRIVER) || defined(VL_HAL_STM32)

#include <string.h>

#define VL_STM32_UID_LEN 12u

#if defined(VL_HAL_STM32_UID_BASE)
/* Register access, no vendor header required. */
static uint32_t vl_uid_word(unsigned i)
{
    const volatile uint32_t *uid = (const volatile uint32_t *)(VL_HAL_STM32_UID_BASE);
    return uid[i];
}
#else
/* Declared rather than #included: the header that provides these is named
 * after the family (stm32f4xx_hal.h, stm32g0xx_hal.h, ...) and this file
 * refuses to guess. The prototype is identical across every Cube HAL. */
extern uint32_t HAL_GetUIDw0(void);
extern uint32_t HAL_GetUIDw1(void);
extern uint32_t HAL_GetUIDw2(void);

static uint32_t vl_uid_word(unsigned i)
{
    switch (i) {
    case 0:  return HAL_GetUIDw0();
    case 1:  return HAL_GetUIDw1();
    default: return HAL_GetUIDw2();
    }
}
#endif

static vl_status_t read_id_segment(void *ctx, uint32_t idx,
                                   uint8_t *out, size_t cap, size_t *out_len)
{
    unsigned i;
    uint32_t all_or = 0u;
    uint32_t all_and = 0xFFFFFFFFu;

    (void)ctx;
    if (out == NULL || out_len == NULL) return VL_ERR_INVALID_ARG;
    if (idx != 0u) return VL_ERR_NO_MORE_SEGMENTS;
    if (cap < VL_STM32_UID_LEN) return VL_ERR_BUFFER_TOO_SMALL;

    for (i = 0; i < 3u; i++) {
        uint32_t w = vl_uid_word(i);
        all_or  |= w;
        all_and &= w;
        out[i * 4u + 0u] = (uint8_t)(w & 0xFFu);
        out[i * 4u + 1u] = (uint8_t)((w >> 8) & 0xFFu);
        out[i * 4u + 2u] = (uint8_t)((w >> 16) & 0xFFu);
        out[i * 4u + 3u] = (uint8_t)((w >> 24) & 0xFFu);
    }

    /* All zeros or all ones means the read did not reach the UID — usually a
     * wrong VL_HAL_STM32_UID_BASE. Every affected board would otherwise share
     * one fingerprint, and therefore one licence. */
    if (all_or == 0u || all_and == 0xFFFFFFFFu) {
        memset(out, 0, VL_STM32_UID_LEN);
        return VL_ERR_PLATFORM;
    }

    *out_len = VL_STM32_UID_LEN;
    return VL_OK;
}

static const vl_hal_t g_hal = {
    read_id_segment,
    NULL,               /* now_epoch:      supply your RTC              */
    NULL, NULL,         /* hwm_load/store: supply your EEPROM/backup RAM */
    NULL, NULL,         /* blob_load/store                              */
    NULL,               /* secure_posture                               */
    NULL
};

const vl_hal_t *vl_hal_stm32(void) { return &g_hal; }

#else  /* not an STM32 build */

const vl_hal_t *vl_hal_stm32(void) { return NULL; }

#endif
