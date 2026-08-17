/*
 * VectiLicense HAL — RP2040 / RP2350. See vl_hal_rp2040.h.
 * (c) 2026 VectiVolt — Apache-2.0 License
 *
 * WRITTEN TO THE DOCUMENTED pico-sdk API, NOT COMPILE-VERIFIED — no pico-sdk
 * on the build machine. Reviewed against the pico-sdk docs for
 * pico_get_unique_board_id(), flash_range_erase(), flash_range_program() and
 * save_and_disable_interrupts().
 */

#include "vl_hal_rp2040.h"

#if (defined(PICO_ON_DEVICE) && PICO_ON_DEVICE) || \
    defined(PICO_RP2040) || defined(PICO_RP2350)

#include <string.h>

#include "pico/unique_id.h"
#include "hardware/flash.h"
#include "hardware/sync.h"
#include "hardware/regs/addressmap.h"      /* XIP_BASE */

/* One sector reserved for licence state. Defaults to the last sector of the
 * configured flash size; override if your linker script already claims it. */
#ifndef VL_HAL_RP2040_FLASH_OFFSET
#define VL_HAL_RP2040_FLASH_OFFSET (PICO_FLASH_SIZE_BYTES - FLASH_SECTOR_SIZE)
#endif

#define VL_RP_MAGIC 0x564C3031u   /* "VL01" */

/* Fits in a single 256-byte flash page; erase still costs a whole sector. */
typedef struct {
    uint32_t magic;
    uint32_t hwm;
    uint32_t blob_len;
    char     blob[VL_BLOB_STR_BUF_LEN];
} vl_rp_record_t;

static void record_read(vl_rp_record_t *rec)
{
    const void *src = (const void *)(XIP_BASE + VL_HAL_RP2040_FLASH_OFFSET);
    memcpy(rec, src, sizeof *rec);
    if (rec->magic != VL_RP_MAGIC || rec->blob_len > VL_BLOB_STR_LEN) {
        /* Erased or corrupt: present it as empty rather than as garbage. */
        memset(rec, 0, sizeof *rec);
        rec->magic = VL_RP_MAGIC;
    }
    rec->blob[VL_BLOB_STR_LEN] = '\0';
}

static vl_status_t record_write(const vl_rp_record_t *rec)
{
    uint8_t page[FLASH_PAGE_SIZE];
    uint32_t irq;

    if (sizeof *rec > sizeof page) return VL_ERR_INTERNAL;
    memset(page, 0xFF, sizeof page);
    memcpy(page, rec, sizeof *rec);

    /* Single-core assumption; see the header for the core1 caveat. */
    irq = save_and_disable_interrupts();
    flash_range_erase(VL_HAL_RP2040_FLASH_OFFSET, FLASH_SECTOR_SIZE);
    flash_range_program(VL_HAL_RP2040_FLASH_OFFSET, page, sizeof page);
    restore_interrupts(irq);

    /* Read back: a failed erase/program is silent otherwise, and a silent
     * failure here means rollback protection that does not protect. */
    if (memcmp((const void *)(XIP_BASE + VL_HAL_RP2040_FLASH_OFFSET),
               page, sizeof page) != 0) {
        return VL_ERR_PLATFORM;
    }
    return VL_OK;
}

/* -------------------------------------------------------------------------- */
static vl_status_t read_id_segment(void *ctx, uint32_t idx,
                                   uint8_t *out, size_t cap, size_t *out_len)
{
    pico_unique_board_id_t id;
    size_t i;
    uint8_t any = 0;

    (void)ctx;
    if (out == NULL || out_len == NULL) return VL_ERR_INVALID_ARG;
    if (idx != 0u) return VL_ERR_NO_MORE_SEGMENTS;
    if (cap < PICO_UNIQUE_BOARD_ID_SIZE_BYTES) return VL_ERR_BUFFER_TOO_SMALL;

    memset(&id, 0, sizeof id);
    pico_get_unique_board_id(&id);

    /* An all-zero or all-ones id means the flash chip did not answer. Hashing
     * it anyway would give every affected board the same fingerprint, and one
     * licence would unlock all of them. */
    for (i = 0; i < PICO_UNIQUE_BOARD_ID_SIZE_BYTES; i++) any |= id.id[i];
    if (any == 0u) return VL_ERR_PLATFORM;
    for (i = 0, any = 0xFFu; i < PICO_UNIQUE_BOARD_ID_SIZE_BYTES; i++) any &= id.id[i];
    if (any == 0xFFu) return VL_ERR_PLATFORM;

    memcpy(out, id.id, PICO_UNIQUE_BOARD_ID_SIZE_BYTES);
    *out_len = PICO_UNIQUE_BOARD_ID_SIZE_BYTES;
    return VL_OK;
}

static vl_status_t hwm_load(void *ctx, uint32_t *out)
{
    vl_rp_record_t rec;
    (void)ctx;
    if (out == NULL) return VL_ERR_INVALID_ARG;
    record_read(&rec);
    *out = rec.hwm;
    return VL_OK;
}

static vl_status_t hwm_store(void *ctx, uint32_t value)
{
    vl_rp_record_t rec;
    (void)ctx;
    record_read(&rec);
    if (rec.hwm == value) return VL_OK;      /* do not burn an erase cycle */
    rec.hwm = value;
    return record_write(&rec);
}

static vl_status_t blob_load(void *ctx, char *out, size_t cap, size_t *out_len)
{
    vl_rp_record_t rec;
    (void)ctx;
    if (out == NULL || out_len == NULL || cap == 0u) return VL_ERR_INVALID_ARG;
    record_read(&rec);
    if (rec.blob_len == 0u) return VL_ERR_NOT_FOUND;
    if (rec.blob_len + 1u > cap) return VL_ERR_BUFFER_TOO_SMALL;
    memcpy(out, rec.blob, rec.blob_len);
    out[rec.blob_len] = '\0';
    *out_len = rec.blob_len;
    return VL_OK;
}

static vl_status_t blob_store(void *ctx, const char *blob, size_t len)
{
    vl_rp_record_t rec;
    (void)ctx;
    if (blob == NULL) return VL_ERR_INVALID_ARG;
    if (len > VL_BLOB_STR_LEN) return VL_ERR_BUFFER_TOO_SMALL;
    record_read(&rec);
    memset(rec.blob, 0, sizeof rec.blob);
    memcpy(rec.blob, blob, len);
    rec.blob_len = (uint32_t)len;
    return record_write(&rec);
}

static const vl_hal_t g_hal = {
    read_id_segment,
    NULL,                       /* now_epoch: no trustworthy clock on board */
    hwm_load, hwm_store,
    blob_load, blob_store,
    NULL,                       /* secure_posture: no secure boot on RP2040 */
    NULL
};

const vl_hal_t *vl_hal_rp2040(void) { return &g_hal; }

#else  /* built without the pico-sdk */

const vl_hal_t *vl_hal_rp2040(void) { return NULL; }

#endif
