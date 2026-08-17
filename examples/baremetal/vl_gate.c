/*
 * VectiLicense example — bare metal, no OS, no libc headers at all.
 * (c) 2026 VectiVolt — Apache-2.0 License
 *
 * This is the portability story with nothing hidden. There is no RTOS here, no
 * heap, no printf, no file system, no clock and no network. A licence still
 * verifies, because verification is arithmetic over 100 bytes and 32 bytes of
 * public key.
 *
 * It is hal/none/ filled in: the stub ships with read_id_segment returning
 * VL_ERR_PLATFORM, and the only thing you have to write to port to a new MCU
 * is the body of that one function. Everything else on this page is your
 * application, not the library.
 *
 * The board here is a Cortex-M with a 96-bit factory die id, which is the STM32
 * layout; the same shape works for an RP2040 board id, an NXP SIM->UIDx set, an
 * ESP32 efuse MAC, or a serial number in a locked OTP page.
 *
 * Build check (from the repository root) — both of these produce zero
 * diagnostics, and both were run to say so:
 *   cc -std=c99 -ffreestanding -Wall -Wextra -Werror -Iinclude -Itransport \
 *      -c examples/baremetal/vl_gate.c -o /dev/null
 *   arm-none-eabi-gcc -std=c99 -Os -ffreestanding -mcpu=cortex-m0plus -mthumb \
 *      -Wall -Wextra -Werror -Iinclude -Itransport \
 *      -c examples/baremetal/vl_gate.c -o /dev/null
 *
 * COMPILED, NEVER LINKED, NEVER RUN. Neither command is a ctest case, this
 * file has never been part of a firmware image, and it obviously cannot run on
 * a host: MY_UID_BASE is a hardware address. See the README's "What has
 * actually been built and run".
 *
 * On the target, add core/vl_*.c and this file to your build and you are done.
 * Measured cost of core/ at -Os: 9,319 bytes of flash on Cortex-M0+ (9,195 on
 * M4), zero bytes of .data and .bss, and a deepest stack chain of 4,376 bytes
 * through vl_verify(). Give the calling task 5 KB.
 */

#include "vectilicense/vectilicense.h"

#include "vl_line.h"           /* optional: framing a blob off a UART */

/* The core's non-elidable wipe. Reached by relative path so this file needs no
 * include flag of its own; a plain memset() on a buffer that is dead afterwards
 * is deleted outright at -O2, which is not what "erase the fingerprint" means.
 * There is no <string.h> here on purpose: it is a HOSTED header, and this file
 * is the example for targets whose toolchain ships no libc at all. */
#include "../../core/vl_util.h"

/* ===========================================================================
 * 1. THE HAL — the only platform-specific code in this file.
 *
 * Two identity segments: the factory die id, and the board serial your
 * production line burns into a locked flash page. Two sources rather than one
 * because a die id alone survives a board swap and a serial alone is only as
 * trustworthy as the page it lives in.
 *
 * The order and content of these segments is part of the on-wire format.
 * Decide on it before you issue your first licence; adding a segment later
 * invalidates every licence already in the field.
 * ========================================================================= */

/* STM32F4 unique device id, three 32-bit words. Substitute your part's. */
#define MY_UID_BASE      0x1FFF7A10UL
#define MY_UID_LEN       12u

/* A locked flash page holding a 4-byte big-endian serial, 0xFFFFFFFF when
 * blank. Substitute your own provisioning scheme, or delete segment 1. */
#define MY_SERIAL_ADDR   0x080E0000UL
#define MY_SERIAL_LEN    4u

/* A byte loop rather than memcpy(): no libc, and `volatile` is what you want
 * when the source is an OTP/eFuse window rather than ordinary memory. */
static void read_bytes(uint8_t *dst, const volatile uint8_t *src, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) {
        dst[i] = src[i];
    }
}

static int all_same(const uint8_t *p, size_t n, uint8_t v)
{
    size_t i;
    for (i = 0; i < n; i++) {
        if (p[i] != v) return 0;
    }
    return 1;
}

static vl_status_t board_read_id_segment(void *ctx, uint32_t idx,
                                         uint8_t *out, size_t cap, size_t *out_len)
{
    (void)ctx;

    switch (idx) {
    case 0:
        if (cap < MY_UID_LEN) return VL_ERR_BUFFER_TOO_SMALL;
        read_bytes(out, (const volatile uint8_t *)MY_UID_BASE, MY_UID_LEN);
        /* An all-0x00 or all-0xFF read means the bus answered with nothing.
         * Returning it anyway would give every unit that fails this way the
         * same fingerprint, and one licence would unlock all of them. */
        if (all_same(out, MY_UID_LEN, 0x00u) || all_same(out, MY_UID_LEN, 0xFFu)) {
            return VL_ERR_PLATFORM;
        }
        *out_len = MY_UID_LEN;
        return VL_OK;

    case 1:
        if (cap < MY_SERIAL_LEN) return VL_ERR_BUFFER_TOO_SMALL;
        read_bytes(out, (const volatile uint8_t *)MY_SERIAL_ADDR, MY_SERIAL_LEN);
        if (all_same(out, MY_SERIAL_LEN, 0xFFu)) {
            /* Never provisioned. A zero-length segment is legal and hashes as
             * a single 0x00 byte, so an unprovisioned board still gets a
             * stable fingerprint from its die id alone — it just gets a
             * different one from a provisioned board, which is correct. */
            *out_len = 0u;
            return VL_OK;
        }
        *out_len = MY_SERIAL_LEN;
        return VL_OK;

    default:
        /* This, not VL_ERR_INVALID_ARG, is how the list ends. */
        return VL_ERR_NO_MORE_SEGMENTS;
    }
}

/* Every optional callback is NULL, and the core handles that:
 *   - no now_epoch:  validity windows are not enforced, and vl_verify() says
 *                    so by leaving VL_CHECKED_TIME clear in lic.checked. If
 *                    you sell time-limited licences on a board with no RTC,
 *                    read that bit — or set VL_FLAG_REQUIRE_CLOCK and refuse.
 *   - no hwm_*:      no clock-rollback protection. There is no clock to roll.
 *   - no blob_*:     you store the 161 bytes yourself, wherever you keep
 *                    settings.
 *   - no posture:    vl_posture() reports VL_POSTURE_UNKNOWN. */
static const vl_hal_t BOARD_HAL = {
    board_read_id_segment,
    NULL,           /* now_epoch */
    NULL, NULL,     /* hwm_load, hwm_store */
    NULL, NULL,     /* blob_load, blob_store */
    NULL,           /* secure_posture */
    NULL            /* ctx */
};

/* ===========================================================================
 * 2. THE CONFIGURATION — static, const, in flash.
 * ========================================================================= */

/* Paste from `python3 tools/vl_mint.py keygen`. This is a PUBLIC key; there is
 * nothing in this image that could sign with it, which is the entire point.
 *
 * REPLACE IT. The key below is a placeholder: a real Ed25519 public key whose
 * private half was generated in memory and discarded, so nothing can sign for
 * it and every licence is refused with VL_ERR_BAD_SIGNATURE until you paste
 * your own. Never put an all-zero key here — 32 zero bytes are a low-order
 * curve point, forgeable with no private key at all; the core rejects them, but
 * a placeholder key has to be a real point to fail closed for the right
 * reason. */
static const vl_pubkey_t VENDOR_KEYS[] = {
    { .key_id = 1, .key = {   /* PLACEHOLDER — no private key exists for it */
        0x70, 0x7d, 0xec, 0x62, 0x84, 0xba, 0x43, 0x82,
        0x4f, 0x75, 0x22, 0xc2, 0x10, 0xb3, 0x6b, 0x13,
        0x15, 0x2b, 0xfe, 0x56, 0xdb, 0xf7, 0xbc, 0xad,
        0x1d, 0xf0, 0xc9, 0x7a, 0xf6, 0xc8, 0x0d, 0xe9,
    } },
};

static const vl_config_t CFG = {
    .keys = VENDOR_KEYS, .key_count = 1,
    .family = 3,
    .revoked_serials = NULL, .revoked_count = 0,
    .flags = 0
};

#define FEATURE_HIGH_SPEED 0
#define FEATURE_CANOPEN    1

/* ===========================================================================
 * 3. THE GATE
 * ========================================================================= */

static vl_license_t g_license;
static vl_status_t  g_status = VL_ERR_NOT_FOUND;

/* Supply these two from your board support. The library needs neither; they
 * are here because an example that cannot show you anything is not an example.
 *
 * board_load_blob() returns 0 if nothing is stored. Storage can be a flash
 * page, an EEPROM, or a struct in battery-backed RAM — 161 bytes. */
extern int  board_load_blob(char *out, size_t cap);
extern void board_save_blob(const char *blob);
extern void board_print(const char *s);

/* Call once at start-up, after the clock tree is up. */
void gate_init(void)
{
    char blob[VL_BLOB_STR_BUF_LEN];

    if (!board_load_blob(blob, sizeof blob)) {
        g_status = VL_ERR_NOT_FOUND;
        return;
    }
    /* Re-verified on every boot. A licence that was good at the factory is not
     * evidence about this boot: the flash may have been swapped since. */
    g_status = vl_verify(blob, &CFG, &BOARD_HAL, &g_license);
    board_print(vl_status_str(g_status));
}

/* What the customer reads off the display, or you read off a label printer.
 * 26 characters, Crockford base32, no ambiguous letters. */
vl_status_t gate_device_id(char *out, size_t cap)
{
    uint8_t fingerprint[VL_FINGERPRINT_LEN];
    vl_status_t st = vl_compute_fingerprint(&BOARD_HAL, fingerprint);

    if (st == VL_OK) {
        st = vl_encode_device_id(fingerprint, out, cap);
    }
    /* On every path, including the failure one — the old code returned early
     * and left the fingerprint on a stack the next task reuses. */
    vl_secure_wipe(fingerprint, sizeof fingerprint);
    return st;
}

/* The gate itself. Note what it is not: it is not a security boundary. Whoever
 * can rewrite this flash can delete this function's caller. What it is, is the
 * difference between copying a licence and reverse-engineering a firmware
 * image — see docs/THREAT_MODEL.md, which says so at length. */
int gate_allows(unsigned feature_bit)
{
    return (g_status == VL_OK) && vl_has_feature(&g_license, feature_bit);
}

int gate_licensed(void)      { return g_status == VL_OK; }
const char *gate_reason(void) { return vl_status_str(g_status); }

/* Whether an expiry on the licence was actually enforced. On this board it
 * never is, because there is no clock — so a caller that sells subscriptions
 * needs to know that rather than assume. */
int gate_expiry_enforced(void)
{
    return (g_status == VL_OK) && (g_license.checked & VL_CHECKED_TIME) != 0u;
}

/* ===========================================================================
 * 4. ACTIVATION over a UART, one interrupt-delivered byte at a time.
 *
 * transport/vl_line.c does the framing: it accumulates until a newline,
 * bounded, and hands up a NUL-terminated string. That is the whole transport
 * layer — vl_verify() takes a string, so anything that can deliver 160
 * characters works with no adapter at all. Over CAN, swap vl_line for
 * transport/vl_chunk.c, which reassembles 8-byte frames out of order.
 * ========================================================================= */

static vl_line_t g_rx;

/* Call from the UART RX interrupt, or from a polling loop. Returns 1 when a
 * complete line was consumed, so the caller can echo a prompt. */
int gate_uart_rx(char ch)
{
    if (vl_line_push(&g_rx, ch) != VL_OK) {
        return 0;
    }
    /* A whole line arrived. Verifying it takes tens of milliseconds, which is
     * far too long for an interrupt handler on most parts — set a flag here
     * and call gate_activate() from your main loop if that is your case. */
    g_status = vl_verify(g_rx.buf, &CFG, &BOARD_HAL, &g_license);
    if (g_status == VL_OK) {
        /* Store only after it verified. Storing first means a mistyped blob
         * survives the next power cycle. */
        board_save_blob(g_rx.buf);
        board_print("licensed");
    } else {
        board_print(vl_status_str(g_status));
    }
    vl_line_reset(&g_rx);
    return 1;
}
