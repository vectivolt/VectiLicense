/* vl_line.h — line framing for UART, USB-CDC and telnet.
 *
 * (c) 2026 VectiVolt — Apache-2.0 License
 *
 * transport/ layer: OPTIONAL, and built to core rules — pure C99, no malloc,
 * no stdio, no recursion, no floats. Delete this file if you do not need it.
 *
 * WHAT IT IS FOR
 *   A byte stream has no message boundaries. Push bytes in as they arrive
 *   from your UART ISR or CDC read; when a line terminator shows up you get
 *   back a bounded, NUL-terminated string to hand straight to vl_verify().
 *
 * WHAT IT DOES WITH WHITESPACE
 *   Drops it. Space, tab, vertical tab and form feed are never stored, so
 *   leading and trailing padding disappear and '\r' is harmless. '\r' AND
 *   '\n' both terminate a line, because a terminal emulator's Enter key sends
 *   '\r' and telnet sends both; an empty line is silently skipped, so CRLF
 *   yields exactly one line and blank lines cost nothing.
 *
 *   This frames licence blobs, not general text — a blob has no meaningful
 *   internal whitespace, and vl_verify() ignores '-' grouping on its own, so
 *   "AR0G E0GD 0000 ..." arrives intact and verifies.
 *
 * A LINE THAT NEVER ENDS
 *   Cannot overflow anything. Once VL_LINE_MAX_LEN characters have piled up
 *   the line is abandoned and the rest of it discarded; the terminator that
 *   finally arrives returns VL_ERR_BAD_FORMAT once, and the next line starts
 *   clean. A peer that streams megabytes without a newline gets one error per
 *   newline and never a corrupted buffer.
 *
 * TYPICAL USE:
 *
 *     static vl_line_t ln;                  // ~200 bytes, wherever you like
 *     vl_line_reset(&ln);
 *     ...
 *     while ((ch = uart_read()) >= 0) {
 *         if (vl_line_push(&ln, (char)ch) == VL_OK)
 *             status = vl_verify(ln.buf, &cfg, &hal, &lic);
 *     }
 */

#ifndef VL_LINE_H
#define VL_LINE_H

#include <stddef.h>
#include <stdint.h>

#include "vectilicense/vectilicense.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Longest line accepted, whitespace excluded. 160 for a bare blob; the
 * default leaves room for '-' grouping and a short command prefix stripped by
 * the caller. Override with -DVL_LINE_MAX_LEN=... */
#ifndef VL_LINE_MAX_LEN
#define VL_LINE_MAX_LEN 200u
#endif

typedef struct {
    char    buf[VL_LINE_MAX_LEN + 1u];  /* valid and NUL-terminated after VL_OK */
    size_t  len;                        /* characters in buf, excluding the NUL */
    uint8_t ready;                      /* a line is sitting in buf */
    uint8_t overflow;                   /* current line too long, discarding it */
} vl_line_t;

/* Drop any partial line and start fresh. Safe on a NULL pointer.
 * A zeroed vl_line_t is already valid, so this is only needed to abandon a
 * line in progress (a timeout, a disconnect, a new session). */
void vl_line_reset(vl_line_t *l);

/*
 * Push one received byte.
 *
 *   VL_OK               a line is ready: l->buf, NUL-terminated, l->len chars.
 *                       Use it before the next push, which starts the next line.
 *   VL_ERR_NOT_FOUND    byte consumed, no line yet. The ordinary return.
 *   VL_ERR_BAD_FORMAT   the line just terminated was longer than
 *                       VL_LINE_MAX_LEN and has been discarded.
 *   VL_ERR_INVALID_ARG  l is NULL.
 *
 * For a buffer of bytes, loop — that is deliberately not wrapped, because the
 * loop is shorter than the wrapper's documentation:
 *
 *     for (i = 0; i < n; i++)
 *         if (vl_line_push(&ln, buf[i]) == VL_OK) { ... }
 */
vl_status_t vl_line_push(vl_line_t *l, char ch);

#ifdef __cplusplus
}
#endif

#endif /* VL_LINE_H */
