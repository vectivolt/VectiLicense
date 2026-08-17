/* vl_line.c — see vl_line.h.
 *
 * (c) 2026 VectiVolt — Apache-2.0 License
 *
 * transport/ layer, built to core rules: <stdint.h> <stddef.h> and core/vl_libc.h
 * only, no allocation, no recursion, no stdio. Note there is no <ctype.h>
 * either — isspace() is locale-dependent and not freestanding, so the
 * whitespace set is spelled out.
 */

#include "vl_line.h"

void vl_line_reset(vl_line_t *l)
{
    if (l == NULL) return;
    l->len      = 0u;
    l->ready    = 0u;
    l->overflow = 0u;
    l->buf[0]   = '\0';
}

vl_status_t vl_line_push(vl_line_t *l, char ch)
{
    unsigned char u = (unsigned char)ch;

    if (l == NULL) return VL_ERR_INVALID_ARG;

    /* The previous line has been handed up; this byte belongs to the next. */
    if (l->ready != 0u) {
        l->len    = 0u;
        l->ready  = 0u;
        l->buf[0] = '\0';
    }

    if (u == '\n' || u == '\r') {
        if (l->overflow != 0u) {
            l->overflow = 0u;
            l->len      = 0u;
            return VL_ERR_BAD_FORMAT;      /* reported once, then forgotten */
        }
        if (l->len == 0u) return VL_ERR_NOT_FOUND;   /* blank line, incl. the LF of CRLF */
        l->buf[l->len] = '\0';
        l->ready = 1u;
        return VL_OK;
    }

    /* Whitespace is never stored: strips padding, and makes '\r' inert if it
     * ever arrives somewhere other than end of line. */
    if (u == ' ' || u == '\t' || u == '\v' || u == '\f') return VL_ERR_NOT_FOUND;

    if (l->overflow != 0u) return VL_ERR_NOT_FOUND;  /* still discarding */

    if (l->len >= (size_t)VL_LINE_MAX_LEN) {
        l->overflow = 1u;
        l->len      = 0u;                  /* drop the partial line now */
        l->buf[0]   = '\0';
        return VL_ERR_NOT_FOUND;
    }

    l->buf[l->len++] = ch;
    return VL_ERR_NOT_FOUND;
}
