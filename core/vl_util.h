/* vl_util.h — constant-time compare and non-elidable secure wipe.
 *
 * Part of VectiLicense. Apache-2.0.
 * core/ layer: pure C99, freestanding. <stdint.h> <stddef.h> and vl_libc.h only. */

#ifndef VL_UTIL_H
#define VL_UTIL_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Zero `len` bytes at `p` in a way the optimiser may not remove.
 * No-op when p is NULL or len is 0. */
void vl_secure_wipe(void *p, size_t len);

/* Constant-time compare. Returns 1 iff the first `len` bytes match.
 * Returns 0 (i.e. "not equal") if either pointer is NULL or len is 0 —
 * fails closed rather than dereferencing or vacuously matching. */
int vl_ct_eq(const void *a, const void *b, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* VL_UTIL_H */
