/* vl_util.c — constant-time compare and non-elidable secure wipe.
 *
 * Part of VectiLicense. Apache-2.0. */

#include "vl_util.h"

#include <stdint.h>
#include "vl_libc.h"

/* A volatile function pointer to memset.
 *
 * A plain memset() over a buffer that is dead afterwards is legally removable
 * under the "as if" rule (C99 5.1.2.3) and GCC/Clang do remove it at -O2.
 * Reading a volatile object is an observable side effect, so the compiler must
 * load this pointer and must issue the indirect call — it cannot know what it
 * points at. Same construct as libsodium's sodium_memzero() fallback and
 * OpenSSL's OPENSSL_cleanse().
 *
 * Chosen over explicit_bzero()/memset_s() because those need per-platform
 * feature macros and are absent on several of the newlibs we target; this
 * works everywhere with no #ifdef. */
static void *(*const volatile vl_memset_ptr)(void *, int, size_t) = memset;

void vl_secure_wipe(void *p, size_t len)
{
    if (p == NULL || len == 0u) {
        return;
    }
    (void)vl_memset_ptr(p, 0, len);
}

int vl_ct_eq(const void *a, const void *b, size_t len)
{
    const uint8_t *pa = (const uint8_t *)a;
    const uint8_t *pb = (const uint8_t *)b;
    uint8_t diff = 0u;
    size_t i;

    /* Fail closed on a NULL argument rather than dereferencing it. A
     * zero-length comparison is also "not equal": no caller in this library
     * has a legitimate reason to compare nothing, so returning "match" there
     * would only ever be a bug that silently passes. */
    if (pa == NULL || pb == NULL || len == 0u) {
        return 0;
    }

    for (i = 0; i < len; i++) {
        diff = (uint8_t)(diff | (uint8_t)(pa[i] ^ pb[i]));
    }

    /* diff == 0 -> 1, diff != 0 -> 0. No branch, no early exit. */
    return (int)((((uint32_t)diff - 1u) >> 8) & 1u);
}
