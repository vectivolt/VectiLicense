/* vl_libc.h — the two or three libc functions core/ actually calls.
 *
 * Part of VectiLicense. Apache-2.0.
 *
 * WHY THIS FILE EXISTS
 *   <string.h> is a HOSTED header. C99 §4p6 lists exactly seven headers a
 *   freestanding implementation must provide — float.h, iso646.h, limits.h,
 *   stdarg.h, stdbool.h, stddef.h, stdint.h — and string.h is not among them.
 *   A real no-libc toolchain does not ship it: arm-none-eabi-gcc 15.2.0
 *   installs stddef.h and stdint.h but no string.h at all, so every core/ file
 *   that included <string.h> failed to compile on the headline target.
 *
 *   GCC and Clang emit calls to memcpy/memset/memcmp from struct assignment and
 *   loop idioms even under -ffreestanding, so the linker needs those three
 *   symbols regardless (every bare-metal runtime provides them). What is not
 *   needed is the header — a prototype is enough.
 *
 *   Hosted builds keep including <string.h>: redeclaring memcpy behind glibc's
 *   _FORTIFY_SOURCE function-like macros would not compile, and there is no
 *   reason to fight a libc that is present. __STDC_HOSTED__ is the C99-defined
 *   way to tell the two apart, and -ffreestanding sets it to 0.
 */

#ifndef VL_LIBC_H
#define VL_LIBC_H

#include <stddef.h>

#if defined(__STDC_HOSTED__) && (__STDC_HOSTED__ == 1)
#include <string.h>
#else
#ifdef __cplusplus
extern "C" {
#endif

void *memcpy(void *dst, const void *src, size_t n);
void *memset(void *dst, int c, size_t n);
int   memcmp(const void *a, const void *b, size_t n);

#ifdef __cplusplus
}
#endif
#endif /* __STDC_HOSTED__ */

#endif /* VL_LIBC_H */
