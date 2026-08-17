/* vl_sha256.h — SHA-256, FIPS 180-4. Used for the device fingerprint.
 *
 * Part of VectiLicense. Apache-2.0.
 * core/ layer: pure C99, freestanding. */

#ifndef VL_SHA256_H
#define VL_SHA256_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define VL_SHA256_BLOCK_LEN   64u
#define VL_SHA256_DIGEST_LEN  32u

typedef struct {
    uint32_t state[8];
    uint64_t bit_count;
    uint8_t  buffer[VL_SHA256_BLOCK_LEN];
    size_t   buffer_len;
} vl_sha256_ctx_t;

void vl_sha256_init(vl_sha256_ctx_t *ctx);
void vl_sha256_update(vl_sha256_ctx_t *ctx, const void *data, size_t len);
/* Wipes ctx as a side effect; re-init before reuse. */
void vl_sha256_final(vl_sha256_ctx_t *ctx, uint8_t out[VL_SHA256_DIGEST_LEN]);
void vl_sha256(const void *data, size_t len, uint8_t out[VL_SHA256_DIGEST_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* VL_SHA256_H */
