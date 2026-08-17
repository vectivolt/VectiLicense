/* vl_sha512.h — SHA-512, FIPS 180-4. Required by Ed25519.
 *
 * Streaming API on purpose: Ed25519 verification hashes R || A || M, and a
 * streaming hash lets us do that without ever materialising the concatenation
 * in a buffer (which is what upstream TweetNaCl's crypto_sign_open does).
 *
 * Part of VectiLicense. Apache-2.0.
 * core/ layer: pure C99, freestanding. */

#ifndef VL_SHA512_H
#define VL_SHA512_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define VL_SHA512_BLOCK_LEN   128u
#define VL_SHA512_DIGEST_LEN  64u

typedef struct {
    uint64_t state[8];
    uint64_t byte_count;   /* total bytes absorbed; caps at 2^61-1 bytes */
    uint8_t  buffer[VL_SHA512_BLOCK_LEN];
    size_t   buffer_len;
} vl_sha512_ctx_t;

void vl_sha512_init(vl_sha512_ctx_t *ctx);
void vl_sha512_update(vl_sha512_ctx_t *ctx, const void *data, size_t len);
/* Wipes ctx as a side effect; re-init before reuse. */
void vl_sha512_final(vl_sha512_ctx_t *ctx, uint8_t out[VL_SHA512_DIGEST_LEN]);
void vl_sha512(const void *data, size_t len, uint8_t out[VL_SHA512_DIGEST_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* VL_SHA512_H */
