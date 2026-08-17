/* vl_ed25519.h — Ed25519 signature VERIFICATION ONLY.
 *
 * There is deliberately no key generation and no signing function in this
 * translation unit, and none anywhere else in the device build. If the code
 * that mints a licence is not present, it cannot be called. Minting lives in
 * tools/vl_mint.py, on the vendor's machine, with the private key.
 *
 * Part of VectiLicense. Apache-2.0.
 * core/ layer: pure C99, freestanding. */

#ifndef VL_ED25519_H
#define VL_ED25519_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define VL_ED25519_PUBKEY_LEN  32u
#define VL_ED25519_SIG_LEN     64u

/* Verify `sig` over `msg` under public key `pk`.
 *
 * Returns 1 if and only if the signature is valid. Returns 0 for every other
 * outcome including NULL arguments, a public key that is not a point on the
 * curve, a public key whose encoding is non-canonical, a public key of low
 * order (the 14 small-order encodings, among them the all-zero placeholder —
 * every one of those is a universal forgery), and a scalar S that is not
 * fully reduced. There is no error code and no third state: anything other
 * than 1 means do not trust the message.
 *
 * No allocation, no recursion, ~1.5 KB of stack. */
int vl_ed25519_verify(const uint8_t sig[VL_ED25519_SIG_LEN],
                      const uint8_t *msg, size_t msg_len,
                      const uint8_t pk[VL_ED25519_PUBKEY_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* VL_ED25519_H */
