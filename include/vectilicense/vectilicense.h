/*
 * VectiLicense v1 — offline, asymmetric device licensing for embedded targets.
 *
 * The device holds only a 32-byte Ed25519 PUBLIC key. A licence is an Ed25519
 * signature over a 36-byte payload bound to the device's hardware fingerprint.
 * Verification is pure local computation: no network, ever.
 *
 * What this eliminates, compared to v0.1's shared-secret HMAC scheme: the
 * keygen. Dumping the firmware yields a public key and nothing else. An
 * attacker cannot mint a licence for their own device, cannot set feature bits
 * they did not buy, cannot extend an expiry, and cannot replay another
 * device's licence.
 *
 * What it does not eliminate, and what no software licensing scheme can: an
 * attacker who can rewrite the firmware can patch out the call site that
 * checks vl_verify()'s return value. That is a property of running on hardware
 * somebody else owns, not a weakness in the signature. The only real
 * mitigation is a hardware root of trust — on ESP32, Secure Boot v2 plus Flash
 * Encryption. Use vl_posture() to find out whether you have one, and decide.
 *
 * Layering (see README):
 *   core/       this API's implementation. Pure C99, freestanding, no deps.
 *   hal/        everything platform-specific, injected via vl_hal_t.
 *   transport/  optional framing helpers. vl_verify() takes a NUL-terminated
 *               string, so it is already transport independent.
 *   bridge/     optional shims for VectiDash / VectiNet / VectiSerial / VectiOTA.
 *
 * Apache-2.0.
 */

#ifndef VECTILICENSE_H
#define VECTILICENSE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define VECTILICENSE_VERSION_MAJOR 1
#define VECTILICENSE_VERSION_MINOR 0
#define VECTILICENSE_VERSION_PATCH 0

/* ========================================================================== */
/* Status codes. 0 is success; every failure is negative. No function in this  */
/* library returns VL_OK on any error path.                                    */
/* ========================================================================== */
typedef enum {
    VL_OK                    =   0,

    VL_ERR_INVALID_ARG       =  -1,  /* NULL or nonsensical argument */
    VL_ERR_BUFFER_TOO_SMALL  =  -2,
    VL_ERR_BAD_FORMAT        =  -3,  /* wrong length, or a byte outside base32 */
    VL_ERR_BAD_MAGIC         =  -4,  /* not a VectiLicense blob at all */
    VL_ERR_BAD_VERSION       =  -5,  /* newer than this firmware understands */
    VL_ERR_BAD_FAMILY        =  -6,  /* minted for a different product */
    VL_ERR_UNKNOWN_KEY       =  -7,  /* key_id not in the embedded key set */
    VL_ERR_BAD_SIGNATURE     =  -8,  /* signature did not verify */
    VL_ERR_DEVICE_MISMATCH   =  -9,  /* minted for a different device */
    VL_ERR_NOT_YET_VALID     = -10,  /* now < not_before */
    VL_ERR_EXPIRED           = -11,  /* now > not_after */
    VL_ERR_REVOKED           = -12,  /* serial is on the deny-list */
    VL_ERR_CLOCK_ROLLBACK    = -13,  /* now < the stored high-water mark */
    VL_ERR_NO_CLOCK          = -14,  /* a time check was required, no clock */
    VL_ERR_PLATFORM          = -15,  /* the HAL could not do its job */
    VL_ERR_NO_MORE_SEGMENTS  = -16,  /* HAL sentinel: end of the id segment list */
    VL_ERR_NOT_FOUND         = -17,  /* HAL blob_load: nothing is stored */
    VL_ERR_INTERNAL          = -18
} vl_status_t;

/* Human-readable status. Never returns NULL, for any int value. */
const char *vl_status_str(vl_status_t status);

/* e.g. "vectilicense/1.0.0". Never NULL. */
const char *vl_version_str(void);

/* ========================================================================== */
/* Sizes. All fixed at compile time; nothing here allocates.                   */
/* ========================================================================== */
#define VL_MAGIC                 0x56u   /* 'V' */
#define VL_FORMAT_VERSION        0x01u

#define VL_PAYLOAD_LEN           36u
#define VL_SIG_LEN               64u
#define VL_BLOB_BIN_LEN          (VL_PAYLOAD_LEN + VL_SIG_LEN)   /* 100 */
#define VL_BLOB_STR_LEN          160u    /* ceil(100 * 8 / 5) */
#define VL_BLOB_STR_BUF_LEN      (VL_BLOB_STR_LEN + 1u)

#define VL_FINGERPRINT_LEN       32u     /* full SHA-256 of the id segments */
#define VL_DEVICE_ID_LEN         16u     /* first 16 bytes of the above */
#define VL_DEVICE_ID_STR_LEN     26u     /* ceil(16 * 8 / 5) */
#define VL_DEVICE_ID_STR_BUF_LEN (VL_DEVICE_ID_STR_LEN + 1u)

#define VL_PUBKEY_LEN            32u

/* Largest single hardware id segment the HAL may return. */
#define VL_ID_SEGMENT_MAX        255u
/* Most segments vl_compute_fingerprint() will read before stopping. */
#define VL_ID_SEGMENT_COUNT_MAX  64u

/* ========================================================================== */
/* Platform security posture — reported, never silently enforced.              */
/* ========================================================================== */
typedef enum {
    VL_POSTURE_UNKNOWN = 0,
    VL_POSTURE_OFF     = 1,
    VL_POSTURE_ON      = 2
} vl_posture_state_t;

typedef struct {
    vl_posture_state_t secure_boot;
    vl_posture_state_t flash_encryption;
} vl_posture_t;

/* ========================================================================== */
/* THE HAL. One struct of function pointers. Only read_id_segment is required; */
/* the core behaves correctly with every other member NULL.                    */
/*                                                                             */
/* Callbacks must not allocate, must not block indefinitely, and must return a */
/* vl_status_t. Anything other than VL_OK (or the documented sentinel) is      */
/* treated as a hard failure and vl_verify() fails closed.                     */
/* ========================================================================== */
typedef struct vl_hal {
    /* REQUIRED. Enumerate hardware identity segments, idx 0..n-1.
     * Write at most `cap` bytes to `out` and set *out_len.
     * Return VL_ERR_NO_MORE_SEGMENTS to end the list. */
    vl_status_t (*read_id_segment)(void *ctx, uint32_t idx,
                                   uint8_t *out, size_t cap, size_t *out_len);

    /* OPTIONAL. Wall-clock epoch seconds. NULL => validity windows are not
     * enforced and vl_verify reports that it could not check them. */
    vl_status_t (*now_epoch)(void *ctx, uint32_t *out_epoch);

    /* OPTIONAL. Monotonic high-water mark, to blunt clock rollback.
     * Both NULL or both set. */
    vl_status_t (*hwm_load)(void *ctx, uint32_t *out);
    vl_status_t (*hwm_store)(void *ctx, uint32_t value);

    /* OPTIONAL. Persist the activated licence blob. NULL => caller stores it. */
    vl_status_t (*blob_load)(void *ctx, char *out, size_t cap, size_t *out_len);
    vl_status_t (*blob_store)(void *ctx, const char *blob, size_t len);

    /* OPTIONAL. Platform security posture, for reporting only. */
    vl_status_t (*secure_posture)(void *ctx, vl_posture_t *out);

    void *ctx;
} vl_hal_t;

/* ========================================================================== */
/* Vendor public keys. Firmware embeds one or more; key_id in the payload      */
/* selects which. Rotation is: ship the new key alongside the old, sign new    */
/* licences with the new key, drop the old one a release later.                */
/* ========================================================================== */
typedef struct {
    uint8_t key_id;
    uint8_t key[VL_PUBKEY_LEN];
} vl_pubkey_t;

/* Bits for vl_config_t.flags. */
#define VL_FLAG_REQUIRE_CLOCK  0x00000001u  /* no clock => VL_ERR_NO_CLOCK,
                                             * even for a perpetual licence */
#define VL_FLAG_ENFORCE_HWM    0x00000002u  /* refuse when now < stored mark;
                                             * needs now_epoch + both hwm_* */

/* Everything static about this firmware image. Build one const instance and
 * pass its address; it is never written to. */
typedef struct {
    const vl_pubkey_t *keys;
    size_t             key_count;

    uint8_t            family;          /* must match the payload's family */

    /* OPTIONAL deny-list of revoked serials. NULL / 0 disables it. */
    const uint32_t    *revoked_serials;
    size_t             revoked_count;

    uint32_t           flags;
} vl_config_t;

/* ========================================================================== */
/* A verified licence. Only ever populated after every check passed.           */
/* ========================================================================== */

/* Bits for vl_license_t.checked — which optional checks actually ran. A licence
 * can be cryptographically valid and still have had its time window unchecked,
 * because the device had no clock. Look at this before you trust `not_after`. */
#define VL_CHECKED_SIGNATURE  0x00000001u
#define VL_CHECKED_DEVICE     0x00000002u
#define VL_CHECKED_TIME       0x00000004u
#define VL_CHECKED_REVOCATION 0x00000008u
#define VL_CHECKED_HWM        0x00000010u

typedef struct {
    uint8_t  version;
    uint8_t  key_id;
    uint8_t  family;
    uint32_t features;                      /* 32-bit bitmap */
    uint8_t  device_id[VL_DEVICE_ID_LEN];
    uint32_t not_before;                    /* epoch seconds, 0 = unbounded */
    uint32_t not_after;                     /* epoch seconds, 0 = perpetual */
    uint32_t serial;
    uint32_t checked;                       /* VL_CHECKED_* bitmask */
} vl_license_t;

/* ========================================================================== */
/* The API.                                                                    */
/* ========================================================================== */

/*
 * Verify a licence blob.
 *
 *   blob  NUL-terminated Crockford base32, 160 significant characters.
 *         '-', ' ', '\t', '\r' and '\n' may appear anywhere as grouping and
 *         are ignored. Case-insensitive. This is the whole transport
 *         contract: anything that can deliver 160 characters — HTTP, MQTT,
 *         BLE, a QR scan, a file, a technician at a terminal — works with no
 *         helper.
 *   cfg   embedded public keys, expected family, optional deny-list, flags.
 *   hal   platform callbacks. cfg->... is static; this is the live hardware.
 *   out   filled in only on VL_OK. May be NULL if you only want the verdict.
 *
 * Checks run in this order, and stop at the first failure:
 *   1. arguments, blob length and alphabet          (no crypto yet)
 *   2. magic, format version, family, key_id lookup (no crypto yet)
 *   3. Ed25519 signature over the domain-separated message
 *   4. device fingerprint, compared in constant time
 *   5. revocation
 *   6. validity window, then the clock high-water mark
 *
 * Returns VL_OK only when every applicable check passed. Every other return
 * means the licence is not valid on this device right now.
 */
vl_status_t vl_verify(const char *blob,
                      const vl_config_t *cfg,
                      const vl_hal_t *hal,
                      vl_license_t *out);

/*
 * Compute this device's 32-byte fingerprint: SHA-256 over a domain-separation
 * string followed by every hardware id segment the HAL yields, each with a
 * one-byte length prefix so concatenation is unambiguous.
 *
 * The order of segments is part of the on-wire format. Changing a HAL's
 * segment order or content invalidates every licence already issued for those
 * devices.
 *
 * Returns VL_ERR_PLATFORM if the HAL yields no segments at all.
 */
vl_status_t vl_compute_fingerprint(const vl_hal_t *hal,
                                   uint8_t out_fingerprint[VL_FINGERPRINT_LEN]);

/*
 * Encode the first VL_DEVICE_ID_LEN bytes of a fingerprint as a 26-character
 * Crockford base32 string. This is what the customer reads off the screen (or
 * scans from a QR code) and sends you, and what you pass to
 * `vl_mint.py issue --device-id`.
 *
 * out_capacity must be at least VL_DEVICE_ID_STR_BUF_LEN.
 */
vl_status_t vl_encode_device_id(const uint8_t fingerprint[VL_FINGERPRINT_LEN],
                                char *out, size_t out_capacity);

/*
 * Is feature bit `bit` (0..31) set in a verified licence?
 * Returns 0 for NULL, for bit > 31, and for an unset bit. There is no error
 * return: an unreadable licence has no features.
 */
int vl_has_feature(const vl_license_t *lic, unsigned bit);

/*
 * Report the platform's security posture. Fails soft to VL_POSTURE_UNKNOWN
 * for both fields when the HAL does not implement secure_posture, so the
 * caller always gets a populated struct.
 *
 * This is information, not enforcement. Deciding that an unprotected device
 * should not honour a licence is the integrator's call, and a defensible one:
 * without Secure Boot and Flash Encryption an attacker can simply patch the
 * branch that reads vl_verify()'s result.
 */
vl_status_t vl_posture(const vl_hal_t *hal, vl_posture_t *out);

#ifdef __cplusplus
}
#endif

#endif /* VECTILICENSE_H */
