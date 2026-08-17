/* vl_core.c — payload parse, signature check, fingerprint, feature gating.
 *
 * The whole of vl_verify() lives here. It is the only place in the device
 * build that decides whether a licence is good, and it does so with a public
 * key. There is no counterpart that produces one.
 *
 * Part of VectiLicense. Apache-2.0.
 * core/ layer: pure C99, freestanding. <stdint.h> <stddef.h> and vl_libc.h only. */

#include "vectilicense/vectilicense.h"

#include "vl_base32.h"
#include "vl_ed25519.h"
#include "vl_sha256.h"
#include "vl_util.h"

#include "vl_libc.h"

/* Domain separation. The signature covers this prefix as well as the payload,
 * so a VectiLicense signature can never be replayed into some other protocol
 * that happens to use the same vendor key, and vice versa. */
#define VL_SIGN_PREFIX      "vectilicense:v1"
#define VL_SIGN_PREFIX_LEN  15u
#define VL_SIGN_MSG_LEN     (VL_SIGN_PREFIX_LEN + 1u + VL_PAYLOAD_LEN)  /* 52 */

/* Separate domain for the fingerprint, so a bare SHA-256 of a MAC address
 * computed outside this library can never collide with a device id. */
#define VL_FP_DOMAIN        "vectilicense:fingerprint:v1"
#define VL_FP_DOMAIN_LEN    27u

/* Payload field offsets — see the format table in the README. */
#define OFF_MAGIC       0u
#define OFF_VERSION     1u
#define OFF_KEY_ID      2u
#define OFF_FAMILY      3u
#define OFF_FEATURES    4u
#define OFF_DEVICE_ID   8u
#define OFF_NOT_BEFORE  24u
#define OFF_NOT_AFTER   28u
#define OFF_SERIAL      32u

static uint32_t rd_le32(const uint8_t *p)
{
    return ((uint32_t)p[0]) |
           ((uint32_t)p[1] <<  8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

/* -------------------------------------------------------------------------- */
const char *vl_status_str(vl_status_t status)
{
    switch (status) {
    case VL_OK:                   return "ok";
    case VL_ERR_INVALID_ARG:      return "invalid argument";
    case VL_ERR_BUFFER_TOO_SMALL: return "output buffer too small";
    case VL_ERR_BAD_FORMAT:       return "licence blob is malformed";
    case VL_ERR_BAD_MAGIC:        return "not a VectiLicense blob";
    case VL_ERR_BAD_VERSION:      return "licence format is newer than this firmware";
    case VL_ERR_BAD_FAMILY:       return "licence is for a different product";
    case VL_ERR_UNKNOWN_KEY:      return "licence signed by an unknown key";
    case VL_ERR_BAD_SIGNATURE:    return "signature did not verify";
    case VL_ERR_DEVICE_MISMATCH:  return "licence is for a different device";
    case VL_ERR_NOT_YET_VALID:    return "licence is not valid yet";
    case VL_ERR_EXPIRED:          return "licence has expired";
    case VL_ERR_REVOKED:          return "licence has been revoked";
    case VL_ERR_CLOCK_ROLLBACK:   return "clock is behind the recorded high-water mark";
    case VL_ERR_NO_CLOCK:         return "no clock available to check the validity window";
    case VL_ERR_PLATFORM:         return "platform callback failed";
    case VL_ERR_NO_MORE_SEGMENTS: return "no more identity segments";
    case VL_ERR_NOT_FOUND:        return "no licence stored";
    case VL_ERR_INTERNAL:         return "internal error";
    default:                      break;
    }
    return "unknown status";
}

const char *vl_version_str(void)
{
    return "vectilicense/1.0.0";
}

int vl_has_feature(const vl_license_t *lic, unsigned bit)
{
    if (lic == NULL || bit > 31u) {
        return 0;
    }
    return (int)((lic->features >> bit) & 1u);
}

vl_status_t vl_posture(const vl_hal_t *hal, vl_posture_t *out)
{
    if (out == NULL) {
        return VL_ERR_INVALID_ARG;
    }
    out->secure_boot      = VL_POSTURE_UNKNOWN;
    out->flash_encryption = VL_POSTURE_UNKNOWN;

    if (hal == NULL || hal->secure_posture == NULL) {
        return VL_OK;   /* "unknown" is a truthful answer, not a failure */
    }
    if (hal->secure_posture(hal->ctx, out) != VL_OK) {
        out->secure_boot      = VL_POSTURE_UNKNOWN;
        out->flash_encryption = VL_POSTURE_UNKNOWN;
        return VL_ERR_PLATFORM;
    }
    return VL_OK;
}

/* -------------------------------------------------------------------------- */
vl_status_t vl_compute_fingerprint(const vl_hal_t *hal,
                                   uint8_t out_fingerprint[VL_FINGERPRINT_LEN])
{
    vl_sha256_ctx_t ctx;
    uint8_t segment[VL_ID_SEGMENT_MAX];
    uint32_t idx;
    uint32_t accepted = 0;
    vl_status_t rc = VL_OK;

    if (hal == NULL || hal->read_id_segment == NULL || out_fingerprint == NULL) {
        return VL_ERR_INVALID_ARG;
    }

    vl_sha256_init(&ctx);
    vl_sha256_update(&ctx, VL_FP_DOMAIN, VL_FP_DOMAIN_LEN);

    for (idx = 0; idx < VL_ID_SEGMENT_COUNT_MAX; idx++) {
        size_t seg_len = 0;
        uint8_t length_byte;
        vl_status_t st = hal->read_id_segment(hal->ctx, idx,
                                              segment, sizeof segment, &seg_len);
        if (st == VL_ERR_NO_MORE_SEGMENTS) {
            break;
        }
        if (st != VL_OK) {
            rc = st;
            goto done;
        }
        if (seg_len > sizeof segment) {
            /* A HAL that lies about how much it wrote would otherwise hash
             * whatever is past the buffer. Refuse instead. */
            rc = VL_ERR_PLATFORM;
            goto done;
        }

        /* Length-prefix each segment so {"AB","C"} and {"A","BC"} differ. */
        length_byte = (uint8_t)seg_len;
        vl_sha256_update(&ctx, &length_byte, 1u);
        if (seg_len > 0u) {
            vl_sha256_update(&ctx, segment, seg_len);
        }
        accepted++;
    }

    if (accepted == 0u) {
        rc = VL_ERR_PLATFORM;
        goto done;
    }

    vl_sha256_final(&ctx, out_fingerprint);

done:
    vl_secure_wipe(segment, sizeof segment);
    if (rc != VL_OK) {
        vl_secure_wipe(&ctx, sizeof ctx);
        vl_secure_wipe(out_fingerprint, VL_FINGERPRINT_LEN);
    }
    return rc;
}

vl_status_t vl_encode_device_id(const uint8_t fingerprint[VL_FINGERPRINT_LEN],
                                char *out, size_t out_capacity)
{
    int n;

    if (fingerprint == NULL || out == NULL) {
        return VL_ERR_INVALID_ARG;
    }
    if (out_capacity < VL_DEVICE_ID_STR_BUF_LEN) {
        return VL_ERR_BUFFER_TOO_SMALL;
    }
    n = vl_base32_encode(fingerprint, VL_DEVICE_ID_LEN, out, out_capacity);
    if (n != (int)VL_DEVICE_ID_STR_LEN) {
        return VL_ERR_INTERNAL;
    }
    return VL_OK;
}

/* -------------------------------------------------------------------------- */
static const vl_pubkey_t *find_key(const vl_config_t *cfg, uint8_t key_id)
{
    size_t i;
    for (i = 0; i < cfg->key_count; i++) {
        if (cfg->keys[i].key_id == key_id) {
            return &cfg->keys[i];
        }
    }
    return NULL;
}

/* ponytail: linear scan over the deny-list. A compiled-in revocation list is
 * a handful of entries; if yours ever runs to thousands, sort it and switch
 * this to a binary search. Linear is also order-independent, which is one
 * fewer thing an integrator can get wrong. */
static int is_revoked(const vl_config_t *cfg, uint32_t serial)
{
    size_t i;
    if (cfg->revoked_serials == NULL || cfg->revoked_count == 0u) {
        return 0;
    }
    for (i = 0; i < cfg->revoked_count; i++) {
        if (cfg->revoked_serials[i] == serial) {
            return 1;
        }
    }
    return 0;
}

vl_status_t vl_verify(const char *blob,
                      const vl_config_t *cfg,
                      const vl_hal_t *hal,
                      vl_license_t *out)
{
    uint8_t bin[VL_BLOB_BIN_LEN];
    uint8_t msg[VL_SIGN_MSG_LEN];
    uint8_t fingerprint[VL_FINGERPRINT_LEN];
    const vl_pubkey_t *pk;
    vl_license_t lic;
    vl_status_t rc;
    int decoded;

    memset(&lic, 0, sizeof lic);
    if (out != NULL) {
        /* Clear the caller's struct before anything can fail. The `fail:`
         * label does this too, but the argument checks below return directly
         * and would otherwise leave a previous call's licence sitting in a
         * reused vl_license_t — features and all. */
        memset(out, 0, sizeof *out);
    }

    /* --- 1. arguments ---------------------------------------------------- */
    if (blob == NULL || cfg == NULL || hal == NULL) {
        return VL_ERR_INVALID_ARG;
    }
    if (cfg->keys == NULL || cfg->key_count == 0u) {
        return VL_ERR_INVALID_ARG;
    }
    if (hal->read_id_segment == NULL) {
        return VL_ERR_INVALID_ARG;
    }
    if ((cfg->flags & VL_FLAG_ENFORCE_HWM) != 0u &&
        (hal->now_epoch == NULL ||
         hal->hwm_load == NULL || hal->hwm_store == NULL)) {
        /* Asked for rollback protection without supplying the parts it is
         * built from. Silently downgrading to "no protection" is exactly the
         * sort of thing that gets discovered in the field.
         *
         * now_epoch belongs in this check as much as the hwm_* pair does: the
         * mark is only ever compared against, and advanced by, the clock, so
         * without a clock the whole step below is skipped and the flag buys
         * nothing — and because the step also carries the validity window,
         * an expired licence would verify. A high-water mark with no clock is
         * not weaker rollback protection, it is none. */
        return VL_ERR_INVALID_ARG;
    }

    /* --- 2. length, alphabet, then the plain header fields ---------------- */
    /* Strict decode: exactly 160 significant base32 characters, exactly 100
     * bytes out, canonical padding. All of this runs before any crypto. */
    decoded = vl_base32_decode(blob, bin, sizeof bin, VL_BLOB_BIN_LEN);
    if (decoded != (int)VL_BLOB_BIN_LEN) {
        rc = VL_ERR_BAD_FORMAT;
        goto fail;
    }
    if (bin[OFF_MAGIC] != VL_MAGIC) {
        rc = VL_ERR_BAD_MAGIC;
        goto fail;
    }
    if (bin[OFF_VERSION] != VL_FORMAT_VERSION) {
        rc = VL_ERR_BAD_VERSION;
        goto fail;
    }

    lic.version    = bin[OFF_VERSION];
    lic.key_id     = bin[OFF_KEY_ID];
    lic.family     = bin[OFF_FAMILY];
    lic.features   = rd_le32(bin + OFF_FEATURES);
    lic.not_before = rd_le32(bin + OFF_NOT_BEFORE);
    lic.not_after  = rd_le32(bin + OFF_NOT_AFTER);
    lic.serial     = rd_le32(bin + OFF_SERIAL);
    memcpy(lic.device_id, bin + OFF_DEVICE_ID, VL_DEVICE_ID_LEN);

    if (lic.family != cfg->family) {
        rc = VL_ERR_BAD_FAMILY;
        goto fail;
    }
    pk = find_key(cfg, lic.key_id);
    if (pk == NULL) {
        rc = VL_ERR_UNKNOWN_KEY;
        goto fail;
    }

    /* --- 3. signature ----------------------------------------------------- */
    memcpy(msg, VL_SIGN_PREFIX, VL_SIGN_PREFIX_LEN);
    msg[VL_SIGN_PREFIX_LEN] = 0x00u;
    memcpy(msg + VL_SIGN_PREFIX_LEN + 1u, bin, VL_PAYLOAD_LEN);

    if (!vl_ed25519_verify(bin + VL_PAYLOAD_LEN, msg, sizeof msg, pk->key)) {
        rc = VL_ERR_BAD_SIGNATURE;
        goto fail;
    }
    lic.checked |= VL_CHECKED_SIGNATURE;

    /* --- 4. device binding ------------------------------------------------ */
    rc = vl_compute_fingerprint(hal, fingerprint);
    if (rc != VL_OK) {
        goto fail;
    }
    if (!vl_ct_eq(fingerprint, lic.device_id, VL_DEVICE_ID_LEN)) {
        rc = VL_ERR_DEVICE_MISMATCH;
        goto fail;
    }
    lic.checked |= VL_CHECKED_DEVICE;

    /* --- 5. revocation ---------------------------------------------------- */
    if (cfg->revoked_serials != NULL && cfg->revoked_count > 0u) {
        if (is_revoked(cfg, lic.serial)) {
            rc = VL_ERR_REVOKED;
            goto fail;
        }
        lic.checked |= VL_CHECKED_REVOCATION;
    }

    /* --- 6. validity window, then clock rollback -------------------------- */
    if (hal->now_epoch == NULL) {
        /* No clock. Per the HAL contract we do not enforce the window; we
         * report that we could not, by leaving VL_CHECKED_TIME clear. A
         * caller that refuses to accept that should set VL_FLAG_REQUIRE_CLOCK
         * and get VL_ERR_NO_CLOCK instead. */
        if ((cfg->flags & VL_FLAG_REQUIRE_CLOCK) != 0u) {
            rc = VL_ERR_NO_CLOCK;
            goto fail;
        }
    } else {
        uint32_t now = 0;
        if (hal->now_epoch(hal->ctx, &now) != VL_OK) {
            rc = VL_ERR_PLATFORM;
            goto fail;
        }
        if (lic.not_before != 0u && now < lic.not_before) {
            rc = VL_ERR_NOT_YET_VALID;
            goto fail;
        }
        if (lic.not_after != 0u && now > lic.not_after) {
            rc = VL_ERR_EXPIRED;
            goto fail;
        }
        lic.checked |= VL_CHECKED_TIME;

        if ((cfg->flags & VL_FLAG_ENFORCE_HWM) != 0u) {
            uint32_t mark = 0;
            if (hal->hwm_load(hal->ctx, &mark) != VL_OK) {
                rc = VL_ERR_PLATFORM;
                goto fail;
            }
            if (now < mark) {
                rc = VL_ERR_CLOCK_ROLLBACK;
                goto fail;
            }
            if (now > mark && hal->hwm_store(hal->ctx, now) != VL_OK) {
                rc = VL_ERR_PLATFORM;
                goto fail;
            }
            lic.checked |= VL_CHECKED_HWM;
        }
    }

    if (out != NULL) {
        *out = lic;
    }
    rc = VL_OK;

fail:
    vl_secure_wipe(bin, sizeof bin);
    vl_secure_wipe(msg, sizeof msg);
    vl_secure_wipe(fingerprint, sizeof fingerprint);
    if (rc != VL_OK && out != NULL) {
        /* Never hand back a half-populated licence on a failure path. */
        memset(out, 0, sizeof *out);
    }
    vl_secure_wipe(&lic, sizeof lic);
    return rc;
}
