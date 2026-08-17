/*
 * VectiLicense example — POSIX host (Linux, Raspberry Pi, macOS).
 * (c) 2026 VectiVolt — Apache-2.0 License
 *
 * The whole activation loop in one file:
 *
 *   $ vl_activate                 print this machine's device id and the
 *                                 status of whatever licence is stored
 *   $ vl_activate <blob>          verify a blob and, if it is good, store it
 *   $ vl_activate --status        just the verdict, exit code 0 or 1
 *
 * Build, from the repository root (Linux):
 *   cc -std=c99 -Wall -Wextra -Iinclude -Icore -Ihal/posix -o vl_activate \
 *      core/vl_*.c hal/posix/vl_hal_posix.c examples/posix/vl_activate.c
 *
 * Build (macOS): the same, plus -framework IOKit -framework CoreFoundation
 *
 * This is the one example that has actually been run: it compiles and runs on
 * macOS, and the keygen -> issue -> activate -> re-check cycle below was
 * exercised end to end against a locally generated key. It has not been built
 * on Linux or a Raspberry Pi, and it is not a ctest case. See the README's
 * "What has actually been built and run".
 *
 * Then, on the vendor's machine:
 *   python3 tools/vl_mint.py keygen --out vendor.key
 *   # paste the printed C array over VENDOR_KEYS below, rebuild
 *   python3 tools/vl_mint.py issue --key vendor.key --family 1 \
 *           --device-id <the 26 characters this program printed> \
 *           --features 0x0d --serial 1001
 *
 * and back here:
 *   ./vl_activate <the 160 characters that printed>
 */

#include "vectilicense/vectilicense.h"
#include "vl_hal_posix.h"

#include <stdio.h>
#include <string.h>

/* ---------------------------------------------------------------------------
 * Everything static about this firmware image.
 *
 * REPLACE THIS KEY — it is a placeholder, not yours. `vl_mint.py keygen` prints
 * exactly this array, ready to paste.
 *
 * It is a real Ed25519 public key whose private half was generated in memory
 * and discarded, so nobody — including us — can sign for it and every blob you
 * paste is refused with VL_ERR_BAD_SIGNATURE. That is the failure mode you
 * want from an unconfigured build: loud, at the first activation.
 *
 * Do NOT substitute an all-zero key. 32 zero bytes are a valid low-order curve
 * point, and against a low-order key a signature can be forged with no private
 * key at all — every feature bit, any device. core/vl_ed25519.c rejects such
 * keys outright now, so it fails closed rather than open, but the shape of the
 * mistake is worth knowing: a placeholder key must be a real point.
 * ------------------------------------------------------------------------- */
/* VectiLicense vendor public key — safe to publish, safe to ship. */
static const vl_pubkey_t VENDOR_KEYS[] = {
    { .key_id = 1, .key = {   /* PLACEHOLDER — no private key exists for it */
        0x70, 0x7d, 0xec, 0x62, 0x84, 0xba, 0x43, 0x82,
        0x4f, 0x75, 0x22, 0xc2, 0x10, 0xb3, 0x6b, 0x13,
        0x15, 0x2b, 0xfe, 0x56, 0xdb, 0xf7, 0xbc, 0xad,
        0x1d, 0xf0, 0xc9, 0x7a, 0xf6, 0xc8, 0x0d, 0xe9,
    } },
};

/* Serials you have revoked. Compiled in, shipped with the next firmware.
 * Set revoked_count below to the array length to turn the check on. */
static const uint32_t REVOKED[] = { 0 };

#define FEATURE_BASE      0
#define FEATURE_ANALYTICS 1
#define FEATURE_EXPORT    2
#define FEATURE_MULTIUSER 3

static const vl_config_t CFG = {
    .keys = VENDOR_KEYS, .key_count = sizeof VENDOR_KEYS / sizeof VENDOR_KEYS[0],
    .family = 1,                 /* your product family byte */
    .revoked_serials = REVOKED, .revoked_count = 0,
    .flags = 0,                  /* see the note at the bottom of this file */
};

/* --------------------------------------------------------------------------- */
static void print_device_id(const vl_hal_t *hal)
{
    uint8_t fingerprint[VL_FINGERPRINT_LEN];
    char id[VL_DEVICE_ID_STR_BUF_LEN];
    vl_status_t st = vl_compute_fingerprint(hal, fingerprint);

    if (st != VL_OK) {
        printf("device id: unavailable (%s)\n", vl_status_str(st));
        return;
    }
    if (vl_encode_device_id(fingerprint, id, sizeof id) != VL_OK) {
        printf("device id: unavailable\n");
        return;
    }
    printf("device id: %s\n", id);
    printf("           send those 26 characters to your vendor\n");
}

static void print_licence(const vl_license_t *lic)
{
    printf("  serial      %u\n", lic->serial);
    printf("  key id      %u\n", lic->key_id);
    printf("  features    0x%08x  [", lic->features);
    if (vl_has_feature(lic, FEATURE_BASE))      printf(" base");
    if (vl_has_feature(lic, FEATURE_ANALYTICS)) printf(" analytics");
    if (vl_has_feature(lic, FEATURE_EXPORT))    printf(" export");
    if (vl_has_feature(lic, FEATURE_MULTIUSER)) printf(" multiuser");
    printf(" ]\n");
    printf("  not before  %u\n", lic->not_before);
    if (lic->not_after) printf("  not after   %u\n", lic->not_after);
    else                printf("  not after   never (perpetual)\n");

    /* The bit integrators skip and then get surprised by. A licence can be
     * cryptographically perfect and still have had its expiry unchecked,
     * because the device had no clock to check it with. */
    printf("  checked     signature%s device%s time%s revocation%s rollback%s\n",
           (lic->checked & VL_CHECKED_SIGNATURE)  ? "+" : "-",
           (lic->checked & VL_CHECKED_DEVICE)     ? "+" : "-",
           (lic->checked & VL_CHECKED_TIME)       ? "+" : "-",
           (lic->checked & VL_CHECKED_REVOCATION) ? "+" : "-",
           (lic->checked & VL_CHECKED_HWM)        ? "+" : "-");
    if ((lic->checked & VL_CHECKED_TIME) == 0u && lic->not_after != 0u) {
        printf("  NOTE: this licence has an expiry that was NOT enforced.\n");
    }
}

static void print_posture(const vl_hal_t *hal)
{
    static const char *const state[] = { "unknown", "off", "on" };
    vl_posture_t p;

    (void)vl_posture(hal, &p);
    printf("platform: secure boot %s, flash encryption %s\n",
           state[p.secure_boot], state[p.flash_encryption]);
    if (p.secure_boot != VL_POSTURE_ON) {
        /* Say it out loud. Anyone who can rewrite this binary can delete the
         * branch below that reads the verdict, and no amount of Ed25519
         * changes that. */
        printf("          without a verified boot chain a licence check is a\n"
               "          speed bump, not a boundary — see docs/THREAT_MODEL.md\n");
    }
}

/* --------------------------------------------------------------------------- */
int main(int argc, char **argv)
{
    const vl_hal_t *hal = vl_hal_posix(NULL, "./vl-state");
    vl_license_t lic;
    vl_status_t st;
    char stored[VL_BLOB_STR_BUF_LEN];
    size_t stored_len = 0;
    const char *blob = NULL;
    int quiet = (argc > 1 && strcmp(argv[1], "--status") == 0);

    if (hal == NULL) {
        fprintf(stderr, "no POSIX HAL on this target\n");
        return 2;
    }

    if (!quiet) {
        printf("%s\n\n", vl_version_str());
        print_device_id(hal);
        print_posture(hal);
        printf("\n");
    }

    if (argc > 1 && !quiet) {
        blob = argv[1];                       /* activating */
    } else if (hal->blob_load != NULL &&
               hal->blob_load(hal->ctx, stored, sizeof stored, &stored_len) == VL_OK) {
        blob = stored;                        /* re-checking what we stored */
    }

    if (blob == NULL) {
        printf("no licence stored. Run: %s <blob>\n", argv[0]);
        return 1;
    }

    /* This one call is the entire library. It takes a NUL-terminated string,
     * which is why there is nothing transport-specific anywhere above: the
     * 160 characters can arrive by QR scan, HTTP, MQTT, serial console, a
     * file, or a technician's clipboard. */
    st = vl_verify(blob, &CFG, hal, &lic);

    if (st != VL_OK) {
        printf("REFUSED: %s\n", vl_status_str(st));
        return 1;
    }

    printf("LICENSED\n");
    print_licence(&lic);

    /* Only store a blob that just verified. Storing first and verifying at the
     * next boot means a bad paste survives a power cycle. */
    if (blob != stored && hal->blob_store != NULL) {
        if (hal->blob_store(hal->ctx, blob, strlen(blob)) == VL_OK) {
            printf("  stored, this device will not ask again\n");
        } else {
            printf("  WARNING: verified but could not be stored\n");
        }
    }
    return 0;
}

/*
 * TWO FLAGS WORTH A DECISION, deliberately left off above.
 *
 * VL_FLAG_REQUIRE_CLOCK — refuse outright when there is no clock, instead of
 *   accepting an expired licence and reporting the gap through
 *   lic.checked & VL_CHECKED_TIME. On a POSIX host there is always a clock, so
 *   it changes nothing here; on a clockless MCU it is the difference between
 *   "expiry is advisory" and "the device will not run".
 *
 * VL_FLAG_ENFORCE_HWM — remember the highest timestamp ever seen and refuse
 *   anything earlier, so winding the clock back does not resurrect an expired
 *   licence. Needs now_epoch, hwm_load and hwm_store; asking for it without all
 *   three is VL_ERR_INVALID_ARG, not a silent downgrade — a high-water mark
 *   with no clock to compare it against is not weaker protection, it is none.
 *   It can also brick a unit whose RTC battery died, which is why it is opt-in.
 */
