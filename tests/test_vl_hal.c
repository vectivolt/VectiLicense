/*
 * Host smoke test for hal/posix and hal/none. Not a unit test of the core —
 * it exercises the two things only a real machine can check: that the POSIX
 * HAL yields a stable, non-constant fingerprint with storage that round-trips,
 * and that the unported stub fails closed instead of handing out a fingerprint
 * every device would share.
 * (c) 2026 VectiVolt — Apache-2.0 License
 *
 *   cc -std=c99 -Wall -Wextra -Werror -DVL_HAL_NONE_ACKNOWLEDGED \
 *      -Iinclude -Ihal/posix -Ihal/none \
 *      core/vl_*.c hal/posix/vl_hal_posix.c hal/none/vl_hal_none.c \
 *      tests/test_vl_hal.c -o /tmp/t \
 *      [-framework IOKit -framework CoreFoundation]   # macOS only
 */

#include <stdio.h>
#include <string.h>

#include "vectilicense/vectilicense.h"
#include "vl_hal_none.h"
#include "vl_hal_posix.h"

#define CHECK(cond) do {                                                      \
        if (!(cond)) {                                                        \
            printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond);            \
            return 1;                                                         \
        }                                                                     \
    } while (0)

int main(void)
{
    const vl_hal_t *hal = vl_hal_posix(NULL, "/tmp/vl_hal_posix_test");
    uint8_t fp1[VL_FINGERPRINT_LEN], fp2[VL_FINGERPRINT_LEN];
    uint8_t zero[VL_FINGERPRINT_LEN];
    char id[VL_DEVICE_ID_STR_BUF_LEN];
    char blob[VL_BLOB_STR_BUF_LEN];
    size_t blob_len = 0;
    uint32_t mark = 0;
    vl_posture_t posture;

    CHECK(hal != NULL);
    CHECK(hal->read_id_segment != NULL);

    /* Fingerprint is computable, stable, and not the hash of nothing. */
    CHECK(vl_compute_fingerprint(hal, fp1) == VL_OK);
    CHECK(vl_compute_fingerprint(hal, fp2) == VL_OK);
    CHECK(memcmp(fp1, fp2, sizeof fp1) == 0);
    memset(zero, 0, sizeof zero);
    CHECK(memcmp(fp1, zero, sizeof fp1) != 0);

    CHECK(vl_encode_device_id(fp1, id, sizeof id) == VL_OK);
    CHECK(strlen(id) == VL_DEVICE_ID_STR_LEN);

    /* The segment list must terminate with the sentinel, not with a hard
     * error, or vl_compute_fingerprint would fail closed on every device. */
    {
        uint8_t seg[VL_ID_SEGMENT_MAX];
        size_t seg_len = 0;
        CHECK(hal->read_id_segment(hal->ctx, 0, seg, sizeof seg, &seg_len) == VL_OK);
        CHECK(seg_len > 0u);
        CHECK(hal->read_id_segment(hal->ctx, 99, seg, sizeof seg, &seg_len)
              == VL_ERR_NO_MORE_SEGMENTS);
    }

    /* Storage round-trips, and reports "absent" rather than a stale value. */
    CHECK(hal->hwm_load(hal->ctx, &mark) == VL_OK);
    CHECK(hal->hwm_store(hal->ctx, 1750000000u) == VL_OK);
    CHECK(hal->hwm_load(hal->ctx, &mark) == VL_OK);
    CHECK(mark == 1750000000u);

    CHECK(hal->blob_store(hal->ctx, "ABCDEFGH", 8) == VL_OK);
    CHECK(hal->blob_load(hal->ctx, blob, sizeof blob, &blob_len) == VL_OK);
    CHECK(blob_len == 8u);
    CHECK(strcmp(blob, "ABCDEFGH") == 0);

    /* Oversized blobs are refused, not truncated. */
    CHECK(hal->blob_store(hal->ctx, blob, VL_BLOB_STR_LEN + 1u)
          == VL_ERR_BUFFER_TOO_SMALL);

    /* No secure_posture callback => UNKNOWN, and still VL_OK. */
    CHECK(vl_posture(hal, &posture) == VL_OK);
    CHECK(posture.secure_boot == VL_POSTURE_UNKNOWN);

    /* hal/none must fail closed, not produce a shared constant fingerprint. */
    {
        const vl_hal_t *stub = vl_hal_none();
        CHECK(stub != NULL);
        CHECK(stub->read_id_segment != NULL);
        CHECK(vl_compute_fingerprint(stub, fp2) == VL_ERR_PLATFORM);
        CHECK(memcmp(fp2, zero, sizeof fp2) == 0);   /* nothing leaked out */
    }

    printf("PASS  device id %s\n", id);
    return 0;
}
