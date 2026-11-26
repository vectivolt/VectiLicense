/* test_vl_hal_esp32.c — the real hal/esp32 source, run on the host.
 *
 * hal/esp32/vl_hal_esp32.c is compiled here as-is against the stand-in IDF
 * headers in tests/esp32_stub/, with fake eFuses and a fake NVS behind them.
 * What that proves, and what it cannot:
 *
 *   - The fingerprint the HAL feeds the core is the one `vl_mint.py device-id
 *     --esp32` computes on the host. The expected ids below are the bench
 *     board's (MAC d0:cf:13:73:b7:38, ESP32-S3, OPTIONAL_UNIQUE_ID
 *     7b9f020ba13575a5299f6e75e66e665a); vl_mint.py's selftest asserts the same
 *     two strings, so the C and the Python cannot drift apart unnoticed.
 *   - The segment rules: MAC, model byte, and the UID only when it is not all
 *     zero; every failed read fails closed.
 *   - The storage edge cases: never written, emptied, NVS not initialised.
 *
 *   It cannot prove that the real IDF returns these bytes in this order. That
 *   rests on the IDF 4.4.7 source (MAC_FACTORY is laid out first octet first,
 *   OPTIONAL_UNIQUE_ID is BLOCK2 bits 0..127, which esp_efuse_read_field_blob
 *   copies byte [0] first, the order `espefuse.py summary` prints) and on the
 *   bench board reporting 19PPVWEP2AD037V5ZMQV3S3XH8.
 *
 * (c) 2026 VectiVolt — Apache-2.0 License */

#define ESP_PLATFORM 1
#include "../hal/esp32/vl_hal_esp32.c"

#include <stdio.h>

static int g_pass = 0, g_fail = 0;
#define CHECK(cond, ...)                                       \
    do {                                                       \
        if (cond) { g_pass++; }                                \
        else {                                                 \
            g_fail++;                                          \
            printf("  FAIL %s:%d: ", __FILE__, __LINE__);      \
            printf(__VA_ARGS__);                               \
            printf("\n");                                      \
        }                                                      \
    } while (0)

/* ---- fake silicon: the bench board --------------------------------------- */
static const uint8_t BENCH_MAC[6] = { 0xd0, 0xcf, 0x13, 0x73, 0xb7, 0x38 };
static const uint8_t BENCH_UID[16] = { 0x7b, 0x9f, 0x02, 0x0b, 0xa1, 0x35, 0x75, 0xa5,
                                       0x29, 0x9f, 0x6e, 0x75, 0xe6, 0x6e, 0x66, 0x5a };
#define BENCH_ID_3SEG "19PPVWEP2AD037V5ZMQV3S3XH8"   /* MAC + model + UID */
#define BENCH_ID_2SEG "V183R9MVD2ER3C294P3TWGSCPR"   /* MAC + model, UID blank */

static uint8_t   g_uid[16];
static esp_err_t g_mac_err, g_uid_err;
static int       g_mac_eui64;        /* write 8 bytes, as an 802.15.4 build does */

esp_err_t esp_efuse_mac_get_default(uint8_t *mac)
{
    if (g_mac_err != ESP_OK) return g_mac_err;
    memcpy(mac, BENCH_MAC, sizeof BENCH_MAC);
    if (g_mac_eui64) { mac[6] = 0xff; mac[7] = 0xfe; }
    return ESP_OK;
}

void esp_chip_info(esp_chip_info_t *out_info)
{
    memset(out_info, 0xa5, sizeof *out_info);   /* nothing but .model may matter */
    out_info->model = CHIP_ESP32S3;
}

static const esp_efuse_desc_t UID_DESC = { 2, 0, 128 };
const esp_efuse_desc_t *ESP_EFUSE_OPTIONAL_UNIQUE_ID[] = { &UID_DESC, NULL };

esp_err_t esp_efuse_read_field_blob(const esp_efuse_desc_t *field[], void *dst,
                                    size_t dst_size_bits)
{
    if (field != ESP_EFUSE_OPTIONAL_UNIQUE_ID || dst_size_bits != 128u) {
        return ESP_ERR_INVALID_ARG;
    }
    if (g_uid_err != ESP_OK) return g_uid_err;
    memcpy(dst, g_uid, sizeof g_uid);
    return ESP_OK;
}

bool esp_secure_boot_enabled(void)      { return false; }
bool esp_flash_encryption_enabled(void) { return true; }

/* ---- fake NVS: one namespace, the two keys the HAL uses ------------------ */
static int       g_ns_exists, g_have_blob, g_have_hwm;
static char      g_blob[VL_BLOB_STR_BUF_LEN];
static uint32_t  g_hwm;
static esp_err_t g_open_err;         /* e.g. ESP_ERR_NVS_NOT_INITIALIZED */

esp_err_t nvs_open(const char *name, nvs_open_mode_t mode, nvs_handle_t *h)
{
    if (strcmp(name, "vectilicense") != 0) return ESP_FAIL;
    if (g_open_err != ESP_OK) return g_open_err;
    if (!g_ns_exists) {
        if (mode == NVS_READONLY) return ESP_ERR_NVS_NOT_FOUND;   /* what IDF does */
        g_ns_exists = 1;
    }
    *h = 1u;
    return ESP_OK;
}
void nvs_close(nvs_handle_t h) { (void)h; }
esp_err_t nvs_commit(nvs_handle_t h) { (void)h; return ESP_OK; }

esp_err_t nvs_get_u32(nvs_handle_t h, const char *key, uint32_t *out)
{
    (void)h; (void)key;
    if (!g_have_hwm) return ESP_ERR_NVS_NOT_FOUND;
    *out = g_hwm;
    return ESP_OK;
}
esp_err_t nvs_set_u32(nvs_handle_t h, const char *key, uint32_t v)
{
    (void)h; (void)key;
    g_hwm = v;
    g_have_hwm = 1;
    return ESP_OK;
}
esp_err_t nvs_get_str(nvs_handle_t h, const char *key, char *out, size_t *len)
{
    size_t need;
    (void)h;
    if (strcmp(key, "blob") != 0 || !g_have_blob) return ESP_ERR_NVS_NOT_FOUND;
    need = strlen(g_blob) + 1u;
    if (*len < need) return ESP_ERR_NVS_INVALID_LENGTH;
    memcpy(out, g_blob, need);
    *len = need;
    return ESP_OK;
}
esp_err_t nvs_set_str(nvs_handle_t h, const char *key, const char *v)
{
    (void)h;
    if (strcmp(key, "blob") != 0 || strlen(v) >= sizeof g_blob) return ESP_FAIL;
    memcpy(g_blob, v, strlen(v) + 1u);
    g_have_blob = 1;
    return ESP_OK;
}

/* -------------------------------------------------------------------------- */
static const char *device_id(const vl_hal_t *hal, vl_status_t *st)
{
    static char id[VL_DEVICE_ID_STR_BUF_LEN];
    uint8_t fp[VL_FINGERPRINT_LEN];
    id[0] = '\0';
    *st = vl_compute_fingerprint(hal, fp);
    if (*st == VL_OK) *st = vl_encode_device_id(fp, id, sizeof id);
    return id;
}

static void test_identity(void)
{
    const vl_hal_t *hal = vl_hal_esp32();
    uint8_t seg[VL_ID_SEGMENT_MAX];
    size_t n = 0;
    vl_status_t st;
    const char *id;

    puts("hal/esp32 identity, bench board");
    CHECK(hal != NULL && hal->read_id_segment != NULL, "ESP_PLATFORM selects the real HAL");

    memcpy(g_uid, BENCH_UID, sizeof g_uid);
    id = device_id(hal, &st);
    CHECK(st == VL_OK && strcmp(id, BENCH_ID_3SEG) == 0,
          "bench board, UID programmed: got %s (%s), want " BENCH_ID_3SEG,
          id, vl_status_str(st));

    CHECK(hal->read_id_segment(NULL, 0, seg, sizeof seg, &n) == VL_OK && n == 6u &&
          memcmp(seg, BENCH_MAC, 6) == 0, "segment 0 is the factory MAC, first octet first");
    CHECK(hal->read_id_segment(NULL, 1, seg, sizeof seg, &n) == VL_OK && n == 1u &&
          seg[0] == 9u, "segment 1 is the chip model byte, ESP32-S3 = 9");
    CHECK(hal->read_id_segment(NULL, 2, seg, sizeof seg, &n) == VL_OK && n == 16u &&
          memcmp(seg, BENCH_UID, 16) == 0, "segment 2 is OPTIONAL_UNIQUE_ID, byte [0] first");
    CHECK(hal->read_id_segment(NULL, 3, seg, sizeof seg, &n) == VL_ERR_NO_MORE_SEGMENTS,
          "three segments, then the end");

    /* A blank UID is not a segment: the id is MAC + model, which is what
     * `vl_mint.py device-id --esp32` gives with --uid omitted. */
    memset(g_uid, 0, sizeof g_uid);
    id = device_id(hal, &st);
    CHECK(st == VL_OK && strcmp(id, BENCH_ID_2SEG) == 0,
          "bench board, UID blank: got %s, want " BENCH_ID_2SEG, id);
    memcpy(g_uid, BENCH_UID, sizeof g_uid);

    /* REGRESSION: the HAL read the MAC into uint8_t[6], and an 802.15.4 build
     * of IDF writes the 8-byte EUI-64 there. The segment stays the MAC-48. */
    g_mac_eui64 = 1;
    id = device_id(hal, &st);
    CHECK(st == VL_OK && strcmp(id, BENCH_ID_3SEG) == 0,
          "an 8-byte EUI-64 write changes nothing: got %s", id);
    g_mac_eui64 = 0;

    /* Every failed read fails closed rather than hashing a default. */
    g_mac_err = ESP_FAIL;
    (void)device_id(hal, &st);
    CHECK(st == VL_ERR_PLATFORM, "MAC read failure -> VL_ERR_PLATFORM, got %s",
          vl_status_str(st));
    g_mac_err = ESP_OK;
    g_uid_err = ESP_FAIL;
    (void)device_id(hal, &st);
    CHECK(st == VL_ERR_PLATFORM, "UID read failure -> VL_ERR_PLATFORM, got %s",
          vl_status_str(st));
    g_uid_err = ESP_OK;

    CHECK(hal->read_id_segment(NULL, 0, seg, 5, &n) == VL_ERR_BUFFER_TOO_SMALL,
          "a short buffer is refused");
}

static void test_storage(void)
{
    const vl_hal_t *hal = vl_hal_esp32();
    char buf[VL_BLOB_STR_BUF_LEN];
    char blob[VL_BLOB_STR_LEN + 2];
    size_t n = 0;
    uint32_t mark = 1u;

    puts("hal/esp32 NVS storage");

    CHECK(hal->blob_load(NULL, buf, sizeof buf, &n) == VL_ERR_NOT_FOUND,
          "namespace never written: no licence stored");
    CHECK(hal->hwm_load(NULL, &mark) == VL_OK && mark == 0u,
          "namespace never written: high-water mark 0");

    memset(blob, 'A', VL_BLOB_STR_LEN);
    blob[VL_BLOB_STR_LEN] = '\0';
    CHECK(hal->blob_store(NULL, blob, VL_BLOB_STR_LEN) == VL_OK, "160 chars store");
    CHECK(hal->blob_load(NULL, buf, sizeof buf, &n) == VL_OK && n == VL_BLOB_STR_LEN &&
          strcmp(buf, blob) == 0, "...and load back, length without the NUL");
    CHECK(hal->blob_load(NULL, buf, VL_BLOB_STR_LEN, &n) == VL_ERR_BUFFER_TOO_SMALL,
          "a buffer without room for the NUL is refused");
    CHECK(hal->blob_store(NULL, blob, VL_BLOB_STR_LEN + 1u) == VL_ERR_BUFFER_TOO_SMALL,
          "161 chars do not fit");

    /* REGRESSION: vecti::License::clear() stores "", and the next boot's
     * blob_load handed that back as VL_OK, so the device reported "licence
     * blob is malformed" instead of "no licence stored". */
    CHECK(hal->blob_store(NULL, "", 0) == VL_OK, "empty store (clear) accepted");
    CHECK(hal->blob_load(NULL, buf, sizeof buf, &n) == VL_ERR_NOT_FOUND,
          "an emptied slot reads as nothing stored");

    /* REGRESSION: every nvs_open failure used to read as "nothing stored" and
     * as a high-water mark of 0. Only a missing namespace means that. */
    g_open_err = ESP_ERR_NVS_NOT_INITIALIZED;
    CHECK(hal->blob_load(NULL, buf, sizeof buf, &n) == VL_ERR_PLATFORM,
          "NVS not initialised: blob_load is a platform error, not 'not found'");
    CHECK(hal->hwm_load(NULL, &mark) == VL_ERR_PLATFORM,
          "NVS not initialised: hwm_load fails closed");
    CHECK(hal->blob_store(NULL, blob, VL_BLOB_STR_LEN) == VL_ERR_PLATFORM,
          "NVS not initialised: blob_store fails");
    g_open_err = ESP_OK;

    CHECK(hal->hwm_store(NULL, 1750000000u) == VL_OK &&
          hal->hwm_load(NULL, &mark) == VL_OK && mark == 1750000000u, "hwm round-trips");
}

static void test_posture(void)
{
    vl_posture_t p;
    puts("hal/esp32 posture");
    CHECK(vl_posture(vl_hal_esp32(), &p) == VL_OK &&
          p.secure_boot == VL_POSTURE_OFF && p.flash_encryption == VL_POSTURE_ON,
          "posture reports what the IDF calls say");
}

int main(void)
{
    test_identity();
    test_storage();
    test_posture();
    printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
