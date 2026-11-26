/* esp_idf_stub.h — just enough of the ESP-IDF 4.4 API for hal/esp32 to compile
 * on the host, so tests/test_vl_hal_esp32.c can run the real HAL source against
 * fake silicon and a fake NVS. Every name and value below is copied from the
 * Arduino-ESP32 2.0.17 (IDF 4.4.7) headers; nothing here is linked into a
 * firmware build. The other headers in this directory only include this one.
 *
 * (c) 2026 VectiVolt — Apache-2.0 License */

#ifndef VL_ESP_IDF_STUB_H
#define VL_ESP_IDF_STUB_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define CONFIG_IDF_TARGET_ESP32S3 1

typedef int esp_err_t;
#define ESP_OK                         0
#define ESP_FAIL                       (-1)
#define ESP_ERR_INVALID_ARG            0x102
#define ESP_ERR_NVS_NOT_INITIALIZED    0x1101
#define ESP_ERR_NVS_NOT_FOUND          0x1102
#define ESP_ERR_NVS_INVALID_LENGTH     0x110c

/* esp_mac.h */
esp_err_t esp_efuse_mac_get_default(uint8_t *mac);

/* esp_chip_info.h */
typedef enum {
    CHIP_ESP32   = 1,
    CHIP_ESP32S2 = 2,
    CHIP_ESP32S3 = 9,
    CHIP_ESP32C3 = 5,
    CHIP_ESP32H2 = 6
} esp_chip_model_t;
typedef struct {
    esp_chip_model_t model;
    uint32_t features;
    uint16_t full_revision;
    uint8_t  cores;
    uint8_t  revision;
} esp_chip_info_t;
void esp_chip_info(esp_chip_info_t *out_info);

/* esp_efuse.h, esp_efuse_table.h */
typedef struct {
    int      efuse_block;
    uint8_t  bit_start;
    uint16_t bit_count;
} esp_efuse_desc_t;
esp_err_t esp_efuse_read_field_blob(const esp_efuse_desc_t *field[], void *dst,
                                    size_t dst_size_bits);
extern const esp_efuse_desc_t *ESP_EFUSE_OPTIONAL_UNIQUE_ID[];

/* nvs.h */
typedef uint32_t nvs_handle_t;
typedef enum { NVS_READONLY, NVS_READWRITE } nvs_open_mode_t;
esp_err_t nvs_open(const char *name, nvs_open_mode_t open_mode, nvs_handle_t *out_handle);
void      nvs_close(nvs_handle_t handle);
esp_err_t nvs_get_u32(nvs_handle_t handle, const char *key, uint32_t *out_value);
esp_err_t nvs_set_u32(nvs_handle_t handle, const char *key, uint32_t value);
esp_err_t nvs_get_str(nvs_handle_t handle, const char *key, char *out_value, size_t *length);
esp_err_t nvs_set_str(nvs_handle_t handle, const char *key, const char *value);
esp_err_t nvs_commit(nvs_handle_t handle);

/* esp_secure_boot.h, esp_flash_encrypt.h */
bool esp_secure_boot_enabled(void);
bool esp_flash_encryption_enabled(void);

#endif /* VL_ESP_IDF_STUB_H */
