/* A real firmware entry point that actually calls into the library, so the
   linker cannot garbage-collect the thing we are trying to measure. */
#include <stdint.h>
#include <stddef.h>
#include "vectilicense/vectilicense.h"

/* Freestanding: no libc, so provide the three functions core declares. */
void *memcpy(void *d, const void *s, size_t n)
{ unsigned char *a=d; const unsigned char *b=s; while(n--) *a++=*b++; return d; }
void *memset(void *d, int c, size_t n)
{ unsigned char *a=d; while(n--) *a++=(unsigned char)c; return d; }
int memcmp(const void *x, const void *y, size_t n)
{ const unsigned char *a=x,*b=y; while(n--){ if(*a!=*b) return *a-*b; a++; b++; } return 0; }

static vl_status_t seg(void *ctx, uint32_t idx, uint8_t *out, size_t cap, size_t *len)
{ (void)ctx; if (idx) return VL_ERR_NO_MORE_SEGMENTS;
  if (cap < 4) return VL_ERR_BUFFER_TOO_SMALL;
  out[0]=0xDE; out[1]=0xAD; out[2]=0xBE; out[3]=0xEF; *len=4; return VL_OK; }

volatile int g_result;
volatile char g_devid[40];

static const vl_pubkey_t KEYS[1] = { { 0, {
  0xd7,0x5a,0x98,0x01,0x82,0xb1,0x0a,0xb7, 0xd5,0x4b,0xfe,0xd3,0xc9,0x64,0x07,0x3a,
  0x0e,0xe1,0x72,0xf3,0xda,0xa6,0x23,0x25, 0xaf,0x02,0x1a,0x68,0xf7,0x07,0x51,0x1a } } };

static const vl_config_t CFG = { KEYS, 1, 7, NULL, 0, 0 };

void reset_handler(void)
{
    vl_hal_t hal = { 0 };
    hal.read_id_segment = seg;

    uint8_t id[VL_FINGERPRINT_LEN];
    g_result = (int)vl_compute_fingerprint(&hal, id);
    (void)vl_encode_device_id(id, (char *)g_devid, sizeof g_devid);

    /* Drag the whole verify path in: Ed25519, SHA-512, base32, payload parse. */
    vl_license_t lic;
    g_result += (int)vl_verify("00000000-00000000-00000000", &CFG, &hal, &lic);
    for (;;) { }
}

__attribute__((section(".vectors"), used))
void (* const vectors[])(void) = { (void (*)(void))0x20020000, reset_handler };
