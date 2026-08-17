/*
 * VectiLicense HAL — POSIX (Linux + macOS). See vl_hal_posix.h.
 * (c) 2026 VectiVolt — Apache-2.0 License
 */

#include "vl_hal_posix.h"

#if defined(__linux__) || defined(__APPLE__)

#include <stdio.h>
#include <string.h>
#include <time.h>

#define VL_POSIX_PATH_MAX   192
#define VL_POSIX_DEFAULT_STATE "/var/lib/vectilicense/state"

typedef struct {
    char iface[64];
    char state[VL_POSIX_PATH_MAX];
} vl_posix_ctx_t;

static vl_posix_ctx_t g_ctx;

/* -------------------------------------------------------------------------- */
/* Small file helpers                                                          */
/* -------------------------------------------------------------------------- */

/* Reads at most `cap` bytes and trims trailing whitespace. Returns 0 on
 * success, -1 if the file could not be opened. */
static int read_text_file(const char *path, char *out, size_t cap, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    size_t n;
    if (f == NULL) return -1;
    n = fread(out, 1, cap, f);
    fclose(f);
    while (n > 0 && (out[n - 1] == '\n' || out[n - 1] == '\r' ||
                     out[n - 1] == ' '  || out[n - 1] == '\t')) {
        n--;
    }
    *out_len = n;
    return 0;
}

/* "<state>.hwm" / "<state>.blob" without needing a formatted-print buffer
 * dance at every call site. */
static int state_path(const char *suffix, char *out, size_t cap)
{
    size_t base = strlen(g_ctx.state);
    size_t suf  = strlen(suffix);
    if (base == 0u || base + suf + 1u > cap) return -1;
    memcpy(out, g_ctx.state, base);
    memcpy(out + base, suffix, suf + 1u);
    return 0;
}

/* -------------------------------------------------------------------------- */
/* Identity — Linux                                                            */
/* -------------------------------------------------------------------------- */
#if defined(__linux__)

#include <dirent.h>

static int mac_is_meaningful(const char *s, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) {
        if (s[i] != '0' && s[i] != ':') return 1;
    }
    return 0;
}

static int read_iface_mac(const char *iface, char *out, size_t cap, size_t *out_len)
{
    char path[256];
    int n = snprintf(path, sizeof path, "/sys/class/net/%s/address", iface);
    if (n <= 0 || (size_t)n >= sizeof path) return -1;
    return read_text_file(path, out, cap, out_len);
}

/* Prefer a wired interface, then any en*, then wireless, then whatever is
 * left. Virtual and container interfaces are skipped outright: they come and
 * go, and a fingerprint that changes when Docker starts is worthless. */
static int pick_iface(char *out, size_t cap)
{
    DIR *d = opendir("/sys/class/net");
    struct dirent *de;
    char best[64];
    int best_score = -1;

    if (d == NULL) return -1;
    best[0] = '\0';

    while ((de = readdir(d)) != NULL) {
        char mac[32];
        size_t mac_len = 0;
        int score;
        const char *n = de->d_name;

        if (n[0] == '.') continue;
        if (strcmp(n, "lo") == 0) continue;
        if (strncmp(n, "docker", 6) == 0) continue;
        if (strncmp(n, "br-",    3) == 0) continue;
        if (strncmp(n, "veth",   4) == 0) continue;
        if (strncmp(n, "virbr",  5) == 0) continue;

        if (read_iface_mac(n, mac, sizeof mac, &mac_len) != 0) continue;
        if (mac_len < 17u) continue;                    /* "xx:xx:..." */
        if (!mac_is_meaningful(mac, mac_len)) continue;

        if      (strncmp(n, "eth",  3) == 0) score = 100;
        else if (strncmp(n, "en",   2) == 0) score = 90;
        else if (strncmp(n, "wlan", 4) == 0) score = 50;
        else if (strncmp(n, "wlp",  3) == 0) score = 50;
        else                                 score = 1;

        if (score > best_score) {
            best_score = score;
            strncpy(best, n, sizeof best - 1u);
            best[sizeof best - 1u] = '\0';
        }
    }
    closedir(d);

    if (best_score < 0) return -1;
    if (strlen(best) >= cap) return -1;
    strcpy(out, best);
    return 0;
}

static int read_machine_id(char *out, size_t cap, size_t *out_len)
{
    if (read_text_file("/etc/machine-id", out, cap, out_len) == 0 && *out_len > 0u) {
        return 0;
    }
    if (read_text_file("/var/lib/dbus/machine-id", out, cap, out_len) == 0 &&
        *out_len > 0u) {
        return 0;
    }
    return -1;
}

/* Pi serial from /proc/cpuinfo, else the DMI product UUID, else nothing.
 * Always succeeds: an empty segment is legal and hashes as a single 0x00. */
static void read_board_serial(char *out, size_t cap, size_t *out_len)
{
    FILE *f;
    char line[256];

    *out_len = 0;
    f = fopen("/proc/cpuinfo", "rb");
    if (f != NULL) {
        while (fgets(line, sizeof line, f) != NULL) {
            char *colon;
            size_t i = 0;
            if (strncmp(line, "Serial", 6) != 0) continue;
            colon = strchr(line, ':');
            if (colon == NULL) continue;
            colon++;
            while (*colon == ' ' || *colon == '\t') colon++;
            while (colon[i] != '\0' && colon[i] != '\n' && colon[i] != '\r' &&
                   i < cap) {
                out[i] = colon[i];
                i++;
            }
            *out_len = i;
            break;
        }
        fclose(f);
    }
    if (*out_len == 0u) {
        /* Root-only on most distributions; absence is not an error. */
        (void)read_text_file("/sys/class/dmi/id/product_uuid", out, cap, out_len);
    }
}

static vl_status_t read_id_segment(void *ctx, uint32_t idx,
                                   uint8_t *out, size_t cap, size_t *out_len)
{
    vl_posix_ctx_t *c = (vl_posix_ctx_t *)ctx;
    char buf[256];
    size_t len = 0;

    if (c == NULL || out == NULL || out_len == NULL) return VL_ERR_INVALID_ARG;

    switch (idx) {
    case 0:
        if (c->iface[0] == '\0' && pick_iface(c->iface, sizeof c->iface) != 0) {
            return VL_ERR_PLATFORM;
        }
        if (read_iface_mac(c->iface, buf, sizeof buf, &len) != 0) return VL_ERR_PLATFORM;
        if (len == 0u) return VL_ERR_PLATFORM;
        break;
    case 1:
        if (read_machine_id(buf, sizeof buf, &len) != 0) return VL_ERR_PLATFORM;
        break;
    case 2:
        read_board_serial(buf, sizeof buf, &len);
        break;
    default:
        return VL_ERR_NO_MORE_SEGMENTS;
    }

    if (len > cap) return VL_ERR_BUFFER_TOO_SMALL;
    if (len > 0u) memcpy(out, buf, len);
    *out_len = len;
    return VL_OK;
}

/* -------------------------------------------------------------------------- */
/* Identity — macOS                                                            */
/* -------------------------------------------------------------------------- */
#else  /* __APPLE__ */

#include <ifaddrs.h>
#include <net/if_dl.h>
#include <sys/socket.h>
#include <sys/types.h>

#if !defined(VL_HAL_POSIX_NO_IOKIT)
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#endif

static int read_iface_mac(const char *iface, char *out, size_t cap, size_t *out_len)
{
    struct ifaddrs *ifap = NULL;
    struct ifaddrs *p;
    int rc = -1;

    if (cap < 18u) return -1;
    if (getifaddrs(&ifap) != 0) return -1;

    for (p = ifap; p != NULL; p = p->ifa_next) {
        struct sockaddr_dl *sdl;
        const uint8_t *m;
        int n;

        if (p->ifa_addr == NULL) continue;
        if (p->ifa_addr->sa_family != AF_LINK) continue;
        if (iface != NULL) {
            if (strcmp(p->ifa_name, iface) != 0) continue;
        } else if (strncmp(p->ifa_name, "en", 2) != 0) {
            continue;                    /* skips lo/awdl/llw/utun/bridge */
        }

        sdl = (struct sockaddr_dl *)(void *)p->ifa_addr;
        if (sdl->sdl_alen != 6) continue;
        m = (const uint8_t *)LLADDR(sdl);
        if ((m[0] | m[1] | m[2] | m[3] | m[4] | m[5]) == 0u) continue;

        n = snprintf(out, cap, "%02x:%02x:%02x:%02x:%02x:%02x",
                     m[0], m[1], m[2], m[3], m[4], m[5]);
        if (n != 17) continue;
        *out_len = (size_t)n;
        rc = 0;
        break;
    }
    freeifaddrs(ifap);
    return rc;
}

#if !defined(VL_HAL_POSIX_NO_IOKIT)
static int read_platform_uuid(char *out, size_t cap, size_t *out_len)
{
    /* MACH_PORT_NULL is the default main port and, unlike
     * kIOMasterPortDefault, is not deprecated. */
    io_service_t svc = IOServiceGetMatchingService(
        MACH_PORT_NULL, IOServiceMatching("IOPlatformExpertDevice"));
    CFTypeRef prop;
    int rc = -1;

    if (svc == 0) return -1;
    prop = IORegistryEntryCreateCFProperty(svc, CFSTR(kIOPlatformUUIDKey),
                                           kCFAllocatorDefault, 0);
    IOObjectRelease(svc);
    if (prop == NULL) return -1;

    if (CFGetTypeID(prop) == CFStringGetTypeID() &&
        CFStringGetCString((CFStringRef)prop, out, (CFIndex)cap,
                           kCFStringEncodingUTF8)) {
        *out_len = strlen(out);
        rc = (*out_len > 0u) ? 0 : -1;
    }
    CFRelease(prop);
    return rc;
}
#endif

static vl_status_t read_id_segment(void *ctx, uint32_t idx,
                                   uint8_t *out, size_t cap, size_t *out_len)
{
    vl_posix_ctx_t *c = (vl_posix_ctx_t *)ctx;
    char buf[256];
    size_t len = 0;

    if (c == NULL || out == NULL || out_len == NULL) return VL_ERR_INVALID_ARG;

    switch (idx) {
    case 0:
        if (read_iface_mac(c->iface[0] != '\0' ? c->iface : NULL,
                           buf, sizeof buf, &len) != 0) {
            return VL_ERR_PLATFORM;
        }
        break;
#if !defined(VL_HAL_POSIX_NO_IOKIT)
    case 1:
        if (read_platform_uuid(buf, sizeof buf, &len) != 0) return VL_ERR_PLATFORM;
        break;
#endif
    default:
        return VL_ERR_NO_MORE_SEGMENTS;
    }

    if (len > cap) return VL_ERR_BUFFER_TOO_SMALL;
    if (len > 0u) memcpy(out, buf, len);
    *out_len = len;
    return VL_OK;
}

#endif /* identity */

/* -------------------------------------------------------------------------- */
/* Clock and storage — shared                                                  */
/* -------------------------------------------------------------------------- */
static vl_status_t now_epoch(void *ctx, uint32_t *out_epoch)
{
    time_t t;
    (void)ctx;
    if (out_epoch == NULL) return VL_ERR_INVALID_ARG;
    t = time(NULL);
    if (t < 0 || (unsigned long long)t > 0xFFFFFFFFull) return VL_ERR_NO_CLOCK;
    *out_epoch = (uint32_t)t;
    return VL_OK;
}

static vl_status_t hwm_load(void *ctx, uint32_t *out)
{
    char path[VL_POSIX_PATH_MAX + 8];
    unsigned char raw[4];
    size_t len = 0;
    (void)ctx;

    if (out == NULL) return VL_ERR_INVALID_ARG;
    *out = 0u;
    if (state_path(".hwm", path, sizeof path) != 0) return VL_ERR_PLATFORM;
    if (read_text_file(path, (char *)raw, sizeof raw, &len) != 0) {
        return VL_OK;               /* never written: no mark, not a failure */
    }
    if (len != 4u) return VL_ERR_PLATFORM;
    *out = (uint32_t)raw[0] | ((uint32_t)raw[1] << 8) |
           ((uint32_t)raw[2] << 16) | ((uint32_t)raw[3] << 24);
    return VL_OK;
}

static vl_status_t hwm_store(void *ctx, uint32_t value)
{
    char path[VL_POSIX_PATH_MAX + 8];
    unsigned char raw[4];
    FILE *f;
    size_t n;
    (void)ctx;

    if (state_path(".hwm", path, sizeof path) != 0) return VL_ERR_PLATFORM;
    raw[0] = (unsigned char)(value & 0xFFu);
    raw[1] = (unsigned char)((value >> 8) & 0xFFu);
    raw[2] = (unsigned char)((value >> 16) & 0xFFu);
    raw[3] = (unsigned char)((value >> 24) & 0xFFu);

    f = fopen(path, "wb");
    if (f == NULL) return VL_ERR_PLATFORM;
    n = fwrite(raw, 1, sizeof raw, f);
    if (fclose(f) != 0 || n != sizeof raw) return VL_ERR_PLATFORM;
    return VL_OK;
}

static vl_status_t blob_load(void *ctx, char *out, size_t cap, size_t *out_len)
{
    char path[VL_POSIX_PATH_MAX + 8];
    size_t len = 0;
    (void)ctx;

    if (out == NULL || out_len == NULL || cap < 2u) return VL_ERR_INVALID_ARG;
    if (state_path(".blob", path, sizeof path) != 0) return VL_ERR_PLATFORM;
    if (read_text_file(path, out, cap - 1u, &len) != 0) return VL_ERR_NOT_FOUND;
    if (len == 0u) return VL_ERR_NOT_FOUND;
    out[len] = '\0';
    *out_len = len;
    return VL_OK;
}

static vl_status_t blob_store(void *ctx, const char *blob, size_t len)
{
    char path[VL_POSIX_PATH_MAX + 8];
    FILE *f;
    size_t n;
    (void)ctx;

    if (blob == NULL) return VL_ERR_INVALID_ARG;
    if (len > VL_BLOB_STR_LEN) return VL_ERR_BUFFER_TOO_SMALL;
    if (state_path(".blob", path, sizeof path) != 0) return VL_ERR_PLATFORM;

    f = fopen(path, "wb");
    if (f == NULL) return VL_ERR_PLATFORM;
    n = fwrite(blob, 1, len, f);
    if (fclose(f) != 0 || n != len) return VL_ERR_PLATFORM;
    return VL_OK;
}

static const vl_hal_t g_hal_template = {
    read_id_segment,
    now_epoch,
    hwm_load, hwm_store,
    blob_load, blob_store,
    NULL,                 /* secure_posture: nothing honest to report here */
    &g_ctx
};

static vl_hal_t g_hal;

const vl_hal_t *vl_hal_posix(const char *iface, const char *state_path_base)
{
    memset(&g_ctx, 0, sizeof g_ctx);

    if (iface != NULL && *iface != '\0') {
        if (strlen(iface) >= sizeof g_ctx.iface) return NULL;
        strcpy(g_ctx.iface, iface);
    }
    if (state_path_base == NULL || *state_path_base == '\0') {
        state_path_base = VL_POSIX_DEFAULT_STATE;
    }
    if (strlen(state_path_base) >= sizeof g_ctx.state) return NULL;
    strcpy(g_ctx.state, state_path_base);

    g_hal = g_hal_template;
    return &g_hal;
}

#else  /* not POSIX */

const vl_hal_t *vl_hal_posix(const char *iface, const char *state_path_base)
{
    (void)iface; (void)state_path_base;
    return NULL;
}

#endif
