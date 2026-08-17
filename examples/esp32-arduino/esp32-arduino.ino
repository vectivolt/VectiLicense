/*
 * VectiLicense example — ESP32, Arduino framework.
 * (c) 2026 VectiVolt — Apache-2.0 License
 *
 * A sealed box with no internet and no app, activated from a phone:
 *
 *   1. It boots, re-verifies whatever is in NVS, and prints its 26-character
 *      device id over USB serial.
 *   2. The operator joins the device's own SoftAP; VectiNet's captive portal
 *      shows the same device id with a copy button and a box to paste the
 *      licence into. (If VectiDash is installed, the dashboard additionally
 *      shows the device id as a QR code.)
 *   3. They send you the device id. You run vl_mint.py issue. They paste the
 *      160 characters back.
 *   4. license.pump() verifies it on the loop task and stores it in NVS.
 *
 * Nothing here needs an internet connection at any point, and the sibling
 * libraries are all optional — every #include below compiles to nothing if
 * the matching library is not installed, so this sketch builds with none of
 * them and activation still works over the serial console.
 *
 * NEVER COMPILED, NEVER FLASHED. This file is written to the ESP32 Arduino API
 * and has not been built once in this repository, which has no ESP32 toolchain
 * — nor has hal/esp32, nor have the four bridges it includes below. The core,
 * transport, vecti::License and the POSIX example are the parts that are built
 * and run here; this sketch is not. See the README's "What has actually been
 * built and run".
 *
 * platformio.ini:
 *
 *   [env:esp32-s3]
 *   platform  = espressif32
 *   board     = esp32-s3-devkitc-1
 *   framework = arduino
 *   lib_deps  = https://github.com/vectivolt/VectiLicense
 *   build_flags = -DVL_FAMILY=2
 */

#include <Arduino.h>
#include <nvs_flash.h>

#include "vectilicense/vectilicense.h"
#include "vl_hal_esp32.h"

#include "vl_bridge.h"           // vecti::License — always available
#include "vl_bridge_net.h"       // captive-portal activation, if VectiNet is here
#include "vl_bridge_dash.h"      // status card + QR, if VectiDash is here
#include "vl_bridge_serial.h"    // `license` console command, if VectiSerial is
#include "vl_bridge_ota.h"       // refuse updates unlicensed, if VectiOTA is

/* ---------------------------------------------------------------------------
 * Your vendor public key. `python3 tools/vl_mint.py keygen` prints exactly
 * this block. It is a PUBLIC key: publishing it costs you nothing, and there
 * is no counterpart in this firmware that could sign anything with it.
 *
 * REPLACE IT — the key below is a placeholder. It is a real Ed25519 public key
 * whose private half was generated in memory and discarded, so nobody can sign
 * for it and every paste is refused with VL_ERR_BAD_SIGNATURE until you put
 * your own key here. Never an all-zero key: 32 zero bytes are a low-order curve
 * point, and licences against one can be forged with no private key at all.
 * ------------------------------------------------------------------------- */
static const vl_pubkey_t VENDOR_KEYS[] = {
    { .key_id = 1, .key = {   /* PLACEHOLDER — no private key exists for it */
        0x70, 0x7d, 0xec, 0x62, 0x84, 0xba, 0x43, 0x82,
        0x4f, 0x75, 0x22, 0xc2, 0x10, 0xb3, 0x6b, 0x13,
        0x15, 0x2b, 0xfe, 0x56, 0xdb, 0xf7, 0xbc, 0xad,
        0x1d, 0xf0, 0xc9, 0x7a, 0xf6, 0xc8, 0x0d, 0xe9,
    } },
};

/* Licences you have burned. Ships with the next firmware image; there is no
 * online revocation and deliberately so — the device never phones home. */
static const uint32_t REVOKED_SERIALS[] = { 0 };

static const vl_config_t CFG = {
    .keys = VENDOR_KEYS, .key_count = 1,
    .family = 2,                                  /* this product line */
    .revoked_serials = REVOKED_SERIALS, .revoked_count = 0,
    .flags = 0,
};

enum {
    FEATURE_BASE      = 0,
    FEATURE_LOGGING   = 1,
    FEATURE_MODBUS    = 2,
    FEATURE_OTA       = 3
};

static const vl_hal_t *hal = nullptr;
static vecti::License *license = nullptr;

#ifdef VL_HAVE_VECTINET
static vecti::NetLicensePortal *portal = nullptr;
#endif
#ifdef VL_HAVE_VECTIDASH
static vecti::DashLicenseCard *card = nullptr;
#endif

/* --------------------------------------------------------------------------- */
static void reportPosture()
{
    vl_posture_t p = license->posture();

    Serial.printf("secure boot: %s, flash encryption: %s\n",
                  p.secure_boot == VL_POSTURE_ON ? "on" :
                  p.secure_boot == VL_POSTURE_OFF ? "OFF" : "unknown",
                  p.flash_encryption == VL_POSTURE_ON ? "on" :
                  p.flash_encryption == VL_POSTURE_OFF ? "OFF" : "unknown");

    if (p.secure_boot != VL_POSTURE_ON || p.flash_encryption != VL_POSTURE_ON) {
        /* Print it, do not enforce it. Refusing to run on an unprotected
         * device is a defensible policy, but it is your policy, not this
         * library's — and it is the sort of thing that bricks a customer's
         * unit at 2am. See docs/THREAT_MODEL.md. */
        Serial.println("WARNING: without Secure Boot v2 + Flash Encryption, "
                       "anyone who can reflash this board can delete the "
                       "licence check entirely. That is true of every software "
                       "licensing scheme, not just this one.");
    }
}

static void onActivation(void *, vl_status_t st)
{
    if (st == VL_OK) {
        Serial.println("licence accepted and stored");
    } else {
        Serial.printf("licence refused: %s\n", vl_status_str(st));
    }
}

/* --------------------------------------------------------------------------- */
void setup()
{
    Serial.begin(115200);
    delay(200);

    /* The HAL's NVS callbacks need an initialised partition, and it will not
     * do this for you: deciding what to do about a full or corrupt NVS is an
     * application decision, not a library one. */
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        nvs_flash_init();
    }

    hal = vl_hal_esp32();
    static vecti::License lic(&CFG, hal);
    license = &lic;
    license->onResult(onActivation, nullptr);

    /* Re-verify what is in NVS. A licence is checked on every boot, not
     * trusted because it was checked once at the factory. */
    vl_status_t st = license->begin();

    Serial.printf("\n%s\n", vl_version_str());
    Serial.printf("device id: %s\n", license->deviceId());
    Serial.printf("licence:   %s\n", vl_status_str(st));
    reportPosture();

    if (license->ok()) {
        const vl_license_t *l = license->license();
        Serial.printf("serial %u, features 0x%08x, checked 0x%02x\n",
                      l->serial, l->features, l->checked);
        if (l->not_after != 0u && (l->checked & VL_CHECKED_TIME) == 0u) {
            /* The clock had not been set when we checked. The licence has an
             * expiry that nobody enforced. Say so rather than pretending. */
            Serial.println("NOTE: expiry not enforced — no valid clock yet.");
        }
    } else {
        Serial.println("Send the device id above to your supplier, then paste "
                       "the 160-character licence into the setup portal, the "
                       "dashboard, or type: license <blob>");
    }

#ifdef VL_HAVE_VECTINET
    static vecti::NetLicensePortal p(*license);
    portal = &p;
    portal->attach();                 /* MUST precede VectiNet.begin() */
    /* VectiNet.begin(&server); VectiNet.autoConnect(); — your sketch's job */
#endif
#ifdef VL_HAVE_VECTIDASH
    static vecti::DashLicenseCard c(*license);
    card = &c;
    card->attach();
#endif
#ifdef VL_HAVE_VECTISERIAL
    VectiSerial.onMessage([](const String &cmd) {
        if (vecti::licenseSerialCommand(*license, cmd)) { return; }
        /* ... your own console commands ... */
    });
#endif
}

/* --------------------------------------------------------------------------- */
void loop()
{
    /* Everything that pastes a blob in — portal, dashboard, console — only
     * queues it. This is where the Ed25519 verify — tens of milliseconds on
     * this part — and the NVS write happen, on the loop task, off the
     * network stack's task. */
    license->pump();

#ifdef VL_HAVE_VECTINET
    portal->loop();
#endif
#ifdef VL_HAVE_VECTIDASH
    card->loop();
#endif
#ifdef VL_HAVE_VECTISERIAL
    vecti::licenseSerialLoop(*license);
#endif
#ifdef VL_HAVE_VECTIOTA
    /* Unlicensed devices do not get filesystem or pull updates, but push OTA
     * stays open so a bricked unit can still be recovered without a technician
     * and a serial cable. */
    vecti::licenseGateOta(*license, FEATURE_OTA, /*gateFirmware=*/false);
#endif

    /* --- and this is the actual product ---------------------------------- */
    if (license->feature(FEATURE_MODBUS)) {
        /* pollModbus(); */
    }
    if (license->feature(FEATURE_LOGGING)) {
        /* flushLogs(); */
    }

    delay(10);
}

/*
 * WHAT THIS DOES NOT DO, on purpose.
 *
 * It does not halt when unlicensed. Whether an unlicensed unit shuts down,
 * runs a reduced feature set, or nags in the UI is a commercial decision, and
 * the failure that will actually cost you money is not piracy — it is a paying
 * customer whose board was repaired, whose efuse MAC therefore changed, and
 * whose device now refuses to boot on a Saturday. Warn, degrade, log. Do not
 * brick.
 *
 * It does not set VL_FLAG_REQUIRE_CLOCK. The ESP32 HAL supplies now_epoch and
 * rejects an unset clock, so a device that has never seen SNTP fails closed
 * with VL_ERR_PLATFORM. If you would rather it boot and run before the clock
 * syncs, copy the HAL struct and NULL now_epoch out — and then read
 * lic.checked, because your expiry dates stop being enforced.
 */
