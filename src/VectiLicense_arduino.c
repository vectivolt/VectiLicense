/* (c) 2026 VectiVolt — Apache-2.0 License
 *
 * Arduino-only unity translation unit.
 *
 * The Arduino library format compiles src/ and nothing else, so this file
 * pulls the real sources in from core/ (and transport/ and the ESP32 HAL, if
 * they are present). Every other build system — CMake, PlatformIO, an IDF
 * component — compiles the core sources directly and never touches this
 * file, which is why the whole thing is behind ARDUINO: two build systems
 * compiling both
 * would be a duplicate-symbol error, not a subtle bug.
 *
 * No logic here. If you are tempted to add some, it belongs in core/. */

#if defined(ARDUINO)

#include "../core/vl_base32.c"
#include "../core/vl_core.c"
#include "../core/vl_ed25519.c"
#include "../core/vl_sha256.c"
#include "../core/vl_sha512.c"
#include "../core/vl_util.c"

/* Optional layers. __has_include keeps this file valid in a checkout where
 * transport/ or hal/ has been deleted, which is the point of them being
 * optional. */
#if defined(__has_include)

#if __has_include("../transport/vl_chunk.c")
#include "../transport/vl_chunk.c"
#endif
#if __has_include("../transport/vl_line.c")
#include "../transport/vl_line.c"
#endif

#if defined(ESP32) || defined(ESP_PLATFORM)
#if __has_include("../hal/esp32/vl_hal_esp32.c")
#include "../hal/esp32/vl_hal_esp32.c"
#endif
#endif

#endif /* __has_include */

#else

/* ISO C forbids an empty translation unit. */
typedef int vl_arduino_unity_not_used;

#endif /* ARDUINO */
