// ---------------------------------------------------------------------------
// VectiLicense — the one header an Arduino / PlatformIO sketch includes
// (c) 2026 VectiVolt — Apache-2.0 License
// ---------------------------------------------------------------------------
//
//     #include <VectiLicense.h>
//
// gives you the C API, and — in C++, and only for the sibling libraries that
// are actually installed — the VectiSuite bridges. Nothing here is required:
// the library works perfectly well included as
// <vectilicense/vectilicense.h> with no Arduino anywhere.
//
// Why this directory exists at all: the Arduino library format compiles
// `src/` and nothing else, while the real layout is core/ + include/ + hal/ +
// bridge/ (see the README's layering table). So `src/` holds three small
// forwarding files and no logic.

#ifndef VECTILICENSE_ARDUINO_H
#define VECTILICENSE_ARDUINO_H

#include "../include/vectilicense/vectilicense.h"

#ifdef __cplusplus
#include "../bridge/vl_bridge.h"
#include "../bridge/vl_bridge_dash.h"
#include "../bridge/vl_bridge_net.h"
#include "../bridge/vl_bridge_ota.h"
#include "../bridge/vl_bridge_serial.h"
#endif

#endif  // VECTILICENSE_ARDUINO_H
