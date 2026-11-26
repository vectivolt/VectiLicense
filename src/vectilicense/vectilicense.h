/* (c) 2026 VectiVolt — Apache-2.0 License
 *
 * Arduino IDE forwarder. The IDE puts src/ and nothing else on the include
 * path, and core/, hal/ and transport/ name the public header
 * "vectilicense/vectilicense.h"; without this file the unity build in
 * src/VectiLicense_arduino.c stops at its first include. Every other build
 * system finds include/ directly and never sees this. */
#include "../../include/vectilicense/vectilicense.h"
