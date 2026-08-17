# Bare-metal link test

Proves `core/` **links into a real firmware image**, not merely that it compiles.
Compiling never surfaces a missing runtime symbol; linking does — this test is why
the libgcc dependency in the top-level README is documented rather than assumed.

    ./tests/link/build.sh          # builds for Cortex-M0+ and Cortex-M4

Produces a flashable `.bin` and prints its section sizes. Nothing here has been
executed on hardware.
