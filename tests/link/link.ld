/* Minimal Cortex-M image: enough to prove VectiLicense core LINKS, not merely
   compiles. Flash/RAM sizes are an RP2040-ish stand-in; the point is a real
   link step producing a real .bin with real section sizes. */
MEMORY {
  FLASH (rx) : ORIGIN = 0x10000000, LENGTH = 512K
  RAM  (rwx) : ORIGIN = 0x20000000, LENGTH = 128K
}
ENTRY(reset_handler)
SECTIONS {
  .text : { KEEP(*(.vectors)) *(.text*) *(.rodata*) } > FLASH
  .data : { _sdata = .; *(.data*) _edata = .; } > RAM AT> FLASH
  .bss  : { _sbss = .; *(.bss*) *(COMMON) _ebss = .; } > RAM
  . = ALIGN(4);
  _estack = ORIGIN(RAM) + LENGTH(RAM);
}
