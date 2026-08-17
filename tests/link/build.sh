#!/usr/bin/env bash
# Link core/ into a minimal bare-metal image for two Cortex-M cores.
set -euo pipefail
cd "$(dirname "$0")/../.."
INC=$(arm-none-eabi-gcc -print-file-name=include)
out=$(mktemp -d)
for cpu in cortex-m0plus cortex-m4; do
  arm-none-eabi-gcc -std=c99 -ffreestanding -nostdlib -nostdinc -isystem "$INC" \
    -Icore -Iinclude -Os -mcpu=$cpu -mthumb -Wall -Wextra \
    -ffunction-sections -fdata-sections -Wl,--gc-sections \
    -T tests/link/link.ld tests/link/main.c core/*.c -lgcc -o "$out/fw_$cpu.elf"
  arm-none-eabi-objcopy -O binary "$out/fw_$cpu.elf" "$out/fw_$cpu.bin"
  # The link is only meaningful if the crypto actually survived --gc-sections.
  for sym in vl_verify vl_ed25519_verify vl_sha512_final vl_base32_decode; do
    arm-none-eabi-nm "$out/fw_$cpu.elf" | grep -q " [tT] $sym" \
      || { echo "FAIL: $sym missing from the $cpu image"; exit 1; }
  done
  printf '%-14s %s  bin=%s B\n' "$cpu" \
    "$(arm-none-eabi-size "$out/fw_$cpu.elf" | tail -1 | awk '{print "text="$1" data="$2" bss="$3}')" \
    "$(wc -c < "$out/fw_$cpu.bin" | tr -d ' ')"
done
