#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[ "$#" = 3 ] || { printf 'usage: %s STATIC_PRODUCT DYNAMIC_PRODUCT WORK\n' "$0" >&2; exit 2; }
static="$1" dynamic="$2" work="$3"
mkdir -p "$work/execution/usr"
cp -a "$dynamic/lib" "$work/execution/"
cp -a "$dynamic/usr/lib" "$work/execution/usr/"
cc=/usr/local/bin/crabc-aarch64-musl-gcc
inc="$($cc -print-file-name=include)"
for probe in binary128_helper_probe binary128_compare_probe binary128_fix_probe binary128_stdio_probe; do
    source="$root/compat/x86_64/$probe.c"
    gcc -specs=/opt/musl-1.2.6/lib/musl-gcc.specs -std=c11 -static -no-pie -O0 -fno-builtin -frounding-math "$source" -lm -o "$work/$probe-oracle"
    "$work/$probe-oracle" > "$work/$probe-oracle.txt"
    for product in static dynamic; do
        if [ "$product" = static ]; then sysroot="$static"; else sysroot="$dynamic"; fi
        "$cc" -std=c11 -O0 -fno-builtin -frounding-math -fPIC -nostdinc -isystem "$inc" -I"$sysroot/usr/include" -c "$source" -o "$work/$probe-$product.o"
        if [ "$product" = static ]; then
            "$static/bin/crabc-cc" "$work/$probe-$product.o" -o "$work/$probe-$product"
            "$work/$probe-$product" > "$work/$probe-$product.txt"
        else
            "$dynamic/bin/crabc-cc-dynamic" --dynamic-pie "$work/$probe-$product.o" -o "$work/execution/$probe"
            chroot "$work/execution" "/$probe" > "$work/$probe-$product.txt"
        fi
        cmp "$work/$probe-oracle.txt" "$work/$probe-$product.txt"
    done
done
printf 'binary128 helper and stdio differential: PASS (oracle, static, dynamic)\n'
