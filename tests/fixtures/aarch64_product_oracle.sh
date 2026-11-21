#!/bin/sh
set -eu
sysroot=$1
work=$2
mkdir -p "$work"
musl=/opt/musl-1.2.6/lib/ld-musl-aarch64.so.1
loader=$sysroot/lib/ld-crabc-aarch64.so.1
for case in aarch64_direct_execfn aarch64_hwcap aarch64_long_double_rounding; do
    gcc -specs=/opt/musl-1.2.6/lib/musl-gcc.specs -fno-builtin "tests/fixtures/$case.c" -o "$work/musl-$case"
    "$sysroot/bin/crabc-cc-dynamic" -pie -fno-builtin "tests/fixtures/$case.c" -o "$work/crabc-$case"
    "$musl" "$work/musl-$case" > "$work/musl-$case.out"
    "$loader" "$work/crabc-$case" > "$work/crabc-$case.out"
    if [ "$case" = aarch64_direct_execfn ]; then
        test "$(cat "$work/musl-$case.out")" = "$musl"
        test "$(cat "$work/crabc-$case.out")" = "$loader"
    else
        diff -u "$work/musl-$case.out" "$work/crabc-$case.out"
    fi
done
