#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/source_runtime_libc.sh"
readonly repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[ "$(uname -s)" = Linux ] && [ "$(uname -m)" = aarch64 ] || exit 1
work="$(mktemp -d "${TMPDIR:?}/crabc-aarch64-default-runtime.XXXXXX")"
trap 'rm -rf -- "$work"' EXIT
build_source_runtime_libc "$work/libc.a"
/usr/local/bin/crabc-aarch64-musl-gcc -std=c11 -I"$repo/include" -nostdlib -static \
    -fno-pie -no-pie -ffreestanding -fno-builtin -fno-stack-protector \
    -Wl,-e,_start -Wl,--no-undefined -Wl,--gc-sections \
    "$repo/compat/x86_64/libc_aarch64_default_runtime_probe.c" \
    "$repo/compat/x86_64/libc_aarch64_default_runtime_start.S" "$work/libc.a" -o "$work/probe"
"$work/probe"
printf 'aarch64 default static runtime regression: PASS\n'
