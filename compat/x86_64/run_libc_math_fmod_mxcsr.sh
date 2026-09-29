#!/usr/bin/env bash
# Pinned-musl raw-result and MXCSR differential for subnormal fmod operands.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/source_runtime_libc.sh"

readonly ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly PROBE="$ROOT/compat/x86_64/owned_math_fmod_mxcsr_probe.c"
readonly START="$ROOT/compat/x86_64/owned_math_fmod_mxcsr_start.S"

[[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]] || {
    printf 'fmod MXCSR differential requires native Linux/x86-64\n' >&2
    exit 1
}
[[ -x "$ORACLE_CC" ]] || {
    printf 'pinned musl compiler is unavailable\n' >&2
    exit 1
}
mkdir -p "$ROOT/.work/x86_64/tmp"
export TMPDIR="$ROOT/.work/x86_64/tmp"
bash "$ROOT/compat/x86_64/run_musl_oracle.sh" >/dev/null
work="$(mktemp -d "$ROOT/.work/x86_64/tmp/math-fmod-mxcsr.XXXXXX")"
trap 'rm -rf -- "$work"' EXIT

"$ORACLE_CC" -std=c11 -O2 -frounding-math -fno-builtin \
    -fno-stack-protector -I"$ROOT/include" "$PROBE" -lm -o "$work/oracle"
"$ORACLE_CC" -std=c11 -O2 -frounding-math -fno-builtin \
    -fno-stack-protector -ffreestanding -I"$ROOT/include" -c "$PROBE" \
    -o "$work/probe.o"
build_source_runtime_libc "$work/libc.a"
"$ORACLE_CC" -nostdlib -static -fno-pie -no-pie -Wl,-e,_start \
    -Wl,--no-undefined "$work/probe.o" "$START" "$work/libc.a" \
    -o "$work/candidate"

"$work/oracle" >"$work/oracle.records"
"$work/candidate" >"$work/candidate.records"
[[ "$(wc -c < "$work/oracle.records")" -eq 512 ]] || {
    printf 'pinned musl emitted an incomplete fmod MXCSR matrix\n' >&2
    exit 1
}
if ! cmp -s "$work/oracle.records" "$work/candidate.records"; then
    cmp -l "$work/oracle.records" "$work/candidate.records" | head -32 >&2 || true
    printf 'fmod MXCSR records differ from pinned musl\n' >&2
    exit 1
fi
printf 'x86 fmod subnormal MXCSR differential: PASS (32 records)\n'
