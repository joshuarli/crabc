#!/usr/bin/env bash
# Focused finite-identity proof retaining the independent musl deficiency.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
mkdir -p .work/x86_64/tmp
work="$(mktemp -d "$root/.work/x86_64/tmp/math-pow-identity110.XXXXXX")"
printf 'Retained power identity evidence: %s\n' "$work"
cc=/usr/local/bin/crabc-x86_64-musl-gcc
rustc --edition=2021 --crate-type=lib --emit=obj \
    --target x86_64-unknown-linux-musl -C opt-level=0 -C panic=abort \
    -C relocation-model=static compat/x86_64/math_pow_identity110_boundary.rs \
    -o "$work/boundary.o"
for arm in oracle candidate; do
    library=/opt/musl-1.2.6/lib/libc.a
    if [ "$arm" = candidate ]; then library="$work/boundary.o"; fi
    "$cc" -std=c11 -O0 -frounding-math -Iinclude -nostdlib -static \
        -fno-pie -no-pie -fno-stack-protector -Wl,-e,_start -Wl,--gc-sections \
        compat/x86_64/math_pow_identity110_probe.c \
        compat/x86_64/math_pow_identity110_start.S "$library" -o "$work/$arm"
    status=0
    "$work/$arm" >"$work/$arm.records" || status=$?
    printf '%s\n' "$status" >"$work/$arm.status"
    if [ "$arm" = candidate ]; then [ "$status" -eq 0 ]; else [ "$status" -eq 1 ]; fi
done
readelf -W -l "$work/candidate" >"$work/candidate.segments"
readelf -W -d "$work/candidate" >"$work/candidate.dynamic"
readelf -W -s "$work/candidate" >"$work/candidate.symbols"
if grep -Eq 'INTERP|NEEDED' "$work/candidate.segments" "$work/candidate.dynamic"; then exit 1; fi
if awk '$7 == "UND" && NF >= 8 { print }' "$work/candidate.symbols" | grep . >/dev/null; then exit 1; fi
python3 - "$work" <<'PY'
import struct
import sys
from pathlib import Path

work = Path(sys.argv[1])
old = (work / 'oracle.records').read_bytes()
new = (work / 'candidate.records').read_bytes()
assert old and len(old) == len(new) and len(old) % 40 == 0
identities = controls = differences = 0
for source, candidate in zip(struct.iter_unpack('<5Q', old), struct.iter_unpack('<5Q', new)):
    base, exponent, result, rounding, flags = candidate
    assert source[:2] == candidate[:2] and source[3] == rounding
    assert rounding >> 32 == rounding & 0xffffffff
    if exponent == 0x3ff0000000000000 and base & 0x7fffffffffffffff < 0x7ff0000000000000:
        assert result == base
        identities += 1
        differences += source != candidate
    else:
        assert source == candidate
        controls += 1
assert identities and controls and differences
print(f'PASS: {identities} exact identities, {controls} unchanged controls; {differences} raw musl differences retained')
PY
