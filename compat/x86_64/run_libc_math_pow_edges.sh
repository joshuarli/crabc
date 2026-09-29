#!/usr/bin/env bash
# Direct production-source object versus pinned source-built musl archive.
set -euo pipefail
root="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
[ "$(uname -s)/$(uname -m)" = Linux/x86_64 ]
[ -n "${TMPDIR:-}" ]
case "$(realpath -e "$TMPDIR")" in "$root"/.work/*) ;; *) exit 2 ;; esac
bash compat/x86_64/run_musl_oracle.sh >/dev/null
work="$(mktemp -d "$TMPDIR/libc-math-pow-edges.XXXXXX")"
chmod a+rx "$work"
printf 'Retained pow edge evidence: %s\n' "$work"
cc=/usr/local/bin/crabc-x86_64-musl-gcc
rustup run "$(python3 "$root/scripts/rust_toolchain.py")" rustc --edition=2021 \
    --crate-type=lib --emit=obj --target x86_64-unknown-linux-musl \
    -C panic=abort -C opt-level=2 \
    compat/x86_64/math_scalar_corrections_boundary.rs -o "$work/boundary.o"
flags=(-std=c11 -I"$root/include" -nostdlib -static -fno-pie -no-pie -ffreestanding
    -fno-builtin -frounding-math -fno-stack-protector -Wl,-e,_start
    -Wl,--no-undefined -Wl,--gc-sections)
for arm in oracle candidate; do
    library=/opt/musl-1.2.6/lib/libc.a
    if [ "$arm" = candidate ]; then library="$work/boundary.o"; fi
    "$cc" "${flags[@]}" compat/x86_64/libc_math_pow_edges_probe.c \
        compat/x86_64/libc_math_pow_edges_start.S "$library" -o "$work/$arm"
    "$work/$arm" >"$work/$arm.records"
done
readelf -W -s "$work/candidate" >"$work/candidate.symbols"
readelf -W -l "$work/candidate" >"$work/candidate.segments"
readelf -W -d "$work/candidate" >"$work/candidate.dynamic"
for symbol in pow powf; do
    grep -Eq "FUNC[[:space:]]+GLOBAL[[:space:]]+DEFAULT[[:space:]]+[0-9]+[[:space:]]+$symbol$" \
        "$work/candidate.symbols"
done
if grep -Eq 'INTERP|TLS|NEEDED' "$work/candidate.segments" "$work/candidate.dynamic"; then exit 1; fi
if awk '$7 == "UND" && NF >= 8 { print }' "$work/candidate.symbols" | grep . >/dev/null; then exit 1; fi
python3 compat/x86_64/verify_math_pow_edges.py \
    "$work/oracle.records" "$work/candidate.records" | tee "$work/summary.txt"
