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
for corpus in edge huge; do
    corpus_flags=()
    verify_flags=()
    if [ "$corpus" = huge ]; then
        corpus_flags=(-DCRABC_MATH_POW_HUGE)
        verify_flags=(--huge)
    fi
    for arm in oracle candidate; do
        library=/opt/musl-1.2.6/lib/libc.a
        if [ "$arm" = candidate ]; then library="$work/boundary.o"; fi
        "$cc" "${flags[@]}" "${corpus_flags[@]}" \
            compat/x86_64/libc_math_pow_edges_probe.c \
            compat/x86_64/libc_math_pow_edges_start.S "$library" \
            -o "$work/$corpus.$arm"
        "$work/$corpus.$arm" >"$work/$corpus.$arm.records"
    done
    readelf -W -s "$work/$corpus.candidate" >"$work/$corpus.candidate.symbols"
    readelf -W -l "$work/$corpus.candidate" >"$work/$corpus.candidate.segments"
    readelf -W -d "$work/$corpus.candidate" >"$work/$corpus.candidate.dynamic"
    for symbol in pow powf; do
        grep -Eq "FUNC[[:space:]]+GLOBAL[[:space:]]+DEFAULT[[:space:]]+[0-9]+[[:space:]]+$symbol$" \
            "$work/$corpus.candidate.symbols"
    done
    if grep -Eq 'INTERP|TLS|NEEDED' "$work/$corpus.candidate.segments" \
        "$work/$corpus.candidate.dynamic"; then exit 1; fi
    if awk '$7 == "UND" && NF >= 8 { print }' "$work/$corpus.candidate.symbols" | grep . >/dev/null; then exit 1; fi
    python3 compat/x86_64/verify_math_pow_edges.py \
        "$work/$corpus.oracle.records" "$work/$corpus.candidate.records" \
        "${verify_flags[@]}" | tee "$work/$corpus.summary.txt"
done
