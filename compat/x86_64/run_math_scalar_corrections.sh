#!/usr/bin/env bash
# Focused native numerical conformance proof; raw fixed-musl failures survive.
set -euo pipefail
ulimit -c 0
root="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
[ "$(uname -s)/$(uname -m)" = Linux/x86_64 ]
[ -n "${TMPDIR:-}" ]
case "$(realpath -e "$TMPDIR")" in "$root"/.work/*) ;; *) exit 2 ;; esac
bash compat/x86_64/run_musl_oracle.sh >/dev/null
work="$(mktemp -d "$TMPDIR/math-scalar-corrections.XXXXXX")"
chmod a+rx "$work"
printf 'Retained scalar correction evidence: %s\n' "$work"
cc=/usr/local/bin/crabc-x86_64-musl-gcc
rustup run "$(python3 "$root/scripts/rust_toolchain.py")" rustc --edition=2021 --crate-type=lib --emit=obj \
    --target x86_64-unknown-linux-musl -C panic=abort -C opt-level=2 \
    compat/x86_64/math_scalar_corrections_boundary.rs -o "$work/boundary.o"
flags=(-std=c11 -I"$root/include" -nostdlib -static -fno-pie -no-pie -ffreestanding
    -fno-builtin -frounding-math -fno-stack-protector -Wl,-e,_start
    -Wl,--no-undefined -Wl,--gc-sections)
for arm in oracle candidate; do
    libraries=(/opt/musl-1.2.6/lib/libc.a)
    if [ "$arm" = candidate ]; then libraries=("$work/boundary.o"); fi
    "$cc" "${flags[@]}" compat/x86_64/math_scalar_corrections_probe.c \
        compat/x86_64/math_scalar_corrections_start.S "${libraries[@]}" -o "$work/$arm.regression"
    status=0
    "$work/$arm.regression" || status=$?
    printf '%s\n' "$status" >"$work/$arm.regression.status"
    if [ "$arm" = candidate ]; then [ "$status" -eq 0 ]; else [ "$status" -eq 63 ]; fi
    "$cc" "${flags[@]}" compat/x86_64/math_scalar_corrections_stream.c \
        compat/x86_64/math_scalar_corrections_start.S "${libraries[@]}" -o "$work/$arm.stream"
done
readelf -W -s "$work/candidate.stream" >"$work/candidate.symbols"
readelf -W -l "$work/candidate.stream" >"$work/candidate.segments"
readelf -W -d "$work/candidate.stream" >"$work/candidate.dynamic"
objdump -d "$work/candidate.stream" >"$work/candidate.disassembly"
for symbol in fmaf fmal powf; do
    grep -Eq "FUNC[[:space:]]+GLOBAL[[:space:]]+DEFAULT[[:space:]]+[0-9]+[[:space:]]+$symbol$" "$work/candidate.symbols"
done
if grep -Eq 'INTERP|TLS|NEEDED' "$work/candidate.segments" "$work/candidate.dynamic"; then exit 1; fi
if awk '$7 == "UND" && NF >= 8 { print }' "$work/candidate.symbols" | grep . >/dev/null; then exit 1; fi
if grep -Eq '[[:space:]](v[a-z0-9]+|addp[sd]|subp[sd]|mulp[sd]|divp[sd]|sqrtp[sd])([[:space:]]|$)' "$work/candidate.disassembly"; then exit 1; fi
python3 compat/x86_64/verify_math_scalar_corrections.py \
    --candidate "$work/candidate.stream" --oracle "$work/oracle.stream" --output "$work/exact"
# Reuse the existing neighbouring function-family corpora against the same
# production-source object. Fixed oracle records are never rewritten.
for family in scalar binary80 pow elementary_long_double special; do
    case "$family" in
        scalar) probe=owned_static_math_scalar_consumer; define=CRABC_MATH_SCALAR_COMPLETION_FREESTANDING; bytes=17024 ;;
        binary80) probe=owned_static_math_binary80_consumer; define=CRABC_OWNED_STATIC_BINARY80_MATH_FREESTANDING; bytes=7840 ;;
        pow) probe=libc_math_pow_probe; define=CRABC_MATH_POW_FREESTANDING; bytes=10240 ;;
        elementary_long_double) probe=libc_math_elementary_long_double_probe; define=CRABC_MATH_ELEMENTARY_LONG_DOUBLE_FREESTANDING; bytes=110560 ;;
        special) probe=libc_math_special_probe; define=CRABC_MATH_SPECIAL_FREESTANDING; bytes=177408 ;;
    esac
    start=${probe%_probe}_start
    for arm in oracle candidate; do
        library="$work/boundary.o"
        if [ "$arm" = oracle ]; then library=/opt/musl-1.2.6/lib/libc.a; fi
        "$cc" "${flags[@]}" -D_GNU_SOURCE -D"$define" "compat/x86_64/$probe.c" \
            "compat/x86_64/$start.S" "$library" -o "$work/$family.$arm"
        "$work/$family.$arm" >"$work/$family.$arm.records"
        [ "$(wc -c <"$work/$family.$arm.records")" -eq "$bytes" ]
    done
    if [ "$family" = pow ]; then
        python3 compat/x86_64/verify_math_pow_records.py "$work/$family.oracle.records" "$work/$family.candidate.records"
    else
        cmp "$work/$family.oracle.records" "$work/$family.candidate.records"
    fi
    printf 'Existing %s corpus: PASS\n' "$family"
done
printf 'Native scalar corrections: PASS (exact checks + 9064 existing records; pinned musl failures retained)\n'
