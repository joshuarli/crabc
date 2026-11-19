#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cc=/usr/local/bin/crabc-aarch64-musl-gcc
fail() { printf 'ERROR: aarch64 binary128 fdiml/exp10l: %s\n' "$*" >&2; exit 1; }
[ "$(uname -s)" = Linux ] && [ "$(uname -m)" = aarch64 ] || fail 'requires native Linux/aarch64'
[ -x "$cc" ] || fail 'missing pinned musl compiler'
mkdir -p "$root/.work/aarch64/tmp"
if [ "$#" = 0 ]; then
    work="$(mktemp -d "$root/.work/aarch64/tmp/long-double-completion.XXXXXX")"
elif [ "$#" = 2 ] && [ "$1" = --retain-output ]; then
    work="$(python3 -B - "$root" "$2" <<'PY'
from pathlib import Path
import sys
root = Path(sys.argv[1]).resolve(strict=True)
path = Path(sys.argv[2])
if not path.is_absolute():
    path = root / path
if '..' in path.parts or not path.is_relative_to(root / '.work/aarch64'):
    raise SystemExit('retained output must be below .work/aarch64')
if path.exists() or path.is_symlink() or path.parent.resolve(strict=True) != path.parent:
    raise SystemExit('retained output must be new with a physical parent')
path.mkdir()
print(path)
PY
)"
else
    fail 'usage: [--retain-output RETAINED_OUTPUT]'
fi
cd "$root"
python3 -B scripts/build_x86_64_owned_sysroot.py --architecture aarch64 --output "$work/product" >"$work/build.log"
compiler_include="$($cc -print-file-name=include)"
probe=compat/x86_64/libc_math_long_double_completion_probe.c
header_probe=compat/x86_64/math_long_double_completion_header_abi_probe.cpp
"$cc" -std=c++17 -x c++ -D_GNU_SOURCE -fno-builtin -c "$header_probe" -o "$work/oracle-header.o"
"$cc" -std=c++17 -x c++ -D_GNU_SOURCE -fno-builtin -nostdinc -isystem "$compiler_include" \
    -I"$work/product/usr/include" -c "$header_probe" -o "$work/candidate-header.o"
for object in "$work/oracle-header.o" "$work/candidate-header.o"; do
    nm --undefined-only "$object" > "$work/header-symbols"
    for symbol in fdiml exp10l pow10l; do
        grep -Eq "[[:space:]]${symbol}$" "$work/header-symbols" || fail "missing C++ declaration for $symbol"
    done
done
"$cc" -std=c11 -D_GNU_SOURCE -fno-builtin -frounding-math -Iinclude -static -no-pie \
    "$probe" -lm -o "$work/oracle"
"$cc" -std=c11 -D_GNU_SOURCE -fno-builtin -frounding-math -nostdinc -isystem "$compiler_include" \
    -I"$work/product/usr/include" -c "$probe" -o "$work/candidate.o"
"$work/product/bin/crabc-cc" "$work/candidate.o" -o "$work/candidate"
readelf -hW "$work/candidate" > "$work/header"
readelf -lW "$work/candidate" > "$work/program"
readelf -dW "$work/candidate" > "$work/dynamic"
readelf -sW "$work/candidate" > "$work/symbols"
grep -Eq 'Machine:[[:space:]]+AArch64' "$work/header" || fail 'candidate machine differs'
if grep -Eq 'INTERP|Requesting program interpreter' "$work/program" || grep -q NEEDED "$work/dynamic"; then
    fail 'candidate selects a dynamic runtime'
fi
for symbol in fdiml exp10l pow10l; do
    grep -Eq "[[:space:]]${symbol}$" "$work/symbols" || fail "candidate lacks $symbol"
done
exp="$(awk '$4 == "FUNC" && $8 == "exp10l" { print $2; exit }' "$work/symbols")"
pow="$(awk '$4 == "FUNC" && $8 == "pow10l" { print $2; exit }' "$work/symbols")"
[ -n "$exp" ] && [ "$exp" = "$pow" ] || fail 'exp10l/pow10l alias differs'
archive="$work/product/usr/lib/libc.a"
nm -A --defined-only "$archive" > "$work/archive-symbols"
for symbol in fdiml exp10l; do
    grep -Eq "[[:space:]]T[[:space:]]${symbol}$" "$work/archive-symbols" || fail "archive lacks strong $symbol"
done
grep -Eq '[[:space:]]W[[:space:]]pow10l$' "$work/archive-symbols" || fail 'archive lacks weak pow10l'
"$cc" -std=c11 -D_GNU_SOURCE -DCRABC_MATH_LONG_DOUBLE_COMPLETION_FREESTANDING \
    -fno-builtin -frounding-math -ffreestanding -fno-stack-protector -fno-pie \
    -nostdinc -isystem "$compiler_include" -I"$work/product/usr/include" \
    -c "$probe" -o "$work/freestanding.o"
"$cc" -c compat/x86_64/libc_math_long_double_completion_aarch64_start.S -o "$work/start.o"
"$cc" -nostdlib -static -no-pie -Wl,-e,_start,--no-undefined,--gc-sections,--trace,--export-dynamic \
    "$work/start.o" "$work/freestanding.o" -Wl,--start-group "$archive" \
    "$work/product/usr/lib/libcrabc-builtins.a" -Wl,--end-group -o "$work/freestanding" > "$work/freestanding.trace"
readelf -sW "$work/freestanding" > "$work/freestanding.symbols"
readelf -lW "$work/freestanding" > "$work/freestanding.program"
readelf -dW "$work/freestanding" > "$work/freestanding.dynamic"
readelf -rW "$work/freestanding" > "$work/freestanding.relocations"
objdump -d "$work/freestanding" > "$work/freestanding.disassembly"
awk '$4 == "FUNC" && ($5 == "GLOBAL" || $5 == "WEAK") { print $8 }' "$work/freestanding.symbols" |
    LC_ALL=C sort -u > "$work/freestanding.functions"
printf '%s\n' __addoti4 __divdc3 __divsc3 __divtc3 __ffsti2 __fpclassifyl __muldc3 __mulsc3 \
    __multc3 __parityti2 __popcountdi2 __popcountti2 __suboti4 _start \
    crabc_x86_64_math_long_double_completion_probe exp10l exp2l fabs fdiml feclearexcept \
    fegetenv fegetround feraiseexcept fesetenv fesetround fetestexcept modfl pow pow10l powl scalbnl |
    LC_ALL=C sort -u > "$work/freestanding.expected-functions"
cmp "$work/freestanding.expected-functions" "$work/freestanding.functions" || fail 'freestanding function closure differs'
for symbol in fdiml exp10l; do
    grep -Eq "[[:space:]]FUNC[[:space:]]+GLOBAL[[:space:]]+DEFAULT[[:space:]]+[0-9]+[[:space:]]${symbol}$" \
        "$work/freestanding.symbols" || fail "freestanding candidate lacks strong $symbol"
done
grep -Eq '[[:space:]]FUNC[[:space:]]+WEAK[[:space:]]+DEFAULT[[:space:]]+[0-9]+[[:space:]]pow10l$' \
    "$work/freestanding.symbols" || fail 'freestanding candidate lacks weak pow10l'
if awk '$7 == "UND" && NF >= 8 && !($5 == "LOCAL" && ($8 == "_PROCEDURE_LINKAGE_TABLE_" || $8 == "__rela_iplt_start" || $8 == "__rela_iplt_end")) { print }' "$work/freestanding.symbols" | grep . >/dev/null; then
    fail 'freestanding candidate has unresolved symbols'
fi
if grep -Eq 'INTERP|[[:space:]]TLS[[:space:]]|Requesting program interpreter' "$work/freestanding.program" ||
    grep -Eq '\((NEEDED|JMPREL|PLTGOT|TEXTREL)\)' "$work/freestanding.dynamic" ||
    grep -Eq 'TLSGD|TLSLD|TLSDESC|DTPMOD|DTPREL|__tls_get_addr' "$work/freestanding.relocations" "$work/freestanding.disassembly"; then
    fail 'freestanding candidate admits dynamic or TLS state'
fi
if grep -Eq 'libgcc|compiler-rt|libm\.so|/[Sr]?crt[^/[:space:]]*\.o' "$work/freestanding.trace"; then
    fail 'freestanding candidate linked an ambient runtime'
fi
if grep -Eq 'crabc_core|mimalloc|float_parse|math_compat|libm\.so|libm-' \
    "$work/freestanding.symbols" "$work/freestanding.disassembly"; then
    fail 'freestanding candidate retained an ambient math or runtime dependency'
fi
aggregate=CRABC_MATH_ELEMENTARY_FENV_SENSITIVE_AGGREGATE_FREESTANDING
"$cc" -std=c11 -D_GNU_SOURCE -D"$aggregate" -fno-builtin -frounding-math -ffreestanding \
    -fno-stack-protector -fno-pie -nostdinc -isystem "$compiler_include" -I"$work/product/usr/include" \
    -c compat/x86_64/libc_math_elementary_fenv_sensitive_aggregate_probe.c -o "$work/aggregate.o"
"$cc" -D"$aggregate" -c compat/x86_64/libc_math_long_double_completion_aarch64_start.S -o "$work/aggregate-start.o"
"$cc" -nostdlib -static -no-pie -Wl,-e,_start,--no-undefined,--gc-sections,--trace,--export-dynamic \
    "$work/aggregate-start.o" "$work/aggregate.o" -Wl,--start-group "$archive" \
    "$work/product/usr/lib/libcrabc-builtins.a" -Wl,--end-group -o "$work/aggregate" > "$work/aggregate.trace"
readelf -sW "$work/aggregate" > "$work/aggregate.symbols"
readelf -lW "$work/aggregate" > "$work/aggregate.program"
readelf -dW "$work/aggregate" > "$work/aggregate.dynamic"
readelf -rW "$work/aggregate" > "$work/aggregate.relocations"
objdump -d "$work/aggregate" > "$work/aggregate.disassembly"
for pair in exp10:pow10 exp10f:pow10f exp10l:pow10l; do
    strong="${pair%%:*}"
    weak="${pair##*:}"
    strong_value="$(awk -v symbol="$strong" '$4 == "FUNC" && $5 == "GLOBAL" && $6 == "DEFAULT" && $8 == symbol { print $2; exit }' "$work/aggregate.symbols")"
    weak_value="$(awk -v symbol="$weak" '$4 == "FUNC" && $5 == "WEAK" && $6 == "DEFAULT" && $8 == symbol { print $2; exit }' "$work/aggregate.symbols")"
    [ -n "$strong_value" ] && [ "$strong_value" = "$weak_value" ] || fail "aggregate alias $pair differs"
done
for symbol in fdim fdimf fdiml rint rintf rintl nearbyint nearbyintf nearbyintl; do
    grep -Eq "[[:space:]]FUNC[[:space:]]+GLOBAL[[:space:]]+DEFAULT[[:space:]]+[0-9]+[[:space:]]${symbol}$" \
        "$work/aggregate.symbols" || fail "aggregate lacks strong $symbol"
done
if awk '$7 == "UND" && NF >= 8 && !($5 == "LOCAL" && ($8 == "_PROCEDURE_LINKAGE_TABLE_" || $8 == "__rela_iplt_start" || $8 == "__rela_iplt_end")) { print }' "$work/aggregate.symbols" | grep . >/dev/null ||
    grep -Eq 'INTERP|[[:space:]]TLS[[:space:]]|Requesting program interpreter' "$work/aggregate.program" ||
    grep -Eq '\((NEEDED|JMPREL|PLTGOT|TEXTREL)\)' "$work/aggregate.dynamic" ||
    grep -Eq 'TLSGD|TLSLD|TLSDESC|DTPMOD|DTPREL|__tls_get_addr|crabc_core|mimalloc|float_parse|math_compat|libm\.so|libm-' \
        "$work/aggregate.symbols" "$work/aggregate.relocations" "$work/aggregate.disassembly" ||
    grep -Eq 'libgcc|compiler-rt|libm\.so|/[Sr]?crt[^/[:space:]]*\.o' "$work/aggregate.trace"; then
    fail 'aggregate candidate has unowned linkage, TLS, or unresolved symbols'
fi
"$work/aggregate" || fail 'aggregate candidate failed'
"$work/oracle" > "$work/oracle.records"
"$work/candidate" > "$work/candidate.records"
"$work/freestanding" > "$work/freestanding.records"
cmp "$work/candidate.records" "$work/freestanding.records" || fail 'freestanding candidate differs from installed product'
python3 -B compat/x86_64/validate_libc_math_long_double_completion_aarch64.py \
    "$work/oracle.records" "$work/candidate.records"
