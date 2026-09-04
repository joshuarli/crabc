#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc floating/locale conversion evidence.
#
# The project-header C fixture executes first against pinned musl, then as a
# true -nostdlib static candidate linked only through the selected archive. It
# selects the complete `numeric.parse-float-locale` symbol set plus the
# already-selected x86 fenv and initial-TLS errno leaves needed to prove
# current-rounding behavior. `strtold`, `strtold_l`, `__strtold_l`, and
# `wcstold` retain the SysV x87 binary80 result ABI. Allocation, general stdio,
# locale databases beyond C/POSIX/C.UTF-8, and a general text runtime remain
# outside this artifact.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly INITIAL_TLS_BYTES=4096
readonly INITIAL_TLS_ALIGNMENT=64

fail() { printf 'ERROR: x86 static libc floating conversion: %s\n' "$*" >&2; exit 1; }
require_tool() { command -v "$1" >/dev/null 2>&1 || fail "requires $1"; }

assert_selected_c_abi_surface() {
    local archive_path="$1" symbols_path="$2" expected_path="$3"
    local members_path="$work_dir/selected-c-abi-members"; local -a members
    mapfile -t members < <(ar t "$archive_path" | grep -E '^c\..+\.rcgu\.o$')
    [ "${#members[@]}" -gt 0 ] || fail "archive has no crabc-libc object members"
    mkdir "$members_path"
    ( cd "$members_path"; ar x "$archive_path" "${members[@]}"; \
      nm -g --defined-only --format=posix "${members[@]}" ) |
        awk '$2 ~ /^[TWDVBR]$/ && $1 !~ /^(_R|_ZN|DW\.ref\.|anon\.)/ && $1 != "crabc_x86_64_signal_restorer" && $1 != "__crabc_x86_pthread_clone" { print $1 }' |
        sort -u >"$symbols_path"
    [ -f "$STATIC_C_ABI_EXPORTS" ] || fail "missing static C ABI export contract"
    grep -Ev '^(#|$)' "$STATIC_C_ABI_EXPORTS" | LC_ALL=C sort -u >"$expected_path"
    if ! cmp -s "$expected_path" "$symbols_path"; then
        diff -u "$expected_path" "$symbols_path" >&2 || true
        fail "selected static C ABI export surface drifted"
    fi
}

assert_fixture_tls_capacity() {
    local tls_filesz tls_memsz tls_alignment

    read -r tls_filesz tls_memsz tls_alignment < <(
        awk '$1 == "TLS" { print $5, $6, $NF; exit }' "$headers"
    )
    [ -n "${tls_filesz:-}" ] || fail "candidate lacks a parsable PT_TLS segment"
    if (( tls_filesz != 0 )); then
        fail "fixture TLS scratch cannot initialize nonzero PT_TLS data"
    fi
    if (( tls_memsz == 0 || tls_memsz > INITIAL_TLS_BYTES )); then
        fail "fixture TLS scratch does not cover PT_TLS memsz ${tls_memsz}"
    fi
    if (( tls_alignment == 0 || tls_alignment > INITIAL_TLS_ALIGNMENT ||
        INITIAL_TLS_ALIGNMENT % tls_alignment != 0 )); then
        fail "fixture TLS scratch is incompatible with PT_TLS alignment ${tls_alignment}"
    fi
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "requires native x86-64" ;; esac
for tool in ar awk cargo cmp diff grep nm objdump readelf rustup sort; do require_tool "$tool"; done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_float_parse_header_abi.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-float-parse.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
target_dir="$work_dir/cargo-target"; archive="$target_dir/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-float-parse-reference"; candidate="$work_dir/crabc-static-float-parse-candidate"
trace="$work_dir/header-trace"; archive_symbols="$work_dir/archive-symbols"
selected_symbols="$work_dir/selected-c-abi-symbols"; expected_symbols="$work_dir/expected-c-abi-symbols"
symbols="$work_dir/candidate-symbols"; headers="$work_dir/candidate-program-headers"
dynamic="$work_dir/candidate-dynamic"; relocs="$work_dir/candidate-relocations"; disassembly="$work_dir/candidate-disassembly"
errno_disassembly="$work_dir/errno-disassembly"; parser_disassembly="$work_dir/parser-disassembly"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_float_parse_probe.c >/dev/null 2>"$trace"
for header in errno.h fenv.h float.h inttypes.h locale.h stdint.h stdlib.h wchar.h features.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$trace" || fail "fixture did not use project $header"
done
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" compat/x86_64/libc_float_parse_probe.c -o "$reference"
"$reference" || fail "pinned-musl floating-conversion fixture failed"

CARGO_TARGET_DIR="$target_dir" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"
nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_symbols" "$expected_symbols"
for symbol in __errno_location __strtod_l __strtof_l __strtold_l atof ecvt fcvt gcvt getsubopt \
    strtod strtod_l strtof strtof_l strtold strtold_l wcstod wcstof wcstoimax wcstol \
    wcstold wcstoll wcstoul wcstoull wcstoumax fegetround fesetround fegetenv fesetenv \
    feraiseexcept; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" ||
        fail "archive does not define ${symbol}"
done
for unselected in __floatscan __intscan __strtod_internal __strtof_internal __strtold_internal \
    malloc calloc realloc free printf fprintf \
    rand srand; do
    if grep -Eq "[[:space:]][TW][[:space:]]${unselected}$" "$archive_symbols"; then
        fail "archive accidentally exports unselected ${unselected}"
    fi
done
readelf --relocs --wide "$archive" >"$work_dir/archive-relocations"
grep -Eq 'R_X86_64_TPOFF(32|64)?' "$work_dir/archive-relocations" ||
    fail "archive errno lacks an initial-TLS TPOFF relocation"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' \
    "$work_dir/archive-relocations"; then
    fail "archive selects dynamic TLS or an unowned runtime dependency"
fi

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_FLOAT_PARSE_FREESTANDING \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    compat/x86_64/libc_float_parse_probe.c \
    compat/x86_64/libc_float_parse_start.S "$archive" -o "$candidate"
readelf --symbols --wide "$candidate" >"$symbols"
readelf --program-headers --wide "$candidate" >"$headers"
readelf --dynamic --wide "$candidate" >"$dynamic" || true
readelf --relocs --wide "$candidate" >"$relocs"
objdump -d "$candidate" >"$disassembly"
for symbol in __errno_location __strtod_l __strtof_l __strtold_l atof ecvt fcvt gcvt getsubopt \
    strtod strtod_l strtof strtof_l strtold strtold_l wcstod wcstof wcstoimax wcstol \
    wcstold wcstoll wcstoul wcstoull wcstoumax fegetround fesetround fegetenv fesetenv \
    feraiseexcept; do
    grep -Eq "[[:space:]]${symbol}$" "$symbols" || fail "candidate lacks ${symbol}"
done
if awk '$7 == "UND" && NF >= 8 { print }' "$symbols" | grep -q .; then
    fail "candidate has unresolved symbols"
fi
if grep -Eq 'Requesting program interpreter|INTERP|NEEDED' "$headers" "$dynamic"; then
    fail "candidate is dynamic"
fi
grep -Eq '[[:space:]]TLS[[:space:]]' "$headers" || fail "candidate lacks the selected errno TLS segment"
assert_fixture_tls_capacity
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
    "$relocs" "$symbols" "$disassembly"; then
    fail "candidate relocations retain a dynamic TLS model"
fi
objdump -d --disassemble=__errno_location "$candidate" >"$errno_disassembly"
grep -Eq '%fs:0x0|%fs:-' "$errno_disassembly" ||
    fail "candidate errno does not use direct fs initial TLS"
objdump -d --disassemble=strtof --disassemble=strtod --disassemble=strtold \
    --disassemble=strtod_l --disassemble=wcstod --disassemble=wcstold \
    --disassemble=ecvt --disassemble=fcvt --disassemble=gcvt \
    --disassemble=atof "$candidate" >"$parser_disassembly"
if grep -Eq 'malloc|calloc|realloc|free|sprintf|snprintf|printf|fprintf|__floatscan|__intscan|__strtod_internal|__strtof_internal|__strtold_internal|crabc_core|mimalloc|sha_crypt' \
    "$symbols" "$disassembly" "$parser_disassembly"; then
    fail "candidate selects allocation, wide/locale/internal conversion, or an unowned runtime dependency"
fi
for helper in crabc_x86_float_parse_floatscan crabc_x86_float_parse_fmodl; do
    grep -Eq "[[:space:]][tT][[:space:]]${helper}$" "$archive_symbols" ||
        fail "archive lacks the private source-faithful ${helper} helper"
done
for instruction in fldt fstpt fprem; do
    grep -Eq "[[:space:]]${instruction}([[:space:]]|$)" "$disassembly" ||
        fail "candidate lacks the source-faithful x87 ${instruction} parser path"
done
if "$candidate"; then
    :
else
    status=$?
    fail "freestanding floating-conversion fixture failed with status ${status}"
fi
printf 'x86 static libc floating/locale conversion: PASS\n'
