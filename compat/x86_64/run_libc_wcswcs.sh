#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc wcswcs evidence.
#
# One project-header C fixture first runs against pinned musl 1.2.6 and then
# as a true `-nostdlib -static` executable linked through the selected
# archive. The candidate extracts exactly the one-export local wide-search
# leaf, not the established broad wide-character, locale, or conversion block.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly EXECUTION_TIMEOUT=20s

fail() {
    printf 'ERROR: x86 static libc wcswcs: %s\n' "$*" >&2
    exit 1
}

require_tool() {
    command -v "$1" >/dev/null 2>&1 || fail "requires $1"
}

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

assert_static_closure() {
    local candidate_path="$1"

    readelf --symbols --wide "$candidate_path" >"$symbols"
    readelf --program-headers --wide "$candidate_path" >"$headers"
    readelf --dynamic --wide "$candidate_path" >"$dynamic" || true
    readelf --relocs --wide "$candidate_path" >"$relocs"
    objdump -d "$candidate_path" >"$disassembly"
    objdump -d --disassemble=wcswcs "$candidate_path" >"$wcswcs_disassembly"
    if awk '$7 == "UND" && NF >= 8 { print }' "$symbols" | grep -q .; then
        fail "candidate has unresolved symbols"
    fi
    if grep -Eq 'Requesting program interpreter|INTERP|NEEDED' "$headers" "$dynamic"; then
        fail "candidate is dynamic"
    fi
    if grep -Eq '[[:space:]]TLS[[:space:]]|TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
        "$headers" "$relocs" "$symbols" "$disassembly"; then
        fail "wcswcs candidate unexpectedly retains TLS"
    fi
    if grep -Eq 'crabc_core|mimalloc|sha_crypt|__errno_location' \
        "$symbols" "$disassembly"; then
        fail "candidate selects an unowned runtime dependency"
    fi
    if grep -Eq 'panic_(bounds_check|nounwind)|rust_begin_unwind|core9panicking' \
        "$symbols" "$disassembly"; then
        fail "candidate selects Rust panic machinery"
    fi
    if grep -Eq '[[:space:]]syscall([[:space:]]|$)' "$wcswcs_disassembly"; then
        fail "wcswcs unexpectedly performs a syscall"
    fi
    # The entry shim has one exit syscall. A second syscall would be selected
    # by this pure wide-substring leaf, which has no kernel boundary.
    local syscall_count
    syscall_count="$(grep -Ec '[[:space:]]syscall([[:space:]]|$)' "$disassembly" || true)"
    [ "$syscall_count" -eq 1 ] ||
        fail "wcswcs candidate contains a syscall outside the test entry shim"
}

assert_candidate_excludes_broad_wide_text() {
    local symbol

    for symbol in wcsstr wcslen wcsnlen wcschr wcsrchr wcscmp wcsncmp \
        wcscasecmp wcsncasecmp wcscoll wcsxfrm wcsdup wcstok wmemchr wmemcmp \
        wmemcpy wmemmove wmemset mbrtowc wcrtomb mbsrtowcs wcsrtombs \
        setlocale iswalpha towlower; do
        if awk -v symbol="$symbol" '$8 == symbol { found = 1 } END { exit !found }' \
            "$symbols"; then
            fail "candidate accidentally selects ${symbol}"
        fi
    done
    if grep -Eq '(<(wcsstr|wcslen|wcschr|wcsrchr|wcscasecmp|wcsncasecmp|wmemchr|wmemcmp|mbrtowc|wcrtomb|setlocale)>)' \
        "$disassembly"; then
        fail "wcswcs implementation retains a broad wide-text helper"
    fi
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "requires native x86-64" ;; esac
for tool in ar awk cargo cmp diff grep mkdir nm objdump readelf rustup sort timeout; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_wcswcs_header_abi.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-wcswcs.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
target_dir="$work_dir/cargo-target"
archive="$target_dir/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-wcswcs-reference"
candidate="$work_dir/crabc-static-wcswcs-candidate"
trace="$work_dir/header-trace"; archive_symbols="$work_dir/archive-symbols"
selected_symbols="$work_dir/selected-c-abi-symbols"; expected_symbols="$work_dir/expected-c-abi-symbols"
symbols="$work_dir/candidate-symbols"; headers="$work_dir/candidate-program-headers"
dynamic="$work_dir/candidate-dynamic"; relocs="$work_dir/candidate-relocations"
disassembly="$work_dir/candidate-disassembly"; wcswcs_disassembly="$work_dir/wcswcs-disassembly"
cd "$ROOT_DIR"

"$ORACLE_CC" -std=c11 -I "$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_wcswcs_probe.c >/dev/null 2>"$trace"
for header in wchar.h features.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$trace" ||
        fail "fixture did not use project $header"
done
"$ORACLE_CC" -std=c11 -fno-builtin -fno-stack-protector \
    -I "$ROOT_DIR/include" compat/x86_64/libc_wcswcs_probe.c \
    -o "$reference"
timeout "$EXECUTION_TIMEOUT" "$reference" ||
    fail "pinned-musl wcswcs fixture failed"

CARGO_TARGET_DIR="$target_dir" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"
nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_symbols" "$expected_symbols"
grep -Eq "[[:space:]][TW][[:space:]]wcswcs$" "$archive_symbols" ||
    fail "archive does not define wcswcs"

"$ORACLE_CC" -std=c11 -DCRABC_WCSWCS_FREESTANDING -I "$ROOT_DIR/include" \
    -nostdlib -static -fno-pie -no-pie -ffreestanding -fno-builtin \
    -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    compat/x86_64/libc_wcswcs_probe.c \
    compat/x86_64/libc_wcswcs_start.S "$archive" -o "$candidate"
assert_static_closure "$candidate"
grep -Eq '[[:space:]]wcswcs$' "$symbols" ||
    fail "candidate lacks wcswcs"
assert_candidate_excludes_broad_wide_text
timeout "$EXECUTION_TIMEOUT" "$candidate" ||
    fail "freestanding wcswcs fixture failed"

printf 'x86 static libc wcswcs: PASS\n'
