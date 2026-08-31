#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc lfind/lsearch evidence.
#
# One project-header C fixture first runs against pinned musl 1.2.6 and then
# as a true `-nostdlib -static` executable linked through the selected archive.
# The candidate must extract exactly the paired linear-search leaf, not binary
# lookup, sorting, search containers, byte-copy helpers, or runtime state.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"

fail() {
    printf 'ERROR: x86 static libc linear search: %s\n' "$*" >&2
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
    objdump -d --disassemble=lfind "$candidate_path" >"$lfind_disassembly"
    objdump -d --disassemble=lsearch "$candidate_path" >"$lsearch_disassembly"
    if awk '$7 == "UND" && NF >= 8 { print }' "$symbols" | grep -q .; then
        fail "candidate has unresolved symbols"
    fi
    if grep -Eq 'Requesting program interpreter|INTERP|NEEDED' "$headers" "$dynamic"; then
        fail "candidate is dynamic"
    fi
    if grep -Eq '[[:space:]]TLS[[:space:]]|TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
        "$headers" "$relocs" "$symbols" "$disassembly"; then
        fail "linear-search candidate unexpectedly retains TLS"
    fi
    if grep -Eq 'crabc_core|mimalloc|sha_crypt|__errno_location' \
        "$symbols" "$disassembly"; then
        fail "candidate selects an unowned runtime dependency"
    fi
    if grep -Eq 'panic_(bounds_check|nounwind)|rust_begin_unwind|core9panicking' \
        "$symbols" "$disassembly"; then
        fail "candidate selects Rust panic machinery"
    fi
    if grep -Eq '[[:space:]]syscall([[:space:]]|$)' \
        "$lfind_disassembly" "$lsearch_disassembly"; then
        fail "linear search unexpectedly performs a syscall"
    fi
    # The entry shim has one exit syscall. A second syscall would be selected
    # by lfind or lsearch, which has no kernel boundary.
    local syscall_count
    syscall_count="$(grep -Ec '[[:space:]]syscall([[:space:]]|$)' "$disassembly" || true)"
    [ "$syscall_count" -eq 1 ] ||
        fail "linear-search candidate contains a syscall outside the test entry shim"
}

assert_candidate_excludes_unowned_algorithms() {
    local symbol

    for symbol in bsearch __qsort_r qsort qsort_r tdelete tdestroy tfind \
        tsearch twalk __tsearch_balance hcreate hcreate_r hdestroy hdestroy_r \
        hsearch hsearch_r memcpy memmove; do
        if awk -v symbol="$symbol" '$8 == symbol { found = 1 } END { exit !found }' \
            "$symbols"; then
            fail "candidate accidentally selects ${symbol}"
        fi
    done
    if grep -Eq '(<(bsearch|__qsort_r|qsort|qsort_r|tdelete|tfind|tsearch|hsearch|memcpy|memmove)>)' \
        "$disassembly"; then
        fail "linear-search implementation retains an unrelated helper"
    fi
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "requires native x86-64" ;; esac
for tool in ar awk cargo cmp diff grep mkdir nm objdump readelf rustup sort; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_linear_search_header_abi.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-linear-search.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
target_dir="$work_dir/cargo-target"
archive="$target_dir/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-linear-search-reference"
candidate="$work_dir/crabc-static-linear-search-candidate"
trace="$work_dir/header-trace"; archive_symbols="$work_dir/archive-symbols"
selected_symbols="$work_dir/selected-c-abi-symbols"; expected_symbols="$work_dir/expected-c-abi-symbols"
symbols="$work_dir/candidate-symbols"; headers="$work_dir/candidate-program-headers"
dynamic="$work_dir/candidate-dynamic"; relocs="$work_dir/candidate-relocations"
disassembly="$work_dir/candidate-disassembly"; lfind_disassembly="$work_dir/lfind-disassembly"
lsearch_disassembly="$work_dir/lsearch-disassembly"
cd "$ROOT_DIR"

"$ORACLE_CC" -std=c11 -I "$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_linear_search_probe.c >/dev/null 2>"$trace"
for header in stddef.h search.h features.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$trace" ||
        fail "fixture did not use project $header"
done
"$ORACLE_CC" -std=c11 -fno-builtin -fno-stack-protector \
    -I "$ROOT_DIR/include" compat/x86_64/libc_linear_search_probe.c \
    -o "$reference"
"$reference" || fail "pinned-musl linear-search fixture failed"

CARGO_TARGET_DIR="$target_dir" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"
nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_symbols" "$expected_symbols"
for symbol in lfind lsearch; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" ||
        fail "archive does not define ${symbol}"
done

"$ORACLE_CC" -std=c11 -DCRABC_LINEAR_SEARCH_FREESTANDING -I "$ROOT_DIR/include" \
    -nostdlib -static -fno-pie -no-pie -ffreestanding -fno-builtin \
    -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    compat/x86_64/libc_linear_search_probe.c \
    compat/x86_64/libc_linear_search_start.S "$archive" -o "$candidate"
assert_static_closure "$candidate"
for symbol in lfind lsearch; do
    grep -Eq "[[:space:]]${symbol}$" "$symbols" ||
        fail "candidate lacks ${symbol}"
done
assert_candidate_excludes_unowned_algorithms
"$candidate" || fail "freestanding linear-search fixture failed"

printf 'x86 static libc lfind/lsearch: PASS\n'
