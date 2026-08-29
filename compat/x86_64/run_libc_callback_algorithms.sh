#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc callback-algorithms evidence.
#
# One GNU-enabled project-header fixture first runs against pinned musl, then
# as a true `-nostdlib -static` executable linked through the selected archive.
# It proves only bsearch, qsort, GNU/BSD qsort_r, and musl's private
# __qsort_r helper: callback ABI, smoothsort's wide-record cycle, and musl's
# same-address weak qsort_r alias without an errno, TLS, allocator, or syscall
# dependency.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"

fail() { printf 'ERROR: x86 static libc callback algorithms: %s\n' "$*" >&2; exit 1; }
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

assert_static_closure() {
    local candidate_path="$1" label="$2"
    local symbols_path="$work_dir/${label}-symbols"
    local headers_path="$work_dir/${label}-program-headers"
    local dynamic_path="$work_dir/${label}-dynamic"
    local relocs_path="$work_dir/${label}-relocations"
    local disassembly_path="$work_dir/${label}-disassembly"

    readelf --symbols --wide "$candidate_path" >"$symbols_path"
    readelf --program-headers --wide "$candidate_path" >"$headers_path"
    readelf --dynamic --wide "$candidate_path" >"$dynamic_path" || true
    readelf --relocs --wide "$candidate_path" >"$relocs_path"
    objdump -d "$candidate_path" >"$disassembly_path"
    if awk '$7 == "UND" && NF >= 8 { print }' "$symbols_path" | grep -q .; then
        fail "${label} has unresolved symbols"
    fi
    if grep -Eq 'Requesting program interpreter|INTERP|NEEDED' "$headers_path" "$dynamic_path"; then
        fail "${label} is dynamic"
    fi
    if grep -Eq '[[:space:]]TLS[[:space:]]|TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
        "$headers_path" "$relocs_path" "$symbols_path" "$disassembly_path"; then
        fail "${label} unexpectedly selects TLS"
    fi
    if grep -Eq 'crabc_core|mimalloc|sha_crypt|__errno_location' \
        "$symbols_path" "$disassembly_path"; then
        fail "${label} selects an unowned runtime dependency"
    fi
    if grep -Eq 'panic_(bounds_check|nounwind)|rust_begin_unwind|core9panicking' \
        "$symbols_path" "$disassembly_path"; then
        fail "${label} selects Rust panic machinery"
    fi
}

assert_musl_weak_alias() {
    local symbols_path="$1" label="$2"
    local alias_value helper_value

    alias_value="$(awk '$8 == "qsort_r" && $5 == "WEAK" && $7 != "UND" { print $2; exit }' "$symbols_path")"
    helper_value="$(awk '$8 == "__qsort_r" && $5 == "GLOBAL" && $7 != "UND" { print $2; exit }' "$symbols_path")"
    [ -n "$alias_value" ] || fail "${label} lacks a weak qsort_r symbol"
    [ -n "$helper_value" ] || fail "${label} lacks a strong __qsort_r symbol"
    [ "$alias_value" = "$helper_value" ] \
        || fail "${label} qsort_r is not the musl same-address weak alias"
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "requires native x86-64" ;; esac
for tool in ar cargo cmp diff grep nm objdump readelf rustup sort; do require_tool "$tool"; done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-callback-algorithms.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
target_dir="$work_dir/cargo-target"; archive="$target_dir/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-callback-algorithms-reference"
candidate="$work_dir/crabc-static-callback-algorithms-candidate"
candidate_override="$work_dir/crabc-static-callback-algorithms-override-candidate"
trace="$work_dir/header-trace"; archive_symbols="$work_dir/archive-symbols"
selected_symbols="$work_dir/selected-c-abi-symbols"; expected_symbols="$work_dir/expected-c-abi-symbols"
cd "$ROOT_DIR"

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_callback_algorithms_probe.c >/dev/null 2>"$trace"
for header in stddef.h stdint.h stdlib.h features.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$trace" \
        || fail "fixture did not use the project $header header"
done
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" compat/x86_64/libc_callback_algorithms_probe.c -o "$reference"
"$reference" || fail "pinned-musl callback-algorithms fixture failed"

CARGO_TARGET_DIR="$target_dir" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"
nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_symbols" "$expected_symbols"
for symbol in bsearch __qsort_r qsort; do
    grep -Eq "[[:space:]]T[[:space:]]${symbol}$" "$archive_symbols" \
        || fail "archive does not strongly define ${symbol}"
done
grep -Eq '[[:space:]]W[[:space:]]qsort_r$' "$archive_symbols" \
    || fail "archive does not weakly define qsort_r"
if grep -Eq '[[:space:]]T[[:space:]]qsort_r$' "$archive_symbols"; then
    fail "archive uses a qsort_r wrapper instead of musl's weak alias"
fi
for unselected in lfind lsearch tsearch tfind tdelete twalk hsearch hcreate hdestroy \
    btree_insert malloc calloc realloc free; do
    if grep -Eq "[[:space:]][TW][[:space:]]${unselected}$" "$archive_symbols"; then
        fail "archive accidentally exports unselected ${unselected}"
    fi
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_CALLBACK_ALGORITHMS_FREESTANDING \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    compat/x86_64/libc_callback_algorithms_probe.c \
    compat/x86_64/libc_callback_algorithms_start.S "$archive" -o "$candidate"
assert_static_closure "$candidate" candidate
candidate_symbols="$work_dir/candidate-symbols"
for symbol in bsearch __qsort_r qsort qsort_r; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" \
        || fail "candidate lacks ${symbol}"
done
assert_musl_weak_alias "$candidate_symbols" candidate
for symbol in bsearch __qsort_r qsort; do
    objdump -d --disassemble="$symbol" "$candidate" >>"$work_dir/callback-algorithms-functions"
done
if grep -Eq '[[:space:]]syscall([[:space:]]|$)' "$work_dir/callback-algorithms-functions"; then
    fail "callback-algorithms implementation emits a syscall"
fi
"$candidate" || fail "freestanding callback-algorithms fixture failed"

# A caller's strong qsort_r must override the archive's weak alias while a
# qsort reference still extracts the same object. This catches a separate
# strong Rust wrapper even if the normal fixture happens to sort correctly.
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_CALLBACK_ALGORITHMS_FREESTANDING \
    -DCRABC_CALLBACK_ALGORITHMS_OVERRIDE_QSORT_R -I"$ROOT_DIR/include" \
    -nostdlib -static -fno-pie -no-pie -ffreestanding -fno-builtin \
    -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    compat/x86_64/libc_callback_algorithms_probe.c \
    compat/x86_64/libc_callback_algorithms_start.S "$archive" -o "$candidate_override"
assert_static_closure "$candidate_override" candidate-override
override_symbols="$work_dir/candidate-override-symbols"
grep -Eq '[[:space:]]GLOBAL[[:space:]].*[[:space:]]qsort_r$' "$override_symbols" \
    || fail "strong caller qsort_r did not override the archive weak alias"
"$candidate_override" || fail "freestanding qsort_r override fixture failed"

printf 'x86 static libc callback algorithms: PASS\n'
