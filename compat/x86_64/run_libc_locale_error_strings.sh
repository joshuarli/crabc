#!/usr/bin/env bash
# Native Linux/x86-64 fixed-profile locale-error-string evidence.
#
# The same project-header fixture runs first through pinned musl 1.2.6 and
# then through a true -nostdlib/-static executable. It proves musl's strong
# __strerror_l plus weak same-address strerror_l ABI, every defined nonnegative
# x86 errno table index through one past the table, and C/POSIX/C.UTF-8
# locale-object behavior under selected-thread/global-following modes without
# selecting message catalogs or a locale database.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly -a SELECTED_SYMBOLS=(__strerror_l strerror_l)

fail() {
    printf 'ERROR: x86 static libc locale error strings: %s\n' "$*" >&2
    exit 1
}

require_tool() {
    command -v "$1" >/dev/null 2>&1 || fail "requires $1"
}

assert_selected_c_abi_surface() {
    local archive_path="$1" symbols_path="$2" expected_path="$3"
    local members_path="$work_dir/selected-c-abi-members"
    local -a members
    mapfile -t members < <(ar t "$archive_path" | grep -E '^c\..+\.rcgu\.o$')
    [ "${#members[@]}" -gt 0 ] || fail "archive has no crabc-libc object members"
    mkdir "$members_path"
    (
        cd "$members_path"
        ar x "$archive_path" "${members[@]}"
        nm -g --defined-only --format=posix "${members[@]}"
    ) | awk '$2 ~ /^[TWDVBR]$/ && $1 !~ /^(_R|_ZN|DW\.ref\.|anon\.)/ && $1 != "crabc_x86_64_signal_restorer" && $1 != "__crabc_x86_pthread_clone" { print $1 }' |
        sort -u >"$symbols_path"
    grep -Ev '^(#|$)' "$STATIC_C_ABI_EXPORTS" | LC_ALL=C sort -u >"$expected_path"
    if ! cmp -s "$expected_path" "$symbols_path"; then
        diff -u "$expected_path" "$symbols_path" >&2 || true
        fail "selected static C ABI export surface drifted"
    fi
}

[ "$#" -eq 0 ] || fail "usage: $0"
[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "requires native x86-64" ;; esac
for tool in ar awk cargo cmp diff grep mkdir mktemp nm objdump readelf rustup sort; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -f "$STATIC_C_ABI_EXPORTS" ] || fail "missing static C ABI export contract"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_error_strings_header_abi.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-locale-error-strings.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
target_dir="$work_dir/cargo-target"
archive="$target_dir/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-locale-error-strings-reference"
candidate="$work_dir/crabc-static-locale-error-strings-candidate"
reference_output="$work_dir/reference-output"
candidate_output="$work_dir/candidate-output"
trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
selected_symbols="$work_dir/selected-c-abi-symbols"
expected_symbols="$work_dir/expected-c-abi-symbols"
symbols="$work_dir/candidate-symbols"
headers="$work_dir/candidate-program-headers"
dynamic="$work_dir/candidate-dynamic"
relocations="$work_dir/candidate-relocations"
disassembly="$work_dir/candidate-disassembly"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_XOPEN_SOURCE=700 -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_locale_error_strings_probe.c >/dev/null 2>"$trace"
for header in errno.h locale.h stdint.h string.h features.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$trace" ||
        fail "fixture did not use the project $header header"
done
"$ORACLE_CC" -std=c11 -D_XOPEN_SOURCE=700 -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" compat/x86_64/libc_locale_error_strings_probe.c \
    -o "$reference"
if env -i "$reference" >"$reference_output"; then :; else
    status=$?
    fail "pinned-musl locale-error-string fixture exited $status"
fi

CARGO_TARGET_DIR="$target_dir" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"
nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_symbols" "$expected_symbols"
grep -Eq '[[:space:]]T[[:space:]]__strerror_l$' "$archive_symbols" ||
    fail "archive does not define strong __strerror_l"
grep -Eq '[[:space:]]W[[:space:]]strerror_l$' "$archive_symbols" ||
    fail "archive does not define weak strerror_l"
for unselected in strfmon strfmon_l mbsnrtowcs wcsnrtombs wcstod_l strftime_l \
    wcsftime_l fwide fgetwc fputwc malloc calloc realloc; do
    if grep -Eq "[[:space:]][TW][[:space:]]${unselected}$" "$archive_symbols"; then
        fail "archive accidentally exports unselected ${unselected}"
    fi
done

"$ORACLE_CC" -std=c11 -D_XOPEN_SOURCE=700 \
    -DCRABC_LOCALE_ERROR_STRINGS_FREESTANDING -I"$ROOT_DIR/include" \
    -nostdlib -static -fno-pie -no-pie -ffreestanding -fno-builtin \
    -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    compat/x86_64/libc_locale_error_strings_probe.c \
    compat/x86_64/libc_locale_error_strings_start.S "$archive" -o "$candidate"

readelf --symbols --wide "$candidate" >"$symbols"
readelf --program-headers --wide "$candidate" >"$headers"
readelf --dynamic --wide "$candidate" >"$dynamic" || true
readelf --relocs --wide "$candidate" >"$relocations"
objdump -d "$candidate" >"$disassembly"
for symbol in __crabc_x86_static_tls_bootstrap strerror __strerror_l strerror_l \
    newlocale freelocale uselocale; do
    grep -Eq "[[:space:]]${symbol}$" "$symbols" || fail "candidate lacks $symbol"
done
internal_value="$(awk '$8 == "__strerror_l" { print $2; exit }' "$symbols")"
public_value="$(awk '$8 == "strerror_l" { print $2; exit }' "$symbols")"
[ -n "$internal_value" ] && [ "$internal_value" = "$public_value" ] ||
    fail "strerror_l is not a same-address __strerror_l alias"
awk '$8 == "strerror_l" && $5 == "WEAK" { found=1 } END { exit !found }' "$symbols" ||
    fail "strerror_l is not weak in final ELF"
if awk '$7 == "UND" && NF >= 8 { print }' "$symbols" | grep -q .; then
    fail "candidate retains an unresolved symbol"
fi
if grep -Eq 'Requesting program interpreter|INTERP|NEEDED' "$headers" "$dynamic"; then
    fail "candidate selects a dynamic dependency"
fi
grep -Eq '[[:space:]]TLS[[:space:]]' "$headers" || fail "candidate lacks PT_TLS"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
    "$relocations" "$symbols" "$disassembly"; then
    fail "candidate retains a dynamic TLS model"
fi
if grep -Eq 'crabc_core|mimalloc|sha_crypt|strfmon|mbsnrtowcs|wcsnrtombs|wcstod_l|strftime_l|wcsftime_l|fgetwc|fputwc' \
    "$symbols" "$disassembly"; then
    fail "candidate selects an excluded locale/runtime dependency"
fi

if env -i "$candidate" >"$candidate_output"; then :; else
    status=$?
    fail "freestanding locale-error-string fixture exited $status"
fi
if ! cmp -s "$reference_output" "$candidate_output"; then
    diff -u "$reference_output" "$candidate_output" >&2 || true
    fail "candidate output differs from pinned musl"
fi
grep -Eq '^locale-error-strings-fnv1a64=[0-9a-f]{16}$' "$candidate_output" ||
    fail "candidate lacks the complete locale/error digest"
grep -Fxq 'strerror-l-alias=weak-same-address' "$candidate_output" ||
    fail "candidate lacks the weak alias witness"
grep -Fxq 'strerror-l-profile=c-posix-cutf8-thread-global' "$candidate_output" ||
    fail "candidate lacks the bounded-profile witness"

printf 'x86 static crabc-libc locale error strings: PASS\n'
