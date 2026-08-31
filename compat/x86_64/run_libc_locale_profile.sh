#!/usr/bin/env bash
# Native Linux/x86-64 selected static C fixed-locale-profile evidence.
#
# The project-header fixture first executes against pinned musl 1.2.6, then
# links as a true -nostdlib/-static candidate through the selected x86
# crabc-libc archive. It proves only fixed C/POSIX/C.UTF-8 `setlocale` state
# and musl's immutable POSIX `localeconv` record. The candidate deliberately
# has no TLS, environment lookup, allocation, locale-object, conversion,
# collation, iconv, gettext, numeric, time, or stdio dependency; it does not
# select a general locale database, a runtime, CRT, loader, or public x86
# support.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly -a SELECTED_SYMBOLS=(setlocale localeconv)

fail() {
    printf 'ERROR: x86 static libc fixed locale profile: %s\n' "$*" >&2
    exit 1
}

require_tool() {
    command -v "$1" >/dev/null 2>&1 || fail "requires $1"
}

assert_selected_c_abi_surface() {
    local archive_path="$1"
    local symbols_path="$2"
    local expected_path="$3"
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

assert_candidate_isolated() {
    local symbol

    for symbol in "${SELECTED_SYMBOLS[@]}"; do
        grep -Eq "[[:space:]]${symbol}$" "$symbols" ||
            fail "candidate lacks $symbol"
    done
    if awk '$7 == "UND" && NF >= 8 { print }' "$symbols" | grep -q .; then
        fail "candidate has unresolved symbols"
    fi
    if grep -Eq 'Requesting program interpreter|INTERP|NEEDED' "$headers" "$dynamic"; then
        fail "candidate is dynamic"
    fi
    if grep -Eq '[[:space:]]TLS[[:space:]]' "$headers"; then
        fail "candidate retains TLS despite the fixed-profile-only boundary"
    fi
    if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
        "$relocations" "$symbols" "$disassembly"; then
        fail "candidate retains a dynamic TLS model"
    fi
    if grep -Eq 'crabc_core|mimalloc|sha_crypt' "$symbols" "$disassembly"; then
        fail "candidate selects an unowned runtime dependency"
    fi
    if grep -Eq '(__ctype_get_mb_cur_max|mblen|mbtowc|wctomb|mbstowcs|wcstombs|btowc|wctob|mbsinit|mbrtowc|wcrtomb|mbrlen|mbsrtowcs|wcsrtombs|mbsnrtowcs|wcsnrtombs|newlocale|duplocale|freelocale|uselocale|strcoll|strxfrm|strfmon|iconv|strtod|wcstod|strftime|wcsftime|fwide|fgetwc|fputwc|malloc|calloc|realloc|free|getenv|setenv|putenv|printf|fprintf|fopen|clock_gettime)(@|$)' \
        "$symbols" "$disassembly"; then
        fail "candidate selects an excluded locale/runtime entry"
    fi
    if grep -Eq 'syscall|malloc|calloc|realloc|free|getenv|setenv|putenv' \
        "$setlocale_disassembly" "$localeconv_disassembly"; then
        fail "selected locale core reaches an excluded implementation boundary"
    fi
}

[ "$#" -eq 0 ] || fail "usage: $0"
[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in
    x86_64|amd64) ;;
    *) fail "requires native x86-64" ;;
esac
for tool in ar awk cargo cmp diff env grep mkdir mktemp nm objdump readelf rustup sort; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -f "$STATIC_C_ABI_EXPORTS" ] || fail "missing static C ABI export contract"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_locale_profile_header_abi.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-locale-profile.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
target_dir="$work_dir/cargo-target"
archive="$target_dir/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-locale-profile-reference"
candidate="$work_dir/crabc-static-locale-profile-candidate"
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
setlocale_disassembly="$work_dir/setlocale-disassembly"
localeconv_disassembly="$work_dir/localeconv-disassembly"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_locale_profile_probe.c >/dev/null 2>"$trace"
for header in limits.h locale.h stddef.h stdint.h features.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$trace" ||
        fail "fixture did not use project $header"
done

"$ORACLE_CC" -std=c11 -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" compat/x86_64/libc_locale_profile_probe.c -o "$reference"
if env -i "$reference" >"$reference_output"; then :; else
    status=$?
    fail "pinned-musl locale-profile fixture exited $status"
fi

CARGO_TARGET_DIR="$target_dir" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"
nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_symbols" "$expected_symbols"
for symbol in "${SELECTED_SYMBOLS[@]}"; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" ||
        fail "archive does not define $symbol"
done

"$ORACLE_CC" -std=c11 -DCRABC_LOCALE_PROFILE_FREESTANDING \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -ffunction-sections -fdata-sections \
    -Wl,--gc-sections -Wl,-e,_start -Wl,--no-undefined \
    compat/x86_64/libc_locale_profile_probe.c \
    compat/x86_64/libc_locale_profile_start.S "$archive" -o "$candidate"

readelf --symbols --wide "$candidate" >"$symbols"
readelf --program-headers --wide "$candidate" >"$headers"
readelf --dynamic --wide "$candidate" >"$dynamic" || true
readelf --relocs --wide "$candidate" >"$relocations"
objdump -d "$candidate" >"$disassembly"
objdump -d --disassemble=setlocale "$candidate" >"$setlocale_disassembly"
objdump -d --disassemble=localeconv "$candidate" >"$localeconv_disassembly"
assert_candidate_isolated

if env -i "$candidate" >"$candidate_output"; then :; else
    status=$?
    fail "freestanding locale-profile fixture exited $status"
fi
if ! cmp -s "$reference_output" "$candidate_output"; then
    diff -u "$reference_output" "$candidate_output" >&2 || true
    fail "candidate output differs from pinned musl"
fi
grep -Eq '^locale-profile-fnv1a64=[0-9a-f]{16}$' "$candidate_output" ||
    fail "candidate lacks the complete fixed-locale digest"

printf 'x86 static crabc-libc fixed locale profile: PASS\n'
