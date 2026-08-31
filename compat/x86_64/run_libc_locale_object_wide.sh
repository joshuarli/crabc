#!/usr/bin/env bash
# Native Linux/x86-64 immutable locale-object and localized-wide evidence.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly -a SELECTED_SYMBOLS=(
    newlocale freelocale uselocale duplocale nl_langinfo nl_langinfo_l
    iswalnum_l iswalpha_l iswblank_l iswcntrl_l iswdigit_l iswgraph_l
    iswlower_l iswprint_l iswpunct_l iswspace_l iswupper_l iswxdigit_l
    iswctype_l wctype_l towlower_l towupper_l towctrans_l wctrans_l
    wcscasecmp_l wcsncasecmp_l wcscoll_l wcsxfrm_l
)

fail() { printf 'ERROR: x86 static libc locale-object/localized-wide: %s\n' "$*" >&2; exit 1; }
require_tool() { command -v "$1" >/dev/null 2>&1 || fail "requires $1"; }

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
for tool in ar awk cargo cmp diff grep mkdir mktemp nm objdump readelf rustup sort wc; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_locale_object_wide_header_abi.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-locale-object-wide.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
target_dir="$work_dir/cargo-target"
archive="$target_dir/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-locale-object-wide-reference"
candidate="$work_dir/crabc-static-locale-object-wide-candidate"
reference_output="$work_dir/reference-fingerprint"
candidate_output="$work_dir/candidate-fingerprint"
trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
archive_relocations="$work_dir/archive-relocations"
selected_symbols="$work_dir/selected-c-abi-symbols"
expected_symbols="$work_dir/expected-c-abi-symbols"
symbols="$work_dir/candidate-symbols"
headers="$work_dir/candidate-program-headers"
dynamic="$work_dir/candidate-dynamic"
relocations="$work_dir/candidate-relocations"
disassembly="$work_dir/candidate-disassembly"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_XOPEN_SOURCE=700 -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_locale_object_wide_probe.c >/dev/null 2>"$trace"
for header in errno.h langinfo.h locale.h pthread.h stdlib.h string.h unistd.h wchar.h \
    wctype.h features.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$trace" ||
        fail "fixture did not use project $header"
done
"$ORACLE_CC" -std=c11 -D_XOPEN_SOURCE=700 -pthread -fno-builtin \
    -fno-stack-protector -I"$ROOT_DIR/include" \
    compat/x86_64/libc_locale_object_wide_probe.c -o "$reference"
if "$reference" >"$reference_output"; then :; else
    status=$?; fail "pinned-musl locale-object fixture failed with status $status"
fi
[ "$(wc -c <"$reference_output")" -eq 8 ] ||
    fail "pinned-musl fixture did not emit one localized-wide fingerprint"

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
for unselected in mbsnrtowcs wcsnrtombs strcoll_l strxfrm_l strcasecmp_l \
    strncasecmp_l wcstod_l strftime_l wcsftime_l fwide fgetwc fputwc \
    malloc calloc realloc free; do
    if grep -Eq "[[:space:]][TW][[:space:]]${unselected}$" "$archive_symbols"; then
        fail "archive accidentally exports unselected $unselected"
    fi
done
readelf --relocs --wide "$archive" >"$archive_relocations"
grep -Eq 'R_X86_64_TPOFF(32|64)?' "$archive_relocations" ||
    fail "archive locale selection lacks direct initial-TLS relocation"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|__tls_get_addr' \
    "$archive_relocations"; then
    fail "archive selects dynamic TLS"
fi
for snippet in '9fa28ece75d8a2191de7c5bb53bed224c5947417' \
    'built-ins reuse their token' \
    'No locale map, environment lookup, allocation'; do
    grep -Fq "$snippet" libc/src/c_abi/x86_64/locale_objects.rs ||
        fail "implementation omits provenance boundary $snippet"
done

"$ORACLE_CC" -std=c11 -D_XOPEN_SOURCE=700 \
    -DCRABC_LOCALE_OBJECT_WIDE_FREESTANDING \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    compat/x86_64/libc_locale_object_wide_probe.c \
    compat/x86_64/libc_locale_object_wide_start.S "$archive" -o "$candidate"
readelf --symbols --wide "$candidate" >"$symbols"
readelf --program-headers --wide "$candidate" >"$headers"
readelf --dynamic --wide "$candidate" >"$dynamic" || true
readelf --relocs --wide "$candidate" >"$relocations"
objdump -d "$candidate" >"$disassembly"
for symbol in __crabc_x86_static_tls_bootstrap pthread_create pthread_join \
    setlocale mbrtowc __ctype_get_mb_cur_max write "${SELECTED_SYMBOLS[@]}"; do
    grep -Eq "[[:space:]]${symbol}$" "$symbols" || fail "candidate lacks $symbol"
done
if awk '$7 == "UND" && NF >= 8 { print }' "$symbols" | grep -q .; then
    fail "candidate has unresolved symbols"
fi
if grep -Eq 'Requesting program interpreter|INTERP|NEEDED' "$headers" "$dynamic"; then
    fail "candidate is dynamic"
fi
grep -Eq '[[:space:]]TLS[[:space:]]' "$headers" || fail "candidate lacks PT_TLS"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
    "$relocations" "$symbols" "$disassembly"; then
    fail "candidate retains a dynamic TLS model"
fi
if grep -Eq 'mimalloc|sha_crypt|malloc|calloc|realloc|strtod_l|wcstod_l|fgetwc|fputwc' \
    "$symbols" "$disassembly"; then
    fail "candidate selects allocation, localized numeric parse, or wide stdio"
fi
if "$candidate" >"$candidate_output"; then :; else
    status=$?; fail "freestanding locale-object fixture failed with status $status"
fi
[ "$(wc -c <"$candidate_output")" -eq 8 ] ||
    fail "candidate did not emit one localized-wide fingerprint"
cmp "$reference_output" "$candidate_output" ||
    fail "localized-wide fingerprint differs from pinned musl"
printf 'x86 static libc built-in locale objects/localized wide: PASS\n'
