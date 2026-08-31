#!/usr/bin/env bash
# Native Linux/x86-64 selected static C locale/wide/iconv evidence.
#
# The project-header fixture first executes against pinned musl 1.2.6, then
# links as a true -nostdlib/-static candidate through the one selected x86
# crabc-libc archive. It composes the already selected named C/POSIX/C.UTF-8
# locale and ordinary multibyte seam with fixed UTF/ASCII iconv descriptors,
# without selecting locale objects, environment lookup, wide streams, general
# iconv state/codepages, libc.so, a CRT, or public x86 support.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly INITIAL_TLS_BYTES=4096
readonly INITIAL_TLS_ALIGNMENT=64

fail() { printf 'ERROR: x86 static libc locale/wide/iconv: %s\n' "$*" >&2; exit 1; }
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
bash "$ROOT_DIR/compat/x86_64/run_locale_multibyte_header_abi.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_iconv_header_abi.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-locale-wide-iconv.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
target_dir="$work_dir/cargo-target"
archive="$target_dir/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-locale-wide-iconv-reference"
candidate="$work_dir/crabc-static-locale-wide-iconv-candidate"
trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
archive_relocations="$work_dir/archive-relocations"
selected_symbols="$work_dir/selected-c-abi-symbols"
expected_symbols="$work_dir/expected-c-abi-symbols"
symbols="$work_dir/candidate-symbols"
headers="$work_dir/candidate-program-headers"
dynamic="$work_dir/candidate-dynamic"
relocs="$work_dir/candidate-relocations"
disassembly="$work_dir/candidate-disassembly"
errno_disassembly="$work_dir/errno-disassembly"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_locale_wide_iconv_probe.c >/dev/null 2>"$trace"
for header in errno.h iconv.h limits.h locale.h stddef.h stdlib.h wchar.h features.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$trace" ||
        fail "fixture did not use project $header"
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" compat/x86_64/libc_locale_wide_iconv_probe.c -o "$reference"
"$reference" || fail "pinned-musl locale/wide/iconv fixture failed"

CARGO_TARGET_DIR="$target_dir" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"
nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_symbols" "$expected_symbols"

for symbol in __ctype_get_mb_cur_max btowc localeconv mblen mbrlen mbrtowc \
    mbsinit mbsrtowcs mbstowcs mbtowc setlocale wcrtomb wcsrtombs wcstombs \
    wctob wctomb iconv iconv_open iconv_close; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" ||
        fail "archive does not define $symbol"
done
for unselected in newlocale duplocale uselocale freelocale nl_langinfo mbsnrtowcs wcsnrtombs wcsftime_l wcscoll wcscoll_l \
    wcsxfrm wcsxfrm_l fwide fgetwc fputwc iswalpha iswalnum towlower towupper; do
    if grep -Eq "[[:space:]][TW][[:space:]]${unselected}$" "$archive_symbols"; then
        fail "archive accidentally exports unselected $unselected"
    fi
done
readelf --relocs --wide "$archive" >"$archive_relocations"
grep -Eq 'R_X86_64_TPOFF(32|64)?' "$archive_relocations" ||
    fail "archive errno lacks an initial-TLS TPOFF relocation"
# Archive DWARF may use DTPOFF metadata for the selected initial-TLS errno
# symbol; only runtime dynamic-TLS relocation forms are rejected here. The
# final linked executable below rejects DTPOFF as well as all dynamic models.
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|__tls_get_addr' \
    "$archive_relocations"; then
    fail "archive selects dynamic TLS or an unowned runtime dependency"
fi

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_LOCALE_WIDE_ICONV_FREESTANDING \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    compat/x86_64/libc_locale_wide_iconv_probe.c \
    compat/x86_64/libc_locale_wide_iconv_start.S "$archive" -o "$candidate"
readelf --symbols --wide "$candidate" >"$symbols"
readelf --program-headers --wide "$candidate" >"$headers"
readelf --dynamic --wide "$candidate" >"$dynamic" || true
readelf --relocs --wide "$candidate" >"$relocs"
objdump -d "$candidate" >"$disassembly"
for symbol in __ctype_get_mb_cur_max __errno_location btowc localeconv mblen \
    mbrlen mbrtowc mbsinit mbsrtowcs mbstowcs mbtowc setlocale wcrtomb \
    wcsrtombs wcstombs wctob wctomb iconv iconv_open iconv_close; do
    grep -Eq "[[:space:]]${symbol}$" "$symbols" || fail "candidate lacks $symbol"
done
if awk '$7 == "UND" && NF >= 8 { print }' "$symbols" | grep -q .; then
    fail "candidate has unresolved symbols"
fi
if grep -Eq 'Requesting program interpreter|INTERP|NEEDED' "$headers" "$dynamic"; then
    fail "candidate is dynamic"
fi
grep -Eq '[[:space:]]TLS[[:space:]]' "$headers" ||
    fail "candidate lacks the selected errno TLS segment"
assert_fixture_tls_capacity
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
    "$relocs" "$symbols" "$disassembly"; then
    fail "candidate relocations retain a dynamic TLS model"
fi
objdump -d --disassemble=__errno_location "$candidate" >"$errno_disassembly"
grep -Eq '%fs:0x0|%fs:-' "$errno_disassembly" ||
    fail "candidate errno does not use direct fs initial TLS"
if grep -Eq 'crabc_core|mimalloc|sha_crypt|newlocale|uselocale|duplocale|freelocale|malloc|free' \
    "$symbols" "$disassembly"; then
    fail "candidate selects an unowned runtime dependency"
fi
"$candidate" || fail "freestanding locale/wide/iconv fixture failed"
printf 'x86 static libc locale/wide/iconv: PASS\n'
