#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc ctype evidence.
#
# The project-header fixture first runs against pinned musl 1.2.6, then as a
# true -nostdlib/-static executable linked only with the selected archive.
# Its closed public surface is the sixteen fixed-C-locale ctype entries.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"

fail() { printf 'ERROR: x86 static libc ctype: %s\n' "$*" >&2; exit 1; }
require_tool() { command -v "$1" >/dev/null 2>&1 || fail "requires $1"; }

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
    ) | awk '$2 ~ /^[TWDVBR]$/ && $1 !~ /^(_R|_ZN|DW\.ref\.|anon\.)/ && $1 != "crabc_x86_64_signal_restorer" { print $1 }' |
        sort -u >"$symbols_path"
    [ -f "$STATIC_C_ABI_EXPORTS" ] || fail "missing static C ABI export contract"
    grep -Ev '^(#|$)' "$STATIC_C_ABI_EXPORTS" | LC_ALL=C sort -u >"$expected_path"
    if ! cmp -s "$expected_path" "$symbols_path"; then
        diff -u "$expected_path" "$symbols_path" >&2 || true
        fail "selected static C ABI export surface drifted"
    fi
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "requires native x86-64" ;; esac
for tool in ar cargo cmp diff grep nm objdump readelf rustup sort; do require_tool "$tool"; done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-ctype.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
target_dir="$work_dir/cargo-target"
archive="$target_dir/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-ctype-reference"
candidate="$work_dir/crabc-static-ctype-candidate"
trace="$work_dir/header-trace"
selected_c_abi_symbols="$work_dir/selected-c-abi-symbols"
expected_c_abi_symbols="$work_dir/expected-c-abi-symbols"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_ctype_probe.c >/dev/null 2>"$trace"
grep -Fq "$ROOT_DIR/include/ctype.h" "$trace" || fail "fixture did not use project ctype.h"
grep -Fq "$ROOT_DIR/include/features.h" "$trace" || fail "fixture did not use project features.h"

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" compat/x86_64/libc_ctype_probe.c -o "$reference"
"$reference" || fail "pinned-musl ctype fixture exited $?"

CARGO_TARGET_DIR="$target_dir" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- -C relocation-model=static \
    -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"
archive_symbols="$work_dir/archive-symbols"
nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_c_abi_symbols" \
    "$expected_c_abi_symbols"
for symbol in isalnum isalpha isblank iscntrl isdigit isgraph islower isprint \
    ispunct isspace isupper isxdigit tolower toupper isascii toascii; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" ||
        fail "archive does not define $symbol"
done
for unselected in isalnum_l isalpha_l isblank_l iscntrl_l isdigit_l isgraph_l \
    islower_l isprint_l ispunct_l isspace_l isupper_l isxdigit_l tolower_l \
    toupper_l iswalpha iswalnum iswblank iswcntrl iswdigit iswgraph iswlower \
    iswprint iswpunct iswspace iswupper iswxdigit strcasecmp strncasecmp \
    strcoll strxfrm malloc free calloc realloc; do
    if grep -Eq "[[:space:]][TW][[:space:]]${unselected}$" "$archive_symbols"; then
        fail "archive accidentally exports unselected $unselected"
    fi
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_CTYPE_FREESTANDING \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    compat/x86_64/libc_ctype_probe.c compat/x86_64/libc_ctype_start.S \
    "$archive" -o "$candidate"
symbols="$work_dir/candidate-symbols"
headers="$work_dir/candidate-program-headers"
dynamic="$work_dir/candidate-dynamic"
relocs="$work_dir/candidate-relocations"
disassembly="$work_dir/candidate-disassembly"
readelf --symbols --wide "$candidate" >"$symbols"
readelf --program-headers --wide "$candidate" >"$headers"
readelf --dynamic --wide "$candidate" >"$dynamic" || true
readelf --relocs --wide "$candidate" >"$relocs"
objdump -d "$candidate" >"$disassembly"
for symbol in isalnum isalpha isblank iscntrl isdigit isgraph islower isprint \
    ispunct isspace isupper isxdigit tolower toupper isascii toascii; do
    grep -Eq "[[:space:]]${symbol}$" "$symbols" || fail "candidate lacks $symbol"
done
awk '$7 == "UND" && NF >= 8 { print }' "$symbols" | grep -q . && fail "candidate has unresolved symbols" || true
grep -Eq 'Requesting program interpreter|INTERP|NEEDED' "$headers" "$dynamic" && fail "candidate is dynamic"
grep -Eq '[[:space:]]TLS[[:space:]]|TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
    "$headers" "$relocs" "$symbols" "$disassembly" && fail "candidate retains TLS" || true
grep -Eq 'crabc_core|mimalloc|sha_crypt|_l$|isw' "$symbols" "$disassembly" && fail "candidate selects unowned ctype/runtime symbols" || true
"$candidate" || fail "freestanding ctype fixture exited $?"
printf 'x86 static libc ctype: PASS\n'
