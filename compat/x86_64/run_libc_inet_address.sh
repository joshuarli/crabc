#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc numeric Internet-address codec evidence.
#
# The project-header fixture first runs against pinned musl 1.2.6, then as a
# `-nostdlib -static` executable linked solely through the selected crabc
# archive. It selects inet_pton, inet_ntop, inet_aton, and inet_addr, with
# musl's hidden __inet_aton/weak inet_aton same-address pair. It deliberately
# excludes DNS/resolver state, netdb, the separate inet_ntoa scratch-buffer
# candidate, allocation,
# stdio, libc.so, CRT, loader, sysroot, and public x86 support.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"

fail() {
    printf 'ERROR: x86 static libc inet address: %s\n' "$*" >&2
    exit 1
}

require_native_linux_x86_64() {
    [ "$(uname -s)" = Linux ] || fail "requires native Linux"
    case "$(uname -m)" in
        x86_64|amd64) ;;
        *) fail "refuses emulation on $(uname -m)" ;;
    esac
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
    [ -f "$STATIC_C_ABI_EXPORTS" ] || fail "missing static C ABI export contract"
    grep -Ev '^(#|$)' "$STATIC_C_ABI_EXPORTS" | LC_ALL=C sort -u >"$expected_path"
    if ! cmp -s "$expected_path" "$symbols_path"; then
        diff -u "$expected_path" "$symbols_path" >&2 || true
        fail "selected static C ABI export surface drifted"
    fi
}

assert_musl_inet_aton_alias() {
    local symbols_path="$1" label="$2"
    local alias_value helper_value

    alias_value="$(awk '$8 == "inet_aton" && $4 == "FUNC" && $5 == "WEAK" && $6 == "DEFAULT" && $7 != "UND" { print $2; exit }' "$symbols_path")"
    helper_value="$(awk '$8 == "__inet_aton" && $4 == "FUNC" && $5 == "GLOBAL" && $6 == "HIDDEN" && $7 != "UND" { print $2; exit }' "$symbols_path")"
    [ -n "$alias_value" ] || fail "$label lacks weak default inet_aton"
    [ -n "$helper_value" ] || fail "$label lacks global hidden __inet_aton"
    [ "$alias_value" = "$helper_value" ] ||
        fail "$label inet_aton/__inet_aton are not a same-address alias pair"
}

require_native_linux_x86_64
for tool in ar cargo cmp diff grep nm objdump readelf rustup sort; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-inet-address.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
cargo_target="$work_dir/cargo-target"
reference="$work_dir/musl-inet-address-reference"
candidate="$work_dir/crabc-static-inet-address-candidate"
archive="$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
musl_archive="$($ORACLE_CC -print-file-name=libc.a)"
musl_members="$work_dir/musl-members"
musl_inet_aton_symbols="$work_dir/musl-inet-aton-symbols"
header_trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
selected_c_abi_symbols="$work_dir/selected-c-abi-symbols"
expected_c_abi_symbols="$work_dir/expected-c-abi-symbols"
archive_relocations="$work_dir/archive-relocations"
candidate_symbols="$work_dir/candidate-symbols"
candidate_program_headers="$work_dir/candidate-program-headers"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"
errno_disassembly="$work_dir/errno-disassembly"

cd "$ROOT_DIR"
case "$musl_archive" in
    /*) ;;
    *) fail "pinned musl compiler did not report an absolute libc.a path" ;;
esac
[ -f "$musl_archive" ] || fail "pinned musl static archive is missing"
mkdir "$musl_members"
(
    cd "$musl_members"
    ar x "$musl_archive" inet_aton.lo
    readelf --symbols --wide inet_aton.lo
) >"$musl_inet_aton_symbols"
assert_musl_inet_aton_alias "$musl_inet_aton_symbols" "pinned-musl static archive"

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_inet_address_probe.c >/dev/null 2>"$header_trace"
for header in arpa/inet.h errno.h netinet/in.h stddef.h stdint.h sys/socket.h \
    sys/types.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture did not use the project $header header"
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" compat/x86_64/libc_inet_address_probe.c \
    -o "$reference"
if "$reference"; then
    :
else
    status=$?
    fail "pinned-musl inet-address fixture exited ${status}"
fi

CARGO_TARGET_DIR="$cargo_target" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"

nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_c_abi_symbols" \
    "$expected_c_abi_symbols"
for symbol in __errno_location __inet_aton inet_addr inet_aton inet_ntop inet_pton; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" ||
        fail "archive does not define ${symbol}"
done
for unselected in inet_network inet_netof \
    gethostbyname gethostbyaddr \
    malloc free calloc realloc; do
    if grep -Eq "[[:space:]][TW][[:space:]]${unselected}$" "$archive_symbols"; then
        fail "archive accidentally exports unselected ${unselected}"
    fi
done
readelf --relocs --wide "$archive" >"$archive_relocations"
grep -Eq 'R_X86_64_TPOFF(32|64)?' "$archive_relocations" ||
    fail "archive errno lacks an initial-TLS TPOFF relocation"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' \
    "$archive_relocations"; then
    fail "archive selects dynamic TLS or an unowned runtime dependency"
fi

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_INET_ADDRESS_FREESTANDING \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie \
    -ffreestanding -fno-builtin -fno-stack-protector -Wl,-e,_start \
    -Wl,--no-undefined compat/x86_64/libc_inet_address_probe.c \
    compat/x86_64/libc_inet_address_start.S "$archive" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
for symbol in __errno_location __inet_aton inet_addr inet_aton inet_ntop inet_pton; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" ||
        fail "candidate does not define ${symbol}"
done
assert_musl_inet_aton_alias "$candidate_symbols" candidate
if grep -Eq '[[:space:]]inet_ntoa$' "$candidate_symbols"; then
    fail "candidate accidentally selects separate inet_ntoa scratch storage"
fi
for unselected in inet_makeaddr inet_lnaof; do
    if grep -Eq "[[:space:]]${unselected}$" "$candidate_symbols"; then
        fail "candidate accidentally selects separate classful IPv4 leaf"
    fi
done
unresolved_symbols="$(awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols")"
if [ -n "$unresolved_symbols" ]; then
    printf '%s\n' "$unresolved_symbols" >&2
    fail "candidate retains an unresolved symbol"
fi
if grep -Eq 'Requesting program interpreter|INTERP' "$candidate_program_headers"; then
    fail "candidate selected a dynamic interpreter"
fi
if grep -Eq 'NEEDED' "$candidate_dynamic"; then
    fail "candidate selected a dynamic dependency"
fi
grep -Eq '[[:space:]]TLS[[:space:]]' "$candidate_program_headers" ||
    fail "candidate lacks the selected errno TLS segment"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
    "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate relocations retain a dynamic TLS model"
fi
if grep -Eq 'crabc_core|mimalloc|sha_crypt' \
    "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate selects an unowned runtime dependency"
fi
objdump -d --disassemble=__errno_location "$candidate" >"$errno_disassembly"
grep -Eq '%fs:0x0|%fs:-' "$errno_disassembly" ||
    fail "candidate errno does not use direct fs initial TLS"

if "$candidate"; then
    :
else
    status=$?
    fail "freestanding inet-address fixture exited ${status}"
fi

printf 'x86 static crabc-libc inet address codecs: PASS\n'
