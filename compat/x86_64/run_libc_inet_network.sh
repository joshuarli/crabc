#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc inet_network evidence.
#
# The project-header fixture first runs against pinned musl 1.2.6, then as a
# `-nostdlib -static` executable. Its final link begins with the one directly
# extracted inet_network object and uses libc.a only as the ordinary
# demand-driven closure for its existing selected numeric-codec and initial-TLS
# dependencies. It is therefore true static evidence, but not an archive-free
# claim. It selects no resolver, DNS, hosts/resolv.conf,
# network database, interface, socket, or byte-order-helper behavior.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"

fail() {
    printf 'ERROR: x86 static libc inet_network: %s\n' "$*" >&2
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

extract_selected_member() {
    local archive_path="$1"
    local members_path="$2"
    local matches_path="$3"
    local member definitions collateral
    local -a members matches

    mapfile -t members < <(ar t "$archive_path" | grep -E '^c\..+\.rcgu\.o$')
    [ "${#members[@]}" -gt 0 ] || fail "archive has no crabc-libc object members"
    mkdir "$members_path"
    (
        cd "$members_path"
        ar x "$archive_path" "${members[@]}"
        for member in "${members[@]}"; do
            definitions="$(nm -g --defined-only "$member")"
            if printf '%s\n' "$definitions" | grep -Eq '[[:space:]][TW][[:space:]]inet_network$'; then
                for collateral in inet_makeaddr inet_lnaof inet_netof; do
                    if printf '%s\n' "$definitions" | grep -Eq "[[:space:]][TW][[:space:]]${collateral}$"; then
                        fail "inet_network archive member also defines ${collateral}"
                    fi
                done
                printf '%s\n' "$member"
            fi
        done
    ) >"$matches_path"
    mapfile -t matches <"$matches_path"
    [ "${#matches[@]}" = 1 ] || fail "inet_network must have exactly one selected archive member"
    printf '%s/%s\n' "$members_path" "${matches[0]}"
}

require_native_linux_x86_64
for tool in ar awk cargo cmp diff grep mapfile mkdir mktemp nm objdump readelf rustup sort; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-inet-network.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
cargo_target="$work_dir/cargo-target"
reference="$work_dir/musl-inet-network-reference"
candidate="$work_dir/crabc-static-inet-network-candidate"
archive="$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
musl_archive="$("$ORACLE_CC" -print-file-name=libc.a)"
musl_object="$work_dir/musl-inet-legacy.o"
header_trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
selected_c_abi_symbols="$work_dir/selected-c-abi-symbols"
expected_c_abi_symbols="$work_dir/expected-c-abi-symbols"
selected_members="$work_dir/selected-inet-network-members"
selected_member_names="$work_dir/selected-inet-network-member-names"
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
ar p "$musl_archive" inet_legacy.lo >"$musl_object"
for symbol in inet_network inet_makeaddr inet_lnaof inet_netof; do
    readelf --symbols --wide "$musl_object" | grep -Eq "[[:space:]]${symbol}$" ||
        fail "pinned musl inet_legacy.c no longer defines ${symbol}"
done
nm --undefined-only "$musl_object" | grep -Eq '[[:space:]]inet_addr$' ||
    fail "pinned musl inet_network no longer carries its inet_addr dependency"

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_inet_network_probe.c >/dev/null 2>"$header_trace"
for header in arpa/inet.h errno.h stddef.h stdint.h sys/socket.h sys/types.h \
    bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture did not use the project $header header"
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" compat/x86_64/libc_inet_network_probe.c \
    -o "$reference"
if env -i LC_ALL=C TZ=UTC "$reference"; then
    :
else
    status=$?
    fail "pinned-musl inet_network fixture exited ${status}"
fi

CARGO_TARGET_DIR="$cargo_target" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"

nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_c_abi_symbols" \
    "$expected_c_abi_symbols"
for symbol in inet_network inet_addr __inet_aton __errno_location; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" ||
        fail "archive does not define ${symbol}"
done
selected_member="$(extract_selected_member "$archive" "$selected_members" \
    "$selected_member_names")"
[ -f "$selected_member" ] || fail "selected inet_network member is missing"

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_INET_NETWORK_FREESTANDING \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie \
    -ffreestanding -fno-builtin -fno-stack-protector -Wl,-e,_start \
    -Wl,--gc-sections -Wl,--no-undefined compat/x86_64/libc_inet_network_probe.c \
    compat/x86_64/libc_inet_network_start.S "$selected_member" "$archive" \
    -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d --disassemble=inet_network "$candidate" >"$candidate_disassembly"
for symbol in inet_network inet_addr __inet_aton; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" ||
        fail "candidate does not define ${symbol}"
done
assert_musl_inet_aton_alias "$candidate_symbols" candidate
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
    fail "candidate lacks the selected inet_addr errno TLS segment"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
    "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate relocations retain a dynamic TLS model"
fi
objdump -d --disassemble=__errno_location "$candidate" >"$errno_disassembly"
grep -Eq '%fs:0x0|%fs:-' "$errno_disassembly" ||
    fail "candidate errno does not use direct fs initial TLS"
grep -Eq 'call.*<inet_addr>' "$candidate_disassembly" ||
    fail "inet_network does not call its selected inet_addr dependency"
grep -Eq 'bswap' "$candidate_disassembly" ||
    fail "inet_network does not retain local little-endian ntohl equivalence"
if grep -Eq 'call.*<(htonl|htons|ntohl|ntohs)>' "$candidate_disassembly"; then
    fail "inet_network calls an unselected byte-order helper"
fi
if grep -Eq '\bsyscall\b' "$candidate_disassembly"; then
    fail "inet_network implementation selects a syscall"
fi
for unselected in htonl htons ntohl ntohs inet_ntoa inet_makeaddr inet_lnaof \
    inet_netof __h_errno_location h_errno hstrerror freeaddrinfo gai_strerror \
    getaddrinfo gethostbyaddr gethostbyname gethostbyname2 gethostent \
    getnameinfo getnetbyaddr getnetbyname getnetent getprotobyname \
    getprotobynumber getprotoent getservbyname getservbyport getservent \
    if_indextoname if_nameindex if_nametoindex if_freenameindex socket bind \
    connect send recv malloc free calloc realloc; do
    if grep -Eq "[[:space:]]${unselected}$" "$candidate_symbols"; then
        fail "candidate accidentally selects ${unselected}"
    fi
done
if grep -Eq 'crabc_core|mimalloc|sha_crypt' \
    "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate selects an unowned runtime dependency"
fi

if env -i LC_ALL=C TZ=UTC "$candidate"; then
    :
else
    status=$?
    fail "freestanding inet_network fixture exited ${status}"
fi

printf 'x86 static crabc-libc inet_network: PASS\n'
