#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc in6addr_any evidence.
#
# The project-header fixture first runs against pinned musl 1.2.6, then as a
# true archive-free `-nostdlib -static` executable linked from exactly one
# extracted crabc object. It selects only the immutable sixteen-byte IPv6
# unspecified-address object. Musl maps it to in6addr_any.c; its independent
# in6addr_loopback.c sibling remains unselected. It does not select
# in6addr_loopback, IPv6 socket transport, address conversion, resolver
# configuration, DNS, netdb, interfaces, Ethernet, errno, TLS, allocation, or
# an ambient runtime.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"

fail() {
    printf 'ERROR: x86 static libc in6addr_any: %s\n' "$*" >&2
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

extract_selected_member() {
    local archive_path="$1"
    local members_path="$2"
    local matches_path="$3"
    local member definitions
    local -a members matches

    mapfile -t members < <(ar t "$archive_path" | grep -E '^c\..+\.rcgu\.o$')
    [ "${#members[@]}" -gt 0 ] || fail "archive has no crabc-libc object members"
    mkdir "$members_path"
    (
        cd "$members_path"
        ar x "$archive_path" "${members[@]}"
        for member in "${members[@]}"; do
            definitions="$(nm -g --defined-only "$member")"
            if printf '%s\n' "$definitions" |
                grep -Eq '[[:space:]][R][[:space:]]in6addr_any$'; then
                if printf '%s\n' "$definitions" |
                    grep -Eq '[[:space:]][R][[:space:]]in6addr_loopback$'; then
                    fail "in6addr_any archive member also defines in6addr_loopback"
                fi
                printf '%s\n' "$member"
            fi
        done
    ) >"$matches_path"
    mapfile -t matches <"$matches_path"
    [ "${#matches[@]}" = 1 ] || fail "in6addr_any must have exactly one selected archive member"
    printf '%s/%s\n' "$members_path" "${matches[0]}"
}

require_native_linux_x86_64
for tool in ar awk cargo cmp diff grep mapfile mkdir mktemp nm objdump readelf rustup sort; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-in6addr-any.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
cargo_target="$work_dir/cargo-target"
reference="$work_dir/musl-in6addr-any-reference"
candidate="$work_dir/crabc-static-in6addr-any-candidate"
archive="$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
musl_archive="$("$ORACLE_CC" -print-file-name=libc.a)"
musl_object="$work_dir/musl-in6addr-any.o"
musl_loopback_object="$work_dir/musl-in6addr-loopback.o"
musl_any_bytes="$work_dir/musl-in6addr-any-bytes"
musl_loopback_bytes="$work_dir/musl-in6addr-loopback-bytes"
header_trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
selected_c_abi_symbols="$work_dir/selected-c-abi-symbols"
expected_c_abi_symbols="$work_dir/expected-c-abi-symbols"
selected_members="$work_dir/selected-in6addr-any-members"
selected_member_names="$work_dir/selected-in6addr-any-member-names"
candidate_symbols="$work_dir/candidate-symbols"
candidate_program_headers="$work_dir/candidate-program-headers"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"

cd "$ROOT_DIR"
case "$musl_archive" in
    /*) ;;
    *) fail "pinned musl compiler did not report an absolute libc.a path" ;;
esac
[ -f "$musl_archive" ] || fail "pinned musl static archive is missing"
ar p "$musl_archive" in6addr_any.lo >"$musl_object"
readelf --symbols --wide "$musl_object" |
    grep -Eq '[[:space:]]FILE[[:space:]]+LOCAL[[:space:]]+DEFAULT[[:space:]]+ABS[[:space:]]+in6addr_any\.c$' ||
    fail "pinned musl in6addr_any object no longer maps to in6addr_any.c"
readelf --symbols --wide "$musl_object" |
    grep -Eq '[[:space:]]16[[:space:]]+OBJECT[[:space:]]+GLOBAL[[:space:]]+DEFAULT[[:space:]]+[0-9]+[[:space:]]+in6addr_any$' ||
    fail "pinned musl in6addr_any object layout drifted"
if [ -n "$(nm --undefined-only "$musl_object")" ]; then
    fail "pinned musl in6addr_any object unexpectedly has a dependency"
fi
readelf --hex-dump=.rodata.in6addr_any "$musl_object" >"$musl_any_bytes"
grep -Eq '00000000[[:space:]]+00000000[[:space:]]+00000000[[:space:]]+00000000[[:space:]]+00000000' \
    "$musl_any_bytes" || fail "pinned musl in6addr_any bytes drifted from all zero"

ar p "$musl_archive" in6addr_loopback.lo >"$musl_loopback_object"
readelf --symbols --wide "$musl_loopback_object" |
    grep -Eq '[[:space:]]FILE[[:space:]]+LOCAL[[:space:]]+DEFAULT[[:space:]]+ABS[[:space:]]+in6addr_loopback\.c$' ||
    fail "pinned musl loopback sibling no longer maps independently"
readelf --symbols --wide "$musl_loopback_object" |
    grep -Eq '[[:space:]]16[[:space:]]+OBJECT[[:space:]]+GLOBAL[[:space:]]+DEFAULT[[:space:]]+[0-9]+[[:space:]]+in6addr_loopback$' ||
    fail "pinned musl loopback sibling layout drifted"
readelf --hex-dump=.rodata.in6addr_loopback "$musl_loopback_object" \
    >"$musl_loopback_bytes"
grep -Eq '00000000[[:space:]]+00000000[[:space:]]+00000000[[:space:]]+00000000[[:space:]]+00000001' \
    "$musl_loopback_bytes" || fail "pinned musl loopback sibling bytes drifted"

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_in6addr_any_probe.c >/dev/null 2>"$header_trace"
for header in netinet/in.h arpa/inet.h stddef.h stdint.h sys/socket.h sys/types.h \
    bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture did not use the project $header header"
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" compat/x86_64/libc_in6addr_any_probe.c \
    -o "$reference"
if env -i LC_ALL=C TZ=UTC "$reference"; then
    :
else
    status=$?
    fail "pinned-musl in6addr_any fixture exited ${status}"
fi

CARGO_TARGET_DIR="$cargo_target" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"

nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_c_abi_symbols" \
    "$expected_c_abi_symbols"
grep -Eq '[[:space:]][R][[:space:]]in6addr_any$' "$archive_symbols" ||
    fail "archive does not define immutable in6addr_any"
selected_member="$(extract_selected_member "$archive" "$selected_members" \
    "$selected_member_names")"
[ -f "$selected_member" ] || fail "selected in6addr_any member is missing"

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_IN6ADDR_ANY_FREESTANDING \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie \
    -ffreestanding -fno-builtin -fno-stack-protector -Wl,-e,_start \
    -Wl,--gc-sections -Wl,--no-undefined compat/x86_64/libc_in6addr_any_probe.c \
    compat/x86_64/libc_in6addr_any_start.S "$selected_member" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
grep -Eq '[[:space:]][R][[:space:]]in6addr_any$' <(nm -g --defined-only "$candidate") ||
    fail "archive-free candidate does not retain read-only in6addr_any"
candidate_size="$(awk '$4 == "OBJECT" && $5 == "GLOBAL" && $6 == "DEFAULT" && $8 == "in6addr_any" { print $3; exit }' "$candidate_symbols")"
[ "$candidate_size" = 16 ] || fail "candidate in6addr_any does not retain its sixteen-byte ABI"
unresolved_symbols="$(awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols")"
if [ -n "$unresolved_symbols" ]; then
    printf '%s\n' "$unresolved_symbols" >&2
    fail "archive-free candidate retains an unresolved symbol"
fi
if grep -Eq 'Requesting program interpreter|INTERP' "$candidate_program_headers"; then
    fail "archive-free candidate selected a dynamic interpreter"
fi
if grep -Eq 'NEEDED' "$candidate_dynamic"; then
    fail "archive-free candidate selected a dynamic dependency"
fi
if grep -Eq '[[:space:]]TLS[[:space:]]' "$candidate_program_headers"; then
    fail "archive-free candidate unexpectedly selects TLS"
fi
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr|__errno_location|__h_errno_location|%fs:' \
    "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly"; then
    fail "archive-free candidate selects errno, h_errno, or a TLS runtime"
fi
for unselected in in6addr_loopback htonl htons ntohl ntohs inet_addr inet_aton \
    inet_ntop inet_pton inet_ntoa inet_network inet_makeaddr inet_lnaof inet_netof \
    __h_errno_location h_errno hstrerror freeaddrinfo gai_strerror getaddrinfo \
    gethostbyaddr gethostbyname gethostbyname2 gethostent getnameinfo \
    getnetbyaddr getnetbyname getnetent getprotobyname getprotobynumber \
    getprotoent getservbyname getservbyport getservent if_indextoname \
    if_nameindex if_nametoindex if_freenameindex socket bind connect send recv \
    malloc free calloc realloc; do
    if grep -Eq "[[:space:]]${unselected}$" "$candidate_symbols"; then
        fail "archive-free candidate accidentally selects ${unselected}"
    fi
done
if grep -Eq 'crabc_core|mimalloc|sha_crypt' \
    "$candidate_symbols" "$candidate_disassembly"; then
    fail "archive-free candidate selects an unowned runtime dependency"
fi

if env -i LC_ALL=C TZ=UTC "$candidate"; then
    :
else
    status=$?
    fail "freestanding in6addr_any fixture exited ${status}"
fi

printf 'x86 static crabc-libc in6addr_any: PASS\n'
