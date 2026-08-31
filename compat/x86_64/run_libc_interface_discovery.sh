#!/usr/bin/env bash
# Native Linux/x86-64 static C interface-discovery evidence.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"

fail() {
    printf 'ERROR: x86 static libc interface discovery: %s\n' "$*" >&2
    exit 1
}

require_tool() {
    command -v "$1" >/dev/null 2>&1 || fail "requires $1"
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "refuses emulation on $(uname -m)" ;; esac
for tool in ar awk cargo cmp diff grep nm objdump readelf rustup sort; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-interface-discovery.XXXXXX)"
cleanup() {
    rm -rf -- "$work_dir"
}
trap cleanup EXIT

cargo_target="$work_dir/cargo-target"
archive="$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-interface-discovery-reference"
candidate="$work_dir/crabc-static-interface-discovery-candidate"
archive_symbols="$work_dir/archive-symbols"
archive_relocations="$work_dir/archive-relocations"
candidate_symbols="$work_dir/candidate-symbols"
candidate_headers="$work_dir/candidate-headers"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"
selected_symbols="$work_dir/selected-symbols"
expected_symbols="$work_dir/expected-symbols"
members_dir="$work_dir/members"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_interface_discovery_probe.c >/dev/null 2>"$work_dir/header-trace"
for header in errno.h ifaddrs.h net/if.h netinet/in.h netpacket/packet.h sys/socket.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$work_dir/header-trace" ||
        fail "fixture did not use project $header"
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" compat/x86_64/libc_interface_discovery_probe.c \
    -o "$reference"
if "$reference"; then :; else status=$?; fail "pinned-musl fixture exited ${status}"; fi

CARGO_TARGET_DIR="$cargo_target" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit x86 static libc archive"

nm -A --defined-only "$archive" >"$archive_symbols"
mapfile -t members < <(ar t "$archive" | grep -E '^c\..+\.rcgu\.o$')
[ "${#members[@]}" -gt 0 ] || fail "archive has no crabc-libc members"
mkdir "$members_dir"
(
    cd "$members_dir"
    ar x "$archive" "${members[@]}"
    nm -g --defined-only --format=posix "${members[@]}"
) | awk '$2 ~ /^[TWDVBR]$/ && $1 !~ /^(_R|_ZN|DW\.ref\.|anon\.)/ && $1 != "crabc_x86_64_signal_restorer" && $1 != "__crabc_x86_pthread_clone" { print $1 }' |
    sort -u >"$selected_symbols"
grep -Ev '^(#|$)' "$STATIC_C_ABI_EXPORTS" | LC_ALL=C sort -u >"$expected_symbols"
if ! cmp -s "$expected_symbols" "$selected_symbols"; then
    diff -u "$expected_symbols" "$selected_symbols" >&2 || true
    fail "selected static C ABI export surface drifted"
fi

for symbol in freeifaddrs getifaddrs if_freenameindex if_indextoname \
    if_nameindex if_nametoindex; do
    grep -Eq "[[:space:]][TWDBR][[:space:]]${symbol}$" "$archive_symbols" ||
        fail "archive does not define ${symbol}"
done
readelf --relocs --wide "$archive" >"$archive_relocations"
grep -Eq 'R_X86_64_TPOFF(32|64)?' "$archive_relocations" ||
    fail "interface errno boundary lacks initial-TLS relocation"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' "$archive_relocations"; then
    fail "archive selects dynamic TLS or an unowned runtime dependency"
fi

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_INTERFACE_DISCOVERY_FREESTANDING \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie \
    -ffreestanding -fno-builtin -fno-stack-protector -Wl,-e,_start \
    -Wl,--no-undefined compat/x86_64/libc_interface_discovery_probe.c \
    compat/x86_64/libc_interface_discovery_start.S "$archive" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
if awk '$7 == "UND" && NF >= 8 { found = 1 } END { exit found ? 0 : 1 }' "$candidate_symbols"; then
    awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols" >&2
    fail "candidate retains an unresolved symbol"
fi
if grep -Eq 'Requesting program interpreter|INTERP' "$candidate_headers"; then fail "candidate selected an interpreter"; fi
if grep -Eq 'NEEDED' "$candidate_dynamic"; then fail "candidate selected a dynamic dependency"; fi
grep -Eq '[[:space:]]TLS[[:space:]]' "$candidate_headers" || fail "candidate lacks initial TLS"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' \
    "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate retains dynamic TLS or an unowned runtime edge"
fi
if grep -Eq '[[:space:]](__res_state|res_(init|mkquery|query|querydomain|search|send)|dn_(comp|expand|skipname)|ns_(initparse|parserr)|h_errno|getaddrinfo|getnameinfo|freeaddrinfo|gethost(byaddr|byname|ent)|get(net|proto|serv)(byaddr|byname|bynumber|ent))$' \
    "$candidate_symbols"; then
    grep -E '[[:space:]](__res_state|res_(init|mkquery|query|querydomain|search|send)|dn_(comp|expand|skipname)|ns_(initparse|parserr)|h_errno|getaddrinfo|getnameinfo|freeaddrinfo|gethost(byaddr|byname|ent)|get(net|proto|serv)(byaddr|byname|bynumber|ent))$' \
        "$candidate_symbols" >&2 || true
    fail "candidate retained resolver configuration, DNS, or network-database behavior"
fi
if grep -Eq '[[:space:]](malloc|calloc|realloc|free)$' "$candidate_symbols"; then
    fail "candidate exposes a general C allocator"
fi
for syscall in 0x29 0x2c 0x2d 0x10; do
    grep -Eq "\\\$${syscall}(,|[[:space:]]|$)" "$candidate_disassembly" ||
        fail "candidate lacks expected direct syscall ${syscall}"
done

if "$candidate"; then :; else status=$?; fail "crabc candidate exited ${status}"; fi

printf 'x86 static crabc-libc interface discovery: PASS\n'
