#!/usr/bin/env bash
# Native Linux/x86-64 hermetic C resolver-runtime evidence.
#
# This is an opt-in resolver package, intentionally outside the default
# selected-static ABI ratchet. A single project-header fixture first runs
# through pinned musl 1.2.6 and then as a true static crabc executable. It
# starts a loopback DNS server before chrooting the client into a temporary
# root with only fixture /etc/hosts and /etc/resolv.conf, so neither arm can
# read ambient resolver configuration or contact an external nameserver.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 static libc resolver runtime: %s\n' "$*" >&2
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

symbol_value() {
    local symbols_path="$1"
    local symbol="$2"

    awk -v symbol="$symbol" \
        '$4 == "FUNC" && $7 != "UND" && $8 == symbol { print $2; exit }' \
        "$symbols_path"
}

assert_weak_hidden_alias_pair() {
    local symbols_path="$1"
    local hidden_symbol="$2"
    local public_symbol="$3"
    local label="$4"
    local hidden_value
    local public_value

    grep -Eq "FUNC +GLOBAL +HIDDEN +.*${hidden_symbol}$" "$symbols_path" ||
        fail "${label} ${hidden_symbol} is not a hidden global function"
    grep -Eq "FUNC +WEAK +DEFAULT +.*${public_symbol}$" "$symbols_path" ||
        fail "${label} ${public_symbol} is not a weak default function"
    hidden_value="$(symbol_value "$symbols_path" "$hidden_symbol")"
    public_value="$(symbol_value "$symbols_path" "$public_symbol")"
    [ -n "$hidden_value" ] || fail "${label} ${hidden_symbol} has no ELF value"
    [ "$hidden_value" = "$public_value" ] ||
        fail "${label} ${public_symbol} is not the same-address alias of ${hidden_symbol}"
}

assert_weak_same_address_alias_pair() {
    local symbols_path="$1"
    local target_symbol="$2"
    local alias_symbol="$3"
    local label="$4"
    local target_value
    local alias_value

    grep -Eq "FUNC +GLOBAL +DEFAULT +.*${target_symbol}$" "$symbols_path" ||
        fail "${label} ${target_symbol} is not a public global function"
    grep -Eq "FUNC +WEAK +DEFAULT +.*${alias_symbol}$" "$symbols_path" ||
        fail "${label} ${alias_symbol} is not a weak default function"
    target_value="$(symbol_value "$symbols_path" "$target_symbol")"
    alias_value="$(symbol_value "$symbols_path" "$alias_symbol")"
    [ -n "$target_value" ] || fail "${label} ${target_symbol} has no ELF value"
    [ "$target_value" = "$alias_value" ] ||
        fail "${label} ${alias_symbol} is not the same-address alias of ${target_symbol}"
}

assert_weak_default_function() {
    local symbols_path="$1"
    local symbol="$2"
    local label="$3"

    grep -Eq "FUNC +WEAK +DEFAULT +.*${symbol}$" "$symbols_path" ||
        fail "${label} ${symbol} is not a weak default function"
}

extract_resolver_object() {
    local archive_path="$1"
    local output_path="$2"
    local member

    while IFS= read -r member; do
        ar p "$archive_path" "$member" >"$output_path"
        if readelf --symbols --wide "$output_path" | grep -Eq \
            '[[:space:]]__res_mkquery$'; then
            return
        fi
    done < <(ar t "$archive_path")
    fail "feature archive has no resolver implementation object"
}

run_fixture() {
    local executable="$1"
    local label="$2"
    local status=0
    timeout 15 "$executable" "$fixture_root" || status=$?
    [ "$status" -eq 0 ] || fail "${label} fixture exited ${status}"
}

require_native_linux_x86_64
for tool in ar awk cargo grep id mkdir nm objdump readelf rustup timeout; do
    require_tool "$tool"
done
[ "$(id -u)" -eq 0 ] || fail "requires root for the fixture-only chroot"
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_resolver_runtime_header_abi.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-resolver-runtime.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
cargo_target="$work_dir/cargo-target"
fixture_root="$work_dir/fixture-root"
archive="$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-resolver-runtime-reference"
candidate="$work_dir/crabc-static-resolver-runtime-candidate"
oracle_archive="$($ORACLE_CC -print-file-name=libc.a)"
oracle_elf_symbols="$work_dir/musl-oracle-elf-symbols"
header_trace="$work_dir/header-trace"
public_calls_object="$work_dir/public-resolver-calls.o"
public_calls_symbols="$work_dir/public-resolver-calls-symbols"
public_calls_relocations="$work_dir/public-resolver-calls-relocations"
archive_symbols="$work_dir/archive-symbols"
archive_elf_symbols="$work_dir/archive-elf-symbols"
resolver_object="$work_dir/resolver-runtime.o"
resolver_disassembly="$work_dir/resolver-runtime-disassembly"
archive_relocations="$work_dir/archive-relocations"
candidate_symbols="$work_dir/candidate-symbols"
candidate_program_headers="$work_dir/candidate-program-headers"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"

mkdir -p "$fixture_root/etc"
printf '%s\n' \
    '192.0.2.44 host.fixture host-alias' \
    >"$fixture_root/etc/hosts"
printf '%s\n' \
    'nameserver 127.0.0.1' \
    'search fixture.test' \
    'options ndots:1 timeout:1 attempts:1' \
    >"$fixture_root/etc/resolv.conf"

cd "$ROOT_DIR"
[ -f "$oracle_archive" ] || fail "pinned musl compiler did not report libc.a"
readelf --symbols --wide "$oracle_archive" >"$oracle_elf_symbols"
assert_weak_hidden_alias_pair "$oracle_elf_symbols" __res_mkquery \
    res_mkquery "pinned-musl archive"
assert_weak_hidden_alias_pair "$oracle_elf_symbols" __res_send res_send \
    "pinned-musl archive"
assert_weak_same_address_alias_pair "$oracle_elf_symbols" res_query res_search \
    "pinned-musl archive"
assert_weak_default_function "$oracle_elf_symbols" res_search \
    "pinned-musl archive"

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_resolver_runtime_probe.c >/dev/null 2>"$header_trace"
for header in errno.h netdb.h netinet/in.h resolv.h sys/socket.h sys/wait.h features.h signal.h bits/alltypes.h bits/signal.h unistd.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture did not use project $header"
done

# The fixture deliberately imports only public `<resolv.h>` spellings.  The
# object relocation audit keeps that call boundary distinct from the hidden
# resolver-internal calls checked in the crabc archive below.
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_RESOLVER_RUNTIME_FREESTANDING \
    -I"$ROOT_DIR/include" -fno-pie -ffreestanding -fno-builtin \
    -fno-stack-protector -c compat/x86_64/libc_resolver_runtime_probe.c \
    -o "$public_calls_object"
readelf --symbols --wide "$public_calls_object" >"$public_calls_symbols"
readelf --relocs --wide "$public_calls_object" >"$public_calls_relocations"
for symbol in res_mkquery res_send; do
    grep -Eq "NOTYPE +GLOBAL +DEFAULT +UND +${symbol}$" \
        "$public_calls_symbols" ||
        fail "fixture does not retain the public ${symbol} call"
    grep -Eq "R_X86_64_(PC32|PLT32).*${symbol}" "$public_calls_relocations" ||
        fail "fixture does not retain the public ${symbol} call relocation"
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -pthread -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" compat/x86_64/libc_resolver_runtime_probe.c \
    -o "$reference"
run_fixture "$reference" "pinned-musl resolver runtime"

CARGO_TARGET_DIR="$cargo_target" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl --features x86-resolver-runtime -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"

nm -A --defined-only "$archive" >"$archive_symbols"
readelf --symbols --wide "$archive" >"$archive_elf_symbols"
for symbol in __h_errno_location __res_mkquery __res_send __res_state dn_comp \
    freeaddrinfo getaddrinfo h_errno res_init res_mkquery res_query \
    res_querydomain res_search res_send; do
    grep -Eq "[[:space:]][TWBD][[:space:]]${symbol}$" "$archive_symbols" ||
        fail "feature archive does not define ${symbol}"
done
assert_weak_hidden_alias_pair "$archive_elf_symbols" __res_mkquery \
    res_mkquery "feature archive"
assert_weak_hidden_alias_pair "$archive_elf_symbols" __res_send res_send \
    "feature archive"
assert_weak_same_address_alias_pair "$archive_elf_symbols" res_query res_search \
    "feature archive"
assert_weak_default_function "$archive_elf_symbols" res_search "feature archive"
extract_resolver_object "$archive" "$resolver_object"
objdump -dr "$resolver_object" >"$resolver_disassembly"
for symbol in __res_mkquery __res_send; do
    grep -Eq "R_X86_64_PLT32[[:space:]]+${symbol}-0x4" \
        "$resolver_disassembly" ||
        fail "resolver implementation does not retain its hidden ${symbol} call"
done
readelf --relocs --wide "$archive" >"$archive_relocations"
grep -Eq 'R_X86_64_TPOFF(32|64)?' "$archive_relocations" ||
    fail "feature archive lacks initial-TLS resolver state relocation"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|__tls_get_addr|mimalloc|sha_crypt' \
    "$archive_relocations"; then
    fail "feature archive selects dynamic TLS or an unrelated runtime"
fi

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_RESOLVER_RUNTIME_FREESTANDING \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    compat/x86_64/libc_resolver_runtime_probe.c \
    compat/x86_64/libc_resolver_runtime_start.S "$archive" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
for symbol in __h_errno_location __res_mkquery __res_send __res_state dn_comp \
    freeaddrinfo getaddrinfo res_init res_mkquery res_query res_querydomain \
    res_search res_send; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" ||
        fail "candidate does not define ${symbol}"
done
assert_weak_hidden_alias_pair "$candidate_symbols" __res_mkquery res_mkquery \
    candidate
assert_weak_hidden_alias_pair "$candidate_symbols" __res_send res_send candidate
assert_weak_same_address_alias_pair "$candidate_symbols" res_query res_search \
    candidate
assert_weak_default_function "$candidate_symbols" res_search candidate
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
    fail "candidate lacks resolver TLS storage"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
    "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate retains a dynamic TLS model"
fi
if grep -Eq 'mimalloc|sha_crypt' "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate selected an unrelated allocator or crypt runtime"
fi
grep -Eq '\$0x9(,|[[:space:]]|$)' "$candidate_disassembly" ||
    fail "candidate lacks C-owned resolver snapshot mmap"
grep -Eq '\$0xb(,|[[:space:]]|$)' "$candidate_disassembly" ||
    fail "candidate lacks C-owned resolver snapshot munmap"

run_fixture "$candidate" "freestanding resolver runtime"

printf 'x86 static crabc-libc resolver runtime: PASS\n'
