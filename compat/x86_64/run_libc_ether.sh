#!/usr/bin/env bash
# Native Linux/x86-64 complete musl ether.c static-provider evidence.
#
# One project-header fixture first executes through pinned musl 1.2.6 and then
# as a true `-nostdlib -static` candidate linked ordinarily against crabc-libc.
# It owns the six conversion/mapping siblings of the separately retained
# ether_line leaf, while preserving musl's fixed -1 line/host stubs. The block
# excludes /etc/ethers, resolver, socket, interface, allocation, stdio,
# libc.so, CRT, loader, sysroot, family promotion, and public x86 support.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly AARCH64_STATIC_ABI="$ROOT_DIR/compat/abi/musl-1.2.6/aarch64/libc.a.static.tsv"
readonly SOURCE="$ROOT_DIR/libc/src/c_abi/x86_64/ether.rs"
readonly HEADER_RUNNER="$ROOT_DIR/compat/x86_64/run_ether_header_abi.sh"
readonly PROBE="$ROOT_DIR/compat/x86_64/libc_ether_probe.c"
readonly START="$ROOT_DIR/compat/x86_64/libc_ether_start.S"
readonly -a ETHER_SYMBOLS=(ether_aton ether_aton_r ether_ntoa ether_ntoa_r ether_line ether_ntohost ether_hostton)
readonly -a NEW_PROVIDER_SYMBOLS=(ether_aton ether_aton_r ether_ntoa ether_ntoa_r ether_ntohost ether_hostton)

fail() {
    printf 'ERROR: x86 static libc ether providers: %s\n' "$*" >&2
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
        LC_ALL=C sort -u >"$symbols_path"
    grep -Ev '^(#|$)' "$STATIC_C_ABI_EXPORTS" | LC_ALL=C sort -u >"$expected_path"
    if ! cmp -s "$expected_path" "$symbols_path"; then
        diff -u "$expected_path" "$symbols_path" >&2 || true
        fail "selected static C ABI export surface drifted"
    fi
}

assert_musl_ether_owner() {
    local symbols_path="$1"
    local symbol

    for symbol in "${ETHER_SYMBOLS[@]}"; do
        grep -Eq "[[:space:]]FUNC[[:space:]]+GLOBAL[[:space:]].*[[:space:]]${symbol}$" \
            "$symbols_path" || fail "pinned musl ether.lo lacks strong $symbol"
    done
}

assert_ordinary_extraction() {
    local archive_path="$1"
    local symbol="$2"
    local object="$work_dir/extract-$symbol.o"

    ld -r --no-undefined --undefined="$symbol" -o "$object" "$archive_path" ||
        fail "ordinary extraction failed for $symbol"
    nm -g --defined-only "$object" | grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" ||
        fail "ordinary extraction did not define $symbol"
}

require_native_linux_x86_64
for tool in ar awk cargo cmp diff grep ld mapfile mkdir mktemp nm objdump readelf rustup sort strings; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -f "$STATIC_C_ABI_EXPORTS" ] || fail "missing static C ABI export contract"
[ -f "$AARCH64_STATIC_ABI" ] || fail "missing AArch64 musl static ABI oracle"
[ -f "$SOURCE" ] || fail "missing target-local ether provider source"
grep -Fq 'integer_parse::strtoul(cursor, &mut end, 16)' "$SOURCE" ||
    fail "ether parser no longer maps musl's base-16 strtoul boundary"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$HEADER_RUNNER" >/dev/null
for symbol in "${ETHER_SYMBOLS[@]}"; do
    grep -Eq "^${symbol}[[:space:]]+ether\\.lo[[:space:]]+T[[:space:]]+GLOBAL" \
        "$AARCH64_STATIC_ABI" || fail "AArch64 musl ABI oracle lost $symbol ownership"
done

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-ether.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
target_dir="$work_dir/cargo-target"
archive="$target_dir/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-ether-reference"
candidate="$work_dir/crabc-static-ether-candidate"
musl_archive="$("$ORACLE_CC" -print-file-name=libc.a)"
musl_object="$work_dir/musl-ether.o"
musl_symbols="$work_dir/musl-ether-symbols"
header_trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
selected_symbols="$work_dir/selected-c-abi-symbols"
expected_symbols="$work_dir/expected-c-abi-symbols"
archive_relocations="$work_dir/archive-relocations"
candidate_symbols="$work_dir/candidate-symbols"
candidate_program_headers="$work_dir/candidate-program-headers"
candidate_sections="$work_dir/candidate-sections"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"
errno_disassembly="$work_dir/errno-disassembly"
aton_disassembly="$work_dir/ether-aton-disassembly"
ntoa_disassembly="$work_dir/ether-ntoa-disassembly"

cd "$ROOT_DIR"
case "$musl_archive" in
    /*) ;;
    *) fail "pinned musl compiler did not report an absolute libc.a path" ;;
esac
[ -f "$musl_archive" ] || fail "pinned musl static archive is missing"
ar p "$musl_archive" ether.lo >"$musl_object"
readelf --symbols --wide "$musl_object" >"$musl_symbols"
assert_musl_ether_owner "$musl_symbols"

"$ORACLE_CC" -std=c11 -I "$ROOT_DIR/include" -E -H "$PROBE" \
    >/dev/null 2>"$header_trace"
for header in errno.h netinet/ether.h netinet/if_ether.h net/ethernet.h stddef.h \
    stdint.h sys/types.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture did not use project $header"
done
"$ORACLE_CC" -std=c11 -fno-builtin -fno-stack-protector -I "$ROOT_DIR/include" \
    "$PROBE" -o "$reference"
"$reference" || fail "pinned-musl ether fixture failed"

CARGO_TARGET_DIR="$target_dir" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"

nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_symbols" "$expected_symbols"
for symbol in __errno_location __crabc_x86_static_tls_bootstrap "${ETHER_SYMBOLS[@]}"; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" ||
        fail "archive does not define $symbol"
done
for symbol in "${NEW_PROVIDER_SYMBOLS[@]}"; do
    assert_ordinary_extraction "$archive" "$symbol"
done
readelf --relocs --wide "$archive" >"$archive_relocations"
grep -Eq 'R_X86_64_TPOFF(32|64)?' "$archive_relocations" ||
    fail "archive errno lacks an initial-TLS TPOFF relocation"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' \
    "$archive_relocations"; then
    fail "archive selects dynamic TLS or an unowned runtime dependency"
fi

"$ORACLE_CC" -std=c11 -DCRABC_ETHER_FREESTANDING -I "$ROOT_DIR/include" \
    -nostdlib -static -fno-pie -no-pie -ffreestanding -fno-builtin \
    -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined -Wl,--gc-sections \
    "$PROBE" "$START" "$archive" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
readelf --sections --wide "$candidate" >"$candidate_sections"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
for symbol in __errno_location __crabc_x86_static_tls_bootstrap "${ETHER_SYMBOLS[@]}"; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" ||
        fail "candidate does not define $symbol"
done
if awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols" | grep -q .; then
    fail "candidate retains an unresolved symbol"
fi
if grep -Eq 'Requesting program interpreter|INTERP|NEEDED' \
    "$candidate_program_headers" "$candidate_dynamic"; then
    fail "candidate selected a dynamic dependency"
fi
grep -Eq '[[:space:]]TLS[[:space:]]' "$candidate_program_headers" ||
    fail "candidate lacks the selected errno TLS segment"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
    "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate relocations retain a dynamic TLS model"
fi
if grep -Eq '[[:space:]]\.plt([[:space:]]|$)' "$candidate_sections"; then
    fail "candidate retains a PLT"
fi
if grep -Eq 'crabc_core|mimalloc|sha_crypt|malloc|calloc|realloc|free|sprintf|snprintf' \
    "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate selects an unowned runtime dependency"
fi
if strings "$candidate" | grep -Fq '/etc/ethers'; then
    fail "candidate embeds an unselected /etc/ethers dependency"
fi
if grep -Eq '[[:space:]](getaddrinfo|getnameinfo|gethostbyaddr|gethostbyname|res_init|socket|connect|open|read|close)$' \
    "$candidate_symbols"; then
    fail "candidate exports an unselected resolver, socket, or filesystem entry"
fi
objdump -d --disassemble=__errno_location "$candidate" >"$errno_disassembly"
grep -Eq '%fs:0x0|%fs:-' "$errno_disassembly" ||
    fail "candidate errno does not use direct fs initial TLS"
objdump -d --disassemble=ether_aton_r "$candidate" >"$aton_disassembly"
if grep -Eq '[[:space:]]syscall([[:space:]]|$)' "$aton_disassembly"; then
    fail "ether_aton_r unexpectedly performs a syscall"
fi
objdump -d --disassemble=ether_ntoa_r "$candidate" >"$ntoa_disassembly"
if grep -Eq '[[:space:]](call|syscall)([[:space:]]|$)' "$ntoa_disassembly"; then
    fail "ether_ntoa_r unexpectedly selects a formatting helper or syscall"
fi

"$candidate" || fail "freestanding ether fixture failed"

printf 'x86 static crabc-libc ether.c providers: PASS\n'
