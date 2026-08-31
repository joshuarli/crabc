#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc getloadavg evidence.
#
# One project-header C fixture runs through pinned musl 1.2.6 and then through
# a true `-nostdlib -static` candidate. It selects only musl's one-sysinfo
# historical load snapshot: zero/negative count behavior, three-entry clamp,
# fixed-point scaling, and caller-owned output. It is not /proc parsing,
# generic sysinfo/uname, processor/page-count, sysconf, or topology policy.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly INITIAL_TLS_BYTES=4096
readonly INITIAL_TLS_ALIGNMENT=64

fail() {
    printf 'ERROR: x86 static libc getloadavg: %s\n' "$*" >&2
    exit 1
}

require_tool() {
    command -v "$1" >/dev/null 2>&1 || fail "requires $1"
}

assert_selected_c_abi_surface() {
    local archive_path="$1" symbols_path="$2" expected_path="$3"
    local members_path="$work_dir/selected-c-abi-members"; local -a members

    mapfile -t members < <(ar t "$archive_path" | grep -E '^c\..+\.rcgu\.o$')
    [ "${#members[@]}" -gt 0 ] || fail "archive has no crabc-libc object members"
    mkdir "$members_path"
    ( cd "$members_path"; ar x "$archive_path" "${members[@]}"; \
      nm -g --defined-only --format=posix "${members[@]}" ) |
        awk '$2 ~ /^[TWDVBR]$/ && $1 !~ /^(_R|_ZN|DW\.ref\.|anon\.)/ && $1 != "crabc_x86_64_signal_restorer" && $1 != "__crabc_x86_pthread_clone" { print $1 }' |
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
    (( tls_filesz == 0 )) || fail "fixture TLS scratch cannot initialize PT_TLS data"
    (( tls_memsz > 0 && tls_memsz <= INITIAL_TLS_BYTES )) ||
        fail "fixture TLS scratch does not cover PT_TLS memsz ${tls_memsz}"
    (( tls_alignment > 0 && tls_alignment <= INITIAL_TLS_ALIGNMENT &&
        INITIAL_TLS_ALIGNMENT % tls_alignment == 0 )) ||
        fail "fixture TLS scratch is incompatible with PT_TLS alignment ${tls_alignment}"
}

assert_getloadavg_syscall_path() {
    objdump -d --disassemble=getloadavg "$candidate" >"$getloadavg_disassembly"
    grep -Eq '\$0x63,%(e|r)ax' "$getloadavg_disassembly" ||
        fail "getloadavg lacks Linux sysinfo=99"
    grep -Eq '[[:space:]]syscall([[:space:]]|$)' "$getloadavg_disassembly" ||
        fail "getloadavg lacks its Linux syscall"
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "requires native x86-64" ;; esac
for tool in ar awk cargo cmp diff grep mkdir nm objdump readelf rustup sort; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_getloadavg_header_abi.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-getloadavg.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
target_dir="$work_dir/cargo-target"
archive="$target_dir/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-getloadavg-reference"
candidate="$work_dir/crabc-static-getloadavg-candidate"
trace="$work_dir/header-trace"; archive_symbols="$work_dir/archive-symbols"
selected_symbols="$work_dir/selected-c-abi-symbols"; expected_symbols="$work_dir/expected-c-abi-symbols"
symbols="$work_dir/candidate-symbols"; headers="$work_dir/candidate-program-headers"
dynamic="$work_dir/candidate-dynamic"; relocs="$work_dir/candidate-relocations"
disassembly="$work_dir/candidate-disassembly"; errno_disassembly="$work_dir/errno-disassembly"
getloadavg_disassembly="$work_dir/getloadavg-disassembly"
cd "$ROOT_DIR"

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I "$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_getloadavg_probe.c >/dev/null 2>"$trace"
for header in errno.h stdlib.h features.h bits/alltypes.h sys/syscall.h bits/syscall.h \
    sys/sysinfo.h sys/prctl.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$trace" ||
        fail "fixture did not use project $header"
done
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fno-builtin -fno-stack-protector \
    -I "$ROOT_DIR/include" compat/x86_64/libc_getloadavg_probe.c -o "$reference"
"$reference" || fail "pinned-musl getloadavg fixture failed"

CARGO_TARGET_DIR="$target_dir" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"
nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_symbols" "$expected_symbols"
for symbol in __errno_location getloadavg; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" ||
        fail "archive does not define ${symbol}"
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_GETLOADAVG_FREESTANDING \
    -I "$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    compat/x86_64/libc_getloadavg_probe.c compat/x86_64/libc_getloadavg_start.S \
    "$archive" -o "$candidate"
readelf --symbols --wide "$candidate" >"$symbols"
readelf --program-headers --wide "$candidate" >"$headers"
readelf --dynamic --wide "$candidate" >"$dynamic" || true
readelf --relocs --wide "$candidate" >"$relocs"
objdump -d "$candidate" >"$disassembly"
for symbol in __errno_location getloadavg; do
    grep -Eq "[[:space:]]${symbol}$" "$symbols" ||
        fail "candidate lacks ${symbol}"
done
for symbol in sysinfo uname get_nprocs get_nprocs_conf get_phys_pages get_avphys_pages \
    sysconf getpagesize getdtablesize gethostid getloadavg_r; do
    if grep -Eq "[[:space:]]${symbol}$" "$symbols"; then
        fail "getloadavg candidate unexpectedly pulls ${symbol}"
    fi
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
    fail "candidate retains dynamic TLS"
fi
if grep -Eq 'crabc_core|mimalloc|sha_crypt|panic_(bounds_check|nounwind)|rust_begin_unwind|core9panicking' \
    "$symbols" "$disassembly"; then
    fail "candidate selects an unowned runtime dependency"
fi
objdump -d --disassemble=__errno_location "$candidate" >"$errno_disassembly"
grep -Eq '%fs:0x0|%fs:-' "$errno_disassembly" ||
    fail "candidate errno does not use direct fs initial TLS"
assert_getloadavg_syscall_path
"$candidate" || fail "freestanding getloadavg fixture failed"

printf 'x86 static libc getloadavg: PASS\n'
