#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc clock_gettime evidence.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"

fail() { printf 'ERROR: x86 static libc clock_gettime: %s\n' "$*" >&2; exit 1; }

require_native_linux_x86_64() {
    [ "$(uname -s)" = Linux ] || fail "requires native Linux"
    case "$(uname -m)" in x86_64|amd64) ;; *) fail "refuses emulation on $(uname -m)" ;; esac
}
require_tool() { command -v "$1" >/dev/null 2>&1 || fail "requires $1"; }

assert_selected_c_abi_surface() {
    local archive_path="$1" symbols_path="$2" expected_path="$3"
    local members_path="$work_dir/selected-c-abi-members"
    local -a members
    mapfile -t members < <(ar t "$archive_path" | grep -E '^c\..+\.rcgu\.o$')
    [ "${#members[@]}" -gt 0 ] || fail "archive has no crabc-libc object members"
    mkdir "$members_path"
    ( cd "$members_path"; ar x "$archive_path" "${members[@]}"; nm -g --defined-only --format=posix "${members[@]}" ) |
        awk '$2 ~ /^[TWDVBR]$/ && $1 !~ /^(_R|_ZN|DW\.ref\.|anon\.)/ && $1 != "crabc_x86_64_signal_restorer" { print $1 }' |
        sort -u >"$symbols_path"
    [ -f "$STATIC_C_ABI_EXPORTS" ] || fail "missing static C ABI export contract"
    grep -Ev '^(#|$)' "$STATIC_C_ABI_EXPORTS" | LC_ALL=C sort -u >"$expected_path"
    cmp -s "$expected_path" "$symbols_path" || { diff -u "$expected_path" "$symbols_path" >&2 || true; fail "selected static C ABI export surface drifted"; }
}

assert_named_syscall() {
    objdump -d --disassemble=clock_gettime "$candidate" >"$work_dir/clock_gettime-disassembly"
    grep -Eq '\$0xe4(,|[[:space:]]|$)' "$work_dir/clock_gettime-disassembly" || fail "clock_gettime lacks syscall 228"
    grep -Eq '[[:space:]]syscall([[:space:]]|$)' "$work_dir/clock_gettime-disassembly" || fail "clock_gettime lacks syscall instruction"
}

require_native_linux_x86_64
for tool in ar cargo cmp diff nm objdump readelf rustup; do require_tool "$tool"; done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_time_header_abi.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-clock-gettime.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
cargo_target="$work_dir/cargo-target"
archive="$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-clock-gettime-reference"
candidate="$work_dir/crabc-static-clock-gettime-candidate"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -E -H compat/x86_64/libc_clock_gettime_probe.c >/dev/null 2>"$work_dir/header-trace"
for header in errno.h time.h sys/syscall.h bits/alltypes.h bits/syscall.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$work_dir/header-trace" || fail "fixture did not use project $header"
done
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fno-builtin -fno-stack-protector -I"$ROOT_DIR/include" compat/x86_64/libc_clock_gettime_probe.c -o "$reference"
"$reference" || fail "pinned-musl clock_gettime fixture failed"

CARGO_TARGET_DIR="$cargo_target" cargo rustc --locked -p crabc-libc --lib --target x86_64-unknown-linux-musl -- -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit x86 static libc archive"
nm -A --defined-only "$archive" >"$work_dir/archive-symbols"
assert_selected_c_abi_surface "$archive" "$work_dir/selected-symbols" "$work_dir/expected-symbols"
for symbol in __errno_location clock_gettime; do grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$work_dir/archive-symbols" || fail "archive does not define ${symbol}"; done
readelf --relocs --wide "$archive" >"$work_dir/archive-relocations"
grep -Eq 'R_X86_64_TPOFF(32|64)?' "$work_dir/archive-relocations" || fail "archive errno lacks TPOFF relocation"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' "$work_dir/archive-relocations"; then fail "archive selects dynamic TLS or unowned dependency"; fi

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_CLOCK_GETTIME_FREESTANDING -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined compat/x86_64/libc_clock_gettime_probe.c compat/x86_64/libc_clock_gettime_start.S "$archive" -o "$candidate"
readelf --symbols --wide "$candidate" >"$work_dir/candidate-symbols"
readelf --program-headers --wide "$candidate" >"$work_dir/candidate-program-headers"
readelf --dynamic --wide "$candidate" >"$work_dir/candidate-dynamic" || true
readelf --relocs --wide "$candidate" >"$work_dir/candidate-relocations"
objdump -d "$candidate" >"$work_dir/candidate-disassembly"
for symbol in __errno_location clock_gettime; do grep -Eq "[[:space:]]${symbol}$" "$work_dir/candidate-symbols" || fail "candidate does not define ${symbol}"; done
unresolved_symbols="$(awk '$7 == "UND" && NF >= 8 { print }' "$work_dir/candidate-symbols")"
[ -z "$unresolved_symbols" ] || { printf '%s\n' "$unresolved_symbols" >&2; fail "candidate retains unresolved symbol"; }
if grep -Eq 'Requesting program interpreter|INTERP' "$work_dir/candidate-program-headers" || grep -Eq 'NEEDED' "$work_dir/candidate-dynamic"; then fail "candidate selects dynamic runtime"; fi
grep -Eq '[[:space:]]TLS[[:space:]]' "$work_dir/candidate-program-headers" || fail "candidate lacks errno TLS segment"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' "$work_dir/candidate-relocations" "$work_dir/candidate-symbols" "$work_dir/candidate-disassembly"; then fail "candidate retains dynamic TLS or unowned dependency"; fi
objdump -d --disassemble=__errno_location "$candidate" >"$work_dir/errno-disassembly"
grep -Eq '%fs:0x0|%fs:-' "$work_dir/errno-disassembly" || fail "candidate errno lacks direct fs initial TLS"
assert_named_syscall
"$candidate" || fail "freestanding clock_gettime fixture failed"
printf 'x86 static crabc-libc clock_gettime: PASS\n'
