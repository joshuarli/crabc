#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc caller-buffered UTC gmtime_r evidence.
#
# The same project-header C fixture first executes through pinned musl, then
# as a `-nostdlib -static` candidate linked solely through the selected crabc
# archive. It proves only caller-owned UTC struct-tm conversion; it is not
# non-reentrant storage, local conversion, timezone/environment state,
# formatting/parsing, clocks, timers, libc.so, CRT, loader, sysroot, or public
# x86 support.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"

fail() { printf 'ERROR: x86 static libc gmtime_r: %s\n' "$*" >&2; exit 1; }

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
        awk '$2 ~ /^[TWDVBR]$/ && $1 !~ /^(_R|_ZN|DW\.ref\.|anon\.)/ && $1 != "crabc_x86_64_signal_restorer" && $1 != "__crabc_x86_pthread_clone" { print $1 }' |
        sort -u >"$symbols_path"
    [ -f "$STATIC_C_ABI_EXPORTS" ] || fail "missing static C ABI export contract"
    grep -Ev '^(#|$)' "$STATIC_C_ABI_EXPORTS" | LC_ALL=C sort -u >"$expected_path"
    cmp -s "$expected_path" "$symbols_path" || {
        diff -u "$expected_path" "$symbols_path" >&2 || true
        fail "selected static C ABI export surface drifted"
    }
}

assert_pure_utc_code() {
    local disassembly="$work_dir/gmtime-r-disassembly"
    objdump -d --disassemble=gmtime_r "$candidate" >"$disassembly"
    if grep -Eq '[[:space:]]syscall([[:space:]]|$)' "$disassembly"; then
        fail "gmtime_r unexpectedly enters the kernel"
    fi
    if grep -Eq 'getenv|tzset|localtime|mktime|strftime|strptime' \
        "$candidate_symbols" "$candidate_disassembly"; then
        fail "candidate selects an ambient time runtime"
    fi
}

require_native_linux_x86_64
for tool in ar cargo cmp diff env grep nm objdump readelf rustup sort; do require_tool "$tool"; done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_time_header_abi.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-gmtime-r.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
cargo_target="$work_dir/cargo-target"
archive="$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-gmtime-r-reference"
candidate="$work_dir/crabc-static-gmtime-r-candidate"
header_trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
archive_relocations="$work_dir/archive-relocations"
candidate_symbols="$work_dir/candidate-symbols"
candidate_program_headers="$work_dir/candidate-program-headers"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_gmtime_r_probe.c >/dev/null 2>"$header_trace"
for header in errno.h limits.h stdint.h time.h features.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture did not use project $header"
done
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" compat/x86_64/libc_gmtime_r_probe.c -o "$reference"
"$reference" || fail "pinned-musl gmtime_r fixture failed"

CARGO_TARGET_DIR="$cargo_target" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit x86 static libc archive"
nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$work_dir/selected-symbols" "$work_dir/expected-symbols"
for symbol in __errno_location gmtime_r; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" ||
        fail "archive does not define ${symbol}"
done
for unselected in asctime asctime_r ctime ctime_r gmtime localtime localtime_r \
    mktime strftime strptime tzset; do
    if grep -Eq "[[:space:]][TW][[:space:]]${unselected}$" "$archive_symbols"; then
        fail "archive accidentally exports unselected ${unselected}"
    fi
done
readelf --relocs --wide "$archive" >"$archive_relocations"
grep -Eq 'R_X86_64_TPOFF(32|64)?' "$archive_relocations" ||
    fail "archive errno lacks TPOFF relocation"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' \
    "$archive_relocations"; then
    fail "archive selects dynamic TLS or unowned dependency"
fi

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_GMTIME_R_FREESTANDING \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    compat/x86_64/libc_gmtime_r_probe.c compat/x86_64/libc_gmtime_r_start.S \
    "$archive" -o "$candidate"
readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
for symbol in __errno_location gmtime_r; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" ||
        fail "candidate does not define ${symbol}"
done
unresolved_symbols="$(awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols")"
[ -z "$unresolved_symbols" ] || { printf '%s\n' "$unresolved_symbols" >&2; fail "candidate retains unresolved symbol"; }
if grep -Eq 'Requesting program interpreter|INTERP' "$candidate_program_headers" ||
    grep -Eq 'NEEDED' "$candidate_dynamic"; then
    fail "candidate selects dynamic runtime"
fi
grep -Eq '[[:space:]]TLS[[:space:]]' "$candidate_program_headers" ||
    fail "candidate lacks errno TLS segment"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' \
    "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate retains dynamic TLS or unowned dependency"
fi
objdump -d --disassemble=__errno_location "$candidate" >"$work_dir/errno-disassembly"
grep -Eq '%fs:0x0|%fs:-' "$work_dir/errno-disassembly" ||
    fail "candidate errno lacks direct fs initial TLS"
assert_pure_utc_code
env -i "$candidate" || fail "freestanding fixed-UTC gmtime_r fixture failed"
printf 'x86 static crabc-libc caller-buffered UTC gmtime_r: PASS\n'
