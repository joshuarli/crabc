#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc GNU CPU-count evidence.
#
# The same project-header C fixture first executes through pinned musl, then
# as a `-nostdlib -static` candidate linked solely through the selected crabc
# archive. It proves only musl's pure bytewise caller-buffer count helper; it
# is not affinity, scheduler policy, CPU topology, timer/clock, or runtime
# support.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"

fail() { printf 'ERROR: x86 static libc sched CPU-count: %s\n' "$*" >&2; exit 1; }

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

assert_byte_count_code() {
    local disassembly="$work_dir/sched-cpucount-disassembly"
    objdump -d --disassemble=__sched_cpucount "$candidate" >"$disassembly"
    grep -Eq '%rdi' "$disassembly" || fail "__sched_cpucount lacks the size register"
    grep -Eq '%rsi' "$disassembly" || fail "__sched_cpucount lacks the set register"
    grep -Eq '%eax' "$disassembly" || fail "__sched_cpucount lacks the int result register"
    grep -Eq '[[:space:]]ret([[:space:]]|$)' "$disassembly" ||
        fail "__sched_cpucount lacks a scalar return"
    if grep -Eq '[[:space:]]syscall([[:space:]]|$)|[[:space:]]call[[:space:]]' "$disassembly"; then
        fail "__sched_cpucount unexpectedly enters a runtime path"
    fi
}

require_native_linux_x86_64
for tool in ar cargo cmp diff env grep nm objdump readelf rustup sort; do require_tool "$tool"; done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_sched_cpucount_header_abi.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-sched-cpucount.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
cargo_target="$work_dir/cargo-target"
archive="$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-sched-cpucount-reference"
candidate="$work_dir/crabc-static-sched-cpucount-candidate"
header_trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
candidate_symbols="$work_dir/candidate-symbols"
candidate_program_headers="$work_dir/candidate-program-headers"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I "$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_sched_cpucount_probe.c >/dev/null 2>"$header_trace"
for header in sched.h sys/types.h time.h features.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture did not use project <$header>"
done
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fno-builtin -fno-stack-protector \
    -I "$ROOT_DIR/include" compat/x86_64/libc_sched_cpucount_probe.c \
    -o "$reference"
"$reference" || fail "pinned-musl CPU-count fixture failed"

CARGO_TARGET_DIR="$cargo_target" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"
nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$work_dir/selected-symbols" "$work_dir/expected-symbols"
grep -Eq "[[:space:]]T[[:space:]]__sched_cpucount$" "$archive_symbols" ||
    fail "archive does not define strong __sched_cpucount"
for marker in 'src/sched/sched_cpucount.c' 'const unsigned char' \
    'while index < size' 'while bit < 8' 'caller-owned'; do
    grep -Fq "$marker" libc/src/c_abi/x86_64/sched_cpucount.rs ||
        fail "sched CPU-count source lacks ${marker}"
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_SCHED_CPUCOUNT_FREESTANDING \
    -I "$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    -Wl,--gc-sections compat/x86_64/libc_sched_cpucount_probe.c \
    compat/x86_64/libc_sched_cpucount_start.S "$archive" -o "$candidate"
readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
grep -Eq "[[:space:]]__sched_cpucount$" "$candidate_symbols" ||
    fail "candidate does not define __sched_cpucount"
unresolved_symbols="$(awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols")"
[ -z "$unresolved_symbols" ] || { printf '%s\n' "$unresolved_symbols" >&2; fail "candidate retains unresolved symbol"; }
if grep -Eq 'Requesting program interpreter|INTERP' "$candidate_program_headers" ||
    grep -Eq 'NEEDED' "$candidate_dynamic"; then
    fail "candidate selects dynamic runtime"
fi
if grep -Eq '[[:space:]]TLS[[:space:]]|TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
    "$candidate_program_headers" "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate retains TLS"
fi
if grep -Eq '__errno_location|sched_getcpu|sched_getaffinity|sched_setaffinity|pthread_getaffinity_np|pthread_setaffinity_np|sched_getparam|sched_setparam|sched_getscheduler|sched_setscheduler|sched_rr_get_interval|sched_get_priority_(max|min)|sched_yield|alarm|ualarm|getitimer|setitimer|timer_|clock_|timegm|gmtime|localtime|mktime|strftime|strptime|tzset|crabc_core|mimalloc' \
    "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate selects an unowned scheduler/time/runtime dependency"
fi
assert_byte_count_code
env -i "$candidate" || fail "freestanding CPU-count fixture failed"
printf 'x86 static crabc-libc GNU sched CPU-count helper: PASS\n'
