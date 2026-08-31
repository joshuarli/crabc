#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc timer_gettime error ABI.
#
# The same project-header C fixture first executes through pinned musl 1.2.6,
# then through a true dependency-free -nostdlib -static candidate. It invokes
# only fresh-process invalid nonnegative opaque timer values with writable
# itimerspec storage and never observes a valid POSIX timer. This is a
# rejected-handle/output-preservation ABI artifact, not timer support.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"

fail() {
    printf 'ERROR: x86 static libc timer_gettime: %s\n' "$*" >&2
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
    local archive_path="$1" symbols_path="$2" expected_path="$3"
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

assert_timer_gettime_syscall() {
    local disassembly="$work_dir/timer-gettime-disassembly"

    objdump -d --disassemble=timer_gettime "$candidate" >"$disassembly"
    # The two System V AMD64 arguments already occupy the kernel's rdi/rsi
    # registers. Musl's selected direct branch translates raw errors through
    # the selected initial-TLS errno slot.
    grep -Eq '\$0xe0(,|[[:space:]]|$)' "$disassembly" ||
        fail "timer_gettime lacks syscall 224"
    grep -Eq '[[:space:]]syscall([[:space:]]|$)' "$disassembly" ||
        fail "timer_gettime lacks the Linux syscall instruction"
    grep -Eq '%fs:|__errno_location' "$disassembly" ||
        fail "timer_gettime must publish raw failure through errno TLS"
}

require_native_linux_x86_64
for tool in ar awk cargo cmp diff env grep mkdir nm objdump readelf rustup sort; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_timer_gettime_header_abi.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-timer-gettime.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
target_dir="$work_dir/cargo-target"
archive="$target_dir/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-timer-gettime-reference"
candidate="$work_dir/crabc-static-timer-gettime-candidate"
header_trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
selected_symbols="$work_dir/selected-c-abi-symbols"
expected_symbols="$work_dir/expected-c-abi-symbols"
archive_relocations="$work_dir/archive-relocations"
candidate_symbols="$work_dir/candidate-symbols"
headers="$work_dir/candidate-program-headers"
dynamic="$work_dir/candidate-dynamic"
relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"
errno_disassembly="$work_dir/errno-disassembly"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_POSIX_C_SOURCE=200809L -I "$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_timer_gettime_probe.c >/dev/null 2>"$header_trace"
for header in errno.h time.h features.h sys/syscall.h bits/alltypes.h bits/syscall.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture did not use the project <$header>"
done
"$ORACLE_CC" -std=c11 -D_POSIX_C_SOURCE=200809L -fno-builtin \
    -fno-stack-protector -I "$ROOT_DIR/include" \
    compat/x86_64/libc_timer_gettime_probe.c -o "$reference"
"$reference" || fail "pinned-musl timer_gettime fixture failed"

CARGO_TARGET_DIR="$target_dir" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"
nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_symbols" "$expected_symbols"
for selected in __errno_location timer_gettime; do
    grep -Eq "[[:space:]][TW][[:space:]]${selected}$" "$archive_symbols" ||
        fail "archive does not define ${selected}"
done
for marker in 'src/time/timer_gettime.c' 'SYS_TIMER_GETTIME' \
    'raw_syscall::syscall2' 'c_status(result)'; do
    grep -Fq "$marker" libc/src/c_abi/x86_64/timer_gettime.rs ||
        fail "timer_gettime source lacks ${marker}"
done
readelf --relocs --wide "$archive" >"$archive_relocations"
grep -Eq 'R_X86_64_TPOFF(32|64)?' "$archive_relocations" ||
    fail "archive errno lacks an initial-TLS relocation"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' \
    "$archive_relocations" "$archive_symbols"; then
    fail "archive selects dynamic TLS or an unowned runtime dependency"
fi

"$ORACLE_CC" -std=c11 -D_POSIX_C_SOURCE=200809L \
    -DCRABC_TIMER_GETTIME_FREESTANDING -I "$ROOT_DIR/include" \
    -nostdlib -static -fno-pie -no-pie -ffreestanding -fno-builtin \
    -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    compat/x86_64/libc_timer_gettime_probe.c \
    compat/x86_64/libc_timer_gettime_start.S "$archive" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$headers"
readelf --dynamic --wide "$candidate" >"$dynamic" || true
readelf --relocs --wide "$candidate" >"$relocations"
objdump -d "$candidate" >"$candidate_disassembly"
for selected in __errno_location timer_gettime; do
    grep -Eq "[[:space:]]${selected}$" "$candidate_symbols" ||
        fail "candidate does not define ${selected}"
done
if awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols" | grep -q .; then
    fail "candidate has unresolved symbols"
fi
if grep -Eq 'Requesting program interpreter|INTERP|NEEDED' "$headers" "$dynamic"; then
    fail "candidate is dynamic"
fi
grep -Eq '[[:space:]]TLS[[:space:]]' "$headers" ||
    fail "candidate lacks the initial-TLS errno segment"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
    "$relocations" "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate retains a dynamic TLS model"
fi
if grep -Eq 'crabc_core|mimalloc|sha_crypt' "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate selects an unowned runtime dependency"
fi
for unselected in timer_create timer_delete timer_getoverrun timer_settime \
    timerfd_create timerfd_settime timerfd_gettime getitimer setitimer alarm \
    ualarm sleep usleep clock_gettime clock_getres clock_settime \
    clock_nanosleep sched_getcpu sched_getscheduler sched_yield sched_getparam \
    sched_setparam sched_setscheduler sched_rr_get_interval time timegm \
    gmtime_r localtime_r pthread_getcpuclockid; do
    if grep -Eq "[[:space:]]${unselected}$" "$candidate_symbols"; then
        fail "candidate unexpectedly selects unselected ${unselected}"
    fi
done
objdump -d --disassemble=__errno_location "$candidate" >"$errno_disassembly"
grep -Eq '%fs:0x0|%fs:-' "$errno_disassembly" ||
    fail "candidate errno does not use direct fs initial TLS"

assert_timer_gettime_syscall
env -i "$candidate" || fail "freestanding timer_gettime fixture failed"
printf 'x86 static crabc-libc timer_gettime: PASS\n'
