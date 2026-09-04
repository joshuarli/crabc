#!/usr/bin/env bash
# Native Linux/x86-64 opt-in static crabc-libc getitimer/setitimer evidence.
#
# The project-header fixture first runs through pinned musl 1.2.6 and then
# through a true archive-free static candidate. It owns only the public C
# interval-timer control pair; raw syscalls in the fixture provide setup and
# output comparison, while alarm/ualarm and signal policy remain separate.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly FEATURE=x86-interval-timers
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly INITIAL_TLS_BYTES=4096
readonly INITIAL_TLS_ALIGNMENT=64

fail() {
    printf 'ERROR: x86 static libc interval timers: %s\n' "$*" >&2
    exit 1
}

require_tool() {
    command -v "$1" >/dev/null 2>&1 || fail "requires $1"
}

collect_global_surface() {
    local archive_path="$1" output_path="$2" members_path="$3"
    local -a members

    mapfile -t members < <(ar t "$archive_path" | grep -E '^c\..+\.rcgu\.o$')
    [ "${#members[@]}" -gt 0 ] || fail "archive has no crabc-libc object members"
    mkdir "$members_path"
    (
        cd "$members_path"
        ar x "$archive_path" "${members[@]}"
        nm -g --defined-only --format=posix "${members[@]}"
    ) | awk '$2 ~ /^[TWDVBR]$/ && $1 !~ /^(_R|_ZN|DW\.ref\.|anon\.)/ && $1 != "crabc_x86_64_signal_restorer" && $1 != "__crabc_x86_pthread_clone" { print $1 }' |
        LC_ALL=C sort -u >"$output_path"
}

assert_fixture_tls_capacity() {
    local filesz memsz alignment

    read -r filesz memsz alignment < <(
        awk '$1 == "TLS" { print $5, $6, $NF; exit }' "$candidate_program_headers"
    )
    [ -n "${filesz:-}" ] || fail "candidate lacks a parsable PT_TLS segment"
    (( filesz == 0 )) || fail "fixture TLS scratch cannot initialize PT_TLS data"
    (( memsz > 0 && memsz <= INITIAL_TLS_BYTES )) ||
        fail "fixture TLS scratch is too small"
    (( alignment > 0 && alignment <= INITIAL_TLS_ALIGNMENT &&
        INITIAL_TLS_ALIGNMENT % alignment == 0 )) ||
        fail "fixture TLS alignment is incompatible"
}

assert_feature_delta() {
    local baseline_symbols="$1" featured_symbols="$2" additions="$3" removed="$4"

    comm -23 "$baseline_symbols" "$featured_symbols" >"$removed"
    if [ -s "$removed" ]; then
        diff -u "$baseline_symbols" "$featured_symbols" >&2 || true
        fail "${FEATURE} removes a default C ABI export"
    fi
    comm -13 "$baseline_symbols" "$featured_symbols" >"$additions"
    if ! cmp -s <(printf 'getitimer\nsetitimer\n') "$additions"; then
        diff -u <(printf 'getitimer\nsetitimer\n') "$additions" >&2 || true
        fail "${FEATURE} changes more than the two interval-timer exports"
    fi
}

assert_named_syscall() {
    local symbol="$1" syscall_hex="$2"
    local disassembly="$work_dir/${symbol}-disassembly"

    objdump -d --disassemble="$symbol" "$candidate" >"$disassembly"
    grep -Fq "0x${syscall_hex}" "$disassembly" ||
        fail "$symbol lacks Linux syscall 0x$syscall_hex"
    grep -Eq '[[:space:]]syscall([[:space:]]|$)' "$disassembly" ||
        fail "$symbol lacks its Linux syscall instruction"
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "requires native x86-64" ;; esac
for tool in ar awk cargo cmp comm diff grep mkdir nm objdump readelf rustup sort; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -f "$STATIC_C_ABI_EXPORTS" ] || fail "missing static C ABI export contract"
for symbol in getitimer setitimer; do
    if grep -Fqx "$symbol" "$STATIC_C_ABI_EXPORTS"; then
        fail "default static export ratchet absorbed opt-in $symbol"
    fi
done

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_x86_getitimer_reference.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_x86_setitimer_reference.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-interval-timers.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
baseline_target="$work_dir/cargo-baseline"
featured_target="$work_dir/cargo-featured"
baseline_archive="$baseline_target/x86_64-unknown-linux-musl/debug/libc.a"
featured_archive="$featured_target/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-interval-timers-reference"
candidate="$work_dir/crabc-interval-timers-candidate"
header_trace="$work_dir/header-trace"
baseline_symbols="$work_dir/baseline-symbols"
featured_symbols="$work_dir/featured-symbols"
expected_symbols="$work_dir/expected-symbols"
archive_symbols="$work_dir/featured-archive-symbols"
feature_additions="$work_dir/feature-additions"
feature_removed="$work_dir/feature-removed"
owner_object="$work_dir/interval-timers-owner.o"
owner_symbols="$work_dir/interval-timers-owner-symbols"
owner_relocations="$work_dir/interval-timers-owner-relocations"
owner_disassembly="$work_dir/interval-timers-owner-disassembly"
candidate_symbols="$work_dir/candidate-symbols"
candidate_program_headers="$work_dir/candidate-program-headers"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"
errno_disassembly="$work_dir/errno-disassembly"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_POSIX_C_SOURCE=200809L -U_GNU_SOURCE \
    -I "$ROOT_DIR/include" -E -H compat/x86_64/libc_interval_timers_probe.c \
    >/dev/null 2>"$header_trace"
for header in errno.h stddef.h sys/time.h sys/select.h sys/syscall.h \
    bits/alltypes.h bits/syscall.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture did not use project <$header>"
done

"$ORACLE_CC" -std=c11 -D_POSIX_C_SOURCE=200809L -U_GNU_SOURCE \
    -fno-builtin -fno-stack-protector -I "$ROOT_DIR/include" \
    compat/x86_64/libc_interval_timers_probe.c -o "$reference"
"$reference" || fail "pinned-musl interval-timers fixture failed"

CARGO_TARGET_DIR="$baseline_target" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
CARGO_TARGET_DIR="$featured_target" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl --features "$FEATURE" -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$baseline_archive" ] || fail "baseline cargo build did not emit libc.a"
[ -f "$featured_archive" ] || fail "feature cargo build did not emit libc.a"
collect_global_surface "$baseline_archive" "$baseline_symbols" \
    "$work_dir/baseline-c-abi-members"
collect_global_surface "$featured_archive" "$featured_symbols" \
    "$work_dir/featured-c-abi-members"
grep -Ev '^(#|$)' "$STATIC_C_ABI_EXPORTS" | LC_ALL=C sort -u >"$expected_symbols"
cmp -s "$expected_symbols" "$baseline_symbols" || {
    diff -u "$expected_symbols" "$baseline_symbols" >&2 || true
    fail "baseline static C ABI export surface drifted"
}
assert_feature_delta "$baseline_symbols" "$featured_symbols" "$feature_additions" "$feature_removed"
nm -A --defined-only "$featured_archive" >"$archive_symbols"
for symbol in __errno_location __crabc_x86_static_tls_bootstrap getitimer setitimer; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" ||
        fail "archive does not define $symbol"
done
mapfile -t owner_members < <(
    nm -A --defined-only "$featured_archive" |
        awk '$NF == "getitimer" || $NF == "setitimer" { member = $1; sub(/^.*\.a:/, "", member); sub(/:.*$/, "", member); print member }' |
        LC_ALL=C sort -u
)
[ "${#owner_members[@]}" -eq 1 ] || fail "feature archive has ambiguous interval-timer ownership"
ar p "$featured_archive" "${owner_members[0]}" >"$owner_object"
readelf --symbols --wide "$owner_object" >"$owner_symbols"
readelf --relocs --wide "$owner_object" >"$owner_relocations"
objdump -dr "$owner_object" >"$owner_disassembly"
for symbol in getitimer setitimer; do
    grep -Eq "FUNC[[:space:]]+GLOBAL[[:space:]]+DEFAULT.*[[:space:]]${symbol}$" "$owner_symbols" ||
        fail "feature owner lacks global-default $symbol"
done
grep -Eq 'R_X86_64_TPOFF(32|64)?' "$owner_relocations" ||
    fail "feature owner lacks direct initial-TLS errno relocation"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' \
    "$owner_relocations" "$owner_symbols" "$owner_disassembly"; then
    fail "feature owner retains dynamic TLS or unowned runtime dependency"
fi

"$ORACLE_CC" -std=c11 -D_POSIX_C_SOURCE=200809L -U_GNU_SOURCE \
    -DCRABC_INTERVAL_TIMERS_FREESTANDING -I "$ROOT_DIR/include" \
    -nostdlib -static -fno-pie -no-pie -ffreestanding -fno-builtin \
    -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    compat/x86_64/libc_interval_timers_probe.c \
    compat/x86_64/libc_interval_timers_start.S "$featured_archive" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
for symbol in __errno_location __crabc_x86_static_tls_bootstrap getitimer setitimer; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" ||
        fail "candidate lacks $symbol"
done
for unrelated in alarm ualarm timer_create timer_delete timer_getoverrun \
    timer_gettime timer_settime timerfd_create timerfd_settime timerfd_gettime \
    sigaction signal sigemptyset sigfillset sigaddset sigdelset sigprocmask \
    sigpending sigsuspend sigpause kill raise sigqueue signalfd pthread_create \
    malloc free calloc realloc; do
    if grep -Eq "[[:space:]]${unrelated}$" "$candidate_symbols"; then
        fail "candidate unexpectedly pulls $unrelated"
    fi
done
if awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols" | grep -q .; then
    fail "candidate has unresolved symbols"
fi
if grep -Eq 'Requesting program interpreter|INTERP|NEEDED' \
    "$candidate_program_headers" "$candidate_dynamic"; then
    fail "candidate is dynamic"
fi
grep -Eq '[[:space:]]TLS[[:space:]]' "$candidate_program_headers" ||
    fail "candidate lacks errno TLS"
assert_fixture_tls_capacity
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' \
    "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate retains dynamic TLS or unowned dependency"
fi
objdump -d --disassemble=__errno_location "$candidate" >"$errno_disassembly"
grep -Eq '%fs:0x0|%fs:-' "$errno_disassembly" ||
    fail "candidate errno does not use direct initial TLS"
assert_named_syscall getitimer 24
assert_named_syscall setitimer 26

"$candidate" || fail "freestanding interval-timers fixture failed"
printf 'x86 opt-in static libc interval timers: PASS\n'
