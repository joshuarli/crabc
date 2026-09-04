#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc C11 thrd_sleep evidence.
#
# The same project-header C fixture first executes through pinned musl, then
# as a true -nostdlib -static candidate linked solely through the selected
# crabc archive. It proves only thrd_sleep's zero/-1/-2 convention and its
# direct clock_nanosleep=230 implementation or delegation without errno
# mutation. Local raw timer calls merely trigger deterministic interruption.
# It does not prove the separately recorded thrd_yield adapter, cancellation,
# synchronization, TSS, lifecycle,
# libc.so, CRT, loader, sysroot, or public x86 support.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"

fail() {
    printf 'ERROR: x86 static libc thrd_sleep: %s\n' "$*" >&2
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

    # Inspect only crate-owned C object members. Compiler-builtins remains
    # toolchain support rather than a selected C ABI export surface.
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

assert_clock_nanosleep_syscall() {
    local symbol="$1"
    local disassembly="$work_dir/${symbol}-disassembly"

    objdump -d --disassemble="$symbol" "$candidate" >"$disassembly"
    grep -Eq '\$0xe6(,|[[:space:]]|$)' "$disassembly" ||
        fail "${symbol} lacks fixed clock_nanosleep syscall 230"
    grep -Eq '[[:space:]]syscall([[:space:]]|$)' "$disassembly" ||
        fail "${symbol} lacks the clock_nanosleep syscall"
    grep -Fq '%r10' "$disassembly" ||
        fail "${symbol} lacks the x86 fourth-argument r10 path"
    if grep -Eq '%fs:' "$disassembly"; then
        fail "${symbol} must not mutate errno TLS"
    fi
}

assert_thrd_sleep_path() {
    local thrd_disassembly="$work_dir/thrd-sleep-disassembly"

    objdump -d --disassemble=thrd_sleep "$candidate" >"$thrd_disassembly"
    if grep -Eq '%fs:' "$thrd_disassembly"; then
        fail "thrd_sleep must not mutate errno TLS"
    fi
    if grep -Eq '\$0xe6(,|[[:space:]]|$)' "$thrd_disassembly"; then
        grep -Eq '[[:space:]]syscall([[:space:]]|$)' "$thrd_disassembly" ||
            fail "thrd_sleep has clock_nanosleep number without syscall"
        grep -Fq '%r10' "$thrd_disassembly" ||
            fail "thrd_sleep lacks the x86 fourth-argument r10 path"
        return
    fi
    grep -Eq 'call.*<clock_nanosleep>' "$thrd_disassembly" ||
        fail "thrd_sleep neither implements nor delegates clock_nanosleep"
    assert_clock_nanosleep_syscall clock_nanosleep
}

require_native_linux_x86_64
for tool in ar cargo cmp diff grep mkdir nm objdump readelf rustup sort; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_pthread_c11_header_abi.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-thrd-sleep.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
cargo_target="$work_dir/cargo-target"
reference="$work_dir/musl-thrd-sleep-reference"
candidate="$work_dir/crabc-static-thrd-sleep-candidate"
archive="$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
header_trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
selected_c_abi_symbols="$work_dir/selected-c-abi-symbols"
expected_c_abi_symbols="$work_dir/expected-c-abi-symbols"
archive_relocations="$work_dir/archive-relocations"
candidate_symbols="$work_dir/candidate-symbols"
candidate_program_headers="$work_dir/candidate-program-headers"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"
errno_disassembly="$work_dir/errno-disassembly"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_thrd_sleep_probe.c >/dev/null 2>"$header_trace"
for header in errno.h features.h signal.h threads.h time.h sys/syscall.h \
    bits/alltypes.h bits/signal.h bits/syscall.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture did not use the project $header header"
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" compat/x86_64/libc_thrd_sleep_probe.c \
    -o "$reference"
if "$reference"; then
    :
else
    status=$?
    fail "pinned-musl thrd_sleep fixture exited ${status}"
fi

CARGO_TARGET_DIR="$cargo_target" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"

nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_c_abi_symbols" \
    "$expected_c_abi_symbols"
for symbol in __errno_location thrd_sleep; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" ||
        fail "archive does not define ${symbol}"
done
 # The shared archive's separately evidenced normal private pthread-mutex,
 # private condition, and TSD lifecycle blocks are deliberately outside this
 # direct sleep adapter.
for unselected in pthread_mutex_timedlock pthread_mutex_consistent \
    pthread_cond_timedwait \
    timer_create \
    setitimer ualarm malloc free calloc realloc; do
    if grep -Eq "[[:space:]][TW][[:space:]]${unselected}$" "$archive_symbols"; then
        fail "archive accidentally exports unselected ${unselected}"
    fi
done
readelf --relocs --wide "$archive" >"$archive_relocations"
grep -Eq 'R_X86_64_TPOFF(32|64)?' "$archive_relocations" ||
    fail "archive errno lacks an initial-TLS TPOFF relocation"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' \
    "$archive_relocations"; then
    fail "archive selects dynamic TLS or an unowned runtime dependency"
fi

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_THRD_SLEEP_FREESTANDING \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie \
    -ffreestanding -fno-builtin -fno-stack-protector -Wl,-e,_start \
    -Wl,--no-undefined compat/x86_64/libc_thrd_sleep_probe.c \
    compat/x86_64/libc_thrd_sleep_start.S "$archive" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
# Link-time inlining may fold the sibling `clock_nanosleep` body into
# `thrd_sleep`; the path proof below accepts that direct implementation or an
# explicit retained delegation. Only the selected C11 entry itself must remain
# a final-ELF definition.
for symbol in __errno_location thrd_sleep; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" ||
        fail "candidate does not define ${symbol}"
done
if grep -Eq '[[:space:]]sleep$' "$candidate_symbols"; then
    fail "thrd_sleep candidate unexpectedly pulls separately selected sleep"
fi
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
    fail "candidate lacks the selected errno TLS segment"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
    "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate relocations retain a dynamic TLS model"
fi
if grep -Eq 'crabc_core|mimalloc|sha_crypt' \
    "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate selects an unowned runtime dependency"
fi
objdump -d --disassemble=__errno_location "$candidate" >"$errno_disassembly"
grep -Eq '%fs:0x0|%fs:-' "$errno_disassembly" ||
    fail "candidate errno does not use direct fs initial TLS"

assert_thrd_sleep_path

if "$candidate"; then
    :
else
    status=$?
    fail "freestanding thrd_sleep fixture exited ${status}"
fi

printf 'x86 static crabc-libc thrd_sleep: PASS\n'
