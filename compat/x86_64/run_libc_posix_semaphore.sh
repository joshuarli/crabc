#!/usr/bin/env bash
# Native Linux/x86-64 selected static unnamed POSIX-semaphore evidence.
#
# One project-header C fixture first runs against pinned musl, then through a
# true -nostdlib/-static crabc-libc archive.  It selects only sem_init,
# sem_destroy, sem_getvalue, sem_trywait, sem_wait, and sem_post: private and
# MAP_SHARED pshared value/waiter/futex handoff.  Timed and named semaphores,
# cancellation, and signal-action restart policy remain outside this artifact.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"

fail() { printf 'ERROR: x86 static libc POSIX semaphore: %s\n' "$*" >&2; exit 1; }
require_tool() { command -v "$1" >/dev/null 2>&1 || fail "requires $1"; }

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
    grep -Ev '^(#|$)' "$STATIC_C_ABI_EXPORTS" | LC_ALL=C sort -u >"$expected_path"
    if ! cmp -s "$expected_path" "$symbols_path"; then
        diff -u "$expected_path" "$symbols_path" >&2 || true
        fail "selected static C ABI export surface drifted"
    fi
}

assert_static_closure() {
    local candidate_path="$1"
    readelf --symbols --wide "$candidate_path" >"$candidate_symbols"
    readelf --program-headers --wide "$candidate_path" >"$candidate_program_headers"
    readelf --dynamic --wide "$candidate_path" >"$candidate_dynamic" || true
    readelf --relocs --wide "$candidate_path" >"$candidate_relocations"
    objdump -d "$candidate_path" >"$candidate_disassembly"
    if awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols" | grep -q .; then
        fail "candidate has unresolved symbols"
    fi
    if grep -Eq 'Requesting program interpreter|INTERP|NEEDED' \
        "$candidate_program_headers" "$candidate_dynamic"; then
        fail "candidate is dynamic"
    fi
    grep -Eq '[[:space:]]TLS[[:space:]]' "$candidate_program_headers" \
        || fail "candidate lacks selected errno TLS"
    if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' \
        "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly"; then
        fail "candidate selects dynamic TLS or an unowned runtime dependency"
    fi
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "requires native x86-64" ;; esac
for tool in ar awk cargo cmp diff grep mkdir nm objdump readelf rustup sort timeout; do require_tool "$tool"; done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_posix_semaphore_header_abi.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-posix-semaphore.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
target_dir="$work_dir/cargo-target"; archive="$target_dir/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-posix-semaphore-reference"
candidate="$work_dir/crabc-static-posix-semaphore-candidate"
trace="$work_dir/header-trace"; archive_symbols="$work_dir/archive-symbols"
selected_symbols="$work_dir/selected-c-abi-symbols"; expected_symbols="$work_dir/expected-c-abi-symbols"
archive_relocations="$work_dir/archive-relocations"; candidate_symbols="$work_dir/candidate-symbols"
candidate_program_headers="$work_dir/candidate-program-headers"; candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"; candidate_disassembly="$work_dir/candidate-disassembly"
errno_disassembly="$work_dir/errno-disassembly"
cd "$ROOT_DIR"

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_posix_semaphore_probe.c >/dev/null 2>"$trace"
for header in errno.h semaphore.h sys/mman.h sys/syscall.h fcntl.h features.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$trace" \
        || fail "fixture did not use the project $header header"
done
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" compat/x86_64/libc_posix_semaphore_probe.c -o "$reference"
timeout 10s "$reference" || fail "pinned-musl POSIX-semaphore fixture failed"

# The instruction judge requires the raw futex adapter in the selected
# wrapper. One codegen unit makes that boundary deterministic.
CARGO_TARGET_DIR="$target_dir" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- -C relocation-model=static -C code-model=small -C panic=abort -C codegen-units=1
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"
nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_symbols" "$expected_symbols"
for symbol in sem_destroy sem_getvalue sem_init sem_post sem_trywait sem_wait; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" \
        || fail "archive does not strongly define ${symbol}"
done
for unselected in sem_close sem_open sem_timedwait sem_unlink mq_open malloc calloc realloc free; do
    if grep -Eq "[[:space:]][TW][[:space:]]${unselected}$" "$archive_symbols"; then
        fail "archive accidentally exports unselected ${unselected}"
    fi
done
readelf --relocs --wide "$archive" >"$archive_relocations"
grep -Eq 'R_X86_64_TPOFF(32|64)?' "$archive_relocations" \
    || fail "archive errno lacks an initial-TLS TPOFF relocation"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' "$archive_relocations"; then
    fail "archive selects dynamic TLS or an unowned runtime dependency"
fi

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_POSIX_SEMAPHORE_FREESTANDING \
    -I"$ROOT_DIR/include" -nostdlib -static -Wl,--gc-sections -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    compat/x86_64/libc_posix_semaphore_probe.c \
    compat/x86_64/libc_posix_semaphore_start.S "$archive" -o "$candidate"
assert_static_closure "$candidate"
objdump -d --disassemble=__errno_location "$candidate" >"$errno_disassembly"
grep -Eq '%fs:0x0|%fs:-' "$errno_disassembly" \
    || fail "candidate errno does not use direct fs initial TLS"
grep -Eq 'call.*__crabc_x86_static_tls_bootstrap' \
    compat/x86_64/libc_posix_semaphore_start.S \
    || fail "fixture start does not delegate first-thread TLS to libc"
if grep -Eqi 'arch_prctl|mov[[:space:]]+%rsi,[[:space:]]*%fs:0' \
    compat/x86_64/libc_posix_semaphore_start.S; then
    fail "fixture start must not install a private FS base"
fi
for symbol in sem_destroy sem_getvalue sem_init sem_post sem_trywait sem_wait; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" \
        || fail "candidate lacks ${symbol}"
    objdump -dr --disassemble="$symbol" "$candidate" >"$work_dir/${symbol}-disassembly"
    if grep -Eq 'panic_(bounds_check|nounwind)|rust_begin_unwind|core9panicking|malloc|calloc|realloc|free' \
        "$work_dir/${symbol}-disassembly"; then
        fail "${symbol} selects panic or allocation machinery"
    fi
done
for unselected in sem_close sem_open sem_timedwait sem_unlink; do
    if grep -Eq "[[:space:]]${unselected}$" "$candidate_symbols"; then
        fail "candidate accidentally defines ${unselected}"
    fi
done
grep -Eq 'mov.*\$0xca,%eax|mov.*\$202,%eax' \
    "$work_dir/sem_wait-disassembly" "$work_dir/sem_post-disassembly" \
    || fail "candidate does not materialize futex=202"
grep -Eq '[[:space:]]syscall([[:space:]]|$)' \
    "$work_dir/sem_wait-disassembly" "$work_dir/sem_post-disassembly" \
    || fail "candidate does not execute a futex syscall"
timeout 10s "$candidate" || fail "freestanding POSIX-semaphore fixture failed"

printf 'x86 static libc unnamed POSIX semaphore: PASS\n'
