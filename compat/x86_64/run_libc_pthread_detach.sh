#!/usr/bin/env bash
# Native Linux/x86-64 bounded static crabc-libc pthread/C11 detach evidence.
#
# The project-header fixture first runs comparable standard detach routes with
# pinned musl 1.2.6, then a true `-nostdlib -static` candidate.  The candidate
# alone selects self-detach completion and 64-slot lazy detached reaping after
# CLONE_CHILD_CLEARTID; join-after-detach is likewise candidate-only
# diagnostic evidence, not general pthread/C11 lifecycle support.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"

fail() {
    printf 'ERROR: x86 static libc pthread/C11 detach: %s\n' "$*" >&2
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
        sort -u >"$symbols_path"
    [ -f "$STATIC_C_ABI_EXPORTS" ] || fail "missing static C ABI export contract"
    grep -Ev '^(#|$)' "$STATIC_C_ABI_EXPORTS" | LC_ALL=C sort -u >"$expected_path"
    if ! cmp -s "$expected_path" "$symbols_path"; then
        diff -u "$expected_path" "$symbols_path" >&2 || true
        fail "selected static C ABI export surface drifted"
    fi
}

require_native_linux_x86_64
for tool in ar cargo cmp diff grep mkdir nm objdump readelf rustup sed sort; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_types_header_abi.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_pthread_c11_header_abi.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-pthread-detach.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
cargo_target="$work_dir/cargo-target"
reference="$work_dir/musl-pthread-detach-reference"
candidate="$work_dir/crabc-static-pthread-detach-candidate"
archive="$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
header_trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
archive_elf_symbols="$work_dir/archive-elf-symbols"
selected_c_abi_symbols="$work_dir/selected-c-abi-symbols"
expected_c_abi_symbols="$work_dir/expected-c-abi-symbols"
archive_relocations="$work_dir/archive-relocations"
archive_disassembly="$work_dir/archive-disassembly"
candidate_symbols="$work_dir/candidate-symbols"
candidate_program_headers="$work_dir/candidate-program-headers"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"
errno_disassembly="$work_dir/errno-disassembly"
clone_disassembly="$work_dir/pthread-clone-disassembly"
detach_disassembly="$work_dir/pthread-detach-disassembly"
thrd_detach_disassembly="$work_dir/thrd-detach-disassembly"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_pthread_detach_probe.c >/dev/null 2>"$header_trace"
for header in errno.h pthread.h threads.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture did not use the project $header header"
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -pthread -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" compat/x86_64/libc_pthread_detach_probe.c -o "$reference"
"$reference"

CARGO_TARGET_DIR="$cargo_target" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"

nm -A --defined-only "$archive" >"$archive_symbols"
readelf --symbols --wide "$archive" >"$archive_elf_symbols"
assert_selected_c_abi_surface "$archive" "$selected_c_abi_symbols" \
    "$expected_c_abi_symbols"
for symbol in __errno_location __crabc_x86_static_tls_bootstrap \
    pthread_create pthread_exit pthread_join pthread_detach \
    thrd_create thrd_exit thrd_join thrd_detach; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" ||
        fail "archive does not define ${symbol}"
done
grep -Eq 'GLOBAL +HIDDEN +.*__crabc_x86_pthread_clone$' "$archive_elf_symbols" ||
    fail "archive pthread clone boundary is not hidden"
grep -Eq 'GLOBAL +HIDDEN +.*__crabc_x86_static_tls_bootstrap$' "$archive_elf_symbols" ||
    fail "archive Static Initial TLS v1 bootstrap is not hidden"
readelf --relocs --wide "$archive" >"$archive_relocations"
objdump -dr "$archive" >"$archive_disassembly"
grep -Eq 'R_X86_64_TPOFF(32|64)?' "$archive_relocations" ||
    fail "archive errno lacks an initial-TLS TPOFF relocation"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' \
    "$archive_relocations" "$archive_disassembly"; then
    fail "archive selects dynamic TLS or an unowned runtime dependency"
fi

# The selected detach state transition is prompt: it marks ownership but does
# not wait or tear mappings down.  Later pthread_create is the selected lazy
# reaping entry and must retain the child-clear-tid lifecycle boundary.
grep -Fq 'CLONE_CHILD_CLEARTID' libc/src/c_abi/x86_64/pthread_create_join.rs ||
    fail "selected worker source lacks CLONE_CHILD_CLEARTID"
detach_source="$(sed -n '/pub(super) unsafe fn detach_selected_worker/,/\/\/\/ Detach one selected static pthread\/C11 worker/p' libc/src/c_abi/x86_64/pthread_create_join.rs)"
printf '%s\n' "$detach_source" | grep -Fq 'SelectedWorkerLifecycleState::Detached' ||
    fail "selected detach source lacks its detached ownership claim"
if printf '%s\n' "$detach_source" | grep -Eq 'reap_finished_detached_selected_workers|reclaim_withdrawn_selected_worker|raw_syscall|unmap_worker'; then
    fail "selected detach source must remain state-only without a wait or reaper"
fi
detached_reaper_source="$(sed -n '/fn claim_finished_detached_selected_worker/,/\/\/\/ Release mappings for a registry-withdrawn/p' libc/src/c_abi/x86_64/pthread_create_join.rs)"
for marker in 'SelectedWorkerLifecycleState::Detached.encode()' \
    'child_tid.load(Ordering::Acquire)' \
    'SelectedWorkerLifecycleState::DetachedReclaiming.encode()' \
    'release_selected_worker_locked'; do
    printf '%s\n' "$detached_reaper_source" | grep -Fq "$marker" ||
        fail "selected detached reaper lacks ${marker}"
done
[ "$(grep -Fc 'reap_finished_detached_selected_workers();' libc/src/c_abi/x86_64/pthread_create_join.rs)" -eq 2 ] ||
    fail "selected detached reaping must occur only at later create/join boundaries"

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_PTHREAD_DETACH_FREESTANDING \
    -DCRABC_PTHREAD_DETACH_SELECTED_WORKER_LIMIT=64 -I"$ROOT_DIR/include" \
    -nostdlib -static -fno-pie -no-pie -ffreestanding -fno-builtin \
    -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    compat/x86_64/libc_pthread_detach_probe.c \
    compat/x86_64/libc_pthread_detach_start.S "$archive" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
for symbol in __errno_location __crabc_x86_static_tls_bootstrap \
    pthread_create pthread_exit pthread_join pthread_detach \
    thrd_create thrd_exit thrd_join thrd_detach __crabc_x86_pthread_clone; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" ||
        fail "candidate does not define ${symbol}"
done
unresolved_symbols="$(awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols")"
if [ -n "$unresolved_symbols" ]; then
    printf '%s\n' "$unresolved_symbols" >&2
    fail "candidate retains an unresolved symbol"
fi
if grep -Eq 'Requesting program interpreter|INTERP' "$candidate_program_headers" ||
    grep -Eq 'NEEDED' "$candidate_dynamic"; then
    fail "candidate selected a dynamic runtime"
fi
grep -Eq '[[:space:]]TLS[[:space:]]' "$candidate_program_headers" ||
    fail "candidate lacks the selected errno TLS segment"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
    "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate relocations retain a dynamic TLS model"
fi
if grep -Eq 'crabc_core|mimalloc|sha_crypt' "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate selects an unowned runtime dependency"
fi
objdump -d --disassemble=__errno_location "$candidate" >"$errno_disassembly"
grep -Eq '%fs:0x0|%fs:-' "$errno_disassembly" ||
    fail "candidate errno does not use direct fs initial TLS"
grep -Eq 'call.*__crabc_x86_static_tls_bootstrap' \
    compat/x86_64/libc_pthread_detach_start.S ||
    fail "fixture start does not delegate first-thread TLS to libc"
if grep -Eqi 'arch_prctl|mov[[:space:]]+%rsi,[[:space:]]*%fs:0' \
    compat/x86_64/libc_pthread_detach_start.S; then
    fail "fixture start must not install a private FS base"
fi
objdump -d --disassemble=__crabc_x86_pthread_clone "$candidate" >"$clone_disassembly"
grep -Eq '\bsyscall\b' "$clone_disassembly" ||
    fail "pthread clone boundary lacks an x86 syscall instruction"
grep -Eq '\$0x38,%al|\$0x0000000000000038,%rax|\$0x38,%rax' "$clone_disassembly" ||
    fail "pthread clone boundary lacks clone syscall number 56"
grep -Eq '0x8\(%rsp\),%r10' "$clone_disassembly" ||
    fail "pthread clone boundary lacks the seventh-argument child-tid shuffle"
objdump -d --disassemble=pthread_detach "$candidate" >"$detach_disassembly"
objdump -d --disassemble=thrd_detach "$candidate" >"$thrd_detach_disassembly"
if grep -Eq '\bsyscall\b' "$detach_disassembly" "$thrd_detach_disassembly"; then
    fail "detach must be a prompt state transition, not a wait or reaper"
fi
if "$candidate"; then
    :
else
    candidate_status=$?
    fail "candidate execution exited ${candidate_status}"
fi

printf 'x86 static crabc-libc pthread/C11 detach: PASS\n'
