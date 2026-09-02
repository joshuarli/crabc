#!/usr/bin/env bash
# Native Linux/x86-64 static crabc-libc pthread-barrier evidence.
#
# The same project-header fixture first executes with pinned musl 1.2.6, then
# as a true `-nostdlib -static` candidate linked solely through the selected
# crabc archive. It proves the complete public barrier surface: attribute
# lifecycle/pshared records, count validation, private reusable two-thread
# handoff, and a shared-futex cross-fork round. The fixture's raw mapping,
# fork, wait, clock, and exit plumbing is test-only and does not select a C
# process runtime, CRT, loader, sysroot, or public x86 support.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly EXECUTION_TIMEOUT=30s

fail() {
    printf 'ERROR: x86 static libc pthread barrier: %s\n' "$*" >&2
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
for tool in ar awk cargo cmp diff grep mkdir mktemp nm objdump readelf rustup sort timeout; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_types_header_abi.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_pthread_c11_header_abi.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-pthread-barrier.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
cargo_target="$work_dir/cargo-target"
reference="$work_dir/musl-pthread-barrier-reference"
candidate="$work_dir/crabc-static-pthread-barrier-candidate"
archive="$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
header_trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
archive_elf_symbols="$work_dir/archive-elf-symbols"
selected_symbols="$work_dir/selected-symbols"
expected_symbols="$work_dir/expected-symbols"
archive_relocations="$work_dir/archive-relocations"
archive_disassembly="$work_dir/archive-disassembly"
candidate_symbols="$work_dir/candidate-symbols"
candidate_headers="$work_dir/candidate-program-headers"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"
barrier_disassembly="$work_dir/pthread-barrier-wait-disassembly"
init_disassembly="$work_dir/pthread-barrier-init-disassembly"
errno_disassembly="$work_dir/errno-disassembly"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_pthread_barrier_probe.c >/dev/null 2>"$header_trace"
for header in errno.h pthread.h bits/alltypes.h sys/mman.h sys/syscall.h time.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture did not use project $header"
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -pthread -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" compat/x86_64/libc_pthread_barrier_probe.c \
    -o "$reference"
if timeout "$EXECUTION_TIMEOUT" "$reference"; then
    :
else
    status=$?
    fail "pinned-musl barrier fixture exited ${status}"
fi

CARGO_TARGET_DIR="$cargo_target" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"

nm -A --defined-only "$archive" >"$archive_symbols"
readelf --symbols --wide "$archive" >"$archive_elf_symbols"
assert_selected_c_abi_surface "$archive" "$selected_symbols" "$expected_symbols"
for symbol in __errno_location __crabc_x86_static_tls_bootstrap pthread_create pthread_join \
    pthread_barrierattr_init pthread_barrierattr_destroy \
    pthread_barrierattr_setpshared pthread_barrierattr_getpshared \
    pthread_barrier_init pthread_barrier_destroy pthread_barrier_wait; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" ||
        fail "archive does not define ${symbol}"
done
readelf --relocs --wide "$archive" >"$archive_relocations"
objdump -dr "$archive" >"$archive_disassembly"
grep -Eq 'R_X86_64_TPOFF(32|64)?' "$archive_relocations" ||
    fail "archive lacks the selected worker initial-TLS relocation"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' \
    "$archive_relocations" "$archive_disassembly"; then
    fail "archive selects dynamic TLS or an unowned runtime dependency"
fi
for marker in \
    'src/thread/pthread_barrierattr_init.c::pthread_barrierattr_init' \
    'src/thread/pthread_barrierattr_destroy.c::pthread_barrierattr_destroy' \
    'src/thread/pthread_barrier_init.c::pthread_barrier_init' \
    'src/thread/pthread_barrier_destroy.c::pthread_barrier_destroy' \
    'src/thread/pthread_barrier_wait.c::pthread_barrier_wait' \
    'process-private' 'process-shared' 'vmlock'; do
    grep -Fq "$marker" libc/src/c_abi/x86_64/pthread_barrier.rs ||
        fail "pthread barrier source lacks ${marker}"
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_PTHREAD_BARRIER_FREESTANDING \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    compat/x86_64/libc_pthread_barrier_probe.c \
    compat/x86_64/libc_pthread_barrier_start.S "$archive" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
for symbol in __errno_location __crabc_x86_static_tls_bootstrap pthread_create pthread_join \
    pthread_barrierattr_init pthread_barrierattr_destroy \
    pthread_barrierattr_setpshared pthread_barrierattr_getpshared \
    pthread_barrier_init pthread_barrier_destroy pthread_barrier_wait \
    __crabc_x86_pthread_clone; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" ||
        fail "candidate does not define ${symbol}"
done
for unselected in pthread_mutex_init pthread_mutex_destroy pthread_mutex_lock \
    pthread_cond_init pthread_cond_destroy pthread_cond_wait pthread_rwlock_init \
    pthread_rwlock_destroy pthread_rwlock_rdlock; do
    if grep -Eq "[[:space:]]${unselected}$" "$candidate_symbols"; then
        fail "candidate pulled unselected ${unselected}"
    fi
done
unresolved_symbols="$(awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols")"
if [ -n "$unresolved_symbols" ]; then
    printf '%s\n' "$unresolved_symbols" >&2
    fail "candidate retains an unresolved symbol"
fi
if grep -Eq 'Requesting program interpreter|INTERP' "$candidate_headers" ||
    grep -Eq 'NEEDED' "$candidate_dynamic"; then
    fail "candidate selected a dynamic runtime"
fi
grep -Eq '[[:space:]]TLS[[:space:]]' "$candidate_headers" ||
    fail "candidate lacks the selected initial-TLS segment"
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
grep -Eq 'call.*__crabc_x86_static_tls_bootstrap' \
    compat/x86_64/libc_pthread_barrier_start.S ||
    fail "fixture start does not delegate first-thread TLS to libc"
if grep -Eqi 'arch_prctl|mov[[:space:]]+%rsi,[[:space:]]*%fs:0' \
    compat/x86_64/libc_pthread_barrier_start.S; then
    fail "fixture start must not install a private FS base"
fi
objdump -d --disassemble=pthread_barrier_wait "$candidate" >"$barrier_disassembly"
grep -Eq '\bsyscall\b' "$barrier_disassembly" ||
    fail "pthread_barrier_wait lacks its futex syscall"
grep -Eq '\$0xca,%eax|\$0xca,%rax|\$0x00000000000000ca,%rax' \
    "$barrier_disassembly" ||
    fail "pthread_barrier_wait lacks futex=202"
grep -Eq 'lock[[:space:]]+(xadd|cmpxchg)' "$barrier_disassembly" ||
    fail "pthread_barrier_wait lacks x86 atomic handoff"
objdump -d --disassemble=pthread_barrier_init "$candidate" >"$init_disassembly"
if grep -Eq '[[:space:]]syscall([[:space:]]|$)|%fs:' "$init_disassembly"; then
    fail "pthread_barrier_init must not select a syscall or TLS seam"
fi

if timeout "$EXECUTION_TIMEOUT" "$candidate"; then
    :
else
    status=$?
    fail "freestanding barrier fixture exited ${status}"
fi

printf 'x86 static crabc-libc pthread barrier: PASS\n'
