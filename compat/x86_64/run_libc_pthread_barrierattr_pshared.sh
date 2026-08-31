#!/usr/bin/env bash
# Native Linux/x86-64 bounded static pthread barrier-attribute pshared evidence.
#
# The same project-header fixture first runs against pinned musl 1.2.6, then
# as a true `-nostdlib -static` executable linked only with the selected crabc
# archive. It proves exactly pthread_barrierattr_setpshared/getpshared's
# four-byte record behavior: accepted 0/1 values replace the word with
# 0/INT_MIN, invalid values preserve it, and every nonzero word queries as 1.
# It does not select attribute lifecycle, barrier initialization or operation,
# process-shared barrier operation, thread, TLS, synchronization, cancellation,
# CRT, loader, sysroot, or public x86 support.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly EXECUTION_TIMEOUT=10s

fail() {
    printf 'ERROR: x86 static pthread barrierattr pshared: %s\n' "$*" >&2
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

assert_no_unselected_barrierattr_exports() {
    local symbols_path="$1"
    local unselected

    for unselected in pthread_barrierattr_init pthread_barrierattr_destroy \
        pthread_barrier_init pthread_barrier_destroy pthread_barrier_wait; do
        [ "$symbols_path" = "$candidate_symbols" ] ||
            fail "barrierattr pshared sibling exclusions apply only to the final candidate"
        if grep -Eq "[[:space:]]${unselected}$" "$symbols_path"; then
            fail "artifact accidentally exports unselected ${unselected}"
        fi
    done
}

assert_direct_record_path() {
    local symbol
    local disassembly

    for symbol in pthread_barrierattr_setpshared pthread_barrierattr_getpshared; do
        disassembly="$work_dir/${symbol}-disassembly"
        objdump -d --disassemble="$symbol" "$candidate" >"$disassembly"
        if grep -Eq '[[:space:]](syscall|call)([[:space:]]|$)|%fs:' "$disassembly"; then
            fail "$symbol must remain a direct TLS-free, syscall-free record operation"
        fi
    done
}

require_native_linux_x86_64
for tool in ar awk cargo cmp diff grep mkdir mktemp nm objdump readelf rustup sort timeout; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_pthread_c11_header_abi.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-pthread-barrierattr-pshared.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
cargo_target="$work_dir/cargo-target"
reference="$work_dir/musl-pthread-barrierattr-pshared-reference"
candidate="$work_dir/crabc-static-pthread-barrierattr-pshared-candidate"
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

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_pthread_barrierattr_pshared_probe.c >/dev/null 2>"$header_trace"
for header in errno.h pthread.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture did not use project $header"
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -pthread -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" compat/x86_64/libc_pthread_barrierattr_pshared_probe.c \
    -o "$reference"
if timeout "$EXECUTION_TIMEOUT" "$reference"; then
    :
else
    status=$?
    fail "pinned-musl barrierattr pshared fixture exited ${status}"
fi

CARGO_TARGET_DIR="$cargo_target" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"

nm -A --defined-only "$archive" >"$archive_symbols"
readelf --symbols --wide "$archive" >"$archive_elf_symbols"
assert_selected_c_abi_surface "$archive" "$selected_symbols" "$expected_symbols"
for symbol in pthread_barrierattr_setpshared pthread_barrierattr_getpshared; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" ||
        fail "archive does not define ${symbol}"
done
readelf --relocs --wide "$archive" >"$archive_relocations"
objdump -dr "$archive" >"$archive_disassembly"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' \
    "$archive_relocations" "$archive_disassembly"; then
    fail "archive selects dynamic TLS or an unowned runtime dependency"
fi
for marker in 'src/thread/pthread_barrierattr_setpshared.c::pthread_barrierattr_setpshared' \
    'src/thread/pthread_attr_get.c::pthread_barrierattr_getpshared' \
    'pshared > 1U' 'a->__attr = pshared ? INT_MIN : 0' \
    '*pshared = !!a->__attr' 'No selected barrier initializer consumes the record'; do
    grep -Fq "$marker" libc/src/c_abi/x86_64/pthread_barrierattr_pshared.rs ||
        fail "pthread barrierattr pshared source lacks ${marker}"
done
if grep -Eq 'use super|raw_syscall::|static_tls::|pthread_identity::|pthread_barrier::|atomic::' \
    libc/src/c_abi/x86_64/pthread_barrierattr_pshared.rs; then
    fail "pthread barrierattr pshared source must not import a runtime seam"
fi

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_PTHREAD_BARRIERATTR_PSHARED_FREESTANDING \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    compat/x86_64/libc_pthread_barrierattr_pshared_probe.c \
    compat/x86_64/libc_pthread_barrierattr_pshared_start.S "$archive" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
for symbol in pthread_barrierattr_setpshared pthread_barrierattr_getpshared; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" ||
        fail "candidate does not define ${symbol}"
done
assert_no_unselected_barrierattr_exports "$candidate_symbols"
for unselected in __errno_location __crabc_x86_static_tls_bootstrap \
    pthread_mutex_init pthread_mutex_destroy pthread_mutex_lock pthread_mutex_trylock \
    pthread_mutex_unlock pthread_cond_init pthread_cond_destroy pthread_cond_wait \
    pthread_cond_signal pthread_cond_broadcast pthread_cond_timedwait; do
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
if grep -Eq '[[:space:]]TLS[[:space:]]' "$candidate_headers" ||
    grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
        "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate must remain TLS-free"
fi
if grep -Eq 'crabc_core|mimalloc|sha_crypt' \
    "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate selects an unowned runtime dependency"
fi

assert_direct_record_path

if timeout "$EXECUTION_TIMEOUT" "$candidate"; then
    :
else
    status=$?
    fail "freestanding barrierattr pshared fixture exited ${status}"
fi

printf 'x86 static crabc-libc pthread barrierattr pshared: PASS\n'
