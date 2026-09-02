#!/usr/bin/env bash
# Native Linux/x86-64 static pthread mutex/condition attribute lifecycle proof.
#
# The exact project-header fixture runs through pinned musl 1.2.6 and then a
# freestanding crabc archive candidate. It admits only four direct record
# entries: init writes the caller-owned word to zero; destroy returns zero
# without reading the record. No mutex/condition runtime or thread creation is
# selected.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly EXECUTION_TIMEOUT=10s

fail() { printf 'ERROR: x86 static pthread attr lifecycle: %s\n' "$*" >&2; exit 1; }
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
    (
        cd "$members_path"
        ar x "$archive_path" "${members[@]}"
        nm -g --defined-only --format=posix "${members[@]}"
    ) | awk '$2 ~ /^[TWDVBR]$/ && $1 !~ /^(_R|_ZN|DW\.ref\.|anon\.)/ && $1 != "crabc_x86_64_signal_restorer" && $1 != "__crabc_x86_pthread_clone" { print $1 }' | sort -u >"$symbols_path"
    grep -Ev '^(#|$)' "$STATIC_C_ABI_EXPORTS" | LC_ALL=C sort -u >"$expected_path"
    cmp -s "$expected_path" "$symbols_path" || { diff -u "$expected_path" "$symbols_path" >&2 || true; fail "selected static C ABI export surface drifted"; }
}

assert_direct_record_path() {
    local symbol disassembly
    for symbol in pthread_mutexattr_init pthread_mutexattr_destroy pthread_condattr_init pthread_condattr_destroy; do
        disassembly="$work_dir/${symbol}-disassembly"
        objdump -d --disassemble="$symbol" "$candidate" >"$disassembly"
        if grep -Eq '[[:space:]](syscall|call)([[:space:]]|$)|%fs:' "$disassembly"; then
            fail "$symbol must remain a direct TLS-free, syscall-free record operation"
        fi
    done
}

require_native_linux_x86_64
for tool in ar awk cargo cmp diff grep mkdir mktemp nm objdump readelf rustup sort timeout; do require_tool "$tool"; done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_pthread_c11_header_abi.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-pthread-attr-lifecycle.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
cargo_target="$work_dir/cargo-target"
reference="$work_dir/musl-pthread-attr-lifecycle-reference"
candidate="$work_dir/crabc-static-pthread-attr-lifecycle-candidate"
archive="$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
header_trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
selected_symbols="$work_dir/selected-symbols"
expected_symbols="$work_dir/expected-symbols"
candidate_symbols="$work_dir/candidate-symbols"
candidate_headers="$work_dir/candidate-program-headers"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -E -H compat/x86_64/libc_pthread_attr_lifecycle_probe.c >/dev/null 2>"$header_trace"
for header in pthread.h bits/alltypes.h; do grep -Fq "$ROOT_DIR/include/$header" "$header_trace" || fail "fixture did not use project $header"; done
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -pthread -fno-builtin -fno-stack-protector -I"$ROOT_DIR/include" compat/x86_64/libc_pthread_attr_lifecycle_probe.c -o "$reference"
timeout "$EXECUTION_TIMEOUT" "$reference" || { status=$?; fail "pinned-musl lifecycle fixture exited ${status}"; }

CARGO_TARGET_DIR="$cargo_target" cargo rustc --locked -p crabc-libc --lib --target x86_64-unknown-linux-musl -- -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"
nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_symbols" "$expected_symbols"
for symbol in pthread_mutexattr_init pthread_mutexattr_destroy pthread_condattr_init pthread_condattr_destroy; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" || fail "archive does not define ${symbol}"
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_PTHREAD_ATTR_LIFECYCLE_FREESTANDING -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined compat/x86_64/libc_pthread_attr_lifecycle_probe.c compat/x86_64/libc_pthread_attr_lifecycle_start.S "$archive" -o "$candidate"
readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
for symbol in pthread_mutexattr_init pthread_mutexattr_destroy pthread_condattr_init pthread_condattr_destroy; do grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" || fail "candidate does not define ${symbol}"; done
for unselected in pthread_mutexattr_settype pthread_mutexattr_gettype pthread_condattr_setclock pthread_condattr_getclock pthread_mutex_init pthread_mutex_destroy pthread_mutex_lock pthread_mutex_trylock pthread_mutex_unlock pthread_cond_init pthread_cond_destroy pthread_cond_wait pthread_cond_signal pthread_cond_broadcast pthread_create; do
    ! grep -Eq "[[:space:]]${unselected}$" "$candidate_symbols" || fail "candidate pulled unselected ${unselected}"
done
unresolved_symbols="$(awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols")"
[ -z "$unresolved_symbols" ] || { printf '%s\n' "$unresolved_symbols" >&2; fail "candidate retains an unresolved symbol"; }
if grep -Eq 'Requesting program interpreter|INTERP' "$candidate_headers" || grep -Eq 'NEEDED' "$candidate_dynamic"; then fail "candidate selected a dynamic runtime"; fi
if grep -Eq '[[:space:]]TLS[[:space:]]' "$candidate_headers" || grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly"; then
    grep -En '[[:space:]]TLS[[:space:]]|TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' "$candidate_headers" "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly" >&2 || true
    fail "candidate selects TLS or an unowned runtime dependency"
fi
assert_direct_record_path
timeout "$EXECUTION_TIMEOUT" "$candidate" || { status=$?; fail "freestanding lifecycle fixture exited ${status}"; }
printf 'x86 static crabc-libc pthread attr lifecycle: PASS\n'
