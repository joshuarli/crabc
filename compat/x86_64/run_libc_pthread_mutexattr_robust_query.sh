#!/usr/bin/env bash
# Native Linux/x86-64 static pthread mutex-attribute robustness differential.
#
# The same project-header fixture first runs against pinned musl 1.2.6, then
# as a true `-nostdlib -static` executable linked only with the selected crabc
# archive. It compares raw traces of getter queries, setter transitions,
# rejected values, and guards around the public four-byte record and output.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/source_runtime_libc.sh"

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly EXECUTION_TIMEOUT=10s

fail() {
    printf 'ERROR: x86 static pthread mutexattr robust query: %s\n' "$*" >&2
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

assert_direct_record_path() {
    local disassembly="$work_dir/pthread_mutexattr_getrobust-disassembly"

    objdump -d --disassemble=pthread_mutexattr_getrobust "$candidate" >"$disassembly"
    if grep -Eq '[[:space:]](syscall|call)([[:space:]]|$)|%fs:' "$disassembly"; then
        fail "pthread_mutexattr_getrobust must remain a direct TLS-free, syscall-free record query"
    fi
}

require_native_linux_x86_64
for tool in ar awk cargo cmp diff grep mkdir mktemp nm objdump readelf rustup sort timeout; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_pthread_c11_header_abi.sh" >/dev/null

mkdir -p "$ROOT_DIR/.work/x86_64/tmp" "$ROOT_DIR/.work/x86_64/reports"
work_dir="$(mktemp -d "$ROOT_DIR/.work/x86_64/tmp/pthread-mutexattr-robust-query.XXXXXX")"
trap 'rm -rf -- "$work_dir"' EXIT
evidence_dir="$ROOT_DIR/.work/x86_64/reports/pthread-mutexattr-robust-query"
mkdir -p "$evidence_dir"
reference_trace="$evidence_dir/musl.trace"
candidate_trace="$evidence_dir/crabc.trace"
cargo_target="$work_dir/cargo-target"
reference="$work_dir/musl-pthread-mutexattr-robust-query-reference"
candidate="$work_dir/crabc-static-pthread-mutexattr-robust-query-candidate"
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
    compat/x86_64/libc_pthread_mutexattr_robust_query_probe.c >/dev/null 2>"$header_trace"
for header in pthread.h bits/alltypes.h features.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture did not use project $header"
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -pthread -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" compat/x86_64/libc_pthread_mutexattr_robust_query_probe.c \
    -o "$reference"
if timeout "$EXECUTION_TIMEOUT" "$reference" >"$reference_trace"; then
    :
else
    status=$?
    fail "pinned-musl mutexattr robust-query fixture exited ${status}"
fi

build_source_runtime_libc "$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"
cp "$archive.source-runtime.json" "$evidence_dir/source-runtime.json"

nm -A --defined-only "$archive" >"$archive_symbols"
readelf --symbols --wide "$archive" >"$archive_elf_symbols"
assert_selected_c_abi_surface "$archive" "$selected_symbols" "$expected_symbols"
grep -Eq '[[:space:]][TW][[:space:]]pthread_mutexattr_getrobust$' "$archive_symbols" ||
    fail "archive does not define pthread_mutexattr_getrobust"
grep -Eq '[[:space:]][TW][[:space:]]pthread_mutexattr_setrobust$' "$archive_symbols" ||
    fail "archive does not define pthread_mutexattr_setrobust"
readelf --relocs --wide "$archive" >"$archive_relocations"
objdump -dr "$archive" >"$archive_disassembly"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' \
    "$archive_relocations" "$archive_disassembly"; then
    fail "archive selects dynamic TLS or an unowned runtime dependency"
fi
if grep -Eq 'use super|raw_syscall::|static_tls::|pthread_mutex::|atomic::' \
    libc/src/c_abi/x86_64/pthread_mutexattr_robust_query.rs; then
    fail "pthread mutexattr robust-query source must not import a runtime seam"
fi

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE \
    -DCRABC_PTHREAD_MUTEXATTR_ROBUST_QUERY_FREESTANDING \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    compat/x86_64/libc_pthread_mutexattr_robust_query_probe.c \
    compat/x86_64/libc_pthread_mutexattr_robust_query_start.S "$archive" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
cp "$candidate_symbols" "$evidence_dir/candidate-symbols"
readelf --program-headers --wide "$candidate" >"$candidate_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
grep -Eq '[[:space:]]pthread_mutexattr_getrobust$' "$candidate_symbols" ||
    fail "candidate does not define pthread_mutexattr_getrobust"
grep -Eq '[[:space:]]pthread_mutexattr_setrobust$' "$candidate_symbols" ||
    fail "candidate does not define pthread_mutexattr_setrobust"
# The setter's archive member retains adjacent mutex entry points and TLS
# bootstrap code. The final link must still resolve everything from the owned
# static archive, and the getter itself must remain a direct record query.
unresolved_symbols="$(awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols")"
if [ -n "$unresolved_symbols" ]; then
    printf '%s\n' "$unresolved_symbols" >&2
    fail "candidate retains an unresolved symbol"
fi
if grep -Eq 'Requesting program interpreter|INTERP' "$candidate_headers" ||
    grep -Eq 'NEEDED' "$candidate_dynamic"; then
    fail "candidate selected a dynamic runtime"
fi
assert_direct_record_path

if timeout "$EXECUTION_TIMEOUT" "$candidate" >"$candidate_trace"; then
    :
else
    status=$?
    fail "freestanding mutexattr robust-query fixture exited ${status}"
fi

if ! cmp -s "$reference_trace" "$candidate_trace"; then
    diff -u "$reference_trace" "$candidate_trace" >&2 || true
    fail "pinned-musl and freestanding robustness traces differ; raw traces: $evidence_dir"
fi

printf 'x86 static crabc-libc pthread mutexattr robust transitions: PASS (%s)\n' "$evidence_dir"
