#!/usr/bin/env bash
# Native Linux/x86-64 bounded C tmpfile evidence.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly ORACLE_ARCHIVE=/opt/musl-1.2.6/lib/libc.a
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly EXECUTION_TIMEOUT=20s
readonly INITIAL_TLS_BYTES=4096
readonly INITIAL_TLS_ALIGNMENT=64

fail() { printf 'ERROR: x86 static libc stdio tmpfile: %s\n' "$*" >&2; exit 1; }
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

assert_fixture_tls_capacity() {
    local tls_filesz tls_memsz tls_alignment
    read -r tls_filesz tls_memsz tls_alignment < <(
        awk '$1 == "TLS" { print $5, $6, $NF; exit }' "$candidate_program_headers"
    )
    [ -n "${tls_filesz:-}" ] || fail "candidate lacks a parsable PT_TLS segment"
    (( tls_filesz == 0 )) || fail "fixture TLS scratch cannot initialize PT_TLS data"
    (( tls_memsz > 0 && tls_memsz <= INITIAL_TLS_BYTES )) ||
        fail "fixture TLS scratch does not cover PT_TLS memsz ${tls_memsz}"
    (( tls_alignment > 0 && tls_alignment <= INITIAL_TLS_ALIGNMENT &&
       INITIAL_TLS_ALIGNMENT % tls_alignment == 0 )) ||
        fail "fixture TLS scratch is incompatible with PT_TLS alignment ${tls_alignment}"
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "requires native x86-64" ;; esac
for tool in ar awk cargo cmp diff grep mkdir nm objdump readelf rustup sort timeout; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -f "$ORACLE_ARCHIVE" ] || fail "missing pinned musl static archive"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-stdio-tmpfile.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
target_dir="$work_dir/cargo-target"
archive="$target_dir/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-stdio-tmpfile-reference"
candidate="$work_dir/crabc-static-stdio-tmpfile-candidate"
trace="$work_dir/header-trace"
cxx_trace="$work_dir/header-cxx-trace"
archive_symbols="$work_dir/archive-symbols"
selected_symbols="$work_dir/selected-c-abi-symbols"
expected_symbols="$work_dir/expected-c-abi-symbols"
candidate_symbols="$work_dir/candidate-symbols"
candidate_program_headers="$work_dir/candidate-program-headers"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"
oracle_archive_symbols="$work_dir/oracle-archive-symbols"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -D_LARGEFILE64_SOURCE \
    -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_stdio_tmpfile_probe.c >/dev/null 2>"$trace"
for header in errno.h fcntl.h stdio.h sys/stat.h unistd.h features.h \
    bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$trace" ||
        fail "fixture did not use the project $header header"
done
"$ORACLE_CC" -std=c++17 -x c++ -D_LARGEFILE64_SOURCE \
    -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_stdio_tmpfile_header_probe.cpp >/dev/null 2>"$cxx_trace"
for header in stdio.h features.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$cxx_trace" ||
        fail "C++ alias probe did not use the project $header header"
done
"$ORACLE_CC" -std=c++17 -x c++ -D_LARGEFILE64_SOURCE -fsyntax-only \
    compat/x86_64/libc_stdio_tmpfile_header_probe.cpp
"$ORACLE_CC" -std=c++17 -x c++ -D_LARGEFILE64_SOURCE \
    -I"$ROOT_DIR/include" -fsyntax-only \
    compat/x86_64/libc_stdio_tmpfile_header_probe.cpp
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -D_LARGEFILE64_SOURCE -fno-builtin \
    -fno-stack-protector -I"$ROOT_DIR/include" \
    compat/x86_64/libc_stdio_tmpfile_probe.c -o "$reference"
timeout "$EXECUTION_TIMEOUT" "$reference" ||
    fail "pinned-musl tmpfile fixture failed"

nm -A --defined-only "$ORACLE_ARCHIVE" >"$oracle_archive_symbols" 2>/dev/null
grep -Eq '[[:space:]]T[[:space:]]tmpfile$' "$oracle_archive_symbols" ||
    fail "pinned-musl archive omits strong tmpfile"
if grep -Eq '[[:space:]][TW][[:space:]]tmpfile64$' "$oracle_archive_symbols"; then
    fail "pinned-musl archive contradicts its header-only tmpfile64 alias"
fi

CARGO_TARGET_DIR="$target_dir" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"
nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_symbols" "$expected_symbols"
for symbol in __errno_location __crabc_x86_static_tls_bootstrap fclose fcntl \
    fileno fseek fstat fread fwrite tmpfile umask; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" ||
        fail "archive does not define ${symbol}"
done
grep -Eq '[[:space:]]T[[:space:]]tmpfile$' "$archive_symbols" ||
    fail "archive tmpfile is not strong"
if grep -Eq '[[:space:]][TW][[:space:]]tmpfile64$' "$archive_symbols"; then
    fail "archive invents a distinct LP64 tmpfile64 symbol"
fi
for unselected in fmemopen open_memstream open_wmemstream fopencookie popen \
    pclose flockfile ftrylockfile funlockfile; do
    if grep -Eq "[[:space:]][TW][[:space:]]${unselected}$" "$archive_symbols"; then
        fail "archive accidentally exports unselected ${unselected}"
    fi
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -D_LARGEFILE64_SOURCE \
    -DCRABC_STDIO_TMPFILE_FREESTANDING -I"$ROOT_DIR/include" \
    -nostdlib -static -fno-pie -no-pie -ffreestanding -fno-builtin \
    -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    compat/x86_64/libc_stdio_tmpfile_probe.c \
    compat/x86_64/libc_stdio_tmpfile_start.S "$archive" -o "$candidate"
readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
for symbol in fclose fcntl fileno fseek fstat fread fwrite tmpfile umask; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" ||
        fail "candidate lacks ${symbol}"
done
awk '$8 == "tmpfile" && $4 == "FUNC" && $5 == "GLOBAL" { found=1 } END { exit !found }' \
    "$candidate_symbols" || fail "candidate tmpfile lost strong ELF binding"
if awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols" | grep -q .; then
    fail "candidate retains an unresolved symbol"
fi
if grep -Eq 'Requesting program interpreter|INTERP|NEEDED' \
    "$candidate_program_headers" "$candidate_dynamic"; then
    fail "candidate selected a dynamic runtime"
fi
grep -Eq '[[:space:]]TLS[[:space:]]' "$candidate_program_headers" ||
    fail "candidate lacks errno TLS"
assert_fixture_tls_capacity
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
    "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate retains a dynamic TLS model"
fi
for syscall_name in SYS_GETRANDOM SYS_OPEN SYS_UNLINK SYS_CLOSE; do
    grep -Fq "raw_syscall::$syscall_name" \
        "$ROOT_DIR/libc/src/c_abi/x86_64/stdio_standard.rs" ||
        fail "tmpfile implementation omits raw ${syscall_name} ownership"
done
grep -Fq 'const TMPFILE_MAX_ATTEMPTS: usize = 100;' \
    "$ROOT_DIR/libc/src/c_abi/x86_64/stdio_standard.rs" ||
    fail "tmpfile implementation drifted from musl's fixed MAXTRIES=100 bound"
grep -Eq 'call.*__crabc_x86_static_tls_bootstrap' \
    compat/x86_64/libc_stdio_tmpfile_start.S ||
    fail "fixture start does not delegate first-thread TLS to libc"
grep -Eq '[[:space:]]syscall$' "$candidate_disassembly" ||
    fail "candidate lacks a direct Linux syscall instruction"
timeout "$EXECUTION_TIMEOUT" "$candidate" ||
    fail "freestanding tmpfile fixture failed"

printf 'x86 static crabc-libc bounded tmpfile stream: PASS\n'
