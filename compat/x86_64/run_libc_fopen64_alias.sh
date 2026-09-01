#!/usr/bin/env bash
# Native Linux/x86-64 static fopen64 LP64 macro-alias evidence.
#
# Pinned musl 1.2.6 defines `fopen64` only as the `_LARGEFILE64_SOURCE`
# preprocessing alias `fopen` and emits no x86 ELF `fopen64` symbol. This
# runner preserves that exact x86 contract: it proves the macro route through
# the existing bounded pathname stream, freezes the normal static export
# surface, and rejects a distinct `fopen64` in both archive and final ELF. It
# is not a new ABI export, general stdio/path-stream completion, CRT, loader,
# sysroot, family promotion, or public x86 support.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly EXECUTION_TIMEOUT=20s
readonly INITIAL_TLS_BYTES=4096
readonly INITIAL_TLS_ALIGNMENT=64

fail() {
    printf 'ERROR: x86 static libc fopen64 macro alias: %s\n' "$*" >&2
    exit 1
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
    grep -Ev '^(#|$)' "$STATIC_C_ABI_EXPORTS" | LC_ALL=C sort -u >"$expected_path"
    if ! cmp -s "$expected_path" "$symbols_path"; then
        diff -u "$expected_path" "$symbols_path" >&2 || true
        fail "selected static C ABI export surface drifted"
    fi
}

assert_fixture_tls_capacity() {
    local tls_filesz
    local tls_memsz
    local tls_alignment

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

assert_no_fopen64_symbol() {
    local symbols_path="$1"
    local artifact="$2"

    if awk '$7 != "UND" && $8 == "fopen64" { found = 1 } END { exit(found ? 0 : 1) }' \
        "$symbols_path"; then
        fail "$artifact unexpectedly defines ELF fopen64"
    fi
    if awk '$7 == "UND" && $8 == "fopen64" { found = 1 } END { exit(found ? 0 : 1) }' \
        "$symbols_path"; then
        fail "$artifact unexpectedly references ELF fopen64"
    fi
}

[ "$#" -eq 0 ] || fail "usage: $0"
[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in
    x86_64|amd64) ;;
    *) fail "requires native x86-64" ;;
esac
for tool in ar awk cargo cmp diff grep mkdir mktemp nm objdump readelf rustup sort timeout; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -f "$STATIC_C_ABI_EXPORTS" ] || fail "missing frozen selected-static export contract"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_fopen64_header_abi.sh" >/dev/null
# The macro must reuse this existing bounded owner rather than silently
# treating the tiny alias proof as a complete pathname-stream claim.
bash "$ROOT_DIR/compat/x86_64/run_libc_stdio_path_stream.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-fopen64-alias.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
target_dir="$work_dir/cargo-target"
archive="$target_dir/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-fopen64-alias-reference"
candidate="$work_dir/crabc-static-fopen64-alias-candidate"
trace="$work_dir/header-trace"
musl_archive_symbols="$work_dir/musl-archive-symbols"
archive_symbols="$work_dir/archive-symbols"
selected_symbols="$work_dir/selected-c-abi-symbols"
expected_symbols="$work_dir/expected-c-abi-symbols"
candidate_symbols="$work_dir/candidate-symbols"
candidate_program_headers="$work_dir/candidate-program-headers"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"
errno_disassembly="$work_dir/errno-disassembly"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_LARGEFILE64_SOURCE -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_fopen64_alias_probe.c >/dev/null 2>"$trace"
for header in errno.h stdio.h unistd.h features.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$trace" ||
        fail "fixture did not use project <$header>"
done
"$ORACLE_CC" -std=c11 -D_LARGEFILE64_SOURCE -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" compat/x86_64/libc_fopen64_alias_probe.c \
    -o "$reference"
timeout "$EXECUTION_TIMEOUT" "$reference" ||
    fail "pinned-musl fopen64 macro-alias fixture failed"

musl_archive="$($ORACLE_CC -print-file-name=libc.a)"
case "$musl_archive" in
    /*) ;;
    *) fail "pinned musl compiler did not report an absolute libc.a path" ;;
esac
[ -f "$musl_archive" ] || fail "pinned musl static archive is missing"
nm -A --defined-only "$musl_archive" >"$musl_archive_symbols"
grep -Eq '[[:space:]]T[[:space:]]fopen$' "$musl_archive_symbols" ||
    fail "pinned-musl archive omits strong fopen"
if awk '$NF == "fopen64" { found = 1 } END { exit(found ? 0 : 1) }' \
    "$musl_archive_symbols"; then
    fail "pinned-musl archive contradicts its header-only fopen64 alias"
fi

CARGO_TARGET_DIR="$target_dir" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"
nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_symbols" "$expected_symbols"
grep -Eq '[[:space:]]T[[:space:]]fopen$' "$archive_symbols" ||
    fail "archive fopen is not strong"
if awk '$NF == "fopen64" { found = 1 } END { exit(found ? 0 : 1) }' \
    "$archive_symbols"; then
    fail "archive invents an ELF fopen64 symbol"
fi
for unselected in fdopen freopen fmemopen open_memstream fopencookie popen pclose; do
    if grep -Eq "[[:space:]][TW][[:space:]]${unselected}$" "$archive_symbols"; then
        fail "archive accidentally exports unselected ${unselected}"
    fi
done

"$ORACLE_CC" -std=c11 -D_LARGEFILE64_SOURCE \
    -DCRABC_FOPEN64_ALIAS_FREESTANDING -I"$ROOT_DIR/include" \
    -nostdlib -static -fno-pie -no-pie -ffreestanding -fno-builtin \
    -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined -Wl,--gc-sections \
    compat/x86_64/libc_fopen64_alias_probe.c \
    compat/x86_64/libc_fopen64_alias_start.S "$archive" -o "$candidate"
readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
awk '$4 == "FUNC" && $5 == "GLOBAL" && $6 == "DEFAULT" && $7 != "UND" && $8 == "fopen" { found = 1 } END { exit(found ? 0 : 1) }' \
    "$candidate_symbols" || fail "candidate fopen lost strong ELF binding"
assert_no_fopen64_symbol "$candidate_symbols" "candidate"
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
objdump -d --disassemble=__errno_location "$candidate" >"$errno_disassembly"
grep -Eq '%fs:0x0|%fs:-' "$errno_disassembly" ||
    fail "candidate errno does not use direct fs initial TLS"
grep -Eq 'call.*__crabc_x86_static_tls_bootstrap' \
    compat/x86_64/libc_fopen64_alias_start.S ||
    fail "fixture start does not delegate first-thread TLS to libc"
grep -Eq '[[:space:]]syscall$' "$candidate_disassembly" ||
    fail "candidate lacks a direct Linux syscall instruction"
timeout "$EXECUTION_TIMEOUT" "$candidate" ||
    fail "freestanding fopen64 macro-alias fixture failed"

printf 'x86 static crabc-libc fopen64 macro alias: PASS\n'
