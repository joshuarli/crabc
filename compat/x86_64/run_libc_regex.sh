#!/usr/bin/env bash
# Native Linux/x86-64 bounded static POSIX regex evidence.
#
# This runner compares the selected grammar against pinned musl 1.2.6, then
# links the same body as a true freestanding candidate through the selected
# crabc archive. It additionally pins the intentional fixed-capacity and
# unsupported-grammar results without selecting a C allocator or wordexp.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly MUSL_ROOT=/opt/musl-1.2.6
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly CANDIDATE_CC=/usr/bin/gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"

fail() { printf 'ERROR: x86 static libc regex: %s\n' "$*" >&2; exit 1; }
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
    ) | awk '$2 ~ /^[TWDVBR]$/ && $1 !~ /^(_R|_ZN|DW\.ref\.|anon\.)/ && $1 != "crabc_x86_64_signal_restorer" && $1 != "__crabc_x86_pthread_clone" { print $1 }' |
        sort -u >"$symbols_path"
    grep -Ev '^(#|$)' "$STATIC_C_ABI_EXPORTS" | LC_ALL=C sort -u >"$expected_path"
    if ! cmp -s "$expected_path" "$symbols_path"; then
        diff -u "$expected_path" "$symbols_path" >&2 || true
        fail "selected static C ABI export surface drifted"
    fi
}

[ "$#" -eq 0 ] || fail "usage: $0"
[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "requires native x86-64" ;; esac
for tool in ar awk cargo cmp diff grep mapfile mkdir mktemp nm objdump readelf rustup sort; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -x "$CANDIDATE_CC" ] || fail "missing raw native candidate compiler"
[ -d "$MUSL_ROOT/include" ] || fail "missing pinned musl include tree"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-regex.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
target_dir="$work_dir/cargo-target"
archive="$target_dir/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-regex-reference"
candidate="$work_dir/crabc-static-regex-candidate"
project_cxx="$work_dir/project-regex-cxx.o"
musl_cxx="$work_dir/musl-regex-cxx.o"
archive_symbols="$work_dir/archive-symbols"
selected_symbols="$work_dir/selected-c-abi-symbols"
expected_symbols="$work_dir/expected-c-abi-symbols"
symbols="$work_dir/candidate-symbols"
headers="$work_dir/candidate-program-headers"
dynamic="$work_dir/candidate-dynamic"
relocations="$work_dir/candidate-relocations"
disassembly="$work_dir/candidate-disassembly"
implementation="$ROOT_DIR/libc/src/c_abi/x86_64/regex.rs"

builtin_include="$($CANDIDATE_CC -print-file-name=include)"
[ -d "$builtin_include" ] || fail "missing compiler builtin include directory"

"$CANDIDATE_CC" -x c -std=c11 -D_GNU_SOURCE -nostdinc \
    -I"$ROOT_DIR/include" -isystem "$builtin_include" -fsyntax-only \
    "$ROOT_DIR/compat/x86_64/regex_header_abi_probe.c"
"$ORACLE_CC" -x c -std=c11 -D_GNU_SOURCE -nostdinc \
    -I"$MUSL_ROOT/include" -isystem "$builtin_include" -fsyntax-only \
    "$ROOT_DIR/compat/x86_64/regex_header_abi_probe.c"
"$CANDIDATE_CC" -x c++ -std=c++17 -D_GNU_SOURCE -nostdinc -nostdinc++ \
    -I"$ROOT_DIR/include" -isystem "$builtin_include" -c \
    "$ROOT_DIR/compat/x86_64/regex_header_abi_probe.cpp" -o "$project_cxx"
"$ORACLE_CC" -x c++ -std=c++17 -D_GNU_SOURCE -nostdinc -nostdinc++ \
    -I"$MUSL_ROOT/include" -isystem "$builtin_include" -c \
    "$ROOT_DIR/compat/x86_64/regex_header_abi_probe.cpp" -o "$musl_cxx"
for object in "$project_cxx" "$musl_cxx"; do
    for symbol in regcomp regexec regerror regfree; do
        nm --undefined-only "$object" | grep -Eq "[[:space:]]${symbol}$" ||
            fail "C++ regex probe lost C linkage for ${symbol}"
    done
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" "$ROOT_DIR/compat/x86_64/libc_regex_probe.c" \
    -o "$reference"
"$reference" || fail "pinned-musl selected regex fixture failed with status $?"

cd "$ROOT_DIR"
CARGO_TARGET_DIR="$target_dir" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"
nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_symbols" "$expected_symbols"
for symbol in regcomp regexec regerror regfree; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" ||
        fail "archive does not define ${symbol}"
done
for unselected in fnmatch glob globfree wordexp wordfree malloc calloc realloc free; do
    if grep -Eq "[[:space:]][TW][[:space:]]${unselected}$" "$archive_symbols"; then
        fail "archive accidentally exports unselected ${unselected}"
    fi
done
for snippet in 'raw_syscall::SYS_MMAP' 'raw_syscall::SYS_MUNMAP' \
    'COMPILED_MAPPING_BYTES' 'MAX_TOKENS' 'MAX_INPUT_BYTES'; do
    grep -Fq "$snippet" "$implementation" ||
        fail "regex implementation omits bounded runtime seam ${snippet}"
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_REGEX_FREESTANDING \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    "$ROOT_DIR/compat/x86_64/libc_regex_probe.c" \
    "$ROOT_DIR/compat/x86_64/libc_regex_start.S" "$archive" -o "$candidate"
readelf --symbols --wide "$candidate" >"$symbols"
readelf --program-headers --wide "$candidate" >"$headers"
readelf --dynamic --wide "$candidate" >"$dynamic" || true
readelf --relocs --wide "$candidate" >"$relocations"
objdump -d "$candidate" >"$disassembly"
for symbol in __crabc_x86_static_tls_bootstrap regcomp regexec regerror regfree; do
    grep -Eq "[[:space:]]${symbol}$" "$symbols" || fail "candidate lacks ${symbol}"
done
if awk '$7 == "UND" && NF >= 8 { print }' "$symbols" | grep -q .; then
    fail "candidate has unresolved symbols"
fi
if grep -Eq 'Requesting program interpreter|INTERP|NEEDED' "$headers" "$dynamic"; then
    fail "candidate is dynamic"
fi
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
    "$relocations" "$symbols" "$disassembly"; then
    fail "candidate retains a dynamic TLS model"
fi
if grep -Eq 'mimalloc|sha_crypt|wordexp|/bin/sh' "$symbols" "$disassembly"; then
    fail "candidate selects an allocator, cryptography, or shell-expansion dependency"
fi
"$candidate" || fail "freestanding selected regex fixture failed with status $?"
printf 'x86 static crabc-libc bounded regex: PASS\n'
