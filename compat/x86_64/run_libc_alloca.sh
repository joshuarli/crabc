#!/usr/bin/env bash
# Native Linux/x86-64 static musl-compatible <alloca.h> builtin evidence.
#
# alloca is a compiler builtin selected by the public musl macro.  This runner
# intentionally links no crabc archive or libc object: its static candidate
# proves that the header macro produces stack storage without a callable
# alloca symbol, heap allocator, TLS, CRT, or ambient runtime dependency.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly MUSL_ALLOCA_HEADER=/opt/musl-1.2.6/include/alloca.h
readonly AARCH64_HEADERS="$ROOT_DIR/compat/abi/musl-1.2.6/aarch64/headers.tsv"
readonly AARCH64_ALLOCA_HEADER_ROW=$'alloca.h\tpublic\t219\t19\t8768404d7cf4af5fb135b1a2ca91765bd2be311ac072e0ec8b68f5cb3e6e0f3e'

fail() {
    printf 'ERROR: x86 static alloca builtin: %s\n' "$*" >&2
    exit 1
}

require_tool() {
    command -v "$1" >/dev/null 2>&1 || fail "requires $1"
}

require_native_linux_x86_64() {
    [ "$(uname -s)" = Linux ] || fail "requires native Linux"
    case "$(uname -m)" in
        x86_64|amd64) ;;
        *) fail "requires native x86-64" ;;
    esac
}

require_builtin_macro() {
    local label="$1"
    shift
    local macro_definitions="$work_dir/${label}-macros"

    "$ORACLE_CC" "$@" -dM -E "$c_header_probe" >"$macro_definitions"
    grep -Fxq '#define alloca __builtin_alloca' "$macro_definitions" \
        || fail "${label} does not retain musl's alloca builtin macro"
}

require_no_alloca_reference() {
    local object_path="$1"
    local undefined

    undefined="$(nm --undefined-only "$object_path")"
    if printf '%s\n' "$undefined" | grep -Eq '[[:space:]]alloca$'; then
        fail "header object retained a callable alloca reference"
    fi
}

require_native_linux_x86_64
for tool in awk cmp diff env grep mktemp nm objdump readelf sed uname; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -r "$MUSL_ALLOCA_HEADER" ] || fail "missing pinned musl alloca.h"
[ -r "$AARCH64_HEADERS" ] || fail "missing AArch64 musl header inventory"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

if ! cmp -s "$MUSL_ALLOCA_HEADER" "$ROOT_DIR/include/alloca.h"; then
    diff -u "$MUSL_ALLOCA_HEADER" "$ROOT_DIR/include/alloca.h" >&2 || true
    fail "project alloca.h differs from the pinned musl 1.2.6 header"
fi
grep -Fxq "$AARCH64_ALLOCA_HEADER_ROW" "$AARCH64_HEADERS" \
    || fail "AArch64 musl header inventory lost the pinned alloca.h identity"

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-alloca.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
c_header_probe="$ROOT_DIR/compat/x86_64/alloca_header_abi_probe.c"
cxx_header_probe="$ROOT_DIR/compat/x86_64/alloca_header_abi_probe.cpp"
runtime_probe="$ROOT_DIR/compat/x86_64/libc_alloca_probe.c"
start="$ROOT_DIR/compat/x86_64/libc_alloca_start.S"
reference="$work_dir/pinned-musl-alloca-reference"
candidate="$work_dir/crabc-static-alloca-candidate"
header_trace="$work_dir/project-header-trace"
oracle_c_object="$work_dir/oracle-alloca-c.o"
candidate_c_object="$work_dir/candidate-alloca-c.o"
oracle_cxx_object="$work_dir/oracle-alloca-cxx.o"
candidate_cxx_object="$work_dir/candidate-alloca-cxx.o"
candidate_symbols="$work_dir/candidate-symbols"
candidate_headers="$work_dir/candidate-program-headers"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"

# Compile the C and C++ macro surface through pinned musl and project headers.
# There is no link step here: alloca remains a compiler expansion, not a C ABI.
"$ORACLE_CC" -std=c11 -fno-builtin -fsyntax-only "$c_header_probe"
"$ORACLE_CC" -std=c11 -fno-builtin -I"$ROOT_DIR/include" \
    -fsyntax-only "$c_header_probe"
"$ORACLE_CC" -std=c++17 -x c++ -fno-builtin -fsyntax-only "$cxx_header_probe"
"$ORACLE_CC" -std=c++17 -x c++ -fno-builtin -I"$ROOT_DIR/include" \
    -fsyntax-only "$cxx_header_probe"

require_builtin_macro pinned-musl -std=c11 -fno-builtin
require_builtin_macro project -std=c11 -fno-builtin -I"$ROOT_DIR/include"

if ! "$ORACLE_CC" -std=c11 -fno-builtin -I"$ROOT_DIR/include" -H \
    -fsyntax-only "$c_header_probe" >/dev/null 2>"$header_trace"; then
    sed -n '1,160p' "$header_trace" >&2
    fail "project C alloca header contract drifted"
fi
for header in alloca.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" \
        || fail "project alloca probe did not use <$header>"
done

"$ORACLE_CC" -std=c11 -fno-builtin -c "$c_header_probe" \
    -o "$oracle_c_object"
"$ORACLE_CC" -std=c11 -fno-builtin -I"$ROOT_DIR/include" -c \
    "$c_header_probe" -o "$candidate_c_object"
"$ORACLE_CC" -std=c++17 -x c++ -fno-builtin -c "$cxx_header_probe" \
    -o "$oracle_cxx_object"
"$ORACLE_CC" -std=c++17 -x c++ -fno-builtin -I"$ROOT_DIR/include" -c \
    "$cxx_header_probe" -o "$candidate_cxx_object"
for object_path in "$oracle_c_object" "$candidate_c_object" \
    "$oracle_cxx_object" "$candidate_cxx_object"; do
    require_no_alloca_reference "$object_path"
done

# Both executions use the same bounded positive-size/nested-frame fixture.
# Pinned musl supplies only the oracle compiler/header/startup for its arm.
"$ORACLE_CC" -std=c11 -O0 -fno-omit-frame-pointer -fno-builtin \
    -fno-stack-protector -static -fno-pie -no-pie "$runtime_probe" \
    -o "$reference"
env -i "$reference" || fail "pinned-musl alloca reference failed"

"$ORACLE_CC" -std=c11 -O0 -fno-omit-frame-pointer \
    -DCRABC_ALLOCA_FREESTANDING -I"$ROOT_DIR/include" \
    -nostdlib -static -fno-pie -no-pie -ffreestanding -fno-builtin \
    -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    "$runtime_probe" "$start" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"

if awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols" | grep -q .; then
    fail "static candidate has unresolved symbols"
fi
if grep -Eq 'Requesting program interpreter|INTERP|NEEDED' \
    "$candidate_headers" "$candidate_dynamic"; then
    fail "static candidate is dynamic"
fi
if grep -Eq '[[:space:]]TLS[[:space:]]|TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
    "$candidate_headers" "$candidate_relocations" "$candidate_symbols" \
    "$candidate_disassembly"; then
    fail "static candidate retains TLS or a dynamic TLS resolver"
fi
if grep -Eq '@plt|\.plt' "$candidate_disassembly"; then
    fail "static candidate retains a PLT call path"
fi
if grep -Eq '[[:space:]]alloca$' "$candidate_symbols"; then
    fail "static candidate retained a callable alloca symbol"
fi
for symbol in aligned_alloc calloc free malloc malloc_usable_size memalign mmap \
    munmap posix_memalign realloc reallocarray sbrk valloc; do
    if grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols"; then
        fail "static candidate selected allocator/runtime symbol ${symbol}"
    fi
done
if grep -Eqi 'glibc|ld-linux|libc\.so\.6|mimalloc|libmimalloc' \
    "$candidate_headers" "$candidate_dynamic" "$candidate_symbols" \
    "$candidate_disassembly"; then
    fail "static candidate selected an ambient libc or allocator backend"
fi

case_disassembly="$(sed -n '/<crabc_x86_64_alloca_case>:/,/^$/p' \
    "$candidate_disassembly")"
[ -n "$case_disassembly" ] || fail "candidate lacks the dynamic alloca case"
printf '%s\n' "$case_disassembly" | \
    grep -Eq 'sub[[:space:]]+%r(ax|dx|cx|si|di|8|9|10|11|12|13|14|15),%rsp' \
    || fail "candidate did not emit a dynamic stack allocation"

env -i "$candidate" || fail "freestanding alloca candidate failed"
printf 'x86 static musl-compatible alloca builtin: PASS\n'
