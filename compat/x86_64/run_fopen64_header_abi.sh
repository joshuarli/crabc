#!/usr/bin/env bash
# Native Linux/x86-64 <stdio.h> fopen64 large-file macro ABI evidence.
#
# Pinned musl 1.2.6 is the public-header oracle. Its LP64 contract is a
# `_LARGEFILE64_SOURCE` preprocessing alias to `fopen`, not an ELF `fopen64`
# symbol. This compile-only runner proves that exact C/C++ header boundary in
# both trees; it deliberately does not select a distinct ELF spelling, a stdio
# runtime, pathname streams, CRT, loader, sysroot, or public x86.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly MUSL_ROOT=/opt/musl-1.2.6
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly CANDIDATE_CC=/usr/bin/gcc
readonly PROJECT_INCLUDE="$ROOT_DIR/include"
readonly C_PROBE="$ROOT_DIR/compat/x86_64/fopen64_header_abi_probe.c"
readonly CXX_PROBE="$ROOT_DIR/compat/x86_64/fopen64_header_abi_probe.cpp"
readonly -a PROFILES=(
    c11-base
    c11-gnu
    c11-file-offset-bits-64
    c11-largefile-source
    c11-largefile64
    cxx17-base
    cxx17-gnu
    cxx17-file-offset-bits-64
    cxx17-largefile-source
    cxx17-largefile64
)

fail() {
    printf 'ERROR: x86 stdio fopen64 header ABI: %s\n' "$*" >&2
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

run_compiler() {
    local compiler="$1"
    shift
    env -u CPATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH -u LIBRARY_PATH \
        -u GCC_EXEC_PREFIX -u GCC_SPECS -u COMPILER_PATH \
        "$compiler" "$@"
}

profile_is_cxx() {
    case "$1" in
        cxx17-*) return 0 ;;
        *) return 1 ;;
    esac
}

profile_arguments() {
    case "$1" in
        c11-base)
            printf '%s\0' -U_GNU_SOURCE -U_BSD_SOURCE -U_XOPEN_SOURCE \
                -U_POSIX_C_SOURCE -U_FILE_OFFSET_BITS -U_LARGEFILE_SOURCE \
                -U_LARGEFILE64_SOURCE -U_DEFAULT_SOURCE \
                -DCRABC_FOPEN64_HEADER_C11_BASE
            ;;
        c11-gnu)
            printf '%s\0' -U_BSD_SOURCE -U_XOPEN_SOURCE -U_POSIX_C_SOURCE \
                -U_FILE_OFFSET_BITS -U_LARGEFILE_SOURCE -U_LARGEFILE64_SOURCE \
                -U_DEFAULT_SOURCE -D_GNU_SOURCE \
                -DCRABC_FOPEN64_HEADER_C11_GNU
            ;;
        c11-file-offset-bits-64)
            printf '%s\0' -U_GNU_SOURCE -U_BSD_SOURCE -U_XOPEN_SOURCE \
                -U_POSIX_C_SOURCE -U_LARGEFILE_SOURCE -U_LARGEFILE64_SOURCE \
                -U_DEFAULT_SOURCE -D_FILE_OFFSET_BITS=64 \
                -DCRABC_FOPEN64_HEADER_C11_FILE_OFFSET_BITS_64
            ;;
        c11-largefile-source)
            printf '%s\0' -U_GNU_SOURCE -U_BSD_SOURCE -U_XOPEN_SOURCE \
                -U_POSIX_C_SOURCE -U_FILE_OFFSET_BITS -U_LARGEFILE64_SOURCE \
                -U_DEFAULT_SOURCE -D_LARGEFILE_SOURCE \
                -DCRABC_FOPEN64_HEADER_C11_LARGEFILE_SOURCE
            ;;
        c11-largefile64)
            printf '%s\0' -U_GNU_SOURCE -U_BSD_SOURCE -U_XOPEN_SOURCE \
                -U_POSIX_C_SOURCE -U_FILE_OFFSET_BITS -U_LARGEFILE_SOURCE \
                -U_DEFAULT_SOURCE -D_LARGEFILE64_SOURCE \
                -DCRABC_FOPEN64_HEADER_C11_LARGEFILE64
            ;;
        cxx17-base)
            printf '%s\0' -U_GNU_SOURCE -U_BSD_SOURCE -U_XOPEN_SOURCE \
                -U_POSIX_C_SOURCE -U_FILE_OFFSET_BITS -U_LARGEFILE_SOURCE \
                -U_LARGEFILE64_SOURCE -U_DEFAULT_SOURCE \
                -DCRABC_FOPEN64_HEADER_CXX17_BASE
            ;;
        cxx17-gnu)
            printf '%s\0' -U_BSD_SOURCE -U_XOPEN_SOURCE -U_POSIX_C_SOURCE \
                -U_FILE_OFFSET_BITS -U_LARGEFILE_SOURCE -U_LARGEFILE64_SOURCE \
                -U_DEFAULT_SOURCE -D_GNU_SOURCE \
                -DCRABC_FOPEN64_HEADER_CXX17_GNU
            ;;
        cxx17-file-offset-bits-64)
            printf '%s\0' -U_GNU_SOURCE -U_BSD_SOURCE -U_XOPEN_SOURCE \
                -U_POSIX_C_SOURCE -U_LARGEFILE_SOURCE -U_LARGEFILE64_SOURCE \
                -U_DEFAULT_SOURCE -D_FILE_OFFSET_BITS=64 \
                -DCRABC_FOPEN64_HEADER_CXX17_FILE_OFFSET_BITS_64
            ;;
        cxx17-largefile-source)
            printf '%s\0' -U_GNU_SOURCE -U_BSD_SOURCE -U_XOPEN_SOURCE \
                -U_POSIX_C_SOURCE -U_FILE_OFFSET_BITS -U_LARGEFILE64_SOURCE \
                -U_DEFAULT_SOURCE -D_LARGEFILE_SOURCE \
                -DCRABC_FOPEN64_HEADER_CXX17_LARGEFILE_SOURCE
            ;;
        cxx17-largefile64)
            printf '%s\0' -U_GNU_SOURCE -U_BSD_SOURCE -U_XOPEN_SOURCE \
                -U_POSIX_C_SOURCE -U_FILE_OFFSET_BITS -U_LARGEFILE_SOURCE \
                -U_DEFAULT_SOURCE -D_LARGEFILE64_SOURCE \
                -DCRABC_FOPEN64_HEADER_CXX17_LARGEFILE64
            ;;
        *) fail "unknown profile: $1" ;;
    esac
}

trace_paths() {
    sed -n -E 's/^[. ]+ (\/[^[:space:]]+).*$/\1/p' "$1"
}

assert_header_provenance() {
    local tree="$1"
    local profile="$2"
    local trace="$3"
    local root
    local path

    case "$tree" in
        reference) root="$MUSL_ROOT/include" ;;
        candidate) root="$PROJECT_INCLUDE" ;;
        *) fail "unknown header tree: $tree" ;;
    esac
    grep -Fq "$root/stdio.h" "$trace" ||
        fail "$tree $profile trace omitted $root/stdio.h"
    grep -Fq "$root/features.h" "$trace" ||
        fail "$tree $profile trace omitted $root/features.h"
    grep -Fq "$root/bits/alltypes.h" "$trace" ||
        fail "$tree $profile trace omitted $root/bits/alltypes.h"
    while IFS= read -r path; do
        case "$tree:$path" in
            reference:"$MUSL_ROOT/include"/*|reference:"$compiler_builtin_include"/*|\
            candidate:"$PROJECT_INCLUDE"/*|candidate:"$compiler_builtin_include"/*) ;;
            *) fail "$tree $profile header trace escaped its declared roots: $path" ;;
        esac
    done < <(trace_paths "$trace")
}

assert_object_references_fopen_only() {
    local tree="$1"
    local profile="$2"
    local object="$3"
    local undefined

    undefined="$(nm --undefined-only "$object" | awk '{ print $NF }')"
    printf '%s\n' "$undefined" | grep -Fxq fopen ||
        fail "$tree $profile did not retain an unmangled fopen reference"
    if printf '%s\n' "$undefined" | grep -Eq '(^fopen64$|_Z.*fopen)'; then
        fail "$tree $profile retained an ELF or mangled fopen64 reference"
    fi
}

compile_one() {
    local tree="$1"
    local profile="$2"
    local trace="$3"
    local object="$4"
    local compiler
    local include_root
    local source
    local -a profile_args
    local -a common_args
    local -a arguments

    mapfile -d '' -t profile_args < <(profile_arguments "$profile")
    case "$tree" in
        reference)
            compiler="$ORACLE_CC"
            include_root="$MUSL_ROOT/include"
            ;;
        candidate)
            compiler="$CANDIDATE_CC"
            include_root="$PROJECT_INCLUDE"
            ;;
        *) fail "unknown header tree: $tree" ;;
    esac
    common_args=(
        -nostdinc -I "$include_root" -isystem "$compiler_builtin_include"
        -H -fno-builtin "${profile_args[@]}"
    )
    if profile_is_cxx "$profile"; then
        source="$CXX_PROBE"
        arguments=(-x c++ -std=c++17 -nostdinc++ "${common_args[@]}" \
            -c "$source" -o "$object")
    else
        source="$C_PROBE"
        arguments=(-x c -std=c11 -Werror=implicit-function-declaration \
            "${common_args[@]}" -c "$source" -o "$object")
    fi
    run_compiler "$compiler" "${arguments[@]}" >/dev/null 2>"$trace"
}

[ "$#" -eq 0 ] || fail "usage: $0"
require_native_linux_x86_64
for tool in awk env grep mapfile mktemp nm realpath sed uname; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -x "$CANDIDATE_CC" ] || fail "missing raw native candidate compiler"
[ -d "$MUSL_ROOT/include" ] || fail "missing pinned musl include tree"
[ -d "$PROJECT_INCLUDE" ] || fail "missing project include tree"
[ -f "$C_PROBE" ] || fail "missing C fopen64 header probe"
[ -f "$CXX_PROBE" ] || fail "missing C++ fopen64 header probe"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

compiler_builtin_include="$(run_compiler "$CANDIDATE_CC" -print-file-name=include)"
case "$compiler_builtin_include" in
    /*) ;;
    *) fail "raw candidate compiler did not report an absolute builtin include directory" ;;
esac
compiler_builtin_include="$(realpath "$compiler_builtin_include")"
[ -d "$compiler_builtin_include" ] ||
    fail "missing raw candidate compiler builtin include directory"
[ "$compiler_builtin_include" != "$MUSL_ROOT/include" ] ||
    fail "compiler builtin include directory aliases pinned musl"

work_dir="$(mktemp -d /tmp/crabc-x86-64-fopen64-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT

for profile in "${PROFILES[@]}"; do
    for tree in reference candidate; do
        trace="$work_dir/$tree-$profile.trace"
        object="$work_dir/$tree-$profile.o"
        compile_one "$tree" "$profile" "$trace" "$object" ||
            fail "$tree $profile compile failed: $(sed -n '/fatal error:/p; /error:/p' "$trace" | sed -n '1p')"
        assert_header_provenance "$tree" "$profile" "$trace"
        assert_object_references_fopen_only "$tree" "$profile" "$object"
    done
done

printf 'x86 stdio fopen64 header ABI: PASS\n'
