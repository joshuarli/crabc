#!/usr/bin/env bash
# Native Linux/x86-64 C11/C++17 floating-parser/locale header ABI gate.
#
# Pinned musl 1.2.6 is the declaration and requested C++ C-linkage oracle.
# The candidate pass uses raw GCC with only project headers and compiler
# builtin headers, so ambient libc headers cannot hide a project mismatch.
# This is compile-only evidence for the complete public
# `numeric.parse-float-locale` declaration family, including x87 binary80,
# locale_t, wchar_t, and intmax_t result/argument types. It neither links
# crabc-libc nor selects general
# text/locale behavior, a C runtime, CRT, loader, sysroot, or public x86
# support.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly MUSL_ROOT=/opt/musl-1.2.6
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly CANDIDATE_CC=/usr/bin/gcc
readonly PROJECT_INCLUDE="$ROOT_DIR/include"
readonly C_PROBE="$ROOT_DIR/compat/x86_64/float_parse_header_abi_probe.c"
readonly CXX_PROBE="$ROOT_DIR/compat/x86_64/float_parse_header_abi_probe.cpp"
readonly -a STRICT_FEATURE_ARGS=(
    -D_GNU_SOURCE
    -U_BSD_SOURCE
    -U_XOPEN_SOURCE
    -U_POSIX_C_SOURCE
    -U_LARGEFILE64_SOURCE
    -U_DEFAULT_SOURCE
)
readonly -a CXX_SYMBOLS=(
    atof
    ecvt
    fcvt
    gcvt
    getsubopt
    strtod
    strtod_l
    strtof
    strtof_l
    strtold
    strtold_l
    wcstod
    wcstof
    wcstoimax
    wcstol
    wcstold
    wcstoll
    wcstoul
    wcstoull
    wcstoumax
)

fail() {
    printf 'ERROR: x86 float-parse header ABI: %s\n' "$*" >&2
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

trace_paths() {
    sed -n -E 's/^[. ]+ (\/[^[:space:]]+).*$/\1/p' "$1"
}

assert_header_provenance() {
    local tree="$1"
    local trace="$2"
    local label="$3"
    local root
    local path
    local header

    case "$tree" in
        reference) root="$MUSL_ROOT/include" ;;
        candidate) root="$PROJECT_INCLUDE" ;;
        *) fail "unknown header tree: $tree" ;;
    esac

    while IFS= read -r path; do
        case "$path" in
            "$root"/*|"$candidate_compiler_builtin_include"/*) ;;
            *) fail "$label trace escaped its declared header roots: $path" ;;
        esac
    done < <(trace_paths "$trace")

    for header in inttypes.h locale.h stdlib.h wchar.h features.h bits/alltypes.h; do
        grep -Fq "$root/$header" "$trace" ||
            fail "$label did not preprocess $root/$header"
    done
}

compile_one() {
    local tree="$1"
    local language="$2"
    local diagnostic="$3"
    local object="$4"
    local compiler
    local include_root
    local source
    local -a arguments

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

    arguments=(
        -nostdinc
        -I "$include_root"
        -isystem "$candidate_compiler_builtin_include"
        -H
        -fno-builtin
        "${STRICT_FEATURE_ARGS[@]}"
    )
    case "$language" in
        c11)
            source="$C_PROBE"
            arguments=(-x c -std=c11 "${arguments[@]}" -fsyntax-only "$source")
            ;;
        cxx17)
            source="$CXX_PROBE"
            arguments=(-x c++ -std=c++17 -nostdinc++ "${arguments[@]}" \
                -c -o "$object" "$source")
            ;;
        *) fail "unknown language: $language" ;;
    esac

    run_compiler "$compiler" "${arguments[@]}" >/dev/null 2>"$diagnostic"
}

check_cxx_c_linkage() {
    local object="$1"
    local label="$2"
    local undefined
    local symbol

    undefined="$(nm --undefined-only "$object" | awk '{print $NF}')"
    for symbol in "${CXX_SYMBOLS[@]}"; do
        if ! printf '%s\n' "$undefined" | grep -Fxq "$symbol"; then
            printf 'C++ linkage mismatch: %s does not retain C-linkage symbol %s\n' \
                "$label" "$symbol" >&2
            return 1
        fi
    done

    if printf '%s\n' "$undefined" | grep -Eq '^_Z.*(atof|ecvt|fcvt|gcvt|getsubopt|strto|wcsto)'; then
        printf 'C++ linkage mismatch: %s retains a mangled float-parser reference\n' \
            "$label" >&2
        return 1
    fi
}

run_one() {
    local tree="$1"
    local language="$2"
    local diagnostic="$work_dir/$tree-$language.trace"
    local object="$work_dir/$tree-$language.o"
    local label="$tree/$language"

    if ! compile_one "$tree" "$language" "$diagnostic" "$object"; then
        sed -n '1,160p' "$diagnostic" >&2
        fail "$label header contract compilation failed"
    fi
    assert_header_provenance "$tree" "$diagnostic" "$label"
    if [ "$language" = cxx17 ] && ! check_cxx_c_linkage "$object" "$label"; then
        fail "$label C++ declarations do not retain C linkage"
    fi
    printf 'PASS: %s\n' "$label"
}

[ "$#" -eq 0 ] || fail "usage: $0"
require_native_linux_x86_64
for tool in awk env grep mktemp nm realpath sed uname; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -x "$CANDIDATE_CC" ] || fail "missing raw native candidate compiler"
[ -d "$MUSL_ROOT/include" ] || fail "missing pinned musl include tree"
[ -d "$PROJECT_INCLUDE" ] || fail "missing project include tree"
[ -f "$C_PROBE" ] || fail "missing C float-parse header probe"
[ -f "$CXX_PROBE" ] || fail "missing C++ float-parse header probe"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

candidate_compiler_builtin_include="$(run_compiler "$CANDIDATE_CC" \
    -print-file-name=include)"
case "$candidate_compiler_builtin_include" in
    /*) ;;
    *) fail "raw candidate compiler did not report an absolute builtin include directory" ;;
esac
candidate_compiler_builtin_include="$(realpath "$candidate_compiler_builtin_include")"
[ -d "$candidate_compiler_builtin_include" ] ||
    fail "missing raw candidate compiler builtin include directory"
[ "$candidate_compiler_builtin_include" != "$MUSL_ROOT/include" ] ||
    fail "candidate compiler builtin include aliases pinned musl"

work_dir="$(mktemp -d /tmp/crabc-x86-64-float-parse-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT

run_one reference c11
run_one reference cxx17
run_one candidate c11
run_one candidate cxx17

printf 'x86 pinned-musl/project C11/C++17 float-parse/locale header ABI: PASS\n'
