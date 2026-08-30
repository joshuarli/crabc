#!/usr/bin/env bash
# Native Linux/x86-64 permanent-standard-stream <stdio.h> ABI matrix.
#
# Pinned musl 1.2.6 supplies the declaration, feature-visibility, opaque-FILE,
# and C++ C-linkage oracle. The candidate uses raw GCC with only project and
# compiler-builtin headers, so an ambient libc cannot conceal a mismatch. This
# is compile-only evidence: it selects no crabc-libc archive, stdio runtime,
# path stream, CRT lifecycle, loader, sysroot, or public x86 support.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly MUSL_ROOT=/opt/musl-1.2.6
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly CANDIDATE_CC=/usr/bin/gcc
readonly PROJECT_INCLUDE="$ROOT_DIR/include"
readonly C_PROBE="$ROOT_DIR/compat/x86_64/stdio_standard_header_abi_probe.c"
readonly CXX_PROBE="$ROOT_DIR/compat/x86_64/stdio_standard_header_abi_probe.cpp"
readonly -a PROFILES=(
    c99-strict
    c11-strict
    c11-posix-2008
    cxx17-strict
    cxx17-posix-2008
)

fail() {
    printf 'ERROR: x86 stdio standard header ABI: %s\n' "$*" >&2
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

profile_is_strict() {
    case "$1" in
        c99-strict|c11-strict|cxx17-strict) return 0 ;;
        *) return 1 ;;
    esac
}

profile_is_posix() {
    case "$1" in
        c11-posix-2008|cxx17-posix-2008) return 0 ;;
        *) return 1 ;;
    esac
}

profile_arguments() {
    case "$1" in
        c99-strict)
            printf '%s\0' \
                -U_GNU_SOURCE -U_BSD_SOURCE -U_XOPEN_SOURCE \
                -U_POSIX_C_SOURCE -U_LARGEFILE64_SOURCE -U_DEFAULT_SOURCE \
                -DCRABC_STDIO_STANDARD_C99_STRICT
            ;;
        c11-strict)
            printf '%s\0' \
                -U_GNU_SOURCE -U_BSD_SOURCE -U_XOPEN_SOURCE \
                -U_POSIX_C_SOURCE -U_LARGEFILE64_SOURCE -U_DEFAULT_SOURCE \
                -DCRABC_STDIO_STANDARD_C11_STRICT
            ;;
        c11-posix-2008)
            printf '%s\0' \
                -U_GNU_SOURCE -U_BSD_SOURCE -U_XOPEN_SOURCE \
                -U_LARGEFILE64_SOURCE -U_DEFAULT_SOURCE \
                -D_POSIX_C_SOURCE=200809L \
                -DCRABC_STDIO_STANDARD_C11_POSIX_2008
            ;;
        cxx17-strict)
            printf '%s\0' \
                -U_GNU_SOURCE -U_BSD_SOURCE -U_XOPEN_SOURCE \
                -U_POSIX_C_SOURCE -U_LARGEFILE64_SOURCE -U_DEFAULT_SOURCE \
                -DCRABC_STDIO_STANDARD_CXX17_STRICT
            ;;
        cxx17-posix-2008)
            printf '%s\0' \
                -U_GNU_SOURCE -U_BSD_SOURCE -U_XOPEN_SOURCE \
                -U_LARGEFILE64_SOURCE -U_DEFAULT_SOURCE \
                -D_POSIX_C_SOURCE=200809L \
                -DCRABC_STDIO_STANDARD_CXX17_POSIX_2008
            ;;
        *) fail "unknown profile: $1" ;;
    esac
}

profile_c_standard() {
    case "$1" in
        c99-*) printf '%s\n' c99 ;;
        c11-*) printf '%s\n' c11 ;;
        *) fail "$1 is not a C profile" ;;
    esac
}

trace_paths() {
    sed -n -E 's/^[. ]+ (\/[^[:space:]]+).*$/\1/p' "$1"
}

first_diagnostic() {
    local diagnostic="$1"
    local line

    line="$(sed -n '/fatal error:/p; /error:/p' "$diagnostic" | sed -n '1p' || true)"
    if [ -n "$line" ]; then
        printf '%s\n' "$line" | tr '\t\r\n' ' '
    else
        printf '%s\n' 'no compiler diagnostic'
    fi
}

trace_has_unapproved_path() {
    local tree="$1"
    local trace="$2"
    local path

    while IFS= read -r path; do
        case "$tree" in
            reference)
                case "$path" in
                    "$MUSL_ROOT/include"/*|"$candidate_compiler_builtin_include"/*) ;;
                    *) return 0 ;;
                esac
                ;;
            candidate)
                case "$path" in
                    "$PROJECT_INCLUDE"/*|"$candidate_compiler_builtin_include"/*) ;;
                    *) return 0 ;;
                esac
                ;;
            *) fail "unknown header tree: $tree" ;;
        esac
    done < <(trace_paths "$trace")
    return 1
}

assert_header_provenance() {
    local tree="$1"
    local profile="$2"
    local trace="$3"
    local root
    local header

    case "$tree" in
        reference) root="$MUSL_ROOT/include" ;;
        candidate) root="$PROJECT_INCLUDE" ;;
        *) fail "unknown header tree: $tree" ;;
    esac

    if trace_has_unapproved_path "$tree" "$trace"; then
        fail "$tree $profile header trace escaped its declared roots"
    fi
    for header in stdio.h features.h bits/alltypes.h; do
        grep -Fq "$root/$header" "$trace" ||
            fail "$tree $profile trace omitted $root/$header"
    done
}

compile_one() {
    local tree="$1"
    local profile="$2"
    local mode="$3"
    local diagnostic="$4"
    local object="$5"
    local compiler
    local include_root
    local source
    local -a profile_args
    local -a mode_args=()
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

    case "$mode" in
        normal) ;;
        strict-hidden)
            profile_is_strict "$profile" ||
                fail "$profile cannot use the strict fileno hidden witness"
            mode_args=(
                -DCRABC_STDIO_STANDARD_HIDDEN_WITNESS_ONLY
                -DCRABC_STDIO_STANDARD_REQUIRE_FILENO_HIDDEN
            )
            ;;
        *) fail "unknown compile mode: $mode" ;;
    esac

    common_args=(
        -nostdinc -I "$include_root"
        -isystem "$candidate_compiler_builtin_include"
        -H -fno-builtin
        "${profile_args[@]}" "${mode_args[@]}"
    )
    if profile_is_cxx "$profile"; then
        source="$CXX_PROBE"
        arguments=(
            -x c++ -std=c++17 -nostdinc++
            "${common_args[@]}"
        )
        if [ "$mode" = normal ]; then
            arguments+=(-c "$source" -o "$object")
        else
            arguments+=(-fsyntax-only "$source")
        fi
    else
        source="$C_PROBE"
        arguments=(
            -x c "-std=$(profile_c_standard "$profile")"
            -Werror=implicit-function-declaration
            "${common_args[@]}" -fsyntax-only "$source"
        )
    fi

    run_compiler "$compiler" "${arguments[@]}" >/dev/null 2>"$diagnostic"
}

expected_cxx_symbols() {
    local profile="$1"

    printf '%s\n' \
        stdin stdout stderr \
        fflush fread fwrite \
        fgetc getc getchar fputc putc putchar ungetc \
        feof ferror clearerr
    if profile_is_posix "$profile"; then
        printf '%s\n' fileno
    fi
}

check_cxx_c_linkage() {
    local tree="$1"
    local profile="$2"
    local object="$3"
    local undefined
    local symbol

    undefined="$(nm --undefined-only "$object" | awk '{print $NF}')"
    while IFS= read -r symbol; do
        [ -n "$symbol" ] || continue
        printf '%s\n' "$undefined" | grep -Fxq "$symbol" ||
            fail "$tree $profile C++ probe does not retain C spelling $symbol"
    done < <(expected_cxx_symbols "$profile")
    if printf '%s\n' "$undefined" | grep -Eq \
        '_Z.*(stdin|stdout|stderr|fflush|fread|fwrite|fgetc|getc|getchar|fputc|putc|putchar|ungetc|feof|ferror|clearerr|fileno)'; then
        fail "$tree $profile C++ probe retained a mangled stdio reference"
    fi
}

record_failure() {
    printf 'stdio standard header mismatch: %s\n' "$*" >&2
    failures=$((failures + 1))
}

record_compile_failure() {
    local tree="$1"
    local profile="$2"
    local diagnostic="$3"
    local summary

    summary="$(first_diagnostic "$diagnostic")"
    if [ "$tree" = candidate ] && [ "$profile" = c99-strict ] && \
        grep -Eq '(incomplete type|sizeof.*FILE|FILE.*incomplete)' "$diagnostic"; then
        record_failure \
            "candidate c99-strict leaves FILE incomplete; pre-C11 <stdio.h> must request the one-byte opaque struct _IO_FILE placeholder before bits/alltypes.h"
    else
        record_failure "$tree $profile normal compile failed: $summary"
    fi
}

[ "$#" -eq 0 ] || fail "usage: $0"
require_native_linux_x86_64
for tool in awk env grep mktemp nm realpath sed tr uname; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -x "$CANDIDATE_CC" ] || fail "missing raw native candidate compiler"
[ -d "$MUSL_ROOT/include" ] || fail "missing pinned musl include tree"
[ -d "$PROJECT_INCLUDE" ] || fail "missing project include tree"
[ -f "$C_PROBE" ] || fail "missing C stdio standard header probe"
[ -f "$CXX_PROBE" ] || fail "missing C++ stdio standard header probe"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

candidate_compiler_builtin_include="$(run_compiler "$CANDIDATE_CC" -print-file-name=include)"
case "$candidate_compiler_builtin_include" in
    /*) ;;
    *) fail "raw candidate compiler did not report an absolute builtin include directory" ;;
esac
candidate_compiler_builtin_include="$(realpath "$candidate_compiler_builtin_include")"
[ -d "$candidate_compiler_builtin_include" ] ||
    fail "missing raw candidate compiler builtin include directory"
[ "$candidate_compiler_builtin_include" != "$MUSL_ROOT/include" ] ||
    fail "compiler builtin include directory aliases pinned musl"

work_dir="$(mktemp -d /tmp/crabc-x86-64-stdio-standard-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
failures=0

for profile in "${PROFILES[@]}"; do
    for tree in reference candidate; do
        trace="$work_dir/$tree-$profile.trace"
        object="$work_dir/$tree-$profile.o"
        if ! compile_one "$tree" "$profile" normal "$trace" "$object"; then
            record_compile_failure "$tree" "$profile" "$trace"
            continue
        fi
        if ! assert_header_provenance "$tree" "$profile" "$trace"; then
            record_failure "$tree $profile failed header provenance checks"
        fi
        if profile_is_cxx "$profile"; then
            if ! check_cxx_c_linkage "$tree" "$profile" "$object"; then
                record_failure "$tree $profile failed C++ C-linkage checks"
            fi
        fi
        if profile_is_strict "$profile"; then
            hidden_trace="$work_dir/$tree-$profile-hidden.trace"
            if compile_one "$tree" "$profile" strict-hidden "$hidden_trace" \
                "$work_dir/$tree-$profile-hidden.o"; then
                record_failure "$tree $profile unexpectedly exposes POSIX fileno"
            elif ! grep -Fq 'fileno' "$hidden_trace"; then
                record_failure "$tree $profile hidden fileno witness named no fileno diagnostic"
            fi
        fi
    done
done

if [ "$failures" -ne 0 ]; then
    fail "$failures stdio standard header profile mismatch(es)"
fi

printf 'x86 pinned-musl/project permanent-standard-stream <stdio.h> ABI: PASS\n'
