#!/usr/bin/env bash
# Native Linux/x86-64 C/C++ <string.h> strtok declaration gate.
#
# Pinned musl 1.2.6 is the declaration oracle. The project pass permits only
# project headers and raw compiler builtins, so host libc headers cannot supply
# the declaration or C++ linkage. `strtok` is unconditional in each strict,
# POSIX, X/Open, GNU, and BSD profile tested here.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly CANDIDATE_CC=/usr/bin/gcc
readonly PROJECT_INCLUDE="$ROOT_DIR/include"
readonly C_PROBE="$ROOT_DIR/compat/x86_64/strtok_header_abi_probe.c"
readonly CXX_PROBE="$ROOT_DIR/compat/x86_64/strtok_header_abi_probe.cpp"

fail() {
    printf 'ERROR: x86 string.h strtok ABI: %s\n' "$*" >&2
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

require_native_linux_x86_64
for tool in env grep mktemp nm realpath sed uname; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -x "$CANDIDATE_CC" ] || fail "missing raw native candidate compiler"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

candidate_compiler_builtin_include="$(run_compiler "$CANDIDATE_CC" -print-file-name=include)"
case "$candidate_compiler_builtin_include" in
    /*) ;;
    *) fail "raw candidate compiler did not report an absolute builtin include directory" ;;
esac
candidate_compiler_builtin_include="$(realpath "$candidate_compiler_builtin_include")"
[ -d "$candidate_compiler_builtin_include" ] ||
    fail "missing raw candidate compiler builtin include directory"

work_dir="$(mktemp -d /tmp/crabc-x86-64-strtok-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT

set_profile_args() {
    local variant="$1"
    case "$variant" in
        oracle)
            compiler="$ORACLE_CC"
            include_args=()
            ;;
        project)
            compiler="$CANDIDATE_CC"
            include_args=(
                -nostdinc
                -I "$PROJECT_INCLUDE"
                -isystem "$candidate_compiler_builtin_include"
            )
            ;;
        *) fail "unknown header tree: $variant" ;;
    esac
}

compile_profile() {
    local definitions_name="$1"
    local language variant object undefined
    declare -n definitions="$definitions_name"

    for language in c cxx; do
        for variant in oracle project; do
            set_profile_args "$variant"
            if [ "$language" = c ]; then
                run_compiler "$compiler" -std=c11 -fno-builtin \
                    -U_GNU_SOURCE -U_BSD_SOURCE -U_XOPEN_SOURCE \
                    -U_POSIX_C_SOURCE -U_DEFAULT_SOURCE "${definitions[@]}" \
                    -DCRABC_EXPECT_STRTOK -Werror=implicit-function-declaration \
                    "${include_args[@]}" -fsyntax-only "$C_PROBE"
            else
                object="$work_dir/${variant}-${definitions_name}-strtok.o"
                run_compiler "$compiler" -std=c++17 -x c++ -fno-builtin \
                    -U_GNU_SOURCE -U_BSD_SOURCE -U_XOPEN_SOURCE \
                    -U_POSIX_C_SOURCE -U_DEFAULT_SOURCE "${definitions[@]}" \
                    -DCRABC_EXPECT_STRTOK -nostdinc++ "${include_args[@]}" \
                    -c "$CXX_PROBE" -o "$object"
                undefined="$(nm --undefined-only "$object")"
                printf '%s\n' "$undefined" | grep -Eq '[[:space:]]strtok$' ||
                    fail "C++ probe does not retain C linkage for strtok (${variant}, ${definitions_name})"
                if printf '%s\n' "$undefined" | grep -Eq '_Z[0-9].*strtok'; then
                    fail "C++ probe retained a mangled strtok reference (${variant}, ${definitions_name})"
                fi
            fi
        done
    done
}

default_definitions=()
strict_definitions=(-D__STRICT_ANSI__)
posix_definitions=(-D_POSIX_C_SOURCE=200809L)
xopen_definitions=(-D_XOPEN_SOURCE=700)
gnu_definitions=(-D_GNU_SOURCE)
bsd_definitions=(-D_BSD_SOURCE)

for definitions_name in default_definitions strict_definitions posix_definitions \
    xopen_definitions gnu_definitions bsd_definitions; do
    compile_profile "$definitions_name"
done

# -H makes project-header provenance observable rather than merely compiling
# through whichever host string.h happens to be installed.
set_profile_args project
header_trace="$work_dir/project-default-header-trace"
run_compiler "$compiler" -std=c11 -fno-builtin -U_GNU_SOURCE -U_BSD_SOURCE \
    -U_XOPEN_SOURCE -U_POSIX_C_SOURCE -U_DEFAULT_SOURCE -DCRABC_EXPECT_STRTOK \
    "${include_args[@]}" -H -fsyntax-only "$C_PROBE" >/dev/null 2>"$header_trace"
while IFS= read -r path; do
    case "$path" in
        "$PROJECT_INCLUDE"/*|"$candidate_compiler_builtin_include"/*) ;;
        *) fail "project header trace escaped its declared roots: $path" ;;
    esac
done < <(trace_paths "$header_trace")
for header in string.h features.h bits/alltypes.h; do
    grep -Fq "$PROJECT_INCLUDE/$header" "$header_trace" ||
        fail "project C probe did not use <$header>"
done

printf 'x86 pinned-musl/project C/C++ <string.h> strtok ABI: PASS\n'
