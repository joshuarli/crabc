#!/usr/bin/env bash
# Native Linux/x86-64 permanent-stderr __flbf <stdio_ext.h> ABI proof.
#
# Pinned musl 1.2.6 supplies the declaration and C++ C-linkage oracle. The
# raw candidate uses only project and compiler-builtin include trees. This
# compile-only matrix selects neither an archive nor a runtime/FILE model.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly MUSL_ROOT=/opt/musl-1.2.6
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly CANDIDATE_CC=/usr/bin/gcc
readonly PROJECT_INCLUDE="$ROOT_DIR/include"
readonly C_PROBE="$ROOT_DIR/compat/x86_64/stdio_permanent_flbf_stderr_header_abi_probe.c"
readonly CXX_PROBE="$ROOT_DIR/compat/x86_64/stdio_permanent_flbf_stderr_header_abi_probe.cpp"
readonly -a PROFILES=(c11 cxx17)

fail() {
    printf 'ERROR: x86 stdio permanent-stderr __flbf header ABI: %s\n' "$*" >&2
    exit 1
}

require_tool() {
    command -v "$1" >/dev/null 2>&1 || fail "requires $1"
}

require_native_linux_x86_64() {
    [ "$(uname -s)" = Linux ] || fail "requires native Linux"
    case "$(uname -m)" in
        x86_64|amd64) ;;
        *) fail "refuses emulation on $(uname -m)" ;;
    esac
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
    local tree="$1" trace="$2"
    local root path

    case "$tree" in
        reference) root="$MUSL_ROOT/include" ;;
        candidate) root="$PROJECT_INCLUDE" ;;
        *) fail "unknown header tree: $tree" ;;
    esac
    while IFS= read -r path; do
        case "$path" in
            "$root"/*|"$candidate_compiler_builtin_include"/*) ;;
            *) fail "$tree header trace escaped its declared roots: $path" ;;
        esac
    done < <(trace_paths "$trace")
    for header in stdio_ext.h stdio.h features.h bits/alltypes.h; do
        grep -Fq "$root/$header" "$trace" ||
            fail "$tree trace omitted $root/$header"
    done
}

profile_arguments() {
    case "$1" in
        c11)
            printf '%s\0' -U_GNU_SOURCE -U_BSD_SOURCE -U_XOPEN_SOURCE \
                -U_POSIX_C_SOURCE -U_LARGEFILE64_SOURCE -U_DEFAULT_SOURCE \
                -DCRABC_STDIO_PERMANENT_FLBF_STDERR_C11
            ;;
        cxx17)
            printf '%s\0' -U_GNU_SOURCE -U_BSD_SOURCE -U_XOPEN_SOURCE \
                -U_POSIX_C_SOURCE -U_LARGEFILE64_SOURCE -U_DEFAULT_SOURCE \
                -DCRABC_STDIO_PERMANENT_FLBF_STDERR_CXX17
            ;;
        *) fail "unknown profile: $1" ;;
    esac
}

compiler_for_tree() {
    case "$1" in
        reference) printf '%s\n' "$ORACLE_CC" ;;
        candidate) printf '%s\n' "$CANDIDATE_CC" ;;
        *) fail "unknown header tree: $1" ;;
    esac
}

include_for_tree() {
    case "$1" in
        reference) printf '%s\n' "$MUSL_ROOT/include" ;;
        candidate) printf '%s\n' "$PROJECT_INCLUDE" ;;
        *) fail "unknown header tree: $1" ;;
    esac
}

compile_profile() {
    local tree="$1" profile="$2" trace="$3" object="$4"
    local compiler include_root source standard
    local -a profile_args language_args include_args output_args
    compiler="$(compiler_for_tree "$tree")"
    include_root="$(include_for_tree "$tree")"
    mapfile -d '' -t profile_args < <(profile_arguments "$profile")
    case "$profile" in
        c11)
            source="$C_PROBE"; standard=c11
            language_args=(-x c)
            include_args=(-nostdinc -I "$include_root")
            output_args=(-fsyntax-only "$source")
            ;;
        cxx17)
            source="$CXX_PROBE"; standard=c++17
            language_args=(-x c++)
            include_args=(-nostdinc -nostdinc++ -I "$include_root")
            output_args=(-c "$source" -o "$object")
            ;;
        *) fail "unknown profile: $profile" ;;
    esac
    run_compiler "$compiler" "${language_args[@]}" -std="$standard" \
        "${include_args[@]}" -isystem "$candidate_compiler_builtin_include" \
        -H -fno-builtin "${profile_args[@]}" "${output_args[@]}" \
        >/dev/null 2>"$trace"
}

assert_cxx_c_linkage() {
    local tree="$1" object="$2"
    local undefined

    undefined="$(nm --undefined-only "$object" | awk '{print $NF}')"
    printf '%s\n' "$undefined" | grep -Fxq __flbf ||
        fail "$tree C++ probe does not retain C spelling __flbf"
    if printf '%s\n' "$undefined" | grep -Eq '_Z.*__flbf'; then
        fail "$tree C++ probe retained a mangled __flbf reference"
    fi
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
[ -f "$C_PROBE" ] || fail "missing C permanent-stderr __flbf header probe"
[ -f "$CXX_PROBE" ] || fail "missing C++ permanent-stderr __flbf header probe"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

candidate_compiler_builtin_include="$(run_compiler "$CANDIDATE_CC" -print-file-name=include)"
case "$candidate_compiler_builtin_include" in
    /*) ;;
    *) fail "raw candidate compiler did not report an absolute builtin include directory" ;;
esac
candidate_compiler_builtin_include="$(realpath "$candidate_compiler_builtin_include")"
[ -d "$candidate_compiler_builtin_include" ] ||
    fail "missing raw candidate compiler builtin include directory"

work_dir="$(mktemp -d /tmp/crabc-x86-64-stdio-permanent-flbf-stderr-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
for tree in reference candidate; do
    for profile in "${PROFILES[@]}"; do
        trace="$work_dir/$tree-$profile.trace"
        object="$work_dir/$tree-$profile.o"
        compile_profile "$tree" "$profile" "$trace" "$object"
        assert_header_provenance "$tree" "$trace"
        if [ "$profile" = cxx17 ]; then
            assert_cxx_c_linkage "$tree" "$object"
        fi
    done
done

printf 'x86 stdio permanent-stderr __flbf header ABI: PASS\n'
