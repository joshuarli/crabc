#!/usr/bin/env bash
# Native Linux/x86-64 permanent-stream feof_unlocked <stdio.h> ABI proof.
#
# Pinned musl 1.2.6 supplies GNU/BSD visibility and C++ C-linkage oracle. The
# raw candidate uses only project and compiler-builtin include trees. This
# compile-only matrix selects neither an archive nor a runtime/FILE model.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly MUSL_ROOT=/opt/musl-1.2.6
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly CANDIDATE_CC=/usr/bin/gcc
readonly PROJECT_INCLUDE="$ROOT_DIR/include"
readonly C_PROBE="$ROOT_DIR/compat/x86_64/stdio_permanent_feof_unlocked_header_abi_probe.c"
readonly CXX_PROBE="$ROOT_DIR/compat/x86_64/stdio_permanent_feof_unlocked_header_abi_probe.cpp"
readonly -a PROFILES=(
    c11-gnu
    c11-bsd
    cxx17-gnu
    cxx17-bsd
    c11-strict
    c11-posix-2008
    cxx17-strict
    cxx17-posix-2008
)

fail() {
    printf 'ERROR: x86 stdio permanent-stream feof_unlocked header ABI: %s\n' "$*" >&2
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
    for header in stdio.h features.h bits/alltypes.h; do
        grep -Fq "$root/$header" "$trace" ||
            fail "$tree trace omitted $root/$header"
    done
}

profile_is_cxx() {
    case "$1" in
        cxx17-*) return 0 ;;
        *) return 1 ;;
    esac
}

profile_is_hidden() {
    case "$1" in
        *-strict|*-posix-2008) return 0 ;;
        *) return 1 ;;
    esac
}

profile_arguments() {
    case "$1" in
        c11-gnu)
            printf '%s\0' -U_BSD_SOURCE -U_XOPEN_SOURCE -U_POSIX_C_SOURCE \
                -U_LARGEFILE64_SOURCE -U_DEFAULT_SOURCE -D_GNU_SOURCE \
                -DCRABC_STDIO_PERMANENT_FEOF_UNLOCKED_C11_GNU
            ;;
        c11-bsd)
            printf '%s\0' -U_GNU_SOURCE -U_XOPEN_SOURCE -U_POSIX_C_SOURCE \
                -U_LARGEFILE64_SOURCE -U_DEFAULT_SOURCE -D_BSD_SOURCE \
                -DCRABC_STDIO_PERMANENT_FEOF_UNLOCKED_C11_BSD
            ;;
        cxx17-gnu)
            printf '%s\0' -U_BSD_SOURCE -U_XOPEN_SOURCE -U_POSIX_C_SOURCE \
                -U_LARGEFILE64_SOURCE -U_DEFAULT_SOURCE -D_GNU_SOURCE \
                -DCRABC_STDIO_PERMANENT_FEOF_UNLOCKED_CXX17_GNU
            ;;
        cxx17-bsd)
            printf '%s\0' -U_GNU_SOURCE -U_XOPEN_SOURCE -U_POSIX_C_SOURCE \
                -U_LARGEFILE64_SOURCE -U_DEFAULT_SOURCE -D_BSD_SOURCE \
                -DCRABC_STDIO_PERMANENT_FEOF_UNLOCKED_CXX17_BSD
            ;;
        c11-strict)
            printf '%s\0' -U_GNU_SOURCE -U_BSD_SOURCE -U_XOPEN_SOURCE \
                -U_POSIX_C_SOURCE -U_LARGEFILE64_SOURCE -U_DEFAULT_SOURCE \
                -DCRABC_STDIO_PERMANENT_FEOF_UNLOCKED_REQUIRE_HIDDEN
            ;;
        c11-posix-2008)
            printf '%s\0' -U_GNU_SOURCE -U_BSD_SOURCE -U_XOPEN_SOURCE \
                -U_LARGEFILE64_SOURCE -U_DEFAULT_SOURCE \
                -D_POSIX_C_SOURCE=200809L \
                -DCRABC_STDIO_PERMANENT_FEOF_UNLOCKED_REQUIRE_HIDDEN
            ;;
        cxx17-strict)
            printf '%s\0' -U_GNU_SOURCE -U_BSD_SOURCE -U_XOPEN_SOURCE \
                -U_POSIX_C_SOURCE -U_LARGEFILE64_SOURCE -U_DEFAULT_SOURCE \
                -DCRABC_STDIO_PERMANENT_FEOF_UNLOCKED_REQUIRE_HIDDEN
            ;;
        cxx17-posix-2008)
            printf '%s\0' -U_GNU_SOURCE -U_BSD_SOURCE -U_XOPEN_SOURCE \
                -U_LARGEFILE64_SOURCE -U_DEFAULT_SOURCE \
                -D_POSIX_C_SOURCE=200809L \
                -DCRABC_STDIO_PERMANENT_FEOF_UNLOCKED_REQUIRE_HIDDEN
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

compile_positive() {
    local tree="$1" profile="$2" trace="$3" object="$4"
    local compiler include_root source standard
    local -a profile_args language_args include_args output_args
    compiler="$(compiler_for_tree "$tree")"
    include_root="$(include_for_tree "$tree")"
    mapfile -d '' -t profile_args < <(profile_arguments "$profile")
    if profile_is_cxx "$profile"; then
        source="$CXX_PROBE"; standard=c++17
        language_args=(-x c++)
        include_args=(-nostdinc -nostdinc++ -I "$include_root")
        output_args=(-c "$source" -o "$object")
    else
        source="$C_PROBE"; standard=c11
        language_args=(-x c)
        include_args=(-nostdinc -I "$include_root")
        output_args=(-fsyntax-only "$source")
    fi
    run_compiler "$compiler" "${language_args[@]}" -std="$standard" \
        "${include_args[@]}" -isystem "$candidate_compiler_builtin_include" \
        -H -fno-builtin "${profile_args[@]}" "${output_args[@]}" \
        >/dev/null 2>"$trace"
}

assert_hidden() {
    local tree="$1" profile="$2" diagnostic="$3"
    local compiler include_root source standard
    local -a profile_args language_args include_args
    compiler="$(compiler_for_tree "$tree")"
    include_root="$(include_for_tree "$tree")"
    mapfile -d '' -t profile_args < <(profile_arguments "$profile")
    if profile_is_cxx "$profile"; then
        source="$CXX_PROBE"; standard=c++17
        language_args=(-x c++)
        include_args=(-nostdinc -nostdinc++ -I "$include_root")
    else
        source="$C_PROBE"; standard=c11
        language_args=(-x c)
        include_args=(-nostdinc -I "$include_root")
    fi

    set +e
    run_compiler "$compiler" "${language_args[@]}" -std="$standard" \
        "${include_args[@]}" -isystem "$candidate_compiler_builtin_include" \
        -H -fno-builtin "${profile_args[@]}" -fsyntax-only "$source" \
        >/dev/null 2>"$diagnostic"
    local status=$?
    set -e
    [ "$status" -ne 0 ] ||
        fail "$tree $profile unexpectedly declares feof_unlocked"
    grep -Eq 'feof_unlocked|undeclared|not declared' "$diagnostic" ||
        fail "$tree $profile did not diagnose hidden feof_unlocked"
}

assert_cxx_c_linkage() {
    local tree="$1" object="$2"
    local undefined

    undefined="$(nm --undefined-only "$object" | awk '{print $NF}')"
    printf '%s\n' "$undefined" | grep -Fxq feof_unlocked ||
        fail "$tree C++ probe does not retain C spelling feof_unlocked"
    if printf '%s\n' "$undefined" | grep -Eq '_Z.*feof_unlocked'; then
        fail "$tree C++ probe retained a mangled feof_unlocked reference"
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
[ -f "$C_PROBE" ] || fail "missing C permanent-stream feof_unlocked header probe"
[ -f "$CXX_PROBE" ] || fail "missing C++ permanent-stream feof_unlocked header probe"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

candidate_compiler_builtin_include="$(run_compiler "$CANDIDATE_CC" -print-file-name=include)"
case "$candidate_compiler_builtin_include" in
    /*) ;;
    *) fail "raw candidate compiler did not report an absolute builtin include directory" ;;
esac
candidate_compiler_builtin_include="$(realpath "$candidate_compiler_builtin_include")"
[ -d "$candidate_compiler_builtin_include" ] ||
    fail "missing raw candidate compiler builtin include directory"

work_dir="$(mktemp -d /tmp/crabc-x86-64-stdio-permanent-feof-unlocked-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
for tree in reference candidate; do
    for profile in "${PROFILES[@]}"; do
        if profile_is_hidden "$profile"; then
            assert_hidden "$tree" "$profile" "$work_dir/$tree-$profile.trace"
            continue
        fi
        trace="$work_dir/$tree-$profile.trace"
        object="$work_dir/$tree-$profile.o"
        compile_positive "$tree" "$profile" "$trace" "$object"
        assert_header_provenance "$tree" "$trace"
        if profile_is_cxx "$profile"; then
            assert_cxx_c_linkage "$tree" "$object"
        fi
    done
done

printf 'x86 stdio permanent-stream feof_unlocked header ABI: PASS\n'
