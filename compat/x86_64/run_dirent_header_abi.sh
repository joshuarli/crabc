#!/usr/bin/env bash
# Native Linux/x86-64 <dirent.h> ABI profile matrix.
#
# Pinned musl 1.2.6 is the declaration, feature-visibility, LP64-layout, and
# requested-C-linkage oracle. The candidate uses raw GCC with project headers
# and compiler builtin headers only, so an ambient libc cannot conceal a
# public-header mismatch. This compile-only matrix checks C++ undefined names
# solely as header-requested C spellings: it neither links a crabc archive nor
# does not claim x86 directory-stream runtime or archive linkage support.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly MUSL_ROOT=/opt/musl-1.2.6
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly CANDIDATE_CC=/usr/bin/gcc
readonly PROJECT_INCLUDE="$ROOT_DIR/include"
readonly C_PROBE="$ROOT_DIR/compat/x86_64/dirent_header_abi_probe.c"
readonly CXX_PROBE="$ROOT_DIR/compat/x86_64/dirent_header_abi_probe.cpp"
readonly EXPECTED_BASE_PROFILE_COUNT=7
readonly EXPECTED_LARGEFILE64_PROFILE_COUNT=4
readonly EXPECTED_SEEK_TELL_VISIBLE_PROFILE_COUNT=4
readonly EXPECTED_GETDENTS_VISIBLE_PROFILE_COUNT=3
readonly EXPECTED_VERSIONSORT_VISIBLE_PROFILE_COUNT=2
readonly -a BASE_PROFILES=(c11-gnu cxx17-gnu c11-strict c11-posix-2008 c11-xopen-700 c11-bsd cxx17-strict)
readonly -a LARGEFILE64_PROFILES=(c11-gnu-largefile64 cxx17-gnu-largefile64 c11-strict-largefile64 cxx17-strict-largefile64)
readonly -a SEEK_TELL_VISIBLE_PROFILES=(c11-gnu cxx17-gnu c11-xopen-700 c11-bsd)
readonly -a GETDENTS_VISIBLE_PROFILES=(c11-gnu cxx17-gnu c11-bsd)
readonly -a VERSIONSORT_VISIBLE_PROFILES=(c11-gnu cxx17-gnu)

fail() {
    printf 'ERROR: x86 dirent header ABI: %s\n' "$*" >&2
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

trace_has_unapproved_path() {
    local tree="$1"
    local trace="$2"
    local path

    while IFS= read -r path; do
        case "$tree" in
            candidate)
                case "$path" in
                    "$PROJECT_INCLUDE"/*|"$candidate_compiler_builtin_include"/*) ;;
                    *) return 0 ;;
                esac
                ;;
            reference)
                case "$path" in
                    "$MUSL_ROOT/include"/*|"$candidate_compiler_builtin_include"/*) ;;
                    *) return 0 ;;
                esac
                ;;
            *) fail "unknown trace tree: $tree" ;;
        esac
    done < <(trace_paths "$trace")
    return 1
}

first_diagnostic() {
    local diagnostic="$1"
    local line

    line="$(sed -n '/fatal error:/p; /error:/p' "$diagnostic" | sed -n '1p' || true)"
    if [ -z "$line" ]; then
        printf '%s\n' 'no compiler diagnostic'
    else
        printf '%s\n' "$line" | tr '\t\r\n' ' '
    fi
}

profile_has_seek_tell() {
    local profile="$1"
    local visible

    case "$profile" in
        c11-gnu-largefile64|cxx17-gnu-largefile64) return 0 ;;
    esac
    for visible in "${SEEK_TELL_VISIBLE_PROFILES[@]}"; do
        [ "$profile" = "$visible" ] && return 0
    done
    return 1
}

profile_has_getdents() {
    local profile="$1"
    local visible

    case "$profile" in
        c11-gnu-largefile64|cxx17-gnu-largefile64) return 0 ;;
    esac
    for visible in "${GETDENTS_VISIBLE_PROFILES[@]}"; do
        [ "$profile" = "$visible" ] && return 0
    done
    return 1
}

profile_has_versionsort() {
    local profile="$1"
    local visible

    case "$profile" in
        c11-gnu-largefile64|cxx17-gnu-largefile64) return 0 ;;
    esac
    for visible in "${VERSIONSORT_VISIBLE_PROFILES[@]}"; do
        [ "$profile" = "$visible" ] && return 0
    done
    return 1
}

profile_arguments() {
    local profile="$1"

    case "$profile" in
        c11-gnu|cxx17-gnu)
            printf '%s\n' '-D_GNU_SOURCE' '-U_LARGEFILE64_SOURCE' \
                '-DCRABC_DIRENT_BASE'
            ;;
        c11-strict|cxx17-strict)
            printf '%s\n' '-U_GNU_SOURCE' '-U_LARGEFILE64_SOURCE' \
                '-DCRABC_DIRENT_BASE'
            ;;
        c11-posix-2008)
            printf '%s\n' '-U_GNU_SOURCE' '-U_LARGEFILE64_SOURCE' \
                '-D_POSIX_C_SOURCE=200809L' '-DCRABC_DIRENT_BASE'
            ;;
        c11-xopen-700)
            printf '%s\n' '-U_GNU_SOURCE' '-U_LARGEFILE64_SOURCE' \
                '-D_XOPEN_SOURCE=700' '-DCRABC_DIRENT_BASE'
            ;;
        c11-bsd)
            printf '%s\n' '-U_GNU_SOURCE' '-U_LARGEFILE64_SOURCE' \
                '-D_BSD_SOURCE' '-DCRABC_DIRENT_BASE'
            ;;
        c11-gnu-largefile64|cxx17-gnu-largefile64)
            printf '%s\n' '-D_GNU_SOURCE' '-D_LARGEFILE64_SOURCE' \
                '-DCRABC_DIRENT_LARGEFILE64'
            ;;
        c11-strict-largefile64|cxx17-strict-largefile64)
            printf '%s\n' '-U_GNU_SOURCE' '-D_LARGEFILE64_SOURCE' \
                '-DCRABC_DIRENT_LARGEFILE64'
            ;;
        *) fail "unknown profile: $profile" ;;
    esac
    if profile_has_seek_tell "$profile"; then
        printf '%s\n' '-DCRABC_DIRENT_SEEK_TELL_VISIBLE'
    else
        printf '%s\n' '-DCRABC_DIRENT_SEEK_TELL_HIDDEN'
    fi
    if profile_has_getdents "$profile"; then
        printf '%s\n' '-DCRABC_DIRENT_GETDENTS_VISIBLE'
    else
        printf '%s\n' '-DCRABC_DIRENT_GETDENTS_HIDDEN'
    fi
    if profile_has_versionsort "$profile"; then
        printf '%s\n' '-DCRABC_DIRENT_VERSIONSORT_VISIBLE'
    else
        printf '%s\n' '-DCRABC_DIRENT_VERSIONSORT_HIDDEN'
    fi
}

profile_is_cxx() {
    case "$1" in
        cxx17-*) return 0 ;;
        *) return 1 ;;
    esac
}

compile_profile() {
    local tree="$1"
    local profile="$2"
    local diagnostic="$3"
    local object="$4"
    local negative="$5"
    local compiler
    local include_root
    local source
    local -a profile_args
    local -a arguments

    case "$tree" in
        candidate)
            compiler="$CANDIDATE_CC"
            include_root="$PROJECT_INCLUDE"
            ;;
        reference)
            compiler="$ORACLE_CC"
            include_root="$MUSL_ROOT/include"
            ;;
        *) fail "unknown compiler tree: $tree" ;;
    esac
    mapfile -t profile_args < <(profile_arguments "$profile")
    arguments=(
        -nostdinc
        -I "$include_root"
        -isystem "$candidate_compiler_builtin_include"
        -H
        -fno-builtin
        "${profile_args[@]}"
    )
    if [ "$negative" = yes ]; then
        arguments+=( -DCRABC_DIRENT_EXPECT_HIDDEN_DECLARATIONS )
    fi
    if profile_is_cxx "$profile"; then
        source="$CXX_PROBE"
        arguments=(-x c++ -std=c++17 -nostdinc++ "${arguments[@]}" \
            -c -o "$object" "$source")
    else
        source="$C_PROBE"
        arguments=(-x c -std=c11 "${arguments[@]}" -fsyntax-only "$source")
    fi
    run_compiler "$compiler" "${arguments[@]}" >/dev/null 2>"$diagnostic"
}

check_trace() {
    local tree="$1"
    local profile="$2"
    local trace="$3"
    local root
    local header
    local -a headers

    case "$tree" in
        candidate)
            root="$PROJECT_INCLUDE"
            headers=(dirent.h features.h sys/types.h)
            if grep -Fq "$MUSL_ROOT/include/" "$trace"; then
                fail "$profile candidate trace reached pinned musl despite -nostdinc"
            fi
            ;;
        reference)
            root="$MUSL_ROOT/include"
            headers=(dirent.h features.h bits/alltypes.h bits/dirent.h)
            ;;
        *) fail "unknown trace tree: $tree" ;;
    esac
    if trace_has_unapproved_path "$tree" "$trace"; then
        fail "$profile $tree trace escaped its declared header roots"
    fi
    for header in "${headers[@]}"; do
        grep -Fq "$root/$header" "$trace" ||
            fail "$profile $tree trace omitted ${root}/$header"
    done
}

check_hidden_declarations() {
    local tree="$1"
    local profile="$2"
    local diagnostic="$3"
    local object="$4"

    if compile_profile "$tree" "$profile" "$diagnostic" "$object" yes; then
        fail "$tree $profile unexpectedly exposed a hidden dirent declaration"
    fi
    grep -Eq '(seekdir|telldir|getdents|versionsort)' "$diagnostic" ||
        fail "$tree $profile hidden dirent diagnostic named no hidden declaration"
}

check_cxx_c_linkage() {
    local tree="$1"
    local profile="$2"
    local object="$3"
    local undefined
    local symbol
    local -a expected=(closedir dirfd fdopendir opendir readdir readdir_r rewinddir posix_getdents alphasort scandir)

    if profile_has_seek_tell "$profile"; then
        expected+=(seekdir telldir)
    fi
    if profile_has_getdents "$profile"; then
        expected+=(getdents)
    fi
    if profile_has_versionsort "$profile"; then
        expected+=(versionsort)
    fi
    undefined="$(nm --undefined-only "$object")"
    for symbol in "${expected[@]}"; do
        printf '%s\n' "$undefined" | grep -Eq "[[:space:]]${symbol}$" ||
            fail "$tree $profile C++ probe does not retain requested C spelling for $symbol"
    done
    if printf '%s\n' "$undefined" | grep -Eq '_Z.*(closedir|dirfd|fdopendir|opendir|readdir|rewinddir|posix_getdents|alphasort|scandir|seekdir|telldir|getdents|versionsort)'; then
        fail "$tree $profile C++ probe retained a mangled dirent reference"
    fi
}

[ "$#" -eq 0 ] || fail "usage: $0"
require_native_linux_x86_64
for tool in env grep mapfile mktemp nm realpath sed tr uname; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -x "$CANDIDATE_CC" ] || fail "missing raw native candidate compiler"
[ -d "$MUSL_ROOT/include" ] || fail "missing pinned musl include tree"
[ -d "$PROJECT_INCLUDE" ] || fail "missing project include tree"
[ -f "$C_PROBE" ] || fail "missing C dirent header probe"
[ -f "$CXX_PROBE" ] || fail "missing C++ dirent header probe"
[ "${#BASE_PROFILES[@]}" = "$EXPECTED_BASE_PROFILE_COUNT" ] ||
    fail "base profile roster drifted"
[ "${#LARGEFILE64_PROFILES[@]}" = "$EXPECTED_LARGEFILE64_PROFILE_COUNT" ] ||
    fail "large-file profile roster drifted"
[ "${#SEEK_TELL_VISIBLE_PROFILES[@]}" = "$EXPECTED_SEEK_TELL_VISIBLE_PROFILE_COUNT" ] ||
    fail "seek/tell visibility roster drifted"
[ "${#GETDENTS_VISIBLE_PROFILES[@]}" = "$EXPECTED_GETDENTS_VISIBLE_PROFILE_COUNT" ] ||
    fail "getdents/type-macro visibility roster drifted"
[ "${#VERSIONSORT_VISIBLE_PROFILES[@]}" = "$EXPECTED_VERSIONSORT_VISIBLE_PROFILE_COUNT" ] ||
    fail "versionsort visibility roster drifted"

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

work_dir="$(mktemp -d /tmp/crabc-x86-64-dirent-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT

for profile in "${BASE_PROFILES[@]}" "${LARGEFILE64_PROFILES[@]}"; do
    for tree in reference candidate; do
        trace="$work_dir/$tree-$profile.trace"
        object="$work_dir/$tree-$profile.o"
        if ! compile_profile "$tree" "$profile" "$trace" "$object" no; then
            fail "$tree $profile dirent header profile failed: $(first_diagnostic "$trace")"
        fi
        check_trace "$tree" "$profile" "$trace"
        if ! profile_has_seek_tell "$profile" || ! profile_has_getdents "$profile" || \
            ! profile_has_versionsort "$profile"; then
            check_hidden_declarations "$tree" "$profile" \
                "$work_dir/$tree-$profile-hidden.trace" \
                "$work_dir/$tree-$profile-hidden.o"
        fi
        if profile_is_cxx "$profile"; then
            check_cxx_c_linkage "$tree" "$profile" "$object"
        fi
    done
done

printf 'x86 pinned-musl/project C/C++ dirent header ABI: PASS (%s base + %s large-file profiles; compile-only header declarations, not runtime linkage)\n' \
    "$EXPECTED_BASE_PROFILE_COUNT" "$EXPECTED_LARGEFILE64_PROFILE_COUNT"
