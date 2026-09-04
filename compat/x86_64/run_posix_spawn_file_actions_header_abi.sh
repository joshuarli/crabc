#!/usr/bin/env bash
# Native Linux/x86-64 spawn file-actions C/C++ declaration and layout gate.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly MUSL_ROOT=/opt/musl-1.2.6
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly CANDIDATE_CC=/usr/bin/gcc
readonly PROJECT_INCLUDE="$ROOT_DIR/include"
readonly C_PROBE="$ROOT_DIR/compat/x86_64/posix_spawn_file_actions_header_abi_probe.c"
readonly CXX_PROBE="$ROOT_DIR/compat/x86_64/posix_spawn_file_actions_header_abi_probe.cpp"
readonly -a PROFILES=(c11-strict c11-posix-2008 c11-xopen-700 c11-gnu cxx17-strict cxx17-gnu)

fail() { printf 'ERROR: x86 spawn file-actions headers: %s\n' "$*" >&2; exit 1; }
require_tool() { command -v "$1" >/dev/null 2>&1 || fail "requires $1"; }
run_compiler() {
    env -u CPATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH -u LIBRARY_PATH \
        -u GCC_EXEC_PREFIX -u GCC_SPECS -u COMPILER_PATH "$@"
}
profile_arguments() {
    case "$1" in
        c11-strict|cxx17-strict) printf '%s\n' '-D__STRICT_ANSI__' ;;
        c11-posix-2008) printf '%s\n' '-D_POSIX_C_SOURCE=200809L' ;;
        c11-xopen-700) printf '%s\n' '-D_XOPEN_SOURCE=700' ;;
        c11-gnu|cxx17-gnu) printf '%s\n' '-D_GNU_SOURCE' ;;
        *) fail "unknown profile $1" ;;
    esac
}
trace_paths() { sed -n -E 's/^[. ]+ (\/[^[:space:]]+).*$/\1/p' "$1"; }
compile_profile() {
    local tree="$1" profile="$2" trace="$3" object="$4"
    local compiler include_root source
    local -a profile_args arguments
    case "$tree" in
        reference) compiler="$ORACLE_CC"; include_root="$MUSL_ROOT/include" ;;
        candidate) compiler="$CANDIDATE_CC"; include_root="$PROJECT_INCLUDE" ;;
        *) fail "unknown tree $tree" ;;
    esac
    mapfile -t profile_args < <(profile_arguments "$profile")
    arguments=(-nostdinc -I "$include_root" -isystem "$candidate_builtin_include"
        -U_GNU_SOURCE -U_BSD_SOURCE -U_DEFAULT_SOURCE -U_XOPEN_SOURCE
        -U_POSIX_C_SOURCE -H -fno-builtin "${profile_args[@]}")
    case "$profile" in
        c11-*) source="$C_PROBE"; arguments=(-x c -std=c11 "${arguments[@]}"
            -Werror=implicit-function-declaration -fsyntax-only "$source") ;;
        cxx17-*) source="$CXX_PROBE"; arguments=(-x c++ -std=c++17
            -nostdinc++ "${arguments[@]}" -c -o "$object" "$source") ;;
        *) fail "unknown profile $profile" ;;
    esac
    run_compiler "$compiler" "${arguments[@]}" >/dev/null 2>"$trace"
}
check_trace() {
    local tree="$1" profile="$2" trace="$3" root path
    case "$tree" in
        reference) root="$MUSL_ROOT/include" ;;
        candidate) root="$PROJECT_INCLUDE" ;;
        *) fail "unknown tree $tree" ;;
    esac
    while IFS= read -r path; do
        case "$path" in
            "$root"/*|"$candidate_builtin_include"/*) ;;
            *) fail "$profile $tree trace escaped declared roots: $path" ;;
        esac
    done < <(trace_paths "$trace")
    for header in spawn.h features.h bits/alltypes.h fcntl.h unistd.h \
        sys/types.h sys/stat.h; do
        grep -Fq "$root/$header" "$trace" ||
            fail "$profile $tree trace omitted $root/$header"
    done
}
check_cxx_linkage() {
    local tree="$1" profile="$2" object="$3" name
    local -a names=(posix_spawn_file_actions_init posix_spawn_file_actions_destroy
        posix_spawn_file_actions_addclose posix_spawn_file_actions_adddup2
        posix_spawn_file_actions_addopen)
    if [ "$profile" = cxx17-gnu ]; then
        names+=(posix_spawn_file_actions_addchdir_np
            posix_spawn_file_actions_addfchdir_np)
    fi
    for name in "${names[@]}"; do
        nm --undefined-only "$object" | grep -Eq "[[:space:]]${name}$" ||
            fail "$profile $tree C++ probe lacks unmangled $name"
        if nm --undefined-only "$object" | grep -Eq "_Z[0-9].*${name}"; then
            fail "$profile $tree C++ probe retained mangled $name"
        fi
    done
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "requires native x86-64" ;; esac
for tool in env grep mapfile mktemp nm realpath sed uname; do require_tool "$tool"; done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl compiler"
[ -d "$MUSL_ROOT/include" ] || fail "missing pinned musl include tree"
[ -d "$PROJECT_INCLUDE" ] || fail "missing project include tree"
candidate_builtin_include="$(run_compiler "$CANDIDATE_CC" -print-file-name=include)"
case "$candidate_builtin_include" in /*) ;; *) fail "candidate compiler has no absolute builtin include" ;; esac
candidate_builtin_include="$(realpath "$candidate_builtin_include")"
[ -d "$candidate_builtin_include" ] || fail "missing candidate builtin include"
work_dir="$(mktemp -d /tmp/crabc-x86-64-spawn-file-actions-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
for profile in "${PROFILES[@]}"; do
    for tree in reference candidate; do
        trace="$work_dir/$profile.$tree.trace"
        object="$work_dir/$profile.$tree.o"
        compile_profile "$tree" "$profile" "$trace" "$object" ||
            fail "$profile $tree declaration compilation failed"
        check_trace "$tree" "$profile" "$trace"
        case "$profile" in
            cxx17-*) check_cxx_linkage "$tree" "$profile" "$object" ;;
        esac
    done
done
printf 'x86 pinned-musl/project C/C++ spawn file-actions header ABI: PASS (%s profiles)\n' "${#PROFILES[@]}"
