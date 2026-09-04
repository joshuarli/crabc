#!/usr/bin/env bash
# Native Linux/x86-64 UAPI include-closure and request vocabulary matrix.
#
# Pinned musl 1.2.6 supplies the public-header oracle.  Candidate invocations
# use raw GCC with only the project tree and compiler builtins, so ambient host
# headers cannot make an incomplete include edge pass.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly MUSL_ROOT=/opt/musl-1.2.6
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly CANDIDATE_CC=/usr/bin/gcc
readonly PROJECT_INCLUDE="$ROOT_DIR/include"
readonly C_PROBE="$ROOT_DIR/compat/x86_64/uapi_header_closure_probe.c"
readonly CXX_PROBE="$ROOT_DIR/compat/x86_64/uapi_header_closure_probe.cpp"
readonly C_INCLUDE_ONLY="$ROOT_DIR/compat/x86_64/uapi_header_include_only.c"
readonly CXX_INCLUDE_ONLY="$ROOT_DIR/compat/x86_64/uapi_header_include_only.cpp"
readonly -a PROFILES=(c11-gnu cxx17-gnu c11-strict c11-posix-2008 c11-xopen-700 c11-bsd cxx17-strict)
readonly -a VARIANTS=(
    CRABC_UAPI_IOCTL_ONLY CRABC_UAPI_MOUNT_ONLY CRABC_UAPI_PTY_ONLY
    CRABC_UAPI_MTIO_ONLY CRABC_UAPI_MOUNT_IOCTL CRABC_UAPI_PTY_IOCTL
    CRABC_UAPI_MTIO_IOCTL CRABC_UAPI_ALL
)

fail() {
    printf 'ERROR: x86 UAPI header closure: %s\n' "$*" >&2
    exit 1
}

run_compiler() {
    local compiler="$1"
    shift
    env -u CPATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH -u LIBRARY_PATH \
        -u GCC_EXEC_PREFIX -u GCC_SPECS -u COMPILER_PATH "$compiler" "$@"
}

trace_paths() {
    sed -n -E 's/^[. ]+ (\/[^[:space:]]+).*$/\1/p' "$1"
}

check_trace() {
    local tree="$1"
    local trace="$2"
    local path

    while IFS= read -r path; do
        case "$tree" in
            candidate)
                case "$path" in
                    "$PROJECT_INCLUDE"/*|"$candidate_builtin"/*) ;;
                    *) fail "candidate header trace escaped project/builtin roots: $path" ;;
                esac
                if [[ "$path" == "$MUSL_ROOT"/* ]]; then
                    fail "candidate header trace reached pinned musl: $path"
                fi
                ;;
            reference)
                case "$path" in
                    "$MUSL_ROOT"/*|"$candidate_builtin"/*) ;;
                    *) fail "reference header trace escaped musl/builtin roots: $path" ;;
                esac
                ;;
            *) fail "unknown trace tree: $tree" ;;
        esac
    done < <(trace_paths "$trace")
}

profile_args() {
    case "$1" in
        c11-gnu|cxx17-gnu) printf '%s\n' '-D_GNU_SOURCE' ;;
        c11-strict|cxx17-strict) ;;
        c11-posix-2008) printf '%s\n' '-D_POSIX_C_SOURCE=200809L' ;;
        c11-xopen-700) printf '%s\n' '-D_XOPEN_SOURCE=700' ;;
        c11-bsd) printf '%s\n' '-D_BSD_SOURCE' ;;
        *) fail "unknown profile: $1" ;;
    esac
}

compile_one() {
    local tree="$1" profile="$2" variant="$3" probe="$4" trace="$5"
    local compiler include_root language
    local -a feature_args=() args=()

    if [[ "$tree" == candidate ]]; then
        compiler="$CANDIDATE_CC"
        include_root="$PROJECT_INCLUDE"
    else
        compiler="$ORACLE_CC"
        include_root="$MUSL_ROOT/include"
    fi
    mapfile -t feature_args < <(profile_args "$profile")
    [[ "$profile" == cxx* ]] && language=cxx || language=c
    args=(-nostdinc -I "$include_root" -isystem "$candidate_builtin" -H
          -fsyntax-only "-D$variant")
    if [[ "$language" == cxx ]]; then
        args=(-x c++ -std=c++17 -nostdinc++ "${feature_args[@]}" "${args[@]}" "$probe")
    else
        args=(-x c -std=c11 "${feature_args[@]}" "${args[@]}" "$probe")
    fi
    run_compiler "$compiler" "${args[@]}" >/dev/null 2>"$trace"
    check_trace "$tree" "$trace"
}

[[ "$(uname -s)" == Linux ]] || fail "requires native Linux"
[[ "$(uname -m)" == x86_64 ]] || fail "requires native x86-64"
[[ -x "$ORACLE_CC" && -d "$MUSL_ROOT/include" ]] || fail "missing pinned musl oracle"
[[ -x "$CANDIDATE_CC" && -d "$PROJECT_INCLUDE" ]] || fail "missing raw candidate compiler/project headers"
for input in "$C_PROBE" "$CXX_PROBE" "$C_INCLUDE_ONLY" "$CXX_INCLUDE_ONLY"; do
    [[ -f "$input" ]] || fail "missing probe $input"
done

candidate_builtin="$(run_compiler "$CANDIDATE_CC" -print-file-name=include)"
candidate_builtin="$(realpath "$candidate_builtin")"
[[ -d "$candidate_builtin" && "$candidate_builtin" != "$MUSL_ROOT/include" ]] ||
    fail "invalid compiler builtin include root"

work_dir="$(mktemp -d /tmp/crabc-x86-64-uapi-header-closure.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT

for profile in "${PROFILES[@]}"; do
    for variant in "${VARIANTS[@]}"; do
        for tree in reference candidate; do
            if [[ "$profile" == cxx* ]]; then
                include_probe="$CXX_INCLUDE_ONLY"
                probe="$CXX_PROBE"
            else
                include_probe="$C_INCLUDE_ONLY"
                probe="$C_PROBE"
            fi
            trace="$work_dir/$tree-$profile-$variant-include.trace"
            compile_one "$tree" "$profile" "$variant" "$include_probe" "$trace" ||
                fail "$tree $profile $variant include-only probe failed"
            trace="$work_dir/$tree-$profile-$variant-abi.trace"
            compile_one "$tree" "$profile" "$variant" "$probe" "$trace" ||
                fail "$tree $profile $variant ABI probe failed"
        done
    done
done

printf 'x86 pinned-musl/project UAPI header closure: PASS (%s profiles; %s include variants; C/C++)\n' \
    "${#PROFILES[@]}" "${#VARIANTS[@]}"
