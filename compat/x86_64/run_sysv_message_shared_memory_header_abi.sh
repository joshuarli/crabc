#!/usr/bin/env bash
# Native Linux/x86-64 SysV message/shared-memory header ABI matrix.
#
# Pinned musl 1.2.6 owns the selected sys/ipc.h, sys/msg.h, and sys/shm.h
# declaration, layout, value, feature-selection, and C++ C-linkage contract.
# The candidate uses raw GCC with only project headers and raw-GCC builtin
# headers, so an ambient libc cannot conceal a public-header mismatch. This is
# compile-only evidence: it proves no crabc static/shared artifact linkage,
# runtime behavior, family closure, or public x86 support.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly MUSL_ROOT=/opt/musl-1.2.6
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly CANDIDATE_CC=/usr/bin/gcc
readonly PROJECT_INCLUDE="$ROOT_DIR/include"
readonly C_PROBE="$ROOT_DIR/compat/x86_64/sysv_message_shared_memory_header_abi_probe.c"
readonly CXX_PROBE="$ROOT_DIR/compat/x86_64/sysv_message_shared_memory_header_abi_probe.cpp"
readonly EXPECTED_PROFILE_COUNT=8
readonly -a PROFILES=(c-default c11-gnu cxx17-gnu c11-strict c11-posix-2008 c11-xopen-700 c11-bsd cxx17-strict)
readonly -a STRICT_IPC_PROFILES=(c11-strict c11-posix-2008 c11-xopen-700 cxx17-strict)
readonly -a STRICT_MSGBUF_PROFILES=(c11-strict c11-posix-2008 c11-xopen-700 cxx17-strict)
readonly -a NON_GNU_SHM_PROFILES=(c-default c11-strict c11-posix-2008 c11-xopen-700 c11-bsd cxx17-strict)

fail() {
    printf 'ERROR: x86 SysV message/shared-memory headers: %s\n' "$*" >&2
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

profile_arguments() {
    local profile="$1"
    case "$profile" in
        c-default|c11-strict) ;;
        c11-gnu|cxx17-gnu) printf '%s\n' '-D_GNU_SOURCE' ;;
        cxx17-strict) printf '%s\n' '-U_GNU_SOURCE' ;;
        c11-posix-2008) printf '%s\n' '-D_POSIX_C_SOURCE=200809L' ;;
        c11-xopen-700) printf '%s\n' '-D_XOPEN_SOURCE=700' ;;
        c11-bsd) printf '%s\n' '-D_BSD_SOURCE' ;;
        *) fail "unknown profile: $profile" ;;
    esac
}

mode_arguments() {
    local mode="$1"
    case "$mode" in
        normal) ;;
        compat-ipc-hidden) printf '%s\n' '-DCRABC_SYSV_MESSAGE_SHM_REQUIRE_COMPAT_IPC' ;;
        msgbuf-hidden) printf '%s\n' '-DCRABC_SYSV_MESSAGE_SHM_REQUIRE_MSGBUF' ;;
        gnu-shm-hidden) printf '%s\n' '-DCRABC_SYSV_MESSAGE_SHM_REQUIRE_GNU_SHM' ;;
        *) fail "unknown compile mode: $mode" ;;
    esac
}

compile_profile() {
    local tree="$1"
    local profile="$2"
    local mode="$3"
    local diagnostic="$4"
    local object="$5"
    local compiler
    local include_root
    local source="$C_PROBE"
    local -a profile_args
    local -a mode_args
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
    mapfile -t mode_args < <(mode_arguments "$mode")
    arguments=(
        -nostdinc
        -I "$include_root"
        -isystem "$candidate_compiler_builtin_include"
        -H
        -fno-builtin
        "${profile_args[@]}"
        "${mode_args[@]}"
    )

    if [ "$mode" = normal ] && [[ "$profile" == cxx17-* ]]; then
        source="$CXX_PROBE"
        arguments=(-x c++ -std=c++17 -nostdinc++ "${arguments[@]}" -c -o "$object" "$source")
    elif [ "$profile" = c-default ]; then
        arguments=(-x c "${arguments[@]}" -fsyntax-only "$source")
    else
        arguments=(-x c -std=c11 "${arguments[@]}" \
            -Werror=implicit-function-declaration -fsyntax-only "$source")
    fi
    run_compiler "$compiler" "${arguments[@]}" >/dev/null 2>"$diagnostic"
}

check_trace() {
    local tree="$1"
    local profile="$2"
    local trace="$3"
    local root
    case "$tree" in
        candidate)
            root="$PROJECT_INCLUDE"
            if grep -Fq "$MUSL_ROOT/include/" "$trace"; then
                fail "$profile candidate trace reached pinned musl despite -nostdinc"
            fi
            ;;
        reference) root="$MUSL_ROOT/include" ;;
        *) fail "unknown trace tree: $tree" ;;
    esac
    if trace_has_unapproved_path "$tree" "$trace"; then
        fail "$profile $tree trace escaped its declared header roots"
    fi
    for header in sys/ipc.h sys/msg.h sys/shm.h; do
        grep -Fq "$root/$header" "$trace" ||
            fail "$profile $tree trace omitted $root/$header"
    done
}

check_cxx_symbols() {
    local tree="$1"
    local profile="$2"
    local object="$3"
    local undefined
    local symbol
    local -a expected=(ftok msgctl msgget msgrcv msgsnd shmat shmctl shmdt shmget)

    undefined="$(nm --undefined-only "$object")"
    for symbol in "${expected[@]}"; do
        printf '%s\n' "$undefined" | grep -Eq "[[:space:]]${symbol}$" ||
            fail "$tree $profile C++ probe does not retain C linkage for $symbol"
    done
    if printf '%s\n' "$undefined" | grep -Eq '_Z(4ftok|6msgctl|6msgget|6msgrcv|6msgsnd|5shmat|6shmctl|5shmdt|6shmget)'; then
        fail "$tree $profile C++ probe retained a mangled SysV IPC reference"
    fi
}

expect_hidden_failure() {
    local tree="$1"
    local profile="$2"
    local mode="$3"
    local diagnostic="$4"
    local object="$5"
    local expected_text="$6"

    if compile_profile "$tree" "$profile" "$mode" "$diagnostic" "$object"; then
        fail "$tree $profile unexpectedly exposes $mode"
    fi
    grep -Fq "$expected_text" "$diagnostic" ||
        fail "$tree $profile $mode diagnostic does not name $expected_text"
}

[ "$#" -eq 0 ] || fail "usage: $0"
require_native_linux_x86_64
for tool in grep mapfile mktemp nm realpath sed tr uname; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -x "$CANDIDATE_CC" ] || fail "missing raw native candidate compiler"
[ -d "$MUSL_ROOT/include" ] || fail "missing pinned musl include tree"
[ -d "$PROJECT_INCLUDE" ] || fail "missing project include tree"
[ -f "$C_PROBE" ] || fail "missing C SysV message/shared-memory header ABI probe"
[ -f "$CXX_PROBE" ] || fail "missing C++ SysV message/shared-memory header ABI probe"
[ "${#PROFILES[@]}" = "$EXPECTED_PROFILE_COUNT" ] || fail "profile roster drifted"

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
    fail "compiler builtin include directory aliases the pinned musl tree"

work_dir="$(mktemp -d /tmp/crabc-x86-64-sysv-message-shm-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT

for profile in "${PROFILES[@]}"; do
    reference_trace="$work_dir/$profile.reference.trace"
    candidate_trace="$work_dir/$profile.candidate.trace"
    reference_object="$work_dir/$profile.reference.o"
    candidate_object="$work_dir/$profile.candidate.o"
    if ! compile_profile reference "$profile" normal "$reference_trace" "$reference_object"; then
        fail "$profile pinned-musl reference failed: $(first_diagnostic "$reference_trace")"
    fi
    check_trace reference "$profile" "$reference_trace"
    if ! compile_profile candidate "$profile" normal "$candidate_trace" "$candidate_object"; then
        fail "$profile project-header candidate failed: $(first_diagnostic "$candidate_trace")"
    fi
    check_trace candidate "$profile" "$candidate_trace"
    if [[ "$profile" == cxx17-* ]]; then
        check_cxx_symbols reference "$profile" "$reference_object"
        check_cxx_symbols candidate "$profile" "$candidate_object"
    fi
done

for profile in "${STRICT_IPC_PROFILES[@]}"; do
    for tree in reference candidate; do
        expect_hidden_failure "$tree" "$profile" compat-ipc-hidden \
            "$work_dir/$profile.$tree.compat-ipc.trace" \
            "$work_dir/$profile.$tree.compat-ipc.o" key
    done
done

for profile in "${STRICT_MSGBUF_PROFILES[@]}"; do
    for tree in reference candidate; do
        expect_hidden_failure "$tree" "$profile" msgbuf-hidden \
            "$work_dir/$profile.$tree.msgbuf.trace" \
            "$work_dir/$profile.$tree.msgbuf.o" msgbuf
    done
done

for profile in "${NON_GNU_SHM_PROFILES[@]}"; do
    for tree in reference candidate; do
        expect_hidden_failure "$tree" "$profile" gnu-shm-hidden \
            "$work_dir/$profile.$tree.gnu-shm.trace" \
            "$work_dir/$profile.$tree.gnu-shm.o" used_ids
    done
done

printf 'x86 pinned-musl/project C/C++ SysV message/shared-memory header ABI matrix: PASS (%s profiles; compile-only)\n' \
    "$EXPECTED_PROFILE_COUNT"
