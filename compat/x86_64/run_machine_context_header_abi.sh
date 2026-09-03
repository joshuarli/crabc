#!/usr/bin/env bash
# Native Linux/x86-64 machine/context public-header ABI profile matrix.
#
# Pinned musl 1.2.6 is the declaration, layout, extension-visibility, and C++
# C-linkage oracle. The candidate uses raw GCC with only project headers and
# compiler builtin headers, so an ambient libc cannot mask an x86 header leak.
# This is compile-only evidence; it selects no runtime API or public x86 scope.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly MUSL_ROOT=/opt/musl-1.2.6
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly CANDIDATE_CC=/usr/bin/gcc
readonly PROJECT_INCLUDE="$ROOT_DIR/include"
readonly C_PROBE="$ROOT_DIR/compat/x86_64/machine_context_header_abi_probe.c"
readonly CXX_PROBE="$ROOT_DIR/compat/x86_64/machine_context_header_abi_probe.cpp"
readonly EXPECTED_PROFILE_COUNT=7
readonly -a PROFILES=(c11-gnu cxx17-gnu c11-strict c11-posix-2008 c11-xopen-700 c11-bsd cxx17-strict)

fail() {
    printf 'ERROR: x86 machine/context header ABI: %s\n' "$*" >&2
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

trace_has_header() {
    local trace="$1"
    local root="$2"
    local header="$3"

    grep -Fq "$root/$header" "$trace"
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
            *) fail "unknown header tree: $tree" ;;
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
    case "$1" in
        c11-gnu|cxx17-gnu)
            printf '%s\n' '-U_BSD_SOURCE' '-D_GNU_SOURCE' \
                '-DCRABC_MACHINE_CONTEXT_EXPECT_CONTEXT' \
                '-DCRABC_MACHINE_CONTEXT_EXPECT_GNU_BSD'
            ;;
        c11-bsd)
            printf '%s\n' '-U_GNU_SOURCE' '-D_BSD_SOURCE' \
                '-DCRABC_MACHINE_CONTEXT_EXPECT_CONTEXT' \
                '-DCRABC_MACHINE_CONTEXT_EXPECT_GNU_BSD'
            ;;
        c11-strict|cxx17-strict)
            printf '%s\n' '-U_GNU_SOURCE' '-U_BSD_SOURCE'
            ;;
        c11-posix-2008)
            printf '%s\n' '-U_GNU_SOURCE' '-U_BSD_SOURCE' '-D_POSIX_C_SOURCE=200809L' \
                '-DCRABC_MACHINE_CONTEXT_EXPECT_CONTEXT'
            ;;
        c11-xopen-700)
            printf '%s\n' '-U_GNU_SOURCE' '-U_BSD_SOURCE' '-D_XOPEN_SOURCE=700' \
                '-DCRABC_MACHINE_CONTEXT_EXPECT_CONTEXT'
            ;;
        *) fail "unknown profile: $1" ;;
    esac
}

profile_is_cxx() {
    case "$1" in
        cxx17-*) return 0 ;;
        *) return 1 ;;
    esac
}

profile_exposes_context() {
    case "$1" in
        c11-strict|cxx17-strict) return 1 ;;
        *) return 0 ;;
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
    local -a profile_args
    local -a mode_args=()
    local -a arguments

    case "$tree" in
        candidate) compiler="$CANDIDATE_CC"; include_root="$PROJECT_INCLUDE" ;;
        reference) compiler="$ORACLE_CC"; include_root="$MUSL_ROOT/include" ;;
        *) fail "unknown header tree: $tree" ;;
    esac

    mapfile -t profile_args < <(profile_arguments "$profile")
    case "$mode" in
        normal) ;;
        context-hidden)
            mode_args=(-DCRABC_MACHINE_CONTEXT_REQUIRE_CONTEXT_HIDDEN)
            ;;
        *) fail "unknown compile mode: $mode" ;;
    esac
    arguments=(
        -nostdinc -I "$include_root" -isystem "$candidate_compiler_builtin_include"
        -H -fno-builtin "${profile_args[@]}" "${mode_args[@]}"
    )
    if profile_is_cxx "$profile"; then
        run_compiler "$compiler" -x c++ -std=c++17 -nostdinc++ "${arguments[@]}" \
            -c -o "$object" "$CXX_PROBE" >/dev/null 2>"$diagnostic"
    else
        run_compiler "$compiler" -x c -std=c11 "${arguments[@]}" \
            -Werror=implicit-function-declaration -fsyntax-only "$C_PROBE" \
            >/dev/null 2>"$diagnostic"
    fi
}

expect_context_hidden() {
    local tree="$1"
    local profile="$2"
    local diagnostic="$3"
    local object="$4"

    if compile_profile "$tree" "$profile" context-hidden "$diagnostic" "$object"; then
        fail "$tree $profile unexpectedly exposes mcontext_t/ucontext_t"
    fi
    grep -Eq 'mcontext_t|ucontext_t' "$diagnostic" ||
        fail "$tree $profile hidden-context diagnostic does not name mcontext_t/ucontext_t"
}

check_trace() {
    local tree="$1"
    local profile="$2"
    local trace="$3"
    local root
    local header

    case "$tree" in
        candidate)
            root="$PROJECT_INCLUDE"
            grep -Fq "$MUSL_ROOT/include/" "$trace" &&
                fail "$profile candidate trace reached pinned musl despite -nostdinc"
            ;;
        reference) root="$MUSL_ROOT/include" ;;
        *) fail "unknown header tree: $tree" ;;
    esac
    trace_has_unapproved_path "$tree" "$trace" &&
        fail "$profile $tree trace escaped its declared header roots"
    for header in elf.h sys/auxv.h bits/hwcap.h sys/ptrace.h bits/ptrace.h \
        sys/reg.h bits/reg.h sys/user.h bits/user.h sys/procfs.h sys/ucontext.h \
        ucontext.h features.h signal.h bits/alltypes.h bits/signal.h; do
        trace_has_header "$trace" "$root" "$header" ||
            fail "$profile $tree trace omitted ${root}/$header"
    done
}

check_cxx_symbols() {
    local tree="$1"
    local profile="$2"
    local object="$3"
    local undefined
    local symbol
    local -a expected=(getauxval ptrace getcontext makecontext setcontext swapcontext)

    undefined="$(nm --undefined-only "$object")"
    for symbol in "${expected[@]}"; do
        printf '%s\n' "$undefined" | grep -Eq "[[:space:]]${symbol}$" ||
            fail "$tree $profile C++ probe does not retain C linkage for $symbol"
    done
    if printf '%s\n' "$undefined" | \
        grep -Eq '_Z.*(getauxval|ptrace|getcontext|makecontext|setcontext|swapcontext)'; then
        fail "$tree $profile C++ probe retained a mangled machine/context reference"
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
[ -f "$C_PROBE" ] || fail "missing C machine/context header ABI probe"
[ -f "$CXX_PROBE" ] || fail "missing C++ machine/context header ABI probe"
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
    fail "compiler builtin include directory aliases pinned musl"

work_dir="$(mktemp -d /tmp/crabc-x86-64-machine-context-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT

for profile in "${PROFILES[@]}"; do
    for tree in reference candidate; do
        trace="$work_dir/$tree-$profile.trace"
        object="$work_dir/$tree-$profile.o"
        if ! compile_profile "$tree" "$profile" normal "$trace" "$object"; then
            fail "$tree $profile machine/context header profile failed: $(first_diagnostic "$trace")"
        fi
        check_trace "$tree" "$profile" "$trace"
        if profile_is_cxx "$profile"; then
            check_cxx_symbols "$tree" "$profile" "$object"
        fi
        if ! profile_exposes_context "$profile"; then
            hidden_trace="$work_dir/$tree-$profile-context-hidden.trace"
            hidden_object="$work_dir/$tree-$profile-context-hidden.o"
            expect_context_hidden "$tree" "$profile" "$hidden_trace" "$hidden_object"
        fi
    done
done

printf 'x86 pinned-musl/project machine/context C/C++ header ABI: PASS (%s profiles; compile-only)\n' \
    "$EXPECTED_PROFILE_COUNT"
