#!/usr/bin/env bash
# Native Linux/x86-64 direct-header topology matrix for pinned musl 1.2.6.
#
# It proves only selected C/C++ direct include, macro, declaration, and
# record-layout behavior; it does not select STREAMS, PTY, ioctl, or terminal
# runtime/provider behavior.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly MUSL_ROOT=/opt/musl-1.2.6
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly CANDIDATE_CC=/usr/bin/gcc
readonly PROJECT_INCLUDE="$ROOT_DIR/include"
readonly C_PROBE="$ROOT_DIR/compat/x86_64/terminal_streams_header_topology_probe.c"
readonly CXX_PROBE="$ROOT_DIR/compat/x86_64/terminal_streams_header_topology_probe.cpp"
readonly C_NEGATIVE="$ROOT_DIR/compat/x86_64/terminal_streams_header_topology_negative.c"
readonly CXX_NEGATIVE="$ROOT_DIR/compat/x86_64/terminal_streams_header_topology_negative.cpp"
readonly -a PROFILES=(c11-gnu cxx17-gnu c11-strict c11-posix-2008 c11-xopen-700 c11-bsd cxx17-strict)
readonly -a VARIANTS=(stropts sys-stropts ttydefaults-direct ttydefaults-with-termios pty termios sys-termios)
readonly -a NEGATIVE_VARIANTS=(stropts-winsize sys-stropts-winsize ttydefaults-tcgetattr)

fail() {
    printf 'ERROR: x86 terminal/STREAMS header topology: %s\n' "$*" >&2
    exit 1
}

run_compiler() {
    local compiler="$1"
    shift
    env -u CPATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH -u LIBRARY_PATH \
        -u GCC_EXEC_PREFIX -u GCC_SPECS -u COMPILER_PATH "$compiler" "$@"
}

profile_arguments() {
    case "$1" in
        c11-gnu|cxx17-gnu) printf '%s\n' '-D_GNU_SOURCE' ;;
        c11-strict|cxx17-strict) ;;
        c11-posix-2008) printf '%s\n' '-D_POSIX_C_SOURCE=200809L' ;;
        c11-xopen-700) printf '%s\n' '-D_XOPEN_SOURCE=700' ;;
        c11-bsd) printf '%s\n' '-D_BSD_SOURCE' ;;
        *) fail "unknown profile: $1" ;;
    esac
}

variant_define() {
    case "$1" in
        stropts) printf '%s\n' '-DCRABC_TERMINAL_STREAMS_STROPTS' ;;
        sys-stropts) printf '%s\n' '-DCRABC_TERMINAL_STREAMS_SYS_STROPTS' ;;
        ttydefaults-direct) printf '%s\n' '-DCRABC_TERMINAL_STREAMS_TTYDEFAULTS_DIRECT' ;;
        ttydefaults-with-termios) printf '%s\n' '-DCRABC_TERMINAL_STREAMS_TTYDEFAULTS_WITH_TERMIOS' ;;
        pty) printf '%s\n' '-DCRABC_TERMINAL_STREAMS_PTY' ;;
        termios) printf '%s\n' '-DCRABC_TERMINAL_STREAMS_TERMIOS' ;;
        sys-termios) printf '%s\n' '-DCRABC_TERMINAL_STREAMS_SYS_TERMIOS' ;;
        *) fail "unknown header variant: $1" ;;
    esac
}

variant_header() {
    case "$1" in
        stropts) printf '%s\n' 'stropts.h' ;;
        sys-stropts) printf '%s\n' 'sys/stropts.h' ;;
        ttydefaults-direct|ttydefaults-with-termios) printf '%s\n' 'sys/ttydefaults.h' ;;
        pty) printf '%s\n' 'pty.h' ;;
        termios) printf '%s\n' 'termios.h' ;;
        sys-termios) printf '%s\n' 'sys/termios.h' ;;
        *) fail "unknown header variant: $1" ;;
    esac
}

negative_variant_define() {
    case "$1" in
        stropts-winsize) printf '%s\n' '-DCRABC_TERMINAL_STREAMS_NEGATIVE_STROPTS_WINSIZE' ;;
        sys-stropts-winsize) printf '%s\n' '-DCRABC_TERMINAL_STREAMS_NEGATIVE_SYS_STROPTS_WINSIZE' ;;
        ttydefaults-tcgetattr) printf '%s\n' '-DCRABC_TERMINAL_STREAMS_NEGATIVE_TTYDEFAULTS_TCGETATTR' ;;
        *) fail "unknown negative header variant: $1" ;;
    esac
}

negative_variant_header() {
    case "$1" in
        stropts-winsize) printf '%s\n' 'stropts.h' ;;
        sys-stropts-winsize) printf '%s\n' 'sys/stropts.h' ;;
        ttydefaults-tcgetattr) printf '%s\n' 'sys/ttydefaults.h' ;;
        *) fail "unknown negative header variant: $1" ;;
    esac
}

trace_paths() {
    sed -n -E 's/^[. ]+ (\/[^[:space:]]+).*$/\1/p' "$1"
}

require_trace_header() {
    local trace="$1" root="$2" header="$3"
    grep -Fq "$root/$header" "$trace" ||
        fail "direct $header include did not resolve through $root"
}

forbid_trace_header() {
    local trace="$1" root="$2" header="$3"
    if grep -Fq "$root/$header" "$trace"; then
        fail "direct include unexpectedly acquired $header"
    fi
}

check_trace_roots() {
    local tree="$1" trace="$2" path
    while IFS= read -r path; do
        case "$tree" in
            candidate)
                case "$path" in
                    "$PROJECT_INCLUDE"/*|"$candidate_builtin"/*) ;;
                    *) fail "candidate include trace escaped project/builtin roots: $path" ;;
                esac
                ;;
            reference)
                case "$path" in
                    "$MUSL_ROOT/include"/*|"$candidate_builtin"/*) ;;
                    *) fail "reference include trace escaped musl/builtin roots: $path" ;;
                esac
                ;;
            *) fail "unknown tree: $tree" ;;
        esac
    done < <(trace_paths "$trace")
}

compile_positive() {
    local tree="$1" profile="$2" variant="$3" trace="$4"
    local compiler include_root source header
    local -a profile_args=() args=()

    case "$tree" in
        candidate) compiler="$CANDIDATE_CC"; include_root="$PROJECT_INCLUDE" ;;
        reference) compiler="$ORACLE_CC"; include_root="$MUSL_ROOT/include" ;;
        *) fail "unknown tree: $tree" ;;
    esac
    mapfile -t profile_args < <(profile_arguments "$profile")
    header="$(variant_header "$variant")"
    args=(-nostdinc -I "$include_root" -isystem "$candidate_builtin" -H -fsyntax-only
        "$(variant_define "$variant")")
    case "$profile" in
        c11-*) source="$C_PROBE"; args=(-x c -std=c11 "${profile_args[@]}" "${args[@]}" "$source") ;;
        cxx17-*) source="$CXX_PROBE"; args=(-x c++ -std=c++17 -nostdinc++ "${profile_args[@]}" "${args[@]}" "$source") ;;
        *) fail "unknown profile: $profile" ;;
    esac
    if ! run_compiler "$compiler" "${args[@]}" >/dev/null 2>"$trace"; then
        fail "$tree $profile direct <$header> probe failed: $(sed -n '/error:/p' "$trace" | sed -n '1p')"
    fi
    check_trace_roots "$tree" "$trace"
    require_trace_header "$trace" "$include_root" "$header"
    case "$variant" in
        stropts|sys-stropts)
            forbid_trace_header "$trace" "$include_root" 'sys/ioctl.h'
            ;;
        ttydefaults-direct)
            forbid_trace_header "$trace" "$include_root" 'termios.h'
            ;;
        pty)
            require_trace_header "$trace" "$include_root" 'termios.h'
            require_trace_header "$trace" "$include_root" 'sys/ioctl.h'
            ;;
        sys-termios)
            grep -Fq 'redirecting incorrect #include <sys/termios.h> to <termios.h>' "$trace" ||
                fail "$tree $profile <sys/termios.h> did not preserve musl's redirect warning"
            ;;
    esac
}

compile_expected_negative() {
    local tree="$1" profile="$2" variant="$3" trace="$4"
    local compiler include_root source header
    local -a profile_args=() args=()
    case "$tree" in
        candidate) compiler="$CANDIDATE_CC"; include_root="$PROJECT_INCLUDE" ;;
        reference) compiler="$ORACLE_CC"; include_root="$MUSL_ROOT/include" ;;
        *) fail "unknown tree: $tree" ;;
    esac
    mapfile -t profile_args < <(profile_arguments "$profile")
    header="$(negative_variant_header "$variant")"
    args=(-nostdinc -I "$include_root" -isystem "$candidate_builtin" -H -fsyntax-only
        "$(negative_variant_define "$variant")")
    case "$profile" in
        c11-*) source="$C_NEGATIVE"; args=(-x c -std=c11 "${profile_args[@]}" "${args[@]}" "$source") ;;
        cxx17-*) source="$CXX_NEGATIVE"; args=(-x c++ -std=c++17 -nostdinc++ "${profile_args[@]}" "${args[@]}" "$source") ;;
        *) fail "unknown profile: $profile" ;;
    esac
    if run_compiler "$compiler" "${args[@]}" >/dev/null 2>"$trace"; then
        fail "$tree $profile direct <$header> unexpectedly acquired $variant"
    fi
    check_trace_roots "$tree" "$trace"
    require_trace_header "$trace" "$include_root" "$header"
    case "$variant" in
        stropts-winsize|sys-stropts-winsize)
            forbid_trace_header "$trace" "$include_root" 'sys/ioctl.h'
            ;;
        ttydefaults-tcgetattr)
            forbid_trace_header "$trace" "$include_root" 'termios.h'
            ;;
    esac
}

[ "$#" -eq 0 ] || fail "usage: $0"
[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "refuses emulation on $(uname -m)" ;; esac
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -x "$CANDIDATE_CC" ] || fail "missing raw native candidate compiler"
[ -d "$MUSL_ROOT/include" ] || fail "missing pinned musl include tree"
[ -d "$PROJECT_INCLUDE" ] || fail "missing project include tree"
for input in "$C_PROBE" "$CXX_PROBE" "$C_NEGATIVE" "$CXX_NEGATIVE"; do
    [ -f "$input" ] || fail "missing probe $input"
done

candidate_builtin="$(run_compiler "$CANDIDATE_CC" -print-file-name=include)"
candidate_builtin="$(realpath "$candidate_builtin")"
[ -d "$candidate_builtin" ] || fail "raw candidate compiler builtin include root is missing"
[ "$candidate_builtin" != "$MUSL_ROOT/include" ] || fail "candidate builtin root aliases musl"

work_dir="$(mktemp -d /tmp/crabc-x86-64-terminal-streams-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT

for profile in "${PROFILES[@]}"; do
    for variant in "${VARIANTS[@]}"; do
        for tree in reference candidate; do
            compile_positive "$tree" "$profile" "$variant" \
                "$work_dir/$tree-$profile-$variant.trace"
        done
    done
    for variant in "${NEGATIVE_VARIANTS[@]}"; do
        for tree in reference candidate; do
            compile_expected_negative "$tree" "$profile" "$variant" \
                "$work_dir/$tree-$profile-$variant-negative.trace"
        done
    done
done

printf 'x86 pinned-musl/project terminal/STREAMS direct-header topology: PASS (%s profiles; %s direct variants; C/C++)\n' \
    "${#PROFILES[@]}" "${#VARIANTS[@]}"
