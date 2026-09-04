#!/usr/bin/env bash
# Native Linux/x86-64 direct-header topology matrix for the fcntl/event
# cluster. Pinned musl 1.2.6 is the source-form and include-closure oracle;
# the project pass is isolated from any ambient libc. This is header evidence
# only: it does not select file, semaphore, readiness, signal, or timer
# providers.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly MUSL_ROOT=/opt/musl-1.2.6
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly CANDIDATE_CC=/usr/bin/gcc
readonly PROJECT_INCLUDE="$ROOT_DIR/include"
readonly C_PROBE="$ROOT_DIR/compat/x86_64/fcntl_event_header_topology_probe.c"
readonly CXX_PROBE="$ROOT_DIR/compat/x86_64/fcntl_event_header_topology_probe.cpp"
readonly -a PROFILES=(c11-gnu cxx17-gnu c11-strict c11-posix-2008 c11-xopen-700 c11-bsd cxx17-strict)
readonly -a VARIANTS=(fcntl sys-fcntl semaphore epoll eventfd inotify signalfd timerfd)

fail() {
    printf 'ERROR: x86 fcntl/event header topology: %s\n' "$*" >&2
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
        c11-strict) ;;
        cxx17-strict) printf '%s\n' '-U_GNU_SOURCE' ;;
        c11-posix-2008) printf '%s\n' '-D_POSIX_C_SOURCE=200809L' ;;
        c11-xopen-700) printf '%s\n' '-D_XOPEN_SOURCE=700' ;;
        c11-bsd) printf '%s\n' '-D_BSD_SOURCE' ;;
        *) fail "unknown profile: $1" ;;
    esac
}

variant_define() {
    case "$1" in
        fcntl) printf '%s\n' '-DCRABC_FCNTL_EVENT_FCNTL' ;;
        sys-fcntl) printf '%s\n' '-DCRABC_FCNTL_EVENT_SYS_FCNTL' ;;
        semaphore) printf '%s\n' '-DCRABC_FCNTL_EVENT_SEMAPHORE' ;;
        epoll) printf '%s\n' '-DCRABC_FCNTL_EVENT_EPOLL' ;;
        eventfd) printf '%s\n' '-DCRABC_FCNTL_EVENT_EVENTFD' ;;
        inotify) printf '%s\n' '-DCRABC_FCNTL_EVENT_INOTIFY' ;;
        signalfd) printf '%s\n' '-DCRABC_FCNTL_EVENT_SIGNALFD' ;;
        timerfd) printf '%s\n' '-DCRABC_FCNTL_EVENT_TIMERFD' ;;
        *) fail "unknown header variant: $1" ;;
    esac
}

variant_header() {
    case "$1" in
        fcntl) printf '%s\n' 'fcntl.h' ;;
        sys-fcntl) printf '%s\n' 'sys/fcntl.h' ;;
        semaphore) printf '%s\n' 'semaphore.h' ;;
        epoll) printf '%s\n' 'sys/epoll.h' ;;
        eventfd) printf '%s\n' 'sys/eventfd.h' ;;
        inotify) printf '%s\n' 'sys/inotify.h' ;;
        signalfd) printf '%s\n' 'sys/signalfd.h' ;;
        timerfd) printf '%s\n' 'sys/timerfd.h' ;;
        *) fail "unknown header variant: $1" ;;
    esac
}

variant_symbol() {
    case "$1" in
        fcntl|sys-fcntl) printf '%s\n' creat ;;
        semaphore) printf '%s\n' sem_getvalue ;;
        epoll) printf '%s\n' epoll_pwait ;;
        eventfd) printf '%s\n' eventfd ;;
        inotify) printf '%s\n' inotify_add_watch ;;
        signalfd) printf '%s\n' signalfd ;;
        timerfd) printf '%s\n' timerfd_settime ;;
        *) fail "unknown header variant: $1" ;;
    esac
}

trace_paths() {
    sed -n -E 's/^[. ]+ (\/[^[:space:]]+).*$/\1/p' "$1"
}

require_trace_header() {
    local trace="$1" root="$2" header="$3"
    grep -Fq "$root/$header" "$trace" ||
        fail "direct <$header> include did not resolve through $root"
}

forbid_trace_header() {
    local trace="$1" root="$2" header="$3"
    if grep -Fq "$root/$header" "$trace"; then
        fail "direct include unexpectedly acquired <$header>"
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

check_variant_trace() {
    local tree="$1" variant="$2" trace="$3" root
    case "$tree" in
        candidate) root="$PROJECT_INCLUDE" ;;
        reference) root="$MUSL_ROOT/include" ;;
        *) fail "unknown tree: $tree" ;;
    esac
    require_trace_header "$trace" "$root" "$(variant_header "$variant")"

    case "$variant" in
        fcntl)
            for header in features.h bits/alltypes.h bits/fcntl.h; do
                require_trace_header "$trace" "$root" "$header"
            done
            forbid_trace_header "$trace" "$root" sys/types.h
            ;;
        sys-fcntl)
            require_trace_header "$trace" "$root" fcntl.h
            require_trace_header "$trace" "$root" bits/fcntl.h
            grep -Fq 'redirecting incorrect #include <sys/fcntl.h> to <fcntl.h>' "$trace" ||
                fail "$tree <sys/fcntl.h> did not retain musl's redirect warning"
            ;;
        semaphore)
            for header in features.h bits/alltypes.h fcntl.h bits/fcntl.h; do
                require_trace_header "$trace" "$root" "$header"
            done
            ;;
        epoll)
            for header in stdint.h sys/types.h sys/ioctl.h fcntl.h bits/alltypes.h bits/fcntl.h; do
                require_trace_header "$trace" "$root" "$header"
            done
            ;;
        eventfd|inotify)
            for header in stdint.h fcntl.h bits/fcntl.h; do
                require_trace_header "$trace" "$root" "$header"
            done
            ;;
        signalfd)
            for header in stdint.h fcntl.h bits/alltypes.h bits/fcntl.h; do
                require_trace_header "$trace" "$root" "$header"
            done
            forbid_trace_header "$trace" "$root" signal.h
            ;;
        timerfd)
            for header in time.h fcntl.h bits/fcntl.h; do
                require_trace_header "$trace" "$root" "$header"
            done
            ;;
        *) fail "unknown header variant: $variant" ;;
    esac
}

compile_variant() {
    local tree="$1" profile="$2" variant="$3" trace="$4" object="$5"
    local compiler include_root source
    local -a profile_args=() args=()
    case "$tree" in
        candidate) compiler="$CANDIDATE_CC"; include_root="$PROJECT_INCLUDE" ;;
        reference) compiler="$ORACLE_CC"; include_root="$MUSL_ROOT/include" ;;
        *) fail "unknown tree: $tree" ;;
    esac
    mapfile -t profile_args < <(profile_arguments "$profile")
    args=(-nostdinc -I "$include_root" -isystem "$candidate_builtin" -H -fno-builtin
        "$(variant_define "$variant")")
    case "$profile" in
        c11-*)
            source="$C_PROBE"
            args=(-x c -std=c11 "${profile_args[@]}" "${args[@]}" -fsyntax-only "$source")
            ;;
        cxx17-*)
            source="$CXX_PROBE"
            args=(-x c++ -std=c++17 -nostdinc++ "${profile_args[@]}" "${args[@]}" -c -o "$object" "$source")
            ;;
        *) fail "unknown profile: $profile" ;;
    esac
    if ! run_compiler "$compiler" "${args[@]}" >/dev/null 2>"$trace"; then
        fail "$tree $profile direct <$(variant_header "$variant")> failed: $(sed -n '/error:/p' "$trace" | sed -n '1p')"
    fi
    check_trace_roots "$tree" "$trace"
    check_variant_trace "$tree" "$variant" "$trace"
}

check_cxx_symbol() {
    local tree="$1" profile="$2" variant="$3" object="$4"
    local symbol undefined
    symbol="$(variant_symbol "$variant")"
    undefined="$(nm --undefined-only "$object")"
    printf '%s\n' "$undefined" | grep -Eq "[[:space:]]${symbol}$" ||
        fail "$tree $profile <$variant> C++ probe does not retain C linkage for $symbol"
    if printf '%s\n' "$undefined" | grep -Eq "_Z.*${symbol}"; then
        fail "$tree $profile <$variant> C++ probe retained a mangled $symbol reference"
    fi
}

[ "$#" -eq 0 ] || fail "usage: $0"
[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "refuses emulation on $(uname -m)" ;; esac
for tool in grep mapfile mktemp nm realpath sed uname; do
    command -v "$tool" >/dev/null 2>&1 || fail "requires $tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -x "$CANDIDATE_CC" ] || fail "missing raw native candidate compiler"
[ -d "$MUSL_ROOT/include" ] || fail "missing pinned musl include tree"
[ -d "$PROJECT_INCLUDE" ] || fail "missing project include tree"
for input in "$C_PROBE" "$CXX_PROBE"; do
    [ -f "$input" ] || fail "missing probe $input"
done

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
candidate_builtin="$(run_compiler "$CANDIDATE_CC" -print-file-name=include)"
candidate_builtin="$(realpath "$candidate_builtin")"
[ -d "$candidate_builtin" ] || fail "raw candidate compiler builtin include root is missing"
[ "$candidate_builtin" != "$MUSL_ROOT/include" ] || fail "candidate builtin root aliases musl"

work_dir="$(mktemp -d /tmp/crabc-x86-64-fcntl-event-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT

for profile in "${PROFILES[@]}"; do
    for variant in "${VARIANTS[@]}"; do
        for tree in reference candidate; do
            object="$work_dir/$tree-$profile-$variant.o"
            trace="$work_dir/$tree-$profile-$variant.trace"
            compile_variant "$tree" "$profile" "$variant" "$trace" "$object"
            case "$profile" in
                cxx17-*) check_cxx_symbol "$tree" "$profile" "$variant" "$object" ;;
            esac
        done
    done
done

printf 'x86 pinned-musl/project fcntl/event direct-header topology: PASS (%s profiles; %s direct headers; C/C++)\n' \
    "${#PROFILES[@]}" "${#VARIANTS[@]}"
