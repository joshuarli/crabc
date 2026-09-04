#!/usr/bin/env bash
# Native Linux/x86-64 direct <pthread.h> source-form closure.
#
# Pinned musl 1.2.6 owns the direct pthread declarations, macro replacements,
# and dependency topology. Both arms see only their declared header root and
# raw compiler builtins: an ambient libc cannot supply signal declarations or
# conceal an extra dependency. This is compile-only header evidence; it does
# not select a pthread/TLS provider, runtime behavior, family completion, or
# public x86 support.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly MUSL_ROOT=/opt/musl-1.2.6
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly CANDIDATE_CC=/usr/bin/gcc
readonly PROJECT_INCLUDE="$ROOT_DIR/include"
readonly C_PROBE="$ROOT_DIR/compat/x86_64/pthread_header_source_form_probe.c"
readonly CXX_PROBE="$ROOT_DIR/compat/x86_64/pthread_header_source_form_probe.cpp"
readonly EXPECTED_PROFILE_COUNT=7
readonly -a PROFILES=(c11-gnu cxx17-gnu c11-strict c11-posix-2008 c11-xopen-700 c11-bsd cxx17-strict)

fail() {
    printf 'ERROR: x86 pthread.h source form: %s\n' "$*" >&2
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

profile_is_cxx() {
    case "$1" in cxx17-*) return 0 ;; *) return 1 ;; esac
}

profile_has_signal_owner() {
    case "$1" in
        c11-gnu|cxx17-gnu|c11-posix-2008|c11-xopen-700|c11-bsd) return 0 ;;
        *) return 1 ;;
    esac
}

profile_arguments() {
    printf '%s\n' \
        -U_GNU_SOURCE -U_BSD_SOURCE -U_XOPEN_SOURCE -U_POSIX_SOURCE \
        -U_POSIX_C_SOURCE -U_DEFAULT_SOURCE -U_ALL_SOURCE -U_LARGEFILE64_SOURCE
    case "$1" in
        c11-gnu|cxx17-gnu) printf '%s\n' '-D_GNU_SOURCE' ;;
        c11-strict|cxx17-strict) : ;;
        c11-posix-2008) printf '%s\n' '-D_POSIX_C_SOURCE=200809L' ;;
        c11-xopen-700) printf '%s\n' '-D_XOPEN_SOURCE=700' ;;
        c11-bsd) printf '%s\n' '-D_BSD_SOURCE' ;;
        *) fail "unknown feature profile: $1" ;;
    esac
}

trace_paths() {
    sed -n -E 's/^[. ]+ (\/[^[:space:]]+).*$/\1/p' "$1"
}

set_tree() {
    case "$1" in
        candidate)
            compiler="$CANDIDATE_CC"
            include_root="$PROJECT_INCLUDE"
            ;;
        reference)
            compiler="$ORACLE_CC"
            include_root="$MUSL_ROOT/include"
            ;;
        *) fail "unknown header tree: $1" ;;
    esac
    include_args=(-nostdinc -I "$include_root" -isystem "$compiler_builtin")
}

set_profile() {
    local profile="$1"

    mapfile -t profile_args < <(profile_arguments "$profile")
    if profile_is_cxx "$profile"; then
        source="$CXX_PROBE"
        language_args=(-x c++ -std=c++17 -nostdinc++)
    else
        source="$C_PROBE"
        language_args=(-x c -std=c11)
    fi
}

first_diagnostic() {
    local diagnostic="$1" line
    line="$(sed -n '/fatal error:/p; /error:/p' "$diagnostic" | sed -n '1p' || true)"
    if [ -n "$line" ]; then
        printf '%s\n' "$line" | tr '\t\r\n' ' '
    else
        printf '%s\n' 'no compiler diagnostic'
    fi
}

compile_probe() {
    local tree="$1" profile="$2" mode="$3" trace="$4" object="$5"
    shift 5
    local -a extra_args=("$@")

    set_tree "$tree"
    set_profile "$profile"
    case "$mode" in
        syntax)
            run_compiler "$compiler" "${language_args[@]}" "${include_args[@]}" \
                "${profile_args[@]}" "${extra_args[@]}" -H -fsyntax-only "$source" \
                >/dev/null 2>"$trace"
            ;;
        object)
            run_compiler "$compiler" "${language_args[@]}" "${include_args[@]}" \
                "${profile_args[@]}" "${extra_args[@]}" -H -c "$source" -o "$object" \
                >/dev/null 2>"$trace"
            ;;
        *) fail "unknown probe mode: $mode" ;;
    esac
}

preprocess_header() {
    local tree="$1" profile="$2" header="$3" declarations="$4" macros="$5"

    set_tree "$tree"
    set_profile "$profile"
    printf '#include <%s>\n' "$header" | run_compiler "$compiler" \
        "${language_args[@]}" "${include_args[@]}" "${profile_args[@]}" -E -P - \
        >"$declarations" || fail "$tree/$profile preprocessing <$header> declarations failed"
    printf '#include <%s>\n' "$header" | run_compiler "$compiler" \
        "${language_args[@]}" "${include_args[@]}" "${profile_args[@]}" -dM -E - \
        >"$macros" || fail "$tree/$profile preprocessing <$header> macros failed"
}

check_trace_roots() {
    local tree="$1" trace="$2" path
    while IFS= read -r path; do
        case "$tree" in
            candidate)
                case "$path" in
                    "$PROJECT_INCLUDE"/*|"$compiler_builtin"/*) ;;
                    *) fail "candidate trace escaped project/builtin roots: $path" ;;
                esac
                ;;
            reference)
                case "$path" in
                    "$MUSL_ROOT/include"/*|"$compiler_builtin"/*) ;;
                    *) fail "reference trace escaped musl/builtin roots: $path" ;;
                esac
                ;;
            *) fail "unknown header tree: $tree" ;;
        esac
    done < <(trace_paths "$trace")
}

check_pthread_topology() {
    local tree="$1" profile="$2" trace="$3" root header
    case "$tree" in
        candidate) root="$PROJECT_INCLUDE" ;;
        reference) root="$MUSL_ROOT/include" ;;
        *) fail "unknown header tree: $tree" ;;
    esac
    check_trace_roots "$tree" "$trace"
    for header in pthread.h features.h bits/alltypes.h sched.h time.h; do
        grep -Fq "$root/$header" "$trace" ||
            fail "$tree/$profile direct <pthread.h> topology omitted $header"
    done
    for header in signal.h bits/signal.h sys/types.h; do
        if grep -Fq "$root/$header" "$trace"; then
            fail "$tree/$profile direct <pthread.h> unexpectedly acquired $header"
        fi
    done
}

extract_pthread_declarations() {
    local input="$1" output="$2"
    grep -E '^(_Noreturn )?void pthread_[[:alnum:]_]*\(|^void \*pthread_[[:alnum:]_]*\(|^pthread_t pthread_[[:alnum:]_]*\(|^int pthread_[[:alnum:]_]*\(|^void _pthread_cleanup_(push|pop)\(' \
        "$input" >"$output" || true
    [ -s "$output" ] || fail "direct <pthread.h> preprocessing lost pthread declarations"
}

extract_pthread_macros() {
    local input="$1" output="$2"
    grep -E '^#define (PTHREAD_[[:alnum:]_]+|pthread_equal\(|pthread_cleanup_push\(|pthread_cleanup_pop\()' \
        "$input" >"$output" || true
    [ -s "$output" ] || fail "direct <pthread.h> preprocessing lost pthread macros"
}

extract_signal_owner_declarations() {
    local input="$1" output="$2"
    grep -E '^int pthread_(sigmask|kill)\(' "$input" >"$output" || true
}

check_selected_declaration_forms() {
    local declarations="$1" form
    for form in \
        '_Noreturn void pthread_exit(void *);' \
        'int pthread_getschedparam(pthread_t, int *restrict, struct sched_param *restrict);' \
        'int pthread_mutex_getprioceiling(const pthread_mutex_t *restrict, int *restrict);' \
        'int pthread_mutex_setprioceiling(pthread_mutex_t *restrict, int, int *restrict);' \
        'int pthread_attr_getstack(const pthread_attr_t *restrict, void **restrict, size_t *restrict);' \
        'int pthread_attr_setschedparam(pthread_attr_t *restrict, const struct sched_param *restrict);' \
        'int pthread_attr_getschedparam(const pthread_attr_t *restrict, struct sched_param *restrict);'; do
        grep -Fxq "$form" "$declarations" ||
            fail "missing exact pinned-musl pthread declaration form: $form"
    done
}

check_pthread_macro_forms() {
    local profile="$1" macros="$2" form
    for form in \
        '#define PTHREAD_CREATE_JOINABLE 0' \
        '#define PTHREAD_CREATE_DETACHED 1' \
        '#define PTHREAD_MUTEX_STALLED 0' \
        '#define PTHREAD_MUTEX_ROBUST 1' \
        '#define PTHREAD_CANCEL_MASKED 2' \
        '#define PTHREAD_CANCELED ((void *)-1)' \
        '#define PTHREAD_BARRIER_SERIAL_THREAD (-1)' \
        '#define PTHREAD_MUTEX_INITIALIZER {{{0}}}' \
        '#define PTHREAD_RWLOCK_INITIALIZER {{{0}}}' \
        '#define PTHREAD_COND_INITIALIZER {{{0}}}' \
        '#define PTHREAD_ONCE_INIT 0'; do
        grep -Fxq "$form" "$macros" ||
            fail "$profile omitted exact pinned-musl pthread macro form: $form"
    done
    if profile_is_cxx "$profile"; then
        if grep -Eq '^#define pthread_equal\(' "$macros"; then
            fail "$profile C++ <pthread.h> unexpectedly defined pthread_equal as a macro"
        fi
    else
        grep -Fxq '#define pthread_equal(x,y) ((x)==(y))' "$macros" ||
            fail "$profile C <pthread.h> omitted pthread_equal macro"
    fi
}

check_no_direct_signal_visibility() {
    local profile="$1" declarations="$2" macros="$3"
    if grep -Eq '^int pthread_(sigmask|kill)\(' "$declarations"; then
        fail "$profile direct <pthread.h> leaked a signal-owned pthread declaration"
    fi
    for macro in SIG_BLOCK SIG_UNBLOCK SIG_SETMASK; do
        if grep -Eq "^#define ${macro}([[:space:](]|$)" "$macros"; then
            fail "$profile direct <pthread.h> leaked signal macro $macro"
        fi
    done
}

check_cxx_linkage() {
    local profile="$1" object="$2" undefined symbol
    local -a symbols=(
        pthread_exit pthread_getschedparam
        pthread_mutex_getprioceiling pthread_mutex_setprioceiling
        pthread_mutexattr_gettype pthread_condattr_getclock
        pthread_condattr_getpshared pthread_rwlockattr_getpshared
        pthread_barrierattr_getpshared pthread_attr_getguardsize
        pthread_attr_getstack pthread_attr_getscope
        pthread_attr_setschedparam pthread_attr_getschedparam
    )
    if [ "$profile" = cxx17-gnu ]; then
        symbols+=(pthread_getname_np)
    fi
    undefined="$(nm --undefined-only "$object")"
    for symbol in "${symbols[@]}"; do
        printf '%s\n' "$undefined" | grep -Eq "[[:space:]]${symbol}$" ||
            fail "$profile C++ probe lost unmangled $symbol linkage"
    done
    if printf '%s\n' "$undefined" | grep -Eq '_Z.*(pthread_exit|pthread_getschedparam|pthread_mutex_getprioceiling|pthread_mutex_setprioceiling|pthread_mutexattr_gettype|pthread_condattr_getclock|pthread_condattr_getpshared|pthread_rwlockattr_getpshared|pthread_barrierattr_getpshared|pthread_attr_getguardsize|pthread_attr_getstack|pthread_attr_getscope|pthread_attr_setschedparam|pthread_attr_getschedparam|pthread_getname_np)'; then
        fail "$profile C++ probe retained a mangled pthread declaration"
    fi
}

check_cxx_signal_owner_linkage() {
    local profile="$1" object="$2" undefined
    undefined="$(nm --undefined-only "$object")"
    for symbol in pthread_sigmask pthread_kill; do
        printf '%s\n' "$undefined" | grep -Eq "[[:space:]]${symbol}$" ||
            fail "$profile C++ signal-owner witness lost unmangled $symbol linkage"
    done
    if printf '%s\n' "$undefined" | grep -Eq '_Z.*(pthread_sigmask|pthread_kill)'; then
        fail "$profile C++ signal-owner witness retained mangled signal linkage"
    fi
}

assert_direct_signal_witness_hidden() {
    local tree="$1" profile="$2" trace="$3"
    if compile_probe "$tree" "$profile" syntax "$trace" /dev/null \
        -DCRABC_PTHREAD_HEADER_SOURCE_FORM_SIGNAL_WITNESS; then
        fail "$tree/$profile direct <pthread.h> unexpectedly exposed signal-owned pthread declarations"
    fi
}

assert_signal_owner_witness() {
    local tree="$1" profile="$2" trace="$3" object="$4"
    local mode=syntax
    if profile_is_cxx "$profile"; then
        mode=object
    fi
    if profile_has_signal_owner "$profile"; then
        compile_probe "$tree" "$profile" "$mode" "$trace" "$object" \
            -DCRABC_PTHREAD_HEADER_SOURCE_FORM_SIGNAL_OWNER \
            -DCRABC_PTHREAD_HEADER_SOURCE_FORM_SIGNAL_WITNESS ||
            fail "$tree/$profile direct <signal.h> did not expose its pthread declarations: $(first_diagnostic "$trace")"
        if profile_is_cxx "$profile"; then
            check_cxx_signal_owner_linkage "$profile" "$object"
        fi
    elif compile_probe "$tree" "$profile" syntax "$trace" /dev/null \
        -DCRABC_PTHREAD_HEADER_SOURCE_FORM_SIGNAL_OWNER \
        -DCRABC_PTHREAD_HEADER_SOURCE_FORM_SIGNAL_WITNESS; then
        fail "$tree/$profile direct <signal.h> unexpectedly exposed signal-owned pthread declarations"
    fi
}

# The selected source form is x86-only, but its explicit selector must not
# silently invalidate the frozen AArch64 public branch. This is a header-only
# syntax proof: force the non-x86 architecture macros while retaining the raw
# candidate include root; it deliberately does not claim an AArch64 codegen
# or runtime transaction from the native x86 runner.
check_frozen_aarch64_branch_syntax() {
    printf '%s\n' '#include <pthread.h>' 'int main(void) { return 0; }' |
        run_compiler "$CANDIDATE_CC" -x c -std=c11 -nostdinc \
            -I "$PROJECT_INCLUDE" -isystem "$compiler_builtin" \
            -U__x86_64__ -D__aarch64__ -fsyntax-only - ||
        fail "frozen AArch64 pthread.h C syntax failed"
    printf '%s\n' '#include <pthread.h>' 'int main() { return 0; }' |
        run_compiler "$CANDIDATE_CC" -x c++ -std=c++17 -nostdinc -nostdinc++ \
            -I "$PROJECT_INCLUDE" -isystem "$compiler_builtin" \
            -U__x86_64__ -D__aarch64__ -fsyntax-only - ||
        fail "frozen AArch64 pthread.h C++ syntax failed"
}

[ "$#" -eq 0 ] || fail "usage: $0"
require_native_linux_x86_64
for tool in cmp diff env grep mapfile mktemp nm realpath sed tr uname wc; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -x "$CANDIDATE_CC" ] || fail "missing raw native candidate compiler"
[ -d "$MUSL_ROOT/include" ] || fail "missing pinned musl include tree"
[ -d "$PROJECT_INCLUDE" ] || fail "missing project include tree"
[ -f "$C_PROBE" ] && [ -f "$CXX_PROBE" ] || fail "missing pthread source-form probes"
[ "${#PROFILES[@]}" -eq "$EXPECTED_PROFILE_COUNT" ] || fail "profile roster drifted"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

compiler_builtin="$(run_compiler "$CANDIDATE_CC" -print-file-name=include)"
compiler_builtin="$(realpath "$compiler_builtin")"
[ -d "$compiler_builtin" ] || fail "raw compiler builtin include root is missing"

check_frozen_aarch64_branch_syntax

work_dir="$(mktemp -d /tmp/crabc-x86-64-pthread-header-source-form.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT

for profile in "${PROFILES[@]}"; do
    for tree in reference candidate; do
        trace="$work_dir/$tree-$profile.trace"
        object="$work_dir/$tree-$profile.o"
        mode=syntax
        if profile_is_cxx "$profile"; then
            mode=object
        fi
        compile_probe "$tree" "$profile" "$mode" "$trace" "$object" ||
            fail "$tree/$profile direct <pthread.h> syntax failed: $(first_diagnostic "$trace")"
        check_pthread_topology "$tree" "$profile" "$trace"
        if profile_is_cxx "$profile"; then
            check_cxx_linkage "$profile" "$object"
        fi

        declarations="$work_dir/$tree-$profile.pthread.declarations"
        macros="$work_dir/$tree-$profile.pthread.macros"
        preprocess_header "$tree" "$profile" pthread.h "$declarations" "$macros"
        extract_pthread_declarations "$declarations" "$work_dir/$tree-$profile.pthread.forms"
        extract_pthread_macros "$macros" "$work_dir/$tree-$profile.pthread-macros"
        check_pthread_macro_forms "$profile" "$macros"
        check_no_direct_signal_visibility "$profile" "$declarations" "$macros"
        if ! profile_is_cxx "$profile"; then
            check_selected_declaration_forms "$declarations"
        fi

        signal_declarations="$work_dir/$tree-$profile.signal.declarations"
        signal_macros="$work_dir/$tree-$profile.signal.macros"
        preprocess_header "$tree" "$profile" signal.h "$signal_declarations" "$signal_macros"
        extract_signal_owner_declarations "$signal_declarations" \
            "$work_dir/$tree-$profile.signal-owner.forms"
        if profile_has_signal_owner "$profile"; then
            [ "$(wc -l < "$work_dir/$tree-$profile.signal-owner.forms")" -eq 2 ] ||
                fail "$tree/$profile direct <signal.h> must own exactly pthread_sigmask and pthread_kill"
        elif [ -s "$work_dir/$tree-$profile.signal-owner.forms" ]; then
            fail "$tree/$profile strict direct <signal.h> unexpectedly exposed pthread signal declarations"
        fi

        assert_direct_signal_witness_hidden "$tree" "$profile" \
            "$work_dir/$tree-$profile.direct-signal-witness.trace"
        assert_signal_owner_witness "$tree" "$profile" \
            "$work_dir/$tree-$profile.signal-owner-witness.trace" \
            "$work_dir/$tree-$profile.signal-owner-witness.o"
    done

    diff -u "$work_dir/reference-$profile.pthread.forms" \
        "$work_dir/candidate-$profile.pthread.forms" >"$work_dir/$profile.pthread.forms.diff" ||
        fail "$profile pthread declaration source forms differ from pinned musl"
    diff -u "$work_dir/reference-$profile.pthread-macros" \
        "$work_dir/candidate-$profile.pthread-macros" >"$work_dir/$profile.pthread.macros.diff" ||
        fail "$profile pthread macro replacement forms differ from pinned musl"
    diff -u "$work_dir/reference-$profile.signal-owner.forms" \
        "$work_dir/candidate-$profile.signal-owner.forms" >"$work_dir/$profile.signal-owner.forms.diff" ||
        fail "$profile signal-owned pthread declarations differ from pinned musl"
done

printf '%s\n' 'x86 pinned-musl/project C/C++ <pthread.h> source form: PASS (7 profiles; compile-only)'
