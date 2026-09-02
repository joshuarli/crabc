#!/usr/bin/env bash
# Native Linux/x86-64 pthread/C11-thread header ABI matrix.
#
# This runner compares pinned musl 1.2.6 and project-header-first C11/C++17
# compilation across selected feature profiles.  It is intentionally
# compile-only: no crabc archive, runtime, CRT, loader, or pthread behavior is
# selected.  C++ object inspection additionally requires pthread declarations
# to retain C linkage rather than being silently mangled as C++ functions.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly MUSL_ROOT=/opt/musl-1.2.6
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly CANDIDATE_CC=/usr/bin/gcc
readonly PROJECT_INCLUDE="$ROOT_DIR/include"
readonly LINUX_UAPI_INCLUDE=/opt/linux-5.10-uapi/include
readonly C_PROBE="$ROOT_DIR/compat/x86_64/pthread_c11_header_abi_probe.c"
readonly CXX_PROBE="$ROOT_DIR/compat/x86_64/pthread_c11_header_abi_probe.cpp"

fail() {
    printf 'ERROR: x86 pthread/C11 header ABI: %s\n' "$*" >&2
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
    env -u CPATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH -u LIBRARY_PATH \
        -u GCC_EXEC_PREFIX -u GCC_SPECS -u COMPILER_PATH \
        "$@"
}

profile_arguments() {
    case "$1" in
        c11-gnu)
            printf '%s\0' -x c -std=c11 -D_GNU_SOURCE \
                -DCRABC_EXPECT_POSIX_SIGNAL_DECLARATIONS=1 \
                -DCRABC_EXPECT_GNU_PTHREAD_EXTENSIONS=1
            ;;
        c11-strict)
            printf '%s\0' -x c -std=c11
            ;;
        c11-posix-2008)
            printf '%s\0' -x c -std=c11 -D_POSIX_C_SOURCE=200809L \
                -DCRABC_EXPECT_POSIX_SIGNAL_DECLARATIONS=1
            ;;
        c11-xopen-700)
            printf '%s\0' -x c -std=c11 -D_XOPEN_SOURCE=700 \
                -DCRABC_EXPECT_POSIX_SIGNAL_DECLARATIONS=1
            ;;
        c11-bsd)
            printf '%s\0' -x c -std=c11 -D_BSD_SOURCE \
                -DCRABC_EXPECT_POSIX_SIGNAL_DECLARATIONS=1
            ;;
        cxx17-gnu)
            printf '%s\0' -x c++ -std=c++17 -nostdinc++ -D_GNU_SOURCE \
                -DCRABC_EXPECT_POSIX_SIGNAL_DECLARATIONS=1 \
                -DCRABC_EXPECT_GNU_PTHREAD_EXTENSIONS=1
            ;;
        cxx17-strict)
            printf '%s\0' -x c++ -std=c++17 -nostdinc++
            ;;
        *) fail "unknown profile: $1" ;;
    esac
}

assert_header_provenance() {
    local tree="$1"
    local trace="$2"
    local root="$3"
    local label="$4"
    local header
    local path

    while IFS= read -r path; do
        case "$tree" in
            reference)
                case "$path" in
                    "$MUSL_ROOT/include"/*|"$candidate_compiler_builtin_include"/*|"$LINUX_UAPI_INCLUDE"/*) ;;
                    *) fail "$label trace escaped its declared reference header roots" ;;
                esac
                ;;
            candidate)
                case "$path" in
                    "$PROJECT_INCLUDE"/*|"$candidate_compiler_builtin_include"/*|"$LINUX_UAPI_INCLUDE"/*) ;;
                    *) fail "$label trace escaped its declared candidate header roots" ;;
                esac
                ;;
            *) fail "unknown header tree: $tree" ;;
        esac
    done < <(sed -n -E 's/^[. ]+ (\/[^[:space:]]+).*$/\1/p' "$trace")
    for header in pthread.h threads.h sched.h signal.h time.h bits/alltypes.h; do
        grep -Fq "$root/$header" "$trace" ||
            fail "$label did not preprocess $root/$header"
    done
}

assert_cxx_c_linkage() {
    local object="$1"
    local label="$2"
    local profile="$3"
    local symbols
    local symbol
    local -a required_symbols=(
        pthread_create
        pthread_attr_init pthread_attr_destroy
        pthread_attr_setdetachstate pthread_attr_getdetachstate
        pthread_attr_setstacksize pthread_attr_getstacksize
        pthread_attr_setstack pthread_attr_getstack
        pthread_attr_setguardsize pthread_attr_getguardsize
        pthread_attr_setscope pthread_attr_getscope
        pthread_attr_setinheritsched pthread_attr_getinheritsched
        pthread_attr_setschedpolicy pthread_attr_getschedpolicy
        pthread_attr_setschedparam pthread_attr_getschedparam
        pthread_detach pthread_self pthread_equal pthread_getconcurrency pthread_getcpuclockid pthread_setconcurrency
        pthread_key_create pthread_key_delete pthread_getspecific pthread_setspecific
        pthread_mutex_init pthread_mutex_destroy pthread_mutex_lock
        pthread_mutex_trylock pthread_mutex_unlock
        pthread_mutex_getprioceiling
        pthread_mutexattr_gettype pthread_mutexattr_settype pthread_mutexattr_getprotocol pthread_mutexattr_getpshared pthread_mutexattr_getrobust
        pthread_cond_init pthread_cond_destroy pthread_cond_wait
        pthread_cond_signal pthread_cond_broadcast
        pthread_rwlock_init pthread_rwlock_destroy pthread_rwlock_rdlock
        pthread_rwlock_tryrdlock pthread_rwlock_timedrdlock pthread_rwlock_wrlock
        pthread_rwlock_trywrlock pthread_rwlock_timedwrlock pthread_rwlock_unlock
        pthread_rwlockattr_init pthread_rwlockattr_destroy
        pthread_rwlockattr_setpshared pthread_rwlockattr_getpshared pthread_once
        pthread_barrierattr_setpshared pthread_barrierattr_getpshared
        pthread_barrierattr_init pthread_barrierattr_destroy pthread_barrier_init pthread_barrier_destroy pthread_barrier_wait
        thrd_create thrd_detach thrd_join thrd_exit thrd_sleep thrd_yield thrd_current thrd_equal
        call_once tss_create tss_delete tss_get tss_set
        mtx_init mtx_destroy mtx_lock mtx_trylock mtx_unlock
        cnd_init cnd_destroy cnd_wait cnd_signal cnd_broadcast
    )

    symbols="$(nm -u "$object" | awk '{print $NF}')"
    if [ "$profile" = cxx17-gnu ]; then
        required_symbols+=(pthread_sigmask pthread_setname_np pthread_getname_np)
    fi
    for symbol in "${required_symbols[@]}"; do
        printf '%s\n' "$symbols" | grep -Fxq "$symbol" ||
            fail "$label does not request C-linkage symbol $symbol"
    done
    if printf '%s\n' "$symbols" | grep -Eq '(^|.*)_Z.*(pthread_create|pthread_attr_init|pthread_attr_destroy|pthread_attr_setdetachstate|pthread_attr_getdetachstate|pthread_attr_setstacksize|pthread_attr_getstacksize|pthread_attr_setstack|pthread_attr_getstack|pthread_attr_setguardsize|pthread_attr_getguardsize|pthread_attr_setscope|pthread_attr_getscope|pthread_attr_setinheritsched|pthread_attr_getinheritsched|pthread_attr_setschedpolicy|pthread_attr_getschedpolicy|pthread_attr_setschedparam|pthread_attr_getschedparam|pthread_detach|pthread_self|pthread_equal|pthread_getcpuclockid|pthread_setname_np|pthread_getname_np|pthread_key_create|pthread_key_delete|pthread_getspecific|pthread_setspecific|pthread_mutex_init|pthread_mutex_destroy|pthread_mutex_lock|pthread_mutex_trylock|pthread_mutex_unlock|pthread_cond_init|pthread_cond_destroy|pthread_cond_wait|pthread_cond_signal|pthread_cond_broadcast|pthread_rwlock_init|pthread_rwlock_destroy|pthread_rwlock_rdlock|pthread_rwlock_tryrdlock|pthread_rwlock_timedrdlock|pthread_rwlock_wrlock|pthread_rwlock_trywrlock|pthread_rwlock_timedwrlock|pthread_rwlock_unlock|pthread_rwlockattr_init|pthread_rwlockattr_destroy|pthread_rwlockattr_setpshared|pthread_rwlockattr_getpshared|pthread_barrierattr_setpshared|pthread_barrierattr_getpshared|pthread_barrierattr_init|pthread_barrierattr_destroy|pthread_barrier_init|pthread_barrier_destroy|pthread_barrier_wait|pthread_once|pthread_sigmask|thrd_create|thrd_detach|thrd_join|thrd_exit|thrd_sleep|thrd_yield|thrd_current|thrd_equal|call_once|tss_create|tss_delete|tss_get|tss_set|mtx_init|mtx_destroy|mtx_lock|mtx_trylock|mtx_unlock|cnd_init|cnd_destroy|cnd_wait|cnd_signal|cnd_broadcast)'; then
        fail "$label requests a mangled C++ pthread/C11 symbol"
    fi
}

compile_one() {
    local tree="$1"
    local profile="$2"
    local include_order="$3"
    local work_dir="$4"
    local compiler
    local include_root
    local source
    local object
    local trace
    local label
    local -a profile_args
    local -a arguments

    mapfile -d '' -t profile_args < <(profile_arguments "$profile")
    case "$tree" in
        reference)
            compiler="$ORACLE_CC"
            include_root="$MUSL_ROOT/include"
            ;;
        candidate)
            compiler="$CANDIDATE_CC"
            include_root="$PROJECT_INCLUDE"
            ;;
        *) fail "unknown header tree: $tree" ;;
    esac

    case "$profile" in
        cxx*) source="$CXX_PROBE" ;;
        *) source="$C_PROBE" ;;
    esac

    label="$tree/$profile/$include_order"
    object="$work_dir/${tree}-${profile}-${include_order}.o"
    trace="$work_dir/${tree}-${profile}-${include_order}.trace"
    arguments=(
        "${profile_args[@]}"
        -nostdinc
        -I "$include_root"
        -isystem "$candidate_compiler_builtin_include"
        -isystem "$LINUX_UAPI_INCLUDE"
        -D"$include_order"
        -H
        -c "$source"
        -o "$object"
    )

    if ! run_compiler "$compiler" "${arguments[@]}" >/dev/null 2>"$trace"; then
        if [ "$tree" = reference ]; then
            sed -n '1,160p' "$trace" >&2
            fail "$label pinned-musl reference compilation failed"
        fi
        printf 'MISMATCH: %s\n' "$label" >&2
        sed -n '1,160p' "$trace" >&2
        failures=$((failures + 1))
        return
    fi

    assert_header_provenance "$tree" "$trace" "$include_root" "$label"
    if [[ "$profile" == cxx* ]]; then
        assert_cxx_c_linkage "$object" "$label" "$profile"
    fi
    printf 'PASS: %s\n' "$label"
}

[ "$#" -eq 0 ] || fail "usage: $0"
require_native_linux_x86_64
for tool in awk grep mktemp nm realpath sed uname; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -x "$CANDIDATE_CC" ] || fail "missing raw native candidate compiler"
[ -d "$MUSL_ROOT/include" ] || fail "missing pinned musl include tree"
[ -d "$PROJECT_INCLUDE" ] || fail "missing project include tree"
[ -d "$LINUX_UAPI_INCLUDE" ] || fail "missing pinned Linux 5.10 UAPI include tree"
[ -f "$C_PROBE" ] || fail "missing C probe"
[ -f "$CXX_PROBE" ] || fail "missing C++ probe"

# The reference compiler and Linux UAPI input are pinned independently before
# they become declaration/layout or transitive-header inputs to this matrix.
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_linux_5_10_uapi.sh" >/dev/null

candidate_compiler_builtin_include="$(run_compiler "$CANDIDATE_CC" -print-file-name=include)"
case "$candidate_compiler_builtin_include" in
    /*) ;;
    *) fail "raw candidate compiler did not report an absolute builtin include directory" ;;
esac
candidate_compiler_builtin_include="$(realpath "$candidate_compiler_builtin_include")"
[ -d "$candidate_compiler_builtin_include" ] ||
    fail "missing raw candidate compiler builtin include directory"
[ "$candidate_compiler_builtin_include" != "$MUSL_ROOT/include" ] ||
    fail "candidate compiler builtin include aliases pinned musl"

work_dir="$(mktemp -d /tmp/crabc-x86-64-pthread-c11-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
failures=0

for profile in \
    c11-gnu c11-strict c11-posix-2008 c11-xopen-700 c11-bsd \
    cxx17-gnu cxx17-strict; do
    for include_order in CRABC_PTHREAD_C11_PTHREAD_FIRST CRABC_PTHREAD_C11_SCHED_FIRST; do
        compile_one reference "$profile" "$include_order" "$work_dir"
    done
done

for profile in \
    c11-gnu c11-strict c11-posix-2008 c11-xopen-700 c11-bsd \
    cxx17-gnu cxx17-strict; do
    for include_order in CRABC_PTHREAD_C11_PTHREAD_FIRST CRABC_PTHREAD_C11_SCHED_FIRST; do
        compile_one candidate "$profile" "$include_order" "$work_dir"
    done
done

if [ "$failures" -ne 0 ]; then
    printf 'x86 pthread/C11 header ABI: INCOMPLETE (%s project-header mismatches; compile-only)\n' \
        "$failures" >&2
    exit 1
fi

printf 'x86 pinned-musl/project pthread/C11 header ABI: PASS (28 contexts; compile-only)\n'
