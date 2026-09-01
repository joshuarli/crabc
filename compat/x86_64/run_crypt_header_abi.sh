#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly CANDIDATE_CC=/usr/bin/gcc
readonly PROJECT_INCLUDE="$ROOT_DIR/include"
readonly C_PROBE="$ROOT_DIR/compat/x86_64/crypt_header_abi_probe.c"
readonly CXX_PROBE="$ROOT_DIR/compat/x86_64/crypt_header_abi_probe.cpp"
readonly UNISTD_C_PROBE="$ROOT_DIR/compat/x86_64/crypt_unistd_visibility_probe.c"
readonly UNISTD_CXX_PROBE="$ROOT_DIR/compat/x86_64/crypt_unistd_visibility_probe.cpp"

fail() {
    printf 'ERROR: x86 crypt.h ABI: %s\n' "$*" >&2
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
    env -u CPATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH -u LIBRARY_PATH -u GCC_EXEC_PREFIX -u GCC_SPECS -u COMPILER_PATH "$compiler" "$@"
}

trace_paths() {
    sed -n -E 's/^[. ]+ (\/[^[:space:]]+).*$/\1/p' "$1"
}

require_native_linux_x86_64
for tool in env grep mktemp nm realpath sed uname; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl compiler"
[ -x "$CANDIDATE_CC" ] || fail "missing raw native candidate compiler"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

builtin_include="$(run_compiler "$CANDIDATE_CC" -print-file-name=include)"
case "$builtin_include" in
    /*) ;;
    *) fail "raw candidate compiler did not report an absolute builtin include directory" ;;
esac
builtin_include="$(realpath "$builtin_include")"
[ -d "$builtin_include" ] || fail "missing raw candidate compiler builtin include directory"

work_dir="$(mktemp -d /tmp/crabc-x86-64-crypt-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT

for profile in strict posix xopen gnu bsd; do
    case "$profile" in
        strict)
            profile_args=(-U_ALL_SOURCE -U_DEFAULT_SOURCE -U_GNU_SOURCE -U_BSD_SOURCE -U_XOPEN_SOURCE -U_POSIX_SOURCE -U_POSIX_C_SOURCE)
            unistd_visibility=hidden
            ;;
        posix)
            profile_args=(-U_ALL_SOURCE -U_DEFAULT_SOURCE -U_GNU_SOURCE -U_BSD_SOURCE -U_XOPEN_SOURCE -U_POSIX_SOURCE -U_POSIX_C_SOURCE -D_POSIX_C_SOURCE=200809L)
            unistd_visibility=hidden
            ;;
        xopen)
            profile_args=(-U_ALL_SOURCE -U_DEFAULT_SOURCE -U_GNU_SOURCE -U_BSD_SOURCE -U_XOPEN_SOURCE -U_POSIX_SOURCE -U_POSIX_C_SOURCE -D_XOPEN_SOURCE=700)
            unistd_visibility=visible
            ;;
        gnu)
            profile_args=(-U_ALL_SOURCE -U_DEFAULT_SOURCE -U_GNU_SOURCE -U_BSD_SOURCE -U_XOPEN_SOURCE -U_POSIX_SOURCE -U_POSIX_C_SOURCE -D_GNU_SOURCE)
            unistd_visibility=visible
            ;;
        bsd)
            profile_args=(-U_ALL_SOURCE -U_DEFAULT_SOURCE -U_GNU_SOURCE -U_BSD_SOURCE -U_XOPEN_SOURCE -U_POSIX_SOURCE -U_POSIX_C_SOURCE -D_BSD_SOURCE)
            unistd_visibility=visible
            ;;
    esac

    for language in c cxx; do
        for variant in oracle project; do
            case "$variant" in
                oracle)
                    compiler="$ORACLE_CC"
                    include_args=()
                    ;;
                project)
                    compiler="$CANDIDATE_CC"
                    include_args=(-nostdinc -I "$PROJECT_INCLUDE" -isystem "$builtin_include")
                    ;;
            esac

            if [ "$language" = c ]; then
                run_compiler "$compiler" -std=c11 "${profile_args[@]}" "${include_args[@]}" -fsyntax-only "$C_PROBE"
                if [ "$unistd_visibility" = visible ]; then
                    run_compiler "$compiler" -std=c11 "${profile_args[@]}" -DCRABC_EXPECT_UNISTD_CRYPT "${include_args[@]}" -fsyntax-only "$UNISTD_C_PROBE"
                elif run_compiler "$compiler" -std=c11 "${profile_args[@]}" "${include_args[@]}" -fsyntax-only "$UNISTD_C_PROBE" >"$work_dir/${variant}-${profile}-unistd-hidden-c.out" 2>&1; then
                    fail "<unistd.h> unexpectedly exposes crypt (${variant}, ${profile}, C)"
                fi
            else
                object="$work_dir/${variant}-${profile}-crypt-header.o"
                run_compiler "$compiler" -std=c++17 "${profile_args[@]}" -nostdinc++ "${include_args[@]}" -c "$CXX_PROBE" -o "$object"
                undefined="$(nm --undefined-only "$object")"
                printf '%s\n' "$undefined" | grep -Eq '[[:space:]]crypt$' || fail "C++ probe does not retain C linkage for crypt (${variant}, ${profile})"
                printf '%s\n' "$undefined" | grep -Eq '[[:space:]]crypt_r$' || fail "C++ probe does not retain C linkage for crypt_r (${variant}, ${profile})"
                if printf '%s\n' "$undefined" | grep -Eq '_Z[0-9].*(crypt|crypt_r)'; then
                    fail "C++ probe retained a mangled crypt reference (${variant}, ${profile})"
                fi

                if [ "$unistd_visibility" = visible ]; then
                    object="$work_dir/${variant}-${profile}-unistd-crypt.o"
                    run_compiler "$compiler" -std=c++17 "${profile_args[@]}" -DCRABC_EXPECT_UNISTD_CRYPT -nostdinc++ "${include_args[@]}" -c "$UNISTD_CXX_PROBE" -o "$object"
                    undefined="$(nm --undefined-only "$object")"
                    printf '%s\n' "$undefined" | grep -Eq '[[:space:]]crypt$' || fail "C++ <unistd.h> probe does not retain C linkage for crypt (${variant}, ${profile})"
                    if printf '%s\n' "$undefined" | grep -Eq '_Z[0-9].*crypt'; then
                        fail "C++ <unistd.h> probe retained a mangled crypt reference (${variant}, ${profile})"
                    fi
                elif run_compiler "$compiler" -std=c++17 "${profile_args[@]}" -nostdinc++ "${include_args[@]}" -c "$UNISTD_CXX_PROBE" -o "$work_dir/${variant}-${profile}-unistd-hidden-cxx.o" >"$work_dir/${variant}-${profile}-unistd-hidden-cxx.out" 2>&1; then
                    fail "<unistd.h> unexpectedly exposes crypt (${variant}, ${profile}, C++)"
                fi
            fi
        done
    done
done

header_trace="$work_dir/project-header-trace"
run_compiler "$CANDIDATE_CC" -std=c11 -D_GNU_SOURCE -nostdinc -I "$PROJECT_INCLUDE" -isystem "$builtin_include" -H -fsyntax-only "$C_PROBE" >/dev/null 2>"$header_trace"
while IFS= read -r path; do
    case "$path" in
        "$PROJECT_INCLUDE"/*|"$builtin_include"/*) ;;
        *) fail "project header trace escaped its declared roots: $path" ;;
    esac
done < <(trace_paths "$header_trace")
grep -Fq "$PROJECT_INCLUDE/crypt.h" "$header_trace" || fail "project probe did not use <crypt.h>"

printf 'x86 pinned-musl/project C/C++ <crypt.h> ABI: PASS\n'
