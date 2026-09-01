#!/usr/bin/env bash
# Native Linux/x86-64 C resolver-runtime declaration and record-layout gate.
#
# Both arms compile exactly the GNU visibility profile: it is the profile
# where the installed netdb header exposes the historical h_errno object.
# Pinned musl 1.2.6 is the C/POSIX declaration oracle; the candidate arm uses
# project headers with only compiler builtin headers, never an ambient libc.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly MUSL_ROOT=/opt/musl-1.2.6
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly CANDIDATE_CC=/usr/bin/gcc
readonly PROJECT_INCLUDE="$ROOT_DIR/include"
readonly C_PROBE="$ROOT_DIR/compat/x86_64/resolver_runtime_header_abi_probe.c"
readonly CXX_PROBE="$ROOT_DIR/compat/x86_64/resolver_runtime_header_abi_probe.cpp"

fail() {
    printf 'ERROR: x86 resolver-runtime headers: %s\n' "$*" >&2
    exit 1
}

require_native_linux_x86_64() {
    [ "$(uname -s)" = Linux ] || fail "requires native Linux"
    case "$(uname -m)" in x86_64|amd64) ;; *) fail "refuses emulation on $(uname -m)" ;; esac
}

require_tool() {
    command -v "$1" >/dev/null 2>&1 || fail "requires $1"
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

compile_probe() {
    local tree="$1" language="$2" trace="$3" object="$4"
    local compiler include_root source
    case "$tree" in
        reference) compiler="$ORACLE_CC"; include_root="$MUSL_ROOT/include" ;;
        candidate) compiler="$CANDIDATE_CC"; include_root="$PROJECT_INCLUDE" ;;
        *) fail "unknown header tree: $tree" ;;
    esac
    case "$language" in
        c)
            source="$C_PROBE"
            run_compiler "$compiler" -x c -std=c11 -nostdinc -I "$include_root" \
                -isystem "$candidate_compiler_builtin_include" -U_GNU_SOURCE -D_GNU_SOURCE \
                -H -fno-builtin -fsyntax-only "$source" >/dev/null 2>"$trace"
            ;;
        cxx)
            source="$CXX_PROBE"
            run_compiler "$compiler" -x c++ -std=c++17 -nostdinc -nostdinc++ -I "$include_root" \
                -isystem "$candidate_compiler_builtin_include" -U_GNU_SOURCE -D_GNU_SOURCE \
                -H -fno-builtin -c -o "$object" "$source" >/dev/null 2>"$trace"
            ;;
        *) fail "unknown language: $language" ;;
    esac
}

check_trace() {
    local tree="$1" trace="$2" root path
    case "$tree" in
        reference) root="$MUSL_ROOT/include" ;;
        candidate) root="$PROJECT_INCLUDE" ;;
        *) fail "unknown header tree: $tree" ;;
    esac
    while IFS= read -r path; do
        case "$path" in "$root"/*|"$candidate_compiler_builtin_include"/*) ;; *)
            fail "$tree header trace escaped its declared roots: $path" ;;
        esac
    done < <(trace_paths "$trace")
    for header in netdb.h resolv.h netinet/in.h arpa/nameser.h; do
        grep -Fq "$root/$header" "$trace" || fail "$tree trace omitted $root/$header"
    done
}

check_cxx_linkage() {
    local object="$1" undefined
    undefined="$(nm --undefined-only "$object")"
    for symbol in __res_state __h_errno_location res_query; do
        printf '%s\n' "$undefined" | grep -Eq "[[:space:]]${symbol}$" ||
            fail "C++ probe lacks unmangled ${symbol}"
    done
    if printf '%s\n' "$undefined" | grep -Eq '_Z[0-9].*(res_state|h_errno|res_query)'; then
        fail "C++ probe retained a mangled resolver reference"
    fi
}

[ "$#" -eq 0 ] || fail "usage: $0"
require_native_linux_x86_64
for tool in env grep mktemp nm realpath sed uname; do require_tool "$tool"; done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl compiler"
[ -x "$CANDIDATE_CC" ] || fail "missing raw native candidate compiler"
[ -d "$MUSL_ROOT/include" ] || fail "missing pinned musl include tree"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

candidate_compiler_builtin_include="$(run_compiler "$CANDIDATE_CC" -print-file-name=include)"
case "$candidate_compiler_builtin_include" in /*) ;; *) fail "raw compiler did not report an absolute builtin include directory" ;; esac
candidate_compiler_builtin_include="$(realpath "$candidate_compiler_builtin_include")"
[ -d "$candidate_compiler_builtin_include" ] || fail "missing raw compiler builtin include directory"

work_dir="$(mktemp -d /tmp/crabc-x86-64-resolver-runtime-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT

for tree in reference candidate; do
    c_trace="$work_dir/$tree.c.trace"
    cxx_trace="$work_dir/$tree.cxx.trace"
    cxx_object="$work_dir/$tree.cxx.o"
    compile_probe "$tree" c "$c_trace" "$work_dir/$tree.c.o" || {
        sed -n '1,160p' "$c_trace" >&2
        fail "$tree C declaration/layout probe failed"
    }
    compile_probe "$tree" cxx "$cxx_trace" "$cxx_object" || {
        sed -n '1,160p' "$cxx_trace" >&2
        fail "$tree C++ declaration/layout probe failed"
    }
    check_trace "$tree" "$c_trace"
    check_trace "$tree" "$cxx_trace"
    check_cxx_linkage "$cxx_object"
done

printf 'x86 pinned-musl/project GNU C/C++ resolver-runtime ABI: PASS\n'
