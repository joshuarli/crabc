#!/usr/bin/env bash
# Native Linux/x86-64 direct <link.h> source-form topology evidence.
#
# Pinned musl 1.2.6 is the header oracle.  The candidate pass sees only the
# project include tree and the raw compiler builtin headers, so a host libc
# header cannot hide an unintended <stddef.h> dependency or a missing
# <bits/link.h> declaration.  This remains a header-only slice: it does not
# select loader runtime, dlfcn provider, archive linkage, or public support.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly MUSL_ROOT=/opt/musl-1.2.6
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly CANDIDATE_CC=/usr/bin/gcc
readonly PROJECT_INCLUDE="$ROOT_DIR/include"
readonly C_PROBE="$ROOT_DIR/compat/x86_64/link_header_source_form_probe.c"
readonly CXX_PROBE="$ROOT_DIR/compat/x86_64/link_header_source_form_probe.cpp"

fail() {
    printf 'ERROR: x86 link.h source form: %s\n' "$*" >&2
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

require_trace_header() {
    local trace="$1" root="$2" header="$3"
    grep -Fq "$root/$header" "$trace" ||
        fail "direct <link.h> include did not resolve $header through $root"
}

forbid_trace_header() {
    local trace="$1" root="$2" header="$3"
    if grep -Fq "$root/$header" "$trace"; then
        fail "direct <link.h> include unexpectedly acquired $header"
    fi
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
            *) fail "unknown include tree: $tree" ;;
        esac
    done < <(trace_paths "$trace")
}

set_tree() {
    local tree="$1"
    case "$tree" in
        candidate)
            compiler="$CANDIDATE_CC"
            include_root="$PROJECT_INCLUDE"
            ;;
        reference)
            compiler="$ORACLE_CC"
            include_root="$MUSL_ROOT/include"
            ;;
        *) fail "unknown include tree: $tree" ;;
    esac
    include_args=(-nostdinc -I "$include_root" -isystem "$compiler_builtin")
}

compile_c() {
    local tree="$1" trace="$2"
    set_tree "$tree"
    if ! run_compiler "$compiler" -std=c11 "${include_args[@]}" -H -fsyntax-only \
        "$C_PROBE" >/dev/null 2>"$trace"; then
        fail "$tree C11 direct <link.h> source-form probe failed: $(sed -n '/error:/p' "$trace" | sed -n '1p')"
    fi
}

compile_cxx() {
    local tree="$1" trace="$2" object="$3" undefined
    set_tree "$tree"
    if ! run_compiler "$compiler" -std=c++17 -x c++ -nostdinc++ "${include_args[@]}" \
        -H -c "$CXX_PROBE" -o "$object" >/dev/null 2>"$trace"; then
        fail "$tree C++17 direct <link.h> source-form probe failed: $(sed -n '/error:/p' "$trace" | sed -n '1p')"
    fi
    undefined="$(nm --undefined-only "$object")"
    printf '%s\n' "$undefined" | grep -Eq '[[:space:]]dl_iterate_phdr$' ||
        fail "$tree C++17 probe lost C linkage for dl_iterate_phdr"
    if printf '%s\n' "$undefined" | grep -Eq '_Z[0-9].*dl_iterate_phdr'; then
        fail "$tree C++17 probe retained mangled dl_iterate_phdr linkage"
    fi
}

check_topology() {
    local tree="$1" trace="$2"
    case "$tree" in
        candidate) include_root="$PROJECT_INCLUDE" ;;
        reference) include_root="$MUSL_ROOT/include" ;;
        *) fail "unknown include tree: $tree" ;;
    esac
    check_trace_roots "$tree" "$trace"
    for header in link.h elf.h bits/alltypes.h bits/link.h; do
        require_trace_header "$trace" "$include_root" "$header"
    done
    forbid_trace_header "$trace" "$include_root" stddef.h
}

[ "$#" -eq 0 ] || fail "usage: $0"
require_native_linux_x86_64
for tool in env grep mktemp nm realpath sed uname; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -x "$CANDIDATE_CC" ] || fail "missing raw native candidate compiler"
[ -d "$MUSL_ROOT/include" ] || fail "missing pinned musl include tree"
[ -d "$PROJECT_INCLUDE" ] || fail "missing project include tree"
[ -f "$C_PROBE" ] || fail "missing C probe"
[ -f "$CXX_PROBE" ] || fail "missing C++ probe"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

compiler_builtin="$(run_compiler "$CANDIDATE_CC" -print-file-name=include)"
compiler_builtin="$(realpath "$compiler_builtin")"
[ -d "$compiler_builtin" ] || fail "raw compiler builtin include root is missing"

work_dir="$(mktemp -d /tmp/crabc-x86-64-link-header-source-form.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT

for tree in reference candidate; do
    c_trace="$work_dir/$tree-c.trace"
    cxx_trace="$work_dir/$tree-cxx.trace"
    compile_c "$tree" "$c_trace"
    compile_cxx "$tree" "$cxx_trace" "$work_dir/$tree-cxx.o"
    check_topology "$tree" "$c_trace"
    check_topology "$tree" "$cxx_trace"
done

printf '%s\n' 'x86 pinned-musl/project C/C++ <link.h> source form: PASS'
