#!/usr/bin/env bash
# Native Linux/x86-64 caller-owned stateful byte-string C/C++ ABI matrix.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "$BASH_SOURCE")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly CANDIDATE_CC=/usr/bin/gcc
readonly PROJECT_INCLUDE="$ROOT_DIR/include"
readonly C_PROBE="$ROOT_DIR/compat/x86_64/stateful_byte_strings_header_abi_probe.c"
readonly CXX_PROBE="$ROOT_DIR/compat/x86_64/stateful_byte_strings_header_abi_probe.cpp"

fail() { printf 'ERROR: x86 stateful byte-string header ABI: %s\n' "$*" >&2; exit 1; }
run_compiler() { local compiler="$1"; shift; env -u CPATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH -u LIBRARY_PATH -u GCC_EXEC_PREFIX -u GCC_SPECS -u COMPILER_PATH "$compiler" "$@"; }
trace_paths() { awk '/^[. ]+ \// { sub(/^[. ]+/, ""); print $1 }' "$1"; }

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "requires native x86-64" ;; esac
for tool in env grep mktemp nm realpath awk uname; do command -v "$tool" >/dev/null || fail "requires $tool"; done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl compiler"
[ -x "$CANDIDATE_CC" ] || fail "missing raw native candidate compiler"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
builtin_include="$(run_compiler "$CANDIDATE_CC" -print-file-name=include)"
case "$builtin_include" in /*) ;; *) fail "candidate compiler did not report builtin includes" ;; esac
builtin_include="$(realpath "$builtin_include")"
[ -d "$builtin_include" ] || fail "candidate compiler builtin includes are missing"
work_dir="$(mktemp -d /tmp/crabc-x86-64-stateful-byte-strings-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT

set_tree() {
    case "$1" in
        oracle) compiler="$ORACLE_CC"; include_args=() ;;
        project) compiler="$CANDIDATE_CC"; include_args=(-nostdinc -I "$PROJECT_INCLUDE" -isystem "$builtin_include") ;;
        *) fail "unknown header tree: $1" ;;
    esac
}

compile_c_profile() {
    local tree
    for tree in oracle project; do
        set_tree "$tree"
        run_compiler "$compiler" -std=c11 -U_GNU_SOURCE -U_BSD_SOURCE -U_XOPEN_SOURCE -U_POSIX_C_SOURCE -U_DEFAULT_SOURCE "$@" -DCRABC_EXPECT_DIRNAME -Werror=implicit-function-declaration ${include_args[@]} -fsyntax-only "$C_PROBE"
    done
}

compile_c_profile -D__STRICT_ANSI__
compile_c_profile -D_POSIX_C_SOURCE=200809L -DCRABC_EXPECT_STRTOK_R
compile_c_profile -D_XOPEN_SOURCE=700 -DCRABC_EXPECT_STRTOK_R
compile_c_profile -D_GNU_SOURCE -DCRABC_EXPECT_STRTOK_R -DCRABC_EXPECT_STRCASESTR
compile_c_profile -D_BSD_SOURCE -DCRABC_EXPECT_STRTOK_R

for tree in oracle project; do
    set_tree "$tree"
    if run_compiler "$compiler" -std=c11 -U_GNU_SOURCE -U_BSD_SOURCE -U_XOPEN_SOURCE -U_POSIX_C_SOURCE -U_DEFAULT_SOURCE -D__STRICT_ANSI__ -DCRABC_REQUIRE_STRTOK_R_HIDDEN -Werror=implicit-function-declaration ${include_args[@]} -fsyntax-only "$C_PROBE" >"$work_dir/$tree-strict-strtok-r" 2>&1; then fail "strtok_r is visible under strict C ($tree)"; fi
    if run_compiler "$compiler" -std=c11 -U_GNU_SOURCE -U_BSD_SOURCE -U_XOPEN_SOURCE -U_POSIX_C_SOURCE -U_DEFAULT_SOURCE -D__STRICT_ANSI__ -DCRABC_REQUIRE_STRCASESTR_HIDDEN -Werror=implicit-function-declaration ${include_args[@]} -fsyntax-only "$C_PROBE" >"$work_dir/$tree-strict-strcasestr" 2>&1; then fail "strcasestr is visible under strict C ($tree)"; fi
    if run_compiler "$compiler" -std=c11 -U_GNU_SOURCE -U_BSD_SOURCE -U_XOPEN_SOURCE -U_POSIX_C_SOURCE -U_DEFAULT_SOURCE -D_BSD_SOURCE -DCRABC_REQUIRE_STRCASESTR_HIDDEN -Werror=implicit-function-declaration ${include_args[@]} -fsyntax-only "$C_PROBE" >"$work_dir/$tree-bsd-strcasestr" 2>&1; then fail "strcasestr is visible under BSD C ($tree)"; fi
done

for tree in oracle project; do
    set_tree "$tree"
    object="$work_dir/$tree-gnu-cxx.o"
    run_compiler "$compiler" -std=c++17 -x c++ -U_GNU_SOURCE -U_BSD_SOURCE -U_XOPEN_SOURCE -U_POSIX_C_SOURCE -U_DEFAULT_SOURCE -D_GNU_SOURCE -nostdinc++ ${include_args[@]} -c "$CXX_PROBE" -o "$object"
    for symbol in dirname strcasestr strtok_r; do
        nm --undefined-only "$object" | grep -Eq "[[:space:]]$symbol$" || fail "C++ probe does not retain C linkage for $symbol ($tree)"
        if nm --undefined-only "$object" | grep -Eq "_Z[0-9].*$symbol"; then fail "C++ probe retained a mangled $symbol reference ($tree)"; fi
    done
done

set_tree project
trace="$work_dir/project-gnu-header-trace"
run_compiler "$compiler" -std=c11 -U_GNU_SOURCE -U_BSD_SOURCE -U_XOPEN_SOURCE -U_POSIX_C_SOURCE -U_DEFAULT_SOURCE -D_GNU_SOURCE -DCRABC_EXPECT_DIRNAME -DCRABC_EXPECT_STRTOK_R -DCRABC_EXPECT_STRCASESTR ${include_args[@]} -H -fsyntax-only "$C_PROBE" >/dev/null 2>"$trace"
while IFS= read -r path; do case "$path" in "$PROJECT_INCLUDE"/*|"$builtin_include"/*) ;; *) fail "project header trace escaped declared roots: $path" ;; esac; done < <(trace_paths "$trace")
for header in libgen.h string.h features.h bits/alltypes.h; do grep -Fq "$PROJECT_INCLUDE/$header" "$trace" || fail "project trace omitted <$header>"; done
printf 'x86 pinned-musl/project C/C++ stateful byte-string ABI: PASS\n'
