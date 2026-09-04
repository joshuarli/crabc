#!/usr/bin/env bash
# Native Linux/x86-64 sys/cachectl.h source-form evidence.
#
# Pinned musl 1.2.6 owns the exact cache-selector macro forms. The three
# declared callables remain explicitly oracle-declared-no-provider: this
# compile-only gate never adds a cache-control runtime, archive member,
# capability, family completion, or public-support claim.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly MUSL_ROOT=/opt/musl-1.2.6
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly CANDIDATE_CC=/usr/bin/gcc
readonly PROJECT_INCLUDE="$ROOT_DIR/include"
readonly C_PROBE="$ROOT_DIR/compat/x86_64/cachectl_header_source_form_probe.c"
readonly CXX_PROBE="$ROOT_DIR/compat/x86_64/cachectl_header_source_form_probe.cpp"
readonly EXPECTED_PROFILE_COUNT=7
readonly -a PROFILES=(c11-gnu cxx17-gnu c11-strict c11-posix-2008 c11-xopen-700 c11-bsd cxx17-strict)

fail() {
    printf 'ERROR: x86 sys/cachectl.h source form: %s\n' "$*" >&2
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
        -u GCC_EXEC_PREFIX -u GCC_SPECS -u COMPILER_PATH "$compiler" "$@"
}

profile_arguments() {
    case "$1" in
        c11-gnu|cxx17-gnu) printf '%s\n' '-D_GNU_SOURCE' ;;
        c11-strict|cxx17-strict) : ;;
        c11-posix-2008) printf '%s\n' '-D_POSIX_C_SOURCE=200809L' ;;
        c11-xopen-700) printf '%s\n' '-D_XOPEN_SOURCE=700' ;;
        c11-bsd) printf '%s\n' '-D_BSD_SOURCE' ;;
        *) fail "unknown feature profile: $1" ;;
    esac
}

set_tree() {
    case "$1" in
        candidate) compiler="$CANDIDATE_CC"; include_root="$PROJECT_INCLUDE" ;;
        reference) compiler="$ORACLE_CC"; include_root="$MUSL_ROOT/include" ;;
        *) fail "unknown header tree: $1" ;;
    esac
}

set_language() {
    case "$1" in
        c11-*) source="$C_PROBE"; language_args=(-x c -std=c11) ;;
        cxx17-*) source="$CXX_PROBE"; language_args=(-x c++ -std=c++17 -nostdinc++) ;;
        *) fail "unknown language profile: $1" ;;
    esac
}

trace_paths() {
    sed -n -E 's/^[. ]+ (\/[^[:space:]]+).*$/\1/p' "$1"
}

first_diagnostic() {
    local diagnostic="$1" line
    line="$(sed -n '/fatal error:/p; /error:/p' "$diagnostic" | sed -n '1p' || true)"
    [ -n "$line" ] && printf '%s\n' "$line" | tr '\t\r\n' ' ' || printf '%s\n' 'no compiler diagnostic'
}

compile_profile() {
    local tree="$1" profile="$2" trace="$3" object="$4"
    local -a profile_args=() include_args=()
    set_tree "$tree"
    set_language "$profile"
    mapfile -t profile_args < <(profile_arguments "$profile")
    include_args=(-nostdinc -I "$include_root" -isystem "$compiler_builtin" -H -fno-builtin)
    if [ "${profile#cxx17-}" = "$profile" ]; then
        run_compiler "$compiler" "${language_args[@]}" "${profile_args[@]}" \
            "${include_args[@]}" -fsyntax-only "$source" >/dev/null 2>"$trace"
    else
        run_compiler "$compiler" "${language_args[@]}" "${profile_args[@]}" \
            "${include_args[@]}" -c "$source" -o "$object" >/dev/null 2>"$trace"
    fi
}

check_trace() {
    local tree="$1" profile="$2" trace="$3" root path
    case "$tree" in
        candidate) root="$PROJECT_INCLUDE" ;;
        reference) root="$MUSL_ROOT/include" ;;
        *) fail "unknown header tree: $tree" ;;
    esac
    while IFS= read -r path; do
        case "$path" in
            "$root"/*|"$compiler_builtin"/*) ;;
            *) fail "$profile $tree trace escaped its declared header roots: $path" ;;
        esac
    done < <(trace_paths "$trace")
    grep -Fq "$root/sys/cachectl.h" "$trace" ||
        fail "$profile $tree trace omitted $root/sys/cachectl.h"
    [ "$(trace_paths "$trace" | wc -l)" -eq 1 ] ||
        fail "$profile $tree direct sys/cachectl.h inclusion acquired transitive headers"
}

extract_x86_branch() {
    awk '
        NR == 1 {
            if ($0 != "#if defined(__x86_64__)") exit 2
            next
        }
        $0 == "#else" { exit }
        { print }
    ' "$1"
}

check_exact_x86_form() {
    local extracted="$work_dir/cachectl.x86" normalized_reference="$work_dir/cachectl.reference"
    if ! extract_x86_branch "$PROJECT_INCLUDE/sys/cachectl.h" >"$extracted"; then
        fail "project sys/cachectl.h lacks an x86 source-form branch"
    fi
    # musl's otherwise exact file contains one space-only separator. The
    # repository rejects trailing whitespace, so normalize only that audited
    # non-token line; every macro/declaration form remains source-identical.
    [ "$(grep -Fxc ' ' "$MUSL_ROOT/include/sys/cachectl.h")" -eq 1 ] ||
        fail "pinned musl cachectl separator form drifted"
    [ "$(grep -Fxc ' ' "$extracted" || true)" -eq 0 ] ||
        fail "project cachectl x86 body retained forbidden trailing whitespace"
    sed 's/^ $//' "$MUSL_ROOT/include/sys/cachectl.h" >"$normalized_reference"
    if ! cmp -s "$normalized_reference" "$extracted"; then
        diff -u "$normalized_reference" "$extracted" || true
        fail "project x86 sys/cachectl.h body differs from pinned musl"
    fi
}

extract_macro_surface() {
    local tree="$1" profile="$2" output="$3" diagnostic="$4"
    local -a profile_args=() include_args=()
    set_tree "$tree"
    set_language "$profile"
    mapfile -t profile_args < <(profile_arguments "$profile")
    include_args=(-nostdinc -I "$include_root" -isystem "$compiler_builtin")
    if ! run_compiler "$compiler" "${language_args[@]}" "${profile_args[@]}" \
        "${include_args[@]}" -dM -E -include sys/cachectl.h - < /dev/null \
        >"$output" 2>"$diagnostic"; then
        fail "$profile $tree macro extraction failed: $(first_diagnostic "$diagnostic")"
    fi
    awk '/^#define (_SYS_CACHECTL_H|_CRABC_SYS_CACHECTL_H|ICACHE|DCACHE|BCACHE|CACHEABLE|UNCACHEABLE)([[:space:]]|$)/' \
        "$output" | LC_ALL=C sort > "$output.surface"
}

check_cxx_linkage() {
    local tree="$1" profile="$2" object="$3" undefined symbol
    undefined="$(nm --undefined-only "$object")"
    for symbol in cachectl cacheflush _flush_cache; do
        printf '%s\n' "$undefined" | grep -Eq "[[:space:]]${symbol}$" ||
            fail "$profile $tree C++ probe lost unmangled $symbol linkage"
        if printf '%s\n' "$undefined" | grep -Eq "_Z.*${symbol}"; then
            fail "$profile $tree C++ probe retained a mangled $symbol reference"
        fi
    done
}

[ "$#" -eq 0 ] || fail "usage: $0"
require_native_linux_x86_64
for tool in awk cmp diff env grep mapfile mktemp nm realpath sed sort tr uname wc; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -x "$CANDIDATE_CC" ] || fail "missing raw native candidate compiler"
[ -d "$MUSL_ROOT/include" ] || fail "missing pinned musl include tree"
[ -d "$PROJECT_INCLUDE" ] || fail "missing project include tree"
[ -f "$C_PROBE" ] || fail "missing C sys/cachectl.h probe"
[ -f "$CXX_PROBE" ] || fail "missing C++ sys/cachectl.h probe"
[ "${#PROFILES[@]}" -eq "$EXPECTED_PROFILE_COUNT" ] || fail "profile roster drifted"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
compiler_builtin="$(run_compiler "$CANDIDATE_CC" -print-file-name=include)"
compiler_builtin="$(realpath "$compiler_builtin")"
[ -d "$compiler_builtin" ] || fail "raw compiler builtin include root is missing"

work_dir="$(mktemp -d /tmp/crabc-x86-64-cachectl-header-source-form.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT

check_exact_x86_form
for profile in "${PROFILES[@]}"; do
    for tree in reference candidate; do
        trace="$work_dir/$profile.$tree.trace"
        object="$work_dir/$profile.$tree.o"
        if ! compile_profile "$tree" "$profile" "$trace" "$object"; then
            fail "$profile $tree direct sys/cachectl.h probe failed: $(first_diagnostic "$trace")"
        fi
        check_trace "$tree" "$profile" "$trace"
        if [ "${profile#cxx17-}" != "$profile" ]; then
            check_cxx_linkage "$tree" "$profile" "$object"
        fi
        extract_macro_surface "$tree" "$profile" \
            "$work_dir/$profile.$tree.macros" "$work_dir/$profile.$tree.macros.trace"
    done
    if ! cmp -s "$work_dir/$profile.reference.macros.surface" \
        "$work_dir/$profile.candidate.macros.surface"; then
        diff -u "$work_dir/$profile.reference.macros.surface" \
            "$work_dir/$profile.candidate.macros.surface" || true
        fail "$profile project cachectl macro surface differs from pinned musl"
    fi
done

printf 'x86 pinned-musl/project C/C++ <sys/cachectl.h> source form: PASS (%s profiles; compile-only)\n' \
    "$EXPECTED_PROFILE_COUNT"
