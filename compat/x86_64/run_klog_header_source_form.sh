#!/usr/bin/env bash
# Native Linux/x86-64 direct <sys/klog.h> source-form evidence.
#
# Pinned musl 1.2.6 owns this public header: it exposes klogctl but no KLOG_*
# command macros. Both trees use only raw compiler builtin headers and their
# own include roots. This compile-only gate neither adds a klog provider nor
# selects runtime behavior, Linux UAPI, family completion, or public support.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly MUSL_ROOT=/opt/musl-1.2.6
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly CANDIDATE_CC=/usr/bin/gcc
readonly PROJECT_INCLUDE="$ROOT_DIR/include"
readonly C_PROBE="$ROOT_DIR/compat/x86_64/klog_header_source_form_probe.c"
readonly CXX_PROBE="$ROOT_DIR/compat/x86_64/klog_header_source_form_probe.cpp"
readonly EXPECTED_PROFILE_COUNT=7
readonly -a PROFILES=(c11-gnu cxx17-gnu c11-strict c11-posix-2008 c11-xopen-700 c11-bsd cxx17-strict)

fail() {
    printf 'ERROR: x86 sys/klog.h source form: %s\n' "$*" >&2
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
        c11-*) language=c; source="$C_PROBE"; language_args=(-x c -std=c11) ;;
        cxx17-*) language=cxx; source="$CXX_PROBE"; language_args=(-x c++ -std=c++17 -nostdinc++) ;;
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
    if [ "$language" = c ]; then
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
    grep -Fq "$root/sys/klog.h" "$trace" ||
        fail "$profile $tree trace omitted $root/sys/klog.h"
    [ "$(trace_paths "$trace" | wc -l)" -eq 1 ] ||
        fail "$profile $tree direct sys/klog.h inclusion acquired transitive headers"
}

extract_klog_macros() {
    local tree="$1" profile="$2" macros="$3" diagnostic="$4"
    local -a profile_args=() include_args=()
    set_tree "$tree"
    set_language "$profile"
    mapfile -t profile_args < <(profile_arguments "$profile")
    include_args=(-nostdinc -I "$include_root" -isystem "$compiler_builtin")
    if ! run_compiler "$compiler" "${language_args[@]}" "${profile_args[@]}" \
        "${include_args[@]}" -dM -E -include sys/klog.h - < /dev/null \
        >"$macros" 2>"$diagnostic"; then
        fail "$profile $tree macro extraction failed: $(first_diagnostic "$diagnostic")"
    fi
    awk '/^#define KLOG_/' < "$macros" | LC_ALL=C sort > "$macros.surface"
    if [ -s "$macros.surface" ]; then
        fail "$profile $tree leaked non-musl KLOG macros: $(tr '\n' ' ' < "$macros.surface")"
    fi
}

check_cxx_linkage() {
    local tree="$1" profile="$2" object="$3" undefined
    undefined="$(nm --undefined-only "$object")"
    printf '%s\n' "$undefined" | grep -Eq '[[:space:]]klogctl$' ||
        fail "$profile $tree C++ probe lost unmangled klogctl linkage"
    if printf '%s\n' "$undefined" | grep -Eq '_Z.*klogctl'; then
        fail "$profile $tree C++ probe retained a mangled klogctl reference"
    fi
}

[ "$#" -eq 0 ] || fail "usage: $0"
[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "refuses emulation on $(uname -m)" ;; esac
for tool in awk cmp diff env grep mapfile mktemp nm realpath sed sort tr uname wc; do
    command -v "$tool" >/dev/null 2>&1 || fail "requires $tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -x "$CANDIDATE_CC" ] || fail "missing raw native candidate compiler"
[ -d "$MUSL_ROOT/include" ] || fail "missing pinned musl include tree"
[ -d "$PROJECT_INCLUDE" ] || fail "missing project include tree"
[ -f "$C_PROBE" ] || fail "missing C sys/klog.h probe"
[ -f "$CXX_PROBE" ] || fail "missing C++ sys/klog.h probe"
[ "${#PROFILES[@]}" -eq "$EXPECTED_PROFILE_COUNT" ] || fail "profile roster drifted"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
compiler_builtin="$(run_compiler "$CANDIDATE_CC" -print-file-name=include)"
compiler_builtin="$(realpath "$compiler_builtin")"
[ -d "$compiler_builtin" ] || fail "raw compiler builtin include root is missing"

work_dir="$(mktemp -d /tmp/crabc-x86-64-klog-header-source-form.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT

for profile in "${PROFILES[@]}"; do
    for tree in reference candidate; do
        trace="$work_dir/$profile.$tree.trace"
        object="$work_dir/$profile.$tree.o"
        if ! compile_profile "$tree" "$profile" "$trace" "$object"; then
            fail "$profile $tree direct sys/klog.h probe failed: $(first_diagnostic "$trace")"
        fi
        check_trace "$tree" "$profile" "$trace"
        if [ "${profile#cxx17-}" != "$profile" ]; then
            check_cxx_linkage "$tree" "$profile" "$object"
        fi
        extract_klog_macros "$tree" "$profile" "$work_dir/$profile.$tree.macros" \
            "$work_dir/$profile.$tree.macros.trace"
    done
    if ! cmp -s "$work_dir/$profile.reference.macros.surface" \
        "$work_dir/$profile.candidate.macros.surface"; then
        diff -u "$work_dir/$profile.reference.macros.surface" \
            "$work_dir/$profile.candidate.macros.surface" || true
        fail "$profile project KLOG macro surface differs from pinned musl"
    fi
done

printf 'x86 pinned-musl/project C/C++ <sys/klog.h> source form: PASS (%s profiles; no KLOG macros; compile-only)\n' \
    "$EXPECTED_PROFILE_COUNT"
