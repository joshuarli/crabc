#!/usr/bin/env bash
# Native Linux/x86-64 direct <stdio.h>/<stdio_ext.h> source-form evidence.
#
# Pinned musl 1.2.6 is the public-header oracle. Both passes see raw compiler
# builtin headers plus only their own include root, which prevents an ambient
# libc from concealing declaration spelling, feature visibility, or include
# topology drift. The paired probes lock __isoc_va_list/restrict forms, the
# deliberately unqualified asprintf direction, and _STDIO_EXT_H rather than
# the frozen _CRABC_STDIO_EXT_H guard. This is compile-only header evidence:
# it does not select a stdio provider, alter permanent-stream coverage, or
# expand x86 support.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly MUSL_ROOT=/opt/musl-1.2.6
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly CANDIDATE_CC=/usr/bin/gcc
readonly PROJECT_INCLUDE="$ROOT_DIR/include"
readonly C_PROBE="$ROOT_DIR/compat/x86_64/stdio_header_source_form_probe.c"
readonly CXX_PROBE="$ROOT_DIR/compat/x86_64/stdio_header_source_form_probe.cpp"
readonly EXPECTED_PROFILE_COUNT=7
readonly -a PROFILES=(c11-gnu cxx17-gnu c11-strict c11-posix-2008 c11-xopen-700 c11-bsd cxx17-strict)

fail() {
    printf 'ERROR: x86 stdio header source form: %s\n' "$*" >&2
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

trace_has_unapproved_path() {
    local tree="$1" trace="$2" path

    while IFS= read -r path; do
        case "$tree" in
            candidate)
                case "$path" in
                    "$PROJECT_INCLUDE"/*|"$compiler_builtin"/*) ;;
                    *) return 0 ;;
                esac
                ;;
            reference)
                case "$path" in
                    "$MUSL_ROOT/include"/*|"$compiler_builtin"/*) ;;
                    *) return 0 ;;
                esac
                ;;
            *) fail "unknown header tree: $tree" ;;
        esac
    done < <(trace_paths "$trace")
    return 1
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
        *) fail "unknown header tree: $tree" ;;
    esac
    include_args=(-nostdinc -I "$include_root" -isystem "$compiler_builtin")
}

profile_arguments() {
    case "$1" in
        c11-gnu|cxx17-gnu)
            printf '%s\n' '-D_GNU_SOURCE'
            ;;
        c11-strict|cxx17-strict)
            printf '%s\n' \
                '-U_GNU_SOURCE' '-U_BSD_SOURCE' '-U_XOPEN_SOURCE' \
                '-U_POSIX_C_SOURCE' '-U_LARGEFILE64_SOURCE' '-U_DEFAULT_SOURCE'
            ;;
        c11-posix-2008)
            printf '%s\n' \
                '-U_GNU_SOURCE' '-U_BSD_SOURCE' '-U_XOPEN_SOURCE' \
                '-U_LARGEFILE64_SOURCE' '-U_DEFAULT_SOURCE' \
                '-D_POSIX_C_SOURCE=200809L'
            ;;
        c11-xopen-700)
            printf '%s\n' \
                '-U_GNU_SOURCE' '-U_BSD_SOURCE' '-U_POSIX_C_SOURCE' \
                '-U_LARGEFILE64_SOURCE' '-U_DEFAULT_SOURCE' '-D_XOPEN_SOURCE=700'
            ;;
        c11-bsd)
            printf '%s\n' \
                '-U_GNU_SOURCE' '-U_XOPEN_SOURCE' '-U_POSIX_C_SOURCE' \
                '-U_LARGEFILE64_SOURCE' '-U_DEFAULT_SOURCE' '-D_BSD_SOURCE'
            ;;
        *) fail "unknown feature profile: $1" ;;
    esac
}

set_language() {
    case "$1" in
        c11-*)
            language=c
            source="$C_PROBE"
            language_args=(-x c -std=c11)
            ;;
        cxx17-*)
            language=cxx
            source="$CXX_PROBE"
            language_args=(-x c++ -std=c++17 -nostdinc++)
            ;;
        *) fail "unknown language profile: $1" ;;
    esac
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
    local tree="$1" profile="$2" trace="$3" object="$4"
    local -a profile_args

    set_tree "$tree"
    set_language "$profile"
    mapfile -t profile_args < <(profile_arguments "$profile")
    if [ "$language" = c ]; then
        run_compiler "$compiler" "${language_args[@]}" "${profile_args[@]}" \
            "${include_args[@]}" -H -fsyntax-only "$source" > /dev/null 2>"$trace"
    else
        run_compiler "$compiler" "${language_args[@]}" "${profile_args[@]}" \
            "${include_args[@]}" -H -c "$source" -o "$object" > /dev/null 2>"$trace"
    fi
}

compile_direct_header() {
    local tree="$1" profile="$2" header="$3" trace="$4"
    local -a profile_args

    set_tree "$tree"
    set_language "$profile"
    mapfile -t profile_args < <(profile_arguments "$profile")
    printf '#include <%s>\n' "$header" | \
        run_compiler "$compiler" "${language_args[@]}" "${profile_args[@]}" \
            "${include_args[@]}" -H -fsyntax-only - > /dev/null 2>"$trace"
}

expected_direct_trace() {
    local root="$1" header="$2"

    case "$header" in
        stdio.h)
            printf '%s\n' \
                "$root/stdio.h" \
                "$root/features.h" \
                "$root/bits/alltypes.h"
            ;;
        stdio_ext.h)
            printf '%s\n' \
                "$root/stdio_ext.h" \
                "$root/stdio.h" \
                "$root/features.h" \
                "$root/bits/alltypes.h"
            ;;
        *) fail "unknown direct stdio header: $header" ;;
    esac
}

trace_tree_headers() {
    local root="$1" trace="$2"

    trace_paths "$trace" | awk -v root="$root/" 'index($0, root) == 1'
}

check_direct_trace() {
    local tree="$1" profile="$2" header="$3" trace="$4" root

    case "$tree" in
        candidate) root="$PROJECT_INCLUDE" ;;
        reference) root="$MUSL_ROOT/include" ;;
        *) fail "unknown header tree: $tree" ;;
    esac
    if trace_has_unapproved_path "$tree" "$trace"; then
        fail "$profile $tree direct <$header> trace escaped its declared header roots"
    fi
    if ! diff -u <(expected_direct_trace "$root" "$header") \
        <(trace_tree_headers "$root" "$trace"); then
        fail "$profile $tree direct <$header> include topology diverges from pinned musl"
    fi
}

check_probe_trace() {
    local tree="$1" profile="$2" trace="$3" root

    case "$tree" in
        candidate) root="$PROJECT_INCLUDE" ;;
        reference) root="$MUSL_ROOT/include" ;;
        *) fail "unknown header tree: $tree" ;;
    esac
    if trace_has_unapproved_path "$tree" "$trace"; then
        fail "$profile $tree probe trace escaped its declared header roots"
    fi
    for header in stdio.h stdio_ext.h features.h bits/alltypes.h; do
        grep -Fq "$root/$header" "$trace" ||
            fail "$profile $tree probe trace omitted $root/$header"
    done
}

expected_cxx_symbols() {
    printf '%s\n' fopen freopen printf vprintf __fsetlocking __fbufsize
    case "$1" in
        cxx17-gnu) printf '%s\n' asprintf vasprintf ;;
    esac
}

check_cxx_linkage() {
    local tree="$1" profile="$2" object="$3" undefined symbol

    undefined="$(nm --undefined-only "$object" | awk '{print $NF}')"
    while IFS= read -r symbol; do
        [ -n "$symbol" ] || continue
        printf '%s\n' "$undefined" | grep -Fxq "$symbol" ||
            fail "$profile $tree C++ probe lost unmangled $symbol linkage"
    done < <(expected_cxx_symbols "$profile")
    if printf '%s\n' "$undefined" | grep -Eq \
        '_Z.*(fopen|freopen|printf|vprintf|asprintf|vasprintf|__fsetlocking|__fbufsize)'; then
        fail "$profile $tree C++ probe retained a mangled stdio reference"
    fi
}

macro_surface() {
    awk '
        /^#define (_STDIO_H|_STDIO_EXT_H|_CRABC_STDIO_EXT_H|__DEFINED_va_list|__NEED_va_list)([[:space:]]|$)/ {
            print
        }
    ' | LC_ALL=C sort
}

expected_lfs_surface() {
    printf '%s\n' \
        '#define fopen64 fopen' \
        '#define fgetpos64 fgetpos' \
        '#define fpos64_t fpos_t' \
        '#define freopen64 freopen' \
        '#define fseeko64 fseeko' \
        '#define fsetpos64 fsetpos' \
        '#define ftello64 ftello' \
        '#define off64_t off_t' \
        '#define tmpfile64 tmpfile' | LC_ALL=C sort
}

lfs_surface() {
    awk '
        /^#define (tmpfile64|fopen64|freopen64|fseeko64|ftello64|fgetpos64|fsetpos64|fpos64_t|off64_t)([[:space:]]|$)/ {
            print
        }
    ' | LC_ALL=C sort
}

extract_macro_surface() {
    local tree="$1" profile="$2" macros="$3" surface="$4" diagnostic="$5"
    local -a profile_args

    set_tree "$tree"
    set_language "$profile"
    mapfile -t profile_args < <(profile_arguments "$profile")
    if ! run_compiler "$compiler" "${language_args[@]}" "${profile_args[@]}" \
        "${include_args[@]}" -dM -E -include stdio_ext.h - < /dev/null \
        >"$macros" 2>"$diagnostic"; then
        fail "$profile $tree $language stdio macro extraction failed: $(first_diagnostic "$diagnostic")"
    fi
    macro_surface < "$macros" > "$surface"
    grep -Eq '^#define _STDIO_H([[:space:]]|$)' "$surface" ||
        fail "$profile $tree did not expose the musl stdio guard"
    grep -Eq '^#define _STDIO_EXT_H([[:space:]]|$)' "$surface" ||
        fail "$profile $tree did not expose the musl stdio_ext guard"
    if grep -Fq '_CRABC_STDIO_EXT_H' "$surface"; then
        fail "$profile $tree leaked the frozen non-x86 stdio_ext guard"
    fi
    case "$profile" in
        c11-strict|cxx17-strict)
            if grep -Fq '__DEFINED_va_list' "$surface"; then
                fail "$profile $tree exposes va_list outside musl's feature block"
            fi
            ;;
        *)
            grep -Fq '__DEFINED_va_list' "$surface" ||
                fail "$profile $tree failed to expose feature-gated va_list"
            ;;
    esac
}

extract_lfs_surface() {
    local tree="$1" profile="$2" macros="$3" surface="$4" diagnostic="$5"
    local -a profile_args

    set_tree "$tree"
    set_language "$profile"
    mapfile -t profile_args < <(profile_arguments "$profile")
    if ! run_compiler "$compiler" "${language_args[@]}" "${profile_args[@]}" \
        -D_LARGEFILE64_SOURCE "${include_args[@]}" -dM -E -include stdio.h - < /dev/null \
        >"$macros" 2>"$diagnostic"; then
        fail "$profile $tree $language LFS macro extraction failed: $(first_diagnostic "$diagnostic")"
    fi
    lfs_surface < "$macros" > "$surface"
    if ! diff -u <(expected_lfs_surface) "$surface"; then
        fail "$profile $tree LFS source aliases diverge from pinned musl"
    fi
}

[ "$#" -eq 0 ] || fail "usage: $0"
require_native_linux_x86_64
for tool in awk cmp diff env grep mapfile mktemp nm realpath sed sort tr uname; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -x "$CANDIDATE_CC" ] || fail "missing raw native candidate compiler"
[ -d "$MUSL_ROOT/include" ] || fail "missing pinned musl include tree"
[ -d "$PROJECT_INCLUDE" ] || fail "missing project include tree"
[ -f "$C_PROBE" ] || fail "missing C stdio source-form probe"
[ -f "$CXX_PROBE" ] || fail "missing C++ stdio source-form probe"
[ "${#PROFILES[@]}" = "$EXPECTED_PROFILE_COUNT" ] || fail "profile roster drifted"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

compiler_builtin="$(run_compiler "$CANDIDATE_CC" -print-file-name=include)"
compiler_builtin="$(realpath "$compiler_builtin")"
[ -d "$compiler_builtin" ] || fail "raw compiler builtin include root is missing"

work_dir="$(mktemp -d /tmp/crabc-x86-64-stdio-header-source-form.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT

for profile in "${PROFILES[@]}"; do
    for tree in reference candidate; do
        probe_trace="$work_dir/$profile.$tree.probe.trace"
        object="$work_dir/$profile.$tree.o"
        if ! compile_probe "$tree" "$profile" "$probe_trace" "$object"; then
            fail "$profile $tree direct stdio probe failed: $(first_diagnostic "$probe_trace")"
        fi
        check_probe_trace "$tree" "$profile" "$probe_trace"
        if [ "${profile#cxx17-}" != "$profile" ]; then
            check_cxx_linkage "$tree" "$profile" "$object"
        fi

        for header in stdio.h stdio_ext.h; do
            direct_trace="$work_dir/$profile.$tree.$header.trace"
            if ! compile_direct_header "$tree" "$profile" "$header" "$direct_trace"; then
                fail "$profile $tree direct <$header> probe failed: $(first_diagnostic "$direct_trace")"
            fi
            check_direct_trace "$tree" "$profile" "$header" "$direct_trace"
        done

        macros="$work_dir/$profile.$tree.macros"
        surface="$work_dir/$profile.$tree.surface"
        diagnostic="$work_dir/$profile.$tree.macros.trace"
        extract_macro_surface "$tree" "$profile" "$macros" "$surface" "$diagnostic"

        lfs_macros="$work_dir/$profile.$tree.lfs.macros"
        lfs_surface_file="$work_dir/$profile.$tree.lfs.surface"
        lfs_diagnostic="$work_dir/$profile.$tree.lfs.trace"
        extract_lfs_surface "$tree" "$profile" "$lfs_macros" "$lfs_surface_file" "$lfs_diagnostic"
    done
    if ! cmp -s "$work_dir/$profile.reference.surface" "$work_dir/$profile.candidate.surface"; then
        diff -u "$work_dir/$profile.reference.surface" "$work_dir/$profile.candidate.surface" || true
        fail "$profile project stdio/stdio_ext macro visibility differs from pinned musl"
    fi
    if ! cmp -s "$work_dir/$profile.reference.lfs.surface" "$work_dir/$profile.candidate.lfs.surface"; then
        diff -u "$work_dir/$profile.reference.lfs.surface" "$work_dir/$profile.candidate.lfs.surface" || true
        fail "$profile project stdio LFS aliases differ from pinned musl"
    fi
done

printf 'x86 pinned-musl/project C/C++ <stdio.h>/<stdio_ext.h> source form: PASS (%s profiles; compile-only)\n' \
    "$EXPECTED_PROFILE_COUNT"
