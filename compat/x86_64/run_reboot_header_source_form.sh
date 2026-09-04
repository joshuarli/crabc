#!/usr/bin/env bash
# Native Linux/x86-64 direct <sys/reboot.h> source-form and visibility evidence.
#
# Pinned musl 1.2.6 is the public-header oracle.  Both trees use raw compiler
# builtin headers plus exactly their own include root, so an ambient libc
# cannot supply a reboot declaration or hide an unintended Linux-private
# macro.  This is compile-only header evidence: it does not select reboot's
# archive provider, runtime behavior, family promotion, or public support.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly MUSL_ROOT=/opt/musl-1.2.6
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly CANDIDATE_CC=/usr/bin/gcc
readonly PROJECT_INCLUDE="$ROOT_DIR/include"
readonly C_PROBE="$ROOT_DIR/compat/x86_64/reboot_header_source_form_probe.c"
readonly CXX_PROBE="$ROOT_DIR/compat/x86_64/reboot_header_source_form_probe.cpp"
readonly EXPECTED_PROFILE_COUNT=7
readonly -a PROFILES=(c11-gnu cxx17-gnu c11-strict c11-posix-2008 c11-xopen-700 c11-bsd cxx17-strict)

fail() {
    printf 'ERROR: x86 sys/reboot.h source form: %s\n' "$*" >&2
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
        c11-gnu|cxx17-gnu) printf '%s\n' '-D_GNU_SOURCE' ;;
        c11-strict|cxx17-strict) : ;;
        c11-posix-2008) printf '%s\n' '-D_POSIX_C_SOURCE=200809L' ;;
        c11-xopen-700) printf '%s\n' '-D_XOPEN_SOURCE=700' ;;
        c11-bsd) printf '%s\n' '-D_BSD_SOURCE' ;;
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

compile_profile() {
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

check_trace() {
    local tree="$1" profile="$2" trace="$3" root path_count

    case "$tree" in
        candidate) root="$PROJECT_INCLUDE" ;;
        reference) root="$MUSL_ROOT/include" ;;
        *) fail "unknown header tree: $tree" ;;
    esac
    if trace_has_unapproved_path "$tree" "$trace"; then
        fail "$profile $tree trace escaped its declared header roots"
    fi
    grep -Fq "$root/sys/reboot.h" "$trace" ||
        fail "$profile $tree trace omitted $root/sys/reboot.h"
    path_count="$(trace_paths "$trace" | wc -l)"
    [ "$path_count" -eq 1 ] ||
        fail "$profile $tree direct sys/reboot.h inclusion acquired $path_count headers"
}

check_cxx_linkage() {
    local tree="$1" profile="$2" object="$3" undefined

    undefined="$(nm --undefined-only "$object")"
    printf '%s\n' "$undefined" | grep -Eq '[[:space:]]reboot$' ||
        fail "$profile $tree C++ probe lost unmangled reboot linkage"
    if printf '%s\n' "$undefined" | grep -Eq '_Z[0-9].*reboot'; then
        fail "$profile $tree C++ probe retained a mangled reboot reference"
    fi
}

macro_surface() {
    awk '
        /^#define RB_(AUTOBOOT|HALT_SYSTEM|ENABLE_CAD|DISABLE_CAD|POWER_OFF|SW_SUSPEND|KEXEC)[[:space:]]/ {
            name = $2
            $1 = ""
            $2 = ""
            sub(/^[[:space:]]+/, "")
            print name "\t" $0
        }
    '
}

linux_reboot_surface() {
    awk '/^#define LINUX_REBOOT_/ { print }'
}

expected_macro_surface() {
    printf '%s\n' \
        $'RB_AUTOBOOT\t0x01234567' \
        $'RB_HALT_SYSTEM\t0xcdef0123' \
        $'RB_ENABLE_CAD\t0x89abcdef' \
        $'RB_DISABLE_CAD\t0' \
        $'RB_POWER_OFF\t0x4321fedc' \
        $'RB_SW_SUSPEND\t0xd000fce2' \
        $'RB_KEXEC\t0x45584543'
}

check_macro_surface() {
    local tree="$1" profile="$2" macros="$3" surface="$4" leaked="$5" diagnostic="$6"
    local -a profile_args

    set_tree "$tree"
    set_language "$profile"
    mapfile -t profile_args < <(profile_arguments "$profile")
    if ! run_compiler "$compiler" "${language_args[@]}" "${profile_args[@]}" \
        "${include_args[@]}" -dM -E -include sys/reboot.h - < /dev/null \
        >"$macros" 2>"$diagnostic"; then
        fail "$profile $tree $language macro extraction failed: $(first_diagnostic "$diagnostic")"
    fi
    macro_surface < "$macros" | LC_ALL=C sort > "$surface"
    linux_reboot_surface < "$macros" > "$leaked"
    [ "$(wc -l < "$surface")" -eq 7 ] ||
        fail "$profile $tree $language macro surface did not expose exactly seven RB_* names"
    if ! diff -u <(expected_macro_surface | LC_ALL=C sort) "$surface"; then
        fail "$profile $tree $language RB_* source form diverges from pinned musl"
    fi
    if [ -s "$leaked" ]; then
        fail "$profile $tree $language leaked Linux-private reboot macros: $(tr '\n' ' ' < "$leaked")"
    fi
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
[ -f "$C_PROBE" ] || fail "missing C sys/reboot.h probe"
[ -f "$CXX_PROBE" ] || fail "missing C++ sys/reboot.h probe"
[ "${#PROFILES[@]}" = "$EXPECTED_PROFILE_COUNT" ] || fail "profile roster drifted"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

compiler_builtin="$(run_compiler "$CANDIDATE_CC" -print-file-name=include)"
compiler_builtin="$(realpath "$compiler_builtin")"
[ -d "$compiler_builtin" ] || fail "raw compiler builtin include root is missing"

work_dir="$(mktemp -d /tmp/crabc-x86-64-reboot-header-source-form.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT

for profile in "${PROFILES[@]}"; do
    for tree in reference candidate; do
        trace="$work_dir/$profile.$tree.trace"
        object="$work_dir/$profile.$tree.o"
        if ! compile_profile "$tree" "$profile" "$trace" "$object"; then
            fail "$profile $tree direct sys/reboot.h probe failed: $(first_diagnostic "$trace")"
        fi
        check_trace "$tree" "$profile" "$trace"
        if [ "${profile#cxx17-}" != "$profile" ]; then
            check_cxx_linkage "$tree" "$profile" "$object"
        fi

        macros="$work_dir/$profile.$tree.macros"
        surface="$work_dir/$profile.$tree.surface"
        leaked="$work_dir/$profile.$tree.leaked"
        diagnostic="$work_dir/$profile.$tree.macros.trace"
        check_macro_surface "$tree" "$profile" "$macros" "$surface" "$leaked" "$diagnostic"
    done
    if ! cmp -s "$work_dir/$profile.reference.surface" "$work_dir/$profile.candidate.surface"; then
        diff -u "$work_dir/$profile.reference.surface" "$work_dir/$profile.candidate.surface" || true
        fail "$profile project RB_* macro surface differs from the pinned musl oracle"
    fi
done

printf 'x86 pinned-musl/project C/C++ <sys/reboot.h> source form: PASS (%s profiles; compile-only)\n' \
    "$EXPECTED_PROFILE_COUNT"
