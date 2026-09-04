#!/usr/bin/env bash
# Native Linux/x86-64 sys/sysmacros.h source-form evidence.
#
# Pinned musl 1.2.6 owns the x86 guard and exact device-number macro forms.
# This is a compile-only public-header boundary check: it adds no device,
# filesystem, UAPI, runtime-provider, capability, or support claim. The
# candidate's non-x86 body is separately compiled as AArch64 and held to its
# frozen macro surface.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly MUSL_ROOT=/opt/musl-1.2.6
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly CANDIDATE_CC=/usr/bin/gcc
readonly AARCH64_CC=/usr/bin/clang
readonly PROJECT_INCLUDE="$ROOT_DIR/include"
readonly C_PROBE="$ROOT_DIR/compat/x86_64/sysmacros_header_source_form_probe.c"
readonly CXX_PROBE="$ROOT_DIR/compat/x86_64/sysmacros_header_source_form_probe.cpp"
readonly EXPECTED_PROFILE_COUNT=7
readonly -a PROFILES=(c11-gnu cxx17-gnu c11-strict c11-posix-2008 c11-xopen-700 c11-bsd cxx17-strict)

fail() {
    printf 'ERROR: x86 sys/sysmacros.h source form: %s\n' "$*" >&2
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
            source="$C_PROBE"
            language_args=(-x c -std=c11)
            ;;
        cxx17-*)
            source="$CXX_PROBE"
            language_args=(-x c++ -std=c++17 -nostdinc++)
            ;;
        *) fail "unknown language profile: $1" ;;
    esac
}

set_x86_tree() {
    case "$1" in
        reference)
            compiler="$ORACLE_CC"
            include_root="$MUSL_ROOT/include"
            ;;
        candidate)
            compiler="$CANDIDATE_CC"
            include_root="$PROJECT_INCLUDE"
            ;;
        *) fail "unknown x86 header tree: $1" ;;
    esac
    include_args=(-nostdinc -I "$include_root" -isystem "$x86_builtin")
}

trace_paths() {
    sed -n -E 's/^[. ]+ (\/[^[:space:]]+).*$/\1/p' "$1"
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

check_direct_trace() {
    local tree="$1" profile="$2" trace="$3" root path
    case "$tree" in
        reference) root="$MUSL_ROOT/include" ;;
        candidate) root="$PROJECT_INCLUDE" ;;
        *) fail "unknown x86 header tree: $tree" ;;
    esac
    while IFS= read -r path; do
        case "$path" in
            "$root"/*|"$x86_builtin"/*) ;;
            *) fail "$profile $tree trace escaped its declared header roots: $path" ;;
        esac
    done < <(trace_paths "$trace")
    grep -Fq "$root/sys/sysmacros.h" "$trace" ||
        fail "$profile $tree trace omitted $root/sys/sysmacros.h"
    [ "$(trace_paths "$trace" | wc -l)" -eq 1 ] ||
        fail "$profile $tree direct sys/sysmacros.h inclusion acquired transitive headers"
    if trace_paths "$trace" | grep -Eq '/(linux|asm)/'; then
        fail "$profile $tree direct sys/sysmacros.h leaked a Linux/UAPI header"
    fi
}

compile_x86_profile() {
    local tree="$1" profile="$2" trace="$3"
    local -a profile_args=()
    set_x86_tree "$tree"
    set_language "$profile"
    mapfile -t profile_args < <(profile_arguments "$profile")
    if ! run_compiler "$compiler" "${language_args[@]}" "${profile_args[@]}" \
        "${include_args[@]}" -H -fsyntax-only "$source" >/dev/null 2>"$trace"; then
        fail "$profile $tree direct sys/sysmacros.h syntax failed: $(first_diagnostic "$trace")"
    fi
    check_direct_trace "$tree" "$profile" "$trace"
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
    local extracted="$work_dir/sysmacros.x86"
    if ! extract_x86_branch "$PROJECT_INCLUDE/sys/sysmacros.h" >"$extracted"; then
        fail "project sys/sysmacros.h lacks an x86 source-form branch"
    fi
    if ! cmp -s "$MUSL_ROOT/include/sys/sysmacros.h" "$extracted"; then
        diff -u "$MUSL_ROOT/include/sys/sysmacros.h" "$extracted" || true
        fail "project x86 sys/sysmacros.h body differs from pinned musl"
    fi
}

macro_surface() {
    awk '
        /^#define (_SYS_SYSMACROS_H|_CRABC_SYS_SYSMACROS_H|major|minor|makedev)([[:space:]]|\()/ {
            if ($2 == "_SYS_SYSMACROS_H" || $2 == "_CRABC_SYS_SYSMACROS_H") {
                sub(/[[:space:]]+$/, "")
            }
            print
        }
    ' | LC_ALL=C sort
}

extract_x86_surface() {
    local tree="$1" profile="$2" surface="$3" diagnostic="$4"
    local -a profile_args=()
    set_x86_tree "$tree"
    set_language "$profile"
    mapfile -t profile_args < <(profile_arguments "$profile")
    if ! run_compiler "$compiler" "${language_args[@]}" "${profile_args[@]}" \
        "${include_args[@]}" -dM -E -include sys/sysmacros.h - < /dev/null \
        >"$surface.raw" 2>"$diagnostic"; then
        fail "$profile $tree sys/sysmacros.h macro extraction failed: $(first_diagnostic "$diagnostic")"
    fi
    macro_surface < "$surface.raw" > "$surface"
}

check_aarch64_trace() {
    local profile="$1" trace="$2" path
    while IFS= read -r path; do
        case "$path" in
            "$PROJECT_INCLUDE"/*|"$aarch64_builtin"/*) ;;
            *) fail "$profile frozen-AArch64 trace escaped project/builtin roots: $path" ;;
        esac
    done < <(trace_paths "$trace")
    grep -Fq "$PROJECT_INCLUDE/sys/sysmacros.h" "$trace" ||
        fail "$profile frozen-AArch64 trace omitted project sys/sysmacros.h"
    [ "$(trace_paths "$trace" | wc -l)" -eq 1 ] ||
        fail "$profile frozen-AArch64 sys/sysmacros.h inclusion acquired transitive headers"
    if trace_paths "$trace" | grep -Eq '/(linux|asm)/'; then
        fail "$profile frozen-AArch64 sys/sysmacros.h leaked a Linux/UAPI header"
    fi
}

compile_aarch64_profile() {
    local profile="$1" trace="$2"
    local -a profile_args=()
    set_language "$profile"
    mapfile -t profile_args < <(profile_arguments "$profile")
    if ! printf '%s\n' '#include <sys/sysmacros.h>' | run_compiler "$AARCH64_CC" --target=aarch64-unknown-linux-musl \
        "${language_args[@]}" "${profile_args[@]}" -nostdinc -I "$PROJECT_INCLUDE" \
        -isystem "$aarch64_builtin" -include sys/sysmacros.h -H -fsyntax-only - \
        >/dev/null 2>"$trace"; then
        fail "$profile frozen-AArch64 direct sys/sysmacros.h syntax failed: $(first_diagnostic "$trace")"
    fi
    check_aarch64_trace "$profile" "$trace"
}

expected_aarch64_surface() {
    printf '%s\n' \
        '#define _CRABC_SYS_SYSMACROS_H' \
        '#define major(value) ((unsigned)((((value) >> 31 >> 1) & 0xfffff000) | (((value) >> 8) & 0x00000fff)))' \
        '#define minor(value) ((unsigned)((((value) >> 12) & 0xffffff00) | ((value) & 0x000000ff)))' \
        '#define makedev(major_value,minor_value) ((((major_value) & 0xfffff000ULL) << 32) | (((major_value) & 0x00000fffULL) << 8) | (((minor_value) & 0xffffff00ULL) << 12) | ((minor_value) & 0x000000ffULL))' \
        | LC_ALL=C sort
}

extract_aarch64_surface() {
    local profile="$1" surface="$2" diagnostic="$3"
    local -a profile_args=()
    set_language "$profile"
    mapfile -t profile_args < <(profile_arguments "$profile")
    if ! run_compiler "$AARCH64_CC" --target=aarch64-unknown-linux-musl \
        "${language_args[@]}" "${profile_args[@]}" -nostdinc -I "$PROJECT_INCLUDE" \
        -isystem "$aarch64_builtin" -dM -E -include sys/sysmacros.h - < /dev/null \
        >"$surface.raw" 2>"$diagnostic"; then
        fail "$profile frozen-AArch64 sys/sysmacros.h macro extraction failed: $(first_diagnostic "$diagnostic")"
    fi
    macro_surface < "$surface.raw" > "$surface"
}

[ "$#" -eq 0 ] || fail "usage: $0"
require_native_linux_x86_64
for tool in awk cmp diff env grep mapfile mktemp realpath sed sort tr uname wc; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -x "$CANDIDATE_CC" ] || fail "missing raw native candidate compiler"
[ -x "$AARCH64_CC" ] || fail "missing target-capable clang"
[ -d "$MUSL_ROOT/include" ] || fail "missing pinned musl include tree"
[ -d "$PROJECT_INCLUDE" ] || fail "missing project include tree"
[ -f "$C_PROBE" ] || fail "missing C sys/sysmacros.h probe"
[ -f "$CXX_PROBE" ] || fail "missing C++ sys/sysmacros.h probe"
[ "${#PROFILES[@]}" -eq "$EXPECTED_PROFILE_COUNT" ] || fail "profile roster drifted"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
x86_builtin="$(run_compiler "$CANDIDATE_CC" -print-file-name=include)"
x86_builtin="$(realpath "$x86_builtin")"
[ -d "$x86_builtin" ] || fail "raw candidate compiler builtin include root is missing"
aarch64_builtin="$(run_compiler "$AARCH64_CC" -print-resource-dir)/include"
aarch64_builtin="$(realpath "$aarch64_builtin")"
[ -d "$aarch64_builtin" ] || fail "AArch64 compiler builtin include root is missing"

work_dir="$(mktemp -d /tmp/crabc-x86-64-sysmacros-header-source-form.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT

check_exact_x86_form
for profile in "${PROFILES[@]}"; do
    for tree in reference candidate; do
        trace="$work_dir/$profile.$tree.trace"
        compile_x86_profile "$tree" "$profile" "$trace"
        extract_x86_surface "$tree" "$profile" \
            "$work_dir/$profile.$tree.surface" "$work_dir/$profile.$tree.macros.trace"
    done
    if ! cmp -s "$work_dir/$profile.reference.surface" "$work_dir/$profile.candidate.surface"; then
        diff -u "$work_dir/$profile.reference.surface" "$work_dir/$profile.candidate.surface" || true
        fail "$profile project sys/sysmacros.h macro source form differs from pinned musl"
    fi

    aarch64_trace="$work_dir/$profile.aarch64.trace"
    compile_aarch64_profile "$profile" "$aarch64_trace"
    aarch64_surface="$work_dir/$profile.aarch64.surface"
    extract_aarch64_surface "$profile" "$aarch64_surface" "$work_dir/$profile.aarch64.macros.trace"
    if ! cmp -s <(expected_aarch64_surface) "$aarch64_surface"; then
        diff -u <(expected_aarch64_surface) "$aarch64_surface" || true
        fail "$profile changed the frozen AArch64 sys/sysmacros.h macro boundary"
    fi
done

printf 'x86 pinned-musl/project C/C++ <sys/sysmacros.h> source form: PASS (%s profiles; frozen AArch64 syntax/forms)\n' \
    "$EXPECTED_PROFILE_COUNT"
