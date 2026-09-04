#!/usr/bin/env bash
# Native Linux/x86-64 <sched.h> cpu_set_t source-form and visibility gate.
#
# Pinned musl 1.2.6 is the public-header oracle. Both trees are compiled with
# raw Clang builtin headers plus exactly their own include root, matching the
# checked declaration-form matrix profiles. This is compile-only header
# evidence: it neither selects scheduler/affinity runtime behavior nor changes
# CPU-set macro, allocator, or byte-string ownership.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly MUSL_ROOT=/opt/musl-1.2.6
readonly COMPILER=clang
readonly PROJECT_INCLUDE="$ROOT_DIR/include"
readonly C_PROBE="$ROOT_DIR/compat/x86_64/sched_cpu_set_source_form_probe.c"
readonly CXX_PROBE="$ROOT_DIR/compat/x86_64/sched_cpu_set_source_form_probe.cpp"
readonly CPU_SET_FORM='typedef struct cpu_set_t { unsigned long __bits[128/sizeof(long)]; } cpu_set_t;'
readonly X86_MARKER='#if defined(__x86_64__) /* pinned-musl cpu_set_t form; the AArch64 form stays frozen */'
readonly EXPECTED_PROFILE_COUNT=7
readonly -a PROFILES=(c11-gnu cxx17-gnu c11-strict c11-posix-2008 c11-xopen-700 c11-bsd cxx17-strict)

fail() {
    printf 'ERROR: x86 sched cpu_set_t source form: %s\n' "$*" >&2
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
        "$COMPILER" "$@"
}

profile_arguments() {
    case "$1" in
        c11-gnu|cxx17-gnu) printf '%s\n' '-D_GNU_SOURCE=1' ;;
        c11-strict|cxx17-strict) : ;;
        c11-posix-2008) printf '%s\n' '-D_POSIX_C_SOURCE=200809L' ;;
        c11-xopen-700) printf '%s\n' '-D_XOPEN_SOURCE=700' ;;
        c11-bsd) printf '%s\n' '-D_BSD_SOURCE=1' ;;
        *) fail "unknown feature profile: $1" ;;
    esac
}

profile_expects_visible_cpu_set() {
    case "$1" in
        c11-gnu|cxx17-gnu|cxx17-strict) return 0 ;;
        c11-strict|c11-posix-2008|c11-xopen-700|c11-bsd) return 1 ;;
        *) fail "unknown feature profile: $1" ;;
    esac
}

set_tree() {
    case "$1" in
        candidate) include_root="$PROJECT_INCLUDE" ;;
        reference) include_root="$MUSL_ROOT/include" ;;
        *) fail "unknown header tree: $1" ;;
    esac
    include_args=(-nostdinc -I "$include_root" -isystem "$compiler_builtin")
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

check_trace() {
    local tree="$1" profile="$2" trace="$3" root

    case "$tree" in
        candidate) root="$PROJECT_INCLUDE" ;;
        reference) root="$MUSL_ROOT/include" ;;
        *) fail "unknown header tree: $tree" ;;
    esac
    if trace_has_unapproved_path "$tree" "$trace"; then
        fail "$profile $tree trace escaped its declared header roots"
    fi
    for header in sched.h features.h bits/alltypes.h; do
        grep -Fq "$root/$header" "$trace" ||
            fail "$profile $tree trace omitted $root/$header"
    done
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
    local tree="$1" profile="$2" expectation="$3" trace="$4"
    local -a profile_args

    set_tree "$tree"
    set_language "$profile"
    mapfile -t profile_args < <(profile_arguments "$profile")
    run_compiler "${language_args[@]}" "${profile_args[@]}" \
        "${include_args[@]}" -D"$expectation" -H -fsyntax-only "$source" \
        > /dev/null 2>"$trace"
}

check_source_form() {
    local selected_form

    [ "$(grep -Fxc "$CPU_SET_FORM" "$MUSL_ROOT/include/sched.h")" -eq 1 ] ||
        fail "pinned musl cpu_set_t source form drifted"
    [ "$(grep -Fxc "$CPU_SET_FORM" "$PROJECT_INCLUDE/sched.h")" -eq 1 ] ||
        fail "project x86 cpu_set_t source form differs from pinned musl"
    selected_form="$(awk -v marker="$X86_MARKER" \
        '$0 == marker { if (getline) print; exit }' "$PROJECT_INCLUDE/sched.h")"
    [ "$selected_form" = "$CPU_SET_FORM" ] ||
        fail "project cpu_set_t source form is not selected by the x86 branch"
}

[ "$#" -eq 0 ] || fail "usage: $0"
require_native_linux_x86_64
for tool in awk clang env grep mapfile mktemp realpath sed tr uname; do
    require_tool "$tool"
done
[ -d "$MUSL_ROOT/include" ] || fail "missing pinned musl include tree"
[ -d "$PROJECT_INCLUDE" ] || fail "missing project include tree"
[ -f "$C_PROBE" ] || fail "missing C sched cpu_set_t probe"
[ -f "$CXX_PROBE" ] || fail "missing C++ sched cpu_set_t probe"
[ "${#PROFILES[@]}" -eq "$EXPECTED_PROFILE_COUNT" ] || fail "profile roster drifted"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
compiler_builtin="$(run_compiler -print-resource-dir)/include"
compiler_builtin="$(realpath "$compiler_builtin")"
[ -d "$compiler_builtin" ] || fail "Clang builtin include root is missing"

check_source_form
work_dir="$(mktemp -d /tmp/crabc-x86-64-sched-cpu-set-source-form.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT

for profile in "${PROFILES[@]}"; do
    for tree in reference candidate; do
        trace="$work_dir/$profile.$tree.trace"
        if profile_expects_visible_cpu_set "$profile"; then
            if ! compile_profile "$tree" "$profile" CRABC_EXPECT_CPU_SET_VISIBLE "$trace"; then
                fail "$profile $tree cpu_set_t visibility probe failed: $(first_diagnostic "$trace")"
            fi
        else
            if compile_profile "$tree" "$profile" CRABC_REQUIRE_CPU_SET_HIDDEN "$trace"; then
                fail "$profile $tree leaked cpu_set_t outside musl's GNU feature block"
            fi
            if grep -Fq 'CPU-set surface escaped its GNU profile' "$trace"; then
                fail "$profile $tree leaked CPU-set macros outside musl's GNU feature block"
            fi
            grep -Fq 'cpu_set_t' "$trace" ||
                fail "$profile $tree did not reject the hidden cpu_set_t name"
        fi
        check_trace "$tree" "$profile" "$trace"
    done
done

printf 'x86 pinned-musl/project C/C++ <sched.h> cpu_set_t source form: PASS (%s profiles; compile-only)\n' \
    "$EXPECTED_PROFILE_COUNT"
