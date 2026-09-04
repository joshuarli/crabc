#!/usr/bin/env bash
# Native x86-64 <sys/mman.h> MCL_ONFAULT source-form evidence.
#
# Pinned musl 1.2.6 is the x86 public-header oracle. Both x86 passes see only
# raw compiler builtin headers and their own header tree, preventing an ambient
# libc or Linux/UAPI wrapper from supplying the lock flag. Musl exposes the
# literal unconditionally; the candidate selects that form only for x86-64,
# while the AArch64 pass retains its existing MCL/mapping boundary and syntax.
# This is compile-only header evidence. It neither selects an mlock provider
# nor makes any mlockall/mmap runtime claim.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly MUSL_ROOT=/opt/musl-1.2.6
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly CANDIDATE_CC=/usr/bin/gcc
readonly AARCH64_CC=/usr/bin/clang
readonly PROJECT_INCLUDE="$ROOT_DIR/include"
readonly C_PROBE="$ROOT_DIR/compat/x86_64/mman_mcl_onfault_source_form_probe.c"
readonly CXX_PROBE="$ROOT_DIR/compat/x86_64/mman_mcl_onfault_source_form_probe.cpp"
readonly EXPECTED_PROFILE_COUNT=7
readonly -a PROFILES=(c11-gnu cxx17-gnu c11-strict c11-posix-2008 c11-xopen-700 c11-bsd cxx17-strict)

fail() {
    printf 'ERROR: x86 sys/mman.h MCL_ONFAULT source form: %s\n' "$*" >&2
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

first_diagnostic() {
    local diagnostic="$1" line

    line="$(sed -n '/fatal error:/p; /error:/p' "$diagnostic" | sed -n '1p' || true)"
    if [ -n "$line" ]; then
        printf '%s\n' "$line" | tr '\t\r\n' ' '
    else
        printf '%s\n' 'no compiler diagnostic'
    fi
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

check_x86_trace() {
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
    for header in sys/mman.h features.h bits/alltypes.h bits/mman.h; do
        grep -Fq "$root/$header" "$trace" ||
            fail "$profile $tree direct <sys/mman.h> trace omitted $root/$header"
    done
    if trace_paths "$trace" | grep -Eq '/(linux|asm)/'; then
        fail "$profile $tree direct <sys/mman.h> leaked a Linux/UAPI header"
    fi
}

compile_x86_profile() {
    local tree="$1" profile="$2" trace="$3"
    local -a profile_args

    set_x86_tree "$tree"
    set_language "$profile"
    mapfile -t profile_args < <(profile_arguments "$profile")
    if ! run_compiler "$compiler" "${language_args[@]}" "${profile_args[@]}" \
        "${include_args[@]}" '-DCRABC_MMAN_HEADER=<sys/mman.h>' -H -fsyntax-only "$source" \
        > /dev/null 2>"$trace"; then
        fail "$profile $tree direct <sys/mman.h> syntax failed: $(first_diagnostic "$trace")"
    fi
    check_x86_trace "$tree" "$profile" "$trace"
}

macro_surface() {
    awk '
        /^#define (MCL_CURRENT|MCL_FUTURE|MCL_ONFAULT|MAP_32BIT)([[:space:]]|$)/ { print }
    ' | LC_ALL=C sort
}

expected_x86_surface() {
    printf '%s\n' \
        '#define MAP_32BIT 0x40' \
        '#define MCL_CURRENT 1' \
        '#define MCL_FUTURE 2' \
        '#define MCL_ONFAULT 4' | LC_ALL=C sort
}

extract_x86_surface() {
    local tree="$1" profile="$2" surface="$3" diagnostic="$4"
    local raw="$surface.raw"
    local -a profile_args

    set_x86_tree "$tree"
    set_language "$profile"
    mapfile -t profile_args < <(profile_arguments "$profile")
    if ! run_compiler "$compiler" "${language_args[@]}" "${profile_args[@]}" \
        "${include_args[@]}" -dM -E -include sys/mman.h - < /dev/null \
        >"$raw" 2>"$diagnostic"; then
        fail "$profile $tree <sys/mman.h> macro extraction failed: $(first_diagnostic "$diagnostic")"
    fi
    macro_surface < "$raw" > "$surface"
}

check_aarch64_trace() {
    local profile="$1" trace="$2" path

    while IFS= read -r path; do
        case "$path" in
            "$PROJECT_INCLUDE"/*|"$aarch64_builtin"/*) ;;
            *) fail "$profile frozen-AArch64 trace escaped project/builtin roots: $path" ;;
        esac
    done < <(trace_paths "$trace")
    grep -Fq "$PROJECT_INCLUDE/sys/mman.h" "$trace" ||
        fail "$profile frozen-AArch64 trace omitted project <sys/mman.h>"
    grep -Fq "$PROJECT_INCLUDE/sys/types.h" "$trace" ||
        fail "$profile frozen-AArch64 trace lost its existing <sys/types.h> branch"
    if grep -Fq "$PROJECT_INCLUDE/bits/mman.h" "$trace"; then
        fail "$profile frozen-AArch64 trace leaked the x86 mapping header"
    fi
    if trace_paths "$trace" | grep -Eq '/(linux|asm)/'; then
        fail "$profile frozen-AArch64 direct <sys/mman.h> leaked a Linux/UAPI header"
    fi
}

compile_aarch64_profile() {
    local profile="$1" trace="$2"
    local -a profile_args

    set_language "$profile"
    mapfile -t profile_args < <(profile_arguments "$profile")
    if ! run_compiler "$AARCH64_CC" --target=aarch64-unknown-linux-musl \
        "${language_args[@]}" "${profile_args[@]}" -nostdinc -I "$PROJECT_INCLUDE" \
        -isystem "$aarch64_builtin" '-DCRABC_MMAN_HEADER=<sys/mman.h>' -H -fsyntax-only "$source" \
        > /dev/null 2>"$trace"; then
        fail "$profile frozen-AArch64 direct <sys/mman.h> syntax failed: $(first_diagnostic "$trace")"
    fi
    check_aarch64_trace "$profile" "$trace"
}

expected_aarch64_surface() {
    printf '%s\n' \
        '#define MCL_CURRENT 1' \
        '#define MCL_FUTURE 2' | LC_ALL=C sort
}

extract_aarch64_surface() {
    local profile="$1" surface="$2" diagnostic="$3"
    local raw="$surface.raw"
    local -a profile_args

    set_language "$profile"
    mapfile -t profile_args < <(profile_arguments "$profile")
    if ! run_compiler "$AARCH64_CC" --target=aarch64-unknown-linux-musl \
        "${language_args[@]}" "${profile_args[@]}" -nostdinc -I "$PROJECT_INCLUDE" \
        -isystem "$aarch64_builtin" -dM -E -include sys/mman.h - < /dev/null \
        >"$raw" 2>"$diagnostic"; then
        fail "$profile frozen-AArch64 <sys/mman.h> macro extraction failed: $(first_diagnostic "$diagnostic")"
    fi
    macro_surface < "$raw" > "$surface"
}

[ "$#" -eq 0 ] || fail "usage: $0"
require_native_linux_x86_64
for tool in awk cmp diff env grep mapfile mktemp realpath sed sort tr uname; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -x "$CANDIDATE_CC" ] || fail "missing raw native candidate compiler"
[ -x "$AARCH64_CC" ] || fail "missing target-capable clang"
[ -d "$MUSL_ROOT/include" ] || fail "missing pinned musl include tree"
[ -d "$PROJECT_INCLUDE" ] || fail "missing project include tree"
[ -f "$C_PROBE" ] || fail "missing C MCL_ONFAULT source-form probe"
[ -f "$CXX_PROBE" ] || fail "missing C++ MCL_ONFAULT source-form probe"
[ "${#PROFILES[@]}" -eq "$EXPECTED_PROFILE_COUNT" ] || fail "profile roster drifted"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

x86_builtin="$(run_compiler "$CANDIDATE_CC" -print-file-name=include)"
x86_builtin="$(realpath "$x86_builtin")"
[ -d "$x86_builtin" ] || fail "raw candidate compiler builtin include root is missing"
aarch64_builtin="$(run_compiler "$AARCH64_CC" -print-resource-dir)/include"
aarch64_builtin="$(realpath "$aarch64_builtin")"
[ -d "$aarch64_builtin" ] || fail "AArch64 compiler builtin include root is missing"

work_dir="$(mktemp -d /tmp/crabc-x86-64-mman-mcl-onfault-source-form.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT

for profile in "${PROFILES[@]}"; do
    for tree in reference candidate; do
        trace="$work_dir/$profile.$tree.trace"
        compile_x86_profile "$tree" "$profile" "$trace"
        surface="$work_dir/$profile.$tree.surface"
        diagnostic="$work_dir/$profile.$tree.macros.trace"
        extract_x86_surface "$tree" "$profile" "$surface" "$diagnostic"
        if ! cmp -s <(expected_x86_surface) "$surface"; then
            diff -u <(expected_x86_surface) "$surface" || true
            fail "$profile $tree MCL_ONFAULT/x86 mapping macro source form diverges from musl"
        fi
    done
    if ! cmp -s "$work_dir/$profile.reference.surface" "$work_dir/$profile.candidate.surface"; then
        diff -u "$work_dir/$profile.reference.surface" "$work_dir/$profile.candidate.surface" || true
        fail "$profile project MCL_ONFAULT source form diverges from pinned musl"
    fi

    aarch64_trace="$work_dir/$profile.aarch64.trace"
    compile_aarch64_profile "$profile" "$aarch64_trace"
    aarch64_surface="$work_dir/$profile.aarch64.surface"
    aarch64_diagnostic="$work_dir/$profile.aarch64.macros.trace"
    extract_aarch64_surface "$profile" "$aarch64_surface" "$aarch64_diagnostic"
    if ! cmp -s <(expected_aarch64_surface) "$aarch64_surface"; then
        diff -u <(expected_aarch64_surface) "$aarch64_surface" || true
        fail "$profile changed the frozen AArch64 MCL/mapping macro boundary"
    fi
done

printf 'x86 pinned-musl/project C/C++ <sys/mman.h> MCL_ONFAULT source form: PASS (%s profiles; frozen AArch64 syntax/forms)\n' \
    "$EXPECTED_PROFILE_COUNT"
