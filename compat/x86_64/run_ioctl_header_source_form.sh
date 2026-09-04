#!/usr/bin/env bash
# Native x86-64 direct <bits/ioctl.h>/<sys/ioctl.h> source-form evidence.
#
# Pinned musl 1.2.6 is the x86 public-header oracle. The x86 passes see only
# raw compiler builtin headers and their own header tree, so an ambient libc or
# Linux/UAPI wrapper cannot supply ioctl forms. Musl's deliberately unguarded
# bits header, empty ioctl_fix sidecar, and six lowercase interface literals
# are selected only for x86-64. The AArch64 pass holds its legacy guard,
# uppercase literals, direct-header syntax, and no-sidecar topology frozen.
# This is compile-only header evidence: it selects no ioctl provider, runtime,
# UAPI boundary, PTY behavior, family completion, or public support.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly MUSL_ROOT=/opt/musl-1.2.6
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly CANDIDATE_CC=/usr/bin/gcc
readonly AARCH64_CC=/usr/bin/clang
readonly PROJECT_INCLUDE="$ROOT_DIR/include"
readonly C_PROBE="$ROOT_DIR/compat/x86_64/ioctl_header_source_form_probe.c"
readonly CXX_PROBE="$ROOT_DIR/compat/x86_64/ioctl_header_source_form_probe.cpp"
readonly EXPECTED_PROFILE_COUNT=7
readonly -a PROFILES=(c11-gnu cxx17-gnu c11-strict c11-posix-2008 c11-xopen-700 c11-bsd cxx17-strict)
readonly -a HEADERS=(bits/ioctl.h sys/ioctl.h)

fail() {
    printf 'ERROR: x86 ioctl header source form: %s\n' "$*" >&2
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

set_header_probe_arguments() {
    header_define="-DCRABC_IOCTL_SOURCE_FORM_HEADER=<$1>"
    header_probe_args=()
    case "$1" in
        bits/ioctl.h) ;;
        sys/ioctl.h) header_probe_args=(-DCRABC_IOCTL_SOURCE_FORM_SYS=1) ;;
        *) fail "unknown direct ioctl header: $1" ;;
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
    local tree="$1" profile="$2" header="$3" trace="$4" root path

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
    grep -Fq "$root/$header" "$trace" ||
        fail "$profile $tree direct <$header> trace omitted $root/$header"
    grep -Fq "$root/bits/ioctl.h" "$trace" ||
        fail "$profile $tree direct <$header> trace omitted bits/ioctl.h"
    grep -Fq "$root/bits/ioctl_fix.h" "$trace" ||
        fail "$profile $tree direct <$header> trace omitted musl's ioctl_fix sidecar"
    case "$header" in
        sys/ioctl.h)
            grep -Fq "$root/bits/alltypes.h" "$trace" ||
                fail "$profile $tree direct <sys/ioctl.h> trace omitted bits/alltypes.h"
            ;;
    esac
    if trace_paths "$trace" | grep -Eq '/(linux|asm)/'; then
        fail "$profile $tree direct <$header> leaked a Linux/UAPI header"
    fi
}

compile_x86_profile() {
    local tree="$1" profile="$2" header="$3" trace="$4"
    local -a profile_args

    set_x86_tree "$tree"
    set_language "$profile"
    set_header_probe_arguments "$header"
    mapfile -t profile_args < <(profile_arguments "$profile")
    if ! run_compiler "$compiler" "${language_args[@]}" "${profile_args[@]}" \
        "${include_args[@]}" "${header_probe_args[@]}" "$header_define" -H -fsyntax-only "$source" \
        > /dev/null 2>"$trace"; then
        fail "$profile $tree direct <$header> syntax failed: $(first_diagnostic "$trace")"
    fi
    check_x86_trace "$tree" "$profile" "$header" "$trace"
}

ioctl_macro_surface() {
    awk '
        $1 == "#define" {
            name = $2
            if (name == "_BITS_IOCTL_H" || name == "_IOC(a,b,c,d)" ||
                name == "_IOC_NONE" || name == "_IOC_WRITE" || name == "_IOC_READ" ||
                name == "_IO(a,b)" || name == "_IOW(a,b,c)" ||
                name == "_IOR(a,b,c)" || name == "_IOWR(a,b,c)" ||
                name == "SIOCSIFBRDADDR" || name == "SIOCGIFNETMASK" ||
                name == "SIOCSIFNETMASK" || name == "SIOCGIFMETRIC" ||
                name == "SIOCSIFMETRIC" || name == "SIOCGIFMEM") {
                if (name == "_BITS_IOCTL_H") print "#define _BITS_IOCTL_H"
                else print
            }
        }
    ' | LC_ALL=C sort
}

expected_x86_bits_surface() {
    printf '%s\n' \
        '#define _IO(a,b) _IOC(_IOC_NONE,(a),(b),0)' \
        '#define _IOC(a,b,c,d) ( ((a)<<30) | ((b)<<8) | (c) | ((d)<<16) )' \
        '#define _IOC_NONE 0U' \
        '#define _IOC_READ 2U' \
        '#define _IOC_WRITE 1U' \
        '#define _IOR(a,b,c) _IOC(_IOC_READ,(a),(b),sizeof(c))' \
        '#define _IOW(a,b,c) _IOC(_IOC_WRITE,(a),(b),sizeof(c))' \
        '#define _IOWR(a,b,c) _IOC(_IOC_READ|_IOC_WRITE,(a),(b),sizeof(c))'
}

expected_x86_surface() {
    {
        expected_x86_bits_surface
        case "$1" in
            bits/ioctl.h) ;;
            sys/ioctl.h)
                printf '%s\n' \
                    '#define SIOCGIFMEM 0x891f' \
                    '#define SIOCGIFMETRIC 0x891d' \
                    '#define SIOCGIFNETMASK 0x891b' \
                    '#define SIOCSIFBRDADDR 0x891a' \
                    '#define SIOCSIFMETRIC 0x891e' \
                    '#define SIOCSIFNETMASK 0x891c'
                ;;
            *) fail "unknown direct ioctl header: $1" ;;
        esac
    } | LC_ALL=C sort
}

extract_x86_surface() {
    local tree="$1" profile="$2" header="$3" surface="$4" diagnostic="$5"
    local raw="$surface.raw"
    local -a profile_args

    set_x86_tree "$tree"
    set_language "$profile"
    mapfile -t profile_args < <(profile_arguments "$profile")
    if ! run_compiler "$compiler" "${language_args[@]}" "${profile_args[@]}" \
        "${include_args[@]}" -dM -E -include "$header" - < /dev/null \
        >"$raw" 2>"$diagnostic"; then
        fail "$profile $tree <$header> macro extraction failed: $(first_diagnostic "$diagnostic")"
    fi
    ioctl_macro_surface < "$raw" > "$surface"
}

check_aarch64_trace() {
    local profile="$1" header="$2" trace="$3" path

    while IFS= read -r path; do
        case "$path" in
            "$PROJECT_INCLUDE"/*|"$aarch64_builtin"/*) ;;
            *) fail "$profile frozen-AArch64 trace escaped project/builtin roots: $path" ;;
        esac
    done < <(trace_paths "$trace")
    grep -Fq "$PROJECT_INCLUDE/$header" "$trace" ||
        fail "$profile frozen-AArch64 trace omitted project <$header>"
    grep -Fq "$PROJECT_INCLUDE/bits/ioctl.h" "$trace" ||
        fail "$profile frozen-AArch64 trace omitted bits/ioctl.h"
    if grep -Fq "$PROJECT_INCLUDE/bits/ioctl_fix.h" "$trace"; then
        fail "$profile frozen-AArch64 trace leaked the x86 ioctl_fix sidecar"
    fi
    case "$header" in
        bits/ioctl.h) ;;
        sys/ioctl.h)
            grep -Fq "$PROJECT_INCLUDE/bits/alltypes.h" "$trace" ||
                fail "$profile frozen-AArch64 trace lost bits/alltypes.h"
            ;;
        *) fail "unknown direct ioctl header: $header" ;;
    esac
    if trace_paths "$trace" | grep -Eq '/(linux|asm)/'; then
        fail "$profile frozen-AArch64 direct <$header> leaked a Linux/UAPI header"
    fi
}

compile_aarch64_profile() {
    local profile="$1" header="$2" trace="$3"
    local -a profile_args

    set_language "$profile"
    set_header_probe_arguments "$header"
    mapfile -t profile_args < <(profile_arguments "$profile")
    if ! run_compiler "$AARCH64_CC" --target=aarch64-unknown-linux-musl \
        "${language_args[@]}" "${profile_args[@]}" -nostdinc -I "$PROJECT_INCLUDE" \
        -isystem "$aarch64_builtin" "${header_probe_args[@]}" "$header_define" -H -fsyntax-only "$source" \
        > /dev/null 2>"$trace"; then
        fail "$profile frozen-AArch64 direct <$header> syntax failed: $(first_diagnostic "$trace")"
    fi
    check_aarch64_trace "$profile" "$header" "$trace"
}

expected_aarch64_bits_surface() {
    printf '%s\n' \
        '#define _BITS_IOCTL_H' \
        '#define _IO(a,b) _IOC(_IOC_NONE, (a), (b), 0)' \
        '#define _IOC(a,b,c,d) (((a) << 30) | ((b) << 8) | (c) | ((d) << 16))' \
        '#define _IOC_NONE 0U' \
        '#define _IOC_READ 2U' \
        '#define _IOC_WRITE 1U' \
        '#define _IOR(a,b,c) _IOC(_IOC_READ, (a), (b), sizeof(c))' \
        '#define _IOW(a,b,c) _IOC(_IOC_WRITE, (a), (b), sizeof(c))' \
        '#define _IOWR(a,b,c) _IOC(_IOC_READ | _IOC_WRITE, (a), (b), sizeof(c))'
}

expected_aarch64_surface() {
    {
        expected_aarch64_bits_surface
        case "$1" in
            bits/ioctl.h) ;;
            sys/ioctl.h)
                printf '%s\n' \
                    '#define SIOCGIFMEM 0x891F' \
                    '#define SIOCGIFMETRIC 0x891D' \
                    '#define SIOCGIFNETMASK 0x891B' \
                    '#define SIOCSIFBRDADDR 0x891A' \
                    '#define SIOCSIFMETRIC 0x891E' \
                    '#define SIOCSIFNETMASK 0x891C'
                ;;
            *) fail "unknown direct ioctl header: $1" ;;
        esac
    } | LC_ALL=C sort
}

extract_aarch64_surface() {
    local profile="$1" header="$2" surface="$3" diagnostic="$4"
    local raw="$surface.raw"
    local -a profile_args

    set_language "$profile"
    mapfile -t profile_args < <(profile_arguments "$profile")
    if ! run_compiler "$AARCH64_CC" --target=aarch64-unknown-linux-musl \
        "${language_args[@]}" "${profile_args[@]}" -nostdinc -I "$PROJECT_INCLUDE" \
        -isystem "$aarch64_builtin" -dM -E -include "$header" - < /dev/null \
        >"$raw" 2>"$diagnostic"; then
        fail "$profile frozen-AArch64 <$header> macro extraction failed: $(first_diagnostic "$diagnostic")"
    fi
    ioctl_macro_surface < "$raw" > "$surface"
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
[ -f "$C_PROBE" ] || fail "missing C ioctl source-form probe"
[ -f "$CXX_PROBE" ] || fail "missing C++ ioctl source-form probe"
[ "${#PROFILES[@]}" -eq "$EXPECTED_PROFILE_COUNT" ] || fail "profile roster drifted"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

x86_builtin="$(run_compiler "$CANDIDATE_CC" -print-file-name=include)"
x86_builtin="$(realpath "$x86_builtin")"
[ -d "$x86_builtin" ] || fail "raw candidate compiler builtin include root is missing"
aarch64_builtin="$(run_compiler "$AARCH64_CC" -print-resource-dir)/include"
aarch64_builtin="$(realpath "$aarch64_builtin")"
[ -d "$aarch64_builtin" ] || fail "AArch64 compiler builtin include root is missing"

work_dir="$(mktemp -d /tmp/crabc-x86-64-ioctl-header-source-form.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT

for profile in "${PROFILES[@]}"; do
    for header in "${HEADERS[@]}"; do
        header_id="${header//\//_}"
        for tree in reference candidate; do
            trace="$work_dir/$profile.$header_id.$tree.trace"
            compile_x86_profile "$tree" "$profile" "$header" "$trace"
            surface="$work_dir/$profile.$header_id.$tree.surface"
            diagnostic="$work_dir/$profile.$header_id.$tree.macros.trace"
            extract_x86_surface "$tree" "$profile" "$header" "$surface" "$diagnostic"
            if ! cmp -s <(expected_x86_surface "$header") "$surface"; then
                diff -u <(expected_x86_surface "$header") "$surface" || true
                fail "$profile $tree <$header> macro source form diverges from musl"
            fi
        done
        reference="$work_dir/$profile.$header_id.reference.surface"
        candidate="$work_dir/$profile.$header_id.candidate.surface"
        if ! cmp -s "$reference" "$candidate"; then
            diff -u "$reference" "$candidate" || true
            fail "$profile project <$header> macro source form diverges from pinned musl"
        fi

        aarch64_trace="$work_dir/$profile.$header_id.aarch64.trace"
        compile_aarch64_profile "$profile" "$header" "$aarch64_trace"
        aarch64_surface="$work_dir/$profile.$header_id.aarch64.surface"
        aarch64_diagnostic="$work_dir/$profile.$header_id.aarch64.macros.trace"
        extract_aarch64_surface "$profile" "$header" "$aarch64_surface" "$aarch64_diagnostic"
        if ! cmp -s <(expected_aarch64_surface "$header") "$aarch64_surface"; then
            diff -u <(expected_aarch64_surface "$header") "$aarch64_surface" || true
            fail "$profile <$header> changed the frozen AArch64 ioctl source form"
        fi
    done
done

printf 'x86 pinned-musl/project C/C++ ioctl header source form: PASS (%s profiles; frozen AArch64 syntax/forms)\n' \
    "$EXPECTED_PROFILE_COUNT"
