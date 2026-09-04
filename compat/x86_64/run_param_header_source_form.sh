#!/usr/bin/env bash
# Native Linux/x86-64 direct <sys/param.h> and <sys/resource.h> source forms.
#
# Pinned musl 1.2.6 supplies the public guard, macro-token, and transitive
# include oracle. The candidate pass has only the project tree and raw
# compiler builtin headers, so an ambient libc cannot supply a declaration or
# hide an include dependency. This is compile-only header evidence: it does
# not select resource runtime behavior or public platform support.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly MUSL_ROOT=/opt/musl-1.2.6
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly CANDIDATE_CC=/usr/bin/gcc
readonly PROJECT_INCLUDE="$ROOT_DIR/include"
readonly C_PROBE="$ROOT_DIR/compat/x86_64/param_header_source_form_probe.c"
readonly CXX_PROBE="$ROOT_DIR/compat/x86_64/param_header_source_form_probe.cpp"
readonly EXPECTED_PROFILE_COUNT=7
readonly -a PROFILES=(c11-gnu cxx17-gnu c11-strict c11-posix-2008 c11-xopen-700 c11-bsd cxx17-strict)

fail() {
    printf 'ERROR: x86 sys/param.h source form: %s\n' "$*" >&2
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
            language_args=(-x c -std=c11)
            source="$C_PROBE"
            ;;
        cxx17-*)
            language_args=(-x c++ -std=c++17 -nostdinc++)
            source="$CXX_PROBE"
            ;;
        *) fail "unknown language profile: $1" ;;
    esac
}

set_tree() {
    case "$1" in
        candidate)
            compiler="$CANDIDATE_CC"
            include_root="$PROJECT_INCLUDE"
            ;;
        reference)
            compiler="$ORACLE_CC"
            include_root="$MUSL_ROOT/include"
            ;;
        *) fail "unknown header tree: $1" ;;
    esac
    include_args=(-nostdinc -I "$include_root" -isystem "$compiler_builtin")
}

trace_paths() {
    sed -n -E 's/^[. ]+ (\/[^[:space:]]+).*$/\1/p' "$1"
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
            *) fail "unknown header tree: $tree" ;;
        esac
    done < <(trace_paths "$trace")
}

check_trace() {
    local tree="$1" header="$2" trace="$3" required

    case "$tree" in
        candidate) include_root="$PROJECT_INCLUDE" ;;
        reference) include_root="$MUSL_ROOT/include" ;;
        *) fail "unknown header tree: $tree" ;;
    esac
    check_trace_roots "$tree" "$trace"
    case "$header" in
        sys/param.h)
            for required in sys/param.h sys/resource.h endian.h limits.h; do
                grep -Fq "$include_root/$required" "$trace" ||
                    fail "$tree direct sys/param.h inclusion omitted $required"
            done
            ;;
        sys/resource.h)
            grep -Fq "$include_root/sys/resource.h" "$trace" ||
                fail "$tree direct sys/resource.h inclusion omitted its public header"
            ;;
        *) fail "unknown direct header: $header" ;;
    esac
}

compile_profile() {
    local tree="$1" profile="$2" header="$3" trace="$4" object="$5"
    local -a profile_args probe_args=()

    set_tree "$tree"
    set_language "$profile"
    mapfile -t profile_args < <(profile_arguments "$profile")
    case "$header" in
        sys/param.h) ;;
        sys/resource.h) probe_args=(-DCRABC_PARAM_HEADER_SOURCE_FORM_DIRECT_RESOURCE) ;;
        *) fail "unknown direct header: $header" ;;
    esac
    run_compiler "$compiler" "${language_args[@]}" "${profile_args[@]}" \
        "${include_args[@]}" "${probe_args[@]}" -H -c "$source" -o "$object" \
        >/dev/null 2>"$trace" ||
        fail "$tree $profile direct $header source-form probe failed: $(sed -n '/error:/p' "$trace" | sed -n '1p')"
}

preprocess_profile() {
    local tree="$1" profile="$2" header="$3" output="$4"
    local -a profile_args

    set_tree "$tree"
    set_language "$profile"
    mapfile -t profile_args < <(profile_arguments "$profile")
    printf '#include <%s>\n' "$header" | run_compiler "$compiler" \
        "${language_args[@]}" "${profile_args[@]}" "${include_args[@]}" -dM -E - \
        >"$output" || fail "$tree $profile $header macro preprocessing failed"
}

check_param_macro_forms() {
    local macros="$1" form

    grep -Eq '^#define _SYS_PARAM_H[[:space:]]*$' "$macros" ||
        fail 'missing x86 musl _SYS_PARAM_H public guard'
    for form in \
        '#define MAXSYMLINKS 20' '#define MAXHOSTNAMELEN 64' \
        '#define MAXNAMLEN 255' '#define MAXPATHLEN 4096' '#define NBBY 8' \
        '#define NGROUPS 32' '#define CANBSIZ 255' '#define NOFILE 256' \
        '#define NCARGS 131072' '#define DEV_BSIZE 512' '#define NOGROUP (-1)' \
        '#define MIN(a,b) (((a)<(b))?(a):(b))' \
        '#define MAX(a,b) (((a)>(b))?(a):(b))' \
        '#define __bitop(x,i,o) ((x)[(i)/8] o (1<<(i)%8))' \
        '#define setbit(x,i) __bitop(x,i,|=)' \
        '#define clrbit(x,i) __bitop(x,i,&=~)' \
        '#define isset(x,i) __bitop(x,i,&)' '#define isclr(x,i) !isset(x,i)' \
        '#define howmany(n,d) (((n)+((d)-1))/(d))' \
        '#define roundup(n,d) (howmany(n,d)*(d))' \
        '#define powerof2(n) !(((n)-1) & (n))'; do
        grep -Fxq "$form" "$macros" || fail "missing exact musl param macro form: $form"
    done
    if grep -Eq '^#define _CRABC_SYS_PARAM_H([[:space:]]|$)' "$macros"; then
        fail 'x86 param macro surface retained _CRABC_SYS_PARAM_H'
    fi
}

check_resource_macro_form() {
    grep -Fxq '#define RUSAGE_CHILDREN (-1)' "$1" ||
        fail 'missing exact musl RUSAGE_CHILDREN source form'
}

extract_param_surface() {
    grep -E '^#define (_SYS_PARAM_H|_CRABC_SYS_PARAM_H|MAXSYMLINKS|MAXHOSTNAMELEN|MAXNAMLEN|MAXPATHLEN|NBBY|NGROUPS|CANBSIZ|NOFILE|NCARGS|DEV_BSIZE|NOGROUP|MIN|MAX|__bitop|setbit|clrbit|isset|isclr|howmany|roundup|powerof2|RUSAGE_CHILDREN)([[:space:](]|$)' "$1" \
        | LC_ALL=C sort >"$2" || true
}

extract_resource_surface() {
    grep -E '^#define RUSAGE_CHILDREN([[:space:](]|$)' "$1" >"$2" || true
}

[ "$#" -eq 0 ] || fail "usage: $0"
require_native_linux_x86_64
for tool in diff env grep mapfile mktemp realpath sed sort uname; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -x "$CANDIDATE_CC" ] || fail "missing raw native candidate compiler"
[ -d "$MUSL_ROOT/include" ] || fail "missing pinned musl include tree"
[ -d "$PROJECT_INCLUDE" ] || fail "missing project include tree"
[ -f "$C_PROBE" ] && [ -f "$CXX_PROBE" ] || fail "missing param source-form probe"
[ "${#PROFILES[@]}" = "$EXPECTED_PROFILE_COUNT" ] || fail "profile roster drifted"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

compiler_builtin="$(run_compiler "$CANDIDATE_CC" -print-file-name=include)"
compiler_builtin="$(realpath "$compiler_builtin")"
[ -d "$compiler_builtin" ] || fail "raw compiler builtin include root is missing"

work_dir="$(mktemp -d /tmp/crabc-x86-64-param-header-source-form.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT

for profile in "${PROFILES[@]}"; do
    for tree in reference candidate; do
        for header in sys/param.h sys/resource.h; do
            header_tag="${header//\//_}"
            trace="$work_dir/$profile.$tree.$header_tag.trace"
            object="$work_dir/$profile.$tree.$header_tag.o"
            macros="$work_dir/$profile.$tree.$header_tag.macros"
            compile_profile "$tree" "$profile" "$header" "$trace" "$object"
            check_trace "$tree" "$header" "$trace"
            preprocess_profile "$tree" "$profile" "$header" "$macros"
            case "$header" in
                sys/param.h)
                    check_param_macro_forms "$macros"
                    extract_param_surface "$macros" "$work_dir/$profile.$tree.param.surface"
                    ;;
                sys/resource.h)
                    check_resource_macro_form "$macros"
                    extract_resource_surface "$macros" "$work_dir/$profile.$tree.resource.surface"
                    ;;
            esac
        done
    done
    if ! diff -u "$work_dir/$profile.reference.param.surface" \
        "$work_dir/$profile.candidate.param.surface" >"$work_dir/$profile.param.diff"; then
        sed -n '1,200p' "$work_dir/$profile.param.diff" >&2
        fail "$profile param macro source forms differ from pinned musl"
    fi
    if ! diff -u "$work_dir/$profile.reference.resource.surface" \
        "$work_dir/$profile.candidate.resource.surface" >"$work_dir/$profile.resource.diff"; then
        sed -n '1,200p' "$work_dir/$profile.resource.diff" >&2
        fail "$profile direct resource macro source form differs from pinned musl"
    fi
done

printf 'x86 pinned-musl/project C/C++ sys/param.h plus direct sys/resource.h source form: PASS (%s profiles; compile-only)\n' \
    "$EXPECTED_PROFILE_COUNT"
