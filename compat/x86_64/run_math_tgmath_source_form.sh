#!/usr/bin/env bash
# Native x86-64 <math.h>/<tgmath.h> source-form and frozen-AArch64 evidence.
#
# Pinned musl 1.2.6 is the x86 public-header oracle. The candidate pass sees
# only the project header root and compiler builtin headers, so ambient libc
# headers cannot supply a replacement macro form. The AArch64 pass intentionally
# compares the existing frozen project form, not musl's x86 form: its exact
# pre-change macro replacements and C/C++ syntax are retained while the x86
# branch selects musl source forms. This is header-only evidence; it does not
# select a math provider, algorithm, fenv runtime, archive linkage, promotion,
# or public x86 support.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly MUSL_ROOT=/opt/musl-1.2.6
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly CANDIDATE_CC=/usr/bin/gcc
readonly AARCH64_CC=/usr/bin/clang
readonly PROJECT_INCLUDE="$ROOT_DIR/include"
readonly C_PROBE="$ROOT_DIR/compat/x86_64/math_tgmath_source_form_probe.c"
readonly CXX_PROBE="$ROOT_DIR/compat/x86_64/math_tgmath_source_form_probe.cpp"
readonly EXPECTED_PROFILE_COUNT=9
readonly -a PROFILES=(
    c11-gnu
    cxx17-gnu
    c11-strict
    c11-posix-2008
    c11-xopen-700
    c11-xopen-800
    c11-bsd
    cxx17-strict
    cxx17-xopen-800
)
readonly -a HEADERS=(math.h tgmath.h)

fail() {
    printf 'ERROR: x86 math/tgmath source form: %s\n' "$*" >&2
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
        c11-gnu|cxx17-gnu) printf '%s\n' '-D_GNU_SOURCE' ;;
        c11-strict|cxx17-strict) : ;;
        c11-posix-2008) printf '%s\n' '-D_POSIX_C_SOURCE=200809L' ;;
        c11-xopen-700) printf '%s\n' '-D_XOPEN_SOURCE=700' ;;
        c11-xopen-800|cxx17-xopen-800) printf '%s\n' '-D_XOPEN_SOURCE=800' ;;
        c11-bsd) printf '%s\n' '-D_BSD_SOURCE' ;;
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
        *) fail "unknown x86 tree: $1" ;;
    esac
    include_args=(-nostdinc -I "$include_root" -isystem "$x86_builtin")
}

check_trace_roots() {
    local tree="$1" trace="$2" builtin="$3" path

    while IFS= read -r path; do
        case "$tree" in
            reference)
                case "$path" in
                    "$MUSL_ROOT/include"/*|"$builtin"/*) ;;
                    *) fail "reference trace escaped musl/builtin roots: $path" ;;
                esac
                ;;
            candidate|aarch64)
                case "$path" in
                    "$PROJECT_INCLUDE"/*|"$builtin"/*) ;;
                    *) fail "$tree trace escaped project/builtin roots: $path" ;;
                esac
                ;;
            *) fail "unknown trace tree: $tree" ;;
        esac
    done < <(trace_paths "$trace")
}

compile_x86_profile() {
    local tree="$1" profile="$2" header="$3" trace="$4"
    local -a profile_args

    set_x86_tree "$tree"
    set_language "$profile"
    mapfile -t profile_args < <(profile_arguments "$profile")
    if ! run_compiler "$compiler" "${language_args[@]}" "${profile_args[@]}" \
        "${include_args[@]}" "-DCRABC_MATH_TGMATH_HEADER=<$header>" -H -fsyntax-only "$source" \
        > /dev/null 2>"$trace"; then
        fail "$profile $tree direct <$header> syntax failed: $(first_diagnostic "$trace")"
    fi
    check_trace_roots "$tree" "$trace" "$x86_builtin"
    grep -Fq "$include_root/$header" "$trace" ||
        fail "$profile $tree direct <$header> trace omitted $include_root/$header"
}

macro_surface() {
    awk '
        $1 == "#define" {
            name = $2
            if (name == "M_E" || name == "M_LOG2E" || name == "M_LOG10E" ||
                name == "M_LN2" || name == "M_LN10" || name == "M_PI" ||
                name == "M_PI_2" || name == "M_PI_4" || name == "M_1_PI" ||
                name == "M_2_PI" || name == "M_2_SQRTPI" || name == "M_SQRT2" ||
                name == "M_SQRT1_2" || name == "MAXFLOAT" ||
                name == "math_errhandling" || name == "isinf(x)" ||
                name == "isnan(x)" || name == "isnormal(x)" ||
                name == "isfinite(x)") print
        }
    '
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
    macro_surface < "$raw" | LC_ALL=C sort > "$surface"
}

maxfloat_is_visible_profile() {
    case "$1" in
        c11-xopen-700|c11-xopen-800|c11-bsd|cxx17-xopen-800) return 0 ;;
        *) return 1 ;;
    esac
}

extract_x86_predefined_maxfloat_surface() {
    local tree="$1" profile="$2" header="$3" surface="$4" diagnostic="$5"
    local raw="$surface.raw"
    local -a profile_args

    set_x86_tree "$tree"
    set_language "$profile"
    mapfile -t profile_args < <(profile_arguments "$profile")
    if ! run_compiler "$compiler" "${language_args[@]}" "${profile_args[@]}" \
        "${include_args[@]}" -DMAXFLOAT=0 -Werror -dM -E -include "$header" - < /dev/null \
        >"$raw" 2>"$diagnostic"; then
        fail "$profile $tree <$header> did not undefine a preexisting MAXFLOAT: $(first_diagnostic "$diagnostic")"
    fi
    macro_surface < "$raw" | LC_ALL=C sort > "$surface"
}

check_x86_maxfloat_boundary() {
    local profile="$1" reference="$2" candidate="$3"
    local expected='#define MAXFLOAT 3.40282346638528859812e+38F'

    case "$profile" in
        c11-xopen-700|c11-xopen-800|c11-bsd|cxx17-xopen-800)
            grep -Fxq "$expected" "$reference" ||
                fail "$profile pinned musl omitted the MAXFLOAT source form"
            grep -Fxq "$expected" "$candidate" ||
                fail "$profile project omitted the x86 MAXFLOAT source form"
            ;;
        *)
            if grep -Fq '#define MAXFLOAT ' "$candidate"; then
                fail "$profile project unexpectedly exposes MAXFLOAT"
            fi
            ;;
    esac
}

expected_aarch64_surface() {
    local profile="$1"

    printf '%s\n' \
        '#define isfinite(x) ( sizeof(x) == sizeof(float) ? (__FLOAT_BITS(x) & 0x7fffffff) < 0x7f800000 : sizeof(x) == sizeof(double) ? (__DOUBLE_BITS(x) & (-1ULL>>1)) < (0x7ffULL<<52) : __fpclassifyl(x) > FP_INFINITE)' \
        '#define isinf(x) ( sizeof(x) == sizeof(float) ? (__FLOAT_BITS(x) & 0x7fffffff) == 0x7f800000 : sizeof(x) == sizeof(double) ? (__DOUBLE_BITS(x) & (-1ULL>>1)) == (0x7ffULL<<52) : __fpclassifyl(x) == FP_INFINITE)' \
        '#define isnan(x) ( sizeof(x) == sizeof(float) ? (__FLOAT_BITS(x) & 0x7fffffff) > 0x7f800000 : sizeof(x) == sizeof(double) ? (__DOUBLE_BITS(x) & (-1ULL>>1)) > (0x7ffULL<<52) : __fpclassifyl(x) == FP_NAN)' \
        '#define isnormal(x) ( sizeof(x) == sizeof(float) ? ((__FLOAT_BITS(x)+0x00800000) & 0x7fffffff) >= 0x01000000 : sizeof(x) == sizeof(double) ? ((__DOUBLE_BITS(x)+(1ULL<<52)) & (-1ULL>>1)) >= (1ULL<<53) : __fpclassifyl(x) == FP_NORMAL)' \
        '#define math_errhandling MATH_ERRNO'

    case "$profile" in
        c11-gnu|cxx17-gnu|c11-xopen-700|c11-xopen-800|c11-bsd|cxx17-strict|cxx17-xopen-800)
            printf '%s\n' \
                '#define M_1_PI 0.318309886183790671538' \
                '#define M_2_PI 0.636619772367581343076' \
                '#define M_2_SQRTPI 1.12837916709551257390' \
                '#define M_E 2.71828182845904523536' \
                '#define M_LN10 2.30258509299404568402' \
                '#define M_LN2 0.693147180559945309417' \
                '#define M_LOG10E 0.434294481903251827651' \
                '#define M_LOG2E 1.44269504088896340736' \
                '#define M_PI 3.14159265358979323846' \
                '#define M_PI_2 1.57079632679489661923' \
                '#define M_PI_4 0.785398163397448309616' \
                '#define M_SQRT1_2 0.707106781186547524401' \
                '#define M_SQRT2 1.41421356237309504880'
            ;;
    esac

    case "$profile" in
        c11-xopen-700|c11-bsd)
            printf '%s\n' '#define MAXFLOAT 3.40282346638528859812e+38F'
            ;;
    esac
}

compile_aarch64_profile() {
    local profile="$1" header="$2" trace="$3"
    local -a profile_args

    set_language "$profile"
    mapfile -t profile_args < <(profile_arguments "$profile")
    if ! run_compiler "$AARCH64_CC" --target=aarch64-unknown-linux-musl \
        "${language_args[@]}" "${profile_args[@]}" -nostdinc -I "$PROJECT_INCLUDE" \
        -isystem "$aarch64_builtin" "-DCRABC_MATH_TGMATH_HEADER=<$header>" -H -fsyntax-only "$source" \
        > /dev/null 2>"$trace"; then
        fail "$profile frozen-AArch64 direct <$header> syntax failed: $(first_diagnostic "$trace")"
    fi
    check_trace_roots aarch64 "$trace" "$aarch64_builtin"
    grep -Fq "$PROJECT_INCLUDE/$header" "$trace" ||
        fail "$profile frozen-AArch64 direct <$header> trace omitted project header"
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
    macro_surface < "$raw" | LC_ALL=C sort > "$surface"
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
[ -f "$C_PROBE" ] || fail "missing C source-form probe"
[ -f "$CXX_PROBE" ] || fail "missing C++ source-form probe"
[ "${#PROFILES[@]}" -eq "$EXPECTED_PROFILE_COUNT" ] || fail "profile roster drifted"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

x86_builtin="$(run_compiler "$CANDIDATE_CC" -print-file-name=include)"
x86_builtin="$(realpath "$x86_builtin")"
[ -d "$x86_builtin" ] || fail "raw candidate compiler builtin include root is missing"

aarch64_builtin="$(run_compiler "$AARCH64_CC" -print-resource-dir)/include"
aarch64_builtin="$(realpath "$aarch64_builtin")"
[ -d "$aarch64_builtin" ] || fail "AArch64 compiler builtin include root is missing"

work_dir="$(mktemp -d /tmp/crabc-x86-64-math-tgmath-source-form.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT

for profile in "${PROFILES[@]}"; do
    for header in "${HEADERS[@]}"; do
        for tree in reference candidate; do
            trace="$work_dir/$profile.$header.$tree.trace"
            compile_x86_profile "$tree" "$profile" "$header" "$trace"
            surface="$work_dir/$profile.$header.$tree.surface"
            diagnostic="$work_dir/$profile.$header.$tree.macros.trace"
            extract_x86_surface "$tree" "$profile" "$header" "$surface" "$diagnostic"
        done
        reference="$work_dir/$profile.$header.reference.surface"
        candidate="$work_dir/$profile.$header.candidate.surface"
        if ! cmp -s "$reference" "$candidate"; then
            diff -u "$reference" "$candidate" || true
            fail "$profile <$header> macro source forms diverge from pinned musl"
        fi
        check_x86_maxfloat_boundary "$profile" "$reference" "$candidate"
        if maxfloat_is_visible_profile "$profile"; then
            for tree in reference candidate; do
                predefined_surface="$work_dir/$profile.$header.$tree.predefined-maxfloat.surface"
                predefined_diagnostic="$work_dir/$profile.$header.$tree.predefined-maxfloat.trace"
                extract_x86_predefined_maxfloat_surface "$tree" "$profile" "$header" \
                    "$predefined_surface" "$predefined_diagnostic"
            done
            predefined_reference="$work_dir/$profile.$header.reference.predefined-maxfloat.surface"
            predefined_candidate="$work_dir/$profile.$header.candidate.predefined-maxfloat.surface"
            if ! cmp -s "$predefined_reference" "$predefined_candidate"; then
                diff -u "$predefined_reference" "$predefined_candidate" || true
                fail "$profile <$header> pre-defined MAXFLOAT form diverges from pinned musl"
            fi
            check_x86_maxfloat_boundary "$profile" "$predefined_reference" "$predefined_candidate"
        fi

        aarch64_trace="$work_dir/$profile.$header.aarch64.trace"
        compile_aarch64_profile "$profile" "$header" "$aarch64_trace"
        aarch64_surface="$work_dir/$profile.$header.aarch64.surface"
        aarch64_diagnostic="$work_dir/$profile.$header.aarch64.macros.trace"
        aarch64_expected="$work_dir/$profile.$header.aarch64.expected"
        extract_aarch64_surface "$profile" "$header" "$aarch64_surface" "$aarch64_diagnostic"
        expected_aarch64_surface "$profile" | LC_ALL=C sort > "$aarch64_expected"
        if ! cmp -s "$aarch64_expected" "$aarch64_surface"; then
            diff -u "$aarch64_expected" "$aarch64_surface" || true
            fail "$profile <$header> changed the frozen AArch64 macro source forms"
        fi
    done
done

printf 'x86 pinned-musl/project math/tgmath source form: PASS (%s C/C++ profiles; frozen AArch64 syntax/forms)\n' \
    "$EXPECTED_PROFILE_COUNT"
