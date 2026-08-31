#!/usr/bin/env bash
# Native Linux/x86-64 <stdlib.h> feature-profile ABI matrix.
#
# Pinned musl 1.2.6 is the declaration, feature-visibility, C++ C-linkage,
# and C++ null-pointer oracle.  The candidate uses raw GCC with only project
# headers and compiler builtin headers, so an ambient system libc header cannot
# hide a project-profile mismatch.  This is compile-only evidence: it selects
# no crabc-libc archive, C runtime, CRT, loader, sysroot, or public x86 support.
#
# A candidate mismatch is intentionally reported as a matrix failure rather
# than masked.  Until project <stdlib.h> has the same profile surface as musl,
# this command is expected to exit nonzero with each failed profile named.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly MUSL_ROOT=/opt/musl-1.2.6
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly CANDIDATE_CC=/usr/bin/gcc
readonly PROJECT_INCLUDE="$ROOT_DIR/include"
readonly C_PROBE="$ROOT_DIR/compat/x86_64/stdlib_header_abi_probe.c"
readonly CXX_PROBE="$ROOT_DIR/compat/x86_64/stdlib_header_abi_probe.cpp"
readonly -a PROFILES=(
    c11-strict
    c11-posix-2008
    c11-xopen-700
    c11-gnu
    c11-bsd
    c11-lfs
    cxx17-strict
    cxx17-posix-2008
    cxx17-xopen-700
    cxx17-gnu
    cxx17-bsd
    cxx17-lfs
)

fail() {
    printf 'ERROR: x86 stdlib header ABI: %s\n' "$*" >&2
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
        "$@"
}

profile_is_cxx() {
    case "$1" in
        cxx17-*) return 0 ;;
        *) return 1 ;;
    esac
}

profile_arguments() {
    case "$1" in
        c11-strict|cxx17-strict)
            printf '%s\0' \
                -U_GNU_SOURCE -U_BSD_SOURCE -U_XOPEN_SOURCE \
                -U_POSIX_C_SOURCE -U_LARGEFILE64_SOURCE -U_DEFAULT_SOURCE \
                -DCRABC_STDLIB_STRICT
            ;;
        c11-posix-2008|cxx17-posix-2008)
            printf '%s\0' \
                -U_GNU_SOURCE -U_BSD_SOURCE -U_XOPEN_SOURCE \
                -U_LARGEFILE64_SOURCE -U_DEFAULT_SOURCE \
                -D_POSIX_C_SOURCE=200809L -DCRABC_STDLIB_POSIX_2008
            ;;
        c11-xopen-700|cxx17-xopen-700)
            printf '%s\0' \
                -U_GNU_SOURCE -U_BSD_SOURCE -U_POSIX_C_SOURCE \
                -U_LARGEFILE64_SOURCE -U_DEFAULT_SOURCE \
                -D_XOPEN_SOURCE=700 -DCRABC_STDLIB_XOPEN_700
            ;;
        c11-gnu|cxx17-gnu)
            printf '%s\0' \
                -U_BSD_SOURCE -U_XOPEN_SOURCE -U_POSIX_C_SOURCE \
                -U_LARGEFILE64_SOURCE -U_DEFAULT_SOURCE \
                -D_GNU_SOURCE -DCRABC_STDLIB_GNU
            ;;
        c11-bsd|cxx17-bsd)
            printf '%s\0' \
                -U_GNU_SOURCE -U_XOPEN_SOURCE -U_POSIX_C_SOURCE \
                -U_LARGEFILE64_SOURCE -U_DEFAULT_SOURCE \
                -D_BSD_SOURCE -DCRABC_STDLIB_BSD
            ;;
        c11-lfs|cxx17-lfs)
            printf '%s\0' \
                -U_GNU_SOURCE -U_BSD_SOURCE -U_XOPEN_SOURCE \
                -U_POSIX_C_SOURCE -U_DEFAULT_SOURCE \
                -D_LARGEFILE64_SOURCE -DCRABC_STDLIB_LFS
            ;;
        *) fail "unknown profile: $1" ;;
    esac
}

profile_hidden_witness() {
    case "$1" in
        c11-strict|cxx17-strict|c11-lfs|cxx17-lfs)
            printf '%s\n' CRABC_STDLIB_REQUIRE_POSIX_HIDDEN
            ;;
        c11-posix-2008|cxx17-posix-2008)
            printf '%s\n' CRABC_STDLIB_REQUIRE_XOPEN_HIDDEN
            ;;
        c11-xopen-700|cxx17-xopen-700)
            printf '%s\n' CRABC_STDLIB_REQUIRE_GNU_BSD_HIDDEN
            ;;
        c11-bsd|cxx17-bsd)
            printf '%s\n' CRABC_STDLIB_REQUIRE_GNU_ONLY_HIDDEN
            ;;
        c11-gnu|cxx17-gnu) ;;
        *) fail "unknown profile: $1" ;;
    esac
}

hidden_witness_symbol() {
    case "$1" in
        CRABC_STDLIB_REQUIRE_POSIX_HIDDEN) printf '%s\n' setenv ;;
        CRABC_STDLIB_REQUIRE_XOPEN_HIDDEN) printf '%s\n' realpath ;;
        CRABC_STDLIB_REQUIRE_GNU_BSD_HIDDEN) printf '%s\n' reallocarray ;;
        CRABC_STDLIB_REQUIRE_GNU_ONLY_HIDDEN) printf '%s\n' secure_getenv ;;
        *) fail "unknown hidden witness: $1" ;;
    esac
}

trace_paths() {
    sed -n -E 's/^[. ]+ (\/[^[:space:]]+).*$/\1/p' "$1"
}

assert_header_provenance() {
    local tree="$1"
    local trace="$2"
    local label="$3"
    local root
    local path
    local header

    case "$tree" in
        reference) root="$MUSL_ROOT/include" ;;
        candidate) root="$PROJECT_INCLUDE" ;;
        *) fail "unknown header tree: $tree" ;;
    esac

    while IFS= read -r path; do
        case "$tree" in
            reference)
                case "$path" in
                    "$MUSL_ROOT/include"/*|"$candidate_compiler_builtin_include"/*) ;;
                    *) fail "$label trace escaped its declared reference header roots" ;;
                esac
                ;;
            candidate)
                case "$path" in
                    "$PROJECT_INCLUDE"/*|"$candidate_compiler_builtin_include"/*) ;;
                    *) fail "$label trace escaped its declared candidate header roots" ;;
                esac
                ;;
        esac
    done < <(trace_paths "$trace")

    for header in stdlib.h features.h bits/alltypes.h; do
        grep -Fq "$root/$header" "$trace" ||
            fail "$label did not preprocess $root/$header"
    done
}

compile_one() {
    local tree="$1"
    local profile="$2"
    local mode="$3"
    local diagnostic="$4"
    local object="$5"
    local compiler
    local include_root
    local source
    local -a profile_args
    local -a mode_args=()
    local -a arguments

    mapfile -d '' -t profile_args < <(profile_arguments "$profile")
    case "$tree" in
        reference)
            compiler="$ORACLE_CC"
            include_root="$MUSL_ROOT/include"
            ;;
        candidate)
            compiler="$CANDIDATE_CC"
            include_root="$PROJECT_INCLUDE"
            ;;
        *) fail "unknown header tree: $tree" ;;
    esac

    case "$mode" in
        normal) ;;
        hidden)
            local witness
            witness="$(profile_hidden_witness "$profile")"
            [ -n "$witness" ] || fail "$profile has no hidden witness"
            mode_args+=(
                -DCRABC_STDLIB_HIDDEN_WITNESS_ONLY
                "-D$witness"
            )
            ;;
        rand-r-hidden)
            case "$profile" in
                c11-strict|cxx17-strict|c11-lfs|cxx17-lfs) ;;
                *) fail "$profile does not hide rand_r" ;;
            esac
            mode_args+=(
                -DCRABC_STDLIB_HIDDEN_WITNESS_ONLY
                -DCRABC_STDLIB_REQUIRE_RAND_R_HIDDEN
            )
            ;;
        cxx-null)
            profile_is_cxx "$profile" || fail "$profile cannot have a C++ null witness"
            mode_args+=(
                -DCRABC_STDLIB_NULL_WITNESS_ONLY
                -DCRABC_STDLIB_REQUIRE_CPP_NULLPTR
            )
            ;;
        cxx-null-stdio-first)
            profile_is_cxx "$profile" || fail "$profile cannot have a C++ null witness"
            mode_args+=(
                -DCRABC_STDLIB_NULL_WITNESS_ONLY
                -DCRABC_STDLIB_REQUIRE_CPP_NULLPTR
                -DCRABC_STDLIB_INCLUDE_STDIO_FIRST
            )
            ;;
        cxx-null-string-first)
            profile_is_cxx "$profile" || fail "$profile cannot have a C++ null witness"
            mode_args+=(
                -DCRABC_STDLIB_NULL_WITNESS_ONLY
                -DCRABC_STDLIB_REQUIRE_CPP_NULLPTR
                -DCRABC_STDLIB_INCLUDE_STRING_FIRST
            )
            ;;
        *) fail "unknown compile mode: $mode" ;;
    esac

    if profile_is_cxx "$profile"; then
        source="$CXX_PROBE"
        arguments=(
            -x c++ -std=c++17 -nostdinc++
            -nostdinc -I "$include_root"
            -isystem "$candidate_compiler_builtin_include"
            -H -fno-builtin
            "${profile_args[@]}" "${mode_args[@]}"
        )
        if [ "$mode" = normal ]; then
            arguments+=(-c "$source" -o "$object")
        else
            arguments+=(-fsyntax-only "$source")
        fi
    else
        source="$C_PROBE"
        arguments=(
            -x c -std=c11
            -nostdinc -I "$include_root"
            -isystem "$candidate_compiler_builtin_include"
            -H -fno-builtin
            "${profile_args[@]}" "${mode_args[@]}"
            -fsyntax-only "$source"
        )
    fi

    run_compiler "$compiler" "${arguments[@]}" >/dev/null 2>"$diagnostic"
}

expected_cxx_symbols() {
    local profile="$1"

    printf '%s\n' malloc strtol qsort getenv
    case "$profile" in
        c11-posix-2008|cxx17-posix-2008|c11-xopen-700|cxx17-xopen-700|\
        c11-gnu|cxx17-gnu|c11-bsd|cxx17-bsd)
            printf '%s\n' setenv unsetenv rand_r
            ;;
    esac
    case "$profile" in
        c11-xopen-700|cxx17-xopen-700|c11-gnu|cxx17-gnu|c11-bsd|cxx17-bsd)
            printf '%s\n' realpath putenv drand48
            ;;
    esac
    case "$profile" in
        c11-gnu|cxx17-gnu|c11-bsd|cxx17-bsd)
            printf '%s\n' mktemp mkstemps mkostemps valloc memalign reallocarray qsort_r clearenv
            ;;
    esac
    case "$profile" in
        c11-gnu|cxx17-gnu)
            printf '%s\n' secure_getenv strtof_l strtod_l strtold_l
            ;;
    esac
}

check_cxx_c_linkage() {
    local object="$1"
    local label="$2"
    local profile="$3"
    local undefined
    local symbol
    local expected

    undefined="$(nm --undefined-only "$object" | awk '{print $NF}')"
    while IFS= read -r expected; do
        [ -n "$expected" ] || continue
        if ! printf '%s\n' "$undefined" | grep -Fxq "$expected"; then
            printf 'C++ linkage mismatch: %s does not retain C-linkage symbol %s\n' \
                "$label" "$expected" >&2
            return 1
        fi
    done < <(expected_cxx_symbols "$profile")
    if printf '%s\n' "$undefined" | grep -Eq \
        '_Z.*(malloc|strtol|qsort|getenv|setenv|unsetenv|rand_r|realpath|putenv|drand48|mktemp|mkstemps|mkostemps|valloc|memalign|reallocarray|qsort_r|clearenv|secure_getenv|strtof_l|strtod_l|strtold_l)'; then
        printf 'C++ linkage mismatch: %s retains a mangled <stdlib.h> reference\n' \
            "$label" >&2
        return 1
    fi
}

record_mismatch() {
    local label="$1"
    local diagnostic="$2"

    printf 'MISMATCH: %s\n' "$label" >&2
    sed -n '1,120p' "$diagnostic" >&2
    failures=$((failures + 1))
}

record_linkage_mismatch() {
    local label="$1"

    printf 'MISMATCH: %s\n' "$label" >&2
    failures=$((failures + 1))
}

run_normal_profile() {
    local tree="$1"
    local profile="$2"
    local diagnostic="$work_dir/$tree-$profile-normal.trace"
    local object="$work_dir/$tree-$profile-normal.o"
    local label="$tree/$profile/normal"

    if ! compile_one "$tree" "$profile" normal "$diagnostic" "$object"; then
        if [ "$tree" = reference ]; then
            sed -n '1,160p' "$diagnostic" >&2
            fail "$label pinned-musl reference compilation failed"
        fi
        record_mismatch "$label required declarations do not match pinned musl" \
            "$diagnostic"
        return
    fi

    assert_header_provenance "$tree" "$diagnostic" "$label"
    if profile_is_cxx "$profile" && ! check_cxx_c_linkage "$object" "$label" \
        "$profile"; then
        if [ "$tree" = reference ]; then
            fail "$label pinned-musl C++ linkage witness failed"
        fi
        record_linkage_mismatch "$label C++ declarations do not retain C linkage"
        return
    fi
    printf 'PASS: %s\n' "$label"
}

run_hidden_witness() {
    local profile="$1"
    local witness
    local symbol
    local tree
    local diagnostic
    local object
    local label

    witness="$(profile_hidden_witness "$profile")"
    [ -n "$witness" ] || return 0
    symbol="$(hidden_witness_symbol "$witness")"

    for tree in reference candidate; do
        diagnostic="$work_dir/$tree-$profile-hidden.trace"
        object="$work_dir/$tree-$profile-hidden.o"
        label="$tree/$profile/$symbol-hidden"
        if compile_one "$tree" "$profile" hidden "$diagnostic" "$object"; then
            assert_header_provenance "$tree" "$diagnostic" "$label"
            if [ "$tree" = reference ]; then
                fail "$label pinned-musl unexpectedly exposes $symbol"
            fi
            record_mismatch "$label unexpectedly exposes a declaration musl hides" \
                "$diagnostic"
            continue
        fi

        assert_header_provenance "$tree" "$diagnostic" "$label"
        grep -Fq "$symbol" "$diagnostic" ||
            fail "$label hidden-witness diagnostic does not name $symbol"
        printf 'PASS: %s\n' "$label"
    done
}

run_rand_r_hidden_witness() {
    local profile="$1"
    local tree
    local diagnostic
    local object
    local label

    case "$profile" in
        c11-strict|cxx17-strict|c11-lfs|cxx17-lfs) ;;
        *) return 0 ;;
    esac

    for tree in reference candidate; do
        diagnostic="$work_dir/$tree-$profile-rand-r-hidden.trace"
        object="$work_dir/$tree-$profile-rand-r-hidden.o"
        label="$tree/$profile/rand_r-hidden"
        if compile_one "$tree" "$profile" rand-r-hidden "$diagnostic" "$object"; then
            assert_header_provenance "$tree" "$diagnostic" "$label"
            if [ "$tree" = reference ]; then
                fail "$label pinned-musl unexpectedly exposes rand_r"
            fi
            record_mismatch "$label unexpectedly exposes a declaration musl hides" \
                "$diagnostic"
            continue
        fi

        assert_header_provenance "$tree" "$diagnostic" "$label"
        grep -Fq "rand_r" "$diagnostic" ||
            fail "$label hidden-witness diagnostic does not name rand_r"
        printf 'PASS: %s\n' "$label"
    done
}

assert_null_include_order_provenance() {
    local tree="$1"
    local trace="$2"
    local mode="$3"
    local label="$4"
    local root
    local header

    assert_header_provenance "$tree" "$trace" "$label"
    case "$tree" in
        reference) root="$MUSL_ROOT/include" ;;
        candidate) root="$PROJECT_INCLUDE" ;;
        *) fail "unknown header tree: $tree" ;;
    esac
    case "$mode" in
        cxx-null) return ;;
        cxx-null-stdio-first) header=stdio.h ;;
        cxx-null-string-first) header=string.h ;;
        *) fail "unknown C++ null witness mode: $mode" ;;
    esac
    grep -Fq "$root/$header" "$trace" ||
        fail "$label did not preprocess $root/$header before <stdlib.h>"
}

run_one_cxx_null_witness() {
    local profile="$1"
    local mode="$2"
    local tree
    local diagnostic
    local object
    local label

    profile_is_cxx "$profile" || return 0
    for tree in reference candidate; do
        diagnostic="$work_dir/$tree-$profile-$mode.trace"
        object="$work_dir/$tree-$profile-$mode.o"
        label="$tree/$profile/$mode"
        if ! compile_one "$tree" "$profile" "$mode" "$diagnostic" "$object"; then
            if [ "$tree" = reference ]; then
                sed -n '1,160p' "$diagnostic" >&2
                fail "$label pinned-musl C++ null-pointer witness failed"
            fi
            record_mismatch "$label C++ NULL is not musl's nullptr type" \
                "$diagnostic"
            continue
        fi
        assert_null_include_order_provenance "$tree" "$diagnostic" "$mode" \
            "$label"
        printf 'PASS: %s\n' "$label"
    done
}

run_cxx_null_witness() {
    local profile="$1"

    profile_is_cxx "$profile" || return 0
    run_one_cxx_null_witness "$profile" cxx-null
    # The direct <stdlib.h> witness alone cannot catch a later header that
    # defines C++ NULL first. Keep these two transitive include orders as
    # dedicated strict-profile regressions without turning this into a raw
    # preprocessor-text comparison.
    if [ "$profile" = cxx17-strict ]; then
        run_one_cxx_null_witness "$profile" cxx-null-stdio-first
        run_one_cxx_null_witness "$profile" cxx-null-string-first
    fi
}

[ "$#" -eq 0 ] || fail "usage: $0"
require_native_linux_x86_64
for tool in awk env grep mktemp nm realpath sed uname; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -x "$CANDIDATE_CC" ] || fail "missing raw native candidate compiler"
[ -d "$MUSL_ROOT/include" ] || fail "missing pinned musl include tree"
[ -d "$PROJECT_INCLUDE" ] || fail "missing project include tree"
[ -f "$C_PROBE" ] || fail "missing C <stdlib.h> profile probe"
[ -f "$CXX_PROBE" ] || fail "missing C++ <stdlib.h> profile probe"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

candidate_compiler_builtin_include="$(run_compiler "$CANDIDATE_CC" \
    -print-file-name=include)"
case "$candidate_compiler_builtin_include" in
    /*) ;;
    *) fail "raw candidate compiler did not report an absolute builtin include directory" ;;
esac
candidate_compiler_builtin_include="$(realpath "$candidate_compiler_builtin_include")"
[ -d "$candidate_compiler_builtin_include" ] ||
    fail "missing raw candidate compiler builtin include directory"
[ "$candidate_compiler_builtin_include" != "$MUSL_ROOT/include" ] ||
    fail "candidate compiler builtin include aliases pinned musl"

work_dir="$(mktemp -d /tmp/crabc-x86-64-stdlib-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
failures=0

for profile in "${PROFILES[@]}"; do
    run_normal_profile reference "$profile"
done
for profile in "${PROFILES[@]}"; do
    run_normal_profile candidate "$profile"
done
for profile in "${PROFILES[@]}"; do
    run_hidden_witness "$profile"
done
for profile in "${PROFILES[@]}"; do
    run_rand_r_hidden_witness "$profile"
done
for profile in "${PROFILES[@]}"; do
    run_cxx_null_witness "$profile"
done

if [ "$failures" -ne 0 ]; then
    printf 'x86 pinned-musl/project <stdlib.h> feature-profile ABI: FAIL (%s candidate mismatches; x86 remains unpromoted)\n' \
        "$failures" >&2
    exit 1
fi

printf 'x86 pinned-musl/project <stdlib.h> feature-profile ABI: PASS\n'
