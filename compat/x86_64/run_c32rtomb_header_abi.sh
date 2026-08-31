#!/usr/bin/env bash
# Native Linux/x86-64 C11/C++17 c32rtomb declaration and linkage gate.
#
# Pinned musl 1.2.6 is the declaration and C++ C-linkage oracle. The raw
# project pass uses only project headers and compiler builtins, so host-libc
# headers cannot supply the C11 `<uchar.h>` surface accidentally. c32rtomb is
# unconditional across the strict, POSIX, X/Open, GNU, and BSD feature
# profiles; this is declaration evidence only, not a locale database,
# locale-object, decoder, UTF-16, runtime, or public-x86 claim.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly MUSL_ROOT=/opt/musl-1.2.6
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly CANDIDATE_CC=/usr/bin/gcc
readonly PROJECT_INCLUDE="$ROOT_DIR/include"
readonly C_PROBE="$ROOT_DIR/compat/x86_64/c32rtomb_header_abi_probe.c"
readonly CXX_PROBE="$ROOT_DIR/compat/x86_64/c32rtomb_header_abi_probe.cpp"
readonly -a RESET_FEATURE_ARGS=(
    -U_GNU_SOURCE
    -U_BSD_SOURCE
    -U_XOPEN_SOURCE
    -U_POSIX_C_SOURCE
    -U_LARGEFILE64_SOURCE
    -U_DEFAULT_SOURCE
)

fail() {
    printf 'ERROR: x86 uchar.h c32rtomb ABI: %s\n' "$*" >&2
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

assert_header_provenance() {
    local tree="$1"
    local trace="$2"
    local label="$3"
    local root path

    case "$tree" in
        oracle) root="$MUSL_ROOT/include" ;;
        project) root="$PROJECT_INCLUDE" ;;
        *) fail "unknown header tree $tree" ;;
    esac

    while IFS= read -r path; do
        case "$path" in
            "$root"/*|"$candidate_builtin_include"/*) ;;
            *) fail "$label trace escaped declared header roots: $path" ;;
        esac
    done < <(trace_paths "$trace")

    for header in uchar.h features.h bits/alltypes.h; do
        grep -Fq "$root/$header" "$trace" ||
            fail "$label did not preprocess $root/$header"
    done
}

check_cxx_c_linkage() {
    local object="$1"
    local label="$2"
    local undefined

    undefined="$(nm --undefined-only "$object" | awk '{print $NF}')"
    printf '%s\n' "$undefined" | grep -Fxq c32rtomb ||
        fail "$label did not retain an unmangled c32rtomb reference"
    if printf '%s\n' "$undefined" | grep -Eq '^_Z.*c32rtomb'; then
        fail "$label retains a mangled c32rtomb reference"
    fi
}

set_profile() {
    local profile="$1"
    profile_args=("${RESET_FEATURE_ARGS[@]}")
    case "$profile" in
        strict) ;;
        posix) profile_args+=( -D_POSIX_C_SOURCE=200809L ) ;;
        xopen) profile_args+=( -D_XOPEN_SOURCE=700 ) ;;
        gnu) profile_args+=( -D_GNU_SOURCE ) ;;
        bsd) profile_args+=( -D_BSD_SOURCE ) ;;
        *) fail "unknown feature profile $profile" ;;
    esac
}

compile_one() {
    local tree="$1"
    local language="$2"
    local profile="$3"
    local trace="$4"
    local object="$5"
    local compiler source
    local -a include_args

    case "$tree" in
        oracle)
            compiler="$ORACLE_CC"
            include_args=()
            ;;
        project)
            compiler="$CANDIDATE_CC"
            include_args=(
                -nostdinc
                -I "$PROJECT_INCLUDE"
                -isystem "$candidate_builtin_include"
            )
            ;;
        *) fail "unknown header tree $tree" ;;
    esac

    set_profile "$profile"
    case "$language" in
        c11)
            source="$C_PROBE"
            run_compiler "$compiler" -x c -std=c11 -fno-builtin -H \
                "${profile_args[@]}" "${include_args[@]}" -fsyntax-only "$source" \
                >/dev/null 2>"$trace"
            ;;
        cxx17)
            source="$CXX_PROBE"
            run_compiler "$compiler" -x c++ -std=c++17 -nostdinc++ -fno-builtin -H \
                "${profile_args[@]}" "${include_args[@]}" -c -o "$object" "$source" \
                >/dev/null 2>"$trace"
            ;;
        *) fail "unknown language $language" ;;
    esac
}

require_native_linux_x86_64
for tool in awk env grep mktemp nm realpath sed uname; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl compiler"
[ -x "$CANDIDATE_CC" ] || fail "missing raw candidate compiler"
[ -d "$MUSL_ROOT/include" ] || fail "missing pinned musl include tree"
[ -d "$PROJECT_INCLUDE" ] || fail "missing project include tree"
[ -f "$C_PROBE" ] || fail "missing C c32rtomb header probe"
[ -f "$CXX_PROBE" ] || fail "missing C++ c32rtomb header probe"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

candidate_builtin_include="$(run_compiler "$CANDIDATE_CC" -print-file-name=include)"
case "$candidate_builtin_include" in
    /*) ;;
    *) fail "raw candidate compiler did not report an absolute builtin include directory" ;;
esac
candidate_builtin_include="$(realpath "$candidate_builtin_include")"
[ -d "$candidate_builtin_include" ] || fail "missing raw compiler builtin include directory"
[ "$candidate_builtin_include" != "$MUSL_ROOT/include" ] ||
    fail "candidate compiler builtin include aliases pinned musl"

work_dir="$(mktemp -d /tmp/crabc-x86-64-c32rtomb-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT

for profile in strict posix xopen gnu bsd; do
    for tree in oracle project; do
        for language in c11 cxx17; do
            trace="$work_dir/$tree-$language-$profile.trace"
            object="$work_dir/$tree-$language-$profile.o"
            if ! compile_one "$tree" "$language" "$profile" "$trace" "$object"; then
                sed -n '1,160p' "$trace" >&2
                fail "$tree/$language/$profile declaration compilation failed"
            fi
            assert_header_provenance "$tree" "$trace" "$tree/$language/$profile"
            if [ "$language" = cxx17 ]; then
                check_cxx_c_linkage "$object" "$tree/$language/$profile"
            fi
        done
    done
done

printf 'x86 pinned-musl/project C11/C++17 c32rtomb header ABI: PASS\n'
