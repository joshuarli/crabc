#!/usr/bin/env bash
# Native Linux/x86-64 <sys/stat.h> through <ftw.h> source-form matrix.
#
# Pinned musl 1.2.6 supplies the exact declaration, macro-replacement, and
# include-topology oracle. The candidate pass uses only the project headers
# plus compiler builtin headers. This is header evidence only: it does not
# link a crabc archive or claim filesystem-traversal runtime completion.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly MUSL_ROOT=/opt/musl-1.2.6
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly CANDIDATE_CC=/usr/bin/gcc
readonly PROJECT_INCLUDE="$ROOT_DIR/include"
readonly C_PROBE="$ROOT_DIR/compat/x86_64/stat_ftw_header_source_form_probe.c"
readonly CXX_PROBE="$ROOT_DIR/compat/x86_64/stat_ftw_header_source_form_probe.cpp"
readonly -a PROFILES=(c11-gnu cxx17-gnu c11-gnu-largefile cxx17-gnu-largefile c11-strict cxx17-strict c11-posix-2008 c11-xopen-700 c11-bsd)

fail() {
    printf 'ERROR: x86 stat/ftw header source form: %s\n' "$*" >&2
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

profile_is_cxx() {
    case "$1" in cxx17-*) return 0 ;; *) return 1 ;; esac
}

profile_has_legacy_aliases() {
    case "$1" in c11-gnu|cxx17-gnu|c11-gnu-largefile|cxx17-gnu-largefile|c11-bsd) return 0 ;; *) return 1 ;; esac
}

profile_has_largefile_aliases() {
    case "$1" in *-largefile) return 0 ;; *) return 1 ;; esac
}

profile_arguments() {
    case "$1" in
        c11-gnu|cxx17-gnu) printf '%s\n' '-D_GNU_SOURCE' ;;
        c11-gnu-largefile|cxx17-gnu-largefile) printf '%s\n' '-D_GNU_SOURCE' '-D_LARGEFILE64_SOURCE' ;;
        c11-strict|cxx17-strict) printf '%s\n' '-U_GNU_SOURCE' ;;
        c11-posix-2008) printf '%s\n' '-U_GNU_SOURCE' '-D_POSIX_C_SOURCE=200809L' ;;
        c11-xopen-700) printf '%s\n' '-U_GNU_SOURCE' '-D_XOPEN_SOURCE=700' ;;
        c11-bsd) printf '%s\n' '-U_GNU_SOURCE' '-D_BSD_SOURCE' ;;
        *) fail "unknown profile: $1" ;;
    esac
}

trace_paths() {
    sed -n -E 's/^[. ]+ (\/[^[:space:]]+).*$/\1/p' "$1"
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

set_profile() {
    local profile="$1"
    mapfile -t profile_args < <(profile_arguments "$profile")
    probe_args=()
    if profile_has_legacy_aliases "$profile"; then
        probe_args+=(-DCRABC_STAT_FTW_EXPECT_LEGACY_ALIASES)
    fi
    if profile_has_largefile_aliases "$profile"; then
        probe_args+=(-DCRABC_STAT_FTW_EXPECT_LARGEFILE_ALIASES)
    fi
    if profile_is_cxx "$profile"; then
        language_args=(-x c++ -std=c++17 -nostdinc++)
        source="$CXX_PROBE"
    else
        language_args=(-x c -std=c11)
        source="$C_PROBE"
    fi
}

compile_profile() {
    local tree="$1" profile="$2" trace="$3" object="$4"
    set_tree "$tree"
    set_profile "$profile"
    run_compiler "$compiler" "${language_args[@]}" "${include_args[@]}" \
        "${profile_args[@]}" "${probe_args[@]}" -H -c "$source" -o "$object" \
        >/dev/null 2>"$trace" ||
        fail "$tree $profile direct stat/ftw source-form probe failed: $(sed -n '/error:/p' "$trace" | sed -n '1p')"
}

preprocess_profile() {
    local tree="$1" profile="$2" macros="$3" declarations="$4"
    set_tree "$tree"
    set_profile "$profile"
    printf '#include <ftw.h>\n' | run_compiler "$compiler" "${language_args[@]}" \
        "${include_args[@]}" "${profile_args[@]}" -dM -E - >"$macros" ||
        fail "$tree $profile macro preprocessing failed"
    printf '#include <ftw.h>\n' | run_compiler "$compiler" "${language_args[@]}" \
        "${include_args[@]}" "${profile_args[@]}" -E -P - >"$declarations" ||
        fail "$tree $profile declaration preprocessing failed"
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

check_topology() {
    local tree="$1" trace="$2" header
    case "$tree" in
        candidate) root="$PROJECT_INCLUDE" ;;
        reference) root="$MUSL_ROOT/include" ;;
        *) fail "unknown header tree: $tree" ;;
    esac
    check_trace_roots "$tree" "$trace"
    for header in ftw.h sys/stat.h features.h bits/alltypes.h bits/stat.h; do
        grep -Fq "$root/$header" "$trace" ||
            fail "$tree trace omitted $header from direct <ftw.h> topology"
    done
    for header in time.h sys/types.h fcntl.h; do
        if grep -Fq "$root/$header" "$trace"; then
            fail "$tree trace unexpectedly acquired $header through <ftw.h>"
        fi
    done
}

check_macro_form() {
    local macros="$1" form
    for form in \
        '#define S_ISDIR(mode) (((mode) & S_IFMT) == S_IFDIR)' \
        '#define S_ISCHR(mode) (((mode) & S_IFMT) == S_IFCHR)' \
        '#define S_ISBLK(mode) (((mode) & S_IFMT) == S_IFBLK)' \
        '#define S_ISREG(mode) (((mode) & S_IFMT) == S_IFREG)' \
        '#define S_ISFIFO(mode) (((mode) & S_IFMT) == S_IFIFO)' \
        '#define S_ISLNK(mode) (((mode) & S_IFMT) == S_IFLNK)' \
        '#define S_ISSOCK(mode) (((mode) & S_IFMT) == S_IFSOCK)'; do
        grep -Fxq "$form" "$macros" || fail "missing exact musl macro form: $form"
    done
    for macro in _BITS_STAT_H AT_FDCWD AT_SYMLINK_NOFOLLOW; do
        if grep -Eq "^#define ${macro}([[:space:](]|$)" "$macros"; then
            fail "unexpected x86 stat/ftw macro: $macro"
        fi
    done
}

check_legacy_aliases() {
    local profile="$1" macros="$2" form
    if profile_has_legacy_aliases "$profile"; then
        for form in '#define S_IREAD S_IRUSR' '#define S_IWRITE S_IWUSR' '#define S_IEXEC S_IXUSR'; do
            grep -Fxq "$form" "$macros" || fail "$profile omitted legacy alias: $form"
        done
    else
        for macro in S_IREAD S_IWRITE S_IEXEC; do
            if grep -Eq "^#define ${macro}([[:space:](]|$)" "$macros"; then
                fail "$profile unexpectedly exposed legacy alias: $macro"
            fi
        done
    fi
}

check_largefile_aliases() {
    local profile="$1" macros="$2" form
    if profile_has_largefile_aliases "$profile"; then
        for form in \
            '#define stat64 stat' '#define fstat64 fstat' '#define lstat64 lstat' \
            '#define fstatat64 fstatat' '#define blkcnt64_t blkcnt_t' \
            '#define fsblkcnt64_t fsblkcnt_t' '#define fsfilcnt64_t fsfilcnt_t' \
            '#define ino64_t ino_t' '#define off64_t off_t' '#define ftw64 ftw' \
            '#define nftw64 nftw'; do
            grep -Fxq "$form" "$macros" || fail "$profile omitted large-file alias: $form"
        done
    else
        for macro in stat64 fstat64 lstat64 fstatat64 ftw64 nftw64; do
            if grep -Eq "^#define ${macro}([[:space:](]|$)" "$macros"; then
                fail "$profile unexpectedly exposed large-file alias: $macro"
            fi
        done
    fi
}

extract_macro_forms() {
    local input="$1" output="$2"
    grep -E '^#define (S_ISDIR|S_ISCHR|S_ISBLK|S_ISREG|S_ISFIFO|S_ISLNK|S_ISSOCK|S_IREAD|S_IWRITE|S_IEXEC|_BITS_STAT_H|AT_FDCWD|AT_SYMLINK_NOFOLLOW|stat64|fstat64|lstat64|fstatat64|blkcnt64_t|fsblkcnt64_t|fsfilcnt64_t|ino64_t|off64_t|ftw64|nftw64)([[:space:](]|$)' "$input" >"$output" || true
}

extract_declarations() {
    local input="$1" output="$2"
    grep -E '^int (stat|lstat|fstatat)\(' "$input" >"$output" ||
        fail "preprocessed <sys/stat.h> lost one of stat/lstat/fstatat"
    [ "$(wc -l <"$output")" -eq 3 ] ||
        fail "preprocessed <sys/stat.h> must retain exactly three source-form declarations"
}

check_cxx_linkage() {
    local object="$1" symbol undefined
    undefined="$(nm --undefined-only "$object")"
    for symbol in stat lstat fstatat ftw nftw; do
        printf '%s\n' "$undefined" | grep -Eq "[[:space:]]${symbol}$" ||
            fail "C++ source-form probe lost C linkage for $symbol"
        if printf '%s\n' "$undefined" | grep -Eq "_Z[0-9].*${symbol}"; then
            fail "C++ source-form probe retained mangled linkage for $symbol"
        fi
    done
}

[ "$#" -eq 0 ] || fail "usage: $0"
require_native_linux_x86_64
for tool in cmp diff env grep mapfile mktemp nm realpath sed uname wc; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -x "$CANDIDATE_CC" ] || fail "missing raw native candidate compiler"
[ -d "$MUSL_ROOT/include" ] || fail "missing pinned musl include tree"
[ -d "$PROJECT_INCLUDE" ] || fail "missing project include tree"
[ -f "$C_PROBE" ] && [ -f "$CXX_PROBE" ] || fail "missing stat/ftw source-form probe"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
cmp -s "$PROJECT_INCLUDE/ftw.h" "$MUSL_ROOT/include/ftw.h" ||
    fail "x86 ftw.h no longer retains the pinned musl source form"

compiler_builtin="$(run_compiler "$CANDIDATE_CC" -print-file-name=include)"
compiler_builtin="$(realpath "$compiler_builtin")"
[ -d "$compiler_builtin" ] || fail "raw compiler builtin include root is missing"

work_dir="$(mktemp -d /tmp/crabc-x86-64-stat-ftw-header-source-form.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT

for profile in "${PROFILES[@]}"; do
    for tree in reference candidate; do
        trace="$work_dir/$tree-$profile.trace"
        object="$work_dir/$tree-$profile.o"
        macros="$work_dir/$tree-$profile.macros"
        declarations="$work_dir/$tree-$profile.declarations"
        compile_profile "$tree" "$profile" "$trace" "$object"
        preprocess_profile "$tree" "$profile" "$macros" "$declarations"
        check_topology "$tree" "$trace"
        check_macro_form "$macros"
        check_legacy_aliases "$profile" "$macros"
        check_largefile_aliases "$profile" "$macros"
        extract_macro_forms "$macros" "$work_dir/$tree-$profile.stat-ftw-macros"
        extract_declarations "$declarations" "$work_dir/$tree-$profile.stat-declarations"
        if profile_is_cxx "$profile"; then
            check_cxx_linkage "$object"
        fi
    done
    diff -u "$work_dir/reference-$profile.stat-ftw-macros" \
        "$work_dir/candidate-$profile.stat-ftw-macros" >"$work_dir/$profile.macros.diff" ||
        fail "$profile macro replacement forms differ from pinned musl"
    diff -u "$work_dir/reference-$profile.stat-declarations" \
        "$work_dir/candidate-$profile.stat-declarations" >"$work_dir/$profile.stat-declarations.diff" ||
        fail "$profile stat/lstat/fstatat declaration forms differ from pinned musl"
done

printf '%s\n' 'x86 pinned-musl/project C/C++ sys/stat.h through ftw.h source form: PASS (9 profiles)'
