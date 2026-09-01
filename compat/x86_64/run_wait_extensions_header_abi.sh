#!/usr/bin/env bash
# Native Linux/x86-64 GNU/BSD <sys/wait.h> wait3/wait4 declaration boundary.
#
# Pinned musl 1.2.6 is the feature-test and C-linkage oracle. `wait3` and
# `wait4` are intentionally absent in strict/POSIX profiles and visible only
# with GNU or BSD source selection; this runner makes both halves observable
# for C and C++ before the static archive is considered.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 sys/wait.h wait extensions ABI: %s\n' "$*" >&2
    exit 1
}

expect_hidden() {
    local language="$1" profile="$2" include_path="$3"
    shift 3

    if "$ORACLE_CC" "$@" -Werror=implicit-function-declaration \
        -DCRABC_WAIT_EXTENSIONS_EXPECT_HIDDEN $include_path \
        -fsyntax-only "$language" >/dev/null 2>&1; then
        fail "${profile} unexpectedly exposes wait3/wait4 for ${include_path:-pinned musl}"
    fi
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "requires native x86-64" ;; esac
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
command -v nm >/dev/null 2>&1 || fail "requires nm"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

c_probe="$ROOT_DIR/compat/x86_64/wait_extensions_header_abi_probe.c"
cxx_probe="$ROOT_DIR/compat/x86_64/wait_extensions_header_abi_probe.cpp"
work_dir="$(mktemp -d /tmp/crabc-x86-64-wait-extensions-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
header_trace="$work_dir/header-trace"

# First prove the negative feature-test contract.  Explicitly undefine the
# extensions so inherited compiler environment cannot accidentally make this
# source-only test visible.
for profile in strict posix; do
    case "$profile" in
        strict) feature_args=() ;;
        posix) feature_args=(-D_POSIX_C_SOURCE=200809L) ;;
    esac
    expect_hidden "$c_probe" "$profile C" "" -std=c11 -U_GNU_SOURCE \
        -U_BSD_SOURCE -fno-builtin "${feature_args[@]}"
    expect_hidden "$c_probe" "$profile project C" "-I $ROOT_DIR/include" \
        -std=c11 -U_GNU_SOURCE -U_BSD_SOURCE -fno-builtin "${feature_args[@]}"
    expect_hidden "$cxx_probe" "$profile C++" "" -std=c++17 -x c++ \
        -U_GNU_SOURCE -U_BSD_SOURCE -fno-builtin "${feature_args[@]}"
    expect_hidden "$cxx_probe" "$profile project C++" "-I $ROOT_DIR/include" \
        -std=c++17 -x c++ -U_GNU_SOURCE -U_BSD_SOURCE -fno-builtin \
        "${feature_args[@]}"
done

# GNU and BSD must expose the exact C signatures and the rusage ABI used as
# Linux wait4's fourth x86-64 argument.  The same source is compiled against
# musl and the project headers.
for profile in gnu bsd; do
    case "$profile" in
        gnu) feature_args=(-D_GNU_SOURCE) ;;
        bsd) feature_args=(-D_BSD_SOURCE) ;;
    esac
    for probe in "$c_probe" "$cxx_probe"; do
        if [ "$probe" = "$c_probe" ]; then
            language_args=(-std=c11)
        else
            language_args=(-std=c++17 -x c++)
        fi
        "$ORACLE_CC" "${language_args[@]}" -U_GNU_SOURCE -U_BSD_SOURCE \
            -fno-builtin "${feature_args[@]}" \
            -DCRABC_WAIT_EXTENSIONS_VISIBLE -fsyntax-only "$probe"
        "$ORACLE_CC" "${language_args[@]}" -U_GNU_SOURCE -U_BSD_SOURCE \
            -fno-builtin "${feature_args[@]}" \
            -DCRABC_WAIT_EXTENSIONS_VISIBLE -I "$ROOT_DIR/include" \
            -fsyntax-only "$probe"
    done
done

"$ORACLE_CC" -std=c11 -U_GNU_SOURCE -U_BSD_SOURCE -D_GNU_SOURCE \
    -DCRABC_WAIT_EXTENSIONS_VISIBLE -I "$ROOT_DIR/include" -H -fno-builtin \
    -fsyntax-only "$c_probe" >/dev/null 2>"$header_trace" || {
    sed -n '1,160p' "$header_trace" >&2
    fail "project GNU C wait-extension header contract drifted"
}
for header in features.h sys/wait.h sys/resource.h sys/time.h sys/types.h \
    bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "GNU C probe did not use the project <$header>"
done

# The visible C++ declarations must retain unmangled C references in both GNU
# and BSD profiles.  Function-pointer initializers ensure the object contains
# exactly the linkage names this header promises.
for profile in gnu bsd; do
    case "$profile" in
        gnu) feature_args=(-D_GNU_SOURCE) ;;
        bsd) feature_args=(-D_BSD_SOURCE) ;;
    esac
    for tree in oracle project; do
        object="$work_dir/${profile}-${tree}.o"
        include_args=()
        if [ "$tree" = project ]; then
            include_args=(-I "$ROOT_DIR/include")
        fi
        "$ORACLE_CC" -std=c++17 -x c++ -U_GNU_SOURCE -U_BSD_SOURCE \
            -fno-builtin "${feature_args[@]}" \
            -DCRABC_WAIT_EXTENSIONS_VISIBLE "${include_args[@]}" \
            -c "$cxx_probe" -o "$object"
        undefined="$(nm --undefined-only "$object")"
        for symbol in wait3 wait4; do
            printf '%s\n' "$undefined" | grep -Eq "[[:space:]]${symbol}$" ||
                fail "${profile} ${tree} C++ probe lacks C linkage for ${symbol}"
        done
        if printf '%s\n' "$undefined" | grep -Eq '_Z(5wait3|5wait4)'; then
            fail "${profile} ${tree} C++ probe retains mangled wait-extension reference"
        fi
    done
done

printf 'x86 pinned-musl/project C/C++ <sys/wait.h> wait extensions ABI: PASS\n'
