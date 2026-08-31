#!/usr/bin/env bash
# Native Linux/x86-64 C/C++ <ulimit.h> declaration evidence.
#
# Pinned musl 1.2.6 is the declaration and C-linkage oracle. The historical
# variadic resource spelling is unconditional under default, strict, POSIX,
# X/Open, GNU, and BSD selectors; this gate neither links nor selects a
# process-resource capability.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 ulimit.h ulimit ABI: %s\n' "$*" >&2
    exit 1
}

require_native_linux_x86_64() {
    [ "$(uname -s)" = Linux ] || fail "requires native Linux"
    case "$(uname -m)" in
        x86_64|amd64) ;;
        *) fail "refuses emulation on $(uname -m)" ;;
    esac
}

require_native_linux_x86_64
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
command -v nm >/dev/null 2>&1 || fail "requires nm"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

c_probe="$ROOT_DIR/compat/x86_64/ulimit_header_abi_probe.c"
cxx_probe="$ROOT_DIR/compat/x86_64/ulimit_header_abi_probe.cpp"
work_dir="$(mktemp -d /tmp/crabc-x86-64-ulimit-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
header_trace="$work_dir/header-trace"

compile_profile() {
    local label="$1"
    shift
    local variant

    for variant in oracle project; do
        local -a include_args=()
        [ "$variant" = project ] && include_args=(-I "$ROOT_DIR/include")
        "$ORACLE_CC" -std=c11 -U_GNU_SOURCE -DCRABC_EXPECT_ULIMIT "$@" \
            -fno-builtin -fsyntax-only "${include_args[@]}" "$c_probe"
        "$ORACLE_CC" -std=c++17 -x c++ -U_GNU_SOURCE \
            -DCRABC_EXPECT_ULIMIT "$@" -fno-builtin -fsyntax-only \
            "${include_args[@]}" "$cxx_probe"
    done
    : "$label"
}

compile_profile default
compile_profile strict -D__STRICT_ANSI__
compile_profile posix-source -D_POSIX_SOURCE
compile_profile posix-2008 -D_POSIX_C_SOURCE=200809L
compile_profile xopen -D_XOPEN_SOURCE=700
compile_profile gnu -D_GNU_SOURCE
compile_profile bsd -D_BSD_SOURCE

if ! "$ORACLE_CC" -std=c11 -U_GNU_SOURCE -D_POSIX_C_SOURCE=200809L \
    -DCRABC_EXPECT_ULIMIT -fno-builtin -I "$ROOT_DIR/include" -H \
    -fsyntax-only "$c_probe" >/dev/null 2>"$header_trace"; then
    sed -n '1,160p' "$header_trace" >&2
    fail "project C ulimit header contract drifted"
fi
grep -Fq "$ROOT_DIR/include/ulimit.h" "$header_trace" ||
    fail "C probe did not use the project <ulimit.h>"

for variant in oracle project; do
    include_args=()
    [ "$variant" = project ] && include_args=(-I "$ROOT_DIR/include")
    object="$work_dir/${variant}-ulimit-cxx.o"
    "$ORACLE_CC" -std=c++17 -x c++ -U_GNU_SOURCE \
        -D_POSIX_C_SOURCE=200809L -DCRABC_EXPECT_ULIMIT -fno-builtin \
        "${include_args[@]}" -c "$cxx_probe" -o "$object"
    undefined="$(nm --undefined-only "$object")"
    printf '%s\n' "$undefined" | grep -Eq '[[:space:]]ulimit$' ||
        fail "C++ probe does not retain C linkage for ulimit (${variant})"
    if printf '%s\n' "$undefined" | grep -Eq '_Z.*ulimit'; then
        fail "C++ probe retained a mangled ulimit reference (${variant})"
    fi
done

printf 'x86 pinned-musl/project C/C++ <ulimit.h> ulimit ABI: PASS\n'
