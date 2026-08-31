#!/usr/bin/env bash
# Native Linux/x86-64 GNU/BSD mktemp C/C++ declaration gate.
#
# Pinned musl 1.2.6 is the declaration and C-linkage oracle. The candidate
# pass puts project headers first. This compile-only boundary establishes only
# the historical `char *mktemp(char *)` spelling: it selects no pathname
# creation, temporary-file policy, tmpnam/tempnam surface, or handle API.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 stdlib.h mktemp ABI: %s\n' "$*" >&2
    exit 1
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in
    x86_64|amd64) ;;
    *) fail "requires native x86-64" ;;
esac
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
command -v nm >/dev/null 2>&1 || fail "requires nm"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

c_probe="$ROOT_DIR/compat/x86_64/mktemp_header_abi_probe.c"
cxx_probe="$ROOT_DIR/compat/x86_64/mktemp_header_abi_probe.cpp"
work_dir="$(mktemp -d /tmp/crabc-x86-64-mktemp-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
header_trace="$work_dir/header-trace"
oracle_cxx_object="$work_dir/oracle-mktemp-cxx.o"
candidate_cxx_object="$work_dir/candidate-mktemp-cxx.o"

for selector in -D_GNU_SOURCE -D_BSD_SOURCE; do
    "$ORACLE_CC" -std=c11 "$selector" -DCRABC_EXPECT_MKTEMP -fno-builtin \
        -fsyntax-only "$c_probe"
    "$ORACLE_CC" -std=c++17 -x c++ "$selector" -DCRABC_EXPECT_MKTEMP \
        -fno-builtin -fsyntax-only "$cxx_probe"
    "$ORACLE_CC" -std=c11 "$selector" -DCRABC_EXPECT_MKTEMP -fno-builtin \
        -I "$ROOT_DIR/include" -fsyntax-only "$c_probe"
    "$ORACLE_CC" -std=c++17 -x c++ "$selector" -DCRABC_EXPECT_MKTEMP \
        -fno-builtin -I "$ROOT_DIR/include" -fsyntax-only "$cxx_probe"
done

if ! "$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_EXPECT_MKTEMP \
    -fno-builtin -I "$ROOT_DIR/include" -H -fsyntax-only "$c_probe" \
    >/dev/null 2>"$header_trace"; then
    sed -n '1,160p' "$header_trace" >&2
    fail "project C mktemp header contract drifted"
fi
for header in stdlib.h features.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "C probe did not use the project <$header>"
done

"$ORACLE_CC" -std=c++17 -x c++ -D_GNU_SOURCE -DCRABC_EXPECT_MKTEMP \
    -fno-builtin -c "$cxx_probe" -o "$oracle_cxx_object"
"$ORACLE_CC" -std=c++17 -x c++ -D_GNU_SOURCE -DCRABC_EXPECT_MKTEMP \
    -fno-builtin -I "$ROOT_DIR/include" -c "$cxx_probe" \
    -o "$candidate_cxx_object"
for object in "$oracle_cxx_object" "$candidate_cxx_object"; do
    undefined="$(nm --undefined-only "$object")"
    printf '%s\n' "$undefined" | grep -Eq '[[:space:]]mktemp$' ||
        fail "C++ probe does not retain C linkage for mktemp"
    if printf '%s\n' "$undefined" | grep -Eq '_Z6mktempPc'; then
        fail "C++ probe retained a mangled mktemp reference"
    fi
done

for selector in -D_POSIX_SOURCE -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700; do
    if "$ORACLE_CC" -std=c11 "$selector" -DCRABC_REQUIRE_MKTEMP_HIDDEN \
        -fno-builtin -fsyntax-only "$c_probe" \
        >/dev/null 2>"$work_dir/oracle-c-hidden-errors"; then
        fail "pinned musl exposes mktemp outside GNU/BSD selection"
    fi
    if "$ORACLE_CC" -std=c11 "$selector" -DCRABC_REQUIRE_MKTEMP_HIDDEN \
        -fno-builtin -I "$ROOT_DIR/include" -fsyntax-only "$c_probe" \
        >/dev/null 2>"$work_dir/project-c-hidden-errors"; then
        fail "project stdlib.h exposes mktemp outside GNU/BSD selection"
    fi
    if "$ORACLE_CC" -std=c++17 -x c++ "$selector" -U_GNU_SOURCE \
        -DCRABC_REQUIRE_MKTEMP_HIDDEN -fno-builtin -fsyntax-only "$cxx_probe" \
        >/dev/null 2>"$work_dir/oracle-cxx-hidden-errors"; then
        fail "pinned musl exposes mktemp to strict/POSIX C++"
    fi
    if "$ORACLE_CC" -std=c++17 -x c++ "$selector" -U_GNU_SOURCE \
        -DCRABC_REQUIRE_MKTEMP_HIDDEN -fno-builtin -I "$ROOT_DIR/include" \
        -fsyntax-only "$cxx_probe" \
        >/dev/null 2>"$work_dir/project-cxx-hidden-errors"; then
        fail "project stdlib.h exposes mktemp to strict/POSIX C++"
    fi
done

printf 'x86 pinned-musl/project C/C++ <stdlib.h> mktemp ABI: PASS\n'
