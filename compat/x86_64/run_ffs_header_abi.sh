#!/usr/bin/env bash
# Native Linux/x86-64 compile-only <strings.h> find-first-set ABI slice.
#
# Pinned musl 1.2.6 is the declaration and C-linkage oracle. Project headers
# are placed first for the candidate pass; neither pass links or selects
# crabc-libc. The ffs family is visible only through XOPEN, GNU, or BSD
# feature selection and stays hidden under strict/POSIX-only selection.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 strings.h find-first-set ABI: %s\n' "$*" >&2
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

c_probe="$ROOT_DIR/compat/x86_64/ffs_header_abi_probe.c"
cxx_probe="$ROOT_DIR/compat/x86_64/ffs_header_abi_probe.cpp"
work_dir="$(mktemp -d /tmp/crabc-x86-64-ffs-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
header_trace="$work_dir/header-trace"
oracle_cxx_object="$work_dir/oracle-ffs-cxx.o"
candidate_cxx_object="$work_dir/candidate-ffs-cxx.o"

for selector in -D_XOPEN_SOURCE=700 -D_GNU_SOURCE -D_BSD_SOURCE; do
    "$ORACLE_CC" -std=c11 "$selector" -DCRABC_EXPECT_FFS -fno-builtin \
        -fsyntax-only "$c_probe"
    "$ORACLE_CC" -std=c++17 -x c++ "$selector" -DCRABC_EXPECT_FFS \
        -fno-builtin -fsyntax-only "$cxx_probe"
    "$ORACLE_CC" -std=c11 "$selector" -DCRABC_EXPECT_FFS -fno-builtin \
        -I "$ROOT_DIR/include" -fsyntax-only "$c_probe"
    "$ORACLE_CC" -std=c++17 -x c++ "$selector" -DCRABC_EXPECT_FFS \
        -fno-builtin -I "$ROOT_DIR/include" -fsyntax-only "$cxx_probe"
done

# -H makes candidate-header provenance observable rather than merely compiling
# against whichever ambient strings.h happens to be installed.
if ! "$ORACLE_CC" -std=c11 -D_XOPEN_SOURCE=700 -DCRABC_EXPECT_FFS \
    -fno-builtin -I "$ROOT_DIR/include" -H -fsyntax-only "$c_probe" \
    >/dev/null 2>"$header_trace"; then
    cat "$header_trace" >&2
    fail "project C find-first-set header contract drifted"
fi
for header in strings.h features.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" || {
        fail "C probe did not use the project <$header>"
    }
done

# C++ references must remain unmangled C symbols, not merely type-compatible
# declarations. This also closes the existing strings.h linkage boundary.
"$ORACLE_CC" -std=c++17 -x c++ -D_XOPEN_SOURCE=700 -DCRABC_EXPECT_FFS \
    -fno-builtin -c "$cxx_probe" -o "$oracle_cxx_object"
"$ORACLE_CC" -std=c++17 -x c++ -D_XOPEN_SOURCE=700 -DCRABC_EXPECT_FFS \
    -fno-builtin -I "$ROOT_DIR/include" -c "$cxx_probe" \
    -o "$candidate_cxx_object"
for object in "$oracle_cxx_object" "$candidate_cxx_object"; do
    undefined="$(nm --undefined-only "$object")"
    for symbol in ffs ffsl ffsll; do
        printf '%s\n' "$undefined" | grep -Eq "[[:space:]]${symbol}$" || {
            fail "C++ probe does not retain C linkage for ${symbol}"
        }
    done
    if printf '%s\n' "$undefined" | grep -Eq '_Z(3ffs|4ffsl|5ffsll)'; then
        fail "C++ probe retained a mangled find-first-set reference"
    fi
done

for selector in -D_POSIX_SOURCE -D_POSIX_C_SOURCE=200809L; do
    if "$ORACLE_CC" -std=c11 "$selector" -DCRABC_REQUIRE_FFS_HIDDEN \
        -fno-builtin -fsyntax-only "$c_probe" \
        >/dev/null 2>"$work_dir/oracle-c-hidden-errors"; then
        fail "pinned musl exposes ffs outside XOPEN/GNU/BSD selection"
    fi
    if "$ORACLE_CC" -std=c11 "$selector" -DCRABC_REQUIRE_FFS_HIDDEN \
        -fno-builtin -I "$ROOT_DIR/include" -fsyntax-only "$c_probe" \
        >/dev/null 2>"$work_dir/project-c-hidden-errors"; then
        fail "project strings.h exposes ffs outside XOPEN/GNU/BSD selection"
    fi
    # The pinned compiler specs inject _GNU_SOURCE for C++; remove that
    # ambient selection so this checks the header's strict/POSIX gate itself.
    if "$ORACLE_CC" -std=c++17 -x c++ "$selector" \
        -U_GNU_SOURCE -DCRABC_REQUIRE_FFS_HIDDEN -fno-builtin \
        -fsyntax-only "$cxx_probe" \
        >/dev/null 2>"$work_dir/oracle-cxx-hidden-errors"; then
        fail "pinned musl exposes ffs to strict/POSIX C++"
    fi
    if "$ORACLE_CC" -std=c++17 -x c++ "$selector" \
        -U_GNU_SOURCE -DCRABC_REQUIRE_FFS_HIDDEN -fno-builtin \
        -I "$ROOT_DIR/include" \
        -fsyntax-only "$cxx_probe" \
        >/dev/null 2>"$work_dir/project-cxx-hidden-errors"; then
        fail "project strings.h exposes ffs to strict/POSIX C++"
    fi
done

printf 'x86 pinned-musl/project C/C++ <strings.h> find-first-set ABI: PASS\n'
