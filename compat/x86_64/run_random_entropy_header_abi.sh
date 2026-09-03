#!/usr/bin/env bash
# Native Linux/x86-64 compile-only <sys/random.h>/<unistd.h> ABI slice.
#
# Pinned musl 1.2.6 is the declaration/value oracle.  Project headers are
# placed first for the candidate pass; neither pass links or selects
# crabc-libc.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 random-entropy headers: %s\n' "$*" >&2
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
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

c_probe="$ROOT_DIR/compat/x86_64/random_entropy_header_abi_probe.c"
cxx_probe="$ROOT_DIR/compat/x86_64/random_entropy_header_abi_probe.cpp"
work_dir="$(mktemp -d /tmp/crabc-x86-64-random-entropy-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
header_trace="$work_dir/header-trace"

# Baseline and feature-selected declarations must compile against the pinned
# oracle.  C++ is checked positively under both selectors; g++ itself enables
# GNU declarations, so strict C++ is not used as a negative feature test.
"$ORACLE_CC" -std=c11 -Werror=implicit-function-declaration -fsyntax-only "$c_probe"
"$ORACLE_CC" -std=c++17 -x c++ -fsyntax-only "$cxx_probe"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_EXPECT_GETENTROPY \
    -fsyntax-only "$c_probe"
"$ORACLE_CC" -std=c11 -D_BSD_SOURCE -DCRABC_EXPECT_GETENTROPY \
    -fsyntax-only "$c_probe"
"$ORACLE_CC" -std=c++17 -x c++ -D_GNU_SOURCE -DCRABC_EXPECT_GETENTROPY \
    -fsyntax-only "$cxx_probe"
"$ORACLE_CC" -std=c++17 -x c++ -D_BSD_SOURCE -DCRABC_EXPECT_GETENTROPY \
    -fsyntax-only "$cxx_probe"

# Strict C must reject use of the feature-gated getentropy declaration.  Keep
# this expected failure for both oracle and project headers so a declaration
# accidentally leaking into the strict namespace is visible.
if "$ORACLE_CC" -std=c11 -Werror=implicit-function-declaration \
    -DCRABC_EXPECT_GETENTROPY_HIDDEN -fsyntax-only "$c_probe" \
    >"$work_dir/oracle-hidden.out" 2>&1; then
    cat "$work_dir/oracle-hidden.out" >&2
    fail "pinned musl C header exposes getentropy in strict mode"
fi

if ! "$ORACLE_CC" -std=c11 -Werror=implicit-function-declaration \
    -I "$ROOT_DIR/include" -H -fsyntax-only "$c_probe" \
    >/dev/null 2>"$header_trace"; then
    cat "$header_trace" >&2
    fail "project C random-entropy header contract drifted"
fi
for header in sys/random.h unistd.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" \
        || fail "C probe did not use the project $header"
done
if grep -Fq "$ROOT_DIR/include/sys/types.h" "$header_trace"; then
    fail "C random-entropy header closure retained broad project sys/types.h"
fi

"$ORACLE_CC" -std=c++17 -x c++ -I "$ROOT_DIR/include" \
    -fsyntax-only "$cxx_probe"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_EXPECT_GETENTROPY \
    -I "$ROOT_DIR/include" -fsyntax-only "$c_probe"
"$ORACLE_CC" -std=c11 -D_BSD_SOURCE -DCRABC_EXPECT_GETENTROPY \
    -I "$ROOT_DIR/include" -fsyntax-only "$c_probe"
"$ORACLE_CC" -std=c++17 -x c++ -D_GNU_SOURCE -DCRABC_EXPECT_GETENTROPY \
    -I "$ROOT_DIR/include" -fsyntax-only "$cxx_probe"
"$ORACLE_CC" -std=c++17 -x c++ -D_BSD_SOURCE -DCRABC_EXPECT_GETENTROPY \
    -I "$ROOT_DIR/include" -fsyntax-only "$cxx_probe"

if "$ORACLE_CC" -std=c11 -Werror=implicit-function-declaration \
    -I "$ROOT_DIR/include" -DCRABC_EXPECT_GETENTROPY_HIDDEN \
    -fsyntax-only "$c_probe" >"$work_dir/project-hidden.out" 2>&1; then
    cat "$work_dir/project-hidden.out" >&2
    fail "project C header exposes getentropy in strict mode"
fi

printf 'x86 pinned-musl/project C/C++ random-entropy headers: PASS\n'
