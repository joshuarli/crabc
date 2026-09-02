#!/usr/bin/env bash
# Native Linux/x86-64 complete pinned-musl <sys/quota.h> ABI proof.
#
# Pinned musl 1.2.6 is the declaration and macro oracle. This header-only
# gate proves the full musl quota header's exact unconditional
# dbtob/btodb/fs_to_dq_blocks/dqoff conversion macros, constants, legacy
# aliases, dqblk and dqinfo LP64 layouts, and C/C++ quotactl declaration
# through compile-time assertions.
# It does not link or execute `quotactl`; it selects no quota policy/accounting,
# filesystem/kernel state, or system.kernel-admin behavior.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 quota header ABI: %s\n' "$*" >&2
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
for tool in grep mktemp uname; do
    command -v "$tool" >/dev/null 2>&1 || fail "requires $tool"
done

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

readonly C_PROBE="$ROOT_DIR/compat/x86_64/quota_header_abi_probe.c"
readonly CXX_PROBE="$ROOT_DIR/compat/x86_64/quota_header_abi_probe.cpp"
[ -f "$C_PROBE" ] || fail "missing C quota header probe"
[ -f "$CXX_PROBE" ] || fail "missing C++ quota header probe"

work_dir="$(mktemp -d /tmp/crabc-x86-64-quota-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
header_trace="$work_dir/project-header-trace"

compile_profile() {
    local name="$1"
    shift
    local -a flags=("$@")

    "$ORACLE_CC" -std=c11 "${flags[@]}" -fsyntax-only "$C_PROBE"
    "$ORACLE_CC" -std=c11 "${flags[@]}" -I "$ROOT_DIR/include" \
        -fsyntax-only "$C_PROBE"
}

compile_cxx_profile() {
    local name="$1"
    shift
    local -a flags=("$@")

    "$ORACLE_CC" -std=c++17 -x c++ "${flags[@]}" -fsyntax-only "$CXX_PROBE"
    "$ORACLE_CC" -std=c++17 -x c++ "${flags[@]}" -I "$ROOT_DIR/include" \
        -fsyntax-only "$CXX_PROBE"
}

# Musl exposes this full header surface unconditionally. Each C and C++ profile
# checks the same header-only constant-expression syntax without linking or
# executing a test image.
compile_profile strict -U_GNU_SOURCE -U_BSD_SOURCE -D__STRICT_ANSI__
compile_profile posix -U_GNU_SOURCE -U_BSD_SOURCE -D_POSIX_C_SOURCE=200809L
compile_profile xopen -U_GNU_SOURCE -U_BSD_SOURCE -D_XOPEN_SOURCE=700
compile_profile gnu -U_BSD_SOURCE -D_GNU_SOURCE
compile_profile bsd -U_GNU_SOURCE -D_BSD_SOURCE
compile_cxx_profile gnu -U_BSD_SOURCE -D_GNU_SOURCE
compile_cxx_profile cxx17-strict -U_GNU_SOURCE -U_BSD_SOURCE

# Project headers must be first and self-contained. No quota archive or kernel
# interaction is admitted by this compile-only gate.
"$ORACLE_CC" -std=c11 -U_GNU_SOURCE -U_BSD_SOURCE -D__STRICT_ANSI__ \
    -I "$ROOT_DIR/include" -H -fsyntax-only "$C_PROBE" \
    >/dev/null 2>"$header_trace"
grep -Fq "$ROOT_DIR/include/sys/quota.h" "$header_trace" ||
    fail "C probe did not use project <sys/quota.h>"

printf 'x86 pinned-musl/project C/C++ <sys/quota.h> complete header: PASS\n'
