#!/usr/bin/env bash
# Native Linux/x86-64 compile-only <sys/resource.h> ABI slice.
#
# Pinned musl 1.2.6 is the declaration/value oracle. Project headers are
# placed first for the candidate pass; neither pass links or selects
# crabc-libc.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 sys/resource.h ABI: %s\n' "$*" >&2
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

c_probe="$ROOT_DIR/compat/x86_64/resource_header_abi_probe.c"
cxx_probe="$ROOT_DIR/compat/x86_64/resource_header_abi_probe.cpp"
work_dir="$(mktemp -d /tmp/crabc-x86-64-resource-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
header_trace="$work_dir/header-trace"
readonly -a GNU_LFS_FLAGS=(-D_GNU_SOURCE -D_LARGEFILE64_SOURCE)

# First prove the strict and extension assertions themselves match pinned musl.
"$ORACLE_CC" -std=c11 -fsyntax-only "$c_probe"
"$ORACLE_CC" -std=c++17 -x c++ -fsyntax-only "$cxx_probe"
"$ORACLE_CC" -std=c11 "${GNU_LFS_FLAGS[@]}" -fsyntax-only "$c_probe"
"$ORACLE_CC" -std=c++17 -x c++ "${GNU_LFS_FLAGS[@]}" -fsyntax-only "$cxx_probe"

# Then prove the same C/C++ contract through project headers, recording the
# direct provenance of the resource/time/type dependency boundary.
if ! "$ORACLE_CC" -std=c11 -I "$ROOT_DIR/include" -H -fsyntax-only "$c_probe" \
    >/dev/null 2>"$header_trace"; then
    cat "$header_trace" >&2
    fail "project C resource-header contract drifted"
fi
for header in sys/resource.h sys/time.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" \
        || fail "C probe did not use the project $header"
done
"$ORACLE_CC" -std=c++17 -x c++ -I "$ROOT_DIR/include" -fsyntax-only "$cxx_probe"
"$ORACLE_CC" -std=c11 "${GNU_LFS_FLAGS[@]}" -I "$ROOT_DIR/include" \
    -fsyntax-only "$c_probe"
"$ORACLE_CC" -std=c++17 -x c++ "${GNU_LFS_FLAGS[@]}" -I "$ROOT_DIR/include" \
    -fsyntax-only "$cxx_probe"

printf 'x86 pinned-musl C/C++ <sys/resource.h> ABI: PASS\n'
