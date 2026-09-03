#!/usr/bin/env bash
# Native Linux/x86-64 ftime C/C++ declaration and timeb-layout gate.
#
# Pinned musl 1.2.6 is the declaration/layout and C-linkage oracle. The
# project pass puts its headers first. This compile-only proof admits exactly
# the legacy `int ftime(struct timeb *)` spelling and its public LP64 record;
# it selects no clock policy, timer, signal, or calendar runtime.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 sys/timeb.h ftime ABI: %s\n' "$*" >&2
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

c_probe="$ROOT_DIR/compat/x86_64/ftime_header_abi_probe.c"
cxx_probe="$ROOT_DIR/compat/x86_64/ftime_header_abi_probe.cpp"
work_dir="$(mktemp -d /tmp/crabc-x86-64-ftime-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
header_trace="$work_dir/header-trace"
oracle_cxx_object="$work_dir/oracle-ftime-cxx.o"
candidate_cxx_object="$work_dir/candidate-ftime-cxx.o"

default_definitions=()
strict_definitions=(-D__STRICT_ANSI__)
posix_definitions=(-D_POSIX_C_SOURCE=200809L)
xopen_definitions=(-D_XOPEN_SOURCE=700)
gnu_definitions=(-D_GNU_SOURCE)

for definitions_name in default_definitions strict_definitions posix_definitions \
    xopen_definitions gnu_definitions; do
    declare -n definitions="$definitions_name"
    "$ORACLE_CC" -std=c11 -fsyntax-only "${definitions[@]}" "$c_probe"
    "$ORACLE_CC" -std=c11 -I "$ROOT_DIR/include" -fsyntax-only \
        "${definitions[@]}" "$c_probe"
    "$ORACLE_CC" -std=c++17 -x c++ -U_GNU_SOURCE "${definitions[@]}" \
        -fsyntax-only "$cxx_probe"
    "$ORACLE_CC" -std=c++17 -x c++ -U_GNU_SOURCE -I "$ROOT_DIR/include" \
        "${definitions[@]}" -fsyntax-only "$cxx_probe"
done

# -H makes project-header provenance observable rather than merely compiling
# against an ambient sys/timeb.h.
if ! "$ORACLE_CC" -std=c11 -I "$ROOT_DIR/include" -H -fsyntax-only \
    "$c_probe" >/dev/null 2>"$header_trace"; then
    sed -n '1,160p' "$header_trace" >&2
    fail "project ftime header contract drifted"
fi
for header in sys/timeb.h features.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "C probe did not use the project <$header>"
done
if grep -Fq "$ROOT_DIR/include/sys/types.h" "$header_trace"; then
    fail "C probe unexpectedly retained the project <sys/types.h> type-owner shortcut"
fi

"$ORACLE_CC" -std=c++17 -x c++ -U_GNU_SOURCE -c "$cxx_probe" \
    -o "$oracle_cxx_object"
"$ORACLE_CC" -std=c++17 -x c++ -U_GNU_SOURCE -I "$ROOT_DIR/include" \
    -c "$cxx_probe" -o "$candidate_cxx_object"
for object in "$oracle_cxx_object" "$candidate_cxx_object"; do
    undefined="$(nm --undefined-only "$object")"
    printf '%s\n' "$undefined" | grep -Eq '[[:space:]]ftime$' ||
        fail "C++ probe does not retain C linkage for ftime"
    if printf '%s\n' "$undefined" | grep -Eq '_Z.*ftime'; then
        fail "C++ probe retained a mangled ftime reference"
    fi
done

printf 'x86 pinned-musl/project C/C++ <sys/timeb.h> ftime ABI: PASS\n'
