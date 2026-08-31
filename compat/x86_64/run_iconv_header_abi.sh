#!/usr/bin/env bash
# Native Linux/x86-64 C11/C++17 <iconv.h> selected UTF/ASCII ABI gate.
#
# Pinned musl 1.2.6 is the declaration and C++ C-linkage oracle. Project
# headers are first for the candidate pass; neither pass links crabc-libc or
# selects a locale database, legacy codepage table, dynamic runtime, CRT,
# loader, sysroot, or public x86 support.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly C_PROBE="$ROOT_DIR/compat/x86_64/iconv_header_abi_probe.c"
readonly CXX_PROBE="$ROOT_DIR/compat/x86_64/iconv_header_abi_probe.cpp"

fail() {
    printf 'ERROR: x86 iconv header ABI: %s\n' "$*" >&2
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
for tool in grep mktemp nm sed; do
    command -v "$tool" >/dev/null 2>&1 || fail "requires $tool"
done
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-iconv-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
trace="$work_dir/project-c.trace"
oracle_cxx_object="$work_dir/oracle-iconv-cxx.o"
candidate_cxx_object="$work_dir/candidate-iconv-cxx.o"

"$ORACLE_CC" -std=c11 -fno-builtin -fsyntax-only "$C_PROBE"
"$ORACLE_CC" -std=c++17 -x c++ -fno-builtin -fsyntax-only "$CXX_PROBE"
"$ORACLE_CC" -std=c11 -fno-builtin -I "$ROOT_DIR/include" -fsyntax-only "$C_PROBE"
"$ORACLE_CC" -std=c++17 -x c++ -fno-builtin -I "$ROOT_DIR/include" \
    -fsyntax-only "$CXX_PROBE"

if ! "$ORACLE_CC" -std=c11 -fno-builtin -I "$ROOT_DIR/include" -H \
    -fsyntax-only "$C_PROBE" >/dev/null 2>"$trace"; then
    sed -n '1,160p' "$trace" >&2
    fail "project C iconv header contract drifted"
fi
for header in iconv.h features.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$trace" ||
        fail "C probe did not use the project <$header>"
done

# C++ references must retain exactly the public unmangled C spellings. This
# proves the header's extern-C boundary without selecting its runtime
# implementation.
"$ORACLE_CC" -std=c++17 -x c++ -fno-builtin -c "$CXX_PROBE" \
    -o "$oracle_cxx_object"
"$ORACLE_CC" -std=c++17 -x c++ -fno-builtin -I "$ROOT_DIR/include" \
    -c "$CXX_PROBE" -o "$candidate_cxx_object"
for object in "$oracle_cxx_object" "$candidate_cxx_object"; do
    undefined="$(nm --undefined-only "$object")"
    for symbol in iconv iconv_close iconv_open; do
        printf '%s\n' "$undefined" | grep -Eq "[[:space:]]${symbol}$" ||
            fail "C++ probe does not retain C linkage for ${symbol}"
    done
    if printf '%s\n' "$undefined" | grep -Eq '^.*[[:space:]]_Z.*iconv'; then
        fail "C++ probe retained a mangled iconv reference"
    fi
done

printf 'x86 pinned-musl/project C/C++ <iconv.h> ABI: PASS\n'
