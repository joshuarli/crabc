#!/usr/bin/env bash
# Native Linux/x86-64 compile-only <inttypes.h> intmax arithmetic ABI slice.
#
# Pinned musl 1.2.6 is the declaration and C-linkage oracle. Project headers
# are placed first for the candidate pass; neither pass links or selects
# crabc-libc. Both selected declarations are unconditional.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 inttypes.h intmax arithmetic ABI: %s\n' "$*" >&2
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

c_probe="$ROOT_DIR/compat/x86_64/intmax_arithmetic_header_abi_probe.c"
cxx_probe="$ROOT_DIR/compat/x86_64/intmax_arithmetic_header_abi_probe.cpp"
work_dir="$(mktemp -d /tmp/crabc-x86-64-intmax-arithmetic-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
header_trace="$work_dir/header-trace"
oracle_cxx_object="$work_dir/oracle-intmax-arithmetic-cxx.o"
candidate_cxx_object="$work_dir/candidate-intmax-arithmetic-cxx.o"

"$ORACLE_CC" -std=c11 -fno-builtin -fsyntax-only "$c_probe"
"$ORACLE_CC" -std=c++17 -x c++ -fno-builtin -fsyntax-only "$cxx_probe"
"$ORACLE_CC" -std=c11 -fno-builtin -I "$ROOT_DIR/include" -fsyntax-only "$c_probe"
"$ORACLE_CC" -std=c++17 -x c++ -fno-builtin -I "$ROOT_DIR/include" \
    -fsyntax-only "$cxx_probe"

# -H makes candidate-header provenance observable rather than merely compiling
# against whichever ambient inttypes.h happens to be installed.
if ! "$ORACLE_CC" -std=c11 -fno-builtin -I "$ROOT_DIR/include" -H \
    -fsyntax-only "$c_probe" >/dev/null 2>"$header_trace"; then
    sed -n '1,160p' "$header_trace" >&2
    fail "project C intmax arithmetic header contract drifted"
fi
for header in stddef.h inttypes.h stdint.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" || {
        fail "C probe did not use the project <$header>"
    }
done

# C++ references must remain unmangled C symbols, not merely type-compatible
# declarations. This closes the inttypes.h linkage boundary around imaxabs and
# imaxdiv without selecting its wider conversion surface.
"$ORACLE_CC" -std=c++17 -x c++ -fno-builtin -c "$cxx_probe" \
    -o "$oracle_cxx_object"
"$ORACLE_CC" -std=c++17 -x c++ -fno-builtin -I "$ROOT_DIR/include" \
    -c "$cxx_probe" -o "$candidate_cxx_object"
for object in "$oracle_cxx_object" "$candidate_cxx_object"; do
    undefined="$(nm --undefined-only "$object")"
    for symbol in imaxabs imaxdiv; do
        printf '%s\n' "$undefined" | grep -Eq "[[:space:]]${symbol}$" || {
            fail "C++ probe does not retain C linkage for ${symbol}"
        }
    done
    if printf '%s\n' "$undefined" | grep -Eq '_Z(7imaxabs|7imaxdiv)'; then
        fail "C++ probe retained a mangled intmax arithmetic reference"
    fi
done

printf 'x86 pinned-musl/project C/C++ <inttypes.h> intmax arithmetic ABI: PASS\n'
