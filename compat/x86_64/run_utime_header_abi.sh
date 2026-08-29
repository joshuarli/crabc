#!/usr/bin/env bash
# Native Linux/x86-64 pinned-musl <utime.h> ABI and C++ C-linkage check.
#
# This covers only the concrete public record and declaration needed by the
# timestamp-update C ABI block. It does not prove callable archive linkage,
# runtime behavior, all header closure, family completion, or public support.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 utime header ABI: %s\n' "$*" >&2
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

c_probe="$ROOT_DIR/compat/x86_64/utime_header_abi_probe.c"
cxx_probe="$ROOT_DIR/compat/x86_64/utime_header_abi_probe.cpp"
work_dir="$(mktemp -d /tmp/crabc-x86-64-utime-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
header_trace="$work_dir/header-trace"
reference_object="$work_dir/reference-cxx.o"
candidate_object="$work_dir/candidate-cxx.o"

"$ORACLE_CC" -std=c11 -fsyntax-only "$c_probe"
"$ORACLE_CC" -std=c++17 -x c++ -c "$cxx_probe" -o "$reference_object"
"$ORACLE_CC" -std=c11 -I"$ROOT_DIR/include" -H -fsyntax-only "$c_probe" \
    >/dev/null 2>"$header_trace"
grep -Fq "$ROOT_DIR/include/utime.h" "$header_trace" ||
    fail "C probe did not use the project <utime.h>"
grep -Fq "$ROOT_DIR/include/sys/types.h" "$header_trace" ||
    fail "C probe did not use the project <sys/types.h>"
"$ORACLE_CC" -std=c++17 -x c++ -I"$ROOT_DIR/include" -c "$cxx_probe" \
    -o "$candidate_object"

for object in "$reference_object" "$candidate_object"; do
    undefined="$(nm --undefined-only "$object")"
    printf '%s\n' "$undefined" | grep -Eq '[[:space:]]utime$' ||
        fail "C++ probe does not retain C linkage for utime"
    if printf '%s\n' "$undefined" | grep -Eq '_Z5utime'; then
        fail "C++ probe retained a mangled utime reference"
    fi
done

printf 'x86 pinned-musl C/C++ <utime.h> ABI: PASS\n'
