#!/usr/bin/env bash
# Native Linux/x86-64 compile-only C/C++ pthread spin-operation ABI proof.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly C_PROBE="$ROOT_DIR/compat/x86_64/pthread_spin_operations_header_abi_probe.c"
readonly CXX_PROBE="$ROOT_DIR/compat/x86_64/pthread_spin_operations_header_abi_probe.cpp"

fail() {
    printf 'ERROR: x86 pthread spin-operations header ABI: %s\n' "$*" >&2
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

work_dir="$(mktemp -d /tmp/crabc-x86-64-pthread-spin-operations-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
reference_object="$work_dir/reference.o"
candidate_object="$work_dir/candidate.o"

"$ORACLE_CC" -std=c11 -fsyntax-only "$C_PROBE"
"$ORACLE_CC" -std=c++17 -x c++ -nostdinc++ -fsyntax-only "$CXX_PROBE"
"$ORACLE_CC" -std=c11 -I "$ROOT_DIR/include" -fsyntax-only "$C_PROBE"
"$ORACLE_CC" -std=c++17 -x c++ -nostdinc++ -I "$ROOT_DIR/include" \
    -fsyntax-only "$CXX_PROBE"
"$ORACLE_CC" -std=c++17 -x c++ -nostdinc++ -c "$CXX_PROBE" \
    -o "$reference_object"
"$ORACLE_CC" -std=c++17 -x c++ -nostdinc++ -I "$ROOT_DIR/include" \
    -c "$CXX_PROBE" -o "$candidate_object"
for object_path in "$reference_object" "$candidate_object"; do
    for symbol in pthread_spin_lock pthread_spin_trylock pthread_spin_unlock; do
        nm -u "$object_path" | grep -Eq "[[:space:]]${symbol}$" ||
            fail "C++ object does not retain an unmangled ${symbol} reference"
        if nm -u "$object_path" | grep -Eq "_Z[[:alnum:]_]*${symbol}"; then
            fail "C++ object mangles ${symbol}"
        fi
    done
done

printf 'x86 pinned-musl/project C/C++ <pthread.h> pthread spin operations ABI: PASS\n'
