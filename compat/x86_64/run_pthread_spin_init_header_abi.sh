#!/usr/bin/env bash
# Native Linux/x86-64 compile-only pthread_spin_init header ABI proof.
#
# Pinned musl 1.2.6 is the declaration oracle. Project headers are placed
# first for the candidate pass; neither pass links or selects crabc-libc.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly C_PROBE="$ROOT_DIR/compat/x86_64/pthread_spin_init_header_abi_probe.c"
readonly CXX_PROBE="$ROOT_DIR/compat/x86_64/pthread_spin_init_header_abi_probe.cpp"

fail() {
    printf 'ERROR: x86 pthread_spin_init header ABI: %s\n' "$*" >&2
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

work_dir="$(mktemp -d /tmp/crabc-x86-64-pthread-spin-init-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
header_trace="$work_dir/header-trace"
reference_object="$work_dir/reference-pthread-spin-init-header.o"
candidate_object="$work_dir/candidate-pthread-spin-init-header.o"

"$ORACLE_CC" -std=c11 -fsyntax-only "$C_PROBE"
"$ORACLE_CC" -std=c++17 -x c++ -nostdinc++ -fsyntax-only "$CXX_PROBE"
"$ORACLE_CC" -std=c11 -I "$ROOT_DIR/include" -H -fsyntax-only "$C_PROBE" \
    >/dev/null 2>"$header_trace" || {
    sed -n '1,160p' "$header_trace" >&2
    fail "project pthread_spin_init C header contract drifted"
}
for header in pthread.h bits/alltypes.h features.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "C probe did not use project $header"
done
"$ORACLE_CC" -std=c++17 -x c++ -nostdinc++ -I "$ROOT_DIR/include" \
    -fsyntax-only "$CXX_PROBE"

"$ORACLE_CC" -std=c++17 -x c++ -nostdinc++ -c "$CXX_PROBE" -o "$reference_object"
"$ORACLE_CC" -std=c++17 -x c++ -nostdinc++ -I "$ROOT_DIR/include" \
    -c "$CXX_PROBE" -o "$candidate_object"
for object_path in "$reference_object" "$candidate_object"; do
    nm -u "$object_path" | grep -Eq '[[:space:]]pthread_spin_init$' ||
        fail "C++ object does not retain an unmangled pthread_spin_init reference"
    if nm -u "$object_path" | grep -Eq '_Z[[:alnum:]_]*pthread_spin_init'; then
        fail "C++ object mangles pthread_spin_init"
    fi
done

printf 'x86 pinned-musl/project C/C++ <pthread.h> pthread_spin_init ABI: PASS\n'
