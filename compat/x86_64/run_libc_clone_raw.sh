#!/usr/bin/env bash
# Source-only native Linux/x86-64 musl-shaped raw clone ABI evidence.
#
# The oracle branch uses pinned musl's public process-clone wrapper only for
# the common `SIGCHLD` callback outcome. The candidate invokes its uniquely
# named fixed-argument leaf directly; neither branch selects crabc-libc.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 raw clone source-only probe: %s\n' "$*" >&2
    exit 1
}

require_native_linux_x86_64() {
    [ "$(uname -s)" = Linux ] || fail "requires native Linux"
    case "$(uname -m)" in
        x86_64|amd64) ;;
        *) fail "refuses emulation on $(uname -m)" ;;
    esac
}

require_tool() {
    command -v "$1" >/dev/null 2>&1 || fail "requires $1"
}

require_native_linux_x86_64
for tool in cc readelf objdump rustup; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-clone.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
object="$work_dir/clone.o"
reference="$work_dir/musl-clone-reference"
candidate="$work_dir/crabc-clone-candidate"
object_symbols="$work_dir/object-symbols"
object_relocations="$work_dir/object-relocations"
object_disassembly="$work_dir/object-disassembly"
object_sections="$work_dir/object-sections"
candidate_dynamic_symbols="$work_dir/candidate-dynamic-symbols"
header_trace="$work_dir/header-trace"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_CLONE_ORACLE \
    compat/x86_64/libc_clone_raw_probe.c -o "$reference"
"$reference"

cc -E -H -D_GNU_SOURCE -I"$ROOT_DIR/include" \
    compat/x86_64/libc_clone_raw_probe.c >/dev/null 2>"$header_trace"
grep -Fq "$ROOT_DIR/include/signal.h" "$header_trace" \
    || fail "candidate fixture did not use the project signal header"

rustup run nightly-2026-07-24 rustc --edition=2021 \
    --target x86_64-unknown-linux-musl \
    --crate-type=lib \
    --emit=obj \
    -C relocation-model=static \
    -C code-model=small \
    -C panic=abort \
    compat/x86_64/libc_clone_raw_probe.rs \
    -o "$object"

readelf --symbols --wide "$object" >"$object_symbols"
readelf --relocs --wide "$object" >"$object_relocations"
readelf --sections --wide "$object" >"$object_sections"
objdump -d "$object" >"$object_disassembly"

grep -Eq '[[:space:]]__crabc_x86_clone_raw$' "$object_symbols" \
    || fail "object does not define its private clone symbol"
if grep -Eq '[[:space:]](__clone|clone)$' "$object_symbols"; then
    fail "object exposes a public musl clone symbol"
fi
if grep -Eq 'crabc_core|crabc_libc|__tls_get_addr' "$object_relocations"; then
    fail "source-only clone object depends on a runtime artifact or dynamic TLS"
fi
grep -Eq '[[:space:]]syscall' "$object_disassembly" \
    || fail "object lacks the x86 syscall boundary"
grep -Eq 'mov.*\%r10' "$object_disassembly" \
    || fail "object lacks clone's fifth kernel argument placement"
grep -Fq '.note.GNU-stack' "$object_sections" \
    || fail "object lacks GNU-stack metadata"

cc -std=c11 -D_GNU_SOURCE -no-pie \
    -I"$ROOT_DIR/include" \
    compat/x86_64/libc_clone_raw_probe.c "$object" -o "$candidate"
readelf --dyn-syms --wide "$candidate" >"$candidate_dynamic_symbols"
if grep -Eq '[[:space:]]UND[[:space:]].*(__clone|clone)$' \
    "$candidate_dynamic_symbols"; then
    fail "candidate leaves clone to the ambient C runtime"
fi
"$candidate"

printf 'x86 raw clone source-only probe: PASS\n'
