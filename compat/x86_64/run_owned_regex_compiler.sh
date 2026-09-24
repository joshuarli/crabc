#!/usr/bin/env bash
# Native Linux/x86-64 compiler semantics check for the owned TRE source port.
#
# The provider is intentionally not selected in the shared static C ABI yet.
# This runner copies the checkout below the approved `.work/x86_64` boundary,
# switches only that disposable copy to `owned_regex/mod.rs`, and proves the
# pinned-musl compiler inputs plus candidate allocation-failure cleanup.  It
# does not invoke regexec/regerror, alter the selected bounded regex leaf, or
# make a runtime/support claim.  The complete owner now emits all four public
# spellings from one Rust object, so their presence in this compiler-focused
# link is intentionally not a failure; execution behavior has its own runner.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/source_runtime_libc.sh"
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly CANDIDATE_CC=/usr/bin/gcc
readonly SOURCE_STATIC_C_ABI="$ROOT_DIR/libc/src/c_abi/x86_64/static_c_abi.rs"

fail() { printf 'ERROR: owned regex compiler checkpoint: %s\n' "$*" >&2; exit 1; }
require_tool() { command -v "$1" >/dev/null 2>&1 || fail "requires $1"; }

[ "$#" -eq 0 ] || fail "usage: $0"
[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "requires native x86-64" ;; esac
for tool in ar cargo cmp diff grep mktemp nm python3 readelf tar; do require_tool "$tool"; done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -x "$CANDIDATE_CC" ] || fail "missing raw native candidate compiler"

case "${CRABC_WORK_DIR:-$ROOT_DIR/.work/x86_64}" in
    "$ROOT_DIR"/.work/x86_64|"$ROOT_DIR"/.work/x86_64/*) work_root="${CRABC_WORK_DIR:-$ROOT_DIR/.work/x86_64}" ;;
    *) fail "CRABC_WORK_DIR must stay below $ROOT_DIR/.work/x86_64" ;;
esac
mkdir -p "$work_root"
work_dir="$(mktemp -d "$work_root/owned-regex-compiler.XXXXXX")"
trap 'rm -rf -- "$work_dir"' EXIT
source_root="$work_dir/source"
target_dir="$work_dir/target"
reference="$work_dir/musl-compiler"
candidate="$work_dir/candidate-compiler"
archive="$target_dir/x86_64-unknown-linux-musl/debug/libc.a"

# A source copy keeps the private selection test from changing any shared
# registration file, including while other worktrees are active.
mkdir "$source_root"
(
    cd "$ROOT_DIR"
    tar --exclude=.git --exclude=.work --exclude=target -cf - .
) | tar -C "$source_root" -xf -

python3 - "$source_root/libc/src/c_abi/x86_64/static_c_abi.rs" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
old = '#[path = "regex.rs"]\nmod regex;'
new = '#[path = "owned_regex/mod.rs"]\nmod regex;'
text = path.read_text()
if text.count(old) != 1:
    raise SystemExit('expected exactly one default regex module routing')
path.write_text(text.replace(old, new))
PY

cmp -s "$SOURCE_STATIC_C_ABI" "$ROOT_DIR/libc/src/c_abi/x86_64/static_c_abi.rs" ||
    fail "shared static C ABI routing changed while preparing the isolated compiler proof"

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" "$ROOT_DIR/compat/x86_64/owned_regex_compiler_probe.c" \
    -o "$reference"
"$reference" || fail "pinned-musl compiler fixture failed with status $?"

(
    cd "$source_root"
    build_source_runtime_libc "$target_dir/x86_64-unknown-linux-musl/debug/libc.a"
)
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_OWNED_REGEX_COMPILER_FREESTANDING \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    "$ROOT_DIR/compat/x86_64/owned_regex_compiler_probe.c" \
    "$ROOT_DIR/compat/x86_64/owned_regex_compiler_start.S" "$archive" -o "$candidate"
readelf --symbols --wide "$candidate" >"$work_dir/symbols"
readelf --program-headers --wide "$candidate" >"$work_dir/headers"
readelf --dynamic --wide "$candidate" >"$work_dir/dynamic" || true
for symbol in regcomp regfree __crabc_x86_regex_cabi_malloc __crabc_x86_regex_cabi_calloc \
    __crabc_x86_regex_cabi_realloc __crabc_x86_regex_cabi_free; do
    grep -Eq "[[:space:]]${symbol}$" "$work_dir/symbols" || fail "candidate lacks ${symbol}"
done
if awk '$7 == "UND" && NF >= 8 { print }' "$work_dir/symbols" | grep -q .; then
    fail "candidate has unresolved symbols"
fi
if grep -Eq 'Requesting program interpreter|INTERP|NEEDED' "$work_dir/headers" "$work_dir/dynamic"; then
    fail "candidate is dynamic"
fi
"$candidate" || fail "owned compiler fixture failed with status $?"
printf 'x86 owned regex compiler checkpoint: PASS\n'
