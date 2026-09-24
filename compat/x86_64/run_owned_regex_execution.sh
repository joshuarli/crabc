#!/usr/bin/env bash
# Native Linux/x86-64 allocator-failure check for the owned musl TRE port.
#
# The selected `x86-owned-static-runtime` route owns TRE semantics.  This
# checkpoint keeps a copied-route build only to retain the frozen, recording
# allocator witness for compiler and executor failure cleanup.  The installed
# header/product proof is `run_owned_regex.sh`; neither runner claims aggregate
# runtime closure.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/source_runtime_libc.sh"
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly CANDIDATE_CC=/usr/bin/gcc
readonly SOURCE_STATIC_C_ABI="$ROOT_DIR/libc/src/c_abi/x86_64/static_c_abi.rs"

fail() { printf 'ERROR: owned regex execution checkpoint: %s\n' "$*" >&2; exit 1; }
require_tool() { command -v "$1" >/dev/null 2>&1 || fail "requires $1"; }

[ "$#" -eq 0 ] || fail "usage: $0"
[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "requires native x86-64" ;; esac
for tool in cargo cmp grep mktemp readelf tar timeout; do require_tool "$tool"; done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -x "$CANDIDATE_CC" ] || fail "missing raw native candidate compiler"

case "${CRABC_WORK_DIR:-$ROOT_DIR/.work/x86_64}" in
    "$ROOT_DIR"/.work/x86_64|"$ROOT_DIR"/.work/x86_64/*)
        work_root="${CRABC_WORK_DIR:-$ROOT_DIR/.work/x86_64}" ;;
    *) fail "CRABC_WORK_DIR must stay below $ROOT_DIR/.work/x86_64" ;;
esac
mkdir -p "$work_root"
work_dir="$(mktemp -d "$work_root/owned-regex-execution.XXXXXX")"
completed=false
cleanup() {
    if [ "$completed" = true ]; then
        rm -rf -- "$work_dir"
    else
        printf 'retained execution diagnostics: %s\n' "$work_dir" >&2
    fi
}
trap cleanup EXIT
source_root="$work_dir/source"
target_dir="$work_dir/target"
reference="$work_dir/musl-execution"
candidate="$work_dir/candidate-execution"
candidate_empty="$work_dir/candidate-empty-backreference"
candidate_regerror="$work_dir/candidate-regerror-table"
archive="$target_dir/x86_64-unknown-linux-musl/debug/libc.a"

# Keep the two prior failure-prone source paths in independent processes with
# their own stdout, stderr, and exit-status records.  This makes a timeout or
# terminator regression attributable without weakening the aggregate suite.
run_timeboxed() {
    local name="$1"
    shift
    local status
    set +e
    timeout 5 "$@" >"$work_dir/${name}.stdout" 2>"$work_dir/${name}.stderr"
    status=$?
    set -e
    printf '%s\n' "$status" >"$work_dir/${name}.status"
    if [ "$status" -ne 0 ]; then
        cat "$work_dir/${name}.stdout" >&2
        cat "$work_dir/${name}.stderr" >&2
        fail "${name} failed with status ${status}"
    fi
}

# Keep this registration experiment isolated even when other x86 owners are
# active in their own worktrees.
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
    fail "shared static C ABI routing changed while preparing the isolated proof"

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" "$ROOT_DIR/compat/x86_64/owned_regex_execution_probe.c" \
    -o "$reference"
run_timeboxed oracle-empty-backreference "$reference" --empty-backreference
run_timeboxed oracle-regerror-table "$reference" --regerror-table
run_timeboxed oracle-all "$reference"

(
    cd "$source_root"
    build_source_runtime_libc "$target_dir/x86_64-unknown-linux-musl/debug/libc.a"
)
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_OWNED_REGEX_EXECUTION_FREESTANDING \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    "$ROOT_DIR/compat/x86_64/owned_regex_execution_probe.c" \
    "$ROOT_DIR/compat/x86_64/owned_regex_execution_start.S" "$archive" -o "$candidate"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_OWNED_REGEX_EXECUTION_FREESTANDING \
    -DCRABC_OWNED_REGEX_EMPTY_BACKREFERENCE_ONLY -I"$ROOT_DIR/include" \
    -nostdlib -static -fno-pie -no-pie -ffreestanding -fno-builtin \
    -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    "$ROOT_DIR/compat/x86_64/owned_regex_execution_probe.c" \
    "$ROOT_DIR/compat/x86_64/owned_regex_execution_start.S" "$archive" -o "$candidate_empty"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_OWNED_REGEX_EXECUTION_FREESTANDING \
    -DCRABC_OWNED_REGEX_REGERROR_TABLE_ONLY -I"$ROOT_DIR/include" \
    -nostdlib -static -fno-pie -no-pie -ffreestanding -fno-builtin \
    -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    "$ROOT_DIR/compat/x86_64/owned_regex_execution_probe.c" \
    "$ROOT_DIR/compat/x86_64/owned_regex_execution_start.S" "$archive" -o "$candidate_regerror"
readelf --symbols --wide "$candidate" >"$work_dir/symbols"
readelf --program-headers --wide "$candidate" >"$work_dir/headers"
readelf --dynamic --wide "$candidate" >"$work_dir/dynamic" || true
for symbol in regcomp regexec regerror regfree __crabc_x86_regex_cabi_malloc \
    __crabc_x86_regex_cabi_calloc __crabc_x86_regex_cabi_realloc \
    __crabc_x86_regex_cabi_free; do
    grep -Eq "[[:space:]]${symbol}$" "$work_dir/symbols" || fail "candidate lacks ${symbol}"
done
if awk '$7 == "UND" && NF >= 8 { print }' "$work_dir/symbols" | grep -q .; then
    fail "candidate has unresolved symbols"
fi
if grep -Eq 'Requesting program interpreter|INTERP|NEEDED' "$work_dir/headers" "$work_dir/dynamic"; then
    fail "candidate is dynamic"
fi
run_timeboxed candidate-empty-backreference "$candidate_empty"
run_timeboxed candidate-regerror-table "$candidate_regerror"
run_timeboxed candidate-all "$candidate"
completed=true
printf 'x86 owned regex execution checkpoint: PASS\n'
