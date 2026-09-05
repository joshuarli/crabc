#!/usr/bin/env bash
# Compare the installed crabc dynamic startup path with pinned musl at the
# 100 KiB RLIMIT_STACK that upstream libc-test applies immediately before exec.
set -euo pipefail
ulimit -c 0

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
python3 -B - "$ROOT" "${TMPDIR:-}" <<'PY'
from pathlib import Path
import sys

root, temporary = map(Path, sys.argv[1:])
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / ".work"):
    raise SystemExit("owned loader short-stack TMPDIR must be a physical checkout .work directory")
PY

readonly work="$(mktemp -d "$TMPDIR/owned-loader-short-stack.XXXXXX")"
readonly candidate_product="$work/candidate-product"
readonly candidate_root="$work/candidate-root"
readonly oracle_root="$work/oracle-root"
readonly expected="$work/expected.stdout"

printf 'owned loader short stack\n' >"$expected"

python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" --output "$candidate_product"

"$candidate_product/bin/crabc-cc-dynamic" --dynamic-pie \
    "$ROOT/compat/x86_64/owned_loader_short_stack.c" -o "$work/candidate"
/usr/local/bin/crabc-x86_64-musl-gcc -fPIE -pie \
    -Wl,--dynamic-linker,/lib/ld-musl-x86_64.so.1 \
    "$ROOT/compat/x86_64/owned_loader_short_stack.c" -o "$work/oracle"
/usr/local/bin/crabc-x86_64-musl-gcc -fPIE -pie \
    "$ROOT/compat/x86_64/owned_loader_short_stack_launcher.c" -o "$work/launcher"

prepare_candidate_root() {
    cp -a "$candidate_product" "$candidate_root"
    cp "$work/candidate" "$candidate_root/short-stack"
}

prepare_oracle_root() {
    mkdir -p "$oracle_root/lib"
    cp "$work/oracle" "$oracle_root/short-stack"
    cp /opt/musl-1.2.6/lib/libc.so "$oracle_root/lib/ld-musl-x86_64.so.1"
    ln -s ld-musl-x86_64.so.1 "$oracle_root/lib/libc.so"
}

run_root() {
    local root="$1" label="$2"
    timeout 20 "$work/launcher" "$root" /short-stack >"$work/$label.stdout"
    cmp "$expected" "$work/$label.stdout"
}

prepare_oracle_root
run_root "$oracle_root" oracle
prepare_candidate_root
run_root "$candidate_root" candidate

printf 'owned loader short stack: PASS; evidence: %s\n' "$work"
