#!/usr/bin/env bash
# Exercise the installed dynamic product, keeping all produced evidence below
# the checkout-local TMPDIR supplied by the native dispatcher.
set -euo pipefail
ulimit -c 0

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly PROFILE="$ROOT/compat/x86_64/owned_atomic_addressable_profile.py"

fail() { printf 'owned atomic addressable profile: %s\n' "$*" >&2; exit 1; }
[ "$(uname -sm)" = 'Linux x86_64' ] || fail 'requires native Linux/x86-64'
[ -n "${TMPDIR:-}" ] || fail 'TMPDIR must be checkout-local'

python3 -B - "$ROOT" "$TMPDIR" "${1:-}" <<'PY'
from pathlib import Path
import os, stat, sys
root, temporary, supplied = map(Path, sys.argv[1:])
root = root.resolve(strict=True)
for path, name in ((temporary, 'TMPDIR'), *((((supplied, 'dynamic product'),) if str(supplied) != '.' else ()))):
    path = path.absolute()
    if '..' in path.parts or not path.is_relative_to(root / '.work'):
        raise SystemExit(f'owned atomic addressable profile {name} must stay below checkout .work')
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        if current.exists() and stat.S_ISLNK(current.lstat().st_mode):
            raise SystemExit(f'owned atomic addressable profile {name} traverses a symlink')
    if not path.is_dir():
        raise SystemExit(f'owned atomic addressable profile {name} is not a directory')
PY

if [ "$#" -gt 1 ]; then
    fail 'usage: run_owned_atomic_addressable_profile.sh [DYNAMIC_SYSROOT]'
fi
run_root="$(mktemp -d "$TMPDIR/owned-atomic-addressable-profile.XXXXXX")"
chmod a+rx "$run_root"
work="$run_root/evidence"
mkdir "$work"
product="${1:-}"
if [ -z "$product" ]; then
    product="$run_root/dynamic-product"
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" --output "$product" >"$run_root/dynamic-build.json"
fi
printf 'owned atomic addressable profile evidence: %s\n' "$work"
python3 -B "$PROFILE" run --work "$work" --product "$product"
