#!/usr/bin/env bash
set -euo pipefail
ulimit -c 0
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
if [ "$#" -eq 2 ] && [ "$1" = --prepare ]; then
    exec python3 -B "$ROOT/compat/x86_64/owned_classic_netdb.py" prepare --work "$2"
elif [ "$#" -eq 2 ] && [ "$1" = --prepared ]; then
    exec python3 -B "$ROOT/compat/x86_64/owned_classic_netdb.py" run --work "$2" --static-sysroot "$2/static-sysroot" --dynamic-sysroot "$2/dynamic-sysroot"
fi
[ "$#" -eq 1 ] || { printf 'usage: %s DYNAMIC_SYSROOT (standalone preparation: dev-x86_64.sh owned-classic-netdb)\n' "$0" >&2; exit 2; }
python3 -B - "$ROOT" "${TMPDIR:-}" "$1" <<'PYTHON'
from pathlib import Path
import sys
root = Path(sys.argv[1]).resolve(strict=True)
for text in sys.argv[2:]:
    path = Path(text)
    physical = path.resolve(strict=True)
    if path.is_symlink() or not physical.is_dir() or not physical.is_relative_to(root / '.work'):
        raise SystemExit('classic netdb temporary/product paths must be physical checkout .work directories')
PYTHON
work="$(mktemp -d "$TMPDIR/owned-classic-netdb.XXXXXX")"
readonly work
exec python3 -B "$ROOT/compat/x86_64/owned_classic_netdb.py" run --work "$work" --dynamic-sysroot "$1"
