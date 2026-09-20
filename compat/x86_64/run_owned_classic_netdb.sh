#!/usr/bin/env bash
set -euo pipefail
ulimit -c 0
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
if [ "$#" -eq 2 ] && [ "$1" = --prepare ]; then
    exec python3 -B "$ROOT/compat/x86_64/owned_classic_netdb.py" prepare --work "$2"
elif [ "$#" -eq 2 ] && [ "$1" = --prepared ]; then
    exec python3 -B "$ROOT/compat/x86_64/owned_classic_netdb.py" run --work "$2" --static-sysroot "$2/static-sysroot" --dynamic-sysroot "$2/dynamic-sysroot"
fi
if ! { [ "$#" -eq 1 ] || { [ "$#" -eq 3 ] && [ "$1" = --static-sysroot ]; }; }; then
    printf 'usage: %s DYNAMIC_SYSROOT | --static-sysroot STATIC_SYSROOT DYNAMIC_SYSROOT (standalone preparation: dev-x86_64.sh owned-classic-netdb)\n' "$0" >&2
    exit 2
fi
if [ "$#" -eq 1 ]; then
    static=''
    dynamic="$1"
else
    static="$2"
    dynamic="$3"
fi
python3 -B - "$ROOT" "${TMPDIR:-}" "$dynamic" ${static:+"$static"} <<'PYTHON'
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
if [ -n "$static" ]; then
    exec python3 -B "$ROOT/compat/x86_64/owned_classic_netdb.py" run --work "$work" --static-sysroot "$static" --dynamic-sysroot "$dynamic"
fi
# A supplied dynamic product replays only the four dynamic cells.  Its emitted
# receipt is deliberately a development measurement and cannot meet a static
# component acceptance requirement.
exec python3 -B "$ROOT/compat/x86_64/owned_classic_netdb.py" run --work "$work" --dynamic-sysroot "$dynamic"
