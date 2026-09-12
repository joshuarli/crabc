#!/usr/bin/env bash
# Focused installed debugger/CRT ABI evidence in the pinned native x86 image.
set -euo pipefail
ulimit -c 0
readonly ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[ "$(uname -sm)" = 'Linux x86_64' ]
[ "$(id -u)" -eq 0 ]
python3 -B - "$ROOT" "${TMPDIR:-}" <<'PY'
from pathlib import Path
import sys
root, temporary = map(Path, sys.argv[1:])
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / '.work'):
    raise SystemExit('loader debugger/CRT TMPDIR must be a physical checkout .work directory')
PY
python3 -B -m unittest discover -s "$ROOT/compat/x86_64/tests" -p test_loader_debug_abi_evidence.py
python3 -B "$ROOT/compat/x86_64/loader_debug_abi_evidence.py" "$@"
