#!/usr/bin/env bash
# Focused product build for the installed dynamic pthread-exit consumer.
set -euo pipefail
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
python3 -B - "$ROOT" "${TMPDIR:-}" <<'PY'
from pathlib import Path
import sys
root, temporary = map(Path, sys.argv[1:])
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / '.work'):
    raise SystemExit('owned pthread-exit TMPDIR must be a physical checkout .work directory')
PY
work="$(mktemp -d "$TMPDIR/owned-dynamic-pthread-exit.XXXXXX")"
readonly work
python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" --output "$work/installed"
bash "$ROOT/compat/x86_64/run_general_dynamic_pthread_exit.sh" "$work/installed"
