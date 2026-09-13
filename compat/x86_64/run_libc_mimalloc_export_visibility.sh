#!/usr/bin/env bash
# Build fresh owned products and prove the exact shared-only mimalloc boundary.
set -euo pipefail

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

fail() {
    printf 'ERROR: owned mimalloc export visibility: %s\n' "$*" >&2
    exit 1
}

[ "$#" -eq 2 ] || {
    printf 'usage: %s PRECHANGE_ABI_REPORT PRECHANGE_LIBC_SO\n' "$0" >&2
    exit 2
}
[ "$(uname -sm)" = 'Linux x86_64' ] || fail 'requires native Linux/x86-64'
for tool in ar nm python3 readelf; do command -v "$tool" >/dev/null 2>&1 || fail "requires $tool"; done

baseline_report="$(realpath -e "$1")"
baseline_shared="$(realpath -e "$2")"
python3 -B - "$ROOT" "${TMPDIR:-}" "$baseline_report" "$baseline_shared" <<'PY'
from pathlib import Path
import sys

root, temporary, report, shared = map(Path, sys.argv[1:])
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / '.work'):
    raise SystemExit('owned mimalloc export visibility TMPDIR must be a physical checkout .work directory')
for path, description in ((report, 'pre-change ABI report'), (shared, 'pre-change libc.so')):
    if not path.is_file() or path.is_symlink():
        raise SystemExit(f'owned mimalloc export visibility {description} must be a physical file')
PY

readonly work="$(mktemp -d "$TMPDIR/owned-mimalloc-export-visibility.XXXXXX")"
printf 'owned mimalloc export visibility evidence: %s\n' "$work"
python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" --output "$work/static" >"$work/static-build.json"
python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" --output "$work/dynamic" >"$work/dynamic-build.json"
python3 -B "$ROOT/compat/x86_64/owned_mimalloc_export_visibility.py" \
    --baseline-report "$baseline_report" --baseline-shared "$baseline_shared" \
    --static-archive "$work/static/usr/lib/libc.a" --dynamic-shared "$work/dynamic/usr/lib/libc.so" \
    --output "$work/export-visibility.json"
# Reuse the installed-product checks that exercise the retained public malloc
# interposition edge and the owned mimalloc lifecycle, rather than inventing
# a replacement behavioral probe for a link-visibility-only change.
bash "$ROOT/compat/x86_64/run_owned_c_allocation_interposition.sh" "$work/dynamic"
bash "$ROOT/compat/x86_64/run_owned_mimalloc_startup_errno.sh" "$work/dynamic"
printf 'owned mimalloc export visibility: PASS (exact 424 shared-only names; static provider retained; allocator interposition and lifecycle components passed); evidence: %s\n' "$work"
