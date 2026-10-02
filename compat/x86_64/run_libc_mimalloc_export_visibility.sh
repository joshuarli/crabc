#!/usr/bin/env bash
# Build fresh owned products and prove the exact shared-only mimalloc boundary.
set -euo pipefail

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

fail() {
    printf 'ERROR: owned mimalloc export visibility: %s\n' "$*" >&2
    exit 1
}

[ "$#" -eq 2 ] || { [ "$#" -eq 1 ] && [ "$1" = --native-shadow ]; } || {
    printf 'usage: %s PRECHANGE_ABI_REPORT PRECHANGE_LIBC_SO | --native-shadow\n' "$0" >&2
    exit 2
}
[ "$(uname -sm)" = 'Linux x86_64' ] || fail 'requires native Linux/x86-64'
for tool in ar nm python3 readelf; do command -v "$tool" >/dev/null 2>&1 || fail "requires $tool"; done

native_shadow=false
if [ "$#" -eq 1 ]; then native_shadow=true; fi
if [ "$native_shadow" = false ]; then
    baseline_report="$(realpath -e "$1")"
    baseline_shared="$(realpath -e "$2")"
fi
python3 -B - "$ROOT" "${TMPDIR:-}" "${baseline_report:-}" "${baseline_shared:-}" <<'PY'
from pathlib import Path
import sys

root, temporary = map(Path, sys.argv[1:3])
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / '.work'):
    raise SystemExit('owned mimalloc export visibility TMPDIR must be a physical checkout .work directory')
for raw, description in ((sys.argv[3], 'pre-change ABI report'), (sys.argv[4], 'pre-change libc.so')):
    if not raw:
        continue
    path = Path(raw)
    if not path.is_file() or path.is_symlink():
        raise SystemExit(f'owned mimalloc export visibility {description} must be a physical file')
PY

source_digest() {
    python3 -B - "$ROOT" <<'PY'
import sys
from pathlib import Path
sys.path.insert(0, str(Path(sys.argv[1]) / 'compat/x86_64'))
import owned_dynamic_qualification as qualification
print(qualification.source_digest())
PY
}

readonly work="$(mktemp -d "$TMPDIR/owned-mimalloc-export-visibility.XXXXXX")"
printf 'owned mimalloc export visibility evidence: %s\n' "$work"
python3 -B "$ROOT/compat/x86_64/owned_mimalloc_export_visibility.py" \
    --check-image-inputs >"$work/image-inputs.json"
source_before="$(source_digest)"
if [ "$native_shadow" = true ]; then
    python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" --allocator-backend native-shadow \
        --output "$work/static" >"$work/static-build.json"
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" --allocator-backend native-shadow \
        --output "$work/dynamic" >"$work/dynamic-build.json"
    [ "$(source_digest)" = "$source_before" ] || fail 'source changed during native product builds'
    python3 -B "$ROOT/compat/x86_64/owned_mimalloc_export_visibility.py" \
        --allocator-backend native-shadow --ar /usr/bin/ar --nm /usr/bin/nm --readelf /usr/bin/readelf \
        --static-archive "$work/static/usr/lib/libc.a" --dynamic-shared "$work/dynamic/usr/lib/libc.so" \
        --output "$work/export-visibility.json"
    printf 'owned mimalloc export visibility: PASS (native-shadow selected; no C allocator exports; image inputs pinned); evidence: %s\n' "$work"
    exit 0
fi
python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" --allocator-backend accepted-c --output "$work/static" >"$work/static-build.json"
python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" --allocator-backend accepted-c --output "$work/dynamic" >"$work/dynamic-build.json"
[ "$(source_digest)" = "$source_before" ] || fail 'source changed during accepted-C product builds'
python3 -B "$ROOT/compat/x86_64/owned_mimalloc_export_visibility.py" \
    --allocator-backend accepted-c --ar /usr/bin/ar --nm /usr/bin/nm --readelf /usr/bin/readelf \
    --baseline-report "$baseline_report" --baseline-shared "$baseline_shared" \
    --static-archive "$work/static/usr/lib/libc.a" --dynamic-shared "$work/dynamic/usr/lib/libc.so" \
    --output "$work/export-visibility.json"
# Reuse the installed-product checks that exercise the retained public malloc
# interposition edge and the owned mimalloc lifecycle, rather than inventing
# a replacement behavioral probe for a link-visibility-only change.
bash "$ROOT/compat/x86_64/run_owned_c_allocation_interposition.sh" "$work/dynamic"
bash "$ROOT/compat/x86_64/run_owned_mimalloc_startup_errno.sh" "$work/dynamic"
printf 'owned mimalloc export visibility: PASS (exact 424 shared-only names; static provider retained; allocator interposition and lifecycle components passed); evidence: %s\n' "$work"
