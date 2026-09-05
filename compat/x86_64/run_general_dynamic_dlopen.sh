#!/usr/bin/env bash
# Next general-runtime regression, deliberately separate from initial-product
# qualification. This must fail until real dlopen dependency admission exists.
set -euo pipefail
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[ "$#" -eq 1 ] || { printf 'usage: %s INSTALLED_DYNAMIC_SYSROOT\n' "$0" >&2; exit 2; }
readonly installed="$1"
readonly driver="$installed/bin/crabc-cc-dynamic"
python3 -B - "$ROOT" "${TMPDIR:-}" <<'PY'
from pathlib import Path
import sys
root, temporary = map(Path, sys.argv[1:])
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / '.work'):
    raise SystemExit('general dynamic dlopen TMPDIR must be a physical checkout .work directory')
PY
work="$(mktemp -d "$TMPDIR/general-dynamic-dlopen.XXXXXX")"
readonly work
# Reuse existing portable source fixtures unchanged. The executable has no
# initial dependency on either plugin; the middle's leaf is also runtime-new.
"$driver" --dynamic-shared-object "$ROOT/compat/ldso/fixtures/nested_leaf.c" -o "$work/libnested_leaf.so"
"$driver" --dynamic-shared-object "$ROOT/compat/ldso/fixtures/nested_mid.c" \
    --application-dso "$work/libnested_leaf.so" -o "$work/libnested_mid.so"
"$driver" --dynamic-pie "$ROOT/compat/ldso/fixtures/nested_dlopen.c" -o "$work/consumer"
cp -a "$installed" "$work/execution-root"
cp "$work/consumer" "$work/execution-root/consumer"
cp "$work/libnested_leaf.so" "$work/libnested_mid.so" "$work/execution-root/usr/lib/"
status=0
timeout 20 chroot "$work/execution-root" /consumer >"$work/consumer.stdout" || status=$?
if [ "$status" -ne 0 ]; then
    printf 'general runtime dlopen: FAIL status=%s; evidence: %s\n' "$status" "$work" >&2
    exit 1
fi
[ "$(<"$work/consumer.stdout")" = 'nested-dlopen=42' ]
printf 'general runtime dlopen: PASS (runtime-new dependency closure); evidence: %s\n' "$work"
