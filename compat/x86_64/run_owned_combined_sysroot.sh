#!/usr/bin/env bash
# Combined installed x86-64 sysroot gate: one tree owns all four link modes.
#
# Two independent clean composed builds must match byte-for-byte over the
# declared regular-file set. Both are packaged, the packages must be
# identical, and one is extracted to a fresh location that must match again.
# Then the static product suite runs from each clean tree with the extracted
# tree, and the dynamic product suite and qualification run from all three.
# Composition fails closed while the static and dynamic products install
# different bytes at a shared runtime path such as usr/lib/crt1.o. A composed
# tree alone is never qualification.
set -euo pipefail
ulimit -c 0
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[ "$#" -eq 0 ] || { printf 'usage: %s\n' "$0" >&2; exit 2; }
[ "$(uname -sm)" = 'Linux x86_64' ]
python3 -B - "$ROOT" "${TMPDIR:-}" <<'PY'
from pathlib import Path
import sys
root, temporary = map(Path, sys.argv[1:])
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / '.work'):
    raise SystemExit('owned combined sysroot TMPDIR must be a physical checkout .work directory')
PY
work="$(mktemp -d "$TMPDIR/owned-combined-sysroot.XXXXXX")"
readonly work
# The container writes as root; the host reviewer must be able to read it.
chmod 0755 "$work"
readonly builder="$ROOT/scripts/build_x86_64_owned_combined_sysroot.py"
printf 'owned combined sysroot evidence: %s\n' "$work"
for label in installed second; do
    python3 -B "$builder" build "$work/$label"
done
python3 -B "$builder" compare "$work/installed" "$work/second"
python3 -B "$builder" package "$work/installed" "$work/runtime.tar"
python3 -B "$builder" package "$work/second" "$work/second-runtime.tar"
cmp "$work/runtime.tar" "$work/second-runtime.tar"
python3 -B "$builder" extract "$work/runtime.tar" "$work/extracted"
python3 -B "$builder" compare "$work/installed" "$work/extracted"
printf 'owned combined sysroot: two clean builds, identical packages and extraction; evidence: %s\n' "$work"
# The static suite's consumer matrix pairs one clean tree with the extracted
# tree; run it once per clean tree so every combined tree executes it.
readonly static_suite="$ROOT/compat/x86_64/run_owned_static_sysroot.sh"
bash "$static_suite" --supplied-sysroots "$work/installed" "$work/second" "$work/extracted"
bash "$static_suite" --supplied-sysroots "$work/second" "$work/installed" "$work/extracted"
bash "$ROOT/compat/x86_64/run_materialized_dynamic_sysroot.sh" --supplied-work "$work"
printf 'owned combined sysroot: PASS (static and dynamic product suites from installed, second and extracted combined trees); evidence: %s\n' "$work"
