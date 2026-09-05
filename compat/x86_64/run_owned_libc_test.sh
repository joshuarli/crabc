#!/usr/bin/env bash
# Run the full finite native libc-test aggregate against one materialized
# owned dynamic product.  This leaf retains exactly one evidence directory
# beneath the caller's repository-local TMPDIR, even when the aggregate is
# incomplete, so every source-graph failure remains inspectable.
set -u

readonly ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly HELPER="$ROOT/compat/x86_64/owned_libc_test.py"

usage() {
    printf 'usage: %s DYNAMIC_SYSROOT\n' "$0" >&2
    exit 2
}

[ "$#" -eq 1 ] || usage
case "$1" in
    ''|-) usage ;;
    -*) usage ;;
esac
[ -n "${TMPDIR:-}" ] && [ -d "$TMPDIR" ] || {
    printf 'owned libc-test: TMPDIR must name a repository-local .work directory\n' >&2
    exit 2
}

if ! python3 -B - "$ROOT" "$TMPDIR" "$1" <<'PY'
from pathlib import Path
import os
import sys

root = Path(sys.argv[1]).resolve()
temporary = Path(sys.argv[2]).resolve()
product = Path(sys.argv[3]).resolve()
if not temporary.is_dir() or not temporary.is_relative_to(root / ".work"):
    raise SystemExit("owned libc-test: TMPDIR must remain below this checkout's .work")
if not product.is_dir() or not product.is_relative_to(root / ".work"):
    raise SystemExit("owned libc-test: supplied dynamic product must remain below this checkout's .work")
if os.geteuid() != 0:
    raise SystemExit("owned libc-test: requires root for contained chroot execution roots")
PY
then
    exit 2
fi

leaf="$(mktemp -d "$TMPDIR/owned-libc-test.XXXXXX")" || exit 2
chmod a+rx "$leaf" || exit 2
printf '%s\n' "$leaf"

python3 -B "$HELPER" --product "$1" --evidence "$leaf"
status=$?
if [ ! -f "$leaf/libc-test.json" ]; then
    printf 'owned libc-test: final report was not published at %s/libc-test.json\n' "$leaf" >&2
    exit 2
fi
exit "$status"
