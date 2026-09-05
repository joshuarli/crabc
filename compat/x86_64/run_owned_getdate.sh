#!/usr/bin/env bash
# One installed-header object: DATEMSK, retained tm/error, cancellation state.
set -euo pipefail
ulimit -c 0
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[ "$#" -le 1 ] || { printf 'usage: %s [DYNAMIC_SYSROOT]\n' "$0" >&2; exit 2; }
provided_dynamic="${1:-}"
python3 -B - "$ROOT" "${TMPDIR:-}" "$provided_dynamic" <<'PY'
from pathlib import Path
import sys
root, temporary = map(Path, sys.argv[1:3])
for label, path in [("TMPDIR", temporary)] + ([("product", Path(sys.argv[3]))] if sys.argv[3] else []):
    if not path.is_absolute() or not path.is_dir() or path.resolve() != path or not path.is_relative_to(root / ".work"):
        raise SystemExit(f"owned getdate {label} must be a physical checkout .work directory")
PY
readonly work="$(mktemp -d "$TMPDIR/owned-getdate.XXXXXX")"
chmod a+rx "$work"
printf 'owned getdate evidence: %s\n' "$work"
mkdir -p "$work/root/templates"
build_static=0
if [ -z "$provided_dynamic" ]; then
    build_static=1
    python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" --output "$work/static-sysroot" >"$work/static-build.json"
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" --output "$work/dynamic-sysroot" >"$work/dynamic-build.json"
    provided_dynamic="$work/dynamic-sysroot"
fi
"$provided_dynamic/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -fno-builtin -c "$ROOT/compat/x86_64/owned_getdate_probe.c" -o "$work/workload.o"
sha256sum "$ROOT/compat/x86_64/owned_getdate_probe.c" "$work/workload.o" >"$work/input.sha256"
observe() {
    local label="$1" result=0
    shift
    timeout 20 env -i PATH="$PATH" chroot "$work/root" "$@" >"$work/$label.stdout" 2>"$work/$label.stderr" || result=$?
    printf '%s\n' "$result" >"$work/$label.status"
    [ "$result" -eq 0 ] || { printf 'owned getdate %s failed: %s\n' "$label" "$result" >&2; return 1; }
}
compare() {
    local label="$1"
    shift
    observe "$label" "$@"
    cmp "$work/oracle.stdout" "$work/$label.stdout"
    cmp "$work/oracle.stderr" "$work/$label.stderr"
}
/usr/local/bin/crabc-x86_64-musl-gcc -static -fno-pie -no-pie "$work/workload.o" -o "$work/root/oracle"
observe oracle /oracle
[ "$(wc -l <"$work/oracle.stdout")" -eq 11 ] && [ ! -s "$work/oracle.stderr" ]
if [ "$build_static" -eq 1 ]; then
    for mode in static static-pie; do
        "$work/static-sysroot/bin/crabc-cc" "-$mode" "$work/workload.o" -o "$work/root/$mode"
        compare "$mode" "/$mode"
    done
fi
cp -a "$provided_dynamic/." "$work/root/"
for mode in pie non-pie; do
    "$provided_dynamic/bin/crabc-cc-dynamic" "--dynamic-$mode" "$work/workload.o" -o "$work/root/dynamic-$mode"
    compare "$mode-kernel" "/dynamic-$mode"
    compare "$mode-direct" /lib/ld-crabc-x86_64.so.1 "/dynamic-$mode"
done
sha256sum -c "$work/input.sha256" >"$work/input-verified.txt"
printf 'owned getdate: PASS (one object; template errors, persistent fields, cancellation state); evidence: %s\n' "$work"
