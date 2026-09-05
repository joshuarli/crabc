#!/usr/bin/env bash
# One installed-header object, ordinary parsing and a bounded unknown-zone read.
set -euo pipefail
ulimit -c 0
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[ "$#" -le 1 ] || { printf 'usage: %s [DYNAMIC_SYSROOT]\n' "$0" >&2; exit 2; }
provided_dynamic="${1:-}"
python3 -B - "$ROOT" "${TMPDIR:-}" "$provided_dynamic" <<'PY'
from pathlib import Path
import sys
root, temporary = map(Path, sys.argv[1:3])
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / '.work'):
    raise SystemExit('owned strptime TMPDIR must be a physical checkout .work directory')
if sys.argv[3]:
    product = Path(sys.argv[3])
    if not product.is_absolute() or not product.is_dir() or product.resolve() != product or not product.is_relative_to(root / '.work'):
        raise SystemExit('owned strptime product must be a physical checkout .work directory')
PY
readonly work="$(mktemp -d "$TMPDIR/owned-strptime.XXXXXX")"
chmod a+rx "$work"
printf 'owned strptime evidence: %s\n' "$work"
mkdir -p "$work/root"
if [ -z "$provided_dynamic" ]; then
    python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" --output "$work/static-sysroot" >"$work/static-build.json"
    "$work/static-sysroot/bin/crabc-cc" -static-pie -std=c11 -fno-builtin -c "$ROOT/compat/x86_64/owned_strptime_probe.c" -o "$work/workload.o"
else
    "$provided_dynamic/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -fno-builtin -c "$ROOT/compat/x86_64/owned_strptime_probe.c" -o "$work/workload.o"
fi
sha256sum "$ROOT/compat/x86_64/owned_strptime_probe.c" "$work/workload.o" >"$work/input.sha256"
observe() {
    local label="$1" expected="$2" result
    shift 2
    set +e
    timeout 20 env -i PATH="$PATH" chroot "$work/root" "$@" >"$work/$label.stdout" 2>"$work/$label.stderr"
    result=$?
    set -e
    printf '%s\n' "$result" >"$work/$label.status"
    [ "$result" -eq "$expected" ] || { printf 'owned strptime %s: expected %s, got %s\n' "$label" "$expected" "$result" >&2; return 1; }
}
compare() {
    local label="$1"
    shift
    observe "$label" 0 "$@"
    cmp "$work/oracle.stdout" "$work/$label.stdout"
    cmp "$work/oracle.stderr" "$work/$label.stderr"
    observe "$label-zone-delimiters" 0 "$@" zone-delimiters
    cmp "$work/candidate-zone-delimiters.expected" "$work/$label-zone-delimiters.stdout"
    [ ! -s "$work/$label-zone-delimiters.stderr" ]
    observe "$label-zone-guard" 0 "$@" zone-guard
    [ ! -s "$work/$label-zone-guard.stdout" ] && [ ! -s "$work/$label-zone-guard.stderr" ]
}
/usr/local/bin/crabc-x86_64-musl-gcc -static -fno-pie -no-pie "$work/workload.o" -o "$work/root/oracle"
observe oracle 0 /oracle
printf '0 end=3 isdst=0\n1 end=3 isdst=1\n2 end=8 isdst=-1\n3 end=8 isdst=-1\n4 end=8 isdst=-1\n5 end=8 isdst=-1\n' >"$work/oracle-zone-delimiters.expected"
printf '0 end=3 isdst=0\n1 end=3 isdst=1\n2 end=7 isdst=-1\n3 end=7 isdst=-1\n4 end=7 isdst=-1\n5 end=7 isdst=-1\n' >"$work/candidate-zone-delimiters.expected"
observe oracle-zone-delimiters 0 /oracle zone-delimiters
cmp "$work/oracle-zone-delimiters.expected" "$work/oracle-zone-delimiters.stdout"
[ ! -s "$work/oracle-zone-delimiters.stderr" ]
# This is a retained oracle defect, never a passing differential cell. Its
# signed-character loop admits NUL after unknown names when both TZ names are
# nonempty. Candidate acceptance is the explicit bounded-read assertion.
observe oracle-zone-guard 139 /oracle zone-guard
if [ -z "$provided_dynamic" ]; then
    for mode in static static-pie; do
        "$work/static-sysroot/bin/crabc-cc" "-$mode" "$work/workload.o" -o "$work/root/$mode"
        compare "$mode" "/$mode"
    done
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" --output "$work/dynamic-sysroot" >"$work/dynamic-build.json"
    provided_dynamic="$work/dynamic-sysroot"
fi
cp -a "$provided_dynamic/." "$work/root/"
for mode in pie non-pie; do
    "$provided_dynamic/bin/crabc-cc-dynamic" "--dynamic-$mode" "$work/workload.o" -o "$work/root/dynamic-$mode"
    compare "$mode-kernel" "/dynamic-$mode"
    compare "$mode-direct" /lib/ld-crabc-x86_64.so.1 "/dynamic-$mode"
done
sha256sum -c "$work/input.sha256" >"$work/input-verified.txt"
printf 'owned strptime: PASS (same-object calendar parsing and bounded unknown-zone read); evidence: %s\n' "$work"
