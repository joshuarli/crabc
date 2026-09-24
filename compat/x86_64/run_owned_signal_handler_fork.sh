#!/usr/bin/env bash
# Early pthread signal delivery, fork admission, and the pinned raise-race case.
set -euo pipefail
ulimit -c 0
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[ "$#" -le 1 ] || { printf 'usage: %s [DYNAMIC_SYSROOT]\n' "$0" >&2; exit 2; }
provided_dynamic="${1:-}"
if [ -n "$provided_dynamic" ]; then provided_dynamic="$(realpath -e "$provided_dynamic")"; fi
python3 -B - "$ROOT" "${TMPDIR:-}" "$provided_dynamic" <<'PY'
from pathlib import Path
import sys
root, temporary = map(Path, sys.argv[1:3])
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / '.work'):
    raise SystemExit('signal-handler fork TMPDIR must be a physical checkout .work directory')
if sys.argv[3]:
    product=Path(sys.argv[3])
    if not product.is_dir() or not product.is_relative_to(root / '.work'):
        raise SystemExit('signal-handler fork product must be a checkout .work directory')
PY
readonly work="$(mktemp -d "$TMPDIR/owned-signal-handler-fork.XXXXXX")"
chmod a+rx "$work"
printf 'owned signal-handler fork evidence: %s\n' "$work"
mkdir -p "$work/root"
python3 -B - "$ROOT" "$work" <<'PY'
from pathlib import Path
import hashlib,json,shutil,sys
root,work=map(Path,sys.argv[1:])
sys.path.insert(0,str(root/'compat/x86_64'))
import owned_libc_test as source_owner
source,provenance=source_owner.ensure_source()
records={}
for name in ['COPYRIGHT','AUTHORS','src/common/test.h','src/common/print.c','src/regression/raise-race.c']:
    origin=source/name
    target=work/'libc-test-source'/name
    target.parent.mkdir(parents=True,exist_ok=True)
    shutil.copyfile(origin,target)
    digest=hashlib.sha256(origin.read_bytes()).hexdigest()
    assert digest==hashlib.sha256(target.read_bytes()).hexdigest()
    records[name]=digest
(work/'upstream-source.json').write_text(json.dumps({'source':provenance,'files':records},indent=2)+'\n')
PY
build_static=0
if [ -z "$provided_dynamic" ]; then
    build_static=1
    python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" --output "$work/static-sysroot" >"$work/static-build.json"
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" --output "$work/dynamic-sysroot" >"$work/dynamic-build.json"
    provided_dynamic="$work/dynamic-sysroot"
fi
"$provided_dynamic/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -fno-builtin -c "$ROOT/compat/x86_64/owned_signal_handler_fork_probe.c" -o "$work/workload.o"
for source in regression/raise-race common/print; do
    "$provided_dynamic/bin/crabc-cc-dynamic" --dynamic-pie -std=c99 -D_POSIX_C_SOURCE=200809L -fno-builtin --application-quote-include-dir "$work/libc-test-source/src/common" -c "$work/libc-test-source/src/$source.c" -o "$work/${source##*/}.o"
done
sha256sum "$ROOT/compat/x86_64/owned_signal_handler_fork_probe.c" "$work/workload.o" "$work/raise-race.o" "$work/print.o" >"$work/input.sha256"
readonly cases=(direct handler raw queued queued-raw default-mask explicit-mask c11-mask clone-failure kill-during-fork)
observe() {
    local label="$1" status
    shift
    set +e
    timeout 30 env -i PATH="$PATH" chroot "$work/root" "$@" >"$work/$label.stdout" 2>"$work/$label.stderr"
    status=$?
    set -e
    printf '%s\n' "$status" >"$work/$label.status"
    [ "$status" -eq 0 ] || { printf '%s failed: %s\n' "$label" "$status" >&2; return 1; }
}
compare() {
    local label="$1" executable="$2" upstream="$3"
    shift 3
    for scenario in "${cases[@]}"; do
        observe "$label-$scenario" "$@" "$executable" "$scenario"
        cmp "$work/oracle-$scenario.stdout" "$work/$label-$scenario.stdout"
        cmp "$work/oracle-$scenario.stderr" "$work/$label-$scenario.stderr"
    done
    observe "$label-raise-race" "$@" "$upstream"
    cmp "$work/oracle-raise-race.stdout" "$work/$label-raise-race.stdout"
    cmp "$work/oracle-raise-race.stderr" "$work/$label-raise-race.stderr"
}
/usr/local/bin/crabc-x86_64-musl-gcc -static -fno-pie -no-pie -pthread "$work/workload.o" -o "$work/root/oracle"
/usr/local/bin/crabc-x86_64-musl-gcc -static -fno-pie -no-pie -pthread "$work/raise-race.o" "$work/print.o" -o "$work/root/oracle-raise-race"
for scenario in "${cases[@]}"; do observe "oracle-$scenario" /oracle "$scenario"; done
observe oracle-raise-race /oracle-raise-race
if [ "$build_static" -eq 1 ]; then
    for mode in static static-pie; do
        "$work/static-sysroot/bin/crabc-cc" "-$mode" "$work/workload.o" -o "$work/root/$mode"
        "$work/static-sysroot/bin/crabc-cc" "-$mode" "$work/raise-race.o" "$work/print.o" -o "$work/root/$mode-raise-race"
        compare "$mode" "/$mode" "/$mode-raise-race"
    done
fi
cp -a "$provided_dynamic/." "$work/root/"
for mode in pie non-pie; do
    "$provided_dynamic/bin/crabc-cc-dynamic" "--dynamic-$mode" "$work/workload.o" -o "$work/root/dynamic-$mode"
    "$provided_dynamic/bin/crabc-cc-dynamic" "--dynamic-$mode" "$work/raise-race.o" "$work/print.o" -o "$work/root/dynamic-$mode-raise-race"
    compare "$mode-kernel" "/dynamic-$mode" "/dynamic-$mode-raise-race"
    compare "$mode-direct" "/dynamic-$mode" "/dynamic-$mode-raise-race" /lib/ld-crabc-x86_64.so.1
done
sha256sum -c "$work/input.sha256" >"$work/input-verified.txt"
printf 'owned signal-handler fork: PASS (early delivery, inherited masks, clone failure, kill during fork, pinned raise-race); evidence: %s\n' "$work"
