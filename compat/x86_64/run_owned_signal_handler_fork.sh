#!/usr/bin/env bash
# Early pthread signal delivery, fork admission, and the pinned raise-race case.
set -euo pipefail
ulimit -c 0
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
usage() {
    printf 'usage: %s [[--static-sysroot STATIC_SYSROOT] DYNAMIC_SYSROOT]\n' "$0" >&2
    exit 2
}
provided_static=''
provided_dynamic=''
while [ "$#" -gt 0 ]; do
    case "$1" in
        --static-sysroot)
            [ "$#" -ge 2 ] && [ -z "$provided_static" ] && [ -n "$2" ] && [[ "$2" != -* ]] || usage
            provided_static="$2"
            shift 2
            ;;
        -*|'') usage ;;
        *)
            [ -z "$provided_dynamic" ] || usage
            provided_dynamic="$1"
            shift
            ;;
    esac
done
[ -z "$provided_static" ] || [ -n "$provided_dynamic" ] || usage
python3 -B - "$ROOT" "${TMPDIR:-}" "$provided_static" "$provided_dynamic" <<'PY_INPUTS'
from pathlib import Path
import sys
root = Path(sys.argv[1])
for value, name in ((sys.argv[2], 'TMPDIR'), (sys.argv[3], 'static product'), (sys.argv[4], 'dynamic product')):
    if not value and name != 'TMPDIR':
        continue
    path = Path(value).absolute()
    if ('..' in path.parts or not path.is_dir() or path.resolve() != path
            or not path.is_relative_to(root / '.work')):
        raise SystemExit(f'signal-handler fork {name} must be a physical checkout .work directory')
PY_INPUTS
if [ -n "$provided_static" ]; then provided_static="$(realpath "$provided_static")"; fi
if [ -n "$provided_dynamic" ]; then provided_dynamic="$(realpath "$provided_dynamic")"; fi
# A supplied pair shares one clean source and allocator selection. An isolated
# pass cannot qualify a previous failed cohort or another product's source.
if [ -n "$provided_static" ]; then
    python3 -B - "$ROOT" "$provided_static" "$provided_dynamic" <<'PY_PAIR'
from pathlib import Path
import json
import sys
root, static, dynamic = map(Path, sys.argv[1:])
sys.path.insert(0, str(root / 'compat/x86_64'))
from owned_posix_product_evidence import ProductEvidenceError, _validate_static_product, _validate_dynamic_product
from owned_dynamic_qualification import QualificationError, product_identity, read
from static_product_contract import git, source_digest
for product, name, validate in ((static, 'static', _validate_static_product), (dynamic, 'dynamic', _validate_dynamic_product)):
    try:
        manifest, _ = validate(product)
    except ProductEvidenceError as error:
        raise SystemExit(f'signal-handler fork {name} product payload is invalid: {error}') from error
    if name == 'static':
        static_manifest = json.loads(manifest.read_text())
if git('status', '--porcelain', '--untracked-files=all'):
    raise SystemExit('signal-handler fork supplied pair requires clean source')
try:
    product_identity(dynamic)
except QualificationError as error:
    raise SystemExit(f'signal-handler fork dynamic product identity is invalid: {error}') from error
state = read(dynamic / 'share/crabc/dynamic-product-state.json')
if static_manifest.get('source_sha256') != state['source_sha256'] or state['source_sha256'] != source_digest():
    raise SystemExit('signal-handler fork supplied product source identities differ')
if static_manifest.get('allocator_backend') != state['allocator_backend']:
    raise SystemExit('signal-handler fork supplied product allocator selections differ')
PY_PAIR
fi
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
if [ -n "$provided_static" ]; then build_static=1; fi
if [ -z "$provided_dynamic" ]; then
    build_static=1
    python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" --output "$work/static-sysroot" >"$work/static-build.json"
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" --output "$work/dynamic-sysroot" >"$work/dynamic-build.json"
    provided_static="$work/static-sysroot"
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
        # Static receipt sidecars are relative to the link working directory.
        # Keeping that directory beside the receipt makes physical replay exact.
        (
            cd "$work/root"
            "$provided_static/bin/crabc-cc" "-$mode" --link-receipt "$mode.crabc-link.json" "$work/workload.o" -o "$work/root/$mode"
        )
        "$provided_static/bin/crabc-cc" "-$mode" "$work/raise-race.o" "$work/print.o" -o "$work/root/$mode-raise-race"
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
