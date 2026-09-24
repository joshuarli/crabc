#!/usr/bin/env bash
# Installed native-shadow worker allocator lifecycle against pinned musl 1.2.6.
#
# One probe runs through the musl oracle and through audit-enabled native-shadow
# static, static-PIE and dynamic PIE/non-PIE (kernel and direct loader)
# products, for ordinary main return and for final-worker exit. Product builds
# add the scalar worker-owner audit checks; every transcript must equal the
# oracle's. Without supplied products the runner builds both; supplied ones
# must record the native-shadow backend and the lifecycle test audit.
set -euo pipefail
ulimit -c 0
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly oracle_cc=/usr/local/bin/crabc-x86_64-musl-gcc
readonly probe="$ROOT/compat/x86_64/owned_native_worker_lifecycle_probe.c"
readonly scenarios=(main final)

usage() {
    printf 'usage: %s [--static-sysroot STATIC_SYSROOT] [DYNAMIC_SYSROOT]\n' "$0" >&2
    exit 2
}

static_sysroot=''
dynamic_sysroot=''
while [ "$#" -gt 0 ]; do
    case "$1" in
        --static-sysroot)
            [ "$#" -ge 2 ] && [ -z "$static_sysroot" ] && [ -n "$2" ] || usage
            static_sysroot="$(realpath -e "$2")"
            shift 2
            ;;
        -*|'') usage ;;
        *)
            [ -z "$dynamic_sysroot" ] || usage
            dynamic_sysroot="$(realpath -e "$1")"
            shift
            ;;
    esac
done

python3 -B - "$ROOT" "${TMPDIR:-}" "$static_sysroot" "$dynamic_sysroot" <<'PY'
from pathlib import Path
import sys
root, temporary = map(Path, sys.argv[1:3])
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / '.work'):
    raise SystemExit('native-worker-lifecycle TMPDIR must be a physical checkout .work directory')
for argument in sys.argv[3:]:
    if argument and not Path(argument).is_relative_to(root / '.work'):
        raise SystemExit('native-worker-lifecycle products must be checkout .work directories')
PY

work="$(mktemp -d "$TMPDIR/owned-native-worker-lifecycle.XXXXXX")"
readonly work
chmod a+rx "$work"
printf 'native-worker-lifecycle evidence: %s\n' "$work"

if [ -z "$static_sysroot" ]; then
    python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" --allocator-backend native-shadow \
        --allocator-lifecycle-test-audit --output "$work/static-sysroot" >"$work/static-build.json"
    static_sysroot="$work/static-sysroot"
fi
if [ -z "$dynamic_sysroot" ]; then
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" --allocator-backend native-shadow \
        --allocator-lifecycle-test-audit --output "$work/dynamic-sysroot" >"$work/dynamic-build.json"
    dynamic_sysroot="$work/dynamic-sysroot"
fi
python3 -B - "$static_sysroot" "$dynamic_sysroot" <<'PY'
import json
import sys
from pathlib import Path
static, dynamic = map(Path, sys.argv[1:])
def load(path):
    with open(path, encoding='utf-8') as stream:
        return json.load(stream)
selections = (
    (load(static / 'share/crabc/manifest.json').get('allocator_backend'),
     load(static / 'share/crabc/libc-static.provenance.json').get('allocator_lifecycle_test_audit'), static),
    (load(dynamic / 'share/crabc/libc-shared.provenance.json').get('allocator_backend'),
     load(dynamic / 'share/crabc/libc-shared.provenance.json').get('allocator_lifecycle_test_audit'), dynamic),
)
for backend, audit, product in selections:
    if backend != 'native-shadow' or audit is not True:
        raise SystemExit(f'{product}: not a native-shadow product with the lifecycle test audit')
PY

# Run one build and scenario; retain stdout, stderr and status, then compare
# with the oracle transcript for the same scenario.
run_case() {
    local mode="$1"
    local scenario="$2"
    local name="$mode-$scenario"
    shift 2
    local status=0
    timeout 60 "$@" >"$work/$name.stdout" 2>"$work/$name.stderr" || status=$?
    printf '%s\n' "$status" >"$work/$name.status"
    if [ "$status" -ne 0 ] || [ -s "$work/$name.stderr" ]; then
        printf 'native-worker-lifecycle: %s exited %s\n' "$name" "$status" >&2
        cat "$work/$name.stderr" >&2
        return 1
    fi
    [ "$mode" != oracle ] || return 0
    cmp "$work/oracle-$scenario.stdout" "$work/$name.stdout" || {
        printf 'native-worker-lifecycle: %s transcript differs from musl\n' "$name" >&2
        return 1
    }
}

"$oracle_cc" -static -fno-pie -no-pie -std=c11 -pthread "$probe" -o "$work/oracle"
for scenario in "${scenarios[@]}"; do
    run_case oracle "$scenario" "$work/oracle" "$scenario"
done

for mode in static static-pie; do
    "$static_sysroot/bin/crabc-cc" "-$mode" -std=c11 -pthread -DCRABC_NATIVE_WORKER_AUDIT \
        "$probe" -o "$work/$mode"
    for scenario in "${scenarios[@]}"; do
        run_case "$mode" "$scenario" "$work/$mode" "$scenario"
    done
done

cp -a "$dynamic_sysroot" "$work/execution-root"
for mode in pie non-pie; do
    "$dynamic_sysroot/bin/crabc-cc-dynamic" "--dynamic-$mode" -std=c11 -pthread \
        -DCRABC_NATIVE_WORKER_AUDIT "$probe" -o "$work/dynamic-$mode"
    cp "$work/dynamic-$mode" "$work/execution-root/consumer-$mode"
    for scenario in "${scenarios[@]}"; do
        run_case "kernel-$mode" "$scenario" chroot "$work/execution-root" "/consumer-$mode" "$scenario"
        run_case "direct-$mode" "$scenario" chroot "$work/execution-root" /lib/ld-crabc-x86_64.so.1 \
            "/consumer-$mode" "$scenario"
    done
done
printf 'owned native-worker lifecycle: PASS (musl + audited native-shadow static/static-PIE/dynamic PIE/non-PIE kernel/direct; main return and final-worker exit); evidence: %s\n' "$work"
