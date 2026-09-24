#!/usr/bin/env bash
# Installed native-allocator fork composition against pinned musl 1.2.6.
#
# The probe runs a multithreaded parent with live allocations and concurrent
# churn, forks from the initial thread, from a worker and after a joined
# worker, forks repeatedly under three-thread churn, and runs a
# single-threaded _Fork, and repeats a credential rendezvous while C11 and
# explicitly scheduled threads attach to the allocator. Allocating pthread_atfork handlers record their
# order. Each owned native-shadow product mode must reproduce the oracle
# transcript exactly. Without supplied products the runner builds both
# native-shadow sysroots; supplied ones must record that backend.
set -euo pipefail
ulimit -c 0
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly oracle_cc=/usr/local/bin/crabc-x86_64-musl-gcc
readonly probe="$ROOT/compat/x86_64/owned_native_allocator_fork_probe.c"
readonly scenarios=(initial worker joined repeat underscore synccall-create)

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
    raise SystemExit('native-allocator-fork TMPDIR must be a physical checkout .work directory')
for argument in sys.argv[3:]:
    if argument and not Path(argument).is_relative_to(root / '.work'):
        raise SystemExit('native-allocator-fork products must be checkout .work directories')
PY

work="$(mktemp -d "$TMPDIR/owned-native-allocator-fork.XXXXXX")"
readonly work
chmod a+rx "$work"
printf 'native-allocator-fork evidence: %s\n' "$work"

if [ -z "$static_sysroot" ]; then
    python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" --allocator-backend native-shadow \
        --output "$work/static-sysroot" >"$work/static-build.json"
    static_sysroot="$work/static-sysroot"
fi
if [ -z "$dynamic_sysroot" ]; then
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" --allocator-backend native-shadow \
        --output "$work/dynamic-sysroot" >"$work/dynamic-build.json"
    dynamic_sysroot="$work/dynamic-sysroot"
fi
python3 -B - "$static_sysroot/share/crabc/manifest.json" \
    "$dynamic_sysroot/share/crabc/libc-shared.provenance.json" <<'PY'
import json
import sys
for path in sys.argv[1:]:
    with open(path, encoding='utf-8') as stream:
        backend = json.load(stream).get('allocator_backend')
    if backend != 'native-shadow':
        raise SystemExit(f'{path}: allocator_backend is {backend!r}, not native-shadow')
PY

# Run one mode and scenario; retain stdout, stderr and status, then compare
# with the oracle transcript for the same scenario.
run_case() {
    local mode="$1"
    local scenario="$2"
    local name="$mode-$scenario"
    shift 2
    local status=0
    timeout 30 "$@" >"$work/$name.stdout" 2>"$work/$name.stderr" || status=$?
    printf '%s\n' "$status" >"$work/$name.status"
    if [ "$status" -ne 0 ]; then
        printf 'native-allocator-fork: %s exited %s\n' "$name" "$status" >&2
        cat "$work/$name.stderr" >&2
        return 1
    fi
    [ ! -s "$work/$name.stderr" ] || { cat "$work/$name.stderr" >&2; return 1; }
    [ "$mode" != oracle ] || return 0
    cmp "$work/oracle-$scenario.stdout" "$work/$name.stdout" || {
        printf 'native-allocator-fork: %s transcript differs from musl\n' "$name" >&2
        return 1
    }
}

"$oracle_cc" -static -fno-pie -no-pie -std=c11 -pthread "$probe" -o "$work/oracle"
for scenario in "${scenarios[@]}"; do
    run_case oracle "$scenario" "$work/oracle" "$scenario"
done

for mode in static static-pie; do
    "$static_sysroot/bin/crabc-cc" "-$mode" -std=c11 -pthread "$probe" -o "$work/$mode"
    for scenario in "${scenarios[@]}"; do
        run_case "$mode" "$scenario" "$work/$mode" "$scenario"
    done
done

cp -a "$dynamic_sysroot" "$work/execution-root"
for mode in pie non-pie; do
    "$dynamic_sysroot/bin/crabc-cc-dynamic" "--dynamic-$mode" -std=c11 -pthread "$probe" -o "$work/dynamic-$mode"
    cp "$work/dynamic-$mode" "$work/execution-root/consumer-$mode"
    for scenario in "${scenarios[@]}"; do
        run_case "kernel-$mode" "$scenario" chroot "$work/execution-root" "/consumer-$mode" "$scenario"
        run_case "direct-$mode" "$scenario" chroot "$work/execution-root" /lib/ld-crabc-x86_64.so.1 \
            "/consumer-$mode" "$scenario"
    done
done
printf 'owned native-allocator fork: PASS (musl + native-shadow static/static-PIE/dynamic PIE/non-PIE kernel/direct; initial/worker/joined/repeated fork, _Fork, credential rendezvous during C11/explicit-scheduling creation); evidence: %s\n' "$work"
