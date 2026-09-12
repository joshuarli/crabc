#!/usr/bin/env bash
# Prove the installed drivers' thread-aware translation and integrated libc link.
set -euo pipefail
ulimit -c 0

readonly ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly oracle_cc=/usr/local/bin/crabc-x86_64-musl-gcc
[ "$#" -eq 0 ]
[ "$(uname -sm)" = 'Linux x86_64' ]
[ "$(id -u)" -eq 0 ]
python3 -B - "$ROOT" "${TMPDIR:-}" <<'PY'
from pathlib import Path
import sys
root, temporary = map(Path, sys.argv[1:])
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / '.work'):
    raise SystemExit('owned driver pthread proof needs a physical checkout .work TMPDIR')
PY
readonly work="$(mktemp -d "$TMPDIR/owned-driver-pthread.XXXXXX")"
chmod a+rx "$work"
printf 'owned driver pthread evidence: %s\n' "$work"
python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" --output "$work/static-product" >"$work/static-build.json"
python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" --output "$work/dynamic-product" >"$work/dynamic-build.json"

cat >"$work/pthread.c" <<'SOURCE'
#ifndef _REENTRANT
#error owned_driver_pthread_translation_missing
#endif
#include <pthread.h>
#include <stdio.h>

static void *worker(void *argument)
{
    int *value = argument;
    *value += 2;
    return argument;
}

int main(void)
{
    pthread_t thread;
    int value = 41;
    void *result = 0;
    if (pthread_create(&thread, 0, worker, &value)) return 10;
    if (pthread_join(thread, &result)) return 11;
    if (result != &value || value != 43) return 12;
    return puts("owned-driver-pthread-ok") < 0;
}
SOURCE

mkdir -p "$work/oracle-root/lib"
cp -L --preserve=mode /opt/musl-1.2.6/lib/libc.so "$work/oracle-root/lib/ld-musl-x86_64.so.1"
cp -a "$work/dynamic-product" "$work/candidate-root"
printf 'owned-driver-pthread-ok\n' >"$work/expected.stdout"
cd "$work"
for mode in static-et-exec static-pie dynamic-pie dynamic-non-pie; do
    case "$mode" in
        static-et-exec) driver="$work/static-product/bin/crabc-cc"; oracle_flags=(-static -no-pie) ;;
        # The pinned musl GCC specs select Scrt1.o, not the self-relocating
        # rcrt1.o needed by -static-pie. Reuse the established static ET_EXEC
        # oracle link for this PIE-capable object; the candidate remains PIE.
        static-pie) driver="$work/static-product/bin/crabc-cc"; oracle_flags=(-static -no-pie) ;;
        dynamic-pie) driver="$work/dynamic-product/bin/crabc-cc-dynamic"; oracle_flags=(-pie -Wl,--dynamic-linker,/lib/ld-musl-x86_64.so.1) ;;
        dynamic-non-pie) driver="$work/dynamic-product/bin/crabc-cc-dynamic"; oracle_flags=(-no-pie -Wl,--dynamic-linker,/lib/ld-musl-x86_64.so.1) ;;
    esac
    # Without the option, the compiler must reject this same source. This
    # prevents headers or ambient defines from making the positive check vacuous.
    if "$driver" "--$mode" -std=c11 -c "$work/pthread.c" -o "$work/$mode-plain.o" \
        >"$work/$mode-plain.stdout" 2>"$work/$mode-plain.stderr"; then
        printf 'missing -pthread unexpectedly compiled in %s\n' "$mode" >&2
        exit 1
    fi
    grep -q 'owned_driver_pthread_translation_missing' "$work/$mode-plain.stderr"
    "$driver" "--$mode" -pthread -std=c11 -c "$work/pthread.c" -o "$work/$mode.o"
    sha256sum "$work/$mode.o" >"$work/$mode.object-before.sha256"
    receipt_flags=()
    case "$mode" in static-*) receipt_flags=(--link-receipt "$mode.crabc-link.json") ;; esac
    "$driver" "--$mode" -pthread "${receipt_flags[@]}" "$work/$mode.o" -o "$work/$mode"
    "$oracle_cc" -pthread "${oracle_flags[@]}" "$work/$mode.o" -o "$work/$mode-oracle"
    sha256sum -c "$work/$mode.object-before.sha256"
    cp -L --preserve=mode "$work/$mode" "$work/candidate-root/application"
    cp -L --preserve=mode "$work/$mode-oracle" "$work/oracle-root/application"
    for lane in candidate oracle; do
        timeout 20 chroot "$work/$lane-root" /application >"$work/$mode-$lane.stdout" 2>"$work/$mode-$lane.stderr"
        cmp "$work/expected.stdout" "$work/$mode-$lane.stdout"
        [ ! -s "$work/$mode-$lane.stderr" ]
    done
    readelf -lW "$work/$mode" >"$work/$mode.segments"
    readelf -dW "$work/$mode" >"$work/$mode.dynamic"
done

python3 -B - "$ROOT" "$work" <<'PY'
import hashlib
import json
from pathlib import Path
import re
import sys
root, work = map(Path, sys.argv[1:])
def identity(path):
    return {'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
cases = {}
for mode in ('static-et-exec', 'static-pie', 'dynamic-pie', 'dynamic-non-pie'):
    dynamic = (work / (mode + '.dynamic')).read_text()
    segments = (work / (mode + '.segments')).read_text()
    needed = re.findall(r'\(NEEDED\).*\[([^]]+)\]', dynamic)
    interpreters = re.findall(r'Requesting program interpreter: ([^]]+)', segments)
    expected_needed = ['libc.so'] if mode.startswith('dynamic-') else []
    expected_interpreters = ['/lib/ld-crabc-x86_64.so.1'] if mode.startswith('dynamic-') else []
    if needed != expected_needed or interpreters != expected_interpreters:
        raise SystemExit(f'{mode}: owned runtime inputs differ: {needed}, {interpreters}')
    cases[mode] = {name: identity(work / (mode + suffix)) for name, suffix in (
        ('object', '.o'), ('candidate', ''), ('oracle', '-oracle'),
        ('link_receipt', '.crabc-link.json'), ('segments', '.segments'), ('dynamic', '.dynamic'),
        ('candidate_stdout', '-candidate.stdout'), ('oracle_stdout', '-oracle.stdout'),
        ('candidate_stderr', '-candidate.stderr'), ('oracle_stderr', '-oracle.stderr'),
        ('missing_option_stderr', '-plain.stderr'),
    )}
    cases[mode]['oracle_link_mode'] = 'static-et-exec' if mode.startswith('static-') else mode
record = {
    'schema': 'crabc.x86_64-owned-driver-pthread/v1', 'status': 'passed',
    'campaign_complete': False, 'public_support': False,
    'runner': identity(root / 'compat/x86_64/run_owned_driver_pthread.sh'),
    'source': identity(work / 'pthread.c'),
    'products': {kind: identity(work / (kind + '-product/share/crabc/manifest.json')) for kind in ('static', 'dynamic')},
    'cases': cases,
}
(work / 'driver-pthread.json').write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
PY
printf 'owned driver pthread: PASS; evidence: %s\n' "$work"
