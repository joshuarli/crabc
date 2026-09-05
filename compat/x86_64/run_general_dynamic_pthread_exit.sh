#!/usr/bin/env bash
# Main/last-thread exit through installed dynamic CRT and a real TLS DSO.
set -euo pipefail
ulimit -c 0
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[ "$#" -eq 1 ] || exit 2
readonly installed="$1" driver="$1/bin/crabc-cc-dynamic"
readonly oracle_cc=/usr/local/bin/crabc-x86_64-musl-gcc
python3 -B - "$ROOT" "${TMPDIR:-}" <<'PY'
from pathlib import Path
import sys
root, temporary = map(Path, sys.argv[1:])
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / '.work'):
    raise SystemExit('pthread-exit TMPDIR must be a physical checkout .work directory')
PY
work="$(mktemp -d "$TMPDIR/general-dynamic-pthread-exit.XXXXXX")"
readonly work
printf 'pthread-exit evidence: %s\n' "$work"
mkdir "$work/oracle"
cp -a "$installed" "$work/execution-root"
readonly dependency="$ROOT/compat/x86_64/general_dynamic_pthread_exit_dependency.c"
readonly consumer="$ROOT/compat/x86_64/general_dynamic_pthread_exit_consumer.c"
"$driver" --dynamic-shared-object "$dependency" -o "$work/libpthread-exit.so"
"$oracle_cc" -std=c11 -fPIC -shared "$dependency" -Wl,-z,now,-soname,libpthread-exit.so -o "$work/oracle/libpthread-exit.so"
cp "$work/libpthread-exit.so" "$work/execution-root/usr/lib/"
printf 'ordinary exit after pthread teardown\nexecutable fini\nDSO fini\n' >"$work/expected.stdout"
for mode in pie non-pie; do
    oracle_entry=(-fPIE -pie)
    [ "$mode" = pie ] || oracle_entry=(-fno-pie -no-pie)
    "$driver" "--dynamic-$mode" -std=c11 "$consumer" --application-dso "$work/libpthread-exit.so" -o "$work/consumer-$mode"
    "$oracle_cc" -std=c11 "${oracle_entry[@]}" "$consumer" -L"$work/oracle" -Wl,-rpath,"$work/oracle" -l:libpthread-exit.so -o "$work/oracle/consumer-$mode"
    cp "$work/consumer-$mode" "$work/execution-root/consumer-$mode"
    python3 -B - "$work" "$mode" <<'PYRUN'
from pathlib import Path
import os
import signal
import subprocess
import sys
import time

work = Path(sys.argv[1])
mode = sys.argv[2]
expected = (work / 'expected.stdout').read_bytes()
for scenario, survivors in [('single', 0), ('simultaneous', 8), ('cancel-main', 1), ('cancel-worker', 0), ('orphan-main', 1), ('orphan-worker', 0)]:
    for product in ['oracle', 'candidate']:
        command = ([str(work / 'oracle' / f'consumer-{mode}'), scenario] if product == 'oracle'
            else ['chroot', str(work / 'execution-root'), f'/consumer-{mode}', scenario])
        label = f'{product}-{mode}-{scenario}'
        with (work / f'{label}.stdout').open('wb') as output, (work / f'{label}.stderr').open('wb') as errors:
            child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=output, stderr=errors, start_new_session=True)
            try:
                deadline = time.monotonic() + 12
                if survivors:
                    while True:
                        if child.poll() is not None:
                            raise SystemExit(f'{label}: exited before initial task retirement: {child.returncode}')
                        try:
                            state = Path(f'/proc/{child.pid}/task/{child.pid}/stat').read_text().rsplit(')', 1)[1].split()[0]
                        except FileNotFoundError:
                            state = ''
                        if state == 'Z':
                            break
                        if time.monotonic() >= deadline:
                            raise SystemExit(f'{label}: initial task did not retire')
                        time.sleep(0.001)
                    child.stdin.write(b'R' * survivors)
                    child.stdin.flush()
                child.stdin.close()
                status = child.wait(timeout=max(0.001, deadline - time.monotonic()))
                if status != 0:
                    raise SystemExit(f'{label}: exit status {status}')
            finally:
                if child.poll() is None:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait()
        orphan = scenario.startswith('orphan-')
        transcript = b'orphaned FILE remains locked\n' if orphan else expected
        if (work / f'{label}.stdout').read_bytes() != transcript:
            raise SystemExit(f'{label}: cleanup/finalizer transcript differs')
        stderr = b'' if orphan else b'cleanup FILE flush\n'
        if (work / f'{label}.stderr').read_bytes() != stderr:
            raise SystemExit(f'{label}: cleanup FILE final flush differs')
PYRUN

done
printf 'general dynamic pthread exit: PASS (both installed entries, DSO TLS/fini, simultaneous last exit, main/worker cancellation, orphan FILE locks); evidence: %s\n' "$work"
