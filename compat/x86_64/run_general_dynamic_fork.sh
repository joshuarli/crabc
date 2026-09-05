#!/usr/bin/env bash
# Ordinary initial/runtime DSO fork transaction, against pinned musl.
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
    raise SystemExit('dynamic-fork TMPDIR must be a physical checkout .work directory')
PY
work="$(mktemp -d "$TMPDIR/general-dynamic-fork.XXXXXX")"
readonly work
printf 'dynamic-fork evidence: %s\n' "$work"
mkdir "$work/oracle"
cp -a "$installed" "$work/execution-root"
readonly library="$ROOT/compat/x86_64/general_dynamic_fork_library.c"
readonly consumer="$ROOT/compat/x86_64/general_dynamic_fork_consumer.c"
for tag in 0 1 2; do
    names=(initial one two)
    name="libfork-${names[$tag]}.so"
    dependencies=() oracle_dependencies=()
    if [ "$tag" != 0 ]; then
        dependencies=(--application-dso "$work/libfork-initial.so")
        oracle_dependencies=(-L"$work/oracle" -l:libfork-initial.so)
    fi
    "$driver" --dynamic-shared-object -DFORK_LIBRARY_TAG="$tag" "$library" "${dependencies[@]}" -o "$work/$name"
    "$oracle_cc" -std=c11 -fPIC -shared -DFORK_LIBRARY_TAG="$tag" "$library" "${oracle_dependencies[@]}" -Wl,-z,now,-soname,"$name" -o "$work/oracle/$name"
    cp "$work/$name" "$work/execution-root/$name"
done
cp "$work/libfork-initial.so" "$work/execution-root/usr/lib/"
for mode in pie non-pie; do
    oracle_entry=(-fPIE -pie)
    [ "$mode" = pie ] || oracle_entry=(-fno-pie -no-pie)
    "$driver" "--dynamic-$mode" -std=c11 -DCRABC_OWNED_WITNESS "$consumer" --application-dso "$work/libfork-initial.so" -o "$work/consumer-$mode"
    "$oracle_cc" -std=c11 "${oracle_entry[@]}" "$consumer" -L"$work/oracle" -Wl,-rpath,"$work/oracle" -l:libfork-initial.so -o "$work/oracle/consumer-$mode"
    cp "$work/consumer-$mode" "$work/execution-root/consumer-$mode"
    for scenario in main worker kernel-main kernel-worker recursive abandoned failure finalizer-single; do
        (cd "$work/oracle" && timeout 20 "./consumer-$mode" "$scenario") >"$work/oracle-$mode-$scenario.stdout" 2>"$work/oracle-$mode-$scenario.stderr"
    done
    for scenario in main worker kernel-main kernel-worker recursive abandoned failure finalizer-single; do
        timeout 20 chroot "$work/execution-root" "/consumer-$mode" "$scenario" >"$work/candidate-$mode-$scenario.stdout" 2>"$work/candidate-$mode-$scenario.stderr"
        cmp "$work/oracle-$mode-$scenario.stdout" "$work/candidate-$mode-$scenario.stdout"
    done
    python3 -B - "$work" "$mode" <<'PYRUN'
from pathlib import Path
import os
import selectors
import signal
import subprocess
import sys

work, mode = Path(sys.argv[1]), sys.argv[2]
for product in ['oracle', 'candidate']:
    command = ([str(work / 'oracle' / f'consumer-{mode}'), 'finalizer-held'] if product == 'oracle'
        else ['chroot', str(work / 'execution-root'), f'/consumer-{mode}', 'finalizer-held'])
    label = f'{product}-{mode}-finalizer-held'
    with (work / f'{label}.stderr').open('wb') as errors:
        process = subprocess.Popen(command, cwd=work / 'oracle', stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=errors, start_new_session=True)
        try:
            selector = selectors.DefaultSelector()
            selector.register(process.stdout, selectors.EVENT_READ)
            prefix = b''
            while len(prefix) < 2:
                if not selector.select(5):
                    raise SystemExit(f'{label}: missing finalizer/fork synchronization')
                data = os.read(process.stdout.fileno(), 2 - len(prefix))
                if not data:
                    raise SystemExit(f'{label}: premature exit {process.wait()}')
                prefix += data
            if prefix != b'FB' or selector.select(0.1):
                raise SystemExit(f"{label}: fork passed another task's held finalizer")
            process.stdin.write(b'R')
            process.stdin.flush()
            rest, _ = process.communicate(timeout=5)
            (work / f'{label}.stdout').write_bytes(prefix + rest)
            if process.returncode != 0 or rest:
                raise SystemExit(f'{label}: fork escaped finalization, status={process.returncode}, output={rest!r}')
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
PYRUN
    python3 -B - "$work" "$mode" <<'PYRUN'
from pathlib import Path
import os
import selectors
import signal
import subprocess
import sys
import time

work, mode = Path(sys.argv[1]), sys.argv[2]
for product in ['oracle', 'candidate']:
    command = ([str(work / 'oracle' / f'consumer-{mode}'), 'worker-survivor'] if product == 'oracle'
        else ['chroot', str(work / 'execution-root'), f'/consumer-{mode}', 'worker-survivor'])
    label = f'{product}-{mode}-worker-survivor'
    with (work / f'{label}.stderr').open('wb') as errors:
        process = subprocess.Popen(command, cwd=work / 'oracle', stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=errors, start_new_session=True)
        try:
            selector = selectors.DefaultSelector()
            selector.register(process.stdout, selectors.EVENT_READ)
            line = b''
            while not line.endswith(b'\n'):
                if not selector.select(5):
                    raise SystemExit(f'{label}: missing adopted child PID')
                byte = os.read(process.stdout.fileno(), 1)
                if not byte or len(line) > 20:
                    raise SystemExit(f'{label}: bad child PID {line!r}')
                line += byte
            child = int(line)
            deadline = time.monotonic() + 5
            while True:
                try:
                    state = Path(f'/proc/{child}/task/{child}/stat').read_text().rsplit(')', 1)[1].split()[0]
                except FileNotFoundError:
                    state = ''
                if state == 'Z':
                    break
                if time.monotonic() >= deadline:
                    raise SystemExit(f'{label}: adopted main task did not retire')
                time.sleep(0.001)
            process.stdin.write(b'R')
            process.stdin.flush()
            output, _ = process.communicate(timeout=5)
            (work / f'{label}.stdout').write_bytes(output)
            if process.returncode != 0 or output != b'dynamic fork survives adopted main exit: ok\n':
                raise SystemExit(f'{label}: exit={process.returncode}, output={output!r}')
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
PYRUN
done
printf 'general dynamic fork: PASS (musl + initial/worker TLS adoption, recursive and vanished constructors); evidence: %s\n' "$work"
