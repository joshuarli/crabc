#!/usr/bin/env bash
# Ordinary initial/runtime DSO fork transaction, against pinned musl.
#
# Three tagged DSO objects and two roles of the same consumer source are
# compiled once through a supplied materialized product. `semantic-consumer`
# is ordinary C/POSIX behavior and is shared unchanged with pinned musl.
# `owned-layout-consumer` adds only the private crabc FS-layout assertions;
# it executes on all candidate entries but is not presented as a musl ABI.
set -euo pipefail
ulimit -c 0

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[ "$#" -eq 1 ] || { printf 'usage: %s DYNAMIC_SYSROOT\n' "$0" >&2; exit 2; }
readonly oracle_cc=/usr/local/bin/crabc-x86_64-musl-gcc
readonly library="$ROOT/compat/x86_64/general_dynamic_fork_library.c"
readonly consumer="$ROOT/compat/x86_64/general_dynamic_fork_consumer.c"

# Reject a symlinked product before creating any mutable evidence.  A dynamic
# qualification caller can therefore retain an exact physical product input.
supplied_installed="$(python3 -B - "$ROOT" "${TMPDIR:-}" "$1" <<'PY'
from pathlib import Path
import os
import stat
import sys

root, temporary, supplied = map(Path, sys.argv[1:])
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / '.work'):
    raise SystemExit('dynamic-fork TMPDIR must be a physical checkout .work directory')
if '..' in supplied.parts:
    raise SystemExit('dynamic-fork product must be a physical checkout .work directory')
absolute = Path(os.path.abspath(supplied))
current = Path(absolute.anchor)
try:
    for component in absolute.parts[1:]:
        current /= component
        if stat.S_ISLNK(current.lstat().st_mode):
            raise SystemExit('dynamic-fork product must be a physical checkout .work directory')
    if not stat.S_ISDIR(absolute.lstat().st_mode) or not absolute.is_relative_to(root / '.work'):
        raise SystemExit('dynamic-fork product must be a physical checkout .work directory')
except OSError:
    raise SystemExit('dynamic-fork product must be a physical checkout .work directory')
print(absolute)
PY
)"
readonly installed="$supplied_installed"
readonly driver="$installed/bin/crabc-cc-dynamic"
readonly work="$(mktemp -d "$TMPDIR/general-dynamic-fork.XXXXXX")"
readonly execution_root="$work/execution-root"
chmod a+rx "$work"
printf 'dynamic fork evidence: %s\n' "$work"
mkdir "$work/oracle" "$work/objects"

# Always retain a raw stdout/stderr/status triplet.  A failing assertion or
# timeout still ends this runner, but it does not erase the observed status.
run_host() {
    local output="$1"
    shift
    local status=0
    timeout 20 env -i PATH="$PATH" "$@" >"$output" 2>"${output%.stdout}.stderr" || status=$?
    printf '%s\n' "$status" >"${output%.stdout}.status"
    return "$status"
}

run_in_root() {
    local root="$1" output="$2"
    shift 2
    local status=0
    timeout 20 env -i PATH="$PATH" chroot "$root" "$@" >"$output" 2>"${output%.stdout}.stderr" || status=$?
    printf '%s\n' "$status" >"${output%.stdout}.status"
    return "$status"
}

compare_observation() {
    local oracle="$1" candidate="$2" suffix
    for suffix in stdout stderr status; do
        cmp "$work/$oracle.$suffix" "$work/$candidate.$suffix"
    done
}

# The library source is instantiated exactly three times with explicit tags;
# each consumer role has a distinct retained object and preprocessing identity.
names=(initial one two)
for tag in 0 1 2; do
    name="${names[$tag]}"
    "$driver" --dynamic-shared-object -std=c11 -fno-builtin "-DFORK_LIBRARY_TAG=$tag" -c "$library" -o "$work/objects/libfork-$name.o"
done
"$driver" --dynamic-pie -std=c11 -fno-builtin -c "$consumer" -o "$work/objects/semantic-consumer.o"
"$driver" --dynamic-pie -std=c11 -fno-builtin -DCRABC_OWNED_WITNESS -c "$consumer" -o "$work/objects/owned-layout-consumer.o"
python3 -B "$ROOT/compat/x86_64/owned_dynamic_fork_evidence.py" record-compile \
    --product "$installed" --work "$work"

# Initial is the startup DSO.  The two runtime DSOs retain the initial DSO as
# their only declared application edge, preserving the original graph.
for tag in 0 1 2; do
    name="${names[$tag]}"
    filename="libfork-$name.so"
    dependencies=()
    oracle_dependencies=()
    if [ "$tag" -ne 0 ]; then
        dependencies=(--application-dso "$work/libfork-initial.so")
        oracle_dependencies=(-L"$work/oracle" -l:libfork-initial.so)
    fi
    "$driver" --dynamic-shared-object "$work/objects/libfork-$name.o" \
        "${dependencies[@]}" -o "$work/$filename"
    "$oracle_cc" -shared "$work/objects/libfork-$name.o" "${oracle_dependencies[@]}" \
        -Wl,-z,now,-soname,"$filename" -o "$work/oracle/$filename"
done

# The semantic object is the actual musl differential.  The layout object is
# linked independently to every candidate entry and never passed to musl,
# because FS+24/FS+32 are a crabc-private runtime ABI rather than C/POSIX.
for mode in pie non-pie; do
    oracle_entry=(-fPIE -pie)
    [ "$mode" = pie ] || oracle_entry=(-fno-pie -no-pie)
    "$driver" "--dynamic-$mode" "$work/objects/semantic-consumer.o" \
        --application-dso "$work/libfork-initial.so" -o "$work/consumer-$mode"
    "$driver" "--dynamic-$mode" "$work/objects/owned-layout-consumer.o" \
        --application-dso "$work/libfork-initial.so" -o "$work/consumer-owned-layout-$mode"
    "$oracle_cc" -std=c11 "${oracle_entry[@]}" "$work/objects/semantic-consumer.o" \
        -L"$work/oracle" -Wl,-rpath,"$work/oracle" -l:libfork-initial.so \
        -o "$work/oracle/consumer-$mode"
done
python3 -B "$ROOT/compat/x86_64/owned_dynamic_fork_evidence.py" validate \
    --product "$installed" --work "$work"

cp -a "$installed" "$execution_root"
for name in initial one two; do
    cp "$work/libfork-$name.so" "$execution_root/libfork-$name.so"
done
cp "$work/libfork-initial.so" "$execution_root/usr/lib/"
for mode in pie non-pie; do
    cp "$work/consumer-$mode" "$execution_root/consumer-$mode"
    cp "$work/consumer-owned-layout-$mode" "$execution_root/consumer-owned-layout-$mode"
done

# The held-finalizer and adopted-main tests need a host parent to synchronize
# with the private chroot.  Each target retains stdout/stderr/status before
# returning a failure.  The adopted-main protocol consumes a live PID line;
# its complete, product-specific stream is additionally retained as
# `.raw.stdout`, while `.stdout` stays the fixed semantic tail used by the
# ordinary musl differential.
run_interactive() {
    local mode="$1" scenario="$2"
    python3 -B - "$work" "$mode" "$scenario" <<'PY'
from pathlib import Path
import os
import selectors
import signal
import subprocess
import sys
import time

work, mode, scenario = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
targets = [
    ('oracle', None, str(work / 'oracle' / f'consumer-{mode}')),
    ('semantic', 'kernel', f'/consumer-{mode}'),
    ('semantic', 'direct', f'/consumer-{mode}'),
    ('owned-layout', 'kernel', f'/consumer-owned-layout-{mode}'),
    ('owned-layout', 'direct', f'/consumer-owned-layout-{mode}'),
]
failed = False
for role, entry, consumer in targets:
    label = f'oracle-{mode}-{scenario}' if role == 'oracle' else f'{role}-{mode}-{entry}-{scenario}'
    if role == 'oracle':
        command = [consumer, scenario]
    elif entry == 'kernel':
        command = ['chroot', str(work / 'execution-root'), consumer, scenario]
    else:
        command = ['chroot', str(work / 'execution-root'), '/lib/ld-crabc-x86_64.so.1', consumer, scenario]
    output, errors, status_path = (work / f'{label}.stdout', work / f'{label}.stderr', work / f'{label}.status')
    raw_output = work / f'{label}.raw.stdout'
    process = None
    status = 125
    captured = bytearray()
    semantic = b''
    try:
        with errors.open('wb') as error_stream:
            process = subprocess.Popen(command, cwd=work / 'oracle', stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=error_stream, start_new_session=True)
            selector = selectors.DefaultSelector()
            selector.register(process.stdout, selectors.EVENT_READ)
            if scenario == 'finalizer-held':
                prefix = b''
                while len(prefix) < 2:
                    if not selector.select(5):
                        raise RuntimeError('missing finalizer/fork synchronization')
                    data = os.read(process.stdout.fileno(), 2 - len(prefix))
                    if not data:
                        raise RuntimeError(f'premature exit {process.wait()}')
                    prefix += data
                    captured += data
                if prefix != b'FB' or selector.select(0.1):
                    raise RuntimeError("fork passed another task's held finalizer")
                process.stdin.write(b'R')
                process.stdin.flush()
                result, _ = process.communicate(timeout=5)
                captured += result
                semantic = bytes(captured)
                output.write_bytes(semantic)
                if result:
                    raise RuntimeError(f'fork escaped finalization: {result!r}')
            else:
                line = b''
                while not line.endswith(b'\n'):
                    if not selector.select(5):
                        raise RuntimeError('missing adopted child PID')
                    byte = os.read(process.stdout.fileno(), 1)
                    if not byte or len(line) > 20:
                        raise RuntimeError(f'bad child PID {line!r}')
                    line += byte
                    captured += byte
                child = int(line)
                if child <= 0:
                    raise RuntimeError(f'bad child PID {line!r}')
                deadline = time.monotonic() + 5
                while True:
                    try:
                        state = Path(f'/proc/{child}/task/{child}/stat').read_text().rsplit(')', 1)[1].split()[0]
                    except FileNotFoundError:
                        state = ''
                    if state == 'Z':
                        break
                    if time.monotonic() >= deadline:
                        raise RuntimeError('adopted main task did not retire')
                    time.sleep(0.001)
                process.stdin.write(b'R')
                process.stdin.flush()
                result, _ = process.communicate(timeout=5)
                captured += result
                semantic = result
                output.write_bytes(semantic)
                if semantic != b'dynamic fork survives adopted main exit: ok\n':
                    raise RuntimeError(f'bad survivor output: {result!r}')
            status = process.returncode
            if status != 0:
                raise RuntimeError(f'exit={status}')
    except BaseException as error:
        failed = True
        print(f'{label}: {error}', file=sys.stderr)
    finally:
        if process is not None and process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        if process is not None and process.stdout is not None:
            try:
                captured += process.stdout.read()
            except (OSError, ValueError):
                pass
        if process is not None:
            status = process.returncode
        if scenario == 'worker-survivor':
            raw_output.write_bytes(captured)
            if not output.exists():
                output.write_bytes(semantic)
        elif not output.exists():
            output.write_bytes(captured)
        status_path.write_text(f'{status}\n')
if failed:
    raise SystemExit(1)
PY
}

for mode in pie non-pie; do
    for scenario in main worker kernel-main kernel-worker recursive abandoned failure finalizer-single; do
        (
            cd "$work/oracle"
            run_host "$work/oracle-$mode-$scenario.stdout" "./consumer-$mode" "$scenario"
        )
        for entry in kernel direct; do
            command=("/consumer-$mode" "$scenario")
            if [ "$entry" = direct ]; then
                command=(/lib/ld-crabc-x86_64.so.1 "/consumer-$mode" "$scenario")
            fi
            run_in_root "$execution_root" "$work/semantic-$mode-$entry-$scenario.stdout" "${command[@]}"
            compare_observation "oracle-$mode-$scenario" "semantic-$mode-$entry-$scenario"
            layout_command=("/consumer-owned-layout-$mode" "$scenario")
            if [ "$entry" = direct ]; then
                layout_command=(/lib/ld-crabc-x86_64.so.1 "/consumer-owned-layout-$mode" "$scenario")
            fi
            run_in_root "$execution_root" "$work/owned-layout-$mode-$entry-$scenario.stdout" "${layout_command[@]}"
        done
    done
    run_interactive "$mode" finalizer-held
    for entry in kernel direct; do
        compare_observation "oracle-$mode-finalizer-held" "semantic-$mode-$entry-finalizer-held"
    done
    run_interactive "$mode" worker-survivor
    for entry in kernel direct; do
        compare_observation "oracle-$mode-worker-survivor" "semantic-$mode-$entry-worker-survivor"
    done
done

# This final receipt requires every semantic differential and every private
# layout proof to have retained successful raw results.  It does not compare
# the private FS layout to musl.
python3 -B "$ROOT/compat/x86_64/owned_dynamic_fork_evidence.py" seal-observations \
    --product "$installed" --work "$work"
printf 'general dynamic fork: PASS (same semantic object against pinned musl and all candidate entries; separately sealed crabc-private FS layout witness; tagged DSO receipt/topology); evidence: %s\n' "$work"
