#!/usr/bin/env bash
# Installed POSIX timers; one object linked to every runtime.
set -euo pipefail
ulimit -c 0
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly oracle_cc=/usr/local/bin/crabc-x86_64-musl-gcc
readonly probe="$ROOT/compat/x86_64/owned_posix_timers_probe.c"
# Aggregate dynamic gates supply an already built installed or extracted
# product. The focused command also builds and checks both static entries.
[ "$#" -eq 0 ] || [ "$#" -eq 1 ] || { printf 'usage: %s [DYNAMIC_SYSROOT]\n' "$0" >&2; exit 2; }
build_static=1
provided_dynamic_sysroot="${1:-}"
if [ -n "$provided_dynamic_sysroot" ]; then
    build_static=0
    provided_dynamic_sysroot="$(python3 -B -c 'import pathlib, sys; print(pathlib.Path(sys.argv[1]).resolve(strict=True))' "$provided_dynamic_sysroot")"
fi
python3 -B - "$ROOT" "${TMPDIR:-}" "$provided_dynamic_sysroot" <<'PY'
from pathlib import Path
import sys
root, temporary = map(Path, sys.argv[1:3])
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / '.work'):
    raise SystemExit('posix-timers TMPDIR must be a physical checkout .work directory')
if sys.argv[3]:
    product = Path(sys.argv[3])
    if not product.is_dir() or not product.is_relative_to(root / '.work'):
        raise SystemExit('posix-timers product must be a physical checkout .work directory')
PY
work="$(mktemp -d "$TMPDIR/owned-posix-timers.XXXXXX")"
readonly work
finish() { chmod -R a+rX "$work"; printf "evidence: %s\n" "$work"; }
trap finish EXIT
if [ "$build_static" -eq 1 ]; then
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" --output "$work/dynamic-sysroot" >"$work/dynamic-build.json"
    provided_dynamic_sysroot="$work/dynamic-sysroot"
fi
# The selected installed (including extracted) product owns compilation.
# Reuse these exact objects in every musl, static and dynamic link.
"$provided_dynamic_sysroot/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -c "$probe" -o "$work/probe.o" >"$work/probe-compile.stdout"
"$oracle_cc" -pthread "$work/probe.o" -o "$work/oracle"
"$provided_dynamic_sysroot/bin/crabc-cc-dynamic" -shared -std=c11 -c "$ROOT/compat/x86_64/owned_posix_timers_tls.c" -o "$work/tls.o" >"$work/tls-compile.stdout"
"$oracle_cc" -shared "$work/tls.o" -o "$work/oracle-tls.so"
timeout 20 "$work/oracle" ordinary >"$work/oracle-ordinary.stdout"
timeout 20 "$work/oracle" dynamic "$work/oracle-tls.so" >"$work/oracle-dynamic.stdout"
# Isolate musl's startup cancellation race in fresh processes. Retain the
# hung parent's actual syscall/task state, then reap only our child.
python3 -B - "$work/oracle" "$work" <<'PYTRACE'
import json, subprocess, sys
from pathlib import Path
root = Path(sys.argv[2])
for attempt in range(1, 17):
    with (root / f'oracle-failure-{attempt}.stdout').open('wb') as out, (root / f'oracle-failure-{attempt}.stderr').open('wb') as err:
        child = subprocess.Popen([sys.argv[1], 'failure-once'], stdout=out, stderr=err)
        try:
            try:
                status = child.wait(timeout=0.1)
                if status: raise SystemExit(f'oracle single failure returned {status}')
                continue
            except subprocess.TimeoutExpired:
                tasks = {}
                for task in Path(f'/proc/{child.pid}/task').iterdir():
                    entry = {}
                    for name in ('status', 'wchan', 'syscall'):
                        try: entry[name] = (task / name).read_text()
                        except OSError as error: entry[name] = str(error)
                    tasks[task.name] = entry
                (root / f'oracle-failure-{attempt}.json').write_text(json.dumps({'pid': child.pid, 'tasks': tasks}, indent=2) + '\n')
                break
        finally:
            if child.poll() is None: child.kill()
            child.wait()
PYTRACE
rustc --edition=2021 --test --cfg 'feature="x86_64-owned-dynamic-runtime"' \
    --cfg crabc_general_initial_graph --cfg crabc_general_initial_lifecycle \
    --cfg crabc_general_initial_tls_materialization_v1 --cfg crabc_general_loader_libc_tls_runtime_v1 \
    --cfg crabc_dynamic_main_thread_runtime_v1 \
    "$ROOT/ldso/src/x86_64_general_initial_tls_runtime_v1_source_root.rs" -o "$work/tls-reset-tests" \
    >"$work/tls-reset-build.stdout" 2>"$work/tls-reset-build.stderr"
timeout 20 "$work/tls-reset-tests" timer_reset >"$work/tls-reset-tests.stdout"
timeout 20 "$work/tls-reset-tests" installed_runtime_function_imports_validate_shape >"$work/tls-import-tests.stdout"
if [ "$build_static" -eq 1 ]; then
    python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" --output "$work/static-sysroot" >"$work/static-build.json"
    for mode in static static-pie; do
        "$work/static-sysroot/bin/crabc-cc" "-$mode" -std=c11 "$work/probe.o" -o "$work/$mode"
        for scenario in ordinary; do
            timeout 20 "$work/$mode" "$scenario" >"$work/$mode-$scenario.stdout"
            cmp "$work/oracle-$scenario.stdout" "$work/$mode-$scenario.stdout"
            timeout 20 "$work/$mode" failure >"$work/$mode-failure.stdout"
        done
    done
fi
cp -a "$provided_dynamic_sysroot" "$work/execution-root"
"$provided_dynamic_sysroot/bin/crabc-cc-dynamic" -shared "$work/tls.o" -o "$work/libtimer-tls.so"
cp "$work/libtimer-tls.so" "$work/execution-root/libtimer-tls.so"
for mode in pie non-pie; do
    "$provided_dynamic_sysroot/bin/crabc-cc-dynamic" "--dynamic-$mode" -std=c11 "$work/probe.o" -o "$work/dynamic-$mode"
    cp "$work/dynamic-$mode" "$work/execution-root/consumer-$mode"
    for scenario in ordinary; do
        timeout 20 chroot "$work/execution-root" "/consumer-$mode" dynamic >"$work/dynamic-$mode-$scenario.stdout"
        cmp "$work/oracle-dynamic.stdout" "$work/dynamic-$mode-$scenario.stdout"
        timeout 20 chroot "$work/execution-root" /lib/ld-crabc-x86_64.so.1 \
            "/consumer-$mode" dynamic >"$work/direct-$mode-$scenario.stdout"
        cmp "$work/oracle-dynamic.stdout" "$work/direct-$mode-$scenario.stdout"
        timeout 20 chroot "$work/execution-root" "/consumer-$mode" failure >"$work/dynamic-$mode-failure.stdout"
        timeout 20 chroot "$work/execution-root" /lib/ld-crabc-x86_64.so.1 "/consumer-$mode" failure >"$work/direct-$mode-failure.stdout"
    done
done
printf 'owned POSIX timers: PASS (same object, musl + installed modes, timer lifecycle, callback TSD/TLS/cancel/exit reset, failure reclamation); retained evidence follows\n'
