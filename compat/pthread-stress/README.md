# Pthread/TLS stress differential

`run.py` runs the existing `tests/fixtures/pthread_stress_test.c` workload as
a pinned-musl differential. The source is compiled exactly once with the pinned musl
1.2.6 headers. That object is linked once to the pinned musl runtime and once
to `target/debug/libc.so` with `target/debug/libldso.so` as the interpreter.
Each requested iteration runs both binaries in fresh process groups. Exit
status, stdout bytes, and stderr bytes normally must match exactly; there is
no PID, loader-diagnostic, or whitespace normalization. A timeout or execution
error is a failed iteration even when both sides report the same error.

Pinned musl 1.2.6 has one explicitly recorded source-failure observation in
this workload: its deferred and asynchronous stdio-cancellation probes fail,
while crabc produces the source's exact clean success output. The runner
accepts only that complete pinned-musl status/stdout/stderr tuple paired with
the complete crabc success tuple, records it as a source improvement for every
iteration, and retains all raw bytes. It does not accept any other mismatch,
timeout, execution error, or non-clean candidate result. This rule is based on
the workload's cancellation contract and does not use a glibc runtime or
glibc behavior as evidence.

The runner requires Linux AArch64 and the pinned `/opt/musl-1.2.6` tree. It is
therefore intended to run in the native AArch64 Docker image, not directly on a
developer host:

```text
./scripts/dev.sh pthread-stress
./scripts/dev.sh pthread-stress --iterations 25 --timeout 15
```

The runner itself accepts `--iterations` from 1 through 100 (default 10) and
`--timeout` from greater than 0 through 300 seconds (default 10). The
environment variables `CRABC_PTHREAD_STRESS_ITERATIONS`,
`CRABC_PTHREAD_STRESS_TIMEOUT`, `MUSL_ROOT`, `MUSL_CC`, `CRABC_TARGET_DIR`,
`CRABC_LDSO`, `CRABC_PTHREAD_STRESS_SOURCE`, and
`CRABC_PTHREAD_STRESS_REPORT` provide equivalent configuration where useful.

The default report is atomically published at
`compat/reports/pthread-stress/latest.json` (the reports directory is ignored
by git). It includes the pinned compiler/header/runtime provenance, source and
artifact hashes, exact build commands, configured limits, every raw result,
per-stream byte hashes and hex bytes, and the aggregate pass state.

## Development-image integration

The paused AArch64 `scripts/dev.sh pthread-stress` command forwards to the
runner as follows:

```sh
ensure_image
run_in_container cargo build --workspace
run_in_container python3 compat/pthread-stress/run.py "$@"
```

`ensure_image` and `run_in_container` are required: they select the pinned
`linux/arm64` image, mount the workspace and AArch64 target volume, and expose
`/opt/musl-1.2.6`. No host compiler, glibc runtime, or host execution path is
part of this evidence.

This AArch64 route is paused. The native x86-64 component runs the same
fixture through the installed product with a derived source profile; see
[owned-pthread-stress.md](../x86_64/owned-pthread-stress.md).

## SCHED_FIFO progress of the selected pthread-key locks

`run_tsd_fifo_progress.sh` asks one question of the installed x86-64 static
product: can a waiter spin on a pthread-key lock while the preempted lock owner
shares its CPU and cannot run? `tsd_fifo_progress.c` is compiled with the
installed `crabc-cc` and linked to the installed libc, and also built against the
pinned musl oracle as a control. Its owner (`SCHED_FIFO` priority 10) and waiter
(priority 20) are pinned to one CPU; the waiter wakes by timer, preempts the
owner at an arbitrary instruction, then reads its key. The control must
complete or the run is invalid.

`tsd_fifo_watchdog.py` runs on a different CPU under the ordinary policy. It
fails a trial when the shared counters stop for 300 ms, reports the state of
`SELECTED_TSD_LOCK` and the selected-worker registry lock read from the stalled
process, and kills the fixture's whole process group. `RLIMIT_RTTIME` is a
kernel backstop, and the container is killed after 240 s. The FIFO section is
about one second per trial.

```text
scripts/build_x86_64_owned_sysroot.py --output /workspace/.work/x86_64/NAME   # in the pinned image
compat/pthread-stress/run_tsd_fifo_progress.sh --sysroot .work/x86_64/NAME [--repeat N] [--include-registry]
```

The container needs only `--cap-add SYS_NICE` and `--network none`. The runner
exits 77 when `SCHED_FIFO` is denied.

The default scenarios keep the lock owner on a task that takes only the
pthread-key lock: `getset` (owner is the main thread, in
`pthread_setspecific`/`pthread_getspecific`) and `delete` (owner is a worker in
`pthread_key_create`/`pthread_key_delete`). `--include-registry` adds `registry`,
two workers calling `pthread_getspecific`/`pthread_setspecific`. A worker's key
lookup takes the selected-worker registry spin lock owned by
`libc/src/c_abi/x86_64/pthread_create_join.rs`, so this scenario fails with that
lock held until its owner stops spinning; it is not part of the default pass
condition.
