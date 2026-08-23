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

`scripts/dev.sh` provides a `pthread-stress` command with the same forwarding
behavior as the other native runners. Its integration hook is:

```sh
ensure_image
run_in_container cargo build --workspace
run_in_container python3 compat/pthread-stress/run.py "$@"
```

`ensure_image` and `run_in_container` are required: they select the pinned
`linux/arm64` image, mount the workspace and AArch64 target volume, and expose
`/opt/musl-1.2.6`. No host compiler, glibc runtime, or host execution path is
part of this evidence. Dashboard integration, if desired, is a separate
caller concern; this runner's report is complete without it.
