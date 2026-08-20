# M6 signal/process stress harness

`run.py` compares a bounded set of Linux/AArch64 signal and process interactions
against the pinned musl reference and crabc.  It compiles
[`tests/signal_process.c`](tests/signal_process.c) exactly once with the
headers under `/opt/musl-1.2.6/include`, links that object once to musl and
once to `target/debug/libc.so`, then runs each selected subcase in a fresh
process group.

The subcases are intentionally deterministic and do not use networking,
wall-clock sleeps, PIDs in output, or host filesystem fixtures:

| Subcase | Contract exercised |
| --- | --- |
| `siginfo` | `SA_SIGINFO`, `sigqueue`, and queued `si_value` data |
| `nodefer` | `SA_NODEFER` and nested handler order (`ABba`) |
| `mask-pending` | blocked-mask, pending-set observation, and delivery on unblock |
| `sa-restart` | `SA_RESTART` action flags and restart of a signal-interrupted pipe read |
| `altstack` | `sigaltstack`, `SA_ONSTACK`, and `SS_ONSTACK` observation |
| `thread-mask` | worker-local mask/pending state and targeted `pthread_kill` |
| `sigwait` | `sigwaitinfo`, `sigwait`, and zero-timeout `sigtimedwait` |
| `timer` | `timer_create`, queued `SIGRTMIN`, and `SI_TIMER` data |
| `wait-signal` | child termination by `SIGTERM` and `WIFSIGNALED`/`WTERMSIG` |
| `wait-nohang` | `WNOHANG`, blocking release through a pipe, and `ECHILD` after reap |
| `atfork` | prepare/parent/child order over eight bounded `fork` iterations |
| `fork-worker-exec` | live worker at `fork`, child-safe `write`, and self-`exec` |

Each subprocess has its own process group.  A timeout kills the entire group,
and the next subcase starts only after that cleanup.  Exit status, stdout, and
stderr are compared byte-for-byte, with no semantic normalization.  Python's
negative return codes for signal termination remain negative; a timeout is
reported as the explicit `TIMEOUT` execution result.

## Run in the pinned Linux image

Build crabc first, then run from the repository root:

```sh
cargo build --workspace
python3 compat/signal-process/run.py
```

The default inputs are:

```text
musl headers: /opt/musl-1.2.6/include
compiler:     musl-gcc (or MUSL_CC)
crabc:        target/debug/libc.so and target/debug/libldso.so
timeout:      10 seconds per subcase
report:       compat/reports/signal-process.json
```

The runner requires native AArch64 Linux.  `--musl-root` must name the pinned
`musl-1.2.6` installation and provide its AArch64 loader and libc under
`lib/`; override it with `MUSL_ROOT` when the installation is mounted at a
different path.

Run one isolated subcase with, for example,
`python3 compat/signal-process/run.py atfork`.  Override paths with
`--musl-root`, `--target-dir`, or `--ldso`; `MUSL_ROOT`, `MUSL_CC`,
`CRABC_TARGET_DIR`, and `CRABC_LDSO` are also accepted.  `--timeout` is capped
at 300 seconds so a mistaken invocation remains bounded.  Use `--report PATH`
or `CRABC_SIGNAL_PROCESS_REPORT` to choose the destination.

The report is written to a temporary file, flushed and fsynced, and atomically
replaced into place.  It records the pinned musl version, compiler
identity, source hash, header and artifact paths, host/kernel/Python inputs,
timeout/isolation settings, every raw stream as byte length/SHA-256/hex/text,
and all three exact comparisons for each subcase.

## Fixture smoke tests

The standard-library-only Python tests check the runner's CLI and raw-byte
comparison/report helpers without requiring a Linux musl toolchain:

```sh
python3 compat/signal-process/tests/runner_test.py
```
