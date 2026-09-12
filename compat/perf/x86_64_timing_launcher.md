# Native x86 timing launcher

`x86_64_timing_launcher.c` is a static measurement supervisor for one native
x86 client invocation.  It keeps supervisor setup out of the child that
`wait4(2)` accounts for.  It is a harness tool, never a selected runtime
provider or an application input.

Build it only with the pinned compiler and ordinary static ET_EXEC flags:

```text
/usr/local/bin/crabc-x86_64-musl-gcc -static -no-pie -std=c11 -O2 \
  compat/perf/x86_64_timing_launcher.c -o TIMING_LAUNCHER
```

The fixed interface is:

```text
TIMING_LAUNCHER ROOT STDOUT_PATH STDERR_PATH RESULT_JSON TIMEOUT_MS BINARY [ARG...]
```

`ROOT`, `STDOUT_PATH`, `STDERR_PATH`, and `RESULT_JSON` are absolute paths.
The caller admits `ROOT` as its physical private client root below
`.work/x86_64`; the launcher opens that directory before it enters the root.
`ROOT/dev/null` must be the staged Linux null character device (major 1,
minor 3).  The launcher opens its terminal component nonblocking and no-follow,
so a FIFO, regular file, or terminal symlink cannot become client stdin or
hold setup past the timeout boundary.  Each output is a distinct, new, regular
`O_NOFOLLOW|O_EXCL` file.
`BINARY` must be a component-safe absolute path below `/app/bin/`.

Before `fork(2)`, the supervisor opens and redirects stdin/stdout/stderr,
retains a close-on-exec result descriptor, enters `ROOT`, changes to `/app`,
and closes every other descriptor with `close_range(2)`.  The child does only
`execve(BINARY, ...)`, or `_exit(127)` when that direct exec fails.  It inherits
the caller's already-scrubbed environment unchanged, including a target
`LD_LIBRARY_PATH`.  The result descriptor closes at exec, so the client sees
only standard descriptors.

The supervisor uses `pidfd_open(2)` plus a deadline-bound `poll(2)`, kills and
reaps only its own child on timeout, and writes a record only after a real
`wait4(2)` result.  A collected client exit, signal, direct-exec failure, or
timeout makes the launcher exit zero; an internal/setup/reaping failure is
nonzero and has no successful record.  The JSON object has exactly this shape:

```json
{
  "schema": "crabc.perf.x86_64-timing-launcher/v1",
  "child_pid": 123,
  "wait_status": 0,
  "timed_out": false,
  "elapsed_wall_ns": 0,
  "resources": {
    "user_cpu_ns": 0,
    "system_cpu_ns": 0,
    "max_rss_kib": 0,
    "minor_faults": 0,
    "major_faults": 0,
    "voluntary_context_switches": 0,
    "involuntary_context_switches": 0
  }
}
```

`elapsed_wall_ns` starts immediately around the production `fork(2)` and ends
after the actual child wait completes.  CPU values are direct `wait4` timeval
microsecond conversions to integer nanoseconds; they are never adjusted by a
supervisor estimate.  The Python collector remains responsible for the fresh
session, external process-group cleanup, client cgroup, timed/observer choice,
and retained report validation.

The focused smoke compiles a static client and launcher, checks static ET_EXEC
ELF headers and the pinned compiler identity, and retains commands, sources,
ELF hashes, raw JSON, and output bytes below `.work/x86_64`.  Its separate
`tests/x86_64_timing_launcher_pre_fork_burn_wrapper.c` source interposes only
the test build's fork call and burns supervisor CPU before the real fork.  The
emitted child CPU remains small while an outer `wait4` of that test supervisor
contains the burn; the production launcher has no test-mode switch.
It also passes a real low and high non-close-on-exec descriptor through Python
`pass_fds` and requires the direct client to observe both exact descriptor
numbers as closed after `close_range(2)`.

Run it in the pinned native image:

```bash
docker run --rm --init --platform linux/amd64 --network none --cap-add=SYS_CHROOT \
  --workdir /workspace --env PYTHONDONTWRITEBYTECODE=1 \
  --env TMPDIR=/workspace/.work/x86_64/tmp --volume "$PWD:/workspace" \
  crabc-core-evidence:x86_64 python3 -B \
  compat/perf/tests/run_x86_64_timing_launcher_smoke.py
```
