# Owned native pthread stress source profile

`run_owned_pthread_stress.sh` measures the remaining native pthread stress
workload through supplied installed x86-64 products. Its default `native-v1`
profile prepares a derivative of `tests/fixtures/pthread_stress_test.c`; the
frozen fixture and AArch64 runner remain unchanged. Passing this component does
not complete the native aggregate, a family, or public support. The composite
owner must additionally bind the same-product I/O-cancellation evidence below.

## Source contract

POSIX §2.9.5.2 permits, but does not require, a cancellation point in `fgetc`.
Section 2.9.5.4 requires asynchronous cancellation safety only for
`pthread_cancel`, `pthread_setcancelstate`, and `pthread_setcanceltype`.
Asynchronous cancellation during a function that is not async-cancel-safe has
undefined behavior. Neither section requires the frozen fixture's successful
deferred or asynchronous cancellation inside `fgetc`.
[POSIX thread cancellation](https://pubs.opengroup.org/onlinepubs/9799919799/functions/V2_chap02.html).

Pinned musl 1.2.6 follows `src/stdio/fgetc.c` through `getc.h`, `__uflow.c`, and
`__stdio_read.c`, whose backend uses raw `SYS_read`/`SYS_readv` rather than a
cancellation-point syscall. Its internal getc lock has no cancellation cleanup;
the explicit `flockfile` ownership list is a separate mechanism. Crabc's
`owned_static_stdio.rs` preserves raw FILE reads in `refill_into` and the
internal `StreamGuard` lock, consistent with `plan.md`'s ordinary FILE
non-cancellation contract. The source audit uses release archive SHA-256
`d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a`.
[Musl 1.2.6 source archive](https://musl.libc.org/releases/musl-1.2.6.tar.gz).

The frozen deferred probe waits for cancellation before releasing its pipe,
which cannot finish under the native FILE non-cancellation contract. The
asynchronous probe can leave the internal FILE lock held when its worker exits,
then block in `fclose`; that is a source-based explanation, not a measured
blocking location. The retained `asynchronous_read_probe` is classified as
pinned-musl source behavior, not a POSIX guarantee that `read` is async-cancel-safe.

`owned_pthread_stress_source.py` pins the original fixture SHA-256
`b8ac2a2d8e68d214b348c12ed6ebe579935aad94496127ea676a6d2527b4fad3`.
It requires exactly one occurrence of each whole main invocation line for
`deferred_stdio_probe` and `asynchronous_stdio_probe`. The `native-v1` preparation
replaces only those two lines (811 and 813) with explanatory comments. Every
other byte, including both function definitions and the asynchronous read call,
is preserved. There are no global defines or edits to the frozen source.
`--source-profile frozen` instead prepares a byte-identical copy and retains the
strict success comparator, allowing the old failure to be reproduced honestly.

## Required replacement evidence

The report's `replacement_io_cancellation_required` is exactly `READ_FILE` and
`ASYNC_LOOP` from the hash-bound `owned_io_cancellation_probe.c`:

- `READ_FILE` witnesses blocked FILE input, submits cancellation, proves that
  the input remains blocked, releases byte `K`, and requires completion before
  cancellation at `pthread_testcancel`. It also requires cleanup order 21,
  successful FILE reacquisition, and `fclose`.
- `ASYNC_LOOP` proves asynchronous delivery and cleanup while the worker executes
  a computation loop with no function calls after publishing its thread ID.

The existing I/O-cancellation family receipt must identify the same source and
selected installed products as the composite aggregate's stress run. Required
coverage includes dynamic PIE/non-PIE through kernel/direct entry and, when a
static product is supplied, static and static-PIE using that same static product.
This component merely declares the requirement: `replacement_io_cancellation_receipt` is null and
`native_aggregate_complete` remains false even when
`remaining_stress_workload_passed` is true. A composite owner must validate and
bind the actual I/O evidence; a fixture hash alone does not satisfy it.

## Invocation and evidence

Inside the pinned Linux/amd64 evidence container, with the checkout mounted at
`/workspace`, invoke:

```sh
bash compat/x86_64/run_owned_pthread_stress.sh \
  --static-sysroot /workspace/.work/products/static \
  --iterations 10 --timeout 10 /workspace/.work/products/dynamic
```

The dynamic product is required; the static product is optional. Options precede
the dynamic path and cannot repeat. Iterations range from 1 through 100, default
10; timeout is finite, greater than zero and at most 300 seconds, default 10.
The default source profile is `native-v1`. Products and `TMPDIR` must be physical
directories under the checkout's `.work`. Malformed arguments exit 2 before
evidence creation. Invalid products, build failures, and failed observations
exit 1. The runner builds no products. The container needs `chroot` authority;
this stress component needs no additional mount authority or procfs witness.

The installed dynamic driver compiles the prepared source exactly once with
`-std=c11 -O2 -D_POSIX_C_SOURCE=200809L -fno-builtin`. The driver supplies its
installed headers, freestanding translation, strong stack protection, and PIE
code generation. The retained object is linked unchanged to pinned musl 1.2.6,
both optional static modes, and dynamic PIE/non-PIE. Each dynamic binary runs
through both kernel interpreter entry and direct loader entry. With both
products the default matrix contains 70 observations: ten iterations of musl,
static, static-PIE, dynamic PIE kernel/direct, and dynamic non-PIE kernel/direct.

`owned_pthread_stress.py` preserves raw status, stdout, and stderr for every cell,
starts a fresh process group, and kills the group on timeout. An interrupted
supervisor sends SIGTERM, waits at most three seconds, then forces SIGKILL if
needed and reaps its child. It retains partial streams and the actual child
return code before propagating interruption. A timeout retains both `TIMEOUT`
and the actual return code. No stream normalization or source-failure exception
is applied. Passing either selected workload requires every cell to exit zero,
print exactly `pthread stress ok\n`, and leave stderr empty. Equal failed
observations are failures.

`source-map.json` records the versioned profile, original/prepared/preparer
identities, and exact removed/replacement bytes and line numbers. `compile.json`
binds that map, the actual installed-driver command, exact clean compiler
environment and compiler identity, source/tool/oracle identities (including the
local product validator and compiler contract helpers), installed-header roster,
preprocessor hashes, and object hash. The header audit names the prepared source;
it admits no ambient header directory.

The shared `owned_posix_product_evidence` validator checks each owned link before
execution and again afterward. `consumed.json` binds source binaries, executed
copies, the copied runtime payload, compiler inputs, prepared source/map, and
link receipts before execution. Final validation rechecks these identities,
the preprocessing closure, and retained raw bytes against observations.
`pthread-stress.json` schema v2 binds the source map, receipts, raw artifacts,
closed cell/iteration roster, source profile, and the narrowly scoped result.

## Native profile measurement

The default ten-iteration run with supplied static and dynamic product copies is
retained at `.work/x86_64/tmp/owned-pthread-stress.sig5hn1h/pthread-stress.json`
from the component worktree. All 70 observations are exactly exit 0, stdout
`pthread stress ok\n`, and empty stderr. The four strict owned links and final
source, tool, header, object, executed-copy, and raw-observation checks passed.
The prepared source SHA-256 is
`9551d1d34918551c7d9a7747e0210ff487026808eebfe9db79384e7f0a2c36bd`;
the common object SHA-256 is
`d9392ff629b2d198539351c604c2a0fdfa590db78f5bc1a227666fa8892700a3`.
This is remaining-workload evidence for those supplied products. The receipt
still declares the complementary I/O requirement and an incomplete native
aggregate; it does not qualify newly built products or bind a family matrix.

## Preserved frozen failure measurement

The original native frozen-source measurement is retained unchanged in
`.work/x86_64/tmp/owned-pthread-stress.btkuqhwq/pthread-stress.json` from the
component worktree. All 70 observations returned exit 1 with
`pthread stress FAIL 4\n`, two
`FAIL: deferred stdio cancellation probe\n` lines, then two
`FAIL: asynchronous stdio cancellation probe\n` lines; none hit the outer timeout.
The source labels at lines 811/813 reach `run_probe_with_timeout` checks at
647/648, accounting for both failures per killed inner child. `waitpid_bounded`
at line 247 performs the bounded wait and kill/reap.

The frozen AArch64 runner accepts its exact musl failure tuple only when paired
with crabc's exact clean success tuple, documenting a historical crabc source
improvement. Equal native failures satisfy neither that rule nor this native
runner's strict comparator. The prepared profile corrects which source calls
belong in the native workload; it never accepts `FAIL 4` as a pass.
