# Owned native pthread stress aggregate

`run_owned_pthread_stress.sh` replays the unchanged
`tests/fixtures/pthread_stress_test.c` aggregate on supplied installed native
x86-64 products. It is a component measurement, not family completion or a
public-support claim. It does not build products or change the frozen AArch64
runner in `compat/pthread-stress/`.

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
Products and `TMPDIR` must be physical directories under the checkout's `.work`.
Malformed arguments exit 2 before evidence creation. Invalid products, build
failures, and failed observations exit 1. The container needs `chroot` authority;
this workload needs no additional mount authority or procfs witness.

The installed dynamic driver compiles the fixture exactly once with `-std=c11
-O2 -D_POSIX_C_SOURCE=200809L -fno-builtin`. The driver supplies its installed
headers, freestanding translation, strong stack protection, and PIE code
generation. The retained object is linked unchanged to pinned musl 1.2.6, both
optional static modes, and dynamic PIE/non-PIE. Each dynamic binary runs through
both kernel interpreter entry and direct loader entry. With both products the
default matrix contains 70 observations: ten iterations of musl, static,
static-PIE, dynamic PIE kernel/direct, and dynamic non-PIE kernel/direct.

`owned_pthread_stress.py` preserves each process's raw status, stdout, and stderr,
starts a fresh process group for every cell, and kills the group on timeout.
An interrupted supervisor sends SIGTERM, waits at most three seconds, then
forces SIGKILL if needed and reaps its child. It retains partial raw streams and
the actual child return code before propagating the interruption; a timeout
retains both the `TIMEOUT` classification and the actual return code.
No stream normalization or source-failure exception is applied. Passing requires
every cell to exit zero, print exactly `pthread stress ok\n`, and leave stderr
empty. Equal failed observations are failures.

The evidence directory retains `compile.json` with the actual installed-driver
command, the exact clean compiler environment and compiler identity,
source/tool/oracle identities (including the local product validator and compiler
contract helpers), installed-header dependency roster,
preprocessor hashes, and object hash. The shared `owned_posix_product_evidence`
validator checks each owned link before execution and again afterward. The
`consumed.json` identities bind source binaries, executed copies, the copied
runtime payload, compiler inputs, and link receipts before execution; final
validation rechecks them and the preprocessing closure. `pthread-stress.json`
binds those receipts, every raw observation artifact, the closed matrix roster,
and the result. There is no private leaf or ambient libc fallback.

The first native measurement uses supplied product copies and is recorded as a
failure: all cells observed exit 1 with `pthread stress FAIL 4\n`, and two
`FAIL: deferred stdio cancellation probe\n` lines followed by two
`FAIL: asynchronous stdio cancellation probe\n` lines. The two labels are passed
at fixture lines 811 and 813 to `run_probe_with_timeout`; its checks at lines 647
and 648 account for both failures per timed-out child. `waitpid_bounded` at line
247 kills and reaps a child after its bounded wait. The workers call `fgetc` at
lines 426 and 527; the aggregate does not expose a finer diagnosis of their
blocked state.

The frozen AArch64 exception has a different acceptance condition: the exact
musl failure tuple paired with crabc's exact clean success tuple. Its documented
rationale is a measured crabc source improvement for deferred/asynchronous stdio
cancellation. Equal native failures satisfy neither that rule nor this native
runner's success contract. No native limitation or rebaseline is authorized by
this component.
