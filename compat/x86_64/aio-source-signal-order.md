# Pinned musl AIO signal-order witness

`run_aio_source_signal_order.sh` is a native Linux/x86-64, **instrumented
fixed-source** witness for one order inside musl 1.2.6 `submit`. It is neither
an unmodified-musl execution nor a crabc runtime/product test. It records a
positive source observation: at the selected submission boundary, a
`SIGUSR1` handler can call `close` on the exact queued descriptor and return.
It does not establish a deadlock in musl or in crabc.

## Fixed source and provenance

The runner accepts only the local fixed archive
`.work/x86_64/source-oracles/musl-1.2.6.tar.gz`, SHA-256
`d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a`,
and invokes the pinned native oracle verifier. The archive is musl 1.2.6,
revision `9fa28ece75d8a2191de7c5bb53bed224c5947417`. Its focal source is under
the standard musl MIT license; the archive's `COPYRIGHT` is SHA-256
`b870108ec5e7790e9f9919064f1b9421d62d5f9b0e6c230c6adf7ea2da62e97b`.

| Pinned file | SHA-256 | Use in the witness |
| --- | --- | --- |
| `src/aio/aio.c` | `a094ee091f0afc34789be384d450e8c5960d14d651ee924f6e08542554202ca4` | Included as immutable source translation-unit bytes. The harness maps only its `pthread_sigmask` spelling to the visible test wrapper. |
| `src/internal/aio_impl.h` | `d89b582d5f2e49890b4830f942555b6a513b1c5125613f9e9f121db267185b16` | Declares the hidden `__aio_close` binding used by the included source. |
| `src/unistd/close.c` | `0a287fdef55394bdedfafc924efcec2d27e584a252cd2c71553fae0bb8ec9672` | Comes from the pinned static archive; its weak hidden `__aio_close` alias must bind to the included `aio.c` definition. |
| `src/signal/block.c` | `c0288b630002171684c42830f219ac2bc94a108f52e18dcddbd7405b3d5477e7` | Documents `__block_app_sigs`, which exists in musl but is not called by this `aio.c` source. |

The runner regenerates only musl's two generated internal headers using the
source Makefile recipes. It verifies `aio.c` before and after compilation, so
those source bytes are never rewritten.

## Actual source order

The selected source is not an `__block_app_sigs` call site. In `submit`, it
gets the queue, increments `q->ref`, and releases `q->lock`; only afterward it
calls `pthread_sigmask(SIG_BLOCK, &allmask, &origmask)`. The runner records the
validated offsets in `source-order.json` and rejects a source file that calls
`__block_app_sigs` or changes that sequence.

This matters for the handler reentry question: the submitter owns a queue
reference at the selected pre-block boundary, but it no longer owns the queue
mutex. The test does not synthesize a held mutex or insert a delay into musl.

The static link is also checked rather than assumed. The direct source object
must define `__aio_close` as `FUNC/GLOBAL/HIDDEN`; the pinned `close.lo` must
provide its weak hidden alias; the final `close` disassembly must call the
included `__aio_close`; and the link map must select `close.lo` without also
selecting archive `aio.lo`.

## Controlled schedules

The parent forks before the child starts AIO workers. The child leaves a pipe
writer open without data and submits a pipe read. `Q` is emitted only after a
non-main task is observed in a `pipe_read` wait channel below
`/proc/self/task`, so the descriptor queue is both live and backed by a
blocked request. It then submits another read for the same descriptor and
uses the wrapper at the real source call.

| Event | Meaning |
| --- | --- |
| `S` | Child signal/pipe setup completed. |
| `Q` | Seed request was observed blocked in a pipe read. |
| `W` | The wrapper reached `submit`'s real pre-block call. |
| `H` | The `SIGUSR1` handler entered. |
| `R` | The handler's `close(exact_seed_fd)` returned. |
| `A` | The early wrapper resumed after handler return. |
| `B` | The source call has blocked signals. |
| `P` | `SIGUSR1` was sent while blocked and remained pending. |
| `U` / `V` | Source `SIG_SETMASK` handoff begins / returns. |
| `X` | Child observed both requests terminal and exited normally. |

The `early` run raises `SIGUSR1` immediately before the real signal-block
call. Its required raw checkpoint stream is `SQWHRAX`. The `deferred` run
first calls the real signal block, raises `SIGUSR1` while it is blocked, then
records delivery only inside the real source `SIG_SETMASK` restore. Its
required stream is `SQWBPUHRVX`.

A parent watchdog bounds each child to three seconds. Its classifications keep
`handler-close-pending` separate from setup, seed handoff, wrapper reach,
sender/delivery, parent pipe, parent wait, and post-handler failures. The
outer runner timeout is only a second containment boundary; a timeout alone
is never a deadlock claim.

## Observed evidence

The native pinned run retained at
`.work/x86_64/tmp/aio-source-signal-order.cuzWnQ` produced raw status `0`,
empty stderr, and these stdout records:

```text
mode=early events=SQWHRAX child_status=0 timeout=0 classification=early-close-returned
mode=deferred events=SQWBPUHRVX child_status=0 timeout=0 classification=deferred-close-returned
```

`evidence.json` binds the source archive, oracle static archive, test source,
runner, object, binary, raw stdout/stderr/status hashes, and the explicit
non-product/non-unmodified identity. `source-order.json`, the link map,
symbol tables, `close` disassembly, and generated source tree stay beside the
raw run records.

Run the script only inside the pinned native x86 container with `TMPDIR` set to
the checkout's `.work/x86_64/tmp`; it intentionally has no dispatcher
registration in this component. A future registration belongs to the owner
integrating the AIO runtime evidence.

## Limits

This witness proves only these two injected schedules. The preprocessor mapping
is test-only and visible in `aio_source_signal_order_witness.c`; there is no
LD_PRELOAD, compiler substitution, source rewrite, product build, or crabc
object. It does not reproduce, relabel, or use prior stochastic sender/hang
probes. It does not claim that arbitrary handler interleavings are safe, that
unmodified musl cannot fail, or that a successful rerun closes an owned AIO
regression.
