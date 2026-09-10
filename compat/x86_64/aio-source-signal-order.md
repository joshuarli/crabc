# Pinned musl AIO signal-order witness

`run_aio_source_signal_order.sh` is a native Linux/x86-64,
**instrumented fixed-source** witness for two distinct signal-mask boundaries
in musl 1.2.6 `src/aio/aio.c`. It neither executes unmodified musl nor builds
or runs crabc. The direct source inclusion maps only `aio.c`'s
`pthread_sigmask` spelling to the visible wrapper in
`aio_source_signal_order_witness.c`; it does not rewrite the pinned source.

The two later `submit` schedules remain positive: a `SIGUSR1` handler's
`close(exact_fd)` returned after `submit` had released `q->lock`. The separate
fresh-queue schedule has a different result: after a real
`__aio_get_queue` signal restore, the handler entered and began that `close`,
but did not return before the bounded supervisor killed the child. These are
separate source locations and are never treated as interchangeable results.

## Fixed source and provenance

The runner accepts only `.work/x86_64/source-oracles/musl-1.2.6.tar.gz`,
SHA-256 `d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a`,
and invokes the pinned native oracle verifier. The archive is musl 1.2.6,
revision `9fa28ece75d8a2191de7c5bb53bed224c5947417`. Its focal source is under
the standard musl MIT license; the archive's `COPYRIGHT` is SHA-256
`b870108ec5e7790e9f9919064f1b9421d62d5f9b0e6c230c6adf7ea2da62e97b`.

| Pinned file | SHA-256 | Use in the witness |
| --- | --- | --- |
| `src/aio/aio.c` | `a094ee091f0afc34789be384d450e8c5960d14d651ee924f6e08542554202ca4` | Immutable direct-inclusion translation unit; only its `pthread_sigmask` spelling maps to the test wrapper. |
| `src/internal/aio_impl.h` | `d89b582d5f2e49890b4830f942555b6a513b1c5125613f9e9f121db267185b16` | Declares the hidden `__aio_close` binding used by the included source. |
| `src/unistd/close.c` | `0a287fdef55394bdedfafc924efcec2d27e584a252cd2c71553fae0bb8ec9672` | Comes from the pinned static archive; its weak hidden `__aio_close` alias must bind to the included `aio.c` definition. |
| `src/signal/block.c` | `c0288b630002171684c42830f219ac2bc94a108f52e18dcddbd7405b3d5477e7` | Establishes that `__block_app_sigs` exists, while the pinned `aio.c` does not call it. |

The runner regenerates only musl's generated internal headers with the source
Makefile recipes. It checks `aio.c` before and after compilation. It also
checks the direct object definition of `__aio_close`, the pinned `close.lo`
weak hidden alias, the link map's exclusion of archive `aio.lo`, and the final
`close` disassembly call to the included `__aio_close`.

## Distinct source boundaries

The receipt in `source-order.json` validates both sequences instead of
inferring either from the wrapper.

`submit` first obtains the queue, increments `q->ref`, and unlocks `q->lock`.
Its all-signal block occurs afterward. The `early` and `deferred` cases cover
that later boundary only.

For the first operation on a fresh descriptor, `__aio_get_queue` has a
separate sequence: its real all-signal block, map-entry registration,
`aio_fd_cnt` increment, `q->lock` acquisition, `maplock` release, and then
the real `pthread_sigmask(SIG_SETMASK, &origmask, 0)` restore before it returns
the still-locked queue. The receipt rejects drift in that exact order. This is
the boundary relevant to the fresh case and to the source comment that says
all AIO locks require signals blocked.

## Controlled schedules and checkpoints

Every request explicitly uses `SIGEV_NONE`; no schedule relies on an invalid
signal number from a zeroed `aiocb`. The parent forks before any AIO worker and
uses a three-second child watchdog plus an outer eight-second containment
timeout. It reports setup, sender, restore, handler, and close checkpoints
separately, so a timeout alone is never a conclusion.

| Case | Required stream | Meaning |
| --- | --- | --- |
| `early` | `SQWHRAX` | A live seed pipe read was observed; the handler was delivered immediately before `submit`'s real block and `close` returned. |
| `deferred` | `SQWBPUHRVX` | The same later `submit` block queued the signal; delivery occurred within that source restore and `close` returned. |
| `fresh` | `SFGBPUHC` | A fresh descriptor reached `__aio_get_queue`'s real block (`G`), the call succeeded (`B`), `SIGUSR1` was queued while blocked (`P`), and the wrapper recorded state immediately before its real restore (`U`). The handler entered (`H`) and reached its exact-fd `close` call (`C`); neither restore return (`V`) nor handler close return (`R`) occurred. |

Before the fresh case invokes the real restore, it writes one fixed report to
the parent. The accepted record requires a registered exact-fd queue,
`ref == 0`, `init == 0`, empty `head`, and `aio_fd_cnt == 1`. The source-order
receipt places that record after source acquisition of `q->lock`; the harness
does not probe or modify the mutex. This separates a valid fresh registered
queue from a setup or sender failure.

## Observed evidence

The retained native run at
`.work/x86_64/tmp/aio-source-signal-order.xE0yJf` produced raw status `0` and
empty stderr for every case:

```text
mode=early events=SQWHRAX child_status=0 timeout=0 classification=early-close-returned
mode=deferred events=SQWBPUHRVX child_status=0 timeout=0 classification=deferred-close-returned
mode=fresh events=SFGBPUHC child_status=9 timeout=1 fresh_report=1 fresh_queue_registered=1 fresh_queue_fd_matches=1 fresh_queue_ref=0 fresh_queue_init=0 fresh_queue_head_empty=1 fresh_aio_fd_count=1 classification=fresh-queue-handler-close-pending
```

For the fresh case, `child_status=9` is the parent watchdog's `SIGKILL`, not a
source-generated status. The classification requires the ordered source and
handler checkpoints plus the fresh queue receipt before it calls the close
pending. `evidence.json` binds the archive, oracle archive, source, runner,
object, binary, and raw stream/status hashes; `source-order.json`, link map,
symbol tables, and disassembly remain beside the raw records.

Run the script only in the pinned native x86 container with `TMPDIR` under the
checkout's `.work/x86_64/tmp`. It deliberately has no dispatcher registration;
the component owner decides any later integration.

## Limits

This is an injected fixed-source observation. It does not establish behavior
of an unmodified musl build, a crabc product, every possible signal schedule,
or the root cause of the nonreturn beyond the instrumented sequence recorded
here. In particular, it does not relabel the successful later-`submit` cases
as fresh-queue evidence, and it does not call a timeout by itself a deadlock.
There is no LD_PRELOAD, compiler substitution, source rewrite, product build,
or crabc object in this witness.
