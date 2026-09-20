# Owned x86 POSIX AIO

`libc/src/c_abi/x86_64/owned_aio.rs` is the native Linux/x86-64
`x86-owned-static-runtime` implementation of the installed POSIX AIO C ABI.
It provides the eight public entries `aio_read`, `aio_write`, `aio_error`,
`aio_return`, `aio_cancel`, `aio_suspend`, `aio_fsync`, and `lio_listio`.
`aio_error` remains the frozen standalone observation leaf outside the owned
runtime selection; the other seven entries are newly supplied there. This is
C ABI request machinery over detached selected pthreads. It neither exposes
nor selects a Rust async runtime.

## Source map and ownership

The semantic source is musl 1.2.6 revision
`9fa28ece75d8a2191de7c5bb53bed224c5947417`, under the upstream MIT license in
the release `COPYRIGHT`. The release archive is pinned by
`compat/upstreams.toml`; its SHA-256 is
`d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a`.

| Pinned source | SHA-256 | Rust owner |
| --- | --- | --- |
| `src/aio/aio.c` | `a094ee091f0afc34789be384d450e8c5960d14d651ee924f6e08542554202ca4` | `owned_aio`: four-level descriptor map, queue/ref lifecycle, one detached worker per request, submit/cleanup/close/fork, read/write/fsync, error/return/cancel, and notification |
| `src/aio/aio_suspend.c` | `8e066c114a861cb2816b9e9661d1a52127b80a1dd7c996938bca3613802eb7c7` | `owned_aio::aio_suspend`: one-control and shared-list futex selection, monotonic timeout conversion, interruption, and cancellation |
| `src/aio/lio_listio.c` | `782cff6af764b518c4de1652809c91a698c015a9248bb5cca50fa90e2cc58abd` | `LioState`, `lio_wait`, `list_wait_thread`, `lio_listio`, and list signal/thread notification |

The map preserves the source's four-level fd route and its map rwlock plus
per-fd queue lock/ref lifetime. A request worker receives stack `AioArgs` and
posts its semaphore only after copying those fields. Queue completion retains
the source ordering: result first, terminal error publication, wakeups,
unlink/broadcast, queue unref, then notification. Raw C `aiocb` storage is
accessed through raw pointers and atomic `__err` words; no Rust reference is
formed to concurrently mutable C storage.

Notification handling reads `sigev_notify` first and snapshots only the active
mode's required fields. Thus a valid `SIGEV_NONE` request need not initialize
`sigev_signo`, `sigev_value`, or the union tail, and a `SIGEV_THREAD` request
need not initialize `sigev_signo`. The `sigval` snapshot is a raw C-union copy
of its active member; it is never interpreted as the inactive Rust scalar.
The installed behavior object leaves those fields indeterminate for both the
request and LIO thread-notification paths.

`aio.c` explicitly maps its allocator spellings to `__libc_malloc` and
`__libc_free`. The port uses the existing noninterposable internal allocator
helpers for that private queue storage. `lio_listio.c` deliberately spells
public `malloc`/`free`; its owner uses hidden assembly PLT thunks so ordinary
ELF interposition remains visible at that boundary. No allocator algorithm,
PRNG, cryptographic core, or dependency was added.

`__aio_atfork` is private and typed. Its safety contract limits callers to the
`-1`, `0`, and `1` phases of one fork transaction; only the sole surviving
child may discard inherited queue visibility and reinitialize the copied map
rwlock. The owned fork seam invokes it in the corresponding source order.

## Deliberate source differences

The ordinary request streams remain source-shaped. The following differences
are explicit rather than silent compatibility changes.

The earlier public sender claim about `submit`'s later worker-creation mask is
withdrawn. The instrumented fixed-source `early` and `deferred` schedules in
[`compat/x86_64/aio-source-signal-order.md`](../../compat/x86_64/aio-source-signal-order.md)
show that source boundary after `submit` has incremented the queue reference
and released `q->lock`; their handler `close` calls return. That source-only
witness neither executes unmodified musl nor a crabc product, and it is a
different source location from the first-descriptor defect below.

* Pinned `aio_cancel` deadlocks for a queued second full-pipe write: a
  canceler holds the queue lock while it waits for a worker whose cancellation
  cleanup must reacquire that lock. The source oracle target and cancel-all
  cases are retained as raw watchdog outcomes (status `137`). The owned port
  uses a stack cancellation cursor to bound the initial request set and
  counted worker pins while it drops the queue lock. Cleanup knows whether a
  canceled condition wait already owns that lock, publishes terminal state
  before pin drainage, and keeps the worker's queue reference until the last
  pin is gone. This avoids both the source deadlock and stack/queue lifetime
  races. Concurrent target/target, all/target, and late-submission cursor
  cases exercise the correction.
* Pinned `__aio_get_queue` has a distinct fresh-descriptor signal window. Its
  first all-signal block precedes map registration, `aio_fd_cnt` increment,
  `q->lock` acquisition, and map-lock release, but it restores the caller
  mask before returning the still-locked queue. The fixed-source direct
  inclusion in `aio_source_signal_order_witness.c` proves that source order
  without rewriting the pinned `aio.c` bytes. Its retained fresh receipt at
  `.work/x86_64/tmp/aio-source-signal-order.xE0yJf/fresh.stdout` is
  `SFGBPUHC`: it records the exact fresh map state after q-lock acquisition,
  queues `SIGUSR1` while blocked, then enters the handler and its same-fd
  `close` without either restore or close returning. This is an instrumented
  fixed-source observation, not an unmodified-musl behavior claim. The owned
  correction blocks application signals before every `submit` `get_queue`
  path, retains that outer mask through the queue reference increment and
  unlock, and restores it on both null/error and unlocked success paths. The
  source-shaped later worker-creation mask remains separate. The public,
  fork-per-attempt candidate watchdog at
  `owned_aio_fresh_signal_probe.c` records setup (`S/T/A`), handler entry and
  exact close start (`H/C`), close return (`R`), and a parent-only bounded
  kill. Before this correction, the unchanged owned static product produced
  `STAHC` without `R` at attempt 0 in
  `.work/x86_64/tmp/owned-aio.xjN7wv/static-fresh-signal.stdout`; this is a
  product regression observation, not an instruction-location attribution.
  After the correction, all six installed product routes report
  `fresh-signal-handler-close-pending=not-observed` in the 128-attempt
  replay at `.work/x86_64/tmp/owned-aio.fjxdKn`. Sender setup or join timeouts have distinct invalid-result
  classifications and cannot become a close-pending result.
* Pinned `__aio_close` cancels matching work but leaves its four-level map
  slot visible until later worker cleanup performs the final queue unref. A
  newly opened pipe can therefore reuse the numeric descriptor while the old
  regular-file queue still supplies cached `seekable`/`append` state; its AIO
  read uses `pread` and fails with `ESPIPE`. The raw pinned-musl witness is
  retained at
  `/workspace/.work/x86_64/tmp/owned-aio.JyQBh7/oracle-fd-reuse.stderr`
  (attempt 103), and the pre-fix owned static witness at
  `/workspace/.work/x86_64/tmp/owned-aio.628s2Q/static-fd-reuse.stderr`
  (attempt 502). This is a scheduling race, so the runner records either a
  complete source run or this exact `ESPIPE` transcript rather than treating
  a source success as parity. After `aio_cancel`, the owned close hook takes
  the map write lock, locks the queue currently in that slot, and clears the
  slot before Linux can recycle the descriptor. Workers and canceler pins
  keep the detached old queue alive. Final unref clears a map slot only if it
  still identifies that exact old queue, while `aio_fd_count` remains an
  allocation-to-final-free count; a new descriptor incarnation cannot be
  erased by old cleanup.
* The source uses public `sem_wait` for the private stack-argument handoff.
  That makes `aio_read`, `aio_write`, and `aio_fsync` cancellation points even
  though they are absent from the POSIX cancellation-point roster. The pinned
  source probe reports `submit-handoff-cancellation=observed`; the owned
  product reports `deferred` and delivers the pending request at the next
  explicit cancellation point. The private semaphore wait retries
  interruption and does not consume or clear the pending cancellation request.
  This follows the POSIX cancellation-point rules in
  [POSIX.1-2017](https://pubs.opengroup.org/onlinepubs/9699919799/functions/V2_chap02.html)
  and [POSIX.1-2024](https://pubs.opengroup.org/onlinepubs/9799919799/functions/V2_chap02.html).
* Musl's internal `__wake(addr, -1, ...)` normalizes the count to `INT_MAX`.
  The port does the same before the raw Linux `FUTEX_WAKE`; passing raw `-1`
  would wake only one waiter on the Linux 5.10 baseline. The multi-waiter
  `aio_suspend` regression covers both its one-control and shared-list words.
* After terminal error publication, an application may observe completion,
  call `aio_return`, and reclaim its `aiocb`. The port caches the aligned
  completion-word address before its release publication and passes that raw
  address only to Linux for the wake; it performs no Rust projection or
  dereference through a potentially reclaimed control block. This is a Rust
  provenance/lifetime correction, not an observable source difference.

The source `lio_listio` pthread-create failure branch blocks all application
signals and returns `EAGAIN` without restoring the prior mask. That odd edge
is retained exactly. `owned_aio_lio_create_failure_probe.c` supplies a copied
attribute record that makes the detached waiter creation fail, verifies
`EAGAIN` and the retained mask, restores its own test mask, then waits for the
already-submitted write before reclaiming its `aiocb`.

## Frozen os-test `aio_suspend` fixture lifetime

The frozen os-test case
`basic/aio/aio_suspend.c` at revision
`5e9456d510612f83b6ec8b1a0c06d6b1303a2512`, tree
`68fd4eef88d0e52b55c7cc2a73659b1e439d33fe`, has SHA-256
`3ff7bf5dc07a92d3c8fe0394d581ccc9c34dbbad10737953be6d7e595904f51d`.
It submits two writes using stack `aiocb`s and one shared stack buffer, calls
`aio_suspend` once, then calls `aio_return` only for requests already terminal
at that instant. `aio_suspend` promises one completed request; it does not
make the remaining listed request terminal. Returning with the other request
live releases its control block, buffer, and descriptor at the function/exit
boundary, violating the caller lifetime required by POSIX and by
`owned_aio.rs`.

The preserved full-campaign raw observation at
`.work/worktrees/os_test_mode_fix_full_replay/.work/x86_64/tmp/owned-os-test.dkxfi_6t/os-test.json`
(SHA-256 `0d2fe146d2cbf166838dccdbd964ecf019610e8ffb14af2fac9834469e19e619`)
records candidate `basic/aio/aio_suspend.out` as `exit: 139` and pinned musl
as `exit: 0`. That outcome is consistent with the invalid lifetime, but it
does not identify the exact faulting instruction or prove a runtime AIO defect.

`owned_aio_suspend_lifetime_probe.c` keeps the same two-write shape, records
the terminal count immediately after the single `aio_suspend` return, and
then drains both controls while their buffer and descriptor remain live. Its
controlled-pipe branch proves that a second request can remain live after the
first completion. Pinned musl and all four dynamic supplied-product routes
recorded `source-shape-completed=1 controlled-second-live=1 drained=2` in
`.work/worktrees/aio_suspend_regression/.work/x86_64/tmp/owned-aio.7DaVMv`; this is bounded development evidence for
the fixture boundary, not a promotion or a replacement for a fresh runtime
build.

`owned_os_test_aio_suspend_source.py` carries the upstream ISC notice and
admits only those exact frozen source bytes. `owned_os_test.py` leaves the
source stage unchanged, applies its single derivative independently to the
musl and dynamic `basic` copies, preserves the original one-completion
assertion, and reaps every submitted request before `fclose` or stack expiry.
Each side has a preparation receipt; the native observation reader requires
the source hash, prepared hash, preparer hash, replacement map, identical
side receipts, and prepared copy bytes. This is an audited fixture repair on
both sides, not a profile waiver or an AIO ABI/state workaround. Earlier v1
raw os-test reports without this explicit `source_preparation` record remain
historical evidence and cannot be silently admitted as a repaired aggregate.

The focused native replay materializes the same derivative with its unchanged
`basic/basic.h`, `misc/errors.h`, and `misc/compile.sh` support inputs. The
last script supplies its frozen `-Wall`, `-Wextra`,
`-Werror=implicit-function-declaration`, `-D_GNU_SOURCE`, `-D_BSD_SOURCE`,
`-D_ALL_SOURCE`, and `-D_DEFAULT_SOURCE` arguments, so the isolated build uses
the source suite's normal C surface. In
`.work/worktrees/aio_suspend_regression/.work/x86_64/tmp/owned-aio.7btggs`,
pinned musl and all four supplied-product dynamic routes (PIE/non-PIE,
kernel/direct loader) compiled and ran the prepared fixture with status zero
and empty streams. `owned_aio_evidence.py validate` re-derived its source tree,
support hashes, preparation receipt, compile flags, links, and execution
records. This remains bounded development evidence against the supplied
pre-existing product; it does not qualify a changed runtime build.

## Installed-product evidence

`compat/x86_64/run_owned_aio.sh` first compiles the installed-header object
`owned_aio_probe.c`; it takes hard references to all eight entries and checks
the x86 `aiocb` layout. The unchanged object links against pinned musl and the
owned products. It also runs focused ordinary behavior, source-deadlock,
cursor/pin, handoff-cancellation, fresh signal/close, lio-create-failure, and
wake-all probes.

The fresh component build and run recorded at
`/workspace/.work/x86_64/tmp/owned-aio.JyQBh7` used the current runtime:

```sh
TMPDIR="$PWD/.work/x86_64" ./scripts/dev-x86_64.sh owned-aio
```

It passed pinned musl, owned static and static-PIE, plus owned dynamic PIE and
non-PIE through both kernel-selected and direct
`/lib/ld-crabc-x86_64.so.1` interpreter paths. The ordinary transcript covers
positioned, append, and nonseekable I/O; queued sequencing; close
cancellation; timeout/interrupted/canceled `aio_suspend`; SIGEV_SIGNAL and
SIGEV_THREAD notification including callback close and partial `sigevent`
records; LIO_WAIT/NOWAIT and list failure; and live AIO across fork. The
wake-all transcript covers eight
simultaneous suspenders on each source futex route. The source fd-reuse
observation reached its `ESPIPE` witness in this run; all six owned products
completed the 512-attempt regular-fd-to-pipe regression. The fresh
signal/close watchdog completed 128 fresh-descriptor attempts in every static,
static-PIE, dynamic PIE, and dynamic non-PIE kernel/direct route without a
handler-close-pending receipt. Its final fixture-only replay is
`/workspace/.work/x86_64/tmp/owned-aio.fjxdKn`; it reused the unchanged
static and dynamic products from `owned-aio.JyQBh7` after the bounded event
receipt was tightened, rather than rebuilding the runtime.

This focused evidence does not promote x86-64 to public support or close the
broader native campaign.

### Retained installed-product receipts

`compat/x86_64/run_owned_aio.sh` now writes a single
`owned-aio-receipts.json` beside its raw artifacts. It seals the nine
installed-header compilation commands and dependency trace, every pinned-musl
source link, every static/static-PIE and dynamic PIE/non-PIE link receipt, and
the raw command, stdout, stderr, and status for each executed cell. The
source-only queued-cancellation deadlocks retain their observed `124`/`137`
status independently; they are not compared as successful oracle cells. The
submit-handoff source observation, ordinary transcript comparisons, and the
owned queue/cursor/fresh-signal corrections remain separately named records.

A supplied static sysroot is accepted only with the supplied dynamic sysroot
that provides the installed headers and compilation driver. With no supplied
products the runner may build both; a dynamic-only supplied run leaves the
static routes absent.

The receipt records only the modes that actually executed: a supplied dynamic
product without a static product emits the four dynamic kernel/direct modes
and cannot claim either static mode. Before and after the run it seals the
selected physical product manifests, source files, installed drivers and
resolved compiler/linker tools, and the pinned musl oracle inputs. A host
reader receives an independently captured `expected-native-inputs.json`; it
rejects a report that merely re-signs a changed native tool or oracle identity.

Each execution root is reconstructed from the selected product manifest,
sealed linked consumer, and required `/dev/null` device. Dynamic roots must
contain every copied product file and the one loader compatibility alias, plus
exactly the nine copied consumers. Static and pinned-musl roots have their
fixed consumer rosters. Extra entries, missing files, changed bytes or modes,
and changed aliases invalidate the receipt. The runner retains failed evidence
under its checkout-local `.work/x86_64/tmp/owned-aio.*` directory for review.
