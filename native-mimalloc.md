# Native mimalloc for crabc

This file is the complete execution contract for finishing crabc's native
mimalloc implementation.

When instructed:

> finish the implementation of aarch64-only native mimalloc as described in
> native-mimalloc.md

treat that instruction as authorization to inspect and modify every relevant
repository file, run all required tests and benchmarks, create implementation
worktrees, launch the mandatory parallel workers described below, and continue
through the final promotion gate. Do not stop after writing another plan,
closing a bounded witness, or reporting an intermediate checkpoint. Continue
from the first unmet objective gate until the Rust allocator is the verified
default production allocator, unless the user explicitly narrows the scope.

The crucial framing is:

> **Do not design a new allocator. Port pinned mimalloc v3.5.0 faithfully.**

The objective is to remove C mimalloc from crabc's production dependency graph
while retaining mimalloc's algorithms, ownership model, concurrency model,
lifecycle behavior, ABI-visible semantics, and performance. This is
compatibility engineering, not allocator research.

---

## 0. Immediate interpretation and execution rules

1. Read this file, `STATUS.md`, `docs/design/allocator.md`,
   `crabc-mimalloc/UPSTREAM.md`, `compat/allocator/port-map.toml`,
   `compat/allocator/known-differences.md`, the current allocator gate
   manifests, and the pinned upstream source before changing production code.
2. Record the current commit and working-tree state. Do not reset or discard
   accepted work merely because this document records an older audited commit.
3. Reproduce the first currently failing legal-C scenario before proposing a
   fix.
4. Use test-first development for every bug fix, behavior change, and
   refactor: write or preserve a failing test, observe the expected failure,
   implement the smallest source-faithful change, then rerun the focused and
   relevant aggregate gates.
5. Use at most eight concurrent Terra `max` implementation subagents in
   isolated git worktrees for every substantial implementation wave. Do not
   substitute Sol or another model tier unless the user explicitly changes
   this rule. The parallel-worktree protocol in this file is mandatory.
6. Prefer deleting or bypassing temporary allocator-control scaffolding over
   extending it.
7. Never weaken, rewrite, or reschedule an upstream workload merely to avoid a
   legal allocator behavior that currently fails.
8. Commit coherent, independently validated behavior slices. Do not mix
   unrelated cleanup, architecture changes, and gate changes in one commit.
9. Every success claim must name the exact command and generated report that
   proves it.
10. Do not claim completion until every final definition-of-done item in this
    file passes at the same commit.

### 0.1 Local workspace boundary

Run this work from the repository checkout and keep every mutable development
artifact below its repository-local `.work/` directory. This includes
temporary files, extracted upstream sources, implementation worktrees, Cargo
targets, generated sysroots, reports, and fixtures. Create subdirectories as
needed, for example `.work/tmp/`, `.work/worktrees/`, and `.work/target/`.
For the canonical checkout this is `/Volumes/dev/d/crabc/.work`.

Do not use `/tmp`, `/private/tmp`, `/var/tmp`, a home-directory scratch path,
or any other worktree or temporary location outside `.work/`. If a tool's
default would write outside this boundary, override its path before running
it; do not proceed with the default.

---

# 1. Fixed target and scope

## 1.1 Upstream baseline

The allocator baseline is fixed:

- project: `microsoft/mimalloc`;
- release: `v3.5.0`;
- exact commit:
  `18b08671c9302247bfb682286e6bf3cc1773f801`;
- archive SHA-256:
  `1e432f0559a4ab512143b9bff7a700541a2c8d4712b26a72de3e0222790da305`.

The archive, license, source map, build recipe, and update procedure belong in
`crabc-mimalloc/UPSTREAM.md` and the allocator compatibility manifests.

Do not silently upgrade the allocator. An upstream version change is a
separate reviewable change containing:

- the exact source diff;
- API and compile-time configuration inventory diffs;
- source-map impact;
- correctness and differential reruns;
- concurrency-model reruns;
- stress reruns;
- performance reruns.

## 1.2 Supported production platform

The production target is deliberately narrow:

- Linux only;
- AArch64 little-endian only;
- the current crabc Linux kernel floor, currently Linux 5.10;
- all Linux/AArch64 kernel page sizes that crabc claims;
- the supported AArch64 virtual-address profiles;
- the current pinned Rust nightly;
- the current crabc owned CRT, loader, and sysroot;
- hermetic Linux/AArch64 development, including Apple-Silicon Docker where
  useful.

Default production code must remain valid for crabc's baseline AArch64 ISA.
Optional newer-AArch64 optimizations must be separate compile-time profiles and
must not become accidental baseline requirements.

Explicitly out of scope:

- x86-64;
- RISC-V;
- macOS;
- Windows;
- generic future-platform scaffolding;
- mimalloc v1 or v2 compatibility;
- allocator invention;
- a generic allocator strategy framework;
- generic OS traits for hypothetical ports;
- runtime allocator selection;
- success-returning unsupported stubs;
- glibc as normative behavior.

Host, Miri, and Loom builds are verification instruments, not supported
production targets. Do not spend implementation time running or repairing
x86-64 production checks.

---

# 2. Definitions of done

Track these outcomes separately and then require all of them for final
completion.

## 2.1 Pure-Rust allocator engine

`crabc-mimalloc` must provide the Linux/AArch64 allocator engine with:

- `#![no_std]`;
- no production `alloc`;
- no dependency on crabc-libc;
- no C or C++ compilation;
- no bindgen-generated implementation;
- no native implementation build script;
- no recursive allocator dependency;
- no normal dependency on `libmimalloc-sys`;
- no hidden C allocator fallback.

The permitted production dependency direction is:

```text
crabc-mimalloc -> crabc-core + chacha20 + zeroize
crabc-libc     -> crabc-core + crabc-mimalloc
```

The reverse dependency is forbidden:

```text
crabc-mimalloc -> crabc-libc
```

Focused pure-Rust dependencies are acceptable only when they preserve the
pinned source behavior and do not introduce allocator recursion. Do not add
async runtimes, libc wrappers, serialization frameworks, logging frameworks,
or benchmark frameworks to production allocator code.

## 2.2 Lifecycle-complete malloc engine

Before broad optional APIs count as progress, the engine must safely support:

- process and initial-thread initialization;
- worker-thread initialization;
- persistent per-thread TLD and Theap ownership;
- local malloc, calloc, realloc, aligned allocation, usable-size query, and
  free;
- cross-thread free while the owner remains alive;
- multiple remote producers;
- thread teardown with no live allocations;
- thread teardown with live allocations;
- generic abandonment;
- post-owner-exit free;
- abandoned-page reclamation where pinned upstream permits it;
- final page, PageMap, bitmap, metadata, arena, and mapping release;
- repeated concurrent thread churn;
- allocator use in constructors, cleanup handlers, TSD destructors,
  cancellation, and fork.

## 2.3 crabc-libc integration

The Rust engine must back crabc's existing malloc-family ABI while preserving
the established musl-compatible policy, including:

- weak and preemptible allocator symbols where required;
- matching allocation/free interposition;
- `errno` behavior;
- zero-size behavior;
- natural allocation alignment;
- `calloc` overflow;
- `realloc` failure preservation;
- crabc's selected `realloc(p, 0)` behavior;
- aligned allocation;
- `posix_memalign` output preservation on failure;
- usable-size behavior;
- static and dynamic linking;
- loader interaction;
- no C-backend fallback for a Rust allocation.

The C ABI policy stays in `crabc-libc`. The allocator engine does not own
`errno`.

## 2.4 Applicable mimalloc v3.5.0 parity

Every public v3.5.0 API and compile-time mode applicable to Linux/AArch64 must
have a machine-readable status. Applicable interfaces must be implemented and
verified before final completion. Platform-inapplicable items may be marked
unsupported only with an explicit source-backed rationale.

Maintain separate dashboards for:

1. malloc-engine readiness;
2. complete Linux/AArch64 mimalloc v3.5.0 parity.

The malloc engine is the immediate critical path. Optional API work must not
delay the architecture convergence described below.

## 2.5 Correctness, stress, and performance evidence

Final completion requires:

- focused unit and invariant tests;
- exact configuration and layout probes;
- unmodified or minimally name-bound upstream tests;
- deterministic C/Rust differential traces;
- real pthread scenarios;
- concurrency model checking;
- Miri-compatible host-model execution;
- deterministic fault injection;
- process-isolated invalid-use tests where applicable;
- pthread, TLS, cancellation, fork, loader, and interposition tests;
- real-program corpus tests;
- deterministic bounded stress;
- a larger soak lane;
- qualified AArch64 performance and memory reports;
- default-backend production purity.

---

# 3. Audited starting point and known architectural failure

This section records the starting evidence from the audit of clean
`main-wip` commit
`90845409710dd5937b95c66be44bd6fc2f9ef09b`. If the branch has advanced,
reproduce these scenarios against the new head. Do not reset to the audited
commit.

## 3.1 First legal-C blocker

The smallest known legal-C failure is:

1. a worker allocates one block;
2. the worker exits;
3. the initial thread joins it;
4. the initial thread frees the surviving block.

```c
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

static void *block;

static void *producer(void *unused) {
  (void)unused;
  block = malloc(16);
  return block == NULL ? (void *)1 : NULL;
}

int main(void) {
  pthread_t worker;
  void *result;

  if (pthread_create(&worker, NULL, producer, NULL) != 0) return 10;
  if (pthread_join(worker, &result) != 0 || result != NULL || block == NULL) {
    return 11;
  }

  free(block);
  puts("ok");
  return 0;
}
```

At the audited commit this aborts because native `free` selects the caller's
initial-thread owner before considering the pointer's actual abandoned page
state. That is a fundamental dispatch defect: `free` must be pointer-centered,
not caller-domain-centered.

Add this exact scenario as a permanent selected-shadow C regression before
changing the implementation. Observe it fail for the expected reason, then
make it pass.

## 3.2 Unmodified upstream stress is currently blocked

Pinned upstream `test/test-stress.c`, changed only by defining
`USE_STD_MALLOC` so standard allocation names bind to the selected crabc libc,
fails at the smallest tested configuration:

```text
1 worker, scale 1, 1 iteration
```

The audited reproducer used the owned driver and loader in this form:

```sh
mkdir -p "$PWD/.work/tmp"
expdir=$(mktemp -d "$PWD/.work/tmp/crabc-upstream-stress.XXXXXX")
tar -xzf .work/allocator-cache/mimalloc-3.5.0.tar.gz -C "$expdir"
src="$expdir/mimalloc-3.5.0"
bin="$expdir/upstream-test-stress-stdmalloc"

./.work/target/crabc-sysroot/bin/crabc-cc   -std=c11 -O2 -DNDEBUG -fPIE -pie -ftls-model=initial-exec -pthread   -DUSE_STD_MALLOC -I "$src/include" -L "$PWD/.work/target/debug"   "$src/test/test-stress.c" -Wl,--allow-shlib-undefined -lc -o "$bin"

unset LD_AUDIT LD_PRELOAD LD_LIBRARY_PATH
export LD_LIBRARY_PATH="$PWD/.work/target/debug"
timeout 30 python3 scripts/run_owned_test_suite.py   --sysroot .work/target/crabc-sysroot --loader .work/target/debug/libldso.so   -- "$bin" 1 1 1
```

If repository paths have changed, preserve the semantic build and execution
conditions rather than copying stale paths mechanically.

The checked-in selected-shadow stress patch is not an acceptable substitute
for this gate because it moves transferred-object cleanup from the surviving
initial thread into fresh pthreads. That materially avoids the known failing
behavior.

Keep the adapted workload only as a separately named regression if it remains
useful. It must not count as upstream stress acceptance. The canonical
upstream lane must preserve upstream scheduling and cleanup behavior and make
only the minimum allocation-name/build adaptation required by the crabc
environment.

## 3.3 The current allocator-control architecture is temporary scaffolding

The following mechanisms have no direct upstream mimalloc counterpart and are
temporary production scaffolding:

- `PreparedOwnerExitClients` and semantic equivalents;
- `NativeLiveRemoteOwnerRegistry` and semantic equivalents;
- `NativePostExitRouteRegistry` and semantic equivalents;
- the process-wide `page_owner_state` scheduler for ordinary page operations;
- per-operation engine park/resume;
- exact-client detached route dispatch;
- B-thread completion objects that keep an exited A admission alive until B
  tears down;
- top-level geometry-shaped post-exit route wrappers.

They may remain briefly as differential oracles while the general source path
is introduced, but they are forbidden in the final production allocator.
Useful scenarios must survive as tests after the scaffolding is deleted.

The required deletion order is:

1. establish persistent per-thread source TLD/Theap ownership and the stable
   page-owned state required for direct pointer dispatch;
2. move local malloc/free/realloc onto that persistent owner;
3. generalize live remote free to pointer-to-page lookup and source page-local
   publication;
4. implement one ownership-preserving `_mi_theap_collect_abandon`
   coordinator over actual page queues;
5. make post-exit free and reclamation use page and process abandonment state;
6. delete the client ledgers, owner registries, route registries, per-call
   scheduler, per-call park/resume, geometry wrappers, and stress scheduling
   workaround.

## 3.4 Current complexity and performance are architecture blockers

At the audited commit, steady-state worker-local calls have added complexity
proportional to both registry high-water and ledger capacity:

```text
O(historical owner-registry nodes + live client-ledger slots)
```

They also acquire a process-wide scheduler transition and PageMap mutation
lease, move the session out of TLS and back, and can spin indefinitely under
contention. Every later-worker allocation consumes a large separate ledger
entry rather than relying solely on mimalloc page metadata.

The audited AArch64 typed control sizes included approximately 56 bytes for
each live-allocation ledger entry, 1,912 bytes for a session ledger with 32
inline slots, 2,176 bytes for the complete worker session, 88 bytes per
live-owner registry-node high-water, and 2,288 bytes per detached-route
registry-node high-water. These are typed sizes before allocator class
rounding and metadata overhead; they are not an acceptable steady-state
production cost model.

The audited cold-process smoke measurements were approximately:

| Workload | pinned C v3.5.0 | native shadow |
|---|---:|---:|
| 50,000 single-thread malloc/free pairs | 158.2M calls/s | 33.2K calls/s |
| four independent local workers | 233.5M calls/s | 2.12M calls/s |
| 20,000 producer/consumer cross-thread frees | 8.21M calls/s | 45.3K calls/s |
| 100 thread create/allocate/free/join cycles | 7.76M calls/s | 1.96M calls/s |

These are early architecture measurements, not final benchmark reports, but
they are far beyond ordinary optimization noise. Do not optimize the current
router. Remove the non-upstream work from the hot path.

## 3.5 Existing bounded evidence remains valuable

Existing direct-engine tests for page classes, remote-free atomics,
abandonment, owner exit, failure retention, and terminal release are valuable
regression witnesses. Preserve them.

However, existing records that call Gates 5A through 5C complete describe
bounded witness contracts. They do not establish general production pthread
allocation, general pointer routing, or a source-faithful hot path. Going
forward, every gate record must state its evidence scope explicitly:

- `bounded_witness`;
- `direct_engine`;
- `shadow_subset`;
- `production_general`;
- `promotion_qualified`.

Only `production_general` or `promotion_qualified` evidence may close a
production capability gate.

---

# 4. Non-negotiable production architecture

These constraints are hard requirements. A test that passes only by violating
them does not represent progress toward the final allocator.

## 4.1 Persistent per-thread source ownership

After initialization, every allocating thread owns a persistent source-shaped
TLD and Theap for its allocator lifetime.

The ordinary shape is:

```text
thread attach
  -> persistent TLD/Theap in TLS
  -> arbitrary local allocator operations
  -> source owner exit
  -> TLD/Theap teardown
```

It is not:

```text
thread attach
  -> take session out of TLS
  -> acquire process scheduler
  -> resume engine
  -> perform one allocator call
  -> suspend engine
  -> restore session to TLS
  -> repeat
```

The initial thread follows the same semantic model, with the source-required
static storage distinction.

A worker may attach before its user start routine, and crabc-libc may retain
explicit control over teardown placement, but the allocator owner itself must
remain persistent.

## 4.2 Local hot paths are owner-local

For an already-initialized thread and an already-owned page:

- small allocation uses the current Theap's direct/queue lookup;
- generic allocation uses the current Theap's source queue and page logic;
- local free updates the current page locally;
- local realloc uses the pinned source in-place or replacement decision;
- usable-size derives from the pointer and page;
- no per-allocation capability record is inserted;
- no owner registry is searched;
- no process-global allocator scheduler is acquired;
- no long PageMap mutation lease is acquired merely to touch an already-owned
  page;
- no engine is parked or resumed around the call.

Slow paths may synchronize where pinned upstream synchronizes: metadata
allocation, arena reservation, PageMap publication, abandoned bitmap claims,
heap/Theap list changes, and OS operations. Do not convert source-local work
into process-global serialization.

Steady-state independent local operations on independent thread-owned pages
must be independently executable.

## 4.3 `free`, usable-size, and realloc are pointer-centered

A valid allocation pointer is the dispatch input.

The production shape for `free(p)` is:

1. recover the source page from `p` through the PageMap and pinned pointer
   geometry;
2. validate the source-relevant page state under the C API's valid-live-pointer
   precondition;
3. recover the canonical block for aligned/interior allocations;
4. determine whether the page is locally owned, remotely owned, or abandoned
   from page-owned/source process state;
5. execute the corresponding pinned local-free, `mi_free_block_mt`, abandoned
   collect, unown, reclaim, or terminal-release path.

Do not first classify the calling thread as ticket zero, a later owner, a
fresh worker, or a post-exit releaser and then search for a pointer in that
domain.

`malloc_usable_size` and allocator-internal usable-size queries likewise derive
the page and usable extent from the pointer. They do not search a client
ledger.

Realloc must follow the pinned `mi_theap_realloc_zero_ex` control shape:

- derive old page and usable size from the old pointer;
- reuse in place only when the source conditions permit and the page belongs
  to the current target heap/Theap;
- otherwise allocate through the current thread's Theap;
- copy the bounded prefix;
- free the old pointer through the general pointer-centered free path;
- preserve the old allocation on replacement failure;
- preserve the selected zero-size behavior.

Cross-thread or post-owner-exit realloc must not require a special exact-client
route.

## 4.4 Live cross-thread free is page-local

Translate the pinned `free.c` remote-free path directly.

A legal live allocation must keep enough page-owned/source lifetime state for
another thread to:

- find the same registered page;
- verify its current source ownership state;
- recover the canonical block;
- publish to the page's remote-free atomic structure;
- return without borrowing the owner's entire allocator or TLD.

The existing direct ticket-zero remote-free path demonstrates the desired
shape. Generalize the source lifetime proof to later owners rather than
retaining a registry of TLS owners and a ledger of every client.

If Rust needs an additional page-owned generation or lifetime word to express
a source invariant safely, it must be:

- constant-size per page, not per allocation;
- documented as an intentional implementation difference;
- absent from local-call complexity;
- model-tested;
- benchmarked;
- removable if the pinned source fields already encode the fact.

Do not solve page lifetime by scanning owner registries or keeping an exact
record for every live allocation.

## 4.5 PageMap lifetime is tied to page/client lifetime

The direct pointer-to-page route requires an explicit invariant:

> A PageMap entry and its page metadata remain valid from allocation
> publication until the allocation has been locally consumed or a remote
> publisher has completed its source atomic publication.

Page creation and destruction must obey this invariant. Page release may occur
only after the source state proves that:

- no live client remains;
- no uncollected remote free remains;
- no remote producer can still legally publish;
- ownership/unown transitions are complete;
- PageMap unregister and metadata/mapping release occur in source order.

Use acquire/release or stronger orderings only where the pinned source
requires them. A plain pointer lookup must not take the global mutation lease
used for structural PageMap changes.

## 4.6 One generic owner-exit coordinator

The canonical upstream control flow is:

```text
_mi_theap_collect_abandon
  -> mi_theap_collect_ex(theap, MI_ABANDON)
  -> deferred-free processing
  -> retired-page collection
  -> generic page-queue traversal
  -> per-page collection
  -> free page if empty
  -> abandon page if live
  -> Theap/TLD detach and release
```

The Rust production implementation must converge on the same shape:

1. preflight the current live Theap and TLD;
2. invoke deferred-free processing in source order;
3. collect retired pages;
4. traverse all applicable queues in source order, including full pages when
   the pinned mode requires it;
5. collect local and remote frees for each page;
6. free pages that become empty;
7. abandon every surviving page into the exact process-visible source
   structure;
8. clear direct-cache/queue/list state as required;
9. detach the Theap from its Heap and TLD;
10. release the Theap and TLD when no surviving page still points to them.

The top-level owner-exit API must not require the caller to choose a route
named after page kind, bin, block count, mapped state, or test geometry.

Low-level helpers may distinguish genuine source branches such as:

- regular versus singleton;
- arena versus OS mapping;
- direct-small cache repair;
- large-span geometry;
- mapped versus source-unmapped abandonment;
- full-page source transitions.

Those distinctions remain beneath one coordinator.

The current bounded implementation connects that coordinator only for a
later `NativePersistentThreadOwner` and its independently held process
`PageMap`/arena pair. Its concrete path is
`NativePersistentThreadOwner::teardown` through
`MainHeapThreadOwnerLocalPageEngine::finish_after_collect_abandon` to
`PageAllocatorEngine<MainHeapThreadPageDrainSession>::collect_abandon_owner_exit`.
Before the coordinator receives its exclusive `Theap`,
`MainHeapThreadOwnerExitDeferredFree` and `ProductionOwnerExitCallbacks` split
out only the disjoint TLD deferred-free cursor, PageMap/arena facts, static-main
Heap lease, and terminal scalar slots. They retain neither a whole engine nor a
whole `Page`; while a live remote producer remains legal, page reads use raw
owner-field or intrusive-link projections and may overlap only the producer's
atomic subobject.

The one-way wrapper makes failure ownership explicit:

- `PreDrain(engine)` is retryable because attachment/root preflight failed
  before fast-slot or owner-local state changed;
- `RetainedTerminalEngine(engine)` retains the exact drained engine after a
  queue, abandonment, or release transition may have changed state and may not
  enter collection again; and
- `AttachmentOnly` proves the page engine was consumed, leaving only the
  no-page attachment boundary retryable.

This is not a scheduler, parked-session, global-registry, or route fallback.
The ticket-zero owner remains independently live while a later worker exits;
the default-off audit requires that direct worker exit add no legacy scheduler
transition. General public allocator routing, post-exit client free/reclaim,
and concurrent queue traversal remain outside this slice.

## 4.7 Exited threads do not remain ghost owners

Pinned mimalloc can finish a thread while its live blocks remain on abandoned
pages. Therefore:

- a worker admission does not remain live until the last future client free;
- an exited A thread is not retained through a B thread's later teardown;
- a post-exit page is owned by page/process abandonment structures, not by an
  exact-client route holding A's TLD lifetime;
- B's ordinary allocator lifetime is independent of the old A lifetime;
- a terminal free releases page/process state directly and does not mint a
  completion object that must wait for B's thread exit.

An internal failure after a one-way ownership transition must still retain one
unique terminal owner, but this is an exceptional fail-closed state, not the
normal representation of abandoned allocations.

## 4.8 No production Cartesian product of tests

Tests may be extremely specific. Production control flow may not become a
Cartesian product of:

- page kind;
- bin;
- used/reserved count;
- full/nonfull state;
- mapped/unmapped state;
- direct-cache state;
- local/remote publication timing;
- exact number of producers;
- exact number of post-exit consumers;
- caller thread identity.

Use types for durable authority and lifetime phases:

- process owner;
- current-thread TLD owner;
- attached Theap;
- live page engine;
- owner-exit drain;
- abandoned-page authority;
- PageMap mutation authority;
- arena/mapping capability;
- terminal retained owner.

Validate transient numerical page state at the transition that needs it.

## 4.9 Forbidden final production mechanisms

Before default promotion, the native production feature must contain no
compiled equivalent of:

- a per-live-allocation client ledger;
- a process-global registry of live TLS allocator owners;
- a process-global registry of exact post-exit client routes;
- a linear scan proportional to historical thread count for `free`;
- a linear scan proportional to live allocation count for local operations;
- a process-global CAS scheduler around ordinary local allocation/free;
- per-call engine suspend/resume;
- an exited-worker admission retained until a freeing worker exits;
- top-level owner-exit route types distinguished only by test geometry;
- a standard-C stress adaptation that changes which thread frees transferred
  objects.

These names may survive in history or test-only oracle modules. They must not
be reachable or compiled in the promoted production allocator.

---

# 5. Rust safety, provenance, and failure policy

Keep:

```rust
#![deny(unsafe_op_in_unsafe_fn)]
```

Every unsafe function must state its caller obligations. Every nontrivial
unsafe block must explain the exact source/lifetime invariant that makes it
valid.

The public C allocator boundary is inherently unsafe. For valid-program
semantics, callers must pass a currently live allocation returned by the
matching allocator. Do not add a production-wide exact-pointer registry merely
to make invalid `free` safe.

Use deliberately:

- raw pointers;
- `UnsafeCell`;
- atomics;
- strict-provenance-compatible address operations;
- short-lived validated projections;
- ownership types at one-way lifecycle boundaries.

Avoid long-lived shared or mutable Rust references over allocator metadata
whose real source aliasing cannot satisfy Rust reference rules.

## 5.1 Valid-operation behavior

For legal allocator use:

- local `free` cannot return unavailable;
- remote `free` cannot fail merely because another legal allocator operation
  is in progress;
- malloc/calloc/aligned allocation cannot report OOM because a temporary
  scheduler token was busy;
- realloc may fail only for the source-permitted allocation/size reasons and
  must preserve the old block;
- synchronization contention must wait or retry according to a bounded
  source-equivalent protocol, not poison the process;
- independent local owners must not contend on a global lifecycle word.

## 5.2 Internal invariant failures

When an internal one-way transition fails after source ownership has moved:

- retain exactly one mechanically identifiable owner;
- never recreate ownership from guesses;
- never fall back to C mimalloc;
- never silently leak an admission/count/map capability;
- expose the failure through deterministic fault tests and the test-only state
  auditor;
- use `core::mem::forget` only as part of an explicit terminal-retained type or
  process-abort path, not as routine success/error control flow.

The page-owned owner-exit continuation makes this exception deliberately
per-claim. `single_thread::continue_post_owner_exit_live_allocation_with_process_page_facts`
first performs the source page-local `allow_collect=true` publication; it does
not consult a process marker before that CAS. A `Detached` PageMap observation
therefore rejects before publication as `RemoteFreeError::NotOwnerAssociated`.
Only an exact W07 claim that has crossed the source one-way boundary may enter
the private `ProcessPostOwnerExitTerminalRetained` sink. That type has no
extraction or retry operation: terminalization records a test-only category,
sets an exception-only marker for later post-CAS operations, and forgets
the exact claim plus any post-tail mutation authority. This avoids both a
process-global owner slot and a pre-CAS scheduler while preserving each
concurrent claim's unique owner. Terminal callbacks acquire PageMap mutation
authority only at the source terminal-release tail. The bounded normal-OS
singleton image additionally accepts an alignment-forced `reserved == 1` page
(for example a 7-byte request rounded to 4 KiB at 128 KiB alignment) through
its exact OS layout; `OsHuge` and `OsRemap` remain fail-closed because this
port does not represent their release owners.

A spin loop requires a source-backed progress argument. Unbounded spinning on
a registry or process-global scheduler is not acceptable.

## 5.3 Invalid-input policy

Do not reproduce upstream memory unsafety solely for visual parity. For
invalid-pointer or double-free behavior:

1. determine the valid-program contract;
2. preserve valid-program behavior;
3. use debug/secure checks where applicable;
4. document deliberate hardening;
5. test intentional aborts in isolated processes.

---

# 6. Mandatory eight-worker Terra max execution

This project must use the available parallelism aggressively and safely.

## 6.1 Hard requirement

For every substantial implementation wave, the primary/root agent must:

- launch no more than **8 Terra `max` subagents**;
- give each subagent its own isolated git worktree and branch;
- assign each subagent an implementation deliverable;
- keep the root slot for architecture, integration, review, conflict
  resolution, and final verification.

Pure scouting, read-only code review, or a prose-only report does not satisfy
this requirement.

Every subagent must produce one of:

- production code;
- an executable failing regression plus the corresponding implementation;
- an executable differential/stress/benchmark harness used by the gate;
- a Loom/Miri/fault model used by the gate;
- deletion/refactor code that removes temporary production scaffolding;
- machine-readable gate/ratchet tooling.

Documentation-only assignments do not count. If a worker finishes early or is
blocked, immediately reassign that slot to another implementation slice.

Use no more than eight worktrees whenever a substantial phase is active.
Choose only independently mergeable slices; dependency ordering and constrained
build resources are reasons to leave a slot idle rather than create competing
or low-value work. Workers not yet able to land a dependent production change
may implement independent tests, harnesses, models, benchmarks, or preparatory
module boundaries that are mergeable in the same wave.

## 6.2 Worktree layout

Use the dedicated repository-local worktree directory, for example:

```text
.work/worktrees/
  w01-<topic>/
  w02-<topic>/
  ...
  w15-<topic>/
```

Use behavior-named branches, for example:

```text
codex/native-mimalloc/wave-01/w01-initial-post-exit-free
codex/native-mimalloc/wave-01/w02-upstream-stress
...
codex/native-mimalloc/wave-01/w15-production-ratchet
```

Each worktree must use an isolated build output, for example:

```sh
export CARGO_TARGET_DIR="$PWD/.work/target/codex-worktree"
```

The pinned upstream archive and immutable downloaded inputs may be shared.
Writable target directories, generated sysroots, reports, and temporary
fixtures must not be shared between concurrent worktrees unless the tooling
explicitly supports it.

## 6.3 Root-agent responsibilities

The root agent is the sole integrator. It must:

1. define the wave's interfaces and file ownership before dispatch;
2. assign one production owner per hotspot in that wave;
3. prevent multiple subagents from independently rewriting the same central
   state machine;
4. review every diff against pinned upstream source;
5. require a commit SHA, changed-file list, commands run, and test results from
   every subagent;
6. cherry-pick or merge only reviewed commits;
7. resolve interfaces centrally rather than accepting duplicate abstractions;
8. run focused tests after each integration;
9. run the wave gate after all accepted commits;
10. delete merged worktrees and create the next wave from the new integrated
    head.

Parallelism is a throughput aid, not permission for competing
allocator designs.

## 6.4 File-ownership discipline

During a wave, assign a single implementation owner to each high-conflict
production area, including:

- `crabc-mimalloc/src/runtime_lifecycle.rs`;
- `crabc-mimalloc/src/main_heap_page.rs`;
- `crabc-mimalloc/src/single_thread.rs`;
- `crabc-mimalloc/src/types.rs` and page ownership;
- `crabc-mimalloc/src/process_page_map.rs`;
- `crabc-mimalloc/src/abandoned.rs`;
- `libc/src/allocator_native_mimalloc.rs`;
- central allocator runners/manifests.

Other agents should work against explicit internal interfaces in disjoint
files or implement tests/harnesses. If a shared interface must change, land
that small interface commit first, rebase affected worktrees, then resume.

## 6.5 Subagent completion contract

Each subagent response must include:

```text
worktree:
branch:
commit:
goal closed:
files changed:
tests added:
commands run:
results:
known integration dependencies:
remaining concern:
```

A subagent must leave a clean worktree with a coherent commit. The root agent
must not accept uncommitted patches, unexplained generated files, or claims
without command output.

## 6.6 Recommended implementation-slice queue

Re-evaluate paths against current head, but choose up to eight independent
slices at a time from this queue unless the repository has already completed a
slice:

1. add the initial-thread-free-after-worker-exit C regression and owned-suite
   wrapper;
2. add a canonical unmodified upstream `test/test-stress.c` lane with only
   allocation-name/build adaptation;
3. implement single-thread local allocation performance smoke and report
   generation;
4. implement independent multi-thread local scaling smoke;
5. implement cross-thread free, churn, and worker-ledger/RSS smoke workloads;
6. fix caller-neutral pointer dispatch for the immediate initial-thread
   post-exit free defect without adding a geometry route;
7. implement the common pointer-to-page classification and canonical aligned
   block recovery boundary;
8. generalize page-local live remote free beyond ticket zero;
9. implement persistent later-thread TLD/Theap storage and direct local
   allocation entry;
10. remove per-operation park/resume and global scheduler use from local
    free/realloc;
11. implement the generic `_mi_theap_collect_abandon` queue coordinator;
12. implement abandoned-page pointer free and terminal release from page state;
13. implement source-permitted abandoned-page reclamation/adoption;
14. extend Loom/fault models for live-owner, abandonment, remote publication,
    and final release;
15. implement machine-enforced architecture/gate ratchets, including explicit
    evidence scope and forbidden-production-scaffolding checks.

Not all queued commits will be independent at final integration. The root
agent must define interfaces, select merge order, and rebase follow-on
worktrees as dependencies land. Every occupied slot nevertheless performs
implementation work.

---

# 7. Source-of-truth and progress discipline

## 7.1 Authoritative records

Use these records for distinct purposes:

- `compat/allocator/port-map.toml`: authoritative machine-readable semantic
  implementation and verification status;
- gate manifests: authoritative only for the exact evidence scope recorded in
  the manifest;
- generated compatibility reports: aggregate evidence, never hand-edited;
- `STATUS.md`: repository-wide status; it does not close or advance native
  mimalloc milestones;
- the live ledger in [§26](#26-native-mimalloc-live-ledger): authoritative
  native-mimalloc milestone status and execution order;
- `docs/design/allocator.md`: durable current architecture;
- `crabc-mimalloc/UPSTREAM.md`: source provenance and update procedure;
- `compat/allocator/known-differences.md`: deliberate differences;
- tests and benchmark reports: executable evidence;
- Git history: delivery history.

`native-mimalloc.md` is the execution contract. Its concise live ledger is not
a commit log: per-source status stays in the port map, and runtime evidence
stays in generated reports.

## 7.2 Progress measures

Do not measure progress primarily by:

- Rust line count;
- number of route types;
- number of page-shape tests;
- number of source-map rows;
- number of unit tests;
- number of bounded witnesses.

Measure the active architecture phase by:

- first failing legal C workload;
- count of forbidden production scaffolding mechanisms;
- process-global synchronization operations on the local hot path;
- extra control metadata per live allocation;
- remote-free lookup complexity;
- unmodified upstream stress coverage;
- deterministic and soak churn coverage;
- allocator-state stability after warmup;
- C/Rust throughput and memory ratios;
- applicable port-map rows at `production_general`;
- final production dependency purity.

## 7.3 Architecture ratchet

Maintain a machine-readable architecture gate with at least these fields:

```text
local_hot_path_process_scheduler_ops
local_hot_path_global_pagemap_leases
local_operation_owner_registry_scans
local_operation_client_ledger_scans
remote_free_owner_registry_scans
extra_control_bytes_per_live_allocation
per_call_engine_park_resume
exited_owner_admission_survives_thread_exit
unmodified_upstream_stress_max_workers
unmodified_upstream_stress_large_mode
forbidden_scaffolding_compiled
single_thread_throughput_ratio
four_thread_local_throughput_ratio
cross_thread_free_throughput_ratio
metadata_plateau_after_warmup
```

The final required values include:

```text
local_hot_path_process_scheduler_ops = 0
local_hot_path_global_pagemap_leases = 0
local_operation_owner_registry_scans = 0
local_operation_client_ledger_scans = 0
remote_free_owner_registry_scans = 0
extra_control_bytes_per_live_allocation = 0
per_call_engine_park_resume = false
exited_owner_admission_survives_thread_exit = false
forbidden_scaffolding_compiled = false
metadata_plateau_after_warmup = true
```

Page-local allocator metadata is not “extra control metadata.” A separate
side ledger or registry record for every live C allocation is.

## 7.4 Bug ratchet

Every fixed bug adds at least one durable artifact:

- focused test;
- minimized C reproducer;
- deterministic trace;
- Loom schedule;
- fault-injection case;
- upstream test adaptation limited to environment binding;
- integration scenario;
- benchmark workload.

Do not remove a regression because the implementation architecture changes.

---

# 8. Porting discipline

## 8.1 Preserve upstream terminology and control structure

Keep source terminology where useful:

- page;
- Heap;
- Theap;
- TLD;
- page queue;
- local free;
- cross-thread/remote free;
- abandoned state;
- subprocess;
- PageMap;
- arena;
- memory provenance;
- bitmap claim.

Do not broadly “Rustify” the design before parity.

When upstream has a generic dispatcher or traversal, port that dispatcher or
traversal. Do not manufacture many top-level operations because tests enter
the source flow in different concrete states.

## 8.2 Source mapping

Each meaningful source unit in `port-map.toml` records:

- upstream file and line/region;
- Rust destination;
- implementation status;
- unit verification;
- differential verification;
- integration verification;
- stress verification;
- performance qualification;
- associated tests;
- intentional differences;
- evidence scope.

A new row must represent a genuinely distinct upstream semantic unit, not a
new Rust scaffolding permutation.

## 8.3 Existing narrow routes become oracles

For a current narrow route that exercises valid source behavior:

1. preserve its test;
2. run the scenario through the narrow route;
3. add the same scenario through the new general production path;
4. compare normalized allocator state;
5. migrate the regression to the general path;
6. move any still-useful narrow helper to test-only code;
7. delete the specialized production route unless it maps to a distinct
   upstream branch.

## 8.4 No test-driven architecture distortion

A test fixture may coordinate threads and preserve deterministic race points.
It may not force production to accept a callback, exact client capability, or
route object that normal C code never supplies.

Test-only capability tokens are permitted only at the edge of the harness.
The production path exercised must be the same path used by standard C
malloc/free calls.

---

# 9. Test-first and debugging workflow

For every behavior slice:

1. identify the exact pinned upstream control flow;
2. reduce the current failure or missing capability;
3. add a minimal test that fails for the expected reason;
4. run it and preserve the failing output;
5. implement the smallest source-faithful behavior;
6. run the focused test;
7. run neighboring allocator tests;
8. run the state auditor;
9. run relevant Loom/Miri/differential tests;
10. run an early performance smoke if a hot path changed;
11. update machine-readable status;
12. commit.

Do not write production code first and then add a test that already passes.

When a stress workload fails:

- preserve the original schedule;
- record seed and arguments;
- minimize operations without changing ownership semantics;
- find the first violated invariant;
- fix the root cause;
- keep both the minimized regression and the original workload.

Do not solve deadlock by changing the workload to join threads earlier or by
moving a free to a different thread.

---

# 10. Architecture convergence phases

These phases replace the misleading assumption that bounded Gates 5A through
5C already establish a production allocator.

## Phase A — freeze the failure and restore legal C behavior

Required deliverables:

- permanent initial-thread-after-worker-exit free regression;
- canonical unmodified upstream stress lane;
- baseline architecture/performance report;
- a minimal pointer-dispatch correction for the known legal-C abort;
- explicit gate scope on all existing M5 records.

The minimal correction derives exact pointer facts from the PageMap before it
consults caller-local state. A valid foreign source may continue only through
generic pointer-first free; direct `realloc` must not query route scaffolding,
select a replacement owner, or use a parked compatibility bridge. This remains
a bounded bridge fix and does not close the architecture gate.

Acceptance:

- the minimized C reproducer prints `ok`;
- `free` from the initial thread no longer aborts solely because the block was
  allocated by an exited worker;
- no new page-geometry route was added;
- upstream stress advances to the next real failure;
- baseline reports are checked and reproducible.

## Phase B — persistent thread-local allocator ownership

Replace per-operation session parking with persistent TLD/Theap ownership.

Required behavior:

- later workers retain their source owner in compiler TLS;
- ordinary local operations call directly into that owner;
- concurrent workers own independent pages and can allocate concurrently;
- structural PageMap/arena slow paths remain correctly synchronized;
- cleanup handlers and TSD destructors can allocate and free before final
  allocator teardown;
- all-free thread exit uses the same generic owner-exit coordinator with no
  live survivors.

Required deletions/bypasses:

- scheduler transition on every local call;
- PageMap mutation lease on every already-owned-page call;
- session move out of and back into TLS per call;
- local client-ledger scan;
- per-call park/resume.

Acceptance:

- one, two, four, and eight independent workers pass mixed local workloads;
- no process-global scheduler operation appears in steady-state local call
  tracing;
- local operation complexity is independent of historical thread count and
  live allocation count;
- allocator state returns to baseline after worker teardown;
- early single-thread local throughput reaches at least 25% of pinned C on the
  architecture smoke before proceeding to broad optional API work;
- four-thread independent local throughput shows real parallel scaling and no
  global serialization signature.

The 25% smoke is not the final performance target. Falling below it is an
architecture blocker, not a request for micro-optimization.

## Phase C — general pointer-to-page free and live remote publication

Make `free`, usable-size, and realloc pointer-centered for every live owner.

Required behavior:

- current-thread local free;
- foreign-thread remote publication;
- multiple remote producers;
- aligned/interior pointer canonical recovery;
- owner collection concurrent with remote publication at deterministic race
  points;
- current owner continues allocating and reuses remote-freed blocks;
- realloc from a non-owning thread uses allocate/copy/general-free;
- no owner registry or exact client ledger is required.

Acceptance:

- remote free lookup is constant-time relative to owner/thread count;
- `NativeLiveRemoteOwnerRegistry` and the per-live-allocation ledger are absent
  from the production path;
- no lost, duplicated, or prematurely reused block;
- existing Loom models use the production atomic transition functions;
- 1/2/4/8-producer pthread tests pass;
- upstream live-owner transfer workloads pass without rescheduling cleanup;
- cross-thread smoke is no longer dominated by owner/ledger scans.

## Phase D — generic source owner exit

Implement the canonical owner-exit coordinator over actual Theap queues.

Required behavior:

- deferred-free phase;
- retired-page collection;
- direct-cache repair;
- regular small, medium, and large queues;
- full-page traversal when required;
- arena singletons;
- OS-backed/aligned singletons;
- pages that become empty during collection;
- pages that remain live;
- source-mapped and source-unmapped abandonment;
- Theap/Heap/TLD detachment and release;
- no surviving page points to torn-down thread-local state.

Acceptance:

- one genuinely mixed departing Theap passes through one top-level production
  coordinator;
- no caller-supplied page-shape route selection;
- existing narrow geometry tests pass through or compare equivalent to the
  general coordinator;
- the exiting worker's lifecycle is complete after pages are safely
  abandoned, even while live allocations remain;
- no A admission waits for a future B teardown;
- the state auditor proves queue, PageMap, bitmap, arena, OS-list, and
  TLD/Theap consistency.

## Phase E — post-exit free, reclamation, and final release

Make future operations use abandoned page/process state rather than exact
client routes.

Required behavior:

- any surviving thread, including the initial thread, can free an exact live
  allocation from an exited owner;
- simultaneous frees of distinct clients serialize only through the source
  page/abandoned structures that require it;
- final free releases page and mapping state in source order;
- source-permitted reclaim/adoption works from allocation/free paths;
- rejected reclaim preserves correct abandoned ownership;
- OS unmap/decommit failure retains one terminal owner;
- usable-size and realloc remain pointer-centered after owner exit;
- no post-exit exact-client registry.

Acceptance:

- `NativePostExitRouteRegistry`,
  `NativePostExitFreeRoute::{Aggregate,SoleMappedRegular}`, and semantic
  equivalents are absent from production;
- post-exit operations do not scan exited owners or client ledgers;
- freeing worker teardown is independent of old owner release;
- mixed owner-exit, concurrent post-exit free, reclamation, and failed terminal
  release tests pass;
- ticket zero can continue ordinary allocator work whenever source ownership
  permits, without route-token accounting.

## Phase F — delete scaffolding and consolidate modules

After the general paths pass:

- delete temporary ledgers, registries, scheduler states, route completions,
  geometry wrappers, and stale feature gates;
- move useful narrow witnesses into test-only modules;
- remove disabled `#[cfg(any())]` historical production implementations;
- split oversized modules by stable allocator responsibility where this
  materially improves reviewability;
- remove comments and docs describing deleted architecture;
- update the source map and known differences;
- prove the production feature no longer compiles forbidden scaffolding.

Do not postpone this cleanup until after performance work. Performance and
correctness qualification must measure the intended final architecture.

## Phase G — churn and selected-shadow closure

Run the general allocator through:

- repeated worker creation/destruction;
- independent local allocation;
- random cross-thread handoff;
- owner exit with live allocations;
- post-exit free;
- abandoned-page reclaim;
- mixed page classes;
- constructors;
- cleanup handlers;
- TSD destructors;
- normal return;
- `pthread_exit`;
- deferred cancellation;
- initial-thread participation;
- multiple concurrent owners and releasers.

Acceptance:

- deterministic bounded stress passes;
- soak passes;
- metadata, PageMap, arena, abandoned-page, TLD/Theap, and process-owner state
  plateaus after warmup;
- unmodified applicable upstream stress passes;
- the complete standard malloc-family ABI fixture passes through the selected
  Rust libc;
- no hidden C fallback exists.

---

# 11. Bootstrap, process initialization, and primitive layer

Preserve allocation-free bootstrap principles.

Initialization must be:

- idempotent;
- race-safe;
- reentrancy-safe;
- allocation-free until raw primitives are ready;
- valid through lazy first allocation;
- valid through explicit crabc startup;
- safe through entropy and diagnostic failure paths.

The startup context may expose raw, nonowning:

- auxiliary-vector values;
- page size;
- `AT_RANDOM`;
- raw environment;
- required process-start facts.

Do not call crabc's public libc ABI from the allocator. Do not use
`/proc/self/environ` as startup plumbing.

Use `crabc-core` for required raw Linux/AArch64 primitives. Preserve pinned
behavior for:

- mmap/reservation;
- unmap;
- commit/decommit;
- purge/reset;
- protect/unprotect;
- remap where applicable;
- page size;
- monotonic time;
- process/thread identity;
- yield/backoff;
- entropy;
- NUMA information;
- memory advice;
- relevant process information.

Keep fault injection at this primitive boundary. Do not create a generic public
OS trait.

Test:

- first allocation before explicit initialization;
- concurrent first entry;
- initialization recursion;
- primitive failure;
- entropy failure;
- PageMap failure;
- partial initialization;
- diagnostic paths during failure.

---

# 12. Page, arena, PageMap, and metadata invariants

Retain and complete the existing low-level port rather than rewriting proven
source mechanics.

The test-only state auditor must be able to verify:

- every live owned page belongs to exactly one valid queue;
- every abandoned page has coherent source ownership and PageMap state;
- Theap `page_count` matches traversal;
- intrusive links are valid;
- direct-cache entries match queue heads;
- PageMap coverage exactly matches each page span;
- large pages retain the complete required span;
- arena bits and counts agree;
- abandoned bitmap/count pairs agree;
- metadata marked released is unreachable;
- OS-abandoned list membership is coherent;
- local and remote free counts are internally possible;
- TLD/Theap/Heap list relationships are coherent;
- process thread counters are correct;
- no terminal owner is silently forgotten.

The auditor may be expensive and test-only. Keep focused source-specific
assertions as well.

Do not assume:

- 4 KiB pages;
- one virtual-address width;
- Armv8.3;
- one arena mapping mode.

---

# 13. crabc-libc allocator boundary

Keep three conceptual layers during migration:

1. backend-independent crabc malloc-family ABI;
2. temporary C mimalloc comparison backend;
3. Rust mimalloc backend.

Selection is compile-time. There is no runtime selector.

The Rust shadow backend must use the same production allocator entry points
that will become default. Do not give tests a privileged pointer capability
that standard C callers do not have.

Required standard operations:

- `malloc`;
- `calloc`;
- `realloc`;
- `free`;
- aligned allocation family;
- `posix_memalign`;
- usable-size query;
- allocator-related helper exports already present in crabc.

Required integration scenarios:

- initial-thread first allocation;
- constructors;
- multiple live pthread owners;
- worker-local operations;
- cross-thread free;
- initial thread freeing worker-owned and abandoned allocations;
- owner exit with live blocks;
- cleanup handlers;
- TSD destructors;
- cancellation;
- `pthread_exit`;
- static and dynamic executables;
- DSOs and weak/preemptible interposition;
- loader use;
- normal process exit.

The native backend must never pass an unrecognized Rust pointer to C mimalloc
or use C mimalloc as recovery.

---

# 14. Fork

Keep the current conservative quiescent bridge while the core ownership
architecture is being replaced. Do not extend the temporary route registries
to implement fork.

Before default promotion, define and verify the final Linux/AArch64 crabc fork
contract from pinned mimalloc behavior and crabc's libc placement.

At minimum prove:

- allocator fork hooks do not allocate;
- the parent remains valid after multithreaded fork;
- no inherited lock remains permanently held in the child;
- vanished-thread TLD/Theap ownership is repaired or converted to valid
  process-owned abandoned state;
- child TLS is coherent;
- the child can malloc, calloc, realloc, aligned-allocate, usable-size, and
  free;
- the parent continues allocating and freeing;
- public `pthread_atfork` handler ordering is correct;
- the raw-fork child path does not pretend an unprepared allocator image is
  safe.

A final default allocator cannot simply disable itself in a normal fork child
that is expected to allocate.

---

# 15. Public APIs, modes, and applicability

Generate the public API and compile-time mode inventory mechanically from
pinned v3.5.0.

Include:

- standard allocation;
- extended allocation;
- aligned operations;
- usable size;
- heaps;
- Theaps;
- arenas;
- managed memory;
- subprocesses;
- collection/purge;
- statistics;
- options;
- callbacks;
- lifecycle;
- visitation/walking;
- debug mode;
- secure mode;
- guarded mode;
- relevant architecture profiles.

For every item record:

- applicable or inapplicable on Linux/AArch64;
- exported;
- implemented;
- unit verified;
- differential verified;
- integration verified;
- stress verified;
- performance qualified;
- intentional difference.

Do not approximate secure, debug, guarded, options, callback, statistics, or
heap lifetime behavior. Finish the malloc lifecycle first, then complete all
applicable inventory groups.

---

# 16. Correctness oracles and differential testing

Use:

- exact pinned C mimalloc v3.5.0 for allocator-engine semantics;
- pinned musl and crabc's established ABI for standard allocator facade policy;
- Linux kernel behavior for VM primitives;
- deterministic shadow allocation/content models;
- crabc startup, pthread, fork, loader, interposition, and errno behavior.

Do not use glibc as normative behavior.

## 16.1 C oracle

Keep the C oracle hermetic and independently pinned. Record:

- source hashes;
- compiler;
- compile/link flags;
- resolved `MI_*` configuration;
- artifact hashes;
- symbols;
- benchmark host facts.

Do not treat the bundled `libmimalloc-sys` source as the v3.5.0 oracle unless
exact equivalence is independently proven.

## 16.2 Differential traces

Use separate processes and logical allocation IDs, never pointer equality
between C and Rust.

The trace language must cover:

- allocate;
- zeroed allocate;
- free;
- realloc;
- aligned allocation;
- usable size;
- fill/check;
- collect;
- heap/Theap operations;
- thread creation;
- cross-thread free;
- thread exit;
- post-exit free;
- reclamation;
- arena operations;
- fault injection;
- fork where normalization is meaningful.

Minimize failing traces and keep them permanently.

## 16.3 Upstream tests

Run applicable pinned upstream tests against:

1. exact C v3.5.0;
2. the Rust allocator through its C adapter or selected crabc-libc boundary.

Track unchanged, environment-bound, adapted, inapplicable, blocked, passed,
and failed mechanically.

An adaptation may account for:

- include/library paths;
- symbol namespace selection;
- available crabc APIs;
- deterministic test arguments;
- watchdog/report integration.

It may not change:

- which thread performs a legal free;
- owner-exit timing;
- transfer ownership;
- join ordering solely to avoid a race;
- cleanup semantics;
- page-class coverage solely to avoid a bug.

---

# 17. Miri, Loom, and fault injection

Miri remains valuable for:

- pointer arithmetic;
- metadata initialization;
- strict provenance;
- local allocation/free;
- realloc;
- ownership transitions;
- page and mapping lifetime.

Loom remains focused on actual atomic protocols:

- remote-free publication and collection;
- page owner/unown transitions;
- abandoned bitmap claims;
- PageMap publication/lifetime where modeled;
- final release;
- fork/admission atomics if they remain source-relevant.

Model the generic protocol, not each page geometry. Page geometry belongs in
deterministic tests unless it changes the atomic state machine.

Fault injection must cover:

- worker TLD/Theap creation;
- metadata allocation/growth;
- page allocation;
- PageMap publication and unregister;
- arena claims;
- remote publication;
- abandonment publication;
- reclaim;
- decommit/purge;
- terminal unmap/release;
- fork preparation.

A failure after a source mutation must leave one auditable owner.

---

# 18. Stress and churn

Provide two primary lanes.

## 18.1 Deterministic bounded development stress

It must include:

- private local allocation/free;
- multiple independent owners;
- producer allocates / consumer frees;
- many producers / one owner;
- random cross-thread handoff;
- owner exits before free;
- post-exit frees from the initial thread and workers;
- partial page liveness;
- mixed small/medium/large/singleton;
- abandonment and reclaim;
- normal return, `pthread_exit`, and cancellation;
- repeated creation/destruction.

Record:

- seed;
- operation count;
- thread count;
- page-class distribution;
- watchdog;
- final liveness;
- state-auditor result;
- metadata/PageMap/arena high-water;
- report artifact.

## 18.2 Soak

The soak lane uses materially larger:

- cycles;
- thread counts;
- operation counts;
- transfer counts;
- owner-exit counts;
- allocation-size distributions.

It must be deterministic by seed, watchdog-bound, and report all state
high-water marks. After warmup, process-owned metadata may plateau but may not
grow merely because equivalent threads churn.

## 18.3 Mandatory upstream stress matrix

At minimum, preserve upstream scheduling and run the standard allocator-bound
`test/test-stress.c` at:

- 1 worker;
- 2 workers;
- 4 workers;
- 8 workers;
- more than one meaningful scale/iteration configuration;
- large-object mode where the implemented source engine claims support.

The smallest configuration must pass before larger failures are classified as
capacity/performance issues.

---

# 19. Performance and memory qualification

## 19.1 Early architecture smoke

Do not wait for final qualification to measure:

- small malloc/free;
- hot-page reuse;
- medium and large allocation;
- aligned allocation;
- local free;
- remote publication;
- remote collection;
- independent thread scaling;
- thread churn;
- owner exit/post-exit free;
- RSS and allocator metadata;
- syscall count;
- code size;
- TLS lookup codegen.

Early measurements are reproducible and informational, but a catastrophic
ratio is an architecture blocker.

Investigate immediately:

- process-global locking/CAS on local calls;
- allocator recursion;
- unexpected TLS helper calls;
- O(thread count) pointer dispatch;
- O(live allocation count) local calls;
- per-allocation side metadata;
- syscall amplification;
- page-fault amplification;
- major code duplication;
- unbounded state growth.

Do not spend time micro-optimizing temporary ledgers or route registries.

## 19.2 Final promotion bands

Compare equivalent opaque C/Rust engine boundaries and fully integrated crabc
builds on a qualified native Linux/AArch64 host.

Initial non-inferiority bands against exact pinned C v3.5.0:

Throughput:

- suite geometric-mean lower 95% bound at least `0.95`;
- no critical workload lower bound below `0.90` without a separately reviewed
  exception.

Tail latency:

- critical p99 upper ratio bound at most `1.10`.

Memory:

- suite geometric-mean peak RSS/PSS upper ratio at most `1.05`;
- no critical workload above `1.10` without explanation;
- no unbounded metadata or mapping growth.

System behavior:

- no material unexplained syscall amplification;
- no material unexplained page-fault amplification;
- no metadata leak.

Code size:

- investigate more than 10% allocator-attributable growth.

Threshold changes are independent reviewed changes, not a way to make the
current implementation pass.

Apple-Silicon Docker is valid for development correctness and smoke. Final
performance qualification requires a recorded native Linux/AArch64
environment.

## 19.3 AArch64 codegen audit

Inspect optimized code for:

- small allocation;
- local free;
- remote-free publication;
- PageMap lookup;
- bin lookup;
- TLS lookup;
- realloc fast path;
- aligned fast path.

Look for:

- panic/unwind paths;
- bounds checks;
- division;
- formatting;
- TLS helper calls;
- missed inlining;
- unnecessary fences;
- SeqCst overuse;
- unnecessary zeroing;
- code duplication.

Optimize only after demonstrating a real regression or obviously bad generated
sequence.

---

# 20. Canonical commands

Maintain or add focused commands equivalent to:

```sh
./scripts/dev.sh allocator --quick
./scripts/dev.sh allocator --full
./scripts/dev.sh allocator-upstream
./scripts/dev.sh allocator-shadow
./scripts/dev.sh allocator --soak
./scripts/dev.sh allocator-perf --smoke
./scripts/dev.sh allocator-perf --full
./scripts/dev.sh check
```

Exact subcommand spelling may follow repository convention, but the capability
separation must remain.

## `allocator --quick`

Runs:

- focused unit/invariant tests;
- architecture ratchets;
- source-map validation;
- small differential set;
- Loom smoke;
- minimal local, remote, owner-exit, and post-exit integration tests.

## `allocator --full`

Runs the complete correctness and lifecycle evidence for all currently
implemented mandatory gates. While work remains, it exits nonzero and names
the first unmet objective gate. It must not use a permanent generic
“future milestone unavailable” failure.

At final completion it passes at the same commit as every other canonical
command.

## `allocator-upstream`

Runs the exact pinned upstream test inventory, including the minimally
environment-bound unmodified stress lane, and records applicability and
results.

## `allocator-shadow`

Builds the owned sysroot, snapshots and attests the ordinary C-backed dynamic
`libc.so`, then selects the Rust allocator libc. The bounded paired ABI matrix
runs one normalized initial-thread `malloc`/`free`/`realloc` trace against each
explicitly selected artifact and writes a deterministic report. Its two
zero-size `realloc` ordinary/native alignment differences are named known reds,
while foreign-worker, owner-exit, DSO/static-linkage, and allocator-layout rows
stay blocked rather than broadening the comparison. The remaining standard
C/pthread/owner-exit/fork/loader fixture matrix proves the loaded/interposed Rust
artifact and must not accidentally load the C-backed libc.

## `allocator --soak`

Runs the larger deterministic churn/stress matrix with watchdog and state
high-water reporting.

## `allocator-perf --smoke`

Runs reproducible development comparisons and architecture ratchets. It may
run in Apple-Silicon Linux/AArch64 Docker but must identify the environment as
unqualified for promotion when applicable.

## `allocator-perf --full`

Runs the statistically qualified native AArch64 performance and memory suite
and emits the promotion report.

## `dev.sh check`

Runs the normal repository-wide final gate with the Rust allocator selected as
default after promotion.

Every command must emit a machine-readable report under a predictable target
directory. Checked-in manifests describe expectations and provenance; generated
results are not manually rewritten to claim success.

---

# 21. Milestones after architecture convergence

The requirements below define closure. The live status of each milestone is
recorded in [§26](#26-native-mimalloc-live-ledger); do not infer completion
from a bounded witness or an implemented source-map item.

## Milestone 0 — pin, scope, inventory, skeleton

Required:

- pinned source and archive hash;
- license/provenance;
- no_std crate;
- dependency policy;
- API inventory;
- source map;
- C oracle;
- configuration/layout baseline;
- canonical harness.

Existing work closes this inventory/skeleton milestone only. Preserve it; this
is not an allocator-engine or source-unit parity claim.

## Milestone 1 — pure foundations

Complete and verify:

- configuration;
- arithmetic;
- types;
- atomics;
- provenance;
- random machinery;
- primitive layer;
- bootstrap types.

These are the six bounded components named by
`compat/allocator/m1-foundations-v3.5.0.json`, not whole `types.h`, `prim.h`,
`prim-tls.h`, `internal.h`, or source-file completion.

## Milestone 2 — memory substrate

Complete and verify:

- VM primitives;
- metadata;
- bitmaps;
- PageMap;
- arenas;
- initialization;
- fault injection;
- no allocator recursion.

## Milestone 3 — single-thread allocation

Complete and verify:

- Heap/Theap bootstrap;
- page queues;
- local allocation/free;
- page retirement/reuse;
- bin/page-class matrix;
- deterministic differential traces;
- Miri-compatible path.

## Milestone 4 — fundamental operations

Complete and verify:

- calloc;
- realloc;
- aligned allocation;
- usable size;
- medium/large/singleton;
- collection;
- OOM semantics;
- focused C adapter;
- upstream API subset.

Existing low-level work substantially covers these foundations. Do not rewrite
them without a failing general-path test.

## Milestone 5 — general concurrency and thread lifecycle

Milestone 5 is open until all architecture convergence Phases A through G
pass.

Required final properties:

- persistent page-bearing per-thread owners;
- pointer-centered standard allocation operations;
- page-local live remote free;
- one generic source owner-exit traversal;
- page/process-owned post-exit free;
- source-permitted reclamation;
- no forbidden temporary production scaffolding;
- deterministic and soak churn;
- unmodified applicable upstream pthread stress;
- selected crabc-libc Rust shadow;
- early performance/codegen evidence.

Historical bounded 5A/5B/5C witnesses remain evidence inputs, not production
completion statuses.

## Milestone 6 — heaps, Theaps, arenas, subprocesses

Complete all applicable:

- first-class Heap APIs;
- Theap APIs;
- arena APIs;
- managed-memory APIs;
- subprocess APIs;
- destruction semantics;
- cross-thread lifecycle and failure tests.

## Milestone 7 — options, callbacks, statistics, and modes

Complete all applicable:

- options/environment handling;
- callbacks/deferred-free APIs;
- statistics;
- visitation/walking;
- debug;
- secure;
- guarded;
- optional newer-AArch64 profile.

## Milestone 8 — full crabc-libc integration

Expand the selected shadow to:

- startup;
- constructors;
- pthread;
- cancellation;
- fork;
- errno/POSIX facade behavior;
- weak symbols;
- interposition;
- static and dynamic linking;
- DSOs;
- loader behavior;
- Rust std;
- Lua;
- selected real-program corpus.

Rust remains nondefault until this and performance qualification pass.

## Milestone 9 — performance convergence

Run:

- full C/Rust benchmark matrix;
- codegen audit;
- targeted source-faithful optimization;
- RSS/purge investigation;
- at least three qualified full reports.

All correctness ratchets remain green.

## Milestone 10 — default promotion

Promotion is a small isolated change:

- switch the default allocator feature to Rust;
- prove C mimalloc is absent from the default production dependency graph;
- prove no C allocator object or shared library is in the default artifact
  graph;
- retain exact C v3.5.0 as a test/performance oracle only;
- regenerate compatibility and performance reports;
- run every canonical command at the promotion commit.

Do not combine promotion with allocator redesign.

## Milestone 11 — stabilization

After promotion:

- remove obsolete transitional features and wrappers;
- preserve the C oracle and differential/performance lanes;
- preserve regression tests;
- simplify feature flags;
- freeze the v3.5.0 parity report;
- document the upstream-update procedure.

---

# 22. Repository and commit discipline

Commit subjects and artifact names describe source behavior, not temporary
delivery order.

Good commit subjects include:

- `test(mimalloc): reproduce initial-thread free after owner exit`
- `fix(mimalloc): dispatch free from pointer page state`
- `refactor(mimalloc): retain worker theap across local calls`
- `refactor(mimalloc): publish remote frees through page owner state`
- `refactor(mimalloc): unify thread exit under collect-abandon`
- `refactor(mimalloc): remove native client route registries`
- `test(mimalloc): run unmodified pthread stress through shadow libc`
- `perf(mimalloc): qualify aarch64 local and remote hot paths`
- `feat(libc): promote native Rust mimalloc backend`

Bad commit subjects include:

- `support another two-block route`
- `m5 update`
- `fix tests`
- `more owner exit cases`

Before each production commit:

1. identify the pinned source region;
2. identify the invariant or objective gate;
3. observe the failing scenario;
4. implement the general source behavior;
5. run focused tests;
6. run relevant model/differential tests;
7. run the state auditor;
8. run performance smoke when the hot path changes;
9. update machine-readable status;
10. commit with a clean worktree.

Do not weaken a test in the same commit as a production fix unless the commit
is explicitly correcting the test contract with pinned-oracle evidence.

Do not commit ephemeral multi-page progress narratives. Durable state belongs
in concise status, design docs, manifests, tests, reports, and history.

---

# 23. Final evidence report

The final report must contain:

- starting and ending crabc commits;
- exact upstream tag, commit, archive hash, and license;
- production dependency graph;
- proof that C mimalloc is absent from default production artifacts;
- source-map coverage;
- applicable API/mode status counts;
- upstream-test results and adaptation classifications;
- differential traces and seeds;
- Miri results;
- Loom results;
- lifecycle integration results;
- stress counts, seeds, watchdogs, and state high-water;
- fault-injection coverage;
- pthread/TLS/cancellation/fork results;
- ABI, weak-symbol, interposition, static/dynamic, DSO, and loader results;
- real-program corpus results;
- performance-host qualification;
- throughput and latency statistics;
- RSS/PSS/peak memory;
- syscall and page-fault measurements;
- code/data/final binary size;
- AArch64 codegen findings;
- deliberate differences;
- inapplicable upstream features;
- default-promotion decision.

Every success claim names the proving command and report artifact.

---

# 24. Final definition of done

The instruction to finish native mimalloc is complete only when all of the
following are true at one commit.

## Architecture

- each thread retains a persistent source-shaped TLD/Theap;
- steady-state local allocation/free/realloc uses no process-global scheduler;
- no per-call engine park/resume remains;
- no per-live-allocation side ledger remains;
- `free`, usable-size, and realloc derive ownership from pointer/page state;
- live remote free is page-local and independent of owner-registry size;
- one generic source-shaped owner-exit coordinator handles mixed Theaps;
- exited threads release their TLD/Theap after safe abandonment;
- post-exit free/reclaim uses page/process abandonment state;
- no exact-client post-exit registry remains;
- no test-geometry top-level production route remains unless it maps to a
  genuinely distinct upstream branch.

## Correctness

- the initial-thread-after-worker-exit reproducer passes;
- all standard allocator ABI tests pass;
- local, remote, owner-exit, post-exit, reclaim, and final-release tests pass;
- cleanup-handler, TSD, return, pthread_exit, and cancellation tests pass;
- fork tests pass under the final crabc guarantee;
- fault-injection failures retain one owner;
- state auditor is clean;
- no old TLD/Theap is accessed after teardown;
- no valid operation returns unavailable because of temporary contention.

## Stress

- unmodified applicable upstream stress passes with 1, 2, 4, and 8 workers;
- large-object mode passes where claimed;
- deterministic bounded stress passes;
- soak passes;
- no deadlock;
- no lost/double-consumed block;
- no unbounded metadata, PageMap, arena, abandoned-page, or owner growth;
- state plateaus after warmup.

## Parity and integration

- all applicable v3.5.0 APIs and modes are explicitly classified;
- all required applicable items are implemented and verified;
- the full selected Rust shadow matrix passes;
- startup, pthread, fork, loader, weak-symbol, interposition, static/dynamic,
  DSO, Rust std, Lua, and corpus gates pass;
- no hidden C fallback exists.

## Performance

- early architecture ratchets are satisfied;
- final native AArch64 performance bands pass;
- memory bands pass;
- no unexplained syscall/page-fault amplification remains;
- AArch64 hot-path codegen is audited;
- at least three qualified full reports agree.

## Promotion

- the Rust allocator is the default crabc allocator;
- `libmimalloc-sys` and C mimalloc are absent from the default production
  dependency and artifact graph;
- the pinned C implementation remains only as an oracle;
- every canonical command passes at the promotion commit;
- compatibility and performance reports are regenerated;
- the repository is clean.

A clean Rust allocator that remains nondefault because a gate is missing is
preferable to an unjustified promotion. But the goal instruction does not end
there: continue until the missing gate is actually closed.

---

# 25. Historical audited checkpoint

The original execution sequence above is historical orientation, not the live
backlog. Do not infer that its numbered actions or its old `main-wip` commit
are complete. The live ledger below supersedes it for native mimalloc.

---

# 26. Native-mimalloc live ledger

This is the current native-mimalloc progress record. It is deliberately concise
rather than a commit log: `compat/allocator/port-map.toml` remains the
machine-readable per-source status and generated reports remain the only
runtime evidence. `STATUS.md` is repository-wide status and does not close or
advance this AArch64 allocator ledger.

## Milestone closure

| Milestone | Status | Evidence and remaining closure condition |
| --- | --- | --- |
| M0 — pin, scope, inventory, skeleton | complete (inventory/skeleton; revalidated) | `crabc-mimalloc/UPSTREAM.md` fixes v3.5.0, its revision, archive hash, and MIT provenance; `crabc-mimalloc` is `#![no_std]`; `compat/allocator/api-v3.5.0.json`, `compat/allocator/port-map.toml`, and `compat/allocator/run.py` provide the inventory, source map, C oracle, layout baseline, and canonical harness. Its latest recorded clean detached native `./scripts/dev.sh allocator --quick` exit 0 is at `bdbcfc7173a7262ee12d4152a8c7c608a51bc086`. This is inventory/skeleton completion only, not engine parity. |
| M1 — pure foundations | complete (6/6 bounded components; revalidated) | `configuration-and-arithmetic`, `atomics-locks-once-and-bootstrap`, `provenance-and-represented-layouts`, `random-image`, `linux-raw-primitives`, and `compiler-tls-roots` have no remaining condition in `compat/allocator/m1-foundations-v3.5.0.json`. Its latest recorded clean detached native revalidation, at `bdbcfc7173a7262ee12d4152a8c7c608a51bc086`, exited 0 with all six components complete, no unmet IDs, and 45 executed records. The compiler-TLS evidence is its selected 32-field image and the 40-field normal-artifact C/Rust same-TLD `D`/`A` terminal trace. These are bounded component claims, not whole-`src/init.c`, `types.h`, `prim.h`, `prim-tls.h`, or `internal.h` completion, and not outer `_mi_thread_done`, page-bearing lifecycle, production deferred/retired prepasses, or allocator integration. |
| M2 — memory substrate | partial (current executable gate) | `compat/allocator/m2-memory-substrate-v3.5.0.json` fixes eight categories. Its current 53-check checked-in shape and exact boundaries appear below. At `bdbcfc7173a7262ee12d4152a8c7c608a51bc086`, clean detached native `./scripts/dev.sh allocator --quick` and `./scripts/dev.sh allocator-m1` exited 0, while `./scripts/dev.sh allocator-m2` executed that exact revision's 47-check shape and exited 3 as defined because exactly seven components remained unmet: `vm-primitives`, `metadata`, `bitmaps`, `arenas`, `initialization`, `fault-injection`, and `allocator-recursion`. That historical run comprised twelve VM primitives, eleven metadata, four bitmap checks, ten PageMap, three arenas, three initialization, one native protect/unprotect fault-injection regression, and three allocator-recursion regressions. The six later 53-check additions require a fresh clean detached full-gate run; PageMap remains the sole complete component and the selected boundaries do not close the other seven categories. |
| M3 — single-thread allocation | not active (historical partial evidence only) | The direct-engine allocator covers selected queues, page classes, retirement, and traces, but Heap/Theap, page, and queue units remain partial. The pinned image has no Miri. A forced `cfg(miri)` smoke is currently unavailable because `os_host_model.rs` lacks the existing NUMA/identity/entropy and `Mapping::page_size` APIs its callers require; the same ten compile errors existed at `265c49ddc21e614dfe055e1bc794e73a3ecf6f1e`. This is not M2 evidence or a reason to advance past the still-partial M2 gate. |
| M4 — fundamental operations | bounded direct-engine evidence | A reviewed private M4 C adapter selects 33 tests and explicitly omits 21, but no clean-current-commit native adapter report exists; it runs only in the `allocator --full`/`--churn` lanes. It is a one-thread private adapter over the still-partial M1–M3 substrate, not a closed production/general milestone. |
| M5 — concurrency and lifecycle | open | `m5.base`, `m5.5a`, `m5.5b`, and `m5.5c` are bounded/direct evidence only. `m5.5d` and `m5.5e` are blocked; all Phase A–G acceptance conditions remain required. |
| M6–M7 | not started | Blocked behind the allocator foundations and M5. |
| M8 | partial, nondefault shadow only | The selected Rust shadow exists; it is not full libc integration. |
| M9 | not started | No qualified AArch64 performance closure. |
| M10 | blocked | C mimalloc remains the default production backend. |
| M11 | not started | Follows promotion. |

A checked-in contract records the current boundary; only its clean-current-commit
report is current runtime evidence. Evidence from an ancestor is historical
supporting evidence, not a pass for a later checkpoint, though it remains the
closure record for the exact contract and revision it attests.

For M2 specifically, the table's `b09b1fd9` 42-check report is historical.
At `bdbcfc7173a7262ee12d4152a8c7c608a51bc086`, a clean detached checkout
attested the then-current 47-check M2 contract: `allocator --quick` exited 0,
`allocator-m1` exited 0 with all six components complete, and `allocator-m2`
exited 3 as its partial contract requires. Its source was clean before and
after, and unchanged during, execution; it recorded exactly twelve
VM-primitives, eleven metadata, four bitmap, ten PageMap, three arena, three
initialization, one fault-injection, and three allocator-recursion checks, and
exactly the seven unmet IDs named in the table. That is current runtime
evidence for `bdbcfc71` only, not for later code. The checked-in contract now
contains 53 selected checks: thirteen VM-primitives, eleven metadata, eight
bitmap checks, ten PageMap, three arenas, four initialization, one
fault-injection, and three allocator-recursion checks. The six additions are
the selected Linux reuse no-op, ordinary bitmap highest-set and popcount
observers, two binned highest-clear witnesses, and canonical static main-Heap
identity publication. Their focused native tests have passed, but a fresh clean
detached full M2 run is still required before this 53-check shape becomes
current runtime evidence.

## M1 closure evidence

`compat/allocator/m1-foundations-v3.5.0.json` records M1 as `complete`: each
of its six named components is complete with no remaining condition, and the
compiler-TLS component requires both independent C/Rust records. The existing
32-field record covers the constructor-suppressed root image, positive
regular-slot reset, and local cached-reference pair. The distinct 40-field
record direct-includes the pinned `src/init.c` into a normal C artifact and
compares the file-static `mi_thread_theaps_done` body with the test-only Rust
same-TLD composite. Its C setup and `_Exit` deliberately exclude outer
`_mi_thread_done`, regular-backing/fast cleanup, statistics, TLD free, process
hooks, page-bearing collection, and public Heap lifecycle; Rust performs its
metadata/key/backing cleanup only after the compared trace. Its page-free
queue-half witness checks the generic coordinator's empty branch and only the
deferred-free → retired-page prepass order; it does not execute those
production prepass algorithms.

M1 closed at `38d0a51fda55f61e4a5985eee0afc90a9211b49f` with a clean native
`./scripts/dev.sh allocator-m1` exit 0 and that revision's
`m1-foundations-latest.json` report. A partial contract or a dirty source makes
exit 3 or a hard failure, respectively; neither is closure. That report is
historical support at a later revision and must be rerun from a clean target
checkout before it can be called current runtime evidence there. The
`fec84761e9fbdb29c32d8f492ca6c9cfa08a015b` report remains historical support
for its older partial contract only. Deferred lifecycle and whole-unit
exclusions remain nonclaims, not implicit M1 coverage.

The M1 gate was rerun from a clean detached native checkout at
`33e9fc801935c02ac30bc50c82674ece93ebca95`: it exited 0 and produced that
checkout's `m1-foundations-latest.json` with all six components complete and
no unmet component IDs. Thus M1 was current evidence for the allocator source
revision that introduced the M2 cold-init record; it remains only the bounded
six-component milestone described above.

The M1 gate was rerun again from a clean detached native checkout at
`265c49ddc21e614dfe055e1bc794e73a3ecf6f1e`: it exited 0 and produced that
checkout's `m1-foundations-latest.json` with all six components complete and
no unmet component IDs. That report is an earlier recorded M1 revalidation;
M1 remains only the bounded six-component milestone described
above.

The M1 gate was rerun once more from a clean detached native checkout at
`2b289b1f8ae10543dfc57ddda0b49b08789be400`: it exited 0 and its
`m1-foundations-latest.json` attests the source was clean before and after
execution, with all six bounded components complete and no unmet component
IDs. This was the recorded revalidation after the detached first-head
random/cookie M2 slice; it does not broaden M1 beyond its six-component
contract.

The M1 gate was rerun again from a clean detached native checkout at
`ffaea4a9a2a3304dad0ff57ed081cc96e3b29978`: it exited 0 and its
`m1-foundations-latest.json` attests the source was clean before and after
execution, with all six bounded components complete and no unmet component
IDs. This makes M1 current evidence for the detached-Theap identity-admission
M2 slice, without broadening M1 beyond its six-component contract.

The M1 gate was rerun again from a clean detached native checkout at
`d965a6699bd65f92f98d96a665eac9ecf60e60f0`: it exited 0 and its
`m1-foundations-latest.json` attests the source was clean before and after
execution, unchanged during the run, with all six bounded components complete
and no unmet component IDs. A separate clean detached
`./scripts/dev.sh allocator --quick` run at that same revision also exited 0.
Those are revalidations of the bounded M0/M1 contracts at that revision only;
they do not broaden either milestone into allocator-engine or lifecycle
completion.

The M1 gate was rerun again from a clean detached native checkout at
`9136162edf724287b64b381125ae4b01671e52bb`: it exited 0 and its
`m1-foundations-latest.json` attests the source was clean before and after
execution, unchanged during the run, with all six bounded components complete
and no unmet component IDs. A separate clean detached
`./scripts/dev.sh allocator --quick` run at that same revision also exited 0.
Those were then-current revalidations of the bounded M0/M1 contracts only; they
do not broaden either milestone into allocator-engine or lifecycle completion.

The M1 gate was rerun again from a clean detached native checkout at
`04e6f49c233c8d3d14d45a5299c54e255ad28917`: it exited 0 with all six bounded
components complete, no unmet component IDs, and 45 executed records. A
separate clean detached `./scripts/dev.sh allocator --quick` run at that same
revision also exited 0. Those were then-current historical revalidations of the bounded
M0/M1 contracts only; they do not broaden either milestone into
allocator-engine or lifecycle completion.

The M1 gate was rerun again from a clean detached native checkout at
`03264676bddff8fdf94cd2ba3d9103124c9c200c`: it exited 0 with all six bounded
components complete, no unmet component IDs, and 45 executed records. Its
report attests the source was clean before and after execution and unchanged
during the run. A separate clean detached `./scripts/dev.sh allocator --quick`
run at that same revision also exited 0. Those were then-current historical
revalidations of the bounded M0/M1 contracts only; they do not broaden either
milestone into allocator-engine or lifecycle completion.

The M1 gate was rerun again from a clean detached native checkout at
`5a2708d5c1e6b463c5eade8f60afa75d6131818a`: it exited 0 with all six bounded
components complete, no unmet component IDs, and 45 executed records. Its
report attests the source was clean before and after execution and unchanged
during the run. A separate clean detached `./scripts/dev.sh allocator --quick`
run at that same revision also exited 0. These are then-current historical revalidations of
the bounded M0/M1 contracts only; they do not broaden either milestone into
allocator-engine or lifecycle completion.

## M2 current partial gate

`compat/allocator/m2-memory-substrate-v3.5.0.json` is the current M2
contract. It names all eight closure categories in the milestone definition,
requires every partial category to state its remaining conditions, and keeps
later allocation and public-backend work as explicit exclusions. Its selected
PageMap check builds a source-private pinned-C producer that directly includes
`src/os.c`, `src/page-map.c`, and `src/init.c`, without duplicate normal-source
objects. It disables `mi_option_pagemap_commit`, fixes `max_vabits` to 48, and
requires a native 4-KiB page size. The C and Rust records compare the 23 stable
control and transition fields for initial partial commitment, lazy extension
across two submaps, one two-slice unregister, final-boundary rollback, and an
absent root after destruction.

The checked-in working set contains 53 native checks: thirteen VM-primitives
checks, eleven metadata checks, four bitmap C/Rust differentials plus four
Rust-only bitmap-observer check records, ten PageMap checks, three arena checks, four
initialization checks, one native protect/unprotect fault-injection check, and
three allocator-recursion checks. The 37-, 38-, 39-, 40-, 41-, and 42-check
reports are historical evidence for prior contracts. The clean detached M2
run at `bdbcfc7173a7262ee12d4152a8c7c608a51bc086` executed its then-current
47-check shape, left its source clean before and after and unchanged during
execution, and exited 3 as the partial-gate contract defines. That exact
revision is therefore attested; the current 53-check shape has focused native
evidence for its six later checks and still needs a fresh clean detached
full-gate revalidation. `page-map` is complete within this M2 contract; the
other seven required components remain partial under their explicit remaining
conditions.

The new VM slice maps only fixed normal/offset non-huge allocation:
`NormalOsAllocation` retains the complete map base/length in `MemoryId::os`
while keeping a distinct client pointer, zero offset delegates to ordinary
aligned allocation normalization, committed-prefix decommit remains
best-effort, reserved prefixes do not decommit, and a failed cleanup/unmap
retains the exact owner for retry. It excludes huge pages, hints, NUMA,
options, statistics, arbitrary memory-kind dispatch, and a source runtime
caller. The new direct TLS slice restores the exact `MetaRelease::Malloc`
capability, root/count/slots, and `Active` state only after a proven pre-claim
same-thread rejection; a successful retry keeps C's free-before-root-clear
order. Generic/free post-claim failures remain terminal, and the outer
`DynamicTheapAttachment` remains terminal because it clears its binding before
calling direct backing teardown.

The selected reuse slice is narrower still. Pinned `src/os.c:643-653`
conservatively normalizes `_mi_os_reuse`; Linux
`src/prim/unix/prim.c:536-542` then returns zero without a VM operation.
`Mapping::reuse` returns `None` for no complete page and an explicit
`ReuseOutcome::NoOp` for a complete contained range, with no syscall, fault
edge, or mapping-state mutation. Its Rust input errors are checked safety
boundaries, not C error parity, and no allocator caller or Apple reuse policy
is present.

The selected bitmap observer ports only `src/bitmap.c:1383-1403`
`mi_bitmap_bsr`: it reads chunk-map/data fields Relaxed in descending order and
scans below a stale in-layout high map bit before returning a lower live bit,
without changing either image. Rust caps a final scan to initialized chunks
instead of deriving the source's assertion-invalid trailing-layout pointer.
The focused test proves only the in-layout stale-high case and map
preservation. A separate direct unit regression writes an out-of-layout high
map bit and proves the checked scan remains bounded, returns the lower live
bit, and retains that invalid map entry. Neither test is a C differential or
an allocator integration claim.

The selected ordinary popcount observer maps `src/bitmap.c:1406-1420` to
`BitmapView::popcount_relaxed`. It walks conservative chunk-map fields from
low to high with Relaxed observations, counts selected data without repairing
an in-layout stale map entry that contributes zero, and retains that map image.
The focused Rust regression also records the safety boundary for an
out-of-layout stale map entry: Rust skips its data access rather than deriving
C's layout-valid pointer. This is not a C differential, mutation, visitor, or
allocator-integration claim.

The two selected binned highest-clear witnesses map the outer
`src/bitmap.c:1616-1634` `mi_bbitmap_bsr_inv` scan and its inner
`src/bitmap.c:997-1009` chunk/field walk to
`BinnedBitmapView::highest_clear_relaxed`. One records the source-rounded top
padding; the other records descending chunk and field order. They are
read-only Rust regressions, not C differentials or evidence for binned search,
claim, flexible-array ownership, Heap/Page/Arena integration, races, or
statistics.

The selected canonical static main-Heap witness maps `src/init.c:196-198` and
the remaining `src/heap.c:102-126` initialization order. After its private
static-foundation claim, a `MainStaticHeapFoundation` reserves a pointer-free
`MainSubprocess` publication before mutating the candidate Heap image, writes
the candidate's kind-only static memid,
then Release-publishes its exact identity before the remaining selected Heap
initialization. Only after that initialization does it make an opaque ready
identity available. A stale candidate remains COLD with `MemoryKind::None`,
after a failed reservation releases the private claim, and an unfinished
publication remains non-ready. The Rust ready lookup is
comparison-only: it does not emulate C's dereference-capable
`_mi_subproc_heap_main`, grant Heap projection, prove general main-Heap
linkage, or close process initialization.

The first bitmap differential directly includes pinned `src/bitmap.c` as its
only C translation unit and compares 21 address-free facts with
`BitmapView::try_find_and_claim_abandoned`. Its static one-chunk image fixes
thread sequence five and candidate bit 17. A `KeepSet` rejection invokes one
callback and restores both the candidate and its conservative chunk-map bit; a
later accepted claim invokes one callback, clears the candidate, and leaves the
conservative map set; a final drained probe invokes no callback and repairs
that stale map bit.

The second directly includes the same pinned source file and compares 26
address-free facts with `BitmapView::visit_set_ranges_clear`, the selected
scalar port of `_mi_bitmap_forall_setc_ranges`. Its static one-chunk completed
walk emits maximal low-to-high runs without crossing a source 64-bit field and
retains the conservative map. Its stopped walk leaves the current visited range
clear, restores only the unvisited same-field residual, and leaves a later
field untouched. The trace calls the generic routine directly; it does not
execute or prove `_mi_bitmap_forall_setc_rangesn` policy, although the pinned
source's `<= 1` delegation makes this generic routine the frozen default-purge
implementation. Those first two bitmap differentials do not claim the C
`keep_set = false` rejection route, multi-chunk or sequence distribution, actual
arena/subprocess ownership, races, `clear_once_set`, other visitor families,
statistics, binned bitmaps, flexible-array allocation ownership, or allocator
integration.

The third directly includes the same pinned source file and compares 52
address-free facts with `BitmapView::visit_set_ranges_clear_aligned`, the selected
scalar port of `_mi_bitmap_forall_setc_rangesn`. Fresh `rngslices == 3` images
cover aligned completed windows, incomplete-window/top-suffix restoration, and
a stopped callback that restores a prior skipped window plus later snapshot
bits; fresh zero and one calls cover generic delegation, and 65 covers the cap
at 64. It does not execute `_mi_os_minimal_purge_size`, transparent-huge-page
policy, or an arena caller.

The fourth directly includes pinned `src/bitmap.c` and compares 30
address-free facts with `BitmapView::visit_set_bits`, the selected scalar port
of `_mi_bitmap_forall_set`. Fresh valid 65-chunk images span source chunk-map
fields zero and one: the completed walk emits bits 1, 65, and 32770 in source
order, while a stopped walk returns at its second callback and leaves the
selected raw data and chunk-map fields unchanged. The C fixture owns a
layout-valid 4,288-byte image; no Heap, Page, or Arena pointer, callback
mutation, binned bitmap, flexible-array ownership, arena/subprocess path,
race, statistic, or allocator integration is exercised. A Rust-only stale
out-of-layout map-bit regression separately documents the safe skip-and-retain
divergence outside the C routine's valid-layout precondition; it is source-level
safety evidence outside this selected C/Rust report.

A separate fresh C process makes only `src/page-map.c`'s first aligned PageMap
allocation fail, so the source `mi_atomic_do_once` state cannot contaminate
the success producer. Its Rust partner injects the first `FaultPoint::Map` in
`ProcessPageMapStorage`. Both records prove one failed initialization body, no
published dynamic map, and no replay. C retains `mi_page_map_empty`, keeps a
null lookup safe, and reports later `_mi_page_map_init` success after consuming
the failed body; Rust retains no fake live `PageMap`, exposes no cold lookup
route in its absent-root/poisoned state, and reports terminal typed poison.
Those values are a recorded, intentionally accepted bounded PageMap safety
divergence, not exact-equality or full-initialization claims. The pinned C
sentinel makes only its null lookup safe after the failed once body; it is not
a valid dynamic map or safe registration/mutation continuation. Rust must not
fabricate a `PageMap` or successful process continuation from that state: the
source-order coordinator has already prepared its Heap and detached metadata.
`process_init::tests::rejected_page_map_after_heap_and_metadata_retains_ticket_zero_without_tls_publication`
proves that the coordinator retains this terminal state without publishing
ticket-zero roots or admitting a later generic thread. A future public C ABI
or complete process lifecycle that needs cold `free(NULL)` semantics must
reopen this boundary with a distinct lookup-only cold-sentinel owner and
lifecycle evidence.

The selected Rust PageMap now carries a paired initial-commit/cleanup failure
through `PageMapInitializationError::Retained` rather than dropping its
non-RAII `Mapping`. `ProcessPageMapStorage` stores that exact unpublished
owner before terminal poison; `MetaAllocator` has a separate final slot for
the same failure before it publishes `FAILED`. The process-owner regressions
cover both the initial top-level and trailing-submap commit branches, and the
metadata regression proves the independent metadata caller cannot collapse a
retained mapping into a scalar error. They explicitly release the retained
owner after disabling the injected fault.

Four additional direct Rust PageMap regressions cover the reachable lazy and
destruction failure matrix: a failed top-level extension commit leaves the
same top-level `Mapping` usable; a failed lazy submap map leaves the same
PageMap usable; a failed lazy-submap reclaim leaves its exact raw slot
published; and a failed final top-level `unmap` leaves its exact `Mapping`
usable. Each test disables the fault and proves the corresponding retry. The
source-shaped CAS loser remains outside that fault matrix because
`PageMapHeader::submaps` and its atomic view are module-private and every
current Rust publisher holds the same PageMap private lock and rechecks the
slot; the M2 concurrent-publication check observes one allocated/published
candidate across four contenders. A future competing writer must retain a
losing candidate before it can make that branch reachable. The C release calls
are void/best-effort, so this is Rust ownership-safety evidence, not a C
retry-parity claim. Together with the explicit cold-root safety decision
above, these checks close the selected M2 PageMap component. They do not close
general process lifecycle, public C ABI behavior, concurrent map lifetime, or
allocator integration.

The selected VM-primitives evidence is deliberately narrower than M2 closure.
`Mapping::map_aligned_for_allocator` now preserves an exact non-RAII owner
through each native cleanup edge: a failed direct-candidate unmap retains that
direct map, a failed prefix trim retains the full overmap, and a failed suffix
trim retains the already prefix-trimmed aligned range plus its live suffix.
`AlignedMappingFailure` transfers that owner to the caller. `OsAlignedPageClaim`
retains it as a claim, `MetaAllocator` stores it beside its already-private
PageMap before terminal failure, and `ProcessSharedArenaStorage` stores it in
its final sidecar before terminal retention. The test adapter additionally
uses `TestContextInitFailure` to retain an unpublished PageMap together with a
failed aligned arena map until reverse-order cleanup succeeds. PageMap itself
uses the direct primitive because its requested alignment is exactly Linux's
base-page mmap guarantee, so no aligned-overmap cleanup owner can arise there.

The M2 manifest selects four direct `os` tests plus the `os_page`, `meta`, and
`process_arena` propagation tests. They use a native-only forcing seam solely
to make direct, prefix, and suffix cleanup deterministic; production retains
the pinned `length + alignment` overmap request. Pinned C's partial frees are
void/best-effort, so retaining the typed Rust owner is a safety strengthening,
not retry-parity or complete aligned-allocation evidence. Reserve, commit,
decommit, purge, protect, reuse, huge-page, hint, NUMA, remaining overmap
policy, and the wider failure matrix still keep VM primitives partial.

The selected native fault-injection evidence is equally narrow. Pinned
`src/prim/unix/prim.c:600-604` supplies `_mi_prim_protect`, and
`src/os.c:690-712` routes `_mi_os_protect`/`_mi_os_unprotect` through
`mi_os_protectx`. The one-page committed-mapping regression injects one
test-only pre-syscall `NOMEM` at each Rust transition. It checks the exact
mapping base and length after each failure; volatile access proves that failed
protect left the page writable, while the failed-unprotect route deliberately
does not dereference until retry. With injection disabled, each route succeeds,
restores access where needed, and unmaps once. This does not observe a live
kernel error, compare C diagnostics or failure behavior, prove state after
failed unprotect, or cover range policy, allocator callers, decommit/commit/
purge, PageMap, arena, metadata, bitmap, release, signals, or races.

The selected `arenas` evidence is deliberately narrower than arena closure.
With the frozen default `minslices == 1`, its unpinned external-arena fixture
holds the legal `[9, 63)` prefix, releases `[63, 65)`, and forces collection.
Pinned `mi_arena_try_purge` reaches `_mi_bitmap_forall_setc_ranges` through
`_mi_bitmap_forall_setc_rangesn`'s `minslices <= 1` delegation. Rust now
reaches that selected scalar source boundary through
`BitmapView::visit_set_ranges_clear`, whose separate bitmap differential proves
its one-chunk completed/stopped semantics. The boundary-spanning arena run
invokes the decommit hook twice, once for each source 64-bit bitmap field, while
the Rust test proves the free bits are restored and the purge bits cleared. This
still proves only default one-slice delayed-purge callback grouping;
configurable purge policy, multi-chunk traversal, other visitor families,
registry-wide collection, concurrent arenas, and arena lifecycle remain
unclaimed. Thus `arenas` and M2 remain partial.

The second selected arena test fixes the frozen Linux default error transition,
not a retry policy. After a valid unpinned page release, it injects the one
`MADV_DONTNEED` failure and forces collection. Pinned `src/prim/unix/prim.c`
still writes `needs_recommit = false` in this normal profile, while
`src/os.c:_mi_os_purge_ex` reports that outcome after its decommit helper
reports an error. Therefore the source keeps `slices_committed` set, restores
`slices_free`, leaves `slices_purge` and the arena-local expiry clear, and
continues collection. The Rust regression proves exactly those facts and that
the external mapping remains owned by its caller. It does not claim general
purge fault parity or error-reporting policy.

The third selected arena test is a sequential partial-reclaim fallback, not a
live allocation/purge race. It schedules the two-slice `[9, 11)` range, then
reclaims `[9, 10)` before forced collection. The source-shaped whole
`slices_free` claim therefore fails; the allocation-won low slice remains
unavailable and does not call the decommit hook, while the high free sibling is
individually claimed, calls that hook exactly once, and is restored to free.
The source-cleared purge bits for both slices remain clear. This does not claim
arbitrary spans or visitor outcomes, configurable/minimal/THP purge policy,
multi-chunk, registry-wide, or multi-arena collection, concurrency, lifecycle
closure, fault/retry behavior, or a C/Rust differential.

The manifest additionally selects
`os::tests::reset_retries_the_initial_advice_after_a_concurrent_global_fallback`.
Pinned `src/prim/unix/prim.c:_mi_prim_reset` takes one Relaxed snapshot of its
process-wide advice before it retries `EAGAIN`; another caller's Release store
from `MADV_FREE` to `MADV_DONTNEED` must not change the in-flight retry. The
regression uses a local atomic advisory mock to make that interleaving
deterministic: the old Rust implementation requested `MADV_FREE` then
`MADV_DONTNEED`, while the source-shaped implementation requests `MADV_FREE`
twice and leaves the shared cache changed for later callers. It proves only
that private control-flow rule, not a kernel `EAGAIN` schedule or complete
purge fault parity.

The record deliberately does not equate source representations that are not
the same: the pinned C header contains the Linux/musl `pthread_mutex_t`, while
the `#![no_std]` Rust header contains `PrivateLock`; its header-dependent
entry counts are retained on both sides of the report. Likewise, C destroys a
live global root and then restores its static empty root, whereas a Rust
`PageMapRoot` is a separate owner and must be unpublished before
`PageMap::destroy`. The report makes both facts explicit. This is selected
success-path plus one cold-init-failure differential, not C/Rust equality for
their cold-root policy, VM failure, full PageMap lifetime, or the remaining
VM, metadata, bitmap, arena, initialization, fault, and recursion closure
conditions.

The metadata witness is deliberately smaller still. `MetaRelease::Malloc`
carries one exact detached `MetaAllocation` and retrieves that capability's
recorded owner internally. Its selected typed boundary enters Rust's backing
lock and same-thread marker before changing LIVE to RELEASING, so only an
invalid entry thread, same-thread recursion, or backing-lock acquisition
failure can return the unchanged exact capability as `MallocRetryable`.
Stale/provenance rejection and every post-claim local-free error remain
`MallocTerminal`; the general `MetaAllocator::free` lifecycle route remains
terminal-on-error for admitted owners. This is a narrow Rust ownership rule,
not C free or mutex equivalence. `MetaRelease::RegularOs` carries only one
normal anonymous `Mapping` and returns it after a failed `munmap` for explicit
retry, but it is a synthetic standalone retry witness, not a C metadata
caller: pinned `_mi_meta_zalloc` forms Malloc IDs, while a real direct-OS
`_mi_arenas_free` owner needs the wider memory-ID/subprocess contract. A
no-free source branch carries no release token. `MetaRelease` deliberately
remains only `Malloc` and `RegularOs`; its separate typed
`ArenaSliceClaim::release_for_subprocess` boundary carries one live arena claim
and checks the selected `MainSubprocess` identity before Rust's
purge/free-bitmap transition. Huge, remap, sanitizer-tracking, integration,
and allocator-recursion coverage remain M2 conditions.

The selected later-TLD direct-Malloc check connects that exact Malloc lifetime
to one real caller without broadening the metadata route: ticket-zero static
storage tears down with no `MetaAllocation`; one injected post-ready
direct-zeroed later request consumes its source sequence without a capability
or live-count lease; and its sequence-two retry is a typed
subprocess-attached/no-theap Malloc TLD whose teardown returns the capability
count to zero while retaining high-water one. It is not normal C
`_mi_meta_zalloc` backing parity, generic `_mi_meta_free` dispatch, complete
`mi_tld_init`/`mi_tld_free` list or lock behavior, or arbitrary-thread/ticket
coverage.

The selected nonexclusive dynamic-Theap check follows one child thread after
ticket zero through a caller-pinned empty Heap with no exclusive arena. It
observes a sequence-one Malloc TLD and Malloc Theap in the selected one-member
TLD/Heap list shape, plus four attached metadata capabilities: TLD, Theap,
regular backing, and the distinct process-owned registry bitmap. The
implementation's no-page path releases regular backing, then the exact Theap,
then the TLD; the audit observes the three attachment-local capabilities gone
and the registry bitmap remaining, which test-only quiescent shutdown releases.
The paired injected-Theap-allocation failure occurs after TLD and registry
creation but before an allocated regular-backing metadata capability, consumes
its ticket without a live count, and retains only the immutable empty dynamic
root plus the registry bitmap in the metadata audit. Two separate selected
requested-parent records cover the exclusive-arena path:
`requested-parent-theap-one-slice-arena-reservation` is only the pre-init
allocation/provenance reservation, and
`requested-parent-arena-theap-prefix-lifecycle` is the synthetic no-page
Arena-prefix lifecycle described below. This nonexclusive check does
not establish normal C `_mi_meta_zalloc` backing, a complete exclusive-arena
Theap lifecycle, generic `_mi_meta_free`, general list/refcount policy, page
ownership, concurrency, or process/thread shutdown parity.

The `threadlocal-live-rezalloc-malloc-capability-lifetime` metadata record
narrows the live regular-TLS replacement branch in
`src/threadlocal.c:103-162,205-214` and `src/subproc.c:49-81`. It begins only
after the existing fresh 16-slot Rust image in one child thread with the
selected main-subprocess identity. An injected pre-allocation failure after
Rust's moving claim restores the exact old Malloc root, count, slot 15, null
slot 16, and capability; one 16-to-32 retry copies slot 15, publishes slot 16,
has one live capability with high-water two, and tears down to zero. This is
the Rust ownership equivalent of C's null replacement result, not production
fault policy. It does not compare C's initial count-zero
`_mi_meta_rezalloc(NULL, ...)` route with Rust's separate fresh zalloc image,
or establish arbitrary growth, normal C metadata backing, generic
`_mi_meta_free`, complete TLS/TLD/Theap/registry lifecycle, concurrency,
pthread/process lifecycle, or ABI integration.

The `meta-cold-demand-requires-prepared-theap-publication` metadata record
narrows only the source precondition at
`src/init.c:184-205` and `src/subproc.c:29-70`. While the Rust owner is COLD,
direct `zalloc`, aligned `zalloc`, and `rezalloc(None)` each return
`TheapMetaUnpublished` before either metadata lock, consuming a map fault,
or creating a capability. `prepare_for_main_subprocess` first forms the
selected static detached image, then one-way Release-CAS publishes its exact
pinned Theap identity through the selected `MainSubprocess` before BOUND; it
does not consume the pending backing fault. The first prepared demand may
consume that fault and return to BOUND, and a later prepared retry succeeds.
This is only a Rust safety strengthening of C's non-null assertion: it does
not provide the actual `mi_subproc_t::theap_meta` field/layout,
C pthread-lock semantics, other `theap_meta_lock` users or lifecycle, pointer
dereference through the subprocess, general or dereference-capable main-Heap
linkage beyond the selected opaque comparison identity, normal
`_mi_meta_zalloc` backing, or complete process initialization.

The `bound-subprocess-metadata-page-identity-query` metadata record maps only
`src/subproc.c:84-88` (`_mi_meta_is_meta_page`). `None` represents C's null
page pointer; a caller-readable `Page` with a null or foreign `theap` field is
false, and only the exact published bound-subprocess identity is true. The
focused test keeps two subprocesses BOUND with no private PageMap backing or
detached session, holds one selected metadata entry while querying, and proves
the query leaves entry attempts, map state, and allocation audit unchanged.
Rust's Release/Acquire identity slot is a safety representation, not C field
layout or memory-order parity. The query neither takes nor proves the separate
selected direct-allocation lock. This has no C/Rust differential claim and does
not provide byte-for-byte `mi_subproc_t`, C pthread-lock semantics, the
remaining `theap_meta_lock` users or lifecycle, a general Theap or
page-lifetime/abandonment API, normal `_mi_meta_zalloc` backing, generic free,
subprocess lifecycle, race proof, C ABI, or allocator integration.

The `bound-subprocess-theap-meta-lock-direct-allocation-phase` metadata record
maps `src/subproc.c:29-70`, the field context at
`include/mimalloc/types.h:667-668`, and the selected source pthread-lock
representation at `include/mimalloc/atomic.h:446-472`. After the existing
identity preflight, `MetaAllocator::enter_for_main_subprocess` takes
`MainSubprocess::lock_metadata_theap` inside Rust's backing lock and same-thread
marker for direct `zalloc`, aligned `zalloc`, and the replacement-allocation
phase of `rezalloc`. `MetaEntry::drop` releases that nested source-shaped guard
before rezalloc copy/free. Pinned `_mi_meta_free`'s `MI_MEM_MALLOC` branch
calls `mi_free` without `theap_meta_lock`; Rust keeps selected exact-owner free
on its separate backing lock. The focused test holds the selected subprocess
lock before first direct demand, observes BOUND with no private backing or
capability until release, and also covers aligned allocation and rezalloc copy
preservation. This is not C byte-layout or pthread-lock parity, other lock
users or lifecycle (including `src/free.c:744-778`, `src/init.c:524-530`, and
`src/subproc.c:141-148,249-251`), a general concurrency proof, normal C
metadata backing, or complete metadata/process initialization parity.

The separately selected
`metadata-same-thread-free-reentry-before-capability-mutation` recursion
record maps only `_mi_meta_free`'s `MI_MEM_MALLOC` branch. Its focused test
holds Rust's backing entry, proves `MetaRelease::Malloc` returns the exact live
pointer, `MemoryId`, and audit as `MallocRetryable` before LIVE-to-RELEASING,
then releases the same value after the entry drops. It deliberately does not
make general `MetaAllocator::free` retryable or claim C lock/deadlock,
callback/signal, cross-thread, other release/copy, backing, lifecycle, or
allocator-integration parity.

The `arena-release-subprocess-identity-gate` metadata record is deliberately a
separate typed arena-release witness, not a `MetaRelease::Arena` variant or a
generic `_mi_meta_free` dispatcher. It selects the `MI_MEM_ARENA` identity assertion in
`_mi_arenas_free`, reachable from the pinned non-Malloc metadata route. Its
one-slice unpinned fixture gives the arena one bounded `MainSubprocess`: a
foreign identity gets the exact unchanged live claim back while the free
bitmap, purge bitmap, and purge expiry remain unchanged; the matching identity
consumes the claim through the existing terminal free-bit result, and a fresh
claim proves the slice is reusable. Rust turns C's internal assertion into a
fail-closed safe refusal. This is source-level safety evidence, not C/Rust
invalid-input parity, normal C metadata-backing parity, generic dispatch,
general purge policy, full registry/subprocess lifetime, no-free/OS/huge/remap
coverage, retry behavior after a false terminal result, races, statistics, or
allocator integration.

The `requested-parent-theap-one-slice-arena-reservation` metadata record maps
only the first requested-parent allocation pass of `src/theap.c:_mi_theap_alloc`.
It treats an already-published direct parent as a caller-selected
`heap->exclusive_arena` value without binding or
inspecting a Heap, passes one caller-supplied `ThreadSequence` value, claims
one committed `MI_ARENA_MIN_OBJ_SIZE` slice, retains its `MI_MEM_ARENA`
`MemoryId`, rejects a foreign bounded `MainSubprocess` before bitmap mutation,
proves that exhaustion does not use the unrelated arena or an OS fallback, and
uses the selected release gate before exact dirty-bit reuse. The C-only `LAYOUT_PROBE`
asserts `sizeof(mi_theap_t) <= MI_ARENA_MIN_OBJ_SIZE`; Rust intentionally
makes no Theap storage/prefix or Rust/C size-equality claim. That C assertion
is companion `allocator --quick` baseline evidence, not a C compile performed
by the focused M2 Rust test. The selected reservation does not model the
nonnegative-NUMA second requested-parent pass, option gates, pinned-acceptance
evidence, an `_mi_os_reuse` caller or integration, debug/tool memory-tracking instrumentation including
`MI_DEBUG > 1` zero validation, a Heap/TLD/thread assertion, `theap->memid`,
`_mi_theap_init`/`_mi_theap_create`, list/TLS/refcount/free lifecycle,
`MetaAllocation`, `MetaRelease::Arena`, generic `_mi_meta_free`, diagnostics,
statistics, races, or allocator
integration. Its foreign refusal is a Rust
fail-closed safety boundary, not invalid-input C parity.

The `requested-parent-arena-theap-prefix-lifecycle` metadata record is a
synthetic bounded subcall, not
`mi_heap_init_theap` or complete `_mi_theap_create` parity. It starts only
after an already-live static default TLD `D` and a fresh caller-pinned Heap
with one direct selected parent are supplied. That parent produces one exact
committed Arena slice for auxiliary Rust-Theap prefix `A`; `A` retains its
`MI_MEM_ARENA` `MemoryId`, is initialized only through the Rust prefix's
`memid` boundary, links before `D` on the TLD and as the caller Heap's sole
member, splits `D`'s random image, and uses the selected Release heap
publication. An unbound caller Heap is rejected before prefix materialization
and its exact reservation can be returned. A successful lifecycle returns the
selected slice, and a dirty second lifecycle reuses that exact slice.

Its page-free teardown composes only the selected heap-delete topology: remove
`A` from the `A → D` TLD list, then remove it from its sole Heap list, then
Rust Release-clears `A.heap` before the final `1 → 0` prefix transition,
typed-prefix drop, and selected-slice release. It deliberately omits C thread
initialization, the regular TLS get/null decision and slot store, cached-root
behavior, retry/yield contention, normal heap/subprocess list and counter
ownership, C subprocess Theap statistics increment/decrement/merge, the
complete C Theap layout/statistics tail, generic `_mi_meta_free` or
`MetaRelease::Arena` dispatch, pages, process/thread shutdown, option/NUMA
second pass, normal metadata backing, faults, races, and allocator
integration. This is therefore a source-mapped prefix-owner witness, not a
complete requested-parent Theap lifecycle.

The two detached-metadata initialization witnesses observe the image before it
can issue a session or acquire private backing. For only the bounded
same-subprocess, empty-head, non-threadpool input, the first observes kind-only
`_mi_memid_create(MI_MEM_STATIC)` provenance (zero union and flags), the frozen
normal `page_reclaim_on_free = 0` result (`allow_page_reclaim = true`), an
initialized possibly-weak random image, and an odd cookie. Its mapped source
order writes that random/cookie state before Release heap publication. The
second witness proves a nonempty head, mismatched subprocess, or thread-pool
input leaves the candidate static image untouched rather than pretending to
model C's locked list/split or option-adjustment paths. These witnesses do not
claim the rest of `_mi_theap_init`, mutable option processing, TLD/Heap list
relations or locking, guarded initialization/statistics, random-split parity,
general or dereference-capable main-Heap linkage beyond the selected opaque
comparison identity, `mi_subproc_t::theap_meta` field/layout, and
the C pthread-lock semantics or remaining `theap_meta_lock` users/lifecycle,
normal `_mi_meta_zalloc` backing parity, or complete process initialization.
The `meta-cold-demand-requires-prepared-theap-publication` record separately
claims only the comparison-only one-way identity-admission publication described
above. C writes the detached non-abandoning/retain special fields after `_mi_theap_init`
publication and list linking; Rust keeps its bounded final image before
publication because it does not model those lists.

Run `./scripts/dev.sh allocator-m2` from a clean native checkout to write the
current-commit `.work/reports/allocator/m2-memory-substrate-latest.json`
report. Its expected exit is 3 until all eight categories are complete; a
report with that exit documents the active gap rather than advancing M2.
At `33e9fc801935c02ac30bc50c82674ece93ebca95`, that clean native command
exited 3 after both PageMap checks passed: the success lifecycle remained
`matched`, while the cold-init check recorded three shared failure facts as
`modeled-safety-divergence`. The report retains all eight categories and the
remaining PageMap conditions as unmet.

At `0e68bcdf8255104eb982852fc3cd0602f62eaf12`, the same clean native command
again exited 3 as designed, with an unchanged source tree. Its five executed
M2 checks all passed: the metadata caller, the success and cold-init
PageMap differentials, and both initial-commit cleanup-owner branches. The
PageMap component now has exactly two remaining conditions: lazy
extension/destruction release fault evidence and the documented C
static-empty-root versus Rust typed-poison cold-root semantic gap.

At `e979923306e2c6e9ab0af724dfd0eb2b8b84af54`, the clean native command again
exited 3 as designed with an unchanged source tree. It passed the metadata
caller plus all nine PageMap checks: both differentials, both bootstrap
cleanup-owner branches, lazy commit and map retry, lazy-submap and top-level
release retry, and the four-contender private-lock publication witness. The
PageMap component has one remaining condition: the documented C
static-empty-root versus Rust typed-poison cold-root semantic gap.

At `265c49ddc21e614dfe055e1bc794e73a3ecf6f1e`, the clean native command again
exited 3 as designed with an unchanged source tree. It passed the metadata
caller plus all ten PageMap checks, adding the process-owner terminal-boundary
regression. `page-map` is now `complete` with no remaining condition. The
report's unmet component IDs are exactly `vm-primitives`, `metadata`,
`bitmaps`, `arenas`, `initialization`, `fault-injection`, and
`allocator-recursion`; M2 itself remains partial.

At `5c0c707774dc575f65d9c64191d6cf789155c1cb`, a clean detached native
checkout ran the extended M2 gate with source unchanged during execution. It
exited 3 as designed and its report executed all seven new VM checks, the
existing metadata check, and all ten PageMap checks successfully. The unmet
component IDs remained exactly `vm-primitives`, `metadata`, `bitmaps`,
`arenas`, `initialization`, `fault-injection`, and `allocator-recursion`.
Thus the aligned-overmap cleanup-owner evidence is current for that allocator
source revision, but does not alter the seven unmet M2 components or authorize
advancement to M3.

At `c07fca49ef7dd0603a59dfcc92470862e1ab27e2`, a clean detached native
checkout reran `./scripts/dev.sh allocator-m2`. Its
`m2-memory-substrate-latest.json` attests that the source was clean before and
after execution and remains partial for exactly `vm-primitives`, `metadata`,
`bitmaps`, `arenas`, `initialization`, `fault-injection`, and
`allocator-recursion`. The runner defines that partial result as exit 3. This
is current-commit confirmation of the same M2 boundary, not evidence that any
later milestone has advanced.

At `1698ee9e9ef88894d2d68fcf2a0a806868f5a547`, a clean detached native
checkout reran `./scripts/dev.sh allocator-m2` after the reset-advice fix. Its
report attests an unchanged clean source before and after execution, eight
passing VM-primitives checks, one passing metadata check, and all ten passing
PageMap checks. The new VM check is the deterministic reset-advice snapshot
regression described above. The report remains partial for exactly
`vm-primitives`, `metadata`, `bitmaps`, `arenas`, `initialization`,
`fault-injection`, and `allocator-recursion`; it does not advance M3 or any
later milestone.

At `0d153612edb33699d0235ccb69eb359f6802e9a8`, a clean detached native
checkout reran `./scripts/dev.sh allocator-m2` after the arena field-boundary
fix. Its report attests an unchanged clean source before and after execution,
with 20 passing selected checks: eight VM-primitives checks, one metadata
check, all ten PageMap checks, and the one arena default delayed-purge
64-bit-field boundary check. The command exited 3 as designed; its unmet IDs
remain exactly `vm-primitives`, `metadata`, `bitmaps`, `arenas`,
`initialization`, `fault-injection`, and `allocator-recursion`. This adds
bounded arena evidence only and does not advance M3 or any later milestone.

At `242f3499c7e99224161b5aca855d537280061139`, a clean detached native
checkout reran `./scripts/dev.sh allocator-m2` after correcting the frozen
Linux default-decommit error result. Its report attests an unchanged clean
source before and after execution, with 21 passing selected checks: eight
VM-primitives checks, one metadata check, all ten PageMap checks, and two
arena delayed-purge checks. The command exited 3 as designed; its unmet IDs
remain exactly `vm-primitives`, `metadata`, `bitmaps`, `arenas`,
`initialization`, `fault-injection`, and `allocator-recursion`. This corrects
one source error transition but does not advance M3 or any later milestone.

At `9bf1d831f14caee780d6c818da6e52c03350983f`, a clean detached native
checkout reran `./scripts/dev.sh allocator-m2` after splitting static detached
metadata-image binding from first-demand private backing. Its report attests
an unchanged clean source before and after execution, with 23 passing selected
checks: eight VM-primitives checks, two metadata checks, all ten PageMap
checks, two arena delayed-purge checks, and one initialization check. The
metadata witness freezes one selected subprocess before any private Map #1,
rejects a foreign subprocess without consuming that fault, returns clean Map
#1 failure to BOUND, and retries only the selected identity. The initialization
witness proves the static image is bound before the global PageMap Map #1,
leaving no private metadata map or ticket-zero roots on that terminal global
map failure. The command exited 3 as designed; its unmet IDs remain exactly
`vm-primitives`, `metadata`, `bitmaps`, `arenas`, `initialization`,
`fault-injection`, and `allocator-recursion`. This is bounded evidence for the
source image/order only: Rust's first valid metadata request still uses its
documented private direct-OS PageMap/external-arena backing rather than a claim
of C normal `_mi_meta_zalloc` backing parity. M2 remains partial and does not
advance M3 or any later milestone.

At `d89155128e00cb47c12269665bc5c3636f178ce5`, a clean detached native
checkout reran `./scripts/dev.sh allocator-m2` after matching the detached
metadata-Theap's source provenance and frozen page-reclaim image. Its
`m2-memory-substrate-latest.json` attests an unchanged clean source tree
before and after execution, with 24 passing selected checks: eight
VM-primitives checks, two metadata checks, all ten PageMap checks, two arena
checks, and two initialization checks. The new initialization witness runs
before any metadata session/backing and proves only the kind-only static
MemoryId (including zero union) plus enabled frozen normal page-reclaim image.
The command exited 3 as designed; its unmet IDs remain exactly
`vm-primitives`, `metadata`, `bitmaps`, `arenas`, `initialization`,
`fault-injection`, and `allocator-recursion`. This advances neither M2
completion nor M3 or any later milestone.

At `9ddae0bcc4bd82146d71c95c10425c1330fa6e78`, a clean detached native
checkout reran `./scripts/dev.sh allocator-m2` after the detached first-head
random/cookie image and fail-closed invalid-input boundary were added to the
M2 contract. Its `m2-memory-substrate-latest.json` attests an unchanged clean
source tree before and after execution, with 25 passing selected checks: eight
VM-primitives checks, two metadata checks, all ten PageMap checks, two arena
checks, and three initialization checks. The new pair covers the bounded
same-subprocess/empty-head/non-threadpool pre-demand image and rejects
nonempty-head, mismatched-subprocess, and thread-pool inputs before mutation;
it does not claim C list/split, option-adjustment, or normal metadata-backing
parity. The command exited 3 as designed; its unmet IDs remain exactly
`vm-primitives`, `metadata`, `bitmaps`, `arenas`, `initialization`,
`fault-injection`, and `allocator-recursion`. This advances neither M2
completion nor M3 or any later milestone.

At `62ad1307d5b3686cc8654aefa4d9748ebcacc667`, a clean detached native
checkout reran `./scripts/dev.sh allocator-m2` after adding the selected
later-TLD direct-Malloc capability-lifetime check. Its
`m2-memory-substrate-latest.json` attests a clean source tree before and after
execution, unchanged during the run, with 26 passing selected checks: eight
VM-primitives checks, three metadata checks, all ten PageMap checks, two arena
checks, and three initialization checks. The added real-caller witness proves
only ticket-zero's no-capability teardown, one injected post-ready direct-
zeroed failure that consumes its later sequence without a capability or live
lease, and one typed subprocess-attached/no-theap Malloc retry through exact-
owner teardown. It does not claim normal C `_mi_meta_zalloc` backing, generic
`_mi_meta_free` dispatch, or full TLD/list/lock lifecycle parity. The command
exited 3 as designed; its unmet IDs remain exactly `vm-primitives`,
`metadata`, `bitmaps`, `arenas`, `initialization`, `fault-injection`, and
`allocator-recursion`. M2 remains partial and does not advance M3 or any later
milestone.

At `e21eb06c076dcb5c0aca3d30f8c3ccf876f89212`, a clean detached native
checkout reran `./scripts/dev.sh allocator-m2` after adding the selected
nonexclusive dynamic-Theap direct-Malloc capability-lifetime checkpoint. Its
`m2-memory-substrate-latest.json` attests a clean source tree before and after
execution, unchanged during the run, with 27 passing selected checks: eight
VM-primitives checks, four metadata checks, all ten PageMap checks, two arena
checks, and three initialization checks. The command exited 3 as designed; its
unmet IDs remain exactly `vm-primitives`, `metadata`, `bitmaps`, `arenas`,
`initialization`, `fault-injection`, and `allocator-recursion`. The fourth
metadata witness selects only a child-thread, caller-pinned empty-Heap,
nonexclusive-Theap lifecycle after ticket zero. It observes the selected
sequence-one Malloc TLD/Theap one-member list shape, four attached metadata
capabilities, and the separate process-owned registry bitmap; it does not
establish normal C `_mi_meta_zalloc` backing, exclusive-arena allocation,
generic `_mi_meta_free`, general list/refcount policy, page ownership,
concurrency, or process/thread shutdown parity. M2 remains partial and does
not advance M3 or any later milestone.

At `a724db5a4ed63c5f689ee90bb101057c39df0a4f`, a clean detached native
checkout reran `./scripts/dev.sh allocator-m2` after adding the selected
live regular-TLS metadata-rezalloc capability-lifetime checkpoint. Its
`m2-memory-substrate-latest.json` attests a clean source tree before and after
execution, unchanged during the run, with 28 passing selected checks: eight
VM-primitives checks, five metadata checks, all ten PageMap checks, two arena
checks, and three initialization checks. The command exited 3 as designed; its
unmet IDs remain exactly `vm-primitives`, `metadata`, `bitmaps`, `arenas`,
`initialization`, `fault-injection`, and `allocator-recursion`. The fifth
metadata witness selects one post-first-image child-thread direct-Malloc
16-to-32 replacement: an injected pre-allocation failure restores the old
root/count/slots/capability, and one retry copies slot 15, publishes slot 16,
reaches live-one/high-water-two, then tears down to zero. It does not establish
the initial C count-zero `_mi_meta_rezalloc(NULL, ...)` route, normal C
metadata backing, arbitrary growth, generic `_mi_meta_free`, complete
TLS/TLD/Theap/registry lifecycle, concurrency, pthread/process lifecycle, or
ABI integration. M2 remains partial and does not advance M3 or any later
milestone.

At `ffaea4a9a2a3304dad0ff57ed081cc96e3b29978`, a clean detached native
checkout reran `./scripts/dev.sh allocator-m2` after adding the detached-Theap
identity-admission prerequisite. Its `m2-memory-substrate-latest.json` attests
the source was clean before and after execution and unchanged during the run,
with 29 passing selected checks: eight VM-primitives checks, six metadata
checks, all ten PageMap checks, two arena checks, and three initialization
checks. The sixth metadata check proves COLD direct `zalloc`, aligned
`zalloc`, and `rezalloc(None)` return `TheapMetaUnpublished` before the
metadata lock, mapping, or capability creation; preparation binds and one-way
publishes only the exact selected detached-Theap identity, then the pending map
fault is consumed by a prepared demand and a later retry succeeds. This is an
identity-only Rust safety strengthening of C's non-null assertion, not the
actual `mi_subproc_t::theap_meta` layout/lock, pointer dereference, main-Heap
linkage, normal C backing, or complete initialization. The command exited 3 as
designed; its unmet IDs remain exactly `vm-primitives`, `metadata`, `bitmaps`,
`arenas`, `initialization`, `fault-injection`, and `allocator-recursion`. M2
remains partial and does not advance M3 or any later milestone.

At `d965a6699bd65f92f98d96a665eac9ecf60e60f0`, a clean detached native
checkout reran `./scripts/dev.sh allocator-m2` after adding the one-chunk
abandoned-claim C/Rust differential. Its
`m2-memory-substrate-latest.json` attests a clean source tree before and after
execution, unchanged during the run, with 30 passing selected checks: eight
VM-primitives checks, six metadata checks, one bitmap differential, all ten
PageMap checks, two arena checks, and three initialization checks. The bitmap
record directly includes pinned `src/bitmap.c` and matches all 21 selected
control and transition fields: reject/restore, accept while retaining the
conservative map, and no-callback stale-map repair. The command exited 3 as
designed; its unmet IDs remain exactly `vm-primitives`, `metadata`, `bitmaps`,
`arenas`, `initialization`, `fault-injection`, and `allocator-recursion`. M2
remains partial and does not advance M3 or any later milestone.

At `9136162edf724287b64b381125ae4b01671e52bb`, a clean detached native
checkout reran `./scripts/dev.sh allocator-m2` after porting the selected
scalar clear-range visitor and correcting its explicit M2 nonclaim. Its
`m2-memory-substrate-latest.json` attests a clean source tree before and after
execution, unchanged during the run, with 31 passing selected checks: eight
VM-primitives checks, six metadata checks, two bitmap differentials, ten
PageMap checks, two arena checks, and three initialization checks. The bitmap
records matched all 21 abandoned-claim fields and all 26 clear-range fields.
The command exited 3 as designed; its unmet IDs remain exactly
`vm-primitives`, `metadata`, `bitmaps`, `arenas`, `initialization`,
`fault-injection`, and `allocator-recursion`. M2 remains partial and does not
advance M3 or any later milestone.

At `1e440d2a70d465cc90391983a986ea37853d24a9`, a clean detached native
checkout reran all current predecessor and M2 gates after porting the selected
scalar `_mi_bitmap_forall_setc_rangesn` wrapper. The clean detached
`./scripts/dev.sh allocator --quick` exited 0, and
`./scripts/dev.sh allocator-m1` exited 0 with all six M1 components complete
and no unmet IDs. `./scripts/dev.sh allocator-m2` ran
32 selected checks, attested a clean source tree before and after execution
and unchanged during the run, and exited 3 as designed. Its three bitmap
C/Rust records matched all 21 abandoned-claim fields, 26 generic clear-range
fields, and 52 direct rangesn-wrapper fields. The new wrapper trace directly
includes pinned `src/bitmap.c`: fresh `rngslices == 3` images cover aligned
completed windows, incomplete-window/top-suffix restoration, and a stopped
callback that restores a prior skipped window plus later snapshot bits; fresh
zero and one calls cover generic delegation, and 65 covers the cap at 64. It
does not execute `_mi_os_minimal_purge_size`, transparent-huge-page policy, or
an arena caller. The unmet IDs remain exactly `vm-primitives`, `metadata`,
`bitmaps`, `arenas`, `initialization`, `fault-injection`, and
`allocator-recursion`. M2 remains partial and does not advance M3 or any later
milestone.

At `3db580e5ae052b5e6d61819ebe866ec9941b2c80`, a clean detached native
checkout reran all predecessor and M2 gates after adding the selected
same-thread metadata direct-demand recursion regression. The clean detached
`./scripts/dev.sh allocator --quick` exited 0. `./scripts/dev.sh allocator-m1`
exited 0 with all six M1 components complete, no unmet IDs, and 45 executed
check records. `./scripts/dev.sh allocator-m2` ran 33 selected checks, attested
that source was clean before and after execution and unchanged during the run,
and exited 3 as designed. Its added `allocator-recursion` check holds Rust's
same-thread entry marker while prepared direct `zalloc`, aligned `zalloc`, and
`rezalloc(None)` each reject before a pending map fault, private backing, or
metadata capability can be consumed; it separately confirms that
`rezalloc(Some(_))` preserves its live old capability before its claim and that
both routes recover after the marker drops. This is a Rust safety boundary over
the source nonrecursive metadata lock, not C lock/deadlock parity or coverage
of callbacks, signals, cross-thread races, PageMap/arena/OS, release/copy, or
general metadata lifecycle paths. The unmet IDs remain exactly
`vm-primitives`, `metadata`, `bitmaps`, `arenas`, `initialization`,
`fault-injection`, and `allocator-recursion`; M2 remains partial and does not
advance M3 or any later milestone.

At `f2f318194fdbc06a9d10d3cec3a7f01c675b6af9`, a clean detached native
checkout reran all predecessor and M2 gates after adding the selected native
protection failure-owner/retry regression. `./scripts/dev.sh allocator --quick`
exited 0. `./scripts/dev.sh allocator-m1` exited 0 with all six bounded
components complete, no unmet IDs, and 45 executed records.
`./scripts/dev.sh allocator-m2` ran 34 selected checks, attested a clean source
tree before and after execution and unchanged during the run, and exited 3 as
designed. Its new `fault-injection` check uses two committed one-page mappings:
one injected pre-syscall `Protect` `NOMEM` retains exact base/length and still
permits volatile access; one successful protect followed by injected
pre-syscall `Unprotect` `NOMEM` retains exact base/length without dereference;
each disabled-plan retry succeeds and its mapping releases exactly once. This
is a test-only Rust owner/retry boundary, not C failure equivalence or
live-kernel failure evidence. The unmet IDs remain exactly `vm-primitives`,
`metadata`, `bitmaps`, `arenas`, `initialization`, `fault-injection`, and
`allocator-recursion`; M2 remains partial and does not advance M3 or any later
milestone.

At `04e6f49c233c8d3d14d45a5299c54e255ad28917`, a clean detached native
checkout reran all predecessor and M2 gates after porting the selected scalar
read-only `_mi_bitmap_forall_set` visitor and correcting the bitmap nonclaim.
`./scripts/dev.sh allocator --quick` exited 0. `./scripts/dev.sh allocator-m1`
exited 0 with all six bounded M1 components complete, no unmet IDs, and 45
executed records. `./scripts/dev.sh allocator-m2` ran 35 selected checks,
attested a clean source tree before and after execution and unchanged during
the run, and exited 3 as designed. Its four bitmap C/Rust records matched all
21 abandoned-claim fields, 26 clear-range fields, 52 rangesn-wrapper fields,
and 30 read-only set-visitor fields. The new direct C/Rust trace uses fresh
valid 65-chunk images across chunk-map fields zero and one: completion visits
bits 1, 65, and 32770 in source order, and a second-callback stop leaves the
selected raw state unchanged. It is not heap/arena integration, callback
mutation, binned or flexible-array bitmap behavior, arena/subprocess
ownership, race, or statistics evidence. The unmet IDs remain exactly
`vm-primitives`, `metadata`, `bitmaps`, `arenas`, `initialization`,
`fault-injection`, and `allocator-recursion`; M2 remains partial and does not
advance M3 or any later milestone.

At `5c2ce5414b8975e4507f7691c037f124850921a5`, a clean detached native
checkout reran all predecessor and M2 gates after adding the typed
arena-release subprocess-identity gate. `./scripts/dev.sh allocator --quick`
exited 0. `./scripts/dev.sh allocator-m1` exited 0 with all six bounded M1
components complete, no unmet IDs, and 45 executed records.
`./scripts/dev.sh allocator-m2` ran 36 selected checks, attested a clean
source tree before and after execution and unchanged during the run, and exited
3 as designed. Metadata now has seven selected checks. The new check uses one
typed, unpinned, one-slice `ArenaSliceClaim`: a foreign `MainSubprocess`
returns the unchanged claim before Rust purge/free-bitmap state can change,
while the matching identity consumes it, returns the existing successful
terminal free-bit result, and permits reclaim of the same slice. This makes
C's internal arena/subprocess assertion a bounded Rust safety boundary; it is
not a C differential, a `MetaRelease::Arena` branch, generic `_mi_meta_free`
dispatch, normal C metadata backing, general purge behavior, full lifecycle,
or invalid-input parity. The unmet IDs remain exactly `vm-primitives`,
`metadata`, `bitmaps`, `arenas`, `initialization`, `fault-injection`, and
`allocator-recursion`; M2 remains partial and does not advance M3 or any later
milestone.

At `50049e9131f729b82615ac99c2a784974775aefd`, a clean detached native
checkout reran all predecessor and M2 gates after adding the selected
allocation-won arena-purge fallback regression. `./scripts/dev.sh allocator
--quick` exited 0. `./scripts/dev.sh allocator-m1` exited 0 with all six
bounded M1 components complete, no unmet IDs, and 45 executed records.
`./scripts/dev.sh allocator-m2` ran 37 selected checks, attested a clean source
tree before and after execution and unchanged during the run, and exited 3 as
designed. The `arenas` category now has three selected checks. Its new
two-slice external-arena witness releases `[9, 11)`, reclaims the low slice
before forced collection, then observes the failed full claim skip that
allocation-won slice while the high free sibling is individually hooked and
restored; both purge bits remain consumed. It is same-thread source-mapped
state evidence, not a live race, broader visitor/purge-policy proof,
multi-arena or lifecycle claim, fault/retry proof, or C/Rust differential. The
unmet IDs remain exactly `vm-primitives`, `metadata`, `bitmaps`, `arenas`,
`initialization`, `fault-injection`, and `allocator-recursion`; M2 remains
partial and does not advance M3 or any later milestone.

At `03264676bddff8fdf94cd2ba3d9103124c9c200c`, a clean detached native
checkout reran the relevant baseline and predecessor gates after adding the
requested-parent Theap reservation. `./scripts/dev.sh allocator --quick`
exited 0 and compiled `LAYOUT_PROBE`, including its C-only assertion that the
complete pinned `mi_theap_t` fits one `MI_ARENA_MIN_OBJ_SIZE` object.
`./scripts/dev.sh allocator-m1` exited 0 with all six bounded components
complete, no unmet IDs, and 45 executed records. `./scripts/dev.sh
allocator-m2` executed all 38 selected checks and exited 3 as its partial-gate
contract defines. Its current category counts are eight VM-primitives, eight
metadata, four bitmaps, ten PageMap, three arenas, three initialization, one
fault-injection, and one allocator-recursion check; PageMap is the sole
complete category. The M1 and M2 reports attest the source was clean before
and after execution and unchanged during it. The seven unmet IDs remain
exactly `vm-primitives`, `metadata`, `bitmaps`, `arenas`, `initialization`,
`fault-injection`, and `allocator-recursion`.

At `5a2708d5c1e6b463c5eade8f60afa75d6131818a`, a clean detached native
checkout reran the relevant baseline and predecessor gates after adding the
separate synthetic requested-parent Arena-Theap-prefix lifecycle.
`./scripts/dev.sh allocator --quick` exited 0. `./scripts/dev.sh allocator-m1` exited 0 with all
six bounded components complete, no unmet IDs, and 45 executed records.
`./scripts/dev.sh allocator-m2` executed all 39 selected checks and exited 3
as its partial-gate contract defines. Its current category counts are eight
VM-primitives, nine metadata, four bitmaps, ten PageMap, three arenas, three
initialization, one fault-injection, and one allocator-recursion check; PageMap
is the sole complete category. The M1 and M2 reports attest the source was
clean before and after execution and unchanged during it. The seven unmet IDs
remain exactly `vm-primitives`, `metadata`, `bitmaps`, `arenas`,
`initialization`, `fault-injection`, and `allocator-recursion`. The new ninth
metadata record is a bounded synthetic prefix-owner lifecycle; it does not
change M2's partial status or advance a later milestone.

At `9c19a64be59e7fb5dab4681136025fbc770b8f00`, a clean detached native
checkout reran the same baseline and predecessor gates after adding the
bounded lock-free metadata-page identity query. `./scripts/dev.sh allocator
--quick` exited 0. `./scripts/dev.sh allocator-m1` exited 0 with all six
bounded components complete, no unmet IDs, and 45 executed records.
`./scripts/dev.sh allocator-m2` executed all 40 selected checks and exited 3
as its partial-gate contract defines. Its current category counts are eight
VM-primitives, ten metadata, four bitmaps, ten PageMap, three arenas, three
initialization, one fault-injection, and one allocator-recursion check; PageMap
is the sole complete category. The M1 and M2 reports attest the source was
clean before and after execution and unchanged during it. The seven unmet IDs
remain exactly `vm-primitives`, `metadata`, `bitmaps`, `arenas`,
`initialization`, `fault-injection`, and `allocator-recursion`. The new
`bound-subprocess-metadata-page-identity-query` record is only the source
read-only `page->theap == subproc->theap_meta` predicate under the bounded Rust
identity representation; it does not change M2's partial status or advance a
later milestone.

At `86143445817a7e1c4e10bb7bb49208faf1b3eeeb`, a clean detached native
checkout reran the baseline, predecessor, and M2 gates after adding the
selected metadata direct-allocation lock phase. `./scripts/dev.sh allocator
--quick` exited 0. `./scripts/dev.sh allocator-m1` exited 0 with all six
bounded components complete, no unmet IDs, and 45 executed records.
`./scripts/dev.sh allocator-m2` executed all 41 selected checks and exited 3
as its partial-gate contract defines. Its category counts are eight
VM-primitives, eleven metadata, four bitmaps, ten PageMap, three arenas, three
initialization, one fault-injection, and one allocator-recursion check; PageMap
is the sole complete category. The M1 and M2 reports attest the source was
clean before and after execution and unchanged during it. The seven unmet IDs
remain exactly `vm-primitives`, `metadata`, `bitmaps`, `arenas`,
`initialization`, `fault-injection`, and `allocator-recursion`. The new
`bound-subprocess-theap-meta-lock-direct-allocation-phase` record holds the
selected subprocess lock before first direct demand, preserves BOUND with no
private backing or capability until release, covers aligned allocation and
rezalloc copy preservation, and proves exact-owner `Malloc` free stays outside
that lock. It does not change M2's partial status or advance a later milestone.

At `b09b1fd98cec6b811f52cf7e972e9dbda2127872`, a clean detached native
checkout reran the baseline, predecessor, and M2 gates after adding the
selected typed Malloc free pre-claim recursion boundary. `./scripts/dev.sh
allocator --quick` exited 0. `./scripts/dev.sh allocator-m1` exited 0 with all
six bounded components complete, no unmet IDs, and 45 executed records.
`./scripts/dev.sh allocator-m2` executed all 42 selected checks and exited 3
as its partial-gate contract defines. Its category counts are eight
VM-primitives, eleven metadata, four bitmaps, ten PageMap, three arenas, three
initialization, one fault-injection, and two allocator-recursion checks;
PageMap is the sole complete category. The M1 and M2 reports attest the source
was clean before and after execution and unchanged during it. The seven unmet
IDs remain exactly `vm-primitives`, `metadata`, `bitmaps`, `arenas`,
`initialization`, `fault-injection`, and `allocator-recursion`. The new
`metadata-same-thread-free-reentry-before-capability-mutation` record selects
only typed `MetaRelease::Malloc` free: it enters Rust's backing entry before
LIVE-to-RELEASING, and a held same-thread entry returns the exact pointer,
`MemoryId`, and audit as `MallocRetryable` with `MetaError::RecursiveEntry` for
post-drop retry. It does not widen general `MetaAllocator::free`, whose
admitted lifecycle errors remain terminal; stale/provenance and post-claim
Malloc failures remain terminal as well. Neither selected free route takes
`MainSubprocess::theap_meta_lock`. This is not C free/mutex/deadlock,
callback/signal, cross-thread, generic `_mi_meta_free`, copy, or lifecycle
parity, and it does not change M2's partial status or advance a later
milestone.

At `bdbcfc7173a7262ee12d4152a8c7c608a51bc086`, a clean detached native
checkout revalidated the then-current checkpoint: `./scripts/dev.sh allocator
--quick` exited 0; `./scripts/dev.sh allocator-m1` exited 0 with all six
bounded components complete; and `./scripts/dev.sh allocator-m2` executed 47
selected checks and exited 3 as its partial-gate contract requires. The M2
counts were twelve VM-primitives, eleven metadata, four bitmaps, ten PageMap,
three arenas, three initialization, one fault-injection, and three
allocator-recursion checks. Its reports attest clean source before and after
the run and no source change during it; the unmet IDs remained exactly
`vm-primitives`, `metadata`, `bitmaps`, `arenas`, `initialization`,
`fault-injection`, and `allocator-recursion`. This is historical evidence for
that exact revision, not for the later 53-check contract.

## Active boundary and priority rule

The integrated owner-local mapped-abandoned medium reclaim slice is a narrowly
mapped M5/Phase-E regression: it is neither a general scan nor a milestone,
shadow, or promotion claim. Keep its source map, regression, and exact test
result, but do not use it to advance M5.

M0 and M1 are closed predecessors under their bounded contracts and were
revalidated cleanly at `bdbcfc7173a7262ee12d4152a8c7c608a51bc086`. M2 is now
the current closure gate. Its checked-in current contract has 53 selected
checks (thirteen VM-primitives, eleven metadata, four bitmap C/Rust
differentials plus four Rust-only bitmap-observer check records, ten PageMap, three arena,
four initialization, one native protection fault-injection check, and three
allocator-recursion checks). The clean detached `bdbcfc71` report is current
runtime evidence for that exact revision's 47-check contract, including its
intentional exit 3 and unchanged clean source; it does not attest the six
later checks. The current 53-check shape must therefore be rerun cleanly
before it can be called current runtime evidence. It will continue to exit 3
by contract until every partial component closes: PageMap is the sole complete
component, and its other seven required components remain partial (including
bitmap, metadata, arena, initialization, fault-injection, and
allocator-recursion).
Do not advance M3, M4, or later milestones until
M2 has its own complete current-commit contract and evidence. The narrowly
scoped M5 work around the bounded process-once envelope does not advance M5.
Existing M3/M4 bounded evidence remains regression evidence, not permission to
skip M2 or milestone closure. M5 remains open until its Phase A–G acceptance
conditions are met.

## Current M5 gate facts

The historical full report at `d5e5901bcfaf7d790632f3c6324afd4019c4e0f4`
recorded `m5.base`, `m5.5a`, `m5.5b`, and `m5.5c` as passed. `m5.5d` is
blocked because the canonical source-bound upstream stress matrix remains a
bounded nondefault shadow subset and the source-derived lane cannot accept
upstream cross-thread transfer or lifecycle. `m5.5e` is blocked because the
selected shadow ABI, pthread, differential, and stress closure is not
established. The Rust backend remains nondefault.
