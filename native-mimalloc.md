# Native mimalloc for crabc

The crucial framing is: **do not design a new allocator**. Produce a provenance-preserving, semantically faithful Rust port of a fixed upstream mimalloc v3 release, then optimize only where measurement shows the Rust translation diverges.

The objective is to remove the C allocator from the production dependency graph while retaining mimalloc's design, behavior, concurrency model, lifecycle semantics, and performance—not to create "mimalloc-inspired" machinery.

The project remains a compatibility-engineering project, not allocator research.

---

## Current checkpoint — 2026-08-29

Current capability checkpoint: Gates 5A and 5B are complete. Gate 5C now has
a bounded mixed regular-page owner-exit witness: it collects two joined
pre-exit remote frees, normalizing one full medium while releasing a distinct
large page made empty during source collection, and keeps a direct-small page,
a non-direct-small page, and a distinct two-client live large page in that
same opaque aggregate route. It tears down A's Theap/TLD, gives a distinct
fresh B only exact C-address query/free handling and one private
allocate/copy/free replacement through that route. B may instead first
establish one independent parked local native session; the route then runs
only while that session is parked. A's admission releases only after the route
terminally releases and B completes its own ordinary attachment finish. While B holds the source low owner bit for its
first direct free of either the existing direct-small page, the first
pre-exit-normalized mapped, non-full medium page, or a distinct medium that A
made mapped and non-full through one ordinary local free before exit, it may
hand joined C and D one scoped opaque pair for two further clients from that
same page. C and D atomically publish their private clients in separate joined
turns; B's existing
`mi_free_try_collect_mt`-shaped tail consumes both before unown or terminal
release. The direct-small and mapped-medium runtime regressions pause after the
route transfers and prove ticket zero remains unavailable until B returns the
terminal proof; the eight-cycle state audit and prefixed C witness continue to
exercise the direct-small handoff. This is not a general post-exit
concurrent-free API. The aggregate route, sole-medium route, and
source-valid direct-small reclaim route now enter as prepared suspended
page-bearing compiler-TLS owners. In addition, a private
`CurrentThreadPageOwnerSession` keeps one generation-checked parked engine and
its private client ledger across multiple ordinary allocation, local-free, and
joined pre-exit-publication operations. The ledger begins with the
source-witness inline capacity and grows through private metadata before a
further C allocation can escape. Its consuming
`prepare_sequential_exit` moves every still-local ledger member into the
typed route without accepting a workload-shaped client list; source-published
members remain solely with source collection. The fixed preparation paths use
the same ledger rules: every allocation must be locally freed,
joined-published before exit, or moved exactly once into the typed route;
omission, duplication, and a fixed selection beyond its explicit inline
capacity reject before suspension. A runtime session instead retains its
metadata-backed private registry with the typed route until every detached
client has terminally released. An active session with a live or
source-published client is not a no-page
finalizer input. A session with no locally live client may instead enter a
distinct all-free page drain: locally freed entries no longer own a client,
while any retired source page releases in its `_mi_theap_collect_retired`
prepass and joined source-published entries remain for source collection. It resumes its exact parked
engine, clears the source fast slot, finishes its PageMap/attachment teardown,
and only then releases its worker admission. A prepared-exit state enters the
aggregate traversal
for the first two or the existing direct-cache-validating small-or-medium drain
for the third, and neither path falls through to the no-page finalizer while a
typed post-exit route or worker admission remains live. Independently, the private runtime page-owner
scheduler now counts independently parked normal-engine tokens: every complete
mutation is still serial `PARKED(n) -> BUSY -> PARKED(n)` or
`PARKED(n) -> BUSY -> PARKED(n + 1)`, and ticket zero remains blocked until
the count returns to zero. Direct runtime evidence parks two distinct engines,
finishes either one first, and proves that the remaining token alone continues
to block ticket zero. Native detached owner exit uses an append-only,
metadata-backed private registry rather than a fixed route count. Each stable
entry owns one typed aggregate or sole route, one parked scheduler count, A's
admission proof, and a private client ledger: fixed preparation routes use
their inline ledger while a normal session moves any metadata-backed overflow
with its detached facts. Empty entries are reused, and registry storage grows
only to the process high-water of independently detached A owners. Its terminal
source release transfers a completion to its matched B; only that B's ordinary
attachment finish removes the exact parked count and then releases A's admission.
Before a retained entry publishes, it closes the same short registry mutation
boundary that installs detached owners: an in-flight A finishes its complete
installation before that closure, while a later A cannot publish beside the
terminal route. The registry never exposes a client address, and each route
takes only short serialized PageMap access; a sibling route blocks consumption
into a long PageMap lease. A metadata-growth or terminal-route failure retains
the exact owner rather than publishing a fallback. This remains a lifecycle
substrate, not general C routing or concurrent page mutation. The
selected C overflow witness drives 80 1 KiB direct-small clients, followed by
non-direct-small, medium, large, and arena-singleton clients, through one
ordinary session. It proves the same aggregate traversal accounts for the
full first direct-small page, a later nonfull same-bin page, and the mixed
tail across eight owner-exit epochs; it does not add a block-count-specific
production route. The
same aggregate coordinator admits full `BIN_FULL` medium or
large pages and full ordinary-bin direct/non-direct small pages. A joined
remote free normalizes one such page to mapped abandonment during source
collection; an unchanged full regular page instead remains source-unmapped
until a later client free crosses the source mostly-used predicate. A live
arena singleton now joins that same route as a PageMap-only raw-terminal tail;
a live OS-aligned singleton joins it through the static main Heap's private
list and clipped-mapping terminal tail. A joined remote free may instead
force-empty either singleton form, whose ordinary terminal release remains
private to the traversal. The runtime witness keeps the OS client private in
the same B-side route, so its list/mapping tail must terminally release before
A's admission becomes fork-quiescent. A source-valid sole-medium route also
crosses to a distinct later thread for reclaim/reuse: its opaque capability
retains A's admission until B has adopted and used the exact page, drained its
engine, and completed B's normal attachment; its A-side ordinary finish uses
the same suspended-owner dispatcher. The direct-small counterpart takes its
distinct source drain so it can validate and clear the rounded direct-cache
image before it transfers that same opaque adoption capability; it shares the
terminal-proof boundary but is not a general aggregate-route expansion. A
direct Rust mixed-page regression now terminally releases the aggregate's
direct-small sibling, then transfers its last mapped medium member through an
exact selected-client bitmap claim into a fresh later-main engine. That engine
reuses the source-freed block, drains the inherited client, and normally
releases the final map/arena state. The pointer-private runtime ledger now
carries the normal request and immutable process pair internally, clears an
empty singleton subregistry on its terminal tail, and reaches that same
handoff only after every sibling has released; B drains and finishes the target
before it returns A's admission proof. Neither path stores a client address or
exposes a generic reclaim surface. The focused held-route integration repeats
that source eight times, while the deterministic state audit and prefixed-C
churn witness alternate it with the sole-medium source without widening the C
ABI. Those are bounded source-specific proofs;
general owner-exit coverage remains next. Every bounded runtime page-owner
exit continuation—the aggregate traversal, direct small-or-medium reclaim,
and all-free drain—now enters the source `_mi_deferred_free` phase before its
first page work: production advances the Theap heartbeat, while a private
attachment-local observer proves the callback ordering and recursion guard;
public callback registration/re-entry remains outside this checkpoint. The
aggregate and all-free continuations then share the source retired-page
prepass, so an already-empty retired page releases before generic force
collection; the direct continuation has no source-retired sibling in its
validated one-page entrance.

The implementation has reached an important phase boundary.

Substantial foundations already exist:

* pinned mimalloc v3.5.0 source provenance;
* `#![no_std]` Linux/AArch64 `crabc-mimalloc`;
* allocator configuration, arithmetic, binning, metadata, bitmap, arena, PageMap, and OS-memory substrates;
* single-thread allocation machinery covering the fundamental page classes;
* ordinary realloc and aligned-allocation machinery;
* compiler TLS machinery;
* dynamic TLD/Theap infrastructure;
* remote-free atomic protocols with Loom schedules;
* bounded abandonment/adoption and terminal-release machinery;
* process-static ticket-zero ownership;
* no-page pthread lifecycle integration with crabc-libc;
* a conservative quiescent fork bridge;
* default arena reservation and process PageMap lifecycle;
* many carefully proven owner-exit page shapes;
* a test-only ticket-zero C adapter that proves real first allocation, zeroing, realloc, free, a retained narrow worker witness, repeated persistent mixed-local worker ownership, and same-arena reactivation;
* deterministic source-map and ratchet infrastructure;
* hundreds of focused allocator tests.

At this checkpoint:

* the `crabc-mimalloc` library suite passes;
* allocator-runner tests pass;
* the source ledger is heavily implemented and unit-verified;
* only a much smaller fraction has differential or stress evidence;
* no performance workload is yet qualified;
* `libmimalloc-sys` remains the production allocator;
* the nondefault `crabc-libc` `native-mimalloc-shadow` feature routes the
  ordinary malloc family through the Rust engine for the initial thread and
  attached workers' private local allocations, including independently parked
  A-live route owners plus independent local B sessions, and
  metadata-backed detached aggregate-or-sole routes: after each A exits with direct-small,
  non-direct-small, medium,
  regular-large, arena-singleton, and OS-aligned-singleton C allocations, a
  fresh B, or a B with one independently parked local session, may return
  those exact addresses through an opaque registry route; an attached worker may also source-publish an exact still-live
  initial-thread normal or aligned client to its page's atomic remote head,
  without receiving a page engine, scheduler claim, or stored client
  capability; it has no C-backend fallback;
* Gates 5A and 5B use one private typed A-side runtime operation, and the private scheduler now admits distinct independently parked normal engines while serializing each PageMap mutation. The selected shadow proves both that a second C worker can retain a local private session while a live A route is active and that two independently parked A routes can each accept an exact B-side query/free; neither witness gives later workers a public, cross-pointer, or general persistent allocator route;
* the worker runtime seam deliberately prevents client pointers from crossing its bounded witnesses: the Gate 5B B/C threads receive only opaque publication capabilities, and Gate 5C gives B/C/D only a scoped same-page atomic producer pair plus an opaque B-side route;
* native-shadow worker pointers remain local to their parked owner session
  except for the pointer-private post-exit aggregate/sole mapped-regular
  routes and one direct source free: an attached worker may present an exact
  still-live initial-thread normal or aligned allocation, which pins its
  registered page while the worker validates the immutable ticket-zero owner,
  recovers the canonical aligned block if needed, and atomically pushes it to
  the remote head. That direct route retains no client address, page engine,
  scheduler operation, or admission proof, and ticket zero collects it during
  a later ordinary operation. The post-exit routes keep client addresses
  private, serve only exact source-recorded usable-size queries, sequential
  frees, and one source-shaped B allocate/copy/free replacement from a fresh B
  or B's independently parked local session, and leave A's admission proof in
  B TLS until B's own ordinary lifecycle finishes. The aggregate branch may consume the
  existing final-member adoption edge only after exact frees reduce its
  private ledger to one source-recorded normal request with A's
  force-collectable local-free fact; natural C ABI alignment (at most 16
  bytes) preserves that normal provenance, while genuinely over-aligned
  requests remain sequential-free-only. That consuming edge keeps the final
  address private and grants C no page, allocator, scan, or reclaim
  capability. The sole branch permits the same exact detached replacement or
  free, but no C-visible adoption or reclaim; while A is still parked and
  live, a fresh attached no-page B/C publisher may claim A's exact
  `NativeLiveRemoteOwnerRegistry` entry to query one source-recorded usable
  extent or prove one exact C address against A's private ledger and atomically
  publish it to A's source remote head. Stable metadata-backed entries carry
  only an A compiler-TLS slot and generation, never a client, page, or
  allocator; empty entries are reused and new nodes are appended only when the
  current live entries are occupied. A foreign exact-address scan restores
  each entry before it considers the next. A query claims and restores only
  the matched entry without acquiring a page engine or scheduler; a free
  returns the scheduler to `PARKED` before that A resumes. While A temporarily
  resumes, its moved session keeps its own entry `BUSY`. A second A may already
  have a separately parked active entry, but the source scheduler still
  serializes every PageMap operation and the registry never exposes either
  client identity. General foreign worker `realloc` beyond the exact
  detached-owner replacement, usable-size outside these exact routes, general
  single-page/adoption/reclaim routes, arbitrary concurrent worker setup or
  allocation, reclamation, and pthread stress remain incomplete.

The selected C evidence also composes those two existing pointer-private
transitions: B source-publishes one exact client while A is parked, A resumes
and collects that remote head, then exits with a different small/medium pair
for fresh C to release through `NativePostExitRoute`. It is a serial,
three-worker lifecycle witness, not a general concurrent pointer dispatcher.
The companion `native_mimalloc_two_owner_exit` fixture retains the two-route
regression, while `native_mimalloc_three_owner_exit` has A1, A2, and A3 all
exit before any fresh B begins. The third OS-singleton tail is installed beside
two route-owned list members; its C fixture releases the owners in non-FIFO
order, while the Rust counterpart interleaves all three B workers' exact frees
and finishes them in a different order. Neither form exposes a sibling page or
client, and ticket zero remains unavailable until the final B completes its
own no-page lifecycle.

The critical path is now Gate 5C: source-shaped general owner exit with live
allocations. Do not add another owner-exit shape first; converge the existing
shape matrix on one validated traversal.

This is no longer primarily a "port another function" problem.

The critical path is now **integrating already-proven allocator mechanisms into the real ownership lifecycle**.

---

# EXECUTION RESET

## Stop expanding the page-shape matrix

Do **not** continue indefinitely by adding production entry points such as:

* another exact live-block-count owner-exit route;
* another homogeneous aggregate;
* another heterogeneous aggregate;
* another direct/non-direct permutation;
* another singleton/medium/large permutation;
* another mapped/unmapped permutation;

unless a failing integration gate demonstrates that pinned upstream mimalloc actually has a semantically distinct branch that cannot be expressed through the existing general machinery.

The existing narrow routes were valuable scaffolding. They established:

* queue-removal ordering;
* PageMap span lifetime;
* arena bitmap/count pairing;
* local versus remote collection;
* direct-cache repair;
* abandonment publication;
* owner-bit acquisition;
* TLD teardown ordering;
* terminal metadata and mapping release;
* failure-retention semantics.

Keep their tests.

Do not require the production allocator to retain a separate top-level control path for every test geometry.

## "Source-shaped" now means source control flow

Preserving upstream semantics does **not** mean encoding every reachable runtime state as a different Rust function or Rust type.

For the next phase, "source-shaped" means mirroring the important upstream control structure.

In particular, pinned mimalloc's thread-exit flow conceptually follows:

```
_mi_theap_collect_abandon
    -> mi_theap_collect_ex(MI_ABANDON)
    -> deferred-free processing
    -> retired-page collection
    -> generic page-queue traversal
    -> per-page collection
    -> if empty: free page
    -> otherwise: abandon page
    -> Theap/TLD teardown
```

The Rust production implementation should converge on the same shape:

1. one source-shaped owner-exit coordinator;
2. one general validated traversal over the departing Theap's pages;
3. shared page collection;
4. shared page abandonment;
5. page-kind-specific low-level mechanics only where the upstream algorithm genuinely distinguishes them;
6. one coherent transition from live thread ownership to post-thread ownership.

Tests may remain extremely specific.

Production control flow should not become a Cartesian product of those tests.

## Types should encode authority, not every geometry

Continue using Rust's type system aggressively for stable ownership boundaries such as:

* process owner;
* current-thread TLD owner;
* attached Theap;
* active page engine;
* owner-exit drain;
* abandoned-page authority;
* PageMap mutation lease;
* arena capability;
* terminal retained owner.

Do **not** attempt to encode every transient combination of:

* page kind;
* bin;
* `used`;
* `reserved`;
* full/nonfull state;
* mapped/unmapped abandonment;
* direct-cache state;
* exact live-block count;

as a distinct production typestate.

Those properties are dynamic allocator metadata in upstream mimalloc. Validate them at the transition that requires them.

Prefer:

```
coarse static authority + explicit runtime invariant validation
```

over:

```
one Rust type or function for every reachable allocator image
```

when the latter causes combinatorial implementation growth.

Generalization does not justify broad unchecked unsafe code. Keep unsafe traversal narrow, source-mapped, locally documented, and surrounded by invariant checks.

## Existing narrow routes become witnesses

Do not immediately delete the current narrow routes.

Use them as an oracle while introducing the general lifecycle:

1. run a scenario through the existing narrow route;
2. run the same scenario through the new general route;
3. compare resulting normalized allocator state;
4. migrate the regression to the general route;
5. remove the specialized production route only when it no longer expresses a distinct upstream branch.

Preserve the scenario as a regression test after removing the scaffolding.

## `native-mimalloc.md` is not a commit log

Do not append another multi-page "Current slice" section after every checkpoint.

Durable detailed state belongs in:

* `STATUS.md`;
* `docs/design/allocator.md`;
* `crabc-mimalloc/UPSTREAM.md`;
* `compat/allocator/port-map.toml`;
* `compat/allocator/known-differences.md`;
* generated reports;
* tests;
* Git history.

Keep the checkpoint section near the top of this document short and update it only when the project's critical path changes.

This document defines strategy and completion criteria.

---

# OBJECTIVE

Implement a pure-Rust, `no_std` port of mimalloc v3.5.0 as `crabc-mimalloc`, integrate it as a selectable allocator backend for crabc-libc, build rigorous differential correctness, lifecycle, stress, and performance evidence against the exact pinned upstream C implementation, and promote the Rust backend to crabc's default allocator only after the objective gates below pass.

This is a large, safety-critical subsystem.

Work incrementally, but an increment must now close a meaningful allocator capability or integration gate—not merely add another example of a capability already proven for a neighboring page shape.

---

# 1. FIXED BASELINE

Upstream allocator baseline:

* Project: `microsoft/mimalloc`
* Release: v3.5.0
* Full tag commit:

  ```
  18b08671c9302247bfb682286e6bf3cc1773f801
  ```

Pin the exact source archive and SHA-256 in `compat/upstreams.toml`.

Do not silently upgrade to a later release.

A mimalloc update requires a separate reviewable change containing:

* source diff;
* API inventory diff;
* configuration diff;
* port-map impact;
* correctness rerun;
* concurrency rerun;
* performance rerun.

Supported production platform:

* Linux only;
* AArch64 little-endian only;
* current crabc Linux kernel floor;
* supported Linux/AArch64 kernel page sizes;
* current pinned Rust nightly;
* hermetic Alpine/Docker development flow.

Explicitly out of scope:

* x86-64;
* RISC-V;
* macOS;
* Windows;
* generic future-platform scaffolding;
* mimalloc v1/v2 compatibility;
* allocator invention;
* a generic allocator strategy framework;
* generic OS abstraction for hypothetical ports;
* C/C++ production allocator code;
* glibc as normative behavior;
* runtime allocator selection;
* success-returning unsupported stubs.

Default production code must remain valid for crabc's baseline AArch64 ISA. Optional newer-AArch64 optimization profiles are later work and must never become an accidental baseline requirement.

---

# 2. DEFINITIONS OF DONE

Track these outcomes separately.

## A. Pure-Rust allocator engine

`crabc-mimalloc` provides the Linux/AArch64-applicable allocator engine with:

* `#![no_std]`;
* no production `alloc`;
* no libc dependency;
* no C/C++ compilation;
* no bindgen-generated implementation;
* no native build script;
* no recursive allocator dependency;
* no normal dependency on `libmimalloc-sys`.

## B. Lifecycle-complete malloc engine

Before worrying about every optional public `mi_*` API, the engine must be capable of safely backing normal malloc workloads involving:

* main-thread allocation;
* worker-thread allocation;
* local free;
* remote free;
* thread teardown;
* live blocks surviving owner exit;
* abandonment;
* reclamation where upstream permits it;
* terminal release;
* repeated thread churn.

This is the current critical objective.

## C. crabc libc integration

The existing crabc malloc-family ABI is backed by the Rust engine while preserving the existing musl-compatible public contract, including:

* weak/preemptible allocator symbols;
* matching allocation/free interposition;
* errno behavior;
* zero-size behavior;
* allocation alignment;
* calloc overflow;
* realloc failure preservation;
* crabc's `realloc(p, 0)` policy;
* aligned allocation behavior;
* `posix_memalign` output preservation on failure.

The C ABI policy stays in `crabc-libc`.

The allocator engine does not own `errno`.

## D. mimalloc feature parity

Every public v3.5.0 interface and compile-time mode applicable to Linux/AArch64 receives an explicit machine-readable status.

Do not infer this inventory manually.

## E. correctness evidence

Evidence includes:

* focused unit/invariant tests;
* configuration/layout probes;
* upstream mimalloc tests;
* deterministic C differential traces;
* integrated pthread scenarios;
* concurrency model checking;
* Miri host-model execution;
* fault injection;
* process-isolated invalid-use tests;
* pthread/TLS/fork tests;
* ABI/interposition tests;
* real programs.

## F. performance and memory parity

The Rust port must be non-inferior to exact C v3.5.0 within the defined promotion bands.

Performance qualification is a promotion requirement, but **informational performance smoke starts much earlier**.

---

# 3. DURABLE SCOPE

crabc may maintain a pure-Rust semantic port of a fixed mature allocator.

The rules are:

* mimalloc v3.5.0 is the fixed initial target;
* this is compatibility engineering;
* upstream algorithms, ownership transitions, data structures, memory orderings, and observable behavior are preserved until parity is established;
* Linux/AArch64 is the only implementation target;
* speculative portability abstractions are rejected;
* material algorithmic divergence requires a design note, correctness evidence, and performance evidence;
* the mature C implementation remains a permanent oracle even after leaving the default production graph.

Durable documentation must keep the source provenance and compatibility story mechanically inspectable.

---

# 4. CRATE AND DEPENDENCY ARCHITECTURE

Production dependency direction:

```
crabc-mimalloc -> crabc-core + chacha20 + zeroize
crabc-libc     -> crabc-core + crabc-mimalloc
```

Forbidden:

```
crabc-mimalloc -> crabc-libc
```

`crabc-mimalloc` may request narrowly scoped raw Linux primitives from `crabc-core` when necessary.

Do not duplicate syscall assembly merely to keep the allocator self-contained.

The focused crypto dependencies remain the boundary around the pinned ChaCha-based random machinery. Do not hand-roll crypto or PRNG cores.

Development-only tools such as Loom are acceptable.

Do not add production dependencies on:

* async runtimes;
* libc wrappers;
* serialization frameworks;
* logging frameworks;
* benchmark frameworks.

The allocator must reject unsupported production targets at compile time.

Host/Miri/Loom configurations are test instruments, not supported production targets.

---

# 5. LIBC BACKEND TRANSITION

Keep three conceptual layers:

1. backend-independent crabc malloc-family ABI;
2. temporary C mimalloc backend;
3. Rust mimalloc backend.

Use compile-time backend selection.

Initially:

* C remains the default;
* Rust is a mandatory test lane;
* exactly one backend is selected;
* there is no runtime selector.

There are **two integration stages**.

## Early shadow integration

During Milestone 5, enable enough Rust-backend integration to run:

* the allocator ABI fixture;
* pthread allocation/free tests;
* remote-free tests;
* thread-exit tests.

This should use the actual crabc facade where practical but remain nondefault.

The purpose is to expose integration defects early.

## Full shadow integration

Later, run the complete:

* startup;
* fork;
* loader;
* weak-symbol;
* interposition;
* static/dynamic link;
* workspace;
* corpus;

matrix before promotion.

Do not postpone every libc interaction until the allocator internals are supposedly "finished."

---

# 6. PORTING DISCIPLINE

Maintain `compat/allocator/port-map.toml`.

Each meaningful upstream source unit records:

* upstream file/region;
* Rust destination;
* implementation status;
* verification status;
* associated tests;
* intentional differences;
* performance qualification.

Use monotonic status dimensions such as:

* `exported`;
* `implemented`;
* `unit_verified`;
* `differential_verified`;
* `integration_verified`;
* `stress_verified`;
* `performance_qualified`.

Add `integration_verified` if not already represented by another explicit field.

## Progress is no longer source-item count

Do not treat increases in:

* source-map row count;
* implemented count;
* unit-test count;

as the primary Milestone 5 progress measure.

Those foundations are already mature enough that integration evidence is the bottleneck.

A new source-map item should represent a genuinely distinct upstream semantic unit, not a new Rust scaffolding permutation for the same source transition.

Milestone 5 progress is measured by closing its integration gates.

## Preserve upstream terminology

Keep source terminology where useful:

* page;
* heap;
* theap;
* TLD;
* page queue;
* local free;
* cross-thread free;
* remote free;
* abandoned state;
* subprocess;
* page map;
* arena;
* memory provenance;
* bitmap claim.

Do not broadly "Rustify" the design before parity.

## Preserve control structure

When upstream has a generic traversal or dispatcher, prefer porting that generic traversal or dispatcher.

Do not manufacture many separate top-level production operations merely because tests enter the flow in different concrete states.

Low-level specialization is appropriate where the upstream source itself distinguishes behavior.

---

# 7. RUST UNSAFETY AND TYPESTATE POLICY

Keep:

```
#![deny(unsafe_op_in_unsafe_fn)]
```

Every unsafe function states its caller obligations.

Every nontrivial unsafe block explains the invariant that makes it valid.

Avoid long-lived Rust references over allocator metadata whose aliasing cannot satisfy Rust reference rules.

Use deliberately:

* raw pointers;
* `UnsafeCell`;
* atomics;
* strict-provenance-compatible address operations;
* short-lived validated projections.

## Typestate rule

Use types to make **authority and lifetime phases** impossible to confuse.

Examples:

* current-thread versus process owner;
* live versus detached TLD;
* mutable PageMap lease versus immutable publication witness;
* live page engine versus exit drain;
* abandoned-page authority versus live-thread authority;
* released versus terminal-retained mapping.

Do not require Rust types to encode every transient numerical page state.

A runtime page with:

```
kind = Large
used = 2
reserved = N
```

does not inherently need a unique production owner type merely because a regression test exercises that exact state.

Instead:

1. the containing owner type proves authority;
2. the transition validates the required page metadata;
3. the shared algorithm executes;
4. postconditions are validated in tests.

This distinction is critical to preventing typestate explosion.

---

# 8. TEST-ONLY ALLOCATOR STATE AUDITOR

Add or consolidate a test-only state auditor capable of checking global allocator consistency after significant operations.

The auditor may be expensive and must not affect production codegen.

It should verify applicable invariants such as:

* each live owned page belongs to exactly one valid queue;
* each abandoned page has the expected owner/map state;
* Theap `page_count` matches traversal;
* intrusive list predecessor/successor relationships are valid;
* direct-cache entries match queue heads;
* PageMap membership covers exactly the expected page span;
* large pages own the full required span;
* arena bits and counts agree;
* abandoned bitmap/count pairs agree;
* metadata marked released is unreachable;
* OS-abandoned list membership is coherent;
* local and remote free counts are internally possible;
* TLD/Theap/Heap list relationships are coherent;
* process thread counters return to the expected value;
* no terminal owner is silently forgotten.

Use this auditor heavily in integration scenarios.

Do not replace source-specific focused assertions with only one giant checker; use both.

The purpose is to make generalized lifecycle testing practical without manually reproducing the same bookkeeping assertions in every test.

---

# 9. EXACT UPSTREAM CONFIGURATION

Keep deterministic configuration probes for the pinned C build.

Capture relevant `MI_*` values and compare important C/Rust layout assumptions.

Rust internal layout need not be C-identical when the algorithm does not rely on it.

Document deliberate differences.

Do not assume:

* 4 KiB kernel pages;
* one userspace VA width;
* Armv8.3 availability.

Keep optional architecture-specific profiles separate.

---

# 10. LINUX/AARCH64 PRIMITIVE LAYER

Use `crabc-core` for the raw Linux primitives required by upstream semantics.

Inventory and preserve behavior for:

* mmap/reservation;
* unmap;
* commit/decommit;
* purge/reset;
* protect/unprotect;
* remap where applicable;
* page size;
* monotonic time;
* process/thread identity;
* yield;
* entropy;
* NUMA information;
* memory advice;
* relevant process information.

Do not call crabc's public libc ABI from the allocator.

Keep memory provenance explicit.

Fault injection belongs at this primitive boundary.

Use compile-time selection for:

* production Linux/AArch64;
* host model;
* Loom/model components;
* deterministic fault injection.

Do not create a generic public OS trait.

---

# 11. BOOTSTRAP AND PROCESS INITIALIZATION

Preserve upstream's allocation-free bootstrap principles.

Initialization must be:

* idempotent;
* race-safe;
* reentrancy-safe;
* allocation-free until primitives are ready;
* valid through lazy first allocation;
* valid through explicit crabc startup;
* safe during diagnostics and entropy fallback.

The startup context remains raw and nonowning.

It may provide:

* page size;
* auxiliary-vector data;
* `AT_RANDOM`;
* raw environment;
* required process startup facts.

Do not depend on libc environment APIs.

Do not use `/proc/self/environ` as a substitute for startup plumbing.

Keep deterministic test entropy.

Test:

* first allocation before explicit initialization;
* concurrent first entry;
* primitive failure;
* entropy failure;
* PageMap failure;
* partial initialization;
* diagnostics during initialization failure.

---

# 12. THREAD/TLS LIFECYCLE IS THE CURRENT CRITICAL PATH

mimalloc v3's thread/Theap model is core allocator machinery.

The implementation must ultimately support:

* fast current/default Theap lookup;
* dynamic versioned TLS slots;
* key allocation/reuse;
* stale generation rejection;
* TLD state;
* lazy thread initialization;
* Theap attachment;
* page-bearing allocation;
* remote frees;
* abandonment;
* thread teardown.

Keep direct compiler TLS for the hot path where appropriate.

Do not implement allocator lifecycle through public pthread keys.

crabc-libc owns the lifecycle placement:

* allocator thread attachment before user thread start;
* allocator teardown only after cleanup handlers and pthread TSD destructors;
* exactly-once teardown;
* correct main-thread initialization;
* explicit lifecycle operations consistent with automatic lifecycle.

The existing no-page bridge is useful groundwork.

It is not the endpoint.

The immediate requirement is to evolve from:

```
attach -> bounded pointer-free page round trip -> detach
```

to:

```
attach -> persistent page-bearing allocator owner
       -> arbitrary ordinary allocation/free activity
       -> remote interactions
       -> source-shaped owner exit
       -> detach
```

Do not add another special adapter for each intermediate shape.

Evolve one integration seam.

---

# 13. CROSS-THREAD FREE

Translate the pinned remote-free protocol exactly before optimizing it.

For every participating atomic field document:

* represented state;
* permitted readers/writers;
* publication operation;
* consuming operation;
* ownership transition;
* memory ordering;
* ABA/version defense;
* destruction/reuse condition.

The production transition functions should remain the same functions modeled by Loom wherever practical.

Do not maintain a separate "verified version" of the protocol.

Once the basic atomic protocol is unit/model verified, priority shifts to proving it in the actual page-bearing pthread lifecycle.

A remote-free implementation is not Milestone-5-complete merely because its CAS loop passes Loom.

---

# 14. GENERAL OWNER EXIT AND ABANDONMENT

Implement one general source-shaped thread-exit path.

The high-level transition must be able to encounter a realistic mixture of qualifying pages across the Theap's queues.

It must not require callers to first classify the entire departing Theap into a named Rust route such as:

* all medium;
* all large;
* exactly one medium and one large;
* exactly two blocks;
* one singleton plus regular;
* etc.

Instead:

1. preflight the live Theap and its ownership;
2. process deferred/remote frees as source requires;
3. collect retired pages;
4. traverse queues using the pinned source order;
5. collect each page;
6. free pages that become empty;
7. abandon pages still containing live blocks;
8. publish exactly the required abandoned ownership state;
9. tear down Theap/TLD only after no state still requires their lifetime;
10. allow subsequent frees/reclaim/release through the process-visible structures.

Per-page helpers may distinguish:

* arena versus OS;
* regular versus singleton;
* direct-small behavior;
* large-span geometry;
* mapped versus initially-unmapped abandoned state;

when the source algorithm genuinely distinguishes those cases.

Those helpers must not force the **top-level thread-exit API** to become page-shape-specific.

The existing narrow routes provide the regression matrix for this work.

---

# 15. MILESTONE 5 INTEGRATION GATES

Milestone 5 is now the only primary implementation frontier.

Do not proceed into broad optional APIs, generalized arena features, secure modes, or nonquiescent fork repair while these gates remain incomplete, except for work directly required to unblock a gate.

## Gate 5A — persistent page-bearing pthread lifecycle

Status: complete. The retained test-only worker witness keeps one engine
through mixed local allocations and normal teardown.

Goal: prove that a real later worker can be an allocator owner rather than a pointer-free round trip.

A worker must be able to:

* attach through the real lifecycle;
* retain a page engine for the duration of its allocator activity;
* allocate multiple live objects;
* use multiple bins;
* span multiple pages;
* exercise representative small, medium, large, and singleton paths;
* locally free objects;
* reuse locally freed space;
* return with all memory freed;
* run normal allocator teardown;
* restore allocator/TLD metadata to the expected baseline.

The engine must not require ticket zero to alternate exclusive page ownership with one worker for every operation.

The relevant process-wide structures should be safely shareable according to the upstream design.

Acceptance:

* focused Rust integration tests;
* prefixed C pthread fixture;
* state-auditor clean;
* no PageMap or arena ownership leaks;
* TLD/Theap counters return to baseline;
* repeated worker creation works;
* existing narrow page tests remain green.

## Gate 5B — remote free while owner remains alive

Status: complete. The private live-owner witness fills one small page, passes
two distinct opaque remote-free capabilities from A to joined B/C pthreads,
and requires A's ordinary allocation path to false-collect and reuse both
exact blocks before normal teardown. Focused state auditing proves each of
three fresh A workers restores PageMap, arena, TLD, and Theap state to the
retained baseline; the source total-thread sequence remains intentionally
monotonic.

Goal: pointers genuinely cross threads.

Required deterministic scenarios:

1. thread A allocates, thread B frees, A collects;
2. A continues allocating after remote frees;
3. remote-freed blocks become reusable;
4. multiple remote producers publish to one owner;
5. partial remote frees on nonfull pages;
6. remote frees involving full-page transitions;
7. remote publication concurrent with owner collection at explicitly synchronized race points.

Use logical pointer handoff through the test harness.

Acceptance:

* existing Loom protocol models pass;
* real pthread tests pass;
* relevant source-state auditor checks pass;
* deterministic high-level C/Rust differential traces pass where observable semantics can be normalized;
* no lost or double-consumed remote block;
* no unexpected permanent page retention.

## Gate 5C — owner exits with live allocations

Goal: prove the actual reason mimalloc needs abandonment.

Required scenarios:

1. A allocates; A exits; B frees the remaining object;
2. A exits with multiple live pages;
3. those pages span multiple bins and page kinds;
4. some remote frees arrive before owner exit;
5. some arrive after owner exit;
6. a page becomes empty during exit collection;
7. another remains live and is abandoned;
8. another thread reclaims/adopts abandoned memory where pinned upstream permits it;
9. final client free releases all PageMap/bitmap/metadata/arena ownership in source order;
10. OS-backed terminal release remains failure-safe.

At least one test must contain a genuinely mixed departing Theap rather than selecting a special route before calling owner exit.

The current mixed witnesses cover scenario 5 only through three bounded,
synchronous same-page B/C/D publication groups. One uses the existing
direct-small page; one uses three remaining clients from the first full-medium
page after its pre-exit remote free has made it mapped and non-full; and one
uses three remaining clients from a distinct full medium after A locally frees
one client before exit. The latter reaches the aggregate already mapped and
non-full, so it exercises the same generic regular-page path without adding a
second medium route. In every case B has already claimed the low owner bit,
and C and D can each append one opaque private client before B collects both
through the normal source unown/release tail. The fixed preparation and active
parked-session regressions carry a group only as three private
generation-checked ledger keys plus its source-page kind; matching
direct-small and mapped-medium producer types prevent a callback for one shape
from consuming the other. A missing or mismatched publisher retains the route
and A's admission claim instead of falling through B's ordinary no-page
finalizer; the mapped-medium missing-publisher regression observes ticket zero
remain retained after B finishes. Neither path claims general concurrent
post-exit free routing.

The direct Rust mixed-page regression additionally covers scenario 8 after
the aggregate has been reduced to its final mapped regular member: its fresh
owner selects that member only through an opaque current client and the pinned
bitmap claim, reuses the released source block, drains the inherited live
client, and completes ordinary terminal release. The native aggregate route
can reach that already-proven edge only on its final exact C free, after its
private ledger has reduced to one normal-request member with A's recorded
force-collectable local-free fact. The natural C ABI alignment is deliberately
recorded as normal provenance; wider alignment remains sequential-free-only.
This does not make the generic pointer-private B runtime route an aggregate
reclamation interface.

At the lower route-selection boundary,
`main_heap_page::tests::later_thread_exit_mapped_one_block_handoff_rejects_then_general_route_releases_live_pages`
keeps the legacy sole-page helper's `NotOnlyPage` refusal for a live mapped
medium plus a live arena singleton. It then consumes that same returned drain
through `MainHeapThreadProcessPageExitDrain::abandon_mapped_regular_pages_to_process_route`,
tears down the old Theap/TLD, and terminally releases the medium followed by
the singleton. This demonstrates that the legacy narrow capability is not a
fallback owner-exit path; it does not by itself satisfy the broader Gate 5C
acceptance contract.

The default-off direct runtime witness
`crabc-mimalloc/tests/native_post_exit_failed_os_release.rs` covers scenario
10 at the opaque B-side boundary. A first builds the existing genuinely mixed
aggregate and transfers it through the general traversal. B receives only the
one OS-aligned client; an injection makes the next source `munmap` fail when B
offers that exact address. The route returns `Retained`, remains the registry's
one retained stable entry after B has completed its own no-page lifecycle, and
keeps ticket zero unavailable. Clearing the injection cannot retry or complete
the source route, so neither A's parked scheduler token nor its worker
admission claim is accidentally released; the same default-off scalar audit
observes that B's ordinary finish removes only B's claim and leaves A's exact
claim counted. Its matching successful aggregate witness observes two claims
after B attaches and before its terminal free, then zero only after B consumes
the typed completion. The injection hook is test-feature
only and exposes no route, client, PageMap, or allocator capability. This is
bounded failure evidence, not closure of the broader Gate 5C contract.

Acceptance:

* one general production owner-exit traversal handles the scenario;
* existing specific geometry tests are routed through or shown equivalent to it;
* no new top-level production route is required solely because the test changes a block count;
* PageMap spans survive exactly as long as required;
* all terminal ownership is either released or explicitly retained by a unique owner;
* old TLD/Theap state is not accessed after teardown.

## Gate 5D — churn and stability

Exercise repeated:

* thread creation/destruction;
* local allocation/free;
* cross-thread free;
* owner exit with live allocations;
* abandoned-page reclamation;
* mixed page classes.

Provide both:

* deterministic bounded development test;
* larger soak lane.

Track at minimum:

* live TLD count;
* metadata high-water mark;
* arena reservations;
* PageMap registrations;
* abandoned-page counts;
* outstanding process owners.

After warmup, allocator metadata must not monotonically grow merely because threads churn.

Acceptance:

* no deadlock;
* watchdog clean;
* no lost ownership;
* no unbounded metadata growth;
* no PageMap growth leak;
* no abandoned-page count leak;
* applicable upstream stress tests pass through the Rust adapter.

Current preliminary upstream evidence is deliberately narrower than that final
criterion: `allocator --full` applies the reviewed v3.5.0
`test/test-stress.c` adaptation with `NTHREADS=1` and the fixed
`1 1 2` invocation. It preserves the source allocation, zero/cookie,
realloc, retained-object, transfer-buffer, and cleanup workload, but its main
thread participates as the sole worker, so the source pthread loop starts at
one and creates no pthread. The adapter hard-rejects libc, heap, theap-walk,
subprocess, leak, and large-object modes. This is source-derived
single-creating-thread stress evidence only; it neither proves nor closes the
required upstream cross-thread transfer, remote-free, thread-recreation, or
broader owner-exit acceptance.

## Gate 5E — minimal real crabc-libc shadow backend

Status: in progress. `./scripts/dev.sh allocator-shadow` builds the ordinary
owned sysroot, then rebuilds only `crabc-libc` with
`native-mimalloc-shadow` and runs the allocator ABI fixture, the pthread
TSD-destructor local-allocation fixture, a pthread owner-exit fixture, and a
pthread live-owner remote-free fixture, plus the exact initial-thread remote
free fixture. It proves `malloc`, `calloc`,
`realloc`, `free`, aligned allocation, and usable-size behavior on the initial
thread; one exact still-live initial-thread normal/aligned client freed by an
attached worker through the source atomic remote head and then collected by
ticket zero; bounded worker-local allocation/free with all-free post-destructor
finish; one live-C-block aggregate where A exits with direct-small and
non-direct-small blocks, a medium block, a regular-large block, an unaligned
arena singleton, and an OS-aligned singleton, and B frees each exact address;
that aggregate also runs one A-side TSD destructor that allocates and frees
locally through normal return, `pthread_exit`, and deferred cancellation. Its
cancellation path first runs a cleanup handler that allocates and frees, then
the TSD destructor, before A may create the deferred route;
one source-produced sole mapped
regular page where A locally frees a sibling before exit and B then frees the
remaining exact address; and one live parked-A exact remote publication where
B frees the supplied C block, restores `PARKED`, and A resumes ordinary
allocation before its all-free finish. A separate C fixture composes that
live remote publication with normal A-side collection and a later regular
owner exit, whose fresh C releases the remaining exact addresses. The
post-exit registry route keeps
addresses private, lets fresh B query an exact source-recorded usable extent,
free that exact client, or perform one exact source-shaped `realloc`: B first
records a normal-alignment local replacement, copies the bounded prefix, and
only then invokes the existing typed free of A's client. A failed replacement
leaves A's client live, while a terminal source failure retains both owners.
The route retains A's admission and the dormant-pair scheduler through its
final PageMap release, then places that typed completion in B's TLS until B
completes its own no-page lifecycle. The sole branch uses the existing mapped
regular failed-reclaim free path and does not expose adoption, reclaim, or
allocation-time authority to C.
The live route keeps addresses private to each A ledger. Its
`NativeLiveRemoteOwnerRegistry` has stable metadata-backed entries that store
only one A TLS slot/generation; an empty entry is reused and a new node is
appended only when all current entries are live. Fresh B/C publishers scan only
to prove one exact address: every foreign entry is restored before the next is
considered, and no entry, address, page, or allocator capability escapes. A
query claims and restores its matched entry without borrowing a page engine or
scheduler; each later free performs one complete `PARKED -> BUSY -> PARKED`
operation before restoring that entry. It never falls back to the C allocator.
This does not claim a general owner-exit pointer domain: the
selected-only `tests/native_mimalloc_owner_exit_realloc.rs` fixture proves one
synchronized exact A/B route uses B allocation, bounded prefix copy, and the
existing terminal A free, while invalid replacement size preserves A's
original client. Usable size outside these exact routes, general
single-page/adoption/reclaim routes,
or arbitrary worker allocation beyond the bounded live-entry witnesses remain
unavailable, so this gate remains open.
The same selected lane runs `pthread_atfork` as a narrow fork smoke: the
original initial thread first allocates and frees so its permanent owner is
all-free dormant, then ordinary `fork` runs the public handler order. No
handler allocates; after the child callback and after the parent joins, each
side independently performs `malloc`/`realloc`/`free`. This proves only the
zero-later-admission copied initial-thread image, not inherited live pointers,
lock repair, multithreaded fork, or general child allocator recovery, and does
not close Gate 5E.
The focused `crabc-mimalloc/tests/native_post_exit_lifecycle.rs` regression
pauses B after its terminal exact free and proves ticket zero remains blocked
until B's normal finish consumes that completion.
`crabc-mimalloc/tests/native_post_exit_split_releaser_lifecycle.rs` proves the
same route may cross two sequential later-worker lifecycles: nonterminal B
frees the OS, arena, and large tails then completes its own no-page teardown;
fresh C frees the remaining medium and small clients, pauses after the terminal
source free, and only C's normal finish releases A's parked scheduler token and
admission. It is a serialized exact-free proof, not concurrent pointer routing.
`crabc-mimalloc/tests/native_sole_post_exit_lifecycle.rs` proves the same
ordering for the source-produced sole mapped-regular result.
`crabc-mimalloc/tests/native_two_post_exit_lifecycle.rs` keeps the original
two-route regression. `crabc-mimalloc/tests/native_three_post_exit_lifecycle.rs`
interleaves every exact free among three attached B workers after all three A
workers have exited, then finishes those B lifecycles in a different order.
`tests/fixtures/native_mimalloc_three_owner_exit_test.c` repeats the same
three-route shape through the selected C ABI with a non-FIFO release order.
Together they prove the metadata-backed registry can retain three independently
published A routes: each B removes only its own clients and parked scheduler
count, and the final B lifecycle is the only one that restores ticket zero.
`crabc-mimalloc/tests/native_post_exit_registry_reuse.rs` additionally holds
B1 after its terminal source release, publishes A3 beside a still-live sibling
route, and proves that reusing B1's now-empty registry entry neither consumes
B1's completion nor reopens ticket zero before B1's own normal finish.
The feature-gated, scalar-only
`crabc-mimalloc/tests/native_post_exit_registry_high_water.rs` then establishes
three concurrent detached routes and repeats eight complete A/B epochs. It
proves that the registry's published metadata-node count stays at that warm
three-entry high-water, every entry returns to empty, and no retained entry is
hidden behind the process-lifetime storage; the audit returns no route, client,
page, allocator, or release capability.
`crabc-mimalloc/tests/native_post_exit_with_local_session.rs` establishes B's
own parked local session before B releases A's exact aggregate clients. Its
exact usable-size queries, one bounded detached replacement, and last A free
all run beside that parked session; the latter transfers the terminal
completion beside it. Its feature-gated scalar audit observes two admissions
until B completes its own owner exit, then one admission for B's successor
route until C terminally releases and finishes it. B then detaches its
still-live local client into B's successor route. A fresh C releases that
successor before ticket zero can reactivate. The selected owner-exit C fixture repeats the
pre-existing-local-session query/free boundary through the shadow ABI and
drains B locally before teardown.
`crabc-mimalloc/tests/native_live_remote_free.rs` and
`tests/fixtures/native_mimalloc_live_remote_free_test.c` prove the bounded
live A/B/C handoff: two independently attached publishers race distinct exact
clients, one matching registry entry serializes them, and A collects both
through the direct runtime and selected libc artifact.
`crabc-mimalloc/tests/native_two_live_remote_owners.rs` and
`tests/fixtures/native_mimalloc_two_live_remote_owners_test.c` then park A1
before A2 enters its own setup transition, leaving two registry entries active
before either fresh B begins. B1/B2 each query and free only their respective
exact address; the entries remain private while the scheduler serializes the
two source operations, both A sessions resume and finish normally, and ticket
zero reactivates. This proves neither an arbitrary pointer registry nor
concurrent PageMap mutation.
The feature-gated, scalar-only
`crabc-mimalloc/tests/native_live_remote_owner_registry_reuse.rs` warms that
two-entry live-owner high-water, then completes four more A1/A2/B1/B2 epochs.
It proves the published metadata-node count stays flat, all entries return to
empty, and no retained entry is hidden behind process-lifetime storage; its
audit returns no entry identity, TLS address, route, client, page, allocator,
or release capability.
`crabc-mimalloc/tests/native_parallel_local_workers.rs` and
`tests/fixtures/native_mimalloc_parallel_local_workers_test.c` prove the
separate two-worker local-only admission boundary: A's live entry remains
reserved through A's temporary resumes while B parks, locally frees, and
finishes B's own allocation; then A finishes and ticket zero reactivates.
The selected C comparison repeats 128 fresh process epochs, so a scheduler
CAS that loses only because a peer changed `PARKED(n)` remains retryable while
the runtime still records `BUSY` or a nonzero parked count; `READY` and
terminal states remain failures. This does not broaden the two-worker local
boundary into concurrent PageMap mutation.

Once 5A-5D work through the prefixed allocator harness, route the existing crabc allocator fixture through the compile-time Rust backend.

Keep C as default.

Prove at least:

* malloc;
* calloc;
* realloc;
* free;
* aligned allocation;
* usable size;
* pthread local allocation;
* pthread remote free;
* pthread owner exit.

This is the first point where the Rust engine has demonstrated that it can plausibly replace the ordinary production malloc engine.

It is still not default-promotion evidence.

---

# 16. FORK CORRECTNESS

Keep the bounded conservative quiescent fork behavior. On libc's direct
`fork` path, the private allocation-free admission gate first excludes every
later owner. It may preserve only the original ticket-zero image when it has
no permanent page owner or that owner is still `AwaitingFreshPage` or has
reached the all-free `DormantExistingArena` state; a live client, active
PageMap operation, parked engine, retained route, or any later admission
disables the child bridge. The selected `pthread_atfork` smoke proves child
and parent allocation only for that all-free initial-thread case, outside the
public callbacks.

The default-off native terminal-proof regression also crosses raw fork while a
fresh B holds A's already-terminal post-exit proof in B TLS. Both A's deferred
admission and B's live attachment remain counted, so the child disables this
bridge rather than attempting route repair; the parent preserves its route and
B later performs the only normal finish that can release A's claim. This is
additional conservative-child evidence, not inherited-route recovery.

Do not allow general nonquiescent fork repair to distract from Milestone 5.

After general page-bearing thread ownership is working, audit exact pinned v3.5.0 behavior and define the crabc child guarantee.

Eventually prove:

* parent remains valid after multithreaded fork;
* child does not inherit permanently deadlocked locks;
* child allocator TLS is repaired;
* vanished-thread ownership is conservatively repaired or handled;
* child can allocate/free/realloc;
* parent continues normally.

Fork hooks must not allocate.

Full fork hardening belongs with broad crabc-libc shadow integration unless an earlier simple fork smoke reveals a foundational lifecycle defect.

---

# 17. PUBLIC API AND FEATURE PARITY

Generate the public inventory mechanically from pinned v3.5.0.

Include:

* standard operations;
* extended allocation;
* aligned operations;
* usable size;
* heaps;
* theaps;
* arenas;
* subprocesses;
* collection/purge;
* statistics;
* options;
* callbacks;
* lifecycle;
* visitation;
* managed-memory APIs;
* compile-time modes.

Classify every item explicitly.

Keep two separate dashboards:

1. **malloc-engine readiness**
2. **complete Linux/AArch64 mimalloc v3.5.0 parity**

The first is now dominated by Milestone 5.

Do not let optional API coverage distract from it.

---

# 18. SECURE, DEBUG, GUARDED, AND STATISTICS MODES

Keep exact mode inventory and compile-time profiles.

Do not approximate upstream secure/debug semantics.

These modes remain important for complete parity, but they are not current Milestone-5 blockers unless a mode exposes a correctness defect in shared production machinery.

Use isolated processes for intentional abort/fault tests.

Diagnostics and callbacks must remain allocator-reentrancy-safe.

---

# 19. CORRECTNESS ORACLES

Use:

* pinned C mimalloc v3.5.0 for allocator-engine semantics;
* pinned musl for crabc's standard allocator facade;
* Linux kernel behavior for VM primitives;
* deterministic shadow models for allocation/content lifetime;
* crabc's existing ABI for startup, pthread, fork, interposition, and errno.

Do not use glibc as normative behavior.

For apparent upstream-invalid or unsafe behavior:

1. reduce it;
2. determine whether valid-program semantics specify it;
3. do not reproduce memory unsafety merely for invalid-input visual parity;
4. document deliberate hardening;
5. preserve valid-program behavior.

---

# 20. C ORACLE

Keep the C oracle hermetic and independently pinned.

Record:

* source hash;
* compiler;
* flags;
* resolved configuration;
* artifact hashes;
* symbols.

Do not use the bundled `libmimalloc-sys` source as the authoritative oracle unless its exact equivalence has independently been established.

---

# 21. PURE ARITHMETIC AND LAYOUT TESTING

Retain exhaustive fast tests around:

* overflow;
* rounding;
* alignment;
* bin boundaries;
* object capacity;
* PageMap indices;
* bitmap arithmetic;
* arena slices;
* pointer encodings;
* allocation limits;
* kernel page sizes;
* VA boundaries.

These remain an inexpensive regression gate.

---

# 22. DIFFERENTIAL TRACE HARNESS

Continue toward deterministic C/Rust operation traces.

Use separate processes.

Use logical allocation IDs rather than addresses.

The trace language must eventually include:

* allocate;
* zeroed allocate;
* free;
* realloc;
* aligned allocation;
* usable size;
* fill/check;
* collect;
* heap operations;
* thread creation;
* cross-thread free;
* thread exit;
* arena operations;
* fault injection.

For Milestone 5, prioritize a deterministic **lifecycle trace subset** containing:

* thread A attach;
* A allocate ID 1;
* publish ID 1 to B;
* B free ID 1;
* A collect/reuse;
* A allocate IDs 2..N;
* A exit while selected IDs remain live;
* B free post-exit IDs;
* C allocate/reclaim where applicable.

Normalize internal events only where doing so gives high-value differential evidence.

Do not compare pointer values.

Keep minimized failing traces permanently.

---

# 23. UPSTREAM TEST SUITE

Run relevant pinned upstream tests against:

1. exact C v3.5.0;
2. Rust test C API adapter.

Track unchanged/adapted/not-applicable/blocked/pass/fail mechanically.

During Milestone 5, prioritize upstream tests exercising:

* stress;
* cross-thread free;
* thread exit;
* heap/Theap lifetime.

Do not block the lifecycle critical path on unrelated optional APIs.

---

# 24. FAULT INJECTION

Continue deterministic, allocation-free fault injection.

Important Milestone-5 additions include failures during:

* worker metadata creation;
* TLD/Theap creation;
* page allocation;
* PageMap changes;
* abandonment publication;
* terminal release;
* OS release.

A failed lifecycle transition must leave one mechanically understandable owner.

Never "recover" by losing provenance.

---

# 25. MIRI AND LOOM

Miri remains valuable for:

* pointer arithmetic;
* metadata initialization;
* ownership transitions;
* local allocation/free;
* realloc;
* strict provenance.

Loom remains focused on actual atomic protocols.

The critical rule is:

> Model the generic protocol, not every page geometry.

Do not create one Loom model for medium, another for large, another for two blocks, etc. unless the atomic state machine itself is different.

Page geometry belongs primarily in deterministic ordinary tests.

Concurrency interleavings belong in the protocol model.

---

# 26. STRESS MATRIX

The stress design remains broad, but phase it.

## Milestone-5 stress first

Prioritize:

* private allocation/free;
* producer allocates / consumer frees;
* many producers / one owner;
* random cross-thread handoff;
* owner exits before remote free;
* repeated thread churn;
* partial page liveness;
* mixed small/medium/large;
* reclamation after abandonment.

Each run records:

* deterministic seed;
* operation count;
* watchdog status;
* final liveness;
* metadata high-water;
* report artifact.

Broader secure/arena/subprocess stress follows the corresponding features.

---

# 27. CRABC-SPECIFIC INTEGRATION

Preserve the existing allocator fixture.

Expand it rather than replacing it.

Eventually cover:

* zero-size allocation;
* required alignment;
* distinct allocations;
* calloc;
* realloc;
* errno preservation;
* aligned allocation;
* usable size;
* constructors;
* thread initialization;
* TSD destructors;
* cleanup handlers;
* cancellation;
* fork;
* interposition;
* static/dynamic linking;
* shared objects;
* loader interactions;
* exit behavior.

## Canonical commands

Maintain focused commands equivalent to:

```
./scripts/dev.sh allocator --quick
./scripts/dev.sh allocator --full
./scripts/dev.sh allocator-perf --smoke
./scripts/dev.sh allocator-perf --full
```

### Command semantics

`allocator --quick`:

* fast current-development gate;
* focused unit tests;
* source ratchet;
* small differential set;
* Loom protocol smoke;
* basic integration scenario once available.

`allocator --full`:

* comprehensive correctness and lifecycle evidence for the **currently claimed milestone**.

During Milestone 5, it runs the checked-in `m5-gate-v3.5.0.json` full lane:
the pinned C-oracle/M4 adapter/TLS/Loom prerequisites, one full-only
source-derived creating-thread `test-stress.c` witness, and a 128-cycle,
30-second deterministic ticket-zero lifecycle witness. Its report classifies
executed bounded evidence separately from Gate 5C--5E acceptance blockers.
While the milestone is incomplete it returns a nonzero status, but must name
the particular unmet gate rather than emit a permanent generic “future
milestone unavailable” result.

Once Milestone 5 is accepted, `allocator --full` should pass for the claimed M5 surface even though M6-M10 remain future work. Later features may be marked blocked/not-yet-applicable in the generated report without turning an accepted earlier milestone into a synthetic failure.

Promotion requires a separate aggregate of all required milestones.

---

# 28. EARLY PERFORMANCE AND CODEGEN SMOKE

Do **not** wait until Milestone 9 to observe performance.

This does not mean optimize prematurely.

It means avoid building months of architecture without noticing an obvious hot-path mistake.

Once Gate 5A provides a stable ordinary allocator boundary, enable informational comparisons for:

* small malloc/free;
* hot-page reuse;
* medium allocation;
* large allocation;
* local free;
* code size;
* TLS lookup codegen.

After Gate 5B, add:

* remote-free publication;
* remote collection.

After Gate 5D, add:

* thread churn;
* RSS/metadata high-water.

Early measurements are:

* informational;
* reproducible;
* stored;
* not default-promotion evidence.

Do not chase small noise.

Investigate large structural anomalies such as:

* accidental global locking;
* allocator recursion;
* unexpected TLS helper calls;
* gross syscall amplification;
* unbounded metadata;
* major code-size duplication;
* obviously catastrophic throughput.

The full statistical non-inferiority gates remain Milestone 9.

---

# 29. PERFORMANCE QUALIFICATION

For final qualification compare:

A. comparable opaque C/Rust allocator boundaries;

B. actual integrated crabc C/Rust builds.

Measure:

* throughput;
* CPU;
* batched latency;
* tail latency;
* cycles/instructions where reliable;
* branches/cache misses;
* syscall counts;
* page faults;
* reserved/committed memory;
* RSS/PSS/USS;
* cgroup peak;
* allocator statistics;
* startup;
* code/data size;
* final binary size.

Use a qualified native AArch64 environment for promotion.

Apple-Silicon Docker is useful for development but is not automatically a promotion-quality performance host.

---

# 30. INITIAL PROMOTION BANDS

Retain explicit non-inferiority bands against exact pinned C v3.5.0.

Default-profile starting targets:

Throughput:

* suite geometric-mean lower 95% bound >= 0.95;
* no critical workload lower bound < 0.90 without a reviewed exception.

Tail latency:

* critical p99 upper ratio bound <= 1.10.

Memory:

* suite geometric-mean peak RSS/PSS upper ratio <= 1.05;
* no critical workload > 1.10 without explanation;
* no unbounded growth.

System behavior:

* no material unexplained syscall amplification;
* no material unexplained page-fault amplification;
* no metadata leak.

Code size:

* investigate >10% allocator-attributable growth.

Threshold changes are independent reviewed changes, not a way to make the current implementation pass.

---

# 31. AARCH64 CODEGEN AUDIT

Inspect optimized:

* small allocation;
* local free;
* remote-free publication;
* PageMap lookup;
* bin lookup;
* TLS lookup;
* aligned fast path.

Look for:

* panic paths;
* bounds checks;
* division;
* formatting/unwind calls;
* TLS helper calls;
* missed inlining;
* unnecessary fences;
* SeqCst overuse;
* unnecessary zeroing;
* code duplication.

Do not optimize on intuition.

First demonstrate a real regression or obviously bad generated sequence.

---

# 32. REVISED IMPLEMENTATION MILESTONES

## Milestone 0 — scope, pin, inventory, skeleton

Existing foundational work substantially covers this milestone.

Required artifacts include:

* pinned source;
* source hash;
* no_std crate;
* dependency policy;
* API inventory;
* port map;
* oracle;
* configuration/layout baseline;
* canonical harness.

## Milestone 1 — pure foundations

Includes:

* configuration;
* arithmetic;
* types;
* atomics;
* provenance;
* random machinery;
* primitive layer;
* bootstrap types.

Evidence:

* exhaustive arithmetic/layout tests;
* C constants differential;
* host-model checks.

## Milestone 2 — memory substrate

Includes:

* VM primitives;
* metadata;
* bitmap;
* PageMap;
* arena substrate;
* initialization;
* fault injection.

Evidence:

* lifecycle and boundary tests;
* failure tests;
* initialization tests;
* no recursive allocation.

## Milestone 3 — single-thread allocation

Includes:

* Heap/Theap bootstrap;
* page queues;
* local allocation/free;
* page retirement/reuse.

Evidence:

* bin matrix;
* differential traces;
* repeated fill/free;
* Miri-compatible path.

## Milestone 4 — fundamental allocation operations

Includes:

* calloc;
* realloc;
* aligned allocation;
* usable size;
* medium/large/singleton;
* collection;
* OOM semantics.

Evidence:

* focused C adapter;
* upstream API subset;
* fault injection;
* fundamental differential traces.

The existing code substantially covers this substrate, although broad production backend integration remains intentionally later.

## Milestone 5 — integrated concurrency and thread lifecycle

**This is the current critical path.**

Complete Gates:

* 5A persistent page-bearing pthread lifecycle;
* 5B remote free while owner lives;
* 5C general owner exit, abandonment, reclamation, and terminal release;
* 5D churn and metadata stability;
* 5E minimal crabc-libc Rust shadow backend.

Acceptance:

* one general page-bearing later-thread lifecycle;
* one general source-shaped owner-exit traversal;
* real pointer-crossing remote-free tests;
* existing Loom protocols;
* pthread stress;
* owner-exit/remote-free tests;
* abandonment/reclamation tests;
* no deadlock;
* no lost ownership;
* no unbounded metadata growth;
* applicable upstream stress tests;
* crabc allocator fixture through Rust shadow backend;
* early performance/codegen smoke recorded.

### Hard Milestone-5 rule

Do not satisfy this milestone by enumerating the remaining page-shape permutations.

If an integration test exposes a missing state:

1. identify the exact upstream branch;
2. decide whether the general dispatcher or a genuinely source-distinct low-level helper is missing;
3. implement that semantic branch;
4. add the discovered geometry as a regression witness.

Do not default to creating another top-level route.

## Milestone 5.5 — consolidation

After the general lifecycle passes and before broadening feature scope:

* route existing narrow regression scenarios through the general lifecycle;
* delete specialized production scaffolding that no longer represents distinct upstream semantics;
* preserve all useful tests;
* split oversized production/test modules where this materially improves reviewability;
* ensure module boundaries map to allocator responsibilities rather than historical implementation slices;
* rerun full M5 evidence.

Do not perform a speculative rewrite.

This is consolidation of a now-proven design.

## Milestone 6 — heaps, theaps, arenas, subprocesses

Complete:

* first-class Heap APIs;
* Theap APIs;
* arena APIs;
* managed memory;
* subprocess API;
* destruction semantics.

Acceptance:

* upstream API tests;
* cross-thread traces;
* lifecycle/failure tests;
* complete inventory for these groups.

## Milestone 7 — options, callbacks, stats, modes

Complete:

* options/environment;
* callbacks;
* statistics;
* visitation;
* debug;
* secure;
* guarded;
* optional architecture profile.

Acceptance:

* applicable API inventory complete;
* required profiles build/test;
* wrong-use subprocess tests;
* no unclassified public holes.

## Milestone 8 — full crabc-libc shadow integration

Expand the earlier M5 shadow lane to the complete integration matrix:

* startup;
* pthread;
* fork;
* facade errno/POSIX behavior;
* weak symbols;
* interposition;
* static/dynamic link;
* loader behavior.

Acceptance:

* existing allocator tests;
* workspace tests;
* pthread/TLS/fork;
* ABI/symbol gates;
* Rust std;
* Lua;
* selected corpus.

Rust remains nondefault.

## Milestone 9 — performance convergence

Run:

* full C/Rust benchmark matrix;
* codegen audit;
* targeted optimization;
* RSS/purge investigation;
* repeated qualified reports.

Acceptance:

* throughput gates;
* latency gates;
* memory gates;
* syscall/page-fault gates;
* code-size gates;
* no correctness-ratchet regression;
* at least three qualified full reports.

## Milestone 10 — default promotion

Promotion is one small isolated change.

* switch default allocator feature to Rust;
* prove C mimalloc is absent from default production dependency/artifact graph;
* retain pinned C oracle;
* regenerate compatibility/performance reports.

Do not combine promotion with allocator redesign.

## Milestone 11 — stabilization

After evidence-backed promotion:

* remove obsolete transitional plumbing where safe;
* preserve C oracle;
* preserve differential/performance lanes;
* simplify feature flags;
* freeze v3.5.0 parity report;
* document upstream-update procedure.

---

# 33. COMPLETENESS RATCHETS

Machine-enforce:

* public API inventory;
* API implementation count;
* API verification count;
* source-map coverage;
* upstream-test coverage;
* configuration coverage;
* differential corpus;
* lifecycle-integration coverage;
* stress coverage;
* ABI contract;
* performance workload coverage.

The dashboard must distinguish:

* absent;
* implemented;
* unit verified;
* differential verified;
* integration verified;
* stress verified;
* performance qualified;
* unsupported by explicit rationale.

## Do not reward decomposition

A refactor that turns one source semantic unit into ten Rust helpers must not make the progress dashboard look ten times more complete.

The ledger describes upstream semantic coverage.

It does not score Rust function count.

## Bugs create regression artifacts

Every fixed bug adds at least one durable:

* focused test;
* minimized trace;
* Loom schedule;
* fault-injection case;
* upstream adaptation;
* integration scenario;
* benchmark workload.

---

# 34. REPOSITORY AND COMMIT DISCIPLINE

Close each milestone in its own dedicated commit. Do not carry an accepted
milestone's working tree into the next milestone. Interim commits are allowed
only when they are coherent, source-backed vertical slices of that same
milestone; they must not mix milestone scopes.

Commit subjects, paths, and checked-in artifact names should describe the
source behavior or contract they carry, rather than a temporary milestone
label. Durable machine-readable gate identifiers are the exception: they name
the acceptance criteria themselves and remain stable across implementation
commits.

Before each meaningful production change:

1. identify pinned upstream control flow;
2. identify the invariant or integration gate being closed;
3. add the failing or missing scenario;
4. implement the smallest source-faithful general behavior;
5. run focused tests;
6. run relevant model/differential tests;
7. run the state auditor;
8. update the ledger;
9. commit the coherent capability.

A commit should ideally answer a question like:

* "workers can now retain a real page engine";
* "live-owner remote free now works end-to-end";
* "thread exit now generically abandons mixed queues";
* "abandoned pages can now be reclaimed after owner exit";
* "thread churn returns metadata to a stable baseline";

rather than:

* "support one more two-block page shape."

Keep commits reviewable.

Do not hide a regression by weakening its test in the same commit unless the commit is explicitly correcting the contract with oracle evidence.

---

# 35. IMMEDIATE NEXT WORK AFTER GATE 5B

The next agent should **not** pick another page-shape exception.

Proceed in this order.

## Step 1 — evolve the general M5 integration fixture (complete)

Evolve the existing prefixed runtime evidence seam rather than creating many independent adapters.

The fixture must ultimately permit:

* process initialization;
* current-thread allocator operations;
* worker attachment;
* persistent worker allocator operations;
* pointer handoff between threads;
* worker teardown.

Keep symbols prefixed and test-only.

Do not export public `malloc`, `free`, or `mi_*` from this adapter.

## Step 2 — persistent worker-local allocator (complete)

Keep the retained narrow worker witness, and add a worker attachment capable
of retaining its page-bearing engine across multiple local operations.

Start local-only.

Use mixed allocations.

Gate 5A is closed by focused Rust state auditing and the prefixed C pthread
fixture. It does not create a general worker allocator route.

## Step 3 — real remote free (complete)

Allow blocks allocated by worker A to be freed by joined workers B/C through the real production protocol.

The bounded witness fills a small page, transfers two distinct opaque
capabilities, then proves A's ordinary allocation path collects and reuses
both exact blocks while A remains live. It includes existing Loom protocol
models, focused Rust state auditing, and the prefixed C pthread fixture.

Gate 5B is closed without adding an owner-exit shape.

## Step 4 — general owner-exit traversal (in progress)

The source-shaped regular `MI_ABANDON` traversal now has one mixed-Theap
runtime witness. Its single general aggregate contains a direct-small page
with three live clients, a non-direct-small page, one `BIN_FULL` medium page
with a joined remote free that source collection makes nonfull, a distinct
one-client large page whose joined remote free becomes all-free and releases
during that same traversal, a distinct two-client live large page, an
unchanged full medium that remains source-unmapped, one live arena singleton,
and one live OS-aligned singleton. It preserves all-free release and
old-Theap/TLD teardown and moves only an opaque post-exit aggregate route.
The runtime installs that route through one internal generic page-owner
transition: the mixed workload is only a regression builder, while TLS retains
either an active parked session with its inline-plus-metadata private client ledger or a
prepared private route. The active session resumes and re-parks the same
engine across ordinary local operations; its consuming exit transition moves
every still-live ledger member into the route without a workload-shaped client
list. Source-published members remain with source collection. Both the
session and fixed preparation path reject omitted or duplicate client sets
before suspension; fixed caller-selected preparations also reject selections
beyond their inline capacity, while a normal session grows private metadata
before an additional C allocation escapes. An active session with no locally
live client instead takes the distinct all-free page drain; no
active or prepared page owner can fall through the no-page finalizer.
Fresh B keeps the arena and OS client addresses private, must finish the
arena's PageMap-only raw-terminal tail and the OS member's
static-main-list/clipped-mapping terminal tail, and then completes its own
no-page runtime attachment before A's admission releases. On the unchanged
full-medium tail, normal sequential freeing remains source-unmapped. The three
bounded post-exit interleavings select either three existing direct-small
clients, three remaining clients on the first mapped, non-full medium after
its joined pre-exit remote free, or three remaining clients on a distinct
medium that A made non-full with one ordinary local free before exit. The
latter reaches the same general aggregate path already mapped and non-full; it
does not add a page-specific route. In every case B directly frees one after it
owns the source low bit, then C and D each publish one same-page client to the
atomic remote head in separate joined turns. B's existing collector consumes
all three clients before it may unown or release that page. This is the source
`mi_free_block_mt` -> `mi_free_try_collect_mt` interleaving, not a new general
concurrent route.
Direct Rust regressions cover the corresponding full-large and full
direct/non-direct-small source branches in both mapped and source-unmapped
states, plus live arena and OS-aligned singletons beside an initially mapped
medium member. The OS case proves source list insertion before unmapped unown
and exact removal before clipped mapping release.

Use the existing narrow route tests as regression inputs.

Do not initially delete them.

Extend the same coordinator to the remaining source-distinct page classes;
do not add another top-level route merely to encode a block count.

## Step 5 — post-exit free and reclamation (in progress)

The mixed runtime witness proves a joined fresh B, or a B with one independently
parked local session, can release all private remaining regular, arena-singleton, and OS clients—including the direct-small,
non-direct-small, and two-client live-large members, a source-unmapped full
regular page, the arena singleton's PageMap-only tail, and the OS singleton's
private-list/clipped-mapping tail—only after A's old owner has detached. B's
first direct-small free, or its first direct free of either the
pre-exit-normalized mapped medium or the distinct A-locally unfull mapped
medium, holds the low-owner claim while joined C and D each atomically publish
one further same-page private client in separate joined turns; B's
ordinary collector consumes the resulting two-node remote chain before its
normal route tail. B then
finishes its own ordinary runtime attachment; only that completed B lifecycle
may return A's terminal proof. The established sole-medium runtime route
separately proves that a distinct B receives no client identity, adopts/reuses
A's exact abandoned page, drains all inherited and B-side clients, and
completes B's engine and normal attachment before its typed proof can release
A's admission. The focused direct-small runtime route enters
`abandon_mapped_small_or_medium_to_process_route` through that same ordinary
finish boundary; its source preflight validates the complete rounded
direct-cache image and immediate local head before B receives the same opaque
regular-page adoption capability. It is separate source-class evidence, not a
claim that the aggregate traversal produces a direct-small adoption result.
Separately, the direct mixed-page regression proves that after sequential
client frees terminally release every sibling, the aggregate's one remaining
mapped regular member may cross its own consuming bitmap-claim handoff into a
fresh engine. The native pointer-private B ledger reaches that same edge only
after its arena/OS singleton subregistries have terminally cleared, the final
exact C input is its sole ledger member, and that member has A's
source-recorded normal request plus force-collectable local-free fact. Natural
C ABI alignment preserves normal provenance; wider alignment stays on the
ordinary sequential route. The route keeps the selected client opaque, uses
no raw member cache or fallback scan, and retains the target on a bitmap miss
or post-claim failure; it does not become a general B allocation or
reclamation interface.

The same dispatcher now receives one actual parked TLS session rather than
only a one-shot preparation closure. `CurrentThreadPageOwnerSession` resumes
and re-parks its exact engine between ordinary local operations, records every
still-live client in the same private ledger, and consumes that ledger through
`prepare_sequential_exit` before destructor finish. When that ledger contains
no locally live client, the dispatcher instead runs the exact all-free
page drain and attachment teardown before releasing the worker admission. Its
ordinary live-client route uses only the ordinary fresh-B consumer. For either
already-proven source interleaving, the session may instead move exactly three
generation-checked private ledger keys and their direct-small or mapped-medium
kind into the scoped B/C/D publication group; it validates all three before
transfer, so a stale or duplicate selection leaves the parked session
recoverable. B gives C and D only the two atomic producers after the source
low-bit claim. This keeps every client address and route selection private and
prevents a live session from reaching the no-page finalizer. A
source-published-only session likewise stays page-bearing: its typed all-free
drain runs the source retired-page prepass, then force-collects the joined
remote heads before it releases A's admission.
Separate isolated regressions warm ticket zero, publish either one or two
joined private clients from an active session without preparing exit, and prove
normal finish collects them, tears down A, and returns ticket zero to ready.

One additional isolated parked-session regression now creates the normal
source mixed state without adding a page-shape route: A locally frees a
direct-small client so its page remains retired, keeps one medium client live
in a distinct bin, and then consumes the session through
`CurrentThreadPageOwnerSessionHandle::prepare_sequential_exit`. The existing
aggregate coordinator must release the retired direct-small span before it
publishes the live medium to B. `PreparedOwnerExitClients` records a private
immediate-local-head fact while A still has exclusive engine ownership; only
that fact permits `TicketZeroOwnerExitFreeRoute::free_remaining_clients` to
attempt the existing final-member reclaim. A missing head is deliberately
sequential-free-only, so B cannot turn an otherwise valid route into a
post-claim retained owner. The regression proves B's ordinary terminal free,
attachment finish, and typed proof restore ticket zero only after the whole
source sequence completes.

The shared retired-page prepass also treats a failed release after queue/count
or PageMap detachment as terminal: it latches the exact page's lifecycle
poison before it returns the aggregate or all-free drain. A focused regression
injects that post-unregister failure beside a still-live medium member, proving
the old owner cannot retry the traversal or reach the normal no-page finalizer.
An independent post-queue/count-detach regression leaves the page
PageMap-published and proves that the `MainHeapThreadProcessPageExitDrain`
wrapper terminally latches every source-mutated `RetainedEngine` before its
ordinary all-free finisher can run; the retained drain keeps its PageMap
mutation lease and cannot reach the no-page finalizer.

Extend those proofs to every source-valid route that remains in scope, while
keeping each terminal failure uniquely retained.

Close Gate 5C only once the complete required source traversal and terminal
release evidence exists.

## Step 6 — churn (in progress)

The deterministic eight-cycle state audits now repeat both mixed post-exit
A/B/C/D cycles and alternating sole-medium/direct-small A-to-B reclamation
cycles. The mixed audit asserts the direct-small, non-direct-small, and
two-client live-large source pages before it makes
B create and finish its own no-page attachment after C and D's scoped
same-page publications and B's terminal release of A's opaque route, including the live
arena singleton's PageMap-only tail and the OS singleton's private-list tail;
its isolated admission model holds A and B independently, releases B after
that finish, and releases A only from the returned terminal proof. Together
they prove the permanent process/page-owner states, PageMap, arena, live-TLD,
caller-visible metadata-capability, shared-Theap, every static-main abandoned
count, and the private OS-abandoned-list baseline are restored after each one;
both metadata high-water marks plateau after warmup. The focused Rust
registry-high-water regression separately establishes three simultaneous
native detached routes and keeps that exact metadata-node count flat through
eight later full route epochs. Its audit is feature-gated and scalar-only, so
the measurement does not turn the private registry into an allocator or
pointer-routing surface. The focused Rust
integration additionally runs eight deterministic epochs from seed
`0x9e3779b97f4a7c15`, shuffling its eight core pointer-private routes (mixed
local, live-owner remote free, all-free parked TLS session, mixed owner exit,
ordinary parked TLS session owner exit, parked TLS session owner exit with the
scoped B/C/D publication group, sole-medium reclaim, and direct-small reclaim) once
per epoch and proving ticket-zero reactivation after every completed route. The
existing prefixed C fixture has
a 128-cycle, 30-second watchdog-bound `allocator --churn` lane that executes
each of its four pointer-private workers exactly once per cycle in a
seed-shuffled order; its recorded seed is `0xd1b54a32d192ed03`. The opt-in
`allocator --soak` lane runs the same four-worker schedule for 1,024 cycles
with recorded seed `0x94d049bb133111eb` under a 180-second watchdog. The
harness report records the command, seed, four routes per C cycle, exact
route-invocation count, and one scalar-only warm baseline after the first
complete cycle. Every later cycle and the final ticket-zero allocation/free
must match that baseline's process/page-owner readiness, PageMap registration
and capacity counts, arena registry, live-TLD, metadata, shared-Theap, and
regular/OS-abandonment state. It exposes no pointer, page, route, allocator,
or release capability. The direct C adapter does not create the native-shadow
post-exit registry, whose metadata-node high-water remains covered by its
focused Rust regression. The
focused Rust integration pauses the
direct-small predecessor across the ordinary-finish and terminal-proof
boundary, then repeats it through eight direct-small cycles; the state audit
and C fixture cover that same source by alternating it with sole-medium
reclamation without adding a direct-specific C ABI. The full lane also runs
the separately patched upstream `test-stress.c` workload as one creating
thread under fixed `NTHREADS=1`/`1 1 2` inputs. These serial,
bounded schedule witnesses and that constrained source-derived route do not
claim general concurrent allocation or applicable upstream thread-transfer
stress coverage; broader source classes and upstream stress coverage remain
required before Gate 5D closes.

Close Gate 5D.

## Step 7 — minimal crabc Rust backend lane

The nondefault `native-mimalloc-shadow` feature now routes the crabc allocator
fixture, the pthread TSD-destructor local-allocation fixture, and one pthread
owner-exit fixture through the compile-time Rust backend. Its C ABI boundary
preserves the existing malloc-family errno/alignment/zero-size policy, and it
never falls back to the C backend for a native pointer. The worker route
creates or resumes only the current `CurrentThreadPageOwnerSession`, records
every C-facing local block in its private inline-plus-metadata ledger, and either completes the
existing all-free page drain or moves a mixed direct-/non-direct-small,
medium, regular-large, arena-singleton, and OS-singleton aggregate,
or the existing source-produced sole mapped-regular result, into a private
`NativePostExitRouteRegistry` entry. A fresh B, or a B with one independently
parked local session, can submit only an exact address to the registry; the
route never returns an address, page, or allocator
  capability. The sole branch permits only an exact free or the same bounded
  detached replacement; it cannot become an adoption or allocation-time route.
  The aggregate branch may use the existing
final-member adoption only for its final exact normal-provenance C input after
A's owner-exit force-collection witness; it returns no page, allocator, or
general reclaim capability. Its terminal completion keeps the dormant-pair
scheduler and A's proof in B TLS until B finishes normally, which is the only
point that settles the scheduler and releases A's admission. `./scripts/dev.sh
allocator-shadow` builds the default sysroot before the selected libc artifact
so the fixture cannot accidentally run the C-backed `libc.so`.
The aggregate C fixture also keeps one local destructor allocation/free in A
and exercises ordinary return, `pthread_exit`, and deferred cancellation. The
cancellation path runs a cleanup allocation/free before the destructor
allocation/free; all three paths must complete that user phase before the live
client ledger crosses owner exit. Its one route carries direct-small,
non-direct-small, medium, regular-large,
arena-singleton, and OS-singleton clients rather than creating a C-specific
owner-exit shape.

The lane now also proves a bounded A-live remote-publication pair:
each `NativeLiveRemoteOwnerRegistry` entry holds only a parked A TLS
slot/generation, and independently attached B/C publishers validate one exact
C address against that A's private ledger. They race their publications, but
the matching entry serializes one complete `PARKED -> BUSY -> PARKED` source
operation at a time; both canonical blocks reach A's remote head before A
resumes. A separate direct and selected-C fixture parks A1 and then A2, so
two independently active entries each receive one exact B-side query/free.
The append-only metadata registry reuses empty storage and never stores a
client address; the source scheduler still serializes every PageMap operation.
Extend this bounded route through broader source-valid owner-exit results and
general concurrent allocator ownership before claiming the general pthread
remote-free evidence required to close Gate 5E.

The selected lane also proves that a live-owner entry is not a global
worker-admission lock. A second C worker can park a distinct local-only native
session while an A route is active, then free only its own client and complete
the ordinary all-free drain. A's session reserves its entry as `BUSY` while A
temporarily resumes, so no B can borrow that A in the resume interval. The
`native_mimalloc_parallel_local_workers` C fixture pauses both engines,
completes B then A, and proves ticket-zero reactivation. It does not grant
cross-worker pointer routing or concurrent PageMap mutation.

The companion selected-C composition fixture keeps the same bounded semantics:
after that live publication, A alone resumes and collects the remote head;
only afterward does it cross its ordinary deferred owner exit and give fresh C
the existing opaque aggregate route for the remaining exact clients. It does
not grant B or C concurrent engine ownership or a general pointer registry.

Keep it nondefault.

Close Gate 5E.

## Step 8 — consolidate

Only after Gates 5A-5E pass:

* remove superseded shape-specific production routes;
* retain their tests;
* split oversized modules where useful;
* update durable allocator design docs;
* run the complete M5 gate again.

Then proceed to Milestone 6.

---

# 36. FINAL EVIDENCE REPORT

The eventual final report must contain:

* starting and ending crabc commits;
* exact upstream tag/commit/archive hash/license;
* production dependency graph;
* source-map coverage;
* API status counts;
* upstream-test results;
* differential traces/seeds;
* Miri results;
* Loom results;
* lifecycle integration results;
* stress counts and seeds;
* fault-injection coverage;
* pthread/TLS/fork results;
* ABI/interposition results;
* real-program/corpus results;
* performance environment qualification;
* throughput;
* tail latency;
* RSS/PSS/peak memory;
* syscall/page faults;
* code size;
* deliberate differences;
* unqualified features;
* promotion decision.

Every success claim names the command and report artifact that proves it.

A clean Rust allocator that remains nondefault because an objective gate is missing is preferable to an unjustified default switch.

The final repository must allow a future maintainer to answer mechanically:

* Which v3.5.0 semantics are ported?
* Which public APIs exist?
* Which are differentially verified?
* Which lifecycle paths have real pthread evidence?
* Which atomic protocols have model evidence?
* Which workloads have stress evidence?
* Which workloads are performance-qualified?
* Which configurations work?
* What intentionally differs from upstream?
* Can the exact C oracle be reproduced?
* Does the default artifact contain C mimalloc?

The key completion hierarchy is:

1. source-faithful foundations;
2. **integrated malloc lifecycle**;
3. complete platform-applicable mimalloc API parity;
4. full crabc integration;
5. performance convergence;
6. default promotion.

Do not invert that order by completing every isolated page geometry before proving step 2.
