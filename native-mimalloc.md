# Native mimalloc for crabc

The crucial framing is: **do not design a new allocator**. Produce a provenance-preserving, semantically faithful Rust port of a fixed upstream mimalloc v3 release, then optimize only where measurement shows the Rust translation diverges.

The objective is to remove the C allocator from the production dependency graph while retaining mimalloc's design, behavior, concurrency model, lifecycle semantics, and performance—not to create "mimalloc-inspired" machinery.

The project remains a compatibility-engineering project, not allocator research.

---

## Current checkpoint — 2026-08-27

Current capability checkpoint: Gate 5A's bounded persistent mixed-local worker
witness is complete. Gate 5B's real remote-free integration is next.

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
* crabc-libc does not yet route its malloc family through the Rust engine;
* Gate 5A proves a bounded persistent page-bearing worker engine, but later workers do not yet own a public, concurrent, or general persistent allocator route;
* the worker runtime seam still deliberately prevents pointers from crossing its bounded local-only witnesses;
* integrated remote free, general page-bearing owner exit, reclamation, and pthread stress remain incomplete.

The critical path is now Gate 5B: real remote free while the page owner remains
alive. Do not add another owner-exit shape before that gate requires it.

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

Status: complete. The retained test-only worker witness now keeps one engine
through mixed local allocations and normal teardown; Gate 5B remains the next
integration gate.

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

## Gate 5E — minimal real crabc-libc shadow backend

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

Keep the current conservative quiescent fork behavior.

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

During Milestone 5, it must become capable of actually running the Milestone-5 integration matrix.

A permanent intentional nonzero result saying "future milestone unavailable" is not the desired steady state.

While a milestone is incomplete, a nonzero status is appropriate.

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

# 35. IMMEDIATE NEXT WORK AFTER GATE 5A

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

## Step 3 — real remote free (next)

Allow a block allocated by worker A to be freed by worker B through the real production protocol.

Prove collection and reuse while A remains live.

Close Gate 5B.

## Step 4 — general owner-exit traversal

Implement the source-shaped generic `MI_ABANDON` traversal.

Use the existing narrow route tests as regression inputs.

Do not initially delete them.

Make one mixed-Theap integration test pass.

## Step 5 — post-exit free and reclamation

Prove remaining pointers can be freed after their owner has exited.

Then prove reclaim/adoption where pinned upstream permits it.

Close Gate 5C.

## Step 6 — churn

Run repeated thread ownership cycles with mixed local/remote/post-exit frees.

Instrument metadata and PageMap high-water behavior.

Close Gate 5D.

## Step 7 — minimal crabc Rust backend lane

Route the crabc allocator fixture and relevant pthread tests through the compile-time Rust backend.

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
