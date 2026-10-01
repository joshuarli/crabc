# Complete crabc's native x86-64 functionality

## Goal

Implement this plan through integrated, qualified completion: reproduce the
frozen selected runtime on native Linux/x86-64, finish the faithful Rust
mimalloc port, make it the correctness-qualified x86 default, and promote public x86
support after complete functional evidence. “Implement plan.md” authorizes the necessary in-scope implementation,
tests, integration, and correctness-backed local promotion changes—not merely
another plan, private fixture, or intermediate handoff.

`AGENTS.md` owns scope and working rules. This file owns the complete active
completion contract and its one progress handoff. Machine-readable manifests
supply exact inventories and evidence requirements; technical guides explain
implementation and runner details, not additional independent plans. Continue
while useful independent work remains. A genuinely external blocker must remain
explicit, never be converted into a pass or a smaller completion claim.

Performance measurement, optimization campaigns, benchmark thresholds, and
performance qualification are outside this plan's active scope. Stop at complete
functionality and correctness, including the allocator default and public x86
transitions. Keep ABI, source fidelity, production architecture, lifetime,
fault/model/stress/soak, bounded-memory/leak, installed-product, reproducibility,
and applicable physical hardware correctness requirements. Deferred performance
reports remain unqualified and cannot supply correctness evidence.

## Progress status

Update this section in place when the frontier changes. A retained report qualifies
only its exact source, configuration, image, products, and execution context.

- **Campaign:** 9/26 frozen families are `foundation-verified`; 17 remain
  planned. The inventory retains 223 capabilities: 180 implemented and 43
  selected-private. Correctness completion requires 25 active families and
  seven ordered gates; the performance family and full eight-gate chain remain
  deferred. Every Codex lane uses `gpt-6.1-sol` at medium, with 16 lane slots.
  Public x86 support and allocator promotion remain disabled pending functional
  qualification; C mimalloc remains selected and AArch64 qualification is paused.
- **Owned runtime:** exact accepted-C `b2a903880` passes the complete combined
  four-mode qualification, independent reproducibility builds, package
  extraction, both full static suites and all 219 installed/rebuilt/extracted
  dynamic executions. Its owning independent read-only reader passes. Separate
  static, dynamic and full54 aggregate readers also pass. These results qualify
  that exact source, not newer merged source or the native allocator.
- **Runtime families:** the same `b2a903880` cohort passes the complete native
  POSIX five-component producer, pthread component, POSIX family admission,
  and independent read-only admission and pthread-join readers. Fresh Rust
  std/LTO passes the unchanged whole consumer and owning read-only reader:
  four frozen gates, installed/extracted cleanup and cross-DSO execution,
  and all provider controls. The earlier private-lockfile mount failure remains
  retained. All 33 retained executables replay successfully; process-specific
  backtrace addresses retain their raw differences and pass the existing
  semantic receiver. This cohort also passes all 206 selected math/fenv entries
  in eighteen execution cells and its independent reader. The complete
  nine-component, sixteen-capability text family producer and independent
  read-only validator pass. This cohort also passes fresh
  183-obligation CRT and 32-helper producers and their owning readers. Its
  historical CRT selector still rejects the older nine-artifact projection
  against the thirteen-artifact receipt. Static Lua passes both modes on all
  three sealed roots and independent replay; dynamic Lua passes complete
  installed/extracted workloads and independent replay; the original normal
  Lua dispatchers and source-build admission also pass their owning read-only
  reader. Three fixed pthread worker fixtures pass 54 candidate cells and owning
  replay. Loader-family assembly and independent read-only validation pass.
  Resolver component producers and assembly pass, but the original read-only
  reader fails on two writes into retained inputs. The scratch repairs are
  integrated. Fresh `d13ce0ffe` static preparation and its owning reader pass;
  the subsequent full installed suite fails on a pinned musl AIO descriptor-reuse
  defect. A causal source control proves that defect, and the integrated receiver
  accepts only its complete signature. The failed cohort remains unqualified;
  fresh `e9de501dd` static preparation and its owning read-only reader pass.
  The complete 219-case installed/rebuilt/extracted dynamic qualification and
  its independent read-only reader pass at `e9de501dd`. All five resolver
  components and the independent whole-family reader also pass. Assembly
  produced the complete assessment, but disk exhaustion prevented recording
  its child status; the empty status and wrapper failure remain retained.
  These results qualify only that frozen source. Ordered family and
  callable-provider closure remain open.
- **Allocator source geometry:** source-faithful auxiliary and ordinary main
  Theap geometry repairs are integrated with ownership repairs. Their exact
  sources pass four-profile C/native layout comparisons and independent replay.
  Child main-Heap birth requests the source's 6,464-byte allocation. Child
  creation still adds 131,072 committed bytes against C's 65,536 in all four
  profiles: remove the separate child control allocation while preserving
  explicit ownership, failure retry and live-thread destruction semantics.
- **Allocator ownership:** coherent pointer/capability repairs are
  integrated. Both original strict environment/TLS startup fixtures and five
  isolated strict regressions pass at their exact repaired sources; all nine
  merged Rust compiler profiles pass. Compiler-selected Miri descriptors,
  dependencies, source files, tools, sysroot and exact phase environments are
  now retained. The original complete roster records fifteen of seventeen
  completions: both remaining interpreter runs exit successfully, but their
  startup markers interleave with libtest output. The strict parser repair is
  integrated. One fresh clean-source six-program/seventeen-test run at
  `1c22908bf` completes all six programs and all seventeen strict tests. Its
  first independent physical replay passes all seventeen strict tests, then
  rejects a cold/cached compiler-record comparison. The authenticated physical
  product comparison is repaired, and omitted original queue inputs are now
  independently retained. The corrected complete read-only replay passes
  at receiver `bd207c0b0` against unchanged producer `1c22908bf`: all seventeen
  strict interpreter tests, all 69 foundation commands and five original
  queue-helper commands pass. Exact producer and receiver identities remain
  separate. The whole gate remains unmet pending M1/M2. Prior full-roster,
  receiver and disk-exhaustion failures remain unqualified and retained.
- **Allocator gates:** existing Heap/subprocess stress, visitation, callbacks,
  statistics, remote ownership and failure evidence remain retained by exact
  source. M6 now requests the supported full-profile producer commands and
  rejects wrong or missing selectors; eight reviewed functional blockers remain.
  The reviewed M4 valid-client four-profile matrix matches all 32 pairs;
  assertion-invalid calls remain separate retained observations. The complete
  eleven-gate API producer and independent owning replay pass at `2891812d7`,
  including rejection of altered nested profile evidence. The accepted live
  aligned-offset C debug defect retains its source refusal and separate native
  correctness proof. Full Heap conveniences and Theap visitors pass all four
  profiles and owning read-only replay at their exact sources. A new real
  cross-thread arena reassociation regression matches all client observations;
  its source-faithful noncollecting metadata free repairs Heap deletion. The
  subsequent child-destroy refusal exposes direct OS metadata pages that pinned
  C retains. The coherent source-faithful repair at `12d00301e` passes the
  unchanged lifecycle judge in all four profiles and owning read-only replay.
  A separate 32-cycle child teardown diagnostic also completes all four
  profiles and owning replay. Both allocators retain about 245 MB of virtual
  mappings across those cycles; bounded-memory/leak qualification remains open.
  The original repeated fixture's startup error and its once-only repair remain
  retained. Heap destroy/finish contention now has causal retry evidence,
  complete compiler-command authentication and four-profile read-only replay.
  All nineteen Heap fault controls pass and replay without writing retained
  inputs. Queue receipts retain executable/compiler authority and replay.
  M7 abort-on-failure passes original C/native production, compiler/provider
  authentication and owning read-only replay at its exact source. Public and
  child visitation pass the four implemented profiles and owning replay.
  Sixteen initial-worker statistics cases pass their exact-source producer and
  owning read-only replay, including address-dependent OS-aligned accounting.
  Secure shuffle, selected-Theap randomness, secure singleton and arena guard
  geometry, guarded error publication, and local and foreign child callback-owner
  primitives are integrated with focused native evidence. Exact frozen sources
  pass their independent read-only replays;
  complete secure and guarded profiles, debug applicability and physical
  options remain open.
  Explicit debug-2 and debug-3 public Theap cohorts each pass 111 C/native
  comparisons and six native controls, with independent read-only replay at
  `3e17f9559`. Recursive caller-owned arena registration and guarded-free
  warning reentry repairs are integrated with exact-source replay. Repeated
  child teardown at `e6972b244` passes all four profiles and whole read-only
  replay. It attributes the C growth to retained source roots; every native
  profile still leaves 270,336 added bytes unexplained. A causal observation
  proves that the fixture's live mapping-reader buffer accounts for 266,240
  of those bytes. The integrated allocation-free observer passes two focused
  tests. Fresh four-profile production and all eight independent read-only
  executable replays pass at `8d7e8e4e8`: C leaves no unexplained growth and
  each native profile leaves 4,096 bytes. A causal syscall trace ties that
  residual to the fixture's live Rust channel; the channel-free fixture repair
  awaits execution after disk exhaustion stopped compilation. Bounded-memory
  qualification stays open, including the retained source-root growth.
  Secure-3 padding, canonical prefixes, encoded visitation and diagnostic
  repairs are integrated with exact-source focused read-only evidence;
  complete secure-3 production remains pending. The pinned C controls prove
  keyed Page geometry; corrected exact layout tests pass all nineteen focused
  secure-3 cases, five nearby cases and independent read-only replay. The
  unchanged caller-locked arena fixture requires a 64-MiB memlock budget;
  original C/native refusals under 8 MiB remain retained. Selected allocation
  admission now retains the actual main or child owner before candidate creation;
  exact main, child and foreign-owner controls and owning replay pass.
  All nine merged compiler profiles pass at `3a2d09895`. Indexed source ELF
  sections authenticate all 32 previously refused callable definitions in the
  retained runtime cohort; 309 merged read-only objects still lack complete
  selected-member proof. ISA correctness passes separately from deferred
  throughput. Complete M2/M3/M4 and merged-source qualification remain open.
- **External correctness:** physical huge-page/NUMA qualification requires two
  allowed NUMA nodes with a free 1-GiB huge page on each. This host has one node
  and no such pages; no alternate host is available. Continue independent
  correctness work and retain this unmet requirement. Performance is outside
  this plan's scope and cannot delay or qualify functional completion.
- **Next:** qualify the merged ownership and geometry repairs, finish child
  control lifetime parity, and close remaining functional families and
  source/API/profile conditions,
  replay the seven ordered gates on merged source, then perform the isolated
  default switch, fresh native qualification and correctness-backed public
  promotion. Retire integrated, stopped worktrees promptly after preserving
  exact source/raw inputs and checking their owning readers. Preserve active
  product leases; use existing ignored report locations. Git owns history.

## Parallel lanes

Use `.agents/skills/lanes/SKILL.md` for Codex coordination, or the
`.claude/skills/lanes` skill for Claude Code; both use
`.claude/agents/crabc-lane.md` for lane boundaries and handoffs. Keep all 16
lane slots occupied while useful work remains, subject to the tool's current
capacity. Every Codex lane uses only `gpt-6.1-sol` with `medium` reasoning effort;
set both explicitly when spawning. Each lane has one bounded, unique deliverable and an
exclusive write boundary in `.work/worktrees/lane-<id>`. The parent session
alone integrates to `main`. A failure outside a lane's boundary goes to one
owner. Nobody uses `git stash`. Do not schedule performance measurement or
optimization lanes in this campaign.

Validators check structure, cross-references, and runtime receipts; they do not
restate ledger prose, owner lists, or counts. Tests exercise behavior; they do
not pin source text. Add neither per-artifact validator functions nor
source-literal tests.

## Fixed contracts

| Boundary | Required contract |
| --- | --- |
| Active target | Native Linux/x86-64 little-endian, Linux >= 5.10; `x86_64-unknown-linux-musl` where a Rust target name is needed. No AArch64 execution or emulation. |
| Compatibility | Pinned musl 1.2.6, Linux ELF and System V AMD64 ABI, and `COMPATIBILITY-PROFILE.md`. Rustix remains test-only; no glibc or ambient target-runtime fallback. |
| Frozen runtime | AArch64 commit `3e100d45c5a0798c2d3862d5e2eef584c610ccf9`: exactly **223 capabilities and 26 required families**. `compat/x86_64/aarch64_frozen_baseline.json` owns the three immutable ledger/ABI/header digests. Validate them, never refresh them to absorb drift. |
| Runtime accounting | `compat/x86_64/parity.toml` owns exact capability mappings, family dependencies, and promotion. Every capability and required family occurs exactly once. Export ratchets are not inventories, schedules, or semantic proof. |
| Allocator source | mimalloc **v3.5.0**, commit `18b08671c9302247bfb682286e6bf3cc1773f801`; archive hash, license, and source provenance in `crabc-mimalloc/UPSTREAM.md`. No silent upgrade or allocator redesign. |
| Allocator accounting | `compat/allocator/port-map.toml`, applicability inventories, milestone manifests, and `known-differences.md`. Source-unit implementation, bounded evidence, integration, and target qualification are distinct. |

Default behavior matches pinned musl's defaults (user decision, 2026-09-25):

- **Loader validation.** At load time the loader rejects what musl rejects.
  Up-front checks musl does not perform are not required and must not keep a
  startup or `dlopen` functional row open; performance comparison is deferred.
- **Transparent huge pages.** The runtime leaves the process THP policy as
  musl does (no `PR_SET_THP_DISABLE`; upstream `allow_thp` stays 1). The
  native allocator's own arena reservations opt out of huge pages with
  `MADV_NOHUGEPAGE`, so first-allocation residency is musl-like. This is a
  recorded divergence from mimalloc v3.5.0 and carries a
  `known-differences.md` entry and a pinned-C correctness differential.
  Comparative performance evidence is deferred.

The accepted `libmimalloc-sys` 0.1.49 backend bundles mimalloc v3.3.2; it is
**not** the exact v3.5.0 engine oracle. Preserve separate candidate, accepted-C
integration comparison, and pinned-v3.5.0 differential/performance inputs.
Preserve the resolved musl BSD-random exception and approved cryptographic
primitive boundaries in `AGENTS.md`; do not reopen them as blanket blockers.

## Execution

Start with current status, the relevant source and manifests, and existing
unfinished work. Distinguish missing implementation from missing evidence and
external qualification. Prefer coherent subsystem behavior with its tests to
one-symbol patches, receipt-only work, or a new audit of already settled facts.

Implementation dependencies and qualification prerequisites are different.
Develop successors against stable interfaces while prerequisites qualify, but
never mark a downstream family or milestone complete before its required gates.
Runtime work can continue with the accepted C backend; static delivery does
not need dynamic startup; allocator engine work need not wait for unrelated
hardware evidence. Prioritize shared prerequisites and the longest remaining
integration path, not the easiest counter to change.

Use current orchestration instructions, isolated persistent worktrees, one
owner per shared state transition, and one writer for integration and central
ledgers. Keep useful implementation, review, integration, and qualification
moving concurrently. A concise outcome, ownership boundary, dependencies, and
proving checks are enough for an assignment. Reuse warm private development
state; integrate reviewed work continuously and test the merged result. Do
not require synchronized waves, per-leaf handoff files, repeated global
rebases, a fixed model roster, or a repository scheduling framework.

Use focused regressions while developing, affected component/family and
installed-product checks at integration, and complete canonical suites for
qualification. A branch pass does not prove merged composition. Review unsafe
ownership, atomics, loader/unwinder trust boundaries, and promotion carefully;
ordinary changes do not need repeated ceremonial audits.

Keep a frozen qualification checkout separate from moving development. One
product cohort binds a clean revision, pinned tools/image/oracles, target,
backend, features, and build configuration. Reuse its immutable products via
existing supplied-product interfaces; keep required independent reproducibility
builds independent. No shared mutable build/report directories, cross-revision
receipt substitution, or relabeling of out-of-order diagnostics as qualification.
Do not throttle agent or compiler/test concurrency; retry a build killed by
memory pressure rather than treating it as a defect. Performance qualification
must not contend with builds or other measurements.

For runner changes, first exercise a small real dispatch → collector → physical
output → independent-reader round trip. Extend existing matrices and readers
rather than creating a proof schema for every case. Preserve raw failures,
upstream schedules, and exact source identity. Update existing machine state
when facts change; keep logs in ignored report paths and history in Git.

## Runtime completion

All 25 active correctness families must reach `foundation-verified` in their
validated dependency order. Preserve the frozen 26-family inventory; the
performance family is deferred outside this completion scope. All 223 capabilities must reach their promotion-recognized
completed states, with no `missing` or `selected-private` entries. The following
contracts describe the integrated outcomes; the frozen mappings define their
finite selected surface, not all of musl or all of POSIX.

### Families and public ABI

| Area | Completion requirement |
| --- | --- |
| Headers and layouts | Complete installed header paths, selected strict/POSIX/XOpen/GNU/BSD/large-file profiles, typedefs/records/enums/constants/macros/data/functions, C and selected C++ linkage, LP64/x87 layouts, transitive includes, and installed-tree isolation. Zero missing selected declarations or unclassified callable owners. A deferred provider disposition can close header routing, not implementation or archive extraction. |
| POSIX runtime | Coherent filesystem/directory/traversal, descriptors, environment, process control, signals, and kernel-administration behavior, including aliases, errno/TLS, shared state, cancellation where selected, errors, output writes, and ownership. Complete native OS/signal/process/libc-test evidence, not merely Rust-facade equivalents. |
| pthread/C11 and TLS | Selected lifecycle, attributes, identity, join/detach, synchronization, once, TSD, cleanup, cancellation, signals, timers/thread notification, atfork/fork, and exit. Main, loader, worker, static TLS, dynamic TLS, DTV/module IDs, and `__tls_get_addr` use one ownership model. Realistic static/dynamic composition and stress are mandatory. |
| Text, math, locale, stdio | Selected iconv/wide/multibyte, regex, word expansion, clock/calendar, and complete stream/path/position/format/scan behavior. One stream engine owns locking, buffering, byte/wide orientation, permanent/created/adopted/memory/cookie streams, positioning, errors, and exit flushing. Preserve restricted locales, x87/MXCSR/fenv and long-double ABI, rounding, signed zero, NaNs, and exceptions. |
| Resolver | End-to-end conventional files and bounded C netdb/resolver behavior: A/AAAA/CNAME, search, UDP/TCP fallback, timeout/retry/server failover, reply validation, errors, cancellation/thread interactions, and result lifetime. Prove controlled-network and file behavior through owned C products; a parser or typed Rust transport alone is insufficient. |
| C compatibility and binding | Selected crypt/crypt-helpers through approved primitives, allocation, legacy compatibility, process globals, and final callable/data provider closure. Verify names, aliases, bindings, visibility, sizes, versions where selected, and static/shared ownership. Use ordinary archive extraction or an explicit structural oracle/builtin/consumer boundary—not hidden unresolved providers that happen not to be extracted. |
| Loader | General admitted dependency graphs, not fixed fixture graphs: self-relocation/entry, kernel main image, search/RPATH/RUNPATH, mapping/protection/RELRO, supported RELA/RELR relocations, weak/global/protected scope, RuntimeV1, initial/runtime TLS, DTV growth, constructors/finalizers, and selected `dl*` introspection. Prove concurrency, callbacks/reentrancy, fork, retained handles, reopen, malformed input, and failed-load rollback. |
| CRT, builtins, sysroot | Owned static/static-PIE and dynamic PIE/non-PIE entry, libc handoff, main lifecycle arrays, finalization, compiler helpers, deterministic link interface, installation, packaging, extraction, and reproducibility. Prove real applications consume the owned artifacts. |
| Rust facade and remaining families | Preserve and complete every other frozen family and exact semantic mapping, including direct native API, error, ownership, dependency, and LTO evidence. A C ABI pass does not prove the Rust-native path or vice versa. |

For pinned musl parity, successful `dlclose` validates a handle but does **not**
unmap the object or invoke its destructors. Reopen observes retained state;
DSO destructors run at process exit. Failed load transactions still release
their owned mappings. Do not implement physical last-close unloading and call
it the selected musl contract.

Use existing family matrices for routine ABI probes, feature profiles,
C/C++ signatures, symbol/data ownership, oracle execution, and aggregate
membership. Keep bespoke fixtures for genuinely unusual ABI, floating-point,
callback/lifetime, TLS/fork/signal, ELF, privilege, or network behavior. Private
opt-in features and extra exports do not create new frozen capabilities or
waive family closure.

### Owned products

Deliver **all four modes**: ordinary static `ET_EXEC`, static PIE, dynamic PIE,
and dynamic non-PIE. The installed sysroot owns headers, CRT objects, `libc.a`,
shared libc, interpreter and required compatibility alias, compiler-builtins,
selected allocator, and deterministic link specifications. A pinned host
compiler is allowed; ambient target headers, CRT, libc, libgcc/compiler-rt,
loader, or other undeclared target libraries are not.

The static product must be admissible from owned headers/libc/allocator,
pthread/TLS, static CRT, builtins, and its link interface without depending on
dynamic startup. The combined sysroot still requires both static and dynamic
products. Preserve this separation in the machine dependency graph.

The static suite jointly proves argument/environment/auxv/program-name
publication; initialized, zero-filled, and high-alignment TLS; errno;
allocation/alignment/reallocation/failure and remote ownership; pthread/C11,
TSD/cancellation/fork/exit; stdio buffering/formatting/positions/errors/flush;
filesystem/process/signal/time; sockets/resolver; constructors/destructors,
`atexit`, and ordinary/immediate termination. Include a compiler-helper
consumer that fails to link when the owned builtins archive is removed.

The dynamic suite uses an installed main, an initial dependency graph, and a
runtime-loaded plugin. It jointly proves interpreter/RuntimeV1 handoff,
search/relocation/scope, lifecycle ordering and retained close/reopen, public
`dlopen`/`dlsym`/`dlclose`/`dlerror`/`dladdr`/`dlinfo`/`dl_iterate_phdr`,
initial-exec/general-dynamic TLS, DTV growth before and after worker creation,
and allocation/errno/stdio/pthread/TSD/signal/exit across DSOs. Include
concurrent lookup/open/close, callback reentrancy, selected fork repair, and
selected malformed, missing, stale, or cyclic-input failures.

For each final ELF inspect link traces/maps, target input identity, interpreter
or its absence, dependencies, relocations, symbols, TLS, stack flags, RELRO,
and unresolved references before execution. Require two independent clean
installed builds to match byte-for-byte over the declared regular-file set,
then package/extract into a fresh location and run the same complete product
suites. Private direct-extraction tests remain useful but do not replace
natural composed links and installed-product execution.

## Native allocator completion

### Engine and source parity

`crabc-mimalloc` is a `#![no_std]` Rust engine with no production `alloc`,
C/C++ implementation, bindgen implementation, native implementation build
script, dependency on crabc-libc, recursive allocator dependency, or hidden C
fallback. Its permitted direction is `crabc-mimalloc → crabc-core + chacha20 +
zeroize`, with libc depending on the engine, never the reverse. Additional
focused pure-Rust primitives must preserve source behavior and allocation-free
bootstrap. Keep errno and C ABI policy in libc.

Port complete source transitions rather than test-shaped routes. Maintain
exact file/function mappings, configuration/layout probes, applicable API/mode
inventory, intentional differences, and unit/differential/integration/stress
evidence in the existing contracts. Each applicable Linux/x86-64
interface and mode must be implemented and verified; inapplicability requires
source-backed reasons, not unavailable hardware or an inconvenient test.
Upstream changes require separately reviewed source/inventory/map diffs and
correctness, model, and stress requalification; performance requalification is deferred.

### Production architecture

1. **Persistent source owners.** Each allocating thread retains its TLD/Theap
   across operations; the initial thread preserves source-required static
   storage. Local small/direct-cache and generic queue operations remain
   owner-local. Independent owners can progress independently.
2. **Pointer-centered dispatch.** `free`, usable-size, and realloc derive the
   page from the pointer and PageMap, recover the canonical aligned block,
   and choose local, live-remote, or abandoned behavior from page/process
   state—not caller identity or an exact-client registry. Realloc follows
   `mi_theap_realloc_zero_ex`: source-permitted local in-place reuse, otherwise
   current-owner allocation, bounded copy, and general free; preserve the old
   allocation on failure and the selected zero-size policy.
3. **Page-local remote publication.** Translate the pinned remote-free atomic
   protocol without borrowing the owner's TLD/engine. PageMap and metadata
   remain valid through every legal live client and unfinished remote
   publication. Unregister/release only after source state proves no client,
   uncollected free, or producer can remain, in source ownership order.
   Ordinary lookup does not acquire a structural PageMap mutation lease.
4. **One owner-exit traversal.** `_mi_theap_collect_abandon` performs deferred
   free, retired-page collection, source queue traversal (including full
   queues where required), per-page collection, empty-page release or live-page
   abandonment, cache/list repair, and Heap/Theap/TLD detachment. Cover regular,
   large, arena/OS singleton, mapped/unmapped, mixed, and late-publication
   cases through that generic coordinator, not caller-selected geometry routes.
5. **Callbacks without invalid borrows.** Source fast-TLS clearing does not
   clear the still-live default Theap. Deferred callbacks may allocate through
   it; execute them outside owner/engine/TLD/Theap reference projections and
   revalidate attachment identity before resuming exclusive collection. Apply
   the same discipline to VM, output, and initialization callbacks.
6. **Abandonment outlives threads, not TLS.** Surviving pages belong to source
   page/process abandonment structures; release old TLD/Theap when safe.
   Any surviving thread can free/reallocate or reclaim as source permits.
   Terminal release does not retain worker A's admission until worker B exits.
   Failed reclaim preserves ownership; a one-way failure retains exactly one
   identifiable terminal owner rather than guessing, leaking a capability, or
   falling back to C.
7. **No production scaffolding.** Before qualification remove per-allocation
   side ledgers, live-TLS-owner/exact-post-exit registries, historical-thread
   scans, per-call park/resume, global ordinary-operation schedulers, and
   top-level fixture-geometry route products. Keep useful witnesses test-only.
   A constant-size page-local lifetime aid needs a documented source invariant,
   model and lifetime proof; it cannot recreate a side ledger. Performance proof is deferred.

The architecture ratchet requires zero local-path global scheduler operations,
structural PageMap leases, owner/client scans, remote owner-registry scans,
and extra control bytes per live allocation; no per-call suspend/resume,
ghost-owner admission, or compiled forbidden scaffolding. Actual source page
metadata is not extra per-allocation control state. Metadata must plateau
after warmup.

Keep `#![deny(unsafe_op_in_unsafe_fn)]`, explicit caller obligations, strict
provenance, atomics/`UnsafeCell` and short validated raw projections. Do not form
long-lived Rust references whose aliasing promises contradict remote access.
A legal free cannot return unavailable, and allocation cannot report OOM
merely because a scheduler token is busy. Contention uses source-backed
progress/retry, not indefinite global spinning or process poisoning. Reserve
intentional forgetting for explicit terminal-retained/abort paths. Invalid-use
hardening may differ from upstream UB; document it and test aborts in isolation.

### Bootstrap, memory, and lifecycle

Initialization must be idempotent, race-safe, reentrant, and allocation-free
until primitives are ready. Support lazy first allocation and explicit startup,
concurrent entry, partial failure, entropy/diagnostic recursion, and PageMap
failure. Receive raw nonowning startup auxv/page-size/`AT_RANDOM`/environment
facts; do not call public libc or read `/proc/self/environ` for startup plumbing.
An initializing-thread allocation lease is not completed process readiness.

Use target-probed page/virtual-address geometry, not assumptions of 4-KiB
pages, one VA width, or one arena mode. Complete raw Linux reservation,
mapping/unmapping, commit/decommit, purge/reset, protection, applicable remap,
time/identity/backoff, entropy, advice, and NUMA behavior. Put deterministic
fault injection at that primitive boundary without a generic public OS trait.

A test-only auditor checks queue uniqueness/links/counts/direct caches, exact
PageMap spans, arena and abandoned bits/counts, OS lists, free counts,
Heap/Theap/TLD relationships, thread counters, released-metadata reachability,
and unique retained owners. Preserve proven low-level mechanics; change them
for a demonstrated source or general-path defect, not a new architecture.

The final fork contract must use allocation-free hooks, preserve the parent,
repair inherited locks, vanished-thread ownership and child TLS, and permit
all standard allocation operations in the supported child. Prove public
`pthread_atfork` ordering and distinguish prepared libc fork from an unprepared
raw-fork image. A conservative bridge that disables normal child allocation
is not final completion.

### Milestones

Each row requires its existing full target-qualified evidence, not a selected
source anchor or bounded witness. Qualification is dependency-ordered;
implementation may overlap. M0–M2 must qualify before dependent milestones
can be declared complete.

| Gate | Required outcome |
| --- | --- |
| M0 | Exact source/archive/license pin, no_std skeleton, API/mode inventory, source map, separate C oracle, configuration/layout baseline, and canonical harness. Inventory closure is not engine parity. |
| M1 | The six manifest-defined bounded foundations: configuration/arithmetic, types/atomics/provenance, source random machinery, primitive and bootstrap foundations. Do not relabel this as whole-header/source-file completion. |
| M2 | All eight components: VM, metadata, scalar bitmaps, PageMap, arenas, initialization, fault injection, and no allocator recursion; full ownership and failure conditions, including required physical hardware evidence. |
| M3 | Heap/Theap bootstrap, page queues, local allocation/free, retirement/reuse, complete selected bin/page-class matrix, deterministic differential traces, and Miri-compatible execution. |
| M4 | calloc, realloc, aligned operations, usable size, medium/large/singleton, collection, OOM/failure preservation, C adapter, and applicable upstream operation tests. |
| M5 | General persistent concurrency/lifecycle: pointer dispatch, remote publication, generic exit, abandonment/reclaim/release, no forbidden scaffolding, selected libc shadow, state auditing, deterministic and soak churn, upstream pthread stress, and structural architecture/purity checks; early performance proof is deferred. |
| M6 | All applicable Heap, Theap, arena, managed-memory and subprocess APIs, including destruction, cross-thread lifetime, and failure behavior. |
| M7 | All applicable options/environment, callbacks/deferred free, statistics, visitation, debug, secure, guarded and optional ISA profiles, without raising the baseline. |
| M8 | Complete owned-libc integration: startup/constructors, pthread/TSD/cleanup/cancellation/fork, errno/C ABI, weak/interposed symbols, static/dynamic products, DSOs/loader, Rust std, Lua, and the selected real-program corpus. |
| M9 | Deferred outside active scope: performance/memory comparisons, optimization codegen audit and three agreeing qualified full reports. Source-faithful convergence and correctness remain required through the active milestones. |
| M10 | Isolated correctness-qualified x86 default switch, without an M9 or performance-release prerequisite; C mimalloc absent from target production dependencies and artifacts, exact C v3.5.0 retained only as oracle, and required native commands rerun at the promotion revision. |
| M11 | Remove obsolete x86 transitional code/features, preserve anything required by paused AArch64, retain oracles/regressions, finalize v3.5.0 parity and the upstream-update procedure, and requalify the final simplified product. |

### Allocator correctness verification

Run real production entry points, not privileged test-only pointer routes.
Keep the permanent legal-C regression in which a worker allocates, exits, is
joined, and the initial thread frees its surviving block. Retain narrow
witnesses as tests while moving their behavior through the general engine.

Use separate pinned-C and Rust processes with logical allocation IDs and
normalized state, not pointer equality. Cover allocation/zeroing/alignment,
reallocation/content/size, heap/Theap/arena/collect, threads/transfers/exit,
post-exit free/reclaim, faults, and fork where normalization is meaningful.
Retain minimized failures and their original upstream workloads.

Miri must exercise provenance, initialization, pointer arithmetic, local
operations, and ownership/mapping lifetimes. Loom must model the production
atomic transitions for remote publication/collection, owner/unown,
abandoned claims, PageMap lifetime, and final release—not a model per numeric
page geometry. Inject failures at TLD/Theap, metadata/page allocation,
PageMap publish/unregister, arena claims, remote/abandon publication, reclaim,
purge/decommit, terminal release, and fork preparation; audit the unique owner.

Run applicable unmodified upstream tests with only environment/name binding.
In `test/test-stress.c`, preserve which thread frees, owner-exit timing,
transfer ownership, and cleanup/join order. Require **1, 2, 4, and 8 workers**,
multiple meaningful scale/iteration settings, and applicable large-object mode.
A fresh-thread cleanup workaround is not upstream acceptance. The smallest
configuration must pass before larger failures are called capacity issues.

Both deterministic bounded stress and a materially larger seeded,
watchdog-bound soak must cover independent owners, multi-producer remote
free, random transfer, partial/mixed pages, exit-before-free, initial-thread
participation, reclaim, constructors, cleanup/TSD, normal return,
`pthread_exit`, cancellation, and concurrent owners/releasers. Retain seeds,
counts, page distribution, final liveness, and metadata/PageMap/arena/abandoned/
TLD high-water. Equivalent thread churn must not cause unbounded growth.

Keep structural architecture and correctness checks active: persistent owners,
source memory orderings, PageMap lifetime, zero forbidden scaffolding, bounded
metadata growth, leak checks, and dependency/artifact purity. Throughput,
latency, scaling speed, comparative memory/size ratios, and optimization-oriented
codegen audits are deferred; they cannot block functional qualification.

## Allocator/runtime integration and Rust consumers

Libc owns standard malloc-family policy: weak/preemptible bindings and matching
allocation/free interposition, errno, zero-size and natural alignment, calloc
overflow, realloc failure and `realloc(p, 0)`, aligned allocation,
`posix_memalign` output preservation, and usable size. Internal allocation
ownership must remain coherent under a strong application allocator override.
A Rust pointer must never cross into the C backend as recovery.

Use the existing explicit `x86-owned-static-native-shadow` and
`x86-owned-dynamic-native-shadow` profiles and owned builders' native-shadow
selection. Keep accepted C default until promotion. Preserve backend-neutral
leaf/callable equivalence and target normal/build-graph plus archive/ELF purity
checks; native provider rows cannot inherit C receipts.

The dynamic RuntimeV1 handshake transfers validated runtime/TLS coordinates,
not allocator pointers. Loader metadata uses its raw mapping owners; libc
initializes its native process state after validated TLS/environment/auxv and
before constructors. Prove absence of cross-backend ownership in real installed
PIE/non-PIE and kernel/direct-loader execution, not just feature checks.
`docs/design/x86-dynamic-native-allocator.md` documents this implemented seam.

Worker attachment must establish its persistent owner before user code, even
before its first allocation. Cleanup and user TSD destructors precede native
owner teardown, which precedes TLS unmapping. Cover failed attachment,
allocation/realloc refusal with subsequent valid use, remote ownership,
final-worker ordinary exit, and fresh-owner reinitialization only after the
old owner is genuinely finished. Do not reopen a retained or borrowed owner.

Preserve source lifecycle placement: logical process-done runs from libc's own
`.fini_array`, not an invented point after all DSO/stdio callbacks. Dependent
and independent DSO finalizers can straddle it; retain the source-required
backing so later callbacks remain valid. Default-release process-done is not
physical destruction of all live allocations. Test the separately applicable
statistics/destroy/cache/TLS-key branches before claiming their source parity.

### Unwinder, std, and LTO

Complete the approved pinned Rust unwinder integration rather than asking for
approval again or copying an ambient unwinder:

```toml
unwinding = { version = "=0.2.10", default-features = false, features = ["unwinder", "fde-phdr-dl", "dwarf-expr"] }
```

Source commit: `0e2de8fb536b1ca42066024609f58d708cf80e69`. Lock and audit
`gimli 0.34.0` (`read-core`, no defaults) and `libc 0.2.186` as the reviewed
normal graph. The bindings target crabc's ABI, not an ambient libc. Keep the
path no_std/allocation-free; disable frame registration, extra personality,
panic-handler, printing, and allocator features. Rust std owns its personality.

Prove the real `_Unwind_*` ABI, ordinary archive extraction and shared symbol
resolution, executable/initial/runtime-DSO EH discovery, bounded malformed and
truncated metadata/DWARF expressions, context restoration, and mapping
lifetimes during `dl_iterate_phdr` callbacks. Preserve already landed bounded
EH/PT_DYNAMIC work rather than restarting it. Do not infer async-signal safety
from loader enumeration. Run backtrace and panic cleanup/resume across calls,
threads and DSOs through installed/extracted static/dynamic products.

Reproduce the frozen stock-std, dependency-bearing std, build-std and LTO
consumer contracts, including their controls and exact toolchain/IR provenance.
`panic=abort`, dummy unwind symbols, suppressed unresolved references, a
musl-hosted standalone pass, or an easier fixture cannot replace those gates.
Likewise reproduce the frozen Lua/source-build and real-software compatibility
rosters through owned products; do not substitute version probes for required
workloads or silently expand the active corpus.

## Runtime correctness qualification

Close runtime/products and family prerequisites, then execute the ordered
qualification chain. Independent diagnostics may run earlier; they do not
constitute an admitted final chain.

```text
compat.abi-differential
  -> compat.posix-process
  -> compat.resolver-network
  -> compat.loader-corpus
  -> consumer.rust-std-lto
  -> consumer.source-build
  -> capability.accounting
```

This active chain ends at `capability.accounting`. Performance release remains
a separately retained, deferred family; it is not an active prerequisite for
the allocator default switch, public x86 support, or completion of this plan.
Do not label deferred benchmark requirements passed or performance qualified.

## Commands and evidence

The active runtime dispatcher owns these aggregate commands:

```sh
./scripts/dev-x86_64.sh campaign-status
./scripts/dev-x86_64.sh campaign-family FAMILY
./scripts/dev-x86_64.sh campaign-static
./scripts/dev-x86_64.sh campaign-dynamic
./scripts/dev-x86_64.sh campaign-qualification
./scripts/dev-x86_64.sh campaign-promotion-check
./scripts/dev-x86_64.sh campaign-all
```

Use `--help` and the owning manifests for focused commands. In particular,
`materialized-dynamic-sysroot` is an executing installed-product gate; do not
confuse a plan-only seed with execution. Admission/replay must use the pinned
qualification dispatcher and its actual reader-enforced prerequisites.

The allocator has a separate contained native lane:

```sh
./compat/allocator/run-x86_64.sh allocator --quick
./compat/allocator/run-x86_64.sh allocator-m1
./compat/allocator/run-x86_64.sh allocator-m2
python3 compat/allocator/run.py --check --architecture x86_64 --offline
```

Use its current help/manifests and finish any missing native command capability
for full correctness, exact upstream tests, installed shadow integration,
seeded soak and post-promotion
repository checks. Do not present paused AArch64 command spellings as native
x86 implementations. A full gate must name actual unmet conditions and fail
closed while incomplete, then pass at completion—not permanently report an
unspecified future milestone.

Keep each proving command and its raw/machine-readable report at the existing
predictable target-qualified location. Allocator M1/M2 reports live beneath
`.work/allocator-x86_64/reports/allocator/x86_64/`; runtime work uses
`.work/x86_64/` and the established ignored report paths. A host replay verifies
retained facts, not native execution by itself. Never hand-edit generated
measurements or infer a pass from a missing report.

## External qualification

The existing huge-page/NUMA job needs native x86 Linux with **two distinct
online allowed memory nodes (IDs <= 62), one free 1-GiB hugetlb page per node,
at least 2 GiB hugetlb cgroup headroom, readable `numa_maps`, the launcher's
canonical capabilities, and authorized `mbind(MPOL_PREFERRED, flags=0)`**.
Keep **RLIMIT_AS=unlimited**: existing composed simulated prerequisites may
reserve **36 GiB + 96 MiB** of virtual address space, separate from physical
huge pages and ordinary compiler/runtime RAM.

A prior private-mapping probe returned `EPERM`. Preserve its diagnostic;
do not infer the policy origin from a seccomp flag, repeat an unchanged denied
operation, or route around it through another agent/tool. After authorized
provisioning and validation of the pinned image, run:

```sh
./compat/allocator/run-x86_64.sh allocator-huge-numa-qualification
```

This proves its bounded native hardware contract, not all of M2. Simulated
fault paths cannot substitute for physical huge-page success and placement.
Do not rent resources, change shared pools/security policy, or reboot without
permission. Record a blocker once with the affected gate, evidence and clearing
action; revisit when those facts change, not after every commit.

## Correctness promotion and definition of done

Promote through evidence-backed, isolated changes: qualify native allocator
functionality and owned integration, switch the x86 default while preserving
AArch64, then enable public x86 support after the functional readiness check.
Performance receipts and thresholds are not prerequisites. Each transition
still requires its post-change correctness reruns.

Finish stabilization before selecting the final clean committed candidate.
Rebuild and qualify all installed modes with the native allocator, including
independent reproducibility builds and extracted consumers. Run the complete
native functional aggregate, active allocator milestones, ordered correctness
chain, model/fault/stress/soak, ABI/interposition/TLS/fork/loader/DSO,
std/LTO/source/corpus, source-convergence and dependency/artifact purity checks.
Different-revision or C-backend evidence cannot satisfy native reruns.

The active goal is complete only when all of the following hold together:

- The frozen baseline and all digests validate; all 223 capabilities are complete
  exactly once. All functional families are verified in dependency order; the
  retained `performance.release` family remains explicitly deferred and is
  excluded from functional readiness, without altering the frozen inventory.
- Both owned products cover all four link modes, reproduce independently, and
  pass the same installed and extracted suites without ambient inputs.
- Allocator M0–M8 and M10–M11 functionality, applicable APIs/modes, source fidelity,
  production architecture, lifetime, fault/model, upstream/stress/soak and bounded
  metadata/leak requirements pass. M5 optimization codegen and throughput,
  along with M9 performance qualification, are deferred.
- Rust mimalloc is the correctness-qualified x86 default. C mimalloc is absent
  from the x86 production dependency/build/artifact graph and survives only in
  isolated oracle/comparison inputs. Paused AArch64 remains unchanged.
- Functional `promotion_ready` is computed from complete correctness evidence
  before public support is enabled. `public_support = true`, documentation,
  `campaign-promotion-check` and the functional `campaign-all` agree.
- Final reports bind the same clean committed source, target, pinned inputs and
  declared configurations, including post-switch and post-promotion products.
  Applicable physical hardware correctness requirements are satisfied.

Keep performance readiness separate and false until a later explicitly scoped
performance campaign proves it. Preserve existing benchmark contracts and raw
results without treating them as active blockers or successful measurements.
Put final results in ignored reports. A necessary source change selects a new
candidate and requires affected correctness requalification. The final response
names the candidate, commands/reports, parity/purity and functional promotion
results, and explicitly states that performance was deferred.

## Deferred work

These retained directions are **not active x86 completion gates**. They do not
resume AArch64 or enlarge the frozen consumer roster. Activating them requires
new direction consistent with the target pause and scope.

- **CPU governor.** Qualified measurements run on the host's configured
  governor (`powersave`). Candidate and reference interleave under the same
  governor, so it is recorded and must be one consistent governor for the
  whole run; it is not forced to `performance`.

**Allocator and runtime performance qualification.** The following retained
criteria belong to later work. They are not scheduled or required by the active
functionality plan, and correctness-backed default/public promotion does not
claim they have passed. Revisit their policy and feasibility when performance
work is explicitly resumed.

Measure architecture early: local allocation/free/realloc, remote publication
and collection, scaling, churn, exit/reclaim, TLS codegen, syscalls/faults,
memory, and code size. Before broad optional-API expansion the persistent local
engine must reach at least **0.25× pinned-C single-thread throughput** and show
real independent four-thread scaling. This is an architecture sanity gate,
not final non-inferiority. Remove structural costs before micro-optimization.

Final allocator comparisons use equivalent opaque C/Rust boundaries and fully
integrated products on a qualified uncontended native x86 host:

| Metric | Promotion gate against exact C mimalloc v3.5.0 |
| --- | --- |
| Throughput | Suite geometric-mean lower 95% bound >= **0.95**; no critical workload lower bound < **0.90** without a separately reviewed exception. |
| Tail latency | Critical p99 upper ratio bound <= **1.10**. |
| Memory | Geometric-mean peak RSS/PSS upper ratio <= **1.05**; no critical workload > **1.10** without explanation; no unbounded metadata/mapping growth. |
| System and size | No material unexplained syscall/page-fault amplification or leak; investigate allocator-attributable code-size growth > **10%**. |
| Repeatability | At least **three qualified full reports** agree, with source/configuration/host identity and raw data. |

Audit optimized allocation, free, remote publication, PageMap/bin/TLS lookup,
realloc and alignment paths for spurious helpers, checks, fences, division,
formatting, zeroing and missed inlining. Preserve source memory orderings.
Threshold changes are independent decisions, never repairs to make a failing
implementation pass. Allocator parity does not waive the separate runtime
performance scorecard below.

Use the existing finite native performance definition and preserve all
mandatory rows: startup/lifecycle and dependency graphs; clocks/identity;
files/descriptors; dynamic lookup at small and 128/1,024+ symbol scales;
memory primitives across sizes/alignments/cache and guard-page boundaries;
allocation/churn/live sets; stdio/parsing; threads/TLS/synchronization; and
hermetic sockets/resolver. Native-facade/Rustix and std-aware build-std/LTO
lanes remain distinct supporting comparisons, not a musl C-ABI claim.

The runtime release scorecard is **per workload**, not a compensating suite
average. Preserve these requirements under native x86 adaptation:

| Metric | Required result against pinned musl |
| --- | --- |
| CPU | One-sided 95% bootstrap upper bound for median candidate/reference user-plus-system CPU <= **0.90**. |
| Peak memory | Both protocol-controlled peak PSS and fresh cgroup-v2 `memory.peak` ratios <= **0.90**. |
| Syscalls | Candidate <= **2R** for reference count R > 0; a zero-call marked reference region requires zero candidate calls. No uncontracted error/retry/fallback calls. |
| Diagnostics | Retain wall median/p95, faults/context switches, RSS/private pages and size; investigate material regressions. All semantic gates remain green. |

Use identical fixture bytes except the explicitly admitted interpreter/runtime
substitution, symmetric inputs, pinned build modes, interleaved reference/
candidate samples, and complete raw provenance. Time without tracing,
profiling, or memory observers. Measure high water with ready/hold/continue
and `smaps_rollup`, plus a fresh delegated cgroup; count loader/runtime and
process memory, not only allocator requests or virtual reservations. Missing
cgroup access, invalid plateaus, omitted rows, or unsupported measurements
cannot pass. Keep syscall startup totals distinct from marked useful work.

Preserve the existing full-sample/statistical protocol and repeat clean runs;
use a second compatible native machine class when available. Attribute
regressions before optimizing; use the existing scorecard, not a new benchmark
framework. A provisional time-route **1.05** CPU ratio is at most development
status, never a relaxation of the **0.90** release gate.

The historical fully touched 32-MiB workload exposes a possible feasibility
conflict in the absolute 0.90 peak-memory rule: payload alone can exceed 90%
of the reference's total. Do not hide the row, subtract candidate-specific
baselines, shrink its live set, or silently replace the metric. Re-evaluate
with native x86 evidence; if the lower bound still precludes the requirement,
retain that precise acceptance-policy blocker for an explicit user decision
while completing independent work. The authorized faithful allocator port
supersedes old instructions forbidding all allocator work, not this scorecard.

**Sustained software-corpus performance.** After the focused scorecard passes,
retain the C0–C4 progression: measurable pinned-corpus substrate; sustained C
baselines; cross-subsystem optimization; native application proof; reproducible
release evidence. Use unmodified package executables with symmetric runtime
overlays, exact outputs/state, pinned DSO/input hashes, fast and release sizes,
hermetic local state, and declared fresh/steady/high-water/concurrency modes.
C workloads cover grep/sed, tar, gzip/zstd, SQLite transactions/queries,
Python data/traversal/subprocess, Git local operations, loopback curl, ssh
configuration, and OpenSSL file digest strictly as a libc consumer. The five
direct `crabc-rs` applications are descriptor pipeline, local service/client,
thread/TLS worker, process/signal tool, and filesystem state tool. Their normal
builds exclude Rustix/libc/nix; compare overlapping Rustix operations only in
separate test builds, without pretending non-overlapping semantics are equal.
Each C workload must meet the same per-row 0.90 CPU/PSS/cgroup and 2R syscall
gates, with zero-call hot regions preserved; native targets are stated
separately. Keep synthetic ABI/loader/POSIX and stock/dependency-bearing std
lanes independent. Require three clean full runs and a second compatible
machine class when available; no dropped unfavorable row or generic distro,
public-network, cryptographic-performance, or package-manager scope.

**CPython source build.** The retained next candidate, only if selected, is
pinned CPython 3.14.3 through the native installed owned sysroot. First build
the interpreter/shared libpython without optional third-party extensions;
prove startup/imports, extension loading, files, threads, subprocess, Unicode,
and deterministic failures with a hermetic subset. Admit optional OpenSSL,
zlib/bzip2/xz, libffi, SQLite, expat, readline/ncurses and other libraries only
after each has independent owned-sysroot evidence. Audit headers, linker
inputs, interpreter/maps/dependencies and raw outcomes; an interpreter launch
is not broad CPython compatibility. A future true cross build must follow
build-Python/CONFIG_SITE requirements, not guessed configure answers. Neither
this direction nor completed AArch64 Lua/sysroot evidence supplies current x86
qualification.
