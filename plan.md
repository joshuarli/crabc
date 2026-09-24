# Complete crabc's native x86-64 runtime

## Goal

Implement this plan through integrated, qualified completion: reproduce the
frozen selected runtime on native Linux/x86-64, finish the faithful Rust
mimalloc port, make it the qualified x86 default, and promote public x86
support. “Implement plan.md” authorizes the necessary in-scope implementation,
tests, integration, performance work, and local promotion changes—not merely
another plan, private fixture, or intermediate handoff.

`AGENTS.md` owns scope and working rules. This file owns the complete active
completion contract and its one progress handoff. Machine-readable manifests
supply exact inventories and evidence requirements; technical guides explain
implementation and runner details, not additional independent plans. Continue
while useful independent work remains. A genuinely external blocker must remain
explicit, never be converted into a pass or a smaller completion claim.

## Progress status

Update this section in place when the frontier changes. Recorded checkpoints
are not transferable passes for a different revision.

- **Runtime:** Frozen accounting validates. `campaign-status` has 9/26 families
  `foundation-verified`, 180 implemented, 26 selected-private, and 17 missing
  capabilities; all eight qualification gates remain incomplete. POSIX,
  pthread, resolver, text, loader, and installed-product components passed on
  frozen `3c47d990d` products, and current-source static/dynamic products
  passed at `ed30f681b`. Integrated fixes now cover `dlinfo`, once
  cancellation, worker self naming, `getopt`, CRT startup rejection, GNU-unique
  scope, late ELF program headers, `fmtmsg`, `fgets`, and allocator-client
  interposition. The BSD-random
  quartet has a physical oracle-rebuilt receipt on its source branch; 497
  unrelated ABI selection blockers remain. Requalify on a stable revision
  before promoting any family; `libc.posix-runtime` is the next ready transition.
- **Allocator:** M1 bounded foundations, M2 PageMap/scalar bitmaps, and a
  metadata lifecycle differential passed at recorded revisions. The integrated
  child metadata page session, source-once startup, arena NUMA order, abandoned
  false collection, aligned realloc, VM warning order, and full-queue byte
  accounting have focused native evidence. Full child Heap/page lifecycle,
  M2 VM/arenas/init/fault/no-recursion, and M3-M7 aggregate gates remain open.
  Source `generic_collect` policy and private zeroed realloc paths are now
  integrated with focused native checks. C remains the selected backend. The
  merged allocator suite passed 1,159 tests at `7d7ea272b` after two fixture
  corrections; later M4 edits still need merged qualification.
- **Integration and qualification:** `rust-toolchain.toml` selects
  `nightly-2026-09-15`; explicit static/dynamic native-shadow products exist.
  Accepted C stays default. Native OS/libc aggregation, installed-product
  unwinder/std/LTO, ordered consumers, allocator M8-M11 and release performance
  remain open. The clean `ad21441d6` Lua source-build admission passed; older
  source-bound receipts do not qualify moving `main`. Hardware prerequisites
  are recorded below.
- **Preservation:** Pre-upgrade dirty worktree source is under
  `refs/archive/pre-toolchain*`. AArch64 remains paused and frozen.
- **Lanes settled (2026-09-24):** No lane agent or lane worktree remains.
  `main` integrated the paused handoff, the `ed4db0ba6` identity fix, the M2
  test-binary fix, the fail-closed `allocator-m6`, `consumer.source-build`,
  and `compat.loader-corpus` gates, the ordered qualification-chain executor
  (every gate `ready` with named unmet conditions), the executable release
  scorecard, the owned static product suite, owned dynamic link inspection,
  musl-exact search/gettext allocation, locale receipt and hidden-body ABI
  selection, the offline mimalloc tag identity, the child fork repair port,
  shared pthread product arguments, the resolver family coordinator, and
  selected-private slices for `text.iconv`, `text.wide-multibyte`, four stdio
  engine capabilities, `runtime.private-facades`, and `process.globals`
  (`campaign-status`: 180 implemented, 34 selected-private, 9 missing).
  Parked on their branches, each ending in a `WIP(lane <id>)` commit:
  `posix` (a POSIX admission candidate to rerun on merged `main`, plus an
  experimental registry lock), `pattern` (regex rework; musl transcript
  differs), `math-time`, `loader`, `m3`, `m6`, `m7`, `alloc-perf` (conflict
  with `main`), `m2-init-fault` and `m5-exit` (fail the Rust check),
  `m5-remote` (fails a runner test), `crt-dynamic`, `dynamic-product`,
  `std-lto`, `m2-vm-arenas`, `alloc-fork` (unfinished), `m5-stress` (an
  untested arena singleton PageMap span fix), and `m4` (scratch probes only).
  Keep `ed4db0ba6` out of `main`. No worktrees remain; every branch is kept,
  and the unmerged commits of the removed pre-campaign worktrees were already
  superseded on `main`. JSON/log receipts from the frozen POSIX, unwinder,
  resolver, and product evidence worktrees are in
  `.work/archive/*-receipts.tar.gz`; keep the allocator SIGSEGV core/log. Old
  stash entries are under `refs/archive/stash/*`.
- **Open cross-lane defects (one owner each):** 358 runner scripts still build
  with plain `cargo rustc` and fail to link `rust_eh_personality` on the pinned
  nightly (`libc-resolver-runtime` included); generalize `2261f8e20`.
  `run_pthread_c11_header_abi.sh` and about 500 other `pipefail` sites lose
  matches through `printf | grep -q`; use here-strings. Static and dynamic
  products install different `usr/lib/crt1.o`; the combined sysroot needs one
  entry valid for static `ET_EXEC` and dynamic non-PIE, keeping the
  static/shared split in libc's `__libc_start_main` as the frozen AArch64
  `crt/src/normal_entry.rs` did. Owned `sysconf` lacks
  `_SC_NPROCESSORS_ONLN`/`_CONF` and `_SC_PHYS_PAGES`/`_SC_AVPHYS_PAGES`. Rust
  page block pops clear `retire_expire`, which pinned `mi_page_malloc_zero`
  never touches (`lane/m3`). Pre-existing host test failures:
  `compat/x86_64/tests/test_runner.py` (8), `test_header_callable_inventory.py`
  (the BSD random quartet awaits the `abi-bsd-receipt` integration),
  `compat/x86_64/test_owned_dynamic_driver.py` outside the image, and the perf
  descriptor-closure test. `scripts/check_structure.py` walks worktrees under
  `.work/`.

## Parallel lanes

Lanes are ownership boundaries, not schedules. Each runs in
`.work/worktrees/lane-<id>` on branch `lane/<id>`, commits coherent verified
increments, rebases on local `main`, and hands off. The integration owner alone
merges to `main`, runs merged checks, edits this file and central ledgers, and
removes a lane worktree once its work is merged. A lane touches shared files
(`compat/x86_64/parity.toml`, `scripts/dev-x86_64.sh`, shared manifests) only
for its own rows or commands. A failure in shared tooling or another lane's
boundary is reported to the integration owner, which assigns exactly one fixer;
lanes never fix it locally in parallel. Assignments are bounded, unique
deliverables. Never use `git stash`: `refs/stash` is shared by every worktree.
Implementation overlaps freely; family and milestone qualification still follows
the dependency order below and in `campaign-status`. Run at most 16 lane agents
at once (`.claude/settings.json`); builds inside a lane are not throttled, and
qualifying performance measurements wait for an uncontended host. The
`.claude/skills/lanes` skill, `.claude/agents/crabc-lane.md`, and
`scripts/lanes/` hold the orchestration workflow and integration helpers.

| Lane | Owns |
| --- | --- |
| `integrate` | Paused-handoff commits above; merged M4 and affected canonical reruns. |
| `posix` | `libc.posix-runtime`: `process.control`, `system.kernel-admin`, its selected-private rows, source-sealed cohort, `owned-posix-native` admission. |
| `pthread` | `libc.pthread-tls`: `thread.pthread-c11`, `time.posix-timer-thread-notify`, `process.atfork-exit-hooks`, TLS ownership model, family evidence. |
| `stdio` | One stream engine: `stdio.stream-io`, `path-stream`, `position-buffering`, `format-scan`, `fopen64-alias`, wide orientation. |
| `text` | `text.iconv`, `text.wide-multibyte`, `locale.core`, `numeric.parse-float-locale`. |
| `pattern` | `pattern.regex`, `pattern.wordexp`. |
| `math-time` | `math.complex`, `math.elementary-fenv-sensitive`, `math.elementary-long-double`, `math.special`, `time.clock-calendar`; text-family assembly. |
| `resolver` | `libc.resolver` end-to-end owned-product evidence. |
| `abi-globals` | `process.globals` and final callable/data provider closure. |
| `abi-selection` | Native ABI selection blockers (`native-abi-selection require-closure`) not owned by a family lane; BSD-random receipt integration. |
| `c-compat` | Remaining `libc.c-abi-compat` selected-private rows: gettext, crypt/helpers, error reporting, legacy misc, qsort helper, search tables, allocator basic/observability. |
| `loader` | `loader.dlfcn-basic`, `loader.dlfcn-introspection`, `runtime.loader` general graphs, concurrency, rollback. |
| `runtime-facades` | `runtime.private-facades` and remaining Rust-facade loader/runtime mappings. |
| `crt-dynamic` | `crt.dynamic-startup`. |
| `static-product` | `sysroot.static-tls` and the complete owned static product suite in all static modes. |
| `dynamic-product` | `sysroot.owned-artifact` dynamic suite, reproducibility, package/extract. |
| `unwinder` | Installed-product unwinder integration and the `ed4db0ba6` identity fix. |
| `std-lto` | `consumer.rust-std-lto`. |
| `source-build` | `consumer.source-build` (Lua) and `compat.loader-corpus` (the frozen 34-workload real-software roster). |
| `qual-chain` | Fail-closed readiness of `compat.abi-differential`, `compat.posix-process`, `compat.resolver-network`, `capability.accounting`, and dispatch/reader wiring for the rest of the chain. |
| `runtime-perf` | `performance.release` harness completeness; no qualifying measurements under contention. |
| `m2-vm-arenas` | Allocator M2 VM and arenas. |
| `m2-init-fault` | Allocator M2 metadata, initialization, fault injection, no recursion. |
| `m3` | Allocator M3. |
| `m4` | Allocator M4, including the aligned-realloc differential. |
| `m5-remote` | M5 pointer dispatch, remote publication, Loom models. |
| `m5-exit` | M5 owner-exit traversal, abandonment/reclaim/release, scaffolding removal and architecture ratchet. |
| `m5-stress` | M5 state auditor, deterministic stress, seeded soak, upstream `test-stress`. |
| `m6` | Allocator M6 APIs. |
| `m7` | Allocator M7. |
| `m8` | Allocator M8 owned-libc integration and native-shadow products. |
| `alloc-fork` | Final allocator fork contract. |
| `alloc-perf` | Architecture sanity gate, codegen audit, M9 harness; no qualifying measurements under contention. |

## Fixed contracts

| Boundary | Required contract |
| --- | --- |
| Active target | Native Linux/x86-64 little-endian, Linux >= 5.10; `x86_64-unknown-linux-musl` where a Rust target name is needed. No AArch64 execution or emulation. |
| Compatibility | Pinned musl 1.2.6, Linux ELF and System V AMD64 ABI, and `COMPATIBILITY-PROFILE.md`. Rustix remains test-only; no glibc or ambient target-runtime fallback. |
| Frozen runtime | AArch64 commit `3e100d45c5a0798c2d3862d5e2eef584c610ccf9`: exactly **223 capabilities and 26 required families**. `compat/x86_64/aarch64_frozen_baseline.json` owns the three immutable ledger/ABI/header digests. Validate them, never refresh them to absorb drift. |
| Runtime accounting | `compat/x86_64/parity.toml` owns exact capability mappings, family dependencies, and promotion. Every capability and required family occurs exactly once. Export ratchets are not inventories, schedules, or semantic proof. |
| Allocator source | mimalloc **v3.5.0**, commit `18b08671c9302247bfb682286e6bf3cc1773f801`; archive hash, license, and source provenance in `crabc-mimalloc/UPSTREAM.md`. No silent upgrade or allocator redesign. |
| Allocator accounting | `compat/allocator/port-map.toml`, applicability inventories, milestone manifests, and `known-differences.md`. Source-unit implementation, bounded evidence, integration, and target qualification are distinct. |

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

All 26 required families must reach `foundation-verified` in their validated
dependency order. All 223 capabilities must reach their promotion-recognized
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
inventory, intentional differences, and unit/differential/integration/stress/
performance evidence in the existing contracts. Each applicable Linux/x86-64
interface and mode must be implemented and verified; inapplicability requires
source-backed reasons, not unavailable hardware or an inconvenient test.
Upstream changes require separately reviewed source/inventory/map diffs and
correctness, model, stress, and performance requalification.

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
   model and performance proof; it cannot recreate a side ledger.

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
| M5 | General persistent concurrency/lifecycle: pointer dispatch, remote publication, generic exit, abandonment/reclaim/release, no forbidden scaffolding, selected libc shadow, state auditing, deterministic and soak churn, upstream pthread stress, and early codegen/performance proof. |
| M6 | All applicable Heap, Theap, arena, managed-memory and subprocess APIs, including destruction, cross-thread lifetime, and failure behavior. |
| M7 | All applicable options/environment, callbacks/deferred free, statistics, visitation, debug, secure, guarded and optional ISA profiles, without raising the baseline. |
| M8 | Complete owned-libc integration: startup/constructors, pthread/TSD/cleanup/cancellation/fork, errno/C ABI, weak/interposed symbols, static/dynamic products, DSOs/loader, Rust std, Lua, and the selected real-program corpus. |
| M9 | Full equivalent C/Rust performance/memory matrix, codegen audit, source-faithful convergence and at least three agreeing qualified full reports; correctness stays green. |
| M10 | Isolated qualified x86 default switch; C mimalloc absent from target production dependencies and artifacts, exact C v3.5.0 retained only as oracle, and required native commands rerun at the promotion revision. |
| M11 | Remove obsolete x86 transitional code/features, preserve anything required by paused AArch64, retain oracles/regressions, finalize v3.5.0 parity and the upstream-update procedure, and requalify the final simplified product. |

### Allocator verification and performance

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

## Runtime performance and qualification

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
  -> performance.release
```

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
seeded soak, performance smoke, qualified performance, and post-promotion
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

## Final promotion and definition of done

Promote only through evidence-backed, isolated changes: first qualify the
native allocator and its owned integration, switch the x86 default without
changing AArch64, then complete the runtime/public-support transition when
its validator computes readiness. Each transition requires its post-change
reruns; neither can infer the other's completion.

Finish all applicable stabilization before selecting the final clean committed
candidate. Rebuild/requalify installed static and dynamic products with the
promoted allocator, including independent reproducibility builds and extracted
consumers. Run the complete native aggregate, allocator commands, ordered
qualification, model/fault/stress/soak, ABI/interposition/TLS/fork/loader/DSO,
std/LTO/source/corpus, dependency purity, and both performance contracts.
Former C-backend or different-revision evidence cannot satisfy this rerun.

The active goal is complete only when **all** of the following hold together:

- The frozen baseline and all digests validate; all 223 capabilities are
  complete exactly once, all 26 required families are `foundation-verified`
  in dependency order, and no required product or qualification remains open.
- Both owned products cover all four link modes, reproduce independently,
  and pass the same installed and extracted suites without ambient inputs.
- All native allocator M0–M11 gates, applicable APIs/modes, production
  architecture, correctness, lifetime, fault/model, upstream/stress/soak, and
  performance requirements pass; no remaining condition is hidden or waived.
- Rust mimalloc is the qualified x86 default. C mimalloc is absent from its
  target production dependency/build/artifact graph and survives only in
  explicitly isolated oracle/comparison inputs. AArch64 is not falsely promoted.
- `promotion_ready` is computed from complete evidence **before** public x86
  support is enabled; `public_support = true` and public documentation agree,
  and `campaign-promotion-check` plus `campaign-all` pass after that change.
- Final reports bind the same clean committed source, target, pinned inputs,
  and declared configurations, including post-promotion products. All required
  external qualification and runtime performance-policy issues are resolved.

Put final results in ignored reports. Do not create a new source commit merely
to write its own SHA into a file being hashed. A necessary source change selects
a successor candidate and requires affected requalification. The final response
names the commit, proving commands/reports, parity and purity results, measured
performance, and permitted limitations. Stop short only for explicit user
interruption or a precise external/policy condition after independent work is
exhausted; report that as incomplete, not as completion.

## Deferred work

These retained directions are **not active x86 completion gates**. They do not
resume AArch64 or enlarge the frozen consumer roster. Activating them requires
new direction consistent with the target pause and scope.

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
