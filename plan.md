# Complete and qualify crabc's native x86-64 runtime

## Goal

Finish the selected native Linux/x86-64 runtime and the faithful Rust mimalloc
v3.5.0 implementation, qualify owned release products, and promote the native
allocator and public x86 support. Feature completeness remains the foundation: every
selected capability, source operation, API and applicable mode must work through
its intended runtime path, including errors, ownership and composition.

User direction (2026-10-02): the feature milestone is complete; reactivate all
previously deferred work. Reconcile current-source correctness, ownership and
tooling first. Investigate performance and qualify release products afterwards;
switch the x86 allocator default and promote public support only when their
existing prerequisites pass. C mimalloc remains selected and public x86 support
remains disabled until those transitions. Historical receipts are not current
qualification, and deliberately deleted reports are not claimed as retained.

User direction (2026-10-02): reduce qualification bookkeeping. Prioritize core
product defects and direct regression evidence; reuse existing runners and
results. Do not expand receipt schemas, duplicate case catalogs, pin helper
revisions unnecessarily or require new administrative proof for each artifact.
Use enough validation to catch real failures without making its machinery a
separate product. Actual failures and unsupported host requirements stay open.

User direction (2026-10-02): ordinary x86 baseline promotion may proceed while
physical NUMA and explicit huge-page modes remain unqualified, including the
additional optional 2-MiB mode found during source review. Floor-limited
total-memory rows use no-regression checks with raw measurements retained;
other performance requirements remain active. Neither decision waives a
functional failure or establishes a hardware qualification pass.

`AGENTS.md` owns scope and working rules. This file is the sole implementation
plan and progress handoff. User direction takes precedence over older gate or
qualification requirements in repository instructions and manifests. Preserve
exact source pins, ABI contracts, selected semantics, failure evidence and
paused AArch64 behavior. A real behavior failure remains a bug.

## Progress status

Update this small section in place when the implementation frontier changes.

- **Feature status:** the selected surface is implemented. Two native opt0
  failures remain open: worker attachment on a legal 16-KiB pthread stack and
  the public-Theap consumer's child-subprocess phase. Accepted-C products and
  larger native worker stacks pass. Constructor and aggregate-copy improvements
  pass focused checks; they do not establish that either failure is repaired.
- **Resumed (2026-10-03):** source/compiler work and ordinary valid-client
  checks are active with parallel lanes and continuous integration. Historical branches
  and raw failures are retained; the two reported opt0 failures remain open.
- **Core fixes:** mixed-family resolver configuration now retains the first three
  nameservers in file order, and C zero-timeout batches retire their sockets and
  preserve unanswered-result semantics. Rust filename matching preserves literal
  bracket ranges and opposite-case classes. Accepted-C tiny calloc and aligned allocation satisfy
  x86 natural alignment; open/openat use their actual variadic ABI; normal worker
  return retires pending loader diagnostics. Generic post-exit frees complete local
  collection before unownership. Heap key release refusal retains its exact lease,
  arena-record release refusal restores its live slot, consumed completion errors
  leave it cleared, and failed registry-bitmap cleanup retains its terminal token.
  Prepared or consumed child Heap images refuse initialized projections. Child
  TLS growth/free now separates consumption from completion and withdraws terminal
  roots while retaining only exact live allocation custody. Arena allocation and
  visitation use the actual Heap sequence and source population sampling.
- **Ownership and construction:** initialized Heap/Theap, metadata, child and
  attachment-only images use final storage. Non-consuming exit prefixes retain
  the source engine across Rust unwind and change only their scalar phase.
  Owner engine/fast-path reads use narrow raw projections; retained-client PageMap
  lookups preserve source check modes. Retained sessions and callback pairing
  project only the local or immutable fields they need. Secure metadata uses the actual mapping
  owner. Compiler evidence removes large aggregate temporaries; ordinary tests
  establish these changes without closing either reported runtime failure.
- **Verification:** merged source passes nine compiler profiles and focused opt0
  ownership/worker/collection checks. Fresh debug comparisons cover selected-C
  dynamic allocation and native fork, signals, timers, stdio, locale, TLS, loader,
  CRT/helpers and Rust facade composition. Secure-1/2/3/4, stat-1/2 and explicitly
  seeded guarded/stat combinations pass 4,314-key source comparisons. Default
  entropy placement differences and guarded-debug oracle failures remain retained;
  the latter combinations are unproved. No qualifying timing or release pass is
  claimed. The opt0 TSD runner's atomic check now follows called helpers; its direct
  runtime and helper-disassembly evidence passes. The cold startup output timeout came from a FILE surrogate
  violating the pinned delayed-flush contract; real FILE and registered allocating
  callbacks have distinct passing checks, with the original timeout retained.
- **Compiler frontier:** eight missing binary80 and float-complex helpers now have
  owned providers; the archive has 40 entries. Numerical, ABI, closed-consumer and
  ordinary owned debug four-mode checks pass. Target-gated Rust assembly preserves
  the legacy source boundary. Complete debug dependency closure remains unproved
  for relocated read-only data, GOT and source-core forms; no release pass is claimed.
- **Qualification:** the frozen inventory remains 223 capabilities and 26 families.
  Eight ordered gates are ready, zero qualified. Structural validation certifies
  no runtime or release behavior. C remains selected and public x86 support disabled.
  Correctness precedes performance, release, the default switch and public promotion.
- **Inputs and tooling:** authenticated core image `a635e97c4bb5` and allocator
  image `3d5e3a88e4f5` are restored, alongside pinned source oracles, package
  archives, std/provider vendors and Lua/Rustybench/Rustix inputs. Current tool
  authorities authenticate these inputs; resolver and C performance launches use
  the inspected immutable image ID. Frozen ABI/header/coverage digests are unchanged.
- **Evidence and cleanup:** `.work/x86_64/reports/integrated-lanes/` retains
  settled lanes' original programs/source, raw failures and focused proofs before
  their worktrees are removed. Merged checks are in
  `.work/x86_64/tmp/resume12*-merged-*.log`. Existing allocator and hardware-policy
  reports remain available. Historical receipts are not transferred to current
  products; other projects' Docker state remains outside cleanup.
- **On resume:** address actual allocator failures, then investigate performance
  on an uncontended host and qualify the final merged-source release cohort. Use
  existing runners and direct regressions; avoid new catalogs or proof layers.
  Baseline allocator qualification, post-switch reruns and public promotion remain open.
  No qualifying timing or full release-family pass is claimed.
- **Constraint:** earlier crash-debugging lanes were rejected by automatic safety
  review and were not restarted. Continue with source/compiler improvements and
  ordinary valid-client checks; do not resume those rejected workflows.
- **Host:** two allowed NUMA nodes and free explicit 2-MiB/1-GiB pages are unavailable. These
  optional hardware modes remain unqualified; ordinary baseline promotion may
  proceed once its other prerequisites pass. Do not repeat unchanged denied
  `mbind`, alter shared pools/security policy, rent resources or reboot without
  authorization.

## Parallel lanes

Campaign work resumed at the user's request on 2026-10-03. The following
coordination rules apply to the active correctness and qualification work.

Use `.agents/skills/lanes/SKILL.md` for Codex coordination and its referenced
lane instructions. Keep 16 `gpt-6.1-sol` medium lanes occupied while useful
campaign work remains, with one difficult deliverable and an exclusive file
boundary per lane. New assignments use medium thinking as directed by the user;
existing assignments may finish at their current setting. The parent alone
integrates to `main` and updates this file.
Each lane works in `.work/worktrees/lane-<id>`, owns its mutable build state and
uses the smallest relevant correctness checks while preparing qualification.
Final release evidence must use current merged source and its pinned environment.
Run qualifying benchmarks on an uncontended host, after parallel preparation;
do not manufacture lane occupancy with duplicate checks during measurement.

When a lane finishes, integrate its coherent changes, preserve needed original
source/programs/raw failures in existing ignored reports, remove the settled
worktree, and start a successor. Keep `.work/tmp/lane-agents.txt` current. No
shared mutable build outputs, scheduling board, handoff schema, duplicate status
file, prose archive or wave ceremony. Do not throttle builds, run formatters,
linters or hooks, or push a remote. Avoid duplicate builds when an unchanged
existing debug program answers the actual question.

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
  startup or `dlopen` functional row open; compare performance after correctness.
- **Transparent huge pages.** The runtime leaves the process THP policy as
  musl does (no `PR_SET_THP_DISABLE`; upstream `allow_thp` stays 1). The
  native allocator's own arena reservations opt out of huge pages with
  `MADV_NOHUGEPAGE`, so first-allocation residency is musl-like. This is a
  recorded divergence from mimalloc v3.5.0 and carries a
  `known-differences.md` entry and a pinned-C correctness differential.
  Comparative performance evidence remains required for qualification.

The accepted `libmimalloc-sys` 0.1.49 backend bundles mimalloc v3.3.2; it is
**not** the exact v3.5.0 engine oracle. Preserve separate candidate, accepted-C
integration comparison, and pinned-v3.5.0 differential inputs.
Preserve the resolved musl BSD-random exception and approved cryptographic
primitive boundaries in `AGENTS.md`; do not reopen them as blanket blockers.

## Execution

Start from current source, the selected behavior, callers, tests and existing
unfinished branches. Distinguish missing implementation from missing release
evidence. Prioritize the longest implementation dependency path and actual
missing behavior. A bookkeeping-only lane or another replay of a settled fact
must not displace a feature implementation lane.

For a bug, first reproduce the smallest legal failure with an isolated regression,
then fix the source cause and retain the regression. For a new feature, specify
its observable behavior and invariants with focused tests. Use the nearest hard
judge: type checker, targeted debug test, actual C/source differential or small
Miri/Loom case. Widen checking only when changed behavior or a failure warrants it.

Implement against stable interfaces while related features are developed. Keep
shared state single-owner. Commit coherent increments and integrate continuously;
no full-cohort rebuild is required between implementation increments. Use a
fixed current-source cohort for final qualification. Preserve unsafe caller obligations, explicit state
transitions, atomics and short validated projections. Never weaken a contract,
mask a failure, fabricate a pass or substitute an easier feature.

Keep raw evidence and retained products inside the owning checkout's ignored
`.work/` boundary. Authenticate inputs needed by a focused check; keep original
failures and configuration identity. Do not add a runner, receipt schema or
per-artifact validator for every case. Preserve historical receipts as written.

## Runtime feature completion

Implement every selected behavior in the frozen 223-capability mapping and
25 functional families. Preserve the 26-family frozen inventory; the performance
family is active for final qualification. Private native development profiles
exercise the intended implementation before public/default promotion.
Feature implementation and current-source qualification remain distinct claims.

### Families and public ABI

| Area | Completion requirement |
| --- | --- |
| Headers and layouts | Complete installed header paths, selected strict/POSIX/XOpen/GNU/BSD/large-file profiles, typedefs/records/enums/constants/macros/data/functions, C and selected C++ linkage, LP64/x87 layouts, transitive includes, and installed-tree isolation. Zero missing selected declarations or unclassified callable owners. A deferred provider disposition can close header routing, not implementation or archive extraction. |
| POSIX runtime | Coherent filesystem/directory/traversal, descriptors, environment, process control, signals, and kernel-administration behavior, including aliases, errno/TLS, shared state, cancellation where selected, errors, output writes, and ownership. Exercise changed behavior through owned C runtime entries as well as the corresponding Rust-native paths. |
| pthread/C11 and TLS | Selected lifecycle, attributes, identity, join/detach, synchronization, once, TSD, cleanup, cancellation, signals, timers/thread notification, atfork/fork, and exit. Main, loader, worker, static TLS, dynamic TLS, DTV/module IDs, and `__tls_get_addr` use one ownership model. Exercise selected static/dynamic composition and focused concurrency cases. |
| Text, math, locale, stdio | Selected iconv/wide/multibyte, regex, word expansion, clock/calendar, and complete stream/path/position/format/scan behavior. One stream engine owns locking, buffering, byte/wide orientation, permanent/created/adopted/memory/cookie streams, positioning, errors, and exit flushing. Preserve restricted locales, x87/MXCSR/fenv and long-double ABI, rounding, signed zero, NaNs, and exceptions. |
| Resolver | End-to-end conventional files and bounded C netdb/resolver behavior: A/AAAA/CNAME, search, UDP/TCP fallback, timeout/retry/server failover, reply validation, errors, cancellation/thread interactions, and result lifetime. Prove controlled-network and file behavior through owned C products; a parser or typed Rust transport alone is insufficient. |
| C compatibility and binding | Selected crypt/crypt-helpers through approved primitives, allocation, legacy compatibility, process globals, and final callable/data provider closure. Verify names, aliases, bindings, visibility, sizes, versions where selected, and static/shared ownership. Use ordinary archive extraction or an explicit structural oracle/builtin/consumer boundary—not hidden unresolved providers that happen not to be extracted. |
| Loader | General admitted dependency graphs, not fixed fixture graphs: self-relocation/entry, kernel main image, search/RPATH/RUNPATH, mapping/protection/RELRO, supported RELA/RELR relocations, weak/global/protected scope, RuntimeV1, initial/runtime TLS, DTV growth, constructors/finalizers, and selected `dl*` introspection. Prove concurrency, callbacks/reentrancy, fork, retained handles, reopen, malformed input, and failed-load rollback. |
| CRT, builtins, sysroot | Owned static/static-PIE and dynamic PIE/non-PIE entry, libc handoff, main lifecycle arrays, finalization, compiler helpers, deterministic link interface and installation. Exercise real application consumption with focused debug links. |
| Rust facade and remaining families | Preserve and complete every other frozen family and exact semantic mapping, including direct native API, error, ownership, dependency and compiler-input ownership. A C ABI pass does not prove the Rust-native path or vice versa. |

For pinned musl parity, successful `dlclose` validates a handle but does **not**
unmap the object or invoke its destructors. Reopen observes retained state;
DSO destructors run at process exit. Failed load transactions still release
their owned mappings. Do not implement physical last-close unloading and call
it the selected musl contract.

Use existing family matrices for routine ABI probes, feature profiles,
C/C++ signatures, symbol/data ownership and focused oracle comparisons. Keep bespoke fixtures for genuinely unusual ABI, floating-point,
callback/lifetime, TLS/fork/signal, ELF, privilege, or network behavior. Private
opt-in features and extra exports do not create new frozen capabilities or
waive family closure.

### Owned products

Implement all four link modes: ordinary static `ET_EXEC`, static PIE, dynamic
PIE and dynamic non-PIE. The sysroot implementation owns headers, CRT objects,
`libc.a`, shared libc, interpreter/compatibility alias, compiler builtins,
allocator selection and deterministic link specifications. A pinned host
compiler is permitted; ambient target headers, CRT, libc, compiler runtime,
loader or undeclared libraries are not target implementation inputs.

Static delivery must work independently of dynamic startup. Use focused debug
application links to exercise argument/environment/auxv/program-name publication,
TLS/errno, constructors/finalizers, allocation, pthread/C11/cancellation/fork,
stdio, files/processes/signals/time and resolver composition when those features
change. Verify owned compiler-helper use with a focused consumer.

Dynamic delivery must support a general initial dependency graph and runtime
plugin, RuntimeV1 handoff, search/relocation/scope, retained close/reopen,
selected `dl*` APIs, initial/dynamic TLS and DTV growth, and cross-DSO ownership.
Test concurrency, callback reentry, fork repair and failed-load rollback at the
changed boundary. Inspect relevant ELF/link inputs for ownership and ABI errors.
Independent reproducibility, full installed/extracted matrices, packaging
certification and selected corpus runs are required final release work.

## Native allocator feature completion

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
inventory, intentional differences and focused unit/differential/integration
evidence in the existing contracts. Each applicable Linux/x86-64
interface and mode must be implemented and verified; inapplicability requires
source-backed reasons, not unavailable hardware or an inconvenient test.
Upstream changes require separately reviewed source/inventory/map diffs and
focused correctness and model checks for affected behavior.

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
7. **No production scaffolding.** For feature completion remove per-allocation
   side ledgers, live-TLS-owner/exact-post-exit registries, historical-thread
   scans, per-call park/resume, global ordinary-operation schedulers, and
   top-level fixture-geometry route products. Keep useful witnesses test-only.
   A constant-size page-local lifetime aid needs a documented source invariant,
   model and lifetime evidence; it cannot recreate a side ledger.

The architecture ratchet requires zero local-path global scheduler operations,
structural PageMap leases, owner/client scans, remote owner-registry scans,
and extra control bytes per live allocation; no per-call suspend/resume,
ghost-owner admission, or compiled forbidden scaffolding. Actual source page
metadata is not extra per-allocation control state. Metadata ownership and reclamation must follow the source lifecycle.

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

### Source feature groups

The existing M0–M8 source inventories identify applicable features. Their
milestone admission and full target-qualified matrices are active qualification
requirements; do not confuse historical source completion with a current pass.

| Area | Required implementation |
| --- | --- |
| Source foundations | Exact source/archive/license pin, source map, configuration/layout, typed atomics/provenance, source random machinery and separate C oracle. |
| Memory substrate | VM, metadata, scalar bitmaps, PageMap, arenas, initialization, failure handling and allocation-free bootstrap. |
| Local engine | Heap/Theap, queues, direct caches, local allocation/free, retirement/reuse and every selected bin/Page class. |
| Allocation API | calloc, realloc, alignment, usable size, medium/large/singleton, collection, OOM preservation and C adapter behavior. |
| Concurrency/lifecycle | Persistent independent owners, remote publication, generic exit, abandonment/reclaim/release, callbacks, source lifetime and removal of forbidden scaffolding. |
| Owned APIs | All applicable Heap, Theap, arena, managed-memory and subprocess operations, including child and huge-page ownership. |
| Configuration | Applicable options/environment, callbacks/deferred free, statistics, visitation, debug, secure levels and guarded/optional ISA behavior without raising the baseline. |
| Runtime composition | Actual libc startup, constructors, pthread/TSD/cleanup/cancellation/fork, errno/interposition, loader/DSOs and Rust/Lua consumer interfaces. |

Preserve the original unmodified upstream workloads as release inputs.
Use a focused workload when it exercises an actual feature or regression;
large stress/soak matrices, leak certification and full milestone reruns are
final release work. Small ownership/model tests remain appropriate for unsafe
state transitions. Fault injection belongs at the actual primitive boundary.
Comparative memory/size ratios and performance thresholds become active after
current-source correctness and architecture checks pass.
For total-memory metrics dominated by mandatory live payload or kernel charge
granularity, require no regression rather than a ten-percent reduction. Keep
the raw reference and candidate measurements and the explicit row threshold;
retain the existing reduction requirement for other memory metrics and CPU.

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
leaf/callable equivalence, target dependency direction and artifact ownership.
Native implementation cannot borrow C behavior as recovery.

The dynamic RuntimeV1 handshake transfers validated runtime/TLS coordinates,
not allocator pointers. Loader metadata uses its raw mapping owners; libc
initializes its native process state after validated TLS/environment/auxv and
before constructors. Exercise absence of cross-backend ownership through
focused debug PIE/non-PIE and kernel/direct-loader consumers.
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
from loader enumeration. Exercise backtrace and panic cleanup/resume across
calls, threads and DSOs through focused debug static/dynamic consumers.

Implement the std, dependency-bearing std, build-std, LTO, Lua/source-build and
selected corpus interfaces faithfully. Use focused debug consumers to find
missing symbols, ABI/ownership behavior, unwind support and linker integration.
Dummy unwind symbols, hidden unresolved providers, C recovery or substituted
behavior are not implementations. Full frozen consumer/corpus rosters, optimized
IR assessment and repeated installed/extracted qualification are release work.


## Development commands

Use `./scripts/dev-x86_64.sh --help` and the owning harness documentation to
find the relevant debug/native component command. For direct Cargo in the
pinned development environment, run `scripts/lanes/rust-check.sh env
CARGO_PROFILE_DEV_OPT_LEVEL=0 CARGO_PROFILE_TEST_OPT_LEVEL=0 cargo test --locked`
with the affected package/test. Type-check
only the profiles whose interfaces changed. Use small existing Miri/Loom
commands for the affected ownership/atomic transition.

Use `campaign-status`, the ordered qualification dispatcher and
`qualification-candidate` to establish dependencies and reuse one authenticated
current-source cohort. Full allocator milestone qualification, release builds,
performance commands and promotion checks are authorized at their proper stage.
Keep focused debug routes for diagnosing failures before rebuilding a cohort.

Restore pinned development tools when needed; building a compiler/test environment
is distinct from a release build of the runtime. A host read-only replay of an
original native program may establish a focused behavior, with its actual context
recorded. It must not be relabeled as a pinned-image or release qualification run.

## Qualification sequence

1. Integrate or settle every open feature lane, remove obsolete local state,
   and preserve source history, exact pins and compact original regressions.
2. Restore pinned native tools and corpus inputs; reconcile current-source
   ownership, architecture and correctness across runtime, allocator and consumers.
   Repair reproduced failures before performance investigation.
3. Investigate algorithmic work, syscalls, allocation and codegen. Measure the
   native allocator against both accepted C integration and exact v3.5.0, and
   runtime against pinned musl, with authenticated uncontended measurements.
   Fix demonstrated regressions without changing selected semantics.
4. Qualify the final owned release cohort: all four link modes, headers/ABI,
   process/resolver/loader, std/LTO and source consumers, installed/extracted
   products, reproducibility, allocator M0–M9 and architecture. Qualify the
   ordinary baseline; record physical NUMA and explicit 2-MiB/1-GiB-page modes
   as unqualified until a suitable host supplies actual evidence. Follow the
   manifest's ordered chain, whose performance gate is last;
   optimized products needed for measurements may be built before final admission.
5. Pass baseline M10 prerequisites and the runtime performance receipt, switch only
   the x86 default, then rerun the required post-switch qualification on that
   source revision. Preserve the paused AArch64 allocator and frozen contracts.
6. Promote public x86 support only with complete current-source receipts and
   default products. Keep optional hardware modes explicitly unqualified; do not
   waive missing baseline inputs or functional failures.

## Definition of completion

Completion requires all of the following together:

- The frozen baseline/digests remain intact. All 223 selected capabilities and
  25 functional families have their intended native implementations and callable/
  data ownership, with no unimplemented selected behavior or hidden fallback.
- Owned CRT/compiler helpers, sysroot installation and all four link modes work
  through their intended interfaces. Native runtime and Rust-facade behavior is
  complete within the compatibility profile.
- The Rust mimalloc v3.5.0 port implements every applicable source operation,
  API and configuration, including actual bootstrap, Page/arena/metadata,
  concurrency, child/fork, secure/guarded and runtime integration behavior.
  Production architecture, provenance, failure ownership and source ordering
  are coherent; no forbidden x86 scaffolding is needed by the native route.
- Every demonstrated functional defect is fixed with its regression retained.
  Focused debug/type/ABI/source-differential and ownership/model checks provide
  evidence appropriate to changed behavior. Report unresolved behavior honestly;
  lack of a release receipt is not an implementation defect.
- Current-source baseline qualification, performance and allocator promotion
  contracts pass with authenticated raw evidence, including reproducibility
  and installed/extracted checks. Optional physical NUMA and explicit huge-page
  modes are unqualified unless actual host evidence establishes a pass.
  Deleted historical evidence cannot establish a pass.
- Native Rust mimalloc is the qualified x86 default and public x86 support is
  enabled through its promotion contract. Paused AArch64 behavior, backend
  selection and frozen evidence remain intact.
