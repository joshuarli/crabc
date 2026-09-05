# Combined native x86-64 completion goal

## Paused handoff — 2026-09-05

Work resumed on 2026-09-05. The expanded 28-case dynamic gate passed at
`6876a064`: both clean builds and extraction, 84 case receipts, identical
product manifests. Host validation and explicit local publication passed for
`.work/x86_64/tmp/materialized-dynamic.J9rIjb/qualification.json`; log
`.work/x86_64/owned-dynamic-expanded-integrated-v2.log`. Subsequent source
changes invalidate that selection. The filesystem mechanism case extends
the catalog to 29; requalification of that expanded catalog remains required.
These component results do not close the planned families or promotion chain.
The paused narrative below records the preceding boundary, not a renewed
instruction to stop.

The user requested winding down the current work, letting the active tasks
finish and commit, and leaving this handoff. Resume only when asked. The
combined goal is **not complete**: AArch64 remains paused, C mimalloc remains
the production backend, and public x86 promotion remains false. The detailed
acceptance criteria below and in the two execution plans remain unchanged.

### Integrated state

- Loader/runtime: musl search/preloads and ORIGIN/AT_SECURE, direct interpreter
  entry, initial dependency cycles and constructor order, retained close,
  deferred GOT/PLT transactions, rollback/RELRO, kernel-main `dladdr`, all-thread
  DTV growth and runtime GD TLS, ELF visibility/scope and interpreter aliases.
  Preserve these implementations; do not restart the historical leaf queue.
- Pthread/process: mapping leases and target kill locks, main/last-thread exit,
  live attributes, dynamic fork/TLS/TSD/robust state, positive 65-live-thread
  pthread/C11 growth, and cancellation-safe join/condition ownership. Syscall
  cancellation covers I/O, sockets/readiness, sleep/waits, open/record locks,
  memory sync, semaphores, signal waits, entropy and SysV messages. SIGCANCEL
  is **33**; timer signal is 32. Ordinary FILE backends, `pclose`, `wait3/wait4`,
  empty `sendmmsg` and nonblocking fcntl retain source non-CP behavior.
- `e3624732` fixes `system` through its source-required public child wait;
  `pclose` keeps the raw wait. `e815c66f` adds timed/clock-selected and shared
  condition transactions, C11 timed status, a typed mutex relock seam,
  normal/shared mutex futex keys, and robust relock error precedence.
  The owned runtime now adds recursive/error-checking mutexes, robust owner
  tracking for those types, and realtime timed locking with C11 timed status.
  PI mutexes remain implementation work. The frozen archive is separate from
  the expanded owned runtime.
- `44f1684b` repairs the legacy condition evidence check: follow exact owned
  atomic helpers and raw syscall edges instead of requiring incidental
  inlining in public symbols. It changes evidence, not runtime algorithms.
- Resolver: `fce59ece` plus `f7015780` qualifies the same unchanged workload
  object through installed **and extracted** static/dynamic products, with
  local configuration files and Docker network isolation. `90bf7896` separates
  verified native evidence from family completion; `9bed2fd3` records the
  executed resolver command while both owning families remain planned.
- Dynamic product qualification: `84ece346`, `836e59b9`, `9bed2fd3` and
  `b1120fa5` wire the canonical gate to preparation, exact case receipts and
  final validation. Both clean builds and the extracted package execute all
  **17** catalog cases. Building remains unqualified; a fresh complete receipt
  is `qualified-pending-review`, followed by explicit local publication.
  Publication replaces only an atomic selection pointer; old receipts remain
  unchanged. Stale source becomes unqualified. Oracle bytes/manifests and
  actual artifacts are retained; evidence becomes host-readable after runtime
  permission tests finish, without following symlink targets.
- `dbc4bfa4` replaces claim-only qualification completion with v2 `planned`/
  `ready` declarations and ordered `qualification-manifest --through GATE`
  execution. All eight promotion gates are still planned; ready declarations
  and execution markers cannot qualify the full chain. Remaining work is in
  `compat/x86_64/qualification-prefix-execution.md`.
- Header aggregate: final worker result and integration are being recorded
  before this handoff is committed.

### Evidence retained at the wind-down boundary

These are component measurements, not final same-revision qualification.

| Evidence | Result and location |
| --- | --- |
| Canonical resolver matrix at `836e59b9` | PASS: one musl reference plus 12 candidate entries, installed/extracted payload identity and expected DNS transitions. Log `.work/x86_64/resolver-extracted-stable.log`; products `.work/x86_64/tmp/owned-resolver-network.KIdHdB/products`; execution `execution/run-1i7isxml/report.json` beneath that run root. The earlier `beihDc` attempt rejected a concurrent source edit during preparation and is not a pass. |
| Canonical system/pclose cancellation | PASS: static ET_EXEC/static PIE and dynamic PIE/non-PIE kernel/direct entry, including contained supervisor failure/timeout cleanup. Log `.work/x86_64/system-cancellation-integrated.log`; product `.work/x86_64/tmp/owned-system-cancellation.8Vba55`. |
| Timed/shared condition component | Worker commit `f5368833`, integrated as `e815c66f`: all 41 scenarios pass against musl and all four installed modes. Worker log `.work/worktrees/owned_pthread_lifecycle/.work/cond-timed-identity-final.log`; product beneath that worktree at `.work/x86_64/tmp/owned-pthread-cond-timed.VgnQF2`. Its earlier aggregate `materialized-dynamic.1WJeci` predates the final identity/error-precedence refinements; use the final focused run for those refinements. |
| Last complete old dynamic matrix | PASS at the `550bb254` runtime plus `906e6d6c` harness: 51 loader, 22 driver, two CRT tests and all then-current cases on both clean builds/extraction. Log `.work/x86_64/three-dynamic-products-integrated.log`; product `.work/x86_64/tmp/materialized-dynamic.uyzJLv`. It predates later cancellation/condition additions and the receipt protocol; do not publish it as current evidence. |
| Shared-runtime I/O cancellation | PASS: 40 ordinary/direct PIE/non-PIE runs at `88fcc133`. Log `.work/x86_64/dynamic-cancellation-integrated.log`; product `.work/x86_64/tmp/owned-dynamic-io-cancellation.gft0iz`. |
| Lua | Dynamic installed/extracted source execution and reproducibility PASS: `.work/x86_64/lua-dynamic-source-integrated.log`, report `.work/x86_64/lua-dynamic-source-build/run-0t1zwhlc/report.json`. Static source/bytecode qualification is also integrated. |
| Allocator huge reservation | `5a48b06f`: 69 C differential values and ten tests PASS; `.work/x86_64/allocator-huge-reservation-integrated.log`. Worker also passed 956 allocator unit tests, quick evidence and performance smoke. Native M2 remains partial; simulated primitives do not replace native huge-page success. |

### Resume sequence and remaining boundaries

1. Read this handoff, `STATUS.md`, `x86-64.md`, `native-mimalloc.md`, and the
   current campaign/ledger before selecting work. Keep source stable during
   builds: the dynamic producer hashes **all nonignored source content and
   modes**, so even a concurrent documentation merge rejects a run.
2. Run `./scripts/dev-x86_64.sh owned-dynamic-sysroot` from a clean committed
   checkout. The new 17-case, three-product qualification path has not yet had
   its first full native run after all these integrations. Review its generated
   `qualification.json`, then use
   `python3 -B compat/x86_64/owned_dynamic_qualification.py publish --receipt PATH`
   to select that exact ignored receipt. Later source edits invalidate the
   selection. This does not close prerequisite families or promote x86.
3. Finish ordered qualification receipt production and validation as specified
   in `compat/x86_64/qualification-prefix-execution.md`: clean revision/content,
   real tools/runtime/artifacts, retained logs/results, fixed pinned Rust paths
   in the scrubbed environment, and retained same-object ABI evidence. Register
   and run real dependency-ready family prefixes. The current first promotion
   gate correctly rejects execution while planned; the private five-case
   admission remains separate and non-promoting.
4. Complete remaining pthread mutex implementations and family evidence.
   The Linux pinned Rust `std::Condvar` uses futexes; its Unix pthread fallback
   is not evidence that Linux Rust-std uses this condition implementation.
5. Continue POSIX family completion from actual current providers. Existing
   `owned_spawn_probe.c` has extensive static evidence, but no equivalent
   installed dynamic semantic matrix yet (the current dynamic base covers
   spawn interposition only). `clone`, `daemon`, `vfork` and several frozen
   kernel-admin providers remain gaps. Audit preserved feature work before
   duplicating it; simple Unix syscall wrappers do not authorize a policy
   framework, and the framework non-goal does not itself waive required APIs.
   `process.signal` is already selected-private; historical prose calling it
   missing is stale. Its legacy aggregate also needs checkout-local scratch
   before execution. Do not confuse private selection with family completion.
6. Continue allocator M2–M11 and Rust-std only after resolving the existing
   automatic tool-review restrictions described below. Requalify installed
   products after native Rust allocator promotion. All 223 capabilities,
   26 families, full product/corpus/performance gates and both plans' final
   predicates must hold at one final source revision.

### Preserved work and external restrictions

All new worktrees, scratch and generated state belong beneath checkout `.work`.
Do not remove historical dirty worktrees or move their contents while resuming.
Completed current worker slices are integrated into main; no new task should be
inferred from their old branch names. Useful source/evidence worktrees are
`owned_dynamic_sysroot`, `owned_pthread_lifecycle`, `owned_stdio_engine`,
`header_declaration_parity`, `native_resolver_network` and `cond_private_evidence`.

Automatic tool review rejected work in `rust_std_unwinder` and
`allocator_m2_metadata`; these tasks were stopped, not retried through another
agent or route. Preserve the unwinder's initial provider `d3ca0e79` and its
unfinished producer/driver/metadata files, and the allocator's uncommitted
snapshot/arena-destruction ownership files. Neither is qualified or integrated
as completed work. The user approved the unwind configuration and delegated
dependency selection; the design record is
`docs/design/x86-rust-unwinder-proposal.md`. Approval of that design does not
resolve the tool restriction. Dummy unwind symbols, libgcc or reduced Rust-std
fixtures cannot replace the required behavior.

The host had zero configured/free 1-GiB huge pages and one NUMA node at the last
inspection. No host huge-page configuration was changed; native huge success
and multi-node qualification remain distinct from simulation.

## Goal prompt

> Implement `plan.md` to completion: fully complete both `x86-64.md` and the
> native Linux/x86-64 scope of `native-mimalloc.md`, working their independent
> critical paths in parallel and integrating them into one qualified runtime.
> AArch64 implementation and qualification work is paused. Preserve its
> existing contracts, implementation, evidence, and frozen parity baseline;
> do not emulate it or transfer its milestone claims to x86. Continue through
> all runtime product/qualification gates and allocator milestones M0–M11,
> including qualified native Rust allocator promotion, final installed-product
> requalification, and public x86 support. Commit coherent completed slices
> with conventional commit subjects. Do not stop at a plan, selected fixture,
> intermediate milestone, stable checkpoint, or handoff. Completion requires
> both plans' full predicates at the same final committed source revision.

This is an execution goal, not a request for another planning exercise.
The two linked plans remain the detailed acceptance contracts; this file
coordinates their scheduling and joint finish without weakening either one.

## Throughput and process budget

Prefer larger, dependency-ready component or family batches over isolated
leaf tasks. The user authorizes revising task boundaries and planning process
to accelerate delivery; no approval is needed merely to widen a coherent
in-scope batch. This does not authorize new product scope or weaker final gates.

The user delegates workflow decisions to the implementer. Treat these documents
as editable execution guidance, not a fixed sequence of paperwork. Prioritize
ordinary installed applications and complete runtime/allocator behavior; revise
task boundaries, sequencing, duplicated checks, and obsolete intermediate gates
when that shortens the path. Preserve the final behavioral, provenance, purity,
and performance requirements, and correct stale contracts rather than repeatedly
working around them. No approval round trip is needed for these in-scope choices.

Use focused tests during development and run expensive aggregate, model, corpus,
or performance suites at meaningful integration or milestone checkpoints.
Do not rerun unchanged suites for every local edit or documentation commit.
Keep a reproducing regression for bugs and verify changed unsafe/interface
boundaries, but do not manufacture a failing test for prose or a behavior-neutral
mechanical change. Reuse existing harnesses and matrices.

Proactively improve test throughput and isolation as harnesses are touched:
parallelize independent checks with bounded concurrency, reuse development
artifacts where valid, and give each run private scratch, reports, and process
ownership. Preserve cold-build reproducibility and clean-revision qualification
at the final gates; faster iteration must not hide failures or weaken evidence.

Record a result once with its owning contract or report. Update planning/status
only when priorities, prerequisites, or completion state materially change;
do not require a new report, handoff essay, or every-document update per slice.
Commit coherent validated slices promptly. Final qualification still requires
all acceptance predicates against the same final committed source revision.

## Scope and authority

Read `AGENTS.md`, `SCOPE.md`, `COMPATIBILITY-PROFILE.md`, `STATUS.md`, both
execution plans, and their relevant machine-readable contracts before choosing
work. Explicit user direction and the governing scope take precedence. This
combined goal supersedes historical instructions that pause all mimalloc work
or resume AArch64 allocator development; only native x86-64 is active here.

- Target native Linux/x86-64 little-endian, Linux 5.10 or newer, using the
  pinned native environment. Do not introduce new platforms or a portability
  framework.
- Preserve the runtime baseline fixed by `x86-64.md`: source
  `3e100d45c5a0798c2d3862d5e2eef584c610ccf9`, all 223 capabilities, all 26
  required families, and the recorded digests. Never refresh it to absorb
  drift or eliminate required work.
- Port mimalloc v3.5.0 at its immutable upstream revision and hash. Preserve
  algorithms, memory orderings, ownership, lifecycle, and observable behavior;
  do not invent an allocator. Keep the exact C source as a separate test oracle.
- Use pinned musl 1.2.6 for C/POSIX evidence and Rustix only in its permitted
  test role. Glibc and ambient target runtime inputs are never fallbacks.
- No AArch64 implementation/qualification campaign, emulation, CI-workflow
  work, unrelated cleanup, formatting, linting, pre-commit hooks, or remote
  pushes. Shared source changes must preserve the paused target's contract.

## Two parallel workstreams, one integration owner

### Runtime parity

Follow `x86-64.md` and `compat/x86_64/parity.toml`, closing finite capability
families and the owned static and dynamic products in dependency order.
Advance static delivery without waiting for unrelated dynamic work; establish
general loader architecture while independent runtime families progress.
Do not resume a one-symbol/export-count campaign or replace ordinary installed
runtime behavior with private fixtures.

Continue runtime work with the accepted C allocator until the native Rust
backend qualifies. Allocator development must not unnecessarily serialize
independent syscall, ABI, CRT, loader, facade, or sysroot work.

### Native x86-64 mimalloc

Follow the active x86 handoff in §26 of `native-mimalloc.md`, its full milestone
definitions, source map, API/mode inventories, and gate manifests. Preserve the
allocator launcher's checked `.work/` containment, then establish target-qualified
baseline and milestone gates. Imported AArch64 M0/M1 closure and partial M2
records are preserved evidence, not x86 completion.

Milestones are qualification boundaries, not blanket implementation barriers.
Work against stable interfaces and actual dependencies: dependent implementation
and integrated regressions may proceed while prerequisite qualification finishes.
M3 cannot be declared complete until all eight M2 components qualify. Work
independent components in parallel where ownership permits. Never substitute
additional trace counts, documentation, selected leaves, or a partial-gate exit
for component closure.

### Shared runtime/allocator boundary

The root integrator owns shared contracts and final integration. Assign one
writer to each shared file or interface, and land interface changes before
dependent implementations. Coordinate these boundaries explicitly:

- raw memory/entropy/syscall primitives, page and address geometry;
- allocation-free bootstrap, process state, errno, and recursion behavior;
- TCB/TLS ownership, pthread creation, teardown, cancellation, and fork;
- pointer-derived allocation ownership, ABI exports, weak symbols, and
  interposition; and
- CRT startup, loader/DSO lifecycle, installed sysroot, and dependency purity.

Allocator engine/API work may proceed before the general runtime is complete.
M8 integration and M10 promotion must wait for their actual owned-runtime
prerequisites. Neither an oracle-hosted allocator test nor a runtime test with
the C backend proves final native Rust allocator integration.

Use independent agents for bounded parallel work under the current orchestration
skill and explicit user model restrictions; do not duplicate that routing policy
here. Give each worker a concrete deliverable, nonoverlapping ownership, required
evidence, and a repository-local worktree. The root reviews and integrates results.

### Relationship to `sysroot.md`

`sysroot.md` describes the earlier AArch64 owned CRT/sysroot work. Its recorded
CRT/sysroot-purity deliverable is complete; full target-runtime Rust purity
remains blocked by the C allocator. Its literal no-native-dependency hard gate
is therefore not a completed whole-runtime claim. See
`docs/design/crt-and-sysroot.md` and `docs/evidence/crabc-owned-sysroot.md` for
that explicit distinction. These are recorded AArch64 results, not current
x86 qualification.

Do not defer the x86 sysroot until after mimalloc or start another AArch64
campaign from `sysroot.md`. The owned x86 static/dynamic sysroots are required
products inside `x86-64.md`; build them in parallel using the accepted backend,
then requalify their final Rust-allocator integration and purity here. Native
x86 allocator completion does not clear the paused AArch64 full-runtime purity
blocker; that requires separate future AArch64 promotion and evidence.

## Execution and evidence discipline

1. Inspect the current commit, dirty work, worktrees, contracts, and available
   evidence. Preserve accepted work and recover unfinished changes before
   replacing them. Derive the next work from unmet gates, not old narratives.
2. Keep all new mutable development state under checkout-local `.work/`:
   worktrees, scratch, sources, Cargo caches/targets, sysroots, and report
   backing storage. Validate physical paths and reject traversal/symlink
   escapes. Override tool defaults before execution; do not use external
   `/tmp` or named external Docker storage. Keep separate workstream paths.
3. Choose coherent behavior or component slices that shorten a required
   product's critical path. For bugs, observe the smallest isolated failing
   regression before fixing the pinned-source root cause.
4. Run the nearest hard judge first, then relevant boundary, differential,
   aggregate, lifecycle, fault, model, and performance evidence as required.
   Repair demonstrated test-contract defects with oracle evidence; never
   weaken acceptance merely to make a gate green.
5. Commit completed slices promptly using `feat`, `fix`, `test`, `refactor`,
   `perf`, `build`, or `docs` subjects with a meaningful scope. Do not bundle
   unrelated work, invoke hooks, or push. Run required clean-revision gates
   at milestone/integration checkpoints; rerun affected evidence after later
   code changes rather than inheriting an unrelated revision's pass.
   Fold trivial documentation/comment fixes into the related implementation
   or next coherent batch; reserve standalone docs commits for substantial
   planning or contract changes. Do not rewrite settled history just to regroup
   earlier small commits.
6. Update concise architecture-qualified handoffs and machine-readable state
   with exact remaining conditions, commands, revision, report paths, and
   results. Do not inflate status files with per-leaf histories or count stale
   generated reports as current evidence.
7. Continue from the next unmet gate. Expected partial results, preexisting
   failures, or task size are unfinished work, not successful terminal states.
   If genuinely blocked on new authority or unavailable external resources,
   report the exact blocker and required action without claiming completion;
   pursue safe independent in-scope work while available.

## Exact joint completion predicate

The goal is complete only when all of the following hold together:

1. Every item in `x86-64.md`'s exact full-completion definition passes: the
   immutable baseline and complete accounting, all 26 required families,
   reproducible installed static and dynamic products, the ordered consumer
   and qualification chain, native performance, computed promotion readiness,
   validated public support, and the post-promotion aggregate rerun.
2. Every applicable native x86 allocator milestone M0–M11 and every item in
   `native-mimalloc.md`'s final definition of done passes. There are no hidden
   incomplete components, remaining conditions, unclassified applicable
   upstream behavior, waived required tests, or unqualified performance gates.
3. Native Rust mimalloc is the default backend for the qualified x86 product.
   Its final target production graph/artifacts exclude C mimalloc; the pinned
   C oracle remains isolated for tests. Do not remove the paused AArch64
   backend or imply its promotion to satisfy an x86 purity check.
4. Rebuild and requalify both installed x86 static and dynamic products after
   backend promotion, including allocator ABI, TLS/pthread/fork, loader/DSO,
   consumers, reproducibility, dependency purity, and performance. A runtime
   pass earned only with the former C backend is insufficient.
5. Required final reports attest the same committed, clean source revision,
   target, pinned inputs, and applicable test configuration. Documentation and
   machine-readable status agree with those results; no required work remains.

Finish with the final commit, the proving commands and report locations,
upstream/source-map and dependency-purity results, measured performance, and
any explicitly supported limitations already permitted by the contracts.
Do not mark the goal complete if either linked program remains incomplete.
