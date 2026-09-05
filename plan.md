# Combined native x86-64 completion goal

## Active integration — 2026-09-05

The combined goal is **not complete**. AArch64 remains paused; C mimalloc
remains the production backend; x86 public promotion remains false. Resume
from the integrated runtime and allocator work below rather than restarting
implementation or the earlier leaf queue.

### Integrated baseline and evidence

Runtime revision `3369c153` includes the previous installed stdio, filesystem,
IPC, spawn/wordexp, robust-mutex and runtime-loader work, plus:

- `05e491dd`: deferred GOT/PLT transactions, all-thread TLS publication before
  atomic pointer stores, permission rollback and RELRO restoration before
  callbacks. The pinned musl GOT/RELRO fault is a documented safety correction,
  not a parity claim.
- `04bc4f3e`: `dladdr` reports the first mapped page for kernel-owned PIE and
  non-PIE executables without making their mappings rollback eligible.
- `7461c67b` and `3369c153`: mapping leases and per-target kill locks,
  SIGCANCEL syscall-PC-window delivery for public `read/readv/write/writev`,
  cleanup/TSD composition, fork state preservation, and explicit FILE-lock
  retirement before FS+32 clearing. Ordinary FILE descriptor I/O remains
  non-canceling. SIGCANCEL is **33**; signal 32 is musl's timer signal. The
  creator blocks SIG33 across clone and the worker publishes FS+32 before
  unmasking it.
- `6d52a714`: incremental arena and OS metadata commitment. The OS-only
  on-demand correction commits backing before publishing capacity and keeps
  failed-page ownership and exact committed-prefix release accounting.
  M2 remains partial.

Both installed-product component gates pass together at `3369c153`:

- `./scripts/dev-x86_64.sh owned-static-sysroot`: 56 harness tests, all 24
  isolated consumer jobs with four workers, installed/extracted ET_EXEC and
  static-PIE modes, and two-build reproducibility. Log:
  `.work/x86_64/resume-cancellation-static-integrated.log`; evidence:
  `.work/x86_64/tmp/crabc-x86-64-owned-static-sysroot.th91gC`.
- `./scripts/dev-x86_64.sh materialized-dynamic-sysroot`: 46 loader tests,
  18 driver/package tests, two CRT-mode tests, installed/extracted PIE and
  non-PIE consumers, deferred binding, 41-module worker TLS, constructor exit,
  scope/rollback and reproducibility. Log:
  `.work/x86_64/resume-cancellation-dynamic-integrated.log`; evidence:
  `.work/x86_64/tmp/materialized-dynamic.Gcawm6`.

The allocator metadata candidate `358a369e` passed 943 unit tests,
`allocator --quick`, and the 23-value on-demand differential in
`.work/worktrees/allocator_m2_metadata/.work/`. Root integration `6d52a714`
adds source-header provenance corrections with no further implementation
change. Its target reports live under that worktree's
`.work/allocator-x86_64/reports/allocator/x86_64/`. This is component evidence,
not native M2 closure or final same-revision qualification.

### Current independent work

All worktrees below are beneath `.work/worktrees/`. Inspect branch and dirty
state before integrating; ongoing work is not a completed feature merely
because an earlier checkpoint is committed.

| Worktree / branch | Current task |
| --- | --- |
| `allocator_m2_metadata` / `allocator/m2-native-metadata` | Distinct huge allocation backing in the same `ProcessArenaBacking` registry, preserving source ownership and partial-failure cleanup. The incremental metadata candidate is already integrated; do not reapply its duplicate prerequisite. |
| `owned_dynamic_sysroot` / `x86/owned-dynamic-sysroot` | Complete source search policy: environment, first-load dependency ancestry, RPATH/RUNPATH and ORIGIN, with authenticated installed-driver options and ordinary consumers. Pinned musl `dlopen` roots lookup at the main object; do not invent return-address caller semantics. |
| `owned_pthread_lifecycle` / `x86/owned-pthread-lifecycle` | Dynamic initial/last-thread exit using the existing shared logical task accounting and the dynamic ordinary-exit owner; qualify cancellation, surviving-worker TLS and DSO finalization. |
| `owned_stdio_engine` / `owned-stdio-closure` | Extend the proven syscall cancellation protocol to the next source-defined descriptor cancellation points. The first public-I/O and FILE-retirement batch is already integrated. |
| `provider_roster_accounting` / `x86/provider-roster-accounting` | Complete the retained scalar `fma/fmaf`, `hypot/hypotf`, `log1p/log1pf` raw-bit/fenv component using pinned-musl generation/PIC and installed-driver machinery. Binary80 is separate. |
| `header_declaration_parity` / `x86/header-declaration-parity` | Reconcile declaration identity, source forms and named/prototype declarations against the compiler-derived header matrices, then qualify the first family. Deferred callable providers remain a separate C-ABI obligation. |

Dynamic fork still needs an explicit loader transaction covering both graph
mutation and constructor/finalizer ownership, followed by surviving-thread TLS
registry adoption and libc lifecycle repair. A copied callback-owner TID or
vanished worker token must not remain live in the child. Preserve recursive
constructor/fork behavior, FS+24/32/40 state and source unlock/callback ordering.
Do not treat enabling the static fork branch as dynamic fork qualification.

Allocator follow-ons must retain a distinct huge owner, not an ordinary
`Mapping` impersonation or an invented capacity limit. Full metadata lifecycle,
cross-thread publication and publication/cleanup failure matrices remain open,
as do the other unqualified M2 components. Keep source cleanup/startup order.

Preserve unrelated historical dirty worktrees. Use the normal sharded Python
runner for broad accounting checks; the retained 95/96 unsharded timeout is
not a pass. Continue independent runtime and allocator work under the current
`orchestrate` skill, with integration and final qualification owned by root.

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
