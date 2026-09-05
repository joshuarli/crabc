# Combined native x86-64 completion goal

## Active integration — 2026-09-05

The combined goal is **not complete**. AArch64 remains paused, C mimalloc
remains the production backend, and x86 public promotion remains false.
Continue the current product, qualification, and allocator work; do not
restart completed leaf implementations or treat private evidence as closure.

### Integrated runtime components

- Loader: canonical-path-bound application receipts, initial/runtime musl
  search and preloads, ORIGIN/AT_SECURE, pure TBSS, coherent all-thread DTV
  growth, deferred GOT/PLT transactions, rollback/RELRO restoration, retained
  close, and kernel-main `dladdr` mapping identity. Direct interpreter entry
  preserves executable role independently of mapping ownership. Its listing
  retains the first admission name even after a later short-name inode alias.
  Initial dependency cycles now follow musl constructor order. Installed ELF
  weak/protected/hidden scope and both interpreter-alias entry paths have
  direct differential evidence.
- Thread/process lifecycle: target mapping leases and kill locks, main/last
  thread exit, pthread/C11 signal handles, live stack/guard/detach attributes,
  and dynamic fork with graph/callback locking, child TID registration and
  surviving TLS/TSD/robust/canary state. Join cancellation restores the target
  claim before user cleanup. Main/worker condition cancellation repairs its
  waiter list and reacquires the mutex before cleanup. Join/condition blocked
  probes observe actual kernel futex waits through an inherited proc descriptor.
- Syscall cancellation: descriptor/vector/positioned I/O, readiness, sockets,
  sleep/child waits, open/record locks, memory sync, unnamed semaphores, signal
  waits, entropy and SysV messages. Shared fixture selection now qualifies
  static and dynamic products separately. `getentropy` preserves its source
  suppression window; ordinary FILE backends, `pclose`, `wait3/wait4`, empty
  `sendmmsg`, and nonblocking fcntl retain source non-CP behavior. SIGCANCEL is
  **33**, timer signal is 32; FS+32 publication and target leases precede signal
  delivery. `system` uses the public cancelable child wait while `pclose`
  preserves its raw wait; contained musl/owned protocol fixtures distinguish
  enabled, disabled and masked cancellation and verify child ownership.
- Scalar and binary80 math completion probes, owned `pthread_sigmask`,
  child-contained `chroot`, and positive 65-live-thread pthread/C11 registry
  growth are integrated. The default export roster includes the three
  previously omitted, already implemented robust-mutex exports.
- Lua source build: static and dynamic source/bytecode graphs execute through
  owned products. `lua-dynamic-source-build` admits versioned application DSOs,
  validates receipt/link/ELF/runtime identity, compares pinned-musl outcomes,
  and repeats through an extracted package. Failure and artifact-drift tests
  prevent publishing a successful latest report.

### Current evidence and boundaries

- The latest three-product dynamic run at the `550bb254` runtime plus the
  `906e6d6c` harness change passes 51 loader, 22 driver and two CRT tests, then
  the same complete then-current suite through both clean builds and the
  extracted package. Log: `.work/x86_64/three-dynamic-products-integrated.log`;
  product: `.work/x86_64/tmp/materialized-dynamic.uyzJLv`. This corrects the old
  second-build comparison without execution. Subsequent join-witness,
  condition-wait and dynamic I/O composition changes need the next combined
  run; historical output must not be relabeled as current qualification.
- Shared-runtime I/O cancellation at `88fcc133` passes all 40 ordinary/direct
  PIE/non-PIE fixture runs against pinned musl. Log:
  `.work/x86_64/dynamic-cancellation-integrated.log`; product:
  `.work/x86_64/tmp/owned-dynamic-io-cancellation.gft0iz`. Root runner/dispatcher
  checks pass 303 tests. Individual cancellation slices also pass the static
  56-test/24-job installed/extracted/reproducibility gate. Successful static
  scratch products are cleaned; retain their logs.
- `system`/`pclose` cancellation at `e3624732` passes both static modes and
  dynamic PIE/non-PIE through kernel and direct interpreter entry, including
  supervisor cleanup after success, injected failure and timeout. Log:
  `.work/x86_64/system-cancellation-integrated.log`; product:
  `.work/x86_64/tmp/owned-system-cancellation.8Vba55`.
- Dynamic Lua passes installed/extracted source execution and artifact
  reproducibility: `.work/x86_64/lua-dynamic-source-integrated.log`, report
  `.work/x86_64/lua-dynamic-source-build/run-0t1zwhlc/report.json`.
- `5a48b06f` integrates typed process-registry huge backing, durable failed-page
  cleanup, exact retry/statistics ownership and huge-before-regular startup.
  `allocator-huge-reservation` passes 69 C differential values and ten tests;
  log `.work/x86_64/allocator-huge-reservation-integrated.log`. The worker also
  passed 956 allocator unit tests, quick evidence and performance smoke.
  Native M2 remains partial. Simulated primitives do not replace native huge
  page success; this host has zero configured/free 1-GiB pages and one NUMA node.

These are component measurements, not final same-revision qualification.

### Remaining work and ownership

All new worktrees and mutable state stay beneath checkout `.work`. Preserve
historical dirty worktrees; no uncommitted checkpoint is a completed feature.

| Worktree | Current task |
| --- | --- |
| `owned_dynamic_sysroot` | Replace impossible planned-only RuntimeV1/product predicates with current source/manifest-bound materialization and fresh per-case receipts. Building alone must not qualify a product; historical foundations and full-family/public promotion remain separate. Root owns the three-product runner and final integration. |
| `owned_pthread_lifecycle` | Timed/clock-selected and process-shared condition waits with their source-required mutex dependencies. Legacy condition machine-code evidence is repaired in `44f1684b`, with exact owned-helper/syscall edges and its native gate passing. |
| `owned_stdio_engine` | `system` child-wait cancellation is integrated and qualified as a component. Complete independently runnable qualification prefixes and source/tool/runtime-bound execution receipts; preserve the full ordered final qualification chain. |
| `header_declaration_parity` | Generic matrices pass; complete the native aggregate/provider audit and qualify the header family only when its executable predicates pass. |
| `native_resolver_network` | Installed/extracted 12-entry resolver differential is implemented in `fce59ece`, with separate ordinary build and network-isolated execution. Rerun canonically after pending source integrations: the first root attempt correctly rejected a concurrent source change during dynamic preparation. Audit remaining resolver family predicates against current providers. |
| `qualification_execution_boundary` | Pinned execution boundary is integrated as `255ec048`; source/tool/runtime-bound completed receipts and independently runnable qualification prefixes still need completion. Private five-case admission remains private. |
| `rust_std_unwinder` | Automatic tool review paused the task. Initial provider `d3ca0e79` and unfinished producer/driver/metadata changes remain isolated and unqualified; resolve the restriction before resuming. |
| `allocator_m2_metadata` | Automatic tool review paused quiescent arena-destruction ownership work. Preserve partial uncommitted snapshot/destruction files and resolve the restriction before resuming. |

The user approved the unwind configuration and delegated dependency selection
on 2026-09-05. `AGENTS.md` and `SCOPE.md` retain scope/audit/qualification rules
without dependency approval round trips. The concrete record is
`docs/design/x86-rust-unwinder-proposal.md`; libgcc, dummy unwind symbols and
reduced Rust-std fixtures cannot replace the required behavior.

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
