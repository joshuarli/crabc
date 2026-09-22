# Finish the native x86-64 runtime and Rust mimalloc

## Mission and authority

Implement this plan to completion: finish `x86-64.md` and the native Linux/x86-64
scope of `native-mimalloc.md`, integrate them, qualify the native Rust allocator
as the default, and complete public x86 support. Continue implementing while
independent qualification runs. Do not stop at a plan, component receipt,
checkpoint, or mechanically unchanged blocker report.

Optimize **elapsed time to integrated, qualified behavior**, not commit count,
agent count, individual witness count, or documentation volume. This is a
throughput-oriented execution contract, not a request to reduce correctness.

For this goal and all its descendants, use
[crabc-orchestrate](.agents/skills/crabc-orchestrate/SKILL.md). It supersedes the
user-global `orchestrate` skill's cost-minimization and smallest-fan-out defaults
for this campaign. The coordinator is the user's GPT 6 Astra session. Model
routing, concurrency budgets, and delegation mechanics have one owner: that
local skill. Do not copy a second competing policy into the allocator plan.

This plan authorizes in-scope changes to execution order, work decomposition,
intermediate development checks, and build/test throughput. It does not waive
final requirements, authorize external spending or machine reconfiguration, or
override tool/system restrictions. Existing unfinished work must be preserved.

Authority: explicit user direction; `SCOPE.md` and `COMPATIBILITY-PROFILE.md` for
product scope; the two detailed completion contracts for acceptance; this plan
and its local skill for execution; executable contracts and pinned-source
behavior for implementation. Reconcile conflicting old scheduling prose once.
Do not repeatedly ask permission for ordinary implementation or batching.

## 1. Fixed boundaries

- Target **native Linux/x86-64 little-endian, Linux >= 5.10**, in the pinned
  native environment. AArch64 implementation, qualification, and emulation stay
  paused. Preserve its code, contracts, evidence, and selected backend.
- Preserve the frozen baseline at
  `3e100d45c5a0798c2d3862d5e2eef584c610ccf9`: **223 capabilities, 26 required
  families**, and every recorded digest. Do not refresh it to absorb drift.
- Use pinned musl 1.2.6 for C/POSIX compatibility and Rustix only in its existing
  test role. No glibc oracle or ambient target-runtime fallback.
- Faithfully port mimalloc v3.5.0 at
  `18b08671c9302247bfb682286e6bf3cc1773f801`, with the archive hash and provenance
  in `crabc-mimalloc/UPSTREAM.md`. Preserve algorithms, ownership, memory
  ordering, lifecycle, and applicable behavior. No allocator invention.
- Preserve the approved narrow musl BSD-random compatibility exception and
  the no-handwritten-cryptography boundary. Do not reopen the resolved policy.
- Continue runtime development with the accepted C allocator. Native shadow
  integration is development work; default promotion requires its real gates.
- Keep new worktrees, scratch, caches, extracted sources, and reports inside
  the owning checkout's permitted `.work/` boundary. Respect each dispatcher's
  stricter physical-path checks. No outside scratch or symlink escapes.
- No unrelated cleanup, formatting/lint campaigns, pre-commit hooks, remote
  pushes, CI-workflow work, new architectures, or new product scope.

The earlier AArch64 `sysroot.md` delivery is historical input, not a dependency
that postpones the x86 sysroot until after mimalloc. Both x86 products belong
inside this goal and must be requalified after native allocator promotion.

## 2. Starting evidence, not a permanent backlog

This replacement was prepared against main
`88e3037faa5a4f41195e42453803d4e1fab5a0fe`. Reconcile later commits and local work
before assigning ownership. Inspect status and useful existing worktrees once;
do not start another whole-repository audit before dispatching known work.

| Area | Recorded starting position | Next useful outcome |
| --- | --- | --- |
| BSD random / native POSIX | The quartet is implemented. At frozen `3aaee635`, installed BSD routes, the POSIX matrix, all five native aggregate components, and the dependent pthread component pass. Family/public promotion is separate. | Consume the existing evidence where its exact source is admissible; complete real family admission and successor families. Do not reimplement or rediscover the resolved quartet. |
| Runtime families / ABI | Component producers and admission machinery exist. Historical ABI closure reported 266 unresolved identities and 25 unavailable family-semantic records, not 291 proven implementation bugs. | Read current unresolved requirements and group them by actual behavior/provider and prerequisite family. Finish bindings or implementation as appropriate. |
| Allocator substrate | Native M2 produces an honest partial receipt. VM, metadata, arenas, initialization, fault injection, and recursion have remaining conditions. PageMap/bitmap passes are historical target-specific evidence. | Close complete source transitions and their required C/Rust evidence; implement dependent engine/lifecycle work without pretending M2 is qualified. |
| Native integration | Selected-static native-shadow lifecycle and failure cases exist; the default remains C. | Complete generic ownership, teardown, transfer/reclaim, fork, and static/dynamic integration, not another fixture-shaped route. |
| Unwinder | The approved pinned provider, standalone cleanup, and bounds work exist. `88e3037f` adds bounded `PT_DYNAMIC` scans after the EH-header and decoded-frame changes. | Assess remaining metadata/indirect-access and mapping-lifetime obligations; complete owned-runtime, DSO, stock-std/build-std, and LTO integration. Do not redo the landed scans. |
| Hardware qualification | A concrete huge-page/NUMA job and resource request already exist. | Use the existing job after authorized provisioning; continue unrelated work now. Do not build a replacement resource-audit framework. |

Receipt locations and exact historical limitations belong to their owning
contracts and the archived previous plan. Verify actual files before reuse;
missing local receipts are unavailable evidence, not implied passes. Never
transfer a worker/checkpoint pass to a different revision.

Keep `plan.md` as the execution contract. Put the current concise frontier in
`STATUS.md`, source requirements in their existing manifests, and execution
records in ignored reports. Archive the previous plan before replacing it;
retain its unique resource request and unfinished obligations. Stop appending
per-commit biographies to this file.

## 3. Two dependency graphs, one continuously running campaign

Maintain separate **implementation dependencies** and **qualification
prerequisites**. An admission requirement is not automatically an implementation
barrier. A technically implementable successor may proceed against a stable
interface before the predecessor's complete qualification finishes.

Use a rolling ready queue, not synchronized waves. Dispatch a replacement when
a worker completes or becomes externally blocked; do not wait for the slowest
worker. Keep implementation, review/integration, and qualification active at
the same time. Build a small ready backlog beyond the active assignments, not a
speculative exhaustive inventory of every future leaf.

Every assignment must name an outcome that advances a required product or
closes a real blocker. Prefer one owner for a coherent source transition,
component, or consumer family, including implementation and focused tests.
Do not split one behavior into separate scouting, design, code, test, receipt,
documentation, and handoff agents. Split only where independently testable
ownership or substantial reasoning work justifies it.

The coordinator owns priorities and shared architectural decisions, but does
not personally redo every test or line of routine review. Area owners perform
substantive implementation/review, not management-only reporting. One merge
operator may execute approved integration; only one writer advances the
integration branch and shared top-level ledgers at a time.

### Immediate allocation of work

Start these lanes together when their actual implementation inputs are ready.
The widths below are opportunities, not instructions to duplicate work or
invent missing features. Count area owners/reviewers in the skill's global
agent budget. Reassign a lane's capacity when its useful work is finished.

| Lane | Useful independent assignments | Deliverable and proof boundary |
| --- | --- | --- |
| Runtime family closure | 3–5 owners: POSIX admission; text/math/locale/stdio; other dependency-ready families; ABI/provider joins. | Real family admission using current admissible products and complete existing readers. Diagnose missing evidence separately from missing behavior; no symbol-count closure. |
| Allocator memory substrate | 4–6 owners: VM/purge; metadata ownership; arena registry/reservation/destruction; bootstrap/recursion; fault composition. | Complete applicable M2 remaining conditions through production owners and pinned-C evidence. Keep genuine hardware conditions separate. |
| Allocator engine and lifecycle | 4–6 owners: local engine/realloc; remote publication; abandon/reclaim; thread/process exit; fork; concurrency models/stress. | Generic legal-client behavior with clear ownership, state-auditor and differential coverage. No per-client registry, global scheduling workaround, or geometry-specific production fast pass. |
| Applicable allocator APIs/modes | 2–4 owners, after the relevant engine interfaces are stable. | Source-faithful heap/Theap/subprocess, managed-memory, visitation, options/statistics/callbacks, debug/secure/guarded groups from the existing applicability inventory. Do not wait for unrelated M2 hardware evidence to write implementable code. |
| Runtime / allocator integration | 2–3 owners: static startup and teardown; loader/libc allocation ownership and dynamic shadow; TLS/pthread/fork composition. | Real installed consumers with the selected backend. Establish the loader descriptor/internal-allocation contract before enabling currently rejected dynamic selection. |
| Unwinder / Rust consumers | 3–4 owners: remaining bounded metadata behavior; loader enumeration/lifetime; owned stock-std and build-std/LTO wiring. | Approved provider and features, real cleanup/backtrace/DSO consumers, no ambient unwinder or dummy symbols. A standalone musl-hosted pass is not owned-runtime qualification. |
| Other consumers / performance | 2–3 owners as dependencies permit. | Finish the frozen source-build/corpus/facade requirements; diagnose performance with existing collectors. Do not invent a larger corpus or call developmental timing release qualification. |
| Throughput / qualification | 2–3 execution owners, shared with the support budget. | Remove demonstrated preparation/replay bottlenecks, run frozen product cohorts, and return actionable failures. No new orchestration service or replacement test framework. |

Assign exact modules, symbols, and shared-file owners after a targeted read.
Several lanes may touch one broad subsystem, but never own the same mutable
state-machine transition independently. The local skill defines how to split
and integrate without serializing an entire directory.

### Prioritize actual critical paths

First unblock prerequisites with many dependents, then shorten the longest
remaining end-to-end path. Preserve capacity for allocator substrate/lifecycle
and unwinder/runtime integration while family qualification proceeds. Do not
spend the entire fleet producing easy receipt or documentation changes because
they finish sooner.

A blocked assignment returns its precise obstruction and retained work. It
must not hold a slot indefinitely waiting for hardware, permission, or an
upstream interface. Reassign its independent remainder or resume it when the
specific dependency changes. Do not commission repeated unchanged audits.

## 4. Worktree and integration pipeline

Use persistent, checkout-local worktrees for coherent assignments. Reuse a
worker and its private build state across related slices. Do not create a new
cold worktree and rebuild every dependency for each small correction.

At dispatch, record the base commit and any explicit prerequisite commits.
Land shared-interface changes early, or give consumers the exact prerequisite
branch/ref and record that dependency. Do not make unrelated workers rebase
on every main commit. Refresh at a relevant dependency change or integration
boundary, and rerun affected checks.

The author delivers a coherent patch or short dependent commit series with
focused evidence and unfinished conditions stated. The reviewer checks the
actual diff, unsafe/source invariants, test adequacy, and applicable evidence.
For ordinary changes, one substantive review is enough. Use an independent
high-capability review for memory ownership, atomics, loader/unwinder trust
boundaries, and promotion; do not repeat ceremonial audits of the same result.

Integrate ready work continuously. Use small compatible batches to amortize
merge-build checks, not huge delayed merges. Preserve useful commit boundaries
for bisection. Run the union of affected focused/interface checks on the merged
result; the author's branch pass alone does not prove composition. Resolve
semantic conflicts with the relevant owners, not an unattended conflict fixer.

Do not let a queue of reviewed, ready changes accumulate while the coordinator
writes handoffs or performs unrelated implementation. If integration becomes
the bottleneck, move agents into review, conflict resolution, and merged-tree
tests before spawning more producers.

Keep a frozen qualification checkout separate from the moving integration
branch. Main can advance while that checkpoint runs. New documentation,
source, modes, or ledger changes must never mutate the frozen checkout.

## 5. Build once per product cohort; test many times

A **product cohort** is one clean source revision, pinned toolchain/image and
oracle set, target, backend, features, and build configuration, with its
required independent builds and extracted products. Share its immutable
prepared products between compatible consumers using the existing supplied-
product interfaces. Preserve exact source/header/object/link and execution-root
proofs. A path label or a summary boolean is not an identity.

Do not rebuild a sysroot separately for every consumer that can use the same
qualified input. Do not share a mutable product directory between producers.
Keep required independent reproducibility builds genuinely independent.

Maintain three verification levels:

| Level | When | What it establishes |
| --- | --- | --- |
| Development | Each coherent implementation/debugging slice. | Nearest regression, affected unit/direct-boundary checks, required local differential or model evidence. Warm builds and explicitly labeled mixed-source experiments may help diagnosis, not promotion. |
| Integration | Compatible patches have landed or an interface changes. | Merged-source checks, relevant installed consumers and complete component/family checks when admissible. Prepare a cohort for reuse rather than rerunning the whole campaign for each patch. |
| Qualification | A major dependency closes, a milestone is ready, or final promotion is being proved. | Clean exact-revision canonical products, complete required suites, independent reconstruction, reproducibility, purity, stress and performance under their real contracts. |

The author records the reproducing regression for a bug; a behavior-neutral
edit or prose correction does not require a manufactured red test. Preserve
upstream sources and raw failures. Test-contract repairs need actual pinned-
oracle justification and must not hide implementation failures.

For a changed dispatcher/collector/reader, exercise a minimal real public
round-trip early: command dispatch, collection, physical output, independent
reader. Catch argument/path/schema/mode/source-identity mismatches before a
full expensive suite. Reuse existing malformed-input and receipt-validation
tests; do not create a new schema or a second reader per small behavior.

Final native qualification retains the existing order:

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

Run independent development diagnostics and independent cases within an
admissible stage in parallel. Do not relabel out-of-order diagnostics as an
ordered final chain. Respect reader-enforced prerequisites. Reuse same-cohort
receipts only when the existing contract permits it; no invented cross-revision
qualification cache.

## 6. Separate agent concurrency from machine concurrency

Many agents may reason, edit, review, or prepare tests simultaneously. That is
not permission for every agent to launch an all-core compiler, LTO link,
upstream suite, or benchmark. The local skill owns the global execution budget.

One execution owner records the effective CPU quota/affinity, memory limit,
observed build/link peaks, and relevant disk/IO constraints. Use a small
coordinator-owned queue to admit expensive jobs. Start conservatively where
peaks are unknown, measure, and increase actual build/test throughput. Do not
stall source work while tuning resources.

Bound nested concurrency as well as outer jobs: Cargo, Make/Ninja, compiler
workers, test sharding, and stress threads count toward the same host budget.
Keep memory headroom for the coordinator, containers, links, and test peaks.
Qualifying performance gets an uncontended host; agents may continue reasoning
or working elsewhere, but not compete for that host's CPU/memory/IO resources.

Each live build writer owns its Cargo target, extraction, report, and temporary
paths. Avoid a single shared writable `CARGO_TARGET_DIR` that serializes
workers. Seed compatible private development caches from verified immutable
inputs or safe copies where supported; never use hard-linked mutable build
state. Keep the canonical cold-build/reproducibility lanes cold as required.
Respect the launchers' per-checkout containment rather than mounting a sibling
cache through an escape. Do not solve cache contention by weakening checks.

Throughput work must remove an observed bottleneck and be small enough to
exercise promptly on a real job. Prefer fixing an existing runner, adding
supplied-product support where truly missing, or repairing isolation over
building a scheduler, database, dashboard, daemon, or universal proof system.

## 7. Close allocator milestones without making them coding barriers

Use current `remaining_conditions`, source maps, applicability inventories,
and milestone contracts as the finite work surface. The milestone number is
an acceptance boundary, not a requirement that every later implementation wait.

For each incomplete component, distinguish:

1. Missing or incorrect production behavior: implement the whole relevant
   source transition and an independently meaningful regression.
2. Existing behavior without adequate evidence: produce its actual required
   C/Rust, ownership, concurrency, or installed-consumer evidence.
3. External qualification: retain the precise resource/permission dependency
   and continue independent behavior. Never mark it inapplicable merely
   because the current machine cannot exercise it.

Do not close M3 before M2 is qualified, but do implement dependency-ready
engine, API, lifecycle, and integration work while M2 qualification proceeds.
M8 and M10 wait for their actual runtime/promotion prerequisites, not for
unrelated implementation agents to become idle. Keep one owner for the
bootstrap/errno/TLS/teardown/fork/loader seams and review their composition.

The end state remains the existing native-mimalloc contract: persistent
source-shaped owners; pointer/page-derived free/realloc ownership; generic
remote-free, owner-exit, abandonment/reclaim, and release; all applicable APIs
and modes; complete fault/model/stress/soak and integration evidence; qualified
performance; default promotion; and post-promotion stabilization. No fixture-
shaped workaround or additional selected witness substitutes for that state.

## 8. External blockers: precise, retained, and off the worker critical path

The previous broad BSD-policy blocker is resolved. Allocator, ordinary ELF,
and approved unwinder work have project authorization. Historical task names
without original diagnostics do not establish a blanket subsystem prohibition.
Preserve any actual denial and use its supported review path; do not retry an
unchanged denied operation or route it through another agent/tool/container.

The recorded hardware request is already specific: native x86 Linux with two
distinct online allowed memory nodes (IDs <= 62), one free 1-GiB hugetlb page
per node, at least 2 GiB hugetlb cgroup headroom, readable `numa_maps`, the
canonical capability requirements, and authorized use of the source's exact
`mbind(MPOL_PREFERRED, flags=0)` operation. The previous environment returned
`EPERM` for that private-mapping probe. Do not infer its precise policy origin
from a seccomp flag or repeat the unchanged denied probe.

Retain `RLIMIT_AS=unlimited`: existing composed simulated prerequisites may
reserve 36 GiB + 96 MiB of virtual address space, separately from physical
huge-page demand and ordinary unmeasured compiler/runtime RAM. Use current
source-derived requirements in `compat/allocator/README.md` and the retained
previous plan; do not silently relax them.

After authorized provisioning, use the existing pinned-image launcher:

```bash
./compat/allocator/run-x86_64.sh allocator-huge-numa-qualification
```

Validate the current pinned image as its contract requires. This job proves
its bounded native huge-page/two-node behavior, not all of M2 or promotion.
Do not rent resources, change shared-host pools/security policy, or reboot
without separate permission. Until real evidence exists, keep the relevant
gates pending external qualification and the joint goal incomplete.

Track a blocker once: exact action/behavior, evidence, affected prerequisites,
clearing action, and useful independent work. Revisit only after relevant
source, resources, permissions, or diagnostics change. When no independent
work remains, report the precise external action needed without invented
progress or a reduced completion claim.

## 9. Minimal campaign state and feedback

Use one coordinator-owned ignored board, for example
`.work/coordination/board.md`, plus worker-private result files and existing
evidence. Reuse an adequate current board rather than creating a competing one.
The board needs only task/outcome, owner, base/dependencies, write boundary,
state, and result/blocker pointer. It is scheduling state, not proof or a new
repository-wide receipt standard. Only the coordinator or designated single
writer updates shared rows.

Give concise event-driven updates: a dependency closes, implementation lands,
a real regression appears, an interface changes, or an external action is
needed. Do not repeatedly poll or ask workers for prose while they are working.
Idle completed threads can be closed after their work/result is preserved.

At meaningful integration boundaries, use existing logs and the board to
inspect accepted outcomes, time waiting for review/build, repeated rebuilds,
conflicts/rework, and active versus blocked work. Treat these as diagnostics,
not scorekeeping gates. Do not optimize commits/day or raw coverage counts.
If the fleet produces more unintegrated work than it lands, fix integration;
if jobs spend time waiting on cache/build locks, fix execution admission;
if components pass but families cannot close, fix the missing admission path.

Update `STATUS.md` when the actual frontier changes, not after every witness.
Routine explanation belongs with the code or owning test. Fold small narrative
updates into the relevant implementation/batch; do not manufacture a follow-on
`docs(plan): retain ...` commit for every test. Preserve substantial design and
provenance changes, but do not make documentation churn a qualification trigger.

## 10. Final convergence and exact joint completion

When the real remaining work is integrated, retire obsolete transitional code
in coherent batches before the last qualification. Native backend promotion
and public support changes follow their existing isolated transactions and
required post-change reruns. No premature default switch or public support.

Freeze the final candidate after source, configuration, required ledger and
public-boundary changes are committed. Run the complete required post-promotion
chain at that clean revision. Keep generated final results in their existing
ignored evidence location. Do not create an unnecessary source/doc commit
just to write the final SHA back into the source being hashed. If a required
source change is discovered, make it, select a successor, and requalify as the
contracts require. Never inherit an unrelated revision's passing result.

The goal is complete only when all of these hold together:

1. Every item in `x86-64.md`'s exact full-completion definition passes: immutable
   baseline/accounting; all 26 required families; reproducible owned static and
   dynamic products and extraction; the ordered consumer/qualification chain;
   native performance; computed promotion readiness; validated public support;
   and the mandatory post-promotion aggregate rerun.
2. Every applicable native x86 allocator milestone M0–M11 and every item in
   `native-mimalloc.md`'s final definition of done passes. No hidden incomplete
   components, remaining conditions, unclassified applicable behavior, waived
   tests, hardware substitutions, or unqualified performance remain.
3. Native Rust mimalloc is the qualified x86 default. Its production dependency
   and artifact graph excludes C mimalloc; the exact pinned C oracle remains
   isolated for testing. The paused AArch64 backend is not falsely promoted.
4. Installed static and dynamic x86 products have been rebuilt and requalified
   after promotion, including ABI, TLS/pthread/fork, loader/DSO, consumers,
   reproducibility, dependency purity, stress, and performance. Former C-backend
   evidence alone does not satisfy this requirement.
5. Required final reports attest the same clean committed source revision,
   target, pinned inputs, and applicable configuration. Documentation and
   machine-readable state agree; neither detailed program remains incomplete.

Finish with the final commit, proving commands and report paths, source-map
and dependency-purity results, measured performance, and permitted limitations.
Do not stop before that point unless the user stops the work or every remaining
path is genuinely blocked by a precise unresolved external condition.
