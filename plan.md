# crabc plan

This is the only active plan. The owner's 2026-11-12 direction is binding:
**finish the selected feature surface first, waive every performance and memory
budget until then, and run a continuously replenished parallel campaign.** It
supersedes the S0–S5/R2–R4 scheduling rules and serial defaults in shared campaign
skills. Parallel implementation gives way to bounded F2 closeout when the feature
queue is closed. Status takes precedence over general dispatch instructions.
Git retains the earlier plans; do not maintain a second handoff or log.

## Status and first action

**Resumed 2026-11-16 for bounded F2 closeout.** Reconcile the retained candidate; open no unrelated lane or replacement attempt. F2 remains open; performance qualification stays deferred.
Resume prompt: "Read plan.md Status and F2 closeout; reconcile the retained candidate, finish only demonstrated blockers, require fresh current-source proof, preserve holds, and stop at F2; do not start F3." First command after owner resume: `codex-campaign-closeout.py cancel`.
Last accepted repair: `fd7351147` (focused native replay and authentication checks green; raw-byte review finding fixed), integrated and pushed through `0a3849e45`. Main has 223 mappings and 18 foundation families; seven gate declarations remain isolated.
Current attempt: `lane/f2-fresh-final4` at `27761fdd35cccad35d7cc45a869da73f9f2f459d`, `.work/wt/f2-fresh-final4/.work/x86_64/feature-complete`. On owner resume, closeout cancellation reported `Campaign closeout is not active`. The original coordinator was absent; steps 0–39 retained completion records, while step 40 (`text-family`) had an invocation and a receipt but no completion record. Its container exited 0 at 17:02:48 UTC; no candidate summary or terminal chain receipt existed. This is interrupted orchestration, not a proved runtime failure or acceptance. The unchanged checkout's existing same-source resume was started after an 86-step correctness dry-run reported no preflight blockers, using `.work/tmp/f2-final4-inputs.json`; coordinator output is `.work/tmp/f2-final4-resume.log`. Product source digest: `e42a60d7485feeed483bf39070afc79970b1beecd5fb0afa40a7af97421c8fe8`. Preserve all original evidence; integrate only after owning readers validate all 86 steps and seven gates with `complete: true`, `fresh: true`. No automatic replacement attempt is authorized by a missing result.
Cleanup retired 18 checkouts. Verified raw evidence and restoration notes: `.work/tmp/f2-cleanup-archives/README.md`. Six permission-held trees remain under `.work/wt/`: `f2-admission-review`, `f2-fresh-final2`, `f2-lua-process-boundary`, `f2-process-control-wait`, `f2-resolver-reader-env`, `f2-run2`; retain their refused fixtures without another access or removal attempt. Preserve the legacy holds below.

- `lane/f2-admissions`: accepted patches equivalent to main; retained around refused fixtures; retry cleanup only after owner resolution.
- `lane/f2-fresh-final`: historical candidate `e30ca23be`, failed Lua static; archived, superseded by current candidate; never merge its unverified declarations.
- `lane/f2-fresh-final2`: historical `79f3d6a44`, failed combined-sysroot oracle; archived except refused records; use current repaired candidate on resume.
- `lane/f2-fresh-final3`: historical `cea501bc0`, steps 0–83 passed, resolver replay failed at 84; archived and checkout retired; repair is in main.
- `lane/f2-fresh-final4`: current attempt and provisional declarations; merge only after its full fresh correctness result, otherwise park exact failure.
- `lane/f2-gate-closure`: accepted patch equivalent to main; keep non-ancestor history, no implementation retry needed.
- `lane/f2-gate-review`: same accepted closure patch; keep non-ancestor history, no implementation retry needed.
- `lane/f2-lua-process-boundary`: accepted Lua repair plus superseded unverified declarations; retain refused logs, use current candidate.
- `lane/f2-timer-diagnostics`: accepted diagnostic patch equivalent to main; CRAB-6 remains unreproduced, retry investigation on a fresh failure.

Next slice after resume: inspect the current attempt's summary and follow [F2 closeout](#f2-closeout); integrate only all 86 steps/seven gates with `complete: true`, `fresh: true`. A missing local result is unknown, not a failed candidate or permission to launch another one; if missing or incomplete, preserve it and require a full fresh run after any repair. CRAB-5/CRAB-6 stay in `TODO.md`; no performance work during winddown; do not start F3.
Closeout allowances record all seven retained trees. The live qualifier is the intentional process-audit exception; no campaign cron or restart was created. Guard precedence repair USR-82 is committed locally in `usr` at `cf0573b` (four tests, Ruff and ty pass); no push was issued during winddown, though freeze commit `e027d2a5c` is already on origin.

## Goal and completion boundary

Finish the entire selected native Linux/x86-64 runtime in
[COMPATIBILITY-PROFILE.md](COMPATIBILITY-PROFILE.md) and
[docs/completion-requirements.md](docs/completion-requirements.md): C/POSIX
behavior, headers/ABI, direct Rust facade, loader/TLS, CRT/builtins/sysroot,
hardening and real consumers. Use the pinned C mimalloc backend. New work that
closes this already-selected surface is authorized; new platforms, unrelated
APIs and the frozen Rust allocator port are outside this campaign.

Feature-complete means all selected obligations have current behavioral proof,
all 223 capability mappings and 25 nonperformance family obligations are closed
(or any genuinely inapplicable case is justified within the existing profile),
and one clean integrated commit passes all seven correctness gates with a
`fresh: true` candidate summary. No selected-private placeholder, missing test,
known semantic failure, unavailable required proof or unbuilt product counts as
complete. Do not shrink the profile or relabel an unimplemented feature to reach
these totals. Ledger totals alone never establish completeness.

Feature completeness, performance qualification and public support are separate
claims. The seven-gate result explicitly defers `performance.release`; it never
implies a passing full chain, allocator-port completion or public promotion.
**Accepted F2 is the terminal deliverable of this campaign.** Report it and stop;
schedule F3 separately instead of silently extending the feature campaign.

## Sequence

| Phase | Work and ownership | Exit proof |
| --- | --- | --- |
| F0 — dispatch | Coordinator reads current status and makes file-disjoint assignments from the lane table; one integration owner seeds existing products and correctness evidence. Repair a shared harness problem only when it blocks a named feature test. This is a bounded startup step, not a new inventory project. | Every launched slice names its capability/failure, base revision, owned paths, real test command and expected behavior. Launch useful independent lanes immediately. |
| F1 — parallel feature closure | Implement missing selected behavior, fix existing failures and complete integration in parallel. Reconcile historical holds with admitted evidence before assigning work; reopen admitted behavior only for a concrete failure or missing obligation. Keep reviewers and an integration/check owner active; refill freed slots from actual remaining work. | Each slice passes its focused behavior/ABI/hardening checks on the integrated tree; update existing capability/family evidence only after it proves the claim. |
| F2 — feature-complete milestone | Follow [F2 closeout](#f2-closeout): reconcile the retained attempt, repair demonstrated blockers with focused checks, then qualify one fixed clean candidate. | All seven gates pass in one complete fresh run; `capability.accounting` closes the full selected surface. Record the accepted commit and evidence path in Status, then stop this campaign. |
| F3 — optimization and full qualification | Separate follow-up after F2, not an automatic next iteration. Rebaseline the completed runtime using existing `perf-c` and `perf-native` commands, resolve retained cost failures, and run a candidate with explicit `--profile full`. | Actual current-source performance evidence and all eight full-chain gates pass under the retained release contracts. Public support/promotion still needs its separate authorization. |

Run focused tests per slice and the affected family suite per coherent integration
batch. A long correctness run uses one clean snapshot while other lanes continue
on separate worktrees; its evidence proves that snapshot. Reuse intermediate
results only under existing product-input/source rules. Final F2 acceptance must
be fresh on the accepted integrated candidate. Never rerun the entire candidate
chain for every leaf edit or treat an old receipt as proof of changed code.

## F2 closeout

These steps apply after owner resume; they do not lift the current winddown.
The remaining task is to accept or reject the selected runtime with evidence,
not to open another feature inventory, proof framework or general review tour.
Useful independent blocker repairs may run in parallel, but there is only one
active acceptance candidate. Extra slots are optional when no independent
selected blocker remains.

1. **Reconcile final4 first.** Inspect its `candidate.json`, `summary.json`,
   terminal chain receipt and raw failure in its original checkout. If still
   running, observe that attempt. If inaccessible, record the exact environment
   blocker. A complete result must have all 86 steps, seven passing correctness
   gates, strict receipt-backed parity validation, `complete: true` and
   `fresh: true`; counters or provisional declarations cannot replace them.
   Validate it under the owning readers before integrating its declarations.
2. **Name the actual blocker.** Separate runtime behavior, test/oracle defects,
   evidence-reader/publication defects and missing environment. Give each
   demonstrated failure one repair owner and independent review. Record its
   command, expected/actual result, source and evidence path in Status; do not
   reopen every family because one reader failed. Any failing required behavior
   stays blocking, including a suspected timing flake. Keep CRAB-6 unresolved:
   passing repetitions do not establish its cause or prove host noise. Use its
   existing diagnostics on recurrence instead of another blind stress campaign.
3. **Prove the repair before paying for a new full run.** Run the affected
   producer/case and its publication and owning gate reader in the environment
   used by final qualification; a helper unit test alone does not prove that
   boundary. Batch demonstrated repairs. Use the existing same-product-source
   candidate resume for development where its input/output checks permit it;
   never edit receipts, force a stale reader, or call a mixed-revision run fresh.
   Changed product inputs need a new cohort. Follow the existing
   [candidate contract](compat/x86_64/qualification-chain.md#one-command-candidate-run),
   not a new resume protocol. After two materially different failed repairs,
   apply P4 to the specific blocker before another acceptance attempt.
4. **Keep the verification loop practical.** CRAB-5's recorded multi-hour
   repeated product hashing is harness overhead, not a waived runtime cost gate.
   If it still delays a necessary retry, measure the current path (some reuse
   fixes have landed) and make only the bounded reuse repair in `TODO.md`, with
   its changed-during-collection rejection intact. Do not interrupt a healthy
   final4 to do it, impose a new numerical budget, or start a harness rewrite.
5. **Freeze the acceptance candidate.** Before a new attempt, finish known
   repairs, run their focused checks and inspect the candidate's `--dry-run`
   output for blockers using the actual seeded inputs and intended work path.
   A dry-run exit of zero alone is not readiness. Use the existing
   `./scripts/dev-x86_64.sh qualification-candidate --work .work/x86_64/feature-complete --profile correctness`
   with the actual `--inputs` file. A fresh attempt uses an isolated prepared
   checkout with the ledger's expected relative receipt paths; preserve earlier
   work directories. Keep the clean candidate SHA and inputs fixed; only that
   run may write its outputs. No rebases, status edits or concurrent writers in
   that checkout. A failure returns to its named repair, not an automatic
   `finalN` rebuild. Do not add unrelated
   features, audits or optimization while waiting for this result.
6. **Accept once and stop.** Record the exact tested SHA, product source digest,
   candidate/chain evidence paths, seven-gate result, 223 accounted mappings,
   25 closed nonperformance families, hold reconciliation and any unresolved
   observations in Status. Missing required proof keeps F2 open. A later
   status-only commit reports that tested SHA; it neither claims its own SHA was
   tested nor requires another full run just to record acceptance. Any change
   to product, test, gate or contract inputs needs the applicable checks and a
   fresh accepted candidate. Leave performance explicitly deferred, preserve
   unresolved observations such as CRAB-6 without claiming them fixed, and stop.

## Performance and memory waiver

**D23 — owner decision, 2026-11-12.** Until F2 is complete, all runtime performance
and resource-efficiency acceptance gates are waived, including:

- wall/CPU time, throughput, latency, startup/first-use cost and tail behavior;
- retired instructions, per-operation/whole-process syscalls and musl ratios;
- RSS, PSS, cgroup `memory.peak`, allocation counts, retained bytes and footprint;
- linked/code size and the old S0–S5/D17 numerical reduction budgets.

No before/after benchmark, quiet host, PMU access, cgroup delegation, matched
performance compiler or favorable ratio is needed to start, accept or integrate
a feature slice. No lane is assigned optimization, benchmark infrastructure or
cost-only cleanup while selected feature work remains. Optional existing
measurements are diagnostic, off the critical path, and never create work ahead
of a feature. Do not manufacture a green report: skipped cost gates are
**deferred**, and an observed regression remains an observed regression.

Memory safety, ownership, allocation-failure behavior, leaks caused by broken
lifecycle, bounded parsing, termination, race freedom and hardening remain
correctness obligations. Practical worker/build limits prevent exhausting the
host; they are scheduling controls, not product memory targets. A defect that
prevents a functional workload from completing is fixed as a correctness blocker.

The default qualification profile and ledger scope are `correctness`, with
`performance.release` explicitly deferred. Explicit `full` and the existing cost
readers remain available for F3; their thresholds and raw evidence are preserved.
The waiver does not silently pass them or authorize a release claim. The retained
[performance methodology](docs/design/performance.md) governs measurements when
used; it imposes no F0–F2 gate.

## Parallel execution

**D24 — owner decision, 2026-11-12.** Parallel work is the default for independent
selected features. Fill useful available slots within the actual harness caps
(current repository settings: 16 Codex threads, 24 Claude subagents; a hosted
session may expose fewer). Keep one coordinator/integrator, sufficient independent
review/check capacity, and a ready queue of component-sized implementation slices.
During F0/F1, do not cap the campaign at one writer or leave slots idle while
independent implementation, tests, failure reproduction or review is ready.
During F2, use only the remaining blocker/review/acceptance work above; do not
replenish from completed families or invent work to maintain agent utilization.

Use the existing `orchestrate` routing/tiers and worktree helpers; no new agent
framework, queue service or receipt schema. This owner direction overrides shared
skills' serial-first and performance-readiness scheduling defaults. The detailed
ownership map, initial workstreams, brief contract and resource policy are in
[docs/lanes.md](docs/lanes.md). Each writer gets an isolated worktree and exact
paths; shared manifests, dispatch, exports and product wiring have one owner.

A prerequisite blocks only work needing its unfinished interface. It does not
block independent implementation against an already-available owned interface.
Final family acceptance remains dependency ordered. Integrate small reviewed
slices continuously; replenish the queue after each completion, failure or merge.
Use one owner to repair a shared blocker while other lanes progress. If review or
builds saturate, move capacity to those stages instead of starting conflicting
writers. Track landed behavior and closed obligations, not agent counts or docs.

## Allocator freeze

The selected backend is pinned upstream C mimalloc v3.5.0 (`[mimalloc]` in
`compat/upstreams.toml`); upstream C source remains unedited. Its crabc integration
in `libc/` is open for selected feature work and correctness fixes: initialization,
options, lifecycle, wrappers, errno, fork/threads and failure handling. A focused
reproducer is sufficient; do not wait for an R1–R4 cost gate to authorize a fix.

The Rust port (`crabc-mimalloc/`), `compat/allocator/` harness/receipts/milestones,
allocator tuning, alternate allocators, native-shadow products, default promotion
and parked allocator branches remain frozen. Ordinary products and regressions
may build/use the C backend. Any optional cost observation retains the
`allocator-attributed` label. Old G2, A0–A5, M1–M10, T4, allocator P0, O3/O4 and
allocator C0/C1 work remains parked and does not block F2.

## Runtime hardening

PIE, non-executable stacks, page-level W^X, effective RELRO, eager binding and
explicit library search rules stay mandatory under the selected
[profile](COMPATIBILITY-PROFILE.md#runtime-hardening-profiles). Each change runs
its area's behavioral protection and failure-path tests. Hardening work runs
alongside implementation; it does not wait until optimization.

## Rules for every agent

1. **Finish behavior.** Prefer the smallest correct implementation within the
   existing ownership model. Broad simplification or tuning is not a prerequisite.
2. **Keep correctness checks.** Never hide a semantic failure, shrink upstream
   workloads or disable hardening. D23 waives cost gates, not test assertions.
3. **Checks test behavior (D22).** Do not rebuild per-symbol ELF/receipt proof
   machinery. Keep caller-visible coverage and necessary ABI/purity boundaries.
4. **One writer per file set.** The coordinator resolves cross-lane edits; no
   worker invents a local substitute for another owner's shared interface.
5. **Native x86-64 only.** Preserve paused AArch64; never execute/emulate it or
   refresh frozen baselines to absorb drift.
6. **Pins stay.** Do not change `rust-toolchain.toml`, `compat/upstreams.toml`,
   the Alpine base digest or pinned core image. Do not run the destructive
   `./scripts/dev-x86_64.sh image` rebuild as routine preparation.
7. **Repository work only.** No unrelated host changes, release or publication.
   The coordinator may commit reviewed changes to main under the owner's direct
   commit instruction; workers never commit, switch branches, stash or push.
8. **Honest status.** Required unavailable proof keeps the affected obligation
   open. A lane blocker does not stop other authorized lanes. A waived cost gate
   stays deferred, never pass.

## Standard procedures

### P1 — Change runtime code

Reproduce a bug with a focused failing behavior test; for new behavior, name the
missing contract and its oracle. Implement the complete slice, run the narrow
behavior/ABI/hardening checks, and hand the diff to independent review. The
coordinator verifies the integrated result. No performance measurement is
required before F2. Preserve cancellation, errno, TLS, ownership and atomics;
never trade correctness for speed or expedience.

### P2 — Measure a row

Deferred from required F0–F2 work. If a bounded diagnostic is directly useful,
use existing `perf-c counts`/`perf-native` machinery and the
[measurement contract](docs/design/performance.md), label unavailable/loaded-host
results honestly and return to the feature. Full performance campaigns wait
until F3. Do not stop feature workers to obtain a quiet measurement window.

### P3 — Remove a mechanism

Only when needed by the feature or to fix its shared blocker: find consumers
with `rg`, retain behavior in existing tests, and delete without stubs or a
parallel framework. Do not turn the feature campaign back into a reduction tour.

### P4 — Handle a blocker

Diagnose the exact failure. After two materially different unsuccessful attempts,
hand the bounded problem and raw evidence to an expert/reviewer or park it with a
retry condition, then refill the slot. A shared blocker gets one owner. Permission,
profile expansion, frozen allocator, AArch64 or pin work remains out of scope;
park only the dependent slice. A denied tool action is stopped with its exact
reason preserved; do not reroute it. No destructive cleanup on stop.

## Preserved decisions and holds

D23/D24 override earlier numerical cost/structure budgets, mandatory measurements,
R3-before-feature sequencing and restrictions on selected-feature parallel lanes.
They do not change these boundaries:

- **D1/D9:** allocator-attributed observations stay labeled, never hidden.
- **D2:** generated musl assembly and its generators stay untouched.
- **D4/D5/D14:** matched LLVM and quiet-host rules still govern any qualifying
  performance claim in F3; they do not gate F0–F2 work.
- **D20:** one definition of each `mem*` symbol in `libc.so`; self-relocation
  makes no `mem*` call.
- **D21:** hardening outranks cost. Its startup/loader/TLS concerns are deferred
  with all other cost work; no new owner-supplied CPU/memory bound is needed to
  execute F0–F2.
- **D22:** qualification tests caller-visible behavior; the allocator harness
  remains excluded from its machinery cleanup.
- `77e5dfc3` explicitly records closure of the October 25 C-ABI admission hold.
  Do not assign that admitted family as missing implementation; its current
  F2 aggregate must still pass. No explicit `math/pow` closure is recorded:
  reconcile the retained failing case against the unmodified required aggregate
  in the accepted candidate, and fix it only if still failing. Name that case
  and evidence in closeout rather than inferring a pass from family counts.
  Never trim the libc-test aggregate, change backends or invent an exception.
  Preserve `.work/tmp/pow-discriminator-*`; this review did not replay those
  host-local records.
- Existing `archive/*`, `cohort/*`, `integration/*`, `lane/*`, `parked/*`,
  `proof/*`, `recovery/*` and `review/*` branches are not automatically adopted.
  Never merge parked allocator branches. New scoped lanes use reviewed current
  main; inspect existing work before any reuse.
- Preserve `.work/retained/`, `.work/allocator-x86_64/`, `.work/x86_64/kache`
  and `.work/tmp/pow-discriminator-*`. `git worktree list` is authoritative;
  never delete unique source, failed evidence or unresolved ignored files.

## Needs environment

Native product/correctness execution requires the pinned x86-64 images and their
existing fixtures/network capabilities. If unavailable, preserve the exact command
and blocker, continue host-side checks and other independent slices, and leave F2
open. PMUs, a quiet host and delegated cgroup memory accounting are only F3 needs;
their absence cannot block feature completion.

## Non-goals

New architectures or non-Linux runtimes; AArch64 execution; Rust allocator-port
restart or backend replacement; new cryptographic/numerical algorithms; weaker
semantics, safety, hardening or tests; a new orchestration/validation framework;
whole-toolchain integration; public-support promotion without authorization.
