# crabc plan

This is the only active plan. The owner's 2026-11-12 direction is binding:
**finish the selected feature surface first, waive every performance and memory
budget until then, and run a continuously replenished parallel campaign.** It
supersedes the S0–S5/R2–R4 scheduling rules and serial defaults in shared campaign
skills. Parallel implementation gives way to bounded F2 closeout when the feature
queue is closed. Status takes precedence over general dispatch instructions.
Git retains the earlier plans; do not maintain a second handoff or log.

## Status and first action

**Fresh final6 correctness qualification running 2026-11-17.** Keep final6 fixed; preserve final5 unchanged. F2 remains open; performance qualification stays deferred.
Resume prompt: "Read plan.md Status and F2 closeout; reconcile the retained candidate, finish only demonstrated blockers, require fresh current-source proof, preserve holds, and stop at F2; do not start F3." First command after owner resume: `codex-campaign-closeout.py cancel`.
Main has 223 mappings and 18 foundation families; seven gate declarations remain isolated. Resolver repair `fd7351147` passed final4's publication and chain gate. CRAB-5's bounded text-reader reuse repair is integrated at `2adf13539` (120 focused tests pass; changed-during-collection rejection retained). Its full-run speedup is unmeasured.
Retained failed attempt: `lane/f2-fresh-final4` at `27761fdd35cccad35d7cc45a869da73f9f2f459d`, `.work/wt/f2-fresh-final4/.work/x86_64/feature-complete`. Its same-source resume completed steps 0–83, then failed step 84 (`qualification-chain`): ABI/differential, POSIX/process and resolver/network passed; loader corpus failed at hardened runtime's three unittest imports. `summary.json` records `complete: false`, `fresh: true`; `parity-ledger` did not run. Chain evidence: `.work/wt/f2-fresh-final4/.work/x86_64/qualification-receipts/chain-capability.accounting-1794872955791848144-tn0cfaeu/receipt.json`; coordinator output: `.work/tmp/f2-final4-resume.log`. Product source digest remains `e42a60d7485feeed483bf39070afc79970b1beecd5fb0afa40a7af97421c8fe8`. Preserve this failed result; never integrate its declarations as accepted.
Integrated repair: `17b8e2100` invokes the physical CRT test file under inherited `PYTHONSAFEPATH=1`, preserving all three native assertions. The old invocation reproduces three `ModuleNotFoundError: crt` errors; the changed invocation passes. Independent review accepted it. The focused dynamic cohort and publication passed, then the actual pinned loader case and its owning validator passed at clean `72b8cd63868c53950d4b5ce3108feedde038b083`, with source unchanged. Evidence: `.work/wt/f2-hardened-selectors/.work/x86_64/qualification-receipts/case-hardened-repair/case.json` and its raw case logs. This is focused repair proof, not seven-gate acceptance. Host reads of final4's `.work/x86_64/tmp/hardened-qualification.ZVkdk5/static-pie-tests.log` and the repair checkout's host write to `.work/tmp/hardened-boundary-dynamic.log` were denied with `Permission denied`; do not retry or reroute those actions.
Retained final5: `lane/f2-fresh-final5` at `1c9ab60107ac5852b30191174abca898618ddf7d`, `.work/wt/f2-fresh-final5/.work/x86_64/feature-complete`. Its prepared `.work/x86_64/inputs.json` seeds Lua and Rust std/LTO; the inspected dry-run selected 86 correctness steps, no preflight blockers, and final `parity-ledger --require-receipts` (`.work/tmp/f2-final5-dry-run.json`). Coordinator output is `.work/tmp/f2-final5-correctness.log`. Its sealed product digest and core image match final4. Keep this checkout, SHA, inputs and failed evidence fixed; its provisional declarations remain isolated without acceptance.
Cleanup retired 18 checkouts. Verified raw evidence and restoration notes: `.work/tmp/f2-cleanup-archives/README.md`. Six permission-held trees remain under `.work/wt/`: `f2-admission-review`, `f2-fresh-final2`, `f2-lua-process-boundary`, `f2-process-control-wait`, `f2-resolver-reader-env`, `f2-run2`; retain their refused fixtures without another access or removal attempt. Preserve the legacy holds below.

- `lane/f2-admissions`: accepted patches equivalent to main; retained around refused fixtures; retry cleanup only after owner resolution.
- `lane/f2-fresh-final`: historical candidate `e30ca23be`, failed Lua static; archived, superseded by current candidate; never merge its unverified declarations.
- `lane/f2-fresh-final2`: historical `79f3d6a44`, failed combined-sysroot oracle; archived except refused records; use current repaired candidate on resume.
- `lane/f2-fresh-final3`: historical `cea501bc0`, steps 0–83 passed, resolver replay failed at 84; archived and checkout retired; repair is in main.
- `lane/f2-fresh-final4`: failed loader/hardened unittest import boundary; retain its exact failure and provisional declarations without acceptance.
- `lane/f2-fresh-final5`: failed combined-sysroot message-queue fixture; retain exact failure and provisional declarations without acceptance.
- `lane/f2-gate-closure`: accepted patch equivalent to main; keep non-ancestor history, no implementation retry needed.
- `lane/f2-gate-review`: same accepted closure patch; keep non-ancestor history, no implementation retry needed.
- `lane/f2-lua-process-boundary`: accepted Lua repair plus superseded unverified declarations; retain refused logs, use current candidate.
- `lane/f2-timer-diagnostics`: accepted diagnostic patch equivalent to main; CRAB-6 remains unreproduced, retry investigation on a fresh failure.

Final5 terminal result: steps 0–51 completed, including text, resolver, C ABI compatibility and loader families; step 52 (`combined-sysroot`) failed with status 1. Its summary records `complete: false`, `fresh: true`, with 33 later steps not run. The first failing leaf is `second/message-queues`: `message-queues:78: maximum>=0 && mq_unlink(long_name)==0 && mq_close(maximum)==0 errno=17`. Evidence: `.work/wt/f2-fresh-final5/.work/x86_64/tmp/owned-combined-sysroot.iFI0YU/qualification-cases/second/message-queues.log`; leaf scratch `.work/x86_64/tmp/owned-message-queues.byCx6B`. The maximum-name probe uses the same 255-byte name in concurrent processes sharing the image's IPC namespace; a deterministic concurrency reproduction and focused repair are pending. A listing encountered `Permission denied` for this cohort's `installed.build/dynamic.build` and `second.build/dynamic.build`; do not retry or reroute access to those paths.

| Blocker | Owner / writable files | Next check | State |
| --- | --- | --- | --- |
| Maximum-length message queue fixture collision | `lane/f2-message-queue-isolation` at `9f879b5b7`; integrated as `0b172bdc7` | Fresh full correctness qualification | Done |

Focused repair proof: two forked processes hold both actual maximum-length `mq_open` results until both opens finish. With the pinned musl compiler, the original probe fails deterministically with the same `EEXIST` diagnostic; the PID-prefixed name passes all four runner tests, including both length boundaries. The dispatcher module passes 4/4 (`.work/wt/f2-message-queue-isolation/.work/python-test-runs/run-2jqhd0p8`); the product digest remains `e42a60d7485feeed483bf39070afc79970b1beecd5fb0afa40a7af97421c8fe8`. The actual `owned-combined-sysroot` producer is running from clean `9f879b5b7c56fdde28e4013439901905ce600119`; output `.work/tmp/f2-message-queue-combined.log`, cohort `.work/wt/f2-message-queue-isolation/.work/x86_64/tmp/owned-combined-sysroot.8APRxS`. No new acceptance candidate has started. The worker's read of `.work/wt/f2-message-queue-isolation/.work/python-test-runs/run-5rwx6isi/modules/001-test-owned-message-queues-runner/stderr.log` was denied with `Permission denied`; it stopped, and that log remains untouched. Parent proof used separate direct-output pinned-image executions.

The actual combined producer above exited 0: both static suites, all three dynamic runtime suites and the owning `owned_dynamic_qualification.py finish` reader passed. Its `qualification.json` binds 231 cases to the unchanged product digest; its `qualified-pending-review` status does not close a parity family or prove F2. Independent file review in `lane/f2-message-queue-review` found no supported defect; the scout could not verify the revision diff with its file-only tools and reported acceptance unmet. Its one-attempt budget rejected a follow-up; no replacement review was launched. The parent inspected the exact two-file diff, source identity, original-fail/fixed-pass evidence and terminal producer result before integrating. No runtime code or upstream source changed.

Current acceptance attempt: `lane/f2-fresh-final6` at `a5c32dfe2bfe69375896c514e438a2a3b88d741e`, `.work/wt/f2-fresh-final6/.work/x86_64/feature-complete`. Preparation exited 0 and seeded its Lua/Rust inputs. The inspected `.work/tmp/f2-final6-dry-run.json` selects 86 correctness steps, no blockers, and final `parity-ledger --require-receipts`. Product digest remains `e42a60d7485feeed483bf39070afc79970b1beecd5fb0afa40a7af97421c8fe8`; core image remains `sha256:91e0733b32a12383565bb9030245cf5793f667eb1ee11b38fa8fe4ffabb438bb`. The coordinator started `static-products`; output `.work/tmp/f2-final6-correctness.log`. Its two provisional declaration files are identical to final5's and remain isolated. Keep this clean checkout, SHA and inputs fixed; no concurrent acceptance attempt or unrelated lane.

Next slice: observe final6 and follow [F2 closeout](#f2-closeout) from its actual result. Acceptance still requires all 86 steps/seven gates, owning-reader validation, strict receipt-backed parity and `complete: true`, `fresh: true`. CRAB-5/CRAB-6 stay in `TODO.md`; CRAB-6's cause remains unresolved. Do not start F3.
Retained closeout allowances predate this resume. Final6 is the only active acceptance qualifier; no campaign cron or automatic restart was created. Guard precedence repair USR-82 is committed locally in `usr` at `cf0573b` (four tests, Ruff and ty pass); no push was issued during winddown, though freeze commit `e027d2a5c` is already on origin.

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
