# crabc plan

This is the only active plan. The owner's 2026-11-12 direction is binding:
**finish the selected feature surface first, waive every performance and memory
budget until then, and run a continuously replenished parallel campaign.** It
supersedes the S0–S5/R2–R4 scheduling rules and serial defaults in shared campaign
skills. Parallel implementation gives way to bounded F2 closeout when the feature
queue is closed. Status takes precedence over general dispatch instructions.
Git retains the earlier plans; do not maintain a second handoff or log.

## Status and first action

**Paused 2026-11-21** (A5 closeout, [CRAB-8](docs/rfc/CRAB-8-linux-aarch64-feature-completion.md)). Resume prompt: "continue A5: build a candidate from main plus the declaration, run x86 and arm fresh at that SHA, fix each blocker through its owning producer". First commands: on a fresh x86-64 Linux host, `git clone https://github.com/joshuarli/crabc && cd crabc && scripts/setup-dev` ([development setup](docs/development.md)); the arm half runs in an OrbStack arm64 Linux VM on the macOS host ([AArch64](docs/development.md#aarch64)).
Hosts: x86 on a fresh Linux box; the x86 core image is now built reproducibly from `docker/image/sources.lock.json` (pin `sha256:c689abaa…` in `compat/x86_64/core_image.py`, inputs mirrored in stuff OCI `crabc/image-inputs:x86_64` and the `core-image-inputs` GitHub release). Verified: two cold threadripper builds reproduce the pin (18m37s for both). A cold ubuntu:24.04 capsule from a fresh clone of `b82313a51` (later commits are docs only) passed `scripts/setup-dev` (pinned ID reproduced), `rust-check`, parity ledger, `owned-exit-gate`, `mimalloc-secure-environment` and a clean `git status` in 14m35s; the pin changed from `6610b286…`, so the next candidate is built on the new image. STUF-104 (stuff edge caches blob 404s) makes the stuff mirror miss in some regions; builds fall through to the GitHub release.
Last accepted revision: `crab8/integration` `ec8937a39`, merged to main on owner direction before acceptance; continue on main. It holds CRAB-17 exit gate, CRAB-18 secure-execution allocator environment (native-shadow and default C backend via `-Denviron=(*__crabc_allocator_environ())`), CRAB-13, CRAB-14, CRAB-16, CRAB-19 and CRAB-20, each failing-then-passing on its owning producer (CRAB-17/18 natively on both arches). Green on focused suites; the Linux host `compat/x86_64/tests` run fails only six image-only modules plus pre-existing `test_owned_posix_family_execution` container-mount and `test_qualification_candidate` cases. No full candidate has completed at it.
Candidate procedure: F2 closeout step 5. Branch = main + `git cherry-pick 5be77042f` (declaration), then `python3 -B compat/x86_64/aarch64_parity_inventory.py` (223/223, no diff) and `validate_parity_ledger.py` (25/1); dry-run must show 86 steps/0 blockers/4 attachments; run `./scripts/dev-x86_64.sh qualification-candidate --work .work/<arch>/feature-complete --profile correctness --inputs .work/<arch>/inputs.json` from a `scripts/lanes/prepare-worktree.sh` checkout on native x86 and native arm64 Linux. Acceptance needs both `complete: true, fresh: true` at one SHA, then a status-only commit; that also records x86 F2 acceptance.
Last candidate: `lane/a5-final8` `909d825dc` (= `ec8937a39` + declaration), stopped for wind-down: x86 passed steps 00–02 and stopped at 03 `posix-family`; arm stopped at 01. SIGTERM ended both cleanly (status 143, no orphan containers). Not accepted; rebuild after CRAB-12.
Parked `lane/crab12-facade-atfork` `e41d722fe` (origin): owner-approved option B removing the AArch64-only facade `process::{fork, register_atfork}` and its registry. Unverified (interrupted before any build). Retry: finish the commit with a `!` subject and `BREAKING CHANGE:` footer, then `scripts/lanes/rust-check.sh` on both arches and the crabc-rs signal/process native tests and `compat/crabc-rs/verify_signal_process.py` in native arm64; integrate only when green. This product change is why the next candidate must be rebuilt.
Next slice: land CRAB-12, rebuild the candidate on the new integration head, run both arches fresh, and repair each blocker on main, using same-product resume for harness-only fixes.
Arm host notes: use native arm64 Linux only (never macOS docker or emulation); the work directory must be ext4 or another filesystem with a nonzero statvfs `f_files` (btrfs breaks it), with at least ~40M inodes. Old orb images and worktrees were deleted; prepare a fresh ext4 volume. Uncommitted leftovers from 8 orb worktrees are on `park/orb-*` (origin), never integrated.
Superseded and parked candidates: `lane/a5-final`–`final8`, `lane/a5-pnative`; earlier F2 candidates `lane/f2-fresh-final`–`final7` and the F2 repair/proof branches. Cherry-picked history (contained in main): `lane/a1-*`, `lane/a2-*`, `a3-*`, `a4-*`, `a5-cohort`, `a5-dynamic-roster*`; their unpicked commits on a2-fixtures, a4-abi2 (28), a4-abi3, a4-builder3, a4-corpus, a4-resolver-network2 (5), a4-tests-harness (2), a5-cohort, a5-dynamic-roster2 (4) and a5-dynamic-roster3 (3), plus `chore(lane)` preservation commits on a4-builder-evidence, a4-product-fixes, a4-wordexp and a4-x86-restore, were never integrated. Deleting any needs `-D`, the owner's call.
Earlier F2 holds (permission-held fixtures, access refusals, `math/pow` reconciliation, CRAB-5/CRAB-6 observations) are recorded in this file at `8fb1553b6`; preserve them, never retry denied actions, and keep CRAB-6 unresolved.
Debt: CRAB-22 (retire `Dockerfile.x86_64` readers), CRAB-21 (two readers still bind the resume revision), CRAB-9, CRAB-10, CRAB-11, CRAB-15 in TODO.md. Performance stays deferred; do not start F3 or frozen Rust allocator work.

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

Follow the active candidate and phase named in Status.
The remaining task is to accept or reject the selected runtime with evidence,
not to open another feature inventory, proof framework or general review tour.
Useful independent blocker repairs may run in parallel, but there is only one
active acceptance candidate. Extra slots are optional when no independent
selected blocker remains.

1. **Reconcile the active candidate first.** Inspect its actual process state,
   `candidate.json`, summary, terminal chain receipt and last useful output.
   If running, keep its checkout, SHA, image, inputs and outputs unchanged.
   A missing or inaccessible summary does not establish failure. Classify a
   terminal result immediately. A complete result must have all 86 steps,
   seven passing correctness gates, strict receipt-backed parity validation,
   `complete: true` and
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
   candidate resume for harness-only development with unchanged product inputs.
   Continue through the remaining chain before another fresh attempt, subject
   to every existing input, output and reader check. If reuse is rejected,
   identify the exact reason and rebuild only what the contract requires.
   Never edit receipts, relocate physical evidence, force a stale reader or
   call a mixed-revision run fresh. Inspect the structured result:
   `complete: true`, `fresh: false` and exit 1 solely for revision reuse proves
   development completion, never F2 acceptance. Changed product inputs need a
   new cohort. Follow the existing
   [candidate contract](compat/x86_64/qualification-chain.md#one-command-candidate-run),
   not a new resume protocol. After two materially different failed repairs,
   apply P4 to the specific blocker before another acceptance attempt.
4. **Keep the verification loop practical.** CRAB-5's bounded repair is landed;
   its full-run speedup remains unmeasured. Reopen implementation or measurement
   only if current evidence shows verification overhead obstructing completion.
   Keep changed-during-collection rejection intact. Do not interrupt a healthy
   candidate, impose a numerical budget or start a harness rewrite.
5. **Freeze the acceptance candidate.** Finish the permitted diagnostic path
   and known repairs before a fresh attempt. Inspect the candidate's `--dry-run`
   output for blockers using the actual seeded inputs and intended work path.
   A dry-run exit of zero alone is not readiness. The candidate branch is the
   integration head plus one provisional declaration commit: the seven chain
   families in `compat/x86_64/parity.toml` set to `foundation-verified` with
   verified evidence, and the regenerated `aarch64_parity_inventory.json`
   (pattern: `5be77042f`). Without it, `prerequisite-families` fails step 84.
   That commit integrates only after its fresh candidate is accepted. Use the existing
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
   observations in Status. Reconcile historical `math/pow` against actual
   aggregate case evidence. Missing required proof keeps F2 open. A later
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
5. **Native x86-64 only on this host.** F2 lanes stay x86-64. AArch64 work
   follows CRAB-8 on the arm64 VM host and its own branches; never emulate it
   or refresh old baselines to absorb drift.
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
profile expansion, frozen allocator, CRAB-8 AArch64 or pin work remains out of F2 scope;
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

New architectures or non-Linux runtimes; AArch64 execution inside F2 (CRAB-8 owns it); Rust allocator-port
restart or backend replacement; new cryptographic/numerical algorithms; weaker
semantics, safety, hardening or tests; a new orchestration/validation framework;
whole-toolchain integration; public-support promotion without authorization.
