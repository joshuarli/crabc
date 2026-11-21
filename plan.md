# crabc plan

This is the only active plan. The owner's 2026-11-12 direction is binding:
**finish the selected feature surface first, waive every performance and memory
budget until then, and run a continuously replenished parallel campaign.** It
supersedes the S0–S5/R2–R4 scheduling rules and serial defaults in shared campaign
skills. Parallel implementation gives way to bounded F2 closeout when the feature
queue is closed. Status takes precedence over general dispatch instructions.
Git retains the earlier plans; do not maintain a second handoff or log.

## Status and first action

**F2 closeout resumed 2026-11-17 by owner; final7 (below) failed on a harness defect, now in same-product diagnostic resume.** One acceptance candidate only; no new lane or unrelated work while it runs. Performance stays deferred.
Active candidate: `lane/f2-fresh-final7` at exact SHA `961b2fca6814c963bd45be10de2383c0012db85d` (main plus the core-image re-pin); checkout `.work/wt/f2-fresh-final7`, work `.work/x86_64/feature-complete`, inputs `.work/x86_64/inputs.json` from `prepare-worktree.sh`; log `.work/tmp/f2-final7-correctness.log`. Dry-run: 86 steps, no blockers, four attached receipts. Pinned image `sha256:8db4261ed9a1ffe5c973f090d7b339796099e7447c5dcddf6d1f015548dda3a6`. Keep its source, image, inputs and outputs unchanged while it runs.
Final7 result: incomplete at step 01 `dynamic-products` (status 1, `steps/01-dynamic-products`). Only case `aio` failed, in all three cohorts (`out/dynamic/qualification-cases/{installed,second,extracted}/aio.log`): `owned_aio_probe.c` treated one 2 s `aio_suspend` EAGAIN as failure with the fsync request still EINPROGRESS (`owned-aio wait errno=11 error=115`, stage fsync), in pinned musl (`owned-aio.lG9AcQ/oracle.stderr`) and crabc alike. Test defect, not runtime behavior. Repair `3e5723482` makes all five AIO probe wait loops retry EAGAIN like EINTR, leaving the reader-pinned host watchdog as the sole bound; scout review accepted; delayed-completion harness old exit 1/new exit 0 for each helper; in-image `./scripts/dev-x86_64.sh owned-aio` PASS (`.work/tmp/aio-lane-owned-aio.log`). Product source digest unchanged (probes are outside `source_seal.py files`).
Accepted repairs on main (lane `f2-aio-completion-wait` retired 2026-11-18): CRT invocation `17b8e2100`, text-validation reuse `2adf13539` (120 tests), message-queue isolation `0b172bdc7` (four tests and actual combined producer/reader).
Final6 (`lane/f2-fresh-final6`, `a5c32dfe2`) is an environment-loss interruption, not a runtime failure: its same-work resume passed steps 00–35, then step 36 `text-extracted-stdio-engine` hit host ENOSPC (`.work/tmp/f2-final6-resume.log`), and a host docker prune removed its pinned image `sha256:91e0733b…`, which cannot be reproduced. Its checkout and evidence stay as history. Its two provisional declaration files remain unaccepted.
Actual final6 math/pow: `out/posix-native/runs/libc-test/tmp/owned-libc-test.mpSqB7/libc-test.json` retains 428 passed/six runtime-failed cases. Its pow source is `6c4dc2812c42592cb8030532ded21908d685baa97df9967ef3c52cc3d12a68ab`; both exits are 0, oracle/candidate diagnostics 24/10. The strict libc-test receipt records the exact 14 identities as candidate-corrected-oracle-discrepancy, raw_passed false; native aggregate/admission passed. Final7 must re-prove it. Its candidate record, step records and that `libc-test.json` (sha256 `6f11327bfecb02f1…`) are copied to `.work/retained/f2-final6/`; the final6 checkout was removed 2026-11-18 (owner `doas` cleanup).
Parked failure branches/physical consumers: `lane/f2-fresh-final4` (`27761fdd3`, step 84 loader imports) and `lane/f2-fresh-final5` (`1c9ab6010`, step 52 shared MQ-name EEXIST); their checkouts keep `candidate.json`, `summary.json`, step records and the leaf trees named here; the owner-approved cleanup removed their other output. Final4 chain receipt is under `qualification-receipts/chain-capability.accounting-1794872955791848144-tn0cfaeu`; final5 leaf is `.work/x86_64/tmp/owned-combined-sysroot.iFI0YU/qualification-cases/second/message-queues.log`.
Retained proof branches/consumers: `lane/f2-hardened-selectors` (`72b8cd638`, loader case `qualification-receipts/case-hardened-repair/case.json`), branches `lane/f2-message-queue-isolation` (`9f879b5b7`) and `lane/f2-text-reuse` (`7aaac3673`), whose integrated checkouts were retired in the owner-approved 2026-11-18 cleanup. Focused proof is not full-run acceptance.
Permission-held fixtures remain untouched in checkouts: `.work/wt/{f2-admission-review,f2-fresh-final2,f2-lua-process-boundary,f2-process-control-wait,f2-resolver-reader-env,f2-run2}`. Their sources are detached `d6271924b`, `lane/f2-fresh-final2`, `lane/f2-lua-process-boundary`, `lane/f2-process-control-wait`, `lane/f2-resolver-reader-env`, and `lane/f2-admissions`, respectively. Retry refused fixture access/cleanup only after owner resolution. Git-only identity/cleanliness checks recorded closeout allowances for all six without reading ignored fixtures.
Historical parked branches: `lane/f2-fresh-final`, `lane/f2-fresh-final3`, `lane/f2-gate-closure`, `lane/f2-gate-review`, `lane/f2-timer-diagnostics` and `lane/f2-message-queue-review`; use repaired current source, not their superseded declarations. Prior archival records stay in `.work/tmp/f2-cleanup-archives/` (the superseded-candidate tarballs were removed in the owner-approved cleanup; `.work/tmp/archives-removed.txt` lists them) and the retired MQ-review diff in `.work/tmp/f2-message-queue-review.diff`; retry only for an actual unresolved consumer. MQ review acceptance was unmet despite no supported defect; parent proof owns the integrated verdict.
Access holds also remain exact: final4 `tmp/hardened-qualification.ZVkdk5/static-pie-tests.log`; hardened repair host write `.work/tmp/hardened-boundary-dynamic.log`; final5 cohort `{installed.build,second.build}/dynamic.build`; MQ worker `run-5rwx6isi/modules/001-test-owned-message-queues-runner/stderr.log`; prior process-inspection refusals. The final4 oracle-static/tools inputs were removed with its `out/` under the owner-approved `doas` cleanup. Do not retry or reroute denied actions. Preserve `.work/retained`, allocator/kache/pow-discriminator holds and all original failures.
Next slice: resume final7's work at the repaired main revision with the same command and inputs (same product digest; step 00 reused, step 01 reruns) through the end; complete true/fresh false is development completion only. Then a fresh final8 in a new isolated prepared checkout, and accept per F2 closeout step 6. CRAB-5 is landed with full-run speedup unmeasured; CRAB-6's cause stays unresolved and any required-behavior recurrence blocks. Do not start F3 or frozen Rust allocator work here.
**AArch64 campaign ([CRAB-8](docs/rfc/CRAB-8-linux-aarch64-feature-completion.md), A5 closeout): winding down 2026-11-20.** No new runs or lanes; handoff follows. Active candidate: `lane/a5-final8` `909d825dc` = `crab8/integration` `ec8937a39` + the provisional declaration (pattern `5be77042f`; see F2 closeout step 5). Inventory 223/223 and ledger 25/1 PASS; dry-run 86/0/4 on both hosts. Both fresh runs launched 2026-11-20 ~19:15: x86 threadripper `.work/wt/x86-final` (log `.work/x86_64/candidate.log`), arm orb `~/crabc/.work/wt/a5-pnative` (log `.work/aarch64/cand-909d825dc.log`). Keep both checkouts, SHA and inputs fixed while they run. Acceptance needs both `complete: true, fresh: true` at this SHA, then the status-only commit; on a failure, repair it on `crab8/integration` and rebuild the candidate.
Integrated since `1ebea762b` (each failing-then-passing on its owning producer): CRAB-17 exit gate (native, both arches), CRAB-18 secure-execution allocator environment for both native-shadow and the default C backend (`-Denviron=(*__crabc_allocator_environ())`, unedited upstream; native, both arches), CRAB-13 candidate stop ends dispatcher group and containers, CRAB-14 rust-std timeout kills the case session, CRAB-16 Safety docs plus `clippy::missing_safety_doc`, CRAB-19 same-product seal comparison (`source_seal.same_evidence`), CRAB-20 procedure, and harness-test triage (threadripper host suite now fails only image-only modules plus the pre-existing container-mount and `qualification_candidate` cases). CRAB-21 files the two readers still binding the resume revision.
Superseded runs: arm `e7a444c50` died at step 01 on inode exhaustion of the old ext4 image; x86 `e7a444c50` and `aaa930db9` were stopped for newer candidates. Their outputs are kept as `feature-complete-<sha>-stopped*` (x86) and on the old arm image.
Arm host after any reboot: `sudo mount -o loop ~/crabc-a5-final8-aarch64.ext4 ~/crabc/.work/wt/a5-pnative/.work/aarch64` (new image, 39M inodes; ext4 because btrfs `f_files=0` breaks statvfs), optionally `sudo mount -o loop ~/crabc-a5-pnative-aarch64.ext4 ~/crabc-a5-pnative-aarch64-old` (all earlier arm runs; preserve), then `sudo rc-service docker start`.
Open decision: CRAB-12 (AArch64-only facade atfork registry) needs owner choice; recommended B removes the facade `register_atfork` and generic `fork` on AArch64 (public API removal), proved in the arm VM.
Parked: `lane/a5-final`–`final7` (declaration candidates) and `lane/a5-pnative` (orb mirror). Lanes `lane/a2-*`, `a3-*`, `a4-*`, `a5-cohort` and `a5-dynamic-roster*` are cherry-picked history; their content is in crab8/integration except unpicked commits on a2-fixtures, a4-abi2 (28), a4-abi3, a4-builder3, a4-corpus, a4-resolver-network2 (5), a4-tests-harness (2), a5-cohort, a5-dynamic-roster2 (4) and a5-dynamic-roster3 (3). Wind-down preserved uncommitted work as `chore(lane)` commits on a4-builder-evidence, a4-product-fixes, a4-wordexp and a4-x86-restore. Deleting any of these needs `-D`, which is the owner's call.
Debt: CRAB-21, pre-existing `test_owned_posix_family_execution` container-mount and `test_qualification_candidate` cases, and six host-only test modules that pass only in the pinned image.
**Unattended x86 tail (2026-11-18):** `.work/tmp/f2-chain.sh <SHA>` (log `.work/tmp/f2-chain.log`) waits for the final7 resume; only if final7 is `complete: true` and ≥60 GB is free does it prepare `.work/wt/f2-fresh-final8` (branch `lane/f2-fresh-final8`) at the fixed main SHA recorded in that log, require dry-run 0 blockers/86 steps/4 attachments, run the fresh correctness candidate (`.work/tmp/f2-final8-correctness.log`), then `perf-queue.sh` on final8's product (`.work/tmp/perf-queue.log`; full budget only on an uncontended host, else smoke). Any STOP line returns to F2 closeout step 2. Acceptance per step 6 is recorded by a later session on this host.
**Wind-down for host reboot (2026-11-18 ~19:10):** resume2 was externally SIGTERMed at 18:26:17 (exit 143, `.work/tmp/f2-final7-resume2.log`) while `combined-sysroot` was running — the same way the 15:44 attempt ended; not a product failure (its inner output shows package corpus pass ×3 and cross-DSO PASS ×3). resume3 (setsid, `.work/tmp/f2-final7-resume3.log`) reused steps 00–51 and reached only the pre-step digest phase; for the reboot it and the chain were stopped before final7 wrote any new state. Final7 is not complete; final8 never built; acceptance is not recorded. `steps/52-combined-sysroot/` retains resume2's partial tree untouched; `summary.json` keeps its stale 2026-11-18 01:30 baseline. Re-run the same resume command after reboot (step 52+ re-runs; 00–51 resume).

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
