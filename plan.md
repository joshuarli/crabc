# crabc plan

This is the only active plan. The owner's 2026-11-12 direction is binding:
**finish the selected feature surface first, waive every performance and memory
budget until then, and run a continuously replenished parallel campaign.** It
supersedes the S0–S5/R2–R4 scheduling rules and serial defaults in shared campaign
skills. Parallel implementation gives way to bounded F2 closeout when the feature
queue is closed. Status takes precedence over general dispatch instructions.
Git retains the earlier plans; do not maintain a second handoff or log.

## Status and first action

**Active 2026-11-23: D25 dual-native correctness milestone** (owner direction).
Goal: one shared runtime whose build inputs, validation machinery, installed
products and native x86-64 and AArch64 results agree at one fixed SHA. Work the
[D25 sequence](#d25-dual-native-milestone) from current main in parallel lanes;
step M6 is the only acceptance attempt. Convergence is already on main by owner
direction; pre-merge sequencing in CRAB-8 and earlier Status no longer blocks.

**Active: M6 candidate `84a8b07b3` running on both native hosts** (started
2026-11-24 ~07:20 UTC). It is main `529358665` plus the provisional
declaration; both dry-runs had 86 steps and no preflight blockers.
x86: `threadripper:~/d/crabc/.work/wt/d25-m6`, `--work .work/x86_64/feature-complete`.
arm: OrbStack machine `crabc`, `/mnt/crabc/home/crabc/.work/wt/d25-m6`,
`--work .work/aarch64/feature-complete`. Both use `--profile correctness
--inputs .work/<arch>/inputs.json`; logs are `../../tmp/m6-run.log` beside each
checkout. Do not write to either checkout while they run.

The owner re-pinned arm to
`sha256:7ac9c379fbd0ba3c6bdd7e28b18f95276615cfecf668f26e104ba14271c0bce0` on
2026-11-24 after the old `7b7cd03d…` image was lost; every manifest-tracked
tool except rustc is byte-identical. The VM is Alpine 3.23, kernel 7.2.12, 4 KiB
pages, 9 CPUs, with the clone, `.work` and Docker data root on a 40M-inode ext4
loop mount at `/mnt/crabc`. Nothing is accepted.

| Step | Done on x86-64 | Still needs native arm64 |
| --- | --- | --- |
| M1 | Toolchain check, current-pin docs and `campaign-status`; check passes | Integrated: manifests collected natively, CI runs the check, readers pass under the new pin |
| M2 | Canonical CI image, readers migrated, recipe deleted, bounded smoke | CI now runs the M1 check |
| M3 | Integrated with the AArch64 no-alloc `Buffer` import fix; no_std profiles and process/signal tests pass | Done in the rebuilt image: no_std profiles, process/signal tests, `verify_signal_process.py --readelf readelf --objdump objdump`; CRAB-12 closed |
| M4 | Futex-backed TSD and worker-registry locks; static FIFO reproducer fails before and passes after, and passes again after the arm port | Reproducer ported and runs; arm proof invalid in the VM (see CRAB-11); the x86-only TSD producer has no arm route |
| M5 | Three readers accept same-product resume; x86 producers pass | Resume tests pass on arm; static product and signal legacy alias producers pass; the dynamic product, including classic netdb, passes under the new pin; five older arm fixture failures remain in `test_compiler_helper_evidence.py` and 40 in `test_owned_posix_product_evidence.py` (x86-only fixture identities) |

Arm64 sequence:

1. Create the VM using [CRAB-8 host setup](docs/rfc/CRAB-8-linux-aarch64-feature-completion.md#host-setup-orbstack).
   Keep the clone on the VM's disk and `.work/aarch64` on ext4 with about 40M
   inodes. Install Docker Engine inside the VM, and never use a macOS bind mount
   or emulation.
2. Confirm `docker image inspect sha256:7ac9c379fbd0ba3c6bdd7e28b18f95276615cfecf668f26e104ba14271c0bce0`
   succeeds. The arm image is not reproducible, so a rebuild with another ID is
   a re-pin that changes the frozen inputs: stop and ask the owner before
   adopting it.
3. M1: collect actual tool identities from that image and repair
   `owned_resolver_alias_image_inputs_aarch64.json`,
   `owned_resolver_network_image_inputs_aarch64.json` and
   `owned_classic_netdb_image_inputs_aarch64.json` together. No dedicated
   collector command exists. Never copy x86 values. Run their readers, then
   confirm `python3 -B compat/x86_64/source_image_toolchain_check.py` changes
   from exit 1 to exit 0. Add it to `.github/workflows/ci.yml` between
   `make test` and the fetch/smoke step.
4. M3: rebase `lane/d25-m3` on main, run the exit proof above, integrate and
   close CRAB-12. `compat/crabc-rs/coverage.toml` is a frozen input and keeps
   its stale atfork entry.
5. M4: build an owned static sysroot, then run
   `compat/pthread-stress/run_tsd_fifo_progress.sh --sysroot <sysroot>` with
   `CAP_SYS_NICE`, plus the pthread producers. Dynamic routes such as
   `owned-dynamic-pthread-exit` and `owned-dynamic-fork` need
   `CRABC_X86_64_CORE_IMAGE` or `CRABC_AARCH64_CORE_IMAGE` set because the
   dispatcher does not call `ensure_image` for them.
6. M5: run the owning arm producers and readers for `6161b069d` and `9c8056050`.
7. Before the candidate, re-collect `compat/x86_64/native-abi-exports.json` from
   a validated collection, because anonymous hashes change with any libc change.
   Check `native-abi-exports-aarch64.json` natively. Never refresh frozen
   AArch64 inputs to absorb drift.
8. M6 at one SHA on both hosts, then M7. The x86 run needs this Linux host or
   another native x86-64 host.

Scratch: passing dynamic cases now keep digests and receipts instead of their
execution roots, cutting a run from about 15 GiB to about 4.3 GiB. Failed cases
keep everything. Loader-synthetic, package-corpus and DNS cases still keep their
roots because their readers replay them. Remove root-owned `.work` paths through
the pinned image before retiring a worktree.

Current environment facts (verify, do not trust): `rust-toolchain.toml` selects
`nightly-2026-11-09` since `6161b069d`, which also rebuilt both core images
(`compat/x86_64/core_image.py`: x86 `sha256:b243d937…`, arm `sha256:7ac9c379…` since the 2026-11-24 re-pin).
The 2026-11-21 cold-capsule and two-build reproduction results proved the earlier
`c689abaa…` image on the earlier nightly at `b82313a51`; they are historical and
prove nothing about the current pair.
Last accepted revision: none for F2. Last integrated checkpoint: `5add38189`
(x86-64 side of M1, M2, M4 and M5), no full candidate completed. Last
candidate `lane/a5-final8` `909d825dc` was stopped for wind-down (x86 at step 03,
arm at 01); not accepted, never resumed.
Hosts: x86 on native Linux ([development setup](docs/development.md)); arm in a
native arm64 Linux VM whose work directory is ext4 (nonzero statvfs `f_files`,
roughly 40M inodes; btrfs breaks it), never macOS Docker or emulation.
Uncommitted orb leftovers stay on `park/orb-*`, never integrated.
Superseded and parked candidates: `lane/a5-final`–`final8`, `lane/a5-pnative`,
`lane/f2-fresh-final`–`final7` and the F2 repair/proof branches; unpicked commits
on earlier `lane/a2-*`–`a5-*` branches were never integrated. Deleting any needs
`-D`, the owner's call.
Debt outside D25: CRAB-9 and CRAB-10 apply only as local repair rules (M7).
CRAB-6 stays open. Earlier F2 holds (permission-held fixtures, access refusals,
CRAB-5/CRAB-6 observations) are recorded at `8fb1553b6`; preserve them and never
retry denied actions. Performance stays deferred; do not start F3 or Rust allocator work.

## D25 dual-native milestone

**D25 — owner decision, 2026-11-23.** It replaces the A5/F2 resume handoff and
extends F2 acceptance to both native architectures at one SHA. F2 closeout steps
1–6 still govern each candidate. Use "integrated checkpoint" for reviewed code on
main and reserve "accepted" for completed qualification. M1–M5 are independent
lanes unless noted; integrate coherent reviewed batches and continue without
waiting for steering when the next step is clear.

| Step | Work | Exit proof |
| --- | --- | --- |
| M1 — environment | Collect actual tool identities from the current pinned native arm image and repair the three stale arm manifests together, keeping their independent expected identities and hash checks (never copy x86 values or relabel old outputs). Run their product and resolver readers natively. Add one small structured check, for both arches, that the current toolchain's expected compiler path appears in every active relevant source-image manifest; native collection still establishes the hashes. Reconcile `docs/development.md` and `campaign-status` with the current image/source pair. Then freeze toolchain, images, profiles and dependencies for the acceptance window; batch any later change a demonstrated correctness blocker forces. | Manifest readers pass natively on arm; the new check fails on the old manifests and passes on the repaired ones; setup docs name the current pins and label the old capsule historical. |
| M2 — CRAB-22 | Move `ci.yml`/`lint.yml` to `docker/image/build.py` + `sources.lock.json` (or its verified pinned result) with cache reuse, migrate every remaining `Dockerfile.x86_64` reader (parity ledger, header/ABI inventories, `owned_posix_native_execution`, `parity.toml` `source_owners`) in the same change, then delete the recipe once it has no consumers. Keep the fast host builder/dispatcher tests. Add a bounded native installed-product smoke (existing runners, selected static and dynamic behavior). It runs M1's consistency check and claims only that; it never stands in for the seven-gate milestone, and CI does not run the full chain. | `rg Dockerfile.x86_64` finds no active consumer; CI catches the old manifest mismatch and runs real installed behavior. |
| M3 — CRAB-12 | Adapt `lane/crab12-facade-atfork` `e41d722fe` (unverified material) to current main. Remove only the AArch64 facade `process::fork`, `process::register_atfork` and their registry. Keep the documented unsafe raw fork, prepared-exec (errors, cleanup, `Child` ownership), libc C `fork`/`pthread_atfork` and existing state-repair and callback-ordering coverage. Docs and coverage references name the current shared C owner; keep arch-specific qualifications where APIs still differ. `!` subject plus `BREAKING CHANGE:` footer. Do not reopen the bridge design or treat this as license to shrink other obligations. | `scripts/lanes/rust-check.sh` focused builds and crabc-rs process/signal native tests on both arches, plus `compat/crabc-rs/verify_signal_process.py` in native arm64; then integrate and close CRAB-12. |
| M4 — CRAB-11 correctness | Separate TSD contention cost (deferred under D23) from progress. Build a bounded native reproducer: controlled affinity and `SCHED_FIFO` priorities, external watchdog, waiter spinning on `SELECTED_TSD_LOCK` while the preempted owner shares its CPU. If reproduced, fix the progress mechanism with the smallest correct design after reading the pinned musl oracle and current ownership; preserve key deletion, destructors, fork interaction and worker-mapping lifetime, and rerun the affected pthread producer. If the environment cannot run it (for example no `CAP_SYS_NICE`), record exactly which proof is missing and keep CRAB-11 open as a correctness item. Unrelated lock optimization stays out. | Reproducer fails before and passes after the fix under the watchdog, plus the pthread producer; or a recorded missing-proof statement. |
| M5 — CRAB-21 and product boundaries | Finish the reader paths (`owned_resolver_alias_contract_reader._source_identity`, `owned_resolver_family._validate_admission_sources`, `compiler_helper_evidence._source_seal`/`_aggregate_record`) that reject a same-product development resume only because the Git revision moved, using the existing source-seal/content-identity model. Keep the checks on product content, tool/image identity, inputs, retained outputs, clean source and changed-during-collection. Test both a permitted harness-only revision change and a forbidden product or evidence-input change. Development reuse stays `fresh: false`. Separately run the owning installed-product producers and readers for the recent toolchain (`6161b069d`), symbol-localization and linker-fixture (`9c8056050`) repairs; a unit fixture alone does not close them. | Both resume cases behave as stated in the owning readers; the named producers/readers pass natively. |
| M6 — candidate | After M1–M5 pass their focused producers, build one clean candidate from main plus the provisional declaration (F2 closeout step 5; regenerate it rather than reuse `5be77042f` if the ledger moved). Inspect the actual dry-run for blockers; capability totals and provisional declarations are readiness inputs only. Run all seven correctness gates natively on x86-64 and AArch64 at the same SHA with full product-mode, hardening, ABI, Lua and Rust std/LTO/unwind obligations and the accepted page-size limit and gaps. On failure: classify (runtime, test/oracle, reader/publication, environment), one owner plus independent review, prove through the smallest test and the owning producer/reader, resume unchanged products only where contracts allow, then one fresh run after all known repairs. Keep healthy checkouts and environments fixed; never run full candidates to discover whether a local fix worked. | Both native summaries report `complete: true` and `fresh: true` at one SHA with complete gates and accounting validated. |
| M7 — report | A status-only commit records the tested commit, both image IDs, both candidate results and evidence paths, installed artifacts, supported linkage/hardening modes, intentional differences, unresolved observations (CRAB-6), tested platform/page-size coverage and deferred performance qualification. It does not restart acceptance. Then propose, without starting it, the next phase: one real downstream consumer through the installed sysroot, followed by measured performance and memory work with the existing harness. | Status names accepted evidence; next phase proposed to the owner. |

Local repair rules during D25: when a lane touches a test family, replace its
redundant source-text mirrors with behavioral checks (CRAB-9); when repairing a
blocked producer, move duplicated architecture facts into `native_arch.py`
(CRAB-10). Keep useful ABI and dispatch checks. No whole-repository test
rewrite, rename campaign, provenance framework, new architecture, macOS backend
or Rust allocator work. CRAB-6: on recurrence use its existing diagnostics; never
widen the wait or call it fixed after unrelated green reruns.

## Goal and completion boundary

Finish the entire selected native Linux/x86-64 runtime in
[COMPATIBILITY-PROFILE.md](COMPATIBILITY-PROFILE.md) and
[docs/completion-requirements.md](docs/completion-requirements.md): C/POSIX
behavior, headers/ABI, direct Rust facade, loader/TLS, CRT/builtins/sysroot,
hardening and real consumers. Use the pinned C mimalloc backend. New work that
closes this already-selected surface is authorized; new platforms, unrelated
APIs and the frozen Rust allocator port are outside this campaign.

Feature-complete means all selected obligations have current behavioral proof
on both native x86-64 and AArch64 (D25),
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
   observations in Status. Missing required proof keeps F2 open. A later
   status-only commit reports that tested SHA; it neither claims its own SHA was
   tested nor requires another full run just to record acceptance. Any change
   to product, test, gate or contract inputs needs the applicable checks and a
   fresh accepted candidate. Under D25 every step here applies to both native
   candidates at one SHA. Leave performance explicitly deferred, preserve
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
5. **Native execution per architecture.** Under D25 both arches are in F2:
   x86-64 runs on native x86 Linux, AArch64 only in its native arm64 Linux VM.
   Never emulate either or refresh old baselines to absorb drift.
6. **Pins stay.** After D25 M1 freezes them, do not change `rust-toolchain.toml`,
   `compat/upstreams.toml`, the Alpine base digest or either pinned core image
   except as one deliberate batch forced by a demonstrated correctness blocker.
   Do not run the destructive `./scripts/dev-x86_64.sh image` rebuild as routine
   preparation.
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
profile expansion, frozen allocator or unbatched pin work remains out of F2 scope;
park only the dependent slice. A denied tool action is stopped with its exact
reason preserved; do not reroute it. No destructive cleanup on stop.

## Preserved decisions and holds

D23/D24 override earlier numerical cost/structure budgets, mandatory measurements,
R3-before-feature sequencing and restrictions on selected-feature parallel lanes.
They do not change these boundaries:

- **D25** extends F2 to both native architectures; D23/D24 still apply.
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
  F2 aggregate must still pass.
- **Math reference (closed).** `7a8839caf`/`f3edf363c` admit exact corrected
  binary64 power identities and `f4aa674bf` bounds arm64 musl departures by
  named difference contracts with rejection tests. Preserve that fix and its
  tests; do not reopen it as an unresolved investigation. A new failing math
  case in a candidate is an ordinary blocker under F2 closeout step 2. Never trim
  the libc-test aggregate or invent an exception.
- Existing `archive/*`, `cohort/*`, `integration/*`, `lane/*`, `parked/*`,
  `proof/*`, `recovery/*` and `review/*` branches are not automatically adopted.
  Never merge parked allocator branches. New scoped lanes use reviewed current
  main; inspect existing work before any reuse.
- Preserve `.work/retained/`, `.work/allocator-x86_64/`, `.work/x86_64/kache`
  and `.work/tmp/pow-discriminator-*`. `git worktree list` is authoritative;
  never delete unique source, failed evidence or unresolved ignored files.

## Needs environment

Native product/correctness execution requires the pinned x86-64 and AArch64
images on native hosts and their existing fixtures/network capabilities. M4
needs real-time scheduling permission for its reproducer. If unavailable, preserve the exact command
and blocker, continue host-side checks and other independent slices, and leave F2
open. PMUs, a quiet host and delegated cgroup memory accounting are only F3 needs;
their absence cannot block feature completion.

## Non-goals

New architectures or non-Linux runtimes; Rust allocator-port
restart or backend replacement; new cryptographic/numerical algorithms; weaker
semantics, safety, hardening or tests; a new orchestration/validation framework;
whole-toolchain integration; public-support promotion without authorization.
