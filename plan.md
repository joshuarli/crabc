# Qualify and promote crabc's native x86-64 runtime

**Status: running unattended 2026-10-13.** Ground tooling and pinned inputs
have merged; all runtime lanes have run their independent checks. All three
H0 dynamic products passed and were published after retained validation;
POSIX-family, crypt, atomic and wordexp steps passed. POSIX-native continues.
M1's layout prerequisite is parked after three narrow experiments failed to
reproduce its aggregate failure. M2 has no failing executed check but remains
partial. M3's Miri matrices pass; its native batch has five stale refused-free
assertions under correction. M4 retains one address-reuse mismatch. M5's native
runner corrections remain under review. M6's four-profile adapter matrix and
retained replay pass; the complete baseline gate is running. Source convergence,
focused defect fixes, cleanup and campaign review continue. Nothing
has been qualified on main: 0 of 8 gates, 9 of 26 families. Earlier receipts
were deleted with `.work/` on 2026-10-07.

- **Resume:** "Read `plan.md` and `docs/lanes.md`, then run the campaign in
  `plan.md` as coordinator, unattended, launching every ready lane in the
  plan's priority order." First command:
  `./scripts/dev-x86_64.sh campaign-status`.
- **State:** branch `main`. The pinned images exist locally and
  `compat/x86_64/core_image.py` names the core image. Do not rebuild an image:
  a rebuild changes its ID and voids every receipt made in it.
- **Open branches:** 62 besides `main`, none needed to resume; see
  [Baseline](#baseline).

## Goal

Make native Linux/x86-64 a publicly supported crabc target, then make the
Rust port of mimalloc v3.5.0 its default allocator. Correctness comes first:
every selected capability works through its intended runtime path and one
revision passes the correctness qualification chain before any performance
work.

Deliverables:

1. **D1 Ground.** The qualification tooling can express every state this
   plan needs, the cohort runner's preflight is clear, and both known
   allocator failures are tracked tests.
2. **D2 Correctness qualification.** One revision on `main` at which all 223
   capabilities are `implemented-foundation`, all 25 functional families are
   `foundation-verified`, and gates 1 to 7 pass.
3. **D3 Runtime performance.** A fresh scorecard exists and the runtime is no
   worse than pinned musl on every row.
4. **D4 Public x86 support,** on the accepted C allocator.
5. **D5 Native allocator default.** The Rust port passes its correctness
   milestones and its performance table, becomes the x86 default, and the
   chain passes again at that revision.
6. **D6 Close.** Dead code removed, review findings fixed, final report.

## Charter

- Decide, log the call in the [decision log](#decision-log), and keep going.
  Never ask, never wait for approval, send no check-in. Run until every
  deliverable is met or every remaining item is parked.
- **Parity before optimization.** No optimization item changes product code
  until every ground, parity and hardening item it depends on is done; a
  parked item does not unblock what depends on it. Before that, performance
  is measured and logged (P0), never gating and never tuned.
- **Hard stops, each of which parks the item:** an action that changes
  anything outside the repository other than fetching a pinned input, or that
  cannot be undone from Git (pushing, renting resources, rebooting, changing
  host huge-page pools or security policy); deleting `.work/` or a `.cache/`
  directory; rebuilding a pinned image; running or emulating AArch64; a
  boundary this document forbids; a harness denial of a tool call (do not
  retry it or route around it); a loop that can no longer check anything.
- **Fix on the way, in its own commit:** a loop command over 5 minutes (get
  it under 90 seconds or give the item a narrower check); a test that is red
  on `main` and blocks the item; a throughput or CPU regression worse than
  2x against the last recorded number. Record anything else seen and leave it.
- **Time-box per failing step.** One failing cohort step, test, or gate
  condition gets 3 attempts, each a hypothesis with a predicted observation
  as `root-cause` describes. Then park that step with the finding and take
  the next one that does not depend on it.
- **A claim commit that is not proven is reverted.** H1, O2 and O4 commit
  what a revision claims before its cohort runs. If that cohort is parked,
  revert the claim commit first, so `main` never carries an unproven
  `foundation-verified`, `public_support = true`, or native default.
- **Bookkeeping stays minimal.** No new receipt schema, validator, runner, or
  status prose per artifact. Reuse `qualification-candidate` and the existing
  family matrices. A validator or test that only restates prose, a source
  literal, or a count is deleted, not fed.
- **Go wide and staggered,** as [Running it fast](#running-it-fast),
  `orchestrate` and [docs/lanes.md](docs/lanes.md) set out. An idle slot
  with ready work is a defect. Budget 8 GiB per lane that builds
  `crabc-mimalloc` tests; read peak memory of the first launches and keep
  12 GiB available.
- Lane worktrees live at `.work/wt/<lane>` on branch `lane/<id>`; all scratch
  stays under `.work/`, never `/tmp`. The coordinator removes a lane's
  worktree and branch once its workstream has nothing ready. A parked lane keeps its
  branch and is named in the [campaign log](#campaign-log).
- **Three files have one writer.** Only the tooling lane edits
  `scripts/dev-x86_64.sh`, `compat/x86_64/parity.toml` and
  `compat/x86_64/validate_parity_ledger.py`. Another lane that needs a change
  there reports it.
- **The frozen inputs never change:** `compat/x86_64/aarch64_frozen_baseline.json`
  and the three files it digests, `compat/crabc-rs/coverage.toml`,
  `compat/abi/musl-1.2.6/aarch64/manifest.json` and
  `compat/abi/musl-1.2.6/aarch64/headers.tsv`.
- Every commit is a Conventional Commit with the workstream as scope. The
  item ID goes in the body. Code comments never cite this document.
- The coordinator integrates, verifies on the merged tree, and edits this
  file. Lanes do not.

## Qualifying a revision

Receipts are sealed to one clean commit, and the cohort runner rechecks that
before and after every step, so it can never run in a checkout that moves.

1. Commit what the revision claims on `main` first: the ledger rows, each
   naming the receipt path the run will produce under `.work/x86_64/cohort/`.
2. `git worktree add --detach .work/wt/cohort-<item> <that commit>`, then
   `scripts/lanes/prepare-worktree.sh` inside it. Receipt paths are relative
   to the worktree, so the ledger names the same path whichever worktree
   runs.
3. Inside it, run
   `./scripts/dev-x86_64.sh qualification-candidate --work .work/x86_64/cohort --profile P --inputs .work/x86_64/inputs.json`.
   Never edit or commit in that worktree. A restart on the same commit resumes
   at the first incomplete step.
4. Receipts prove that commit and no other. Campaign-log lines and every later
   change are later commits; `main` stays green afterwards because receipt
   binding is checked only on request (T0).
5. Allocator milestone reports and `allocator-m10 --build-audit` are bound to
   the checkout and commit in the same way: for O3 and O4, rerun them inside
   that cohort worktree.
6. Keep a qualified revision's worktree until the next one is qualified;
   then remove it with `scripts/lanes/remove-worktree.sh`.

Rehearsals (H0) and lane checks are not qualification: they may reuse one
worktree with a fresh `--work` name each time.

## Decisions

### Owner-decided (2026-10-13)

1. **Parity first.** The two known allocator failures and the correctness
   chain come before performance work. This replaces the 2026-10-03 direction
   to defer known blockers to the end.
2. **Public x86 support is decoupled from the native allocator.** x86 is
   promoted on the accepted C allocator once D2 and D3 hold. The native
   allocator becomes the default later, through its own gate (D5).
3. **Runtime performance gates on no regression.** Promotion requires the
   one-sided 95% upper bound of candidate over musl to be at most 1.00 for
   CPU and for PSS and `memory.peak` on every row, and syscalls at most 2R.
   The 0.90 figure is reported per row as a target and gates nothing.
4. **Branch cleanup.** Delete every `lane/*` and `lane-*` branch that
   `git cherry main` shows as empty or fully integrated; keep the rest. Done.
5. **Only x86-64 is in scope.** AArch64 is preserved and never run or
   emulated on this host.
6. **Pristine before resuming.** Fix or delete what is stale, dead, or
   unverified rather than listing it.

Earlier owner decisions that still hold: default behavior matches pinned
musl's defaults (2026-09-25, see [Reference](#fixed-contracts)); ordinary
baseline promotion may proceed with physical NUMA and explicit 2-MiB and
1-GiB page modes unqualified (2026-10-02); floor-limited total-memory rows use
a no-regression check (2026-10-02); qualification bookkeeping is to be reduced
(2026-10-02).

### Prescribed

| Decision | Reason | Reverse if |
| --- | --- | --- |
| The ledger validator checks structure at every commit and checks receipts only when asked (T0). | A verified family is bound to a receipt sealed to one commit, so today the tree would turn red at the first commit after qualification. | The owner wants qualification to be a terminal, tagged state. |
| No ledger state changes before H1. All 43 capability and 16 family transitions land in the one H1 commit. | A transition is only true at the revision whose cohort proves it. | — |
| M10's `promotion-rerun` condition is met by a validated full-profile chain receipt for the switched revision (T4). | It is hard-coded unmet today (`compat/allocator/x86_64_m10_gate.py:332`), so D5 could never be proven. This defines the condition; it relaxes nothing. | The owner wants a different proof of the rerun. |
| The cohort runner's own validation is the review that product publication requires. It publishes the dynamic product after `dynamic-products` and the static product after `static-sysroot` (T5). | Gate 4, the static-TLS family and the promotion closure each require a "reviewed" publication (`compat/x86_64/qualify_loader_corpus.py:108`, `validate_parity_ledger.py:9412`, `campaign_promotion_closure.py:75`), and no script performs one. | The owner wants to review products by hand before each qualification. |
| The checked-in qualification profile stays `full`. Everything before O1 passes `--profile correctness` explicitly. | The promotion closure requires the chain, declaration and ledger profiles to agree. | — |
| Lanes are `orchestrate` tiers, default `worker`; no repository agent types and no fixed model or lane count. | The harness refuses other agent types, and width is set by memory and disjoint files. | The owner wants a fixed model for all lanes. |
| The 16-KiB worker-stack and public-Theap child failures must pass in the release product. The opt0 debug product is required too, but may be parked after the time-box if release passes. | Release is what ships; the failures were only ever recorded at opt0. | The owner wants opt0 parity to block promotion. |
| A denied debugging action is a hard stop for that item, not something to rephrase. | The earlier "crash investigation workflows rejected by safety review" was never written down, so the only safe rule is the general one. | The owner says exactly what was rejected. |
| Privileged containers are allowed only as the tracked launchers start them (`SYS_CHROOT` probes, the `perf-c` collector's `SYS_ADMIN`, `SYS_PTRACE`, unconfined seccomp). No ad hoc privileged `docker run`. | They are part of the checked-in contract; anything else is an unreviewed host action. | — |
| Allocator code size is logged, not gated. | No gate bounds it today, and adding one is new bookkeeping. | The owner sets a bound. |
| Package corpus: first try to recover the 9 missing APKs byte-exact with `compat/corpus/fetch_x86.py --mirror-base-url` (2 mirrors at most). Failing that, re-pin all 59 archives to one current signed v3.24 index, with the package roster and every scenario unchanged. | The pinned bytes are gone upstream and no copy survives on this host; the corpus tests loader behavior on real packages, not those exact revisions. | The owner holds a copy of the original archives. |
| Pinned upstream inputs that a `.work/` reset would lose are cached in an ignored `.cache/` directory beside their harness, as `compat/allocator/.cache/` and `compat/lua/.cache/` already are. | The 2026-10-07 reset is what lost the corpus. | — |

### Delegated

The executor decides, inside the bound, with the smallest reversible
assumption, and logs it:

- **Design inside a lane's files.** Structure, test shape, and names.
- **Dependencies.** A focused pure-Rust crate may be added when
  [docs/scope.md](docs/scope.md) allows it. The repository has no build-time
  or binary-size gate, so state both deltas in the commit body. Nothing may
  be added to `crabc-mimalloc` outside its fixed dependency direction.
- **Splitting or merging parity items** when discovery shows failures
  cluster differently than the workstreams below assume.
- **Parking D5.** Park O3 after 12 measured increments, or sooner when three
  consecutive increments each move suite throughput lower95 by less than
  0.02. The campaign then closes with D1 to D4.

## Baseline

Measured 2026-10-13 on this host (32 CPUs, 60 GiB).

**Loop timings**

| Command | Time |
| --- | --- |
| `scripts/lanes/rust-check.sh` (nine `cargo check` profiles) | 98 s cold, 10 s warm |
| `scripts/lanes/rust-check.sh cargo check -q --locked -p crabc-core` | 2 s |
| `./compat/allocator/run-x86_64.sh allocator-unit --filter <one test>` | 52 s cold, 9 s after an edit |
| `python3 -B scripts/test_python.py --directory compat/x86_64/tests --jobs 6` | 127 s |
| `python3 -B scripts/test_python.py --directory compat/allocator/tests --jobs 6` | 73 s warm, 149 s in a fresh worktree |
| `python3 -B compat/allocator/architecture_ratchet.py --check` | 28 s |
| `scripts/lanes/prepare-worktree.sh` in a fresh worktree | 66 s, network |
| `./scripts/dev-x86_64.sh owned-posix-static-products DIR` (cohort step 1) | 58 s, passes |
| `validate_parity_ledger.py`, `aarch64_parity_inventory.py`, `check_structure.py`, `campaign-status` | 1 to 6 s |

**Green on `main`**

Every host-side test directory (23 directories, 5,802 tests),
`scripts/check_structure.py`, the parity ledger and inventory checks,
`campaign-status`, all nine `rust-check.sh` profiles,
`architecture_ratchet.py --check`, the static product build, and one
allocator unit test through the launcher, all from a clean worktree at
`7a86c7a7a`. Three test modules compare a
digest of the whole checkout (`test_native_abi_selection`,
`test_owned_static_sysroot_package`, `test_owned_posix_static_products`):
run them in a tree nothing else is editing.

**Not exercised on this host**

- Tests of the paused AArch64 target skip when its Rust target is absent
  (`builtins/tests/test_link.py`, `crt/tests/test_build.py`,
  `crt/tests/test_static_pie_link.py`).
- `test_owned_pthread_lifecycle` and `test_owned_pthread_timed_dynamic_authority`
  skip without a native-built fixture; `compat/perf/tests/test_x86_64_peers.py`
  skips its DNS peer when loopback port 53 cannot be bound.

**Known blockers**

- **The qualification tooling cannot reach the states this plan needs.**
  T0 to T5 exist because of these, each read in the code:
  - A verified family must name a receipt sealed to the current clean commit
    (`compat/x86_64/validate_parity_ledger.py`, the family admission
    functions near lines 6700 to 7080, the Lua admission near 7827 and the
    static-TLS publication at 9373 to 9418), so the ledger check would fail
    at every commit after the one that was qualified.
  - The promotion closure requires the native allocator to be the default
    (`compat/x86_64/campaign_promotion_closure.py:68-73`).
  - Full performance runs require `correctness_admission == available`
    (`compat/perf/run_x86_64.py:720`), which lists every active gate as
    incomplete unconditionally
    (`compat/x86_64/generate_qualification_manifest.py:325`).
  - `m10.promotion-rerun` is appended unmet unconditionally
    (`compat/allocator/x86_64_m10_gate.py:332`).
  - The generator hard-codes `public_support` false
    (`compat/x86_64/generate_qualification_manifest.py:291`).
- **Cohort preflight.** `qualification-candidate --dry-run` reports the two
  unseeded source oracles and the missing Lua, std/LTO and performance
  inputs. It reports the package corpus only when its directory is absent
  (`compat/x86_64/qualification_candidate.py:519`), so the partial corpus
  that `prepare-worktree.sh` leaves, 50 of 59 archives, hides that blocker.
- **The pinned package corpus can no longer be fetched.** 9 of the 59 APKs in
  `compat/corpus/manifest-x86_64.toml` return 404 from the Alpine v3.24
  repository (superseded revisions of `python3`, `libcrypto3`, `libssl3`,
  `libexpat`, `nghttp2-libs`, `ca-certificates-bundle`), and no copy survives
  on this host. `dynamic-products` and gate 4 consume this input.
- **Two allocator failures have no test.** "Worker attachment on a legal
  16-KiB pthread stack" and "the public-Theap consumer's child-subprocess
  phase" were recorded only as prose, at opt0. No fixture, command, or commit
  message reproduces them. The nearest harness is
  `compat/allocator/x86_64_m6_public_theap.py` (`--debug`, contexts `main`,
  `worker`, `child`, `fork`) and
  `allocator-m4 --differential SCENARIO --build-profile debug --valid-clients-only`.
- The static-TLS repair (`ec57a0b1f`, `libc/src/c_abi/x86_64/static_tls.rs`)
  landed with a regression; its separate oracle execution was never run.

**State**

- `campaign-status`: capabilities 180 `implemented-foundation`, 43
  `selected-private`; families 9 `foundation-verified`, 17 `planned`; 0 of 8
  gates. Unresolved capabilities by family: text-math-locale-stdio 16,
  c-abi-compat 11, posix-runtime 9, dynamic-runtime 4, pthread-tls 3.
- No allocator milestone (M1 to M10) has a current pass; `--check` on a
  gate validates its contract only and exits 0 today.
- The port is not source-complete.
  `python3 -B compat/allocator/source_convergence.py --summary` prints
  `implemented: unmet (173)`, `transitional: unmet (29)`,
  `intentional-differences: unmet (5)` and `known-differences: unmet (2)`.
  `crabc-mimalloc/UPSTREAM.md` lists about 24 pinned source ranges that
  `compat/allocator/port-map.toml` does not map and four differences with no
  register entry.
- Production free and realloc route by the page, and production owner exit
  goes through one traversal (`collect_abandon_owner_exit`). The per-geometry
  `abandon_*` routes, the page-owner session ledger and the parked-engine
  scheduler are reachable only from tests and audit features.

**Dead weight, for C1**

- `crabc-mimalloc/src` is about 330,000 lines, half of it tests; pinned
  mimalloc v3.5.0 is about 22,000. Its library build prints 1,032 dead-code
  warnings, and `crabc-libc` built with either native-shadow feature prints
  1,174. A third of them are in `single_thread.rs`.
- 74 harness scripts (about 14,500 lines) under `compat/` and `scripts/` are
  referenced by nothing outside tests. Check for discovery by glob before
  deleting any.
- `scripts/dev-x86_64.sh` is 12,662 lines with about 2,600 lines of help, and
  `compat/x86_64/` holds 549 Python files.

**Branches**

62 besides `main` (46 `lane/*`, 7 `parked/*`, 6 `recovery/*`, 2 `review/*`,
`integration/os82`). None is needed to resume. Measured by whether the
functions a branch adds exist on `main`, only `lane/childsourceclosure41`,
`lane/theapmetasnapshot54`, `lane/guardedsource54`, `lane/guardedruntime55`
and `lane/terminalmodel43` hold work `main` lacks.

**Reference numbers for optimization (historical, raw data deleted)**

Allocator at `e8b25e956`: suite throughput lower95 0.37 of pinned C against a
required 0.95, with code 977,406 bytes against C's 108,311. No runtime
scorecard survives.

## Sequence

Sizes: S is under half a session, M one session, L several sessions in one
lane. An item ends on its acceptance check.

### Running it fast

The sections below order what may be *claimed*, not what may be *started*. Nothing is a
wave barrier: an item starts the moment the narrowest thing it needs has
merged, and an item that needs something is split into the part that does
not and the part that does.

- **Launch everything ready at once,** in the priority order below, up to
  the width memory allows. When a lane reports, merge it and launch what it
  unblocked before doing anything slow.
- **Every lane's first act is its own discovery:** run its family's cohort
  steps, or its gates, in its own worktree on its own committed branch, and
  report the failures. No lane waits for a campaign-wide discovery run.
- **The dynamic product is the choke point.** Until G1b lands, runtime lanes
  work the static half of their family: the per-component dispatcher commands
  that take only `--static-sysroot` or the static preparation, and unit
  tests. When G1b merges, every runtime lane is told at once.
- **Keep lanes warm.** A workstream with more ready work keeps its worktree,
  its built targets, and its agent: rebase it onto `main` and send the next
  item to the same agent. Remove a worktree only when its workstream has
  nothing ready.
- **Verify merges in batches.** Lanes own disjoint files, so merge every lane
  that has reported, then run the verification once on the merged tip in the
  scratch worktree; bisect by lane only if it fails.
- **Rehearse qualification continuously** (H0), so the qualification commit
  is not the first time a gate case runs.
- **Measure in windows.** A qualifying measurement needs a quiet host. Batch
  every pending measurement into one window: tell running lanes to finish the
  command in flight and hold, measure, then release them. Diagnosis never
  needs a window: use CPU time and instruction counts.

Launch priority, most urgent first. Every lane has work ready on the first
day except R6 and R8, which start when G1b lands:

| Lane | Items, in order | Shares files with |
| --- | --- | --- |
| Corpus | G1b | — |
| Ledger tooling | T0, T5, T1 | The three single-writer files, the cohort runner |
| Runtime, one lane each | R1 to R8 | — |
| Allocator failures | G2, A1, A2 | `runtime_lifecycle.rs` |
| Allocator discovery, then module groups | A0, A3, A5 | The four large allocator files, one owner each at a time |
| Seeds | G1a | — |
| Performance tooling | T3, T2 | — |
| Reconnaissance | P0 | — |
| M10 tooling | T4 | — |
| Dead-code inventory | C0 | — |

That is 17 lanes before the allocator splits into module groups. Width is
the smaller of 24 (`.claude/settings.json`) and what memory allows.

### Ground and tooling

| ID | Size | Item | Owns | Acceptance |
| --- | --- | --- | --- | --- |
| T0 | M | Split receipt binding out of the always-on ledger check. `validate_parity_ledger.py` validates structure by default and validates each verified family's receipt only under `--require-receipts`, which the chain, the cohort runner's last step and the promotion closure pass. `campaign-status` reports receipt state without failing on it. | The three single-writer files, `compat/x86_64/campaign_report.py`, `qualification_gates.py`, `campaign_promotion_closure.py`, `qualification_candidate.py`, `native_abi_selection.py` (its ledger call stays structure-only: it runs before the Lua steps), their tests | A fixture ledger with all 16 planned functional families flipped and no `.work` evidence passes the default check and fails `--require-receipts`; `compat/x86_64/tests/test_parity_ledger.py` and `test_campaign_report.py` pass |
| T5 | M | Cohort runner. Add `--profile correctness` (skip the two performance steps, pass the profile to the chain step). Add the two publication steps the prescribed decision names. Seal each `--inputs` group when its first consuming step runs, not all at the start, so performance inputs measured after the consumer steps can join the same work directory. Make the preflight check the package corpus against its manifest instead of testing that a directory exists. | `compat/x86_64/qualification_candidate.py`, its test, `compat/x86_64/qualification-chain.md` | Its test module passes, including a run that adds the performance inputs after a `--through` prefix and resumes |
| T1 | M | Decouple promotion (owner decision 2). The promotion closure accepts the accepted-C default with its manifests, provenance and symbol ownership. `performance.release` reads the runtime scorecard and the facade report only, and its runtime constants gate at 1.00 as T2 describes (this item owns `performance_release_gate.py` whole). The allocator table moves, values unchanged, from `compat/x86_64/performance_release_gate.py:73-77` into `compat/allocator/x86_64_m9_gate.py`, which has no thresholds today. | `compat/x86_64/campaign_promotion_closure.py`, `performance_release_gate.py`, `qualification_gates.py`, the `performance.release` row of `parity.toml` and its validator pin, `qualification_candidate.py`, `compat/allocator/x86_64_m9_gate.py`, their tests, `compat/x86_64/qualification-chain.md` | Their test modules pass; `qualification-candidate --dry-run` no longer asks for `allocator_reports`; a unit test of the M9 gate rejects a report below the table and accepts one at it |
| T3 | S | Let full performance runs start. `perf-c` full and `perf-native --mode full` require `correctness_admission == available`, which today lists every active gate as incomplete whatever exists. Make it read a validated correctness-chain receipt for the current source. The admission record binds that receipt's source identity and passed correctness prefix, replays on the host (where `performance_release_gate.py evaluate` runs), and does not change when a full-profile receipt appears later. | `compat/perf/x86_64_evidence.py`, `compat/perf/run_x86_64.py`, `compat/perf/native/x86_64_runner.py`, `compat/x86_64/generate_qualification_manifest.py`, their tests | A unit test supplies a valid correctness receipt for the current source and gets `available`, and a receipt for another revision and gets refused |
| T2 | S | Runtime bounds (owner decision 3): gate at 1.00, report each row against 0.90, in the two x86 files that hold the bound besides the gate itself. `compat/perf/run.py` is the AArch64 contract and must not change. | `compat/perf/run_x86_64.py`, `compat/perf/x86_64_evidence.py`, their tests, `docs/design/performance.md`, `compat/perf/README.md` | Their test modules pass with one row at 0.95 accepted and one at 1.02 rejected; `git diff` shows `compat/perf/run.py` untouched |
| T4 | S | Make M10 provable (prescribed decision): `m10.promotion-rerun` reads a full-profile chain receipt for the current revision, and the build audit is evaluated at the switched revision instead of raising. The native-ELF audit in `scripts/build_x86_64_owned_dynamic_sysroot.py` covers the `native` backend, not only `native-shadow`. | `compat/allocator/x86_64_m10_gate.py`, its test, `scripts/build_x86_64_owned_dynamic_sysroot.py` | Unit tests drive `evaluate` with fixtures: before the switch only `m10.switch` and `m10.promotion-rerun` are unmet; after it, with a full-profile receipt, none is |
| G1a | S | Seed what the cohort needs besides the corpus: extend `scripts/lanes/prepare-worktree.sh` to seed the two source oracles, the Lua archive seed and the std/LTO vendor directories into a fresh worktree, and to write `.work/x86_64/inputs.json`. | `scripts/lanes/prepare-worktree.sh` | In a fresh worktree after `prepare-worktree.sh`, `qualification-candidate --dry-run` reports no oracle, Lua or std/LTO blocker |
| G1b | M | **Critical path.** Recover the package corpus as the prescribed decision says, and cache its archives in an ignored `compat/corpus/.cache/` that `prepare-worktree.sh` copies from. Almost every cohort step consumes the dynamic product, and it cannot be built without this. | `compat/corpus/fetch_x86.py`, `compat/corpus/manifest-x86_64.toml`, `.gitignore` | `python3 -B compat/corpus/fetch_x86.py` exits 0 with all 59 archives matching the manifest, and `./scripts/dev-x86_64.sh materialized-dynamic-sysroot --work DIR` builds the dynamic product in a fresh worktree |
| G2 | M | Turn the two prose failures into tracked tests through the existing allocator fixtures, in release and opt0 products. If one does not reproduce on current source in 3 attempts, keep the test as a passing regression and log that. | `compat/allocator/` fixtures and their test files | Each test has a one-line command in the campaign log and fails on `main`, or passes and is logged as not reproducible |
| P0 | M | Performance reconnaissance, changing no product code: development-mode `allocator-perf-engine` runs against pinned C with CPU time and instruction counts (valid under load), and a CPU profile of the worst rows. | Worktree and scratch only | A ranked list in the campaign log of where the port spends more than C, by function, with the measurement behind each |
| C0 | M | Dead-code inventory for C1, read-only: for each dead-code warning and each unreferenced harness script, establish whether anything reaches it (features, `cfg`, glob discovery, dispatcher arms). | Scratch only | A list in the campaign log of what C1 may delete, each with the search that shows nothing reaches it |

### Parity and completeness

The ledger does not change here. A runtime item is done when its cohort steps
pass on merged `main`, which the coordinator checks in the rehearsal (H0).
Each lane owns its workstream's files; where a fix needs a file another lane
owns, it reports the change and the owning lane makes it.

| ID | Size | Workstream and outcome | Owns | Needs | Acceptance |
| --- | --- | --- | --- | --- | --- |
| R1 | L | `libc.posix-runtime`: 9 capabilities, steps `posix-family` to `posix-admission` | POSIX, filesystem, process and signal modules under `libc/src/c_abi/x86_64/`; `compat/x86_64/owned_posix_*` | Static half: nothing. Dynamic half: G1b | Those steps pass |
| R2 | M | `libc.pthread-tls`: 3 capabilities, step `pthread-family` | pthread, TLS and cancellation modules; `owned_pthread_*` | As R1 | The step passes |
| R3 | L | `libc.text-math-locale-stdio`: 16 capabilities, steps `text-*` | stdio, locale, wide, iconv, regex, wordexp, calendar and math modules; their `owned_*` contracts | As R1 | All `text-*` steps and `text-family` pass |
| R4 | M | `libc.resolver`: steps `resolver-family`, `publish-resolver-network` | resolver and netdb modules; `owned_resolver_*`, `compat/resolver-network/` | As R1 | Both steps pass |
| R5 | M | `libc.c-abi-compat`: 11 capabilities, step `c-abi-compat-family` | crypt, legacy compatibility and process-global modules | As R1 | The step passes |
| R6 | L | `ldso.dynamic-runtime` (4 capabilities) and `crt.dynamic-startup`: steps `loader-*`, `crt-dynamic-startup` | `ldso/`, `crt/`, `compat/x86_64/*loader*`, `general_*` | G1b | Those steps pass |
| R7 | L | Products and ABI: steps `static-products`, `dynamic-products`, `static-sysroot`, `combined-sysroot`, then `abi-*`, plus the static-TLS oracle execution | `scripts/build_x86_64_owned_sysroot.py`, `scripts/build_x86_64_owned_dynamic_sysroot.py`, `libc/src/c_abi/x86_64/static_tls.rs`, sysroot contracts, `native_abi_*`, `header_*` | Static products: nothing. Dynamic products: G1b. Its `abi-*` half: R5 and R6 merged | Those steps pass on all four link modes |
| R8 | M | Consumers: steps `rust-std-lto`, `lua-static`, `lua-dynamic`, `lua-admission` | `unwinder/`, `compat/lto/`, `compat/rust-std/`, `compat/lua/` | G1a, G1b; R7 merged | Those steps pass |
| A0 | S | Allocator discovery, fixing nothing: run `allocator-m1` to `allocator-m7` and `source_convergence.py --summary` (without `--summary` for the full condition list), each gate in its own worktree, and record every failing condition with the module it points at. | Worktrees only | A table in the campaign log of failing conditions by gate and by `crabc-mimalloc/src` module |
| A1 | L | Fix the two failures from G2 at their origin | `crabc-mimalloc/src` | G2 | Both G2 tests pass in release; opt0 passes or is parked per the prescribed decision |
| A2 | S | Prove pointer-first realloc by behavior. Reading the code says `native_reallocate` routes by the page; no test realloc's a block owned by another live thread or a block on an abandoned page. Add both; fix the product if either refuses. | `crabc-mimalloc/src` | A1 | Two named unit tests pass; `python3 -B compat/allocator/architecture_ratchet.py --check` still exits 0 |
| A3 | L | Allocator milestones M1 to M7. `--check` only validates a gate's contract and passes today; the gate itself must run. | `crabc-mimalloc/src`, `compat/allocator/` gates and fixtures | A0; a module group starts when its files are free | `./compat/allocator/run-x86_64.sh allocator-mN` exits 0 for N in 1..7 with `overall_status: passed` in its report (`--qualification-profile full` for M5, which M9 and M10 read; `baseline` for M6 and M7) |
| A4 | M | Allocator milestone M8, which runs the loader, package corpus, std/LTO and Lua consumers under the native-shadow backend | `compat/allocator/` M8 gate and drivers, `libc` native-shadow integration modules | A3, G1b, R6 to R8 merged | `./compat/allocator/run-x86_64.sh allocator-m8` exits 0 with `overall_status: passed` |
| A5 | L | Source convergence, which M9 requires: every pinned source unit implemented, no transitional route left, every difference registered and closed | `crabc-mimalloc/src`, `compat/allocator/port-map.toml`, `compat/allocator/known-differences.md` | A0; a source unit starts when its Rust modules are free | `python3 -B compat/allocator/source_convergence.py --summary` prints `met` on all five lines |

The allocator is several lanes, not one. `runtime_lifecycle.rs`,
`single_thread.rs`, `main_heap_page.rs` and `dynamic_theap.rs` hold 144,000
lines and most cross-cutting logic: each has one owning lane at a time, and
A1 and A2 hold `runtime_lifecycle.rs` first. From A0's table the coordinator
splits A3 by module group (memory substrate; local engine and allocation;
Heap, Theap, arena and subprocess APIs; options and statistics) and A5 by
pinned source file, one lane per group whose files are free.

### Hardening

H0 starts as soon as its needs merge, alongside the parity lanes.

| ID | Size | Item | Needs | Acceptance |
| --- | --- | --- | --- | --- |
| H0 | L | Rolling rehearsal. On a throwaway branch `cohort/rehearsal`, never merged, commit the ledger exactly as H1 will and run the correctness cohort in `.work/wt/cohort-rehearsal`. Past the first failing step, run the remaining steps' commands directly, as `--dry-run` prints them. Send each failure to the lane that owns it, and repeat on the new `main` whenever routed fixes have merged. | T0, T5, G1a, G1b | A rehearsal passes end to end; its step table with wall times is in the campaign log |
| H1 | L | The qualification commit, as [Qualifying a revision](#qualifying-a-revision) describes: one commit flips the 16 families (capability state follows family state; regenerate the derived inventory with `python3 scripts/lanes/refresh-parity-digests.py`) and names a receipt on every family row that takes one (posix, pthread, text, resolver, c-abi; static TLS takes the static product publication and no `receipt` key), then the cohort runs under `--profile correctness` at that commit. This is the first time the gate cases themselves execute; a failure is fixed forward in a new commit and the cohort is rerun. | H0 passing | In the cohort worktree, `./scripts/dev-x86_64.sh qualification-manifest --validate-receipt PATH` exits 0 on a receipt whose `qualified_gates` has seven entries, and `python3 compat/x86_64/validate_parity_ledger.py --require-receipts` passes |
| H2 | S | Write up: every contract change made so far under [Contract changes](#contract-changes), docs updated for what landed, cases found on the way added as regressions | H1 | `mdtool links` and `mdtool router` report no error |

### Optimization and promotion

The runtime track (O1, O2) and the allocator track (O3, O4) are independent
and run side by side. Qualifying measurements are taken in windows, as
[Running it fast](#running-it-fast) describes; `perf-gate-ready` must exit 0
before and after each. Performance evidence is bound to the source it
measured. O3 starts from P0's ranked list and runs one lane per mechanism
whose files are disjoint, all measured in the same window.

| ID | Size | Item | Needs | Acceptance |
| --- | --- | --- | --- | --- |
| O1 | L | Runtime scorecard in the cohort worktree at the H1 commit: three `perf-c` attempts and `perf-native --mode full`. Fix any row above 1.00 or over 2R by removing work (syscalls, copies, passes), as `performance-by-mechanism` describes, without changing selected semantics; confirm each fix with a focused development-mode rerun of its rows, since a full run binds to a qualified commit. Log every row against 0.90. | H1, A1, T2, T3 | The full scorecard is in the campaign log, and every row above 1.00 has a merged fix whose focused rerun is at or below 1.00 |
| O2 | L | The promotion revision (D4). One commit sets `public_support = true` in the ledger, the generator and the manifest, marks `performance.release` verified with its receipt path, and updates `README.md`, `AGENTS.md` and `docs/scope.md`. Then, at that commit, in one work directory: the cohort `--through publish-lua-source-build`, the correctness chain, the performance measurements, then the same cohort resumed with the performance inputs under `--profile full`, and the promotion check. A failure is fixed forward and the revision is requalified. | O1, T1, T5 | In the cohort worktree, `./scripts/dev-x86_64.sh campaign-promotion-check --qualification-receipt PATH` passes |
| O3 | L | Allocator performance. First a fresh three-run engine baseline (`allocator-perf-engine --full`) and a profile. Then remove work in the order the profile gives. Each increment is one mechanism with before and after numbers vetted by `benchmark-checklist`. | A4, A5, T1 | In one checkout at one commit, `./compat/allocator/run-x86_64.sh allocator-m9 --profile baseline` exits 0 on three agreeing full reports: suite throughput lower95 at least 0.95, critical rows at least 0.90, critical p99 cost upper95 at most 1.10, peak RSS and PSS upper95 at most 1.05 geomean and 1.10 critical; `architecture_ratchet.py --gate --runtime-evidence FILE` exits 0 |
| O4 | L | The switch revision (D5): one commit sets `DEFAULT_ALLOCATOR_BACKEND = "native"` in `scripts/build_x86_64_owned_sysroot.py`; then requalify that commit as O2 did | O2, O3, T4 | `./compat/allocator/run-x86_64.sh allocator-m10 --profile baseline --check --performance-receipt PATH --qualification-receipt CHAIN` passes, and the promotion check passes at the switched revision |

### Close

| ID | Size | Item | Acceptance |
| --- | --- | --- | --- |
| C1 | L | Delete what is dead, proving liveness as `dead-code-archaeology` describes. Known candidates are listed under [Baseline](#baseline). | A library build of `crabc-mimalloc`, and of `crabc-libc` with each native-shadow feature, prints no dead-code warning; `scripts/lanes/rust-check.sh` and every host-side test directory still pass |
| C2 | M | `ultrareview` on the campaign's diff; fix its P1 and P2 findings | No open P1 or P2 |
| C3 | S | Final report at the top of this file: what merged, every contract change, measurements, parked items with findings | — |

## Acceptance

| Deliverable | Proof |
| --- | --- |
| D1 | T0 to T5, G1a and G1b acceptance checks pass; G2's tests exist |
| D2 | H1's acceptance, at the qualification commit |
| D3 | O1's scorecard, and `python3 compat/x86_64/performance_release_gate.py evaluate ...` passing at the promotion revision |
| D4 | `./scripts/dev-x86_64.sh campaign-promotion-check --qualification-receipt PATH` passes at a revision with `public_support = true` |
| D5 | O4's acceptance, at the switched revision |
| D6 | C1 and C2 acceptance; the final report is committed |

Every host-side test directory (`fd -t d '^tests$' -E .work -E target`) must
exit 0 under `python3 -B scripts/test_python.py --directory D --jobs 6` at
each merge batch, with `python3 scripts/check_structure.py`,
`python3 compat/x86_64/validate_parity_ledger.py` and
`scripts/lanes/rust-check.sh`. Physical NUMA and explicit 2-MiB and 1-GiB
page modes stay recorded as unqualified; no proof above depends on them.

## Contract changes

Pre-authorized:

- Receipt binding checked on request instead of at every commit (T0).
- Promotion no longer requires the native allocator default; allocator
  inputs leave `performance.release` and its table moves to M9 (T1).
- Runtime performance bounds gate at 1.00 (T2).
- Performance admission reads a correctness-chain receipt (T3).
- M10's `promotion-rerun` condition and build audit become evaluable (T4).
- `qualification-candidate --profile`, its two publication steps, and
  per-group input sealing (T5).
- Re-pinning the x86 package corpus to a current signed v3.24 index, roster
  and scenarios unchanged, only if the original archives cannot be recovered
  byte-exact (G1b).
- Ledger transitions in the H1 commit that its cohort then proves:
  capability to `implemented-foundation`, family to `foundation-verified`.
- `public_support = true` for x86-64 (O2), and the x86 allocator default (O4),
  each proven at its own revision.
- Deleting a host-side test or validator rule that asserts prose, source
  text, or a count.

Forbidden:

- Changing the frozen inputs, the 223-capability and 26-family inventory, or
  any AArch64 behavior, default or gate (`compat/perf/run.py` included).
- Lowering a correctness threshold, shrinking a corpus, rewriting an upstream
  workload, or reclassifying a failure as expected to pass a gate.
- Changing an upstream pin (musl 1.2.6, mimalloc v3.5.0, the Rust nightly,
  `unwinding` 0.2.10).
- Widening the public C ABI or header surface beyond the selected profile.
- An allocator algorithm that diverges from pinned mimalloc without a
  `known-differences.md` entry and the differential and performance evidence
  [docs/scope.md](docs/scope.md) requires.
- Relaxing any allocator performance bound, or any M10 condition other than
  making `promotion-rerun` and the build audit evaluable as T4 states.

Made so far, each with its commit, for the owner:

- `ee4a6b41c` (T0): ledger checks structure by default; qualification and
  promotion explicitly require current physical receipts.
- `486960326` (T5): correctness/full cohort profiles, reviewed product
  publication and input sealing when each group is first consumed.
- `7fb666ca8` (T1): accepted-C runtime promotion closure; runtime/facade
  release evidence separated from unchanged native allocator thresholds in M9.
- `d946ccdff`, `8ccb393ed` (T3/T2): current correctness-chain admission;
  runtime CPU and paired memory upper-95 release bounds at 1.00, with 0.90
  retained as a reporting target. Memory uses the three retained attempts.
- `78c303340` (G1b): 59 archives re-pinned to one authenticated v3.24 index
  after the original bytes could not be recovered from the canonical source
  or two mirrors; package and scenario rosters unchanged.
- `db004cc5e` (M2): bitmap evidence checks the complete producer-listed
  roster and each exact outcome instead of a stale expected test count.
- `d7ec2008f` (T4): M10 accepts `--qualification-receipt` and requires a
  passing full-profile chain bound to the current revision for its rerun
  condition; native and native-shadow both receive the ELF ownership audit.
- `e01831558`, `88adf84c1` (A5): the hidden native adapter exposes the source
  threadpool setter; an attached TLD's threadpool bit is mutable policy,
  rather than part of its owner identity. Existing Theap retention stays
  frozen and subsequent Theaps apply the source quarter-retention policy.
  The unsafe observer states concrete pointer and exclusion obligations.
- `78efb9cd5`, `fc736a86b`: wordexp offers a diagnostic single-cell replay
  with full input validation and physical checks before and after hashing;
  it cannot publish a qualification receipt.
- `19465aa4a`, `68cfffc06`: resolver diagnostic replay accepts the exact
  private or retained fixture modes and validates all retained inputs before
  comparing one selected transcript; canonical qualification stays complete.
- `8c7abf176`, `366bfc8f5`: milestone readers reject selected native targets
  that execute no passing tests. M6 checks abandoned singleton counts return
  to baseline for arena and OS backing. Invalid aligned-realloc input is an
  isolated precondition control: pinned debug C asserts; native Rust returns
  NULL and reports EINVAL through the registered handler.

- `de3a8e968`: the core image identity in `compat/x86_64/core_image.py` is
  the image rebuilt on 2026-10-13 from the unchanged recipe.
- `e8d4deedb`: unsafe output-handler registration documents the existing
  source startup obligation: automatic startup, including delayed-output
  post-initialization, must finish before registering a public handler.
  The NUMA startup witness observes READY and a live TLD before delivery.

## Non-goals

- AArch64 work of any kind, and any new architecture or portability layer.
- LLVM/Clang integration and the macOS backend.
- Physical NUMA and explicit huge-page qualification on this host.
- New receipt schemas, validators, per-artifact proofs, or status documents.
- Tuning before its parity items are done, and beating musl by 10% as a gate.
- Rewriting the allocator port for size or idiom. Optimization removes measured
  work; a structural rewrite is an owner decision, not a lane's.
- Pushing, releasing, or publishing anything.

## Reference

Product scope is in [docs/scope.md](docs/scope.md), selected behavior in
[COMPATIBILITY-PROFILE.md](COMPATIBILITY-PROFILE.md), the lane workflow in
[docs/lanes.md](docs/lanes.md), the gate chain and cohort runner in
[compat/x86_64/qualification-chain.md](compat/x86_64/qualification-chain.md),
and the harness commands in [compat/x86_64/README.md](compat/x86_64/README.md)
and [compat/allocator/README.md](compat/allocator/README.md).

### Fixed contracts

| Boundary | Required contract |
| --- | --- |
| Active target | Native Linux/x86-64 little-endian, Linux >= 5.10; `x86_64-unknown-linux-musl` where a Rust target name is needed. No AArch64 execution or emulation. |
| Compatibility | Pinned musl 1.2.6, Linux ELF and System V AMD64 ABI, and `COMPATIBILITY-PROFILE.md`. Rustix remains test-only; no glibc or ambient target-runtime fallback. |
| Frozen runtime | AArch64 commit `3e100d45c5a0798c2d3862d5e2eef584c610ccf9`: exactly 223 capabilities and 26 required families. `compat/x86_64/aarch64_frozen_baseline.json` owns the three immutable ledger, ABI and header digests. Validate them, never refresh them to absorb drift. |
| Runtime accounting | `compat/x86_64/parity.toml` owns exact capability mappings, family dependencies, and promotion. Every capability and required family occurs exactly once. Export ratchets are not inventories, schedules, or semantic proof. |
| Allocator source | mimalloc v3.5.0, commit `18b08671c9302247bfb682286e6bf3cc1773f801`; archive hash, license, and source provenance in `crabc-mimalloc/UPSTREAM.md`. No silent upgrade or allocator redesign. |
| Allocator accounting | `compat/allocator/port-map.toml`, the applicability inventories, milestone manifests, and `known-differences.md`. Source-unit implementation, bounded evidence, integration, and target qualification are distinct. |
| Accepted C backend | `libmimalloc-sys` 0.1.49 bundles mimalloc v3.3.2. It is the selected default and is not the v3.5.0 oracle. Keep candidate, accepted-C comparison, and pinned-v3.5.0 differential inputs separate. |
| Unwinder | `unwinding = { version = "=0.2.10", default-features = false, features = ["unwinder", "fde-phdr-dl", "dwarf-expr"] }`, source commit `0e2de8fb536b1ca42066024609f58d708cf80e69`, with `gimli 0.34.0` (`read-core`) and `libc 0.2.186` as the reviewed graph. Design in [docs/design/unwinder.md](docs/design/unwinder.md). |

Default behavior matches pinned musl's defaults:

- **Loader validation.** At load time the loader rejects what musl rejects.
  Up-front checks musl does not perform are not required and must not keep a
  startup or `dlopen` row open.
- **`dlclose`.** A successful `dlclose` validates a handle but does not unmap
  the object or run its destructors. Reopen observes retained state; DSO
  destructors run at process exit. Failed load transactions still release
  their mappings.
- **Transparent huge pages.** The runtime leaves the process THP policy as
  musl does. The native allocator's own arena reservations opt out with
  `MADV_NOHUGEPAGE`, a recorded divergence from mimalloc v3.5.0 with a
  `known-differences.md` entry and a pinned-C differential.

### Completion requirements

What "complete" means for each runtime family and for the allocator port is in
[docs/completion-requirements.md](docs/completion-requirements.md). Parity
items are judged against it, not against the cohort steps alone.

## Decision log

Append one line per judgment call a reader would otherwise miss.

- 2026-10-13: plan restructured for unattended execution; the earlier
  progress narrative is in Git history at `6e54203fb`.
- 2026-10-13: an independent cold read found that the first restructure
  could not be executed (single-commit receipt binding, an M10 condition that
  could never be met, performance admission that could never open, wrong
  files named for the runtime bounds). The sequence was rebuilt around
  tooling items and a cohort worktree at a fixed commit. A second cold read
  then found acceptance checks that passed vacuously, two manual publication
  steps nothing performed, and unowned source-convergence work; those are
  fixed in T5, A3 to A5 and the prescribed decisions.
- 2026-10-13: M7's opaque metadata-layout exclusions do not waive numeric
  statistics parity. Preserve the child-control and positive-arena retry
  storage's raw physical metadata charges and failing comparisons. The
  empty-child correction avoids unnecessary storage; it does not establish
  parity for populated children or authorize substituting C-sized charges.

## Campaign log

Append one line per merge batch, per parked item, and per contract change.

- 2026-10-13: pre-resume sweep done outside the sequence. Core image
  rebuilt and pinned; 1,778 integrated lane branches deleted; every
  host-side test directory, the structure check and the architecture check
  made green; the allocator's one-test route built unoptimized; comments and
  documentation cleaned of planning labels, run records and unverified
  quantities.

- 2026-10-13: unattended campaign started at `e4be1288e`; baseline
  campaign-status confirms 0 of 8 gates, 180 of 223 capabilities and 9 of
  26 families. Fifteen ready lanes launched in priority order, each in its
  own `.work/wt/` worktree. Native cold allocator builds reserve 8 GiB each;
  initial available memory was 45 GiB, with a 12-GiB minimum margin.

- 2026-10-13: first integration batch: `d7ec2008f` (T4, full-profile
  current-revision M10 rerun receipt and native ELF audit), `03527a113`
  (pthread dispatcher image initialization and installed-product arguments),
  `09acf288b` (R7 static-TLS scratch confinement), `c03d7857e` (G1a source,
  Lua and Rust vendor seeding), `072bcfb89` (stale resolver-fixture assertion).
  Static-TLS oracle, installed pthread lifecycle and primary POSIX components
  pass in their lanes; merged batch verification is running in a detached
  checkout. No qualification or promotion claim has changed.

- 2026-10-13: second integration batch through `d62e9d910`: T0, T1,
  T2, T3 and T5, complete corpus inputs, Lua seed confinement, pthread
  dispatcher argument preservation, source-faithful child Heap teardown,
  process-global statistics observation, stale R7 driver/fenv expectations,
  allocator public-Theap and pointer-first realloc regressions, bitmap
  roster validation, exact startup-recursion filters, and source-map
  reconciliation. Focused lane checks pass. Merged-tree structural checks
  and all nine Rust profiles pass; every host-side test directory is running
  in the frozen verification worktree. No qualification claim changed.
- 2026-10-13: H0 started at throwaway `21e9a89cf` in
  `.work/wt/cohort-rehearsal`: 25 functional families declared, five
  family receipts named, derived inventory regenerated. Fresh preparation
  authenticates all 59 APKs; correctness dry-run has no preflight blocker.
  This branch is never merged and is not a qualification of main.
- 2026-10-13: G2 release public-Theap fixture passes all 112 C/Rust keys:
  `./compat/allocator/run-x86_64.sh allocator-public-theap`.
  Its `--debug` 16-KiB worker attaches, then SIGSEGVs allocating 64 bytes;
  three real hypotheses localized opt0 stack exhaustion. Opt0 parked on
  `lane/allocator-failures`; its later child/fork legs remain untested.
  The release child and fork regressions pass; no release failure reproduced.
- 2026-10-13: R6 direct-staticlib private source-root fixtures parked after
  three linker hypotheses: prebuilt core retains `rust_eh_personality`.
  Cargo target-root graph/TLS equivalents and relocation/CRT/lifecycle
  checks pass. Evidence and exact commands are in
  `docs/evidence/native-static-source-runtime-closure.md`; parked branch
  `lane/r6-loader`. Installed-product family acceptance remains independent.
- 2026-10-13: A0 discovery: M1 found child Heap teardown/statistics defects
  now fixed; M2 found stale bitmap count and three zero-test startup filters
  now fixed. M3 trace pairs match 458,179 ordered observations, M4 valid
  operation/page/alignment clients match, Heap/subprocess lifecycle matches,
  and M7 options matches 660 keys. These are lane discovery, not current
  full milestone passes. Source convergence still reports 180 unmet rows,
  29 transitional, five intentional-difference and two register conditions.
  Complete source-unit audits continue across all four allocator groups.
- 2026-10-13: long discovery aggregates have narrow iteration routes:
  exact `allocator-unit --filter NAME`, individual M2/M7 producers, and
  M3 `--queue-reorder-only`. Do not repeat cold aggregates to iterate on
  a named assertion. M7's first statistics discovery remains running;
  host memory stays above the 12-GiB reserve. Performance reconnaissance
  under load remains diagnostic and has made no product changes.
- 2026-10-13: third integration batch through `0e44d7ccf`: aggregate-memory
  release consumers, allocator source-map corrections, M6 matrix dispatch,
  wordexp single-cell diagnostic and post-hash physical checks, source
  threadpool policy and its 113-key release comparison, and three host-test
  fixture races. The preceding frozen batch passed all nine Rust profiles,
  ledger/structure/inventory checks and host directories except those three
  races; the corrected frozen tip is being verified. `567d5e675` adds the
  exact threadpool and selected page-map boundary mappings; source
  convergence now has 164 unmet rows and 24 transitional rows.
- 2026-10-13: P0 produced six alternating diagnostic C/R pairs on one commit
  and image. Largest median CPU ratios: batch 4096x256 3.47, remote-free four
  workers 3.19, batch 64x1024 3.09. Host load overlaps these measurements;
  they qualify nothing. Sampled profiling is parked: the pinned image lacks
  `perf`, and changing the image or host permissions is forbidden. The image
  also lacks the requested `kache` wrapper; no image was rebuilt.
- 2026-10-13: C0 found 19 unused-function leads, 1,021 allocator warnings
  and 125 libc warnings in each native-shadow profile. Of 38 scripts without
  production textual references, seven have test callers and 31 remain
  unproven standalone tools. C1 is deleting only individually proven leaves;
  no script or oracle fixture has been deleted. C2 found a child-destroy
  regression expecting scratch after its successful early release; its
  exact test and fault boundary are being corrected.
- 2026-10-13: M5 selected discovery passes pointer dispatch, generic exit,
  abandon/reclaim/release and the architecture check. Remote publication's
  two Cargo-cache misses pass after seeding the actual producer cache; its
  failed aggregate is retained. State auditing fails in a shared test
  process even serially, while the second test alone passes; its owner is
  isolating leftover state. Churn passes its native test but lacks the
  canonical stress receipt, whose producer is now routed.
- 2026-10-13: M6 adapter matrix at fixed `0e44d7ccf` fails collection page
  counts, the C debug trace and four native Heap contract checks. Raw output
  is retained and narrow root-cause checks are routed. An earlier matrix
  was stopped after the coordinator moved its checkout; it is invalid and
  cannot count as evidence. M7's 34 differential entries pass in discovery,
  but required metadata, arena-commit and bin/owner coverage remains open.
- 2026-10-13: integration through `be460576b` passes all 23 host-side test
  directories, ledger/structure/inventory checks and all nine Rust profiles
  in its frozen verification checkout. C1 deletes eight proven unused Rust
  leaf groups; unproven standalone scripts remain. C2's child-destroy test
  now asserts terminal scratch release and Gone after refused orphan finish.
  M5 Heap-birth checks share the initial process-owner thread, retaining all
  observations; their native target passes and readers reject zero tests.
  Canonical M5 stress at `d62e9d910` passes 100 stress and 13 soak/growth rows;
  this is not a full current-revision M5 pass.
- 2026-10-13: actual M1 at `8c7abf176` stops in its M0 Rust layout
  prerequisite before producing an M1 report. The aggregate output was
  truncated and its first failing test is unknown. The visible failed unmap
  lifecycle test passes alone, its six-test module passes serially, and its
  paired fault-injection control passes concurrently. Three hypotheses did
  not reproduce the failure; prerequisite parked on `lane/allocator-discovery`.
- 2026-10-13: actual M2 at frozen `0e44d7ccf` executes 109 rows with no failed
  or zero-pass check, then exits 3 with four partial components: VM primitives,
  arenas, initialization and fault injection. The legacy processless OS-page
  difference stays explicit. Remaining direct proofs include huge-reservation
  progress, cross-owner arena reclaim/purge, installed startup composition,
  and Unix policy-file failure/descriptor closure. Independent witnesses are
  routed; no whole-unit or milestone pass is claimed.
- 2026-10-13: M6 collection mismatch traced to an abandoned singleton Heap
  counter missing its terminal decrement. `47d186d3b` fixes arena and OS
  release edges; `366bfc8f5` adds their public C/R witnesses and corrects the
  stale native contract selector and invalid debug-input trace. Release
  matches all 143 keys; the debug assertion control and nine Rust profiles
  pass. A fresh official four-profile adapter matrix and merged-tree checks
  run in frozen `4ca0812a2`. The default-child OOM callback differential is
  independently red and its existing phase-driver fix is in progress.
- 2026-10-13: H0 finishes all three dynamic product case rosters and its
  inner receipt collector passes. Outer validation replays the same retained
  evidence before recording the step. The largest wordexp integrity check
  has a 32-second narrow route; its snapshot spends substantial CPU forming
  relative paths. Tooling owns a snapshot-equivalence cleanup, preserving
  every file, mode, symlink, device and content check. No validation is skipped.
- 2026-10-13: integration through `2811b1890` passes all 23 host test
  directories, ledger/structure/inventory, nine Rust profiles and the TLS
  code-generation probe profile. Native checks match 128 M2 VM fields and
  184,350 arena lifecycle fields; the empty-child failure-storage regression
  passes. `e53406289` restores forced default-child OOM callback timing;
  its public C/R trace matches all 18 keys. `2811b1890` bypasses fixed arena
  retry storage for genuinely empty children, retaining existing populated
  child failure custody. `1efe2ff22` preserves byte-identical snapshots of
  all 135,380 retained wordexp entries. Four C1 commits scope proven test-only
  helpers; other source algorithms and unproven scripts remain.
- 2026-10-13: `ee35efcba` and `2d08c815e` record bounded M2 and child-callback
  proofs without closing aggregate source units. Source convergence has
  156 unmet implementation rows, 24 transitional rows, five intentional
  differences and two register conditions before the latest two bounded
  mappings. M3's initial finite Miri matrices and M5's full-profile lifecycle
  models remain active; no fresh full milestone pass is claimed.
- 2026-10-13: the official M6 matrix at `4ca0812a2` matches all 143 keys in
  release and both statistics profiles; all four native Heap contract checks
  pass. Debug fails on the pinned source's valid offset-pointer rejection
  and OS-address diagnostics. Its scoped source option correction and
  original-option negative control pass against the corrected retained
  native archive; the earlier replay against an older archive is withdrawn.
  Integration waits for a retained-log replay correction, then reruns the
  complete official matrix on a frozen merged revision.
- 2026-10-13: H0 publishes the three dynamic products after all independent
  receipt replays pass, then passes POSIX-family, crypt-profile, atomic-profile,
  wordexp-profile and wordexp-inputs. POSIX-native differential passes and
  its native os-test continues. The throwaway `21e9a89cf` branch still changes
  no claims on main and is not a main qualification.

- 2026-10-13: integration through `7a26c4526` passes all 23 host-side test
  directories, ledger/structure/inventory checks and all nine Rust profiles.
  Its official M6 adapter matrix passes all four profiles with 145 keys;
  retained replay passes the physical receipt, original-option negative
  controls and invalid-precondition controls. Debug comparison checks the
  source option proof and masks only independently validated OS-address
  operands; raw diagnostics remain retained. This is adapter evidence, not
  a full milestone or main qualification.
- 2026-10-13: `0efa7ebd8` restores option-aware NUMA cold-cache verbose
  output after cache publication and before the current-node primitive;
  `e8d4deedb` proves early output stays buffered until post-initialization,
  then children reuse the process cache after option mutation. In frozen
  `e8d4deedb`, the 141-field C/R VM comparison, exact startup regression and
  all nine Rust profiles pass. Physical NUMA remains unqualified.
- 2026-10-13: actual M3 at `8c7abf176` passes all four Miri profiles and
  its 458,179-observation C/R traces, but exits unmet: prerequisites and five
  native refused-unmap assertions fail. Source page free consumes its
  capability after a refused unmap, warns and leaves the range mapped; the
  old owner tests incorrectly require retained retry custody. Their owner
  is correcting the tests while preserving real child-arena failure custody.
- 2026-10-13: actual M4 at `8c7abf176` retains one stat-2 operation mismatch:
  aligned allocation 846 reports historical address reuse 845 only in the
  original Rust run. Size, alignment, slice geometry and client contract
  match. Three gates consume that same failed differential. Exact-environment
  retained-binary controls do not reproduce it; source release/re-map analysis
  continues. Raw failure is preserved and no gate is reclassified.
- 2026-10-13: actual full M5 at `be460576b` passes lifecycle models,
  functional differential groups and canonical shadow/stress/soak receipts,
  but remains unmet. Its three native groups misread nested child summaries,
  and two secure targets run zero tests without their feature profiles.
  The runner correction checks each target/profile's final parent summary;
  cancellation ownership defects found in review are being fixed before merge.
  Code-generation/performance proof is still missing.
- 2026-10-13: M7 positive-child metadata statistics remain numerically
  different after destruction; live-child and owner-count observations match.
  This is retained diagnostic output without a qualification seal, not an
  accepted numeric waiver. Its fresh-arena witness is committed unverified
  on `lane/allocator-options` after an image-inspection failure. `71de81358`
  preserves Docker's actual inspection error; there is no observed harness
  denial and the parked witness has not been retried.
- 2026-10-13: `perf-gate-ready` exits 75 after its three load checks:
  perf gate deferred: host busy. No qualifying timing was collected; no
  performance-dependent promotion is claimed.

## For the owner afterwards

- The contract changes list, and the commits it names.
- Parked items and their findings in the campaign log.
- The 0.90 column of the runtime scorecard, to decide whether it becomes a
  gate.
- Allocator code size and source size against pinned C, to decide whether a
  structural consolidation of the port is worth a campaign of its own.
- The 62 remaining branches, to delete or mine.
