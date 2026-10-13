# Qualify and promote crabc's native x86-64 runtime

**Status: paused 2026-10-13, ready to resume at G1.** No lane, worktree, or
process is running. Nothing has been qualified: 0 of 8 gates, 9 of 26
families, and every earlier receipt was deleted with `.work/` on 2026-10-07.

- **Resume:** "Read `plan.md` and `docs/lanes.md`, then run the campaign in
  `plan.md` from item G1 as coordinator, unattended." First command:
  `./scripts/dev-x86_64.sh image`.
- **State:** branch `main`. The loop runs only with
  `CRABC_X86_64_CORE_IMAGE=crabc-core-evidence:x86_64` until G1 lands. Known
  red is listed under [Baseline](#baseline).
- **Open branches:** 1,778 `lane/*` and `lane-*` branches are empty or fully
  on `main` by patch-id and are deleted by G2. 62 others stay: 46 `lane/*`
  holding 504 commits not on `main`, 7 `parked/*`, 6 `recovery/*`,
  2 `review/*`, and `integration/os82`.

## Goal

Make native Linux/x86-64 a publicly supported crabc target, then make the
Rust port of mimalloc v3.5.0 its default allocator. Correctness comes first:
every selected capability works through its intended runtime path and one
current-source cohort passes the correctness qualification chain before any
performance work.

Deliverables:

1. **D1 Ground.** The pinned loop runs from a clean checkout, the host-side
   suites are green, and both known allocator failures are tracked tests.
2. **D2 Runtime parity.** All 223 capabilities are `implemented-foundation`
   and all 25 functional families are `foundation-verified` on `main`.
3. **D3 Correctness qualification.** Gates 1 to 7 pass on one clean cohort.
4. **D4 Runtime performance.** A fresh scorecard exists and the runtime is no
   worse than pinned musl on every row.
5. **D5 Public x86 support,** on the accepted C allocator.
6. **D6 Native allocator default.** The Rust port passes its correctness
   milestones and its performance table, becomes the x86 default, and the
   chain passes again on that revision.
7. **D7 Close.** Dead code removed, review findings fixed, final report.

## Charter

- Decide, log the call in the [decision log](#decision-log), and keep going.
  Never ask, never wait for approval, send no check-in. Run until every
  deliverable is met or every remaining item is parked.
- **Parity before optimization.** No item in phase 3 starts while an item in
  phases 0 to 2 is neither done nor parked. Until phase 3, performance is
  measured and logged, never gating.
- **Hard stops, each of which parks the item:** an action outside the
  repository or one that cannot be undone from Git (pushing, renting
  resources, rebooting, changing host huge-page pools or security policy);
  running or emulating AArch64; a boundary this document forbids; a harness
  denial of a tool call (do not retry it or route around it); a loop that can
  no longer check anything.
- **Fix on the way, in its own commit:** a loop command over 5 minutes (get
  it under 90 seconds or give the item a narrower check); a test that is red
  on `main` and blocks the item; a throughput or CPU regression worse than
  2x against the last recorded number. Record anything else seen and leave it.
- **Time-box.** A failing item gets 3 attempts, each a hypothesis with a
  predicted observation as `root-cause` describes. Then park it with the
  finding and take the next item that does not depend on it.
- **Bookkeeping stays minimal.** No new receipt schema, validator, runner, or
  status prose per artifact. Reuse `qualification-candidate` and the existing
  family matrices. A failing validator that only restates prose is deleted,
  not fed.
- **Run as wide as ownership and memory allow,** as `orchestrate` and
  [docs/lanes.md](docs/lanes.md) set out: one lane per workstream with ready
  work, the largest slice a lane can finish. Budget 8 GiB per lane that builds
  `crabc-mimalloc` tests; measure the others on first launch and keep 12 GiB
  available.
- Worktrees live at `.work/wt/<lane>` on branch `lane/<id>`; all scratch stays
  under `.work/`, never `/tmp`. The coordinator removes a lane's worktree and
  branch once it is merged and verified. A parked lane keeps its branch and
  is named in the [campaign log](#campaign-log).
- Every commit is a Conventional Commit with the workstream as scope. The
  item ID goes in the body. Code comments never cite this document.
- The coordinator integrates, verifies on the merged tree, and edits this
  file. Lanes do not.

## Decisions

### Owner-decided (2026-10-13)

1. **Parity first.** The two known allocator failures and the correctness
   chain come before performance work. This replaces the 2026-10-03 direction
   to defer known blockers to the end.
2. **Public x86 support is decoupled from the native allocator.** x86 is
   promoted on the accepted C allocator once D3 and D4 hold. The native
   allocator becomes the default later, through its own gate (D6).
3. **Runtime performance gates on no regression.** Promotion requires the
   one-sided 95% upper bound of candidate over musl to be at most 1.00 for
   CPU and for PSS and `memory.peak` on every row, and syscalls at most 2R.
   The 0.90 figure is reported per row as a target and gates nothing.
4. **Branch cleanup.** Delete every `lane/*` and `lane-*` branch that
   `git cherry main` shows as empty or fully integrated. Keep and list the
   rest, and keep `parked/*`, `recovery/*`, `review/*`, `integration/*`.
5. **Only x86-64 is in scope.** AArch64 is preserved and never run or
   emulated on this host.

Earlier owner decisions that still hold: default behavior matches pinned
musl's defaults (2026-09-25, see [Reference](#fixed-contracts)); ordinary
baseline promotion may proceed with physical NUMA and explicit 2-MiB and
1-GiB page modes unqualified (2026-10-02); floor-limited total-memory rows use
a no-regression check (2026-10-02); qualification bookkeeping is to be reduced
(2026-10-02).

### Prescribed

| Decision | Reason | Reverse if |
| --- | --- | --- |
| Lanes are `orchestrate` tiers, default `worker`; no repository agent types and no fixed model or lane count. | The harness refuses other agent types, and width is set by memory and disjoint files. | The owner wants a fixed model for all lanes. |
| Work runs under `--profile correctness` until D3; the full profile is used only from O1. | The profile already exists and drops exactly `performance.release`. | Never; D5 and D6 still require the full profile. |
| The 16-KiB worker-stack and public-Theap child failures must pass in the release product. The opt0 debug product is required too, but may be parked after the time-box if release passes. | Release is what ships; the failures were only ever recorded at opt0. | The owner wants opt0 parity to block promotion. |
| A denied debugging action is a hard stop for that item, not something to rephrase. | The earlier "crash investigation workflows rejected by safety review" was never written down, so the only safe rule is the general one. | The owner says exactly what was rejected. |
| Privileged containers are allowed only as the tracked launchers start them (`SYS_CHROOT` probes, the `perf-c` collector's `SYS_ADMIN`, `SYS_PTRACE`, unconfined seccomp). No ad hoc privileged `docker run`. | They are part of the checked-in contract; anything else is an unreviewed host action. | — |
| Allocator code size is logged, not gated. | No gate bounds it today (`compat/allocator/perf_engine_x86_64.py:1129`), and adding one is new bookkeeping. | The owner sets a bound. |
| The 46 `lane/*` branches with commits not on `main` are classified, never merged wholesale and never deleted. | Nobody has compared them with current `main`; the owner asked to keep and list them. | — |
| A host-side test that asserts source text or doc prose is deleted when it goes red, and named in the decision log. | [docs/scope.md](docs/scope.md) forbids source-literal tests. | — |
| Package corpus: first try to recover the 9 missing APKs byte-exact with `compat/corpus/fetch_x86.py --mirror-base-url` (2 mirrors at most). Failing that, re-pin all 59 archives to one current signed v3.24 index, with the package roster and every scenario unchanged. | The pinned bytes are gone upstream; the corpus tests loader behavior on real packages, not those exact revisions. The pinned SHA-256 check still decides what is accepted. | The owner holds a copy of the original archives. |
| Pinned upstream inputs that a `.work/` reset would lose are cached in an ignored `.cache/` directory beside their harness, as `compat/allocator/.cache/` and `compat/lua/.cache/` already are. | The 2026-10-07 reset is what lost the corpus. | — |

### Delegated

The executor decides, inside the bound, with the smallest reversible
assumption, and logs it:

- **Design inside a lane's files.** Structure, test shape, and names.
- **Dependencies.** A focused pure-Rust crate may be added when
  [docs/scope.md](docs/scope.md) allows it. The repository has no build-time
  or binary-size gate, so state both deltas in the commit body. Nothing may
  be added to `crabc-mimalloc` outside its fixed dependency direction.
- **Splitting or merging items** when the discovery run (G7) shows a family's
  failures cluster differently than the workstreams below assume.
- **Parking D6.** Park O3 when three consecutive measured increments each
  move suite throughput lower95 by less than 0.02. The campaign then closes
  with D1 to D5.

## Baseline

Measured 2026-10-13 at `6e54203fb` on this host (32 CPUs, 60 GiB).

**Loop timings**

| Command | Time |
| --- | --- |
| `./scripts/dev-x86_64.sh image`, `./compat/allocator/run-x86_64.sh image` | 2.5 min each, network |
| `scripts/lanes/rust-check.sh cargo fetch --locked` | 12 s |
| `scripts/lanes/rust-check.sh` (nine `cargo check` profiles) | 98 s cold, 10 s warm |
| `scripts/lanes/rust-check.sh cargo check -q --locked -p crabc-core` | 2 s |
| `./compat/allocator/run-x86_64.sh allocator-unit --filter <one test>` | 299 s cold, 3 s unchanged |
| The same test built at `opt-level = 0` through `rust-check.sh` | 52 s cold |
| `python3 -B scripts/test_python.py --directory compat/x86_64/tests --jobs 6` | 147 s |
| `python3 -B scripts/test_python.py --directory compat/allocator/tests --jobs 6` | 302 s |
| `scripts/lanes/prepare-worktree.sh` in a fresh worktree | 66 s, network |
| `./scripts/dev-x86_64.sh owned-posix-static-products DIR` (cohort step 1) on clean `HEAD` | 58 s, passes |
| `python3 -B compat/allocator/architecture_ratchet.py --check` | 28 s |
| `validate_parity_ledger.py`, `aarch64_parity_inventory.py`, `campaign-status` | 1 to 2 s |

**Known red on `main`**

- The pinned core image ID in `compat/x86_64/core_image.py` matches no local
  image; a rebuild produces a different ID. Stale image IDs are also
  hard-coded in `compat/perf/native/x86_64_runner.py:71`,
  `compat/perf/native/x86_64_profile.toml:7`,
  `compat/x86_64/locale_alias_contract_receipt.py:39`, and several
  `*image-inputs*.json` files.
- `compat/x86_64/tests`: 31 of 318 modules fail (3,154 tests run). Among
  them `test_parity_ledger`, `test_runner`, `test_campaign_report`,
  `test_campaign_runner`, `test_qualification_manifest`,
  `test_qualification_prefix`, `test_qualification_profile_dispatch`,
  `test_native_abi_selection` (four tests expect the default profile to be
  `correctness`; the data says `full`), and the two alias contract readers
  (stale image pins).
- `compat/allocator/tests`: 12 of 133 modules fail (1,828 tests, 302 s),
  among them `test_runner`, `test_x86_64_runner`, `test_x86_64_m9_gate`,
  `test_perf_engine_x86_64`, `test_x86_64_huge_numa_qualification` (asserts a
  source line that no longer exists), and `test_architecture_ratchet`, which
  hits the runner's 300 s module timeout.
- Nine more modules fail elsewhere: `builtins/tests/test_link.py`,
  `compat/crabc-rs/tests/test_dev_dispatch.py`,
  `compat/perf/tests/test_run_x86_64.py`,
  `compat/perf/tests/test_x86_64_peers.py`,
  `compat/rustix/tests/test_harness.py`, `crt/tests/test_build.py`,
  `crt/tests/test_static_pie_link.py`,
  `scripts/tests/test_build_owned_sysroot.py`,
  `scripts/tests/test_x86_64_owned_dynamic_sysroot_entry.py`. The rustix
  module also reads a stale ignored report,
  `compat/reports/symbols/crabc-aarch64.dynamic.tsv`, when one is present.
- `python3 scripts/check_structure.py` fails: it requires `crabc-mimalloc`
  dependencies to be exactly `chacha20`, `crabc-core`, `loom`, `zeroize`, and
  `crabc-mimalloc/Cargo.toml` also has `rand_xoshiro`.
- `qualification-candidate --dry-run` reports ten preflight blockers: image
  identity, the two unseeded source oracles, the package-corpus input, and the
  Lua, std/LTO and performance inputs.
- **The pinned package corpus can no longer be fetched.** 9 of the 59 APKs in
  `compat/corpus/manifest-x86_64.toml` return 404 from the Alpine v3.24
  repository (the `python3`, `libcrypto3`, `libssl3`, `libexpat`,
  `nghttp2-libs`, `ca-certificates-bundle` revisions have been superseded),
  and the local copies went with `.work/`. `dynamic-products` and gate 4
  consume this input.
- `python3 -B compat/allocator/architecture_ratchet.py --check` fails:
  structural violation "native_reallocate caller-current nonlocal refusal",
  and a ratchet regression in the page-local remote-free projection. The
  check is syntactic and finds none of its own source anchors, so either
  realloc does not dispatch pointer-first (requirement 2 under
  [Native allocator completion requirements](#native-allocator-completion-requirements))
  or the checker is stale. `crabc-mimalloc/src` also holds 77
  `abandon_full_*` and `abandon_mapped_*` functions, one per fixture
  geometry, beside the generic `theap_collect_abandon_queues`
  (`crabc-mimalloc/src/page_queue.rs:575`); whether production still reaches
  them is not established (requirement 4).
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
- No allocator milestone (M1 to M10) has a current pass.
- `crabc-mimalloc/src` is about 330,000 lines, half of it tests; pinned
  mimalloc v3.5.0 is about 22,000 lines. An opt0 test build prints about
  5,000 lines of dead-code warnings.

**Reference numbers for phase 3 (historical, raw data deleted)**

- Allocator at `e8b25e956`: suite throughput lower95 0.369 to 0.371 of pinned
  C against a required 0.95; nine critical throughput rows and eight tail rows
  failed; code 977,406 bytes against C's 108,311.
- A later change improved 256-KiB allocation throughput 4.8x in development
  samples; no full run followed it.
- No runtime scorecard survives.

## Sequence

Sizes: S is under half a session, M one session, L several sessions in one
lane. An item ends on its acceptance check. A phase ends on the checks of the
areas it touched.

### Phase 0: ground

Coordinator work, in order unless marked parallel. Widest: 3 lanes (G3, G4,
G6 are parallel once G1 lands).

| ID | Size | Item | Owns | Acceptance |
| --- | --- | --- | --- | --- |
| G1 | S | Rebuild both images. Set `CORE_IMAGE_ID` to the rebuilt ID and make every other reader take the identity from `core_image.py` instead of a second literal. | `compat/x86_64/core_image.py`, the files with stale IDs | `scripts/lanes/rust-check.sh` exits 0 with no override; no 64-hex image ID remains outside `core_image.py` and synthetic test fixtures |
| G2 | S | Delete the 1,778 `lane/*` and `lane-*` branches for which `git cherry main B` prints no `+` line. Delete nothing else. For the 46 `lane/*` branches that remain, record in the campaign log whether each is superseded by `main`, or names commits a phase 1 item should port. | Git refs only | Every remaining `lane/*` branch has a `+` line in `git cherry main B` and a line in the campaign log; `parked/*`, `recovery/*`, `review/*` and `integration/*` are untouched |
| G3 | S | Make the allocator's one-test route fast: `allocator-unit --filter` builds at `opt-level = 0`. | `compat/allocator/run_unit_x86_64.py`, `compat/allocator/run-x86_64.sh` | Editing one line in `crabc-mimalloc/src` and rerunning one test takes under 90 s |
| G4 | M | Make the host-side suites green and the allocator suite fast. Stale pins follow G1. A stale expectation is corrected to the decided contract. A test of prose or source text is deleted and logged. Fix `check_structure.py` to the real dependency set. Get `compat/allocator/tests` under 3 minutes (one module runs into the 300 s timeout). | Every `tests/` directory holding `test_*.py`, `scripts/check_structure.py` | `python3 -B scripts/test_python.py --directory D --jobs 6` exits 0 for each such directory `D` (`fd -t d '^tests$' -E .work -E target` lists them), and `python3 scripts/check_structure.py` exits 0 |
| G5 | M | Clear the cohort runner's preflight: seed the two source oracles, prepare the Lua archive seed and the std/LTO vendor directories, and add `--profile correctness` to `qualification-candidate` so it skips the two performance steps and passes the profile to the chain step. Recover the package corpus as the prescribed decision says, and keep its verified archives in an ignored cache beside the harness so a `.work/` reset cannot lose them again. | `compat/x86_64/qualification_candidate.py`, its test, `compat/x86_64/qualification-chain.md`, `compat/corpus/fetch_x86.py`, `compat/corpus/manifest-x86_64.toml`, `.gitignore` | `./scripts/dev-x86_64.sh qualification-candidate --work .work/x86_64/cohort --profile correctness --inputs FILE --dry-run \| jaq -e '.preflight_blockers == []'` |
| G6 | M | Turn the two prose failures into tracked tests through the existing allocator fixtures, in release and opt0 products. If one does not reproduce on current source in 3 attempts, keep the test as a passing regression and log that. | `compat/allocator/` fixtures and their test files | Each test has a one-line command in the campaign log and fails on `main`, or passes and is logged as not reproducible |
| G7 | L | Discovery run: execute the cohort runner on clean `main` under the correctness profile and fix nothing. The runner stops at the first failing step; past that point run the remaining steps' commands directly, as `--dry-run` prints them, feeding each the outputs that exist. Record for every step the result, the first error, and the time; a step whose input is missing is blocked-by its producer. | `.work/x86_64/cohort` only | A table in the campaign log of all 66 correctness steps with pass, fail, or blocked-by, and the wall time of each |

G7 replaces assumption with a list. Until it finishes, the phase 1 items
below are sized from the family ledger, not from observed failures.

### Phase 1: parity and completeness

One lane per workstream. Workstreams are drawn so their files are disjoint,
and the coordinator fixes each lane's exact file list in its brief from G7's
failures; two running lanes never share a file. All can run at once: widest
is 12 lanes, bounded by memory. Family admission is
ordered by dependency and is the coordinator's job on merged `main`: posix,
pthread, text, resolver, c-abi, loader, crt, static sysroot, combined sysroot.

| ID | Size | Workstream and outcome | Owns | Prerequisite | Acceptance |
| --- | --- | --- | --- | --- | --- |
| R1 | L | `libc.posix-runtime`: 9 capabilities, steps `posix-family` to `posix-admission` | POSIX, filesystem, process and signal modules under `libc/src/c_abi/x86_64/`; `compat/x86_64/owned_posix_*`, `owned-posix-*` | G7 | Those steps pass; `campaign-family libc.posix-runtime` shows no unresolved capability |
| R2 | M | `libc.pthread-tls`: 3 capabilities, step `pthread-family` | pthread, TLS and cancellation modules; `owned_pthread_*`, `owned-pthread-*` | G7; admission after R1 | Step passes; no unresolved capability |
| R3 | L | `libc.text-math-locale-stdio`: 16 capabilities, steps `text-*` | stdio, locale, wide, iconv, regex, wordexp, calendar and math modules; their `owned_*` contracts | G7; admission after R2 | All `text-*` steps and `text-family` pass |
| R4 | M | `libc.resolver`: steps `resolver-family`, `publish-resolver-network` | resolver and netdb modules; `owned_resolver_*`, `compat/resolver-network/` | G7; admission after R3 | Both steps pass |
| R5 | L | `libc.c-abi-compat`: 11 capabilities, steps `c-abi-compat-family`, `abi-*` | crypt, legacy compatibility and process-global modules; `native_abi_*`, `header_*` | G7; admission after R4 | Those steps pass |
| R6 | L | `ldso.dynamic-runtime` (4 capabilities) and `crt.dynamic-startup`: steps `loader-*`, `crt-dynamic-startup` | `ldso/`, `crt/`, `compat/x86_64/*loader*`, `general_*` | G7 | Those steps pass |
| R7 | M | `sysroot.static-tls` and `sysroot.owned-artifact`: steps `static-products`, `dynamic-products`, `static-sysroot`, `combined-sysroot`, plus the static-TLS oracle execution | `scripts/build_x86_64_owned_sysroot.py`, `scripts/build_x86_64_owned_dynamic_sysroot.py`, `libc/src/c_abi/x86_64/static_tls.rs`, sysroot contracts | G7; admission after R5 and R6 | Those steps pass on all four link modes |
| R8 | M | Consumers: steps `rust-std-lto`, `lua-static`, `lua-dynamic`, `lua-admission` | `unwinder/`, `compat/lto/`, `compat/rust-std/`, `compat/lua/` | G5; admission after R7 | Those steps pass |
| A1 | L | Fix the two failures from G6 at their origin | The `crabc-mimalloc/src` modules G6 implicates (worker attachment in `runtime_lifecycle.rs`, child teardown in `subproc_lifecycle.rs`) | G6 | Both G6 tests pass in release; opt0 passes or is parked per the prescribed decision |
| A2 | L | Allocator correctness milestones M1 to M8 | `compat/allocator/` gates and fixtures; `crabc-mimalloc/src` outside A1's and A3's files | G1 | `./compat/allocator/run-x86_64.sh allocator-m1`, `allocator-m2` and `allocator-m3` pass, and `allocator-mN --check` passes for N in 4..8 (`--qualification-profile correctness` for M5, `baseline` for M6 and M7) |
| A3 | L | Pointer-first realloc and one owner-exit traversal. First settle by behavior, not source text, whether realloc of a block owned by another live thread, and of a block on an abandoned page, succeeds in place of refusing; fix the product if it refuses. Then establish whether selected production reaches any per-geometry `abandon_*` exit route; route what it reaches through the generic traversal of requirement 4 and leave test-only ones for C1. Repair or delete the syntactic checks in `architecture_ratchet.py` that no longer find their anchors. | The realloc, remote-free and owner-exit modules of `crabc-mimalloc/src`; `compat/allocator/architecture_ratchet.py` | G1 | Two named unit tests cover cross-thread and abandoned-page realloc and pass; the existing owner-exit unit and Loom tests pass; `python3 -B compat/allocator/architecture_ratchet.py --check --report .work/tmp/arch.json` exits 0 (28 s) |
| T1 | S | Decouple promotion (owner decision 2): the promotion closure stops requiring the native default; `performance.release` reads the runtime scorecard and the facade report only; the allocator bounds move unchanged to the allocator's own M9 and M10 gates | `compat/x86_64/campaign_promotion_closure.py`, `compat/x86_64/performance_release_gate.py`, `compat/allocator/x86_64_m10_gate.py`, their tests, `compat/x86_64/qualification_candidate.py` (after G5) | G5 | Their test modules pass; `qualification-candidate --dry-run` no longer asks for `allocator_reports` |
| T2 | S | Runtime bounds (owner decision 3): gate at 1.00, report each row against 0.90 | `compat/x86_64/performance_release_gate.py`, `compat/perf/x86_64_evidence.py`, `compat/perf/run.py`, their tests, `docs/design/performance.md` | T1 | Their test modules pass with one row at 0.95 accepted and one at 1.02 rejected |

A1 and A3 touch `crabc-mimalloc/src`. They are separate lanes only while
their files are disjoint; if G6 places a failure in a scheduler or admission
module, A1 takes that file and A3 waits for it.

### Phase 2: hardening

| ID | Size | Item | Acceptance |
| --- | --- | --- | --- |
| H1 | L | One clean cohort end to end. Commit the ledger rows first: each family row names the receipt its `--work` directory will produce (the `attachments` list of `--dry-run` must show every family `attached`) and carries the state those receipts support (43 capabilities, 16 families). Then run `qualification-candidate --profile correctness` from an empty work directory on that revision. | `./scripts/dev-x86_64.sh qualification-manifest --profile correctness --status` reports gates 1 to 7 qualified; `campaign-status` shows 223 `implemented-foundation` and only `performance.release` planned |
| H2 | M | Repeat H1 from a second empty work directory and compare products | The static and dynamic packages are byte-identical between the two runs |
| H3 | S | Write up: every contract change made so far under [Contract changes](#contract-changes), docs updated for what landed, cases found on the way added as regressions | `mdtool links` and `mdtool router` report no error |

### Phase 3: optimization and promotion

Starts only when phases 0 to 2 are done or parked. Measurements need an
uncontended host: no lane builds while one runs, and `perf-gate-ready` must
exit 0 before and after.

| ID | Size | Item | Acceptance |
| --- | --- | --- | --- |
| O1 | L | Runtime scorecard: three `perf-c` attempts and `perf-native --mode full` on the H1 products. Fix any row above 1.00 or over 2R by removing work (syscalls, copies, passes), as `performance-by-mechanism` describes, without changing selected semantics. Log every row against 0.90. | `performance_release_gate.py evaluate` passes; the full-profile chain passes: `./scripts/dev-x86_64.sh qualification-manifest --profile full --status` shows 8 gates |
| O2 | S | Promote x86 (D5): set `public_support = true` where the ledger, generator and manifest hold it, update `README.md`, `AGENTS.md` and `docs/scope.md` | `./scripts/dev-x86_64.sh campaign-promotion-check --qualification-receipt PATH` passes on that revision |
| O3 | L | Allocator performance. First a fresh three-run engine baseline (`allocator-perf-engine --full`) and a profile. Then remove work in the order the profile gives; expect admission, scheduling and ledger overhead (requirement 7) before any micro-tuning. Each increment is one mechanism with before and after numbers vetted by `benchmark-checklist`. | The M9 table holds on three agreeing full reports: suite throughput lower95 at least 0.95, critical rows at least 0.90, critical p99 cost upper95 at most 1.10, peak RSS and PSS upper95 at most 1.05 geomean and 1.10 critical; `architecture_ratchet.py --gate --runtime-evidence FILE` exits 0 |
| O4 | M | Switch the default (D6): M9 and M10 at the baseline profile, then `DEFAULT_ALLOCATOR_BACKEND = "native"` in `scripts/build_x86_64_owned_sysroot.py`, then rerun H1 and O1 on that revision | `allocator-m10 --profile baseline --check` passes; the full chain and the promotion check pass on the switched revision |

### Phase 4: close

| ID | Size | Item | Acceptance |
| --- | --- | --- | --- |
| C1 | M | Delete what is dead, proving liveness as `dead-code-archaeology` describes: never-constructed variants and unreachable routes in `crabc-mimalloc`, test-only scaffolding no gate reads, validators and readers no command reaches | An opt0 build of `crabc-mimalloc` prints no dead-code warning; `scripts/lanes/rust-check.sh` and the phase 2 checks still pass |
| C2 | M | `ultrareview` on the campaign's diff; fix its P1 and P2 findings | No open P1 or P2 |
| C3 | S | Final report at the top of this file: what merged, every contract change, measurements, parked items with findings | — |

## Acceptance

| Deliverable | Proof |
| --- | --- |
| D1 | G1, G3, G4 and G5 acceptance commands exit 0; G6 tests exist |
| D2 | `./scripts/dev-x86_64.sh campaign-status \| jaq -e '.state_counts.capabilities["implemented-foundation"] == 223'`, and every family except `performance.release` is `foundation-verified` |
| D3 | `./scripts/dev-x86_64.sh qualification-manifest --profile correctness --validate-receipt PATH` exits 0 on a receipt whose `qualified_gates` has seven entries for the current revision |
| D4 | `python3 compat/x86_64/performance_release_gate.py evaluate ...` passes on fresh uncontended measurements |
| D5 | `./scripts/dev-x86_64.sh campaign-promotion-check --qualification-receipt PATH` passes with `public_support = true` |
| D6 | `./compat/allocator/run-x86_64.sh allocator-m10 --profile baseline --check` passes, the builders default to `native`, and D3 to D5 pass again on that revision |
| D7 | C1 and C2 acceptance; the final report is committed |

Physical NUMA and explicit 2-MiB and 1-GiB page modes stay recorded as
unqualified; no proof above depends on them.

## Contract changes

Pre-authorized:

- The core image identity in `compat/x86_64/core_image.py` (G1).
- `qualification-candidate --profile` (G5).
- Re-pinning the x86 package corpus to a current signed v3.24 index, roster
  and scenarios unchanged, only if the original archives cannot be recovered
  byte-exact (G5).
- Promotion no longer requires the native allocator default; allocator
  inputs leave `performance.release` (T1).
- Runtime performance bounds gate at 1.00 (T2).
- Ledger transitions that a passing aggregate on merged `main` supports:
  capability to `implemented-foundation`, family to `foundation-verified`.
- `public_support = true` for x86-64 (O2), and the x86 allocator default (O4),
  each only on its acceptance.
- Deleting a host-side test of prose or source text (G4).

Forbidden:

- Changing the frozen AArch64 baseline digests, the 223-capability and
  26-family inventory, or any AArch64 behavior or default.
- Lowering a correctness threshold, shrinking a corpus, rewriting an upstream
  workload, or reclassifying a failure as expected to pass a gate.
- Changing an upstream pin (musl 1.2.6, mimalloc v3.5.0, the Rust nightly,
  `unwinding` 0.2.10).
- Widening the public C ABI or header surface beyond the selected profile.
- An allocator algorithm that diverges from pinned mimalloc without a
  `known-differences.md` entry and the differential and performance evidence
  [docs/scope.md](docs/scope.md) requires.
- Relaxing any allocator performance bound or M10 baseline prerequisite.

Made so far, each with its commit, for the owner: none.

## Non-goals

- AArch64 work of any kind, and any new architecture or portability layer.
- LLVM/Clang integration and the macOS backend.
- Physical NUMA and explicit huge-page qualification on this host.
- New receipt schemas, validators, per-artifact proofs, or status documents.
- Performance work before phase 3, and beating musl by 10% as a gate.
- Rewriting the allocator port for size or idiom. Phase 3 removes measured
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

### Runtime completion requirements

Feature implementation and current-source qualification are distinct claims.
A C ABI pass does not prove the Rust-native path, or the reverse.

| Area | Requirement |
| --- | --- |
| Headers and layouts | Complete installed header paths, the selected strict, POSIX, XOpen, GNU, BSD and large-file profiles, declarations of every kind, C and selected C++ linkage, LP64 and x87 layouts, transitive includes, and installed-tree isolation. No missing selected declaration or unclassified callable owner. |
| POSIX runtime | Coherent filesystem, directory and traversal, descriptor, environment, process-control, signal and kernel-administration behavior, including aliases, errno and TLS, shared state, selected cancellation, errors, and ownership, through the owned C entries and the Rust-native paths. |
| pthread, C11 and TLS | Lifecycle, attributes, join and detach, synchronization, once, TSD, cleanup, cancellation, signals, timers, atfork and fork, and exit. Main, loader, worker, static TLS, dynamic TLS, DTV and `__tls_get_addr` use one ownership model. |
| Text, math, locale, stdio | Selected iconv, wide and multibyte, regex, word expansion, calendar, and complete stream behavior. One stream engine owns locking, buffering, orientation, every stream kind, positioning, errors, and exit flushing. Preserve restricted locales, x87, MXCSR and fenv, the long-double ABI, rounding, signed zero, NaNs, and exceptions. |
| Resolver | Conventional files and bounded netdb behavior end to end: A, AAAA and CNAME, search, UDP and TCP fallback, timeout, retry and failover, reply validation, errors, cancellation, and result lifetime, proven through owned C products on controlled networks. |
| C compatibility | Selected crypt through approved primitives, allocation, legacy compatibility, process globals, and final provider closure: names, aliases, bindings, visibility, sizes, and static and shared ownership, by ordinary archive extraction or an explicit structural boundary, never a hidden unresolved provider. |
| Loader | General admitted dependency graphs: self-relocation and entry, search, RPATH and RUNPATH, mapping, protection and RELRO, supported RELA and RELR relocations, symbol scope, RuntimeV1, initial and runtime TLS, DTV growth, constructors and finalizers, and selected `dl*` introspection, including concurrency, reentrancy, fork, retained handles, malformed input, and failed-load rollback. |
| CRT, builtins, sysroot | Owned static, static-PIE, dynamic PIE and dynamic non-PIE entry, libc handoff, lifecycle arrays, finalization, compiler helpers, and a deterministic link interface. The sysroot owns headers, CRT objects, `libc.a`, shared libc, the interpreter, builtins, allocator selection and link specifications; a pinned host compiler is permitted, ambient target inputs are not. |
| Consumers | Rust std, dependency-bearing std, build-std, LTO, and the Lua source build through the real `_Unwind_*` ABI, ordinary archive extraction, and shared symbol resolution. Dummy unwind symbols, hidden providers, or C recovery are not implementations. |
| Rust facade | Every other frozen family and exact semantic mapping, with direct native API, error, ownership, and dependency ownership. |

### Native allocator completion requirements

`crabc-mimalloc` is a `#![no_std]` engine with no production `alloc`, C or C++
implementation, bindgen, native build script, dependency on crabc-libc, or
hidden C fallback. Libc owns errno and C ABI policy and depends on the engine,
never the reverse. Port complete source transitions, not test-shaped routes.
Inapplicability needs a source-backed reason, not unavailable hardware.

1. **Persistent source owners.** Each allocating thread keeps its TLD and
   Theap across operations; the initial thread keeps source-required static
   storage. Local small, direct-cache and generic queue operations stay
   owner-local, and independent owners progress independently.
2. **Pointer-centered dispatch.** `free`, usable-size and realloc derive the
   page from the pointer and PageMap, recover the canonical aligned block,
   and choose local, live-remote or abandoned behavior from page and process
   state, not caller identity or a client registry. Realloc follows
   `mi_theap_realloc_zero_ex` and preserves the old allocation on failure.
3. **Page-local remote publication.** Translate the pinned remote-free atomic
   protocol without borrowing the owner's TLD or engine. PageMap and metadata
   stay valid through every legal live client and unfinished publication.
   Ordinary lookup takes no structural PageMap mutation lease.
4. **One owner-exit traversal.** `_mi_theap_collect_abandon` performs deferred
   free, retired-page collection, queue traversal, per-page collection,
   release or abandonment, cache repair, and Heap, Theap and TLD detachment
   through one generic coordinator, not caller-selected geometry routes.
5. **Callbacks without invalid borrows.** Deferred, VM, output and
   initialization callbacks run outside owner, engine, TLD and Theap reference
   projections, and attachment identity is revalidated before exclusive
   collection resumes.
6. **Abandonment outlives threads, not TLS.** Surviving pages belong to source
   page and process abandonment structures. Any surviving thread can free,
   reallocate or reclaim as source permits. A failed reclaim preserves
   ownership and retains exactly one identifiable terminal owner.
7. **No production scaffolding.** No per-allocation side ledger, live-TLS-owner
   or post-exit registry, historical-thread scan, per-call park and resume,
   global ordinary-operation scheduler, or fixture-geometry route. A
   constant-size page-local lifetime aid needs a documented source invariant
   and model evidence.

Also required:

- **Bootstrap.** Initialization is idempotent, race-safe, reentrant and
  allocation-free until primitives are ready, from raw startup auxv,
  page-size, `AT_RANDOM` and environment facts, with no public libc call.
- **Memory.** Target-probed page and address geometry; complete raw Linux
  reservation, commit, purge, protection, remap, entropy, advice and NUMA
  behavior, with fault injection at that primitive boundary.
- **Fork.** Allocation-free hooks that preserve the parent, repair inherited
  locks, vanished-thread ownership and child TLS, and permit all standard
  allocation in the child. A bridge that disables child allocation is not
  completion.
- **Integration.** Libc owns malloc-family policy (interposition, errno,
  zero-size, alignment, overflow, `realloc(p, 0)`, usable size). A Rust
  pointer never crosses into the C backend as recovery. Worker attachment
  establishes its owner before user code; cleanup and TSD destructors precede
  owner teardown, which precedes TLS unmapping. Logical process-done runs
  from libc's own `.fini_array`. The dynamic RuntimeV1 handshake transfers
  runtime and TLS coordinates, not allocator pointers
  ([docs/design/x86-dynamic-native-allocator.md](docs/design/x86-dynamic-native-allocator.md)).
- **Safety.** `#![deny(unsafe_op_in_unsafe_fn)]`, strict provenance, short
  validated raw projections, no long-lived reference that contradicts remote
  access. A legal free cannot return unavailable, and allocation cannot
  report OOM because a scheduler token is busy.
- **Memory metrics.** For total-memory rows dominated by mandatory live
  payload or kernel charge granularity, require no regression; keep the raw
  reference and candidate measurements.

Source feature groups, each of which must be implemented and verified for
Linux/x86-64: source foundations, memory substrate, local engine, allocation
API, concurrency and lifecycle, owned Heap, Theap, arena and subprocess APIs,
configuration and options, and runtime composition. The applicable
inventories are the milestone manifests under `compat/allocator/`.

## Decision log

Append one line per judgment call a reader would otherwise miss.

- 2026-10-13: plan restructured for unattended execution; the earlier
  progress narrative is in Git history at `6e54203fb`.

## Campaign log

Append one line per phase end, per parked item, and per contract change.

## For the owner afterwards

- The contract changes list, and the commits it names.
- Parked items and their findings in the campaign log.
- The 0.90 column of the runtime scorecard, to decide whether it becomes a
  gate.
- Allocator code size and source size against pinned C, to decide whether a
  structural consolidation of the port is worth a campaign of its own.
- Branches G2 kept, to delete or mine.
