# Campaign lanes

[plan.md](../plan.md) owns the active S0–S5 sequence. The October 30 reset
supersedes the old fill-every-slot campaign. **No allocator lane, including
read-only discovery, profiling, cleanup, receipts or promotion, is authorized.**
Keep parked work and its evidence intact. A historical command or agent brief
is not permission to resume it.

## Roles and width

The coordinator scopes reductions, reviews and integrates changes, verifies the
merged tree, and alone updates `plan.md` and `AGENTS.md`. A lane owns one concrete
mechanism and its focused behavioral checks, with explicit files and an exit
condition. A reviewer independently challenges semantics, liveness and whether
the change actually removes complexity. Use the existing `orchestrate` tiers;
there are no repository-specific agent types.

Start only work that fits the current simplification phase and has no unresolved
ownership/dependency overlap. Prefer one implementation owner per mechanism and
one reviewer over parallel slices that each invent an adapter or proof format.
Parallelize independent reductions only. **An idle slot is not a defect.**
Neither the subagent cap nor spare memory is a target for concurrency.

Each brief must state: the mechanism being removed, retained behavior, allowed
files, baseline/reduction budget, focused test/measurement, and allocator freeze.
Do not create a per-lane receipt system. Keep ready work narrow instead of
launching discovery for every old family at once.

## Worktrees

Use an existing suitable clean worktree when possible. For a genuinely new
non-allocator stream:

```sh
git worktree add -b lane/<id> .work/wt/<id> main
(cd .work/wt/<id> && scripts/lanes/prepare-worktree.sh)
```

The current preparation script may copy cached allocator inputs as part of the
runtime build environment; that does not authorize an allocator build campaign.
Do not expand preparation or rerun expensive inventories speculatively. S2 may
simplify shared preparation without changing frozen allocator tooling/contracts.

Keep a warm worktree for its bounded workstream. Never use `git stash`; the
repository's `rebase.autostash` setting shares state between worktrees. Commit
or discard only the lane's own changes before rebasing. Lanes never push and
write no ref except their own branch. A coordinator publication requires actual
owner authorization, not a historical unattended-work instruction.

Removal requires completed custody checks and explicit permission within the
current task. Use the existing helper only for authorized, reconciled paths;
respect all exact refusals in [plan.md](../plan.md#preserved-checkpoint-and-holds).
A path containing unique source, failed evidence or unresolved ignored files is
not disposable merely because the lane is parked. No bulk cleanup on stop.

## Development loop

1. Reproduce the relevant behavior and record the selected mechanism's baseline.
2. Remove one source of duplication/work without adding a replacement framework.
3. Run the smallest relevant behavioral checks and S1's focused cost route when
   available. Record missing counters or other unavailable evidence honestly.
4. Review correctness, retained case coverage, emitted/linked cost and the actual
   reduction in mechanisms; do not count moved code or deleted comments as wins.
5. Integrate and rerun the affected checks on the merged revision.

Use the pinned native x86 environment. Never run `scripts/dev.sh`, emulate
AArch64, or invoke the allocator runner directly. Examples for in-scope work:

```sh
scripts/lanes/rust-check.sh cargo check -q --locked -p <non-allocator-crate>
python3 -B scripts/test_python.py --module <path/to/test_file.py>
python3 compat/x86_64/validate_parity_ledger.py
./scripts/dev-x86_64.sh campaign-status
```

Select the actual touched crate/test; do not assume placeholder commands are
ready to run. The native harness is documented in
[compat/x86_64/README.md](../compat/x86_64/README.md). The current perf commands
are in [compat/perf/README.md](../compat/perf/README.md); S1 adds the focused
route without calling a development report a release scorecard.

Reproduce a behavioral bug with a failing test before fixing it. Existing
regression checks may expose an allocator defect: retain the failure and park
the dependent change; do not reopen allocator work. Shared source changes must
preserve the frozen allocator/AArch64 contracts or be deferred.

## Ownership and verification

One writer owns shared tooling at a time, particularly `scripts/dev-x86_64.sh`,
`compat/x86_64/parity.toml`, `validate_parity_ledger.py`, product builders and
shared report readers. A lane needing another owner's file reports the need;
it does not create a local substitute. Do not touch frozen allocator files.

Lanes do not promote ledger/support/default state. Inspect each diff before
integration, reconcile concurrent changes, and rerun checks on the actual merged
tip. A lane receipt proves its commit, not the merged tree. If a derived inventory
conflicts, regenerate it from the resolved inputs rather than choosing a side.
Do not regenerate frozen AArch64 manifests or their digested inputs to absorb
changes. Retain source/product binding and behavioral cases when consolidating
validators.

Focused checks run continuously; full qualification remains distinct and parked
until simplification review. A problem in an old global qualification chain is
not permission to skip a touched path's tests or to defer every useful cost
measurement. Narrow an untestable change instead of adding more infrastructure.

Use quiet, pinned measurement windows for qualifying comparisons, including
retired instructions. CPU time/counters under load may aid diagnosis but are
not automatically stable proof. Stop competing work safely and retain rejected
samples; never choose the best run. Unsupported PMUs remain unsupported.

## Stop and retained work

For frozen allocator work, stop at a safe process/tool boundary and preserve
uncommitted source and evidence; do not finish another fix or merge a partial
result. For an in-scope lane, preserve its reviewed work and concise blocker.
Do not kill unrelated processes, remove retained directories, retry denied
cleanup or delete branches as a side effect of a campaign stop.

The current result/blocker table belongs in `plan.md`; detailed history belongs
in Git and raw local reports, not more status prose or new archive documents.
