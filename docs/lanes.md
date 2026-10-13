# Campaign lanes

How parallel work on [plan.md](../plan.md) is run in this repository. The
general mechanics (workstreams, rolling waves, the lane contract, review then
merge then verify) are the campaign reference of the `orchestrate` skill; this
file holds only what is specific to crabc. `plan.md` owns what to work on and
in which order.

## Roles

- **Coordinator.** Selects ready items, briefs lanes, reviews and merges their
  commits into `main`, verifies on the merged tree, and updates `plan.md`. It
  alone edits `plan.md` and `AGENTS.md`, and it writes no feature code while
  lanes are running.
- **Lane.** Delivers one workstream slice end to end (code, tests, the docs it
  makes stale) in its own worktree and branch, inside the files its brief
  names. Lanes never coordinate with each other; a lane that needs something
  outside its boundary reports it.

## Agents

Route by difficulty, not size, using the `orchestrate` tiers. The harness
refuses any other agent type, so the repository defines none of its own.

| Work | Tier |
| --- | --- |
| Read-only inventory, log triage, "where is X" | `scout` |
| Fully specified edits: registrations, renames, runner flags | `mechanic` |
| A slice with a named method and acceptance check (most lanes) | `worker` |
| No hypothesis yet, or a change spanning owners | `expert` |
| A failure an `expert` could not explain; a design others build on | `god` |

Under Codex use the model and effort the `orchestrate` skill's Codex column
gives for the same row. Escalate a tier on evidence that the work was harder
than briefed, not because a command failed.

## Worktrees

```sh
git worktree add -b lane/<id> .work/wt/<id> main
(cd .work/wt/<id> && scripts/lanes/prepare-worktree.sh)
```

`prepare-worktree.sh` fetches and vendors the locked Cargo closure into the
worktree's own `.work/x86_64/cargo`, seeds the verified mimalloc archive from
the primary checkout, and materializes the pinned package-corpus input. It
needs the core image and, the first time, the network.

Every worktree has its own `.work/` and therefore its own cold target
directories. Containers write root-owned files there, so remove a worktree
with the helper, then delete the merged branch:

```sh
scripts/lanes/remove-worktree.sh .work/wt/<id>
git branch -d lane/<id>
```

The helper refuses a path outside `.work/wt/` and a worktree with uncommitted
tracked changes. A workstream keeps its worktree, with its built targets,
for as long as it has ready or running work; remove it when the workstream
has nothing ready.

## Width and pace

An idle slot with ready work is a defect. The limit is memory and disjoint
file ownership, not a fixed lane count: a cold `crabc-mimalloc` test build
was measured at roughly 8 GiB resident on this 32-CPU, 60 GiB host. Launch
the first lanes, read peak memory once they build, and keep at least 12 GiB
available. `.claude/settings.json` caps concurrent subagents at 24.

- **Stagger, never wave.** Launch a lane the moment the narrowest thing it
  needs has merged. Split an item into the part that needs nothing and the
  part that waits, and start the first part now.
- **Discovery belongs to the lane.** A lane's first act is to run its own
  family's steps or gates on its own committed branch and report what fails.
- **Resume, do not respawn.** When a lane reports and its workstream has more
  ready work, rebase its branch onto `main` and send the next item to the
  same agent in the same worktree.
- **Read-side lanes are free.** Inventories, reconnaissance and profiling
  that change no product code never conflict; keep them running.
- **Measurement windows.** Qualifying benchmarks need a quiet host. Collect
  every pending measurement, tell running lanes to finish the command in
  flight and hold, measure, then release them. Diagnose with CPU time and
  instruction counts instead, which need no window.

## The lane loop

A lane uses the cheapest build that compiles its change and runs only the
tests it wrote or changed, by name. Suites, optimized builds, family
aggregates and qualification gates belong to the coordinator, after the merge.

| Need | Command | Measured |
| --- | --- | --- |
| Type-check one crate | `scripts/lanes/rust-check.sh cargo check -q --locked -p <crate>` | 2 s warm |
| Type-check every runtime feature profile (before each handoff) | `scripts/lanes/rust-check.sh` | 98 s cold, 10 s warm |
| One allocator unit test (built unoptimized) | `./compat/allocator/run-x86_64.sh allocator-unit --filter <module::tests::name>` | 52 s cold, 9 s after an edit |
| One host-side reader or validator test | `python3 -B scripts/test_python.py --module <path/to/test_file.py>` | under 1 s to 30 s |
| Ledger structure | `python3 compat/x86_64/validate_parity_ledger.py` | 1 s |
| Family and gate state | `./scripts/dev-x86_64.sh campaign-status` | 2 s |

Other narrow routes are in the harness guides:
[native x86-64](../compat/x86_64/README.md) and
[allocator](../compat/allocator/README.md).

## Rules specific to this repository

- Build and test only through the pinned native x86-64 environment
  (`scripts/lanes/rust-check.sh`, `./scripts/dev-x86_64.sh`,
  `./compat/allocator/run-x86_64.sh`). Never `scripts/dev.sh`, and never
  `compat/allocator/run.py` directly: it defaults to AArch64.
- Never use `git stash`. This repository sets `rebase.autostash`, which would
  use the stash stack shared by all worktrees: commit or discard every change
  before rebasing. Never push, and write no ref other than the lane's branch.
- Reproduce a bug with a failing regression before fixing it, and keep the
  regression.
- Three files have one writer, the tooling lane: `scripts/dev-x86_64.sh`,
  `compat/x86_64/parity.toml` and `compat/x86_64/validate_parity_ledger.py`.
  A lane that needs a change there reports it. `compat/allocator/run.py` and
  the shared receipt readers likewise have one owner at a time.
- No lane changes ledger state. A family or capability becomes verified only
  in a qualification commit, proven by a cohort run at that exact commit, as
  `plan.md` describes.
- Never change the frozen AArch64 inputs:
  `compat/x86_64/aarch64_frozen_baseline.json` and the three files it
  digests (`compat/crabc-rs/coverage.toml` and the two files under
  `compat/abi/musl-1.2.6/aarch64/`).
- Never rebuild a pinned image. A rebuild changes its ID, and every receipt
  made in the old one stops counting.
- Do not record qualifying performance numbers from a lane, and do not
  throttle builds; retry one killed by memory pressure and report it.
- Every commit is a Conventional Commit with the workstream as scope.

## Integrate

Merge every lane that has reported, then verify the merged tip once:

1. Read each diff. Rebase each lane onto `main` and fast-forward; lanes own
   disjoint files, so order does not matter.
2. If `compat/x86_64/aarch64_parity_inventory.json` conflicts, take either
   side and run `python3 scripts/lanes/refresh-parity-digests.py`; the file is
   fully derived from the ledgers.
3. Verify the merged tip from a scratch worktree (`.work/wt/verify`), never
   in the integration tree, and bisect by lane only if it fails: `python3 compat/x86_64/validate_parity_ledger.py`,
   `python3 compat/x86_64/aarch64_parity_inventory.py`,
   `python3 scripts/check_structure.py`, `scripts/lanes/rust-check.sh`, the
   test files the commits touch, and the lane's native command.
4. A receipt a lane produced proves the lane's commit, not `main`. Rerun the
   cohort steps the lane claims to have fixed in the cohort worktree at the
   merged commit.
5. Launch what the merge unblocked before anything slow. A parked lane keeps
   its committed branch and is named in `plan.md`.

Send a failure back to the lane that holds the context, with the command and
its output, rather than starting a new one.

## Stop

Tell running lanes to finish the item they hold and take no other. Stop the
containers mounting their worktrees, commit leftover work to each lane branch,
merge what verifies, remove every lane worktree, and write the handoff at the
top of `plan.md`.
