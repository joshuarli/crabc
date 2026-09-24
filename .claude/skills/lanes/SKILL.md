---
name: lanes
description: Run crabc's parallel plan.md campaign — plan bounded, non-overlapping lanes, start at most 16 crabc-lane agents in .work worktrees, integrate their commits into main, and settle or park every lane before stopping.
---

# Lanes

The parent session is the only integration owner: it plans lanes, merges to
`main`, edits `plan.md` and central ledgers, and removes worktrees. Lane agents
follow `.claude/agents/crabc-lane.md`.

## Plan

- Start from `plan.md` Progress status and Parallel lanes plus
  `./scripts/dev-x86_64.sh campaign-status`.
- Give each lane one bounded, unique deliverable with an exclusive write
  boundary. Before launching, check that no two lanes will edit the same
  source files; shared runner code (`compat/allocator/run.py`,
  `scripts/dev-x86_64.sh`, `compat/x86_64/*` readers) gets exactly one owner.
- A lane that hits a failure outside its boundary reports it; the owner routes
  it to one fixer. Never let two lanes fix the same breakage.
- Run at most 16 lane agents at once (`.claude/settings.json`). Do not invent
  lanes to fill slots.

## Start

```sh
git worktree add -b lane/<id> .work/worktrees/lane-<id> main
```

Spawn with `subagent_type: crabc-lane` and `run_in_background: true`. If that
type is not loaded yet, use `general-purpose`, `model: opus`, and tell the
agent to read `.claude/agents/crabc-lane.md` as its contract. A brief names the
lane id, worktree, outcome, reusable branches to evaluate, and boundary. Keep
the lane → agent id map in `.work/tmp/lane-agents.txt` and address messages
from it.

## While lanes run

- Sweep proactively rather than waiting for completions:
  `git log --oneline main..lane/<id>` and the worktree's `git status`.
- Merge coherent, verified commits as they land; resume a returned agent with
  its next bounded deliverable.
- Nobody uses `git stash`; `refs/stash` is shared by every worktree.

## Integrate

1. `git cherry-pick <lane commits>` onto `main` (lanes rebase, but `main`
   moves). Skip commits that apply empty.
2. Derived parity digest files always conflict. Take either side, then run
   `python3 scripts/lanes/refresh-parity-digests.py` and stage those files
   explicitly before committing.
3. Check: `python3 compat/x86_64/validate_parity_ledger.py`,
   `python3 compat/x86_64/aarch64_parity_inventory.py`,
   `python3 compat/x86_64/generate_qualification_manifest.py --check`,
   `scripts/lanes/rust-check.sh`, the host tests the commits touch, and the
   lane's native dispatcher command when it claims new evidence.
4. Test count pins that drift only because merged ledgers moved are updated to
   the derived values; do not reconstruct their history.
5. Never merge a lane's family admission (`status = "foundation-verified"`):
   its receipt binds the lane revision. Rerun admission on merged `main`.
6. Commit with `--no-verify`, then
   `scripts/lanes/remove-worktree.sh .work/worktrees/lane-<id>` once the lane
   is fully merged. Branches are kept.

## Pause or stop

Stop agents (TaskStop), stop containers that mount `.work/worktrees/lane-*`,
commit each lane's remaining edits as one `WIP(lane <id>)` commit on its own
branch, then merge what verifies, park the rest on its branch, remove every
lane worktree, and record merged and parked lanes in `plan.md` Progress.
