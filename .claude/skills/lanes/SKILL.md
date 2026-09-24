---
name: lanes
description: Run crabc's parallel plan.md campaign — plan bounded, non-overlapping lanes, start at most 16 crabc-lane agents in .work worktrees, integrate their commits into main, and settle or park every lane before stopping.
---

# Lanes

The parent session plans lanes, integrates to `main`, and owns `plan.md`.
Lane agents follow `.claude/agents/crabc-lane.md`.

## Plan

- Start from `plan.md` Progress status (parked `lane/*` branches first) and
  `./scripts/dev-x86_64.sh campaign-status`.
- Give each lane one bounded deliverable and an exclusive set of files. Check
  for overlap before launching; shared tooling (`scripts/dev-x86_64.sh`,
  `compat/allocator/run.py`, shared readers) gets exactly one owner.
- At most 16 lanes at once (`.claude/settings.json`). Don't invent lanes.

## Run

```sh
git worktree add -b lane/<id> .work/worktrees/lane-<id> main   # or reuse a parked lane/<id>
```

Spawn `subagent_type: crabc-lane`, `run_in_background: true`, with the lane id,
worktree, outcome, and boundary. Keep the lane → agent id map in
`.work/tmp/lane-agents.txt`. Sweep lane branches proactively
(`git log main..lane/<id>`, `git -C <worktree> status`) and merge coherent
commits as they land; route broken shared tooling to one owner.

## Integrate

1. Cherry-pick the lane's commits onto `main`.
2. If `compat/x86_64/aarch64_parity_inventory.json` conflicts, take either side
   and run `python3 scripts/lanes/refresh-parity-digests.py`.
3. Check with `python3 compat/x86_64/validate_parity_ledger.py`,
   `python3 compat/x86_64/aarch64_parity_inventory.py`,
   `scripts/lanes/rust-check.sh`, the tests the commits touch, and the lane's
   native command when it claims new evidence.
4. Never merge a lane's family admission; rerun it on merged `main`.
5. Commit with `--no-verify`; remove merged worktrees with
   `scripts/lanes/remove-worktree.sh .work/worktrees/lane-<id>`.

## Stop

Stop agents and the containers mounting their worktrees, commit leftover edits
as `WIP(lane <id>)` on each lane branch, merge what verifies, remove every lane
worktree, and update `plan.md` Progress status.
