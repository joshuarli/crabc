---
name: lanes
description: Coordinate crabc's plan.md campaign lanes from Codex. Use for parallel lane planning, delegation, and integration.
---

# Codex lane adapter

The campaign contract remains in `AGENTS.md`, `plan.md`, `.claude/skills/lanes/SKILL.md`, and `.claude/agents/crabc-lane.md`. Follow those lane boundaries, proof requirements, integration checks, and stop rules. This adapter translates only the coordinator and agent mechanics to Codex.

- Create or reuse each lane's `.work/worktrees/lane-<id>` worktree before launching it with `spawn_agent`. Give the agent the lane id, absolute worktree path, outcome, exclusive file boundary, proving command, and relevant lane brief. Agents share the checkout's filesystem, so require all lane commands and edits to use the assigned worktree.
- Use `list_agents`, `send_message`, `wait_agent`, and `followup_task` to coordinate progress and keep the repo's 16-lane target moving. Maintain `.work/tmp/lane-agents.txt`; the parent alone integrates to `main`.
- Claude's `subagent_type`, `run_in_background`, and model frontmatter are not Codex controls. For difficult design or debugging lanes, use `gpt-6-sol` at medium or high effort; use `gpt-6-luna` at max effort for routine, well-specified implementation. Never use Astra. This Codex model policy supersedes model choices in the Claude lane instructions. Do not use the Claude-specific `Co-Authored-By` trailer in lane commits.
- Before integration, inspect the lane worktree and commits; cherry-pick coherent commits to `main` and run the shared integration checks. Keep shared state single-owner and never use `git stash`.
