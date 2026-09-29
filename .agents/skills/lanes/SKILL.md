---
name: lanes
description: Coordinate crabc's plan.md campaign lanes from Codex. Use for parallel lane planning, delegation, and integration.
---

# Codex lane adapter

The campaign contract remains in `AGENTS.md`, `plan.md`, `.claude/skills/lanes/SKILL.md`, and `.claude/agents/crabc-lane.md`. Follow those lane boundaries, proof requirements, integration checks, and stop rules. This adapter translates only the coordinator and agent mechanics to Codex.

- Create or reuse each lane's `.work/worktrees/lane-<id>` worktree before launching it with `spawn_agent`. Give the agent the lane id, absolute worktree path, outcome, exclusive file boundary, proving command, and relevant lane brief. Agents share the checkout's filesystem, so require all lane commands and edits to use the assigned worktree.
- Use `list_agents`, `send_message`, `wait_agent`, and `followup_task` to coordinate progress and keep the repo's 16-lane target moving. Maintain `.work/tmp/lane-agents.txt`; the parent alone integrates to `main`.
- Claude's `subagent_type`, `run_in_background`, and model frontmatter are not Codex controls. Use `gpt-6.1-sol` at medium or high reasoning effort for every Codex lane. Never use `gpt-6-sol`, `gpt-6-luna`, or Astra. This Codex model policy supersedes model choices in the Claude lane instructions. Do not use the Claude-specific `Co-Authored-By` trailer in lane commits.
- Before integration, inspect the lane worktree and commits; cherry-pick coherent commits to `main` and run the shared integration checks. Keep shared state single-owner and never use `git stash`.
- Treat worktrees as disposable after integration. When a lane's commits are merged and its agent has stopped, remove its worktree in the same integration pass with `scripts/lanes/remove-worktree.sh .work/worktrees/lane-<id>`; do not keep merged worktrees for later tasks. Start a successor in a fresh worktree. Put any raw evidence still needed by a qualification reader in an existing ignored report location under the main checkout before removal, and verify that reader can use it there. The worktree is never the long-term evidence store.
- Keep `.work/tmp/lane-agents.txt` current as worktrees are removed and successors start. Do not delete a worktree with uncommitted tracked edits, unintegrated commits, a running agent, or a process still using its files; settle those first, then remove it promptly.
