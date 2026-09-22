---
name: crabc-orchestrate
description: Execute crabc plan.md with an Astra coordinator, high useful implementation parallelism, continuous integration, frozen qualification cohorts, and separately budgeted build/test resources. Use for this completion campaign and all delegated tasks; not for unrelated repositories or small standalone crabc requests.
---

# crabc completion orchestration

Read the root `plan.md`. This skill is its local execution policy, not a second
product specification. For this campaign, it overrides the user-global
`orchestrate` defaults that prefer the smallest fan-out and minimize delegation
cost. Optimize time to integrated, qualified outcomes while preserving the
plan's scope, safety, provenance, and acceptance requirements.

Do not change the user's global skill. Do not rely on same-name skill shadowing:
this skill deliberately has the distinct name `crabc-orchestrate`. The root
plan and `AGENTS.md` must explicitly route this campaign here. Include the exact
local path and applicable policy in every self-contained child brief.

## 1. Root ownership and model routing

The user's **GPT 6 Astra** session is the root coordinator. Retain the user's
selected root reasoning effort. Keep root attention on the critical path,
shared architectural decisions, conflicting evidence, unblock actions, and
final acceptance. Delegate implementation, routine review, and execution.

Use the following project-authorized routing. These identifiers come from the
user's current orchestration policy; verify their availability in the actual
harness. Do not silently substitute an unknown alias or unsupported effort.

| Work | Model | Effort |
| --- | --- | --- |
| Working area owner; difficult ownership/ABI/concurrency design; critical-path integration; high-risk independent review | `gpt-6-astra` | `medium` for difficult reasoning; `low` for bounded follow-through |
| General implementation, debugging, tests, component review, integration execution | `gpt-5.6-terra` | `xhigh`; `max` for a genuinely demanding supported task |
| Read-only inventory, bounded log extraction, straightforward execution/result collation | `gpt-5.6-luna` | `low` |
| Mechanical edits with an unambiguous specification and proportionate checks | `gpt-5.6-luna` | `xhigh` |

Use Astra implementers directly when a hard shared contract or correctness
problem lies on the critical path. Do not insist on several failed cheaper
attempts first. Conversely, do not assign routine collection work to an Astra
owner while a Terra/Luna execution slot can do it correctly.

Preserve the user's parent-intelligence boundary: no child above its parent.
Astra area owners may delegate only within explicitly assigned budgets; Terra
and Luna workers do not escalate by spawning Astra. Escalation goes to root.
Sol (`gpt-5.6-sol`) and GPT-5.5 (`gpt-5.5`) remain prohibited, including fallbacks.

Every spawn specifies `model`, `reasoning_effort`, and `fork_turns` explicitly.
Use `fork_turns: "none"` with a self-contained brief unless a small explicit
turn count is actually necessary. Do not copy the entire campaign history into
each child. Check that any selected custom-agent configuration does not
silently override the intended model or reasoning effort.

## 2. High useful parallelism is the default

Recommended campaign configuration: **48 concurrent child-thread slots,
excluding the primary coordinator**. Begin with a useful working set of about
**24–32 children**, then grow toward 48 when dependency-ready ownership and
integration capacity justify it. This is a scheduling recommendation, not a
claim about the installed harness's current limits or measured optimal width.

Discover and respect the effective session/backend limit. A Markdown file
cannot raise a runtime cap. Use the supported project configuration when
available; report a lower effective cap once and work efficiently within it.
Do not bypass a limit by creating unbudgeted agent trees or external sessions.

An illustrative 32-child working set is four Astra working area owners,
twenty-four Terra implementation/review workers, and four execution,
integration, or triage workers. These are movable allocations, not permanent
positions. Keep at least roughly two-thirds of occupied capacity on substantive
implementation/integration while that work remains; shift toward qualification
as the code converges. Area owners must also deliver code, design decisions,
or substantive reviews, not merely relay status.

Astra working areas normally cover runtime/family closure, allocator substrate,
allocator engine/lifecycle, and loader/unwinder/consumer integration. Give each
an exact domain and interface boundary. They do not all reread/audit the whole
repository. Root can combine these roles when the effective cap is small.

Do not leave slots unused solely to honor the global skill's smallest-fan-out
preference. Do leave them unused when there is no genuinely independent useful
work, the queue is backpressured, or resources/permissions prevent execution.
Agent occupancy is not a deliverable.

### One global budget, including descendants

Root owns the global count of open child threads and task assignments. Count
area owners, reviewers, waiting workers, and nested descendants, not just
leaf implementers. Close idle finished threads after preserving their result.

Default to root-spawned workers with area-owner oversight; this works without
nested-delegation support. Where the harness supports nested delegation and
root can account for it, root may grant an area owner a bounded child budget
and exact domain. Maximum organizational depth is root -> area owner -> worker.
No worker creates grandchildren; no lead allocates its own unlimited budget.
Unused budget is returned to root. This policy never overrides a platform cap.

## 3. Dispatch continuously, not in lockstep waves

Start obvious dependency-ready work during the initial targeted inspection.
Do not make all implementation wait for a complete repository map, a new
scheduler, resource-tuning project, or every area owner's report.

Maintain a small rolling ready queue. At each meaningful completion, blocker,
or dependency change:

1. Integrate/review ready results or assign the next concrete reviewer.
2. Release newly ready implementation and qualified-stage work.
3. Refill useful free capacity with nonoverlapping assignments.
4. Adjust execution/review capacity when that queue is the bottleneck.

Do not wait for every member of a wave to finish. Let long-running stress,
qualification, or a difficult ownership fix coexist with other implementation.
Preserve a live frozen cohort while the integration branch advances.

Keep one compact board in the existing coordination surface or under
`.work/coordination/`. Root or its designated single writer owns it. Workers
write their own result files and send a pointer; they do not concurrently edit
one shared Markdown/JSON file. Do not build a task database or scheduling daemon.

## 4. Assignment contract

Give each worker one coherent outcome and the following minimal information:

```text
Outcome / existing requirement:
Base commit and exact prerequisite commits or interfaces:
Writable files or semantic regions; shared-file owner:
Relevant source/oracle and nearest existing implementation/tests:
Required focused checks; intended product/backend and evidence level:
Resource class and permission boundaries:
Deliverable / stopping condition / result location:
Delegation budget: none unless explicitly granted.
Read plan.md and .agents/skills/crabc-orchestrate/SKILL.md.
```

A good task owns a complete source transition plus its tests and integration
adapter. A bad task adds one more artificially narrowed witness while leaving
the same generic behavior unimplemented. Another bad task asks a scout, coder,
tester, documentation writer, and verifier to serially hand off one change.

Use existing source maps and capability/milestone inventories. Distinguish
missing behavior, missing evidence, and external qualification. Do not infer
that an entire implementation is absent from a `partial` family status.

The child stops when its deliverable is ready for integration or a precise
external dependency blocks its remaining work, not when the whole goal is
complete. Completed slices should be committed as authorized by the plan.
A child's completion never claims joint campaign completion.

## 5. Ownership without unnecessary serialization

Each active mutable region has one owner. Allocate by module, source-defined
state transition, or explicit disjoint symbol group, not a broad directory
reservation that needlessly excludes other work. Each code-writing worker has
an isolated repository-local worktree and private mutable build state.

Shared hotspots—such as the native dispatcher, crate feature manifests, central
ABI selection, the parity ledger, or shared allocator lifecycle roots—have a
named owner. Other workers return the small required patch or precise request
to that owner. The owner must integrate these requests promptly; it is not a
reason to leave everyone waiting for an entire subsystem to finish.

Independent work in different worktrees may propose disjoint edits to one file
only when the semantic regions are explicitly agreed in advance. The shared
owner integrates and verifies the composition. Never assign two workers to
independently redesign the same interface or concurrency protocol.

Publish small shared-interface changes early. Give dependent workers exact
prerequisite refs; avoid generic abstraction layers created only to make the
work split easier. Rebase when relevant dependencies change or at integration,
not automatically for every documentation/main commit.

## 6. Integration is a staffed lane

The author owns focused implementation checks. An assigned reviewer owns the
substantive diff review. An execution owner owns merged-tree or frozen-cohort
runs. Root approves cross-cutting decisions and final promotion rather than
repeating all three jobs.

Root may delegate local cherry-picks/merges to one integration operator, with
one writer on the integration branch. Routine reviewed slices may land without
root line-by-line re-review. Ownership/ABI/atomic/loader/unwinder boundaries
need the relevant high-capability owner or independent review; promotion stays
with root. No remote pushes or destructive cleanup are implied.

Batch a few compatible ready patches to amortize a merged build, keeping
meaningful commit boundaries. Do not wait for all lanes to finish or create a
large unreviewed merge avalanche. Check the union of affected boundaries after
integration. A semantic conflict requires owner review and relevant reruns.

When the ready-to-merge backlog persistently grows, assign existing workers to
review/integration/failure repair instead of increasing producer fan-out.
Avoid unbounded stale branches and an accumulating queue of untested changes.

## 7. A separate host execution budget

Agent threads are not CPU tokens. One coordinator-appointed execution owner
admits heavyweight jobs using observed effective CPUs, memory limits/peaks,
and IO capacity. Root reasoning and light code edits can continue while the
host build queue is full.

Use these starting rules, then adjust from actual logs rather than guessed
machine capacity:

| Job class | Admission rule |
| --- | --- |
| Searches, edits, bounded inspection | No heavy-job token; avoid unlimited parallel scans. |
| Small host/unit/reader tests | Bounded pool within the effective CPU/memory budget. |
| Product build, LTO link, upstream suite, large model/stress run | Explicit heavy-job slot. Start with one when memory is unknown; use two or more only when measured headroom permits. |
| Qualified performance | Exclusive, otherwise uncontended qualification host for the required measurements. |
| Hardware-qualified huge-page/NUMA job | Authorized topology/resources and its own reservation; never repeat an unchanged denied operation. |

Budget inner and outer parallelism together. Explicitly bound Cargo, Make/Ninja,
compiler, test-worker, and stress concurrency using supported controls. Do not
launch N jobs each assuming it owns every core. Rebalance when links/OOMs,
scheduler contention, or IO saturation reduce completed work.

Use persistent private targets per active writer. Reuse verified immutable
product cohorts and safe private cache seeds under accepted containment.
Never share one writable Cargo target across the entire fleet, mutate a sealed
product, use hard-linked mutable caches, or warm a required independent clean
reproducibility build. Keep pinned runtime and allocator lanes distinct.

Use an existing execution queue or a tiny single-owner board. A helper script
is justified only for an observed repeated race or scheduling error and must
have a bounded tested purpose. Do not spend a campaign building infrastructure.

## 8. Evidence and reviews without duplication

Apply the development/integration/qualification levels in `plan.md`. Check
changed behavior now; reserve full suites for real admission/integration
checkpoints. A worker need not rerun unrelated accepted suites because it
updated a comment. Final exact-source requirements remain unchanged.

One authoritative execution can serve multiple appropriate consumers through
an authenticated immutable receipt. Independent reconstruction is useful;
blindly rerunning the same job three times as three approvals is not. Preserve
required independent reproducibility builds, stochastic/stress runs, oracle
arms, and the explicitly required repeated performance scorecards.

For a producer/reader or dispatcher change, run a minimal real public
round-trip before an expensive aggregate. For unsafe/state-machine changes,
review the actual invariant and adversarial behavior, not just receipt shape.
Source/reference pinning is not a substitute for runtime correctness.

Workers return a compact result:

```text
Result: ready / partial / blocked / failed
Commit(s), base, and changed ownership boundary:
Behavior implemented or exact requirement closed:
Checks: commands, outcomes, source/product identities, report paths:
Remaining risk/dependency and integration instructions:
```

Usually a few paragraphs suffice. Detailed raw evidence stays in its artifact,
not in the root conversation or a new multi-page handoff. Do not copy large
logs into every area owner's context.

## 9. Escalation, blocked work, and cancellation

Escalate a genuinely hard invariant/architecture problem to root or an Astra
owner with the exact failing case, relevant source, attempted approaches, and
remaining uncertainty. After two materially different failed fixes to the same
well-understood failure, reassess ownership/model/approach rather than spawning
another fresh agent to rediscover it. Missing packages, ordinary command
mistakes, and unavailable hardware are not model-escalation reasons by themselves.

A genuine tool/system denial is binding. Preserve the exact action and
diagnostic and seek the supported external review. Do not reroute it through
another model, worker, shell, container, or tool. A historical label without a
diagnostic is not license to invent either a blanket ban or a blanket override.

Cancel only demonstrably obsolete/duplicate work or a job whose inputs are
known invalid, preserving diagnostics and owned process cleanup. Do not kill
a useful frozen qualification merely because main advances. Avoid repeated
status polling, unchanged reruns, and reassignments that discard accumulated
context. Idle external-blocked workers return their slot and resumable state.

## 10. Convergence

As implementation closes, shift capacity from producers to independent
integration, stress, remaining family admission, source-map/purity checks,
and resource-qualified final runs. This is not permission to manufacture more
implementation tasks to keep a large fleet busy.

Root calls the goal complete only through the exact joint predicate in
`plan.md` and the two detailed contracts. All required final source-bound
results refer to the same clean committed revision with the native backend
selected. A large fleet, clean build, many commits, or a stack of standalone
passes is not the completion predicate.
