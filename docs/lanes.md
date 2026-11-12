# Campaign lanes

[plan.md](../plan.md) owns the active feature-completion campaign. The owner's
2026-11-12 direction replaces the serial simplification campaign: finish the
selected native x86-64 runtime with sustained parallel implementation,
behavioral review and integration. All performance and memory-efficiency gates
are waived until full feature completeness. Correctness, memory safety, ABI,
ownership and selected hardening remain mandatory.

The Rust allocator port and its private harness remain frozen; the pinned C
backend's crabc integration is open for functional fixes. Preserve AArch64
without executing or emulating it. The exact boundaries remain in
[scope.md](scope.md) and [plan.md](../plan.md#allocator-freeze).

## Roles and width

The coordinator maintains a ready queue, assigns explicit file ownership,
resolves dependency and interface questions, reviews integration, and alone
updates `plan.md` and `AGENTS.md`. Workers implement complete behavior slices;
reviewers independently challenge semantics, liveness, safety and coverage.
Use the available native multi-agent or existing `orchestrate` facilities and
retain their bridge tiers/routing where available. The current owner direction
supersedes serial defaults and any `perf-gate-ready`/quiet-host headroom
prerequisite for parallel dispatch. Do not create new repository-specific agent
types, a scheduler or a receipt system.

**Fill every available agent slot with ready implementation, review or focused
validation work.** Refill a slot when a lane finishes or blocks; do not wait for
all members of a batch. The lane pool below is deliberately wider than a small
harness's concurrency cap. With more capacity, split independent file sets and
test matrices; with fewer slots, run successive waves from the same queue.
Respect actual tool/provider limits and the configured caps (Codex 16, Claude
24); these are ceilings, not reasons to invent work. Idle capacity needs a
concrete reason such as no independent ready work or exhausted build resources,
not the old preference for a narrow campaign.

Agent parallelism and build parallelism are separate. Keep reasoning, coding
and review lanes running while queuing heavy native builds to fit the host.
Reuse the pinned image and warm caches. Give concurrent test processes separate
output directories where the existing commands support them; otherwise serialize
those commands. Do not overlap writers in one worktree or corrupt a shared
build/output directory to inflate concurrency. Resource scheduling prevents
failed runs; it does not reinstate a runtime memory or performance target.

## Ready queue and dependency handling

Use one compact table in `plan.md`: item/behavior, owner, allowed files,
prerequisites, next check, and state (`ready`, `running`, `review`, `integrating`,
`done`, or `blocked` with the exact dependency). No second tracking framework.

1. Read the existing parity families, capability coverage, current failing
   behavioral cases and consumer results. Turn each unresolved selected
   behavior into an implementable work item. Existing evidence avoids duplicate
   work; a `foundation-verified` slice is not proof of complete family behavior.
2. Start independent items immediately. Prioritize prerequisites that unblock
   several consumers, then high-value missing behavior and real regressions.
   Do not spend a whole wave producing inventories or plans before coding.
3. `depends_on` in `compat/x86_64/parity.toml` constrains integration and final
   qualification. It does not forbid downstream implementation against an
   agreed existing interface while another lane finishes its prerequisite.
   `campaign-status`/`next_dependency_ready_transitions` describes family
   acceptance order, not the whole implementation queue. Never count mocks or
   partial dependency fixtures as final consumer evidence.
4. When lanes need the same file, give it one writer. The other lane submits a
   small requested interface change, then continues independent work. Split
   broad family ownership into explicit files before dispatch; a directory in
   the table below is a routing hint, not a blanket write grant.
5. Review and integrate completed slices continuously. A blocked lane reports
   its failing case and exact dependency, then takes another ready item; an
   unrelated failure never stalls the entire campaign.

## Parallel lane pool

Select work from actual remaining obligations; do not reopen completed behavior
just to occupy a named lane. The coordinator can split or combine these lanes
to match available capacity and file ownership. Starting checks below name
existing `./scripts/dev-x86_64.sh` dispatcher commands; use the focused cases
for the brief, not every command on every edit. They are routes to evidence,
not claims that an area is missing or already complete.

| Lane | Existing owners and families | First useful result / integration dependency | Starting checks |
| --- | --- | --- | --- |
| POSIX filesystem and descriptors | `libc/src/c_abi/x86_64/` filesystem, descriptor and directory modules; `libc.posix-runtime` | Close a missing/error-path behavior with ordinary C and applicable Rust-native coverage; coordinate shared errno/cancellation interfaces with threading. | `owned-posix-filesystem`, `owned-posix-composition` |
| Processes, signals and administration | Process, signal, spawn, timer and credential modules; `compat/signal-process/`, `compat/os-test/` | Fix an existing selected process composition or failing upstream case; preserve fork, cancellation and process-wide contracts. | `owned-process-control`, `owned-posix-signals` |
| Threads and TLS | pthread/C11 and thread-runtime modules, `compat/pthread-stress/`; `libc.pthread-tls` | Close lifecycle, synchronization, cancellation or TLS failures; publish shared loader/runtime interface changes through one writer. | `owned-pthread-lifecycle`, `owned-pthread-family` |
| Stdio and formatted I/O | `owned_stdio_*`, `owned_scanf*`, `owned_printf*`, stream modules and their fixtures | Complete stream/format/scan behavior through the shared engine; cover error, lifetime and concurrency paths. | `owned-stdio-file-engine`, `owned-stdio` |
| Text, patterns, locale and time | x86 text/locale/regex/iconv/time modules and their fixtures | Close selected encoding, pattern, locale or time semantics without expanding the bounded profile; partition files from stdio and math. | `owned-regex`, `owned-text-locale-numeric-component` |
| Math and floating-point state | x86 `math_*`, fenv and long-double fixtures | Resolve current numerical/ABI blockers, including the retained `pow` failure, against the pinned oracle; preserve generated assembly and the evidence behind admission holds. | `libc-math-pow`, `owned-math-fenv-all-entry` |
| Resolver and system databases | `owned_resolver_*`, `owned_netdb_*`, resolver modules; `compat/resolver-network/` | Complete controlled-network and conventional-file behavior, cancellation and result lifetime; no live third-party test targets. | `owned-resolver-family`, `owned-resolver-network` |
| Dynamic loader | `ldso/src/x86_64_*`, owned-loader fixtures; `ldso.dynamic-runtime` | Close graph, relocation, TLS, rollback, concurrent `dl*` or hardening behavior; coordinate shared RuntimeV1 changes with threading. | `owned-loader-family`, `hardened-runtime` |
| Headers, CRT, builtins and sysroot | `include/`, `crt/`, `builtins/`, owned sysroot builders | Finish installed declarations, startup modes and target-input closure; split independent headers/builtins work from the single product-builder writer. | `headers-layouts-aggregate`, `owned-crt-dynamic-startup`, `owned-static-sysroot` |
| Rust facade | `crabc-rs/`, corresponding `crabc-core/` mechanisms; `facade.direct`, `facade.record-owning` | Complete selected direct/owning APIs and their semantic mapping; test native paths independently of C ABI success. | `facade`, `facade-record-owning` |
| Rust consumers and unwinding | `compat/rust-std/`, `compat/lto/`, `unwinder/` | Make the real std/build-std/LTO/unwind consumers pass on owned products; report minimal runtime failures to their implementation owners. | `consumer-rust-std-lto` |
| Source consumers and integration coverage | `compat/lua/`, `compat/corpus/`, existing ABI/differential matrices | Make selected source/package workloads pass without rewriting them; run independent consumer preparation and review while runtime fixes land. | `lua-static-source-build`, `lua-dynamic-source-build`, `owned-package-corpus` |

The accepted C backend's lifecycle, initialization and wrapper fixes belong to
the relevant runtime lane. They need a reproducible functional failure or
missing selected behavior, not an R1–R4 cost report. Do not open a Rust allocator,
allocator benchmark, native-shadow or promotion lane under this campaign.

Keep a reviewer and the integration/check pipeline active as implementations
arrive; these roles may rotate when the available cap is small. Qualification
machinery and capability accounting have one shared owner. Correctness harness
repairs are justified by a real blocked behavior, not an opportunity to build
more evidence machinery.

## Brief and worktree contract

Each brief states the selected behavior and completion criterion, exact writable
files, dependencies/interfaces, existing focused tests, repository-owned fixture
isolation, and the allocator/AArch64 boundaries. State that cost measurements
are optional diagnostics and cannot block feature work. A brief must produce
code plus behavioral evidence or a concrete blocker; a report alone is not a
replacement for an implementable task.

Use an existing suitable clean worktree when possible. The coordinator prepares
an isolated worktree for a new stream:

```sh
git worktree add -b lane/<id> .work/wt/<id> main
(cd .work/wt/<id> && scripts/lanes/prepare-worktree.sh)
```

Prepare once, then keep the worktree warm. The helper may copy cached allocator
inputs needed by ordinary products; that does not authorize a private allocator
campaign. Never use `git stash`; the repository's `rebase.autostash` setting
shares state between worktrees. Workers return their diff, focused check results
and blockers without staging, committing, merging or pushing. The coordinator
owns checkpoints, rebases, integration and publication under the owner's current
authorization. Preserve each lane's uncommitted work before changing its base.
When a focused runner requires a clean commit, request an immediate coordinator
checkpoint of that lane's owned changes; do not wait for the whole wave or final
integration. The coordinator services these checkpoints while other lanes keep
working, so clean-source checks do not become a serial implementation barrier.

Removal requires completed custody checks and permission within the current
task. Respect [retained work](../plan.md#preserved-decisions-and-holds). Unique
source, failed evidence and unresolved ignored files survive lane retirement;
no bulk cleanup, branch deletion or unrelated process termination on stop.

## Continuous integration and completion

Follow [plan.md](../plan.md#standard-procedures) and use the pinned native x86
environment. Never run `scripts/dev.sh`, emulate AArch64 or invoke the frozen
allocator runner. Examples for scoped work:

```sh
scripts/lanes/rust-check.sh cargo check -q --locked -p <non-allocator-crate>
python3 -B scripts/test_python.py --module <path/to/test_file.py>
python3 compat/x86_64/validate_parity_ledger.py
./scripts/dev-x86_64.sh campaign-status
./scripts/dev-x86_64.sh qualification-candidate --work DIR --profile correctness
```

Replace placeholders with actual touched crates/tests and a dedicated work
directory. The first command is deliberately scoped: the helper's no-argument
legacy sweep includes frozen allocator profiles. Qualification is a coordinator
checkpoint, not a full run after every leaf edit.

Reproduce a bug with a failing behavior test, implement it, run focused behavior
and applicable hardening checks, and send the coherent patch for review.
The coordinator inspects the diff, resolves shared-file changes, commits and
integrates onto the current tip and reruns affected checks there. Regenerate
derived inventories from resolved inputs; never rewrite frozen AArch64 inputs
or inherit a worker's receipt as proof of a different merged product.

Run correctness checkpoints after coherent integration batches, and one complete
fresh correctness run after the feature queue is closed. Keep other ready lanes
running in their worktrees during these runs. A change invalidating a checkpoint
is tested at the next applicable checkpoint; it does not justify holding all
feature implementation until a global run finishes.

No pre/post benchmark, instruction/syscall ratio, CPU/RSS/allocation/footprint
budget or quiet-host measurement window is required to merge feature work.
Do not pause productive lanes to collect waived metrics. Record optional
observations honestly as diagnostic; missing, failed or deferred performance
evidence is never a pass and never a feature-completion blocker. Memory safety,
valid failure handling, resource ownership and required cleanup remain behavior
obligations, independent of memory-efficiency comparisons.

The exit criteria are in [completion-requirements.md](completion-requirements.md).
Only after that feature milestone may the campaign move to performance/memory
optimization and full release qualification. Feature completion itself does
not promote a backend, a target or a public-support claim.
