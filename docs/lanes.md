# Campaign lanes

[plan.md](../plan.md) owns the active feature-completion campaign. The owner's
2026-11-12 direction replaces the serial simplification campaign: finish the
selected native x86-64 runtime with sustained parallel implementation,
behavioral review and integration. All performance and memory-efficiency gates
are waived until full feature completeness. Correctness, memory safety, ABI,
ownership and selected hardening remain mandatory.

Read [Status](../plan.md#status-and-first-action) first. Its active candidate and
phase override dispatch guidance here. In F2 closeout, reconcile that attempt
and use only the demonstrated blocker, review and acceptance work in
[F2 closeout](../plan.md#f2-closeout).
The implementation pool below is not a queue to restart at every resume.

The Rust allocator port and its private harness remain frozen; the pinned C
backend's crabc integration is open for functional fixes. AArch64 convergence runs on branches and natively in its own Linux VM; never
emulate it. The exact boundaries remain in
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

**During F0/F1, fill useful available slots with ready implementation, review or
focused validation work.** Refill a slot when a lane finishes or blocks; do not
wait for all members of a batch. The lane pool below is deliberately wider than a small
harness's concurrency cap. With more capacity, split independent file sets and
test matrices; with fewer slots, run successive waves from the same queue.
Respect actual tool/provider limits and the configured caps (Codex 16, Claude
24); these are ceilings, not reasons to invent work. Idle capacity needs a
concrete reason such as no independent ready work or exhausted build resources,
not the old preference for a narrow campaign.

During F2, keep one fixed acceptance candidate. Assign independent demonstrated
blockers and their review in parallel where useful; do not reopen completed
families to fill slots. If no independent selected blocker is ready, leave
unused capacity idle. While acceptance runs, open no other acceptance attempt
or unrelated lane.

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
python3 -B scripts/test_python.py --module <dispatcher_test.py>
scripts/lanes/rust-check.sh python3 -B scripts/test_python.py --module <toolchain_test.py>
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
fresh correctness run after the feature queue is closed. During F0/F1, keep other
ready lanes running in their worktrees during checkpoints. A change invalidating
a checkpoint is tested at the next applicable checkpoint; it does not justify holding all
feature implementation until a global run finishes.
For F2, finish known repairs and their producer/publication/reader checks before
the fresh run. Keep that candidate checkout unchanged throughout qualification;
record progress elsewhere. A later status-only commit names the tested SHA
without restarting qualification or relabeling its evidence.

No pre/post benchmark, instruction/syscall ratio, CPU/RSS/allocation/footprint
budget or quiet-host measurement window is required to merge feature work.
Do not pause productive lanes to collect waived metrics. Record optional
observations honestly as diagnostic; missing, failed or deferred performance
evidence is never a pass and never a feature-completion blocker. Memory safety,
valid failure handling, resource ownership and required cleanup remain behavior
obligations, independent of memory-efficiency comparisons.

The exit criteria are in [completion-requirements.md](completion-requirements.md).
At that feature milestone, report acceptance and stop this campaign.
Performance/memory optimization and full release qualification are a separate
follow-up. Feature completion itself does not promote a backend, a target or a
public-support claim.

## Campaign operating rules

**Feature completeness first; all performance and memory budgets waived until
then; independent work runs in parallel.** The owner's D23/D24 decisions in
[plan.md](../plan.md) supersede the old simplification/serial-first campaign and
mandatory cost measurements. S0–S5 are accepted; do not repeat them as a
prerequisite to implementing the selected native x86-64 surface.

Read [Status](../plan.md#status-and-first-action) before dispatch. Its active
candidate and phase take precedence over general parallel-work instructions.
Follow [F2 closeout](../plan.md#f2-closeout), starting with that candidate's actual
result. While it runs, keep it fixed and open no other acceptance attempt or
unrelated lane. Do not restart F0/F1 or invent work to fill slots.
During F0/F1, dispatch independent selected behavior work and integrate it
continuously. F2 requires one fresh seven-gate correctness run and ends this
feature campaign. F3 is a separate follow-up, not an automatic continuation.
Default qualification is `correctness`; `performance.release` stays explicitly
deferred. A parked receipt or status count never proves a current-source
capability or full-chain result.

No CPU/time, instruction, syscall-count, RSS/PSS/peak-memory, allocation,
footprint or old numerical reduction budget blocks F0–F2. No mandatory
before/after benchmark, quiet host or performance tool is needed. Correctness,
memory safety, ABI/errno/TLS/cancellation semantics and hardening remain binding.
Keep one owner for process-global state, thin C ABI adaptation and direct native
syscall/vDSO paths; implement the simplest complete behavior before tuning it.

The pinned C mimalloc v3.5.0 backend remains selected. Its crabc glue is open
for feature integration and correctness fixes backed by focused behavior tests;
an R1–R4 failure is no longer required to start that work. Upstream C source
stays unedited. The Rust allocator port, its harness/receipts, shadow products,
alternate allocators and promotion remain frozen under
[Allocator freeze](../plan.md#allocator-freeze).

During feature implementation, fill useful available slots within the actual
harness limits. During closeout, assign only demonstrated remaining blockers,
their review and acceptance; keep the candidate checkout fixed. Use
component-sized tasks, isolated worktrees, explicit file ownership and independent
review; keep the feature queue replenished while the coordinator integrates.
Family acceptance dependencies do not serialize independent implementation. Read
[docs/lanes.md](lanes.md) before delegating. Use existing orchestration
routing and helpers; this owner direction overrides their serial-first and
performance-readiness scheduling defaults. Keep status small; Git is history.

The active target is native Linux/x86-64 on an x86-64 host. Linux/AArch64,
the public target, is converging onto the same runtime under the accepted
[CRAB-8](rfc/CRAB-8-linux-aarch64-feature-completion.md): it runs only
natively in an arm64 Linux VM with its own disk on the Apple Silicon host,
never emulated and never on a macOS bind mount. Until x86 F2 is accepted,
AArch64 work stays on branches; nothing touching the x86 product source seal
(including `docker/`) merges. The macOS facade backend (CRAB-7) is deferred.


## Check environments

The commands are listed in [AGENTS.md](../AGENTS.md#commands).

Python harness modules have two homes. Modules that drive the dispatcher or
container launcher (`*_dispatch*`, promotion phases, the resolver network
gate) run on the host. Modules that compile or inspect objects need the
image's `gcc`, binutils and pinned Rust toolchain; run them through
`rust-check.sh` from a worktree prepared by `scripts/lanes/prepare-worktree.sh`.
A missing-tool failure on the host or a path/Docker failure in the image is
the wrong environment, not a pass; rerun the module where it belongs.
The placeholders above require the actual touched crate/test. Full legacy
profile checks are regression tools, not permission to run allocator campaigns.
The full correctness command is the integrated milestone, not a per-edit loop.
Performance commands in [compat/perf/README.md](../compat/perf/README.md) are
deferred from required work until feature completeness. Do not invent command support.
Do not run `./scripts/dev-x86_64.sh image` unless a plan step says so: a
rebuild changes the image ID and must be followed by a re-pin of
`compat/x86_64/core_image.py`.

### Reproducible core image

`./scripts/dev-x86_64.sh image` builds the x86-64 core-evidence image from
`docker/image/sources.lock.json`, not from `docker build`. `docker/image/build.py`
runs inside the digest-pinned builder recorded in the lock and works in two
phases so the network boundary is real: `fetch` downloads and verifies every
locked input, then `assemble` runs with the network off, installs the exact
locked `.apk` closure into a chroot offline (apk verifies each package
signature), installs the pinned Rust toolchain from a loopback dist server that
serves only locked files, and builds the pinned musl trees and Linux 5.10 UAPI
headers. It emits a normalized rootfs tar and a single-layer OCI layout whose
manifest digest is the image ID, then loads it.

Two cold builds from the same lock produce the same image ID;
`./scripts/dev-x86_64.sh image-repro` builds twice into fresh output roots and
fails unless the IDs match. Every byte comes from the lock: the Alpine
minirootfs per stage, each stage's resolved `.apk` closure, the Rust channel
manifest and component archives, the native musl oracle source, kache, and the
Linux UAPI source. `docker/image/lock.py` regenerates the lock deliberately
(network required) from `docker/image/mirrors.json`, `compat/upstreams.toml`
and `rust-toolchain.toml`, and stages every locked file under `.work/image-mirror`
for publishing. Mirror templates in `mirrors.json` are tried before each
input's upstream URL. Do not hand-edit the lock.
