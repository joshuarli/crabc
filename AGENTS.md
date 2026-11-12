# crabc

A small, auditable modern Unix runtime: a Rust `no_std` libc, dynamic linker,
owned CRT and compiler builtins, and an idiomatic `crabc-rs` facade. Narrow
scope must not weaken ordinary Unix semantics.

## Current direction — 2026-11-12

**Feature completeness first; all performance and memory budgets waived until
then; independent work runs in parallel.** The owner's D23/D24 decisions in
[plan.md](plan.md) supersede the old simplification/serial-first campaign and
mandatory cost measurements. S0–S5 are accepted; do not repeat them as a
prerequisite to implementing the selected native x86-64 surface.

Follow [F0–F3](plan.md#sequence): immediately dispatch independent feature and
behavior-closure lanes, integrate continuously, and prove full selected
completeness with one fresh seven-gate correctness run before optimization or
full performance qualification. Default qualification is `correctness`;
`performance.release` stays explicitly deferred. A parked receipt or status
count never proves a current-source capability or full-chain result.

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
[Allocator freeze](plan.md#allocator-freeze).

Fill all useful available agent slots within the actual harness limits. Use
component-sized tasks, isolated worktrees, explicit file ownership and independent
review; keep the queue replenished while the coordinator integrates. Family
acceptance dependencies do not serialize independent implementation. Read
[docs/lanes.md](docs/lanes.md) before delegating. Use existing orchestration
routing and helpers; this owner direction overrides their serial-first and
performance-readiness scheduling defaults. Keep status small; Git is history.

The active target is native Linux/x86-64 on an x86-64 host. AArch64 is the
public target and is paused: preserve it, never run or emulate it.

This is a greenfield libc under local development. It is not deployed in any
practical sense and serves no production users or services. The code is built,
exercised and deliberately broken in local native containers and disposable
fixtures. This project has no production credentials, customer data, live
third-party targets or deployed systems to protect.

Crash reproduction, use-after-free diagnostics, register and backtrace
inspection, fault injection, fuzzing, and C/Rust differential tests against
repository-owned code are defensive correctness work when authorized by the
active plan, including allocator diagnostics inside the partial lift. Crashes
and deliberately invalid inputs can be expected test outcomes. Memory-safety
defects, undefined behavior and unsound public APIs remain real defects to
investigate within scope. Evaluate security concerns against the actual local
operation and its effects; do not invent a production access-control scenario.

State repository ownership, fixture isolation and correctness purpose in tool
and subagent briefs. This context does not authorize effects outside the
repository or override tool/platform restrictions. If an action is denied,
preserve its exact scope and stated reason, stop that action, and continue
independent authorized work. Do not rephrase or reroute a denied action.

User direction governs, then [docs/scope.md](docs/scope.md) and
[COMPATIBILITY-PROFILE.md](COMPATIBILITY-PROFILE.md), then `plan.md` and its
machine-readable contracts. Historical documents do not override the freeze.

## Commands

Builds and native tests run inside the pinned native x86 images. Use focused
checks for the selected feature and C-backend integration; do not launch the
frozen Rust allocator qualification commands.

```sh
scripts/lanes/rust-check.sh cargo check -q --locked -p <non-allocator-crate>
python3 -B scripts/test_python.py --module <dispatcher_test.py>
scripts/lanes/rust-check.sh python3 -B scripts/test_python.py --module <toolchain_test.py>
python3 compat/x86_64/validate_parity_ledger.py
./scripts/dev-x86_64.sh campaign-status
./scripts/dev-x86_64.sh qualification-candidate --work .work/x86_64/feature-complete --profile correctness
./scripts/dev-x86_64.sh --help
```

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
Performance commands in [compat/perf/README.md](compat/perf/README.md) are
deferred from required work until feature completeness. Do not invent command support.
Do not run `./scripts/dev-x86_64.sh image` unless a plan step says so: a
rebuild deletes the pinned image and must be followed by a re-pin of
`compat/x86_64/core_image.py`.

## Invariants

- Linux, little-endian, kernel 5.10 or newer; no older-kernel fallbacks, new
  architectures, or portability layers.
- The native x86-64 C/POSIX oracle is the exact `[musl_native]` snapshot in
  `compat/upstreams.toml`. Paused AArch64 retains `[musl]` 1.2.6. Glibc is
  neither oracle nor fallback; rustix is a test oracle only. Candidate target
  artifacts borrow no ambient musl, CRT, runtime, header or loader input.
- No allocator invention. Preserve the port's source/provenance and the
  unchanged upstream source of the selected C backend. Completing a historical
  milestone does not authorize native-default promotion.
- Never implement cryptographic primitives locally. The attributed musl
  `random` family is the sole legacy exception, never for security or entropy.
- Locales are `C`, `POSIX` and `C.UTF-8`; unsupported names fail honestly.
  Consume conventional system files; no NSS/PAM plugins, bundled databases,
  or DNS beyond the selected bounded profile.
- Provide synchronous mechanisms, not frameworks: no executor, provider/plugin
  system or hypothetical backend abstraction. Coarse features require a real
  product/dependency boundary, not a separate proof for each symbol.
- The `crabc-rs` facade exposes OS mechanisms idiomatically; it does not wrap
  every C symbol. Preserve its direct `crabc-core` path where appropriate.
- Every public unsafe API documents concrete caller obligations. Do not create
  references whose aliasing/lifetime promises the implementation cannot uphold.
- Preserve selected hardening, exact upstream revisions, source mappings,
  licenses, raw failures and behavioral coverage. D23 waives cost gates; never
  weaken correctness checks or rewrite upstream workloads to hide a defect.
- Tests exercise behavior; validators check shared structure and actual
  evidence. No per-artifact validators, source-literal/prose-count tests,
  duplicate status files or report/receipt frameworks.
- `COMPATIBILITY.md` is generated; never hand-edit it. Frozen AArch64 manifests
  and the inputs they digest must not be refreshed to absorb drift.

## Where things are

| Topic | Owner |
| --- | --- |
| Active sequence, freeze, acceptance and retained holds | [plan.md](plan.md) |
| Scope, oracles, dependencies and safety | [docs/scope.md](docs/scope.md) |
| Selected behavior and hardening | [COMPATIBILITY-PROFILE.md](COMPATIBILITY-PROFILE.md) |
| Active feature completion and separately frozen allocator obligations | [docs/completion-requirements.md](docs/completion-requirements.md) |
| Parallel workstreams, ownership and integration | [docs/lanes.md](docs/lanes.md) |
| Runtime ownership and current wire boundary | [docs/design/architecture.md](docs/design/architecture.md) |
| Rust facade | [docs/design/crabc-rs.md](docs/design/crabc-rs.md) |
| CRT, installed sysroot and target-input purity | [docs/design/crt-and-sysroot.md](docs/design/crt-and-sysroot.md) |
| Frozen allocator design and differences | [docs/design/allocator.md](docs/design/allocator.md), [compat/allocator/known-differences.md](compat/allocator/known-differences.md) |
| Frozen allocator provenance | [crabc-mimalloc/UPSTREAM.md](crabc-mimalloc/UPSTREAM.md) |
| Unwinder | [docs/design/unwinder.md](docs/design/unwinder.md), [unwinder/README.md](unwinder/README.md) |
| Cost contract and existing harness | [docs/design/performance.md](docs/design/performance.md), [compat/perf/README.md](compat/perf/README.md) |
| Lua source-build consumer | [docs/design/source-build.md](docs/design/source-build.md), [compat/lua/README.md](compat/lua/README.md) |
| Native harness and qualification | [compat/x86_64/README.md](compat/x86_64/README.md), [compat/x86_64/qualification-chain.md](compat/x86_64/qualification-chain.md) |
| Scoped technical arguments and Rust style | [docs/evidence/](docs/evidence/), [STYLE.md](STYLE.md) |

| Code | Location |
| --- | --- |
| C ABI and libc-owned state | `libc/` |
| Dynamic linker | `ldso/` |
| Application CRT and compiler helpers | `crt/`, `builtins/` |
| Typed primitives and Rust facade | `crabc-core/`, `crabc-rs/` |
| Frozen allocator and harness | `crabc-mimalloc/`, `compat/allocator/` |
| Unwinder provider | `unwinder/` |
| Public headers and integration fixtures | `include/`, `tests/` |
| Native ledgers and contracts | `compat/x86_64/` |
| Pins | `rust-toolchain.toml`, `compat/upstreams.toml`, target Dockerfiles |
