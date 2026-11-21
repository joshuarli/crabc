# crabc

A small, auditable modern Unix runtime: a Rust `no_std` libc, dynamic linker,
owned CRT and compiler builtins, and an idiomatic `crabc-rs` facade. Narrow
scope must not weaken ordinary Unix semantics.

## Current direction — 2026-11-17

Read [Status](plan.md#status-and-first-action) and [F2 closeout](plan.md#f2-closeout) before dispatch. The active candidate and phase govern.
Feature completeness comes first; performance and memory budgets are waived until then. See [campaign rules](docs/lanes.md#campaign-operating-rules).
User direction governs, then [docs/scope.md](docs/scope.md) and [COMPATIBILITY-PROFILE.md](COMPATIBILITY-PROFILE.md), then `plan.md`.
This is a local, undeployed greenfield libc: crash reproduction, fault injection, fuzzing and differential tests on repository-owned code are defensive correctness work ([local correctness work](docs/scope.md#local-correctness-work)).

## Commands

Run focused builds and native tests in the pinned x86 images. See [check environments](docs/lanes.md#check-environments).

```sh
scripts/lanes/rust-check.sh cargo check -q --locked -p <non-allocator-crate>
python3 -B scripts/test_python.py --module <dispatcher_test.py>
scripts/lanes/rust-check.sh python3 -B scripts/test_python.py --module <toolchain_test.py>
python3 compat/x86_64/validate_parity_ledger.py
./scripts/dev-x86_64.sh campaign-status
./scripts/dev-x86_64.sh qualification-candidate --work .work/x86_64/feature-complete --profile correctness
./scripts/dev-x86_64.sh --help
```

## Invariants

- Linux, little-endian, kernel 5.10 or newer; no older-kernel fallbacks, new architectures or portability layers.
- The exact `[musl_native]` snapshot in `compat/upstreams.toml` is the native C/POSIX oracle for both targets; glibc is neither oracle nor fallback, rustix is a test oracle only, and candidate artifacts borrow no ambient musl, CRT, runtime, header or loader input.
- Do not invent allocators; preserve the port's source and provenance and the selected C backend's unchanged upstream source. A historical milestone does not authorize native-default promotion.
- Never implement cryptographic primitives locally; attributed musl `random` is the sole legacy exception, never for security or entropy.
- Support only `C`, `POSIX` and `C.UTF-8` locales; unsupported names fail honestly. Consume conventional system files; no NSS/PAM plugins, bundled databases or DNS beyond the selected bounded profile.
- Provide synchronous mechanisms, not frameworks, executors, provider/plugin systems or hypothetical backends. Coarse features require a real product/dependency boundary, not a proof per symbol.
- Expose OS mechanisms idiomatically in `crabc-rs`, not every C symbol; preserve its direct `crabc-core` path where appropriate.
- Document concrete caller obligations for every public unsafe API; never create references with unsupported aliasing or lifetime promises.
- Preserve selected hardening, exact upstream revisions, source mappings, licenses, raw failures and behavioral coverage. D23 waives cost gates, not correctness checks; never rewrite upstream workloads to hide a defect.
- Tests exercise behavior; validators check shared structure and actual evidence. No per-artifact validators, source-literal/prose-count tests, duplicate status files or report/receipt frameworks.
- AArch64 runs only natively in its arm64 Linux VM, never emulated or on a macOS bind mount.
- Do not run `./scripts/dev-x86_64.sh image` unless a plan step says so; a rebuild must be followed by a re-pin of `compat/x86_64/core_image.py`.
- Never hand-edit generated `COMPATIBILITY.md`; old AArch64 manifests and their digested inputs are superseded by CRAB-8 evidence and never refreshed to absorb drift.

## Where things are

| Topic | Owner |
| --- | --- |
| Active sequence, freeze, acceptance and retained holds | [plan.md](plan.md) |
| Scope, oracles, dependencies and safety | [docs/scope.md](docs/scope.md) |
| Selected behavior and hardening | [COMPATIBILITY-PROFILE.md](COMPATIBILITY-PROFILE.md) |
| Active feature completion and separately frozen allocator obligations | [docs/completion-requirements.md](docs/completion-requirements.md) |
| Parallel workstreams, ownership and integration | [docs/lanes.md](docs/lanes.md) |
| Runtime ownership and current wire boundary | [docs/design/architecture.md](docs/design/architecture.md), [dynamic allocator placement](docs/design/x86-dynamic-native-allocator.md) |
| AArch64 convergence; deferred macOS backend | [CRAB-8](docs/rfc/CRAB-8-linux-aarch64-feature-completion.md), [CRAB-7](docs/rfc/CRAB-7-macos-libsystem-backend.md) |
| Rust facade | [docs/design/crabc-rs.md](docs/design/crabc-rs.md) |
| Review backlog and open child-wait decision | [TODO.md](TODO.md), [child-wait RFC](docs/rfc/CRAB-2-child-wait-ownership.md) |
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
| Runtime and loader | `libc/`, `ldso/`, `crt/`, `builtins/` |
| Rust and allocator | `crabc-core/`, `crabc-rs/`, `crabc-mimalloc/`, `compat/allocator/` |
| Other code and evidence | `unwinder/`, `include/`, `tests/`, `compat/x86_64/` |
| Pins | `rust-toolchain.toml`, `compat/upstreams.toml`, target Dockerfiles |
