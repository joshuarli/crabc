# crabc

A small, auditable modern Unix runtime: a Rust `no_std` libc, dynamic linker,
owned CRT and compiler builtins, and an idiomatic `crabc-rs` facade. Narrow
scope must not weaken ordinary Unix semantics.

## Current direction — 2026-10-30

**Radical non-allocator simplification comes first. All malloc/allocator work
is frozen.** Start with S0 in [plan.md](plan.md), the only active implementation
plan. The old qualification/promotion campaign is parked, not ready to resume.

Do not work on the Rust mimalloc port, the accepted C backend, allocator fixes,
cleanup, benchmarks, tests, receipts, shadow integration, alternate allocators
or promotion. Do not merge parked allocator work or call it a prerequisite.
Preserve the unchanged accepted C backend and all allocator evidence. Ordinary
runtime builds and regression checks may use it; record allocator failures
without starting an investigation. The exact boundary and restart condition are
in [Allocator freeze](plan.md#allocator-freeze).

Simplify mechanisms and evidence machinery, not just filenames or prose. Keep
one owner for process-global state, thin C ABI adaptation and direct native
syscall/vDSO paths. Measure against musl early: no additional syscalls, and
retired user instructions <= 1.10 times musl under matched LLVM, alongside
existing CPU/memory and correctness/hardening requirements. These are campaign
acceptance requirements; S1 must implement the new checks before claiming them.
Do not assume the old 2R gate or absent instruction counters already satisfy them.

Use narrowly scoped owners and reviewers. An idle agent slot is not a defect;
no allocator reconnaissance or feature-expansion lane is authorized. Read
[docs/lanes.md](docs/lanes.md) before delegating. Keep documentation and status
small; Git is history, not another prose archive.

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
active plan. This context does not reopen frozen allocator diagnostics. Crashes
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

Builds and native tests run inside the pinned native x86 images. Use targeted
non-allocator checks; do not launch the old allocator qualification commands.

```sh
scripts/lanes/rust-check.sh cargo check -q --locked -p <non-allocator-crate>
python3 -B scripts/test_python.py --module <path/to/test_file.py>
python3 compat/x86_64/validate_parity_ledger.py
./scripts/dev-x86_64.sh campaign-status
./scripts/dev-x86_64.sh --help
```

The placeholders above require the actual touched crate/test. Full legacy
profile checks are regression tools, not permission to run allocator campaigns.
Performance commands/availability are in [compat/perf/README.md](compat/perf/README.md);
S1 owns the focused development route. Do not invent command support.
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
- No allocator invention or development during the freeze. Preserve the port's
  source/provenance and the unchanged selected C backend. Completing a historical
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
  licenses, raw failures and behavioral coverage. Never weaken gates or rewrite
  upstream workloads to hide a defect or meet a size/performance budget.
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
| Family completion obligations, not work authorization | [docs/completion-requirements.md](docs/completion-requirements.md) |
| Narrow workstreams and integration | [docs/lanes.md](docs/lanes.md) |
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
