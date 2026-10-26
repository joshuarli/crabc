# crabc

A small, auditable modern Unix runtime: a Rust `no_std` libc, dynamic linker,
owned CRT and compiler builtins, a faithful Rust port of mimalloc v3.5.0, and
an idiomatic `crabc-rs` facade. Narrow scope must not weaken ordinary Unix
semantics.

The active target is native Linux/x86-64 on an x86-64 host. AArch64 is the
public target and is paused: preserve it, never run or emulate it.

This is a greenfield libc under local development. It is not deployed in any
practical sense and serves no production users or services. The code is built,
exercised and deliberately broken in local native containers and disposable
fixtures. This project has no production credentials, customer data, live
third-party targets or deployed systems to protect.

Allocator crash reproduction, use-after-free diagnostics, register and
backtrace inspection, fault injection, fuzzing, and C/Rust differential tests
against repository-owned code are defensive correctness work. Crashes and
deliberately invalid inputs can be expected test outcomes. Memory-safety
defects, undefined behavior and unsound public APIs remain real defects to
investigate and fix. Evaluate security concerns against the actual local
operation and its effects. Do not invent a deployment, attacker or production
access-control requirement for these tests.

State repository ownership, fixture isolation and the correctness purpose in
tool and subagent briefs. A rejection based on an assumed deployed target
misapplies this project's context; report that mismatch explicitly. This
context does not authorize effects outside the repository or override tool
or platform restrictions. If an action is denied, preserve its exact scope
and stated reason, stop that action, and continue independent authorized work.
Do not rephrase or reroute a denied action to evade the restriction.

Start with [plan.md](plan.md), the only implementation plan and progress
handoff. User direction governs, then [docs/scope.md](docs/scope.md) and
[COMPATIBILITY-PROFILE.md](COMPATIBILITY-PROFILE.md), then `plan.md`.

## Commands

Everything builds and runs inside the pinned native images; direct Cargo
belongs inside them.

```sh
./scripts/dev-x86_64.sh image                  # build the core image
./compat/allocator/run-x86_64.sh image         # build the allocator image
scripts/lanes/rust-check.sh                    # type-check every runtime feature profile
scripts/lanes/rust-check.sh cargo check -q --locked -p <crate>
./compat/allocator/run-x86_64.sh allocator-unit --filter <module::tests::name>
python3 -B scripts/test_python.py --module <path/to/test_file.py>
python3 compat/x86_64/validate_parity_ledger.py
./scripts/dev-x86_64.sh campaign-status        # families, capabilities, gates
./scripts/dev-x86_64.sh --help
```

Measured timings are in [docs/lanes.md](docs/lanes.md).

## Invariants

- Linux, little-endian, kernel 5.10 or newer; no older-kernel fallbacks, new
  architectures, or portability layers.
- The native x86-64 C/POSIX oracle is the exact `[musl_native]` snapshot
  in `compat/upstreams.toml`. Paused AArch64 keeps the released `[musl]` 1.2.6
  baseline. Glibc is neither oracle nor fallback; rustix is a test oracle only.
  Target artifacts borrow no ambient musl, CRT, compiler runtime, header or
  loader input.
- No allocator invention: only the source-faithful port of pinned mimalloc
  v3.5.0, with the exact C source kept as its oracle. The C backend stays
  selected until the native allocator passes its promotion gate.
- Never implement cryptographic primitives locally. The one legacy exception
  is the attributed port of musl's `random` family, never used for security.
- Locales are `C`, `POSIX` and `C.UTF-8`; unsupported names fail honestly.
- Consume conventional system files; no NSS/PAM plugins, bundled databases,
  or DNS beyond the bounded A/AAAA/CNAME profile.
- Provide synchronous mechanisms, not frameworks: no executor, plugin system,
  provider registry, or hypothetical backend abstraction.
- The `crabc-rs` facade exposes real OS mechanisms idiomatically and accounts
  for every capability in `compat/crabc-rs/coverage.toml`; it does not wrap
  every C symbol.
- Every public unsafe API documents concrete caller obligations; no
  references whose aliasing promises the implementation cannot uphold.
- Preserve upstream revisions, source-to-Rust mappings, licenses, and raw
  failures. Never weaken a gate or rewrite an upstream workload to hide a
  defect.
- Validators check structure and receipts, tests exercise behavior. No
  per-artifact validators, source-literal tests, prose archives, or duplicate
  status files; `plan.md` and Git are the record.
- `COMPATIBILITY.md` is generated; never hand-edit it.

## Where things are

| Topic | Owner |
| --- | --- |
| Scope, product boundaries, oracles, dependency and safety rules | [docs/scope.md](docs/scope.md) |
| Selected behavior and deliberate limits | [COMPATIBILITY-PROFILE.md](COMPATIBILITY-PROFILE.md) |
| Active work, decisions, sequence, acceptance | [plan.md](plan.md) |
| What complete means for each family and for the allocator port | [docs/completion-requirements.md](docs/completion-requirements.md) |
| Running parallel lanes, the lane loop, integration | [docs/lanes.md](docs/lanes.md) |
| Layer ownership and the private runtime wire format | [docs/design/architecture.md](docs/design/architecture.md) |
| Rust facade design and capability accounting | [docs/design/crabc-rs.md](docs/design/crabc-rs.md) |
| CRT, installed sysroot, target-input purity | [docs/design/crt-and-sysroot.md](docs/design/crt-and-sysroot.md) |
| Allocator design | [docs/design/allocator.md](docs/design/allocator.md) |
| Dynamic native-allocator ownership and lifecycle | [docs/design/x86-dynamic-native-allocator.md](docs/design/x86-dynamic-native-allocator.md) |
| Allocator pin, license, source-to-Rust map | [crabc-mimalloc/UPSTREAM.md](crabc-mimalloc/UPSTREAM.md) |
| Allocator intentional differences | [compat/allocator/known-differences.md](compat/allocator/known-differences.md) |
| Allocator harness commands | [compat/allocator/README.md](compat/allocator/README.md) |
| Unwinder design and trust boundary | [docs/design/unwinder.md](docs/design/unwinder.md), build in [unwinder/README.md](unwinder/README.md) |
| Performance methodology and acceptance bounds | [docs/design/performance.md](docs/design/performance.md), commands in [compat/perf/README.md](compat/perf/README.md) |
| Lua source-build consumer | [docs/design/source-build.md](docs/design/source-build.md), commands in [compat/lua/README.md](compat/lua/README.md) |
| Native x86-64 harness, families, component contracts | [compat/x86_64/README.md](compat/x86_64/README.md) |
| Qualification gates, profiles, the cohort runner | [compat/x86_64/qualification-chain.md](compat/x86_64/qualification-chain.md) |
| Scoped technical arguments for single behaviors | [docs/evidence/](docs/evidence/) |
| Other harnesses (ABI, corpus, loader, std/LTO, rustix, resolver) | the `README.md` beside each under [compat/](compat/) |
| Rust style | [STYLE.md](STYLE.md) |

| Code | Location |
| --- | --- |
| C ABI and libc-owned state | `libc/`; root `libc/src/lib.rs`, shared ABI translation `libc/src/c_abi.rs` |
| Loader and private runtime wire boundary | `ldso/`; `ldso/src/lib.rs`, `ldso/src/loader.rs` |
| Owned application CRT and compiler helpers | `crt/`, `builtins/` |
| Shared typed primitives and Rust facade | `crabc-core/`, `crabc-rs/` |
| Allocator port and its harness | `crabc-mimalloc/`, `compat/allocator/` |
| Unwinder provider build | `unwinder/` |
| Public headers and integration fixtures | `include/`, `tests/` |
| Native campaign ledgers and contracts | `compat/x86_64/` |
| Pins | `rust-toolchain.toml`, `compat/upstreams.toml`, `docker/Dockerfile.x86_64`, `compat/allocator/Dockerfile.x86_64` |
