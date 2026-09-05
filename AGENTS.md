# Project handoff

## Identity and scope

`crabc` is a small, auditable modern Unix runtime for **Linux/AArch64
little-endian**: a Rust `no_std` libc, dynamic linker, and an idiomatic
`crabc-rs` facade. Linux **5.10** is the kernel baseline. Public support remains
AArch64; the user has opened native x86-64 runtime parity and native x86-64
mimalloc work under `x86-64.md` and `native-mimalloc.md`, coordinated by
`plan.md`. AArch64 implementation/qualification work is paused; preserve its
contracts and frozen parity baseline. Do not add RISC-V, 32-bit, big-endian,
non-Linux support, or portability abstractions without explicit user direction.

`crabc-rs` exposes useful OS/runtime capabilities; it is not a mechanical
C-wrapper layer. A future macOS/AArch64 libSystem backend would be separately
scoped and does not make `crabc` portable.

Musl 1.2.6 is the C/POSIX compatibility oracle. Rustix is a pinned native-API
and behavior oracle for tests only. Glibc is never an oracle or fallback.

Read [`SCOPE.md`](SCOPE.md), [`COMPATIBILITY-PROFILE.md`](COMPATIBILITY-PROFILE.md),
and [`STATUS.md`](STATUS.md) before selecting new work.

## Code map

| Path | Contract |
| --- | --- |
| `libc/` | `crabc-libc`: `no_std` C ABI, producing `libc.so` and `libc.a`. `libc/src/lib.rs` is the target/linkage root; `libc/src/c_abi.rs` owns shared C ABI translation and libc runtime state, while independent ABI leaves are normal private modules. |
| `ldso/` | `crabc-ldso`: AArch64 dynamic linker and private runtime-state owner. `ldso/src/lib.rs` is the target/linkage root; `ldso/src/loader.rs` owns loader algorithms and state. |
| `crt/` | `crabc-crt`: Rust-produced `crt1.o`, `Scrt1.o`, `rcrt1.o`, `crti.o`, and `crtn.o`; `crt/build.py` owns deterministic object production and provenance. |
| `builtins/` | Rust `no_std` compiler-helper archive and deterministic builder for `libcrabc-builtins.a`; it replaces foreign target compiler-runtime archives. |
| `crabc-core/` | Shared typed `no_std` primitives used by the Rust facade; public AArch64 contract and staged native x86 foundations. |
| `crabc-rs/` | Public idiomatic Rust facade, direct probes, and native tests. |
| `crabc-mimalloc/` | Fixed-upstream allocator provenance and incomplete `#![no_std]` semantic port. Native x86-64 work is active; AArch64 work is paused. It is not a new allocator design or the current production backend. |
| `include/` | Installed public C headers. |
| `tests/` | Root Rust integration tests and C fixtures. |
| `compat/` | ABI, differential, loader, corpus, POSIX, Rust-std, LTO, Rustix, performance, and capability-ledger evidence. |
| `libc-test-harness/` | Pinned upstream libc-test runner and its oracle evidence. |
| `docker/` | Pinned target-specific development images. |
| `scripts/dev-x86_64.sh` | Active native x86 Docker-first dispatcher; `scripts/dev.sh` preserves the paused AArch64 command surface. |
| `compat/reports/` | Ignored generated evidence. |
| `COMPATIBILITY.md` | Generated repository status dashboard; never edit it by hand. |

## Documentation router

| Need | Read |
| --- | --- |
| Governing scope and non-goals | [`SCOPE.md`](SCOPE.md) |
| Public support/limitation boundary | [`COMPATIBILITY-PROFILE.md`](COMPATIBILITY-PROFILE.md) |
| Current completion state and roadmap router | [`STATUS.md`](STATUS.md) |
| Combined native x86-64 execution goal | [`plan.md`](plan.md), [`x86-64.md`](x86-64.md), and [`native-mimalloc.md`](native-mimalloc.md) |
| Runtime ownership and dependency architecture | [`docs/design/architecture.md`](docs/design/architecture.md) |
| Owned application CRT/sysroot design and purity boundary | [`docs/design/crt-and-sysroot.md`](docs/design/crt-and-sysroot.md) and [`docs/evidence/crabc-owned-sysroot.md`](docs/evidence/crabc-owned-sysroot.md) |
| Completed Lua source-build gate | [`docs/design/source-build.md`](docs/design/source-build.md) and [`docs/evidence/lua-source-build.md`](docs/evidence/lua-source-build.md) |
| Future CPython source-build contract | [`docs/roadmap/source-build.md`](docs/roadmap/source-build.md) |
| Performance completion contract | [`docs/roadmap/performance-completion.md`](docs/roadmap/performance-completion.md) |
| Follow-on software-corpus validation | [`docs/roadmap/software-corpus-validation.md`](docs/roadmap/software-corpus-validation.md) |
| Current measured results | [`COMPATIBILITY.md`](COMPATIBILITY.md) and `compat/reports/**` |
| Cross-cutting document index | [`docs/README.md`](docs/README.md) |
| Current Rust-facade architecture | [`docs/design/crabc-rs.md`](docs/design/crabc-rs.md) |
| Allocator-port scope, ownership, and provenance | [`docs/design/allocator.md`](docs/design/allocator.md) and [`crabc-mimalloc/UPSTREAM.md`](crabc-mimalloc/UPSTREAM.md) |
| Performance contract and active cost frontier | [`docs/design/performance.md`](docs/design/performance.md) and [`compat/perf/README.md`](compat/perf/README.md) |
| Allocator differential evidence and recorded differences | [`compat/allocator/README.md`](compat/allocator/README.md) and [`compat/allocator/known-differences.md`](compat/allocator/known-differences.md) |
| Exact native capability classification | [`compat/crabc-rs/coverage.toml`](compat/crabc-rs/coverage.toml) |
| Historical delivery rationale and rename provenance | [`docs/history/`](docs/history/) — provenance only, never a live backlog |
| Harness mechanics | The nearest `compat/*/README.md` or package `README.md` |
| Toolchain/oracle pins | `rust-toolchain.toml`, `compat/upstreams.toml`, `docker/Dockerfile` |

When documentation disagrees, use this precedence:

1. Explicit user direction and this working contract.
2. `SCOPE.md`, then `COMPATIBILITY-PROFILE.md`, then `plan.md` and the
   applicable execution or machine-readable contract. `STATUS.md` routes
   current work; it cannot override acceptance criteria.
3. Executable and machine-readable contracts: manifests, headers, pins,
   ledgers, scripts, and focused tests.
4. Musl/POSIX/source-oracle evidence for the named behavior.
5. Generated reports and dashboards as measurements, not normative policy.
6. README and historical prose as orientation/provenance.

Do not silently follow a stale paragraph. Reconcile its scope/status claim or
record why it is historical.

## Development and evidence

Active work uses the pinned native Linux/x86-64 environment through
`./scripts/dev-x86_64.sh`. Direct `cargo` is appropriate only inside the
relevant pinned environment. Start with the campaign surface:

```bash
./scripts/dev-x86_64.sh --help
./scripts/dev-x86_64.sh campaign-status
./scripts/dev-x86_64.sh campaign-family FAMILY
./scripts/dev-x86_64.sh campaign-all
```

The allocator lane uses `compat/allocator/run-x86_64.sh` with its separate
`.work/allocator-x86_64/` state. Its standalone
evidence cannot replace runtime integration. `scripts/dev.sh` and the pinned
Apple Silicon → Linux/AArch64 workflow are paused reference paths, not commands
to execute for this goal. Do not emulate AArch64.

Detailed runner options and report contracts live next to each harness.
`libc-test-harness/run.sh` is a compatibility launcher, not the canonical host
entry point. `scripts/local-ci.sh` is legacy host-architecture convenience and
does not replace the pinned native evidence environment.

## Scope rules that affect implementation

- Kernel-facing code may rely on Linux 5.10. Do not add pre-5.10 fallbacks;
  centrally document a newer requirement before relying on it.
- Allocator invention is out of scope. The one exception is a
  provenance-preserving semantic port of fixed mimalloc v3.5.0 (native x86-64
  active; AArch64 paused):
  preserve its algorithms, data structures, memory orderings, and observable
  behavior until parity is proved; retain the pinned C implementation as a
  differential oracle; require a written design note plus differential and
  performance evidence for any algorithmic divergence. `crabc-rs` uses normal
  Rust allocation and does not expose C allocation APIs.
- Never hand-roll cryptography, including when porting compatibility source.
  Entropy syscalls and domain-specific state machines are in scope; every
  cryptographic algorithm or PRNG/DRBG core requires a reviewed focused Rust
  dependency or the feature remains explicitly limited.
- Locale support is `C`, `POSIX`, and `C.UTF-8`; Rust-facing text is UTF-8.
  Do not add general locale/legacy-encoding databases.
- Parse conventional system files. Do not build NSS, plugin/provider systems,
  bundled tzdata, gettext, IDNA policy, async runtimes, process supervisors,
  security-policy frameworks, or portability layers.
- DNS is the bounded `/etc/hosts` + `/etc/resolv.conf`, A/AAAA/CNAME, search,
  UDP/TCP fallback, retry/failover profile. Exclude DNSSEC, DoH, DoT, and mDNS.
- Dependency selection is delegated to implementation judgment; no separate
  user approval is required. Apply `SCOPE.md`'s preference for small, mature,
  focused dependencies and scrutinize broad or difficult-to-audit choices.
  Document the primitive, exact normal transitive graph, build/native code,
  allocation/global state, `no_std`, and LTO consequences. This authority does
  not expand project scope or waive provenance and qualification requirements.
- Scalar behavior is canonical. Remove structural and algorithmic cost first;
  use SIMD only as a separately proven, measured final optimization (except
  for a fully proved established math kernel). Crypto stays in approved
  RustCrypto primitives, never hand-rolled vector code.
- Every public unsafe Rust API documents its concrete caller obligations.

## Working contract

Implementation is cheap; ambiguity is not. Spend care on durable names,
types, interfaces, state transitions, permissions, tests, and explanations.

- Before editing, find the behavior, boundaries, callers, tests, and docs.
  Classify scope as core Unix runtime, useful POSIX/runtime, C ABI machinery,
  Rust-subsumed, or deliberately unsupported legacy.
- Work vertical slices: contract → focused regression → implementation →
  direct-boundary/ABI proof → musl/POSIX/external evidence → ledger/docs.
  Do not mass-add stubs or chase a symbol count.
- For bugs, add the smallest isolated failing regression before the fix.
- Keep unsafe boundaries explicit and preserve compatibility algorithms where
  musl behavior is subtle. Do not hide fallbacks merely to make a patch fit.
- For a translated fixed-upstream subsystem, record its exact revision, source
  file/function-to-Rust-module mapping, source-specific license provenance,
  and intentional differences before treating an implementation as a port.
- Preserve unrelated dirty work. Do not run formatters, linters, pre-commit
  hooks, or push a remote unless the user explicitly asks.
- Keep development worktrees, scratch files, extracted sources, build/cache
  state, and generated evidence under the checkout's ignored `.work/` tree.
  Use `.work/x86_64/` for x86 runtime work. Override tools' temporary paths;
  do not create new work under `/tmp` or outside the checkout. Existing
  architecture-qualified evidence paths remain provenance, not permission
  to create new external scratch directories.
- A completed feature needs coherent tests, ledger/documentation updates, and
  a commit when requested.
