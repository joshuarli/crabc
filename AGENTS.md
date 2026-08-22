# Project handoff

## Identity and scope

`crabc` is a small, auditable modern Unix runtime for **Linux/AArch64
little-endian**: a Rust `no_std` libc, dynamic linker, and an idiomatic
`crabc-rs` facade. Linux **5.10** is the kernel baseline. This is the only
active `crabc` platform: do not add x86_64, RISC-V, 32-bit, big-endian, or
non-Linux support or portability abstractions unless the user explicitly
reopens the scope.

`crabc-rs` exposes useful OS/runtime capabilities; it is not a mechanical
C-wrapper layer. A future macOS/AArch64 libSystem backend would be separately
scoped and does not make `crabc` portable.

Musl 1.2.6 is the C/POSIX compatibility oracle. Rustix is a pinned native-API
and behavior oracle for tests only. Glibc is never an oracle or fallback.

Read [`SCOPE.md`](SCOPE.md), [`COMPATIBILITY-PROFILE.md`](COMPATIBILITY-PROFILE.md),
and [`TODO.md`](TODO.md) before selecting new work.

## Code map

| Path | Contract |
| --- | --- |
| `libc/` | `crabc-libc`: monolithic `no_std` C ABI, producing `libc.so` and `libc.a`. `libc/src/lib.rs` includes its subsystem files. |
| `ldso/` | `crabc-ldso`: AArch64 dynamic linker and private runtime-state owner. |
| `crabc-core/` | Shared typed `no_std` Linux/AArch64 primitives used by the Rust facade. |
| `crabc-rs/` | Public idiomatic Rust facade, direct probes, and native tests. |
| `src/` | Root `loader` helper/ELF runner; distinct from `ldso`. |
| `include/` | Installed public C headers. |
| `tests/` | Root Rust integration tests and C fixtures. |
| `compat/` | ABI, differential, loader, corpus, POSIX, Rust-std, LTO, Rustix, performance, and capability-ledger evidence. |
| `libc-test-harness/` | Pinned upstream libc-test runner and its oracle evidence. |
| `docker/` | Pinned Linux/AArch64 development image. |
| `scripts/dev.sh` | Canonical Docker-first command dispatcher. |
| `compat/reports/` | Ignored generated evidence. |
| `COMPATIBILITY.md` | Generated repository status dashboard; never edit it by hand. |

## Documentation router

| Need | Read |
| --- | --- |
| Governing scope and non-goals | [`SCOPE.md`](SCOPE.md) |
| Public support/limitation boundary | [`COMPATIBILITY-PROFILE.md`](COMPATIBILITY-PROFILE.md) |
| Exact active work | [`TODO.md`](TODO.md) |
| Source-build gate before performance work | [`pregoal.md`](pregoal.md) |
| Performance completion contract | [`goal.md`](goal.md) |
| Follow-on software-corpus validation | [`goal2.md`](goal2.md) |
| Current measured results | [`COMPATIBILITY.md`](COMPATIBILITY.md) and `compat/reports/**` |
| Cross-cutting document index | [`docs/README.md`](docs/README.md) |
| Current Rust-facade architecture | [`docs/design/crabc-rs.md`](docs/design/crabc-rs.md) |
| Performance contract and active cost frontier | [`docs/design/performance.md`](docs/design/performance.md) and [`compat/perf/README.md`](compat/perf/README.md) |
| Exact native capability classification | [`compat/crabc-rs/coverage.toml`](compat/crabc-rs/coverage.toml) |
| Historical M0–M12 rationale | [`docs/history/`](docs/history/) — provenance only, never a live backlog |
| Harness mechanics | The nearest `compat/*/README.md` or package `README.md` |
| Toolchain/oracle pins | `rust-toolchain.toml`, `compat/upstreams.toml`, `docker/Dockerfile` |

When documentation disagrees, use this precedence:

1. Explicit user direction and this working contract.
2. `SCOPE.md`, then `COMPATIBILITY-PROFILE.md`, then `TODO.md`.
3. Executable and machine-readable contracts: manifests, headers, pins,
   ledgers, scripts, and focused tests.
4. Musl/POSIX/source-oracle evidence for the named behavior.
5. Generated reports and dashboards as measurements, not normative policy.
6. README and historical prose as orientation/provenance.

Do not silently follow a stale paragraph. Reconcile its scope/status claim or
record why it is historical.

## Development and evidence

The supported host path is Apple Silicon macOS → Docker → Linux/AArch64. Use
`./scripts/dev.sh`; direct `cargo` is appropriate only inside that pinned
container.

```bash
./scripts/dev.sh image
./scripts/dev.sh build [cargo args]
./scripts/dev.sh test [cargo args]
./scripts/dev.sh crabc-rs
./scripts/dev.sh compat
./scripts/dev.sh libc-test functional|math|regression|api|all
./scripts/dev.sh os-test | pthread-stress | static-pthread-tls
./scripts/dev.sh signal-process | resolver-network | ldso | corpus
./scripts/dev.sh rust-std | rust-std-dependent | lto | lto-m12
./scripts/dev.sh lua [--offline]
./scripts/dev.sh perf [--label NAME]
./scripts/dev.sh perf-native [--label NAME]
./scripts/dev.sh abi-probe | loader-inventory | dashboard | shell
```

The detailed runner options and report contracts live next to each harness.
`libc-test-harness/run.sh` is a compatibility launcher, not the canonical host
entry point. `scripts/local-ci.sh` is legacy host-architecture convenience and
does not replace the pinned native evidence environment.

## Scope rules that affect implementation

- Kernel-facing code may rely on Linux 5.10. Do not add pre-5.10 fallbacks;
  centrally document a newer requirement before relying on it.
- `malloc` implementation research is out of scope. The public C allocator
  boundary uses the mature mimalloc strategy; `crabc-rs` uses normal Rust
  allocation and does not expose C allocation APIs.
- Never hand-roll cryptography. Entropy syscalls are in scope; compatibility
  crypto requires an approved focused Rust dependency or an explicit limit.
- Locale support is `C`, `POSIX`, and `C.UTF-8`; Rust-facing text is UTF-8.
  Do not add general locale/legacy-encoding databases.
- Parse conventional system files. Do not build NSS, plugin/provider systems,
  bundled tzdata, gettext, IDNA policy, async runtimes, process supervisors,
  security-policy frameworks, or portability layers.
- DNS is the bounded `/etc/hosts` + `/etc/resolv.conf`, A/AAAA/CNAME, search,
  UDP/TCP fallback, retry/failover profile. Exclude DNSSEC, DoH, DoT, and mDNS.
- A new production dependency needs user consultation unless the user has
  already approved that exact decision. Document its primitive, normal
  transitive graph, build/native code, allocation/global state, `no_std`, and
  LTO consequences.
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
- Preserve unrelated dirty work. Do not run formatters, linters, pre-commit
  hooks, or push a remote unless the user explicitly asks.
- A completed feature needs coherent tests, ledger/documentation updates, and
  a commit when requested.
