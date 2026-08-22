# Agent Handoff

## Mission and scope

`crabc` is a small, auditable, modern Unix runtime: a Rust `no_std` libc and
dynamic linker for **Linux/AArch64 little-endian**. The platform baseline is
**Linux kernel 5.10**. This is the only active `crabc` platform; do not add
x86_64, RISC-V, 32-bit, big-endian, or non-Linux work or abstractions unless
the user explicitly reopens that scope.

`crabc-rs` is a separate idiomatic Rust facade for useful OS/runtime
capabilities. It may eventually have a macOS/AArch64 libSystem backend, but
that does not make `crabc` portable. It must not mechanically wrap C-era
machinery just because a libc symbol exists.

The governing doctrine is [`SCOPE.md`](SCOPE.md). The externally visible
limits and classification rules are in
[`COMPATIBILITY-PROFILE.md`](COMPATIBILITY-PROFILE.md). Read both before
choosing new work. Musl is the Linux libc compatibility oracle; glibc is never
an oracle or semantic fallback.

The project pursues a useful modern Unix contract, not a Rust reimplementation
of every historical libc facility. Core filesystem, descriptor, pipe, signal,
fork/exec, pthread/TLS, socket, mmap, time, stdio-basic, resolver, errno, ABI,
and dynamic-linker behavior remain high-rigor work. A public ABI symbol can be
compatibility machinery without becoming a first-class native subsystem.

## Scope rules that affect implementation

- Kernel-facing code may rely on Linux 5.10 facilities. Do not add pre-5.10
  fallbacks; document any newer requirement and raise the MSRV only centrally.
- `malloc` implementation research is out of scope. Use the chosen mature
  allocator strategy (currently mimalloc) behind the C allocation ABI. Do not
  present `malloc`/`free` as idiomatic `crabc-rs` APIs.
- Never hand-roll cryptography. Entropy syscalls are in scope; historical APIs
  needing crypto require a proven, focused Rust dependency or an explicit
  profile limitation.
- Locale support is only `C`, `POSIX`, and `C.UTF-8` (with cheap UTF-8 aliases
  only when correct). Rust-facing text is UTF-8. Do not add historical
  encodings beyond the documented ASCII/UTF-8/UTF-16/UTF-32 compatibility set.
- Parse conventional system files; do not build NSS, provider/plugin systems,
  bundled tzdata, gettext, IDNA policy, locale databases, async runtimes,
  process-management frameworks, or security-policy frameworks.
- DNS is the documented small resolver profile: hosts/resolv.conf, A/AAAA/
  CNAME, search, UDP, required TCP fallback, and basic retry/failover.
- Prefer a small excellent pure-Rust dependency to bespoke crypto or optimized
  primitives when it is easier to audit and preserves `no_std`/LTO goals. For
  every new production dependency, document its primitive, why `core`/`alloc`
  is insufficient, transitive normal dependencies, proc-macros/build scripts/
  native code, allocation or global state, `no_std`, and LTO implications.
- Scalar behavior is canonical; SIMD is a separately verified optimization.
  Use focused kernels rather than generic SIMD or platform frameworks.
- Keep unsafe boundaries explicit. Each public unsafe Rust API must state its
  concrete caller obligations.

## Repository layout

| Path | What it is |
|---|---|
| `src/` | `loader` binary — minimal static-PIE ELF runner. |
| `libc/` | `libc.so` / `libc.a` — monolithic `no_std` libc. Crate name is `c`. |
| `ldso/` | `libldso.so` — dynamic linker (`_start`, relocation, DT_NEEDED, TLS). |
| `crabc-rs/` | Idiomatic, capability-accounted Rust OS/runtime facade. |
| `include/` | Public C headers. |
| `tests/` | Rust integration tests and C fixtures. |
| `compat/` | ABI, differential, corpus, loader, and crabc-rs evidence harnesses. |
| `libc-test-harness/` | Runner for the pinned upstream musl `libc-test` suite. |
| `scripts/dev.sh` | Docker-first Linux/AArch64 development entry point. |

`libc/src/lib.rs` includes subsystem files into one `no_std` libc crate.
Preserve the existing implementation unless a scope limit creates real
maintenance cost; this reset changes future prioritization, not correct code.

## Docker-first build and evidence

The host development path is Apple Silicon macOS → Docker → Linux/AArch64.
The pinned image/oracles are listed in `compat/upstreams.toml`.

```bash
./scripts/dev.sh image
./scripts/dev.sh build
./scripts/dev.sh test
./scripts/dev.sh crabc-rs
./scripts/dev.sh compat
./scripts/dev.sh dashboard
```

For a narrow C subsystem test, integration tests compile a fixture with
`musl-gcc`, link it to `libldso.so`/`libc.so`, and assert runtime behavior.
Use `libc-test-harness/run.sh` for the appropriate pinned musl subset, not a
host-glibc result. `COMPATIBILITY.md` is generated evidence; do not edit it by
hand.

## Working contract

Implementation is cheap; ambiguity is not. Spend care where meaning becomes
durable: names, types, schemas, interfaces, state transitions, permissions,
tests, and explanations.

- Before editing, find the intended behavior, boundaries, callers, tests, and
  docs. Use the smallest reversible assumption. Classify proposed scope as
  core Unix runtime, useful POSIX/runtime, C ABI machinery, Rust-subsumed, or
  deliberately unsupported legacy.
- Work in vertical slices: inventory → implementation → ABI/direct-boundary
  verification → focused observable tests → musl differential/external test →
  verified. Do not mass-add stubs or chase symbol count.
- Put explanations next to the definitions and maintain machine-readable
  capability accounting. “100% coverage” for `crabc-rs` means semantic
  accounting, not a wrapper for every C export.
- For a bug, first add the smallest isolated regression, then fix its root
  cause. Run the nearest hard judge before broadening verification.
- New dependencies need the scope review above and user consultation unless
  the user has explicitly approved the relevant dependency decision.
- Keep C compatibility machinery boring, mature, and well tested. Port musl
  algorithms literally in subtle math/compatibility areas; do not invent them.

Do not run formatters, linters, or pre-commit hooks. Do not push a remote
unless explicitly asked. Preserve unrelated dirty work. Each completed feature
needs coherent tests, documentation/accounting, and a commit when requested.
