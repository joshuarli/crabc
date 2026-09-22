# crabc

A small Rust `no_std` Unix runtime: libc, a dynamic linker, owned application
CRT/compiler helpers, and an idiomatic, capability-accounted Rust facade.

Public support remains **Linux/AArch64 little-endian**, with **Linux 5.10** as
the kernel minimum. The active work is native Linux/x86-64 runtime parity and
a faithful Rust port of fixed mimalloc v3.5.0. x86 becomes publicly supported,
and the native allocator becomes its default, only after their respective
qualification gates.
AArch64 implementation and qualification are paused, not discarded.

The goal is exact modern Unix behavior without an unlimited historical libc
surface. Musl 1.2.6 is the compatibility oracle; glibc is neither an oracle nor
a fallback. Core filesystem, process, signal, thread/TLS, socket, memory,
stdio, resolver and loader semantics remain rigorous. The Rust facade exposes
useful OS capabilities rather than a wrapper for every C symbol.

## Development

[AGENTS.md](AGENTS.md) contains project scope, engineering rules, and the code
map. [plan.md](plan.md) is the sole active implementation plan and progress
handoff; **“implement plan.md”** means carry it through qualification and
promotion, not stop at private fixtures or a partial milestone.

Run active work in the repository's pinned native Linux/x86-64 environment:

```sh
./scripts/dev-x86_64.sh campaign-status
./scripts/dev-x86_64.sh --help
./compat/allocator/run-x86_64.sh allocator --quick
```

The runtime and allocator launchers keep separate mutable state under the
checkout's ignored `.work/`. Use focused checks during development and the
plan's complete native gates for qualification. The Apple-Silicon/macOS →
Docker → Linux/AArch64 `scripts/dev.sh` route remains a paused reference, not
the execution route for active x86 work.

## Contracts and references

- [Compatibility profile](COMPATIBILITY-PROFILE.md): intentional public and
  semantic limits. [COMPATIBILITY.md](COMPATIBILITY.md) is generated measured
  evidence, not an unconditional completeness claim.
- [Documentation index](docs/README.md): architecture, subsystem design,
  source provenance, and harness guides to consult for the boundary at hand.
- [Allocator provenance](crabc-mimalloc/UPSTREAM.md): the immutable native-port
  source pin and license. The accepted C backend remains separate until
  qualified promotion.

The recorded AArch64 owned-sysroot and Lua source-build results are scoped
artifacts, not whole-runtime C-free claims or x86 evidence. Existing AArch64
experimental sysroot snapshots are commit-pinned and make no cross-version
ABI/API/header/layout guarantee; no released downstream LLVM/C++ SDK is a
prerequisite for crabc's own artifact tests.

## License

MIT OR Apache-2.0
