# crabc

`crabc` is a small Rust `no_std` Unix runtime: a libc, dynamic linker, and
capability-accounted Rust facade for **Linux/AArch64 little-endian**. Its Linux
kernel baseline is **5.10**.

The project targets the useful modern Unix runtime contract—not an unlimited
reimplementation of historical libc breadth. It is AArch64-first and
Linux-only. x86_64, RISC-V, 32-bit, big-endian, and non-Linux `crabc` ports are
out of scope unless explicitly reopened. `crabc-rs` may later add a separate
macOS/AArch64 libSystem backend; that does not make the libc portable.

Read [`SCOPE.md`](SCOPE.md) for the engineering doctrine,
[`COMPATIBILITY-PROFILE.md`](COMPATIBILITY-PROFILE.md) for the supported
semantic profile, [`STATUS.md`](STATUS.md) for the current completion and
roadmap router, and [`docs/design/architecture.md`](docs/design/architecture.md)
for runtime ownership. [`docs/README.md`](docs/README.md) routes design,
evidence, historical records, and code-adjacent harness guides. Compatibility
evidence does not promise a native Rust wrapper for every C symbol.

The active acceptance contracts are purpose-led rather than milestone-led:
[`docs/roadmap/performance-completion.md`](docs/roadmap/performance-completion.md)
defines the measurable Linux/AArch64 performance bar;
[`docs/roadmap/software-corpus-validation.md`](docs/roadmap/software-corpus-validation.md)
defines the sequenced real-software and `crabc-rs` application corpus; and
[`docs/roadmap/source-build.md`](docs/roadmap/source-build.md) retains the
future CPython source-build contract. The completed Rust-owned application
CRT/sysroot and Lua source-build gates are documented in
[`docs/design/crt-and-sysroot.md`](docs/design/crt-and-sysroot.md) and
[`docs/design/source-build.md`](docs/design/source-build.md). Their purity
evidence distinguishes the completed CRT/sysroot boundary from the remaining
native allocator dependency.

The selected musl/Rustix performance evidence and current optimization frontier
are documented in [`docs/design/performance.md`](docs/design/performance.md).

## What remains rigorous

The scope is narrow around historical breadth, not around normal Unix
behavior. Filesystems, descriptors and pipes, signals, fork/exec, pthread/TLS,
sockets, mmap, time, stdio basics, the documented resolver profile, dynamic
linking, errno, ABI, and AArch64 behavior are treated as core compatibility
work. Musl is the compatibility oracle; glibc is neither an oracle nor a
fallback.

## Native AArch64 development

The supported development loop is Apple Silicon macOS → Docker → Linux/AArch64.
The image and compatibility oracles are pinned in
[`compat/upstreams.toml`](compat/upstreams.toml).

Install Docker Desktop (with Linux containers enabled), then build the pinned
development image from the repository root:

```bash
make docker
```

After that, use `./scripts/dev.sh` for builds, tests, compatibility checks, and
an interactive container shell. The first build downloads the pinned Rust,
musl, and test-tool sources and may take several minutes.

Use the repository-local `.work/` directory for disposable development
artifacts; it is excluded from both Git and Docker build contexts.

```bash
./scripts/dev.sh image       # build the Linux/AArch64 development image
./scripts/dev.sh build
./scripts/dev.sh test
./scripts/dev.sh crabc-rs    # native Rust capability suite and proofs
./scripts/dev.sh lto-native-facade # native crabc-rs O3/fat-LTO evidence
./scripts/dev.sh sysroot     # Rust-owned CRT, sealed driver, and purity proof
./scripts/dev.sh lua         # pinned Lua 5.4 source-build/extension-loading gate
./scripts/dev.sh perf --label baseline # controlled musl-vs-crabc performance evidence
./scripts/dev.sh perf-native --label baseline # crabc-rs vs Rustix direct facade evidence
./scripts/dev.sh compat      # symbol/ABI accounting ratchet
./scripts/dev.sh differential
./scripts/dev.sh libc-test functional
./scripts/dev.sh dashboard   # regenerate COMPATIBILITY.md from reports
./scripts/dev.sh shell
```

`COMPATIBILITY.md` is generated evidence. It records the current measured
surface; it is not a statement that every historical musl subsystem is active
project scope.

## Experimental sysroot snapshots

On Apple Silicon macOS, Docker is the only local build dependency for an
experimental Linux/AArch64 sysroot snapshot:

```bash
./scripts/dev.sh image
./scripts/dev.sh sysroot-dist
```

The build, deterministic package, extraction, and smoke run entirely inside
the pinned `linux/arm64` Docker image; GitHub Actions invokes the same command.
The four tested snapshot assets appear under `dist/`. Each is an
experimental commit snapshot with no ABI, API, header/layout, or
cross-version compatibility guarantee. The smoke uses the container's pinned
disposable Clang/lld, not a released `llvm-clang-crabc` toolchain. x86-64 is
not built.

## Project layout

| Path | Description |
|---|---|
| `libc/` | `libc.so` / `libc.a`: Rust `no_std` C ABI and libc-owned runtime state |
| `ldso/` | `libldso.so`: AArch64 dynamic linker |
| `crt/` | Rust-produced application CRT start/end objects |
| `builtins/` | Rust `no_std` compiler-helper archive for final C links |
| `crabc-core/` | Shared typed `no_std` Linux/AArch64 implementation layer; private native x86-64 primitives exist only for fixed-mimalloc evidence |
| `crabc-rs/` | Idiomatic Rust OS/runtime capabilities |
| `include/` | Public C headers |
| `tests/` | Runtime integration tests and C fixtures |
| `compat/` | ABI, differential, corpus, loader, LTO, Rustix, and capability evidence |
| `libc-test-harness/` | Pinned Laputa Systems `libc-test` runner |
| `docs/` | Cross-cutting design, evidence, and historical delivery records |
| `scripts/` and `docker/` | Docker-first development commands and pinned native image |

## Design boundaries

- Linux kernel 5.10 is the MSRV; no archaeological older-kernel fallbacks.
- The C allocation ABI uses the chosen external allocator strategy (currently
  mimalloc); allocator design is not a project research area.
- No hand-rolled crypto. OS entropy is supported; crypto-heavy compatibility
  needs a focused proven Rust crate or a documented limitation.
- Locales are `C`, `POSIX`, and `C.UTF-8`; Rust-facing text is UTF-8. There is
  no general locale database or historical-encoding expansion.
- No NSS/plugin stack, bundled tzdata, gettext framework, IDNA policy, async
  runtime, process-management framework, or security-policy framework.

## License

MIT OR Apache-2.0
