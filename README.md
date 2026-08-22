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
semantic profile, and [`TODO.md`](TODO.md) for the exact active Linux/AArch64
work. [`docs/README.md`](docs/README.md) routes design, evidence, historical
records, and code-adjacent harness guides. Compatibility evidence does not
promise a native Rust wrapper for every C symbol.

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

```bash
./scripts/dev.sh image       # build the Linux/AArch64 development image
./scripts/dev.sh build
./scripts/dev.sh test
./scripts/dev.sh crabc-rs    # native Rust capability suite and proofs
./scripts/dev.sh lto-m12     # native crabc-rs O3/fat-LTO evidence
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

## Project layout

| Path | Description |
|---|---|
| `libc/` | `libc.so` / `libc.a`: monolithic Rust `no_std` libc |
| `ldso/` | `libldso.so`: AArch64 dynamic linker |
| `crabc-core/` | Shared typed `no_std` Linux/AArch64 implementation layer |
| `crabc-rs/` | Idiomatic Rust OS/runtime capabilities |
| `include/` | Public C headers |
| `tests/` | Runtime integration tests and C fixtures |
| `compat/` | ABI, differential, corpus, loader, LTO, Rustix, and capability evidence |
| `libc-test-harness/` | Pinned upstream musl `libc-test` runner |
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
