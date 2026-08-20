# crabc

A Rust `no_std` musl-compatible libc with a dynamic linker. Development is
currently AArch64-first: the supported maturity target is native Linux/AArch64
under Docker on Apple Silicon macOS.

## Why crabc over musl?

| | musl | crabc |
|---|---|---|
| **Language** | C (~60k lines) | Rust `no_std` (~15k lines) |
| **Memory safety** | Manual — depends on developer discipline | Compiler-guaranteed — no buffer overflows, use-after-free, or UB |
| **Dynamic linker** | Separate `ld-musl-*.so` | Built-in `libldso.so` — runs musl binaries directly |
| **Embedded/kernel** | Requires cross-compile + link | `no_std` — `use crabc_libc` directly in Rust kernels |
| **Architecture** | 10+ arches | Linux AArch64 (current maturity target) |
| **Dynamic exports** | 1,647 musl AArch64 baseline | 683 crabc AArch64 exports |

**The core advantage: a Rust libc can be integrated directly into Rust `no_std` projects without FFI or cross-compilation.**

## Native AArch64 development

The host only needs Docker. The development image is pinned to Alpine 3.24.1,
Rust `nightly-2026-07-24`, and a separately built musl 1.2.6 ABI oracle; see
[`compat/upstreams.toml`](compat/upstreams.toml) for exact revisions.

```bash
./scripts/dev.sh image       # builds the native linux/arm64 image once
./scripts/dev.sh build
./scripts/dev.sh test
./scripts/dev.sh symbols     # writes compat/reports/symbols/
./scripts/dev.sh compat      # checks the symbol-parity regression ratchet
./scripts/dev.sh libc-test functional
./scripts/dev.sh differential
./scripts/dev.sh loader-inventory
./scripts/dev.sh dashboard   # writes COMPATIBILITY.md from structured reports
./scripts/dev.sh shell
```

`symbols` compares public dynamic symbols by name, ELF kind, binding, and
visibility. It intentionally fails while the candidate differs from musl and
leaves machine-readable evidence in `compat/reports/symbols/`.

## Direct host requirements

For the legacy direct-host commands below, install Rust **nightly** and
`musl-gcc` (from `musl-tools` / `musl-dev`). The Docker commands above are the
primary AArch64 development path.

## Build

```bash
cargo build --workspace
```

This produces:

- `target/debug/libc.so`
- `target/debug/libldso.so`
- `target/debug/loader`

## Test

Run all integration tests:

```bash
cargo test --workspace
```

Run a single subsystem:

```bash
cargo test --test math
cargo test --test ctype
cargo test --test string
cargo test --test ldso_real_binary
```

Run the upstream musl `libc-test` harness:

```bash
cd libc-test-harness
./run.sh              # functional subset
./run.sh math         # math subset
./run.sh regression   # regression subset
./run.sh api          # API/header checks
./run.sh all          # everything
```

## Project layout

| Path | Description |
|------|-------------|
| `src/` | `loader` binary — minimal static-PIE ELF runner |
| `libc/` | `libc.so` / `libc.a` — `no_std` libc implementation |
| `ldso/` | `libldso.so` — dynamic linker |
| `include/` | Public C headers |
| `tests/` | Rust integration tests and C fixtures |
| `libc-test-harness/` | Python runner and reporting for upstream musl `libc-test` |

## Notes

- AArch64 `long double` compatibility is still incomplete; the upstream
  `strtold` functional case is currently a known failure.
- `libc-test` reports many `BUILDERROR`s until the full musl symbol set is
  exported; this is expected.

## License

MIT OR Apache-2.0
