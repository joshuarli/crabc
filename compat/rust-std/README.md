# Stock Rust `std` compatibility harness

`run.py` builds the ordinary `fixtures/src/main.rs` application with the
pinned nightly Rust toolchain and stock Rust sources:

```text
normal Rust source → stock std (`-Z build-std`) → pinned musl ABI → crabc
```

The build happens in a temporary Cargo project outside the repository so the
libc crate's `-C link-dead-code` flags cannot leak into Rust's standard-library
build. It uses `musl-gcc`, whose image-pinned specs select `/opt/musl-1.2.6`,
and disables `crt-static` to produce a dynamic AArch64 PIE. The default
fixture has no project dependencies; a separate dependency-bearing application
is covered below.

Run it inside the pinned native development image after building crabc:

```bash
python3 compat/rust-std/run.py
```

The runner requires native AArch64, Rust `nightly-2026-07-24`, the pinned musl
tree, and `target/debug/{libc.so,libldso.so}`. It rejects glibc evidence,
records toolchain/ABI/artifact digests, and writes
`compat/reports/rust-std/latest.json`. The reference and candidate executions
share one environment and one textual `LD_LIBRARY_PATH`; only the staged musl
libc/loader bytes change. Exit status, stdout, and stderr are retained as raw
comparisons with no normalization.

The staged libc uses the canonical musl ABI filename
`libc.musl-aarch64.so.1`, which is what the Rust executable and Alpine's
`libgcc_s.so.1` request through `DT_NEEDED`. It is the same symmetric loader
search boundary used by the Alpine corpus, not an `LD_PRELOAD` workaround.

The fixture covers allocation, `Vec`/`String`, files/directories, environment,
clock, TCP, UDP, localhost DNS, threads, `Mutex`, `Condvar`, process spawn, a
child pipe, and stdio. A candidate mismatch is a crabc compatibility failure;
the report keeps the exact evidence needed to investigate it.

Host-side helper tests need no Rust toolchain:

```bash
python3 -m unittest discover -s compat/rust-std/tests -p 'test_*.py'
```

## Dependency-bearing application

The M10.5 workload is the normal Cargo application in
`dependent-fixture/`. Its pinned direct dependencies (`async-net`,
`futures-lite`, and `smol`) provide an async local TCP round trip while the
application also exercises filesystem state, a `Mutex`/`Condvar`, a captured
subprocess, and an explicit `NotFound` error path. Output is deterministic and
the same raw status/stdout/stderr comparison is used:

```bash
./scripts/dev.sh rust-std-dependent
python3 compat/rust-std/run.py \
  --fixture compat/rust-std/dependent-fixture/src/main.rs \
  --report compat/reports/rust-std-dependent/latest.json
```

The runner copies the application manifest (and `Cargo.lock` when supplied)
into its temporary project, builds it with stock `std`, and records dependency
presence in the structured report. The application is never linked against a
crabc-specific Rust library or invoked through `libldso.so` as a program.
