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

The runner requires native AArch64, Rust channel selected by `rust-toolchain.toml`, the pinned musl
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

The dependency-bearing workload is the normal Cargo application in
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

## Native x86-64 consumer gate

The frozen AArch64 runner above is paused. On native Linux/x86-64 both
fixtures are reproduced unchanged by `compat/x86_64/consumer_rust_std_lto.py`,
the leaf of the `consumer.rust-std-lto` qualification gate (it also covers the
`compat/lto` gates):

```sh
./scripts/dev-x86_64.sh consumer-rust-std-lto-vendor .work/x86_64/RUN/fixture-vendor
./scripts/dev-x86_64.sh consumer-rust-std-lto run \
  --static-preparation .work/x86_64/STATIC/preparation.json \
  --dynamic-qualification .work/x86_64/tmp/materialized-dynamic.XXXX/qualification.json \
  --provider-vendor .work/x86_64/RUN/provider-vendor \
  --dependency-vendor .work/x86_64/RUN/fixture-vendor \
  --output .work/x86_64/RUN/consumer
```

The only networked step vendors the dependency-bearing and native-facade
fixtures' locked crates; `dependency_vendor` rehashes every vendored file
against those locks. The build itself is `--offline`, with Rust's own
`library/vendor` and that fixture vendor composed by
`owned_cleanup.compose_offline_cargo_sources`.

The x86 purity contract changes one thing: the candidate is no longer the
musl-linked image run with swapped runtime bytes. The same stock sources are
built with `-Z build-std=std,panic_abort` twice. The candidate is linked by
the Cargo origin of `unwinder/owned_rust_link.py` from the installed dynamic
product and the fresh `libcrabc-unwind.a`, which Rust's `-lgcc_s` request
selects by ordinary archive extraction; the control is linked by the pinned
musl oracle compiler with the frozen `-L/usr/lib` libgcc path. Each runs by
kernel `PT_INTERP` in a private chroot root. The roots share `/tmp`,
`/dev/null`, a localhost `/etc/hosts` and a `/proc/self/exe` link for
`current_exe()`, and differ only in runtime files (the installed product
versus pinned musl plus `libgcc_s.so.1`). Status, stdout and stderr compare
raw.
