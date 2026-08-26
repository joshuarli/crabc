# Native x86_64 core evidence

This closed, native Linux/x86_64 lane is the first foundation evidence named
by [`x86-64.md`](../../x86-64.md). It runs only `crabc-core` lib tests for the
`x86_64-unknown-linux-musl` target; it is not public x86_64 runtime support.

Run it only on a native Linux x86_64 host:

```sh
./scripts/dev-x86_64.sh image
./scripts/dev-x86_64.sh core
```

The runner rejects non-Linux and non-x86_64 hosts before Docker, requests
`linux/amd64` for both image build and execution, and validates the image
identity. Its exact evidence command is:

```sh
cargo test --locked --target x86_64-unknown-linux-musl -p crabc-core --lib --no-default-features -- --test-threads=1
```

The lane owns no allocator evidence and exposes no generic Cargo, shell, libc,
dynamic-loader, CRT, sysroot, or `crabc-rs` command. Those remain separate
future completion work under `x86-64.md`; passing this command must not be
reported as x86_64 runtime parity.
