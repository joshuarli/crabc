# Native `crabc-rs` LTO fixture

This package is a bounded `no_std` Linux/AArch64 application for comparing
an O3 control lane and fat LTO. It uses `crabc-rs` with `default-features = false`, fixed
stack buffers, and direct `fs`, `io`, `pipe`, `eventfd`, and process calls. It
does not call the public C ABI or read C `errno`. A successful run writes:

```text
native-facade-lto:ok
```

The fixture uses the target's normal dynamic musl startup objects, while its
named `native_facade_direct_route` remains a direct `crabc-rs` syscall witness. The
equivalent build setup (with the candidate runtime already built) is:

```bash
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=clang
export RUSTFLAGS='-C opt-level=3 -C codegen-units=1 -C panic=abort -C target-feature=-crt-static -C link-arg=--target=aarch64-unknown-linux-musl -C link-arg=--sysroot=/opt/musl-1.2.6 -C link-arg=-fuse-ld=lld -C link-arg=-L/workspace/target/debug -C link-arg=-lc'
cargo build --manifest-path compat/lto/native-facade-lto-fixture/Cargo.toml \
  --target aarch64-unknown-linux-musl --release
```

The harness uses LTO off for the O3 control and fat LTO with embedded bitcode
for the optimized lane. The exported
`crabc_rs_native_facade_getpid_witness` has three fixed direct `getpid` observations for
function-scoped `svc #0` inspection.
