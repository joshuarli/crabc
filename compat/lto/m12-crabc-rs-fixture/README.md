# M12 native `crabc-rs` fixture

This package is a bounded `no_std` Linux/AArch64 application for comparing
an O3 control lane and fat LTO. It uses `crabc-rs` with `default-features = false`, fixed
stack buffers, and direct `fs`, `io`, `pipe`, `eventfd`, and process calls. It
does not call the public C ABI or read C `errno`. A successful run writes:

```text
m12-crabc-rs:ok
```

The fixture uses the target's normal dynamic musl startup objects, while its
named `m12_direct_route` remains a direct `crabc-rs` syscall witness. The
equivalent build setup (with the candidate runtime already built) is:

```bash
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=clang
export RUSTFLAGS='-C opt-level=3 -C codegen-units=1 -C panic=abort -C target-feature=-crt-static -C link-arg=--target=aarch64-unknown-linux-musl -C link-arg=--sysroot=/opt/musl-1.2.6 -C link-arg=-fuse-ld=lld -C link-arg=-L/workspace/target/debug -C link-arg=-lc'
cargo build --manifest-path compat/lto/m12-crabc-rs-fixture/Cargo.toml \
  --target aarch64-unknown-linux-musl --release
```

The harness uses LTO off for the O3 control and fat LTO with embedded bitcode
for the optimized lane. The exported
`crabc_rs_m12_getpid_witness` has three fixed direct `getpid` observations for
function-scoped `svc #0` inspection.
