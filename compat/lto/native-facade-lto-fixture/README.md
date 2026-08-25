# Native `crabc-rs` LTO fixture

This package is a bounded `no_std` Linux/AArch64 application for comparing
an O3 control lane and fat LTO. It uses `crabc-rs` with `default-features = false`, fixed
stack buffers, and direct `fs`, `io`, `pipe`, `eventfd`, and process calls. It
does not call the public C ABI or read C `errno`. A successful run writes:

```text
native-facade-lto:ok
```

The fixture uses the installed crabc CRT through the sealed `crabc-cc` driver,
while its named `native_facade_direct_route` remains a direct `crabc-rs`
syscall witness. The harness disables Rust's self-contained musl link path and
records Cargo's actual linker argv, rejecting any musl CRT/sysroot, GCC target
runtime, compiler-rt, or Rust self-contained input. The equivalent candidate
setup (after `./scripts/dev.sh sysroot`) is:

```bash
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER="$PWD/target/crabc-sysroot/bin/crabc-cc"
export RUSTFLAGS="-C opt-level=3 -C codegen-units=1 -C panic=abort -C target-feature=-crt-static -C link-self-contained=no -C link-arg=-L$PWD/target/crabc-sysroot/usr/lib -C link-arg=-lc -C link-arg=-l:libcrabc-builtins.a"
cargo build --manifest-path compat/lto/native-facade-lto-fixture/Cargo.toml \
  --target aarch64-unknown-linux-musl --release
```

The harness uses LTO off for the O3 control and fat LTO with embedded bitcode
for the optimized lane. The exported
`crabc_rs_native_facade_getpid_witness` has three fixed direct `getpid` observations for
function-scoped `svc #0` inspection.
