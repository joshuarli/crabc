# Build and install owned products

The products are experimental and commit-pinned. There is no stable ABI, API,
header, or layout guarantee across revisions. Linux x86-64 remains in development.
Run Docker natively on Linux for the target architecture, never under emulation.
Run the commands from the checkout root with the pinned native image available.

The dispatcher selects the native architecture. Its work root is `.work/x86_64`
or `.work/aarch64`; the respective Rust target triples are
`x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl`.

## Build installed trees

Choose fresh output directories under the native work root. For example, set
`ARCH` from the native machine and run:

```sh
ARCH=$(uname -m)
./scripts/dev-x86_64.sh owned-posix-static-products .work/$ARCH/example-static
./scripts/dev-x86_64.sh materialized-dynamic-sysroot --work .work/$ARCH/example-dynamic
```

The primary static tree is `.work/$ARCH/example-static/products/primary`.
The build also produces `products/reproduction` and an extracted tree below
`products/extracted`. The primary dynamic tree is
`.work/$ARCH/example-dynamic/installed`; `second` and `extracted` are other
copies under the same work directory. These are installed trees in the checkout,
not system-wide installations.

The static tree contains `bin/crabc-cc`, headers in `usr/include`, CRT objects
and `libc.a` in `usr/lib`, and `usr/lib/libcrabc-builtins.a`. The dynamic tree
contains `bin/crabc-cc-dynamic`, `usr/include`, `usr/lib/libc.so`, CRT objects,
and compiler helpers. Its interpreter is `lib/ld-crabc-x86_64.so.1` or
`lib/ld-crabc-aarch64.so.1`, respectively. Both trees include product metadata
under `share/crabc`.

The separate static and combined sysroot suites are invoked with:

```sh
./scripts/dev-x86_64.sh owned-static-sysroot
./scripts/dev-x86_64.sh owned-combined-sysroot
```

## Compile and run a C consumer

Use the pinned image for the installed drivers. The following example uses the
repository's C consumer and writes outside the installed trees. Run it after
the builds above:

```sh
scripts/lanes/rust-check.sh sh -c '
  arch=$(uname -m)
  static=.work/$arch/example-static/products/primary
  "$static/bin/crabc-cc" -static compat/x86_64/owned_static_startup_tls_probe.c -o .work/$arch/consumer-static
  .work/$arch/consumer-static
'
```

For a standalone C source, substitute its path for the example source. The
example dynamic consumer also requires an application DSO, so build and supply
that DSO. The driver embeds the absolute interpreter path. Run the program in a
separate copy of the installed tree with `chroot` so that path resolves to the
owned interpreter. The image must permit `chroot`.

```sh
scripts/lanes/rust-check.sh sh -c '
  arch=$(uname -m)
  work=.work/$arch
  dynamic=$work/example-dynamic/installed
  "$dynamic/bin/crabc-cc-dynamic" --dynamic-shared-object compat/x86_64/owned_dynamic_dependency.c -o "$work/libexample.so"
  "$dynamic/bin/crabc-cc-dynamic" --dynamic-pie compat/x86_64/owned_dynamic_consumer.c --application-dso "$work/libexample.so" -o "$work/consumer-dynamic"
  cp -a "$dynamic" "$work/example-execution-root"
  mkdir "$work/example-execution-root/tmp"
  cp "$work/consumer-dynamic" "$work/example-execution-root/consumer"
  cp "$work/libexample.so" "$work/example-execution-root/usr/lib/libexample.so"
  chroot "$work/example-execution-root" /consumer
'
```

Use a fresh `example-execution-root`. For a standalone source with no application
DSO, omit the DSO build, `--application-dso` argument, and DSO copy.

## Other consumers

[Lua source-build commands](../compat/lua/README.md) cover static and dynamic
consumers. The direct `crabc-rs` facade and Rust std/LTO consumer commands are:

```sh
./scripts/dev-x86_64.sh facade
./scripts/dev-x86_64.sh consumer-rust-std-lto run --static-preparation STATIC_PREPARATION --dynamic-qualification DYNAMIC_QUALIFICATION --provider-vendor PROVIDER_VENDOR --dependency-vendor DEPENDENCY_VENDOR --output NEW_DIR
```

The Rust std/LTO command requires the preparation and qualification files from
the same product cohort and the two vendor inputs. See the
[qualification driver](../compat/x86_64/qualification_candidate.py) for their
use in the consumer invocation.
