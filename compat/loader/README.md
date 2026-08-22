# AArch64 loader inventory and evidence

Milestone 0 keeps the reference loader ABI and the crabc loader feature
surface explicit without treating either one as full loader parity.

## Reports

[`../abi/musl-1.2.6/aarch64/loader-runtime.json`](../abi/musl-1.2.6/aarch64/loader-runtime.json)
is a mechanically generated snapshot of musl 1.2.6's
`lib/ld-musl-aarch64.so.1`. The pinned installation makes that path a symlink
to `libc.so`; the report captures the link target and hashes, ELF headers,
program-header types, dynamic tags, relocation sections/types, and dynamic
symbol counts. It is a reference runtime shape, not a crabc implementation
report.

[`../abi/crabc/aarch64/loader-features.json`](../abi/crabc/aarch64/loader-features.json)
inspects the current AArch64 `target/debug/libldso.so` and
`ldso/src/lib.rs`. Each feature records source-marker evidence and, where
available, an existing loader test target. `runtime_test_executed` and
`verified` are intentionally `false`: generating this report does not run
tests and does not infer a pass from a symbol, constant, or test filename.

The feature states mean:

- `source_and_test_target`: source markers and a focused test target exist;
  no test result is asserted.
- `source_only`: source markers exist, but no focused test target is recorded.
- `surface_only`: a name or constant exists, but implementation evidence is
  intentionally insufficient. Runtime behavior belongs in the synthetic
  loader differential suite, not in this source inventory.
- `not_evidenced`: no implementation marker was found in the inspected source.

## Reproduce in native Docker

The image is pinned to Alpine 3.24.1 and `linux/arm64`. From the repository
root, run:

```sh
./scripts/dev.sh loader-inventory
```

The command builds the workspace, generates both reports with Python and
`readelf`, and runs the generator's byte-for-byte check. To invoke the script
directly inside the existing image:

```sh
docker run --rm --platform linux/arm64 \
  --workdir /workspace \
  --volume "$PWD:/workspace" \
  --volume crabc-target-aarch64:/workspace/target \
  --volume crabc-cargo-aarch64:/opt/cargo \
  crabc-dev:aarch64 \
  python3 compat/scripts/generate-aarch64-loader-inventory.py --check
```

The candidate report is tied to the hashes of the current loader artifact and
source. Regenerate it after changing `ldso/src/lib.rs` or rebuilding the
workspace.

The parser/report invariants can be checked without Docker dependencies:

```sh
python3 compat/loader/tests/test_inventory.py
```

## Runtime evidence targets

These existing Rust integration targets exercise the mechanisms named by the
candidate inventory when run in the native image:

```sh
./scripts/dev.sh test --test ldso_real_binary
./scripts/dev.sh test --test ldso_interp
./scripts/dev.sh test --test ldso_self_relocation
./scripts/dev.sh test --test ldso_deps
./scripts/dev.sh test --test ldso_startup
./scripts/dev.sh test --test ldso_tls
./scripts/dev.sh test --test dso_tls
```

Their existence is recorded as test-target evidence only. A passing run is not
copied into the generated inventory; retain command output separately when a
loader slice is ready to move to `verified`.
