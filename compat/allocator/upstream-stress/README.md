# Canonical upstream `test-stress.c` lane

`run.py` is the canonical, source-unmodified upstream stress lane for the
selected `native-mimalloc-shadow` `crabc-libc`. It extracts the SHA-256-pinned
mimalloc v3.5.0 archive and compiles its exact `test/test-stress.c` member with
only the upstream `USE_STD_MALLOC` preprocessor symbol. This selects standard
`calloc`, `realloc`, and `free` names from the selected crabc libc; it does not
apply a patch, copy a source fixture, alter worker scheduling, or move the
upstream initial-thread transfer cleanup into another thread.

The current canonical invocation is intentionally the smallest audited
configuration: one worker, scale one, and one iteration. The report records
the one attempted process as the first failure or pass fact. It does not retry
or shrink the workload, and it is not a claim that the mandatory larger
upstream stress matrix has passed.

Run this from the native Linux/AArch64 development image after building the
owned sysroot and then building the selected shadow libc last:

```sh
./scripts/dev.sh shell

cargo build --workspace
cargo build --workspace --release
python3 scripts/build_owned_sysroot.py
cargo build -p crabc-libc --features native-mimalloc-shadow
python3 scripts/run_owned_test_suite.py \
  --sysroot target/crabc-sysroot \
  --loader target/debug/libldso.so \
  -- python3 compat/allocator/upstream-stress/run.py
```

The owned-suite wrapper is required. It stages the owned canonical loader and
debug libc aliases for the test process; the lane itself then selects the
last-built `target/debug/libc.so` via `LD_LIBRARY_PATH`. The runner writes its
binary only under `target/compat/allocator/upstream-stress/` and atomically
publishes the report at
`compat/reports/allocator/upstream-stress/latest.json`. Override those ignored
outputs with `CRABC_UPSTREAM_STRESS_OUTPUT_DIR` and
`CRABC_UPSTREAM_STRESS_REPORT`. `--offline` requires both the verified source
archive and annotated-tag attestation already present in
`compat/allocator/.cache/`; `--check` validates the closed source/build/ownership
contract without compiling or executing it.

This is intentionally separate from `native-shadow-stress-v3.5.0.json` and
its patched fresh-pthread cleanup witness. That witness may remain useful as a
narrow regression, but it cannot stand in for this canonical upstream lane.
