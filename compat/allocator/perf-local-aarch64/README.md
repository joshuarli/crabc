# Local AArch64 allocator worker-performance smoke

`run.py` compares the same C fixture against two intentionally narrow
boundaries at 1, 2, 4, and 8 ordinary pthread workers:

- pinned mimalloc v3.5.0 C source through the fixture-private direct
  `mi_malloc`/`mi_free` shim;
- one freshly built Cargo-release `crabc-libc` with the compile-time
  `native-mimalloc-shadow` feature, through the fixture-private normal C-ABI
  `malloc`/`free` shim.

Every worker allocates, touches, and frees only its own blocks for multiple
batches, then returns normally and is joined before shutdown. The fixture has
no address handoff, allocation ledger, route table, or scheduler transition.
Its three batch barriers only form a common ready/start/finish interval; one
`CLOCK_MONOTONIC` pair measures every all-worker batch.

Before timing the Rust lane, the harness records and requires all of these:

- a fresh Cargo-release fingerprint with exactly `default` and
  `native-mimalloc-shadow` enabled;
- the selected `libc.so` hash, its exported `malloc`/`free`, no `mi_*`
  relocation, and no direct `malloc`/`free` transfer to `mi_*`;
- an exact `-l:libc.so` link with `-nodefaultlibs`, one selected library root,
  the owned builtins archive after libc, a linker trace containing the selected
  artifact, and no sysroot `libc.so` selection;
- a fixture `DT_NEEDED` list containing only `libc.so`, no RPATH/RUNPATH, and
  the canonical owned loader.

The JSON report contains raw batch durations, elapsed wall time, operation
counts, randomized paired sample plans, warmups, build commands, source and
artifact hashes, host affinity, worker oversubscription facts, and the
Rust/C throughput ratio for every workload/worker-scale pair. A ratio is never
published without those raw samples and provenance.

This is an early architecture smoke. Its `0.25` ratio is the local ratchet in
`native-mimalloc.md` §§7.2–7.3, not a final band. The report always records
`final_promotion_qualified: false`. Apple-Silicon Docker is useful for this
development smoke but is explicitly unqualified for promotion; §19.2 requires
a recorded native Linux/AArch64 final-performance environment.

The harness requires an existing owned sysroot and its staged loader because
the selected Rust C-ABI fixture must run through crabc's real pthread/runtime
boundary. Run it in the pinned AArch64 image after the ordinary sysroot has
been built, using a unique worktree target directory for the loader:

```sh
CARGO_TARGET_DIR=/workspace/target/wave-07-w09-local-performance-smoke \
  cargo build --locked --package crabc-ldso

python3 scripts/run_owned_test_suite.py \
  --sysroot target/crabc-sysroot \
  --loader target/wave-07-w09-local-performance-smoke/debug/libldso.so \
  -- python3 compat/allocator/perf-local-aarch64/run.py --smoke --label local
```

`run.py` creates its own temporary Cargo target for the selected shadow
`libc.so`; it does not reuse a normal workspace artifact. The default report
path is `compat/reports/allocator/aarch64/local-perf/<label>.json`. A completed
report can be architecture-blocked when any ratio is below `0.25`; neither
outcome is a final-promotion claim.
