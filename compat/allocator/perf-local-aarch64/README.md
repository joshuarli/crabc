# Local AArch64 allocator performance smoke

`run.py` compares one source-shared, single-thread allocation/free fixture
through two opaque, fixture-private boundaries: the SHA-verified pinned
mimalloc v3.5.0 C source and the prefixed `crabc_test_*` Rust-native shadow
adapter. It records the exact workload sizes, batches, iterations, warmups,
host observation, build commands, source/artifact hashes, and the Rust/C
throughput ratio in a JSON report.

Run it inside the pinned AArch64 development image:

```sh
python3 compat/allocator/perf-local-aarch64/run.py --smoke --label local
```

The default output is
`compat/reports/allocator/aarch64/local-perf/<label>.json`. Rust builds use a
temporary `--target-dir`; this lane never writes the shared workspace target.

This is deliberately an early architecture smoke. Its `0.25` throughput
ratio is the local ratchet from `native-mimalloc.md` §3.4/§7.3, not a final
performance target. The report always records
`final_promotion_qualified: false`: Docker is useful development evidence,
but final promotion needs the separately scoped qualified native Linux/AArch64
suite described in §19.2.

The script exits nonzero after writing a complete report if either workload is
below the architecture-smoke ratio. It makes no public `mi_*`, libc-backend,
cross-thread, memory, latency, or final-promotion claim.
