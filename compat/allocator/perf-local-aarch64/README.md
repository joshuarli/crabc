# Local AArch64 allocator performance smoke

`run.py` compares one source-shared, single-thread allocation/free fixture
through two opaque, fixture-private boundaries: the SHA-verified pinned
mimalloc v3.5.0 C source and the prefixed `crabc_test_*` Rust-native shadow
adapter. It records the exact workload sizes, batches, iterations, warmups,
host observation, build commands, source/artifact hashes, and the Rust/C
throughput ratio in a JSON report.

Before timing, the Rust lane executes a fixture-private selected-artifact
attestation. It requires the build identity
`rust-native-shadow-crabc-test-free-v1`, the `crabc_test_free` route, the
linked executable's `crabc_test_free` symbol, and absence of `mi_free`. The
report records the backend-source, static-archive, executable, and canonical
build-identity hashes. A C/default fixture cannot enter the Rust timing lane.

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

`measurement_boundary.kind` is explicitly
`direct-engine-friend-boundary`: the prefixed `crabc_test_*` adapter enters the
Rust engine directly, rather than measuring `crabc-libc`'s production
malloc-family ABI/backend selection. Its boundary record sets both
`production_libc_measurement` and
`final_promotion_qualification_eligible` to `false`; report validation rejects
any attempt to promote a passing friend-boundary ratio.

The script exits nonzero after writing a complete report if either workload is
below the architecture-smoke ratio. It makes no public `mi_*`, libc-backend,
cross-thread, memory, latency, or final-promotion claim.
