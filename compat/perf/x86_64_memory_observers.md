# Native x86-64 memory observers

`x86_64_memory_observer_workload.c`,
`x86_64_memory_observer_constructor.c`, and
`x86_64_memory_observer_graph.c` are the separate memory-observer artifacts
for the 74 frozen legacy performance rows.  Each translation unit includes its
corresponding fixture unchanged after renaming its original `main`; the timed
fixtures remain untouched.  The adapter selects one of these three observer
artifacts by source family and records that artifact identity for every memory
sample.  It passes the exact timed argv with no observer-specific CLI flag.

The closed row-to-source-family/category roster is
`CRABC_PERF_MEMORY_OBSERVER_ROSTER` in
`x86_64_memory_observer_protocol.h`.  The focused contract test compares all
74 entries with both `run.py:WORKLOADS` and the
`legacy_memory_phase` entries in `x86_64-profile.toml`.

## Supplemental source families

The 40 supplemental rows use three additional memory-only artifacts. The
adapter replaces only `argv[0]`; the selected artifact receives the timed
fixture's unchanged mode, iteration count, and fixed arguments.

| Timed source family | Memory artifact identity and source | Closed profile rows | Source-owned plateau |
| --- | --- | --- | --- |
| `x86_64_clock_allocator_workload` | `x86_64_memory_observer_clock_allocator` — `x86_64_memory_observer_clock_allocator.c` | `clock_gettime_realtime`, `clock_gettime_process_cpu`, `clock_gettime_thread_cpu`, `clock_gettime_monotonic_raw`, `clock_gettime_realtime_coarse`, `clock_gettime_monotonic_coarse`, `clock_gettime_boottime`, `clock_gettime_realtime_alarm`, `clock_gettime_boottime_alarm`, `clock_gettime_tai`, `allocator_live_4m`, `allocator_live_32m`, `allocator_refill_4m`, `allocator_worker_local_64`, `allocator_worker_local_4k` | `clock-final-call`, `allocator-live`, `allocator-refill-live`, or `allocator-workers-complete` |
| `x86_64_network_workload` | `x86_64_memory_observer_network` — `x86_64_memory_observer_network.c` | `loopback_tcp_ipv4_4k`, `loopback_tcp_ipv6_4k`, `loopback_udp_ipv4_4k`, `loopback_udp_ipv6_4k`, `resolver_hosts`, `resolver_dns_dual`, `resolver_dns_tcp` | `network-final-echo-open` or `resolver-final-result-live` |
| `x86_64_primitive_boundary_workload` | `x86_64_memory_observer_primitive` — `x86_64_memory_observer_primitive.c` | each of `memcpy`, `memset`, `strlen`, `memchr`, `strstr`, and `memmem` with `empty`, `short31_unaligned`, and `guard63` | `primitive-guard-window-live` |

Each supplemental translation unit includes its corresponding timed source
unchanged after renaming the source `main`. It redirects only that source's
existing `crabc_perf_observer_reach` call, so the fixed profile plateau stays
at the original live resource and the wrapper adds `main-initial` before the
renamed `main` and `main-final` after its successful return. It has no
row-specific work, peer, allocation, or output path.

Together, the three legacy and three supplemental artifact families cover the
closed 74 + 40 = 114 memory rows. This is six artifact families, not a
requirement to compile or link 114 separate executables.

## R/C boundary

The opt-in wire protocol is `crabc.perf.observer-r-c/v1`.

- With both `CRABC_PERF_OBSERVER_READY_FD` and
  `CRABC_PERF_OBSERVER_CONTINUE_FD` absent, an observer runs its frozen source
  normally and does no observer descriptor I/O.
- With observation enabled, their only accepted values are canonical `97` and
  `98`.  Every declared checkpoint writes one `R` to 97 and requires one `C`
  from 98.  A partial or malformed pair exits before source work. Failure at
  the initial handshake skips the original main; a missing or wrong
  acknowledgement at a later checkpoint makes the observer fail after the
  unchanged source has taken its normal cleanup path.
- `main-initial` precedes the renamed original main and `main-final` follows a
  successful original main.  The three startup rows use only those two phases.
  Other rows add exactly one category phase, except dynamic TLS, which adds
  `tls-parent-load-0` through `tls-parent-load-7` and then
  `tls-worker-complete`.

The source-local wrappers preserve the wrapped call's result and `errno`
across observer-only descriptor operations.  They pause before the source
resource releases (`close`, `fclose`, `free`, `munmap`, `dlclose`, and mutex
destruction), after the final selected clock call, and in a fixed-storage
trampoline after the original worker callback returns but before that worker
exits.  Scalar rows pause immediately before the frozen source's real
`puts("ok")`; no observer defers, fabricates, or re-emits stdout.  The
constructor fixture's direct `write("ok\\n")` likewise occurs in the real
original main before `main-final`.

The supplemental wrapper likewise restores `errno` around its initial,
source-plateau, and final descriptor I/O. It accepts only the canonical `97` /
`98` pair. A malformed pair fails before the renamed source `main`; a failed
initial R/C skips it; a later failed source plateau lets the source perform its
ordinary cleanup; and `main-final` occurs after the source's real `puts` and
return path.

The observer does not infer that `dlclose` unmaps an image.  Its TLS and DSO
checkpoints prove live handles/mappings before the source close; retained
closed mappings follow the established
[`materialized dynamic sysroot`](../x86_64/materialized-dynamic-sysroot.md)
contract.

`compat/perf/tests/run_x86_64_memory_observers_smoke.py` is a reduced pinned
native correctness smoke.  It checks the R/C ordering, real live-resource
plateaus, failure cleanup, preserved source output/status, distinct observer
ELF identities, and the multi-iteration TLS callback boundary.  It is not a
timing run or release-qualification result.

`compat/perf/tests/run_x86_64_supplemental_memory_observers_smoke.py` gives
the same reduced native implementation evidence for all 40 supplemental
routes. It checks the three-checkpoint order, source-owned allocation, socket,
and guarded-mapping plateaus, resolver and loopback setup, cleanup failures,
real source stdout before the final checkpoint, and distinct timed/memory ELF
identities. It is also not timing or release-qualification evidence.
