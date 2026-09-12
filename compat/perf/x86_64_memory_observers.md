# Native x86-64 legacy memory observers

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
