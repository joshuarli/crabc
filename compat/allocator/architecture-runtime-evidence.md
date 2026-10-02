# Native allocator architecture runtime evidence

Architecture admission separates measurements from claims about source routes.
The native and pinned-C engine fixture already measures ordinary allocation,
independent local owners, and remote free through one external allocator boundary.
Its qualified reader checks every full-matrix raw sample, paired ordering,
workload parameters, source seal, retained executable and link-map bytes, and
recorded host contention before a measurement can be used.

`architecture-gate-v3.5.0.json` registers the schema-3
`perf_engine_x86_64.py` producer and its `validate_qualified_full_report` reader.
Registration enables consumption of genuine samples; it does not qualify a run.
Smoke, architecture-only, failed, incomplete, changed-source, changed-artifact,
and contended-host reports fail the qualified reader.

The existing `crabc-mimalloc-architecture-runtime-evidence` record accepts a
`benchmark_report` file identity:

```json
{
  "benchmark_report": {
    "path": "compat/reports/allocator/x86_64/perf-engine/run.json",
    "bytes": 123456,
    "sha256": "the actual SHA-256 of the retained report"
  }
}
```

This is a fragment of the runtime evidence record. Its selected-production
source hashes, selected artifact, exact `promotion_qualified` scope, metrics
object, and explicit `phase_bc` fields remain required. The report's sibling
`run.artifacts` directory must retain the products and link maps expected by
the engine reader. Paths may be checkout-relative, so a reader can consume a
retained report after its owning worktree is removed.

`architecture_ratchet.py` derives the one-sided 95% lower native/C throughput
bound for `local_scaling_1`, `local_scaling_4`, and `remote_free_1`. These become
`single_thread_throughput_ratio`, `four_thread_local_throughput_ratio`, and
`cross_thread_free_throughput_ratio`, respectively. Each must meet the existing
critical-workload lower bound from
`performance_release_gate.ALLOCATOR_CRITICAL_THROUGHPUT_LOWER_MIN` (0.90).
A slow but otherwise qualified measurement is retained as a threshold failure.
An optional metric claim in the runtime record must match the derived value;
booleans and status strings cannot stand in for a ratio.

The complete allocator suite, tail-latency, memory-ratio, repeated-report, and
runtime performance requirements remain owned by the release performance gate.
Passing the three architecture throughput rows does not close those obligations.

Allocator metadata high-water and plateau are separate observations. Process
RSS/PSS, application workload liveness, PageMap registrations, and metadata
capability counts do not establish byte-valued allocator metadata high-water.
The current benchmark receipt does not produce that observation. Neither does
it produce ordinary-operation scheduler, structural PageMap lease, owner/client
scan, extra allocation-control-byte, owner-exit admission, or compiled-scaffolding
observations. `load_runtime_evidence` returns verified throughput separately in
`validated_metrics`; `gate_unmet` keeps every unsupported raw-observation
requirement unmet even if the supplied `metrics` and `phase_bc` claims match the
required values. A future observation producer must expose the actual source
state and bind it to the measured artifacts before its reader can admit it.

Read the retained runtime record through the existing command:

```sh
python3 compat/allocator/architecture_ratchet.py \
  --runtime-evidence compat/reports/allocator/x86_64/runtime-evidence.json \
  --report .work/architecture/runtime-report.json --check
```

`--check` validates supplied inputs and the source ratchet. `--gate` additionally
requires every architecture obligation, including the independently verified
unmodified upstream stress and raw runtime/artifact observations. Missing
observations keep final admission open.
