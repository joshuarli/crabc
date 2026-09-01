# Canonical upstream `test-stress.c` lane

`run.py` is the canonical, source-unmodified upstream stress lane for the
selected `native-mimalloc-shadow` `crabc-libc`. It extracts the SHA-256-pinned
mimalloc v3.5.0 archive and compiles its exact `test/test-stress.c` member with
only the upstream `USE_STD_MALLOC` preprocessor symbol. This selects standard
`calloc`, `realloc`, and `free` names from the selected crabc libc; it does not
apply a patch, copy a source fixture, alter worker scheduling, or move the
upstream initial-thread transfer cleanup into another thread.

The closed applicable matrix invokes that one binary in fresh processes with
1, 2, 4, and 8 pthread workers, first at scale/iterations `1 1` and then at
`2 2`. Each case has one 30-second watchdog and no retry. Cases run in manifest
order and dispatch stops at the first non-pass; the runner never shrinks or
reschedules a source case. The source itself fixes `srand(0x7feb352d)` and each
worker's local state starts from `(tid + 1) * 43`; pthread scheduling remains
nondeterministic and there is no harness seed override. Large-object mode is
explicitly not claimed.

The canonical Docker-first dispatch builds the owned sysroot, builds the
selected shadow libc last, stages the owned loader, and runs the matrix:

```sh
./scripts/dev.sh allocator-upstream
```

Before the full matrix compiles its archived source or starts a stress process,
it attests the current-head companion written beside the selected Cargo build
record. Capture always records the source state before and after Cargo so a
dirty, changed, or non-Git source remains observable. Full-matrix execution
requires both captured states and the execution-time state to be the same
clean Git `HEAD`; it also rebinds the companion to the normal Cargo record and
both selected libc hashes. A missing, dirty, changed, non-Git, or mismatched
companion produces an atomic `status: "blocked"` report before source
compilation or a stress process. The full report's `current_head` object has
the same `status`, `record`, and `source` schema and meaning as the diagnostic
report below.

Runner-owned mutable state defaults below `CRABC_WORK_DIR`, or the checkout's
`.work/` directory when that variable is unset: the pinned archive and tag
attestation use `.work/allocator-cache/`, fixture output and selected-libc
build records use `.work/target/`, and reports use `.work/reports/`. The
selected runtime remains the logical `target/debug` ABI location; the canonical
dispatcher maps the repository-local work target there for the container.

## Current-head first-case diagnostic

For a reproducible, narrowly scoped observation of the current checkout, run:

```sh
./scripts/dev.sh allocator-upstream --diagnose
```

The dispatch still builds the selected `native-mimalloc-shadow` libc last. Its
capture phase writes the normal selected Cargo compiler-artifact record plus
`selected-libc-build-current-head.json`, recording source state before and
after Cargo even when it cannot later qualify as current-head evidence. The
diagnostic applies the same clean, unchanged Git capture-and-execution
attestation as the full matrix and refuses a missing, dirty, changed, non-Git,
or mismatched source/build companion before it starts a stress process.

`--diagnose` compiles the same byte-for-byte archived source with the same
`USE_STD_MALLOC` selection, verifies the same ELF and selected-free route
boundaries, and executes only the first closed case: `1 1 1`. Its fixture is
isolated under `.work/target/compat/allocator/upstream-stress/current-head/`
and its default report is
`.work/reports/allocator/upstream-stress/current-head.json` (override with
`CRABC_UPSTREAM_STRESS_DIAGNOSTIC_REPORT` or `--report`). The report records
the current-head companion, Cargo artifact hashes, runtime `LD_LIBRARY_PATH`
selection, `DT_NEEDED` proof, and the complete process observation.
When using custom selected-build paths, pass the same derived or explicit
`--current-head-build-record` to the capture and diagnostic phases.

A diagnostic `status: "passed"` means only that this one current-head source
case produced the exact expected result. Its report separately fixes the
canonical matrix at `status: "not-run"` and M5 acceptance at `false`; it is
never full-matrix, allocator-promotion, large-object, or M5 evidence.

The owned-suite wrapper is required. Before entering it, the canonical
dispatch builds `crabc-libc` with Cargo's JSON message format and atomically
records the exact matching compiler-artifact from that invocation plus the
source-state companion. The normal record binds the `crabc-libc` package and
library target to the `dev` semantic profile, exact
`default,native-mimalloc-shadow` features, ordered `libc.so` and `libc.a`
filenames, and both files' byte counts and SHA-256 hashes. The runner does not
select from Cargo's global fingerprint cache, so legitimate coexisting dev and
test fingerprints do not make the selected build ambiguous.

The owned-suite wrapper stages the owned canonical loader and debug libc
aliases for the test process; the lane itself then selects the attested
`target/debug/libc.so` via `LD_LIBRARY_PATH`. Before execution it rehashes both
Cargo outputs against the passed build record and rejects an exported `free`
route to the C `mi_free` backend. It also requires the staged
`/lib/ld-crabc-aarch64.so.1` bytes to match the selected loader, then attests
that the compiled fixture is little-endian AArch64 ELF64 with that exact
`PT_INTERP` and only the expected `libc.so` `DT_NEEDED` entry. By default, the
runner writes its binary and selected-libc build record under
`.work/target/compat/allocator/upstream-stress/` and atomically publishes the
report at `.work/reports/allocator/upstream-stress/latest.json`. Override
those ignored outputs with `CRABC_UPSTREAM_STRESS_OUTPUT_DIR`,
`CRABC_UPSTREAM_STRESS_LIBC_BUILD_RECORD`, and
`CRABC_UPSTREAM_STRESS_REPORT`. Pass runner options through the canonical
dispatch, for example `./scripts/dev.sh allocator-upstream --offline`.
`--offline` requires both the verified source archive and annotated-tag
attestation already present in `.work/allocator-cache/`; direct host
`python3 compat/allocator/upstream-stress/run.py --check` validates only the
closed contract and reports capability `not-run`, without compiling or
executing it.

The checked-in manifest inventories the sole applicable target
(`Linux/AArch64` little-endian, kernel baseline 5.10), the nondefault native
shadow backend, the source seed policy, per-process watchdog, and report
schema. Report format 5 records the passed Cargo build record, a required
current-head companion attestation, and the selected shared and static libc
artifacts separately. Every file artifact record has `path`, `bytes`, and
`sha256`; captured
stdout/stderr records have `bytes`, `sha256`, and `hex`. The report reserves
named slots for the contract, pinned archive/source, owned sysroot inputs,
selected and staged loaders, both libc outputs, the backend build record, and compiled stress
binary; `current_head.record` identifies the separate companion. The extracted source artifact is recorded as the stable archive member
`mimalloc-3.5.0/test/test-stress.c`; compiler commands and diagnostics replace
the deleted random extraction directory with
`<pinned-source>/mimalloc-3.5.0`, so identical observations serialize
deterministically.

If a native prerequisite is unavailable, the runner still atomically writes a
report with `status: "blocked"`. Its `blocked` record names the exact missing
boundary—such as the owned-sysroot manifest/driver, selected shadow libc,
missing compiler-artifact build record,
selected loader, owned canonical-loader staging, native Linux/AArch64 host, or
the current-head source/build attestation—and declares that no stress process
started. Capability status is fail-closed:
`not-run`, `blocked`, and `failed` are all non-success states, and `passed` is
published only after every listed case completes natively with its exact
expected status and streams. A blocked or partial report is neither a pass nor
a skipped workload result.

This is intentionally separate from `native-shadow-stress-v3.5.0.json` and
its patched fresh-pthread cleanup witness. That witness may remain useful as a
narrow regression, but it cannot stand in for this canonical upstream lane.
