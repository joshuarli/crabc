# Native x86-64 allocator harness

The allocator harness reproduces and checks the fixed mimalloc v3.5.0 Rust
port against the pinned C source: it builds the C oracle, runs deterministic
C/Rust differential lanes, the Rust unit and integration suites, the milestone
gates, and the allocator performance and codegen measurements. Native
Linux/x86-64 is the only active target. The paused AArch64 route is in
[`aarch64.md`](aarch64.md); its reports never qualify x86 and x86 reports never
qualify AArch64.

Related: the allocator design is in
[`docs/design/allocator.md`](../../docs/design/allocator.md), the Rust/C
difference register is [`known-differences.md`](known-differences.md), the
source pins and licensing are in
[`crabc-mimalloc/UPSTREAM.md`](../../crabc-mimalloc/UPSTREAM.md), and the
repository plan is [`plan.md`](../../plan.md). Reports are measurements, never
qualification by themselves; the checked-in contracts below are the review
inputs.

## Narrowest loops

All commands run through `./compat/allocator/run-x86_64.sh`, which starts the
pinned allocator container image (`image` builds it; every other command builds
it on first use).

```sh
# One Rust unit test. The name must be fully qualified (contain `::`) and is run
# with `--exact`; zero matches, an ignored test, or a failure all fail.
./compat/allocator/run-x86_64.sh allocator-unit --filter module::tests::exact_test_name
# Compare public Theap behavior in release or the opt0 debug product. Both run
# the main, worker, child-subprocess, and fork contexts.
./compat/allocator/run-x86_64.sh allocator-public-theap [--debug]
# The whole crabc-mimalloc library unit suite.
./compat/allocator/run-x86_64.sh allocator-unit
# Local engine under strict-provenance Miri only (writes a separate report, never closes M3).
./compat/allocator/run-x86_64.sh allocator-m3 --miri-only
# Contract/source-map regeneration check plus the five exact C oracle profiles.
./compat/allocator/run-x86_64.sh allocator --quick
```

`allocator-unit --filter` and `allocator-unit` produce no qualification
receipt. They build at the workspace `opt-level = 2` dev profile, so a cold
target directory takes minutes (about five on the reference host); later runs
reuse `.work/allocator-x86_64/target`. The other `allocator-m3` subsets are `--differential-only`,
`--owner-only`, `--miri-ownership-only`, `--miri-guarded-ownership-only`,
`--miri-page-ownership-only`, `--page-ownership-only`, and
`--queue-reorder-only`.

Python-only checks need no container (see
[Host-side Python tests](#host-side-python-tests)):

```sh
python3 scripts/test_python.py --module compat/allocator/tests/test_x86_64_runner.py
```

## Launcher

`run-x86_64.sh` is a closed command set. It requires a native x86-64 host
(emulation is refused), provides no generic shell or Cargo, and builds no
crabc libc, loader, sysroot, or `crabc-rs`. `./compat/allocator/run-x86_64.sh
--help` prints the complete command list; an unknown command exits 2.

- State lives under `.work/allocator-x86_64/`: `cargo/`, `target/`, `tmp/`,
  `reports/`, and `allocator-cache/` (verified source archive and tag
  attestation; a direct host run of `run.py` uses `.work/allocator-cache/`
  instead). Inside the container `reports/` is `compat/reports/`. Two roots
  hold results: `target/compat/allocator/x86_64/<lane>/` holds lane logs, oracle
  builds, and evidence JSON, and also the `report.json` of the M4, M5, M6, M7,
  M9, and M10 gates (`<gate>` is `m4-gate`, and so on) and the M3 traces and
  workloads (`m3-local-engine/`); `reports/allocator/x86_64/` holds the M1, M2,
  M3, and `allocator --quick` records (`m1-foundations-latest.json`,
  `m2-memory-substrate-latest.json`, `m3-local-engine-latest.json`,
  `latest.json`), the M8 gate (`m8-gate/`), the performance reports, and the
  huge/NUMA receipt. Each command prints the paths it wrote.
- `CRABC_ALLOCATOR_X86_64_WORK_DIR` selects an isolated physical descendant of
  that directory; escaping paths and symlinks are rejected before Docker
  starts.
- `CRABC_ALLOCATOR_X86_64_CPU_LIMIT` (Docker CPU quota) and `CARGO_BUILD_JOBS`
  are forwarded only when set; each must be a positive integer.
- The image authenticates its toolchain (the dated nightly in
  `rust-toolchain.toml`, musl 1.2.6 oracle, Miri) before every run.
- In a linked git worktree the launcher mounts the worktree's git metadata
  read-only so revision attestation works; it never invents a clean state.
- `allocator-huge-numa-qualification` adds `CAP_IPC_LOCK`;
  `allocator-perf-integrated` and `allocator-m9` (except `--check` and
  `--reader-tests`) run in the pinned core evidence image because the installed product builders and the
  integrated-product reader need the owned Linux UAPI inputs (the integrated
  lane compiles with `/usr/local/bin/crabc-x86_64-musl-gcc`; every other lane,
  including `allocator-perf-engine`, uses the allocator image's `musl-gcc`);
  `allocator-heap-convenience --read|--replay` and `allocator-m4
  --operations-matrix --read|--replay` re-read retained inputs with a
  read-only mount and no network.
- Reviewed source manifests keep their original archive-path spelling;
  relocating the execution path does not change upstream identity or archive
  hash verification.

## Commands

Arguments are as `--help` lists them; the launcher rejects anything else.

### Gates

Gates are fail-closed: they print every unmet prerequisite and exit nonzero
until all evidence passes. Each has a checked-in contract except M9, which its
script defines.

| Command | Contract and behavior |
| --- | --- |
| `allocator --quick` | `run.py --quick`: verifies the annotated tag and archive identities, regenerates the checked-in contracts in memory, checks the source-map ratchet, builds the exact C oracle profiles, and checks the allocator dependency graph (see [Random state in the design](../../docs/design/allocator.md#random-state)). |
| `allocator-m1` | `run.py --m1 --offline --architecture x86_64` (the launcher supplies the architecture; a direct `run.py` defaults to the paused AArch64 route) against `m1-foundations-x86_64-v3.5.0.json`. A partial report exits 3. |
| `allocator-m2` | `m2-memory-substrate-x86_64-v3.5.0.json`: memory-substrate evidence for eight components (VM primitives, metadata, bitmaps, PageMap, arenas, initialization, fault injection, allocator recursion). A partial report exits 3. See [What `allocator-m2` compares](#what-allocator-m2-compares). |
| `allocator-m3 [subset]` | `m3-local-engine-x86_64-v3.5.0.json`. Requires complete M1/M2 reports, then runs `m3_x86_64.py`: generated workloads (a sweep of every reachable bin past one page, retirement/reuse probes, generic administration, queue-candidate probes, seeded churn) run in separate pinned-C (`m3_local_trace_x86_64.c`, default Theap, `MIMALLOC_PAGE_FULL_RETAIN=-1`) and Rust (`single_thread::local_trace`) processes over identical in-place arenas, and their normalized traces must match line by line. It also derives the bin/page-class transition matrix and runs the queue reorder and retirement differentials, the persistent-owner differential (`native_allocate_aligned`/`native_free` on the initial and a later owner against `mi_malloc_aligned`/`mi_free`), the page-ownership unit batch, and the Miri ownership profiles. Unit and Miri tests are selected by exact module-path prefix from `--list` (libtest filters are substrings); each Miri test runs in its own process and results aggregate per module group, so one abort does not hide the others. Exits 3 while any prerequisite or checked-in remaining condition is unmet; the subsets are development shortcuts that never close M3. |
| `allocator-m4 [--check\|--gate ID\|--reader-tests\|--operations-matrix [--read\|--replay]\|--differential SCENARIO …]` | `m4-gate-x86_64-v3.5.0.json` selects the standard, extended, and aligned allocation groups plus `mi_collect`, minus items the M6/M7 contracts own (`excluded_items` maps each to an `owner: reason` string). `--differential SCENARIO` links [`x86_64_m4_operations_driver.c`](x86_64_m4_operations_driver.c) against the pinned C sources and against the native adapter ([`native-mi-adapter/`](native-mi-adapter/)) and requires equal address-free traces for `operations`, `page-kinds`, `collection`, `oom`, `oom-survival` (its own driver), `threads`, `aligned-preservation`, and `api-modes`. `--differential` takes `--build-profile debug --valid-clients-only --source-profile PROFILE` options: `--build-profile debug` and a non-release `--source-profile` also require `--valid-clients-only`. `x86_64_m4_gate.py` also has `--native-tests` and `--adapter-boundary` modes that the launcher does not expose. Report: `m4-gate/report.json` (differentials write `<scenario>-<side>.trace` beside it). |
| `allocator-m5 [--qualification-profile correctness\|full] [--check\|--gate ID\|--reader-tests]` | `m5-gate-x86_64-v3.5.0.json` (the unsuffixed `m5-gate-v3.5.0.json` is the frozen AArch64 contract) gives each M5 condition one gate: groups of `crabc-mimalloc/tests/native_*` targets (every target in exactly one group), allocator-container runners, and receipts of the runtime-launcher native-shadow runners (`./scripts/dev-x86_64.sh libc-native-mimalloc-shadow-pthread-teardown` and `./scripts/dev-x86_64.sh owned-native-allocator-stress`) read through [`native_shadow_receipt.py`](../x86_64/native_shadow_receipt.py). Each native target runs in its own Cargo invocation with the audit and fault seams; secure and guarded targets also run under the feature profiles that enable their tests. The report retains the checked helper argv, and its evidence log records each target command and both output streams. Receipts are accepted only when they seal the current checkout and every case passed, so run those runners on the tree first. Full M5 also consumes `compat/reports/allocator/x86_64/perf-engine/engine.json`; produce it first with `./compat/allocator/run-x86_64.sh allocator-perf-engine --full --set matrix --label engine`. The qualified reader requires the complete matrix, including cross-thread rows, a current source seal, retained products, recorded tools, and an uncontended host. M5 then requires a one-sided 95% lower wall-throughput Rust/C bound >= 0.25 for each manifest-named `local_scaling_1` and `local_scaling_4` row. Report: `m5-gate/report.json` (`m5-correctness-gate/` for the correctness profile). |
| `allocator-m6 [--qualification-profile baseline\|full] [--check\|--reader-tests]` | `m6-gate-v3.5.0.json` partitions every applicable Heap, Theap, arena, managed-memory, and subprocess item selected from [`api-v3.5.0.json`](api-v3.5.0.json) (the pinned header inventory; its `target_applicability` field selects the x86-applicable items) into gates plus cross-cutting destruction/lifetime and upstream-test gates. Unlike the contract-only `--check`, a run executes every evidence entry that has a runner (profile-matrix runners with `--matrix`, the public heap alignment runner with `--profile all`). A gate passes only with no reviewed blocker and all evidence runnable and passing; the validator rejects inventory gaps, double ownership, and unblocked gates that depend on missing evidence. Report: `x86_64/m6-gate/report.json`. |
| `allocator-m7 [--qualification-profile baseline\|full] [--check\|--gate ID\|--reader-tests\|--arena-print\|--private-context-arena-print]` | `m7-gate-x86_64-v3.5.0.json` via `x86_64_m7_gate.py`: selects the applicable interfaces and compile-time modes from the same pinned inventory (`api-v3.5.0.json`), partitions them into gates (options and environment, option effects, callbacks, statistics, visitation, debug, secure, guarded, optional ISA, baseline), and names each gate's evidence. A gate passes only when it has no reviewed blocker and every evidence entry has a command that ran successfully this run; evidence without a command is declared missing. The gate itself owns two evidence checks (`--options-differential`, `--option-effects-differential`) that build a pinned-C oracle and compare its `key=value` trace with one exact Rust test. `--arena-print` and `--private-context-arena-print` run the arena-print comparisons. Report: `x86_64/m7-gate/report.json`. |
| `allocator-m8 [--check\|--gate ID\|--reader-tests]` | `m8-gate-x86_64-v3.5.0.json` names, per plan row (startup/constructors, threads/fork, errno/C ABI, weak/interposed symbols, static/dynamic products, DSOs/loader, Rust std, Lua, corpus), the installed native-shadow `scripts/dev-x86_64.sh` product commands it requires. `owned-native-allocator-policy` builds the sysroots that product-consuming rows receive as `{static_sysroot}` and `{dynamic_sysroot}`. Because each row starts its own container, the gate runs on the native host; logs and `report.json` are under `.work/allocator-x86_64/reports/allocator/x86_64/m8-gate/`. |
| `allocator-m9 [--profile baseline\|full] [--check\|--reader-tests\|--report PATH…]` | `x86_64_m9_gate.py` (no JSON contract). Conditions: a complete performance matrix, at least three distinct qualified engine reports with matching source, configuration, host and products (agreement), a complete codegen audit that replays retained executables without measuring, source convergence, one qualified integrated-product report, and current M4-M7 correctness reports. Every unmet condition is named. Report: `x86_64/m9-gate/report.json`. |
| `allocator-divergence-evidence [--profile correctness\|full] [--check\|--reader-tests]` | `divergence-evidence-v3.5.0.json`: every `port-map.toml` row with `difference_kind = algorithmic` needs an entry naming its differential and performance evidence (or, where pinned C has no valid-program behavior to compare, the C defect and its `known-differences.md` entry); `--check` requires the two sets to match. The run executes each differential and reads the qualified reports; the launcher defaults to `correctness`, which executes the differentials and defers performance evidence, and `full` also reads the timing reports. It never sets the port-map evidence flags. |
| `allocator-m10 [--profile correctness\|baseline\|full] [--check [--performance-receipt PATH] [--qualification-receipt PATH]\|--build-audit\|--reader-tests]` | `x86_64_m10_gate.py`: default-backend qualification. `--check` builds nothing: every profile requires source convergence, native product purity, the retained C oracle, and a passing full-profile qualification-chain receipt for the current revision; it records the selected default and explicit accepted-C selections, and rejects a switch before its prerequisites pass. It never edits the default backend line. Supply `--qualification-receipt` after switching to prove the chain reran at that revision. `--build-audit` builds native static and dynamic products and checks archives, symbols, headers, provenance, and resolved Cargo graphs for C mimalloc. `correctness` (the launcher default) checks functional M0-M8 evidence and source convergence, while deferring M9 and performance.release; it is a functional discovery pass and makes no backend-promotion or performance qualification claim. `baseline` requires baseline M0-M9 and performance.release evidence but leaves physical NUMA and 2-MiB/1-GiB pages unqualified; `full` requires full M0-M9 and performance.release evidence plus those hardware modes. A full-profile reader rejects a baseline report. |

### Unit and integration suites

| Command | Runs |
| --- | --- |
| `allocator-unit [--filter NAME]` | `cargo test -p crabc-mimalloc --lib --no-default-features` for `x86_64-unknown-linux-musl`; with `--filter` (a fully qualified name, at least one `::`), `run_unit_x86_64.py` runs that one test with `--exact` and requires exactly one executed, passing test. |
| `allocator-native-integration` | Every `crabc-mimalloc/tests/native_*` target (one process each, `--no-fail-fast`) with the default-off `native-runtime-test-audit` and `native-runtime-test-fault` features. The tests register their std worker threads' allocator descriptors as libc's x86 pthread start does before attaching. |
| `allocator-core-unit` | The `crabc-core` thread-pointer identity test (`--exact --test-threads=1`, feature `allocator-x86-evidence`). |

### Pinned-C/Rust differential lanes

Each lane compares one fixed scenario's address-free trace from the pinned C
source with the Rust port and prints where it wrote its evidence (under
`target/compat/allocator/x86_64/<lane>/` or `reports/allocator/x86_64/`, see
[Launcher](#launcher)); a lane takes no arguments unless listed. Most
`allocator-<name>` lanes run `x86_64_<name>_evidence.py` (underscores for
hyphens); the launcher's case statement is the exact map and
`./compat/allocator/run-x86_64.sh --help` lists every command. The
[Checked-in contracts](#checked-in-contracts) table names each lane's
contract. Lanes whose driver is a `.c` plus `.py` pair in this directory are:

- Heap and arena lifecycle: `allocator-arena-destroy`, `allocator-heap-destroy`,
  `allocator-reclaim-on-free`, `allocator-subprocess-lifecycle`,
  `allocator-heap-lifecycle [--faults]`, `allocator-m2-arena-lifecycle [--profile
  release|debug-1|stat-1|stat-2|all]`, `allocator-m2-metadata-ownership`.
  `--faults` runs only the existing failure/retry group.
  Heap fault builds use the launcher's checkout-owned Cargo target, then copy
  each compiler-selected executable into the fixture before execution. Cargo
  owns source, feature and profile invalidation. Retained replay still checks
  the exact revision, source inputs and copied products.
  Drivers: `arena_destroy.c`, `heap_destroy.c`, `reclaim_on_free.c`,
  `subprocess_lifecycle.c`, `heap_lifecycle.c`, `m2_arena_lifecycle_x86_64.c`,
  `m2_metadata_ownership_x86_64.c`. `allocator-reclaim-on-free` also reruns its
  cases under seven option profiles (`default` sets nothing, the other six set
  `mimalloc_*` environment variables) so each process reads them from its own
  option table.
- Public API adapter: `allocator-m6-adapter [--matrix]` links
  [`x86_64_m6_adapter_driver.c`](x86_64_m6_adapter_driver.c) once against the
  pinned C sources and once against the native adapter's M6 exports and
  compares valid-client traces. The default runs `release`; `--matrix` runs
  `release`, `debug-1`, `stat-1`, and `stat-2`, as the M6 gate does. In
  `debug-1`, the source C workload enables `guarded_precise=1` only after
  preprocessing proves the pinned debug source has one active option use;
  native remains at option 0. A separate aligned-offset control runs both at
  option 0: source C reports `EINVAL` with its diagnostic and retains the live
  page, while Rust stays quiet. Invalid alignment passed to
  `mi_heap_realloc_aligned_at` is another control, outside the valid-client
  domain: debug C asserts on the source precondition while Rust reports
  `EINVAL` through its error callback. These controls stay separate from the
  valid-client parity claim. Other public API lanes include
  `allocator-public-heap-alignment`,
  `allocator-heap-convenience [--read|--replay]`,
  `allocator-public-theap [--matrix|--profile release|debug-1|stat-1|stat-2]`,
  `allocator-upstream-heap-stress`, `allocator-upstream-subprocess-stress`.
  Theap's existing `--debug` action keeps its unoptimized ordinary legal-client
  workload. It cannot be combined with a profile or matrix selection.
- Options and output statistics development traces: `allocator-m7 --differential
  TRACE` accepts `options-environment`, `option-effects`,
  `statistics-level-one-output-merge`, `statistics-level-two-requested`,
  `statistics-level-two-bins`, `statistics-level-two-page-huge` and
  `statistics-aligned-debug`. The aligned-debug selection runs the existing
  public allocation driver in three fresh processes per backend, with
  request/alignment pairs 8193/4096, 65537/4096 and 262145/65536. It checks
  client payloads and normal/requested/bin statistics through free and collection.
  Output traces compare a pinned C oracle with one exact Rust test. The
  aligned-debug trace links the public native adapter using the existing owned
  source-runtime closure. Both compilers use optimization level zero. Reports live under `m7-gate/development` and are
  explicitly ineligible for qualification. These traces do not replace release
  admission or the complete M7 gate.
- Scheduled arena purge failure: `allocator-medium-pressure-delayed-purge-fault`
  builds the pinned C oracle and runs the exact Rust delayed-purge receiver.
  It compares 28 fields covering expiry, consumed decommit failure, warning
  accounting, surviving claims and later slice reuse. The command takes no
  arguments and uses the cached pinned source archive offline. Its retained
  evidence does not close the full M2 gate.
- Local trace: `allocator-native-local-trace [--profile initial|worker]`
  compares warmed owner-local allocation traces.
- Process/thread lifecycle and startup: `allocator-tls`, `allocator-lifecycle
  [--only runtime-process-policy-first-arena]`, `allocator-startup-regular-arena
  [--reader-tests]`, `allocator-init-recursion`, `allocator-concurrent-init`,
  `allocator-initialization-tld [--reader-tests]`, `allocator-fault`,
  `allocator-fault-seam-inventory [OPTION]` (options: `--os-publication-receiver`,
  `--metadata-publication-receiver`, `--compile-only`,
  `--canonical-m2-vm-c-compile-regression`, `--retry-helper-regression`,
  `--timeout-clock-helper-regression`, `--placement-warning-helper-regression`,
  `--mbind-boundary-regression`, `--huge-branch-diagnosis`, `--reader-tests`).
  The fault commands cover fixed crate-private selections, not general fault,
  lifecycle, or stress qualification.
- Huge pages: `allocator-huge-registry`, `allocator-huge-reservation`,
  `allocator-huge-numa-qualification [--reader-tests]`.
- C-oracle artifact evidence: `allocator-release-evidence`,
  `allocator-api-coverage`, `allocator-header-modes`, `allocator-cmake-modes`,
  `allocator-static-modes` observe the pinned C build outputs; they do not
  claim behavior or Rust parity.
- Abandon/adopt/exit scenarios: the remaining `allocator-*` commands in the
  contract table (remote free, mapped reclaim/adoption, unmapped reabandon,
  on-demand commit, full-page force-collect and reabandon, aggregate
  post-exit, pthread-destructor and cancellation, deferred-free callback,
  automatic arena reservation, and so on). `allocator-automatic-arena-reservation
  --reader-tests` runs the host reader tests only.

### Performance and codegen

| Command | Measures |
| --- | --- |
| `allocator-perf --smoke\|--full [options]` | `perf_x86_64.py`: private-adapter C/Rust timing and post-init live-memory comparison of two disposable fixture executables. Not the public `compat/perf/` matrix. |
| `allocator-perf-engine [--smoke\|--full] [--set architecture\|matrix\|destruction] [options]`, `--reader-tests` | `perf_engine_x86_64.py`: one source-shared C workload fixture linked once with the pinned C backend and once with the Rust persistent engine behind one opaque boundary. Retains fixture stdout/stderr under each run's `compat/reports/allocator/x86_64/perf-engine/<label>.artifacts/output`, including samples that fail before producing a comparison. A rerun with the same `--label` first deletes that label's `.artifacts`. |
| `allocator-perf-integrated [--smoke\|--full] [options]` | `perf_integrated_x86_64.py`: the same comparison through four installed static and dynamic products. Retains fixture output under `.work/allocator-x86_64/integrated/<label>/output`. |
| `allocator-codegen-audit [options]`, `--reader-tests` | `codegen_audit_x86_64.py`: optimized machine-code audit of the two static engine fixtures. |

The shared engine fixture keeps its volatile payload and usable-size
accumulator private to each thread; independent workers must not race or
contend on it. Both backends compile the same fixture bytes, so a fixture
change requires fresh products and measurements in both lanes. Time-based
performance runs are only meaningful on an uncontended host; see
[`compat/perf/README.md`](../perf/README.md) for the public-runtime matrix.

### What `allocator-m2` compares

Beyond the memory-substrate fragments (`m2-*-x86_64-v3.5.0.fragment.json`),
`allocator-m2` compares child-isolated direct pinned-C records with private Rust
captures for these Linux VM-policy boundaries. They are direct VM-policy
evidence only: none qualifies successful hardware huge pages, ambient
diagnostics, or an allocator/runtime caller.

- Large-page retry suppression: `_mi_prim_alloc` against
  `Mapping::map_unix_policy` with forced failed `MAP_HUGETLB` attempts, the
  eight-call suppression lifetime, and a competing `AcqRel` decrement (the
  source ignores the strong-CAS failure). `allow_large=false`, ineligible
  geometry, and a disabled `allow_large_os_pages` do not consume the counter.
- THP policy matrix: `_mi_prim_mem_init` against a private Rust `VmPolicy`
  capture for `allow_thp=1` (no PRCTL calls) and `allow_thp=0` with
  `PR_GET_THP_DISABLE` returning EPERM, EINVAL, nonzero, or zero followed by
  `PR_SET_THP_DISABLE`. C records only tuple/count control flow and its void
  continuation; Rust records the typed `DisabledQueryFailed`,
  `DisabledAlready`, `DisabledSet`, and `DisabledSetFailed` outcomes. The
  `process-main-thp-policy-owner-traversal` Rust unit check separately walks the
  `ProcessMainInitializationStorage` owners in raw-fork children.
- One-GiB large-only terminal failure: `_mi_os_alloc_huge_os_pages` against
  `HugeOsAllocation::allocate_for_process`. A failed one-GiB map retries as a
  two-MiB map with the same hint, then the upper request attempts only the
  sticky two-MiB form; both sides observe unchanged reserve/commit statistics
  and the warning order. Failure-only evidence for one requested page.
- Aligned over-map cleanup: `src/os.c` aligned allocation and
  `src/prim/unix/prim.c` free. A failed direct, prefix, or suffix release is
  warned, still counted, and leaked live, and the aligned middle is returned;
  `os::tests::emit_m2_aligned_overmap_cleanup_c_rust_boundary_trace` emits the
  twelve row verdicts that must equal C.
- Huge registry and reservation: `allocator-huge-registry` compares the pinned
  multi-arena manage path with the same-process Rust registry and checks
  unpublished rejection and partial-publication ownership over a 17-GiB span;
  `allocator-huge-reservation` compares pinned interleave/free policy
  functions and runs focused Rust tests for metadata-backed failed-page
  ownership and startup reservation order. Both simulate huge primitives with
  anonymous memory.

### Bitmap component

`m2-bitmaps-x86_64-v3.5.0.fragment.json` is component evidence, not an M2
report; the aggregate references the fragment by path and `run.py` checks its schema, upstream pin, and target. It covers
fixed mimalloc 3.5.0 scalar bitmap behavior for the default Linux/x86-64
profile (64-bit fields, 512-bit chunks, `MI_OPT_SIMD=0`, release `MI_STAT=0`):
the field/chunk primitives, ordinary and binned bitmap families, the three
visitors, inverse/high scans and counts, rollback, and their mandatory
subprocess statistics calls. SIMD/debug configurations and statistics
ABI/reset/merge/reporting are separate claims.

`crabc-mimalloc/src/bitmap.rs` preserves source algorithms and atomic orders.
`AbandonedBitmapClaim::Discarded` is the source callback outcome
`claim=false, keep_set=false`; arena ownership callers still restore rejected
pages because a concurrent unabandon writer can be waiting for them. The
`chunk_bins` transitions and `pages_unabandon_busy_wait` counter live in
`SubprocessIdentity::bitmap_statistics`, reached through `MainSubprocess`
(signed 64-bit current, peak, and positive total in source order; the source `NONE` bin has no update); this typed subset
is not a `mi_stats_t` byte layout. `m2_bitmaps_x86_64.py::run_evidence(harness,
offline=..., test_program=...)` builds the direct C fixture from the pinned
`stats.c` and Linux primitives, runs the `bitmap::` Rust module once, and
compares the ordered unsigned observations; that single Rust execution
supplies both the differential and the unit-invariant rows, and the M2
aggregate must record it as one execution (`rust_execution_count: 1`). The C
fixture pins `_mi_cpu_stosb_max = 0`, the one environment input the scalar-only
claim depends on. Host tests: `compat/allocator/test_m2_bitmaps_x86_64.py` and
`compat/allocator/tests/test_x86_64_m2_bitmaps.py`.

### Architecture runtime evidence

Full engine report admission rereads the current clean Git commit, source
seal, tool versions and immutable launcher image. It inspects retained static
ELF products, the Rust archive and source-selected build/link arguments, and
requires every row's CPUs to be covered by the recorded uncontended-host
roster. The full producer retains complete Cargo artifact messages and image
identity; historical reports without those bindings cannot qualify. M5 reads
both local wall-throughput bounds from that same validated snapshot and keeps
its 0.25 lower-bound floor; the correctness profile continues to defer this
performance evidence. Encoded Rust flags that override the selected engine
configuration are rejected, and full M5 receipt reads revalidate the engine
proof alongside the structural audit.

The architecture gate admission rules (qualified engine performance report
file identity, derived throughput ratios, the 0.90 lower bound) are in
[`architecture-runtime-evidence.md`](architecture-runtime-evidence.md). The
source ratchet runs on the host without a container:
`python3 -B compat/allocator/architecture_ratchet.py --check`.

### Hardware huge-page and NUMA qualification

Ordinary x86 qualification uses `--qualification-profile baseline` for M6/M7
and `--profile baseline` for M9/M10 (the launcher defaults M6, M7, and M9 to
`full`, and M5, M10, and the divergence lane to `correctness`). The pinned `allow_large_os_pages` option
defaults to zero. The baseline profile keeps every ordinary producer, logical
NUMA policy, failure/fallback check, convergence condition, performance
threshold, and artifact audit, and records `physical-numa`, `2mib-pages`, and
`1gib-pages` as unqualified; it changes neither the selected C backend nor
public support. The full profile also requires successful physical
reservation and placement; baseline qualification never rewrites failed
hardware receipts. THP advice is not proof of a 2-MiB `MAP_HUGETLB` mapping.

`allocator-huge-numa-qualification` is the hardware-only companion. It runs the
simulated reservation and registry workloads first, then the pinned C
`mi_reserve_huge_os_pages_at(1, node, 0)` and Rust
`HugeOsAllocation::allocate_for_process`, each holding two one-GiB mappings
concurrently and recording the kernel's `/proc/self/numa_maps`. `--reader-tests`
runs only the parser and source-boundary tests. Requirements:

- Two distinct online nodes (IDs 0 through 62) permitted by both the process
  `Mems_allowed_list` and `cpuset.mems.effective`, each with at least one free
  one-GiB huge page.
- `RLIMIT_AS=unlimited`. The source-shaped virtual-address peak of the
  prerequisite workloads is **36 GiB + 96 MiB** (`38,755,368,960` bytes) for
  the registry lane's three `huge_` tests (a 17-GiB replacement beside a
  32-MiB arena twice, and a one-GiB replacement whose aligned retry can occupy
  two GiB beside a third arena); the huge-reservation C fixture spans three
  GiB and each Rust reservation test at most four GiB. The executable, loader,
  libtest, and compiler address space are excluded, so no finite total floor is
  claimed.
- Readable `/proc/self/numa_maps`, the launcher's `CAP_IPC_LOCK`, and an
  approved `mbind(MPOL_PREFERRED, flags=0)`. A private-page preflight performs
  that raw `mbind`; a nonzero result is recorded as a pending external gate.
  Keep the default seccomp profile and approve only that rule; never use an
  unconfined profile.

Each invocation writes an immutable receipt under
`compat/reports/allocator/x86_64/huge-numa-hardware-qualification-runs/`; the
stable `huge-numa-hardware-qualification.json` beside it is only an atomic
pointer to the latest receipt with its hash, and the collector refuses to
reuse a run directory or executable path. A missing topology, pool, cgroup
headroom, capability, observer, or `mbind` gate exits 3 with
`pending_external_resources`; build, parser, or harness problems are a
separate failed receipt. The job supplies no M2 completion, runtime-integration,
or AArch64 evidence.

## Host-side Python tests

The source-only suite under `compat/allocator/tests/` reads contracts and
source, uses mocks, or creates temporary fixtures, and is audited for
module-level parallel execution. Run it through the isolating helper:

```sh
python3 scripts/test_python.py --directory compat/allocator/tests
python3 scripts/test_python.py --directory compat/allocator/tests --jobs 1
python3 scripts/test_python.py --module compat/allocator/tests/test_x86_64_runner.py
```

The helper runs each module in its own process with unique `TMPDIR`, scratch,
report, and log directories beneath `.work/python-test-runs/run-*/` (default
workers: the lesser of CPUs and four; `--jobs` accepts at most eight;
`--timeout` bounds a module, default 300 s), retains a `summary.json`, and fails
when discovery or a module runs zero tests. A worker that leaves a live
descendant in its process group is reported as `PROCESS-GROUP-LEAK`; a test that
calls `setsid` escapes that containment undetected. A timeout sends SIGTERM and
then SIGKILL after two seconds, and SIGINT/SIGTERM to the helper terminate the
active workers and exit 128 plus the signal. Each worker gets `CRABC_WORK_DIR`
and `TMPDIR` set to its private root (`run.py` reads `CRABC_WORK_DIR` at import,
and some tests depend on it). Process and `TMPDIR` separation is not a
filesystem sandbox: Cargo state and fixed repository report paths are shared, so
audit any other suite's mutable inputs before using the helper, and treat it as
a unit-test convenience, not qualification evidence.

Maintainer operations run directly on the host and need a diff review. A direct
`run.py` defaults to the paused AArch64 route, so `--check` needs
`--architecture x86_64`; `--generate-contracts` and `--snapshot-ratchet` take no
architecture and rewrite only the AArch64 artifacts (`api-v3.5.0.json`,
`upstream-tests-v3.5.0.json`, and the frozen `ratchet-v3.5.0.json` from
`port-map.toml`), so do not run them for x86 work:

```sh
python3 compat/allocator/run.py --check --architecture x86_64 --offline
python3 compat/allocator/run.py --generate-contracts --offline
python3 compat/allocator/run.py --snapshot-ratchet
```

The x86 contracts have no regeneration command: `x86_64_api_inventory.py
--print-observed` and `x86_64_source_map.py --print-source-records` print
material for a reviewed hand edit and write nothing.

`--offline` performs no network access. The verified archive and tag
attestation live in `.work/allocator-cache/` for a direct run (the launcher uses
`.work/allocator-x86_64/allocator-cache/`). The attestation file records a
remote tag observation made by an online run; when it is absent, an offline run
still accepts a digest-verified archive whose `git archive` pax commit equals
the pinned peeled revision (`pinned_archive_tag_identity`), but that admission
is not written as an attestation, so consumers that require a remote
observation need one online run. Contract or source-map changes require an
explicit ratchet snapshot after review; the normal gate never updates its own
baseline.

## Checked-in contracts

Generated reports are measurements and remain ignored. Linking a symbol,
parsing a declaration, or building a C profile does not make a Rust feature
implemented or verified.

| Path | Contract |
| --- | --- |
| `api-v3.5.0.json` | Deterministic, source-audited AArch64 public-header and root-CMake mode inventory. |
| `x86_64-api-v3.5.0.json` | Target-local, source-only inventory of the pinned base `mimalloc.h` `mi_decl_export` declarations. |
| `x86_64-api-coverage-v3.5.0.json` and `x86_64_api_coverage.py` | Target-local source-only ledger for the pinned installed headers, source-form modes, test inputs, and symbol dispositions. |
| `x86_64-source-map-v3.5.0.json` and `x86_64_source_map.py` | Target-local pinned-source mapping and ratchet foundation. |
| `upstream-tests-v3.5.0.json` | Exact pinned upstream test/support-file inventory and current execution status. |
| `upstream-stress-v3.5.0.json` and `upstream-stress/run.py` | Canonical source-unmodified `test/test-stress.c` native-shadow contract and runner. |
| `adapted-tests-v3.5.0.json` | Reviewed selected-API omissions, source hashes, patch identity, prefixed symbol inventory, and native link contract for pinned upstream `test-api.c`. |
| `adapted-tests-x86_64-v3.5.0.json` | Target-local private x86-64 adapter contract. |
| `adapted/test-api-selected.patch` | Minimal source adaptation applied to the exact extracted upstream file; no copied upstream source fork is stored. |
| `adapted-stress-test-v3.5.0.json` | Reviewed creating-thread stress source/provenance map, exact patch/hash, fixed `NTHREADS=1`/`1 1 2` invocation, unsupported-mode rejections, and native link contract for the constrained upstream `test/test-stress.c` route. |
| `adapted/test-stress-creating-thread.patch` | Minimal source adaptation of the exact upstream stress fixture; it keeps the source workload but intentionally excludes every unsupported scheduler or allocator mode rather than copying a C fork. |
| `native-shadow-stress-v3.5.0.json` | Reviewed selected-libc source-stress provenance map, behavior-named patch/hash, fixed four-pthread `4 1 2` execution, fresh-process count, source-transfer cleanup boundary, and unsupported-mode rejections. |
| `adapted/test-stress-native-shadow-pthreads.patch` | Minimal selected-shadow adaptation of the exact upstream stress fixture; standard C allocation names bind to the native shadow `libc.so`, while unsupported upstream modes fail at compile time. |
| `shadow-abi-matrix-v1.json` and `shadow-abi-matrix/` | Closed paired-artifact local C ABI contract and runner. |
| `test-adapter/` | Standalone default-off Rust staticlib/cdylib, private C header, and checked-in wrapper for the existing allocator fixture. |
| `runtime-ticket-zero-test-v3.5.0.json` | Reviewed source map, nine-symbol inventory, one-shot caller contract, native link contract, and durable 1,024-cycle soak-report contract for the process-lifetime ticket-zero C witness, including scalar-only lifecycle stability auditing plus the retained narrow, persistent mixed-local, and live-owner remote-free worker round trips. |
| `native-owner-exit-lifecycle-v3.5.0.json` | Reviewed direct-engine Gate 5C suite: exact Cargo feature set, fifteen focused runtime/source traversal checks, and the required owner-exit scenario coverage. |
| `owner-exit-publication-v3.5.0.json` | Pinned-source order gate for collection, queue detach, abandoned identity, mapped bitmap/count or non-arena OS-list publication, and common unown. |
| `m5-gate-v3.5.0.json` | Frozen AArch64 full-lane contract for the 128-cycle lifecycle schedule and its Gate 5A--5E acceptance/blocker classification (`m5-gate-x86_64-v3.5.0.json` is the x86 gate). |
| `runtime-ticket-zero-adapter/` | Separate `no_std` staticlib/cdylib and direct C fixture for the hidden ticket-zero runtime owner; it has no libc allocator or `mi_*` export. |
| `port-map.toml` | AArch64 source-unit and meaningful-item translation/verification ledger with separate monotonic status fields. |
| `ratchet-v3.5.0.json` | Reviewed AArch64 inventory hashes, counts, and non-regression baseline. |
| `x86_64-parity-v3.5.0.json` | Target-local x86-64 parity/evidence ledger. |
| `x86_64_release_evidence.py` and `x86_64-release-evidence-v3.5.0.json` | Native x86-64-only C release-mode, ELF identity, object-symbol, and dynamic-symbol evidence. Command: `allocator-release-evidence`. |
| `x86_64_api_native_coverage.py` and `x86_64-api-native-coverage-v3.5.0.json` | Native x86-64-only selected-release per-source-form object/dynamic-symbol assessment. Command: `allocator-api-coverage`. |
| `x86_64_header_mode_evidence.py` and `x86_64-header-mode-evidence-v3.5.0.json` | Native x86-64-only staged public-header C/C++ compile/link evidence for six selected forms, including one C11 probe that instantiates five base-header `*_csize` static-inline dispatch helpers, plus the linked pinned C shared object. Command: `allocator-header-modes`. |
| `x86_64_cmake_mode_evidence.py` and `x86_64-cmake-mode-evidence-v3.5.0.json` | Native x86-64-only CMake normal-release shared configure/build/install evidence. Command: `allocator-cmake-modes`. |
| `x86_64_static_mode_evidence.py` and `x86_64-static-mode-evidence-v3.5.0.json` | Native x86-64-only selected static archive and `src/static.c` override-object artifact evidence. Command: `allocator-static-modes`. |
| `x86_64_remote_free_evidence.py` and `x86_64-remote-free-evidence-v3.5.0.json` | Native x86-64-only private pinned-C/Rust differential for one quiescent live-owner remote-free publication/owner-collection protocol. Command: `allocator-remote-free`. |
| `x86_64_live_owner_full_medium_remote_release_evidence.py` and `x86_64-live-owner-full-medium-remote-release-evidence-v3.5.0.json` | Native x86-64-only private pinned-C/Rust differential for one live owner with a non-abandoning full-medium arena page (10248-byte request, 12288-byte blocks, capacity/reserved 42, eight slices) and a regular successor. Command: `allocator-live-owner-full-medium-remote-release`. |
| `x86_64_live_owner_full_medium_one_remote_unfull_reuse_evidence.py` and `x86_64-live-owner-full-medium-one-remote-unfull-reuse-evidence-v3.5.0.json` | Native x86-64-only private pinned-C/Rust differential for one non-abandoning full-medium live owner and one regular successor. Command: `allocator-live-owner-full-medium-one-remote-unfull-reuse`. |
| `x86_64_direct_remote_evidence.py` and `x86_64-direct-remote-evidence-v3.5.0.json` | Native x86-64-only private pinned-C/Rust differential for one small direct-cache remote-free/reuse route. Command: `allocator-direct-remote`. |
| `x86_64_mapped_reclaim_evidence.py` and `x86_64-mapped-reclaim-evidence-v3.5.0.json` | Native x86-64-only private pinned-C/Rust differential for one mapped arena page’s nonempty same-origin reclaim and requeue. Command: `allocator-mapped-reclaim`. |
| `x86_64_mapped_adoption_evidence.py` and `x86_64-mapped-adoption-evidence-v3.5.0.json` | Native x86-64-only private pinned-C/Rust differential for one arena-backed, same-origin, one-thread nonfull medium page. Command: `allocator-mapped-adoption`. |
| `x86_64_direct_small_allocation_adoption_evidence.py` and `x86_64-direct-small-allocation-adoption-evidence-v3.5.0.json` | Native x86-64-only private pinned-C/Rust differential for one same-origin, same-thread/same-Theap, arena-backed 1024-byte direct-small page with two live blocks. Command: `allocator-direct-small-allocation-adoption`. |
| `x86_64_unmapped_reabandon_evidence.py` and `x86_64-unmapped-reabandon-evidence-v3.5.0.json` | Native x86-64-only private pinned-C/Rust differential for one full medium arena page's unmapped-abandonment to threshold-triggered mapped reabandon. Command: `allocator-unmapped-reabandon`. |
| `x86_64_on_demand_evidence.py` and `x86_64-on-demand-evidence-v3.5.0.json` | Native x86-64-only private pinned-C/Rust differential for one ordinary reserved medium page whose first allocation exhausts the fixed four-OS-page prefix and whose second allocation directly commits before free-list extension and same-page reuse. Command: `allocator-on-demand`. |
| `x86_64_direct_on_demand_evidence.py` and `x86_64-direct-on-demand-evidence-v3.5.0.json` | Native x86-64-only private pinned-C/Rust differential for one reserved 1024-byte small direct-cache page: direct exhaustion at eight objects, generic zero-commit extension at allocation nine, and direct prefix growth before the allocation-seventeen extension. Command: `allocator-direct-on-demand`. |
| `x86_64_regular_small_evidence.py` and `x86_64-regular-small-evidence-v3.5.0.json` | Native x86-64-only private pinned-C/Rust differential for one 1025-byte ordinary regular-small arena page. Command: `allocator-regular-small`. |
| `x86_64_direct_small_full_retire_evidence.py` and `x86_64-direct-small-full-retire-evidence-v3.5.0.json` | Native x86-64-only private pinned-C/Rust differential for one same-thread/same-Theap 1024-byte direct-small arena page (1024-byte blocks, capacity 64, one slice). Command: `allocator-direct-small-full-retire`. |
| `x86_64_medium_full_retire_evidence.py` and `x86_64-medium-full-retire-evidence-v3.5.0.json` | Native x86-64-only private pinned-C/Rust differential for one same-thread/same-Theap, arena-backed ordinary 10241-byte medium page (12288-byte block size, 42 capacity, eight slices) under C full-retain `-1`. Command: `allocator-medium-full-retire`. |
| `x86_64_full_non_direct_small_force_collect_post_exit_evidence.py` and `x86_64-full-non-direct-small-force-collect-post-exit-evidence-v3.5.0.json` | Native x86-64-only private pinned-C/Rust differential for one worker-owned arena full non-direct-small regular-bin page. Command: `allocator-full-non-direct-small-force-collect-post-exit`. |
| `x86_64_full_direct_small_force_collect_post_exit_evidence.py` and `x86_64-full-direct-small-force-collect-post-exit-evidence-v3.5.0.json` | Native x86-64-only private pinned-C/Rust differential for one worker-owned arena full direct-small regular-bin page. Command: `allocator-full-direct-small-force-collect-post-exit`. |
| `x86_64_automatic_pthread_destructor_evidence.py` and `x86_64-automatic-pthread-destructor-evidence-v3.5.0.json` | Native x86-64-only private pinned-C automatic pthread-destructor oracle. Command: `allocator-automatic-pthread-destructor`. |
| `x86_64_cancellation_pthread_destructor_evidence.py` and `x86_64-cancellation-pthread-destructor-evidence-v3.5.0.json` | Native x86-64-only private pinned-C cancellation-triggered automatic pthread-destructor oracle. Command: `allocator-cancellation-pthread-destructor`. |
| `x86_64_dynamic_full_medium_one_remote_force_collect_to_mapped_evidence.py` and `x86_64-dynamic-full-medium-one-remote-force-collect-to-mapped-evidence-v3.5.0.json` | Native x86-64-only private pinned-C/Rust differential for one sole full `BIN_FULL` medium arena page. Command: `allocator-dynamic-full-medium-one-remote-force-collect-to-mapped`. |
| `x86_64_dynamic_full_medium_unmapped_reabandon_evidence.py` and `x86_64-dynamic-full-medium-unmapped-reabandon-evidence-v3.5.0.json` | Native x86-64-only private pinned-C/Rust differential for one sole full `BIN_FULL` medium arena page: request 10248 yields 12288-byte blocks, capacity/reserved 42, and eight slices. Command: `allocator-dynamic-full-medium-unmapped-reabandon`. |
| `x86_64_dynamic_full_large_one_remote_force_collect_to_mapped_evidence.py` and `x86_64-dynamic-full-large-one-remote-force-collect-to-mapped-evidence-v3.5.0.json` | Native x86-64-only private pinned-C/Rust differential for one sole full `BIN_FULL` large arena page. Command: `allocator-dynamic-full-large-one-remote-force-collect-to-mapped`. |
| `x86_64_dynamic_full_large_unmapped_reabandon_evidence.py` and `x86_64-dynamic-full-large-unmapped-reabandon-evidence-v3.5.0.json` | Native x86-64-only private pinned-C/Rust differential for one sole full `BIN_FULL` large arena page. Command: `allocator-dynamic-full-large-unmapped-reabandon`. |
| `x86_64_dynamic_full_singleton_homogeneous_aggregate_evidence.py` and `x86_64-dynamic-full-singleton-homogeneous-aggregate-evidence-v3.5.0.json` | Native x86-64-only private pinned-C/Rust differential for exactly two same-size full `BIN_FULL` arena singleton pages: request 524289 yields 589824-byte blocks, capacity/reserved 1, and nine arena slices per member. Command: `allocator-dynamic-full-singleton-homogeneous-aggregate`. |
| `x86_64_dynamic_full_direct_small_one_remote_force_collect_to_mapped_evidence.py` and `x86_64-dynamic-full-direct-small-one-remote-force-collect-to-mapped-evidence-v3.5.0.json` | Native x86-64-only private pinned-C/Rust differential for one sole full direct-small ordinary regular-bin arena page. Command: `allocator-dynamic-full-direct-small-one-remote-force-collect-to-mapped`. |
| `x86_64_dynamic_full_direct_small_unmapped_reabandon_evidence.py` and `x86_64-dynamic-full-direct-small-unmapped-reabandon-evidence-v3.5.0.json` | Native x86-64-only private pinned-C/Rust differential for one sole full direct-small ordinary regular-bin arena page: request/block size 1024, capacity/reserved 64, one slice, and exact rounded direct-cache range `[113, 128]`. Command: `allocator-dynamic-full-direct-small-unmapped-reabandon`. |
| `x86_64_later_thread_exit_full_direct_small_pages_evidence.py` and `x86_64-later-thread-exit-full-direct-small-pages-evidence-v3.5.0.json` | Native x86-64-only private pinned-C/Rust differential for exactly two same-bin full ordinary regular-bin direct-small arena pages: request/block size 1024, capacity/reserved 64, one slice per member, and complete direct-cache range `[113, 128]`. Command: `allocator-later-thread-exit-full-direct-small-pages`. |
| `x86_64_dynamic_full_non_direct_small_unmapped_reabandon_evidence.py` and `x86_64-dynamic-full-non-direct-small-unmapped-reabandon-evidence-v3.5.0.json` | Native x86-64-only private pinned-C/Rust differential for one sole full non-direct-small ordinary regular-bin arena page: request 1032 yields 1280-byte blocks, capacity/reserved 51, one slice, and an empty direct-cache image. Command: `allocator-dynamic-full-non-direct-small-unmapped-reabandon`. |
| `x86_64_dynamic_full_non_direct_small_one_remote_force_collect_to_mapped_evidence.py` and `x86_64-dynamic-full-non-direct-small-one-remote-force-collect-to-mapped-evidence-v3.5.0.json` | Native x86-64-only private pinned-C/Rust differential for one sole full non-direct-small ordinary regular-bin arena page. Command: `allocator-dynamic-full-non-direct-small-one-remote-force-collect-to-mapped`. |
| `x86_64_mapped_post_exit_evidence.py` and `x86_64-mapped-post-exit-evidence-v3.5.0.json` | Native x86-64-only private pinned-C/Rust differential for one worker `mi_thread_done()` followed by `pthread_join()` before consumer frees, selected mapped failed-reclaim/unown, and three observed terminal cleanup checks. Command: `allocator-mapped-post-exit`. |
| `x86_64_retired_prepass_evidence.py` and `x86_64-retired-prepass-evidence-v3.5.0.json` | Native x86-64-only private pinned-C/Rust differential for one worker-local retirement, real `mi_thread_done()`/`pthread_join()` retired-page force-release, one distinct live mapped-abandoned page, and one consumer terminal free. Command: `allocator-retired-prepass`. |
| `x86_64_deferred_free_callback_evidence.py` and `x86_64-deferred-free-callback-evidence-v3.5.0.json` | Native x86-64-only private pinned-C/Rust differential for the doc-hidden `__crabc_runtime` deferred-free registration adapter. Command: `allocator-deferred-free-callback`. |
| `x86_64_aggregate_post_exit_evidence.py` and `x86_64-aggregate-post-exit-evidence-v3.5.0.json` | Native x86-64-only private pinned-C/Rust differential for exactly two distinct live nonfull medium arena pages in distinct bins. Command: `allocator-aggregate-post-exit`. |
| `x86_64_aggregate_still_live_evidence.py` and `x86_64-aggregate-still-live-evidence-v3.5.0.json` | Native x86-64-only private pinned-C/Rust differential for two distinct clients on one nonfull medium page A and a one-client distinct-bin medium page B. Command: `allocator-aggregate-still-live`. |
| `x86_64_aggregate_same_bin_still_live_evidence.py` and `x86_64-aggregate-same-bin-still-live-evidence-v3.5.0.json` | Native x86-64-only private pinned-C/Rust differential for two distinct clients on one nonfull medium page A plus a one-client medium page B in the same bin. Command: `allocator-aggregate-same-bin-still-live`. |
| `x86_64_dynamic_os_aligned_singleton_evidence.py` and `x86_64-dynamic-os-aligned-singleton-evidence-v3.5.0.json` | Native x86-64-only private differential for real Rust Heap attachment, worker finish and joined consumer free of one or three 7-byte OS singletons. The three-page case uses 128, 256 and 512 KiB alignments and frees the middle, tail and head while checking surviving clients. Command: `allocator-dynamic-os-aligned-singleton`. The separate `native_dynamic_os_singleton_owner_exit` integration test checks released and surviving client pages without allocator audit features. |
| `x86_64_dynamic_arena_singleton_post_exit_evidence.py` and `x86_64-dynamic-arena-singleton-post-exit-evidence-v3.5.0.json` | Native x86-64-only private pinned-C/Rust differential for one full arena singleton (request 524289, 589824-byte block size, capacity/reserved 1, nine arena slices). Command: `allocator-dynamic-arena-singleton-post-exit`. |
| `x86_64_aligned_overalloc_realloc_evidence.py`, `x86_64_dynamic_full_large_homogeneous_aggregate_evidence.py`, `x86_64_dynamic_full_medium_homogeneous_aggregate_evidence.py`, `x86_64_dynamic_full_non_direct_small_homogeneous_aggregate_evidence.py`, `x86_64_dynamic_nonfull_regular_pages_distinct_bin_aggregate_evidence.py`, `x86_64_process_done_pthread_key_evidence.py`, `x86_64_regular_mapped_reclaim_evidence.py` | Native x86-64-only private pinned-C/Rust lanes with `x86_64-<lane>-evidence-v3.5.0.json` contracts: aligned over-allocation `realloc` (33 bytes, 64-byte alignment, offset 7), homogeneous dynamic full-page aggregates (large, medium, non-direct-small), a two-page nonfull distinct-bin aggregate, the pinned C `mi_process_done` private pthread-key boundary, and regular mapped reclaim. Commands: `allocator-aligned-overalloc-realloc`, `allocator-dynamic-full-large-homogeneous-aggregate`, `allocator-dynamic-full-medium-homogeneous-aggregate`, `allocator-dynamic-full-non-direct-small-homogeneous-aggregate`, `allocator-dynamic-nonfull-regular-pages-distinct-bin-aggregate`, `allocator-process-done-pthread-key`, `allocator-regular-mapped-reclaim`. |
| `x86_64_lifecycle_evidence.py` | Native x86-only fixed private lifecycle/concurrency selections. |
| `m1-foundations-x86_64-v3.5.0.json`, `m2-memory-substrate-x86_64-v3.5.0.json`, `m3-local-engine-x86_64-v3.5.0.json`, `m4-gate-x86_64-v3.5.0.json`, `m5-gate-x86_64-v3.5.0.json`, `m6-gate-v3.5.0.json`, `m7-gate-x86_64-v3.5.0.json`, `m8-gate-x86_64-v3.5.0.json`, `divergence-evidence-v3.5.0.json`, `architecture-gate-v3.5.0.json` | The gate contracts behind the [Gates](#gates) table (M6 reads `api-v3.5.0.json`); the architecture gate is described in [`architecture-runtime-evidence.md`](architecture-runtime-evidence.md). |
| `x86_64_automatic_arena_reservation_evidence.py` and `x86_64-automatic-arena-reservation-evidence-v3.5.0.json` | Native x86-64-only private pinned-C/Rust differential for automatic regular-arena reservation. Command: `allocator-automatic-arena-reservation`. |
| `x86_64_init_recursion_evidence.py` and `x86_64-init-recursion-evidence-v3.5.0.json` | Native x86-64-only private pinned-C/Rust differential for the explicit process-init, worker init/repeat-init, explicit teardown/repeat-teardown, and recovery-init route. Command: `allocator-init-recursion`. |
| `x86_64_initialization_tld_evidence.py` and `m2-initialization-x86_64-v3.5.0.fragment.json` | Native x86-64-only five-row direct pinned-C/Rust initialization matrix for detached static preimage, direct normal TLD init, first-main static TLD create, and selected generic later-main metadata-allocation success and failure. Command: `allocator-initialization-tld`. |
| `x86_64_fault_evidence.py` | Native x86-only fixed crate-private fault-injection state-preservation selections. |
| `perf_x86_64.py` and `perf-x86_64/` | Native x86-only private-adapter C/Rust timing and post-init live-memory measurement harness. |
| `known-differences.md` | Sole register for observed, pending, accepted, or rejected Rust/C differences; every entry must identify its architecture profile. |

The v3.5.0 API contract records 194 external C declarations, seven header-only
static-inline helpers, 16 typedefs, and 52 exact `mi_option_e` enumerators. The
normal pinned release profile defines 190 `mi_*` symbols: `mi_collect_reduce`
and `mi_stats_merge` are stale header-only declarations, while
`mi_malloc_size` and `mi_malloc_usable_size` come only from the opt-in upstream
override translation unit. The oracle gate fails on any other header/symbol
discrepancy. `mi_wdupenv_s` is in the C oracle symbol set but deliberately
unsupported by crabc's Linux ABI; no inventory item permits a crabc-libc `mi_*`
export. The five legacy `mi_option_*` aliases are separate deprecated inventory
entries, distinct from the explicit `mi_option_deprecated_*` enumerators.

## Baselines and oracles

The exact pinned C v3.5.0 source archive is the mandatory differential oracle
for engine behavior, layout/configuration probes, upstream tests, and
performance. It is built separately: the production `libmimalloc-sys` 0.1.49
backend bundles mimalloc v3.3.2, so it cannot stand in for the v3.5.0
comparison. That backend stays the default until a promotion gate passes, and
production never chooses its allocator at runtime. Musl is the C/POSIX ABI
oracle at the `crabc-libc` boundary; glibc is never an oracle or fallback.

`allocator-native-integration` runs the `crabc-mimalloc` engine's own `native_*`
witnesses and builds no libc. The native-shadow `crabc-libc` build
(`native-mimalloc-shadow`) is exercised by the installed-product runners of
`scripts/dev-x86_64.sh` (`libc-native-mimalloc-shadow-pthread-teardown`,
`owned-native-allocator-fork`, `owned-native-allocator-stress`,
`owned-native-allocator-dso`, `owned-native-allocator-policy`,
`owned-native-worker-lifecycle`), whose receipts the M5 and M8 gates consume. The
selected boundary has no C fallback: a pointer the engine does not own is
reported invalid and is never handed to the C allocator. Pinned
musl permits live cross-thread `realloc`, so the shadow witness for it is a
differential, not a native-contract divergence. The paired ordinary/shadow
`libc.so` matrix is the paused AArch64 harness in
[`shadow-abi-matrix/README.md`](shadow-abi-matrix/README.md).

## Completion tracks

Record these outcomes independently; passing one does not assert another, and
basic malloc/free tests pass none by themselves.

| Track | Required question |
| --- | --- |
| libc allocator readiness | Can the Rust engine back crabc's `malloc` family while preserving the existing C ABI, interposition, `errno`, failure, alignment, zero-size, and output-preservation rules? |
| mimalloc v3.5.0 AArch64 parity | Is every public Linux/AArch64-applicable `mi_*` API and compile-time mode derived from the pinned headers, symbols, declarations, and upstream tests accounted for? |
| mimalloc v3.5.0 x86-64 parity | Is every selected native Linux/x86-64-applicable `mi_*` API and compile-time mode separately accounted for and verified against native C, without implying public x86 `crabc` support? |

## Required evidence

Each vertical slice records the pinned source revision and configuration, then
adds focused invariants, exact-C layout/configuration probes, deterministic
differential traces, and minimally adapted upstream tests. Cross-thread free,
atomic protocols, process/thread initialization, teardown, fork, fault
injection, corruption/wrong-use isolation, pthread/TLS, ABI/interposition, and
real-program/corpus cases need direct evidence before promotion.

Performance evidence compares Rust and exact pinned C under matching
configuration, fixture, build profile, artifact hashes, host provenance, and
sample contract, covering throughput, latency, RSS, virtual mappings, startup,
and allocation-path behavior. The musl-versus-crabc matrix in
[`compat/perf/README.md`](../perf/README.md) is complementary, not a
substitute.

Do not change an upstream algorithm, configuration, allocation policy, or
fixture merely to make the Rust port look better; a measured divergence may be
investigated only under the design-note, differential, and performance rule in
[`docs/design/allocator.md`](../../docs/design/allocator.md).

## Difference register

[`known-differences.md`](known-differences.md) is the single durable register
for accepted or pending Rust/C differences. A missing entry is not permission to
deviate.
