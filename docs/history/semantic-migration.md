# Semantic migration record

This record preserves the 2026-08-22 migration from delivery-milestone names
and chronology-led planning to semantic identifiers and purpose-led documents.
It is deliberately a loss-prevention ledger, not a new backlog. Current
completion and future acceptance contracts are routed by
[`STATUS.md`](../../STATUS.md).

## Baseline and recovery

- Starting revision: `b47d9c86d48779efd9207824ec3d443c11db82b2`.
- Starting worktree: the user-provided `cleanup.md` was staged; no other
  change was present.
- Starting tracked-file inventory: 1,331 paths.
- Original historical-runtime-plan blob:
  `674b4b98cf210efce09f32af656dc41bbf43383f`.
- Original historical-`crabc-rs`-plan blob:
  `e0446edba04a71f19a0c9ce1f6b231ea954e7d3e`.

The original blobs retain the full contemporaneous chronology. The concise
historical records retain only provenance and rationale that are still useful
to a current reader. They never become a source of active work.

## Status vocabulary

The classifications below are intentionally narrow:
`implemented-current`, `implemented-historical`, `partially-implemented`,
`unimplemented-active`, `unimplemented-sequenced-future`,
`blocked-or-open-decision`, `explicitly-superseded`,
`explicitly-out-of-scope`, `generated-measurement`, and
`ambiguous-needs-adjudication`.

## Loss-prevention ledger

| Source | Subject and exact retained content | Status | Evidence | Scope disposition | Destination and action | Confidence | Old/new mapping |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `SCOPE.md` §§1–35; `COMPATIBILITY-PROFILE.md` | Linux/AArch64/5.10 boundary; musl-only C oracle; narrow locale, resolver, allocator, crypto, dependency, and framework limits; vertical-slice evidence rule. | implemented-current | Governing documents and capability ledger. | In scope or explicit boundary as stated. | Retain at repository root; current design documents link to them. | Proven | No identifier change. |
| Former backlog: current status | Current generated ABI/libc-test/corpus measurements are evidence, not claims of complete historical breadth; typed page-size and loader cases are completed scope records. | generated-measurement / implemented-current | Dashboard, tests, and `coverage.toml`. | In scope. | Current owner: `COMPATIBILITY.md` and `STATUS.md`; historical snapshots remain here only. | Proven for present owner; old snapshots remain historical. | Milestone wording becomes semantic historical-delivery wording. |
| Former backlog: P0 | Shared Linux/AArch64 vDSO time route is implemented, but the selected `clock_gettime` CPU row remains red and must retain forced-fallback, malformed-vDSO, error, and marked-loop evidence. | unimplemented-active | `docs/design/performance.md`, performance reports, direct regressions. | In scope. | Current owner: `docs/roadmap/performance-completion.md`. | Proven. | No path identity; historical `M` label removed. |
| Former backlog: P1 loader | Handle-local GNU/SYSV lookup is CPU-green, while whole-process syscall cost and five-DSO graph CPU remain red; preserve interposition, mutable-name, and loader lifecycle contracts. | partially-implemented | Loader tests and performance evidence. | In scope. | Current owner: performance roadmap. | Proven. | No path identity; historical `M` label removed. |
| Former backlog: P1 scalar primitives | `memcpy` and `memset` scorecard rows are red; `strlen`, `memchr`, `strstr`, and `memmem` are green. Guard-page, alignment, and span evidence remains mandatory before any SIMD decision. | partially-implemented | Direct differential tests and performance matrix. | In scope. | Current owner: performance design and roadmap. | Proven. | No path identity. |
| Former backlog: P1 file/stdio | `fd_file_4k`, `stdio_file_4k`, and `stdio_format_parse` retain red CPU rows despite preserved descriptor, cancellation, stream-position, and parser contracts. | partially-implemented | Focused C and pthread regressions; performance reports. | In scope. | Current owner: performance roadmap. | Proven. | No path identity. |
| Former backlog: P1 pthread/TLS | Create/join, condition handoff, and dynamic TLS growth remain CPU-red; mutex fast path is green. Preserve lifecycle, cancellation, TLS, and loader differentials. | partially-implemented | pthread/loader suites and performance reports. | In scope. | Current owner: performance roadmap. | Proven. | No path identity. |
| Former backlog: P2 startup | Minimal, constructor/destructor, and startup-linked graph rows retain red CPU results; only non-contract loader work may be removed. | unimplemented-active | Loader tests and performance matrix. | In scope. | Current owner: performance roadmap. | Proven. | No path identity. |
| Former backlog: scope decision | The universal allocator plateau cannot meet the current PSS target with a fully touched 32-MiB payload; cgroup `memory.peak` is unsupported in the read-only Docker mount. A user must choose the allocator-scope disposition. | blocked-or-open-decision | `docs/design/performance.md`, performance reports, allocator audit. | Unresolved, with allocator research otherwise out of scope. | Current owner: scope, status, and performance roadmap. | Proven blocker. | No path identity. |
| Former backlog: tooling and maintenance | Rustybench dependency-bearing `build-std` remains unsupported due duplicate `core`; static evidence, ABI/header scope, focused fuzzing, and additional suites remain conditional maintenance frontiers rather than hidden feature backlog. | blocked-or-open-decision / unimplemented-active | Native performance harness, LTO evidence, historical record. | In scope only when selected by a defined contract. | Current owner: status and performance roadmap. | Proven. | Historical native-LTO label becomes `native-facade LTO`. |
| Former backlog: out-of-scope categories | Accounted C ABI-only, Rust-subsumed, internal-runtime, allocator, and explicit project-scope boundaries remain boundaries, not postponed native work. | explicitly-out-of-scope | `compat/crabc-rs/coverage.toml`, scope/profile. | Explicitly out of scope as stated. | Current owner: scope/profile and capability ledger. | Proven. | No path identity. |
| `pregoal.md` current Lua sections | Lua 5.4.8 adapter-sysroot source build, shared runtime, bytecode, extensions, isolation proof, and failure taxonomy are a completed permanent gate. Borrowed musl CRT objects remain recorded build support, never a pure crabc-sysroot claim. | implemented-current | `compat/lua/`, generated Lua report. | In scope current evidence. | `docs/design/source-build.md` and `docs/evidence/lua-source-build.md`; move and rewrite. | Proven. | `pregoal.md` retired after links move. |
| `pregoal.md` CPython promotion | CPython 3.14.3 adapter-sysroot build: interpreter/shared `libpython`, built-in/import/extension/files/thread/process/Unicode/error evidence, then individually proved optional dependencies and selected hermetic tests. | unimplemented-sequenced-future | Original source-build contract. | In scope after its stated promotion condition. | `docs/roadmap/source-build.md`; retain all acceptance criteria. | Proven. | `pregoal.md` retired after links move. |
| `pregoal.md` owned sysroot | Replace borrowed CRT bridge with crabc-owned start/end objects and wrapper; prove startup, TLS, constructors/destructors, stack protector, interpreter selection, static/PIE behavior, compiler runtime, and no musl target artifacts. | unimplemented-sequenced-future | Original source-build contract. | Separate later scope stage. | `docs/roadmap/source-build.md`; retain as later stage, not a Lua/CPython prerequisite. | Proven. | `pregoal.md` retired after links move. |
| `goal.md` scorecard, methodology, and ladder | Per-workload CPU, PSS/cgroup peak, syscall, correctness, provenance, and no-omitted-red-row rules; scalar-first optimization doctrine; all named current red, green, and unsupported rows. | unimplemented-active / generated-measurement | Performance design, harness README, reports, tests. | In scope. | Stable method goes to `docs/design/performance.md`; release gates, row status, P0–P6, review rules, and definition of done go to `docs/roadmap/performance-completion.md`. | Proven. | `goal.md` retired after links move. |
| `goal.md` allocator and LTO limits | Allocator scorecard block needs a user decision; dependency-free native/standard-library LTO proof is bounded, while dependency-bearing Rustybench `build-std` evidence is unsupported and dynamic-libc/whole-program LTO is unproved. | blocked-or-open-decision / partially-implemented | LTO harness and performance evidence. | In scope with stated limits. | Performance roadmap and LTO README; retain unfavorable/unsupported states. | Proven. | `lto-m12` becomes `lto-native-facade`; report identity becomes `native-facade-lto`. |
| `goal2.md` activation and corpus | Broad C and direct-native corpus activates only after focused performance completion; existing package/Rust evidence is compatibility evidence, not sustained performance proof. | unimplemented-sequenced-future | Corpus and Rust-std harnesses. | In scope, sequenced future. | `docs/roadmap/software-corpus-validation.md`; preserve activation condition. | Proven. | `goal2.md` retired after links move. |
| `goal2.md` C0–C4 | Preserve measurable-substrate, C baseline, cross-subsystem closure, native-application, and maintenance/release stages; mandatory workload tables, per-workload gates, guardrails, and definition of done remain intact. | unimplemented-sequenced-future | Original corpus contract. | In scope, sequenced future. | `docs/roadmap/software-corpus-validation.md`; move verbatim except semantic title/link updates. | Proven. | `goal2.md` retired after links move. |
| `docs/history/runtime-plan.md` §§1–16 and gates | Docker-first laboratory, pinned oracle policy, exported/implemented/verified distinction, vertical-slice ratchet, loader/TLS/ABI rationale, and bounded LTO non-claims remain useful provenance or current design invariants. | implemented-historical / implemented-current | Current scope/design/compat harness docs and original blob. | Current portions reconciled; chronology itself historical. | Condense in place after extracting current owners; record original blob. | Proven. | Historical milestone labels retained only in historical narrative. |
| `docs/history/runtime-plan.md` historical ambitions | Broad portability, broad historical-parity expansion, and chronology-led queues conflict with the scope reset; they must remain recoverable as rejected/superseded direction, not live backlog. | explicitly-superseded | `SCOPE.md`, compatibility profile, original blob. | Explicitly out of current scope. | Compact historical record with governing decision link. | Proven. | Historical labels retained only for provenance. |
| `docs/history/crabc-rs-delivery-plan.md` §§3–76 | Direct typed syscall boundary, no public C ABI/`errno` round trip, shared-core/non-singleton distinction, `RuntimeV1` ownership, typed safety and capability accounting are current design invariants. | implemented-current | `docs/design/crabc-rs.md`, `coverage.toml`, focused probes. | In scope. | Preserve in current design, with concise historical rationale. | Proven. | Historical labels retained only for provenance. |
| `docs/history/crabc-rs-delivery-plan.md` deferred breadth | Former wrapper-per-symbol, broad C-family, `io_uring`, policy-framework, locale/codec, broad synchronization, and global-policy aspirations are governed by the current ledger/scope; none becomes active merely because old prose said deferred. | explicitly-superseded / explicitly-out-of-scope | Scope/profile and machine ledger. | As classified by current ledger. | Compact historical record and exact ledger rationale; do not revive as TODO. | Proven where current ledger classifies; otherwise historical provenance only. | Historical labels retained only for provenance. |
| Historical count and measurement snapshots | Delivery documents contain dated, incompatible capability counts and superseded performance values. The machine ledger and generated reports are authoritative for current values; historical snapshots remain provenance rather than being silently normalized. | ambiguous-needs-adjudication / generated-measurement | `coverage.toml`, generated reports, original blobs. | Unresolved only as historical chronology; no active contract depends on choosing one old count. | Compact history records the ambiguity and points to present owners. | Deliberately not adjudicated. | No rename beyond semantic current documentation. |
| `compat/crabc-rs/coverage.toml` and harness inputs | Exact capability classification and evidence paths are executable authority. Its chronology-only phase/comments and deferred-entry `target_milestone` field must use semantic names, while schema/version fields are real stable identities. | implemented-current | Ledger validators, manifests, focused tests. | In scope. | Update paths and semantic metadata atomically; retain schema/version values. | Proven. | `M11-core-runtime-slices` becomes `core-runtime-slices`; `target_milestone` becomes `target_workstream`; review labels become `rust-std` or `native-capability`. |
| Live milestone-derived paths and identifiers | 641 tracked `m0_`–`m13_` paths, their Rust/C/Python identifiers, Cargo target names, fixture names, scripts, report readers, and comments encode delivery chronology instead of behavior. | implemented-current | Tracked inventory and focused tests. | In scope mechanical rename only. | Rename by the table below and update every owned reference atomically. | Proven after collision audit. | See semantic rename map. |

## Semantic rename map

The following rules are complete for the tracked path inventory at the baseline
revision. The semantic suffix already identifies the capability; the removed
prefix records only delivery order.

| Old form | New form | Behavior represented | Historical provenance |
| --- | --- | --- | --- |
| `{crabc-rs/tests,crabc-rs/examples,compat/rustix/source,tests,tests/fixtures}/mN_<subject>` | the same directory and `<subject>` | The test, probe, or fixture's named capability. | Former delivery milestone `N`. |
| `libc/src/m4_<subject>.rs` | `libc/src/<subject>.rs` | C ABI implementation module for `<subject>`. | Former fourth delivery batch. |
| `compat/crabc-rs/verify_mN_<subject>.py` and matching test | `verify_<subject>.py` and matching test | Direct-boundary verifier for `<subject>`. | Former delivery milestone `N`. |
| `compat/lto/m12_run.py` | `compat/lto/native_facade_lto.py` | Bounded direct-native O3/fat-LTO proof. | Former twelfth delivery batch. |
| `compat/lto/m12-crabc-rs-fixture/` | `compat/lto/native-facade-lto-fixture/` | Direct-native LTO fixture. | Former twelfth delivery batch. |
| `compat/lto/m12-std-fixture/` | `compat/lto/native-std-lto-fixture/` | Stock-`std` fat-LTO fixture. | Former twelfth delivery batch. |
| `./scripts/dev.sh lto-m12` | `./scripts/dev.sh lto-native-facade` | Runs the bounded native-facade LTO proof. | Former twelfth delivery batch. |
| `compat/reports/lto/m12/latest.json` | `compat/reports/lto/native-facade/latest.json` | Ignored report for that proof. | Former twelfth delivery batch. |
| `m4_`/`M4_` private C-ABI implementation names | `cabi_`/`CABI_` | Private implementation state for the C ABI slice. | Former fourth delivery batch. |
| `m4r_`/`CabiR*` resolver names | `resolver_`/`Resolver*` | Private legacy resolver implementation. | Former fourth delivery batch. |
| `m6_f128_`/`M6_F128_` | `f128_`/`F128_` | Private f128 complex-math kernels. | Former sixth delivery batch. |
| `m11_loader_`/`M11_` fixture names | `loader_dlfcn_`/`LOADER_` | Loader dlfcn test DSO symbols and build macros. | Former eleventh delivery batch. |
| `m12_report_state` | `native_facade_lto_report_state` | Dashboard reader for the native-facade LTO proof. | Former twelfth delivery batch. |
| Hand-maintained `--example` list in `scripts/dev.sh` | Manifest-driven per-target builder using `required-features` | The complete staticlib probe build, with target names and allocator/runtime features declared beside their targets in Cargo metadata. | Former per-target dispatcher maintenance. |

The only stripping collision audit found was among generic direct probes. They
receive these explicit names rather than an ambiguous `direct_probe`:

| Old path | New path | Behavior |
| --- | --- | --- |
| `crabc-rs/examples/m0_direct_probe.rs` | `crabc-rs/examples/direct_io_probe.rs` | Foundational typed open/read/write/ioctl route. |
| `crabc-rs/examples/m2_direct_probe.rs` | `crabc-rs/examples/filesystem_probe.rs` | Filesystem and metadata route. |
| `crabc-rs/examples/m3_direct_probe.rs` | `crabc-rs/examples/core_os_probe.rs` | Pipes, clocks, polling, sockets, mappings, and randomness. |
| `crabc-rs/examples/m4_direct_probe.rs` | `crabc-rs/examples/process_system_probe.rs` | Process, system, terminal, shared-memory, and mount route. |
| `crabc-rs/examples/m5_direct_probe.rs` | `crabc-rs/examples/descriptor_mapping_probe.rs` | Descriptor, event, timer, and file-mapping route. |
| `crabc-rs/examples/m6_direct_probe.rs` | `crabc-rs/examples/signal_process_probe.rs` | Signal, fork, exec, and wait route. |
| `crabc-rs/examples/m7_sync_direct_probe.rs` | `crabc-rs/examples/synchronization_probe.rs` | Futex-backed synchronization route. |
| `crabc-rs/examples/m10_sync_direct_probe.rs` | `crabc-rs/examples/filesystem_sync_probe.rs` | Global filesystem writeback route. |

Internal identifiers follow the same semantic rule: `mN_`/`MN_` prefixes are
removed or replaced with the owning domain where a bare suffix would collide.
The durable internal namespaces are `cabi_`/`CABI_` for C-ABI implementation
state, `resolver_`/`Resolver*` for resolver state, `f128_`/`F128_` for
long-double complex math, and `loader_dlfcn_`/`LOADER_` for loader fixtures.
`M4Complex*` becomes `Complex*`, and the private clone assembly route becomes
`__crabc_clone`.

The intentionally retained apparent matches are not delivery names: POSIX TZ
transition rules such as `M3.2.0` and `M11.1.0`, the standard `m64a` backing
buffer `M64A_BUFFER`, the local mathematical variables `m0` and `m1` in
`math_sqrtfmod.rs`, ABI/protocol/schema versions, Linux/package/tool versions,
architecture constants in installed headers, and historical provenance under
`docs/history/`. `COMPATIBILITY.md` remains a generated measurement and is
regenerated rather than edited in this migration.

## Deletion gate result

Every current or future contract above has a named current-document owner. The
only intentionally unresolved material is explicitly recorded as either a
user scope decision, an unsupported measurement, or historical-count
provenance. Historical documents may therefore be condensed only after their
current design material, future contracts, and inbound machine-readable links
have been moved and validated.

## Inventory and validation record

- The baseline had 641 tracked paths with a chronology-only `mN_`/`mN-`
  component; the current index has zero. The retained apparent matches are the
  narrow allowlist above, not delivery identifiers.
- The tracked test-and-fixture inventory is 628 both before and after the path
  migration (a path with a `tests` or `fixtures` component, or a `test_*`
  filename). No existing test or fixture contract was removed; focused runner
  regression coverage was added for manifest example builds and native-facade
  LTO boundary conditions.
- The 151 flat `crabc-rs/examples/*.rs` source files are all represented by
  151 `[[example]]` entries. The manifest-driven runner builds every target
  independently with its declared feature boundary, rather than maintaining a
  dispatcher-owned name list.
- Relative Markdown links resolve after the root-plan moves. There are no
  remaining inbound repository links to `pregoal.md`, `goal.md`, or `goal2.md`,
  and `lto-native-facade` is the live command for the renamed LTO proof.
