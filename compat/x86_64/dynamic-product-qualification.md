# Owned dynamic product qualification

Materialization, runtime qualification, campaign family completion, and public
platform support are separate claims. The checked-in `dynamic-product.toml`
and `loader-libc-tls-runtime-v1.toml` describe an implemented, unqualified
product. Their private foundation tables continue to describe the exact
historical proof roots. They cannot supply current owned-product evidence.

`build_x86_64_owned_dynamic_sysroot.py` emits a
`materialized-unqualified` state. It binds the installed payload to the live
source content and modes, both contracts, and every installed payload hash.
The manifest additionally binds that state. Source must remain unchanged
through the build. Building does not publish RuntimeV1, finish a campaign, or
assert public support. The hash is computed from live nonignored source,
including untracked source during development; generated `.work` evidence is
excluded, so there is no checked-in self-hash or commit cycle.

`owned_dynamic_qualification.py` owns the evidence producer and validator:

- `prepare --work PATH` runs the installed-driver tests, owned CRT tests,
  owned loader source tests, and pinned musl oracle check. It retains their
  log and copies of the observed oracle runtime, tracked compiler wrapper,
  specs and verification manifests. Hashes are checked against those retained
  bytes; the wrapper must match tracked source, and the source/specs manifests
  must match the upstream pins and copied specs. The live files must still
  match before and after every case. The runtime hash identifies observed
  executable bytes; it is not a claimed reproducible upstream binary pin.
- `run --work PATH --product LABEL --case CASE` executes one exact registered
  leaf with its selected mode. It removes inherited loader and leaf-selection
  environment overrides, retains the subprocess log, and records success only
  after checking unchanged source and installed payload. The record seals the
  leaf's retained artifact directories, including ELF files, link receipts,
  observations, symlinks and fixture node types, without following symlinks.
- `finish --work PATH` validates every registered case for `installed`,
  `second`, and `extracted`; exact manifests and payloads; base consumer,
  spawn and non-PIE observations and owned-driver receipts; oracle evidence;
  identical independent archives and their exact installed payload contents.
  It writes `qualification.json` with status `qualified-pending-review`.
- `validate --receipt PATH` revalidates that receipt against live source,
  contracts and all retained evidence. Missing evidence or changed bytes fail.
- `publish --receipt PATH` is an explicit operation after review. It requires
  a clean source revision and atomically replaces the ignored publication pointer under
  `.work/x86_64/`, after rechecking source and receipt identity immediately
  before replacement. Immutable receipts and prior case evidence are never
  rewritten. No schema check or build invokes publication implicitly.

The finite `CASES` roster maps the contract to CLI, dependency cycles, ELF
weak/protected/hidden scope and interpreter aliases, PIE/non-PIE runtime
loading and deferred binding, constructor exit, pthread signals and exit,
fork repair, stack attributes, join cancellation, condition-wait cancellation,
the shared full I/O cancellation roster, and the separate `system()`
cancellation protocol, plus the contained C `syslog` state/delivery matrix.
The runtime-loading leaf also
runs search policy, all-thread GD TLS growth, initial IE, new-runtime-IE
rejection, retained scope/lifecycle and rollback differentials. Both clean
builds and the extracted package must run the complete same roster; neither
identical manifests nor another product's pass substitutes for execution.

The spawn case links one unchanged application object into the pinned musl
reference and installed PIE/non-PIE consumers, then executes both kernel and
direct-interpreter parent entry. `owned_spawn_probe.c` uses the explicit
`/consumer` path in each private chroot, preserving its host-static default
`/proc/self/exe` path. The workload checks attributes, signal masks/defaults,
sessions, ordered file actions and descriptor collisions, directory actions,
PATH search, worker spawn, denied syscalls, descriptor exhaustion and rollback.
`run_owned_dynamic_spawn.sh` retains the object, link receipts, ELF inspections
and observations; the qualification catalog executes it on both clean products
and the extracted package. Run its focused gate with
`./scripts/dev-x86_64.sh owned-dynamic-spawn`.

The `atfork-registry` case verifies more than 65 ordered registrations,
parent/child/worker additions, and failed-fork parent completion in both
dynamic linkage forms and direct interpreter entry. Its source and private
archive boundary are in
[`owned-atfork-registry.md`](owned-atfork-registry.md).

The main thread keeps the initial wire DTV/count at FS+8/FS+16. The loader
publishes current runtime TLS views at FS+24 and owns generation and module
IDs, worker allocation/release, and old-view lifetime. The private 72-byte
RuntimeV1 descriptor and 144-byte owned CRT record are validated before libc
TLS access. `owned_runtime` names the current producer, attachment, worker
adapter and runtime-view definitions. This ownership remains separate from
static TLS and from the earlier private foundations.

Successful `dlclose` retains mappings and module IDs as musl does. Failed
load transactions roll back before publication. Initial IE and GD TLS are
supported; runtime GD grows all live thread views, while new runtime IE is
rejected cleanly. Linking defaults to NOW with RELRO; the explicit declared
lazy-import DSO path retains its documented GOT/RELRO safety boundary.

Only a valid reviewed publication makes the product report `materialized`
and the RuntimeV1 report `verified`/published. `campaign_report.py` still
requires every declared prerequisite family and the independent full-26,
capability and platform qualification gates. Product publication does not
change the ledger, those family states, or public support. A stale or dirty-source publication is unqualified rather than reused;
its pointer remains available for inspection and cannot block fresh
qualification. Explicit receipt validation still reports the precise stale
or missing evidence. A fresh reviewed receipt can replace the old pointer. All generated receipts and referenced evidence
must remain available under the checkout's ignored `.work` tree.

Retained evidence is readable from the host without a Docker status wrapper.
`prepare` adds read/traverse permission only to the fresh top-level evidence
work directory and makes its log readable, including on preparation failure.
Runtime fixture roots keep their original permissions while their leaf runs.
After each leaf exits, the producer adds directory read/traverse and regular-file
read permissions only within the exact `.work` evidence roots named by that
leaf, before sealing artifact snapshots. Symlinks are never followed, special
nodes stay unchanged, regular-file executable/write bits stay intact, and no
whole `.work` permission rewrite occurs. `finish` applies the same retention
policy to its exact completed work tree before validation. Snapshot modes thus
describe retained evidence; runtime permission semantics come from the executed
fixture assertions and musl observations, before normalization.
