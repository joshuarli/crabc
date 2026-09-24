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
  spawn and non-PIE observations and owned-driver receipts; each base
  executable's replayed ELF inspection and link map; oracle evidence;
  identical independent archives and their exact installed payload contents.
  It writes `qualification.json` with status `qualified-pending-review`.
- `validate --receipt PATH` revalidates that receipt against live source,
  contracts and all retained evidence. Missing evidence or changed bytes fail.
- `publish --receipt PATH` is an explicit operation after review. It requires
  a clean source revision and atomically replaces the ignored publication pointer under
  `.work/x86_64/`, after rechecking source and receipt identity immediately
  before replacement. Immutable receipts and prior case evidence are never
  rewritten. No schema check or build invokes publication implicitly.

`dynamic-product.toml` maps each `coverage.required` obligation to the
registered cases that prove it (`[[coverage.evidence]]`); the contract
validator rejects an unmapped obligation or an unregistered case name. The
`cross-dso` case (`run_owned_dynamic_cross_dso.sh`) is the application-shaped
composition witness: in PIE and non-PIE entries, an initial dependency with
initial-exec TLS (`DF_STATIC_TLS`, reached by the executable's own
`R_X86_64_TPOFF64`) is reopened through `dlopen`, and a runtime plugin's GD
TLS, allocation ownership, errno, stdout, a TSD destructor, a SA_SIGINFO
handler, retained close/reopen, and atexit/destructor/stdio exit order cross
module boundaries, byte-identical with pinned musl.

The finite `CASES` roster maps the contract to CLI, dependency cycles, ELF
weak/protected/hidden scope and interpreter aliases, PIE/non-PIE runtime
loading and deferred binding, constructor exit, pthread signals and exit,
fork repair, stack attributes, join cancellation, condition-wait cancellation,
recursive/error-checking/timed and priority-inheritance mutex state with robust
recovery, C11 mapping, and both `PT_INTERP` and direct-loader consumer entry,
the shared full I/O cancellation roster, and the separate `system()`
cancellation protocol, the contained C `syslog` state/delivery matrix, and
private/shared pthread spin-lock publication, owned Linux-control and
kernel-residual mechanisms, filesystem mechanisms, the `perror`/`err(3)`
reporting matrix, and the C filename-pattern matrix. The catalog also requires
held-live pthread CPU-clock targets, public FILE allocator interposition,
allocator lifecycle errno preservation, and fork from an application signal
delivered at worker startup. These regression cases run the supplied product;
their standalone self-build results cannot replace a product's case receipt.
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
`run_owned_dynamic_spawn.sh` retains `compile.json` and `workload.d` alongside
the one installed-driver object. The compile receipt binds the source, installed
dynamic driver, installed shared compiler helper, helper-selected compiler,
clean environment, and exact `/consumer` compile command. Its dependency-only
audit repeats the installed dynamic driver's C11/freestanding/stack-protector
and PIE translation flags through that helper, records every installed header
hash, and requires the spawn, signal, process, descriptor, resource, and
pthread source headers. The object, compile inputs, dependency output, and
installed headers are checked before and after every oracle, static, and
dynamic link. The runner also retains link receipts, ELF inspections,
shared-validator link identities, and raw stdout/stderr/exit status for every
entry. Each candidate's three raw results are compared to the oracle; a
nonzero timeout/chroot status is retained before failing. The qualification
catalog executes it on both clean products
and the extracted package. Run its focused gate with
`./scripts/dev-x86_64.sh owned-dynamic-spawn`.

For reused POSIX-family evidence inside the pinned native environment, the
leaf accepts `bash compat/x86_64/run_owned_dynamic_spawn.sh [--static-sysroot STATIC_SYSROOT] [DYNAMIC_SYSROOT]`.
Its default remains dynamic-only. Supplying a static product additionally
links the same `/consumer` workload object as ordinary static and static PIE,
requests sealed static receipts, and checks each link through
`owned_posix_product_evidence.validate_link`. Dynamic links use that same
strict validator. The exact returned identities are retained in
`static.link-identity.json`, `static-pie.link-identity.json`,
`pie.link-identity.json`, and `non-pie.link-identity.json` for the selected modes.
There is no static producer in this leaf. Static-only replay builds the default
dynamic product for compilation and dynamic execution; supplying both products
invokes no producer. Empty, option-valued, or duplicate product arguments fail
with usage status 2 before evidence creation. This extra replay does not close
the POSIX family or replace its per-product execution receipt.

The `atfork-registry` case verifies more than 65 ordered registrations,
parent/child/worker additions, and failed-fork parent completion in both
dynamic linkage forms and direct interpreter entry. Its source and private
archive boundary are in
[`owned-atfork-registry.md`](owned-atfork-registry.md).

The `process-trio` catalog case runs the installed `clone`, `vfork`, and
`daemon` differential in both dynamic forms and direct interpreter entry.
Its source mapping, child-state contract, and static companion evidence are
in [`owned-process-trio.md`](owned-process-trio.md). Run the focused full
linkage matrix with `./scripts/dev-x86_64.sh owned-process-trio`.

The `process-control` catalog case runs one installed-header workload for the
residual exec, priority, group/session, wait, and spawn-attribute names in
both dynamic forms and by direct interpreter entry. Its 31-name source mapping,
real child lifecycle checks, cancellation-point distinction, and stated
`fexecve` direct `execveat(2)` `ENOSYS` difference are in
[`owned-process-control.md`](owned-process-control.md). The documented 44-name
process-control accounting remains a composite with separate trio, fork, and
spawn/file-action evidence. Run the full focused matrix with
`./scripts/dev-x86_64.sh owned-process-control`.

Every installed-driver link also inspects its final ELF before any caller can
execute it. `owned_dynamic_elf.py`, installed as
`share/crabc/owned_dynamic_elf.py`, parses the output directly rather than
reading `readelf` text. It requires the declared ELF type, the canonical
`PT_INTERP` for executables and none for DSOs, and `DT_NEEDED` equal to the
declared direct DSOs then `libc.so`. `DT_SONAME`, the declared RUNPATH or
RPATH, NOW or declared lazy binding, and the hash style must also match. The
output needs exactly one non-executable `PT_GNU_STACK` and one
`PT_GNU_RELRO`, no writable executable load, and at most one `PT_TLS`. Text
relocations, symbol versioning and IFUNC fail. Dynamic relocation kinds must
be ones the owned loader applies, COPY stays out of DSOs, and every strong
import resolves through declared providers or a declared lazy import. A
rejected output is removed. An accepted one gets `<output>.crabc-elf.json`
and LLD's `<output>.crabc-link.map` beside its receipt. The receipt schema is
unchanged.

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
Leaves with independently sealed permission records must finish this same
retention step before publishing their reports and validate exact retained
permissions. The wordexp version-5 receipt does so while preserving its
separate private-directory assertions during execution; repeating the outer
retention step leaves its sealed evidence unchanged.

## Combined four-mode sysroot

`scripts/build_x86_64_owned_combined_sysroot.py` composes this product with
the owned static product into one tree; its docstring owns the composition
rules. The installed dynamic driver accepts that tree only through
`validate_combined` in `crabc_cc_owned_dynamic.py`: the combined manifest must
match the whole tree exactly, its only aliases are this product's, and every
file named by the embedded `share/crabc/dynamic/manifest.json` must be
installed unchanged at its own path; only product metadata may move within
`share/crabc/`. The static driver applies the same rule to
`share/crabc/static/manifest.json` in `combined_manifest_payload`
(`crabc_cc_static.py`), except that the static product's unlinked
`usr/lib/Scrt1.o` yields to the dynamic PIE entry.
Links from a combined tree otherwise follow the same inspection and receipt
contract; the receipt's `manifest_sha256` names the combined manifest.
`owned_posix_product_evidence._validate_static_product` and
`_validate_dynamic_product` accept the same combined trees and return the
combined manifest and the tree's whole installed roster.

`./scripts/dev-x86_64.sh owned-combined-sysroot` builds two clean combined
trees, compares them byte-for-byte, requires identical packages and compares a
fresh extraction. It then runs `run_owned_static_sysroot.sh --supplied-sysroots`
once per clean tree with the extracted tree, and
`run_materialized_dynamic_sysroot.sh --supplied-work` over the installed,
second and extracted trees, so this qualification's `finish` binds the combined
packages. The supplied static run retains its evidence instead of writing the
static product receipt. The gate fails closed until both products install one
shared `usr/lib/crt1.o`, and until every dynamic-suite leaf that re-validates
its product accepts a combined tree.
