# x86 loader/libc TLS RuntimeV1 contract

`compat/x86_64/loader-libc-tls-runtime-v1.toml` records the first private
contract that can eventually join the x86 dynamic loader to libc's pthread/TLS
runtime. It remains a planned, non-promoting design and validation gate for
the dynamic product. It records two cfg-isolated initial-TLS
producer/consumer foundations (one fixed graph and one bounded general initial
graph) plus one narrower real-Scrt1 bridge to a private dynamic-libc evidence
DSO. It does not claim that static TLS, normal fixed initial-TLS, ordinary
general initial-TLS materialization, or pthread worker fixtures implement the
general RuntimeV1 lifecycle.

Run the fail-closed contract check with:

```text
python3 compat/x86_64/validate_loader_libc_tls_runtime_v1.py --json
```

The check accepts only `status = "planned"` and `non_promoting = true` until
a later implementation changes the contract, focused native evidence, ledger,
and product gates together.

## Ownership and process selection

The startup mode is selected from `PT_INTERP`, never from ELF type. A static
PIE can be `ET_DYN`, so `ET_DYN` is not evidence of an interpreter or a
dynamic loader.

| Process shape | Selector | TCB owner | DTV owner | Thread source |
| --- | --- | --- | --- | --- |
| Owned static executable or static PIE | no `PT_INTERP` | `crabc-libc` Static Initial TLS v1 | none | libc's static owner |
| Owned dynamic PIE or non-PIE | `PT_INTERP` naming the installed crabc loader | `crabc-ldso` RuntimeV1 | `crabc-ldso` RuntimeV1 | libc consumes the loader operation |

The static row is intentionally the existing limited owner in
`libc/src/c_abi/x86_64/static_tls.rs`: one final executable image, direct
local-exec TLS, and no module registry or DTV. It cannot be invoked by an
interpreter-mediated process. Conversely, dynamic startup must not invoke
`__crabc_x86_static_tls_bootstrap`, copy `StaticInitialTlsPlan`, or make
`pthread_create` choose a private static layout.

Each process selects exactly one owner before any TLS access. The static and
dynamic branches share a consumer boundary, not an allocation owner. The
dynamic row has one authoritative owner. `crabc-ldso` owns the module
registry, module IDs, TLS layout, TCB/DTV allocation, generation, DTV growth,
and dynamic `__tls_get_addr` route. `crabc-libc` owns pthread identity, errno,
cancellation, TSD, and other libc per-thread state only through the
loader-provided attachment boundary. It does not allocate or resize a dynamic
DTV and does not install a dynamic `%fs` base directly.

## RuntimeV1 handshake

RuntimeV1 is private loader/libc state, not an installed C declaration. The
eventual dynamic loader producer must validate all initially mapped main-image
and DSO `PT_TLS` descriptors in loader link-map order before it publishes the
descriptor.

Its input is that validated initial object set; its main-thread output is:

- a `%fs` thread pointer installed only after the full Variant-II block is
  materialized;
- an initialized TCB, DTV, module registry generation, and all initial module
  slots; and
- one private descriptor carrying a magic, version, ABI size, mode, owner,
  generation, and a libc attachment operation.

The future CRT handoff validates every one of those descriptor fields before
any libc direct-TLS access. A bad field, missing generation, owner/mode
mismatch, or failed allocation is a startup failure; it is never a reason to
fall back to libc's static TLS plan.

## Implemented private initial-TLS foundation

`ldso/src/x86_64_initial_graph.rs` now has one cfg-isolated sibling compiled
with `crabc_initial_tls_graph` and `crabc_loader_libc_tls_runtime_v1`. After
its fixed graph has materialized every admitted initial `PT_TLS` image and
successfully installed `%fs`, it publishes the 72-byte private
`__crabc_x86_64_loader_tls_runtime_v1` record. The record carries its ready
state, magic, version, ABI size, dynamic-mode tag, ldso-owner tag, one initial
generation, thread pointer, DTV pointer, DTV capacity, and populated module
count.

The only consumer is the isolated
`libc/src/c_abi/x86_64/loader_tls_runtime_v1_source_root.rs` evidence root.
Its `__crabc_x86_loader_tls_runtime_v1_attach` entry resolves one weak loader
record import. It first checks ready state, magic, version, ABI size, mode,
owner, generation, pointer alignment, and DTV bounds. Only after that complete
gate does it obtain `ARCH_GET_FS` and read `%fs:0`, `%fs:8`, and the declared
DTV count. The malformed fixtures deliberately publish pointer value `1`, so
a metadata-validation regression faults rather than accidentally succeeding.

`compat/x86_64/run_loader_libc_tls_runtime_v1.sh` proves the positive live
handoff and independent bad-magic, bad-version, bad-ABI-size, bad-mode,
bad-owner, and bad-generation rejections with live initial-TLS coordinates,
plus a valid-metadata poisoned-DTV rejection before a DTV read. It verifies
the backing record stays out of the interpreter dynamic symbol table, then
builds a no-`PT_INTERP` static executable with the explicit static consumer
stub, verifies that it has no loader-record import, and requires rejection
before an FS access. The foundation therefore preserves
`libc/src/c_abi/x86_64/static_tls.rs` as the static-mode owner.

This is not a general dynamic loader completion: there is no loader registry
mutation, runtime `PT_TLS` admission, DTV growth or replacement, old-DTV
reclamation, dynamic pthread/`CLONE_SETTLS` materialization, dynamic CRT
carrier, general `__tls_get_addr` route, unload policy, or product promotion.
The descriptor generation is exactly one initial publication, not a growth
protocol.

## Implemented initial registry-state foundation

`ldso/src/x86_64_initial_tls_registry.rs` now owns the typed state used by
that private producer's initial planner. It assigns only TLS-bearing initial
objects stable one-based `TlsModuleId` values in loader order, records their
object-index association, and seals the sole `InitialTlsGeneration` value
(`1`) before installation and publication. The planner, installer, and
publisher cross-check that sealed registry rather than treating a local
counter as the RuntimeV1 owner.

The registry has an explicit `reject_runtime_tls_growth` result:
`DtvGrowthProtocolUnavailable`. It leaves the sealed IDs and generation
unchanged. This is a real state boundary, but not an admission implementation:
it does not inspect or reject a future DSO before mapping, because no general
x86 runtime TLS mapper exists yet. The ordinary cfg-isolated general
initial-TLS materializer below consumes the sealed registry only for the
already mapped initial graph; it is not a RuntimeV1 producer. The separate
general RuntimeV1 wire also consumes that sealed initial registry, but remains
one generation-one publication with no growth protocol. The required pre-map
rejection belongs with a future general mapping transaction that also owns
module-ID publication, relocation, constructors, thread refresh, and DTV
lifetime.

Run `./scripts/dev-x86_64.sh loader-libc-tls-runtime-v1-registry` for the
pinned native state proof. It compiles the registry alone and proves stable
initial IDs, sealing, capacity/duplicate rejection, and no-mutation runtime
growth rejection. It is not a loader product test and makes no static libc,
dynamic pthread, DTV-growth, capability, or promotion claim.

## Implemented private general initial-TLS materialization

`ldso/src/x86_64_general_initial_tls_source_root.rs` is the ordinary
`crabc_general_initial_tls_materialization_v1` sibling. It keeps the bounded
general initial `DT_NEEDED` graph private, assigns its TLS-bearing main and
DSO objects generation-one IDs in loader order, validates each `PT_TLS`
template, lays every image below TP using Variant II, copies initialized bytes,
zeroes TBSS, and resolves the graph's direct GNU TLS indexes. This ordinary
source root is not a RuntimeV1 descriptor producer and has no libc attachment,
CRT carrier, pthread/new-thread operation, runtime map operation, DTV
replacement, or unload policy.

All fallible graph, relocation, protection, RELRO, registry, and publication
arbitration work finishes before `ARCH_SET_FS`. The state reserves its sole
private publication slot before that syscall; any pre-FS failure rolls the
reservation back to unpublished. After a successful install, the retained
loader snapshot commits without a fallible step, so it never reports failure
with a changed `%fs` and no owner. The source-root and feature-gated target
roots both run a pinned-musl diamond differential and malformed-input matrix,
including the reservation rollback/retry regression:

```text
./scripts/dev-x86_64.sh ldso-general-initial-tls
./scripts/dev-x86_64.sh ldso-general-initial-tls-target-root
```

Those ordinary-source-root commands are private evidence only. They do not
establish installed dynamic PIE/non-PIE startup, RuntimeV1 publication,
dynamic pthread behavior, DTV growth, `dlopen`, a dynamic CRT/sysroot, a
loader family transition, or public x86 support.

## Implemented private general initial-TLS RuntimeV1 wire

`ldso/src/x86_64_general_initial_tls_runtime_v1_source_root.rs` is a separate
cfg-isolated root. It combines `crabc_general_initial_graph`,
`crabc_general_initial_tls_materialization_v1`, and
`crabc_general_loader_libc_tls_runtime_v1` over the already bounded arbitrary
initial `PT_TLS` diamond. It is the dedicated private general RuntimeV1
producer; it does not alter the ordinary source root described above.

Before `ARCH_SET_FS`, the loader reserves both the retained general-TLS state
and its descriptor. Each moves from `UNPUBLISHED` to `PUBLISHING`; every
pre-FS failure releases both reservations. After the successful install, the
retained state commits without a fallible successor, fills the 72-byte
loader-owned descriptor, and release-publishes `READY` last. Dependency
constructors run only after that `READY` transition, so their
`__crabc_x86_loader_tls_runtime_v1_attach` observation cannot see a partial
descriptor.

The descriptor is local/hidden private writable data, exactly 72 bytes, absent
from `.dynsym`, and outside even the page-rounded `PT_GNU_RELRO` interval. The
libc observer remains the same isolated
`libc/src/c_abi/x86_64/loader_tls_runtime_v1_source_root.rs`: it validates
ready state, magic, version, ABI size, mode, owner, generation, alignment, and
DTV bounds before `ARCH_GET_FS`, `%fs:0`, `%fs:8`, or a DTV read. Its one GOT
record import is accepted only when it is undefined and weak in the main image.
A strong main-image record import or a weak DSO import fails in the loader
before `ARCH_SET_FS`; a no-`PT_INTERP` static observer has no record import and
rejects before any FS access.

Run the direct and Cargo-root private evidence with:

```text
./scripts/dev-x86_64.sh loader-libc-general-tls-runtime-v1
./scripts/dev-x86_64.sh loader-libc-general-tls-runtime-v1-target-root
```

The source-root command runs malformed magic/version/size/mode/owner/generation
and poisoned-DTV variants as isolated consumer checks. The Cargo-root command
proves the positive feature-gated `crabc-ldso` path; it deliberately retains
the source-root malformed variants because they isolate the private descriptor
wire. Both commands first rerun the ordinary general-TLS musl diamond as an
independent initial-layout/value base proof. Musl cannot compare this private
record or constructor attachment, so it is not a descriptor-wire oracle.

This wire is not a dynamic CRT handoff or product: it has no installed
interpreter, dynamic PIE/non-PIE product, libc startup carrier, pthread/new
thread operation, DTV growth/replacement, runtime mapping/`dlopen`, unload,
general lifecycle, family/capability promotion, or public x86 support.

## Implemented private dynamic main-thread RuntimeV1 bridge

`ldso/src/x86_64_dynamic_main_thread_runtime_v1_source_root.rs` is a fourth,
explicitly dependent general RuntimeV1 root. It adds only the shape needed by
the private real-Scrt1 fixture: `crabc_dynamic_main_thread_runtime_v1` keeps
the existing retained general initial-TLS state and 72-byte RuntimeV1 record,
then admits the ordinary null weak owned-CRT relocation emitted by the
Rust-produced `Scrt1.o`. It does not select the older owned-CRT carrier.

That admission is intentionally exact and happens in relocation evaluation
before normal lookup. Only the unmapped main image's default-visible,
undefined `STB_WEAK` `STT_OBJECT`
`__crabc_x86_64_owned_crt_handoff` `R_X86_64_GLOB_DAT` relocation with a zero
addend receives zero. A strong main import, a weak DSO import, another
relocation form, or a nonzero addend rejects before `ARCH_SET_FS`. A dependency
DSO definition of the name cannot interpose: the exact Scrt1 slot still reads
null, so it cannot accidentally select the 32-byte owned-CRT carrier or a
loader finalizer.

`crt/build_x86_64.py --dynamic-main-thread-runtime-v1` produces this private
`Scrt1.o` variant only. Immediately after its ordinary null-owned-handoff
decode and immediately before `__libc_start_main`, it calls the existing
main-resident `__crabc_x86_loader_tls_runtime_v1_attach` consumer. A malformed
descriptor returns failure before preinit, init, main, or the private dynamic
libc boundary. The loader validates the real main image's `DT_INIT`,
`DT_FINI`, preinit, init, and fini array tag shape but does not dispatch those
entries; `Scrt1.o` retains that executable lifecycle ownership.

The fixture-local DSO at
`libc/src/c_abi/x86_64/dynamic_main_thread_runtime_v1_source_root.rs` exports
only `__libc_start_main` and `__errno_location`. It requires the musl-shaped
null sixth `rtld_fini` argument, observes zero dynamic TLS `errno`, invokes
the callbacks, and exits directly. The real main and that DSO each carry
`PT_TLS`; the source-root evidence requires `PIMFL` to prove preinit, init,
main, fini, and final dynamic-libc sequencing with a dynamic errno/TLS write.
It does not make this minimal DSO an installed `libc.so` or ordinary-exit
implementation.

Run the two private roots with:

```text
./scripts/dev-x86_64.sh dynamic-main-thread-runtime-v1
./scripts/dev-x86_64.sh dynamic-main-thread-runtime-v1-target-root
```

The direct root also runs magic/version/ABI-size/mode/owner/generation and
poisoned-DTV negatives with empty output/status 127, uses the no-`ARCH_SET_FS`
trace for strong-main and weak-DSO owned-record imports, and proves that a DSO
definition of the owned-record name cannot interpose. The target-root command
builds the dedicated Cargo `crabc-ldso` feature for the same positive graph.
Pinned musl remains the ordinary bounded general-TLS layout/value oracle; it
does not define this private record, direct Scrt1 attachment, or minimal libc
boundary.

This is deliberately not a general loader lifecycle or dynamic product. It
does not defer dependency constructors to Scrt1, publish an owned-CRT carrier,
invoke loader finalizers, add `dlopen`/unload, grow or replace a DTV, create
workers, install an x86 sysroot, or promote a family, capability, or public
x86 support claim.

For a new pthread, libc supplies its per-thread initializer to the active
owner. In dynamic mode, RuntimeV1 produces a fresh complete TLS/TCB/DTV block,
runs the libc attachment operation, and returns the only thread pointer that
may be passed to `CLONE_SETTLS`. In static mode, the independent static owner
does that work. The two branches must be selected before the clone boundary,
not inferred from a cached `%fs` value.

At fork, the dynamic child repair order is loader state first and libc's
thread registry second. Cancellation remains libc state, but it is attached to
the one RuntimeV1-created thread context rather than becoming another TCB
owner.

## Linux/x86-64 Variant II

RuntimeV1 fixes the private geometry needed by current x86 ELF TLS code:

- `%fs` is the thread pointer; the TCB begins at TP and its self word is at
  `%fs:0`.
- The DTV pointer is at `%fs:8`; consumers must not reach farther into the TCB
  by guessed offsets.
- Every `PT_TLS` image is below TP. `p_filesz <= p_memsz`, `p_align` is a
  power of two, and the loader preserves the source `p_vaddr`/`p_offset`
  alignment phase while copying initialized bytes and zeroing TBSS.
- The final placement observes the maximum required alignment. A contiguous
  but misaligned image, a missing self word, or a DTV published before its
  slots are ready is rejected.

This matches the direction and initialization rules exercised in the existing
private loader fixture, but does not bless its fixed-capacity prefix as a
pthread TCB.

## DTV growth and the current rejection boundary

Initial TLS-bearing objects receive nonzero, loader-owned module IDs before
GNU dynamic TLS relocations or the libc handoff. The registry generation is
monotonic while a module remains addressable. Dynamic `__tls_get_addr` may
resolve only through the current loader-owned RuntimeV1 state.

Until the general loader has all four pieces of DTV growth—registry expansion,
current-thread refresh, new-thread materialization at the current generation,
and safe reclamation of old DTV storage—a `dlopen` closure containing `PT_TLS`
must fail before mapping, relocation, constructors, module-ID publication, or
a generation change. Raising a fixed `TLS_DTV_WORDS` constant is not growth.

After growth exists, old DTV storage remains live until no thread or loader
reader can observe it. TLS-bearing unload must likewise reject or retain the
module until module lifetime and DTV slot safety are proved. This prevents an
unloaded image or stale DTV pointer from being hidden behind a successful
`dlclose`.

## Current regression seeds and future seams

The following normal fixtures remain private regressions, not RuntimeV1 producers:

- `libc/src/c_abi/x86_64/static_tls.rs` — static final-image TLS owner.
- `libc/src/c_abi/x86_64/pthread_create_join.rs` — selected static worker
  materialization and `CLONE_SETTLS` seam.
- `ldso/src/x86_64_initial_graph.rs` — normal fixed-graph initial dynamic
  TLS/DTV fixture. Its separate cfg-isolated RuntimeV1 foundation above is a
  one-shot producer/consumer proof, not a general loader runtime.
- `ldso/src/x86_64_general_initial_tls_source_root.rs` — ordinary bounded
  general initial-TLS materialization. Its separate
  `x86_64_general_initial_tls_runtime_v1_source_root.rs` sibling is the
  one-shot bounded-general private producer above, not a dynamic product.

The next narrowly scoped implementation points are the loader runtime state in
`ldso/src/loader.rs`, the future CRT carrier over the established RuntimeV1
descriptor, the dynamic consumer branch in
`libc/src/c_abi/x86_64/pthread_create_join.rs`, static/dynamic separation in
`libc/src/c_abi/x86_64/static_tls.rs`, and the future dynamic CRT carrier near
`ldso/src/x86_64_initial_graph.rs`. The existing
`compat/x86_64/run_ldso_initial_tls.sh` stays a regression seed while an
installed product-level test is built; it is not that product test.

Descriptor-negative proof is complete at both the private fixed-graph and
bounded-general foundations. The remaining required native evidence is still
planned: installed dynamic PIE and non-PIE Variant-II layout; dynamic pthread
workers; runtime TLS DTV growth before and after worker creation; clean
pre-growth rejection through the installed loader; and loader/pthread fork,
cancellation, and TLS-lifetime stress. Those are prerequisites to a later
`libc.pthread-tls`, `ldso.dynamic-runtime`, and owned dynamic-product
transition, not evidence for either transition now.
