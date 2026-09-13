# Native x86 ABI selection and ownership

The native ABI contract selects observable C interfaces and their owners. An
ELF inventory records what an artifact contains; the dynamic ratchet prevents
regression against a reviewed observation. Neither chooses the supported ABI.
This contract supplies the ownership rules for the complete callable/data
manifest required by `x86-64.md`, under `libc.c-abi-compat` and
`compat.abi-differential`. The executable accounting below retains unresolved
selection and evidence requirements; complete provider proof remains required.

## Executable accounting

The reviewed selection policy is `native-abi-selection.toml`.
`native_abi_selection.py` expands its finite owner groups together with the
frozen capability requirements and current header/provider contracts. It joins
those logical obligations to the complete ELF observations, preserving each
artifact, archive-member occurrence, symbol-table row, and defining section.
Unresolved selections and unowned observations remain enumerable report records.
They cannot disappear through a symbol-name prefix, visibility filter, or an
expected-count adjustment.

Use the native dispatcher to build or replay an audit from retained evidence:

```bash
./scripts/dev-x86_64.sh native-abi-selection build-report \
  --measurement-checkout .work/worktrees/measurement-source \
  --elf-facts .work/x86_64/elf-facts/report.json \
  --base-inventory .work/x86_64/abi-inventory/report.json \
  --static-product .work/x86_64/static/products/primary \
  --dynamic-product .work/x86_64/dynamic-product \
  --static-preparation .work/x86_64/static/preparation.json \
  --output .work/x86_64/abi-selection
```

The output directory must be fresh and remain under the selecting checkout's
`.work/x86_64/`. Inputs may refer to preserved physical worktrees and evidence
under the canonical checkout's `.work/`. These operations run the retained-fact
readers on the host. They do not compile or rebuild a runtime product.
`validate-report REPORT` takes the same explicit measurement and product inputs
and recomputes the audit; it does not accept the report's claimed sets or flags
as evidence. `require-closure REPORT` performs that replay and then requires the
complete selected contract. Neither replay command takes `--output`.

The measurement checkout identifies the unchanged collector that owns the
supplied ELF receipts. The selecting checkout identifies the policy and source
being assessed. Both identities remain in the result. Historical products can
support an incomplete audit, but cannot establish current selection closure.
The existing inventory and ELF readers keep their same-collector validation;
selecting a historical measurement checkout does not relax that contract.

Supply `--declaration-report REPORT` when the enumerable compiler declaration
receipt from [the declaration collector](header-declaration-inventory.md) is
available. Missing declarations, unresolved linkage or layout,
unproved extraction/alias/protocol behavior, and incomplete owning family
evidence remain closure blockers even when the physical symbol metadata
matches. Successful audit generation means the inputs were accounted for; only
`require-closure` establishes that none of those obligations remains open.
The full report and retained physical evidence belong under ignored `.work/`,
while the reviewed policy stays in source control. No selection operation
changes family, qualification, or public-platform promotion state.

When both current owner receipts are available, supply
`--public-data-ordinary-link-report REPORT` and
`--loader-debug-abi-report REPORT`. They are an optional pair: one without the
other, or either repeated, is rejected. The first reader authenticates ordinary
addressability for the exact 32 static/shared data objects and ten declared
aliases against the same supplied static preparation and dynamic product. The
second reader authenticates the shared-only eight-byte `_dl_debug_addr` loader
pointer from its own same-source product cohort. Its retained `libc.so`, loader,
dynamic manifest, and dynamic state must nevertheless have the same bytes as
the selected dynamic product; the report retains both cohort paths. The
selection report records a `public_data_linkage_companion` and scoped physical
import joins. It discharges
only a selected object import when every candidate import for that exact object
is in the static product covered by the ordinary-link receipt. It does not set
the aggregate semantic-receipt gate, `runtime_semantics_proven`, family
completion, qualification, or public support.

Supply `--compiler-helper-aggregate-report REPORT` to attach the
[`compiler-helper archive proof`](../../builtins/x86_64-helper-contract.md).
Its owning reader joins the clean aggregate source and exact archive bytes to
both installed builtins roles. The selecting and measuring checkout must be
the same. With the ordinary-data receipt pair above, the component also checks
the static and static-PIE extraction maps for `__popcountdi2`. Selection
discharges its import obligation only when the complete candidate import set
is that exact static archive member occurrence and symbol-table row. Another
candidate import keeps the obligation open. An aggregate without ordinary
maps proves the installed archive ABI component while leaving the import
obligation unchanged. Shared helper visibility, runtime semantics and family
completion remain separate; the report retains both the component and its
scoped import join.

The current reader accounts for physical placements and source-selected
metadata. After the single public declaration replay, it applies
[`native_data_declarations.py`](native-data-declarations.md) to the 19 installed
variables, `h_errno` accessor macro and 13 ABI-only spellings. The nested account
retains its adapter and policy identities, qualified types, direct and transitive
observations, and current-source comparison. This selected data agreement leaves
callable declarations, object layout and accessor-to-storage behavior open.
Component and family receipt adapters remain to be integrated, so current
reports retain those blockers and `require-closure` refuses them. The optional
public-data linkage companion is a narrow exception to that absence: it records
ordinary link/addressability evidence without claiming object lifecycle,
strong override, interposition, COPY relocation, header feature-profile, or
runtime mutation semantics.

The same replay also feeds
[`native_callable_declarations.py`](native-callable-declarations.md).  That
adapter consumes the already checked header-matrix projection and existing
provider/deferred/ABI-only partitions.  It preserves every selected raw
`FunctionDecl` occurrence and requires exact multiplicity-preserving compiler
type/linker-spelling-pair agreement where a pinned declaration is comparable.
It first requires the complete derived header envelope and binds each selected
raw declaration to its retained AST job and physical-header dependency.  Its
sole candidate-only native extension is the existing exact `tgkill` record.
It does not infer language linkage, select a provider, use macro or GCC
fallback records as declarations, prove runtime behavior, or close any family.

When the current ordinary declaration-object receipt is available, supply it
as `--ordinary-declaration-abi-report REPORT` together with
`--declaration-report REPORT`. The selector replays the full public header
envelope once, then passes that exact authenticated envelope to
[`native_declaration_abi.py`](native-declaration-abi.md). The component still
reconstructs and checks its own current source snapshots, raw compiler/object
evidence, callable plan, and record-layout projection; the shared envelope
only avoids rereading the retained header receipt. Its finite joins retain all
ordinary C/C++ object observations, including the four `membarrier` C++
spelling mismatches, and attach only `_ns_flagdata` element and `in6_addr`
record facts. They do not select a provider, establish `h_errno` storage
lifecycle, erase language-linkage differences, or change the aggregate
completion, family, promotion, or public-support flags.

`--prepared-worker-tls-report REPORT` is independently optional. Its owner
reader authenticates the same selected static preparation, dynamic product,
complete ELF facts, and current source transaction before the selector joins
three private shared-libc source-dispatch imports, the seven retired prepared
worker-token names. It separately authenticates the source contract for the
72-byte initial TLS descriptor, including its exact field roster and owned
runtime provenance. The descriptor has no selected shared-libc consumer and
no loader ELF provider definition. Instead, its only selected source endpoint
is the weak unversioned `WEAK DEFAULT NOTYPE UND` `.symtab` row in
`dynamic-crabc-dynamic-attach.o`, with zero value and size; the CRT receipt
then binds its GOTPCREL reference to one weak `GLOB_DAT` slot in each owned
normal/empty PIE and non-PIE main image, and proves no slot in static,
conventional, default, or oracle images. The owned probe checks 72-byte/8-byte
geometry, magic/version/mode/owner, acquire-READY, and FS TP/DTV coordinates.
Those measured transport and geometry requirements discharge only through the
current CRT receipt. Release-READY ordering, malformed-record rejection,
worker lifetime/mapping generation, and fork ownership remain open; source
fixtures do not qualify installed products. The owner records its supplied preparation,
public reports, product roots, manifests, and dynamic state as exact
checkout-relative path/hash/size identities; the selector joins each to the
same supplied path and content, then retains its mode-bearing product cohort
for the post-attachment transaction recheck. It does not attach the distinct
owned CRT handoff carrier, fabricate a loader provider or shared consumer, or
claim RuntimeV1 facade parity, general pthread semantics, family completion,
promotion, or public support.

`--errno-storage-lifecycle-report REPORT` is also independently optional. Its
owner reader and the selector bind the current static/dynamic manifests,
`libc.a`, `libc.so`, shared-libc provenance, complete ELF observations, source
snapshot, and report bytes before and after the attachment. The finite join
accounts for `__errno_location`, `__h_errno_location`, `h_errno`, and the
private `___errno_location` same-definition alias. The alias remains a static
`WEAK HIDDEN` provider and a shared local `.symtab` definition with no shared
dynamic export; it is never selected as a public callable. The runtime receipt
proves main/live-worker accessor behavior and pointer lifetime within its own
contract. `__h_errno_location` keeps the assembled
`checked-header-provider-routing` owner while the exact `x86-h-errno` feature
roster remains a required receipt precondition; the feature membership does not
rewrite that selected provider route. Without that receipt, the private alias retains its own unresolved
component requirement even when its static and shared metadata match. It also
retains the source-required four-byte `h_errno` alignment in each static
and shared defining section, without promoting incidental shared-section
over-alignment into a generic ABI rule. It does not prove the `h_errno` header
macro/declaration or accessor-to-storage relation, broad TLS or loader behavior,
family completion, promotion, or public support.

`--native-c-allocator-boundary-report REPORT` is independently optional as
well. Its owner reader replays the selected static preparation, static product,
dynamic product, complete ELF facts, fixed-C producer provenance, and the
bounded wrapper/lifecycle and interposition transcripts. The selector seals
the report before and after that replay, binds its manifests, libc bytes,
static and shared provenance, dynamic materialization state, and ELF report to
the same current transaction, then rechecks them after placement joins. It
discharges the ordinary-import reason only for the seven unversioned
`NOTYPE GLOBAL DEFAULT` candidate-static `.symtab` imports in the authenticated
static Rust-root archive member: `_mi_auto_process_done`,
`_mi_auto_process_init`, `mi_free`, `mi_malloc_aligned`,
`mi_realloc_aligned`, `mi_usable_size`, and `mi_zalloc`. The fixed-C producer
account must also supply the matching selected static and shared provider
metadata. An import of the same name from another member or artifact remains
an unresolved ordinary consumer. This does not make the C v3.3.2 backend an
allocator-family, general allocation semantics, promotion, or public-support
claim.

`--stdio-alias-contract-report REPORT` is independently optional. Its owner
reader replays the current selected source, static preparation, static and
dynamic products, complete ELF facts, ordinary candidate links, and its
contained FILE runtime controls. The selector seals that report before and
after the replay, then binds all four retained `.symtab` views to the same
complete ELF transaction. It discharges the finite feature-receipt requirement
for the 39 pending weak FILE aliases only when each has its named target in
the same archive-member/section or shared definition domain. It also selects
only `__fdopen`, `__fseeko`, and `__ftello` as the private
`x86-owned-stdio-private-bodies`: static `FUNC GLOBAL HIDDEN`, shared
`.symtab` `FUNC LOCAL HIDDEN`, and absent from shared `.dynsym`. Their public
weak aliases remain separate public identities. `__uflow` and `__overflow`
remain retained protected-body controls; this receipt does not widen their
scope. Missing or invalid FILE evidence leaves the three named private bodies'
explicit receipt requirements open. The attachment does not establish general
stdio semantics, declarations/profiles, runtime qualification, family
completion, promotion, or public support.

The expanded FILE receipt observes 42 aliases across its five exact source
owners. `attach_native_stdio_alias` binds the 39 aliases with outstanding
feature-receipt obligations: four narrow scan aliases belong to
`x86-stdio-permanent-format-scan`; the other 35 belong to
`x86-owned-static-runtime`. `__getdelim`, `__isoc99_sscanf`, and
`__isoc99_vsscanf` remain observed in the owning receipt but acquire no
invented selector obligation or discharge. The three hidden bodies and two
protected controls retain their existing boundaries.

`--syscall-alias-contract-report REPORT` is independently optional. Its v3
owner reader is the only process-free host replay of the retained native
receipt. The selector seals the report before and after that replay and binds
its current collector and selected product source, static preparation, complete
ELF facts/base inventory, selected static archive and driver, shared libc,
loader, manifest, dynamic materialization state, driver, producer-tools and
shared-provenance bytes, selected dynamic list, and retained source snapshots
to the same selection transaction. It also binds each concrete installed input
used by the sealed final links: static `crt1.o`, `rcrt1.o`, `crti.o`, `crtn.o`,
`libc.a`, and `libcrabc-builtins.a`; and dynamic `crt1.o`, `Scrt1.o`, `crti.o`,
`crtn.o`, `libc.so`, `libcrabc-builtins.a`, and
`crabc-dynamic-attach.o`. Each retained file must be physical, have the digest
recorded by its retained product manifest, and match the finite source-owned
installed-role mode policy: the six static roles are `0644`; dynamic `libc.so`
is `0755` and its other six roles are `0644`. The receipt replay and selector
both compare raw retained/current files with that collector-source policy;
current-versus-retained mode equality remains a transaction mutation check,
not the authority that chooses a mode. The dynamic state follows the same
retained-tree/manifest binding.
The reader retains its pinned image, musl oracle tools, exact 47 command
envelopes, and native semantic/override/interposition controls; the selector
does not replace those retained executions with ambient host tools.

The finite source-owner group `component-owned-syscall-private-bodies` selects
only the thirteen named `FUNC GLOBAL HIDDEN` static bodies
`__clock_gettime`, `__clock_nanosleep`, `__dup3`, `__fstat`, `__fstatat`,
`__lseek`, `__madvise`, `__mmap`, `__mprotect`, `__munmap`, `__lsysinfo`,
`__sigaction`, and `__libc_sigaction`. The receipt joins their matching shared
`.symtab` `FUNC LOCAL HIDDEN` bodies, requires no same-named shared `.dynsym`
definition, and joins the fourteen public `WEAK DEFAULT` aliases to their
same-definition domains. It discharges only those thirteen bodies' explicit
receipt requirements. `__statfs` and `__fstatfs` are source-local observations,
not selected providers. The six public ordinary-import reasons for
`clock_gettime`, `madvise`, `mmap`, `mprotect`, `munmap`, and `sysinfo` remain
open because this attachment has no selected installed-caller relocation
receipt. All unowned and unnamed physical rows remain in the complete ELF
accounting. No syscall family, qualification, promotion, or public-support
claim follows.

`--utmpx-receipt-report REPORT` is independently optional. Its owning
process-free reader reconstructs the retained eight selected aliases and
sixteen provider spellings, static executable function proof, dynamic import
proof, header evidence, retained commands and runtime controls. The selector
seals the report around replay, requires its collector and selected product
source to match the current selected cohort, and binds the static preparation,
complete ELF facts/base inventory, manifests, dynamic state, drivers, libc
products, loader, shared provenance, producer-tools, and every actual final
link input to current bytes and modes. The finite static input roster is
`crt1.o`, `rcrt1.o`, `crti.o`, `crtn.o`, `libc.a`, and
`libcrabc-builtins.a`; the dynamic roster is `crt1.o`, `Scrt1.o`, `crti.o`,
`crtn.o`, `libc.so`, `libcrabc-builtins.a`, and
`crabc-dynamic-attach.o`. Its unchanged v1 receipt envelope does not make a
mode field authoritative: the owner reader validates retained products through
the shared source-owned static/dynamic mode policy, and the selector reads that
same policy for its current and retained roster checks. Retained-tree or
manifest mode fields cannot replace it. Retained product manifests and trees
must seal each input, and the transaction rechecks the same roster after
attachment.

`attach_native_utmpx` maps only the reader's eight aliases — `endutent`,
`setutent`, `getutent`, `getutid`, `getutline`, `pututline`, `updwtmp`, and
`utmpxname` — to their existing `x86-owned-static-runtime` source-selected
feature-alias requirement. It reconstructs and matches the whole current
source-owned record: alias and target, binding and owner, state, evidence
record, runner, baseline and enabled feature closures, selection source, and
source provenance. It requires candidate static and shared alias/target
definition domains and preserves the complete named and unnamed ELF occurrence
roster. The remaining provider spelling `utmpname` is an unchanged
checked-header public provider with no selected feature-alias requirement; this
adapter creates no private-provider scope or new receipt requirement for it.
It does not change public imports, establish utmp semantics, complete a family,
qualify runtime support, or promote public support.

These runtime attachments run before the one public declaration-envelope replay
and are rechecked after their scoped joins. Their source/product/ELF cohort is
therefore shared with the selection transaction without rereading the header
receipt or turning a component account into a generic runtime claim.

`--crt-startup-report REPORT` is independently optional. Its owner replays the
installed CRT receipt before the selector reads its finite twelve-identity
projection. The selector requires the owner’s current collector and selected
runtime source identities, its static/dynamic product roots, their three
mode-bearing manifest/state inputs, the public ELF facts, and all nine owned
installed CRT/runtime artifacts to match the same selection transaction. It
requires relocation observations for the eight non-archive artifacts; the
selected static archive remains in the separate complete named-row placement
proof because it has no one relocation table of its own. The selector then
joins every retained named row to exactly one
complete-ELF occurrence and rejects an added, omitted, duplicated, or
substituted occurrence. `_GLOBAL_OFFSET_TABLE_` remains the one exact
link-time boundary: the attachment requires its archive undefined row and the
shared local `.got.plt` definition with their distinct metadata; it never
turns that spelling into a provider rule. The 32-byte owned handoff and the
88-byte conventional snapshot remain separate from the prepared-worker
72-byte descriptor. The owner evidence retains a separate finite main-image
descriptor-handoff account: the dynamic attachment object's weak GOTPCREL
input, four exact owned final-main weak `GLOB_DAT` slots, every non-owned/static
no-slot control, and the owned probe's geometry and TP/DTV observations. It
does not supply release-READY ordering, malformed rejection, worker lifetime,
mapping-generation, fork, general CRT lifecycle, runtime qualification, family
completion, promotion, or public support.

The v3 receipt additionally requires the canonical owner's finite descriptor
admission controls for kernel and direct entry. The selector checks that exact
contract in `_crt_startup_identity_names` and accepts the publicly replayed
`descriptor_admission` observation in `native_crt_startup_adapter`. These
checks include the DSO source object's weak `REX_GOTPCRELX` relocation before
its shared-object link; the owner separately reconstructs both fixture links.
The controls do not add a selector discharge: malformed-record rejection and the
other outstanding descriptor protocol requirements remain explicit obligations.

## Selection inputs and definition domains

Keep the frozen AArch64 capability, header, and ABI inputs unchanged. Correlate
their semantic requirements with the installed native header declarations,
the pinned musl 1.2.6 x86 ABI, explicit project extensions, and the selected
native runtime protocols. A Rust-facade classification such as `internal-runtime`
or `rust-subsumed` does not remove a C consumer obligation. A macro or static
inline definition does not create an independent external provider obligation.

An identity is the exact name, version, and version-defaultness triple. A
logical obligation records its selecting source, capability/family, and native
disposition. A provider placement additionally identifies its product profile
and artifact: the libc archive, shared libc, interpreter, individual CRT
object, builtins archive, or consumer. Binding, visibility, data layout,
undefined imports, and alias relations belong to that definition domain.

In particular:

- `_dl_debug_state` has separate weak definitions in libc and the interpreter.
  The loader's `r_brk` names the locally bound interpreter definition.
- Weak libc `_init` and `_fini` defaults coexist with strong CRT fragments.
  Calling a weak default does not replay process initialization or finalization.
- Static and shared `dlopen`, `dladdr`, and `dl_iterate_phdr` have separately
  selected bindings and runtime behavior.
- `_dl_debug_addr` is an eight-byte libc pointer to the loader's canonical
  40-byte `r_debug`. It is not a 40-byte public object or a second loader graph.

Consequently, neither one-provider-per-name across all artifacts nor equality
of addresses across different DSOs is a valid ownership rule. The exact
debugger/CRT relations are defined in
[`loader-debug-crt-abi.md`](loader-debug-crt-abi.md).

Static placement includes archive identity, member occurrence, symbol-table
section, and defining section. Repeated member or section names are valid;
equal `nm` values alone do not prove aliases. Source-selected function aliases
require their named target and binding. Data aliases additionally require the
same storage, type, and byte size in the same definition domain. Ordinary
extraction and the relevant strong-override/runtime proofs remain required.

[`native-abi-inventory.md`](native-abi-inventory.md) describes the complete ELF
text projections. They retain local, hidden, undefined, and unknown rows.
Successful parsing is not source-bound collection, ABI selection, or proof of
every ELF validity condition. A collector must bind the exact commands and
artifacts before selection can consume those facts.

## Exact structural native owners

Historical private spellings are not reproduced when the native runtime owns
the actual selected caller requirement through a different protocol. Each
mapping below is specific to the named frozen caller; it grants no general
permission to omit double-underscore names.

| Frozen identity | Native owner and retained requirement |
| --- | --- |
| `__dls2b`, `__dls3`, `_dlstart` | Native interpreter entry, self-relocation, TLS setup, and general startup own the real stage transitions. `loader-debug-crt-abi.md` defines the exact entry/ordering proof; returning libc stage probes are not substitutes. |
| `__auxv` | `auxv_observation.rs::install_initial` receives the validated initial vector from static or dynamic startup before constructors; `getauxval` observes it. No current selected x86 consumer requires the old writable raw global. |
| `__ldso_register_dlopen`, `__ldso_register_dlsym`, `__ldso_register_dlclose` | `general_dlfcn.rs` imports the selected direct operations from `x86_64_runtime_registry.rs`. Their loader operation, lifetime, locking, and error contracts replace mutable callback registration. |
| `__ldso_register_dlerror` | The loader returns operation errors; `general_dlfcn.rs` owns the calling thread's diagnostic state and consumes it through `dlerror`. This is an explicit owner split, not a renamed callback slot. |
| `__ldso_register_mark_multithreaded` | `x86_64_runtime_lock.rs::RuntimeGuard` uses its atomic graph lock from the first transaction. Worker TLS preparation acquires that lock before clone; there is no native single-thread recursion state to transfer. |
| `__rc_clone` | The actual frozen caller is `pthread_create`. Native `pthread_create_join.rs` owns its hidden pthread clone bridge, prepared worker entry, stack, TID pointers, and TLS token. The separate raw process-clone leaf is not this mapping. |
| `__rc_init_thread_tls`, `__rc_tls_block_size` | The selected static/dynamic TLS owner returns an already allocated and initialized token before pthread clone. The native consumer does not independently size and initialize the old combined stack/TLS mapping. |
| `__rc_tls_block_size_for`, `__rc_tls_base_offset_for` | Exact token release retains the mapping, size, thread pointer, and generation. The pthread exit/reap protocol proves release ownership instead of reconstructing a mapping from an arbitrary FS base. |
| `__rc_create_thread_tls`, `__rc_tls_base_offset` | The frozen repository has no separate caller beyond the old provider protocol. Selected native pthread callers use the complete allocation token; no separate allocation or offset-query export is implied. |
| `__sigsetjmp_tail` | `setjmp.rs` owns the local x86 assembly tail and its saved-mask/control-transfer contract. A local label need not become a public ELF identity. |
| `fopen64` | The selected `_LARGEFILE64_SOURCE` header macro names `fopen`, as recorded by `parity.toml::stdio.fopen64-alias`. Preserve the frozen AArch64 forwarding definition separately. |

The frozen archive-only `__invtrigl_R`, `__pio2_hi`, and `__pio2_lo` belong to
the generic inverse-trig source route. Native `math_x87_extended.rs` selects
the pinned x86 public long-double algorithms. Frozen `__restore` maps to the
native hidden `rt_sigreturn` restorer in `signal_foundation.rs`. None implies
a fabricated native helper export.

`__crabc_runtime_v1` needs separate treatment. The current `crabc-rs` crate root
gates its old `cfile`, `dl`, and `runtime_thread` consumers to AArch64. Their
absent native getter is not a current unresolved link. Full native facade
parity still requires explicit native consumer/protocol selection and evidence;
the existing private loader TLS descriptor does not automatically satisfy that
future facade contract.

## Runtime component attachments

The selection reader can independently attach either current-product receipt
without replaying the header declaration envelope.

- `loader_runtime_registry_evidence.py` is the sole reader for the nine
  `loader-runtime-operations` imports. The attachment binds its exact shared
  libc occurrences and selected loader provenance, then discharges only the
  protocol’s source-dispatch admission and finite runtime-behavior reasons.
  Its v2 receipt retains the tools and preprocessing inputs needed by the
  owning host reader. The selector binds the retained ELF report's exact
  `/workspace` path, bytes, size, and mode to the supplied checkout file and
  independently checks the public replay input identity. These remain private
  loader operations, never installed libc providers.
- `owned_pthread_alias_contract_reader.py` is the sole reader for its fixed 17
  public weak aliases, 15 internal providers, and the static `mq_notify`
  public `pthread_detach` relocation. Its retained copied-artifact records
  carry path, hash, and size; selected product modes remain sealed by the
  public ELF/product cohort rather than being invented by that reader. The
  attachment binds those byte identities to the selected cohort and discharges
  an ordinary import only if the exact selected static undefined row exists.
  It does not select the private provider spellings or close the general
  pthread family.

Each receipt must name the current selected source and product cohort. Their
status flags remain false; header, semantic, family, and public-support gates
are unchanged.

## Source-owned callable and CRT placements

The policy also selects a finite source-backed set of 108 frozen-project
callable identities. The exact names, artifacts, and metadata live in
`native-abi-selection.toml` under `source-owned-*`; this section records the
owner boundary that makes those finite lists meaningful. The retained source
ownership audit was navigation evidence only and is not an input to the
selection reader. Selection comes from the named current source roots. It does
not promote another spelling with a common prefix or an equal ELF value.

| Source-owner groups | Native root and selected placement |
| --- | --- |
| `source-owned-stdio-io-aliases`, `source-owned-stdio-aliases`, `source-owned-stdio-protected-boundaries`, `source-owned-wide-stdio-same-definition-aliases` (12) | `owned_stdio_extensions.rs`, `owned_static_stdio.rs`, and `owned_wide_stdio.rs` select static/shared providers. The existing `owned-stdio-alias-contract.md` remains the alias, override, and internal-call judge. `__uflow` and `__overflow` are direct `GLOBAL PROTECTED` bodies in both placements, so internal FILE operations do not preempt to an application definition. |
| `source-owned-locale-*`, `source-owned-ctype-locator-bodies`, `source-owned-float-locale-same-definition-aliases` (52) | The named locale leaves select static/shared providers. `owned-locale-alias-contract.md` remains the same-definition alias contract; source selects each listed alias before static oracle metadata is consulted. |
| `source-owned-integer-parse-*`, `source-owned-isoc99-scan-*`, `source-owned-stat-version-wrappers`, `source-owned-setjmp-*`, `source-owned-qsort-context-body`, `source-owned-long-double-*`, `source-owned-sysv-*`, `source-owned-xpg-*`, `source-owned-getopt-*` (30) | Their named parser, stdio, callback, math, signal, error, basename, and getopt roots select static/shared callable providers. `__qsort_r` is the direct context body; `qsort_r` is its distinct weak same-definition alias. The static helper is hidden while the owned dynamic feature retains the selected shared exposure. Their C signatures and behavioral receipts remain component requirements. |
| `source-owned-exit-and-atfork-runtime`, `source-owned-auxv-observation-alias`, `source-owned-stack-check-fail`, `source-owned-pivot-root-syscall` (7) | Process lifecycle, auxv, compiler-failure, and kernel-admin roots select static/shared providers. `pivot_root` stays in its existing kernel-admin feature and capability/error contract. |
| `source-owned-crypt-private-helper-bodies` (5) | `crypt.rs` selects five direct private static/shared bodies. They are not aliases merely because some values coincide. `crypt_r` is a distinct weak wrapper of `__crypt_r`, outside this five-member group. |
| `source-owned-crt-libc-startup-boundary`, `source-owned-loader-libc-tls-boundary` (2) | `__libc_start_main` has distinct static and shared libc bodies; the five CRT undefined edges retain their independent startup proof. `__tls_get_addr` has distinct shared-libc and loader bodies and deliberately has no static-libc placement. |

For public source-selected functions with a static placement, the policy may use
`selected-native-oracle-function` only to obtain the static `FUNC` binding and
visibility after the source group has selected the exact name. Shared metadata
is the inherited frozen dynamic requirement unless source gives a narrower
placement such as the two protected stdio bodies. Candidate ELF never creates a
selection or determines a new normative alias relation. Private crypt bodies
and all CRT placements state their metadata explicitly.

The six audit exclusions `__crabc_runtime_v1`, `initstate`, `random`,
`setstate`, `srandom`, and `rust_eh_personality` are not in these source-owner
groups. This section also does not add the BSD random quartet, allocator
metadata, or Rust unwinder identities.

### Native CRT definition placements

The CRT groups select only definitions in the five real ET_REL artifacts; an
undefined edge is not converted into a definition obligation.

| Policy group | Exact placement and contract |
| --- | --- |
| `source-crt-linker-array-address-bridges` | Six `__crabc_{preinit,init,fini}_array_{start,end}_address` names are `FUNC GLOBAL HIDDEN` in `static-crt1.o`, `static-Scrt1.o`, `static-rcrt1.o`, `dynamic-crt1.o`, and `dynamic-Scrt1.o`. They bridge bounded linker-array addresses and are not installed C callables. |
| `source-crt-static-lifecycle-bodies` | `__crabc_x86_64_static_pie_start`, `__crabc_x86_64_executable_init`, and `__crabc_x86_64_executable_fini` are `FUNC GLOBAL DEFAULT` in `static-crt1.o` and `static-rcrt1.o`; the static CRT contract retains the ET_EXEC/ET_DYN startup split. |
| `source-crt-dynamic-lifecycle-bodies` | `__crabc_x86_64_dynamic_start`, `__crabc_x86_64_dynamic_executable_init`, and `__crabc_x86_64_dynamic_executable_fini` are `FUNC GLOBAL DEFAULT` in `static-Scrt1.o`, `dynamic-crt1.o`, and `dynamic-Scrt1.o`. |
| `source-crt-owned-handoff-accessor` | `__crabc_x86_64_owned_crt_handoff_value` is an exported `FUNC GLOBAL DEFAULT` in those same three dynamic-mode objects. It is distinct from the weak undefined `__crabc_x86_64_owned_crt_handoff` `OBJECT` transport edge. |
| `source-crt-raw-entry-symbol` | `_start` is `FUNC GLOBAL DEFAULT` in all five objects. It is the raw kernel/interpreter entry point, never a C-callable provider. |

## Project extensions and implementation visibility

The six installed addressable C11 atomic functions remain project extensions:
`atomic_flag_clear`, `atomic_flag_clear_explicit`,
`atomic_flag_test_and_set`, `atomic_flag_test_and_set_explicit`,
`atomic_signal_fence`, and `atomic_thread_fence`. Their exact declaration and
behavior evidence remains with the atomic component.

Native C `tgkill(int, int, int)` is selected as the existing frozen project's
thread-signal extension. It preserves the caller's TGID and TID, signal zero,
and C return/errno behavior. Its declaration belongs to the native GNU/BSD
`signal.h` surface. The safe Rust same-process `signal::kill_thread` operation
is narrower and does not replace this C boundary. Musl has no `tgkill` export:
a differential workload must identify a separate oracle adapter over
`syscall(SYS_tgkill)` and reuse the unchanged installed-header workload object.
The declaration, provider, exact metadata, and required ratchet addition must
land together; a raw musl comparison still records it as an extra identity.

The bundled C allocator's upstream API is not an installed crabc API.
`libc/src/allocator_mimalloc.rs` owns the public allocation wrappers and states
that backend `mi_*` names are private. The exact 424-name
`libc/src/c_abi/x86_64/owned_mimalloc_hidden.list` is owned by the fixed-C
producer account in
[`owned_mimalloc_producer_metadata.py`](owned_mimalloc_producer_metadata.py).
That account binds the selected static and dynamic products, their provenance
files, the dynamic manifest, and every static/shared type, binding, visibility,
and applicable size/alignment field before the selection reader observes a
candidate row. Data and TLS symbol alignment is the C source minimum in both
placements; the producer's static-section over-alignment remains a separate
measurement. The shared builder still localizes the names with its exact
version script. The [visibility component](owned-mimalloc-export-visibility.md)
requires their absence from dynsym, their LOCAL shared symtab definitions, and
preserved static providers and public allocation metadata. This fixed-C
attachment supplies metadata only for that exact list. It neither selects an
unrelated private owner. The separate native C allocator-boundary receipt can
prove only its seven exact static Rust-root imports; allocator semantics,
lifecycle beyond that bounded receipt, family completion, promotion, and
public support remain open.

The private feature witnesses have actual evidence consumers. Crypt helper
names, private musl alias targets, process/runtime seams, compiler helpers,
and `rust_eh_personality` also require their own physical visibility and
consumer decisions. They do not inherit the allocator decision. Compiler
helpers in the installed builtins archive remain a consumer link-closure
contract even if a shared export is eventually removed. An implementation
classification by itself neither approves a public export nor authorizes
removal of a concrete consumer's provider.

The finite `owned-compiler-helper-archive` group reads
[`builtins/x86_64-helper-contract.toml`](../../builtins/x86_64-helper-contract.toml):
its exact 23 Rust `extern "C"` definitions are unversioned `FUNC GLOBAL
DEFAULT` in the distinct `static-builtins` and `dynamic-builtins` archive
placements. When the helper reader has replayed the same selected products,
the selection attachment also consumes its exact source-bound `shared_libc`
projection: each of those names is `FUNC LOCAL DEFAULT` in the selected
`candidate-shared` `.symtab`, with no defining `.dynsym` row. That private
copy is bound to the source's one `--exclude-libs=libcrabc-builtins.a` policy;
it is neither inferred from an archive definition nor treated as a public
export. The component reader keeps its own `shared_placement_selected` flag
false because it only supplies evidence; this selection join records the
separate owner decision. The ordinary `__popcountdi2` import still requires
its exact fresh consumer receipt, and semantic/family/public-support flags
remain false.

## Data objects and remaining proof

The public object manifest must retain exact native size, kind, binding,
visibility, mutability/qualifiers, applicable declarations, and profile
placement. Pointer objects describe the pointer's storage, not the pointee's
size. The current shared object requirements include these distinct owners:

| Objects | Native storage and owner |
| --- | --- |
| `__environ`, `environ`, `_environ`, `___environ` | One eight-byte environment pointer plus its weak same-storage aliases, owned by `environment_runtime.rs`. |
| `__progname`, `__progname_full`, `program_invocation_name`, `program_invocation_short_name`, `optarg` | Eight-byte pointers from `process_globals.rs` and `libc/src/getopt_exports.rs`; program-name aliases share the named canonical storage. |
| `optind`, `opterr`, `optopt`, `__optpos`, `__optreset`, `optreset` | Four-byte option-parser integers; `optreset` is the weak alias of `__optreset`. |
| `__timezone`, `timezone`, `__daylight`, `daylight`, `__tzname`, `tzname` | Eight-byte long, four-byte integer, and sixteen-byte pointer array, with exact aliases in `owned_timezone.rs`. |
| `__signgam`, `signgam` | Four-byte shared mathematical result state selected by `math_special.rs`. |
| `stdin`, `stdout`, `stderr` | Eight-byte stream pointers owned by `owned_static_stdio.rs` in owned products. |
| `h_errno`, `getdate_err` | Four-byte objects from `h_errno.rs` and `owned_getdate.rs`. A location-function header macro does not make the exported `h_errno` object TLS. |
| `in6addr_any`, `in6addr_loopback` | Distinct immutable sixteen-byte, four-byte-aligned IPv6 records from their named leaves. |
| `_ns_flagdata` | Immutable 128-byte table of sixteen two-integer records in `ns_flagdata.rs`. |
| `__stack_chk_guard` | Eight-byte compiler-guard object, owned separately by `static_tls.rs` in the owned static runtime and `dynamic_main_thread_runtime_v1_lifecycle.rs` in the owned shared runtime. Each bootstrap publishes its initialized FS+40 guard in the addressable object. |
| `_dl_debug_addr` | Eight-byte shared-only debugger pointer; no static-libc placement is selected. |

The addressable `__stack_chk_guard` object is selected in both owned libc
placements, preserving pinned musl's storage contract. The static bootstrap
publishes its existing `AT_RANDOM`-derived value after successful FS-base
installation and before preinit or worker entry. It does not introduce a
second seed or a reseeding entry point. The standalone private TLS archive
retains its narrower FS-relative guard contract. Static ordinary-link,
startup, and worker evidence remains distinct from shared metadata evidence.

Other static-only names likewise need exact owner accounting rather than
automatic public promotion or silent exclusion. Private runtime imports need
their authorized producer/consumer, type/binding/visibility, relocation
contract, descriptor version/layout where applicable, and lifecycle owner.
Header-provided names require compiler-derived profile and linker-name proof;
the existing header ABI workflow already extracts `VarDecl` facts, but a
summary digest alone is not an enumerable public-data declaration manifest.

The BSD random quartet (`initstate`, `random`, `setstate`, `srandom`) remains
unresolved under the pending user policy decision. Do not invent a PRNG core
or turn an absent provider into a structural exclusion.

Final selection validation must bind one clean integrated policy/collector
revision, prepared/materialized product identities, complete ELF observations,
header/provider contracts, and the owning component evidence. Keep historical
collector and product-build identities explicit. Missing selection, unresolved
placement, changed metadata, unauthorized visibility, absent ordinary
extraction, or incomplete family evidence prevents closure. Run the dynamic
ratchet independently; neither check promotes a family or the platform.
