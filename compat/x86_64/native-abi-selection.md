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
type/linker-spelling agreement where a pinned declaration is comparable.  Its
sole candidate-only native extension is the existing exact `tgkill` record.
It does not infer language linkage, select a provider, use macro or GCC
fallback records as declarations, prove runtime behavior, or close any family.

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
`libc/src/c_abi/x86_64/owned_mimalloc_hidden.list` selects non-public shared
visibility for 172 upstream-header and 252 non-header definitions. The shared
builder localizes those definitions with an exact version script; it preserves
the static provider graph, public allocation aliases, interposition, and
allocator lifecycle. The [visibility component](owned-mimalloc-export-visibility.md)
requires their absence from dynsym, their LOCAL shared symtab definitions,
and preserved static providers and surviving public metadata. This placement
contract supplies the allocator portion of the complete selection manifest;
it does not select visibility for any other runtime owner.

The private feature witnesses have actual evidence consumers. Crypt helper
names, private musl alias targets, process/runtime seams, compiler helpers,
and `rust_eh_personality` also require their own physical visibility and
consumer decisions. They do not inherit the allocator decision. Compiler
helpers in the installed builtins archive remain a consumer link-closure
contract even if a shared export is eventually removed. An implementation
classification by itself neither approves a public export nor authorizes
removal of a concrete consumer's provider.

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
