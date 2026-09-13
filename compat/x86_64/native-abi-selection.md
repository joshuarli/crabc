# Native x86 ABI selection and ownership

The native ABI contract selects observable C interfaces and their owners. An
ELF inventory records what an artifact contains; the dynamic ratchet prevents
regression against a reviewed observation. Neither chooses the supported ABI.
This contract supplies the ownership rules for the complete callable/data
manifest required by `x86-64.md`, under `libc.c-abi-compat` and
`compat.abi-differential`. The complete executable selection manifest and its
provider proof remain required; this document does not establish their closure.

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
