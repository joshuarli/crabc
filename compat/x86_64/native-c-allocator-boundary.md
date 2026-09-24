# Installed C allocator boundary

`native_c_allocator_boundary.py` joins the selected `libmimalloc-sys` 0.1.49
implementation (C mimalloc v3.3.2) to the installed x86 allocator wrappers. It
consumes supplied static and dynamic products; it never builds a product or
selects a general allocator policy.

The fixed-C producer account remains the authority for the exact C member and
the seven Rust-root imports. This component adds the consumer side: the static
Rust members import exactly `_mi_auto_process_init`, `_mi_auto_process_done`,
`mi_free`, `mi_malloc_aligned`, `mi_realloc_aligned`, `mi_usable_size`, and
`mi_zalloc`; the same final shared C definitions remain local. Its source
check binds the C ABI wrappers for `malloc`, `calloc`, `realloc`,
`reallocarray`, `free`, `aligned_alloc`, `posix_memalign`, `memalign`,
`valloc`, and `malloc_usable_size`, and binds the process initializer/finalizer
to the selected x86 root.

The same producer account authenticates the selected C static member. This
reader separately records its finite inverse dependency roster: 27 `NOTYPE
GLOBAL DEFAULT UND` imports from that one current archive member to selected
public Rust libc providers, each defined by exactly one Rust archive member
(the installed archive emits one member per Rust module). Each row is reconstructed from the current static
archive and shared libc facts, including the exact `GLOBAL` or `WEAK` provider
binding in static `.symtab` and shared `.dynsym`/`.symtab`. The static ET_EXEC
and static-PIE startup links must each select both that C member and the static
Rust provider member in their LLD map and trace sidecars. The same installed-header object
is also linked through the existing dynamic PIE and non-PIE roots, while the
shared provider rows bind that selected shared product. This proves a finite
ordinary link-availability boundary; it does not claim that every imported API
was executed by the startup probe.

The source provenance remains `libmimalloc-sys` 0.1.49 carrying C mimalloc
v3.3.2 and its pinned 32-source `static.c` closure. It is distinct from the
fixed v3.5.0 Rust-port oracle.

`malloc` is the only weak wrapper. `calloc`, `realloc`, `reallocarray`,
`free`, `aligned_alloc`, `posix_memalign`, `memalign`, `valloc`, and
`malloc_usable_size` are exact global definitions. The reader checks each
Rust `extern "C"` declaration head, its no-mangle/weak state, and its selected
backend or wrapper call; a name match alone cannot admit a different C ABI.
It checks those same ten definition rows, each in the one static archive
member that defines it, and in both `.dynsym` and `.symtab` of the selected shared libc. Every
row must be a defined, unversioned `FUNC DEFAULT` definition with its exact
weak/global binding.

The lifecycle source check keeps `_mi_auto_process_init` and
`_mi_auto_process_done` private. It binds their zero-argument `extern "C"`
declarations, the corresponding zero-argument callbacks, and the typed
`unsafe extern "C" fn()` `.init_array`/`.fini_array` entries. It does not make
either upstream name a public C ABI symbol.

The source check binds the C lifecycle, allocation, and observation modules
to their existing feature gates together with `not(feature =
"native-mimalloc-shadow")`. The default-off native provider therefore leaves
this C product boundary available without allowing both providers into the
same selected module. `source_resolution` still requires all runtime source
blobs to equal the supplied product revision.

The collector runs only two existing installed-product workloads:

- `run_owned_mimalloc_startup_errno.sh --static-sysroot STATIC DYNAMIC` keeps
  static ET_EXEC/static PIE and dynamic PIE/non-PIE kernel/direct entries. The
  retained link receipts prove the exact product and CRT inputs; the probe
  checks preinit, user constructor, main allocation and final errno. Its one
  installed-header `workload.o` is the exact link input for every candidate
  static/static-PIE and dynamic mode. The two musl startup executables retain
  their own identities: their source intentionally defines
  `CRABC_MIMALLOC_STARTUP_ERRNO_ORACLE` so pinned musl explicitly invokes the
  callbacks it does not dispatch from this fixture's preinit array. This is a
  behavioral oracle comparison, not a false same-object claim for that
  macro-specific oracle path.
- `run_owned_c_allocation_interposition.sh DYNAMIC` reuses one installed-header
  object against musl and candidate PIE/non-PIE kernel/direct roots. It checks
  `asprintf`, passwd cleanup, and AIO list state against executable
  `malloc`/`realloc`/`free` interposition. These candidate links deliberately
  request `-rdynamic`; their sealed linker commands must contain exactly the
  resulting `--export-dynamic` flag. Ordinary candidate links retain the
  no-export command contract. Replay derives those false/true expectations
  from the startup and interposition workload roles, rather than accepting a
  report-provided flag as policy.

Both runner work directories, their terminal streams, selected executable
roots, and owned link receipts are sealed before and after replay. The product
source epoch is retained separately from the collector source: a later reader
requires the wrapper/lifecycle source blobs to equal that product revision,
the static preparation source to equal the ELF-facts collector source, and the
dynamic materialization source hash to equal the same content hash. It also
compares the supplied static tree with the preparation receipt's primary tree.
The component records each link's format and product-manifest digest, while
the supplied-product account records the physical product location. This lets
the retained host reader compare one container collection with its host path
without weakening either product-byte check.
This permits an immutable prior product epoch while rejecting a mixed static,
dynamic, or facts epoch; it does not call a historical collector result a
current-source proof.

This is a bounded C-wrapper/lifecycle receipt. It does not prove allocator
family completion, Rust-port promotion, broad allocation behavior, public C
API semantics, or public x86 support.
