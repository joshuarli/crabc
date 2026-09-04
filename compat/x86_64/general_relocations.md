# General initial relocation and symbol ownership

`ldso/src/x86_64_general_relocation.rs` is the sole relocation transaction
for the arbitrary admitted initial graph, with or without initial TLS.
`./scripts/dev-x86_64.sh general-relocations` is its pinned native Docker gate. This is an
initial-loader component, not runtime load/unload or installed shared-product
closure. RuntimeV1 remains 72 bytes and OwnedCrtHandoffV1 remains 32 bytes;
the canonical graph, mapping order, retained TLS IDs and lifetime do not change.
Public support and the frozen AArch64 223/26 baseline remain unchanged.

## Source and ABI contract

The implementation follows musl 1.2.6 revision
`9fa28ece75d8a2191de7c5bb53bed224c5947417`, under its MIT license:

| Pinned source | General owner |
| --- | --- |
| `ldso/dynlink.c::load_deps`, `find_sym2` | `InitialSymbolScope::from_graph`, `lookup` |
| `ldso/dynlink.c::do_relocs` / `REL_COPY` | `copy_relocation`, final copy phase |
| `ldso/dynlink.c::__dls3` library-before-main relocation | `relocate_initial_graph` |
| `arch/x86_64/reloc.h` and `do_relocs` TLS cases | `word_value`, `tls_coordinates` |
| Existing Variant-II initial layout | `GeneralInitialTlsState::plan_initial_tls`, unchanged |

The [pinned musl source](https://git.musl-libc.org/cgit/musl/tree/ldso/dynlink.c?h=v1.2.6)
selects COPY lookup after the main executable and copies the **executable**
symbol's `st_size`, not the provider symbol's size. The implementation retains
that rule even when provider sizes differ, but validates both the provider's
declared extent and the entire actual read against readable `PT_LOAD` memory.
It does not demand equal sizes or silently truncate to the provider's size.
Initialized and zero-filled readable source memory are admissible.

The [ELF symbol-visibility contract](https://gabi.xinuos.com/elf/05-symtab.html#symbol-visibility)
requires a defining object's references to its protected symbol to bind
locally, while other objects use normal global scope. `lookup` enforces that
rule for ordinary and TLS references. Local/hidden/internal definitions cannot
satisfy another object's imports. Global and weak definitions follow the
main-first breadth-first dependency order; the first weak definition wins
over a later strong one, as in musl. This search view is derived from graph
edges and does not reorder mapping ownership or TLS IDs.

## Admitted operations and preflight

The general owner admits NONE, RELATIVE, 64, GLOB_DAT, JUMP_SLOT and COPY
RELA forms plus existing RELR. Initial-TLS roots also admit DTPMOD64,
DTPOFF64 and TPOFF64. Static-link GOTTPOFF/TPOFF32 and runtime TLSDESC remain
unsupported; this slice does not add GNU-unique/common/versioned/IFUNC scope.
Undefined weak ordinary references resolve to zero; TLS references require
a real retained module, including valid symbol type and full symbol extent.

All objects are preflighted before any relocation writes. Each object's
complete destination spans must be disjoint and writable and must not
overlap its program headers, symbol/string tables, or relocation tables.
Word destinations retain the existing eight-byte alignment rule. COPY is a
byte operation and admits unaligned storage. It requires a main-image
OBJECT definition at the destination, zero addend, an exported non-protected
DSO OBJECT source, and checked source/destination ranges. Undefined, local,
hidden, protected, TLS, function, unmapped, overflowing, or cross-range COPY
sources fail before writes. DSO COPY and COPY in PLT relocation tables fail.
Ordinary typed object/function imports cannot resolve to the opposite type;
their full definition extents must fit the owning mapping. These explicit
range/type/overflow rejections are hardening constraints over musl's less
defensive ELF reads; no recovery or ambient loader fallback is added.

Libraries receive ordinary relocations first, main next, and COPY last.
This preserves main interposition addresses in relocated provider data:
a provider's pointer to the copied object's field already names the main's
canonical destination when its bytes are copied. ELF metadata remains
immutable between preflight and application. Segment protection, RELRO,
TLS image copying/FS installation, and callbacks follow this transaction.

TLS calculations use the selected provider's retained module:
`DTPOFF64 = st_value + addend`,
`TPOFF64 = st_value + addend - tls_offset_below_tp`.
The symbol extent and adjusted offset must fit that module, arithmetic is
checked, and the module ID/placement must exist. Symbol index zero uses the
requesting module. The one-past-module offset remains admitted, matching the
existing resolver's address-only boundary; dereferencing it is not allowed.
`DF_STATIC_TLS` marks a consumer requirement, not provider ownership. An IE
consumer may own no PT_TLS and refer to an initially mapped GD provider;
the relocation itself validates the requirement even if the flag is absent.
No runtime-loaded module, worker, or DTV-growth policy is implied.

General owned CRT admission now accepts absent main preinit/init/fini array
tag pairs. Present arrays retain their bounds/alignment validation and a
half-pair fails parsing. The actual constructor-free consumer proves this;
legacy private CRT modes retain their strict original shape.

## Native evidence and known oracle difference

The gate builds four cold owned startup combinations: PIC/ordinary PIE main
addressing crossed with GD/IE dependencies. Each runs the six existing
return/exit/_Exit lifecycle cases, startup rejection cases, and single-FS
ownership trace. Ordinary PIE exercises `environ` COPY. Candidate linking
does not ignore unresolved executable symbols.
Before implementation, the same ordinary-PIE lifecycle application against
baseline `cf7fe88f` exited 127 with `reloc` and no callback output because its
real `environ` COPY relocation was rejected. The default standalone lifecycle
runner now uses PIE; PIC is an explicit regression profile.

The dedicated ordinary-PIE application additionally proves pointer-bearing
COPY data after R_X86_64_64 provider fixups, byte data, breadth-first scope,
first-weak/strong order reversal, undefined weak null, and constructor-free
main admission. A PT_TLS-free IE DSO and GD provider share 4096-aligned
initialized TLS and 64-aligned TBSS, bind main TLS and preemptible definitions,
and compare/mutate the same addresses. Provider size 16/80 against main COPY
size 64 and removal of the consumer STATIC_TLS flag remain musl differentials.
Twenty-one ELF mutations must exit 127 before any FS installation or callback.
Unit tests additionally prove no earlier graph writes on a later failure,
byte alignment, overlapping/metadata writes, exact symbol scopes and signed
TLS bounds. The negative tracer now kills/reaps a fatal stopped child rather
than suppressing its fault forever; a trap regression checks that cleanup.

One controlled case deliberately differs from pinned musl: main defines
`protected_tls = 99`, while the GD provider defines protected TLS initialized
to 17. Its ELF retains named DTPMOD64/DTPOFF64 relocations. Musl `do_relocs`
special-cases STB_LOCAL but otherwise calls `find_sym`, without a protected
visibility check, so the provider observes main's 99 and its constructor
exits 81. The candidate enforces protected local binding and returns 33.
The gate records symbol visibility, relocation evidence, both statuses and
outputs separately; this is an ABI-specific pass and a musl difference,
**not parity**. Ordinary differential cases have no protected-name collision.

Remaining loader/product conditions include installed shared-runtime and
sealed-driver closure, remaining frozen relocation/symbol-version policy,
general runtime mapping/unload, reference counts, worker TLS/DTV growth,
loader synchronization/fork/reentrancy, and full libc runtime integration.
