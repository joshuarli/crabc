#![allow(unexpected_cfgs)]
#![cfg_attr(crabc_general_initial_graph, allow(dead_code))]

//! A bounded Linux/x86-64 initial-interpreter graph.
//!
//! This is intentionally a separately-built bootstrap artifact, not the
//! `crabc-ldso` public target. It is compiled through the private
//! `x86_64-initial-interpreter` feature only, which proves the earliest x86-64 dynamic-loader
//! transaction against one ordinary shape: a kernel-mapped PIE, one direct
//! DSO, and that DSO's direct DSO.  `_start` performs *this interpreter's*
//! `R_X86_64_RELATIVE` relocations in assembly before entering Rust.  Rust
//! then discovers the two `DT_NEEDED` edges through absolute `DT_RUNPATH`
//! directories, maps the two ET_DYN images, and processes RELATIVE,
//! GLOB_DAT, JUMP_SLOT, and the GNU dynamic-TLS DTPMOD64/DTPOFF64 ELF64 RELA
//! records plus one bounded packed `DT_RELR` stream in the leaf dependency.
//! The TLS sibling graphs first lay out every initial `PT_TLS` image below an
//! x86 Variant-II TP, installs the minimal `%fs:0` self / `%fs:8` DTV prefix,
//! and resolves `__tls_get_addr`; the original no-TLS graph remains a
//! deliberately independent fixture. Once all mappings are relocated and
//! initial TLS is materialized, it seals every present `PT_GNU_RELRO` range
//! and runs the two dependency `DT_INIT_ARRAY` lists in leaf-before-mid order.
//!
//! Musl 1.2.6 oracle: `ldso/dynlink.c` initial-TLS layout and `do_relocs`,
//! `src/thread/__tls_get_addr.c`, and `arch/x86_64/reloc.h`. The narrow
//! relocation set and all exclusions are
//! deliberate evidence boundaries: the interpreter's own pre-Rust bootstrap
//! remains `DT_RELA`-only; the GNU-Dynamic initial-TLS slice accepts only
//! DTPMOD64/DTPOFF64 plus `__tls_get_addr`. Its cfg-isolated initial-exec
//! sibling additionally admits exactly one leaf-local `R_X86_64_TPOFF64`
//! definition under `DF_STATIC_TLS`; both reject TLSDESC, DTV growth,
//! `DT_INIT`, main-image constructor dispatch (that
//! remains CRT-owned), preload/environment search, public `dl*`, audit,
//! secure-exec filtering, symbolic versioning, or a general dependency graph.
//! One cfg-isolated no-TLS sibling publishes only a callback-free copied
//! snapshot/address/information record over this exact immutable graph. A
//! second no-TLS sibling adds loader-owned reference handles and scoped symbol
//! lookup for objects already in that graph. Its separately selected bounded
//! runtime sibling can add exactly one no-TLS DSO from the main image's fixed
//! absolute RUNPATH when every dependency is already retained. That one DSO
//! may carry a validated legacy `DT_INIT` entry followed by its bounded init
//! array and one validated-but-inert legacy `DT_FINI` entry, then make
//! no-mapping `RTLD_NOLOAD` acquisitions of its appended identity. It still
//! cannot promote, finalize, or unload an object, and neither sibling
//! publishes borrowed link-map state or public dlfcn entry points.

#![allow(clippy::missing_safety_doc)]

#[cfg(not(test))]
use core::arch::global_asm;
use core::ffi::c_void;
#[cfg(crabc_general_initial_graph)]
#[path = "x86_64_initial_graph_state.rs"]
mod x86_64_initial_graph_state;
#[cfg(crabc_general_initial_graph)]
#[path = "x86_64_general_initial_loader_state.rs"]
mod x86_64_general_initial_loader_state;
#[cfg(crabc_general_initial_lifecycle)]
#[path = "x86_64_general_initial_lifecycle.rs"]
mod x86_64_general_initial_lifecycle;
#[cfg(crabc_general_initial_graph)]
#[path = "x86_64_general_initial_graph.rs"]
mod x86_64_general_initial_graph;
#[cfg(crabc_general_initial_graph)]
#[path = "x86_64_general_relocation.rs"]
mod x86_64_general_relocation;
#[cfg(any(
    crabc_loader_libc_tls_runtime_v1,
    crabc_general_initial_tls_materialization_v1
))]
#[path = "x86_64_initial_tls_registry.rs"]
mod x86_64_initial_tls_registry;
#[cfg(crabc_general_initial_tls_materialization_v1)]
#[path = "x86_64_general_initial_tls_state.rs"]
mod x86_64_general_initial_tls_state;
#[cfg(feature = "x86_64-owned-dynamic-runtime")]
#[path = "x86_64_initial_worker_tls.rs"]
mod x86_64_initial_worker_tls;
#[cfg(crabc_general_initial_graph)]
use x86_64_initial_graph_state::ObjectIdentity;
#[cfg(any(crabc_fixed_graph_introspection, crabc_fixed_graph_dlfcn))]
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
#[cfg(crabc_loader_libc_tls_runtime_v1)]
use core::sync::atomic::{AtomicU8, Ordering};

// The RuntimeV1 record is addressed only by the loader's exact relocation
// exception below; it is never a dynamic-linker lookup/export.  Keep the
// backing ELF symbol out of `.dynsym` even though `no_mangle` gives the Rust
// static a stable assembler name for that internal address calculation.
#[cfg(all(
    not(test),
    any(
        crabc_loader_libc_tls_runtime_v1,
        crabc_general_loader_libc_tls_runtime_v1
    )
))]
global_asm!(".hidden __crabc_x86_64_loader_tls_runtime_v1");

#[cfg(all(
    crabc_fixed_graph_introspection,
    any(crabc_initial_tls_graph, crabc_initial_exec_tls_graph, crabc_owned_crt_handoff)
))]
compile_error!("fixed-graph introspection is an independent no-TLS/owned-CRT sibling");

#[cfg(all(
    crabc_fixed_graph_dlfcn,
    any(
        crabc_fixed_graph_introspection,
        crabc_initial_tls_graph,
        crabc_initial_exec_tls_graph,
        crabc_owned_crt_handoff
    )
))]
compile_error!("fixed-graph dlfcn is an independent no-TLS/owned-CRT sibling");

#[cfg(all(crabc_bounded_runtime_dlopen, not(crabc_fixed_graph_dlfcn)))]
compile_error!("bounded runtime dlopen requires the fixed-graph dlfcn record sibling");

// The general initial-TLS materialization package is an x86-private extension
// of the arbitrary initial graph, not another fixed graph or a RuntimeV1
// descriptor producer.  Keeping the cfg pair explicit makes accidental
// admission through the older no-TLS source root fail at compile time.
#[cfg(all(
    crabc_general_initial_tls_materialization_v1,
    not(crabc_general_initial_graph)
))]
compile_error!("general initial TLS materialization requires the general initial graph");

#[cfg(all(
    crabc_general_initial_tls_materialization_v1,
    any(
        crabc_initial_tls_graph,
        crabc_initial_exec_tls_graph,
        crabc_owned_crt_handoff,
        crabc_fixed_graph_introspection,
        crabc_fixed_graph_dlfcn,
        crabc_bounded_runtime_dlopen,
        crabc_loader_libc_tls_runtime_v1
    )
))]
compile_error!("general initial TLS materialization is separate from fixed RuntimeV1 and lifecycle siblings");

// The general RuntimeV1 wire is an explicit third sibling. It needs the
// arbitrary graph and its generation-one TLS state together, and cannot share
// the fixed RuntimeV1's post-ARCH_SET_FS publication hole or any fixed-graph
// lifecycle/dlfcn state.
#[cfg(all(
    crabc_general_loader_libc_tls_runtime_v1,
    not(crabc_general_initial_graph)
))]
compile_error!("general loader/libc TLS RuntimeV1 requires the general initial graph");

#[cfg(all(
    crabc_general_loader_libc_tls_runtime_v1,
    not(crabc_general_initial_tls_materialization_v1)
))]
compile_error!("general loader/libc TLS RuntimeV1 requires general initial TLS materialization");

#[cfg(all(
    crabc_general_loader_libc_tls_runtime_v1,
    any(
        crabc_initial_tls_graph,
        crabc_initial_exec_tls_graph,
        crabc_owned_crt_handoff,
        crabc_fixed_graph_introspection,
        crabc_fixed_graph_dlfcn,
        crabc_bounded_runtime_dlopen,
        crabc_loader_libc_tls_runtime_v1
    )
))]
compile_error!("general loader/libc TLS RuntimeV1 is disjoint from fixed RuntimeV1, CRT, and dlfcn siblings");

// The dynamic-main-thread bridge is a fourth, explicitly dependent general
// RuntimeV1 cfg. It admits one Rust-produced Scrt1.o shape and one
// main-resident attachment before libc startup; it does not reuse the fixed
// owned-CRT graph. With the general lifecycle feature it reuses the record
// layout to authenticate the conventional rdx finalizer and defer callbacks.
#[cfg(all(
    crabc_dynamic_main_thread_runtime_v1,
    not(crabc_general_loader_libc_tls_runtime_v1)
))]
compile_error!("dynamic main-thread RuntimeV1 requires the general RuntimeV1 descriptor");

#[cfg(all(
    crabc_dynamic_main_thread_runtime_v1,
    any(
        crabc_initial_tls_graph,
        crabc_initial_exec_tls_graph,
        crabc_owned_crt_handoff,
        crabc_fixed_graph_introspection,
        crabc_fixed_graph_dlfcn,
        crabc_bounded_runtime_dlopen,
        crabc_loader_libc_tls_runtime_v1
    )
))]
compile_error!("dynamic main-thread RuntimeV1 is disjoint from fixed graph and owned-CRT siblings");

// The first loader/libc RuntimeV1 wire is intentionally an initial-TLS
// sibling. It must not silently attach to the older no-TLS graph, the one
// initial-exec exception, an owned-CRT fixture, or the general non-TLS graph.
// Those packages have different ownership boundaries and cannot supply this
// descriptor's loader-owned Variant-II DTV invariants.
#[cfg(all(crabc_loader_libc_tls_runtime_v1, not(crabc_initial_tls_graph)))]
compile_error!("loader/libc TLS RuntimeV1 requires the GNU-Dynamic initial-TLS sibling");

#[cfg(all(
    crabc_loader_libc_tls_runtime_v1,
    any(
        crabc_initial_exec_tls_graph,
        crabc_owned_crt_handoff,
        crabc_fixed_graph_introspection,
        crabc_fixed_graph_dlfcn,
        crabc_general_initial_graph
    )
))]
compile_error!("loader/libc TLS RuntimeV1 is a separate initial-TLS handoff artifact");

const AT_PHDR: u64 = 3;
const AT_PHNUM: u64 = 5;
const AT_ENTRY: u64 = 9;
const AT_NULL: u64 = 0;

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_PHDR: u32 = 6;
const PT_TLS: u32 = 7;
const PT_GNU_RELRO: u32 = 0x6474_e552;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;

const DT_NULL: i64 = 0;
const DT_NEEDED: i64 = 1;
const DT_PLTRELSZ: i64 = 2;
const DT_HASH: i64 = 4;
const DT_STRTAB: i64 = 5;
const DT_SYMTAB: i64 = 6;
const DT_RELA: i64 = 7;
const DT_RELASZ: i64 = 8;
const DT_RELAENT: i64 = 9;
const DT_STRSZ: i64 = 10;
const DT_SYMENT: i64 = 11;
const DT_INIT: i64 = 12;
const DT_FINI: i64 = 13;
const DT_RPATH: i64 = 15;
const DT_SYMBOLIC: i64 = 16;
const DT_REL: i64 = 17;
const DT_RELSZ: i64 = 18;
const DT_RELENT: i64 = 19;
const DT_PLTREL: i64 = 20;
const DT_TEXTREL: i64 = 22;
const DT_JMPREL: i64 = 23;
const DT_INIT_ARRAY: i64 = 25;
const DT_FINI_ARRAY: i64 = 26;
const DT_INIT_ARRAYSZ: i64 = 27;
const DT_FINI_ARRAYSZ: i64 = 28;
const DT_RUNPATH: i64 = 29;
const DT_FLAGS: i64 = 30;
const DT_PREINIT_ARRAY: i64 = 32;
const DT_PREINIT_ARRAYSZ: i64 = 33;
const DT_RELR: i64 = 36;
const DT_RELRSZ: i64 = 35;
const DT_RELRENT: i64 = 37;
const DT_GNU_HASH: i64 = 0x6fff_fef5;
const DT_VERSYM: i64 = 0x6fff_fff0;
const DT_VERDEF: i64 = 0x6fff_fffc;
const DT_VERDEFNUM: i64 = 0x6fff_fffd;
const DT_VERNEED: i64 = 0x6fff_fffe;
const DT_VERNEEDNUM: i64 = 0x6fff_ffff;
const DT_FLAGS_1: i64 = 0x6fff_fffb;

const DF_BIND_NOW: u64 = 0x8;
const DF_STATIC_TLS: u64 = 0x10;
const DF_1_NOW: u64 = 0x1;
const DF_1_PIE: u64 = 0x0800_0000;

const ELF64_RELA: u64 = 7;
const R_X86_64_GLOB_DAT: u32 = 6;
const R_X86_64_JUMP_SLOT: u32 = 7;
const R_X86_64_RELATIVE: u32 = 8;
const R_X86_64_DTPMOD64: u32 = 16;
const R_X86_64_DTPOFF64: u32 = 17;
const R_X86_64_TPOFF64: u32 = 18;
const R_X86_64_GOTTPOFF: u32 = 22;
const R_X86_64_TPOFF32: u32 = 23;
const R_X86_64_GOTPC32_TLSDESC: u32 = 34;
const R_X86_64_TLSDESC_CALL: u32 = 35;
const R_X86_64_TLSDESC: u32 = 36;

const SYS_WRITE: i64 = 1;
const SYS_CLOSE: i64 = 3;
const SYS_FSTAT: i64 = 5;
const SYS_MMAP: i64 = 9;
const SYS_MPROTECT: i64 = 10;
const SYS_MUNMAP: i64 = 11;
const SYS_ARCH_PRCTL: i64 = 158;
const SYS_OPENAT: i64 = 257;
const SYS_EXIT: i64 = 60;
const AT_FDCWD: i64 = -100;
const PROT_READ: i64 = 1;
const PROT_WRITE: i64 = 2;
const PROT_EXEC: i64 = 4;
const MAP_PRIVATE: i64 = 2;
const MAP_FIXED: i64 = 0x10;
const MAP_ANONYMOUS: i64 = 0x20;
const ARCH_SET_FS: i64 = 0x1002;
const PAGE: u64 = 4096;
// Linux 5.10 x86-64 `fstat=5` fills the same 144-byte LP64 `struct stat`
// whose signed `st_size` lives at byte offset 48 in the selected x86 C ABI.
// Keep this private byte storage here: this isolated bootstrap must validate
// a DSO file range before mapping it, without selecting the C ABI leaf.
const X86_64_STAT_BYTE_LEN: usize = 144;
const X86_64_STAT_SIZE_OFFSET: usize = 48;

const INITIAL_OBJECT_COUNT: usize = 3;
#[cfg(crabc_general_initial_graph)]
const MAX_OBJECTS: usize = x86_64_initial_graph_state::MAX_INITIAL_GRAPH_OBJECTS;
#[cfg(not(crabc_general_initial_graph))]
#[cfg(crabc_bounded_runtime_dlopen)]
const MAX_OBJECTS: usize = INITIAL_OBJECT_COUNT + 1;
#[cfg(not(crabc_general_initial_graph))]
#[cfg(not(crabc_bounded_runtime_dlopen))]
const MAX_OBJECTS: usize = INITIAL_OBJECT_COUNT;
const MAX_PHDRS: usize = 32;
#[cfg(crabc_general_initial_graph)]
const MAX_NEEDED: usize = x86_64_initial_graph_state::MAX_INITIAL_GRAPH_NEEDED;
#[cfg(not(crabc_general_initial_graph))]
const MAX_NEEDED: usize = 2;
const MAX_PATH: usize = 512;
// The general initial graph owns one startup-only dependency constructor
// transition, not a reusable DSO lifecycle. Keep each admitted dependency
// array small enough to preflight every relocated entry before the first
// callback and to retain the complete once-only dispatch plan on the initial
// stack without an allocator.
const MAX_GENERAL_INITIAL_DEPENDENCY_INIT_ARRAY_ENTRIES: usize = 16;
// The runtime mapper retains no allocator or general lifecycle owner. Keep
// every runtime array-shaped tag at the existing small constructor ceiling.
#[cfg(crabc_bounded_runtime_dlopen)]
const MAX_BOUNDED_RUNTIME_ARRAY_ENTRIES: usize = 16;
#[cfg(any(crabc_fixed_graph_introspection, crabc_fixed_graph_dlfcn))]
const FIXED_GRAPH_TEXT_CAPACITY: usize = 256;
// This private fixed graph has no allocation owner. Bound both packed-RELR
// records and relocation destinations before reads or writes: an otherwise
// empty bitmap record has no destination, so a destination-only cap would let
// a malformed table consume unbounded loader time. The valid main -> mid ->
// leaf graph is intentionally far below both ceilings.
const MAX_RELOCATION_TARGETS: usize = 512;
const ELF64_RELA_SIZE: usize = 24;
const ELF64_RELR_SIZE: usize = 8;
const ELF64_RELR_BITMAP_BITS: u64 = 63;
const MAX_RELR_ENTRIES: usize = 512;
const MAX_RELR_BYTE_LEN: usize = MAX_RELR_ENTRIES * ELF64_RELR_SIZE;
// The first initial-TLS graph deliberately carries only the musl-compatible
// non-pthread prefix used by GNU Dynamic TLS: `self` at `%fs:0` and the DTV
// pointer at `%fs:8`. The remaining bytes reserve the usual early TCB prefix
// (including the stack-canary slot) without claiming a full pthread TCB.
const TLS_TCB_PREFIX_SIZE: usize = 64;
const TLS_TCB_MODULE_SIZE_TABLE_OFFSET: usize = core::mem::size_of::<usize>() * 2;
const TLS_DTV_WORDS: usize = MAX_OBJECTS + 1;
const TLS_DTV_BYTE_LEN: usize = TLS_DTV_WORDS * core::mem::size_of::<usize>();
const TLS_MODULE_SIZE_TABLE_BYTE_LEN: usize = TLS_DTV_WORDS * core::mem::size_of::<usize>();

// The initial RuntimeV1 graph has the same fixed object and nonzero-DTV-slot
// capacity. This state is private to the loader and remains separate from
// libc's static TLS owner; a future general loader must replace it only with
// a real registry/DTV-growth lifecycle, not a larger constant.
#[cfg(crabc_loader_libc_tls_runtime_v1)]
type LoaderInitialTlsRegistry =
    x86_64_initial_tls_registry::InitialTlsRegistry<MAX_OBJECTS, MAX_OBJECTS>;
#[cfg(crabc_loader_libc_tls_runtime_v1)]
static mut INITIAL_TLS_RUNTIME_V1_REGISTRY: LoaderInitialTlsRegistry =
    LoaderInitialTlsRegistry::new();

// -------------------------------------------------------------------------
// Private loader/libc RuntimeV1 initial-TLS handoff
// -------------------------------------------------------------------------
//
// This record is deliberately smaller than a loader runtime. It carries only
// the already-materialized main-thread Variant-II coordinates for this one
// fixed initial graph. In particular, it has no registry mutation operation,
// allocator, new-thread initializer, DTV growth, old-DTV reclamation, or
// dlclose protocol. `generation == 1` means the initial population has been
// published once; it is not permission to grow the fixed DTV.
//
// The libc consumer has an independently spelled `repr(C)` mirror because
// ldso remains a standalone no_std interpreter. Keep every field and the
// exact 72-byte LP64 layout synchronized with
// `libc/src/c_abi/x86_64/loader_tls_runtime_v1.rs`.
#[cfg(crabc_loader_libc_tls_runtime_v1)]
const LOADER_TLS_RUNTIME_V1_MAGIC: u64 = if cfg!(crabc_loader_libc_tls_runtime_v1_bad_magic) {
    0
} else {
    0x4352_4142_435f_5451
};
#[cfg(crabc_loader_libc_tls_runtime_v1)]
const LOADER_TLS_RUNTIME_V1_VERSION: u32 = if cfg!(crabc_loader_libc_tls_runtime_v1_bad_version) {
    0
} else {
    1
};
#[cfg(crabc_loader_libc_tls_runtime_v1)]
const LOADER_TLS_RUNTIME_V1_PROCESS_MODE_DYNAMIC: u32 = if cfg!(crabc_loader_libc_tls_runtime_v1_bad_mode) {
    0
} else {
    2
};
#[cfg(crabc_loader_libc_tls_runtime_v1)]
const LOADER_TLS_RUNTIME_V1_OWNER_LDSO: u32 = if cfg!(crabc_loader_libc_tls_runtime_v1_bad_owner) {
    0
} else {
    1
};
#[cfg(crabc_loader_libc_tls_runtime_v1)]
const LOADER_TLS_RUNTIME_V1_GENERATION_INITIAL: u64 = if cfg!(crabc_loader_libc_tls_runtime_v1_bad_generation) {
    0
} else {
    1
};
#[cfg(crabc_loader_libc_tls_runtime_v1)]
const LOADER_TLS_RUNTIME_V1_STATE_UNPUBLISHED: u8 = 0;
#[cfg(crabc_loader_libc_tls_runtime_v1)]
const LOADER_TLS_RUNTIME_V1_STATE_PUBLISHING: u8 = 1;
#[cfg(crabc_loader_libc_tls_runtime_v1)]
const LOADER_TLS_RUNTIME_V1_STATE_READY: u8 = 2;

/// Loader-owned, private RuntimeV1 coordinates for one initial TLS graph.
///
/// The record's acquire/release `state` is part of the private wire: the
/// loader writes every coordinate while it is `PUBLISHING`, then makes them
/// visible with `READY`. A libc consumer must first validate `magic`,
/// `version`, `abi_size`, `process_mode`, `owner`, and `generation`; it may
/// only read the pointed-to TCB/DTV after that check succeeds. The record is
/// intentionally not an installed header declaration or a general dynamic
/// linker API.
#[cfg(crabc_loader_libc_tls_runtime_v1)]
#[repr(C)]
pub struct LoaderLibcTlsRuntimeV1 {
    magic: u64,
    version: u32,
    abi_size: u32,
    process_mode: u32,
    owner: u32,
    state: AtomicU8,
    reserved: [u8; 7],
    thread_pointer: *const u8,
    dtv: *const usize,
    dtv_words: usize,
    module_count: usize,
    generation: u64,
}

#[cfg(crabc_loader_libc_tls_runtime_v1)]
const _: () = assert!(core::mem::size_of::<LoaderLibcTlsRuntimeV1>() == 72);

/// The one private loader record imported weakly by the freestanding libc
/// consumer. The dynamic linker itself fills its coordinates only after
/// `ARCH_SET_FS` succeeds. Metadata-negative fixtures retain those valid
/// coordinates, so each required metadata check is independently observable.
/// The separate poisoned-DTV fixture has valid metadata but an unusable DTV
/// pointer, proving pointer validation remains before a DTV read.
#[cfg(crabc_loader_libc_tls_runtime_v1)]
#[used]
#[no_mangle]
pub static mut __crabc_x86_64_loader_tls_runtime_v1: LoaderLibcTlsRuntimeV1 =
    LoaderLibcTlsRuntimeV1 {
        magic: LOADER_TLS_RUNTIME_V1_MAGIC,
        version: LOADER_TLS_RUNTIME_V1_VERSION,
        abi_size: if cfg!(crabc_loader_libc_tls_runtime_v1_bad_abi_size) {
            0
        } else {
            core::mem::size_of::<LoaderLibcTlsRuntimeV1>() as u32
        },
        process_mode: LOADER_TLS_RUNTIME_V1_PROCESS_MODE_DYNAMIC,
        owner: LOADER_TLS_RUNTIME_V1_OWNER_LDSO,
        state: AtomicU8::new(LOADER_TLS_RUNTIME_V1_STATE_UNPUBLISHED),
        reserved: [0; 7],
        thread_pointer: core::ptr::null(),
        dtv: core::ptr::null(),
        dtv_words: 0,
        module_count: 0,
        generation: LOADER_TLS_RUNTIME_V1_GENERATION_INITIAL,
    };

/// The transient result of one successful initial TLS install.
///
/// The fixed RuntimeV1 fixture may use these coordinates to populate its
/// isolated wire.  The general-initial TLS state instead retains them only in
/// its private committed loader snapshot.  Neither use exposes a pthread,
/// RuntimeV1, or DTV-growth operation.
#[cfg_attr(
    not(any(
        crabc_loader_libc_tls_runtime_v1,
        crabc_general_initial_tls_materialization_v1
    )),
    allow(dead_code)
)]
#[derive(Copy, Clone)]
struct InstalledInitialTls {
    #[cfg_attr(not(crabc_general_initial_tls_materialization_v1), allow(dead_code))]
    mapping: *mut u8,
    #[cfg_attr(not(crabc_general_initial_tls_materialization_v1), allow(dead_code))]
    mapping_byte_len: usize,
    thread_pointer: *mut u8,
    dtv: *mut usize,
    dtv_words: usize,
    module_count: usize,
}
// Each Scrt1-admitting sibling accepts exactly one tiny Rust-Scrt1 lifecycle
// shape. This caps every executable array before the handoff without
// pretending to be a general constructor-array policy.
#[cfg(any(crabc_owned_crt_handoff, crabc_dynamic_main_thread_runtime_v1))]
const MAX_OWNED_CRT_MAIN_ARRAY_ENTRIES: usize = 16;

// The fixed owned-CRT sibling and general owned lifecycle composition share
// this record layout, not graph algorithms or state. Older fixed no-TLS and
// GNU-Dynamic-TLS direct-main artifacts retain their no-handoff boundary.
#[cfg(any(crabc_owned_crt_handoff, all(crabc_general_initial_lifecycle, crabc_dynamic_main_thread_runtime_v1)))]
const OWNED_CRT_HANDOFF_MAGIC: u64 = if cfg!(crabc_owned_crt_handoff_malformed) {
    0
} else {
    0x4352_4142_435f_4831
};
#[cfg(any(crabc_owned_crt_handoff, all(crabc_general_initial_lifecycle, crabc_dynamic_main_thread_runtime_v1)))]
const OWNED_CRT_HANDOFF_VERSION: u32 = 1;
#[cfg(crabc_owned_crt_handoff)]
const OWNED_CRT_STATE_UNPUBLISHED: u8 = 0;
#[cfg(crabc_owned_crt_handoff)]
const OWNED_CRT_STATE_READY: u8 = 1;
#[cfg(crabc_owned_crt_handoff)]
const OWNED_CRT_STATE_CONSTRUCTORS_COMPLETE: u8 = 2;
#[cfg(crabc_owned_crt_handoff)]
const OWNED_CRT_STATE_FINALIZED: u8 = 3;

#[cfg(any(crabc_owned_crt_handoff, all(crabc_general_initial_lifecycle, crabc_dynamic_main_thread_runtime_v1)))]
type OwnedCrtLifecycleHook = unsafe extern "C" fn();

/// Exact post-relocation wire consumed by the Rust-produced private Scrt1.o.
///
/// This data record authenticates the general composition's rdx address. It
/// is self-relocated before the interpreter enters Rust and sealed with this
/// interpreter's final RELRO transition before the executable can read it.
#[cfg(any(crabc_owned_crt_handoff, all(crabc_general_initial_lifecycle, crabc_dynamic_main_thread_runtime_v1)))]
#[repr(C)]
pub struct OwnedCrtHandoffV1 {
    magic: u64,
    version: u32,
    abi_size: u32,
    dependency_constructors: OwnedCrtLifecycleHook,
    process_fini: OwnedCrtLifecycleHook,
}

#[cfg(crabc_owned_crt_handoff)]
#[used]
#[no_mangle]
pub static __crabc_x86_64_owned_crt_handoff: OwnedCrtHandoffV1 = OwnedCrtHandoffV1 {
    magic: OWNED_CRT_HANDOFF_MAGIC,
    version: OWNED_CRT_HANDOFF_VERSION,
    abi_size: core::mem::size_of::<OwnedCrtHandoffV1>() as u32,
    dependency_constructors: owned_crt_dependency_constructors,
    process_fini: owned_crt_process_fini,
};

#[cfg(crabc_fixed_graph_introspection)]
const FIXED_GRAPH_INTROSPECTION_MAGIC: u64 = if cfg!(crabc_fixed_graph_introspection_malformed) {
    0
} else {
    0x4352_4142_435f_5849
};
#[cfg(crabc_fixed_graph_introspection)]
const FIXED_GRAPH_INTROSPECTION_VERSION: u32 = 1;

#[cfg(crabc_fixed_graph_dlfcn)]
const FIXED_GRAPH_DLFCN_MAGIC: u64 = if cfg!(crabc_fixed_graph_dlfcn_malformed) {
    0
} else {
    0x4352_4142_435f_5844
};
#[cfg(crabc_fixed_graph_dlfcn)]
const FIXED_GRAPH_DLFCN_VERSION: u32 = 1;
#[cfg(crabc_fixed_graph_dlfcn)]
const FIXED_GRAPH_RTLD_LAZY: i32 = 1;
#[cfg(crabc_fixed_graph_dlfcn)]
const FIXED_GRAPH_RTLD_NOW: i32 = 2;
#[cfg(crabc_fixed_graph_dlfcn)]
const FIXED_GRAPH_RTLD_NOLOAD: i32 = 4;
#[cfg(crabc_fixed_graph_dlfcn)]
const FIXED_GRAPH_RTLD_GLOBAL: i32 = 0x100;
#[cfg(crabc_fixed_graph_dlfcn)]
const FIXED_GRAPH_RTLD_NODELETE: i32 = 4096;
#[cfg(all(crabc_fixed_graph_dlfcn, crabc_bounded_runtime_dlopen))]
const FIXED_GRAPH_ALLOWED_OPEN_FLAGS: i32 = FIXED_GRAPH_RTLD_LAZY
    | FIXED_GRAPH_RTLD_NOW
    | FIXED_GRAPH_RTLD_NOLOAD
    | FIXED_GRAPH_RTLD_NODELETE;
#[cfg(all(crabc_fixed_graph_dlfcn, not(crabc_bounded_runtime_dlopen)))]
const FIXED_GRAPH_ALLOWED_OPEN_FLAGS: i32 =
    FIXED_GRAPH_RTLD_LAZY | FIXED_GRAPH_RTLD_NOW | FIXED_GRAPH_RTLD_NOLOAD;

/// Caller-owned bounded text on the fixed-graph introspection wire.
///
/// This layout deliberately matches `crabc_core::runtime::TextV1` without
/// making the private interpreter depend on crabc-core or publishing that
/// larger process-singleton runtime contract.
#[cfg(any(crabc_fixed_graph_introspection, crabc_fixed_graph_dlfcn))]
#[repr(C)]
#[derive(Copy, Clone)]
pub struct FixedGraphTextV1 {
    len: u16,
    flags: u16,
    bytes: [u8; FIXED_GRAPH_TEXT_CAPACITY],
}

#[cfg(any(crabc_fixed_graph_introspection, crabc_fixed_graph_dlfcn))]
const EMPTY_FIXED_GRAPH_TEXT: FixedGraphTextV1 = FixedGraphTextV1 {
    len: 0,
    flags: 0,
    bytes: [0; FIXED_GRAPH_TEXT_CAPACITY],
};

/// One caller-owned image record copied from the immutable three-object graph.
#[cfg(any(crabc_fixed_graph_introspection, crabc_fixed_graph_dlfcn))]
#[repr(C)]
pub struct FixedGraphImageV1 {
    image_base: *mut c_void,
    program_headers: *const c_void,
    program_header_count: u16,
    reserved: u16,
    additions: u64,
    removals: u64,
    tls_module: usize,
    tls_data: *mut c_void,
    image_name: FixedGraphTextV1,
}

/// Caller-owned `dladdr`-shaped values with both names copied.
#[cfg(any(crabc_fixed_graph_introspection, crabc_fixed_graph_dlfcn))]
#[repr(C)]
pub struct FixedGraphAddressV1 {
    image_base: *mut c_void,
    symbol_address: *mut c_void,
    image_name: FixedGraphTextV1,
    symbol_name: FixedGraphTextV1,
}

/// Caller-owned useful `RTLD_DI_LINKMAP`-shaped values for one graph object.
#[cfg(any(crabc_fixed_graph_introspection, crabc_fixed_graph_dlfcn))]
#[repr(C)]
pub struct FixedGraphInformationV1 {
    image_base: *mut c_void,
    dynamic_address: *mut c_void,
    image_name: FixedGraphTextV1,
}

#[cfg(any(crabc_fixed_graph_introspection, crabc_fixed_graph_dlfcn))]
type FixedGraphSnapshotFn = unsafe extern "C" fn(
    *mut FixedGraphImageV1,
    usize,
    *mut usize,
    *mut u64,
    *mut FixedGraphTextV1,
) -> i32;
#[cfg(any(crabc_fixed_graph_introspection, crabc_fixed_graph_dlfcn))]
type FixedGraphAddressFn = unsafe extern "C" fn(
    *const c_void,
    *mut FixedGraphAddressV1,
    *mut FixedGraphTextV1,
) -> i32;
#[cfg(crabc_fixed_graph_introspection)]
type FixedGraphInformationFn = unsafe extern "C" fn(
    usize,
    *mut FixedGraphInformationV1,
    *mut FixedGraphTextV1,
) -> i32;

#[cfg(crabc_fixed_graph_dlfcn)]
type FixedGraphOpenFn = unsafe extern "C" fn(
    *const u8,
    i32,
    *mut *mut c_void,
    *mut FixedGraphTextV1,
) -> i32;
#[cfg(crabc_fixed_graph_dlfcn)]
type FixedGraphSymbolFn = unsafe extern "C" fn(
    *mut c_void,
    *const u8,
    *mut *mut c_void,
    *mut FixedGraphTextV1,
) -> i32;
#[cfg(crabc_fixed_graph_dlfcn)]
type FixedGraphCloseFn = unsafe extern "C" fn(*mut c_void, *mut FixedGraphTextV1) -> i32;
#[cfg(crabc_fixed_graph_dlfcn)]
type FixedGraphHandleInformationFn = unsafe extern "C" fn(
    *mut c_void,
    *mut FixedGraphInformationV1,
    *mut FixedGraphTextV1,
) -> i32;

/// Exact immutable callback record imported weakly by the private main image.
///
/// The callbacks return copied values from loader-owned state. No callback
/// returns a `link_map *`, borrowed name, ordinary `dlopen` handle, or a route
/// for changing the fixed graph.
#[cfg(crabc_fixed_graph_introspection)]
#[repr(C)]
pub struct FixedGraphIntrospectionV1 {
    magic: u64,
    version: u32,
    abi_size: u32,
    snapshot: FixedGraphSnapshotFn,
    address: FixedGraphAddressFn,
    information: FixedGraphInformationFn,
}

#[cfg(crabc_fixed_graph_introspection)]
#[used]
#[no_mangle]
pub static __crabc_x86_64_fixed_graph_introspection_v1: FixedGraphIntrospectionV1 =
    FixedGraphIntrospectionV1 {
        magic: FIXED_GRAPH_INTROSPECTION_MAGIC,
        version: FIXED_GRAPH_INTROSPECTION_VERSION,
        abi_size: core::mem::size_of::<FixedGraphIntrospectionV1>() as u32,
        snapshot: fixed_graph_snapshot,
        address: fixed_graph_address,
        information: fixed_graph_information,
    };

/// RuntimeV1-shaped loader prefix for the already-loaded fixed graph.
///
/// Handles are loader-owned identity tokens with explicit acquisition counts;
/// callbacks return copied text and metadata. `open` accepts only the retained
/// main/mid/leaf identities, except that the cfg-isolated bounded sibling can
/// map one runtime object and then `RTLD_NOLOAD`-acquire only that published
/// identity. It cannot search the filesystem, add an object beyond that one
/// bounded transaction, mutate global scope, or make mappings unloadable.
#[cfg(crabc_fixed_graph_dlfcn)]
#[repr(C)]
pub struct FixedGraphDlfcnV1 {
    magic: u64,
    version: u32,
    abi_size: u32,
    open: FixedGraphOpenFn,
    symbol: FixedGraphSymbolFn,
    close: FixedGraphCloseFn,
    address: FixedGraphAddressFn,
    snapshot: FixedGraphSnapshotFn,
    information: FixedGraphHandleInformationFn,
}

#[cfg(crabc_fixed_graph_dlfcn)]
#[used]
#[no_mangle]
pub static __crabc_x86_64_fixed_graph_dlfcn_v1: FixedGraphDlfcnV1 = FixedGraphDlfcnV1 {
    magic: FIXED_GRAPH_DLFCN_MAGIC,
    version: FIXED_GRAPH_DLFCN_VERSION,
    abi_size: core::mem::size_of::<FixedGraphDlfcnV1>() as u32,
    open: fixed_graph_open,
    symbol: fixed_graph_symbol,
    close: fixed_graph_close,
    address: fixed_graph_address,
    snapshot: fixed_graph_snapshot,
    information: fixed_graph_handle_information,
};

/// How an object mapping entered the one initial loader transaction.
///
/// The map span is recorded together with this provenance rather than
/// reconstructed from ELF headers at rollback time.  In particular, the
/// kernel-owned main image is never a transaction rollback candidate.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum ObjectMapProvenance {
    None,
    KernelMain,
    Transaction,
}

#[derive(Copy, Clone)]
struct Object {
    base: u64,
    phdr: *const u8,
    phnum: usize,
    #[cfg(any(crabc_fixed_graph_introspection, crabc_fixed_graph_dlfcn))]
    dynamic: *const u8,
    strtab: *const u8,
    strsz: usize,
    symtab: *const u8,
    symcount: usize,
    rela: *const u8,
    relasz: usize,
    jmprel: *const u8,
    pltrelsz: usize,
    relr: *const u8,
    relrsz: usize,
    // Only the cfg-isolated one-slot runtime mapper may retain this legacy
    // initializer. It validates a legacy DT_FINI target transiently but does
    // not retain or dispatch it: pinned musl makes that tag inert on dlclose.
    // Startup objects remain on the established init-array-only boundary,
    // and runtime finalization remains deliberately unsupported.
    #[cfg(crabc_bounded_runtime_dlopen)]
    init: usize,
    init_array: *const usize,
    init_count: usize,
    #[cfg(crabc_general_initial_lifecycle)]
    general_init: usize,
    #[cfg(crabc_general_initial_lifecycle)]
    general_fini: usize,
    #[cfg(crabc_general_initial_lifecycle)]
    general_fini_array: *const usize,
    #[cfg(crabc_general_initial_lifecycle)]
    general_fini_count: usize,
    relro_virtual_address: u64,
    relro_byte_len: u64,
    runpath: *const u8,
    runpath_len: usize,
    needed: [usize; MAX_NEEDED],
    needed_count: usize,
    mapped: bool,
    map_provenance: ObjectMapProvenance,
    map_span_start: u64,
    map_span_byte_len: u64,
    tls_image: *const u8,
    tls_filesz: usize,
    tls_memsz: usize,
    tls_align: usize,
    tls_offset_below_tp: usize,
    tls_module_id: usize,
    #[cfg(crabc_initial_exec_tls_graph)]
    static_tls: bool,
}

const EMPTY_OBJECT: Object = Object {
    base: 0,
    phdr: core::ptr::null(),
    phnum: 0,
    #[cfg(any(crabc_fixed_graph_introspection, crabc_fixed_graph_dlfcn))]
    dynamic: core::ptr::null(),
    strtab: core::ptr::null(),
    strsz: 0,
    symtab: core::ptr::null(),
    symcount: 0,
    rela: core::ptr::null(),
    relasz: 0,
    jmprel: core::ptr::null(),
    pltrelsz: 0,
    relr: core::ptr::null(),
    relrsz: 0,
    #[cfg(crabc_bounded_runtime_dlopen)]
    init: 0,
    init_array: core::ptr::null(),
    init_count: 0,
    #[cfg(crabc_general_initial_lifecycle)]
    general_init: 0,
    #[cfg(crabc_general_initial_lifecycle)]
    general_fini: 0,
    #[cfg(crabc_general_initial_lifecycle)]
    general_fini_array: core::ptr::null(),
    #[cfg(crabc_general_initial_lifecycle)]
    general_fini_count: 0,
    relro_virtual_address: 0,
    relro_byte_len: 0,
    runpath: core::ptr::null(),
    runpath_len: 0,
    needed: [0; MAX_NEEDED],
    needed_count: 0,
    mapped: false,
    map_provenance: ObjectMapProvenance::None,
    map_span_start: 0,
    map_span_byte_len: 0,
    tls_image: core::ptr::null(),
    tls_filesz: 0,
    tls_memsz: 0,
    tls_align: 1,
    tls_offset_below_tp: 0,
    tls_module_id: 0,
    #[cfg(crabc_initial_exec_tls_graph)]
    static_tls: false,
};

// The record itself is immutable RELRO data.  The two dynamic values it needs
// are deliberately separate one-shot bootstrap state: the loader writes them
// after it has relocated and sealed all three graph objects, then Scrt1 calls
// the constructor callback exactly once before the process finalizer is
// admissible.  This is neither a pthread-safe registry nor a general loader
// lifecycle model.
#[cfg(crabc_owned_crt_handoff)]
#[derive(Copy, Clone)]
struct OwnedCrtInitializerRange {
    base: u64,
    phdr: *const u8,
    phnum: usize,
    init_array: *const usize,
    init_count: usize,
}

#[cfg(crabc_owned_crt_handoff)]
const EMPTY_OWNED_CRT_INITIALIZER_RANGE: OwnedCrtInitializerRange = OwnedCrtInitializerRange {
    base: 0,
    phdr: core::ptr::null(),
    phnum: 0,
    init_array: core::ptr::null(),
    init_count: 0,
};

#[cfg(crabc_owned_crt_handoff)]
static mut OWNED_CRT_INITIALIZER_RANGES: [OwnedCrtInitializerRange; MAX_OBJECTS - 1] =
    [EMPTY_OWNED_CRT_INITIALIZER_RANGE; MAX_OBJECTS - 1];
#[cfg(crabc_owned_crt_handoff)]
static mut OWNED_CRT_HANDOFF_STATE: u8 = OWNED_CRT_STATE_UNPUBLISHED;

// This state is written once after the fixed graph's relocation, protection,
// and dependency constructors complete, then is immutable for process life.
// The release/acquire publication flag makes concurrent object-state readers
// well-defined. The dlfcn sibling's separate reference counters are atomics;
// neither sibling invents a mutable graph registry or loader lock.
#[cfg(any(crabc_fixed_graph_introspection, crabc_fixed_graph_dlfcn))]
static FIXED_GRAPH_RUNTIME_PUBLISHED: AtomicBool = AtomicBool::new(false);
#[cfg(any(crabc_fixed_graph_introspection, crabc_fixed_graph_dlfcn))]
static FIXED_GRAPH_RUNTIME_COUNT: AtomicUsize = AtomicUsize::new(0);
#[cfg(any(crabc_fixed_graph_introspection, crabc_fixed_graph_dlfcn))]
static FIXED_GRAPH_RUNTIME_ADDITIONS: AtomicU64 = AtomicU64::new(0);
#[cfg(any(crabc_fixed_graph_introspection, crabc_fixed_graph_dlfcn))]
static FIXED_GRAPH_RUNTIME_LOCK: AtomicBool = AtomicBool::new(false);
#[cfg(any(crabc_fixed_graph_introspection, crabc_fixed_graph_dlfcn))]
static mut FIXED_GRAPH_RUNTIME_OBJECTS: [Object; MAX_OBJECTS] = [EMPTY_OBJECT; MAX_OBJECTS];
#[cfg(any(crabc_fixed_graph_introspection, crabc_fixed_graph_dlfcn))]
static mut FIXED_GRAPH_RUNTIME_NAMES: [[u8; FIXED_GRAPH_TEXT_CAPACITY]; MAX_OBJECTS] =
    [[0; FIXED_GRAPH_TEXT_CAPACITY]; MAX_OBJECTS];

#[cfg(crabc_fixed_graph_dlfcn)]
#[repr(C)]
#[derive(Copy, Clone)]
struct FixedGraphHandleToken {
    identity: u8,
}

#[cfg(crabc_fixed_graph_dlfcn)]
static FIXED_GRAPH_HANDLE_TOKENS: [FixedGraphHandleToken; MAX_OBJECTS] =
    [FixedGraphHandleToken { identity: 0 }; MAX_OBJECTS];

// Startup mappings own one permanent graph reference. These counters cover
// only explicit dlfcn acquisitions, so the last `close` invalidates a token
// without pretending that the image was finalized or unmapped.
#[cfg(crabc_fixed_graph_dlfcn)]
static FIXED_GRAPH_HANDLE_REFERENCES: [AtomicUsize; MAX_OBJECTS] =
    [const { AtomicUsize::new(0) }; MAX_OBJECTS];

/// Serializes the copied graph view with the one admitted runtime mapping
/// transaction. The immutable siblings still use the same guard so the
/// callback contract has one race-free implementation.
#[cfg(any(crabc_fixed_graph_introspection, crabc_fixed_graph_dlfcn))]
struct FixedGraphRuntimeGuard;

#[cfg(any(crabc_fixed_graph_introspection, crabc_fixed_graph_dlfcn))]
impl FixedGraphRuntimeGuard {
    fn lock() -> Self {
        while FIXED_GRAPH_RUNTIME_LOCK
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        Self
    }
}

#[cfg(any(crabc_fixed_graph_introspection, crabc_fixed_graph_dlfcn))]
impl Drop for FixedGraphRuntimeGuard {
    fn drop(&mut self) {
        FIXED_GRAPH_RUNTIME_LOCK.store(false, Ordering::Release);
    }
}

// The private source roots use their own panic terminal at runtime.  Native
// state tests use the standard test harness instead, so compiling the same
// bounded loader modules with `--test` must not introduce a second panic
// implementation.
#[cfg(not(test))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    unsafe { die(b"panic\n") }
}

// The interpreter cannot rely on any relocated Rust address before this
// sequence.  Linux supplies AT_BASE for PT_INTERP; the loop finds this
// object's PT_DYNAMIC and applies only the linker's self-relative records.
#[cfg(not(test))]
global_asm!(
    ".global _start",
    ".type _start,@function",
    "_start:",
    "mov %rsp, %r12",
    "mov (%rsp), %rax",
    "lea 8(%rsp,%rax,8), %rdi",
    "add $8, %rdi",
    ".Lx86_argv:",
    "cmpq $0, (%rdi)",
    "lea 8(%rdi), %rdi",
    "jne .Lx86_argv",
    "xor %r13, %r13",
    ".Lx86_auxv:",
    "mov (%rdi), %rax",
    "test %rax, %rax",
    "je .Lx86_have_base",
    "cmp $7, %rax",
    "jne .Lx86_next_auxv",
    "mov 8(%rdi), %r13",
    ".Lx86_next_auxv:",
    "add $16, %rdi",
    "jmp .Lx86_auxv",
    ".Lx86_have_base:",
    "mov 32(%r13), %rax",
    "movzwl 56(%r13), %ecx",
    "lea (%r13,%rax), %rdi",
    ".Lx86_find_dynamic:",
    "test %ecx, %ecx",
    "je .Lx86_call_rust",
    "cmpl $2, (%rdi)",
    "je .Lx86_dynamic_found",
    "add $56, %rdi",
    "dec %ecx",
    "jmp .Lx86_find_dynamic",
    ".Lx86_dynamic_found:",
    "mov 16(%rdi), %rax",
    "mov 40(%rdi), %rcx",
    "lea (%r13,%rax), %rdi",
    "add %rdi, %rcx",
    "xor %r8, %r8",
    "xor %r9, %r9",
    ".Lx86_dynamic_scan:",
    "cmp %rcx, %rdi",
    "jae .Lx86_apply_self",
    "mov (%rdi), %rax",
    "test %rax, %rax",
    "je .Lx86_apply_self",
    "cmp $7, %rax",
    "jne .Lx86_check_relasz",
    "mov 8(%rdi), %r8",
    "add %r13, %r8",
    ".Lx86_check_relasz:",
    "cmp $8, %rax",
    "jne .Lx86_next_dynamic",
    "mov 8(%rdi), %r9",
    ".Lx86_next_dynamic:",
    "add $16, %rdi",
    "jmp .Lx86_dynamic_scan",
    ".Lx86_apply_self:",
    "test %r8, %r8",
    "je .Lx86_call_rust",
    "lea (%r8,%r9), %rcx",
    ".Lx86_rela_loop:",
    "cmp %rcx, %r8",
    "jae .Lx86_call_rust",
    "mov 8(%r8), %rax",
    "cmp $8, %rax",
    "jne .Lx86_next_rela",
    "mov (%r8), %rdx",
    "add %r13, %rdx",
    "mov 16(%r8), %rax",
    "add %r13, %rax",
    "mov %rax, (%rdx)",
    ".Lx86_next_rela:",
    "add $24, %r8",
    "jmp .Lx86_rela_loop",
    ".Lx86_call_rust:",
    ".hidden x86_64_initial_graph_run",
    "mov %r12, %rdi",
    "mov %r13, %rsi",
    "call x86_64_initial_graph_run",
    "ud2",
    options(att_syntax),
);

/// The first general-runtime x86 slice owns arbitrary initial non-TLS
/// `DT_NEEDED` topology plus dependency-only `DT_INIT_ARRAY` dispatch. It
/// intentionally stops before TLS in this root, main-image/CRT lifecycle,
/// public dlfcn, runtime mapping or unload, and any persistent loader
/// lifecycle ownership.
#[cfg(crabc_general_initial_graph)]
#[no_mangle]
pub unsafe extern "C" fn x86_64_initial_graph_run(sp: usize, ldso_base: usize) -> ! {
    // SAFETY: forwarded unchanged from `_start` to the general package.
    unsafe { x86_64_general_initial_graph::run(sp, ldso_base) }
}

#[cfg(not(crabc_general_initial_graph))]
#[no_mangle]
pub unsafe extern "C" fn x86_64_initial_graph_run(sp: usize, ldso_base: usize) -> ! {
    // SAFETY: `_start` preserves the kernel's initial stack and supplies the
    // AT_BASE it decoded. All later raw accesses remain bounded by validated
    // program-header, file-range, and dynamic-table sizes in this deliberately
    // small fixture ABI.
    unsafe {
        let (main_phdr, main_phnum, main_entry) = auxv_main(sp).unwrap_or_else(|| fail(b"auxv\n"));
        let main_base = main_load_bias(main_phdr, main_phnum).unwrap_or_else(|| fail(b"mainbase\n"));
        let mut objects = [EMPTY_OBJECT; MAX_OBJECTS];
        // Keep packed RELR ownership at exactly one mapped dependency.  The
        // main and mid images remain RELA-only, while the fixed leaf carries
        // the one required packed table; accepting the same tags elsewhere
        // would silently widen this private graph's ABI.
        objects[0] = parse_mapped(main_base, main_phdr, main_phnum, false, false, false)
            .unwrap_or_else(|| fail(b"mainelf\n"));
        if objects[0].needed_count != 1 || objects[0].runpath.is_null() || objects[0].relrsz != 0 {
            fail(b"mainshape\n");
        }
        objects[1] = load_needed(&objects[0], 0).unwrap_or_else(|| fail(b"midmap\n"));
        if objects[1].needed_count != 1 || objects[1].runpath.is_null() || objects[1].relrsz != 0 {
            fail(b"midshape\n");
        }
        objects[2] = load_needed(&objects[1], 0).unwrap_or_else(|| fail(b"leafmap\n"));
        if objects[2].needed_count != 0 || objects[2].relrsz == 0 {
            fail(b"leafshape\n");
        }
        // The initial-exec sibling does not turn DF_STATIC_TLS into ambient
        // admission.  This one fixed graph has exactly one static-TLS leaf;
        // the TLS-free main and GNU-Dynamic mid are required to remain so.
        #[cfg(crabc_initial_exec_tls_graph)]
        if objects[0].static_tls || objects[1].static_tls || !objects[2].static_tls {
            fail(b"ieshape\n");
        }
        // Keep module IDs stable in this fixed main -> mid -> leaf graph
        // before relocation writes their GNU-Dynamic DTPMOD/DTPOFF slots. The
        // no-TLS graph retains its old behavior: a layout with no PT_TLS image
        // does not install or modify `%fs`.
        let has_initial_tls = plan_initial_tls(&mut objects).unwrap_or_else(|| fail(b"tlsplan\n"));
        #[cfg(crabc_loader_libc_tls_runtime_v1)]
        let runtime_v1_registry =
            initial_tls_runtime_v1_registry(&objects).unwrap_or_else(|| fail(b"tlsregistry\n"));
        for object in &objects {
            relocate(object, &objects).unwrap_or_else(|| fail(b"reloc\n"));
        }
        for object in &objects[1..] {
            protect_segments(object).unwrap_or_else(|| fail(b"protect\n"));
        }
        // PT_TLS templates may contain relocated data, so copy them only after
        // relocation but before any dependency initializer or application TLS
        // access. `install_initial_tls` installs `%fs` only on success.
        if has_initial_tls {
            // RuntimeV1 is a deliberately separate consumer seam. The older
            // initial-TLS graph keeps its direct transfer and never publishes
            // an ambient loader record merely because it has a DTV.
            #[cfg(crabc_loader_libc_tls_runtime_v1)]
            {
                let installed_tls = install_initial_tls(&objects)
                    .unwrap_or_else(|| fail(b"tlsinit\n"));
                publish_loader_tls_runtime_v1(installed_tls, runtime_v1_registry)
                    .unwrap_or_else(|| fail(b"tlswire\n"));
            }
            #[cfg(not(crabc_loader_libc_tls_runtime_v1))]
            {
                let _installed_tls = install_initial_tls(&objects)
                    .unwrap_or_else(|| fail(b"tlsinit\n"));
            }
        }
        #[cfg(crabc_loader_libc_tls_runtime_v1)]
        if !has_initial_tls {
            // This one producer cannot manufacture a dynamic-mode handoff
            // without a loader-installed TCB and initial DTV.
            fail(b"tlswire\n");
        }
        for object in &objects {
            apply_relro(object).unwrap_or_else(|| fail(b"relro\n"));
        }
        #[cfg(crabc_owned_crt_handoff)]
        publish_owned_crt_handoff(&objects).unwrap_or_else(|| fail(b"crtwire\n"));
        #[cfg(not(crabc_owned_crt_handoff))]
        run_initializers(&objects[1..]).unwrap_or_else(|| fail(b"init\n"));
        #[cfg(any(crabc_fixed_graph_introspection, crabc_fixed_graph_dlfcn))]
        publish_fixed_graph_runtime(sp, &objects)
            .unwrap_or_else(|| fail(b"fixedgraph\n"));
        // The interpreter's bootstrap RELA table was applied in `_start`, so
        // its own PT_GNU_RELRO is the final protection transition before
        // handing the original stack to the already-relocated main image.
        apply_self_relro(ldso_base as u64).unwrap_or_else(|| fail(b"selfrelro\n"));
        jump(main_entry as usize, sp)
    }
}

unsafe fn auxv_main(sp: usize) -> Option<(*const u8, usize, u64)> {
    let argc = *(sp as *const usize);
    let mut cursor = (sp + 8 + (argc + 1) * 8) as *const usize;
    while !(*cursor).eq(&0) { cursor = cursor.add(1); }
    cursor = cursor.add(1);
    let mut phdr = 0usize;
    let mut phnum = 0usize;
    let mut entry = 0u64;
    loop {
        let tag = *cursor as u64;
        let value = *cursor.add(1) as u64;
        if tag == AT_NULL { break; }
        if tag == AT_PHDR { phdr = value as usize; }
        if tag == AT_PHNUM { phnum = value as usize; }
        if tag == AT_ENTRY { entry = value; }
        cursor = cursor.add(2);
    }
    if phdr == 0 || phnum == 0 || phnum > MAX_PHDRS || entry == 0 { None } else { Some((phdr as *const u8, phnum, entry)) }
}

unsafe fn main_load_bias(phdr: *const u8, phnum: usize) -> Option<u64> {
    let mut phdr_virtual_address = None;
    for index in 0..phnum {
        let header = phdr.add(index * 56);
        if read_u32(header) == PT_PHDR {
            if phdr_virtual_address.replace(read_u64(header.add(16))).is_some() { return None; }
        }
    }
    let virtual_address = phdr_virtual_address?;
    let byte_len = u64::try_from(phnum).ok()?.checked_mul(56)?;
    if !virtual_range_in_load(phdr, phnum, virtual_address, byte_len) { return None; }
    (phdr as u64).checked_sub(virtual_address)
}

unsafe fn parse_mapped(
    base: u64,
    phdr: *const u8,
    phnum: usize,
    mapped: bool,
    allow_bounded_runtime_legacy_tags: bool,
    general_initial_graph: bool,
) -> Option<Object> {
    // Legacy DT_INIT/DT_FINI are not general mapped-object features. The only
    // caller that may opt in is the one-slot runtime transaction below; it
    // must never accidentally select main-image or startup-DSO lifecycle.
    if allow_bounded_runtime_legacy_tags && !mapped {
        return None;
    }
    if general_initial_graph && allow_bounded_runtime_legacy_tags {
        return None;
    }
    let mut dynamic_virtual_address = None;
    let mut dynamic_byte_len = None;
    let mut relro = None;
    #[cfg(any(
        crabc_initial_tls_graph,
        crabc_initial_exec_tls_graph,
        crabc_general_initial_tls_materialization_v1
    ))]
    let mut tls: Option<(u64, u64, u64, usize)> = None;
    #[cfg(not(any(
        crabc_initial_tls_graph,
        crabc_initial_exec_tls_graph,
        crabc_general_initial_tls_materialization_v1
    )))]
    let tls: Option<(u64, u64, u64, usize)> = None;
    for index in 0..phnum {
        let header = phdr.add(index * 56);
        match read_u32(header) {
            PT_DYNAMIC => {
                if dynamic_virtual_address.is_some() { return None; }
                let address = read_u64(header.add(16));
                let byte_len = read_u64(header.add(40));
                if byte_len == 0 || byte_len % 16 != 0 || !virtual_range_in_load(phdr, phnum, address, byte_len) { return None; }
                dynamic_virtual_address = Some(address);
                dynamic_byte_len = Some(byte_len);
            }
            PT_GNU_RELRO => {
                if relro.is_some() { return None; }
                let address = read_u64(header.add(16));
                let byte_len = read_u64(header.add(40));
                // Linkers commonly extend PT_GNU_RELRO through the final page
                // that owns a writable PT_LOAD prefix. Validate against the
                // actual page-rounded mapping rather than raw p_memsz, but do
                // not accept an arbitrary span beyond that mapping.
                if byte_len == 0 || !virtual_range_in_page_mapped_load(phdr, phnum, address, byte_len) { return None; }
                relro = Some((address, byte_len));
            }
            // The original graph is intentionally a no-TLS artifact and its
            // negative runner mutates a spare program header into PT_TLS.
            // Compile the sibling initial-TLS graph with the explicit cfg so
            // this shared bootstrap source cannot silently widen the older
            // fixture's contract.
            #[cfg(not(any(
                crabc_initial_tls_graph,
                crabc_initial_exec_tls_graph,
                crabc_general_initial_tls_materialization_v1
            )))]
            PT_TLS => return None,
            #[cfg(any(
                crabc_initial_tls_graph,
                crabc_initial_exec_tls_graph,
                crabc_general_initial_tls_materialization_v1
            ))]
            PT_TLS => {
                if tls.is_some() {
                    return None;
                }
                let file_offset = read_u64(header.add(8));
                let virtual_address = read_u64(header.add(16));
                let filesz = read_u64(header.add(32));
                let memsz = read_u64(header.add(40));
                let raw_align = read_u64(header.add(48));
                let align = if raw_align == 0 { 1 } else { raw_align };
                if filesz > memsz
                    || !align.is_power_of_two()
                    || virtual_address & (align - 1) != file_offset & (align - 1)
                {
                    return None;
                }
                let align = usize::try_from(align).ok()?;
                if memsz != 0 && !virtual_range_in_load(phdr, phnum, virtual_address, memsz) {
                    return None;
                }
                // The initialized prefix is copied after relocation. It must
                // originate in an explicitly readable, file-backed PT_LOAD,
                // never in a BSS extension that happens to be mapped today.
                if filesz != 0
                    && !virtual_range_in_readable_file_load(
                        phdr,
                        phnum,
                        virtual_address,
                        filesz,
                    )
                {
                    return None;
                }
                tls = Some((virtual_address, filesz, memsz, align));
            }
            _ => {}
        }
    }
    let dynamic_address = dynamic_virtual_address?;
    let dynamic_byte_len = dynamic_byte_len?;
    let dynamic = runtime_address(base, dynamic_address)? as *const u8;
    let dynamic_count = usize::try_from(dynamic_byte_len / 16).ok()?;
    let (relro_virtual_address, relro_byte_len) = relro.unwrap_or((0, 0));
    let mut object = Object {
        base,
        phdr,
        phnum,
        #[cfg(any(crabc_fixed_graph_introspection, crabc_fixed_graph_dlfcn))]
        dynamic,
        mapped,
        relro_virtual_address,
        relro_byte_len,
        ..EMPTY_OBJECT
    };
    if let Some((virtual_address, filesz, memsz, align)) = tls {
        object.tls_filesz = usize::try_from(filesz).ok()?;
        object.tls_memsz = usize::try_from(memsz).ok()?;
        object.tls_align = align;
        if object.tls_memsz != 0 {
            object.tls_image = runtime_address(base, virtual_address)? as *const u8;
        }
    }
    let mut needed_offsets = [0usize; MAX_NEEDED];
    let mut runpath_offset = None;
    let mut init_array_virtual_address = None;
    let mut init_array_byte_len = None;
    #[cfg(crabc_bounded_runtime_dlopen)]
    let mut bounded_runtime_init_virtual_address = None;
    #[cfg(crabc_bounded_runtime_dlopen)]
    let mut bounded_runtime_fini_virtual_address = None;
    #[cfg(crabc_bounded_runtime_dlopen)]
    let mut bounded_runtime_preinit_array_virtual_address = None;
    #[cfg(crabc_bounded_runtime_dlopen)]
    let mut bounded_runtime_preinit_array_byte_len = None;
    // Neither Scrt1-admitting sibling executes main-image lifecycle entries.
    // The fixed owned-CRT path validates this exact shape before its record
    // takes over; the dynamic-main-thread bridge validates the same shape
    // before Scrt1 makes its direct libc startup call. The two established
    // general siblings retain the old reject-only main-image rule below.
    #[cfg(any(crabc_owned_crt_handoff, crabc_dynamic_main_thread_runtime_v1))]
    let mut owned_crt_main_init = None;
    #[cfg(any(crabc_owned_crt_handoff, crabc_dynamic_main_thread_runtime_v1))]
    let mut owned_crt_main_fini = None;
    #[cfg(any(crabc_owned_crt_handoff, crabc_dynamic_main_thread_runtime_v1))]
    let mut owned_crt_main_preinit_array = None;
    #[cfg(any(crabc_owned_crt_handoff, crabc_dynamic_main_thread_runtime_v1))]
    let mut owned_crt_main_preinit_array_len = None;
    #[cfg(any(crabc_owned_crt_handoff, crabc_dynamic_main_thread_runtime_v1))]
    let mut owned_crt_main_init_array = None;
    #[cfg(any(crabc_owned_crt_handoff, crabc_dynamic_main_thread_runtime_v1))]
    let mut owned_crt_main_init_array_len = None;
    #[cfg(any(crabc_owned_crt_handoff, crabc_dynamic_main_thread_runtime_v1))]
    let mut owned_crt_main_fini_array = None;
    #[cfg(any(crabc_owned_crt_handoff, crabc_dynamic_main_thread_runtime_v1))]
    let mut owned_crt_main_fini_array_len = None;
    let mut strtab_virtual_address = None;
    let mut strtab_byte_len = None;
    let mut symtab_virtual_address = None;
    let mut symtab_entry_len = None;
    let mut hash_virtual_address = None;
    let mut rela_virtual_address = None;
    let mut rela_byte_len = None;
    let mut rela_entry_len = None;
    let mut relr_virtual_address = None;
    let mut relr_byte_len = None;
    let mut relr_entry_len = None;
    let mut jmprel_virtual_address = None;
    let mut pltrel_byte_len = None;
    let mut plt_is_rela = None;
    let mut terminated = false;
    #[cfg(crabc_general_initial_lifecycle)]
    let (mut general_init, mut general_fini, mut general_fini_array, mut general_fini_len) =
        (None, None, None, None);
    for index in 0..dynamic_count {
        let entry = dynamic.add(index * 16);
        let tag = read_i64(entry);
        let value = read_u64(entry.add(8));
        match tag {
            DT_NULL => { terminated = true; break; }
            DT_NEEDED => {
                if object.needed_count == MAX_NEEDED { return None; }
                needed_offsets[object.needed_count] = usize::try_from(value).ok()?;
                object.needed_count += 1;
            }
            DT_STRTAB => { if strtab_virtual_address.replace(value).is_some() { return None; } }
            DT_STRSZ => { if strtab_byte_len.replace(value).is_some() { return None; } }
            DT_SYMTAB => { if symtab_virtual_address.replace(value).is_some() { return None; } }
            DT_SYMENT => { if symtab_entry_len.replace(value).is_some() { return None; } }
            DT_HASH => { if hash_virtual_address.replace(value).is_some() { return None; } }
            DT_RELA => { if rela_virtual_address.replace(value).is_some() { return None; } }
            DT_RELASZ => { if rela_byte_len.replace(value).is_some() { return None; } }
            DT_RELAENT => { if rela_entry_len.replace(value).is_some() { return None; } }
            DT_RELR => { if relr_virtual_address.replace(value).is_some() { return None; } }
            DT_RELRSZ => { if relr_byte_len.replace(value).is_some() { return None; } }
            DT_RELRENT => { if relr_entry_len.replace(value).is_some() { return None; } }
            DT_JMPREL => { if jmprel_virtual_address.replace(value).is_some() { return None; } }
            DT_PLTRELSZ => { if pltrel_byte_len.replace(value).is_some() { return None; } }
            DT_PLTREL => { if plt_is_rela.replace(value == ELF64_RELA).is_some() { return None; } }
            #[cfg(any(crabc_owned_crt_handoff, crabc_dynamic_main_thread_runtime_v1))]
            DT_INIT if !mapped => { if owned_crt_main_init.replace(value).is_some() { return None; } }
            #[cfg(crabc_bounded_runtime_dlopen)]
            DT_INIT if mapped && allow_bounded_runtime_legacy_tags => {
                if bounded_runtime_init_virtual_address.replace(value).is_some() {
                    return None;
                }
            }
            // Musl does not dispatch a DSO's preinit array during dlopen.
            // This one-slot mapper records only bounded structural metadata;
            // it neither retains nor dereferences the entry pointers below.
            #[cfg(crabc_bounded_runtime_dlopen)]
            DT_PREINIT_ARRAY if mapped && allow_bounded_runtime_legacy_tags => {
                if bounded_runtime_preinit_array_virtual_address.replace(value).is_some() {
                    return None;
                }
            }
            #[cfg(crabc_bounded_runtime_dlopen)]
            DT_PREINIT_ARRAYSZ if mapped && allow_bounded_runtime_legacy_tags => {
                if bounded_runtime_preinit_array_byte_len.replace(value).is_some() {
                    return None;
                }
            }
            #[cfg(any(crabc_owned_crt_handoff, crabc_dynamic_main_thread_runtime_v1))]
            DT_FINI if !mapped => { if owned_crt_main_fini.replace(value).is_some() { return None; } }
            #[cfg(crabc_bounded_runtime_dlopen)]
            DT_FINI if mapped && allow_bounded_runtime_legacy_tags => {
                if bounded_runtime_fini_virtual_address.replace(value).is_some() {
                    return None;
                }
            }
            #[cfg(any(crabc_owned_crt_handoff, crabc_dynamic_main_thread_runtime_v1))]
            DT_PREINIT_ARRAY if !mapped => {
                if owned_crt_main_preinit_array.replace(value).is_some() { return None; }
            }
            #[cfg(any(crabc_owned_crt_handoff, crabc_dynamic_main_thread_runtime_v1))]
            DT_PREINIT_ARRAYSZ if !mapped => {
                if owned_crt_main_preinit_array_len.replace(value).is_some() { return None; }
            }
            #[cfg(any(crabc_owned_crt_handoff, crabc_dynamic_main_thread_runtime_v1))]
            DT_INIT_ARRAY if !mapped => {
                if owned_crt_main_init_array.replace(value).is_some() { return None; }
            }
            #[cfg(any(crabc_owned_crt_handoff, crabc_dynamic_main_thread_runtime_v1))]
            DT_INIT_ARRAYSZ if !mapped => {
                if owned_crt_main_init_array_len.replace(value).is_some() { return None; }
            }
            #[cfg(any(crabc_owned_crt_handoff, crabc_dynamic_main_thread_runtime_v1))]
            DT_FINI_ARRAY if !mapped => {
                if owned_crt_main_fini_array.replace(value).is_some() { return None; }
            }
            #[cfg(any(crabc_owned_crt_handoff, crabc_dynamic_main_thread_runtime_v1))]
            DT_FINI_ARRAYSZ if !mapped => {
                if owned_crt_main_fini_array_len.replace(value).is_some() { return None; }
            }
            #[cfg(crabc_general_initial_lifecycle)]
            DT_INIT if general_initial_graph && mapped => {
                if general_init.replace(value).is_some() { return None; }
            }
            #[cfg(crabc_general_initial_lifecycle)]
            DT_FINI if general_initial_graph && mapped => {
                if general_fini.replace(value).is_some() { return None; }
            }
            #[cfg(crabc_general_initial_lifecycle)]
            DT_FINI_ARRAY if general_initial_graph && mapped => {
                if general_fini_array.replace(value).is_some() { return None; }
            }
            #[cfg(crabc_general_initial_lifecycle)]
            DT_FINI_ARRAYSZ if general_initial_graph && mapped => {
                if general_fini_len.replace(value).is_some() { return None; }
            }
            // Without the lifecycle owner, the general graph admits only
            // a dependency DSO's bounded DT_INIT_ARRAY. Main-image arrays
            // remain CRT-owned, and legacy/preinit/finalizer tags stay
            // reject-only because this initial transaction owns neither a
            // process lifecycle nor unload/finalization state.
            DT_INIT_ARRAY if general_initial_graph && mapped => {
                if init_array_virtual_address.replace(value).is_some() {
                    return None;
                }
            }
            DT_INIT_ARRAYSZ if general_initial_graph && mapped => {
                if init_array_byte_len.replace(value).is_some() {
                    return None;
                }
            }
            DT_INIT | DT_FINI | DT_PREINIT_ARRAY | DT_PREINIT_ARRAYSZ
            | DT_INIT_ARRAY | DT_INIT_ARRAYSZ | DT_FINI_ARRAY | DT_FINI_ARRAYSZ
                if general_initial_graph => return None,
            DT_INIT_ARRAY => { if init_array_virtual_address.replace(value).is_some() { return None; } }
            DT_INIT_ARRAYSZ => { if init_array_byte_len.replace(value).is_some() { return None; } }
            DT_RUNPATH => { if runpath_offset.replace(usize::try_from(value).ok()?).is_some() { return None; } }
            // DF_STATIC_TLS denotes a consumer's initial-exec requirement,
            // not a promise that only this object may supply its definition.
            // General initial TLS assigns all modules retained placements;
            // the older fixed IE sibling keeps its one-leaf restriction.
            DT_FLAGS => {
                #[cfg(not(any(crabc_initial_exec_tls_graph, crabc_general_initial_tls_materialization_v1)))]
                if value & DF_STATIC_TLS != 0 {
                    return None;
                }
                if value & !(DF_BIND_NOW | DF_STATIC_TLS) != 0 {
                    return None;
                }
                #[cfg(crabc_initial_exec_tls_graph)]
                {
                    object.static_tls = value & DF_STATIC_TLS != 0;
                }
            }
            DT_FLAGS_1 if value & !(DF_1_NOW | DF_1_PIE) != 0 => return None,
            // These imply relocation, finalization, hash, or initialization
            // semantics outside the closed fixture ABI.  Reject before any
            // corresponding pointer can be used.
            DT_INIT | DT_FINI | DT_RPATH | DT_SYMBOLIC | DT_REL | DT_RELSZ | DT_RELENT | DT_FINI_ARRAY | DT_FINI_ARRAYSZ
            | DT_PREINIT_ARRAY | DT_PREINIT_ARRAYSZ | DT_GNU_HASH
            | DT_VERSYM | DT_VERDEF | DT_VERDEFNUM | DT_VERNEED | DT_VERNEEDNUM | DT_TEXTREL => return None,
            _ => {}
        }
    }
    #[cfg(any(crabc_owned_crt_handoff, crabc_dynamic_main_thread_runtime_v1))]
    if !mapped {
        // Scrt1's private `__crabc_*_array_*_address` bridges own dispatch;
        // the interpreter does not execute main entries or retain their
        // pointers. Legacy private modes require all three nonempty arrays.
        // General owned startup also admits a normal executable with no
        // callbacks; absent tag pairs do not select another CRT convention.
        let init = owned_crt_main_init?;
        let fini = owned_crt_main_fini?;
        if !virtual_range_in_executable_load(phdr, phnum, init, 1)
            || !virtual_range_in_executable_load(phdr, phnum, fini, 1)
        {
            return None;
        }
        for pair in [
            (owned_crt_main_preinit_array, owned_crt_main_preinit_array_len),
            (owned_crt_main_init_array, owned_crt_main_init_array_len),
            (owned_crt_main_fini_array, owned_crt_main_fini_array_len),
        ] {
            match pair {
                (None, None) if cfg!(all(crabc_general_initial_lifecycle, crabc_dynamic_main_thread_runtime_v1)) => {},
                (Some(address), Some(length)) if scrt1_array_in_load(phdr, phnum, address, length) => {},
                _ => return None,
            }
        }
    }
    object.strsz = usize::try_from(strtab_byte_len?).ok()?;
    if !terminated || object.strsz == 0 { return None; }
    let strtab_address = strtab_virtual_address?;
    if !virtual_range_in_load(phdr, phnum, strtab_address, object.strsz as u64) { return None; }
    object.strtab = runtime_address(base, strtab_address)? as *const u8;
    let hash_address = hash_virtual_address?;
    if !virtual_range_in_load(phdr, phnum, hash_address, 8) { return None; }
    let hash = runtime_address(base, hash_address)? as *const u8;
    object.symcount = usize::try_from(read_u32(hash.add(4))).ok()?;
    if object.symcount == 0 { return None; }
    let symtab_address = symtab_virtual_address?;
    if symtab_entry_len? != 24 { return None; }
    let symtab_len = u64::try_from(object.symcount).ok()?.checked_mul(24)?;
    if !virtual_range_in_load(phdr, phnum, symtab_address, symtab_len) { return None; }
    object.symtab = runtime_address(base, symtab_address)? as *const u8;
    match (rela_virtual_address, rela_byte_len, rela_entry_len) {
        (None, None, None) => {}
        (Some(address), Some(byte_len), Some(entry_len))
            if entry_len == ELF64_RELA_SIZE as u64
                && byte_len % ELF64_RELA_SIZE as u64 == 0
                && virtual_range_in_load(phdr, phnum, address, byte_len) =>
        {
            object.rela = runtime_address(base, address)? as *const u8;
            object.relasz = usize::try_from(byte_len).ok()?;
        }
        _ => return None,
    }
    match (jmprel_virtual_address, pltrel_byte_len, plt_is_rela) {
        (None, None, None) => {}
        (Some(address), Some(byte_len), Some(true))
            if byte_len % ELF64_RELA_SIZE as u64 == 0
                && virtual_range_in_load(phdr, phnum, address, byte_len) =>
        {
            object.jmprel = runtime_address(base, address)? as *const u8;
            object.pltrelsz = usize::try_from(byte_len).ok()?;
        }
        _ => return None,
    }
    match (relr_virtual_address, relr_byte_len, relr_entry_len) {
        (None, None, None) => {}
        (Some(address), Some(byte_len), Some(entry_len))
            if entry_len == ELF64_RELR_SIZE as u64
                && byte_len != 0
                && byte_len % ELF64_RELR_SIZE as u64 == 0
                && byte_len <= MAX_RELR_BYTE_LEN as u64
                && address & (ELF64_RELR_SIZE as u64 - 1) == 0
                && virtual_range_in_load(phdr, phnum, address, byte_len) =>
        {
            object.relr = runtime_address(base, address)? as *const u8;
            object.relrsz = usize::try_from(byte_len).ok()?;
        }
        _ => return None,
    }
    match (init_array_virtual_address, init_array_byte_len) {
        (None, None) => {}
        (Some(address), Some(byte_len)) if general_initial_graph && mapped => {
            let pointer_size = core::mem::size_of::<usize>() as u64;
            if byte_len == 0
                || byte_len % pointer_size != 0
                || byte_len
                    > (MAX_GENERAL_INITIAL_DEPENDENCY_INIT_ARRAY_ENTRIES
                        * core::mem::size_of::<usize>()) as u64
                || address & (pointer_size - 1) != 0
                || !virtual_range_in_load(phdr, phnum, address, byte_len)
            {
                return None;
            }
            object.init_array = runtime_address(base, address)? as *const usize;
            object.init_count = usize::try_from(byte_len / pointer_size).ok()?;
            #[cfg(crabc_general_initial_lifecycle)]
            if !virtual_range_in_readable_file_load(phdr, phnum, address, byte_len) {
                return None;
            }
        }
        // The executable's constructors are deliberately CRT-owned.  A
        // main-image init tag is a malformed request for this handoff.
        (Some(_), Some(_)) if !mapped => return None,
        (Some(address), Some(byte_len)) if byte_len % 8 == 0 && virtual_range_in_load(phdr, phnum, address, byte_len) => {
            object.init_array = runtime_address(base, address)? as *const usize;
            object.init_count = usize::try_from(byte_len / 8).ok()?;
        }
        _ => return None,
    }
    #[cfg(crabc_general_initial_lifecycle)]
    {
        // Direct legacy callbacks are validated before relocation. Array
        // storage is bounded here; relocated targets are all preflighted
        // together before any initializer may run.
        for (address, destination) in [
            (general_init, &mut object.general_init),
            (general_fini, &mut object.general_fini),
        ] {
            if let Some(address) = address {
                if address == 0 || !virtual_range_in_executable_load(phdr, phnum, address, 1) {
                    return None;
                }
                *destination = runtime_address(base, address)? as usize;
            }
        }
        match (general_fini_array, general_fini_len) {
            (None, None) => {}
            (Some(address), Some(byte_len))
                if byte_len != 0 && byte_len % 8 == 0 && address % 8 == 0
                    && byte_len <= (MAX_GENERAL_INITIAL_DEPENDENCY_INIT_ARRAY_ENTRIES * 8) as u64
                    && virtual_range_in_readable_file_load(phdr, phnum, address, byte_len) =>
            {
                object.general_fini_array = runtime_address(base, address)? as *const usize;
                object.general_fini_count = usize::try_from(byte_len / 8).ok()?;
            }
            _ => return None,
        }
    }
    #[cfg(crabc_bounded_runtime_dlopen)]
    match (
        bounded_runtime_preinit_array_virtual_address,
        bounded_runtime_preinit_array_byte_len,
    ) {
        (None, None) => {}
        // A runtime DSO preinit array is intentionally inert, matching musl's
        // dlopen behavior. Validate the tag pair's bounded storage only: do
        // not inspect or dispatch the function-pointer entries.
        (Some(address), Some(byte_len))
            if byte_len != 0
                && byte_len % core::mem::size_of::<usize>() as u64 == 0
                && byte_len
                    <= (MAX_BOUNDED_RUNTIME_ARRAY_ENTRIES * core::mem::size_of::<usize>())
                        as u64
                && address & (core::mem::size_of::<usize>() as u64 - 1) == 0
                && virtual_range_in_load(phdr, phnum, address, byte_len) => {}
        _ => return None,
    }
    #[cfg(crabc_bounded_runtime_dlopen)]
    if mapped && allow_bounded_runtime_legacy_tags {
        if let Some(address) = bounded_runtime_init_virtual_address {
            // DT_INIT is a direct code pointer, not an array pointer. Make
            // its one permitted runtime use executable-load-contained before
            // relocation or any constructor can observe the mapping.
            if address == 0 || !virtual_range_in_executable_load(phdr, phnum, address, 1) {
                return None;
            }
            object.init = runtime_address(base, address)? as usize;
        }
        if let Some(address) = bounded_runtime_fini_virtual_address {
            // Pinned musl preserves a legacy DT_FINI tag but does not dispatch
            // it on the dlclose path. Admit only the one-slot runtime shape
            // after proving its direct code target; do not retain it or infer
            // a DT_FINI_ARRAY/unload lifecycle from its presence.
            if address == 0 || !virtual_range_in_executable_load(phdr, phnum, address, 1) {
                return None;
            }
            let _ = runtime_address(base, address)?;
        }
    }
    if let Some(offset) = runpath_offset {
        if offset >= object.strsz { return None; }
        object.runpath = object.strtab.add(offset);
        object.runpath_len = bounded_nul(object.runpath, object.strsz - offset)?;
        if general_initial_graph {
            if !is_selected_absolute_runpath(object.runpath, object.runpath_len) {
                return None;
            }
        } else if !is_fixture_absolute_runpath(object.runpath, object.runpath_len) {
            return None;
        }
    }
    for slot in 0..object.needed_count {
        if needed_offsets[slot] >= object.strsz { return None; }
        let name = object.strtab.add(needed_offsets[slot]);
        if bounded_nul(name, object.strsz - needed_offsets[slot]).is_none() { return None; }
        object.needed[slot] = needed_offsets[slot];
    }
    Some(object)
}

unsafe fn load_needed(parent: &Object, needed_index: usize) -> Option<Object> {
    if needed_index >= parent.needed_count || parent.runpath.is_null() { return None; }
    let name = parent.strtab.add(parent.needed[needed_index]);
    let name_len = bounded_nul(name, parent.strsz - parent.needed[needed_index])?;
    let fd = open_from_runpath(parent.runpath, parent.runpath_len, name, name_len)?;
    let result = map_elf(fd, false, false);
    let _ = syscall1(SYS_CLOSE, fd);
    result
}

unsafe fn open_from_runpath(runpath: *const u8, runpath_len: usize, name: *const u8, name_len: usize) -> Option<i64> {
    let mut start = 0;
    while start < runpath_len {
        let mut end = start;
        while end < runpath_len && *runpath.add(end) != b':' { end += 1; }
        let directory_len = end - start;
        if directory_len != 0 && directory_len + 1 + name_len + 1 <= MAX_PATH {
            let mut path = [0u8; MAX_PATH];
            core::ptr::copy_nonoverlapping(runpath.add(start), path.as_mut_ptr(), directory_len);
            path[directory_len] = b'/';
            core::ptr::copy_nonoverlapping(name, path.as_mut_ptr().add(directory_len + 1), name_len);
            let fd = syscall4(SYS_OPENAT, AT_FDCWD, path.as_ptr() as i64, 0, 0);
            if fd >= 0 { return Some(fd); }
        }
        start = end + 1;
    }
    None
}

/// This artifact owns only fixture-style absolute directories.  In
/// particular, an empty component, a relative directory, and `$ORIGIN` are
/// search-policy features rather than safe inputs for this bounded proof.
unsafe fn is_fixture_absolute_runpath(runpath: *const u8, runpath_len: usize) -> bool {
    if runpath_len == 0 || *runpath != b'/' { return false; }
    for index in 0..runpath_len {
        let byte = *runpath.add(index);
        // A second component and `$ORIGIN`/variable expansion are search
        // policy, not part of this one-directory fixture ABI.
        if byte == b':' || byte == b'$' { return false; }
    }
    true
}

/// The selected general-initial policy searches only explicit absolute
/// RUNPATH components.  Empty and relative components, `$ORIGIN`, RPATH,
/// environment paths, the cache, and default directories remain outside this
/// first transaction package, so a failed lookup cannot fall through to an
/// ambient host loader decision.
unsafe fn is_selected_absolute_runpath(runpath: *const u8, runpath_len: usize) -> bool {
    if runpath_len == 0 || *runpath != b'/' {
        return false;
    }
    let mut component_start = 0;
    for index in 0..=runpath_len {
        if index != runpath_len && *runpath.add(index) != b':' {
            if *runpath.add(index) == b'$' {
                return false;
            }
            continue;
        }
        if index == component_start || *runpath.add(component_start) != b'/' {
            return false;
        }
        component_start = index + 1;
    }
    true
}

unsafe fn file_size_from_fd(fd: i64) -> Option<u64> {
    let mut stat = [0u8; X86_64_STAT_BYTE_LEN];
    if syscall2(SYS_FSTAT, fd, stat.as_mut_ptr() as i64) < 0 { return None; }
    u64::try_from(read_i64(stat.as_ptr().add(X86_64_STAT_SIZE_OFFSET))).ok()
}

#[cfg(crabc_general_initial_graph)]
unsafe fn file_identity_from_fd(fd: i64) -> Option<ObjectIdentity> {
    let mut stat = [0u8; X86_64_STAT_BYTE_LEN];
    if syscall2(SYS_FSTAT, fd, stat.as_mut_ptr() as i64) < 0 {
        return None;
    }
    let identity = ObjectIdentity {
        // Linux x86-64's selected 144-byte `struct stat` places `st_dev` and
        // `st_ino` at offsets zero and eight.  The graph stores both rather
        // than a pathname so aliases and repeated SONAME edges deduplicate by
        // the opened file, not by one search spelling.
        device: read_u64(stat.as_ptr()),
        inode: read_u64(stat.as_ptr().add(8)),
    };
    if identity.device == 0 && identity.inode == 0 {
        return None;
    }
    Some(identity)
}

struct MappingLease {
    address: i64,
    byte_len: u64,
}

impl Drop for MappingLease {
    fn drop(&mut self) {
        // SAFETY: every lease is created from a successful mmap result and
        // owns exactly the page-rounded span reserved by this mapper.
        unsafe {
            let _ = syscall2(SYS_MUNMAP, self.address, self.byte_len as i64);
        }
    }
}

unsafe fn map_elf(
    fd: i64,
    allow_bounded_runtime_legacy_tags: bool,
    general_initial_graph: bool,
) -> Option<Object> {
    let file_byte_len = file_size_from_fd(fd)?;
    if file_byte_len < 64 {
        return None;
    }
    let header_map_len = file_byte_len.min(PAGE);
    let first = syscall6(SYS_MMAP, 0, header_map_len as i64, PROT_READ, MAP_PRIVATE, fd, 0);
    if is_linux_error(first) {
        return None;
    }
    let header_mapping = MappingLease {
        address: first,
        byte_len: header_map_len,
    };
    let header = first as *const u8;
    let valid = *header == 0x7f && *header.add(1) == b'E' && *header.add(2) == b'L' && *header.add(3) == b'F'
        && *header.add(4) == 2 && *header.add(5) == 1 && read_u16(header.add(16)) == 3 && read_u16(header.add(18)) == 62
        && read_u16(header.add(54)) == 56;
    let phoff = usize::try_from(read_u64(header.add(32))).ok()?;
    let phnum = read_u16(header.add(56)) as usize;
    let ph_table_len = phnum.checked_mul(56)?;
    let ph_file_end = phoff.checked_add(ph_table_len)?;
    if !valid || phnum == 0 || phnum > MAX_PHDRS || ph_file_end > header_map_len as usize {
        return None;
    }
    let mut min = u64::MAX;
    let mut max = 0u64;
    for index in 0..phnum {
        let p = header.add(phoff + index * 56);
        if read_u32(p) == PT_LOAD {
            min = min.min(align_down(read_u64(p.add(16))));
            max = max.max(align_up(read_u64(p.add(16)).checked_add(read_u64(p.add(40)))?));
        }
    }
    if min == u64::MAX || max <= min {
        return None;
    }
    let reserve_len = max.checked_sub(min)?;
    let reserve = syscall6(
        SYS_MMAP,
        0,
        reserve_len as i64,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    if is_linux_error(reserve) {
        return None;
    }
    let reservation = MappingLease {
        address: reserve,
        byte_len: reserve_len,
    };
    let base = (reserve as u64).checked_sub(min)?;
    for index in 0..phnum {
        let p = header.add(phoff + index * 56);
        if read_u32(p) != PT_LOAD {
            continue;
        }
        let vaddr = read_u64(p.add(16));
        let offset = read_u64(p.add(8));
        let filesz = read_u64(p.add(32));
        let memsz = read_u64(p.add(40));
        let file_end = offset.checked_add(filesz)?;
        if filesz > memsz || file_end > file_byte_len || vaddr % PAGE != offset % PAGE {
            return None;
        }
        let page_vaddr = align_down(vaddr);
        let page_offset = align_down(offset);
        let delta = vaddr - page_vaddr;
        let map_len = align_up(filesz.checked_add(delta)?);
        if map_len != 0
            && is_linux_error(syscall6(
                SYS_MMAP,
                base.checked_add(page_vaddr)? as i64,
                map_len as i64,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_FIXED,
                fd,
                page_offset as i64,
            ))
        {
            return None;
        }
        let zero_start = base.checked_add(vaddr)?.checked_add(filesz)?;
        let zero_end = base.checked_add(vaddr)?.checked_add(memsz)?;
        if zero_end > zero_start {
            core::ptr::write_bytes(zero_start as *mut u8, 0, usize::try_from(zero_end - zero_start).ok()?);
        }
    }
    // The temporary header mapping cannot own retained program-header
    // pointers. Locate the actual PT_LOAD file bytes before it is dropped.
    let phoff_u64 = u64::try_from(phoff).ok()?;
    let ph_file_end_u64 = u64::try_from(ph_file_end).ok()?;
    let mut runtime_phdr = None;
    for index in 0..phnum {
        let p = header.add(phoff + index * 56);
        if read_u32(p) != PT_LOAD {
            continue;
        }
        let file_offset = read_u64(p.add(8));
        let file_end = file_offset.checked_add(read_u64(p.add(32)))?;
        if phoff_u64 < file_offset || ph_file_end_u64 > file_end {
            continue;
        }
        let virtual_address = read_u64(p.add(16)).checked_add(phoff_u64 - file_offset)?;
        if !virtual_range_in_load(header.add(phoff), phnum, virtual_address, ph_table_len as u64) {
            return None;
        }
        runtime_phdr = Some(runtime_address(base, virtual_address)? as *const u8);
        break;
    }
    let runtime_phdr = runtime_phdr?;
    drop(header_mapping);
    let mut object = parse_mapped(
        base,
        runtime_phdr,
        phnum,
        true,
        allow_bounded_runtime_legacy_tags,
        general_initial_graph,
    )?;
    object.map_provenance = ObjectMapProvenance::Transaction;
    object.map_span_start = reserve as u64;
    object.map_span_byte_len = reserve_len;
    // Successful callers now own the exact reservation and release it through
    // the graph rollback/unload boundary.  Every earlier error drops it.
    core::mem::forget(reservation);
    Some(object)
}

/// Assign the fixed graph's one-based GNU TLS module IDs and Variant-II
/// offsets before relocation writes use them. This is a layout plan only: it
/// neither maps a thread block nor touches `%fs`, so a later relocation or
/// mapping failure cannot leave a partially initialized thread pointer.
///
/// The offset calculation is the x86 branch of musl 1.2.6
/// `ldso/dynlink.c`'s initial TLS layout: account for the source image's
/// alignment phase rather than treating every PT_TLS image as a standalone
/// `align_up(p_memsz)` block. The fixture fixes loader order to main, mid,
/// leaf; as in musl, only TLS-bearing images receive one-based module IDs, so
/// the TLS-free main image consumes neither an ID nor a DTV slot.
unsafe fn plan_initial_tls(objects: &mut [Object; MAX_OBJECTS]) -> Option<bool> {
    let mut offset_below_tp = 0usize;
    let mut module_count = 0usize;
    let mut has_tls = false;
    #[cfg(crabc_loader_libc_tls_runtime_v1)]
    // SAFETY: this fixed interpreter has one startup transaction before it
    // transfers to application code or can create a thread. The registry is
    // mutated here once, then sealed before any shared reference is returned.
    let registry = unsafe { &mut *core::ptr::addr_of_mut!(INITIAL_TLS_RUNTIME_V1_REGISTRY) };
    for (_object_index, object) in objects.iter_mut().enumerate() {
        object.tls_module_id = 0;
        object.tls_offset_below_tp = 0;
        if object.tls_memsz == 0 {
            continue;
        }
        has_tls = true;
        if object.tls_image.is_null()
            || object.tls_filesz > object.tls_memsz
            || object.tls_align == 0
            || !object.tls_align.is_power_of_two()
        {
            return None;
        }
        let with_alignment_slack = offset_below_tp
            .checked_add(object.tls_memsz)?
            .checked_add(object.tls_align - 1)?;
        let source_phase = object.tls_image as usize & (object.tls_align - 1);
        let placement_phase = with_alignment_slack.checked_add(source_phase)?
            & (object.tls_align - 1);
        offset_below_tp = with_alignment_slack.checked_sub(placement_phase)?;
        if offset_below_tp < object.tls_memsz {
            return None;
        }
        #[cfg(crabc_loader_libc_tls_runtime_v1)]
        let module_id = registry.assign_initial(_object_index).ok()?.get();
        #[cfg(not(crabc_loader_libc_tls_runtime_v1))]
        let module_id = module_count.checked_add(1)?;
        if module_id >= TLS_DTV_WORDS {
            return None;
        }
        module_count = module_id;
        object.tls_module_id = module_id;
        object.tls_offset_below_tp = offset_below_tp;
    }
    #[cfg(crabc_loader_libc_tls_runtime_v1)]
    {
        registry.seal().ok()?;
        if registry.module_count() != module_count || registry.generation().get() != 1 {
            return None;
        }
    }
    Some(has_tls)
}

/// Returns the sealed, loader-owned initial RuntimeV1 registry.
///
/// This state stays private to the interpreter and records only generation
/// one. The fixed graph has no runtime mapping entry point, and the registry's
/// explicit growth rejection prevents that absence from becoming an implicit
/// libc or fixed-DTV fallback.
#[cfg(crabc_loader_libc_tls_runtime_v1)]
unsafe fn initial_tls_runtime_v1_registry(
    objects: &[Object; MAX_OBJECTS],
) -> Option<&'static LoaderInitialTlsRegistry> {
    // SAFETY: `plan_initial_tls` sealed this one startup-owned static before
    // this accessor runs; the fixed graph exposes no later mutation path.
    let registry = unsafe { &*core::ptr::addr_of!(INITIAL_TLS_RUNTIME_V1_REGISTRY) };
    if registry.phase() != x86_64_initial_tls_registry::RegistryPhase::Sealed
        || registry.generation().get() != 1
        || registry.module_count() >= TLS_DTV_WORDS
        || registry.reject_runtime_tls_growth(MAX_OBJECTS)
            != Err(
                x86_64_initial_tls_registry::RuntimeTlsGrowthError::DtvGrowthProtocolUnavailable,
            )
    {
        return None;
    }
    let mut module_count = 0usize;
    for (object_index, object) in objects.iter().enumerate() {
        if object.tls_memsz == 0 {
            if registry.module_id(object_index).is_some() || object.tls_module_id != 0 {
                return None;
            }
            continue;
        }
        module_count = module_count.checked_add(1)?;
        if object.tls_module_id != module_count
            || registry.module_id(object_index).map(|module_id| module_id.get())
                != Some(module_count)
            || object.tls_offset_below_tp < object.tls_memsz
        {
            return None;
        }
    }
    if registry.module_count() != module_count {
        return None;
    }
    Some(registry)
}

/// Materialize every fixed-graph initial TLS image and install its minimal
/// GNU-Dynamic x86 thread-pointer prefix.
///
/// This owns exactly one main-thread block. `%fs:0` is the self pointer and
/// `%fs:8` is a DTV with one count word followed by one one-based module slot
/// per TLS-bearing object. The prefix intentionally does not claim a full musl pthread
/// TCB, a DTV growth protocol, or a worker allocation interface.
unsafe fn install_initial_tls(
    objects: &[Object; MAX_OBJECTS],
) -> Option<InstalledInitialTls> {
    let installed = unsafe { materialize_initial_tls(objects, 0) }?;
    if syscall2(SYS_ARCH_PRCTL, ARCH_SET_FS, installed.thread_pointer as i64) < 0 {
        let _ = syscall2(SYS_MUNMAP, installed.mapping as i64, installed.mapping_byte_len as i64);
        return None;
    }
    Some(installed)
}

/// Materialize a checked initial module layout without changing the caller's
/// FS. Startup and worker construction use this same template/DTV owner.
unsafe fn materialize_initial_tls(objects: &[Object; MAX_OBJECTS], ownership_prefix: usize) -> Option<InstalledInitialTls> {
    let mut total_tls_size = 0usize;
    let mut tp_alignment = core::mem::align_of::<usize>();
    let mut module_count = 0usize;
    for object in objects {
        if object.tls_memsz == 0 {
            continue;
        }
        if object.tls_offset_below_tp < object.tls_memsz
            || object.tls_align == 0
            || !object.tls_align.is_power_of_two()
        {
            return None;
        }
        total_tls_size = total_tls_size.max(object.tls_offset_below_tp);
        tp_alignment = tp_alignment.max(object.tls_align);
        module_count = module_count.checked_add(1)?;
        if object.tls_module_id != module_count || module_count >= TLS_DTV_WORDS {
            return None;
        }
    }
    if total_tls_size == 0 || !tp_alignment.is_power_of_two() {
        return None;
    }

    let reserved_after_tp = TLS_TCB_PREFIX_SIZE
        .checked_add(TLS_DTV_BYTE_LEN)?
        .checked_add(TLS_MODULE_SIZE_TABLE_BYTE_LEN)?;
    let raw_mapping_size = total_tls_size
        .checked_add(ownership_prefix)?
        .checked_add(reserved_after_tp)?
        // `align_down` may discard almost one complete TP-alignment unit.
        .checked_add(tp_alignment)?;
    let mapping_size = align_up_usize(raw_mapping_size, PAGE as usize)?;
    let mapping = syscall6(
        SYS_MMAP,
        0,
        mapping_size as i64,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    if is_linux_error(mapping) {
        return None;
    }
    let block = mapping as usize;
    let mapping_end = block.checked_add(mapping_size)?;
    let unaligned_tp = mapping_end.checked_sub(reserved_after_tp)?;
    let thread_pointer = align_down_usize(unaligned_tp, tp_alignment);
    let tls_start = thread_pointer.checked_sub(total_tls_size)?;
    let dtv_end = thread_pointer.checked_add(reserved_after_tp)?;
    if tls_start < block.checked_add(ownership_prefix)? || dtv_end > mapping_end {
        let _ = syscall2(SYS_MUNMAP, mapping, mapping_size as i64);
        return None;
    }

    let tcb = thread_pointer as *mut u8;
    let dtv = tcb.add(TLS_TCB_PREFIX_SIZE) as *mut usize;
    let module_sizes = (dtv as *mut u8).add(TLS_DTV_BYTE_LEN) as *mut usize;
    // SAFETY: the fresh anonymous mapping spans the checked TCB/DTV ranges;
    // no application code can observe it until ARCH_SET_FS succeeds below.
    core::ptr::write_unaligned(tcb as *mut usize, thread_pointer);
    core::ptr::write_unaligned(tcb.add(core::mem::size_of::<usize>()) as *mut usize, dtv as usize);
    core::ptr::write_unaligned(
        tcb.add(TLS_TCB_MODULE_SIZE_TABLE_OFFSET) as *mut usize,
        module_sizes as usize,
    );
    core::ptr::write_unaligned(dtv, module_count);
    for module_id in 1..TLS_DTV_WORDS {
        core::ptr::write_unaligned(dtv.add(module_id), 0);
        core::ptr::write_unaligned(module_sizes.add(module_id), 0);
    }

    for object in objects {
        if object.tls_memsz == 0 {
            continue;
        }
        if object.tls_module_id == 0 || object.tls_module_id >= TLS_DTV_WORDS {
            let _ = syscall2(SYS_MUNMAP, mapping, mapping_size as i64);
            return None;
        }
        let destination = thread_pointer.checked_sub(object.tls_offset_below_tp)? as *mut u8;
        if object.tls_filesz != 0 {
            core::ptr::copy_nonoverlapping(object.tls_image, destination, object.tls_filesz);
        }
        if object.tls_memsz > object.tls_filesz {
            core::ptr::write_bytes(
                destination.add(object.tls_filesz),
                0,
                object.tls_memsz - object.tls_filesz,
            );
        }
        core::ptr::write_unaligned(dtv.add(object.tls_module_id), destination as usize);
        core::ptr::write_unaligned(module_sizes.add(object.tls_module_id), object.tls_memsz);
    }
    Some(InstalledInitialTls {
        mapping: mapping as *mut u8,
        mapping_byte_len: mapping_size,
        thread_pointer: tcb,
        dtv,
        dtv_words: TLS_DTV_WORDS,
        module_count,
    })
}

/// Publish the one loader-owned RuntimeV1 record after a complete initial TLS
/// materialization.
///
/// This is a one-shot startup handoff, not a dynamic TLS registry mutation.
/// The fixed graph has no operation that can add a TLS module, replace the
/// DTV, advance the generation, or reclaim the initial block. Deliberately
/// poison the malformed-fixture coordinates after their metadata is fixed so
/// the freestanding libc negative tests prove validation occurs before any
/// consumer TCB/DTV dereference. The six metadata variants retain valid
/// coordinates so no later pointer guard can mask an omitted metadata check.
#[cfg(crabc_loader_libc_tls_runtime_v1)]
unsafe fn publish_loader_tls_runtime_v1(
    installed: InstalledInitialTls,
    registry: &LoaderInitialTlsRegistry,
) -> Option<()> {
    if registry.phase() != x86_64_initial_tls_registry::RegistryPhase::Sealed
        || registry.generation().get() != 1
        || registry.module_count() != installed.module_count
        || registry.module_count() >= installed.dtv_words
    {
        return None;
    }
    let record = core::ptr::addr_of_mut!(__crabc_x86_64_loader_tls_runtime_v1);
    if unsafe {
        (*record).state.compare_exchange(
            LOADER_TLS_RUNTIME_V1_STATE_UNPUBLISHED,
            LOADER_TLS_RUNTIME_V1_STATE_PUBLISHING,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
    }
    .is_err()
    {
        return None;
    }

    let poisoned_dtv = cfg!(crabc_loader_libc_tls_runtime_v1_poisoned_dtv);
    let (thread_pointer, dtv, dtv_words, module_count) = if poisoned_dtv {
        // `1` is intentionally not an aligned Linux x86-64 DTV address. The
        // thread pointer remains valid so an accidental DTV read reaches this
        // poison rather than being hidden by the earlier thread-pointer
        // comparison. Every metadata variant below uses the valid branch.
        (
            installed.thread_pointer.cast_const(),
            1usize as *const usize,
            installed.dtv_words,
            installed.module_count,
        )
    } else {
        (
            installed.thread_pointer.cast_const(),
            installed.dtv.cast_const(),
            installed.dtv_words,
            installed.module_count,
        )
    };
    if !poisoned_dtv
        && (thread_pointer.is_null()
            || dtv.is_null()
            || module_count == 0
            || dtv_words < module_count.checked_add(1)?)
    {
        unsafe {
            (*record)
                .state
                .store(LOADER_TLS_RUNTIME_V1_STATE_UNPUBLISHED, Ordering::Release);
        }
        return None;
    }

    unsafe {
        (*record).thread_pointer = thread_pointer;
        (*record).dtv = dtv;
        (*record).dtv_words = dtv_words;
        (*record).module_count = module_count;
        // The metadata values above are initialized in the static record and
        // never changed by this fixture. Publish the coordinates only after
        // every field has been written.
        (*record)
            .state
            .store(LOADER_TLS_RUNTIME_V1_STATE_READY, Ordering::Release);
    }
    Some(())
}

#[repr(C)]
pub struct TlsIndex {
    ti_module: usize,
    ti_offset: usize,
}

/// Resolve the private fixed-graph GNU TLS index ABI from the minimal DTV at
/// `%fs:8`.
///
/// # Safety
///
/// `index` must point to a readable [`TlsIndex`]. Its module ID must identify
/// a TLS-bearing image materialized by this fixed graph, and its offset must
/// be the ABI offset of a symbol in that module (or its one-past boundary).
/// The resolver returns null for an unmaterialized module or an offset outside
/// that module's recorded `PT_TLS.p_memsz`; it cannot establish that a
/// non-null result is safe for a caller's eventual typed dereference. This
/// private exported ELF symbol is not an installed or public x86 API.
#[no_mangle]
pub unsafe extern "C" fn __tls_get_addr(index: *const TlsIndex) -> *mut c_void {
    if index.is_null() {
        return core::ptr::null_mut();
    }
    let module_id = core::ptr::read_unaligned(core::ptr::addr_of!((*index).ti_module));
    let offset = core::ptr::read_unaligned(core::ptr::addr_of!((*index).ti_offset));
    let thread_pointer = read_thread_pointer();
    if thread_pointer == 0 {
        return core::ptr::null_mut();
    }
    let dtv = core::ptr::read_unaligned(
        (thread_pointer as *const u8).add(core::mem::size_of::<usize>()) as *const usize,
    ) as *const usize;
    if dtv.is_null() {
        return core::ptr::null_mut();
    }
    let module_sizes = core::ptr::read_unaligned(
        (thread_pointer as *const u8).add(TLS_TCB_MODULE_SIZE_TABLE_OFFSET) as *const usize,
    ) as *const usize;
    if module_sizes.is_null() {
        return core::ptr::null_mut();
    }
    let module_count = core::ptr::read_unaligned(dtv);
    if module_id == 0 || module_id > module_count || module_id >= TLS_DTV_WORDS {
        return core::ptr::null_mut();
    }
    let module_base = core::ptr::read_unaligned(dtv.add(module_id));
    let module_size = core::ptr::read_unaligned(module_sizes.add(module_id));
    if module_size == 0 || offset > module_size {
        return core::ptr::null_mut();
    }
    match module_base.checked_add(offset) {
        Some(address) if module_base != 0 => address as *mut c_void,
        _ => core::ptr::null_mut(),
    }
}

unsafe fn relocate(object: &Object, objects: &[Object; MAX_OBJECTS]) -> Option<()> {
    // Do not let a malformed table change an earlier target before the graph
    // discovers that another table or packed bitmap is invalid. The fixed
    // stack block records every target in this bounded fixture, rejects table
    // writes and duplicate destinations, then permits the actual RELA-before-
    // RELR transaction.
    preflight_relocation_table_layout(object)?;
    let mut targets = [0u64; MAX_RELOCATION_TARGETS];
    let mut target_count = 0usize;
    target_count = preflight_rela_table(
        object,
        objects,
        object.rela,
        object.relasz,
        &mut targets,
        target_count,
    )?;
    target_count = preflight_rela_table(
        object,
        objects,
        object.jmprel,
        object.pltrelsz,
        &mut targets,
        target_count,
    )?;
    target_count = preflight_relr_table(object, &mut targets, target_count)?;
    let used_targets = &mut targets[..target_count];
    used_targets.sort_unstable();
    if used_targets.windows(2).any(|pair| pair[0] == pair[1]) {
        return None;
    }

    apply_rela_table(object, objects, object.rela, object.relasz)?;
    apply_rela_table(object, objects, object.jmprel, object.pltrelsz)?;
    apply_relr_table(object)
}

fn preflight_relocation_table_layout(object: &Object) -> Option<()> {
    let tables = [
        (object.rela, object.relasz),
        (object.jmprel, object.pltrelsz),
        (object.relr, object.relrsz),
    ];
    for (index, (table, byte_len)) in tables.iter().copied().enumerate() {
        if byte_len == 0 {
            continue;
        }
        if table.is_null() {
            return None;
        }
        let byte_len = u64::try_from(byte_len).ok()?;
        for (other_table, other_byte_len) in tables[index + 1..].iter().copied() {
            if other_byte_len == 0 {
                continue;
            }
            if other_table.is_null()
                || ranges_overlap(
                    table as u64,
                    byte_len,
                    other_table as u64,
                    u64::try_from(other_byte_len).ok()?,
                )?
            {
                return None;
            }
        }
    }
    Some(())
}

unsafe fn preflight_rela_table(
    object: &Object,
    objects: &[Object; MAX_OBJECTS],
    table: *const u8,
    length: usize,
    targets: &mut [u64; MAX_RELOCATION_TARGETS],
    mut target_count: usize,
) -> Option<usize> {
    if length == 0 {
        return Some(target_count);
    }
    if table.is_null() || length % ELF64_RELA_SIZE != 0 {
        return None;
    }
    for index in 0..(length / ELF64_RELA_SIZE) {
        let rela = table.add(index * ELF64_RELA_SIZE);
        let relocation_offset = read_u64(rela);
        preflight_relocation_target(object, relocation_offset)?;
        let info = read_u64(rela.add(8));
        let kind = info as u32;
        let symbol = (info >> 32) as usize;
        let addend = read_i64(rela.add(16));
        let _ = relocation_value(kind, object, objects, symbol, addend)?;
        target_count = record_relocation_target(targets, target_count, relocation_offset)?;
    }
    Some(target_count)
}

unsafe fn preflight_relr_table(
    object: &Object,
    targets: &mut [u64; MAX_RELOCATION_TARGETS],
    mut target_count: usize,
) -> Option<usize> {
    if object.relrsz == 0 {
        return Some(target_count);
    }
    if object.relr.is_null()
        || object.relrsz % ELF64_RELR_SIZE != 0
        || object.relrsz > MAX_RELR_BYTE_LEN
    {
        return None;
    }
    let mut next_virtual_address = None;
    for index in 0..(object.relrsz / ELF64_RELR_SIZE) {
        let encoded = read_u64(object.relr.add(index * ELF64_RELR_SIZE));
        if encoded & 1 == 0 {
            preflight_relr_target(object, encoded)?;
            target_count = record_relocation_target(targets, target_count, encoded)?;
            next_virtual_address = Some(encoded.checked_add(ELF64_RELR_SIZE as u64)?);
            continue;
        }

        let start = next_virtual_address?;
        let bitmap = encoded >> 1;
        for bit in 0..ELF64_RELR_BITMAP_BITS {
            if bitmap & (1u64 << bit) == 0 {
                continue;
            }
            let target = start.checked_add(bit.checked_mul(ELF64_RELR_SIZE as u64)?)?;
            preflight_relr_target(object, target)?;
            target_count = record_relocation_target(targets, target_count, target)?;
        }
        next_virtual_address = Some(
            start.checked_add(ELF64_RELR_BITMAP_BITS.checked_mul(ELF64_RELR_SIZE as u64)?)?,
        );
    }
    Some(target_count)
}

unsafe fn preflight_relr_target(object: &Object, virtual_address: u64) -> Option<()> {
    preflight_relocation_target(object, virtual_address)?;
    let address = runtime_address(object.base, virtual_address)?;
    // Packed RELR uses the preexisting pointer word as its addend. Check this
    // arithmetic before any table changes, matching musl's add-the-load-bias
    // operation while failing closed on an overflowing malformed input.
    let addend = read_u64(address as *const u8);
    let _ = addend.checked_add(object.base)?;
    Some(())
}

unsafe fn preflight_relocation_target(object: &Object, virtual_address: u64) -> Option<()> {
    if virtual_address & (ELF64_RELR_SIZE as u64 - 1) != 0
        || !virtual_range_in_writable_load(object.phdr, object.phnum, virtual_address, ELF64_RELR_SIZE as u64)
    {
        return None;
    }
    let address = runtime_address(object.base, virtual_address)?;
    for (table, byte_len) in [
        (object.rela, object.relasz),
        (object.jmprel, object.pltrelsz),
        (object.relr, object.relrsz),
    ] {
        if byte_len == 0 {
            continue;
        }
        if table.is_null()
            || ranges_overlap(address, ELF64_RELR_SIZE as u64, table as u64, byte_len as u64)?
        {
            return None;
        }
    }
    Some(())
}

fn record_relocation_target(
    targets: &mut [u64; MAX_RELOCATION_TARGETS],
    count: usize,
    virtual_address: u64,
) -> Option<usize> {
    let slot = targets.get_mut(count)?;
    *slot = virtual_address;
    count.checked_add(1)
}

unsafe fn apply_rela_table(
    object: &Object,
    objects: &[Object; MAX_OBJECTS],
    table: *const u8,
    length: usize,
) -> Option<()> {
    if length == 0 { return Some(()); }
    if table.is_null() || length % ELF64_RELA_SIZE != 0 { return None; }
    for index in 0..(length / ELF64_RELA_SIZE) {
        let rela = table.add(index * ELF64_RELA_SIZE);
        let relocation_offset = read_u64(rela);
        let slot = runtime_address(object.base, relocation_offset)? as *mut u64;
        let info = read_u64(rela.add(8));
        let kind = info as u32;
        let symbol = (info >> 32) as usize;
        let addend = read_i64(rela.add(16));
        let value = relocation_value(kind, object, objects, symbol, addend)?;
        *slot = value;
    }
    Some(())
}

unsafe fn apply_relr_table(object: &Object) -> Option<()> {
    if object.relrsz == 0 {
        return Some(());
    }
    if object.relr.is_null()
        || object.relrsz % ELF64_RELR_SIZE != 0
        || object.relrsz > MAX_RELR_BYTE_LEN
    {
        return None;
    }
    let mut next_virtual_address = None;
    for index in 0..(object.relrsz / ELF64_RELR_SIZE) {
        let encoded = read_u64(object.relr.add(index * ELF64_RELR_SIZE));
        if encoded & 1 == 0 {
            apply_relr_target(object, encoded)?;
            next_virtual_address = Some(encoded.checked_add(ELF64_RELR_SIZE as u64)?);
            continue;
        }

        let start = next_virtual_address?;
        let bitmap = encoded >> 1;
        for bit in 0..ELF64_RELR_BITMAP_BITS {
            if bitmap & (1u64 << bit) != 0 {
                let target = start.checked_add(bit.checked_mul(ELF64_RELR_SIZE as u64)?)?;
                apply_relr_target(object, target)?;
            }
        }
        next_virtual_address = Some(
            start.checked_add(ELF64_RELR_BITMAP_BITS.checked_mul(ELF64_RELR_SIZE as u64)?)?,
        );
    }
    Some(())
}

unsafe fn apply_relr_target(object: &Object, virtual_address: u64) -> Option<()> {
    let slot = runtime_address(object.base, virtual_address)? as *mut u64;
    *slot = (*slot).checked_add(object.base)?;
    Some(())
}

/// Evaluate the constrained relocation vocabulary before a relocation table
/// changes any destination word. The GNU-Dynamic TLS pair uses module IDs and
/// module-relative offsets; TP-relative initial-exec and descriptor records
/// deliberately remain a later loader boundary.
unsafe fn relocation_value(
    kind: u32,
    requestor: &Object,
    objects: &[Object; MAX_OBJECTS],
    symbol: usize,
    addend: i64,
) -> Option<u64> {
    // Rust-produced Scrt1.o always retains this optional owned-CRT object
    // import. The dynamic-main-thread bridge intentionally does not publish
    // the fixed 32-byte carrier: it admits only this exact ordinary weak-null
    // form so Scrt1 preserves its musl-shaped null finalizer. Classify it
    // before generic lookup, otherwise a DSO definition could interpose or a
    // different relocation form could accidentally become loader policy.
    #[cfg(crabc_dynamic_main_thread_runtime_v1)]
    if symbol != 0 && symbol < requestor.symcount {
        let requested = requestor.symtab.add(symbol * 24);
        let name_offset = read_u32(requested) as usize;
        if name_offset < requestor.strsz {
            let name = requestor.strtab.add(name_offset);
            if matches!(
                bounded_nul(name, requestor.strsz - name_offset),
                Some(length)
                    if length == b"__crabc_x86_64_owned_crt_handoff".len()
                        && bytes_eq(
                            name,
                            b"__crabc_x86_64_owned_crt_handoff".as_ptr(),
                            length,
                        )
            ) {
                let is_main = !requestor.mapped
                    && requestor.base == objects[0].base
                    && requestor.phdr == objects[0].phdr;
                let binding = *requested.add(4) >> 4;
                let symbol_type = *requested.add(4) & 0x0f;
                let visibility = *requested.add(5) & 0x03;
                let section = read_u16(requested.add(6));
                if kind == R_X86_64_GLOB_DAT
                    && addend == 0
                    && is_main
                    && binding == 2
                    && symbol_type == 1
                    && visibility == 0
                    && section == 0
                {
                    #[cfg(crabc_general_initial_lifecycle)]
                    return Some(x86_64_general_initial_lifecycle::owned_crt_handoff_address());
                    #[cfg(not(crabc_general_initial_lifecycle))]
                    return Some(0);
                }
                return None;
            }
        }
    }
    match kind {
        R_X86_64_RELATIVE if symbol == 0 => add_signed(requestor.base, addend),
        R_X86_64_GLOB_DAT | R_X86_64_JUMP_SLOT => {
            add_signed(resolve_symbol(requestor, objects, symbol)?, addend)
        }
        #[cfg(any(
            crabc_initial_tls_graph,
            crabc_initial_exec_tls_graph,
            crabc_general_initial_tls_materialization_v1
        ))]
        R_X86_64_DTPMOD64 => {
            if addend != 0 {
                return None;
            }
            let (module_id, _, _) = resolve_tls_symbol(requestor, objects, symbol)?;
            u64::try_from(module_id).ok()
        }
        #[cfg(any(
            crabc_initial_tls_graph,
            crabc_initial_exec_tls_graph,
            crabc_general_initial_tls_materialization_v1
        ))]
        R_X86_64_DTPOFF64 => {
            let (_, symbol_offset, module_memsz) = resolve_tls_symbol(requestor, objects, symbol)?;
            let offset = add_signed(symbol_offset, addend)?;
            if offset > module_memsz as u64 {
                return None;
            }
            Some(offset)
        }
        #[cfg(not(any(
            crabc_initial_tls_graph,
            crabc_initial_exec_tls_graph,
            crabc_general_initial_tls_materialization_v1
        )))]
        R_X86_64_DTPMOD64 | R_X86_64_DTPOFF64 => None,
        #[cfg(crabc_initial_exec_tls_graph)]
        R_X86_64_TPOFF64 => {
            // The admitted initial-exec relocation is intentionally more
            // constrained than a generic static-TLS policy: it must be the
            // fixed leaf's local definition and uses no addend.  That keeps
            // the established GNU-Dynamic graph and every other TPOFF route
            // on the fail-closed side of the boundary.
            if addend != 0
                || !requestor.static_tls
                || !relocation_symbol_name_is(requestor, symbol, b"leaf_initial_exec_tls")
            {
                return None;
            }
            let (module_id, symbol_offset, module_memsz) =
                resolve_tls_symbol(requestor, objects, symbol)?;
            let owner = objects
                .iter()
                .find(|object| object.tls_module_id == module_id)?;
            if !owner.static_tls
                || module_id != requestor.tls_module_id
                || symbol_offset >= module_memsz as u64
                || owner.tls_offset_below_tp < owner.tls_memsz
            {
                return None;
            }
            let symbol_offset = i64::try_from(symbol_offset).ok()?;
            let placement = i64::try_from(owner.tls_offset_below_tp).ok()?;
            Some(symbol_offset.checked_sub(placement)? as u64)
        }
        // Naming these rejected forms makes this source's boundary auditable:
        // no GOTTPOFF/TPOFF32 admission and no TLSDESC resolver are implied
        // by the GNU-Dynamic DTV implementation or its fixed-TPOFF sibling.
        #[cfg(not(crabc_initial_exec_tls_graph))]
        R_X86_64_TPOFF64
        | R_X86_64_GOTTPOFF
        | R_X86_64_TPOFF32
        | R_X86_64_GOTPC32_TLSDESC
        | R_X86_64_TLSDESC_CALL
        | R_X86_64_TLSDESC => None,
        #[cfg(crabc_initial_exec_tls_graph)]
        R_X86_64_GOTTPOFF
        | R_X86_64_TPOFF32
        | R_X86_64_GOTPC32_TLSDESC
        | R_X86_64_TLSDESC_CALL
        | R_X86_64_TLSDESC => None,
        _ => None,
    }
}

/// The fixed initial-exec sibling admits one named leaf definition.  This is
/// intentionally fixture topology, not a global symbol-lookup rule.
#[cfg(crabc_initial_exec_tls_graph)]
unsafe fn relocation_symbol_name_is(requestor: &Object, index: usize, wanted: &[u8]) -> bool {
    if index == 0 || index >= requestor.symcount {
        return false;
    }
    let symbol = requestor.symtab.add(index * 24);
    let name_offset = read_u32(symbol) as usize;
    if name_offset >= requestor.strsz || *symbol.add(4) & 0x0f != 6 {
        return false;
    }
    let name = requestor.strtab.add(name_offset);
    matches!(
        bounded_nul(name, requestor.strsz - name_offset),
        Some(length) if length == wanted.len() && bytes_eq(name, wanted.as_ptr(), length)
    )
}

unsafe fn resolve_symbol(requestor: &Object, objects: &[Object; MAX_OBJECTS], index: usize) -> Option<u64> {
    if index >= requestor.symcount { return None; }
    let symbol = requestor.symtab.add(index * 24);
    let name_offset = read_u32(symbol) as usize;
    if name_offset >= requestor.strsz { return None; }
    let name = requestor.strtab.add(name_offset);
    let len = bounded_nul(name, requestor.strsz - name_offset)?;
    // The initial TLS sibling has no libc object. Its direct `__tls_get_addr`
    // import is resolved by that interpreter only; compile this special scope
    // out of the older no-TLS artifact so it cannot silently widen its
    // ordinary GLOB_DAT/JUMP_SLOT lookup contract.
    #[cfg(any(
        crabc_initial_tls_graph,
        crabc_initial_exec_tls_graph,
        crabc_general_initial_tls_materialization_v1
    ))]
    if len == b"__tls_get_addr".len() && bytes_eq(name, b"__tls_get_addr".as_ptr(), len) {
        return Some(__tls_get_addr as *const () as usize as u64);
    }
    // The first RuntimeV1 handoff is one explicit weak data import from the
    // freestanding libc-side consumer in the main image. It is not normal
    // global lookup: a DSO request, a defined main symbol, or a strong import
    // is rejected before this loader-owned TLS descriptor can cross into
    // libc. That keeps static mode outside this private initial-TLS seam. A
    // separately cfg-selected general RuntimeV1 wire reaches the same private
    // symbol only through its own loader-owned descriptor record below; it
    // does not make this fixed special case into general symbol lookup.
    #[cfg(crabc_loader_libc_tls_runtime_v1)]
    if len == b"__crabc_x86_64_loader_tls_runtime_v1".len()
        && bytes_eq(
            name,
            b"__crabc_x86_64_loader_tls_runtime_v1".as_ptr(),
            len,
        )
    {
        let is_main = !requestor.mapped
            && requestor.base == objects[0].base
            && requestor.phdr == objects[0].phdr;
        let binding = *symbol.add(4) >> 4;
        let section = read_u16(symbol.add(6));
        if !is_main || binding != 2 || section != 0 {
            return None;
        }
        return Some(core::ptr::addr_of!(__crabc_x86_64_loader_tls_runtime_v1) as usize as u64);
    }
    // The arbitrary initial-TLS graph has a distinct producer with the same
    // private 72-byte ABI. Its cfg is disjoint from the fixed seam above, and
    // its publication reservation occurs before ARCH_SET_FS in the retained
    // general TLS state. This remains one exact weak main-image data import,
    // never an ambient loader symbol-resolution rule.
    #[cfg(crabc_general_loader_libc_tls_runtime_v1)]
    if len == b"__crabc_x86_64_loader_tls_runtime_v1".len()
        && bytes_eq(
            name,
            b"__crabc_x86_64_loader_tls_runtime_v1".as_ptr(),
            len,
        )
    {
        let is_main = !requestor.mapped
            && requestor.base == objects[0].base
            && requestor.phdr == objects[0].phdr;
        let binding = *symbol.add(4) >> 4;
        let section = read_u16(symbol.add(6));
        if !is_main || binding != 2 || section != 0 {
            return None;
        }
        return Some(
            x86_64_general_initial_tls_state::loader_tls_runtime_v1_record_address(),
        );
    }
    // The owned-CRT handoff is one explicit weak data import from the one
    // Rust-Scrt1 main image.  It is not a normal global lookup: accepting a
    // DSO request, a defined main symbol, or a strong import would turn this
    // private post-relocation wire into ambient loader policy.
    #[cfg(crabc_owned_crt_handoff)]
    if len == b"__crabc_x86_64_owned_crt_handoff".len()
        && bytes_eq(
            name,
            b"__crabc_x86_64_owned_crt_handoff".as_ptr(),
            len,
        )
    {
        let is_main = !requestor.mapped
            && requestor.base == objects[0].base
            && requestor.phdr == objects[0].phdr;
        let binding = *symbol.add(4) >> 4;
        let section = read_u16(symbol.add(6));
        if !is_main || binding != 2 || section != 0 {
            return None;
        }
        return Some(core::ptr::addr_of!(__crabc_x86_64_owned_crt_handoff) as usize as u64);
    }
    // The introspection sibling has one explicit weak record import from its
    // fixed main image. Like the owned-CRT record above, this is not ambient
    // global lookup policy: DSOs, strong imports, and definitions are rejected
    // before the interpreter address can cross the relocation boundary.
    #[cfg(crabc_fixed_graph_introspection)]
    if len == b"__crabc_x86_64_fixed_graph_introspection_v1".len()
        && bytes_eq(
            name,
            b"__crabc_x86_64_fixed_graph_introspection_v1".as_ptr(),
            len,
        )
    {
        let is_main = !requestor.mapped
            && requestor.base == objects[0].base
            && requestor.phdr == objects[0].phdr;
        let binding = *symbol.add(4) >> 4;
        let section = read_u16(symbol.add(6));
        if !is_main || binding != 2 || section != 0 {
            return None;
        }
        return Some(
            core::ptr::addr_of!(__crabc_x86_64_fixed_graph_introspection_v1) as usize as u64,
        );
    }
    // The dlfcn sibling exposes a different exact weak record only to its
    // fixed main image. It cannot be imported strongly, defined by the main,
    // or requested by either DSO.
    #[cfg(crabc_fixed_graph_dlfcn)]
    if len == b"__crabc_x86_64_fixed_graph_dlfcn_v1".len()
        && bytes_eq(
            name,
            b"__crabc_x86_64_fixed_graph_dlfcn_v1".as_ptr(),
            len,
        )
    {
        let is_main = !requestor.mapped
            && requestor.base == objects[0].base
            && requestor.phdr == objects[0].phdr;
        let binding = *symbol.add(4) >> 4;
        let section = read_u16(symbol.add(6));
        if !is_main || binding != 2 || section != 0 {
            return None;
        }
        return Some(core::ptr::addr_of!(__crabc_x86_64_fixed_graph_dlfcn_v1) as usize as u64);
    }
    for object in objects {
        for candidate in 1..object.symcount {
            let symbol = object.symtab.add(candidate * 24);
            if read_u16(symbol.add(6)) == 0 { continue; }
            if *symbol.add(4) & 0x0f == 6 {
                // STT_TLS has an offset in a module image, not an ordinary
                // runtime virtual address. Only the DTP* relocation path may
                // consume it.
                continue;
            }
            let candidate_offset = read_u32(symbol) as usize;
            if candidate_offset >= object.strsz { continue; }
            let candidate_name = object.strtab.add(candidate_offset);
            let Some(candidate_len) = bounded_nul(candidate_name, object.strsz - candidate_offset) else { continue; };
            if candidate_len == len && bytes_eq(name, candidate_name, len) {
                let address = read_u64(symbol.add(8));
                if !virtual_range_in_load(object.phdr, object.phnum, address, 1) { return None; }
                return runtime_address(object.base, address);
            }
        }
    }
    None
}

/// Resolve a dynamic-symbol-table TLS definition to its fixed-graph module
/// index and module-relative `st_value` offset.
#[cfg(any(
    crabc_initial_tls_graph,
    crabc_initial_exec_tls_graph,
    crabc_general_initial_tls_materialization_v1
))]
unsafe fn resolve_tls_symbol(
    requestor: &Object,
    objects: &[Object; MAX_OBJECTS],
    index: usize,
) -> Option<(usize, u64, usize)> {
    if index == 0 {
        for object in objects {
            if object.base == requestor.base
                && object.phdr == requestor.phdr
                && object.tls_memsz != 0
                && object.tls_module_id != 0
            {
                return Some((object.tls_module_id, 0, object.tls_memsz));
            }
        }
        return None;
    }
    if index >= requestor.symcount {
        return None;
    }
    let requested = requestor.symtab.add(index * 24);
    let name_offset = read_u32(requested) as usize;
    if name_offset >= requestor.strsz || *requested.add(4) & 0x0f != 6 {
        return None;
    }
    let name = requestor.strtab.add(name_offset);
    let name_len = bounded_nul(name, requestor.strsz - name_offset)?;
    for object in objects {
        if object.tls_memsz == 0 {
            continue;
        }
        for candidate in 1..object.symcount {
            let definition = object.symtab.add(candidate * 24);
            if read_u16(definition.add(6)) == 0 || *definition.add(4) & 0x0f != 6 {
                continue;
            }
            let definition_name_offset = read_u32(definition) as usize;
            if definition_name_offset >= object.strsz {
                continue;
            }
            let definition_name = object.strtab.add(definition_name_offset);
            let Some(definition_len) = bounded_nul(definition_name, object.strsz - definition_name_offset) else {
                continue;
            };
            if definition_len == name_len && bytes_eq(name, definition_name, name_len) {
                let offset = read_u64(definition.add(8));
                if offset > object.tls_memsz as u64 {
                    return None;
                }
                if object.tls_module_id == 0 {
                    return None;
                }
                return Some((object.tls_module_id, offset, object.tls_memsz));
            }
        }
    }
    None
}

unsafe fn protect_segments(object: &Object) -> Option<()> {
    if !object.mapped { return Some(()); }
    for index in 0..object.phnum {
        let p = object.phdr.add(index * 56);
        if read_u32(p) != PT_LOAD { continue; }
        let flags = read_u32(p.add(4));
        let start = object.base + align_down(read_u64(p.add(16)));
        let end = object.base + align_up(read_u64(p.add(16)).checked_add(read_u64(p.add(40)))?);
        let mut protection = 0;
        if flags & PF_R != 0 { protection |= PROT_READ; }
        if flags & PF_W != 0 { protection |= PROT_WRITE; }
        if flags & PF_X != 0 { protection |= PROT_EXEC; }
        if end > start && syscall3(SYS_MPROTECT, start as i64, (end - start) as i64, protection) < 0 { return None; }
    }
    Some(())
}

unsafe fn apply_relro(object: &Object) -> Option<()> {
    apply_relro_span(
        object.base,
        object.relro_virtual_address,
        object.relro_byte_len,
    )
}

unsafe fn apply_self_relro(base: u64) -> Option<()> {
    let header = base as *const u8;
    if *header != 0x7f || *header.add(1) != b'E' || *header.add(2) != b'L' || *header.add(3) != b'F'
        || *header.add(4) != 2 || *header.add(5) != 1 || read_u16(header.add(16)) != 3
        || read_u16(header.add(18)) != 62 || read_u16(header.add(54)) != 56
    {
        return None;
    }
    let phoff = usize::try_from(read_u64(header.add(32))).ok()?;
    let phnum = read_u16(header.add(56)) as usize;
    if phnum == 0 || phnum > MAX_PHDRS || phoff.checked_add(phnum.checked_mul(56)?)? < phoff {
        return None;
    }
    let phdr = header.add(phoff);
    let mut relro = None;
    for index in 0..phnum {
        let program_header = phdr.add(index * 56);
        if read_u32(program_header) != PT_GNU_RELRO { continue; }
        let address = read_u64(program_header.add(16));
        let byte_len = read_u64(program_header.add(40));
        if relro.replace((address, byte_len)).is_some() || byte_len == 0
            || !virtual_range_in_page_mapped_load(phdr, phnum, address, byte_len)
        {
            return None;
        }
    }
    let (address, byte_len) = relro?;
    apply_relro_span(base, address, byte_len)
}

unsafe fn apply_relro_span(base: u64, virtual_address: u64, byte_len: u64) -> Option<()> {
    if byte_len == 0 { return Some(()); }
    let start = align_down(base.checked_add(virtual_address)?);
    let end = align_up(base.checked_add(virtual_address)?.checked_add(byte_len)?);
    if end <= start || syscall3(SYS_MPROTECT, start as i64, (end - start) as i64, PROT_READ) < 0 { return None; }
    Some(())
}

#[cfg(any(crabc_fixed_graph_introspection, crabc_fixed_graph_dlfcn))]
unsafe fn fixed_graph_text_from_bytes(source: *const u8, source_len: usize) -> FixedGraphTextV1 {
    let mut text = EMPTY_FIXED_GRAPH_TEXT;
    let copied = core::cmp::min(source_len, FIXED_GRAPH_TEXT_CAPACITY);
    for index in 0..copied {
        text.bytes[index] = *source.add(index);
    }
    text.len = copied as u16;
    text.flags = (copied < source_len) as u16;
    text
}

#[cfg(any(crabc_fixed_graph_introspection, crabc_fixed_graph_dlfcn))]
unsafe fn fixed_graph_clear_error(error: *mut FixedGraphTextV1) {
    if !error.is_null() {
        core::ptr::write(error, EMPTY_FIXED_GRAPH_TEXT);
    }
}

#[cfg(any(crabc_fixed_graph_introspection, crabc_fixed_graph_dlfcn))]
unsafe fn fixed_graph_set_error(error: *mut FixedGraphTextV1, message: &[u8]) {
    if !error.is_null() {
        core::ptr::write(
            error,
            fixed_graph_text_from_bytes(message.as_ptr(), message.len()),
        );
    }
}

#[cfg(any(crabc_fixed_graph_introspection, crabc_fixed_graph_dlfcn))]
unsafe fn fixed_graph_object(index: usize) -> Object {
    core::ptr::read(
        core::ptr::addr_of!(FIXED_GRAPH_RUNTIME_OBJECTS)
            .cast::<Object>()
            .add(index),
    )
}

#[cfg(any(crabc_fixed_graph_introspection, crabc_fixed_graph_dlfcn))]
unsafe fn fixed_graph_name(index: usize) -> FixedGraphTextV1 {
    let name = core::ptr::addr_of!(FIXED_GRAPH_RUNTIME_NAMES)
        .cast::<u8>()
        .add(index * FIXED_GRAPH_TEXT_CAPACITY);
    let len = bounded_nul(name, FIXED_GRAPH_TEXT_CAPACITY).unwrap_or(FIXED_GRAPH_TEXT_CAPACITY);
    fixed_graph_text_from_bytes(name, len)
}

#[cfg(any(crabc_fixed_graph_introspection, crabc_fixed_graph_dlfcn))]
unsafe fn fixed_graph_store_name(index: usize, source: *const u8, maximum: usize) -> Option<()> {
    if index >= MAX_OBJECTS || source.is_null() {
        return None;
    }
    let length = bounded_nul(source, maximum)?;
    if length >= FIXED_GRAPH_TEXT_CAPACITY {
        return None;
    }
    let destination = core::ptr::addr_of_mut!(FIXED_GRAPH_RUNTIME_NAMES)
        .cast::<u8>()
        .add(index * FIXED_GRAPH_TEXT_CAPACITY);
    for offset in 0..length {
        core::ptr::write(destination.add(offset), *source.add(offset));
    }
    core::ptr::write(destination.add(length), 0);
    Some(())
}

/// Publish the actual post-constructor object records for process-lifetime
/// observation and retained-object lookup. The fixed graph has no mutation
/// operation, so its load/unload generation remains exactly zero.
#[cfg(any(crabc_fixed_graph_introspection, crabc_fixed_graph_dlfcn))]
unsafe fn publish_fixed_graph_runtime(
    sp: usize,
    objects: &[Object; MAX_OBJECTS],
) -> Option<()> {
    if FIXED_GRAPH_RUNTIME_PUBLISHED.load(Ordering::Relaxed) {
        return None;
    }
    if objects.iter().any(|object| object.tls_memsz != 0) {
        return None;
    }
    let argv0 = *((sp + core::mem::size_of::<usize>()) as *const *const u8);
    fixed_graph_store_name(0, argv0, MAX_PATH)?;
    if objects[0].needed_count != 1 || objects[1].needed_count != 1 {
        return None;
    }
    fixed_graph_store_name(
        1,
        objects[0].strtab.add(objects[0].needed[0]),
        objects[0].strsz.checked_sub(objects[0].needed[0])?,
    )?;
    fixed_graph_store_name(
        2,
        objects[1].strtab.add(objects[1].needed[0]),
        objects[1].strsz.checked_sub(objects[1].needed[0])?,
    )?;
    let destination = core::ptr::addr_of_mut!(FIXED_GRAPH_RUNTIME_OBJECTS).cast::<Object>();
    for index in 0..INITIAL_OBJECT_COUNT {
        core::ptr::write(destination.add(index), objects[index]);
    }
    FIXED_GRAPH_RUNTIME_COUNT.store(INITIAL_OBJECT_COUNT, Ordering::Relaxed);
    FIXED_GRAPH_RUNTIME_ADDITIONS.store(0, Ordering::Relaxed);
    FIXED_GRAPH_RUNTIME_PUBLISHED.store(true, Ordering::Release);
    Some(())
}

#[cfg(any(crabc_fixed_graph_introspection, crabc_fixed_graph_dlfcn))]
fn fixed_graph_object_count() -> usize {
    FIXED_GRAPH_RUNTIME_COUNT.load(Ordering::Acquire)
}

#[cfg(any(crabc_fixed_graph_introspection, crabc_fixed_graph_dlfcn))]
unsafe fn fixed_graph_object_contains(object: &Object, address: usize) -> bool {
    for index in 0..object.phnum {
        let header = object.phdr.add(index * 56);
        if read_u32(header) != PT_LOAD {
            continue;
        }
        let Some(start) = (object.base as usize).checked_add(read_u64(header.add(16)) as usize)
        else {
            continue;
        };
        let Some(end) = start.checked_add(read_u64(header.add(40)) as usize) else {
            continue;
        };
        if address >= start && address < end {
            return true;
        }
    }
    false
}

#[cfg(any(crabc_fixed_graph_introspection, crabc_fixed_graph_dlfcn))]
unsafe extern "C" fn fixed_graph_snapshot(
    records: *mut FixedGraphImageV1,
    capacity: usize,
    count: *mut usize,
    generation: *mut u64,
    error: *mut FixedGraphTextV1,
) -> i32 {
    let _guard = FixedGraphRuntimeGuard::lock();
    fixed_graph_clear_error(error);
    if count.is_null() || generation.is_null() || (capacity != 0 && records.is_null()) {
        fixed_graph_set_error(error, b"loader snapshot output is invalid");
        return -1;
    }
    core::ptr::write(count, 0);
    core::ptr::write(generation, 0);
    if !FIXED_GRAPH_RUNTIME_PUBLISHED.load(Ordering::Acquire) {
        fixed_graph_set_error(error, b"fixed graph introspection unavailable");
        return -1;
    }
    let object_count = fixed_graph_object_count();
    if capacity < object_count {
        fixed_graph_set_error(error, b"loader snapshot capacity is too small");
        return -1;
    }
    let additions = FIXED_GRAPH_RUNTIME_ADDITIONS.load(Ordering::Acquire);
    for index in 0..object_count {
        let object = fixed_graph_object(index);
        core::ptr::write(
            records.add(index),
            FixedGraphImageV1 {
                image_base: object.base as *mut c_void,
                program_headers: object.phdr.cast(),
                program_header_count: object.phnum as u16,
                reserved: 0,
                additions,
                removals: 0,
                tls_module: 0,
                tls_data: core::ptr::null_mut(),
                image_name: fixed_graph_name(index),
            },
        );
    }
    core::ptr::write(count, object_count);
    core::ptr::write(generation, additions);
    0
}

#[cfg(any(crabc_fixed_graph_introspection, crabc_fixed_graph_dlfcn))]
unsafe extern "C" fn fixed_graph_address(
    address: *const c_void,
    result: *mut FixedGraphAddressV1,
    error: *mut FixedGraphTextV1,
) -> i32 {
    let _guard = FixedGraphRuntimeGuard::lock();
    fixed_graph_clear_error(error);
    if result.is_null() {
        fixed_graph_set_error(error, b"loader address lookup is invalid");
        return -1;
    }
    core::ptr::write(
        result,
        FixedGraphAddressV1 {
            image_base: core::ptr::null_mut(),
            symbol_address: core::ptr::null_mut(),
            image_name: EMPTY_FIXED_GRAPH_TEXT,
            symbol_name: EMPTY_FIXED_GRAPH_TEXT,
        },
    );
    if address.is_null() {
        fixed_graph_set_error(error, b"loader address lookup is invalid");
        return -1;
    }
    if !FIXED_GRAPH_RUNTIME_PUBLISHED.load(Ordering::Acquire) {
        fixed_graph_set_error(error, b"fixed graph introspection unavailable");
        return -1;
    }
    let address_value = address as usize;
    for object_index in 0..fixed_graph_object_count() {
        let object = fixed_graph_object(object_index);
        if !fixed_graph_object_contains(&object, address_value) {
            continue;
        }
        let mut best_address = 0usize;
        let mut best_size = 0u64;
        let mut best_name = core::ptr::null();
        let mut best_name_len = 0usize;
        for symbol_index in 1..object.symcount {
            let symbol = object.symtab.add(symbol_index * 24);
            let name_offset = read_u32(symbol) as usize;
            let symbol_type = *symbol.add(4) & 0x0f;
            let section = read_u16(symbol.add(6));
            let value = read_u64(symbol.add(8));
            if section == 0 || value == 0 || symbol_type == 6 || name_offset >= object.strsz {
                continue;
            }
            let Some(symbol_address) = runtime_address(object.base, value) else {
                continue;
            };
            if symbol_address as usize > address_value
                || (symbol_address as usize) < best_address
                || !virtual_range_in_load(object.phdr, object.phnum, value, 1)
            {
                continue;
            }
            let symbol_name = object.strtab.add(name_offset);
            let Some(symbol_name_len) = bounded_nul(symbol_name, object.strsz - name_offset) else {
                continue;
            };
            best_address = symbol_address as usize;
            best_size = read_u64(symbol.add(16));
            best_name = symbol_name;
            best_name_len = symbol_name_len;
        }
        // Musl's `dynlink.c:dladdr` first identifies the containing DSO and
        // then chooses its nearest eligible dynamic symbol.  A finite symbol
        // does not describe the rest of that DSO: when the address falls at
        // or after `st_size`, musl retains dli_fname/dli_fbase but clears the
        // two symbol fields.  Its unsigned `st_size - 1` comparison treats a
        // zero-sized dynamic symbol as open-ended; preserve that deliberate
        // compatibility detail instead of inventing a synthetic empty range.
        // This is metadata over the already-published no-TLS fixed graph only;
        // it neither changes symbol lookup nor admits another object.
        let symbol_contains_address = best_address != 0
            && (best_size == 0
                || matches!(
                    usize::try_from(best_size),
                    Ok(size) if address_value - best_address < size
                ));
        core::ptr::write(
            result,
            FixedGraphAddressV1 {
                image_base: object.base as *mut c_void,
                symbol_address: if symbol_contains_address {
                    best_address as *mut c_void
                } else {
                    core::ptr::null_mut()
                },
                image_name: fixed_graph_name(object_index),
                symbol_name: if !symbol_contains_address || best_name.is_null() {
                    EMPTY_FIXED_GRAPH_TEXT
                } else {
                    fixed_graph_text_from_bytes(best_name, best_name_len)
                },
            },
        );
        return 0;
    }
    fixed_graph_set_error(error, b"loader address not found");
    -1
}

#[cfg(crabc_fixed_graph_dlfcn)]
unsafe fn fixed_graph_handle(index: usize) -> *mut c_void {
    core::ptr::addr_of!(FIXED_GRAPH_HANDLE_TOKENS)
        .cast::<FixedGraphHandleToken>()
        .add(index) as *mut c_void
}

#[cfg(crabc_fixed_graph_dlfcn)]
unsafe fn fixed_graph_handle_index(handle: *mut c_void) -> Option<usize> {
    if handle.is_null() {
        return None;
    }
    for index in 0..fixed_graph_object_count() {
        if handle == fixed_graph_handle(index)
            && (index == 0
                || FIXED_GRAPH_HANDLE_REFERENCES[index].load(Ordering::Acquire) != 0)
        {
            return Some(index);
        }
    }
    None
}

#[cfg(crabc_fixed_graph_dlfcn)]
unsafe fn fixed_graph_name_matches(index: usize, name: *const u8) -> bool {
    let Some(name_len) = bounded_nul(name, FIXED_GRAPH_TEXT_CAPACITY) else {
        return false;
    };
    let retained = fixed_graph_name(index);
    name_len == retained.len as usize
        && bytes_eq(name, retained.bytes.as_ptr(), name_len)
}

#[cfg(crabc_fixed_graph_dlfcn)]
unsafe fn fixed_graph_acquire(index: usize) -> bool {
    let counter = &FIXED_GRAPH_HANDLE_REFERENCES[index];
    let mut current = counter.load(Ordering::Acquire);
    loop {
        if current == usize::MAX {
            return false;
        }
        match counter.compare_exchange_weak(
            current,
            current + 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return true,
            Err(observed) => current = observed,
        }
    }
}

#[cfg(crabc_bounded_runtime_dlopen)]
unsafe fn bounded_runtime_unmap(object: &Object) {
    let mut minimum = u64::MAX;
    let mut maximum = 0u64;
    for index in 0..object.phnum {
        let header = object.phdr.add(index * 56);
        if read_u32(header) != PT_LOAD {
            continue;
        }
        minimum = minimum.min(align_down(read_u64(header.add(16))));
        let Some(end) = read_u64(header.add(16)).checked_add(read_u64(header.add(40))) else {
            return;
        };
        maximum = maximum.max(align_up(end));
    }
    if minimum != u64::MAX && maximum > minimum {
        let _ = syscall2(
            SYS_MUNMAP,
            object.base.wrapping_add(minimum) as i64,
            (maximum - minimum) as i64,
        );
    }
}

#[cfg(crabc_bounded_runtime_dlopen)]
unsafe fn bounded_runtime_dependency_index(
    object: &Object,
    needed_slot: usize,
    retained_count: usize,
) -> Option<usize> {
    if needed_slot >= object.needed_count {
        return None;
    }
    let offset = object.needed[needed_slot];
    let name = object.strtab.add(offset);
    let Some(name_len) = bounded_nul(name, object.strsz - offset) else {
        return None;
    };
    for index in 1..retained_count {
        let retained = fixed_graph_name(index);
        if retained.len as usize == name_len
            && bytes_eq(name, retained.bytes.as_ptr(), name_len)
        {
            return Some(index);
        }
    }
    None
}

#[cfg(crabc_bounded_runtime_dlopen)]
unsafe fn bounded_runtime_preflight_initializers(object: &Object) -> Option<()> {
    if object.init != 0 {
        let virtual_address = object.init.checked_sub(object.base as usize)? as u64;
        if !virtual_range_in_executable_load(object.phdr, object.phnum, virtual_address, 1) {
            return None;
        }
    }
    if object.init_count != 0 && object.init_array.is_null() {
        return None;
    }
    for index in 0..object.init_count {
        let initializer = *object.init_array.add(index);
        if initializer == 0 {
            return None;
        }
        let virtual_address = initializer.checked_sub(object.base as usize)? as u64;
        if !virtual_range_in_executable_load(object.phdr, object.phnum, virtual_address, 1) {
            return None;
        }
    }
    Some(())
}

/// Run the sole admitted legacy initializer before the bounded init array.
///
/// This is intentionally separate from `run_initializers`: the initial graph
/// stays legacy-tag-rejecting, while the one runtime DSO may carry one
/// validated executable DT_INIT entry followed by its already-bounded init
/// array. Its separately validated legacy DT_FINI remains inert, matching
/// pinned musl; DT_FINI_ARRAY and every unload transition remain rejected.
#[cfg(crabc_bounded_runtime_dlopen)]
unsafe fn run_bounded_runtime_initializers(object: &Object) -> Option<()> {
    if object.init != 0 {
        let virtual_address = object.init.checked_sub(object.base as usize)? as u64;
        if !virtual_range_in_executable_load(object.phdr, object.phnum, virtual_address, 1) {
            return None;
        }
        let initializer: unsafe extern "C" fn() = core::mem::transmute(object.init);
        initializer();
    }
    invoke_initializer_range(
        object.base,
        object.phdr,
        object.phnum,
        object.init_array,
        object.init_count,
    )
}

/// Map and publish the single admitted runtime DSO.
///
/// The name must be a basename found through the already-validated absolute
/// RUNPATH of the main image. The DSO is RELA-only, has no PT_TLS, may carry
/// one validated executable legacy `DT_INIT` entry followed by a bounded
/// initializer array, plus one validated-but-inert legacy `DT_FINI` entry.
/// It may depend only on objects already retained by the initial graph.
/// Failed transactions never enter the published graph.
#[cfg(crabc_bounded_runtime_dlopen)]
unsafe fn bounded_runtime_map(path: *const u8) -> Result<usize, &'static [u8]> {
    let Some(path_len) = bounded_nul(path, FIXED_GRAPH_TEXT_CAPACITY) else {
        return Err(b"loader object name is invalid");
    };
    if path_len == 0 {
        return Err(b"loader object name is invalid");
    }
    for offset in 0..path_len {
        if *path.add(offset) == b'/' {
            return Err(b"runtime loader accepts a RUNPATH basename only");
        }
    }
    let retained_count = fixed_graph_object_count();
    if retained_count >= MAX_OBJECTS {
        return Err(b"runtime loader object capacity is exhausted");
    }
    let main = fixed_graph_object(0);
    if main.runpath.is_null() {
        return Err(b"runtime loader RUNPATH is unavailable");
    }
    let Some(fd) = open_from_runpath(main.runpath, main.runpath_len, path, path_len) else {
        return Err(b"runtime loader object was not found in RUNPATH");
    };
    let mapped = map_elf(fd, true, false);
    let _ = syscall1(SYS_CLOSE, fd);
    let Some(object) = mapped else {
        return Err(b"runtime loader rejected malformed ELF");
    };
    if object.tls_memsz != 0
        || object.relrsz != 0
        || object.runpath_len != 0
        || object.needed_count > MAX_NEEDED
        || object.init_count > MAX_BOUNDED_RUNTIME_ARRAY_ENTRIES
    {
        bounded_runtime_unmap(&object);
        return Err(b"runtime loader rejected unsupported DSO metadata");
    }
    for slot in 0..object.needed_count {
        if bounded_runtime_dependency_index(&object, slot, retained_count).is_none() {
            bounded_runtime_unmap(&object);
            return Err(b"runtime loader dependency is not already retained");
        }
    }
    let mut objects = [EMPTY_OBJECT; MAX_OBJECTS];
    for index in 0..retained_count {
        objects[index] = fixed_graph_object(index);
    }
    objects[retained_count] = object;
    if relocate(&object, &objects).is_none()
        || protect_segments(&object).is_none()
        || apply_relro(&object).is_none()
        || fixed_graph_store_name(retained_count, path, FIXED_GRAPH_TEXT_CAPACITY).is_none()
        || bounded_runtime_preflight_initializers(&object).is_none()
    {
        bounded_runtime_unmap(&object);
        return Err(b"runtime loader mapping transaction failed");
    }
    // Every fallible validation and protection transition precedes the first
    // constructor side effect. The preflight above makes this invocation
    // infallible for the now-immutable mapped metadata.
    if run_bounded_runtime_initializers(&object).is_none() {
        bounded_runtime_unmap(&object);
        return Err(b"runtime loader constructor transaction failed");
    }
    let destination = core::ptr::addr_of_mut!(FIXED_GRAPH_RUNTIME_OBJECTS)
        .cast::<Object>()
        .add(retained_count);
    core::ptr::write(destination, object);
    FIXED_GRAPH_RUNTIME_ADDITIONS.store(1, Ordering::Relaxed);
    FIXED_GRAPH_RUNTIME_COUNT.store(retained_count + 1, Ordering::Release);
    Ok(retained_count)
}

#[cfg(crabc_fixed_graph_dlfcn)]
unsafe extern "C" fn fixed_graph_open(
    path: *const u8,
    flags: i32,
    handle: *mut *mut c_void,
    error: *mut FixedGraphTextV1,
) -> i32 {
    let _guard = FixedGraphRuntimeGuard::lock();
    fixed_graph_clear_error(error);
    if handle.is_null() {
        fixed_graph_set_error(error, b"loader open output is invalid");
        return -1;
    }
    core::ptr::write(handle, core::ptr::null_mut());
    if !FIXED_GRAPH_RUNTIME_PUBLISHED.load(Ordering::Acquire) {
        fixed_graph_set_error(error, b"fixed graph runtime unavailable");
        return -1;
    }
    let binding = flags & (FIXED_GRAPH_RTLD_LAZY | FIXED_GRAPH_RTLD_NOW);
    let no_load = flags & FIXED_GRAPH_RTLD_NOLOAD != 0;
    // The one-slot mapping is process-lifetime owned, so this bounded sibling
    // can accept NODELETE only for that fourth identity. It neither changes
    // the permanent mapping nor widens initial-object or general unload rules.
    let no_delete = flags & FIXED_GRAPH_RTLD_NODELETE != 0;
    if (binding != FIXED_GRAPH_RTLD_LAZY && binding != FIXED_GRAPH_RTLD_NOW)
        || flags & !FIXED_GRAPH_ALLOWED_OPEN_FLAGS != 0
    {
        if flags & FIXED_GRAPH_RTLD_GLOBAL != 0 {
            fixed_graph_set_error(error, b"fixed graph cannot promote global scope");
        } else {
            fixed_graph_set_error(error, b"loader open flags are invalid");
        }
        return -1;
    }
    if path.is_null() {
        if no_load {
            fixed_graph_set_error(error, b"RTLD_NOLOAD is limited to the runtime object");
            return -1;
        }
        if no_delete {
            fixed_graph_set_error(error, b"RTLD_NODELETE is limited to the runtime object");
            return -1;
        }
        core::ptr::write(handle, fixed_graph_handle(0));
        return 0;
    }
    let object_count = fixed_graph_object_count();
    for index in 1..object_count {
        if fixed_graph_name_matches(index, path) {
            if no_load && index < INITIAL_OBJECT_COUNT {
                fixed_graph_set_error(error, b"RTLD_NOLOAD is limited to the runtime object");
                return -1;
            }
            if no_delete && index < INITIAL_OBJECT_COUNT {
                fixed_graph_set_error(error, b"RTLD_NODELETE is limited to the runtime object");
                return -1;
            }
            if !fixed_graph_acquire(index) {
                fixed_graph_set_error(error, b"loader handle reference overflow");
                return -1;
            }
            core::ptr::write(handle, fixed_graph_handle(index));
            return 0;
        }
    }
    // A no-load query must observe only the already-published appended object;
    // it never reaches the mapper or changes the copied graph state.
    if no_load {
        fixed_graph_set_error(error, b"RTLD_NOLOAD object is not loaded");
        return -1;
    }
    #[cfg(crabc_bounded_runtime_dlopen)]
    match bounded_runtime_map(path) {
        Ok(index) => {
            if !fixed_graph_acquire(index) {
                fixed_graph_set_error(error, b"loader handle reference overflow");
                return -1;
            }
            core::ptr::write(handle, fixed_graph_handle(index));
            return 0;
        }
        Err(message) => {
            fixed_graph_set_error(error, message);
            return -1;
        }
    }
    #[cfg(not(crabc_bounded_runtime_dlopen))]
    {
        fixed_graph_set_error(error, b"fixed graph object is not already loaded");
        -1
    }
}

#[cfg(crabc_fixed_graph_dlfcn)]
unsafe fn fixed_graph_lookup_in_object(object_index: usize, name: *const u8, name_len: usize) -> Option<u64> {
    let object = fixed_graph_object(object_index);
    let mut weak = None;
    for symbol_index in 1..object.symcount {
        let symbol = object.symtab.add(symbol_index * 24);
        let name_offset = read_u32(symbol) as usize;
        let information = *symbol.add(4);
        let binding = information >> 4;
        let symbol_type = information & 0x0f;
        let visibility = *symbol.add(5) & 0x03;
        let section = read_u16(symbol.add(6));
        let value = read_u64(symbol.add(8));
        if section == 0
            || (binding != 1 && binding != 2)
            || (symbol_type != 0 && symbol_type != 1 && symbol_type != 2)
            || (visibility != 0 && visibility != 3)
            || name_offset >= object.strsz
        {
            continue;
        }
        let candidate_name = object.strtab.add(name_offset);
        let Some(candidate_len) = bounded_nul(candidate_name, object.strsz - name_offset) else {
            continue;
        };
        if candidate_len != name_len || !bytes_eq(name, candidate_name, name_len) {
            continue;
        }
        if !virtual_range_in_load(object.phdr, object.phnum, value, 1) {
            return None;
        }
        let address = runtime_address(object.base, value)?;
        if binding == 1 {
            return Some(address);
        }
        weak = Some(address);
    }
    weak
}

#[cfg(crabc_bounded_runtime_dlopen)]
unsafe fn fixed_graph_lookup_runtime_dependencies(
    object_index: usize,
    name: *const u8,
    name_len: usize,
) -> Option<u64> {
    if let Some(found) = fixed_graph_lookup_in_object(object_index, name, name_len) {
        return Some(found);
    }
    let object = fixed_graph_object(object_index);
    for slot in 0..object.needed_count {
        let offset = object.needed[slot];
        let dependency_name = object.strtab.add(offset);
        let dependency_len = bounded_nul(dependency_name, object.strsz - offset)?;
        for direct in 1..INITIAL_OBJECT_COUNT {
            let retained = fixed_graph_name(direct);
            if retained.len as usize == dependency_len
                && bytes_eq(dependency_name, retained.bytes.as_ptr(), dependency_len)
            {
                // The retained startup graph's index suffix is its dependency
                // closure: mid -> leaf and leaf -> none.
                for candidate in direct..INITIAL_OBJECT_COUNT {
                    if let Some(found) = fixed_graph_lookup_in_object(candidate, name, name_len) {
                        return Some(found);
                    }
                }
            }
        }
    }
    None
}

#[cfg(crabc_fixed_graph_dlfcn)]
unsafe extern "C" fn fixed_graph_symbol(
    handle: *mut c_void,
    name: *const u8,
    address: *mut *mut c_void,
    error: *mut FixedGraphTextV1,
) -> i32 {
    let _guard = FixedGraphRuntimeGuard::lock();
    fixed_graph_clear_error(error);
    if address.is_null() || name.is_null() {
        if !address.is_null() {
            core::ptr::write(address, core::ptr::null_mut());
        }
        fixed_graph_set_error(error, b"loader symbol request is invalid");
        return -1;
    }
    core::ptr::write(address, core::ptr::null_mut());
    if !FIXED_GRAPH_RUNTIME_PUBLISHED.load(Ordering::Acquire) {
        fixed_graph_set_error(error, b"fixed graph runtime unavailable");
        return -1;
    }
    let Some(handle_index) = fixed_graph_handle_index(handle) else {
        fixed_graph_set_error(error, b"loader symbol handle is invalid");
        return -1;
    };
    let Some(name_len) = bounded_nul(name, FIXED_GRAPH_TEXT_CAPACITY) else {
        fixed_graph_set_error(error, b"loader symbol name is invalid");
        return -1;
    };
    if name_len == 0 {
        fixed_graph_set_error(error, b"loader symbol name is invalid");
        return -1;
    }
    #[cfg(crabc_bounded_runtime_dlopen)]
    if handle_index >= INITIAL_OBJECT_COUNT {
        if let Some(found) = fixed_graph_lookup_runtime_dependencies(handle_index, name, name_len) {
            core::ptr::write(address, found as *mut c_void);
            return 0;
        }
        fixed_graph_set_error(error, b"symbol not found in runtime handle scope");
        return -1;
    }
    let scope_end = core::cmp::min(fixed_graph_object_count(), INITIAL_OBJECT_COUNT);
    for object_index in handle_index..scope_end {
        if let Some(found) = fixed_graph_lookup_in_object(object_index, name, name_len) {
            core::ptr::write(address, found as *mut c_void);
            return 0;
        }
    }
    fixed_graph_set_error(error, b"symbol not found in fixed handle scope");
    -1
}

#[cfg(crabc_fixed_graph_dlfcn)]
unsafe extern "C" fn fixed_graph_close(
    handle: *mut c_void,
    error: *mut FixedGraphTextV1,
) -> i32 {
    let _guard = FixedGraphRuntimeGuard::lock();
    fixed_graph_clear_error(error);
    if !FIXED_GRAPH_RUNTIME_PUBLISHED.load(Ordering::Acquire) {
        fixed_graph_set_error(error, b"fixed graph runtime unavailable");
        return -1;
    }
    if handle == fixed_graph_handle(0) {
        return 0;
    }
    let mut index = None;
    for candidate in 1..fixed_graph_object_count() {
        if handle == fixed_graph_handle(candidate) {
            index = Some(candidate);
            break;
        }
    }
    let Some(index) = index else {
        fixed_graph_set_error(error, b"loader close handle is invalid");
        return -1;
    };
    let counter = &FIXED_GRAPH_HANDLE_REFERENCES[index];
    let mut current = counter.load(Ordering::Acquire);
    loop {
        if current == 0 {
            fixed_graph_set_error(error, b"loader close handle is invalid");
            return -1;
        }
        match counter.compare_exchange_weak(
            current,
            current - 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return 0,
            Err(observed) => current = observed,
        }
    }
}

#[cfg(any(crabc_fixed_graph_introspection, crabc_fixed_graph_dlfcn))]
unsafe fn fixed_graph_information_by_index(
    image_index: usize,
    information: *mut FixedGraphInformationV1,
    error: *mut FixedGraphTextV1,
) -> i32 {
    fixed_graph_clear_error(error);
    if information.is_null() {
        fixed_graph_set_error(error, b"loader information output is invalid");
        return -1;
    }
    core::ptr::write(
        information,
        FixedGraphInformationV1 {
            image_base: core::ptr::null_mut(),
            dynamic_address: core::ptr::null_mut(),
            image_name: EMPTY_FIXED_GRAPH_TEXT,
        },
    );
    if !FIXED_GRAPH_RUNTIME_PUBLISHED.load(Ordering::Acquire) {
        fixed_graph_set_error(error, b"fixed graph introspection unavailable");
        return -1;
    }
    if image_index >= fixed_graph_object_count() {
        fixed_graph_set_error(error, b"loader information image is invalid");
        return -1;
    }
    let object = fixed_graph_object(image_index);
    core::ptr::write(
        information,
        FixedGraphInformationV1 {
            image_base: object.base as *mut c_void,
            dynamic_address: object.dynamic as *mut c_void,
            image_name: fixed_graph_name(image_index),
        },
    );
    0
}

#[cfg(crabc_fixed_graph_introspection)]
unsafe extern "C" fn fixed_graph_information(
    image_index: usize,
    information: *mut FixedGraphInformationV1,
    error: *mut FixedGraphTextV1,
) -> i32 {
    let _guard = FixedGraphRuntimeGuard::lock();
    fixed_graph_information_by_index(image_index, information, error)
}

#[cfg(crabc_fixed_graph_dlfcn)]
unsafe extern "C" fn fixed_graph_handle_information(
    handle: *mut c_void,
    information: *mut FixedGraphInformationV1,
    error: *mut FixedGraphTextV1,
) -> i32 {
    let _guard = FixedGraphRuntimeGuard::lock();
    if information.is_null() {
        fixed_graph_clear_error(error);
        fixed_graph_set_error(error, b"loader information output is invalid");
        return -1;
    }
    let Some(image_index) = fixed_graph_handle_index(handle) else {
        core::ptr::write(
            information,
            FixedGraphInformationV1 {
                image_base: core::ptr::null_mut(),
                dynamic_address: core::ptr::null_mut(),
                image_name: EMPTY_FIXED_GRAPH_TEXT,
            },
        );
        fixed_graph_clear_error(error);
        fixed_graph_set_error(error, b"loader information handle is invalid");
        return -1;
    };
    fixed_graph_information_by_index(image_index, information, error)
}

#[cfg(not(crabc_owned_crt_handoff))]
unsafe fn run_initializers(objects: &[Object]) -> Option<()> {
    // The closed dependency graph has already been mapped and relocated.
    // Walking this suffix in reverse produces leaf then mid. Main-image
    // constructor dispatch remains a future CRT handoff boundary.
    for object in objects.iter().rev() {
        invoke_initializer_range(
            object.base,
            object.phdr,
            object.phnum,
            object.init_array,
            object.init_count,
        )?;
    }
    Some(())
}

unsafe fn invoke_initializer_range(
    base: u64,
    phdr: *const u8,
    phnum: usize,
    init_array: *const usize,
    init_count: usize,
) -> Option<()> {
    if init_count != 0 && init_array.is_null() {
        return None;
    }
    for index in 0..init_count {
        let initializer = *init_array.add(index);
        if initializer == 0 {
            return None;
        }
        let initializer_virtual_address = initializer.checked_sub(base as usize)? as u64;
        if !virtual_range_in_executable_load(phdr, phnum, initializer_virtual_address, 1) {
            return None;
        }
        let initializer: unsafe extern "C" fn() = core::mem::transmute(initializer);
        initializer();
    }
    Some(())
}

/// Publish the two fixed dependency initializer ranges for the checked
/// post-relocation record.  This runs after every object is relocated and
/// RELRO sealed, but before the interpreter seals its own record and jumps to
/// the Rust-produced main image.
#[cfg(crabc_owned_crt_handoff)]
unsafe fn publish_owned_crt_handoff(objects: &[Object; MAX_OBJECTS]) -> Option<()> {
    if core::ptr::read(core::ptr::addr_of!(OWNED_CRT_HANDOFF_STATE))
        != OWNED_CRT_STATE_UNPUBLISHED
    {
        return None;
    }
    for index in 0..MAX_OBJECTS - 1 {
        let object = objects[index + 1];
        // The handoff is intentionally not a generic empty-array callback.
        // This exact fixture has one named initializer range for each DSO.
        if object.init_count == 0 || object.init_array.is_null() {
            return None;
        }
        core::ptr::write(
            core::ptr::addr_of_mut!(OWNED_CRT_INITIALIZER_RANGES).cast::<OwnedCrtInitializerRange>().add(index),
            OwnedCrtInitializerRange {
                base: object.base,
                phdr: object.phdr,
                phnum: object.phnum,
                init_array: object.init_array,
                init_count: object.init_count,
            },
        );
    }
    core::ptr::write(
        core::ptr::addr_of_mut!(OWNED_CRT_HANDOFF_STATE),
        OWNED_CRT_STATE_READY,
    );
    Some(())
}

#[cfg(crabc_owned_crt_handoff)]
unsafe extern "C" fn owned_crt_dependency_constructors() {
    if core::ptr::read(core::ptr::addr_of!(OWNED_CRT_HANDOFF_STATE)) != OWNED_CRT_STATE_READY {
        fail(b"crtinit\n");
    }
    for index in (0..MAX_OBJECTS - 1).rev() {
        let range = core::ptr::read(
            core::ptr::addr_of!(OWNED_CRT_INITIALIZER_RANGES)
                .cast::<OwnedCrtInitializerRange>()
                .add(index),
        );
        invoke_initializer_range(
            range.base,
            range.phdr,
            range.phnum,
            range.init_array,
            range.init_count,
        )
        .unwrap_or_else(|| fail(b"crtinit\n"));
    }
    core::ptr::write(
        core::ptr::addr_of_mut!(OWNED_CRT_HANDOFF_STATE),
        OWNED_CRT_STATE_CONSTRUCTORS_COMPLETE,
    );
}

#[cfg(crabc_owned_crt_handoff)]
unsafe extern "C" fn owned_crt_process_fini() {
    // This fixed graph still rejects DSO DT_FINI/DT_FINI_ARRAY.  Its one
    // process-finalizer callback therefore closes the record's lifecycle
    // phase rather than selecting general DSO destruction semantics.
    if core::ptr::read(core::ptr::addr_of!(OWNED_CRT_HANDOFF_STATE))
        != OWNED_CRT_STATE_CONSTRUCTORS_COMPLETE
    {
        fail(b"crtfini\n");
    }
    core::ptr::write(
        core::ptr::addr_of_mut!(OWNED_CRT_HANDOFF_STATE),
        OWNED_CRT_STATE_FINALIZED,
    );
}

unsafe fn virtual_range_in_load(phdr: *const u8, phnum: usize, address: u64, byte_len: u64) -> bool {
    let Some(end) = address.checked_add(byte_len) else { return false; };
    for index in 0..phnum {
        let header = phdr.add(index * 56);
        if read_u32(header) != PT_LOAD { continue; }
        let start = read_u64(header.add(16));
        let Some(load_end) = start.checked_add(read_u64(header.add(40))) else { return false; };
        if address >= start && end <= load_end { return true; }
    }
    false
}

/// Whether a range fits the page-rounded mapping of one PT_LOAD segment.
/// This is intentionally narrower than an arbitrary adjacent mapping: it
/// exists solely for the linker-permitted final-page extension of PT_GNU_RELRO.
unsafe fn virtual_range_in_page_mapped_load(
    phdr: *const u8,
    phnum: usize,
    address: u64,
    byte_len: u64,
) -> bool {
    let Some(end) = address.checked_add(byte_len) else { return false; };
    for index in 0..phnum {
        let header = phdr.add(index * 56);
        if read_u32(header) != PT_LOAD {
            continue;
        }
        let start = align_down(read_u64(header.add(16)));
        let Some(raw_end) = read_u64(header.add(16)).checked_add(read_u64(header.add(40))) else {
            return false;
        };
        let mapped_end = align_up(raw_end);
        if address >= start && end <= mapped_end {
            return true;
        }
    }
    false
}

/// Require a PT_TLS initialized prefix or initial lifecycle array to be backed by one readable file
/// segment. `p_memsz` may legitimately extend through BSS, but copying
/// `p_filesz` from that extension would turn a malformed ELF record into a
/// speculative read from whatever virtual mapping happens to follow it.
#[cfg(any(
    crabc_initial_tls_graph,
    crabc_initial_exec_tls_graph,
    crabc_general_initial_tls_materialization_v1,
    crabc_general_initial_lifecycle
))]
unsafe fn virtual_range_in_readable_file_load(
    phdr: *const u8,
    phnum: usize,
    address: u64,
    byte_len: u64,
) -> bool {
    let Some(end) = address.checked_add(byte_len) else { return false; };
    for index in 0..phnum {
        let header = phdr.add(index * 56);
        if read_u32(header) != PT_LOAD || read_u32(header.add(4)) & PF_R == 0 {
            continue;
        }
        let start = read_u64(header.add(16));
        let Some(file_end) = start.checked_add(read_u64(header.add(32))) else {
            return false;
        };
        if address >= start && end <= file_end {
            return true;
        }
    }
    false
}

unsafe fn virtual_range_in_writable_load(phdr: *const u8, phnum: usize, address: u64, byte_len: u64) -> bool {
    let Some(end) = address.checked_add(byte_len) else { return false; };
    for index in 0..phnum {
        let header = phdr.add(index * 56);
        if read_u32(header) != PT_LOAD || read_u32(header.add(4)) & PF_W == 0 { continue; }
        let start = read_u64(header.add(16));
        let Some(load_end) = start.checked_add(read_u64(header.add(40))) else { return false; };
        if address >= start && end <= load_end { return true; }
    }
    false
}

unsafe fn virtual_range_in_executable_load(phdr: *const u8, phnum: usize, address: u64, byte_len: u64) -> bool {
    let Some(end) = address.checked_add(byte_len) else { return false; };
    for index in 0..phnum {
        let header = phdr.add(index * 56);
        if read_u32(header) != PT_LOAD || read_u32(header.add(4)) & PF_X == 0 { continue; }
        let start = read_u64(header.add(16));
        let Some(load_end) = start.checked_add(read_u64(header.add(40))) else { return false; };
        if address >= start && end <= load_end { return true; }
    }
    false
}

/// Validate the exact nonempty pointer-array shape that Rust-produced Scrt1
/// later reaches through its hidden linker-boundary bridges.  The interpreter
/// never dispatches these main-image entries itself.
#[cfg(any(crabc_owned_crt_handoff, crabc_dynamic_main_thread_runtime_v1))]
unsafe fn scrt1_array_in_load(
    phdr: *const u8,
    phnum: usize,
    address: u64,
    byte_len: u64,
) -> bool {
    byte_len != 0
        && byte_len % core::mem::size_of::<usize>() as u64 == 0
        && byte_len / core::mem::size_of::<usize>() as u64
            <= MAX_OWNED_CRT_MAIN_ARRAY_ENTRIES as u64
        && address % core::mem::align_of::<usize>() as u64 == 0
        && virtual_range_in_load(phdr, phnum, address, byte_len)
}

fn runtime_address(base: u64, virtual_address: u64) -> Option<u64> { base.checked_add(virtual_address) }

fn ranges_overlap(
    first_address: u64,
    first_byte_len: u64,
    second_address: u64,
    second_byte_len: u64,
) -> Option<bool> {
    let first_end = first_address.checked_add(first_byte_len)?;
    let second_end = second_address.checked_add(second_byte_len)?;
    Some(first_address < second_end && second_address < first_end)
}

unsafe fn bounded_nul(pointer: *const u8, maximum: usize) -> Option<usize> { for index in 0..maximum { if *pointer.add(index) == 0 { return Some(index); } } None }
unsafe fn bytes_eq(left: *const u8, right: *const u8, length: usize) -> bool { for index in 0..length { if *left.add(index) != *right.add(index) { return false; } } true }
unsafe fn read_u16(pointer: *const u8) -> u16 { core::ptr::read_unaligned(pointer as *const u16) }
unsafe fn read_u32(pointer: *const u8) -> u32 { core::ptr::read_unaligned(pointer as *const u32) }
unsafe fn read_u64(pointer: *const u8) -> u64 { core::ptr::read_unaligned(pointer as *const u64) }
unsafe fn read_i64(pointer: *const u8) -> i64 { core::ptr::read_unaligned(pointer as *const i64) }
fn align_down(value: u64) -> u64 { value & !(PAGE - 1) }
fn align_up(value: u64) -> u64 { value.checked_add(PAGE - 1).unwrap_or(u64::MAX) & !(PAGE - 1) }
fn align_down_usize(value: usize, align: usize) -> usize { value & !(align - 1) }
fn align_up_usize(value: usize, align: usize) -> Option<usize> {
    if align == 0 || !align.is_power_of_two() {
        return None;
    }
    value.checked_add(align - 1).map(|rounded| rounded & !(align - 1))
}
fn add_signed(value: u64, addend: i64) -> Option<u64> { if addend >= 0 { value.checked_add(addend as u64) } else { value.checked_sub(addend.unsigned_abs()) } }
fn is_linux_error(value: i64) -> bool { (-4_095..=-1).contains(&value) }

#[inline(always)]
unsafe fn read_thread_pointer() -> usize {
    let thread_pointer: usize;
    core::arch::asm!(
        "mov {thread_pointer}, fs:[0]",
        thread_pointer = out(reg) thread_pointer,
        options(readonly, nostack, preserves_flags),
    );
    thread_pointer
}

unsafe fn syscall1(number: i64, one: i64) -> i64 { let result: i64; core::arch::asm!("syscall", inlateout("rax") number => result, in("rdi") one, lateout("rcx") _, lateout("r11") _, options(nostack)); result }
unsafe fn syscall2(number: i64, one: i64, two: i64) -> i64 { let result: i64; core::arch::asm!("syscall", inlateout("rax") number => result, in("rdi") one, in("rsi") two, lateout("rcx") _, lateout("r11") _, options(nostack)); result }
unsafe fn syscall3(number: i64, one: i64, two: i64, three: i64) -> i64 { let result: i64; core::arch::asm!("syscall", inlateout("rax") number => result, in("rdi") one, in("rsi") two, in("rdx") three, lateout("rcx") _, lateout("r11") _, options(nostack)); result }
unsafe fn syscall4(number: i64, one: i64, two: i64, three: i64, four: i64) -> i64 { let result: i64; core::arch::asm!("syscall", inlateout("rax") number => result, in("rdi") one, in("rsi") two, in("rdx") three, in("r10") four, lateout("rcx") _, lateout("r11") _, options(nostack)); result }
unsafe fn syscall6(number: i64, one: i64, two: i64, three: i64, four: i64, five: i64, six: i64) -> i64 { let result: i64; core::arch::asm!("syscall", inlateout("rax") number => result, in("rdi") one, in("rsi") two, in("rdx") three, in("r10") four, in("r8") five, in("r9") six, lateout("rcx") _, lateout("r11") _, options(nostack)); result }

unsafe fn jump(entry: usize, sp: usize) -> ! {
    #[cfg(crabc_general_initial_lifecycle)]
    core::arch::asm!("mov rsp, {stack}", "jmp {target}", stack = in(reg) sp,
        target = in(reg) entry,
        in("rdx") x86_64_general_initial_lifecycle::process_finalizer as *const () as usize,
        options(noreturn));
    #[cfg(not(crabc_general_initial_lifecycle))]
    core::arch::asm!("mov rsp, {stack}", "jmp {target}", stack = in(reg) sp,
        target = in(reg) entry, options(noreturn));
}
fn fail(message: &[u8]) -> ! { unsafe { die(message) } }
unsafe fn die(message: &[u8]) -> ! { let _ = syscall3(SYS_WRITE, 2, message.as_ptr() as i64, message.len() as i64); let _ = syscall1(SYS_EXIT, 127); core::hint::unreachable_unchecked() }

#[no_mangle]
pub unsafe extern "C" fn memset(destination: *mut c_void, byte: i32, length: usize) -> *mut c_void {
    let destination = destination as *mut u8;
    for index in 0..length { *destination.add(index) = byte as u8; }
    destination.cast()
}
#[no_mangle]
pub unsafe extern "C" fn memcpy(destination: *mut c_void, source: *const c_void, length: usize) -> *mut c_void {
    let destination = destination as *mut u8;
    let source = source as *const u8;
    for index in 0..length { *destination.add(index) = *source.add(index); }
    destination.cast()
}
#[no_mangle]
pub unsafe extern "C" fn memmove(destination: *mut c_void, source: *const c_void, length: usize) -> *mut c_void {
    let destination = destination as *mut u8;
    let source = source as *const u8;
    if (destination as usize) <= (source as usize) { for index in 0..length { *destination.add(index) = *source.add(index); } }
    else { for index in (0..length).rev() { *destination.add(index) = *source.add(index); } }
    destination.cast()
}
#[no_mangle]
pub unsafe extern "C" fn bcmp(left: *const c_void, right: *const c_void, length: usize) -> i32 { memcmp(left, right, length) }
#[no_mangle]
pub unsafe extern "C" fn memcmp(left: *const c_void, right: *const c_void, length: usize) -> i32 { let left = left as *const u8; let right = right as *const u8; for index in 0..length { let delta = *left.add(index) as i32 - *right.add(index) as i32; if delta != 0 { return delta; } } 0 }
#[cfg(not(test))]
#[no_mangle]
pub extern "C" fn rust_eh_personality() {}
