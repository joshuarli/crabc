#![allow(dead_code, deref_nullptr)]

//! ELF loading, relocation, symbol resolution, and loader-owned runtime state.

use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use super::aarch64::{
    syscall1, syscall2, syscall3, syscall6, syscall_noreturn1, SYS_CLOSE, SYS_EXIT, SYS_FSTAT,
    SYS_LSEEK, SYS_MMAP, SYS_MPROTECT, SYS_MUNMAP, SYS_OPENAT, SYS_READ, SYS_WRITE,
};

#[cfg(not(test))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

// ============================================================
// Constants
// ============================================================

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_NOTE: u32 = 4;
const PT_PHDR: u32 = 6;
const PT_TLS: u32 = 7;
const PT_GNU_RELRO: u32 = 0x6474e552;
const PF_R: u32 = 4;
const PF_W: u32 = 2;
const PF_X: u32 = 1;

const DT_NULL: u64 = 0;
const DT_NEEDED: u64 = 1;
const DT_PLTRELSZ: u64 = 2;
const DT_HASH: u64 = 4;
const DT_STRTAB: u64 = 5;
const DT_SYMTAB: u64 = 6;
const DT_RELA: u64 = 7;
const DT_RELASZ: u64 = 8;
const DT_STRSZ: u64 = 10;
const DT_INIT: u64 = 12;
const DT_FINI: u64 = 13;
const DT_RPATH: u64 = 15;
const DT_JMPREL: u64 = 23;
const DT_INIT_ARRAY: u64 = 25;
const DT_FINI_ARRAY: u64 = 26;
const DT_INIT_ARRAYSZ: u64 = 27;
const DT_FINI_ARRAYSZ: u64 = 28;
const DT_RUNPATH: u64 = 29;
// DT_RELR packs base-relative pointer relocations into an address/bitmap
// stream. Alpine package binaries use it to reduce the size of large PIE
// relocation tables, so it is part of the ordinary musl ELF surface rather
// than an optional linker optimization we can ignore.
const DT_RELRSZ: u64 = 35;
const DT_RELR: u64 = 36;
const DT_RELRENT: u64 = 37;
const DT_GNU_HASH: u64 = 0x6ffffef5;

const R_AARCH64_NONE: u64 = 0;
// This non-standard relocation value was historically accepted by the loader
// as a COPY relocation on the prior supported build. Keep that narrow behavior
// for malformed-input compatibility without reviving an inactive ABI table.
const LEGACY_COPY_RELOCATION: u64 = 5;
const R_AARCH64_ABS64: u64 = 257;
const R_AARCH64_GLOB_DAT: u64 = 1025;
const R_AARCH64_JUMP_SLOT: u64 = 1026;
const R_AARCH64_RELATIVE: u64 = 1027;
const R_AARCH64_TLS_DTPMOD64: u64 = 1028;
const R_AARCH64_TLS_DTPREL64: u64 = 1029;
const R_AARCH64_TLS_TPREL64: u64 = 1030;
const R_AARCH64_TLSLE_ADD_TPREL_HI12: u64 = 549;
const R_AARCH64_TLSLE_ADD_TPREL_LO12: u64 = 550;
const R_AARCH64_TLSLE_ADD_TPREL_LO12_NC: u64 = 551;
const R_AARCH64_TLSDESC: u64 = 1031;

const RTLD_LAZY: i32 = 1;
const RTLD_NOW: i32 = 2;
const RTLD_LOCAL: i32 = 0;
const RTLD_GLOBAL: i32 = 0x100;

const AT_NULL: u64 = 0;
const AT_PHDR: u64 = 3;
const AT_PHENT: u64 = 4;
const AT_PHNUM: u64 = 5;
const AT_PAGESZ: u64 = 6;
const AT_BASE: u64 = 7;
const AT_ENTRY: u64 = 9;
const AT_UID: u64 = 11;
const AT_EUID: u64 = 12;
const AT_GID: u64 = 13;
const AT_EGID: u64 = 14;
const AT_SECURE: u64 = 23;
const AT_RANDOM: u64 = 25;
const AT_EXECFN: u64 = 31;
const AT_SYSINFO_EHDR: u64 = 33;

const PROT_READ: i32 = 1;
const PROT_WRITE: i32 = 2;
const PROT_EXEC: i32 = 4;
const PROT_NONE: i32 = 0;
const MAP_PRIVATE: i32 = 0x02;
const MAP_FIXED: i32 = 0x10;
const MAP_ANONYMOUS: i32 = 0x20;
const MAP_FAILED: usize = !0usize;

const PHDR_SIZE: usize = 56;
const PH_TYPE: usize = 0;
const PH_FLAGS: usize = 4;
const PH_OFFSET: usize = 8;
const PH_VADDR: usize = 16;
const PH_FILESZ: usize = 32;
const PH_MEMSZ: usize = 40;
const PH_ALIGN: usize = 48;

// Private `Scrt1.o` lifecycle capability note. The marker deliberately lives
// in a mapped ELF note instead of libc's dynamic export namespace; `crt` and
// this parser are its only producers/consumers.
const OWNED_CRT_NOTE_NAME: &[u8] = b"CRABC\0";
const OWNED_CRT_NOTE_TYPE: u32 = 0x4352_5401;
const OWNED_CRT_NOTE_REVISION: u32 = 1;
const MAX_OWNED_CRT_NOTE_BYTES: usize = 64 * 1024;
const OWNED_CRT_STARTUP_HANDOFF_MAGIC: u64 = 0x4352_4142_435f_4831;
const OWNED_CRT_STARTUP_HANDOFF_VERSION: u32 = 1;

const SYMTAB_ENT_SIZE: usize = 24;
const MAX_LOADED: usize = 16;
const TCB_SIZE: usize = 256;
const DSO_BASE_START: u64 = 0x200000000;
const DSO_BASE_STRIDE: u64 = 0x100000000;
const RTLD_DI_LINKMAP: i32 = 2;
const STT_TLS: u8 = 6;
const TCB_GENERATION_OFFSET: usize = 8;
const TCB_BLOCK_SIZE_OFFSET: usize = 16;
const TCB_TP_OFFSET_OFFSET: usize = 24;
// The libc-facing TCB fields stop at the stack guard at 0x28. This following
// range remains loader-private inside the fixed 256-byte allocation: the
// original TP is a stable owner token across dynamic-TLS replacement, the
// error-node pointer avoids a `gettid` syscall for every successful `dlsym`,
// the cache range stores one verified handle-local symbol lookup per thread,
// and the following word records the allocation's initialized TLS frontier.
const TCB_LOADER_OWNER_OFFSET: usize = 48;
const TCB_DLERROR_NODE_OFFSET: usize = 56;
const TCB_DLSYM_CACHE_HANDLE_OFFSET: usize = 64;
const TCB_DLSYM_CACHE_RESULT_OFFSET: usize = 72;
const TCB_DLSYM_CACHE_NAME_LEN_OFFSET: usize = 80;
const TCB_DLSYM_CACHE_HASH_OFFSET: usize = 88;
const TCB_DLSYM_CACHE_NAME_OFFSET: usize = 96;
const DLSYM_CACHE_NAME_LIMIT: usize = 64;
const TCB_TLS_MODULE_COUNT_OFFSET: usize = TCB_DLSYM_CACHE_NAME_OFFSET + DLSYM_CACHE_NAME_LIMIT;
const _: () = assert!(TCB_TLS_MODULE_COUNT_OFFSET + core::mem::size_of::<usize>() <= TCB_SIZE);

// ============================================================
// Loaded object tracking
// ============================================================

/// Immutable table bases and selectors decoded once from a valid GNU hash
/// header. Retaining these object-relative addresses removes repeated header
/// loads and checked base arithmetic from every symbol lookup without making
/// a malformed header look valid.
#[derive(Copy, Clone)]
struct GnuHashMetadata {
    // ELF encodes all three selectors as `u32`. Preserve that width so the
    // AArch64 lookup can use 32-bit remainder instructions before converting
    // the bounded result into a pointer element index.
    bucket_count: u32,
    symbol_offset: u32,
    bloom_count: u32,
    // A power-of-two Bloom word count can use a mask. `u32::MAX` is the
    // non-power-of-two sentinel: no representable power-of-two count can
    // produce that mask, so nonconforming-but-mapped GNU tables retain the
    // generic modulo route.
    bloom_mask: u32,
    bloom_shift: u32,
    bloom: *const u64,
    buckets: *const u32,
    chains: *const u32,
}

struct LoadedObject {
    base: u64,
    map_start: *mut u8,
    map_size: usize,
    symtab: *const u8,
    sym_count: usize,
    // `DT_GNU_HASH` takes precedence when present, matching musl's lookup
    // selection. Keep both table bases because a DSO may carry both formats
    // and a SysV-only object still needs its legacy chain lookup.
    gnu_hash: *const u8,
    gnu_hash_metadata: Option<GnuHashMetadata>,
    sysv_hash: *const u8,
    strtab: *const u8,
    strsz: usize,
    search_path: *const u8,
    search_path_len: usize,
    relro_addr: u64,
    relro_size: u64,
    relro_applied: bool,
    dependencies: [usize; MAX_LOADED],
    dependency_count: usize,
    constructing: bool,
    constructed: bool,
    dyn_addr: usize,
    dyn_memsz: usize,
    tls_image: *const u8,
    tls_filesz: u64,
    tls_memsz: u64,
    tls_align: u64,
    init: u64,
    init_array: u64,
    init_array_sz: u64,
    init_present: bool,
    init_array_present: bool,
    fini: u64,
    fini_array: u64,
    fini_array_sz: u64,
    fini_present: bool,
    fini_array_present: bool,
    global: bool,
    // Initial objects are permanently resident (`usize::MAX`). Runtime
    // handles use an ordinary reference count. musl preserves a finalized
    // mapping for a later reopen, so `finalized` gates fini execution rather
    // than eagerly tearing down its loader metadata.
    ref_count: usize,
    active: bool,
    finalized: bool,
    file_identity_valid: bool,
    file_dev: u64,
    file_ino: u64,
    // A bare startup dependency may safely reuse this object by name only
    // while the initial graph is still being discovered and the object first
    // resolved through the immutable process `LD_LIBRARY_PATH`. Parent
    // RUNPATH/RPATH and post-constructor dlopen keep inode-based matching.
    initial_ld_library_path_name: bool,
    name: [u8; 256],
}

const EMPTY_OBJ: LoadedObject = LoadedObject {
    base: 0,
    map_start: core::ptr::null_mut(),
    map_size: 0,
    symtab: core::ptr::null(),
    sym_count: 0,
    gnu_hash: core::ptr::null(),
    gnu_hash_metadata: None,
    sysv_hash: core::ptr::null(),
    strtab: core::ptr::null(),
    strsz: 0,
    search_path: core::ptr::null(),
    search_path_len: 0,
    relro_addr: 0,
    relro_size: 0,
    relro_applied: false,
    dependencies: [0; MAX_LOADED],
    dependency_count: 0,
    constructing: false,
    constructed: false,
    dyn_addr: 0,
    dyn_memsz: 0,
    tls_image: core::ptr::null(),
    tls_filesz: 0,
    tls_memsz: 0,
    tls_align: 0,
    init: 0,
    init_array: 0,
    init_array_sz: 0,
    init_present: false,
    init_array_present: false,
    fini: 0,
    fini_array: 0,
    fini_array_sz: 0,
    fini_present: false,
    fini_array_present: false,
    global: false,
    ref_count: 0,
    active: false,
    finalized: false,
    file_identity_valid: false,
    file_dev: 0,
    file_ino: 0,
    initial_ld_library_path_name: false,
    name: [0; 256],
};

// Safety: only accessed from single-threaded _start -> run_main
static mut LOADED: [LoadedObject; MAX_LOADED] = [EMPTY_OBJ; MAX_LOADED];
static mut LOADED_COUNT: usize = 0;
// `exit` reaches this hook through the dynamic CRT's `rtld_fini` callback.
// It is deliberately one-shot: a nested/duplicated finalization request must
// never replay DSO fini arrays after their mappings or runtime state have
// begun to wind down.
static mut PROCESS_FINALIZED: bool = false;
// The executable CRT enters this callback after its preinit array.  Keep the
// initial graph one-shot even if malformed application code reaches the
// private libc bridge again; runtime dlopen uses `run_constructors_for`
// directly and is not covered by this flag.
static mut INITIAL_CONSTRUCTORS_RAN: bool = false;
// Set exactly once after the main image's mapped ELF note is inspected and
// before libc can invoke the private conventional-CRT callback.
static mut INITIAL_MAIN_USES_OWNED_CRT: bool = false;
// No application code runs while the initial DT_NEEDED graph is discovered.
// This makes the process's loader search path stable for the narrowly scoped
// bare-name reuse cache below. Runtime dlopen deliberately never uses it.
static mut INITIAL_LOAD_IN_PROGRESS: bool = false;

// These layouts are the public ELF/link.h ABI.  The arrays are kept beside
// LOADED so a dlinfo result remains stable even though dlopen handles retain
// their historical LoadedObject representation for dlsym/dlclose.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct LdsoDlPhdrInfo {
    dlpi_addr: usize,
    dlpi_name: *const u8,
    dlpi_phdr: *const u8,
    dlpi_phnum: u16,
    dlpi_adds: u64,
    dlpi_subs: u64,
    dlpi_tls_modid: usize,
    dlpi_tls_data: *mut u8,
}

#[repr(C)]
pub struct LdsoDladdrResult {
    fname: *const u8,
    fbase: usize,
    sname: *const u8,
    saddr: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct LdsoLinkMap {
    l_addr: usize,
    l_name: *mut u8,
    l_ld: *mut u8,
    l_next: *mut LdsoLinkMap,
    l_prev: *mut LdsoLinkMap,
}

// These records are a private callback-free wire boundary with libc.  Keep
// the layout independent of `crabc-core`: ldso is the owner of loader state
// and must remain a standalone no_std interpreter.  The corresponding libc
// and Rust types are repr(C) copies of these fields.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct LdsoSnapshotText {
    len: u16,
    flags: u16,
    bytes: [u8; 256],
}

#[repr(C)]
pub struct LdsoLoaderImageV1 {
    image_base: *mut c_void,
    program_headers: *const c_void,
    program_header_count: u16,
    reserved: u16,
    additions: u64,
    removals: u64,
    tls_module: usize,
    tls_data: *mut c_void,
    image_name: LdsoSnapshotText,
}

#[repr(C)]
pub struct LdsoLoaderInformationV1 {
    image_base: *mut c_void,
    dynamic_address: *mut c_void,
    image_name: LdsoSnapshotText,
}

const EMPTY_SNAPSHOT_TEXT: LdsoSnapshotText = LdsoSnapshotText {
    len: 0,
    flags: 0,
    bytes: [0; 256],
};

const EMPTY_LINK_MAP: LdsoLinkMap = LdsoLinkMap {
    l_addr: 0,
    l_name: core::ptr::null_mut(),
    l_ld: core::ptr::null_mut(),
    l_next: core::ptr::null_mut(),
    l_prev: core::ptr::null_mut(),
};

static mut LINK_MAPS: [LdsoLinkMap; MAX_LOADED] = [EMPTY_LINK_MAP; MAX_LOADED];
// musl's dl_phdr_info exposes process-wide load/unload counters.  This
// loader keeps unload as a no-op, so only successful post-startup additions
// advance the observable state.
static mut DL_ADDS: u64 = 0;
static mut DL_SUBS: u64 = 0;

// musl exposes the loader's debugger rendezvous through `_dl_debug_addr`.
// Its private `struct debug` has the same C layout as the public `struct
// r_debug` in link.h: the debugger observes the current link-map head, the
// breakpoint hook, the load/unload state, and the interpreter base.  Keep the
// object in ldso, beside the authoritative LOADED/LINK_MAPS state, rather than
// synthesizing a callback-only compatibility object in libc.
const RT_CONSISTENT: i32 = 0;
const RT_ADD: i32 = 1;
const RT_DELETE: i32 = 2;

#[repr(C)]
pub struct LdsoDebug {
    pub r_version: i32,
    pub r_map: *mut LdsoLinkMap,
    pub r_brk: usize,
    pub r_state: i32,
    pub r_ldbase: usize,
}

static mut LDSO_DEBUG: LdsoDebug = LdsoDebug {
    r_version: 1,
    r_map: core::ptr::null_mut(),
    r_brk: 0,
    r_state: RT_CONSISTENT,
    r_ldbase: 0,
};

/// Pointer-valued object required by musl's loader/debugger ABI.
///
/// The pointer is relocated by the same self-relative relocation pass as the
/// rest of ldso's data.  Its pointee is updated from LOADED/LINK_MAPS whenever
/// the loader reaches a debugger-visible state transition.
#[no_mangle]
pub static mut _dl_debug_addr: *mut LdsoDebug = core::ptr::addr_of_mut!(LDSO_DEBUG);

static mut LDSO_BASE: usize = 0;

/// Debugger rendezvous hook from musl's loader ABI.
///
/// The default hook is deliberately inert, as in musl.  Debuggers replace or
/// instrument the rendezvous through the `r_brk` address in `_dl_debug_addr`;
/// ldso still calls this weak definition at each state transition so the hook
/// is a real part of loader progress rather than an uncallable placeholder.
#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn _dl_debug_state() {}

static mut TLS_TOTAL_SIZE: usize = 0;
// The logical end of placed TLS modules.  ``TLS_TOTAL_SIZE`` is deliberately
// a larger allocated capacity so a newly loaded DSO can extend the layout
// without discarding the static modules that have already been initialized.
static mut TLS_USED_SIZE: usize = 0;
// On AArch64, TP must retain the strongest static TLS alignment.  The TCB
// lives below TP, so a fixed 256-byte TCB alone is insufficient when an
// executable has, for example, a 4 KiB-aligned local-exec TLS variable.
static mut TLS_TP_OFFSET: usize = TCB_SIZE;
static mut TLS_LAYOUT_OFFSET: [usize; MAX_LOADED] = [0; MAX_LOADED];
static mut TLS_FILESZ: [u64; MAX_LOADED] = [0; MAX_LOADED];
static mut TLS_MEMSZ: [u64; MAX_LOADED] = [0; MAX_LOADED];
static mut TLS_IMAGE: [*const u8; MAX_LOADED] = [core::ptr::null(); MAX_LOADED];
static mut TLS_MODULE_COUNT: usize = 0;
// Modules present before the initial TLS block is created can use a fixed
// TP-relative descriptor. A module loaded later must consult the current
// thread because pre-existing threads do not yet contain its TLS image.
static mut TLS_STATIC_MODULE_COUNT: usize = 0;
// Each allocation retains its layout generation in its TCB. A later lookup
// compares that generation with the current process layout, then initializes
// only the stable module-ID suffix recorded as missing by that allocation.
// This covers several dlopen calls before an existing thread touches any of
// their TLS symbols without rescanning the already-initialized prefix.
static mut TLS_GENERATION: u64 = 1;
static TLS_LOCK: AtomicBool = AtomicBool::new(false);
// Runtime loader operations are serialized like musl's global loader lock.
// The lock is recursive for constructor callbacks, which may call dlopen or
// dlsym while the outer operation is still mutating the object graph.
static LOADER_LOCK: AtomicBool = AtomicBool::new(false);
static LOADER_OWNER: AtomicUsize = AtomicUsize::new(0);
static LOADER_DEPTH: AtomicUsize = AtomicUsize::new(0);
// A process starts with one execution context, so loader operations need no
// atomic synchronization until libc is about to publish its first pthread.
// The transition is one-way: retaining the locked route after a thread exits,
// a failed create, or fork is conservative and avoids inferring liveness from
// racy thread-registry state.
static LOADER_MULTI_THREADED: AtomicBool = AtomicBool::new(false);
static mut LOADER_SINGLE_DEPTH: usize = 0;

const DLERROR_BUF_SIZE: usize = 128;

#[repr(C)]
struct DlErrorNode {
    set: AtomicBool,
    buf: [u8; DLERROR_BUF_SIZE],
}

// Error nodes are allocated once per loader-owned TCB and are intentionally
// retained. A new thread gets a freshly cleared TCB cache entry, so a recycled
// thread-pointer allocation cannot inherit a prior thread's pending error.
static DLERROR_LOCK: AtomicBool = AtomicBool::new(false);
static mut LD_LIBRARY_PATH: *const u8 = core::ptr::null();
// The loader samples LD_LIBRARY_PATH from the initial kernel stack before
// application code can create another thread. Its nonempty components are
// therefore immutable loader input. Cache a bounded common case so every
// DT_NEEDED edge need not rescan the same delimiters; an unusually long path
// deliberately uses the existing bytewise route rather than truncating its
// search. Parent RUNPATH/RPATH strings and direct dlopen names never use this
// cache because their owning object's search semantics remain separate.
const INITIAL_LD_LIBRARY_PATH_COMPONENT_CAPACITY: usize = 16;

#[derive(Copy, Clone)]
struct LibraryPathComponent {
    offset: usize,
    length: usize,
}

const EMPTY_LIBRARY_PATH_COMPONENT: LibraryPathComponent = LibraryPathComponent {
    offset: 0,
    length: 0,
};

static mut INITIAL_LD_LIBRARY_PATH_COMPONENTS: [LibraryPathComponent;
    INITIAL_LD_LIBRARY_PATH_COMPONENT_CAPACITY] =
    [EMPTY_LIBRARY_PATH_COMPONENT; INITIAL_LD_LIBRARY_PATH_COMPONENT_CAPACITY];
static mut INITIAL_LD_LIBRARY_PATH_COMPONENT_COUNT: usize = 0;
static mut INITIAL_LD_LIBRARY_PATH_COMPONENTS_COMPLETE: bool = false;
static mut RUNPATH: *const u8 = core::ptr::null();
static mut RUNPATH_LEN: usize = 0;
const ORIGIN_CAPACITY: usize = 256;
static mut ORIGIN_DIR: [u8; ORIGIN_CAPACITY] = [0; ORIGIN_CAPACITY];
static mut ORIGIN_LEN: usize = 0;

// ============================================================
// _start: self-relocate ldso, then call run_main(sp)
// ============================================================

// aarch64 _start: self-relocate ldso, then call run_main(sp, ldso_base)
#[cfg(not(test))]
core::arch::global_asm!(
    ".global _start",
    ".type _start, @function",
    "_start:",
    // Save sp into x29 (frame pointer, callee-saved)
    "mov x29, sp",
    // Walk stack: argc, argv[], NULL, envp[], NULL, auxv[]
    "ldr x0, [sp]",              // argc
    "add x1, sp, #8",            // &argv[0]
    "add x2, x1, x0, lsl #3",   // skip argv[]
    "add x2, x2, #8",            // skip NULL after argv -> &envp[0]
    "2:",
    "ldr x3, [x2]",
    "cbz x3, 3f",
    "add x2, x2, #8",
    "b 2b",
    "3:",
    "add x2, x2, #8",            // &auxv[0]
    "mov x20, #0",                // ldso_base = 0
    "4:",
    "ldr x3, [x2]",              // auxv tag
    "cbz x3, 5f",                // AT_NULL -> done
    "cmp x3, #7",                // AT_BASE
    "bne 6f",
    "ldr x20, [x2, #8]",         // ldso_base
    "6:",
    "add x2, x2, #16",
    "b 4b",
    "5:",
    // x20 = ldso_base. Walk ldso's ELF phdrs to find PT_DYNAMIC.
    "ldr x0, [x20, #32]",        // e_phoff
    "ldrh w1, [x20, #56]",       // e_phnum
    "add x2, x20, x0",           // phdr table
    "mov x3, #0",                 // i
    "7:",
    "cmp x3, x1",
    "bge 8f",
    "ldr w4, [x2]",              // p_type
    "cmp w4, #2",                // PT_DYNAMIC
    "beq 9f",
    "add x2, x2, #56",           // next phdr (PHDR_SIZE=56)
    "add x3, x3, #1",
    "b 7b",
    "9:",
    // Found PT_DYNAMIC. Read DT_RELA and DT_RELASZ from dynamic section.
    "ldr x4, [x2, #16]",         // p_vaddr
    "ldr x5, [x2, #40]",         // p_memsz
    "add x4, x4, x20",           // dyn_addr = base + p_vaddr
    "add x5, x4, x5",            // dyn_end
    "mov x6, #0",                 // rela = 0
    "mov x7, #0",                 // relasz = 0
    "10:",
    "cmp x4, x5",
    "bge 11f",
    "ldr x8, [x4]",              // d_tag
    "ldr x9, [x4, #8]",          // d_val
    "cbz x8, 11f",               // DT_NULL
    "cmp x8, #7",                // DT_RELA
    "bne 12f",
    "add x6, x20, x9",           // rela = base + d_val
    "12:",
    "cmp x8, #8",                // DT_RELASZ
    "bne 13f",
    "mov x7, x9",                // relasz = d_val
    "13:",
    "add x4, x4, #16",
    "b 10b",
    "11:",
    // Apply R_AARCH64_RELATIVE (type 1027) relocations.
    "cbz x7, 8f",
    "cbz x6, 8f",
    "add x8, x6, x7",            // table_end
    "14:",
    "cmp x6, x8",
    "bge 8f",
    "ldr x9, [x6]",              // r_offset
    "ldr x10, [x6, #8]",         // r_info
    "ldr x11, [x6, #16]",        // r_addend
    "cmp w10, #1027",             // R_AARCH64_RELATIVE
    "bne 15f",
    "add x9, x9, x20",           // slot = base + r_offset
    "add x11, x11, x20",         // val = base + r_addend
    "str x11, [x9]",
    "15:",
    "add x6, x6, #24",
    "b 14b",
    "8:",
    ".hidden {run_main}",
    "mov x0, x29",               // sp
    "mov x1, x20",               // ldso_base
    "bl {run_main}",
    "brk #1",
    run_main = sym run_main,
);

// ============================================================
// Entry point
// ============================================================

// Keep a named, default-visible raw-entry bridge for libc's `_dlstart` GOT
// trampoline.  This is deliberately a naked tail branch: it preserves the
// initial stack/register convention and must never be called as a C function.
#[no_mangle]
#[unsafe(naked)]
#[cfg(not(test))]
pub unsafe extern "C" fn __ldso_dlstart() -> ! {
    core::arch::naked_asm!("b _start");
}

#[no_mangle]
pub unsafe extern "C" fn run_main(sp: usize, ldso_base: u64) -> ! {
    unsafe { load_and_jump(sp, ldso_base) }
}

// ============================================================
// String helpers (no_std)
// ============================================================

unsafe fn str_len(s: *const u8) -> usize {
    let mut len = 0;
    while *s.add(len) != 0 {
        len += 1;
    }
    len
}

// LLVM may lower inlined `str_len` callers to the C `strlen` symbol.  The
// loader needs that implementation before it has mapped libc, but applications
// must resolve their public `strlen` calls from libc rather than this bootstrap
// helper.  Keep the symbol linkable within this DSO and mark it hidden below.
#[no_mangle]
unsafe extern "C" fn strlen(s: *const u8) -> usize {
    unsafe { str_len(s) }
}

// This is intentionally an ELF visibility directive rather than a Rust
// visibility modifier: `no_mangle` keeps the bootstrap definition linkable,
// while `.hidden` prevents it from entering the loader's public lookup scope.
core::arch::global_asm!(".hidden strlen");

unsafe fn sym_count_from_gnu_hash(gh: usize) -> usize {
    let nb = u32::from_le_bytes(core::ptr::read_unaligned(gh as *const [u8; 4])) as usize;
    let symoffset =
        u32::from_le_bytes(core::ptr::read_unaligned((gh + 4) as *const [u8; 4])) as usize;
    let bloom_size =
        u32::from_le_bytes(core::ptr::read_unaligned((gh + 8) as *const [u8; 4])) as usize;
    let buckets = gh + 16 + bloom_size * 8;
    let chain = buckets + nb * 4;
    let mut max_idx = 0usize;
    let mut has_any = false;
    for i in 0..nb {
        let symidx = u32::from_le_bytes(core::ptr::read_unaligned(
            (buckets + i * 4) as *const [u8; 4],
        )) as usize;
        if symidx == 0 || symidx < symoffset {
            continue;
        }
        let mut idx = symidx;
        loop {
            let cidx = idx - symoffset;
            if cidx > max_idx {
                max_idx = cidx;
            }
            has_any = true;
            let entry = u32::from_le_bytes(core::ptr::read_unaligned(
                (chain + cidx * 4) as *const [u8; 4],
            ));
            if entry & 1 != 0 {
                break;
            }
            idx += 1;
        }
    }
    if has_any {
        symoffset + max_idx + 1
    } else {
        symoffset
    }
}

unsafe fn sym_count_from_hash(h: usize) -> usize {
    let nchain = u32::from_le_bytes(core::ptr::read_unaligned((h + 4) as *const [u8; 4])) as usize;
    nchain
}

/// GNU hash-table function specified by the generic ELF ABI.
///
/// The caller already knows the name's NUL-terminated length. Keeping the
/// length at this boundary avoids a second unbounded string walk on every
/// relocation and `dlsym` lookup.
unsafe fn gnu_symbol_hash(name: *const u8, name_len: usize) -> u32 {
    let mut hash = 5381u32;
    for i in 0..name_len {
        hash = hash.wrapping_mul(33).wrapping_add(*name.add(i) as u32);
    }
    hash
}

/// Read a public C symbol name once while deriving its GNU hash.
///
/// `dlsym` must retain the byte length for its private-name and dlerror
/// paths. Deriving it here avoids walking the same NUL-terminated name once
/// for `str_len` and again in `gnu_symbol_hash` before an ordinary GNU lookup.
unsafe fn gnu_symbol_hash_c_string(name: *const u8) -> (usize, u32) {
    let mut name_len = 0;
    let mut hash = 5381u32;
    loop {
        let byte = *name.add(name_len);
        if byte == 0 {
            return (name_len, hash);
        }
        hash = hash.wrapping_mul(33).wrapping_add(byte as u32);
        name_len += 1;
    }
}

/// Legacy System V ELF hash-table function.
unsafe fn sysv_symbol_hash(name: *const u8, name_len: usize) -> u32 {
    let mut hash = 0u32;
    for i in 0..name_len {
        hash = hash.wrapping_shl(4).wrapping_add(*name.add(i) as u32);
        let high = hash & 0xf000_0000;
        if high != 0 {
            hash ^= high >> 24;
        }
        hash &= !high;
    }
    hash
}

unsafe fn read_hash_u32(address: usize) -> Option<u32> {
    address.checked_add(4)?;
    // Hash addresses originate in a mapped ELF dynamic table. Their integer
    // form is used only for checked ELF address arithmetic before restoring
    // exposed provenance at the raw read boundary.
    let pointer = core::ptr::with_exposed_provenance::<u8>(address).cast::<[u8; 4]>();
    Some(u32::from_le_bytes(core::ptr::read_unaligned(pointer)))
}

/// Decode the fixed GNU hash header once while registering an object.
///
/// The dynamic table has already supplied a mapped `DT_GNU_HASH` address. We
/// keep each derived address as a raw pointer, but use integer arithmetic only
/// for the checked offsets that ELF encodes. This leaves lookup to load just
/// the bucket and chain entries it needs, rather than reparsing immutable
/// header fields for every symbol resolution.
unsafe fn gnu_hash_metadata(table: *const u8, sym_count: usize) -> Option<GnuHashMetadata> {
    if table.is_null() {
        return None;
    }

    let table_addr = table.addr();
    let bucket_count = read_hash_u32(table_addr)?;
    let symbol_offset = read_hash_u32(table_addr.checked_add(4)?)?;
    let bloom_count = read_hash_u32(table_addr.checked_add(8)?)?;
    let bloom_shift = read_hash_u32(table_addr.checked_add(12)?)?;
    if bucket_count == 0
        || bloom_count == 0
        || bloom_shift >= u32::BITS
        || symbol_offset as usize > sym_count
    {
        return None;
    }

    let bloom_addr = table_addr.checked_add(16)?;
    let bucket_addr = bloom_addr.checked_add((bloom_count as usize).checked_mul(8)?)?;
    let chain_addr = bucket_addr.checked_add((bucket_count as usize).checked_mul(4)?)?;
    Some(GnuHashMetadata {
        bucket_count,
        symbol_offset,
        bloom_count,
        bloom_mask: if bloom_count.is_power_of_two() {
            bloom_count - 1
        } else {
            u32::MAX
        },
        bloom_shift,
        // These addresses denote the same retained mapped ELF bytes that the
        // table address did. Exposed provenance is restored only at the raw
        // pointer boundary after checked integer offset arithmetic. Their
        // typed forms encode the fixed ELF entry widths for the hot lookup.
        bloom: core::ptr::with_exposed_provenance::<u64>(bloom_addr),
        buckets: core::ptr::with_exposed_provenance::<u32>(bucket_addr),
        chains: core::ptr::with_exposed_provenance::<u32>(chain_addr),
    })
}

#[inline(always)]
fn gnu_bloom_index(hash: u32, bloom_count: u32, bloom_mask: u32) -> usize {
    let bloom_hash = hash >> 6;
    if bloom_mask == u32::MAX {
        (bloom_hash % bloom_count) as usize
    } else {
        (bloom_hash & bloom_mask) as usize
    }
}

/// Check a dynamic symbol candidate before returning its index from a hash
/// chain. This preserves the loader's historical rules for undefined and
/// local definitions while letting all scope walks share one indexed lookup.
unsafe fn symbol_matches<const REQUIRE_GLOBAL: bool>(
    obj: &LoadedObject,
    sym_idx: usize,
    name: *const u8,
    name_len: usize,
) -> bool {
    if sym_idx >= obj.sym_count {
        return false;
    }
    let sym = obj.symtab.add(sym_idx * SYMTAB_ENT_SIZE);
    if REQUIRE_GLOBAL && *sym.add(4) >> 4 == 0 {
        return false;
    }
    let value = u64::from_le_bytes(core::ptr::read_unaligned(sym.add(8) as *const [u8; 8]));
    if value == 0 {
        return false;
    }
    let name_offset = u32::from_le_bytes(core::ptr::read_unaligned(sym as *const [u8; 4])) as usize;
    name_offset < obj.strsz && str_eq(name, name_len, obj.strtab.add(name_offset))
}

unsafe fn lookup_gnu_hash_symbol<const REQUIRE_GLOBAL: bool>(
    obj: &LoadedObject,
    name: *const u8,
    name_len: usize,
    hash: u32,
) -> Option<usize> {
    let metadata = obj.gnu_hash_metadata?;
    let bloom_index = gnu_bloom_index(hash, metadata.bloom_count, metadata.bloom_mask);
    // `gnu_hash_metadata` decoded a nonzero table count and restored these
    // pointers from the mapped immutable table. The modular indices remain
    // within their respective table counts, so no per-lookup integer address
    // reconstruction is needed at this raw ELF boundary.
    let bloom_word = u64::from_le(core::ptr::read_unaligned(metadata.bloom.add(bloom_index)));
    let bloom_mask = (1u64 << (hash % 64)) | (1u64 << ((hash >> metadata.bloom_shift) % 64));
    if bloom_word & bloom_mask != bloom_mask {
        return None;
    }

    let bucket_index = (hash % metadata.bucket_count) as usize;
    let mut sym_idx = u32::from_le(core::ptr::read_unaligned(
        metadata.buckets.add(bucket_index),
    )) as usize;
    if sym_idx < metadata.symbol_offset as usize || sym_idx >= obj.sym_count {
        return None;
    }
    while sym_idx < obj.sym_count {
        let chain_idx = sym_idx - metadata.symbol_offset as usize;
        let chain_hash = u32::from_le(core::ptr::read_unaligned(metadata.chains.add(chain_idx)));
        if (chain_hash | 1) == (hash | 1)
            && symbol_matches::<REQUIRE_GLOBAL>(obj, sym_idx, name, name_len)
        {
            return Some(sym_idx);
        }
        if chain_hash & 1 != 0 {
            return None;
        }
        sym_idx = sym_idx.checked_add(1)?;
    }
    None
}

unsafe fn lookup_sysv_hash_symbol<const REQUIRE_GLOBAL: bool>(
    obj: &LoadedObject,
    name: *const u8,
    name_len: usize,
) -> Option<usize> {
    let table = obj.sysv_hash.addr();
    let bucket_count = read_hash_u32(table)? as usize;
    let chain_count = read_hash_u32(table.checked_add(4)?)? as usize;
    if bucket_count == 0 || chain_count == 0 {
        return None;
    }
    let buckets = table.checked_add(8)?;
    let chains = buckets.checked_add(bucket_count.checked_mul(4)?)?;
    let hash = sysv_symbol_hash(name, name_len);
    let mut sym_idx =
        read_hash_u32(buckets.checked_add((hash as usize % bucket_count).checked_mul(4)?)?)?
            as usize;
    for _ in 0..chain_count.min(obj.sym_count) {
        if sym_idx == 0 || sym_idx >= obj.sym_count || sym_idx >= chain_count {
            return None;
        }
        if symbol_matches::<REQUIRE_GLOBAL>(obj, sym_idx, name, name_len) {
            return Some(sym_idx);
        }
        sym_idx = read_hash_u32(chains.checked_add(sym_idx.checked_mul(4)?)?)? as usize;
    }
    None
}

unsafe fn lookup_linear_symbol<const REQUIRE_GLOBAL: bool>(
    obj: &LoadedObject,
    name: *const u8,
    name_len: usize,
) -> Option<usize> {
    for sym_idx in 0..obj.sym_count {
        if symbol_matches::<REQUIRE_GLOBAL>(obj, sym_idx, name, name_len) {
            return Some(sym_idx);
        }
    }
    None
}

/// Look up one defined dynamic symbol in one object. The GNU table is the
/// authoritative index when present; SysV is used only by legacy objects.
/// A no-hash object retains the existing bounded linear fallback.
unsafe fn lookup_symbol_index_in_object<const REQUIRE_GLOBAL: bool>(
    obj: &LoadedObject,
    name: *const u8,
    name_len: usize,
    gnu_hash: u32,
) -> Option<usize> {
    if obj.symtab.is_null() || obj.strtab.is_null() {
        return None;
    }
    if !obj.gnu_hash.is_null() {
        lookup_gnu_hash_symbol::<REQUIRE_GLOBAL>(obj, name, name_len, gnu_hash)
    } else if !obj.sysv_hash.is_null() {
        lookup_sysv_hash_symbol::<REQUIRE_GLOBAL>(obj, name, name_len)
    } else {
        lookup_linear_symbol::<REQUIRE_GLOBAL>(obj, name, name_len)
    }
}

#[no_mangle]
pub unsafe extern "C" fn memcmp(a: *const c_void, b: *const c_void, n: usize) -> i32 {
    let a = a as *const u8;
    let b = b as *const u8;
    let mut i = 0;
    while i < n {
        let va = *a.add(i);
        let vb = *b.add(i);
        if va != vb {
            return va as i32 - vb as i32;
        }
        i += 1;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn bcmp(a: *const c_void, b: *const c_void, n: usize) -> i32 {
    memcmp(a, b, n)
}

/// Compare null-terminated `a` (with known length) against null-terminated `b`.
unsafe fn str_eq(a: *const u8, a_len: usize, b: *const u8) -> bool {
    let mut i = 0;
    while i < a_len {
        if *a.add(i) != *b.add(i) {
            return false;
        }
        i += 1;
    }
    *b.add(a_len) == 0
}

/// Walk kernel-stack envp for a var starting with `prefix` (e.g. b"LD_LIBRARY_PATH=").
/// Returns pointer to the value part (after the '=') or None.
unsafe fn find_env(sp: usize, prefix: &[u8]) -> Option<*const u8> {
    let argc = *(sp as *const u64) as usize;
    // skip: argc + argv[0..argc] + NULL
    let mut p = sp + 8 + (argc + 1) * 8;
    loop {
        let env_ptr = *(p as *const u64) as *const u8;
        if env_ptr.is_null() {
            break;
        }
        let mut matches = true;
        let mut i = 0;
        while i < prefix.len() {
            if *env_ptr.add(i) != prefix[i] {
                matches = false;
                break;
            }
            i += 1;
        }
        if matches {
            return Some(env_ptr.add(prefix.len()));
        }
        p += 8;
    }
    None
}

/// Read one auxiliary-vector value without copying or truncating the kernel
/// startup vector.  The kernel guarantees a terminating AT_NULL entry.
unsafe fn find_auxv_value(sp: usize, tag_wanted: u64) -> u64 {
    let argc = *(sp as *const u64) as usize;
    let argv_start = sp + 8;
    let envp_start = argv_start + (argc + 1) * 8;
    let mut envc = 0usize;
    while *((envp_start + envc * 8) as *const u64) != 0 {
        envc += 1;
    }
    let auxv = (envp_start + (envc + 1) * 8) as *const u64;
    let mut i = 0usize;
    loop {
        let tag = *auxv.add(i * 2);
        let value = *auxv.add(i * 2 + 1);
        if tag == AT_NULL {
            return 0;
        }
        if tag == tag_wanted {
            return value;
        }
        i += 1;
    }
}

/// Read the already-mapped main image from the kernel's initial auxiliary
/// vector. Linux has loaded this PIE before it transfers control to PT_INTERP,
/// so remapping it would retain a redundant executable image and invalidate
/// the kernel-provided load layout.
unsafe fn kernel_main_image(sp: usize) -> KernelMainImage {
    let phdr_address = find_auxv_value(sp, AT_PHDR);
    let phent = find_auxv_value(sp, AT_PHENT);
    let phnum = find_auxv_value(sp, AT_PHNUM);
    let entry = find_auxv_value(sp, AT_ENTRY);
    if phdr_address == 0 || entry == 0 || phent as usize != PHDR_SIZE || phnum == 0 {
        die(97, b"auxv_main", phdr_address as usize);
    }
    let phnum = phnum as usize;
    if phnum.checked_mul(PHDR_SIZE).is_none() {
        die(97, b"auxv_phnum", phnum);
    }

    // SAFETY: `AT_PHDR` is a Linux kernel ABI address for the mapped main
    // image's program-header table. The checked table size above bounds only
    // our arithmetic; the kernel owns the mapping's lifetime through exec.
    let phdr = core::ptr::with_exposed_provenance::<u8>(phdr_address as usize);
    let mut base = None;
    for index in 0..phnum {
        let offset = match index.checked_mul(PHDR_SIZE) {
            Some(offset) => offset,
            None => die(97, b"auxv_phoff", index),
        };
        let header = unsafe {
            // SAFETY: `offset` is within the kernel-advertised program-header
            // table, whose entry size was validated against the ELF64 ABI.
            phdr.add(offset)
        };
        let header_type = unsafe {
            // SAFETY: `header` points at one complete kernel-provided ELF64
            // program header, so its four-byte type field is initialized.
            u32::from_le_bytes(core::ptr::read_unaligned(header.cast::<[u8; 4]>()))
        };
        if header_type != PT_PHDR {
            continue;
        }
        let virtual_address = unsafe {
            // SAFETY: `PH_VADDR..PH_VADDR + 8` lies inside the validated
            // ELF64 program-header entry addressed by `header`.
            let field = header.add(PH_VADDR).cast::<[u8; 8]>();
            u64::from_le_bytes(core::ptr::read_unaligned(field))
        };
        let Some(candidate) = phdr_address.checked_sub(virtual_address) else {
            die(97, b"auxv_phdr", virtual_address as usize);
        };
        if let Some(existing) = base {
            if existing != candidate {
                die(97, b"auxv_phdr", candidate as usize);
            }
        } else {
            base = Some(candidate);
        }
    }
    let Some(base) = base else {
        die(97, b"auxv_phdr", phdr_address as usize);
    };

    KernelMainImage {
        base,
        phdr,
        phnum,
        entry,
    }
}

/// Seed the executable `$ORIGIN` directory from Linux's kernel-owned
/// `AT_EXECFN` path, keeping the historic 256-byte loader storage bound.
unsafe fn initialize_main_origin(sp: usize) {
    ORIGIN_LEN = 0;
    let executable_address = find_auxv_value(sp, AT_EXECFN);
    if executable_address == 0 {
        return;
    }
    // SAFETY: `AT_EXECFN` names a NUL-terminated executable path in the
    // kernel-built startup stack. The loop never reads past the loader's
    // fixed 256-byte origin capacity.
    let executable = core::ptr::with_exposed_provenance::<u8>(executable_address as usize);
    let mut length = 0usize;
    while length < ORIGIN_CAPACITY {
        let byte = unsafe {
            // SAFETY: the kernel owns the NUL-terminated `AT_EXECFN` string,
            // and the loop bounds this read to the fixed origin capacity.
            *executable.add(length)
        };
        if byte == 0 {
            break;
        }
        length += 1;
    }
    let mut slash = length;
    let mut found_slash = false;
    while slash > 0 {
        slash -= 1;
        let byte = unsafe {
            // SAFETY: `slash < length <= ORIGIN_CAPACITY`, which is the
            // same bounded prefix already read from `AT_EXECFN` above.
            *executable.add(slash)
        };
        if byte == b'/' {
            found_slash = true;
            break;
        }
    }
    if !found_slash {
        return;
    }
    unsafe {
        // SAFETY: both source and destination hold distinct kernel/loader-
        // owned byte ranges, and `slash < ORIGIN_CAPACITY` by the bounded
        // search.
        core::ptr::copy_nonoverlapping(
            executable,
            core::ptr::addr_of_mut!(ORIGIN_DIR).cast::<u8>(),
            slash,
        );
    }
    ORIGIN_LEN = slash;
}

unsafe fn secure_env_entry_is_unsafe(entry: *const u8) -> bool {
    let library_path = b"LD_LIBRARY_PATH=";
    let preload = b"LD_PRELOAD=";
    let entry_len = str_len(entry);
    if entry_len < library_path.len() && entry_len < preload.len() {
        return false;
    }
    let mut path_match = entry_len >= library_path.len();
    let mut preload_match = entry_len >= preload.len();
    for i in 0..library_path.len() {
        if path_match && *entry.add(i) != library_path[i] {
            path_match = false;
        }
    }
    for i in 0..preload.len() {
        if preload_match && *entry.add(i) != preload[i] {
            preload_match = false;
        }
    }
    path_match || preload_match
}

// ============================================================
// Syscall wrappers (raw, no_std)
// ============================================================

// The syscall implementation and AArch64 numbers live in `aarch64`.

const AT_FDCWD: i64 = -100;

// ============================================================
// Syscall wrappers (raw, no_std)
// ============================================================

fn sys_open(path: *const u8) -> i64 {
    unsafe { syscall3(SYS_OPENAT, AT_FDCWD, path as i64, 0) }
}

fn sys_read(fd: i64, buf: *mut u8, count: usize) -> i64 {
    unsafe { syscall3(SYS_READ, fd, buf as i64, count as i64) }
}

fn sys_fstat(fd: i64, buf: *mut u8) -> i64 {
    unsafe { syscall2(SYS_FSTAT, fd, buf as i64) }
}

fn sys_write(fd: i64, buf: *const u8, count: usize) -> i64 {
    unsafe { syscall3(SYS_WRITE, fd, buf as i64, count as i64) }
}

fn sys_close(fd: i64) {
    unsafe {
        syscall1(SYS_CLOSE, fd);
    }
}

/// Return an identity that remains stable while a thread owns the recursive
/// loader lock. Dynamic TLS growth changes TP, so the first TP installed for
/// a loader-owned TCB is preserved in that TCB and becomes the token. The
/// low-bit tag reserves zero as the unlocked sentinel.
unsafe fn loader_owner_token() -> usize {
    let thread_pointer = read_tp();
    if thread_pointer == 0 {
        // Loader entry has no public dl* callers before it installs a TCB.
        // Keep the early single-threaded case representable without a syscall.
        return 1;
    }
    let tcb = tcb_for_thread(thread_pointer);
    let initial_thread_pointer =
        core::ptr::read_unaligned(tcb.add(TCB_LOADER_OWNER_OFFSET) as *const usize);
    let identity = if initial_thread_pointer == 0 {
        thread_pointer
    } else {
        initial_thread_pointer
    };
    identity | 1
}

unsafe fn loader_lock() {
    if !LOADER_MULTI_THREADED.load(Ordering::Acquire) {
        LOADER_SINGLE_DEPTH = LOADER_SINGLE_DEPTH.wrapping_add(1);
        return;
    }
    let owner = loader_owner_token();
    if LOADER_OWNER.load(Ordering::Acquire) == owner {
        LOADER_DEPTH.fetch_add(1, Ordering::Relaxed);
        return;
    }
    while LOADER_LOCK.swap(true, Ordering::Acquire) {}
    LOADER_OWNER.store(owner, Ordering::Relaxed);
    LOADER_DEPTH.store(1, Ordering::Release);
}

unsafe fn loader_unlock() {
    if !LOADER_MULTI_THREADED.load(Ordering::Acquire) {
        if LOADER_SINGLE_DEPTH != 0 {
            LOADER_SINGLE_DEPTH -= 1;
        }
        return;
    }
    let owner = loader_owner_token();
    if LOADER_OWNER.load(Ordering::Acquire) != owner {
        return;
    }
    if LOADER_DEPTH.fetch_sub(1, Ordering::Release) == 1 {
        LOADER_OWNER.store(0, Ordering::Relaxed);
        LOADER_LOCK.store(false, Ordering::Release);
    }
}

/// A successful `dlsym` only reads the already-published object graph. Before
/// libc can publish another pthread, that graph has no concurrent reader or
/// writer, so there is no lock state to maintain. Once the process has become
/// multi-threaded this acquires the ordinary recursive loader lock and the
/// caller must release it through `dlsym_unlock`.
unsafe fn dlsym_lock() -> bool {
    if !LOADER_MULTI_THREADED.load(Ordering::Acquire) {
        return false;
    }
    loader_lock();
    true
}

unsafe fn dlsym_unlock(locked: bool) {
    if locked {
        loader_unlock();
    }
}

/// Escalate loader synchronization before libc makes a second pthread
/// runnable. If `pthread_create` occurs in a loader callback, the current
/// single-thread recursion depth is transferred into the established lock
/// before `clone` can start its child. Outside a loader operation, only the
/// one-way mode bit changes.
///
/// # Safety
/// libc may call this only before publishing its first pthread. Calling it
/// after another execution context can enter loader code would race the
/// single-thread state being transferred into `LOADER_LOCK`.
#[no_mangle]
pub unsafe extern "C" fn __ldso_mark_multithreaded() {
    if LOADER_MULTI_THREADED.swap(true, Ordering::AcqRel) {
        return;
    }
    let depth = LOADER_SINGLE_DEPTH;
    if depth == 0 {
        return;
    }
    // This callback runs before libc issues the first successful `clone`, so
    // no other thread can hold the newly initialized lock yet.
    while LOADER_LOCK.swap(true, Ordering::Acquire) {}
    LOADER_OWNER.store(loader_owner_token(), Ordering::Relaxed);
    LOADER_DEPTH.store(depth, Ordering::Release);
}

unsafe fn dlerror_lock() {
    while DLERROR_LOCK.swap(true, Ordering::Acquire) {}
}

unsafe fn dlerror_unlock() {
    DLERROR_LOCK.store(false, Ordering::Release);
}

/// Find or allocate the caller's error node. The caller holds DLERROR_LOCK.
/// Its pointer is cached in the current loader-owned TCB, so successful dl*
/// calls do not need a Linux thread-id syscall just to clear error state.
unsafe fn dlerror_node_locked() -> *mut DlErrorNode {
    let thread_pointer = read_tp();
    if thread_pointer == 0 {
        return core::ptr::null_mut();
    }
    let tcb = tcb_for_thread(thread_pointer);
    let cached = core::ptr::read_unaligned(tcb.add(TCB_DLERROR_NODE_OFFSET) as *const usize);
    if cached != 0 {
        // The value was produced by `sys_mmap`, stored in this live TCB, and
        // the mapping is intentionally retained for the thread's lifetime.
        return core::ptr::with_exposed_provenance_mut::<DlErrorNode>(cached);
    }
    let size = core::mem::size_of::<DlErrorNode>();
    let map_size = match size.checked_add(4095).map(|value| value & !4095) {
        Some(value) => value,
        None => return core::ptr::null_mut(),
    };
    let mapping = sys_mmap(
        core::ptr::null_mut(),
        map_size,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    if mapping as usize == MAP_FAILED {
        return core::ptr::null_mut();
    }
    let node = mapping as *mut DlErrorNode;
    core::ptr::write(
        node,
        DlErrorNode {
            set: AtomicBool::new(false),
            buf: [0; DLERROR_BUF_SIZE],
        },
    );
    core::ptr::write_unaligned(tcb.add(TCB_DLERROR_NODE_OFFSET) as *mut usize, node.addr());
    node
}

fn sys_mmap(addr: *mut u8, length: usize, prot: i32, flags: i32, fd: i32, offset: i64) -> *mut u8 {
    let result = unsafe {
        syscall6(
            SYS_MMAP,
            addr as i64,
            length as i64,
            prot as i64,
            flags as i64,
            fd as i64,
            offset,
        )
    };
    if result < 0 && result > -4096 {
        return MAP_FAILED as *mut u8;
    }
    result as *mut u8
}

fn sys_mprotect(addr: *mut u8, length: usize, prot: i32) -> i64 {
    unsafe { syscall3(SYS_MPROTECT, addr as i64, length as i64, prot as i64) }
}

fn sys_exit(code: i32) -> ! {
    unsafe { syscall_noreturn1(SYS_EXIT, code as i64) }
}

fn sys_lseek(fd: i64, offset: i64) -> i64 {
    unsafe { syscall3(SYS_LSEEK, fd, offset, 0) }
}



#[inline(always)]
unsafe fn read_tp() -> usize {
    let tp: usize;
    core::arch::asm!("mrs {}, tpidr_el0", out(reg) tp);
    tp
}



#[inline(always)]
unsafe fn write_tp(addr: usize) {
    core::arch::asm!("msr tpidr_el0, {}", in(reg) addr);
}


unsafe fn write_stderr(msg: &[u8]) {
    let _ = sys_write(2, msg.as_ptr(), msg.len());
}

unsafe fn write_hex_stderr(v: usize) {
    let mut buf = [0u8; 18];
    buf[0] = b'0';
    buf[1] = b'x';
    for i in 0..16 {
        let nibble = ((v >> (60 - i * 4)) & 0xf) as u8;
        buf[2 + i] = if nibble < 10 {
            b'0' + nibble
        } else {
            b'a' + nibble - 10
        };
    }
    write_stderr(&buf);
}

unsafe fn die(code: i32, label: &[u8], detail: usize) -> ! {
    write_stderr(b"[ldso fatal ");
    write_stderr(label);
    write_stderr(b" ");
    write_hex_stderr(detail);
    write_stderr(b"]\n");
    sys_exit(code)
}

// ============================================================
// ELF helpers
// ============================================================

fn prot_from_flags(flags: u32) -> i32 {
    let mut prot = 0;
    if flags & PF_R != 0 {
        prot |= PROT_READ;
    }
    if flags & PF_W != 0 {
        prot |= PROT_WRITE;
    }
    if flags & PF_X != 0 {
        prot |= PROT_EXEC;
    }
    prot
}

// ============================================================
// Library search
// ============================================================

unsafe fn try_open(
    path_buf: &mut [u8; 512],
    dir: *const u8,
    dir_len: usize,
    lib_name: *const u8,
    lib_name_len: usize,
) -> i64 {
    if dir_len + 1 + lib_name_len >= 512 {
        return -1;
    }
    let mut pos = 0;
    let mut i = 0;
    while i < dir_len {
        path_buf[pos] = *dir.add(i);
        pos += 1;
        i += 1;
    }
    path_buf[pos] = b'/';
    pos += 1;
    let mut i = 0;
    while i < lib_name_len {
        path_buf[pos] = *lib_name.add(i);
        pos += 1;
        i += 1;
    }
    path_buf[pos] = 0;
    sys_open(path_buf.as_ptr())
}

unsafe fn try_open_expanded(
    path_buf: &mut [u8; 512],
    dir: *const u8,
    dir_len: usize,
    lib_name: *const u8,
    lib_name_len: usize,
    origin_dir: *const u8,
    origin_len: usize,
) -> i64 {
    if dir_len >= 7 {
        let origin = b"$ORIGIN";
        let mut matches = true;
        let mut i = 0;
        while i < 7 {
            if *dir.add(i) != origin[i] {
                matches = false;
                break;
            }
            i += 1;
        }
        if matches {
            let rem_len = dir_len - 7;
            if origin_len + rem_len + 1 + lib_name_len >= 512 {
                return -1;
            }
            let mut pos = 0;
            let mut i = 0;
            while i < origin_len {
                path_buf[pos] = *origin_dir.add(i);
                pos += 1;
                i += 1;
            }
            let mut i = 0;
            while i < rem_len {
                path_buf[pos] = *dir.add(7 + i);
                pos += 1;
                i += 1;
            }
            path_buf[pos] = b'/';
            pos += 1;
            let mut i = 0;
            while i < lib_name_len {
                path_buf[pos] = *lib_name.add(i);
                pos += 1;
                i += 1;
            }
            path_buf[pos] = 0;
            return sys_open(path_buf.as_ptr());
        }
    }
    try_open(path_buf, dir, dir_len, lib_name, lib_name_len)
}

#[derive(Copy, Clone, Eq, PartialEq)]
enum LibrarySearchSource {
    DirectName,
    LibraryPath,
    ParentSearchPath,
    DefaultPath,
}

#[derive(Copy, Clone)]
struct OpenedLibrary {
    fd: i64,
    source: LibrarySearchSource,
}

/// Captures the bounded initial `LD_LIBRARY_PATH` component list.
///
/// The path comes directly from the initial environment before the loader
/// transfers control to user code. Empty components retain the existing
/// behavior of not making the current working directory an implicit library
/// search root. Reaching the fixed capacity leaves `COMPLETE` false, which
/// makes every caller use the pre-existing unbounded scanner.
unsafe fn initialize_initial_ld_library_path(path: Option<*const u8>) {
    LD_LIBRARY_PATH = path.unwrap_or(core::ptr::null());
    INITIAL_LD_LIBRARY_PATH_COMPONENT_COUNT = 0;
    INITIAL_LD_LIBRARY_PATH_COMPONENTS_COMPLETE = false;

    let Some(path) = path else {
        INITIAL_LD_LIBRARY_PATH_COMPONENTS_COMPLETE = true;
        return;
    };

    let path_len = str_len(path);
    let mut start = 0usize;
    let mut count = 0usize;
    while start < path_len {
        let mut end = start;
        while end < path_len && *path.add(end) != b':' {
            end += 1;
        }
        if end > start {
            if count == INITIAL_LD_LIBRARY_PATH_COMPONENT_CAPACITY {
                return;
            }
            INITIAL_LD_LIBRARY_PATH_COMPONENTS[count] = LibraryPathComponent {
                offset: start,
                length: end - start,
            };
            count += 1;
        }
        if end == path_len {
            break;
        }
        start = end + 1;
    }
    INITIAL_LD_LIBRARY_PATH_COMPONENT_COUNT = count;
    INITIAL_LD_LIBRARY_PATH_COMPONENTS_COMPLETE = true;
}

unsafe fn find_library_fd(
    lib_name: *const u8,
    lib_name_len: usize,
    ld_path: Option<*const u8>,
    parent: Option<usize>,
) -> Option<OpenedLibrary> {
    if lib_name_len == 0 {
        return None;
    }
    let mut path_buf = [0u8; 512];
    let mut origin = [0u8; 256];

    // A bare DT_NEEDED name is searched only through the loader's configured
    // paths and trusted defaults.  Opening it directly would make the
    // process's current working directory an implicit search directory.
    let mut has_slash = false;
    for i in 0..lib_name_len {
        if *lib_name.add(i) == b'/' {
            has_slash = true;
            break;
        }
    }
    if has_slash {
        let fd = sys_open(lib_name);
        if fd >= 0 {
            return Some(OpenedLibrary {
                fd,
                source: LibrarySearchSource::DirectName,
            });
        }
    }

    if let Some(ldp) = ld_path {
        if ldp == LD_LIBRARY_PATH && INITIAL_LD_LIBRARY_PATH_COMPONENTS_COMPLETE {
            for index in 0..INITIAL_LD_LIBRARY_PATH_COMPONENT_COUNT {
                let component = INITIAL_LD_LIBRARY_PATH_COMPONENTS[index];
                let fd = try_open(
                    &mut path_buf,
                    ldp.add(component.offset),
                    component.length,
                    lib_name,
                    lib_name_len,
                );
                if fd >= 0 {
                    return Some(OpenedLibrary {
                        fd,
                        source: LibrarySearchSource::LibraryPath,
                    });
                }
            }
        } else {
            let ldp_len = str_len(ldp);
            let mut start = 0usize;
            while start < ldp_len {
                let mut end = start;
                while end < ldp_len && *ldp.add(end) != b':' {
                    end += 1;
                }
                if end > start {
                    let fd = try_open(
                        &mut path_buf,
                        ldp.add(start),
                        end - start,
                        lib_name,
                        lib_name_len,
                    );
                    if fd >= 0 {
                        return Some(OpenedLibrary {
                            fd,
                            source: LibrarySearchSource::LibraryPath,
                        });
                    }
                }
                if end >= ldp_len {
                    break;
                }
                start = end + 1;
            }
        }
    }

    let (rp, rp_len, origin_ptr, origin_len) = if let Some(idx) = parent {
        if idx >= LOADED_COUNT {
            (core::ptr::null(), 0, core::ptr::null(), 0)
        } else if idx == 0 {
            // The main executable's RUNPATH/RPATH is kept in startup state
            // rather than copied into LOADED[0]. Direct DT_NEEDED edges from
            // the executable still arrive here with parent index zero.
            (
                RUNPATH,
                RUNPATH_LEN,
                core::ptr::addr_of!(ORIGIN_DIR).cast::<u8>(),
                ORIGIN_LEN,
            )
        } else {
            let name = &LOADED[idx].name;
            let mut name_len = 0usize;
            while name_len < name.len() && name[name_len] != 0 {
                name_len += 1;
            }
            let mut slash = name_len;
            while slash > 0 {
                slash -= 1;
                if name[slash] == b'/' {
                    break;
                }
            }
            let origin_len = if name_len > 0 && name[slash] == b'/' {
                if slash == 0 {
                    1
                } else {
                    slash
                }
            } else {
                0
            };
            for i in 0..origin_len {
                origin[i] = name[i];
            }
            (
                LOADED[idx].search_path,
                LOADED[idx].search_path_len,
                origin.as_ptr(),
                origin_len,
            )
        }
    } else {
        (
            RUNPATH,
            RUNPATH_LEN,
            core::ptr::addr_of!(ORIGIN_DIR).cast::<u8>(),
            ORIGIN_LEN,
        )
    };

    if rp_len > 0 {
        let mut start = 0usize;
        while start < rp_len {
            let mut end = start;
            while end < rp_len && *rp.add(end) != b':' {
                end += 1;
            }
            if end > start {
                let fd = try_open_expanded(
                    &mut path_buf,
                    rp.add(start),
                    end - start,
                    lib_name,
                    lib_name_len,
                    origin_ptr,
                    origin_len,
                );
                if fd >= 0 {
                    return Some(OpenedLibrary {
                        fd,
                        source: LibrarySearchSource::ParentSearchPath,
                    });
                }
            }
            if end >= rp_len {
                break;
            }
            start = end + 1;
        }
    }

    let defaults: &[(&[u8], usize)] = &[(b"/lib", 4), (b"/usr/lib", 8), (b"/usr/local/lib", 14)];
    for &(dir_bytes, dir_len) in defaults {
        let fd = try_open(
            &mut path_buf,
            dir_bytes.as_ptr(),
            dir_len,
            lib_name,
            lib_name_len,
        );
        if fd >= 0 {
            return Some(OpenedLibrary {
                fd,
                source: LibrarySearchSource::DefaultPath,
            });
        }
    }

    None
}

// ============================================================
// DSO loading
// ============================================================

#[derive(Copy, Clone)]
struct FileIdentity {
    dev: u64,
    ino: u64,
}

/// Kernel-provided metadata for the main image already mapped before PT_INTERP
/// gains control.
///
/// `phdr` has exposed provenance because the address originates in Linux's
/// initial auxiliary vector. The kernel guarantees that the table belongs to
/// the live main image for this process.
#[derive(Clone, Copy)]
struct KernelMainImage {
    base: u64,
    phdr: *const u8,
    phnum: usize,
    entry: u64,
}

/// Read the kernel file identity for an open DSO.  Symlink aliases resolve to
/// the same `(st_dev, st_ino)` pair, while distinct files remain distinct even
/// when their DT_NEEDED names happen to match.
fn file_identity(fd: i64) -> Option<FileIdentity> {
    // The first two fields of Linux/AArch64 stat
    // layouts are st_dev and st_ino.  Keep the buffer private to the loader;
    // no libc struct layout is needed at this boundary.
    let mut stat = [0u8; 128];
    if sys_fstat(fd, stat.as_mut_ptr()) < 0 {
        return None;
    }
    Some(FileIdentity {
        dev: u64::from_ne_bytes(stat[0..8].try_into().unwrap()),
        ino: u64::from_ne_bytes(stat[8..16].try_into().unwrap()),
    })
}

/// Load a shared object from an already-open fd at the given base address.
/// Registers it in the LOADED array. Returns true on success.
fn sys_munmap(addr: *mut u8, length: usize) -> i64 {
    unsafe { syscall2(SYS_MUNMAP, addr as i64, length as i64) }
}

unsafe fn load_dso_from_fd(
    fd: i64,
    _desired_base: u64,
    identity: Option<FileIdentity>,
) -> Option<u64> {
    // The loaded-object array is the authoritative dependency graph.  Refuse
    // a new mapping before touching address space when its bounded capacity is
    // exhausted; returning a base without registering the object would leave
    // subsequent relocation and TLS passes with an incoherent graph.
    if LOADED_COUNT >= MAX_LOADED {
        return None;
    }
    let mut buf = [0u8; 4096];
    let n = sys_read(fd, buf.as_mut_ptr(), buf.len());
    if n < 64 {
        return None;
    }
    if buf[0] != 0x7f || buf[1] != b'E' {
        return None;
    }

    let e_phoff = u64::from_le_bytes(buf[32..40].try_into().unwrap());
    let e_phnum = u16::from_le_bytes(buf[56..58].try_into().unwrap()) as usize;
    let phdr_end = e_phoff as usize + e_phnum * PHDR_SIZE;
    if phdr_end > n as usize {
        return None;
    }

    #[derive(Copy, Clone)]
    struct LoadSeg {
        p_offset: u64,
        p_vaddr: u64,
        p_filesz: u64,
        p_memsz: u64,
        p_flags: u32,
    }

    let mut segs: [LoadSeg; 8] = [LoadSeg {
        p_offset: 0,
        p_vaddr: 0,
        p_filesz: 0,
        p_memsz: 0,
        p_flags: 0,
    }; 8];
    let mut seg_count: usize = 0;
    let mut lowest_segment = 0usize;
    let mut min_vaddr = u64::MAX;
    let mut max_vaddr_end = 0u64;

    let mut tls_vaddr: u64 = 0;
    let mut tls_filesz: u64 = 0;
    let mut tls_memsz: u64 = 0;
    let mut tls_align: u64 = 0;

    for i in 0..e_phnum {
        let ph = buf.as_ptr().add(e_phoff as usize + i * PHDR_SIZE);
        let p_type = u32::from_le_bytes(core::ptr::read_unaligned(ph as *const [u8; 4]));
        if p_type == PT_TLS {
            tls_vaddr =
                u64::from_le_bytes(core::ptr::read_unaligned(ph.add(PH_VADDR) as *const [u8; 8]));
            tls_filesz = u64::from_le_bytes(core::ptr::read_unaligned(
                ph.add(PH_FILESZ) as *const [u8; 8]
            ));
            tls_memsz =
                u64::from_le_bytes(core::ptr::read_unaligned(ph.add(PH_MEMSZ) as *const [u8; 8]));
            tls_align =
                u64::from_le_bytes(core::ptr::read_unaligned(ph.add(PH_ALIGN) as *const [u8; 8]));
            continue;
        }
        if p_type != PT_LOAD {
            continue;
        }
        if seg_count >= segs.len() {
            return None;
        }
        let p_flags =
            u32::from_le_bytes(core::ptr::read_unaligned(ph.add(PH_FLAGS) as *const [u8; 4]));
        let p_offset = u64::from_le_bytes(core::ptr::read_unaligned(
            ph.add(PH_OFFSET) as *const [u8; 8]
        ));
        let p_vaddr =
            u64::from_le_bytes(core::ptr::read_unaligned(ph.add(PH_VADDR) as *const [u8; 8]));
        let p_filesz = u64::from_le_bytes(core::ptr::read_unaligned(
            ph.add(PH_FILESZ) as *const [u8; 8]
        ));
        let p_memsz =
            u64::from_le_bytes(core::ptr::read_unaligned(ph.add(PH_MEMSZ) as *const [u8; 8]));
        segs[seg_count] = LoadSeg {
            p_offset,
            p_vaddr,
            p_filesz,
            p_memsz,
            p_flags,
        };
        if p_vaddr < min_vaddr {
            lowest_segment = seg_count;
        }
        seg_count += 1;
        if p_vaddr < min_vaddr {
            min_vaddr = p_vaddr;
        }
        let end = p_vaddr + p_memsz;
        if end > max_vaddr_end {
            max_vaddr_end = end;
        }
    }

    if seg_count == 0 || min_vaddr == u64::MAX {
        return None;
    }

    const PAGE: u64 = 4096;
    let image_start = min_vaddr & !(PAGE - 1);
    let image_end = (max_vaddr_end + PAGE - 1) & !(PAGE - 1);
    let total_size = (image_end - image_start) as usize;

    // musl maps the complete image span from the lowest PT_LOAD first, then
    // overlays only subsequent segments. This reserves the final contiguous
    // cleanup range and lets the lowest file-backed segment serve as the
    // initial mapping, saving a separate anonymous reservation for ordinary
    // small DSOs. Include its file offset so the first mapping still covers
    // the complete virtual span when a valid ELF layout starts at a nonzero
    // file page.
    let first = segs[lowest_segment];
    let first_offset = (first.p_offset & !(PAGE - 1)) as usize;
    let mapping_size = match total_size.checked_add(first_offset) {
        Some(size) => size,
        None => return None,
    };
    let mapping = sys_mmap(
        core::ptr::null_mut(),
        mapping_size,
        prot_from_flags(first.p_flags),
        MAP_PRIVATE,
        fd as i32,
        first_offset as i64,
    );
    if mapping as usize == MAP_FAILED {
        return None;
    }
    let actual_base = (mapping as u64).wrapping_sub(image_start);

    macro_rules! fail_mapping {
        () => {{
            // The fixed segment mappings all remain within this initial span.
            // One unmap therefore releases mapped segments and untouched
            // inter-segment holes together after a failed overlay.
            sys_munmap(mapping, mapping_size);
            return None;
        }};
    }

    let tls_image = (actual_base + tls_vaddr) as *const u8;

    for i in 0..seg_count {
        let seg = segs[i];
        let adj = seg.p_vaddr & (PAGE - 1);
        let map_addr = actual_base + seg.p_vaddr - adj;
        let map_off = seg.p_offset - adj;
        let map_len = ((seg.p_memsz + adj + PAGE - 1) & !(PAGE - 1)) as usize;
        let prot = prot_from_flags(seg.p_flags);

        let file_map_len = ((seg.p_filesz + adj + PAGE - 1) & !(PAGE - 1)) as usize;
        // The initial full-span mapping already supplies the lowest segment.
        // Every later PT_LOAD must replace its file-backed pages so its
        // protection and file offset take effect.
        if i != lowest_segment && file_map_len > 0 {
            let fptr = sys_mmap(
                map_addr as *mut u8,
                file_map_len,
                prot,
                MAP_PRIVATE | MAP_FIXED,
                fd as i32,
                map_off as i64,
            );
            if fptr as usize == MAP_FAILED {
                fail_mapping!();
            }
        }
        if map_len > file_map_len {
            let Some(tail_addr) = map_addr.checked_add(file_map_len as u64) else {
                fail_mapping!();
            };
            // The file image already covers its rounded final page. Map only
            // the remaining `p_memsz` tail anonymously for BSS. This also
            // replaces a low-segment tail that the full initial file mapping
            // may have placed beyond EOF.
            let tail = sys_mmap(
                tail_addr as *mut u8,
                map_len - file_map_len,
                prot,
                MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS,
                -1,
                0,
            );
            if tail as usize == MAP_FAILED {
                fail_mapping!();
            }
        }

        if seg.p_memsz > seg.p_filesz {
            let bss_start = (actual_base + seg.p_vaddr + seg.p_filesz) as *mut u8;
            let bss_len = (seg.p_memsz - seg.p_filesz) as usize;
            core::ptr::write_bytes(bss_start, 0, bss_len);
        }
    }

    // Find PT_DYNAMIC
    let mut dyn_vaddr: u64 = 0;
    let mut dyn_memsz: u64 = 0;
    let mut relro_vaddr: u64 = 0;
    let mut relro_memsz: u64 = 0;
    for i in 0..e_phnum {
        let ph = buf.as_ptr().add(e_phoff as usize + i * PHDR_SIZE);
        let p_type = u32::from_le_bytes(core::ptr::read_unaligned(ph as *const [u8; 4]));
        if p_type == PT_DYNAMIC {
            dyn_vaddr =
                u64::from_le_bytes(core::ptr::read_unaligned(ph.add(PH_VADDR) as *const [u8; 8]));
            dyn_memsz =
                u64::from_le_bytes(core::ptr::read_unaligned(ph.add(PH_MEMSZ) as *const [u8; 8]));
        } else if p_type == PT_GNU_RELRO {
            relro_vaddr =
                u64::from_le_bytes(core::ptr::read_unaligned(ph.add(PH_VADDR) as *const [u8; 8]));
            relro_memsz =
                u64::from_le_bytes(core::ptr::read_unaligned(ph.add(PH_MEMSZ) as *const [u8; 8]));
        }
    }
    if dyn_vaddr == 0 {
        fail_mapping!();
    }

    let dyn_addr = (actual_base + dyn_vaddr) as usize;
    let dyn_end = dyn_addr + dyn_memsz as usize;

    // Parse DT_SYMTAB, DT_STRTAB, DT_STRSZ
    let mut dt_symtab: u64 = 0;
    let mut dt_strtab: u64 = 0;
    let mut dt_strsz: u64 = 0;
    let mut dt_init: u64 = 0;
    let mut dt_init_array: u64 = 0;
    let mut dt_init_array_sz: u64 = 0;
    let mut dt_init_present = false;
    let mut dt_init_array_present = false;
    let mut dt_fini: u64 = 0;
    let mut dt_fini_array: u64 = 0;
    let mut dt_fini_array_sz: u64 = 0;
    let mut dt_fini_present = false;
    let mut dt_fini_array_present = false;
    let mut dt_runpath_off: u64 = 0;
    let mut dt_runpath_present = false;
    let mut dt_rpath_off: u64 = 0;
    let mut dt_rpath_present = false;
    let mut dt_gnu_hash: u64 = 0;
    let mut dt_hash: u64 = 0;
    let mut dp = dyn_addr;
    while dp + 16 <= dyn_end {
        let d_tag = u64::from_le_bytes(core::ptr::read_unaligned(dp as *const [u8; 8]));
        let d_val = u64::from_le_bytes(core::ptr::read_unaligned((dp + 8) as *const [u8; 8]));
        if d_tag == DT_NULL {
            break;
        }
        match d_tag {
            DT_SYMTAB => dt_symtab = d_val,
            DT_STRTAB => dt_strtab = d_val,
            DT_STRSZ => dt_strsz = d_val,
            DT_GNU_HASH => dt_gnu_hash = d_val,
            DT_HASH => dt_hash = d_val,
            DT_INIT => {
                dt_init = d_val;
                dt_init_present = true;
            }
            DT_INIT_ARRAY => {
                dt_init_array = d_val;
                dt_init_array_present = true;
            }
            DT_INIT_ARRAYSZ => dt_init_array_sz = d_val,
            DT_FINI => {
                dt_fini = d_val;
                dt_fini_present = true;
            }
            DT_FINI_ARRAY => {
                dt_fini_array = d_val;
                dt_fini_array_present = true;
            }
            DT_FINI_ARRAYSZ => dt_fini_array_sz = d_val,
            DT_RUNPATH => {
                dt_runpath_off = d_val;
                dt_runpath_present = true;
            }
            DT_RPATH => {
                dt_rpath_off = d_val;
                dt_rpath_present = true;
            }
            _ => {}
        }
        dp += 16;
    }

    let symtab_ptr = (actual_base + dt_symtab) as *const u8;
    let strtab_ptr = (actual_base + dt_strtab) as *const u8;
    let strsz = dt_strsz as usize;
    let search_path_offset = if dt_runpath_present {
        Some(dt_runpath_off as usize)
    } else if dt_rpath_present {
        Some(dt_rpath_off as usize)
    } else {
        None
    };
    let (search_path, search_path_len) = if let Some(offset) = search_path_offset {
        if offset >= strsz {
            fail_mapping!();
        }
        let path = strtab_ptr.add(offset);
        let Some(len) = dynamic_string_len(path, strsz - offset) else {
            fail_mapping!();
        };
        (path, len)
    } else {
        (core::ptr::null(), 0)
    };

    let mut sym_count: usize = 0;
    if dt_gnu_hash != 0 {
        sym_count = sym_count_from_gnu_hash((actual_base + dt_gnu_hash) as usize);
    } else if dt_hash != 0 {
        sym_count = sym_count_from_hash((actual_base + dt_hash) as usize);
    } else if dt_strtab > dt_symtab && dt_strtab - dt_symtab >= SYMTAB_ENT_SIZE as u64 {
        sym_count = ((dt_strtab - dt_symtab) / SYMTAB_ENT_SIZE as u64) as usize;
    }
    let gnu_hash = if dt_gnu_hash == 0 {
        core::ptr::null()
    } else {
        (actual_base + dt_gnu_hash) as *const u8
    };
    let gnu_hash_metadata = gnu_hash_metadata(gnu_hash, sym_count);

    LOADED[LOADED_COUNT] = LoadedObject {
        base: actual_base,
        map_start: mapping,
        map_size: mapping_size,
        symtab: symtab_ptr,
        sym_count,
        gnu_hash,
        gnu_hash_metadata,
        sysv_hash: if dt_hash == 0 {
            core::ptr::null()
        } else {
            (actual_base + dt_hash) as *const u8
        },
        strtab: strtab_ptr,
        strsz,
        search_path,
        search_path_len,
        relro_addr: actual_base + relro_vaddr,
        relro_size: relro_memsz,
        relro_applied: false,
        dependencies: [0; MAX_LOADED],
        dependency_count: 0,
        constructing: false,
        constructed: false,
        dyn_addr,
        dyn_memsz: dyn_memsz as usize,
        tls_image,
        tls_filesz,
        tls_memsz,
        tls_align,
        init: actual_base + dt_init,
        init_array: actual_base + dt_init_array,
        init_array_sz: dt_init_array_sz,
        init_present: dt_init_present,
        init_array_present: dt_init_array_present,
        fini: actual_base + dt_fini,
        fini_array: actual_base + dt_fini_array,
        fini_array_sz: dt_fini_array_sz,
        fini_present: dt_fini_present,
        fini_array_present: dt_fini_array_present,
        global: false,
        ref_count: 0,
        active: true,
        finalized: false,
        file_identity_valid: identity.is_some(),
        file_dev: identity.map_or(0, |id| id.dev),
        file_ino: identity.map_or(0, |id| id.ino),
        initial_ld_library_path_name: false,
        name: [0; 256],
    };
    LOADED_COUNT += 1;

    Some(actual_base)
}

/// Return the length of a dynamic-string-table entry only if its terminating
/// NUL lies inside the recorded table. Dynamic `DT_NEEDED` values are untrusted
/// ELF offsets; using the general unbounded C-string helper here could let a
/// malformed DSO make the loader walk beyond its own mapping.
unsafe fn dynamic_string_len(string: *const u8, available: usize) -> Option<usize> {
    for len in 0..available {
        if *string.add(len) == 0 {
            return Some(len);
        }
    }
    None
}

/// Load one named DSO and its complete direct/transitive `DT_NEEDED` closure.
///
/// Identity deduplication happens before recursing, which makes this safe for
/// ordinary dependency diamonds and bounded cycles: a back-edge observes its
/// already registered parent instead of mapping it again. The object is
/// registered before its children so relocations can resolve symbols exported
/// by a cyclic peer after the whole closure has been discovered.
unsafe fn load_named_with_dependencies(
    name: *const u8,
    name_len: usize,
    ld_path: Option<*const u8>,
) -> Option<usize> {
    load_named_with_dependencies_from_parent(name, name_len, ld_path, None)
}

unsafe fn load_named_with_dependencies_from_parent(
    name: *const u8,
    name_len: usize,
    ld_path: Option<*const u8>,
    parent: Option<usize>,
) -> Option<usize> {
    if let Some(idx) = loaded_initial_ld_library_path_object_by_name(name, name_len) {
        return Some(idx);
    }
    if let Some(idx) = loaded_initial_libc_by_needed_name(name, name_len) {
        return Some(idx);
    }
    let opened = find_library_fd(name, name_len, ld_path, parent)?;
    let fd = opened.fd;
    let identity = file_identity(fd);
    if let Some(identity) = identity {
        if let Some(idx) = loaded_object_by_identity(identity) {
            sys_close(fd);
            return Some(idx);
        }
    }
    let desired_base = DSO_BASE_START + (LOADED_COUNT as u64) * DSO_BASE_STRIDE;
    if load_dso_from_fd(fd, desired_base, identity).is_none() {
        sys_close(fd);
        return None;
    }
    sys_close(fd);
    let idx = LOADED_COUNT - 1;
    LOADED[idx].initial_ld_library_path_name =
        INITIAL_LOAD_IN_PROGRESS && opened.source == LibrarySearchSource::LibraryPath;
    if !set_loaded_name(idx, name, name_len) {
        return None;
    }
    if !load_needed_dependencies(idx, ld_path) {
        return None;
    }
    Some(idx)
}

/// Roll back every DSO added after `first`.  Each object owns one contiguous
/// load span, so failed dependency closure discovery cannot leave executable
/// mappings behind for a later dlsym or dlopen to observe.
unsafe fn cleanup_loaded_objects_from(first: usize) {
    while LOADED_COUNT > first {
        let idx = LOADED_COUNT - 1;
        let map_start = LOADED[idx].map_start;
        let map_size = LOADED[idx].map_size;
        if !map_start.is_null() && map_size != 0 {
            sys_munmap(map_start, map_size);
        }
        LOADED[idx] = EMPTY_OBJ;
        LOADED_COUNT = idx;
    }
}

/// Record an already-discovered dependency edge for constructor ordering.
/// The graph is bounded with the same fixed capacity as the loaded-object
/// table, and duplicate DT_NEEDED entries do not create duplicate callbacks.
unsafe fn record_dependency(parent: usize, child: usize) -> bool {
    if parent >= LOADED_COUNT || child >= LOADED_COUNT || parent == child {
        return true;
    }
    let count = LOADED[parent].dependency_count;
    for i in 0..count {
        if LOADED[parent].dependencies[i] == child {
            return true;
        }
    }
    if count < MAX_LOADED {
        LOADED[parent].dependencies[count] = child;
        LOADED[parent].dependency_count = count + 1;
        true
    } else {
        false
    }
}

/// Discover and load every `DT_NEEDED` edge directly named by one object.
/// The direct child search starts with `LD_LIBRARY_PATH`, then uses the
/// parent's `DT_RUNPATH`/`DT_RPATH` with that DSO's own `$ORIGIN`. What matters
/// here is that every discovered ELF edge becomes part of the same relocation
/// graph before relocation begins.
unsafe fn load_needed_dependencies(idx: usize, ld_path: Option<*const u8>) -> bool {
    if idx >= LOADED_COUNT {
        return false;
    }
    let dyn_addr = LOADED[idx].dyn_addr;
    let dyn_end = dyn_addr.saturating_add(LOADED[idx].dyn_memsz);
    let strtab = LOADED[idx].strtab;
    let strsz = LOADED[idx].strsz;
    if strtab.is_null() || strsz == 0 {
        return false;
    }

    let mut pos = dyn_addr;
    let mut found_null = false;
    while pos + 16 <= dyn_end {
        let tag = u64::from_le_bytes(core::ptr::read_unaligned(pos as *const [u8; 8]));
        let value = u64::from_le_bytes(core::ptr::read_unaligned((pos + 8) as *const [u8; 8]));
        if tag == DT_NULL {
            found_null = true;
            break;
        }
        if tag == DT_NEEDED {
            let offset = value as usize;
            if offset >= strsz {
                return false;
            }
            let name = strtab.add(offset);
            let Some(name_len) = dynamic_string_len(name, strsz - offset) else {
                return false;
            };
            let Some(child) =
                load_named_with_dependencies_from_parent(name, name_len, ld_path, Some(idx))
            else {
                return false;
            };
            if !record_dependency(idx, child) {
                return false;
            }
        }
        pos += 16;
    }
    found_null
}

/// Load the whitespace- or colon-separated `LD_PRELOAD` list before ordinary
/// startup dependencies are relocated. Entries are made global immediately so
/// the existing lookup order (main, preload, then DT_NEEDED) gives musl's
/// intended interposition result without a special relocation-only path.
unsafe fn load_preload_list(list: *const u8, ld_path: Option<*const u8>) -> bool {
    let list_len = str_len(list);
    let mut start = 0usize;
    while start < list_len {
        while start < list_len && (*list.add(start) == b':' || *list.add(start) == b' ') {
            start += 1;
        }
        if start == list_len {
            break;
        }
        let mut end = start;
        while end < list_len && *list.add(end) != b':' && *list.add(end) != b' ' {
            end += 1;
        }
        let name = list.add(start);
        let Some(idx) = load_named_with_dependencies(name, end - start, ld_path) else {
            return false;
        };
        LOADED[idx].global = true;
        if !record_dependency(0, idx) {
            return false;
        }
        start = end;
    }
    true
}

// ============================================================
// Symbol resolution
// ============================================================

/// Look up symbol name from object's own symtab, then search all loaded objects.
unsafe fn resolve_symbol_from_index(obj_idx: usize, sym_idx: usize) -> u64 {
    let obj = &LOADED[obj_idx];
    if sym_idx == 0 || obj.symtab.is_null() || obj.strtab.is_null() {
        return 0;
    }
    let sym_entry = obj.symtab.add(sym_idx * SYMTAB_ENT_SIZE);
    let st_name =
        u32::from_le_bytes(core::ptr::read_unaligned(sym_entry as *const [u8; 4])) as usize;
    if st_name >= obj.strsz {
        return 0;
    }
    let name = obj.strtab.add(st_name);
    resolve_symbol(name)
}

/// Search all loaded objects for a symbol with the given null-terminated name.
/// Returns the resolved address (base + st_value) or 0 if not found.
unsafe fn resolve_symbol(name: *const u8) -> u64 {
    resolve_symbol_with_size(name, usize::MAX).0
}

/// Same as resolve_symbol but also returns the defining symbol's st_size.
/// `exclude` is an object index to skip (use usize::MAX to skip nothing).
unsafe fn resolve_symbol_with_size(name: *const u8, exclude: usize) -> (u64, usize) {
    let name_len = str_len(name);
    if name_len == 0 {
        return (0, 0);
    }
    if str_eq(name, name_len, b"__ldso_dlstart\0".as_ptr()) {
        // The interpreter image is not part of LOADED: it is already running
        // before the main executable and DT_NEEDED objects are registered.
        // Resolve this libc GOT trampoline target explicitly to the named raw
        // entry bridge rather than leaving its GLOB_DAT slot at zero.
        #[cfg(not(test))]
        return (__ldso_dlstart as *const () as usize as u64, 0);
        #[cfg(test)]
        return (0, 0);
    }
    let name_gnu_hash = gnu_symbol_hash(name, name_len);
    if str_eq(name, name_len, b"__tls_get_addr\0".as_ptr()) {
        // Prefer libc's public ABI shim once it is loaded.  This makes normal
        // GD-model relocations exercise the same registration bridge as a
        // direct libc caller.  The loader's implementation remains the
        // fallback for startup configurations that do not provide libc's
        // exported symbol (and is deliberately skipped here to avoid picking
        // the ldso self-image before libc).
        let internal = __tls_get_addr as *const () as usize;
        for i in 0..LOADED_COUNT {
            let candidate = lookup_symbol_in_object(i, name, name_len, name_gnu_hash);
            if candidate != 0 && candidate as usize != internal {
                return (candidate, 0);
            }
        }
        return ((__tls_get_addr as *const () as usize) as u64, 0);
    }
    if str_eq(name, name_len, b"__rc_create_thread_tls\0".as_ptr()) {
        return ((__rc_create_thread_tls as *const () as usize) as u64, 0);
    }
    if str_eq(name, name_len, b"__rc_init_thread_tls\0".as_ptr()) {
        return ((__rc_init_thread_tls as *const () as usize) as u64, 0);
    }
    if str_eq(name, name_len, b"__rc_tls_block_size\0".as_ptr()) {
        return ((__rc_tls_block_size as *const () as usize) as u64, 0);
    }
    if str_eq(name, name_len, b"__rc_tls_block_size_for\0".as_ptr()) {
        return ((__rc_tls_block_size_for as *const () as usize) as u64, 0);
    }
    if str_eq(name, name_len, b"__rc_tls_base_offset_for\0".as_ptr()) {
        return ((__rc_tls_base_offset_for as *const () as usize) as u64, 0);
    }
    for i in 0..LOADED_COUNT {
        if i == exclude {
            continue;
        }
        let obj = &LOADED[i];
        let Some(sym_idx) =
            lookup_symbol_index_in_object::<true>(obj, name, name_len, name_gnu_hash)
        else {
            continue;
        };
        let sym_entry = obj.symtab.add(sym_idx * SYMTAB_ENT_SIZE);
        let st_value =
            u64::from_le_bytes(core::ptr::read_unaligned(sym_entry.add(8) as *const [u8; 8]));
        let st_size = u64::from_le_bytes(core::ptr::read_unaligned(
            sym_entry.add(16) as *const [u8; 8]
        ));
        return (obj.base + st_value, st_size as usize);
    }
    (0, 0)
}

unsafe fn resolve_copy_source(obj_idx: usize, sym_idx: usize) -> (u64, usize) {
    let obj = &LOADED[obj_idx];
    if sym_idx == 0 || obj.symtab.is_null() || obj.strtab.is_null() {
        return (0, 0);
    }
    if sym_idx * SYMTAB_ENT_SIZE >= obj.sym_count * SYMTAB_ENT_SIZE {
        return (0, 0);
    }
    let sym_entry = obj.symtab.add(sym_idx * SYMTAB_ENT_SIZE);
    let st_name =
        u32::from_le_bytes(core::ptr::read_unaligned(sym_entry as *const [u8; 4])) as usize;
    if st_name >= obj.strsz {
        return (0, 0);
    }
    let name = obj.strtab.add(st_name);
    resolve_symbol_with_size(name, obj_idx)
}

unsafe fn resolve_symbol_module(obj_idx: usize, sym_idx: usize) -> usize {
    let obj = &LOADED[obj_idx];
    if sym_idx == 0 || obj.symtab.is_null() || obj.strtab.is_null() {
        return obj_idx;
    }
    if sym_idx * SYMTAB_ENT_SIZE >= obj.sym_count * SYMTAB_ENT_SIZE {
        return obj_idx;
    }
    let sym_entry = obj.symtab.add(sym_idx * SYMTAB_ENT_SIZE);
    let st_name =
        u32::from_le_bytes(core::ptr::read_unaligned(sym_entry as *const [u8; 4])) as usize;
    if st_name == 0 || st_name >= obj.strsz {
        return obj_idx;
    }
    let st_info = *sym_entry.add(4);
    if (st_info & 0xf) == 6 {
        return obj_idx;
    }
    let name = obj.strtab.add(st_name);
    let name_len = str_len(name);
    let name_gnu_hash = gnu_symbol_hash(name, name_len);
    for i in 0..LOADED_COUNT {
        let o = &LOADED[i];
        if lookup_symbol_index_in_object::<false>(o, name, name_len, name_gnu_hash).is_some() {
            return i;
        }
    }
    obj_idx
}

unsafe fn tls_sym_offset(obj_idx: usize, sym_idx: usize) -> u64 {
    let obj = &LOADED[obj_idx];
    if sym_idx == 0 || obj.symtab.is_null() {
        return 0;
    }
    if sym_idx * SYMTAB_ENT_SIZE >= obj.sym_count * SYMTAB_ENT_SIZE {
        return 0;
    }
    let sym_entry = obj.symtab.add(sym_idx * SYMTAB_ENT_SIZE);
    u64::from_le_bytes(core::ptr::read_unaligned(sym_entry.add(8) as *const [u8; 8]))
}

unsafe fn tls_tprel_offset(obj_idx: usize, sym_idx: usize, addend: i64) -> i64 {
    let module = if sym_idx == 0 {
        obj_idx
    } else {
        resolve_symbol_module(obj_idx, sym_idx)
    };
    let off_in_mod = tls_sym_offset(obj_idx, sym_idx) as i64 + addend;
    (TLS_LAYOUT_OFFSET[module] as i64) + off_in_mod - (tls_var_area_offset_from_tp() as i64)
}

unsafe fn tls_var_area_offset_from_block() -> usize {
    TLS_TP_OFFSET
}

unsafe fn tls_tcb_offset_from_block() -> usize {
    0
}

unsafe fn tls_tp_offset_from_block() -> usize {
    TLS_TP_OFFSET
}

/// Read the TP offset recorded in one allocation's TCB. AArch64 can raise
/// this offset when a late TLS module has a stronger alignment than the
/// initial image, so consulting the process-global value would mislocate an
/// older thread's TCB.
unsafe fn thread_tp_offset(fs_base: usize) -> usize {
    let recorded = core::ptr::read_unaligned((fs_base as *const usize).add(1));
    if recorded >= TCB_SIZE {
        recorded
    } else {
        TLS_TP_OFFSET
    }
}

unsafe fn tcb_for_thread(fs_base: usize) -> *mut u8 {
    (fs_base.wrapping_sub(thread_tp_offset(fs_base))) as *mut u8
}

/// Return the TP-relative distance from a thread's allocation base.
///
/// AArch64 records the TP offset in the otherwise-unused gap immediately
/// above TP, because late TLS can raise that offset for future allocations.
unsafe fn thread_block_tp_offset(fs_base: usize, data_size: usize) -> usize {
    let _ = data_size;
    thread_tp_offset(fs_base)
}

/// Initialize loader-owned TCB metadata for one TLS allocation.  The
/// per-allocation TP offset is needed when a later dlopen introduces a more
/// strongly aligned TLS image: old threads remain on their old allocation
/// until their next TLS lookup and must still be unmapped from its true base.
unsafe fn initialize_tls_tcb(tcb: *mut u8, tp: *mut u8, data_size: usize) {
    core::ptr::write_unaligned(tcb as *mut u64, tcb as u64);
    core::ptr::write_unaligned(tcb.add(TCB_GENERATION_OFFSET) as *mut u64, TLS_GENERATION);
    core::ptr::write_unaligned(tcb.add(TCB_BLOCK_SIZE_OFFSET) as *mut usize, data_size);
    core::ptr::write_unaligned(
        tcb.add(TCB_TP_OFFSET_OFFSET) as *mut usize,
        tls_tp_offset_from_block(),
    );
    // Module IDs are append-only for successful runtime loads. Record the
    // first absent module only after this allocation has received every
    // current image, so future growth need not inspect its initialized prefix.
    core::ptr::write_unaligned(
        tcb.add(TCB_TLS_MODULE_COUNT_OFFSET) as *mut usize,
        TLS_MODULE_COUNT,
    );
    // TP+8 is in the ABI-mandated gap before the first positive TLS offset
    // (GAP_ABOVE_TP is 16), so it is safe metadata storage even when the TCB
    // is below TP by several pages.
    core::ptr::write_unaligned(
        tp.add(TCB_GENERATION_OFFSET) as *mut usize,
        tls_tp_offset_from_block(),
    );
}

/// Initialize fields that identify one logical thread rather than one TLS
/// allocation. `expand_thread_tls` copies these fields to its replacement
/// block, while a freshly created pthread must receive a distinct owner token
/// and empty dlerror and handle-local symbol caches.
unsafe fn initialize_loader_thread_state(tcb: *mut u8, tp: *mut u8) {
    core::ptr::write_unaligned(tcb.add(TCB_LOADER_OWNER_OFFSET) as *mut usize, tp.addr());
    core::ptr::write_unaligned(tcb.add(TCB_DLERROR_NODE_OFFSET) as *mut usize, 0);
    core::ptr::write_unaligned(tcb.add(TCB_DLSYM_CACHE_RESULT_OFFSET) as *mut u64, 0);
}

unsafe fn tls_var_area_offset_from_tp() -> usize {
    0
}

// ============================================================
// Relocation processing
// ============================================================

/// Process the complete initial loader graph before any object can have been
/// relocated. Runtime `dlopen` uses `process_relocation_suffix` instead: GNU
/// RELRO is optional, while packed `DT_RELR` entries update their slots in
/// place and must never be replayed for an already loaded no-RELRO object.
unsafe fn process_all_relocations() {
    process_relocation_suffix(0);
}

/// Relocate exactly the dependency-graph suffix appended by one `dlopen`.
///
/// The loader registers an object before it discovers its children, so this
/// suffix contains the entire new closure in a stable order. Every object
/// before `first_new` completed relocation in an earlier transaction; keeping
/// that boundary separate from `relro_applied` preserves no-RELRO `DT_RELR`
/// images and avoids revisiting prior loader work.
unsafe fn process_relocation_suffix(first_new: usize) {
    let first_new = first_new.min(LOADED_COUNT);
    // First pass: non-COPY relocations so source symbols have final values.
    for i in first_new..LOADED_COUNT {
        let (base, rela_off, rela_sz, jmprel_off, jmprel_sz, relr_off, relr_sz, relr_ent) =
            relocation_info(i);
        apply_relr_table(i, base, relr_off, relr_sz, relr_ent);
        apply_rela_table(i, base, rela_off, rela_sz, false);
        apply_rela_table(i, base, jmprel_off, jmprel_sz, false);
    }
    // Second pass: COPY relocations copy initialized data into the executable.
    for i in first_new..LOADED_COUNT {
        let (base, rela_off, rela_sz, _, _, _, _, _) = relocation_info(i);
        apply_rela_table(i, base, rela_off, rela_sz, true);
    }
}

/// Lock every mapped GNU_RELRO span after all relocations that may touch it.
/// Runtime transactions relocate only their newly appended graph suffix, so
/// sealing is an independent protection step rather than its completion mark.
unsafe fn apply_relro() {
    apply_relro_suffix(0);
}

/// Seal GNU RELRO only for the dependency-graph suffix appended by one
/// `dlopen`. Earlier maps were sealed in their own completed transaction.
unsafe fn apply_relro_suffix(first_new: usize) {
    const PAGE: u64 = 4096;
    for i in first_new.min(LOADED_COUNT)..LOADED_COUNT {
        let obj = &mut LOADED[i];
        if obj.relro_applied || obj.relro_size == 0 {
            continue;
        }
        let start = obj.relro_addr & !(PAGE - 1);
        let end = (obj.relro_addr + obj.relro_size + PAGE - 1) & !(PAGE - 1);
        if end <= start || sys_mprotect(start as *mut u8, (end - start) as usize, PROT_READ) < 0 {
            die(90, b"relro", i);
        }
        obj.relro_applied = true;
    }
}

unsafe fn relocation_info(i: usize) -> (u64, u64, u64, u64, u64, u64, u64, u64) {
    let obj = &LOADED[i];
    let base = obj.base;
    let dp = obj.dyn_addr;
    let dyn_end = dp + obj.dyn_memsz;

    let mut rela_off: u64 = 0;
    let mut rela_sz: u64 = 0;
    let mut jmprel_off: u64 = 0;
    let mut jmprel_sz: u64 = 0;
    let mut relr_off: u64 = 0;
    let mut relr_sz: u64 = 0;
    let mut relr_ent: u64 = 0;

    let mut pos = dp;
    while pos + 16 <= dyn_end {
        let d_tag = u64::from_le_bytes(core::ptr::read_unaligned(pos as *const [u8; 8]));
        let d_val = u64::from_le_bytes(core::ptr::read_unaligned((pos + 8) as *const [u8; 8]));
        if d_tag == DT_NULL {
            break;
        }
        match d_tag {
            DT_RELA => rela_off = d_val,
            DT_RELASZ => rela_sz = d_val,
            DT_JMPREL => jmprel_off = d_val,
            DT_PLTRELSZ => jmprel_sz = d_val,
            DT_RELR => relr_off = d_val,
            DT_RELRSZ => relr_sz = d_val,
            DT_RELRENT => relr_ent = d_val,
            _ => {}
        }
        pos += 16;
    }
    (
        base, rela_off, rela_sz, jmprel_off, jmprel_sz, relr_off, relr_sz, relr_ent,
    )
}

/// Apply the ELF ``DT_RELR`` address/bitmap stream.
///
/// An even entry names one relocated pointer directly. An odd entry is a
/// bitmap for the following 63 pointer-sized slots. Each recorded pointer is
/// an in-place addend and therefore receives the object's load bias exactly
/// once, before ordinary RELA relocations and before GNU_RELRO is sealed.
unsafe fn apply_relr_table(
    obj_idx: usize,
    base: u64,
    table_off: u64,
    table_sz: u64,
    table_ent: u64,
) {
    if table_sz == 0 {
        return;
    }
    if table_ent != 8 || table_sz % table_ent != 0 {
        die(86, b"relr", obj_idx);
    }

    let table = (base + table_off) as *const u64;
    let count = (table_sz / table_ent) as usize;
    let mut next_slot = 0u64;
    let mut have_next_slot = false;

    for i in 0..count {
        let entry = core::ptr::read_unaligned(table.add(i));
        if entry & 1 == 0 {
            if entry & 7 != 0 {
                die(86, b"relr", obj_idx);
            }
            next_slot = base.wrapping_add(entry);
            let slot = next_slot as *mut u64;
            *slot = (*slot).wrapping_add(base);
            next_slot = next_slot.wrapping_add(8);
            have_next_slot = true;
            continue;
        }

        if !have_next_slot {
            die(86, b"relr", obj_idx);
        }
        let bitmap = entry >> 1;
        for bit in 0..63u64 {
            if bitmap & (1u64 << bit) != 0 {
                let slot = (next_slot + bit * 8) as *mut u64;
                *slot = (*slot).wrapping_add(base);
            }
        }
        next_slot = next_slot.wrapping_add(63 * 8);
    }
}

/// Apply entries from one relocation table.
unsafe fn apply_rela_table(
    obj_idx: usize,
    base: u64,
    table_off: u64,
    table_sz: u64,
    copy_only: bool,
) {
    if table_sz == 0 {
        return;
    }
    let table = (base + table_off) as *const u8;
    let count = table_sz as usize / 24;

    for i in 0..count {
        let entry = table.add(i * 24);
        let r_offset = u64::from_le_bytes(core::ptr::read_unaligned(entry as *const [u8; 8]));
        let r_info = u64::from_le_bytes(core::ptr::read_unaligned(entry.add(8) as *const [u8; 8]));
        let r_addend =
            i64::from_le_bytes(core::ptr::read_unaligned(entry.add(16) as *const [u8; 8]));

        let r_type = r_info & 0xffffffff;
        let r_sym_idx = (r_info >> 32) as usize;
        let slot = (base + r_offset) as *mut u64;

        if r_type == LEGACY_COPY_RELOCATION {
            if !copy_only {
                continue;
            }
            let (src, sym_size) = resolve_copy_source(obj_idx, r_sym_idx);
            if src != 0 && sym_size != 0 {
                let dst = (base + r_offset) as *mut u8;
                core::ptr::copy_nonoverlapping(src as *const u8, dst, sym_size);
            }
            continue;
        }
        if copy_only {
            continue;
        }

        match r_type {
            R_AARCH64_RELATIVE => {
                *slot = (base as i64 + r_addend) as u64;
            }
            R_AARCH64_ABS64 => {
                let sym_value = resolve_symbol_from_index(obj_idx, r_sym_idx);
                *slot = (sym_value as i64 + r_addend) as u64;
            }
            R_AARCH64_GLOB_DAT | R_AARCH64_JUMP_SLOT => {
                let sym_value = resolve_symbol_from_index(obj_idx, r_sym_idx);
                *slot = sym_value;
            }
            R_AARCH64_TLS_DTPMOD64 => {
                let module = if r_sym_idx == 0 {
                    obj_idx
                } else {
                    resolve_symbol_module(obj_idx, r_sym_idx)
                };
                *slot = (module + 1) as u64;
            }
            R_AARCH64_TLS_DTPREL64 => {
                let off = (tls_sym_offset(obj_idx, r_sym_idx) as i64 + r_addend) as u64;
                *slot = off;
            }
            R_AARCH64_TLS_TPREL64 => {
                let fs_off = tls_tprel_offset(obj_idx, r_sym_idx, r_addend);
                *slot = fs_off as u64;
            }
            _ => {}
        }
        if r_type == R_AARCH64_TLSLE_ADD_TPREL_HI12 {
            let fs_off = tls_tprel_offset(obj_idx, r_sym_idx, r_addend);
            let insn = core::ptr::read_unaligned(slot as *const u32);
            let imm = ((fs_off >> 12) & 0xFFF) as u32;
            let new_insn = (insn & !(0xFFFu32 << 10)) | (imm << 10);
            core::ptr::write_unaligned(slot as *mut u32, new_insn);
        } else if r_type == R_AARCH64_TLSLE_ADD_TPREL_LO12
            || r_type == R_AARCH64_TLSLE_ADD_TPREL_LO12_NC
        {
            let fs_off = tls_tprel_offset(obj_idx, r_sym_idx, r_addend);
            let insn = core::ptr::read_unaligned(slot as *const u32);
            let imm = (fs_off & 0xFFF) as u32;
            let new_insn = (insn & !(0xFFFu32 << 10)) | (imm << 10);
            core::ptr::write_unaligned(slot as *mut u32, new_insn);
        } else if r_type == R_AARCH64_TLSDESC {
            let fs_off = tls_tprel_offset(obj_idx, r_sym_idx, r_addend);
            let desc = slot as *mut [u64; 2];
            if obj_idx >= TLS_STATIC_MODULE_COUNT {
                let module = if r_sym_idx == 0 {
                    obj_idx
                } else {
                    resolve_symbol_module(obj_idx, r_sym_idx)
                };
                let offset = (tls_sym_offset(obj_idx, r_sym_idx) as i64 + r_addend) as usize;
                if module >= (1usize << (usize::BITS as usize - TLSDESC_MODULE_SHIFT))
                    || offset > TLSDESC_OFFSET_MASK
                {
                    die(94, b"tlsdesc", offset);
                }
                (*desc)[0] = __tlsdesc_dynamic as *const () as u64;
                (*desc)[1] = (((module + 1) << TLSDESC_MODULE_SHIFT) | offset) as u64;
                continue;
            }
            (*desc)[0] = __tlsdesc_static as *const () as u64;
            (*desc)[1] = fs_off as u64;
        }
    }
}

unsafe extern "C" fn run_dependency_constructors() {
    if INITIAL_CONSTRUCTORS_RAN {
        return;
    }
    INITIAL_CONSTRUCTORS_RAN = true;
    // The CRT owns the main executable's preinit/_init/init-array sequence.
    // The loader owns only its dependency closure, whose roots begin after
    // LOADED[0]. libc invokes this callback after main preinit but before
    // main `_init`, matching musl's documented dynamic-start ordering.
    for i in 1..LOADED_COUNT {
        run_constructors_for(i);
    }
}

/// Private x0 handoff from crabc ldso into a recognized owned `Scrt1.o`.
///
/// Function pointers are used rather than integer addresses so this immutable
/// static remains a normal Rust value. `crt/src/startup.rs` reads their exact
/// one-word C-layout representation as raw addresses after validating the
/// magic, revision, and complete record size.
#[repr(C)]
struct OwnedCrtStartupHandoff {
    magic: u64,
    version: u32,
    abi_size: u32,
    dependency_constructors: unsafe extern "C" fn(),
    process_fini: unsafe extern "C" fn(),
}

static OWNED_CRT_STARTUP_HANDOFF: OwnedCrtStartupHandoff = OwnedCrtStartupHandoff {
    magic: OWNED_CRT_STARTUP_HANDOFF_MAGIC,
    version: OWNED_CRT_STARTUP_HANDOFF_VERSION,
    abi_size: core::mem::size_of::<OwnedCrtStartupHandoff>() as u32,
    dependency_constructors: run_dependency_constructors,
    process_fini: __ldso_process_fini,
};

/// Preserve the historical constructor boundary for an executable linked with
/// a conventional musl CRT. That CRT has no owned lifecycle note and expects
/// its main `.init_array` to have run before `main`.
///
/// This is intentionally separate from `run_dependency_constructors`: owned
/// CRT objects must never let ldso run the main executable because they own
/// preinit, legacy `_init`, and init-array ordering themselves. Calling the
/// main recursive walk here keeps the legacy main array after its dependency
/// closure and retains the existing one-shot protection.
unsafe fn run_legacy_crt_initial_constructors() {
    if INITIAL_CONSTRUCTORS_RAN {
        return;
    }
    INITIAL_CONSTRUCTORS_RAN = true;
    run_constructors_for(0);
}

/// Private operation reached through libc's already-registered ldso dlsym
/// callback. It runs only for a conventional CRT, after libc has initialized
/// its guard and initial TLS. An owned `Scrt1.o` receives the dependency-only
/// callback through x0 and invokes it after its executable preinit array.
unsafe extern "C" fn run_initial_legacy_constructors_from_libc() {
    if !INITIAL_MAIN_USES_OWNED_CRT {
        unsafe { run_legacy_crt_initial_constructors() };
    }
}

/// Return whether the main image was linked with the owned application CRT.
///
/// `Scrt1.o` emits one small `CRABC` ELF note. It is a lifecycle capability
/// marker, not an ldso API: the owned CRT consumes the x0 handoff after the
/// executable preinit array, while a conventional musl CRT keeps a direct x0
/// finalizer. Inspect the mapped note rather than requiring a libc export.
///
/// A malformed or unrecognized note is deliberately treated as the legacy
/// path. The parser bounds every address through the main image's PT_LOAD
/// segments before reading the note payload; it never manufactures a Rust
/// reference to kernel-owned ELF storage.
unsafe fn main_uses_owned_crt_lifecycle(
    program_headers: *const u8,
    program_header_count: usize,
    image_base: u64,
) -> bool {
    for index in 0..program_header_count {
        let Some(offset) = index.checked_mul(PHDR_SIZE) else {
            return false;
        };
        let header = unsafe { program_headers.add(offset) };
        let program_type = unsafe { core::ptr::read_unaligned(header.cast::<u32>()) };
        if program_type != PT_NOTE {
            continue;
        }
        let note_vaddr = unsafe {
            u64::from_le_bytes(core::ptr::read_unaligned(header.add(PH_VADDR).cast::<[u8; 8]>()))
        };
        let note_size = unsafe {
            u64::from_le_bytes(core::ptr::read_unaligned(header.add(PH_FILESZ).cast::<[u8; 8]>()))
        };
        let Ok(note_size) = usize::try_from(note_size) else {
            return false;
        };
        if note_size == 0 || note_size > MAX_OWNED_CRT_NOTE_BYTES {
            continue;
        }
        if !main_range_is_loaded(program_headers, program_header_count, note_vaddr, note_size as u64) {
            continue;
        }
        let Some(note_address) = image_base.checked_add(note_vaddr).map(|value| value as usize) else {
            return false;
        };
        let Some(note_end) = note_address.checked_add(note_size) else {
            return false;
        };
        let mut cursor = note_address;
        while cursor < note_end {
            let Some(header_end) = cursor.checked_add(12) else {
                return false;
            };
            if header_end > note_end {
                return false;
            }
            let namesz = unsafe { core::ptr::read_unaligned(cursor as *const u32) } as usize;
            let descsz = unsafe { core::ptr::read_unaligned((cursor + 4) as *const u32) } as usize;
            let note_type = unsafe { core::ptr::read_unaligned((cursor + 8) as *const u32) };
            let Some(names_padded) = note_word_padded_size(namesz) else {
                return false;
            };
            let Some(names_end) = header_end.checked_add(names_padded) else {
                return false;
            };
            let Some(desc_padded) = note_word_padded_size(descsz) else {
                return false;
            };
            let Some(next) = names_end.checked_add(desc_padded) else {
                return false;
            };
            if names_end > note_end || next > note_end {
                return false;
            }
            if note_type == OWNED_CRT_NOTE_TYPE
                && namesz == OWNED_CRT_NOTE_NAME.len()
                && descsz == core::mem::size_of::<u32>()
            {
                let name = header_end as *const u8;
                let mut name_matches = true;
                for name_index in 0..OWNED_CRT_NOTE_NAME.len() {
                    if unsafe { core::ptr::read(name.add(name_index)) } != OWNED_CRT_NOTE_NAME[name_index] {
                        name_matches = false;
                        break;
                    }
                }
                let revision = unsafe { core::ptr::read_unaligned(names_end as *const u32) };
                if name_matches && revision == OWNED_CRT_NOTE_REVISION {
                    return true;
                }
            }
            cursor = next;
        }
    }
    false
}

fn note_word_padded_size(size: usize) -> Option<usize> {
    size.checked_add(3).map(|value| value & !3)
}

/// Confirm a PT_NOTE payload lies in one mapped main-image PT_LOAD segment
/// before its raw bytes are examined.
unsafe fn main_range_is_loaded(
    program_headers: *const u8,
    program_header_count: usize,
    address: u64,
    size: u64,
) -> bool {
    let Some(end) = address.checked_add(size) else {
        return false;
    };
    for index in 0..program_header_count {
        let Some(offset) = index.checked_mul(PHDR_SIZE) else {
            return false;
        };
        let header = unsafe { program_headers.add(offset) };
        let program_type = unsafe { core::ptr::read_unaligned(header.cast::<u32>()) };
        if program_type != PT_LOAD {
            continue;
        }
        let segment_address = unsafe {
            u64::from_le_bytes(core::ptr::read_unaligned(header.add(PH_VADDR).cast::<[u8; 8]>()))
        };
        let segment_size = unsafe {
            u64::from_le_bytes(core::ptr::read_unaligned(header.add(PH_MEMSZ).cast::<[u8; 8]>()))
        };
        let Some(segment_end) = segment_address.checked_add(segment_size) else {
            continue;
        };
        if address >= segment_address && end <= segment_end {
            return true;
        }
    }
    false
}

unsafe fn run_constructors_for(idx: usize) {
    if idx >= LOADED_COUNT
        || !LOADED[idx].active
        || LOADED[idx].constructed
        || LOADED[idx].constructing
    {
        return;
    }
    // Mark before descending so a cyclic DT_NEEDED edge cannot recurse
    // forever. The cycle's remaining object finishes its callbacks first.
    LOADED[idx].constructing = true;
    let dependency_count = LOADED[idx].dependency_count;
    for i in 0..dependency_count {
        run_constructors_for(LOADED[idx].dependencies[i]);
    }
    let init_array_present = LOADED[idx].init_array_present;
    let init_array = LOADED[idx].init_array;
    let init_array_sz = LOADED[idx].init_array_sz;
    // Pinned musl preserves legacy DT_INIT tags in an ELF object but does not
    // dispatch them on this dlopen path. Its observable constructor contract
    // is the init-array sequence below, so do not infer execution from the
    // presence of the legacy dynamic tag.
    if init_array_present && init_array != 0 && init_array_sz >= 8 {
        let count = (init_array_sz / 8) as usize;
        for j in 0..count {
            let entry = (init_array as *const u8).add(j * 8);
            let fp = u64::from_le_bytes(core::ptr::read_unaligned(entry as *const [u8; 8]));
            if fp != 0 {
                let f: extern "C" fn() = core::mem::transmute(fp);
                f();
            }
        }
    }
    LOADED[idx].constructed = true;
    LOADED[idx].constructing = false;
}

/// Finalize one active DSO using pinned musl's dlclose contract: fini-array
/// entries run in reverse order, while a legacy DT_FINI tag remains inert.
/// This is invoked when a runtime handle's final reference is closed.
unsafe fn run_destructors_for(idx: usize) {
    if idx >= LOADED_COUNT || !LOADED[idx].active {
        return;
    }
    let obj = &LOADED[idx];
    if obj.fini_array_present && obj.fini_array != 0 && obj.fini_array_sz >= 8 {
        let mut count = (obj.fini_array_sz / 8) as usize;
        while count > 0 {
            count -= 1;
            let entry = (obj.fini_array as *const u8).add(count * 8);
            let fp = u64::from_le_bytes(core::ptr::read_unaligned(entry as *const [u8; 8]));
            if fp != 0 {
                let f: extern "C" fn() = core::mem::transmute(fp);
                f();
            }
        }
    }
}

/// Complete the initial DSO graph after the CRT has finalized the main
/// executable. This callback is handed to dynamic `Scrt1.o` in x0 at entry,
/// then registered by libc as `rtld_fini`; ordinary application `atexit`
/// callbacks and the executable fini callback therefore run before this
/// reverse dependency walk.
#[no_mangle]
unsafe extern "C" fn __ldso_process_fini() {
    if PROCESS_FINALIZED {
        return;
    }
    PROCESS_FINALIZED = true;

    // LOADED[0] is the main program and belongs to the CRT lifecycle. Walk
    // its roots in dependency-*reverse* order: each consumer's fini array
    // precedes the providers it used during construction. Raw load-index
    // reversal is not sufficient because recursive mapping naturally places
    // a provider after its consumer (leaf-before-middle would be wrong).
    let root_count = LOADED[0].dependency_count;
    let roots = LOADED[0].dependencies;
    for root in roots[..root_count].iter().copied() {
        finalize_dependency_graph(root);
    }

    // Preloads or loader-private images need not be direct main dependencies.
    // Finalize any such residual initial object once, preserving the same
    // consumer-before-provider recursion when it has its own graph.
    let mut index = LOADED_COUNT;
    while index > 1 {
        index -= 1;
        finalize_dependency_graph(index);
    }
}

// The owned-CRT handoff stores this function's address directly in loader
// state. It is not an ELF lookup ABI: keeping the Rust `no_mangle` name lets
// the handoff retain a stable code address while this visibility directive
// prevents it from escaping through the loader's default dynamic namespace.
core::arch::global_asm!(".hidden __ldso_process_fini");

/// Finalize one dependency graph in the inverse of its constructor relation.
///
/// `run_constructors_for` visits providers before consumers. This function
/// intentionally invokes a consumer's fini hooks first, then descends to its
/// providers. The `finalized` bit handles a shared provider and makes the
/// traversal exactly-once even if the initial graph contains a cycle.
unsafe fn finalize_dependency_graph(idx: usize) {
    if idx == 0 || idx >= LOADED_COUNT || !LOADED[idx].active || LOADED[idx].finalized {
        return;
    }
    LOADED[idx].finalized = true;
    let dependency_count = LOADED[idx].dependency_count;
    let dependencies = LOADED[idx].dependencies;
    run_destructors_for(idx);
    for dependency in dependencies[..dependency_count].iter().copied() {
        finalize_dependency_graph(dependency);
    }
}

/// AArch64 stores the descriptor argument in one machine word. `MAX_LOADED`
/// is deliberately small, leaving 56 bits for a TLS symbol offset and making
/// this encoding lossless for every addressable TLS image in this loader.
const TLSDESC_MODULE_SHIFT: usize = 56;
const TLSDESC_OFFSET_MASK: usize = (1usize << TLSDESC_MODULE_SHIFT) - 1;

// AArch64 TLSDESC call sites may retain their thread pointer in `x1` across
// the resolver call; optimized musl-built DSOs do so. The descriptor ABI also
// reserves `x2` for the same sequence. These stubs therefore preserve `x2`
// rather than relying on the ordinary Rust C ABI, which may freely clobber
// caller-saved registers. The dynamic helper can migrate the calling thread
// to a larger TLS block, so its stub refreshes `x1` from the new TP instead of
// restoring the now-stale value that musl's non-migrating resolver restores.
// The temporary frame preserves LR while the private Rust helper runs.
core::arch::global_asm!(
    ".text",
    ".global __tlsdesc_static",
    ".hidden __tlsdesc_static",
    ".type __tlsdesc_static,%function",
    "__tlsdesc_static:",
    "ldr x0, [x0, #8]",
    "ret",
    ".size __tlsdesc_static, .-__tlsdesc_static",
    ".global __tlsdesc_dynamic",
    ".hidden __tlsdesc_dynamic",
    ".type __tlsdesc_dynamic,%function",
    "__tlsdesc_dynamic:",
    "stp x2, x30, [sp, #-16]!",
    "bl __crabc_tlsdesc_dynamic_resolve",
    "mrs x1, tpidr_el0",
    "ldp x2, x30, [sp], #16",
    "ret",
    ".size __tlsdesc_dynamic, .-__tlsdesc_dynamic",
    ".hidden __crabc_tlsdesc_dynamic_resolve",
);

// The resolver entry points above are emitted as AArch64 assembly so their
// addresses can be installed directly into ELF TLSDESC records below.
unsafe extern "C" {
    fn __tlsdesc_static(desc: *const u64) -> u64;
    fn __tlsdesc_dynamic(desc: *const u64) -> u64;
}

/// Resolve TLS from a DSO loaded after threads may already exist. The assembly
/// TLSDESC entry preserves the ABI-required registers before calling this
/// helper. `__tls_get_addr` expands an older thread's TLS block before the
/// returned address is converted back to the TP-relative descriptor value.
#[no_mangle]
unsafe extern "C" fn __crabc_tlsdesc_dynamic_resolve(desc: *const u64) -> u64 {
    let encoded = core::ptr::read_unaligned(desc.add(1)) as usize;
    let index = TlsIndex {
        ti_module: encoded >> TLSDESC_MODULE_SHIFT,
        ti_offset: encoded & TLSDESC_OFFSET_MASK,
    };
    let address = __tls_get_addr(&index) as usize;
    address.wrapping_sub(read_tp()) as u64
}

unsafe fn tls_lock() {
    while TLS_LOCK.swap(true, Ordering::Acquire) {}
}

unsafe fn tls_unlock() {
    TLS_LOCK.store(false, Ordering::Release);
}

/// Materialize only TLS images in the suffix absent from one allocation. The
/// prefix was either initialized when the thread was created or copied from
/// its prior block, and may contain thread-private writes that a later dlopen
/// must never reinitialize.
unsafe fn initialize_missing_tls_images(var_base: *mut u8, first_missing_module: usize) {
    let first = core::cmp::min(first_missing_module, TLS_MODULE_COUNT);
    for i in first..TLS_MODULE_COUNT {
        if TLS_MEMSZ[i] == 0 {
            continue;
        }
        let dst = var_base.add(TLS_LAYOUT_OFFSET[i]);
        let src = TLS_IMAGE[i];
        let filesz = TLS_FILESZ[i] as usize;
        let memsz = TLS_MEMSZ[i] as usize;
        if filesz > 0 {
            core::ptr::copy_nonoverlapping(src, dst, filesz);
        }
        if memsz > filesz {
            core::ptr::write_bytes(dst.add(filesz), 0, memsz - filesz);
        }
    }
}

unsafe fn expand_thread_tls() -> bool {
    let old_fs = read_tp();
    if old_fs == 0 {
        return false;
    }
    let old_tcb = tcb_for_thread(old_fs);
    let recorded_data =
        core::ptr::read_unaligned(old_tcb.add(TCB_BLOCK_SIZE_OFFSET) as *const usize);
    if recorded_data == 0 {
        return false;
    }
    let old_data = recorded_data;
    let old_module_count =
        core::ptr::read_unaligned(old_tcb.add(TCB_TLS_MODULE_COUNT_OFFSET) as *const usize);
    let old_tp_offset = thread_block_tp_offset(old_fs, old_data);
    let old_block = (old_fs as usize).wrapping_sub(old_tp_offset) as *mut u8;
    let old_var_base = {
                {
            old_fs as *mut u8
        }
    };

    // The initial TLS allocation deliberately has spare capacity. Keep a
    // simple late image in that allocation when its recorded TP placement and
    // data capacity remain valid: replacing the whole block would discard no
    // state but would add one mmap/munmap pair for every ordinary `dlopen`.
    // A larger layout or a stronger AArch64 TP alignment still takes the
    // replacement path below, which is required to preserve every address and
    // the per-allocation cleanup metadata.
    if old_data >= TLS_TOTAL_SIZE && old_tp_offset == tls_tp_offset_from_block() {
        initialize_missing_tls_images(old_var_base, old_module_count);
        initialize_tls_tcb(old_tcb, old_fs as *mut u8, old_data);
        return true;
    }

    let total = match TLS_TOTAL_SIZE.checked_add(tls_tp_offset_from_block()) {
        Some(total) => total,
        None => return false,
    };
    let block = sys_mmap(
        core::ptr::null_mut(),
        total,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    if block as usize == MAP_FAILED {
        return false;
    }
    let new_var_base = block.add(tls_var_area_offset_from_block());
    let copy_size = if old_data < TLS_TOTAL_SIZE {
        old_data
    } else {
        TLS_TOTAL_SIZE
    };
    core::ptr::copy_nonoverlapping(old_var_base, new_var_base, copy_size);
    initialize_missing_tls_images(new_var_base, old_module_count);
    let tcb = block.add(tls_tcb_offset_from_block());
    // Preserve libc's TCB fields while
    // replacing the allocation.  Only the loader-owned metadata below is
    // rewritten after the copy.
    core::ptr::copy_nonoverlapping(old_tcb, tcb, TCB_SIZE);
    let new_tp = block.add(tls_tp_offset_from_block());
    initialize_tls_tcb(tcb, new_tp, TLS_TOTAL_SIZE);
    let old_block_size = match old_data.checked_add(old_tp_offset) {
        Some(size) => size,
        None => {
            sys_munmap(block, total);
            return false;
        }
    };
    write_tp(new_tp as usize);
    if old_block_size != 0 && old_block != block {
        sys_munmap(old_block, old_block_size);
    }
    true
}

/// Reserve every TLS image in a newly loaded dependency graph. The caller
/// holds the resulting lock until relocations have made all of those images
/// usable, then completes the update with `initialize_new_module_tls`.
unsafe fn register_tls_for_new_modules(first_new: usize) -> bool {
    if first_new >= LOADED_COUNT {
        return false;
    }
    let mut contains_tls = false;
    for idx in first_new..LOADED_COUNT {
        if LOADED[idx].tls_memsz != 0 {
            contains_tls = true;
            break;
        }
    }
    if !contains_tls {
        return false;
    }
    tls_lock();
    let mut new_used = TLS_USED_SIZE;
    for idx in first_new..LOADED_COUNT {
        let obj = &LOADED[idx];
        if obj.tls_memsz == 0 {
            continue;
        }
        let align = if obj.tls_align > 0 {
            obj.tls_align as usize
        } else {
            1
        };

        // Existing modules retain their original alignments. Reusing the new
        // image's alignment for every prior image could move their offsets;
        // `TLS_USED_SIZE` is therefore the monotonic logical frontier while
        // `TLS_TOTAL_SIZE` remains allocation capacity.
        if !align.is_power_of_two() {
            tls_unlock();
            return false;
        }
                if align > TLS_TP_OFFSET {
            // AArch64's TP is above the TCB and static TLS. A late DSO with a
            // stronger PT_TLS alignment needs a correspondingly larger gap in
            // newly allocated blocks; existing threads retain their recorded
            // offset until they migrate on the next TLS lookup.
            TLS_TP_OFFSET = align;
        }
        let new_offset = (new_used + align - 1) & !(align - 1);
        new_used = match new_offset.checked_add(obj.tls_memsz as usize) {
            Some(value) => value,
            None => {
                tls_unlock();
                return false;
            }
        };
        TLS_LAYOUT_OFFSET[idx] = new_offset;
        TLS_FILESZ[idx] = obj.tls_filesz;
        TLS_MEMSZ[idx] = obj.tls_memsz;
        TLS_IMAGE[idx] = obj.tls_image;
    }
    if new_used > TLS_TOTAL_SIZE {
        let doubled = new_used.saturating_mul(2);
        let minimum = if doubled < 4096 { 4096 } else { doubled };
        TLS_TOTAL_SIZE = (minimum + 4095) & !4095;
    }
    TLS_USED_SIZE = new_used;
    TLS_MODULE_COUNT = LOADED_COUNT;
    TLS_GENERATION = TLS_GENERATION.wrapping_add(1);
    if TLS_GENERATION == 0 {
        TLS_GENERATION = 1;
    }

    true
}

/// Copy relocated images missing from the calling thread's TLS block, then
/// thread, then let other threads observe the new generation.
unsafe fn initialize_new_module_tls() {
    let _ = expand_thread_tls();
    tls_unlock();
}

// Keep the complete GNU/SysV/linear dispatch out of `__ldso_dlsym` itself.
// The public entry also carries all special-handle and error paths; inlining
// the lookup into each scope arm made its AArch64 hot code exceed the small
// instruction footprint that a repeated handle-local lookup needs. This
// remains one direct internal call, with no allocation or synchronization
// boundary added to the lookup contract.
#[inline(never)]
unsafe fn lookup_symbol_in_object(
    obj_idx: usize,
    name: *const u8,
    name_len: usize,
    name_gnu_hash: u32,
) -> u64 {
    let obj = &LOADED[obj_idx];
    let Some(sym_idx) = lookup_symbol_index_in_object::<false>(obj, name, name_len, name_gnu_hash)
    else {
        return 0;
    };
    let sym_entry = obj.symtab.add(sym_idx * SYMTAB_ENT_SIZE);
    let st_value =
        u64::from_le_bytes(core::ptr::read_unaligned(sym_entry.add(8) as *const [u8; 8]));
    obj.base + st_value
}

/// Return a previously resolved definition from this exact handle, if the
/// current C-string bytes still match the bounded per-thread cache entry.
///
/// `dlsym` accepts a mutable C string. Caching only its address would make a
/// caller-visible lookup stale after the caller reuses and edits that array.
/// The entry is therefore keyed by the current length, GNU hash, and a copied
/// prefix that covers every cacheable name. It contains only a definition in
/// the requested object's own symbol table: later global loads cannot
/// interpose before that direct definition, and this loader retains a closed
/// object's mapping as musl does.
///
/// # Safety
///
/// `symbol` must be a valid NUL-terminated C string of `name_len` bytes. The
/// caller holds the loader lock whenever another thread could mutate loader
/// state, and `handle` is the C ABI address previously returned for a loaded
/// object.
unsafe fn cached_handle_local_symbol(
    handle: *mut u8,
    symbol: *const u8,
    name_len: usize,
    name_gnu_hash: u32,
) -> u64 {
    if name_len > DLSYM_CACHE_NAME_LIMIT {
        return 0;
    }
    let thread_pointer = read_tp();
    if thread_pointer == 0 {
        return 0;
    }
    let tcb = tcb_for_thread(thread_pointer);
    let cached_result =
        core::ptr::read_unaligned(tcb.add(TCB_DLSYM_CACHE_RESULT_OFFSET) as *const u64);
    if cached_result == 0
        || core::ptr::read_unaligned(tcb.add(TCB_DLSYM_CACHE_HANDLE_OFFSET) as *const usize)
            != handle.addr()
        || core::ptr::read_unaligned(tcb.add(TCB_DLSYM_CACHE_NAME_LEN_OFFSET) as *const usize)
            != name_len
        || core::ptr::read_unaligned(tcb.add(TCB_DLSYM_CACHE_HASH_OFFSET) as *const u32)
            != name_gnu_hash
    {
        return 0;
    }
    let cached_name = tcb.add(TCB_DLSYM_CACHE_NAME_OFFSET);
    for offset in 0..name_len {
        if *symbol.add(offset) != *cached_name.add(offset) {
            return 0;
        }
    }
    cached_result
}

/// Store one successful direct definition in the calling thread's private
/// cache. The result address is written last, so zero always denotes an empty
/// entry while a new thread initializes its loader state.
///
/// # Safety
///
/// `symbol` must be a valid C string of at most `DLSYM_CACHE_NAME_LIMIT`
/// bytes, and `handle`/`result` must be the direct loaded-object definition
/// just resolved by `lookup_symbol_in_object` for the calling thread.
unsafe fn cache_handle_local_symbol(
    handle: *mut u8,
    symbol: *const u8,
    name_len: usize,
    name_gnu_hash: u32,
    result: u64,
) {
    if result == 0 || name_len > DLSYM_CACHE_NAME_LIMIT {
        return;
    }
    let thread_pointer = read_tp();
    if thread_pointer == 0 {
        return;
    }
    let tcb = tcb_for_thread(thread_pointer);
    core::ptr::copy_nonoverlapping(symbol, tcb.add(TCB_DLSYM_CACHE_NAME_OFFSET), name_len);
    core::ptr::write_unaligned(
        tcb.add(TCB_DLSYM_CACHE_HANDLE_OFFSET) as *mut usize,
        handle.addr(),
    );
    core::ptr::write_unaligned(
        tcb.add(TCB_DLSYM_CACHE_NAME_LEN_OFFSET) as *mut usize,
        name_len,
    );
    core::ptr::write_unaligned(
        tcb.add(TCB_DLSYM_CACHE_HASH_OFFSET) as *mut u32,
        name_gnu_hash,
    );
    core::ptr::write_unaligned(tcb.add(TCB_DLSYM_CACHE_RESULT_OFFSET) as *mut u64, result);
}

unsafe fn set_dlerror(msg: &[u8]) {
    dlerror_lock();
    let node = dlerror_node_locked();
    if node.is_null() {
        dlerror_unlock();
        return;
    }
    let len = if msg.len() >= DLERROR_BUF_SIZE {
        DLERROR_BUF_SIZE - 1
    } else {
        msg.len()
    };
    core::ptr::copy_nonoverlapping(msg.as_ptr(), (*node).buf.as_mut_ptr(), len);
    (*node).buf[len] = 0;
    (*node).set.store(true, Ordering::Release);
    dlerror_unlock();
}

/// Record a failed `dlsym` lookup without dropping the requested symbol.
///
/// Consumers such as Lua include `dlerror()` text in their own diagnostic,
/// and a bare “symbol not found” makes a loadable-module failure needlessly
/// opaque.  The message is bounded by the existing per-thread dlerror buffer;
/// truncation is explicit rather than allocating while the loader lock is held.
unsafe fn set_dlsym_symbol_not_found(symbol: *const u8, name_len: usize) {
    const PREFIX: &[u8] = b"dlsym: symbol not found: ";
    dlerror_lock();
    let node = dlerror_node_locked();
    if node.is_null() {
        dlerror_unlock();
        return;
    }
    let prefix_len = PREFIX.len().min(DLERROR_BUF_SIZE - 1);
    core::ptr::copy_nonoverlapping(PREFIX.as_ptr(), (*node).buf.as_mut_ptr(), prefix_len);
    let symbol_len = name_len.min(DLERROR_BUF_SIZE - 1 - prefix_len);
    core::ptr::copy_nonoverlapping(symbol, (*node).buf.as_mut_ptr().add(prefix_len), symbol_len);
    (*node).buf[prefix_len + symbol_len] = 0;
    (*node).set.store(true, Ordering::Release);
    dlerror_unlock();
}

const DL_GLOBAL_SENTINEL: *mut u8 = 1usize as *mut u8;
// This handle is never exposed through dlfcn.h.  libc uses it only through
// the established ldso dlsym callback to obtain typed internal operations
// without adding more public registration symbols to libc.so.
const DL_PRIVATE_SENTINEL: *mut u8 = 2usize as *mut u8;

type LdsoDlopenFn = unsafe extern "C" fn(*const u8, i32) -> *mut u8;
type LdsoDlsymFn = unsafe extern "C" fn(*mut u8, *const u8) -> *mut u8;
type LdsoDlcloseFn = unsafe extern "C" fn(*mut u8) -> i32;
type LdsoDlerrorFn = unsafe extern "C" fn() -> *const u8;
type LdsoMarkMultithreadedFn = unsafe extern "C" fn();
pub type LdsoIterateCallback = unsafe extern "C" fn(*mut LdsoDlPhdrInfo, usize, *mut u8) -> i32;

unsafe fn register_dlopen_callbacks() {
    let debug_addr = resolve_symbol(b"_dl_debug_addr\0".as_ptr());
    if debug_addr != 0 {
        core::ptr::write(debug_addr as *mut *mut u8, _dl_debug_addr as *mut u8);
    }

    let reg_open = resolve_symbol(b"__ldso_register_dlopen\0".as_ptr());
    if reg_open != 0 {
        let f: extern "C" fn(LdsoDlopenFn) = core::mem::transmute(reg_open);
        f(__ldso_dlopen as LdsoDlopenFn);
    }
    let reg_sym = resolve_symbol(b"__ldso_register_dlsym\0".as_ptr());
    if reg_sym != 0 {
        let f: extern "C" fn(LdsoDlsymFn) = core::mem::transmute(reg_sym);
        f(__ldso_dlsym as LdsoDlsymFn);
    }
    let reg_close = resolve_symbol(b"__ldso_register_dlclose\0".as_ptr());
    if reg_close != 0 {
        let f: extern "C" fn(LdsoDlcloseFn) = core::mem::transmute(reg_close);
        f(__ldso_dlclose as LdsoDlcloseFn);
    }
    let reg_error = resolve_symbol(b"__ldso_register_dlerror\0".as_ptr());
    if reg_error != 0 {
        let f: extern "C" fn(LdsoDlerrorFn) = core::mem::transmute(reg_error);
        f(__ldso_dlerror as LdsoDlerrorFn);
    }
    let reg_threaded = resolve_symbol(b"__ldso_register_mark_multithreaded\0".as_ptr());
    if reg_threaded != 0 {
        let f: extern "C" fn(LdsoMarkMultithreadedFn) = core::mem::transmute(reg_threaded);
        f(__ldso_mark_multithreaded as LdsoMarkMultithreadedFn);
    }
}

#[no_mangle]
pub unsafe extern "C" fn __ldso_dlopen(filename: *const u8, flags: i32) -> *mut u8 {
    loader_lock();
    if filename.is_null() {
        loader_unlock();
        return DL_GLOBAL_SENTINEL;
    }
    publish_debug_state(RT_ADD);
    let name_len = str_len(filename);
    if let Some(idx) = loaded_object_by_name(filename, name_len) {
        if LOADED[idx].ref_count != usize::MAX {
            LOADED[idx].ref_count = LOADED[idx].ref_count.saturating_add(1);
        }
        LOADED[idx].global = LOADED[idx].global || (flags & RTLD_GLOBAL) != 0;
        publish_debug_state(RT_CONSISTENT);
        loader_unlock();
        return &mut LOADED[idx] as *mut LoadedObject as *mut u8;
    }
    let ld = if LD_LIBRARY_PATH.is_null() {
        None
    } else {
        Some(LD_LIBRARY_PATH)
    };
    let first_new = LOADED_COUNT;
    let idx = match load_named_with_dependencies(filename, name_len, ld) {
        Some(idx) => idx,
        None => {
            cleanup_loaded_objects_from(first_new);
            set_dlerror(b"dlopen: failed to load dependency graph\0");
            publish_debug_state(RT_CONSISTENT);
            loader_unlock();
            return core::ptr::null_mut();
        }
    };
    if idx < first_new {
        if LOADED[idx].ref_count != usize::MAX {
            LOADED[idx].ref_count = LOADED[idx].ref_count.saturating_add(1);
        }
        LOADED[idx].global = LOADED[idx].global || (flags & RTLD_GLOBAL) != 0;
        publish_debug_state(RT_CONSISTENT);
        loader_unlock();
        return &mut LOADED[idx] as *mut LoadedObject as *mut u8;
    }
    if !set_loaded_name(idx, filename, name_len) {
        cleanup_loaded_objects_from(first_new);
        set_dlerror(b"dlopen: library name too long\0");
        publish_debug_state(RT_CONSISTENT);
        loader_unlock();
        return core::ptr::null_mut();
    }
    LOADED[idx].global = (flags & RTLD_GLOBAL) != 0;
    LOADED[idx].ref_count = 1;
    DL_ADDS = DL_ADDS.wrapping_add((LOADED_COUNT - first_new) as u64);
    // TLS descriptors need the final module offset, while the TLS image can
    // contain ordinary relocations. Reserve the layout, relocate the image,
    // then copy that relocated image into the current thread's TLS block.
    let tls_update = register_tls_for_new_modules(first_new);
    process_relocation_suffix(first_new);
        apply_relro_suffix(first_new);
    if tls_update {
        initialize_new_module_tls();
    }
    run_constructors_for(idx);
    publish_debug_state(RT_CONSISTENT);
    loader_unlock();
    &mut LOADED[idx] as *mut LoadedObject as *mut u8
}

#[no_mangle]
pub unsafe extern "C" fn __ldso_dlsym(handle: *mut u8, symbol: *const u8) -> *mut u8 {
    let loader_locked = dlsym_lock();
    // musl leaves a prior, unobserved failure available to `dlerror()` across
    // a successful loader operation. Callers clear it before the lookup
    // sequence whose result they intend to observe.
    if symbol.is_null() {
        set_dlerror(b"dlsym: null symbol\0");
        dlsym_unlock(loader_locked);
        return core::ptr::null_mut();
    }
    let (name_len, name_gnu_hash) = gnu_symbol_hash_c_string(symbol);
    if handle == DL_PRIVATE_SENTINEL {
        let private = if str_eq(
            symbol,
            name_len,
            b"__crabc_ldso_run_initial_legacy_constructors\0".as_ptr(),
        ) {
            run_initial_legacy_constructors_from_libc as *mut u8
        } else if str_eq(symbol, name_len, b"__crabc_ldso_iterate_phdr\0".as_ptr()) {
            __ldso_dl_iterate_phdr as *mut u8
        } else if str_eq(symbol, name_len, b"__crabc_ldso_dladdr\0".as_ptr()) {
            __ldso_dladdr as *mut u8
        } else if str_eq(symbol, name_len, b"__crabc_ldso_dlinfo\0".as_ptr()) {
            __ldso_dlinfo as *mut u8
        } else if str_eq(symbol, name_len, b"__crabc_ldso_tls_get_addr\0".as_ptr()) {
            __ldso_tls_get_addr as *mut u8
        } else if str_eq(symbol, name_len, b"__crabc_ldso_loader_snapshot\0".as_ptr()) {
            __ldso_loader_snapshot as *mut u8
        } else if str_eq(
            symbol,
            name_len,
            b"__crabc_ldso_loader_information\0".as_ptr(),
        ) {
            __ldso_loader_information as *mut u8
        } else {
            core::ptr::null_mut()
        };
        if private.is_null() {
            set_dlsym_symbol_not_found(symbol, name_len);
        }
        dlsym_unlock(loader_locked);
        return private;
    }
    let mut result: u64 = 0;
    // dlfcn.h exposes RTLD_DEFAULT as a null handle.  The libc bridge uses
    // the private sentinel for dlopen(NULL), but direct callers must retain
    // the standard null-handle global lookup semantics as well.
    if handle.is_null() || handle == DL_GLOBAL_SENTINEL {
        for i in 0..LOADED_COUNT {
            if i == 0 || LOADED[i].global {
                result = lookup_symbol_in_object(i, symbol, name_len, name_gnu_hash);
                if result != 0 {
                    break;
                }
            }
        }
    } else {
        if let Some(idx) = loaded_handle_index(handle) {
            result = cached_handle_local_symbol(handle, symbol, name_len, name_gnu_hash);
            if result == 0 {
                result = lookup_symbol_in_object(idx, symbol, name_len, name_gnu_hash);
                cache_handle_local_symbol(handle, symbol, name_len, name_gnu_hash, result);
            }
            if result == 0 {
                for i in 0..LOADED_COUNT {
                    if i == 0 || LOADED[i].global {
                        result = lookup_symbol_in_object(i, symbol, name_len, name_gnu_hash);
                        if result != 0 {
                            break;
                        }
                    }
                }
            }
        }
    }
    if result == 0 {
        set_dlsym_symbol_not_found(symbol, name_len);
    }
    dlsym_unlock(loader_locked);
    result as *mut u8
}

#[no_mangle]
pub unsafe extern "C" fn __ldso_dlclose(handle: *mut u8) -> i32 {
    loader_lock();
    // `dlopen(NULL, ...)` returns the permanent global process handle. musl
    // accepts `dlclose` for it as a no-op; it is not an address inside LOADED.
    if handle == DL_GLOBAL_SENTINEL {
        loader_unlock();
        return 0;
    }
    let Some(idx) = loaded_handle_index(handle) else {
        set_dlerror(b"dlclose: invalid handle\0");
        loader_unlock();
        return -1;
    };
    if LOADED[idx].ref_count == usize::MAX {
        // Startup objects are permanently retained, as musl does for its
        // global process scope. A handle obtained for one still closes
        // successfully without unmapping the process runtime.
        loader_unlock();
        return 0;
    }
    if LOADED[idx].ref_count == 0 {
        set_dlerror(b"dlclose: invalid handle\0");
        loader_unlock();
        return -1;
    }
    LOADED[idx].ref_count -= 1;
    if LOADED[idx].ref_count == 0 {
        if !LOADED[idx].finalized {
            publish_debug_state(RT_DELETE);
            run_destructors_for(idx);
            // musl invokes the finalizer but retains the mapping. A later
            // dlopen of the same identity reuses its initialized image rather
            // than replaying constructors. Preserve that observable lifecycle
            // while recording that this object's fini hooks are one-shot.
            LOADED[idx].finalized = true;
            publish_debug_state(RT_CONSISTENT);
        }
    }
    loader_unlock();
    0
}

#[no_mangle]
pub unsafe extern "C" fn __ldso_dlerror() -> *const u8 {
    dlerror_lock();
    let node = dlerror_node_locked();
    let result = if !node.is_null() && (*node).set.swap(false, Ordering::AcqRel) {
        (*node).buf.as_ptr()
    } else {
        core::ptr::null()
    };
    dlerror_unlock();
    result
}

unsafe fn loaded_object_phdrs(idx: usize) -> Option<(*const u8, usize)> {
    if idx >= LOADED_COUNT || !LOADED[idx].active {
        return None;
    }
    let base = LOADED[idx].base as usize;
    let ehdr = base as *const u8;
    if *ehdr != 0x7f || *ehdr.add(1) != b'E' || *ehdr.add(2) != b'L' || *ehdr.add(3) != b'F' {
        return None;
    }
    let phoff =
        u64::from_le_bytes(core::ptr::read_unaligned(ehdr.add(32) as *const [u8; 8])) as usize;
    let phentsize =
        u16::from_le_bytes(core::ptr::read_unaligned(ehdr.add(54) as *const [u8; 2])) as usize;
    let phnum =
        u16::from_le_bytes(core::ptr::read_unaligned(ehdr.add(56) as *const [u8; 2])) as usize;
    if phentsize != PHDR_SIZE || phnum == 0 {
        return None;
    }
    Some((ehdr.add(phoff), phnum))
}

unsafe fn loaded_object_contains(idx: usize, address: usize) -> bool {
    let Some((phdr, phnum)) = loaded_object_phdrs(idx) else {
        return false;
    };
    let base = LOADED[idx].base as usize;
    for i in 0..phnum {
        let ph = phdr.add(i * PHDR_SIZE);
        let p_type = u32::from_le_bytes(core::ptr::read_unaligned(ph as *const [u8; 4]));
        if p_type != PT_LOAD {
            continue;
        }
        let vaddr =
            u64::from_le_bytes(core::ptr::read_unaligned(ph.add(PH_VADDR) as *const [u8; 8]))
                as usize;
        let memsz =
            u64::from_le_bytes(core::ptr::read_unaligned(ph.add(PH_MEMSZ) as *const [u8; 8]))
                as usize;
        let start = base.wrapping_add(vaddr);
        let end = start.wrapping_add(memsz);
        if address >= start && address < end {
            return true;
        }
    }
    false
}

unsafe fn loaded_object_tls_data(idx: usize) -> *mut u8 {
    if idx >= LOADED_COUNT || !LOADED[idx].active || LOADED[idx].tls_memsz == 0 {
        return core::ptr::null_mut();
    }
    // A calling thread may predate a late TLS module.  Use the ordinary
    // generation-aware resolver rather than applying the process-global
    // offset to that thread's older allocation.
    let index = TlsIndex {
        ti_module: idx + 1,
        ti_offset: 0,
    };
    __tls_get_addr(&index)
}

unsafe fn snapshot_text(source: &[u8; 256]) -> LdsoSnapshotText {
    let mut result = EMPTY_SNAPSHOT_TEXT;
    let mut len = 0usize;
    while len < source.len() && source[len] != 0 {
        len += 1;
    }
    result.bytes[..len].copy_from_slice(&source[..len]);
    result.len = len as u16;
    result
}

unsafe fn snapshot_error(error: *mut LdsoSnapshotText, message: &[u8]) {
    if error.is_null() {
        return;
    }
    let mut result = EMPTY_SNAPSHOT_TEXT;
    let len = core::cmp::min(message.len(), result.bytes.len());
    result.bytes[..len].copy_from_slice(&message[..len]);
    result.len = len as u16;
    result.flags = (len < message.len()) as u16;
    core::ptr::write(error, result);
}

/// Copy the loader's current image metadata into caller-owned records.
///
/// The lock is held only for this bounded copy.  No callback is invoked and no
/// pointer to `LOADED`, `LINK_MAPS`, or a loader-owned name is returned. The
/// opaque address fields are values for diagnostics; callers must not infer a
/// lifetime or dereference permission from this API.
#[no_mangle]
pub unsafe extern "C" fn __ldso_loader_snapshot(
    records: *mut LdsoLoaderImageV1,
    capacity: usize,
    count: *mut usize,
    generation: *mut u64,
    error: *mut LdsoSnapshotText,
) -> i32 {
    if count.is_null() || generation.is_null() || (capacity != 0 && records.is_null()) {
        snapshot_error(error, b"loader snapshot output is invalid");
        return -1;
    }
    loader_lock();
    let mut total = 0usize;
    for i in 0..LOADED_COUNT {
        if LOADED[i].active {
            total += 1;
        }
    }
    core::ptr::write(count, 0);
    core::ptr::write(generation, DL_ADDS.wrapping_add(DL_SUBS));
    if capacity < total {
        loader_unlock();
        snapshot_error(error, b"loader snapshot capacity is too small");
        return -1;
    }
    let mut output = 0usize;
    for i in 0..LOADED_COUNT {
        if !LOADED[i].active {
            continue;
        }
        let (program_headers, program_header_count) = loaded_object_phdrs(i)
            .map_or((core::ptr::null(), 0), |(phdr, phnum)| {
                (phdr as *const c_void, phnum)
            });
        let record = LdsoLoaderImageV1 {
            image_base: LOADED[i].base as *mut c_void,
            program_headers,
            program_header_count: core::cmp::min(program_header_count, u16::MAX as usize) as u16,
            reserved: 0,
            additions: DL_ADDS,
            removals: DL_SUBS,
            tls_module: if LOADED[i].tls_memsz == 0 { 0 } else { i + 1 },
            tls_data: loaded_object_tls_data(i) as *mut c_void,
            image_name: snapshot_text(&LOADED[i].name),
        };
        core::ptr::write(records.add(output), record);
        output += 1;
    }
    core::ptr::write(count, total);
    loader_unlock();
    0
}

/// Copy useful per-handle metadata without exposing the loader's link map.
#[no_mangle]
pub unsafe extern "C" fn __ldso_loader_information(
    handle: *mut u8,
    info: *mut LdsoLoaderInformationV1,
    error: *mut LdsoSnapshotText,
) -> i32 {
    if info.is_null() {
        snapshot_error(error, b"loader information output is invalid");
        return -1;
    }
    core::ptr::write(
        info,
        LdsoLoaderInformationV1 {
            image_base: core::ptr::null_mut(),
            dynamic_address: core::ptr::null_mut(),
            image_name: EMPTY_SNAPSHOT_TEXT,
        },
    );
    loader_lock();
    let main_index = if handle == DL_GLOBAL_SENTINEL && LOADED_COUNT != 0 && LOADED[0].active {
        Some(0)
    } else {
        None
    };
    let Some(idx) = main_index.or_else(|| loaded_handle_index(handle)) else {
        loader_unlock();
        snapshot_error(error, b"loader information handle is invalid");
        return -1;
    };
    core::ptr::write(
        info,
        LdsoLoaderInformationV1 {
            image_base: LOADED[idx].base as *mut c_void,
            dynamic_address: LOADED[idx].dyn_addr as *mut c_void,
            image_name: snapshot_text(&LOADED[idx].name),
        },
    );
    loader_unlock();
    0
}

/// Invoke a public dl_iterate_phdr callback over the loader's stable snapshot.
#[no_mangle]
pub unsafe extern "C" fn __ldso_dl_iterate_phdr(
    callback: LdsoIterateCallback,
    data: *mut u8,
) -> i32 {
    loader_lock();
    if callback as usize == 0 {
        loader_unlock();
        return -1;
    }
    for i in 0..LOADED_COUNT {
        if !LOADED[i].active {
            continue;
        }
        let Some((phdr, phnum)) = loaded_object_phdrs(i) else {
            continue;
        };
        let info = LdsoDlPhdrInfo {
            dlpi_addr: LOADED[i].base as usize,
            dlpi_name: LOADED[i].name.as_ptr(),
            dlpi_phdr: phdr,
            dlpi_phnum: phnum as u16,
            dlpi_adds: DL_ADDS,
            dlpi_subs: DL_SUBS,
            dlpi_tls_modid: if LOADED[i].tls_memsz == 0 { 0 } else { i + 1 },
            dlpi_tls_data: loaded_object_tls_data(i),
        };
        let mut info = info;
        let result = callback(
            core::ptr::addr_of_mut!(info),
            core::mem::size_of::<LdsoDlPhdrInfo>(),
            data,
        );
        if result != 0 {
            loader_unlock();
            return result;
        }
    }
    loader_unlock();
    0
}

/// Resolve an address to its containing loaded object and nearest dynamic
/// symbol.  The dynamic symbol table is the same table used for relocation,
/// so addresses reported here are post-relocation addresses.
#[no_mangle]
pub unsafe extern "C" fn __ldso_dladdr(address: *const u8, result: *mut LdsoDladdrResult) -> i32 {
    loader_lock();
    if address.is_null() || result.is_null() {
        loader_unlock();
        return 0;
    }
    (*result).fname = core::ptr::null();
    (*result).fbase = 0;
    (*result).sname = core::ptr::null();
    (*result).saddr = 0;

    let address = address as usize;
    for i in 0..LOADED_COUNT {
        if !loaded_object_contains(i, address) {
            continue;
        }
        let obj = &LOADED[i];
        (*result).fname = obj.name.as_ptr();
        (*result).fbase = obj.base as usize;

        if obj.symtab.is_null() || obj.strtab.is_null() {
            loader_unlock();
            return 1;
        }

        let mut best_addr = 0usize;
        let mut best_name = core::ptr::null();
        for sym_idx in 1..obj.sym_count {
            let sym = obj.symtab.add(sym_idx * SYMTAB_ENT_SIZE);
            let name_off =
                u32::from_le_bytes(core::ptr::read_unaligned(sym as *const [u8; 4])) as usize;
            let info = *sym.add(4);
            let shndx = u16::from_le_bytes(core::ptr::read_unaligned(sym.add(6) as *const [u8; 2]));
            let value = u64::from_le_bytes(core::ptr::read_unaligned(sym.add(8) as *const [u8; 8]))
                as usize;
            if shndx == 0 || value == 0 || (info & 0x0f) == STT_TLS || name_off >= obj.strsz {
                continue;
            }
            let symbol_addr = (obj.base as usize).wrapping_add(value);
            if symbol_addr <= address && symbol_addr >= best_addr {
                best_addr = symbol_addr;
                best_name = obj.strtab.add(name_off);
            }
        }
        (*result).sname = best_name;
        (*result).saddr = best_addr;
        loader_unlock();
        return 1;
    }
    loader_unlock();
    0
}

unsafe fn loaded_handle_index(handle: *mut u8) -> Option<usize> {
    if handle.is_null() || handle == DL_GLOBAL_SENTINEL {
        return None;
    }
    let first = core::ptr::addr_of!(LOADED) as usize;
    let handle = handle as usize;
    let span = core::mem::size_of::<LoadedObject>() * LOADED_COUNT;
    if handle < first || handle >= first.saturating_add(span) {
        return None;
    }
    let offset = handle - first;
    let stride = core::mem::size_of::<LoadedObject>();
    if stride == 0 || offset % stride != 0 {
        return None;
    }
    let idx = offset / stride;
    if idx < LOADED_COUNT {
        Some(idx)
    } else {
        None
    }
}

unsafe fn refresh_link_maps() {
    for i in 0..LOADED_COUNT {
        LINK_MAPS[i] = LdsoLinkMap {
            l_addr: LOADED[i].base as usize,
            l_name: LOADED[i].name.as_mut_ptr(),
            l_ld: LOADED[i].dyn_addr as *mut u8,
            l_next: core::ptr::null_mut(),
            l_prev: core::ptr::null_mut(),
        };
    }
    for i in 0..LOADED_COUNT {
        if i > 0 {
            LINK_MAPS[i].l_prev = core::ptr::addr_of_mut!(LINK_MAPS[i - 1]);
        }
        if i + 1 < LOADED_COUNT {
            LINK_MAPS[i].l_next = core::ptr::addr_of_mut!(LINK_MAPS[i + 1]);
        }
    }
}

/// Publish the loader's current rendezvous state and notify debuggers.
///
/// `LINK_MAPS` is rebuilt from `LOADED` before the callback observes the
/// state, so `r_map` and every next/prev link describe the same snapshot as
/// crabc's dl* introspection APIs.  The initial CONSISTENT notification is
/// emitted only after startup relocation/TLS/constructors; runtime additions
/// bracket the actual dlopen mutation with RT_ADD and RT_CONSISTENT.
unsafe fn publish_debug_state(state: i32) {
    refresh_link_maps();
    let debug = core::ptr::addr_of_mut!(LDSO_DEBUG);
    (*debug).r_version = 1;
    (*debug).r_map = if LOADED_COUNT == 0 {
        core::ptr::null_mut()
    } else {
        core::ptr::addr_of_mut!(LINK_MAPS[0])
    };
    (*debug).r_brk = _dl_debug_state as *const () as usize;
    (*debug).r_state = state;
    (*debug).r_ldbase = LDSO_BASE;
    _dl_debug_state();
}

/// Implement RTLD_DI_LINKMAP for handles returned by the existing dlopen
/// bridge.  Unsupported requests and invalid handles use musl's -1 result.
#[no_mangle]
pub unsafe extern "C" fn __ldso_dlinfo(handle: *mut u8, request: i32, arg: *mut u8) -> i32 {
    loader_lock();
    if request != RTLD_DI_LINKMAP || arg.is_null() {
        loader_unlock();
        return -1;
    }
    let Some(idx) = loaded_handle_index(handle) else {
        loader_unlock();
        return -1;
    };
    refresh_link_maps();
    *(arg as *mut *mut LdsoLinkMap) = core::ptr::addr_of_mut!(LINK_MAPS[idx]);
    loader_unlock();
    0
}

unsafe fn compute_tls_layout() {
    let mut total: usize = 0;
    let mut tp_alignment: usize = TCB_SIZE;
    for i in 0..LOADED_COUNT {
        let obj = &LOADED[i];
        let align = if obj.tls_align > 0 {
            obj.tls_align as usize
        } else {
            1
        };
        if align > tp_alignment {
            tp_alignment = align;
        }
        let block_size = ((obj.tls_memsz as usize + align - 1) / align) * align;
        total += block_size;
    }
    if total < 4096 {
        total = 4096;
    }
    total += total;
    TLS_TOTAL_SIZE = (total + 4095) & !4095;
    TLS_TP_OFFSET = tp_alignment;
    // AArch64 uses TLS_ABOVE_TP: static TLS starts at a positive offset from
    // TP. The static linker has already encoded those offsets in local-exec
    // instructions, so the first module must begin at the next boundary of
    // its PT_TLS alignment *relative to TP*. Matching the file-image address
    // here is wrong when the TCB itself is not aligned to that boundary (for
    // example a 4 KiB-aligned TLS variable).
    const GAP_ABOVE_TP: usize = 16;
    let mut offset = GAP_ABOVE_TP;
    for i in 0..LOADED_COUNT {
        let obj = &LOADED[i];
        if obj.tls_memsz == 0 {
            TLS_LAYOUT_OFFSET[i] = 0;
            TLS_FILESZ[i] = 0;
            TLS_MEMSZ[i] = 0;
            TLS_IMAGE[i] = core::ptr::null();
            continue;
        }
        let align = if obj.tls_align > 0 {
            obj.tls_align as usize
        } else {
            1
        };
        offset = (offset + align - 1) & !(align - 1);
        TLS_LAYOUT_OFFSET[i] = offset;
        TLS_FILESZ[i] = obj.tls_filesz;
        TLS_MEMSZ[i] = obj.tls_memsz;
        TLS_IMAGE[i] = obj.tls_image;
        let block_size = ((obj.tls_memsz as usize + align - 1) / align) * align;
        offset += block_size;
    }
    TLS_USED_SIZE = offset;
    TLS_MODULE_COUNT = LOADED_COUNT;
}

/// Materialize only the per-module variable images in a fresh TLS allocation.
/// A pthread subsequently copies its parent's ABI TCB into the same block, so
/// it must not first initialize metadata that that copy will immediately
/// overwrite.
unsafe fn init_tls_images(block: *mut u8) -> *mut u8 {
    let var_base = block.add(tls_var_area_offset_from_block());
    for i in 0..TLS_MODULE_COUNT {
        if TLS_MEMSZ[i] == 0 {
            continue;
        }
        let dst = var_base.add(TLS_LAYOUT_OFFSET[i]);
        let src = TLS_IMAGE[i];
        let filesz = TLS_FILESZ[i] as usize;
        let memsz = TLS_MEMSZ[i] as usize;
        if filesz > 0 {
            core::ptr::copy_nonoverlapping(src, dst, filesz);
        }
        if memsz > filesz {
            core::ptr::write_bytes(dst.add(filesz), 0, memsz - filesz);
        }
    }
    block.add(tls_tp_offset_from_block())
}

/// Materialize a complete initial TLS block, including its loader-owned TCB.
/// The ldso startup path has no parent ABI state to inherit, unlike a new
/// pthread allocation handled by `__rc_init_thread_tls` below.
unsafe fn init_tls_block(block: *mut u8) -> *mut u8 {
    let tp = init_tls_images(block);
    let tcb = block.add(tls_tcb_offset_from_block());
    initialize_tls_tcb(tcb, tp, TLS_TOTAL_SIZE);
    initialize_loader_thread_state(tcb, tp);
    tp
}

#[repr(C)]
pub struct TlsIndex {
    ti_module: usize,
    ti_offset: usize,
}

/// Bridge the public musl TLS index ABI to the loader's TLS state.  The
/// pointed-to index uses the standard one-based module IDs; the internal
/// resolver performs the checked conversion to its zero-based layout arrays.
unsafe extern "C" fn __ldso_tls_get_addr(ti: *const u8) -> *mut u8 {
    if ti.is_null() {
        return core::ptr::null_mut();
    }
    let public = ti as *const usize;
    let module = core::ptr::read_unaligned(public);
    if module == 0 || module > LOADED_COUNT {
        return core::ptr::null_mut();
    }
    let index = TlsIndex {
        ti_module: module,
        ti_offset: core::ptr::read_unaligned(public.add(1)),
    };
    __tls_get_addr(&index)
}

#[no_mangle]
pub unsafe extern "C" fn __tls_get_addr(ti: *const TlsIndex) -> *mut u8 {
    if ti.is_null() {
        return core::ptr::null_mut();
    }
    // The ELF ABI reserves module zero and numbers TLS modules from one. The
    // layout arrays remain indexed by the corresponding zero-based loaded
    // object, so convert only after validating the public module number.
    let module_id = (*ti).ti_module;
    let offset = (*ti).ti_offset;
    if module_id == 0 || module_id > TLS_MODULE_COUNT {
        return core::ptr::null_mut();
    }
    let module = module_id - 1;
    // A module without PT_TLS has no addressable TLS block.  Do not impose a
    // byte-range check on `ti_offset`: the ABI passes symbol/addend offsets,
    // and the allocated image may include alignment padding beyond p_memsz.
    if TLS_MEMSZ[module] == 0 {
        return core::ptr::null_mut();
    }
    let fs_base = read_tp();
    let tcb = tcb_for_thread(fs_base);
    let thread_gen = core::ptr::read_unaligned(tcb.add(TCB_GENERATION_OFFSET) as *const u64);
    if thread_gen != TLS_GENERATION {
        tls_lock();
        let fs_base_locked = read_tp();
        let tcb_locked = tcb_for_thread(fs_base_locked);
        let thread_gen2 =
            core::ptr::read_unaligned(tcb_locked.add(TCB_GENERATION_OFFSET) as *const u64);
        if thread_gen2 != TLS_GENERATION {
            if !expand_thread_tls() {
                tls_unlock();
                return core::ptr::null_mut();
            }
        }
        tls_unlock();
    }
    let fs_base2 = read_tp();
    let tls_base = fs_base2 - tls_var_area_offset_from_tp();
    (tls_base as *mut u8)
        .add(TLS_LAYOUT_OFFSET[module])
        .add(offset) as *mut u8
}

#[no_mangle]
pub unsafe extern "C" fn __rc_create_thread_tls() -> *mut u8 {
    let total = TLS_TOTAL_SIZE + tls_tp_offset_from_block();
    if total == 0 {
        return core::ptr::null_mut();
    }
    let block = sys_mmap(
        core::ptr::null_mut(),
        total,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    if block as usize == MAP_FAILED {
        return core::ptr::null_mut();
    }
    __rc_init_thread_tls(block)
}

/// Initialize a fresh, caller-owned TLS allocation for a pthread. libc uses
/// this private bridge to place the block immediately above its downward-
/// growing stack, avoiding a second anonymous mapping while preserving the
/// loader's per-thread TCB and TLS-image initialization.
#[no_mangle]
pub unsafe extern "C" fn __rc_init_thread_tls(block: *mut u8) -> *mut u8 {
    if block.is_null() || TLS_TOTAL_SIZE == 0 {
        return core::ptr::null_mut();
    }
    let new_tp = init_tls_images(block);
    let new_tcb = block.add(tls_tcb_offset_from_block());
    // New pthreads inherit the process's TCB ABI state (including the stack
    // protector) while receiving fresh TLS variable images.
    let old_fs = read_tp();
    if old_fs != 0 {
        let old_tcb = tcb_for_thread(old_fs) as *const u8;
        core::ptr::copy_nonoverlapping(old_tcb, new_tcb, TCB_SIZE);
    }
    // The parent copy above carries libc's ABI TCB fields. Rewrite only the
    // loader-owned allocation and logical-thread metadata once afterwards.
    initialize_tls_tcb(new_tcb, new_tp, TLS_TOTAL_SIZE);
    initialize_loader_thread_state(new_tcb, new_tp);
    new_tp
}

#[no_mangle]
pub unsafe extern "C" fn __rc_tls_block_size() -> usize {
    TLS_TOTAL_SIZE + tls_tp_offset_from_block()
}

#[no_mangle]
pub unsafe extern "C" fn __rc_tls_base_offset() -> usize {
    tls_tp_offset_from_block()
}

/// Return the allocation size for a specific thread pointer.  Runtime TLS
/// growth can leave an existing thread on an older allocation until its next
/// `__tls_get_addr`; callers reclaiming another thread (pthread slot cleanup,
/// for example) must therefore not use the process-global current size.
#[no_mangle]
pub unsafe extern "C" fn __rc_tls_block_size_for(fs_base: *const u8) -> usize {
    if fs_base.is_null() {
        return 0;
    }
    let tcb = tcb_for_thread(fs_base as usize) as *const u8;
    let data = core::ptr::read_unaligned(tcb.add(TCB_BLOCK_SIZE_OFFSET) as *const usize);
    if data == 0 {
        return 0;
    }
    data.saturating_add(thread_block_tp_offset(fs_base as usize, data))
}

#[no_mangle]
pub unsafe extern "C" fn __rc_tls_base_offset_for(fs_base: *const u8) -> usize {
    if fs_base.is_null() {
        return 0;
    }
    let tcb = tcb_for_thread(fs_base as usize) as *const u8;
    let data = core::ptr::read_unaligned(tcb.add(TCB_BLOCK_SIZE_OFFSET) as *const usize);
    if data == 0 {
        return 0;
    }
    thread_block_tp_offset(fs_base as usize, data)
}

unsafe fn register_self(ldso_base: u64) {
    LDSO_BASE = ldso_base as usize;
    let ehdr = ldso_base as *const u8;
    if *ehdr != 0x7f || *ehdr.add(1) != b'E' {
        return;
    }
    let e_phoff = u64::from_le_bytes(core::ptr::read_unaligned(ehdr.add(32) as *const [u8; 8]));
    let e_phnum =
        u16::from_le_bytes(core::ptr::read_unaligned(ehdr.add(56) as *const [u8; 2])) as usize;
    let mut dyn_vaddr: u64 = 0;
    let mut dyn_memsz: u64 = 0;
    let mut relro_vaddr: u64 = 0;
    let mut relro_memsz: u64 = 0;
    for i in 0..e_phnum {
        let ph = ehdr.add(e_phoff as usize + i * PHDR_SIZE);
        let p_type = u32::from_le_bytes(core::ptr::read_unaligned(ph as *const [u8; 4]));
        if p_type == PT_DYNAMIC {
            dyn_vaddr =
                u64::from_le_bytes(core::ptr::read_unaligned(ph.add(PH_VADDR) as *const [u8; 8]));
            dyn_memsz =
                u64::from_le_bytes(core::ptr::read_unaligned(ph.add(PH_MEMSZ) as *const [u8; 8]));
        } else if p_type == PT_GNU_RELRO {
            relro_vaddr =
                u64::from_le_bytes(core::ptr::read_unaligned(ph.add(PH_VADDR) as *const [u8; 8]));
            relro_memsz =
                u64::from_le_bytes(core::ptr::read_unaligned(ph.add(PH_MEMSZ) as *const [u8; 8]));
        }
    }
    if dyn_vaddr == 0 {
        return;
    }
    let dyn_addr = (ldso_base + dyn_vaddr) as usize;
    let dyn_end = dyn_addr + dyn_memsz as usize;
    let mut dt_symtab: u64 = 0;
    let mut dt_strtab: u64 = 0;
    let mut dt_strsz: u64 = 0;
    let mut dt_gnu_hash: u64 = 0;
    let mut dt_hash: u64 = 0;
    let mut pos = dyn_addr;
    while pos + 16 <= dyn_end {
        let d_tag = u64::from_le_bytes(core::ptr::read_unaligned(pos as *const [u8; 8]));
        let d_val = u64::from_le_bytes(core::ptr::read_unaligned((pos + 8) as *const [u8; 8]));
        if d_tag == DT_NULL {
            break;
        }
        match d_tag {
            DT_SYMTAB => dt_symtab = d_val,
            DT_STRTAB => dt_strtab = d_val,
            DT_STRSZ => dt_strsz = d_val,
            DT_GNU_HASH => dt_gnu_hash = d_val,
            DT_HASH => dt_hash = d_val,
            _ => {}
        }
        pos += 16;
    }
    if dt_symtab == 0 || dt_strtab == 0 {
        return;
    }
    let symtab_ptr = (ldso_base + dt_symtab) as *const u8;
    let strtab_ptr = (ldso_base + dt_strtab) as *const u8;
    let sym_count = if dt_gnu_hash != 0 {
        sym_count_from_gnu_hash((ldso_base + dt_gnu_hash) as usize)
    } else if dt_hash != 0 {
        sym_count_from_hash((ldso_base + dt_hash) as usize)
    } else {
        ((dt_strtab - dt_symtab) / SYMTAB_ENT_SIZE as u64) as usize
    };
    let gnu_hash = if dt_gnu_hash == 0 {
        core::ptr::null()
    } else {
        (ldso_base + dt_gnu_hash) as *const u8
    };
    let gnu_hash_metadata = gnu_hash_metadata(gnu_hash, sym_count);
    if LOADED_COUNT < MAX_LOADED {
        LOADED[LOADED_COUNT] = LoadedObject {
            base: ldso_base,
            map_start: core::ptr::null_mut(),
            map_size: 0,
            symtab: symtab_ptr,
            sym_count,
            gnu_hash,
            gnu_hash_metadata,
            sysv_hash: if dt_hash == 0 {
                core::ptr::null()
            } else {
                (ldso_base + dt_hash) as *const u8
            },
            strtab: strtab_ptr,
            strsz: dt_strsz as usize,
            search_path: core::ptr::null(),
            search_path_len: 0,
            relro_addr: ldso_base + relro_vaddr,
            relro_size: relro_memsz,
            relro_applied: false,
            dependencies: [0; MAX_LOADED],
            dependency_count: 0,
            constructing: false,
            constructed: false,
            dyn_addr,
            dyn_memsz: dyn_memsz as usize,
            tls_image: core::ptr::null(),
            tls_filesz: 0,
            tls_memsz: 0,
            tls_align: 0,
            init: 0,
            init_array: 0,
            init_array_sz: 0,
            init_present: false,
            init_array_present: false,
            fini: 0,
            fini_array: 0,
            fini_array_sz: 0,
            fini_present: false,
            fini_array_present: false,
            global: false,
            ref_count: usize::MAX,
            active: true,
            finalized: false,
            file_identity_valid: false,
            file_dev: 0,
            file_ino: 0,
            initial_ld_library_path_name: false,
            name: [0; 256],
        };
        LOADED_COUNT += 1;
    }
}

unsafe fn set_loaded_name(idx: usize, name: *const u8, name_len: usize) -> bool {
    if idx >= MAX_LOADED {
        return false;
    }
    if name_len >= 255 {
        return false;
    }
    let len = name_len;
    let buf = &mut LOADED[idx].name;
    for i in 0..len {
        buf[i] = *name.add(i);
    }
    buf[len] = 0;
    true
}

unsafe fn loaded_object_by_name(name: *const u8, name_len: usize) -> Option<usize> {
    if name_len == 0 {
        return None;
    }
    // `LOADED[0].name` is the main program's argv[0] for dladdr and
    // dl_iterate_phdr. It is not an existing dlopen object: an explicit path
    // to the executable must map a distinct object, while dlopen(NULL) takes
    // the separate permanent global-handle path above.
    for i in 1..LOADED_COUNT {
        if !LOADED[i].active || LOADED[i].name[0] == 0 {
            continue;
        }
        if str_eq(name, name_len, LOADED[i].name.as_ptr()) {
            return Some(i);
        }
    }
    None
}

unsafe fn loaded_initial_ld_library_path_object_by_name(
    name: *const u8,
    name_len: usize,
) -> Option<usize> {
    if !INITIAL_LOAD_IN_PROGRESS || name_len == 0 {
        return None;
    }
    // A slash makes this a direct name, whose exact path remains subject to
    // normal identity resolution. The startup cache is only for bare
    // DT_NEEDED names whose configured global search result cannot vary while
    // the loader has exclusive control before constructors run.
    for offset in 0..name_len {
        if *name.add(offset) == b'/' {
            return None;
        }
    }
    for idx in 0..LOADED_COUNT {
        let object = &LOADED[idx];
        if object.active
            && object.initial_ld_library_path_name
            && object.name[0] != 0
            && str_eq(name, name_len, object.name.as_ptr())
        {
            return Some(idx);
        }
    }
    None
}

/// Reuse the initial libc for a conventional `DT_NEEDED libc.so` edge.
///
/// Musl gives its initial runtime image the `libc.so` short name, so a DSO
/// loaded later does not reopen and stat the same libc only to rediscover its
/// identity. Preserve the deliberately narrower runtime alias policy for all
/// other names: `$ORIGIN`, RUNPATH/RPATH, direct paths, and arbitrary bare
/// names retain inode-based matching. `TLS_STATIC_MODULE_COUNT` is frozen only
/// after the initial graph is complete, which makes this exact-name reuse
/// unavailable while startup still constructs its dependency closure.
unsafe fn loaded_initial_libc_by_needed_name(name: *const u8, name_len: usize) -> Option<usize> {
    const LIBC_NEEDED_NAME: &[u8] = b"libc.so\0";
    if !str_eq(name, name_len, LIBC_NEEDED_NAME.as_ptr()) {
        return None;
    }
    for idx in 1..TLS_STATIC_MODULE_COUNT {
        let object = &LOADED[idx];
        if object.active && object.name[0] != 0 && str_eq(name, name_len, object.name.as_ptr()) {
            return Some(idx);
        }
    }
    None
}

unsafe fn loaded_object_by_identity(identity: FileIdentity) -> Option<usize> {
    for i in 0..LOADED_COUNT {
        let obj = &LOADED[i];
        if obj.active
            && obj.file_identity_valid
            && obj.file_dev == identity.dev
            && obj.file_ino == identity.ino
        {
            return Some(i);
        }
    }
    None
}

// ============================================================
// Main flow: load executable + dependencies, relocate, jump
// ============================================================

unsafe fn load_and_jump(sp: usize, ldso_base: u64) -> ! {
    // 1. Secure-exec startup ignores all loader-controlled environment
    // search/interposition inputs.  Read AT_SECURE before looking at envp so
    // a set-id or capability transition cannot be influenced by LD_* values.
    let secure = find_auxv_value(sp, AT_SECURE) != 0;
    let ld_path = if secure {
        None
    } else {
        find_env(sp, b"LD_LIBRARY_PATH=")
    };
    initialize_initial_ld_library_path(ld_path);

    // 2. Linux has already mapped the main PIE. Consume the kernel's exact
    // layout instead of opening and mapping a second executable image.
    let main_image = kernel_main_image(sp);
    let exec_base = main_image.base;
    let phdr = main_image.phdr;
    let e_phnum = main_image.phnum;
    initialize_main_origin(sp);

    let mut exec_relro_vaddr = 0u64;
    let mut exec_relro_memsz = 0u64;
    let mut exec_tls_image: *const u8 = core::ptr::null();
    let mut exec_tls_filesz: u64 = 0;
    let mut exec_tls_memsz: u64 = 0;
    let mut exec_tls_align: u64 = 0;
    for i in 0..e_phnum {
        let ph = phdr.add(i * PHDR_SIZE);
        let p_type = u32::from_le_bytes(core::ptr::read_unaligned(ph as *const [u8; 4]));
        if p_type == PT_GNU_RELRO {
            exec_relro_vaddr =
                u64::from_le_bytes(core::ptr::read_unaligned(ph.add(PH_VADDR) as *const [u8; 8]));
            exec_relro_memsz =
                u64::from_le_bytes(core::ptr::read_unaligned(ph.add(PH_MEMSZ) as *const [u8; 8]));
        } else if p_type == PT_TLS {
            let p_vaddr =
                u64::from_le_bytes(core::ptr::read_unaligned(ph.add(PH_VADDR) as *const [u8; 8]));
            exec_tls_filesz = u64::from_le_bytes(core::ptr::read_unaligned(
                ph.add(PH_FILESZ) as *const [u8; 8]
            ));
            exec_tls_memsz =
                u64::from_le_bytes(core::ptr::read_unaligned(ph.add(PH_MEMSZ) as *const [u8; 8]));
            exec_tls_align =
                u64::from_le_bytes(core::ptr::read_unaligned(ph.add(PH_ALIGN) as *const [u8; 8]));
            exec_tls_image = (exec_base + p_vaddr) as *const u8;
        }
    }

    // 3. Parse the executable's PT_DYNAMIC table in its kernel mapping.
    let mut dyn_vaddr: u64 = 0;
    let mut dyn_memsz: u64 = 0;
    for i in 0..e_phnum {
        let ph = phdr.add(i * PHDR_SIZE);
        let p_type = u32::from_le_bytes(core::ptr::read_unaligned(ph as *const [u8; 4]));
        if p_type == PT_DYNAMIC {
            dyn_vaddr =
                u64::from_le_bytes(core::ptr::read_unaligned(ph.add(PH_VADDR) as *const [u8; 8]));
            dyn_memsz =
                u64::from_le_bytes(core::ptr::read_unaligned(ph.add(PH_MEMSZ) as *const [u8; 8]));
            break;
        }
    }

    let mut dt_symtab: u64 = 0;
    let mut dt_strtab: u64 = 0;
    let mut dt_strsz: u64 = 0;
    let mut dt_init: u64 = 0;
    let mut dt_init_array: u64 = 0;
    let mut dt_init_array_sz: u64 = 0;
    let mut dt_init_present = false;
    let mut dt_init_array_present = false;
    let mut dt_runpath_off: u64 = 0;
    let mut dt_runpath_present = false;
    let mut dt_rpath_off: u64 = 0;
    let mut dt_rpath_present = false;
    let mut dt_gnu_hash: u64 = 0;
    let mut dt_hash: u64 = 0;

    let mut dynamic_terminated = dyn_vaddr == 0;
    if dyn_vaddr != 0 {
        let dyn_start = (exec_base + dyn_vaddr) as usize;
        let dyn_end = dyn_start + dyn_memsz as usize;
        let mut dp = dyn_start;
        while dp + 16 <= dyn_end {
            let d_tag = u64::from_le_bytes(core::ptr::read_unaligned(dp as *const [u8; 8]));
            let d_val = u64::from_le_bytes(core::ptr::read_unaligned((dp + 8) as *const [u8; 8]));
            if d_tag == DT_NULL {
                dynamic_terminated = true;
                break;
            }
            match d_tag {
                DT_SYMTAB => dt_symtab = d_val,
                DT_STRTAB => dt_strtab = d_val,
                DT_STRSZ => dt_strsz = d_val,
                DT_GNU_HASH => dt_gnu_hash = d_val,
                DT_HASH => dt_hash = d_val,
                DT_INIT => {
                    dt_init = d_val;
                    dt_init_present = true;
                }
                DT_INIT_ARRAY => {
                    dt_init_array = d_val;
                    dt_init_array_present = true;
                }
                DT_INIT_ARRAYSZ => dt_init_array_sz = d_val,
                DT_RUNPATH => {
                    dt_runpath_off = d_val;
                    dt_runpath_present = true;
                }
                DT_RPATH => {
                    dt_rpath_off = d_val;
                    dt_rpath_present = true;
                }
                _ => {}
            }
            dp += 16;
        }
    }
    if !dynamic_terminated {
        die(96, b"dynamic_overflow", dyn_memsz as usize);
    }

    if dt_runpath_present {
        if dt_runpath_off >= dt_strsz {
            die(96, b"runpath_overflow", dt_runpath_off as usize);
        }
        RUNPATH = (exec_base + dt_strtab + dt_runpath_off) as *const u8;
        let available = (dt_strsz - dt_runpath_off) as usize;
        let Some(length) = dynamic_string_len(RUNPATH, available) else {
            die(96, b"runpath_string", available);
        };
        RUNPATH_LEN = length;
    } else if dt_rpath_present {
        if dt_rpath_off >= dt_strsz {
            die(96, b"rpath_overflow", dt_rpath_off as usize);
        }
        RUNPATH = (exec_base + dt_strtab + dt_rpath_off) as *const u8;
        let available = (dt_strsz - dt_rpath_off) as usize;
        let Some(length) = dynamic_string_len(RUNPATH, available) else {
            die(96, b"rpath_string", available);
        };
        RUNPATH_LEN = length;
    }

    // Register executable as LOADED[0]
    let mut exec_sym_count: usize = 0;
    if dt_gnu_hash != 0 {
        exec_sym_count = sym_count_from_gnu_hash((exec_base + dt_gnu_hash) as usize);
    } else if dt_hash != 0 {
        exec_sym_count = sym_count_from_hash((exec_base + dt_hash) as usize);
    } else if dt_strtab > dt_symtab && dt_strtab - dt_symtab >= SYMTAB_ENT_SIZE as u64 {
        exec_sym_count = ((dt_strtab - dt_symtab) / SYMTAB_ENT_SIZE as u64) as usize;
    }
    let exec_gnu_hash = if dt_gnu_hash == 0 {
        core::ptr::null()
    } else {
        (exec_base + dt_gnu_hash) as *const u8
    };
    let exec_gnu_hash_metadata = gnu_hash_metadata(exec_gnu_hash, exec_sym_count);
    LOADED[0] = LoadedObject {
        base: exec_base,
        // The main image belongs to the kernel's exec mapping, not this
        // loader. Never hand it to generic DSO cleanup.
        map_start: core::ptr::null_mut(),
        map_size: 0,
        symtab: (exec_base + dt_symtab) as *const u8,
        sym_count: exec_sym_count,
        gnu_hash: exec_gnu_hash,
        gnu_hash_metadata: exec_gnu_hash_metadata,
        sysv_hash: if dt_hash == 0 {
            core::ptr::null()
        } else {
            (exec_base + dt_hash) as *const u8
        },
        strtab: (exec_base + dt_strtab) as *const u8,
        strsz: dt_strsz as usize,
        search_path: core::ptr::null(),
        search_path_len: 0,
        relro_addr: exec_base + exec_relro_vaddr,
        relro_size: exec_relro_memsz,
        relro_applied: false,
        dependencies: [0; MAX_LOADED],
        dependency_count: 0,
        constructing: false,
        constructed: false,
        dyn_addr: (exec_base + dyn_vaddr) as usize,
        dyn_memsz: dyn_memsz as usize,
        tls_image: exec_tls_image,
        tls_filesz: exec_tls_filesz,
        tls_memsz: exec_tls_memsz,
        tls_align: exec_tls_align,
        init: exec_base + dt_init,
        init_array: exec_base + dt_init_array,
        init_array_sz: dt_init_array_sz,
        init_present: dt_init_present,
        init_array_present: dt_init_array_present,
        fini: 0,
        fini_array: 0,
        fini_array_sz: 0,
        fini_present: false,
        fini_array_present: false,
        global: true,
        ref_count: usize::MAX,
        active: true,
        finalized: false,
        file_identity_valid: false,
        file_dev: 0,
        file_ino: 0,
        initial_ld_library_path_name: false,
        name: [0; 256],
    };
    LOADED_COUNT = 1;
    // dladdr/dl_iterate_phdr report the invocation path for the main object,
    // matching the name exposed by musl rather than an empty DT_NEEDED name.
    let argv0 = *((sp + 8) as *const u64) as *const u8;
    if !argv0.is_null() {
        set_loaded_name(0, argv0, str_len(argv0));
    }
    register_self(ldso_base);

    // Inspect the mapped main image before any constructor runs. The owned
    // CRT note selects the private x0 handoff; every other executable retains
    // the conventional direct `rtld_fini` pointer.
    let owned_crt_lifecycle = unsafe { main_uses_owned_crt_lifecycle(phdr, e_phnum, exec_base) };
    INITIAL_MAIN_USES_OWNED_CRT = owned_crt_lifecycle;

    // `LD_PRELOAD` belongs ahead of the executable's DT_NEEDED graph: its
    // definitions must already be visible when the ordinary dependencies'
    // PLT/GOT relocations are resolved. Preserve the kernel envp pointer until
    // after this point; the replacement application stack is built later.
    INITIAL_LOAD_IN_PROGRESS = true;
    if !secure {
        if let Some(preload) = find_env(sp, b"LD_PRELOAD=") {
            if !load_preload_list(preload, ld_path) {
                cleanup_loaded_objects_from(1);
                die(87, b"preload_graph", 0);
            }
        }
    }

    // 5. Load every DT_NEEDED entry directly from the dynamic table.  This
    // avoids any fixed local list: malformed or unusually large tables are
    // walked to their terminator and dependency-capacity failures are
    // reported by the graph builder rather than silently truncated.
    if !load_needed_dependencies(0, ld_path) {
        cleanup_loaded_objects_from(1);
        die(89, b"needed_graph", 0);
    }
    INITIAL_LOAD_IN_PROGRESS = false;

    compute_tls_layout();
    TLS_STATIC_MODULE_COUNT = TLS_MODULE_COUNT;

    process_all_relocations();
    register_dlopen_callbacks();
        apply_relro();

    // Always allocate a TCB so that %fs-relative accesses (e.g. stack canary
    // at %fs:0x28) work even when there is no TLS data in the binary.
    {
        let alloc_size = TLS_TOTAL_SIZE + tls_tp_offset_from_block();
        let tls_block = sys_mmap(
            core::ptr::null_mut(),
            alloc_size,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        );
        if tls_block as usize == MAP_FAILED {
            die(93, b"tls_mmap", alloc_size);
        }
        let _tcb = init_tls_block(tls_block);
        write_tp(_tcb as usize);
    }

    // Set libc.so's __auxv so constructors (e.g. compiler_builtins CPU feature
    // detection) can call getauxval before __libc_start_main runs.
    let argc = *(sp as *const u64) as usize;
    let argv_start = sp + 8;
    let envp_start = argv_start + (argc + 1) * 8;
    let mut envc = 0usize;
    while *((envp_start + envc * 8) as *const u64) != 0 {
        envc += 1;
    }
    let auxv = (envp_start + (envc + 1) * 8) as *const usize;
    let auxv_sym = resolve_symbol(b"__auxv\0".as_ptr());
    if auxv_sym != 0 {
        core::ptr::write(auxv_sym as *mut *const usize, auxv);
    }

    // Publish the complete post-relocation object graph.  This mirrors musl's
    // initial RT_CONSISTENT rendezvous and leaves `_dl_debug_addr` pointing at
    // the same map snapshot that runtime dl* queries use.
    publish_debug_state(RT_CONSISTENT);

    if secure {
        build_and_jump(
            main_image.entry,
            phdr.addr() as u64,
            e_phnum as u16,
            sp,
            true,
            owned_crt_lifecycle,
        )
    }
    jump_to_entry(main_image.entry, sp, owned_crt_lifecycle)
}

// ============================================================
// Build a fresh filtered stack for secure execution and jump
// ============================================================

unsafe fn build_and_jump(
    entry: u64,
    phdr_addr: u64,
    phnum: u16,
    orig_sp: usize,
    secure: bool,
    owned_crt_lifecycle: bool,
) -> ! {
    let argc = *(orig_sp as *const u64) as usize;
    let argv_start = orig_sp + 8;
    let envp_start = argv_start + (argc + 1) * 8;

    let mut original_envc: usize = 0;
    while *((envp_start + original_envc * 8) as *const u64) != 0 {
        original_envc += 1;
    }

    let auxv = (envp_start + (original_envc + 1) * 8) as *const u64;
    let mut envc = original_envc;
    if secure {
        envc = 0;
        for i in 0..original_envc {
            let entry = *((envp_start + i * 8) as *const u64) as *const u8;
            if !secure_env_entry_is_unsafe(entry) {
                envc += 1;
            }
        }
    }
    let mut aux_entries = 0usize;
    loop {
        let tag = *auxv.add(aux_entries * 2);
        aux_entries = match aux_entries.checked_add(1) {
            Some(value) => value,
            None => die(94, b"stack_auxv", 0),
        };
        if tag == AT_NULL {
            break;
        }
    }

    // Size the replacement stack from the complete vectors.  Bounded local
    // arrays cannot safely represent the kernel-provided startup contract.
    let mut strings_size = 0usize;
    for i in 0..argc {
        let s = *((argv_start + i * 8) as *const u64) as *const u8;
        let len = match str_len(s).checked_add(1) {
            Some(value) => value,
            None => die(94, b"stack_strings", i),
        };
        strings_size = match strings_size.checked_add(len) {
            Some(value) => value,
            None => die(94, b"stack_strings", i),
        };
    }
    for i in 0..envc {
        let mut source_index = i;
        if secure {
            let mut seen = 0usize;
            source_index = 0;
            while source_index < original_envc {
                let entry = *((envp_start + source_index * 8) as *const u64) as *const u8;
                if !secure_env_entry_is_unsafe(entry) {
                    if seen == i {
                        break;
                    }
                    seen += 1;
                }
                source_index += 1;
            }
        }
        let s = *((envp_start + source_index * 8) as *const u64) as *const u8;
        let len = match str_len(s).checked_add(1) {
            Some(value) => value,
            None => die(94, b"stack_strings", i),
        };
        strings_size = match strings_size.checked_add(len) {
            Some(value) => value,
            None => die(94, b"stack_strings", i),
        };
    }
    let ptr_count = match argc
        .checked_add(1)
        .and_then(|value| envc.checked_add(1).and_then(|env| value.checked_add(env)))
    {
        Some(value) => value,
        None => die(94, b"stack_ptrs", 0),
    };
    let ptr_bytes = match ptr_count.checked_mul(8) {
        Some(value) => value,
        None => die(94, b"stack_ptrs", ptr_count),
    };
    let aux_bytes = match aux_entries.checked_mul(16) {
        Some(value) => value,
        None => die(94, b"stack_auxv", aux_entries),
    };
    let required = match strings_size
        .checked_add(ptr_bytes)
        .and_then(|value| value.checked_add(aux_bytes))
        .and_then(|value| value.checked_add(16 + 128))
    {
        Some(value) => value,
        None => die(94, b"stack_size", 0),
    };
    let minimum_stack = 256 * 1024usize;
    let requested_stack = if required > minimum_stack {
        required
    } else {
        minimum_stack
    };
    let stack_size = match requested_stack.checked_add(4095).map(|value| value & !4095) {
        Some(value) => value,
        None => die(94, b"stack_size", requested_stack),
    };
    let stack_base = sys_mmap(
        core::ptr::null_mut(),
        stack_size,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    if stack_base as usize == MAP_FAILED {
        die(94, b"stack_mmap", stack_size);
    }
    let stack_end = stack_base as usize + stack_size;
    let strings_start = (stack_end - strings_size) & !15usize;
    let random_ptr = (strings_start - 16) & !15usize;
    let aux_base = (random_ptr - aux_bytes) & !15usize;
    // Keep argc at a 16-byte boundary (including AArch64's strict process
    // entry rule), then place argv immediately after it.  Rounding down may
    // leave a small gap before auxv; the size calculation reserves it.
    let sp = (aux_base - ptr_bytes - 8) & !15usize;
    let ptr_base = sp + 8;

    let argv_ptrs = ptr_base as *mut u64;
    let envp_ptrs = argv_ptrs.add(argc + 1);
    let mut string_cursor = strings_start;
    for i in 0..argc {
        let s = *((argv_start + i * 8) as *const u64) as *const u8;
        let len = str_len(s) + 1;
        core::ptr::copy_nonoverlapping(s, string_cursor as *mut u8, len);
        *argv_ptrs.add(i) = string_cursor as u64;
        string_cursor += len;
    }
    *argv_ptrs.add(argc) = 0;
    for i in 0..envc {
        let mut source_index = i;
        if secure {
            let mut seen = 0usize;
            source_index = 0;
            while source_index < original_envc {
                let entry = *((envp_start + source_index * 8) as *const u64) as *const u8;
                if !secure_env_entry_is_unsafe(entry) {
                    if seen == i {
                        break;
                    }
                    seen += 1;
                }
                source_index += 1;
            }
        }
        let s = *((envp_start + source_index * 8) as *const u64) as *const u8;
        let len = str_len(s) + 1;
        core::ptr::copy_nonoverlapping(s, string_cursor as *mut u8, len);
        *envp_ptrs.add(i) = string_cursor as u64;
        string_cursor += len;
    }
    *envp_ptrs.add(envc) = 0;

    // Preserve AT_RANDOM on the replacement stack and copy every auxv pair,
    // changing only values whose addresses changed when the PIE was remapped.
    let mut random_bytes = [0u8; 16];
    let mut original_random = core::ptr::null();
    for i in 0..aux_entries {
        if *auxv.add(i * 2) == AT_RANDOM {
            original_random = *auxv.add(i * 2 + 1) as *const u8;
            break;
        }
    }
    if !original_random.is_null() {
        core::ptr::copy_nonoverlapping(original_random, random_bytes.as_mut_ptr(), 16);
    } else {
        for i in 0..16 {
            random_bytes[i] = (i as u8).wrapping_add(1);
        }
    }
    core::ptr::copy_nonoverlapping(random_bytes.as_ptr(), random_ptr as *mut u8, 16);

    let aux = aux_base as *mut u64;
    for i in 0..aux_entries {
        let tag = *auxv.add(i * 2);
        let original = *auxv.add(i * 2 + 1);
        let value = match tag {
            AT_PHDR => phdr_addr,
            AT_PHENT => PHDR_SIZE as u64,
            AT_PHNUM => phnum as u64,
            AT_ENTRY => entry,
            AT_RANDOM => random_ptr as u64,
            _ => original,
        };
        *aux.add(i * 2) = tag;
        *aux.add(i * 2 + 1) = value;
    }

    *(sp as *mut u64) = argc as u64;

    let auxv_sym = resolve_symbol(b"__auxv\0".as_ptr());
    if auxv_sym != 0 {
        core::ptr::write(auxv_sym as *mut *const usize, aux_base as *const usize);
    }

    jump_to_entry(entry, sp, owned_crt_lifecycle)
}

/// Transfer to the already relocated main image while retaining Linux's
/// original startup stack. Non-secure startup needs no copied argv/envp/auxv
/// because their kernel addresses continue to describe the same main mapping.
unsafe fn jump_to_entry(entry: u64, sp: usize, owned_crt_lifecycle: bool) -> ! {
    // The ELF dynamic-entry convention reserves x0 for the loader's process
    // finalizer. A recognized owned Scrt1 receives a private record containing
    // both that finalizer and the dependency callback; a conventional CRT
    // receives the musl-shaped direct finalizer function unchanged.
    let startup = if owned_crt_lifecycle {
        core::ptr::addr_of!(OWNED_CRT_STARTUP_HANDOFF) as usize
    } else {
        __ldso_process_fini as *const () as usize
    };
    core::arch::asm!(
        "mov sp, {sp}",
        "br {entry}",
        sp = in(reg) sp,
        in("x0") startup,
        entry = in(reg) entry,
        options(noreturn)
    );
}

// ============================================================
// Memory functions (required by no_std linker)
// ============================================================

#[no_mangle]
pub unsafe extern "C" fn memset(s: *mut c_void, c: i32, n: usize) -> *mut c_void {
    let s = s as *mut u8;
    let mut p = s;
    let mut i = 0;
    while i < n {
        unsafe {
            *p = c as u8;
        }
        p = unsafe { p.add(1) };
        i += 1;
    }
    s as *mut c_void
}

#[no_mangle]
pub unsafe extern "C" fn memcpy(dst: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    let dst = dst as *mut u8;
    let src = src as *const u8;
    let mut i = 0;
    while i < n {
        unsafe {
            *dst.add(i) = *src.add(i);
        }
        i += 1;
    }
    dst as *mut c_void
}

#[no_mangle]
pub unsafe extern "C" fn memmove(dst: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    let dst = dst as *mut u8;
    let src = src as *const u8;
    if (dst as usize) < (src as usize) {
        let mut i = 0;
        while i < n {
            unsafe {
                *dst.add(i) = *src.add(i);
            }
            i += 1;
        }
    } else {
        let mut i = n;
        while i > 0 {
            i -= 1;
            unsafe {
                *dst.add(i) = *src.add(i);
            }
        }
    }
    dst as *mut c_void
}
