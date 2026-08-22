#![no_std]
#![no_main]
#![feature(linkage)]
#![allow(dead_code, deref_nullptr)]

use core::ffi::{c_char, c_void};
use core::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};

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

const R_X86_64_64: u64 = 1;
const R_X86_64_COPY: u64 = 5;
const R_X86_64_GLOB_DAT: u64 = 6;
const R_X86_64_JUMP_SLOT: u64 = 7;
const R_X86_64_RELATIVE: u64 = 8;
const R_X86_64_DTPMOD64: u64 = 16;
const R_X86_64_DTPOFF64: u64 = 17;
const R_X86_64_TPOFF64: u64 = 18;

const R_AARCH64_NONE: u64 = 0;
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

const R_RISCV_RELATIVE: u64 = 3;
const R_RISCV_64: u64 = 2;
const R_RISCV_GLOB_DAT: u64 = 5;  // skipped, RISC-V uses R_RISCV_64=2 as GLOB_DAT
const R_RISCV_JUMP_SLOT: u64 = 5;
const R_RISCV_TLS_DTPMOD64: u64 = 7;
const R_RISCV_TLS_DTPREL64: u64 = 9;
const R_RISCV_TLS_TPREL64: u64 = 11;
const R_RISCV_TLSDESC: u64 = 772;
const R_RISCV_COPY: u64 = 4;

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

// ============================================================
// Loaded object tracking
// ============================================================

struct LoadedObject {
    base: u64,
    map_start: *mut u8,
    map_size: usize,
    symtab: *const u8,
    sym_count: usize,
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
    name: [u8; 256],
}

const EMPTY_OBJ: LoadedObject = LoadedObject {
    base: 0,
    map_start: core::ptr::null_mut(),
    map_size: 0,
    symtab: core::ptr::null(),
    sym_count: 0,
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
    name: [0; 256],
};

// Safety: only accessed from single-threaded _start -> run_main
static mut LOADED: [LoadedObject; MAX_LOADED] = [EMPTY_OBJ; MAX_LOADED];
static mut LOADED_COUNT: usize = 0;

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
static mut TLS_GENERATION: u64 = 1;
static mut TLS_OLD_TOTAL: usize = 0;
static mut TLS_OLD_MODULE_COUNT: usize = 0;
static TLS_LOCK: AtomicBool = AtomicBool::new(false);
// Runtime loader operations are serialized like musl's global loader lock.
// The lock is recursive for constructor callbacks, which may call dlopen or
// dlsym while the outer operation is still mutating the object graph.
static LOADER_LOCK: AtomicBool = AtomicBool::new(false);
static LOADER_OWNER: AtomicI64 = AtomicI64::new(0);
static LOADER_DEPTH: AtomicUsize = AtomicUsize::new(0);

const DLERROR_BUF_SIZE: usize = 128;

#[repr(C)]
struct DlErrorNode {
    tid: usize,
    thread_pointer: usize,
    set: AtomicBool,
    buf: [u8; DLERROR_BUF_SIZE],
    next: *mut DlErrorNode,
}

// Error nodes are allocated once for each observed (tid, thread-pointer)
// identity and are never shared between distinct live threads.  Including the
// thread pointer prevents a recycled Linux tid from exposing an exited
// thread's pending error before the new thread has performed another loader
// operation. Nodes are intentionally retained so no thread-exit hook or
// allocator is needed in the early loader.
static mut DLERROR_HEAD: *mut DlErrorNode = core::ptr::null_mut();
static DLERROR_LOCK: AtomicBool = AtomicBool::new(false);
static mut LD_LIBRARY_PATH: *const u8 = core::ptr::null();
static mut RUNPATH: *const u8 = core::ptr::null();
static mut RUNPATH_LEN: usize = 0;
static mut ORIGIN_DIR: [u8; 256] = [0; 256];
static mut ORIGIN_LEN: usize = 0;

// ============================================================
// _start: self-relocate ldso, then call run_main(sp)
// ============================================================

#[cfg(not(test))]
#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    ".global _start",
    ".type _start, @function",
    "_start:",
    "mov rdi, rsp",
    "mov rax, [rsp]",
    "lea rbx, [rsp + 8]",
    "lea rcx, [rbx + rax*8]",
    "add rcx, 8",
    "2:",
    "cmp qword ptr [rcx], 0",
    "je 3f",
    "add rcx, 8",
    "jmp 2b",
    "3:",
    "add rcx, 8",
    "xor rsi, rsi",
    "4:",
    "mov rax, [rcx]",
    "cmp rax, 0",
    "je 5f",
    "cmp rax, 7",
    "jne 6f",
    "mov rsi, [rcx + 8]",
    "6:",
    "add rcx, 16",
    "jmp 4b",
    "5:",
    "mov rax, [rsi + 32]",
    "movzx rcx, word ptr [rsi + 56]",
    "lea r8, [rsi + rax]",
    "xor r9, r9",
    "7:",
    "cmp r9, rcx",
    "jge 8f",
    "mov eax, [r8]",
    "cmp eax, 2",
    "je 9f",
    "add r8, 56",
    "inc r9",
    "jmp 7b",
    "9:",
    "mov r10, [r8 + 16]",
    "mov r11, [r8 + 40]",
    "add r10, rsi",
    "xor rax, rax",
    "xor rbx, rbx",
    "mov rcx, r10",
    "lea rdx, [r10 + r11]",
    "10:",
    "cmp rcx, rdx",
    "jge 11f",
    "mov r12, [rcx]",
    "mov r13, [rcx + 8]",
    "cmp r12, 0",
    "je 11f",
    "cmp r12, 7",
    "jne 12f",
    "lea rax, [rsi + r13]",
    "12:",
    "cmp r12, 8",
    "jne 13f",
    "mov rbx, r13",
    "13:",
    "add rcx, 16",
    "jmp 10b",
    "11:",
    "test rbx, rbx",
    "jz 8f",
    "test rax, rax",
    "jz 8f",
    "xor rcx, rcx",
    "14:",
    "cmp rcx, rbx",
    "jge 8f",
    "mov r12, [rax + rcx]",
    "mov r13, [rax + rcx + 8]",
    "mov r14, [rax + rcx + 16]",
    "and r13d, 0xffffffff",
    "cmp r13d, 8",
    "jne 15f",
    "add r12, rsi",
    "add r14, rsi",
    "mov [r12], r14",
    "15:",
    "add rcx, 24",
    "jmp 14b",
    "8:",
    ".hidden {run_main}",
    "call {run_main}",
    "ud2",
    run_main = sym run_main,
);

// aarch64 _start: self-relocate ldso, then call run_main(sp, ldso_base)
#[cfg(not(test))]
#[cfg(target_arch = "aarch64")]
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

// riscv64 _start: self-relocate ldso, then call run_main(sp, ldso_base)
#[cfg(not(test))]
#[cfg(target_arch = "riscv64")]
core::arch::global_asm!(
    ".global _start",
    ".type _start, @function",
    "_start:",
    // Save sp into s0 (frame pointer, callee-saved)
    "mv s0, sp",
    // Walk stack: argc, argv[], NULL, envp[], NULL, auxv[]
    "ld a0, 0(sp)",              // argc
    "add a1, sp, 8",            // &argv[0]
    "slli a2, a0, 3",
    "add a2, a1, a2",           // skip argv[]
    "addi a2, a2, 8",           // skip NULL after argv -> &envp[0]
    "2:",
    "ld a3, 0(a2)",
    "beqz a3, 3f",
    "addi a2, a2, 8",
    "j 2b",
    "3:",
    "addi a2, a2, 8",           // &auxv[0]
    "li s1, 0",                 // ldso_base = 0
    "4:",
    "ld a3, 0(a2)",             // auxv tag
    "beqz a3, 5f",              // AT_NULL -> done
    "li a4, 7",                 // AT_BASE
    "bne a3, a4, 6f",
    "ld s1, 8(a2)",             // ldso_base
    "6:",
    "addi a2, a2, 16",
    "j 4b",
    "5:",
    // s1 = ldso_base. Walk ldso's ELF phdrs to find PT_DYNAMIC.
    "ld a0, 32(s1)",            // e_phoff
    "lhu a1, 56(s1)",           // e_phnum
    "add a2, s1, a0",           // phdr table
    "li a3, 0",                 // i
    "7:",
    "bgeu a3, a1, 8f",
    "lw a4, 0(a2)",             // p_type
    "li a5, 2",                 // PT_DYNAMIC
    "beq a4, a5, 9f",
    "addi a2, a2, 56",          // next phdr (PHDR_SIZE=56)
    "addi a3, a3, 1",
    "j 7b",
    "9:",
    // Found PT_DYNAMIC. Read DT_RELA and DT_RELASZ from dynamic section.
    "ld a4, 16(a2)",            // p_vaddr
    "ld a5, 40(a2)",            // p_memsz
    "add a4, a4, s1",           // dyn_addr = base + p_vaddr
    "add a5, a4, a5",           // dyn_end
    "li a6, 0",                 // rela = 0
    "li a7, 0",                 // relasz = 0
    "10:",
    "bgeu a4, a5, 11f",
    "ld t0, 0(a4)",             // d_tag
    "ld t1, 8(a4)",             // d_val
    "beqz t0, 11f",             // DT_NULL
    "li t2, 7",                 // DT_RELA
    "bne t0, t2, 12f",
    "add a6, s1, t1",           // rela = base + d_val
    "12:",
    "li t2, 8",                 // DT_RELASZ
    "bne t0, t2, 13f",
    "mv a7, t1",                // relasz = d_val
    "13:",
    "addi a4, a4, 16",
    "j 10b",
    "11:",
    // Apply R_RISCV_RELATIVE (type 3) relocations.
    "beqz a7, 8f",
    "beqz a6, 8f",
    "add t3, a6, a7",           // table_end
    "14:",
    "bgeu a6, t3, 8f",
    "ld t4, 0(a6)",             // r_offset
    "ld t5, 8(a6)",             // r_info
    "ld t6, 16(a6)",            // r_addend
    "li t0, 3",                 // R_RISCV_RELATIVE
    "slli t1, t5, 32",
    "srli t1, t1, 32", // r_type = r_info & 0xffffffff
    "bne t1, t0, 15f",
    "add t4, t4, s1",           // slot = base + r_offset
    "add t6, t6, s1",           // val = base + r_addend
    "sd t6, 0(t4)",
    "15:",
    "addi a6, a6, 24",
    "j 14b",
    "8:",
    ".hidden {run_main}",
    "mv a0, s0",               // sp
    "mv a1, s1",               // ldso_base
    "call {run_main}",
    "unimp",
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
#[cfg(all(target_arch = "aarch64", not(test)))]
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

unsafe fn sym_count_from_gnu_hash(gh: usize) -> usize {
    let nb = u32::from_le_bytes(core::ptr::read_unaligned(gh as *const [u8; 4])) as usize;
    let symoffset = u32::from_le_bytes(core::ptr::read_unaligned((gh + 4) as *const [u8; 4])) as usize;
    let bloom_size = u32::from_le_bytes(core::ptr::read_unaligned((gh + 8) as *const [u8; 4])) as usize;
    let buckets = gh + 16 + bloom_size * 8;
    let chain = buckets + nb * 4;
    let mut max_idx = 0usize;
    let mut has_any = false;
    for i in 0..nb {
        let symidx = u32::from_le_bytes(core::ptr::read_unaligned((buckets + i * 4) as *const [u8; 4])) as usize;
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
            let entry = u32::from_le_bytes(core::ptr::read_unaligned((chain + cidx * 4) as *const [u8; 4]));
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

#[no_mangle]
pub unsafe extern "C" fn strlen(s: *const c_char) -> usize {
    str_len(s as *const u8)
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

trait Syscalls {
    unsafe fn syscall0(n: i64) -> i64;
    unsafe fn syscall1(n: i64, a1: i64) -> i64;
    unsafe fn syscall2(n: i64, a1: i64, a2: i64) -> i64;
    unsafe fn syscall3(n: i64, a1: i64, a2: i64, a3: i64) -> i64;
    unsafe fn syscall4(n: i64, a1: i64, a2: i64, a3: i64, a4: i64) -> i64;
    unsafe fn syscall5(n: i64, a1: i64, a2: i64, a3: i64, a4: i64, a5: i64) -> i64;
    unsafe fn syscall6(n: i64, a1: i64, a2: i64, a3: i64, a4: i64, a5: i64, a6: i64) -> i64;
    unsafe fn syscall_noreturn1(n: i64, a1: i64) -> !;
}

struct X86_64;
struct Aarch64;
struct Riscv64;

#[cfg(target_arch = "x86_64")]
impl Syscalls for X86_64 {
    #[inline(always)]
    unsafe fn syscall0(n: i64) -> i64 {
        let result: i64;
        core::arch::asm!(
            "syscall",
            inlateout("rax") n => result,
            lateout("rcx") _,
            lateout("r11") _,
        );
        result
    }
    #[inline(always)]
    unsafe fn syscall1(n: i64, a1: i64) -> i64 {
        let result: i64;
        core::arch::asm!(
            "syscall",
            inlateout("rax") n => result,
            in("rdi") a1,
            lateout("rcx") _,
            lateout("r11") _,
        );
        result
    }
    #[inline(always)]
    unsafe fn syscall2(n: i64, a1: i64, a2: i64) -> i64 {
        let result: i64;
        core::arch::asm!(
            "syscall",
            inlateout("rax") n => result,
            in("rdi") a1,
            in("rsi") a2,
            lateout("rcx") _,
            lateout("r11") _,
        );
        result
    }
    #[inline(always)]
    unsafe fn syscall3(n: i64, a1: i64, a2: i64, a3: i64) -> i64 {
        let result: i64;
        core::arch::asm!(
            "syscall",
            inlateout("rax") n => result,
            in("rdi") a1,
            in("rsi") a2,
            in("rdx") a3,
            lateout("rcx") _,
            lateout("r11") _,
        );
        result
    }
    #[inline(always)]
    unsafe fn syscall4(n: i64, a1: i64, a2: i64, a3: i64, a4: i64) -> i64 {
        let result: i64;
        core::arch::asm!(
            "syscall",
            inlateout("rax") n => result,
            in("rdi") a1,
            in("rsi") a2,
            in("rdx") a3,
            in("r10") a4,
            lateout("rcx") _,
            lateout("r11") _,
        );
        result
    }
    #[inline(always)]
    unsafe fn syscall5(n: i64, a1: i64, a2: i64, a3: i64, a4: i64, a5: i64) -> i64 {
        let result: i64;
        core::arch::asm!(
            "syscall",
            inlateout("rax") n => result,
            in("rdi") a1,
            in("rsi") a2,
            in("rdx") a3,
            in("r10") a4,
            in("r8") a5,
            lateout("rcx") _,
            lateout("r11") _,
        );
        result
    }
    #[inline(always)]
    unsafe fn syscall6(n: i64, a1: i64, a2: i64, a3: i64, a4: i64, a5: i64, a6: i64) -> i64 {
        let result: i64;
        core::arch::asm!(
            "syscall",
            inlateout("rax") n => result,
            in("rdi") a1,
            in("rsi") a2,
            in("rdx") a3,
            in("r10") a4,
            in("r8") a5,
            in("r9") a6,
            lateout("rcx") _,
            lateout("r11") _,
        );
        result
    }
    #[inline(always)]
    unsafe fn syscall_noreturn1(n: i64, a1: i64) -> ! {
        core::arch::asm!(
            "syscall",
            in("rax") n,
            in("rdi") a1,
            options(noreturn)
        );
    }
}

#[cfg(target_arch = "aarch64")]
impl Syscalls for Aarch64 {
    #[inline(always)]
    unsafe fn syscall0(n: i64) -> i64 {
        let result: i64;
        core::arch::asm!(
            "svc #0",
            inlateout("x8") n => _,
            lateout("x0") result,
            options(nostack),
        );
        result
    }
    #[inline(always)]
    unsafe fn syscall1(n: i64, a1: i64) -> i64 {
        let result: i64;
        core::arch::asm!(
            "svc #0",
            inlateout("x8") n => _,
            inlateout("x0") a1 => result,
            options(nostack),
        );
        result
    }
    #[inline(always)]
    unsafe fn syscall2(n: i64, a1: i64, a2: i64) -> i64 {
        let result: i64;
        core::arch::asm!(
            "svc #0",
            inlateout("x8") n => _,
            inlateout("x0") a1 => result,
            inlateout("x1") a2 => _,
            options(nostack),
        );
        result
    }
    #[inline(always)]
    unsafe fn syscall3(n: i64, a1: i64, a2: i64, a3: i64) -> i64 {
        let result: i64;
        core::arch::asm!(
            "svc #0",
            inlateout("x8") n => _,
            inlateout("x0") a1 => result,
            inlateout("x1") a2 => _,
            inlateout("x2") a3 => _,
            options(nostack),
        );
        result
    }
    #[inline(always)]
    unsafe fn syscall4(n: i64, a1: i64, a2: i64, a3: i64, a4: i64) -> i64 {
        let result: i64;
        core::arch::asm!(
            "svc #0",
            inlateout("x8") n => _,
            inlateout("x0") a1 => result,
            inlateout("x1") a2 => _,
            inlateout("x2") a3 => _,
            inlateout("x3") a4 => _,
            options(nostack),
        );
        result
    }
    #[inline(always)]
    unsafe fn syscall5(n: i64, a1: i64, a2: i64, a3: i64, a4: i64, a5: i64) -> i64 {
        let result: i64;
        core::arch::asm!(
            "svc #0",
            inlateout("x8") n => _,
            inlateout("x0") a1 => result,
            inlateout("x1") a2 => _,
            inlateout("x2") a3 => _,
            inlateout("x3") a4 => _,
            inlateout("x4") a5 => _,
            options(nostack),
        );
        result
    }
    #[inline(always)]
    unsafe fn syscall6(n: i64, a1: i64, a2: i64, a3: i64, a4: i64, a5: i64, a6: i64) -> i64 {
        let result: i64;
        core::arch::asm!(
            "svc #0",
            inlateout("x8") n => _,
            inlateout("x0") a1 => result,
            inlateout("x1") a2 => _,
            inlateout("x2") a3 => _,
            inlateout("x3") a4 => _,
            inlateout("x4") a5 => _,
            inlateout("x5") a6 => _,
            options(nostack),
        );
        result
    }
    #[inline(always)]
    unsafe fn syscall_noreturn1(n: i64, a1: i64) -> ! {
        core::arch::asm!(
            "svc #0",
            in("x8") n,
            in("x0") a1,
            options(noreturn, nostack),
        );
    }
}

#[cfg(target_arch = "riscv64")]
impl Syscalls for Riscv64 {
    #[inline(always)]
    unsafe fn syscall0(n: i64) -> i64 {
        let result: i64;
        core::arch::asm!(
            "ecall",
            inlateout("a7") n => _,
            lateout("a0") result,
            options(nostack),
        );
        result
    }
    #[inline(always)]
    unsafe fn syscall1(n: i64, a1: i64) -> i64 {
        let result: i64;
        core::arch::asm!(
            "ecall",
            inlateout("a7") n => _,
            inlateout("a0") a1 => result,
            options(nostack),
        );
        result
    }
    #[inline(always)]
    unsafe fn syscall2(n: i64, a1: i64, a2: i64) -> i64 {
        let result: i64;
        core::arch::asm!(
            "ecall",
            inlateout("a7") n => _,
            inlateout("a0") a1 => result,
            inlateout("a1") a2 => _,
            options(nostack),
        );
        result
    }
    #[inline(always)]
    unsafe fn syscall3(n: i64, a1: i64, a2: i64, a3: i64) -> i64 {
        let result: i64;
        core::arch::asm!(
            "ecall",
            inlateout("a7") n => _,
            inlateout("a0") a1 => result,
            inlateout("a1") a2 => _,
            inlateout("a2") a3 => _,
            options(nostack),
        );
        result
    }
    #[inline(always)]
    unsafe fn syscall4(n: i64, a1: i64, a2: i64, a3: i64, a4: i64) -> i64 {
        let result: i64;
        core::arch::asm!(
            "ecall",
            inlateout("a7") n => _,
            inlateout("a0") a1 => result,
            inlateout("a1") a2 => _,
            inlateout("a2") a3 => _,
            inlateout("a3") a4 => _,
            options(nostack),
        );
        result
    }
    #[inline(always)]
    unsafe fn syscall5(n: i64, a1: i64, a2: i64, a3: i64, a4: i64, a5: i64) -> i64 {
        let result: i64;
        core::arch::asm!(
            "ecall",
            inlateout("a7") n => _,
            inlateout("a0") a1 => result,
            inlateout("a1") a2 => _,
            inlateout("a2") a3 => _,
            inlateout("a3") a4 => _,
            inlateout("a4") a5 => _,
            options(nostack),
        );
        result
    }
    #[inline(always)]
    unsafe fn syscall6(n: i64, a1: i64, a2: i64, a3: i64, a4: i64, a5: i64, a6: i64) -> i64 {
        let result: i64;
        core::arch::asm!(
            "ecall",
            inlateout("a7") n => _,
            inlateout("a0") a1 => result,
            inlateout("a1") a2 => _,
            inlateout("a2") a3 => _,
            inlateout("a3") a4 => _,
            inlateout("a4") a5 => _,
            inlateout("a5") a6 => _,
            options(nostack),
        );
        result
    }
    #[inline(always)]
    unsafe fn syscall_noreturn1(n: i64, a1: i64) -> ! {
        core::arch::asm!(
            "ecall",
            in("a7") n,
            in("a0") a1,
            options(noreturn, nostack),
        );
    }
}

#[cfg(target_arch = "x86_64")]
type Arch = X86_64;
#[cfg(target_arch = "aarch64")]
type Arch = Aarch64;
#[cfg(target_arch = "riscv64")]
type Arch = Riscv64;



// Architecture-specific syscall numbers
#[cfg(target_arch = "x86_64")]
mod sysnr {
    pub const SYS_READ: i64 = 0;
    pub const SYS_WRITE: i64 = 1;
    pub const SYS_OPENAT: i64 = 257;
    pub const SYS_CLOSE: i64 = 3;
    pub const SYS_FSTAT: i64 = 5;
    pub const SYS_LSEEK: i64 = 8;
    pub const SYS_MMAP: i64 = 9;
    pub const SYS_MPROTECT: i64 = 10;
    pub const SYS_MUNMAP: i64 = 11;
    pub const SYS_READLINKAT: i64 = 267;
    pub const SYS_GETTID: i64 = 186;
    pub const SYS_ARCH_PRCTL: i64 = 158;
    pub const SYS_EXIT: i64 = 60;
}
#[cfg(target_arch = "aarch64")]
mod sysnr {
    pub const SYS_READ: i64 = 63;
    pub const SYS_WRITE: i64 = 64;
    pub const SYS_OPENAT: i64 = 56;
    pub const SYS_CLOSE: i64 = 57;
    pub const SYS_FSTAT: i64 = 80;
    pub const SYS_LSEEK: i64 = 62;
    pub const SYS_MMAP: i64 = 222;
    pub const SYS_MPROTECT: i64 = 226;
    pub const SYS_MUNMAP: i64 = 215;
    pub const SYS_READLINKAT: i64 = 78;
    pub const SYS_GETTID: i64 = 178;
    pub const SYS_EXIT: i64 = 93;
}
#[cfg(target_arch = "riscv64")]
mod sysnr {
    pub const SYS_READ: i64 = 63;
    pub const SYS_WRITE: i64 = 64;
    pub const SYS_OPENAT: i64 = 56;
    pub const SYS_CLOSE: i64 = 57;
    pub const SYS_FSTAT: i64 = 80;
    pub const SYS_LSEEK: i64 = 62;
    pub const SYS_MMAP: i64 = 222;
    pub const SYS_MUNMAP: i64 = 215;
    pub const SYS_READLINKAT: i64 = 78;
    pub const SYS_GETTID: i64 = 178;
    pub const SYS_EXIT: i64 = 93;
}
pub use sysnr::*;

const AT_FDCWD: i64 = -100;

// ============================================================
// Syscall wrappers (raw, no_std)
// ============================================================

fn sys_open(path: *const u8) -> i64 {
    unsafe { <Arch as Syscalls>::syscall3(SYS_OPENAT, AT_FDCWD, path as i64, 0) }
}

fn sys_readlink(path: *const u8, buf: *mut u8, bufsz: usize) -> i64 {
    unsafe { <Arch as Syscalls>::syscall4(SYS_READLINKAT, AT_FDCWD, path as i64, buf as i64, bufsz as i64) }
}

fn sys_read(fd: i64, buf: *mut u8, count: usize) -> i64 {
    unsafe { <Arch as Syscalls>::syscall3(SYS_READ, fd, buf as i64, count as i64) }
}

fn sys_fstat(fd: i64, buf: *mut u8) -> i64 {
    unsafe { <Arch as Syscalls>::syscall2(SYS_FSTAT, fd, buf as i64) }
}

fn sys_write(fd: i64, buf: *const u8, count: usize) -> i64 {
    unsafe { <Arch as Syscalls>::syscall3(SYS_WRITE, fd, buf as i64, count as i64) }
}

fn sys_close(fd: i64) {
    unsafe { <Arch as Syscalls>::syscall1(SYS_CLOSE, fd); }
}

#[inline(always)]
fn current_tid() -> i64 {
    unsafe { <Arch as Syscalls>::syscall0(SYS_GETTID) }
}

unsafe fn loader_lock() {
    let tid = current_tid();
    if LOADER_OWNER.load(Ordering::Acquire) == tid {
        LOADER_DEPTH.fetch_add(1, Ordering::Relaxed);
        return;
    }
    while LOADER_LOCK.swap(true, Ordering::Acquire) {}
    LOADER_OWNER.store(tid, Ordering::Relaxed);
    LOADER_DEPTH.store(1, Ordering::Release);
}

unsafe fn loader_unlock() {
    let tid = current_tid();
    if LOADER_OWNER.load(Ordering::Acquire) != tid {
        return;
    }
    if LOADER_DEPTH.fetch_sub(1, Ordering::Release) == 1 {
        LOADER_OWNER.store(0, Ordering::Relaxed);
        LOADER_LOCK.store(false, Ordering::Release);
    }
}

unsafe fn dlerror_lock() {
    while DLERROR_LOCK.swap(true, Ordering::Acquire) {}
}

unsafe fn dlerror_unlock() {
    DLERROR_LOCK.store(false, Ordering::Release);
}

/// Find or allocate the caller's error node.  The caller holds DLERROR_LOCK;
/// allocation failure is explicit and returns null rather than borrowing a
/// different thread's storage.
unsafe fn dlerror_node_locked(tid: usize, thread_pointer: usize) -> *mut DlErrorNode {
    let mut node = DLERROR_HEAD;
    while !node.is_null() {
        if (*node).tid == tid && (*node).thread_pointer == thread_pointer {
            return node;
        }
        node = (*node).next;
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
    node = mapping as *mut DlErrorNode;
    core::ptr::write(
        node,
        DlErrorNode {
            tid,
            thread_pointer,
            set: AtomicBool::new(false),
            buf: [0; DLERROR_BUF_SIZE],
            next: DLERROR_HEAD,
        },
    );
    DLERROR_HEAD = node;
    node
}

fn sys_mmap(
    addr: *mut u8,
    length: usize,
    prot: i32,
    flags: i32,
    fd: i32,
    offset: i64,
) -> *mut u8 {
    let result = unsafe { <Arch as Syscalls>::syscall6(SYS_MMAP, addr as i64, length as i64, prot as i64, flags as i64, fd as i64, offset) };
    if result < 0 && result > -4096 {
        return MAP_FAILED as *mut u8;
    }
    result as *mut u8
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn sys_mprotect(addr: *mut u8, length: usize, prot: i32) -> i64 {
    unsafe { <Arch as Syscalls>::syscall3(SYS_MPROTECT, addr as i64, length as i64, prot as i64) }
}

fn sys_exit(code: i32) -> ! {
    unsafe { <Arch as Syscalls>::syscall_noreturn1(SYS_EXIT, code as i64) }
}

fn sys_lseek(fd: i64, offset: i64) -> i64 {
    unsafe { <Arch as Syscalls>::syscall3(SYS_LSEEK, fd, offset, 0) }
}

#[cfg(target_arch = "x86_64")]
fn sys_arch_prctl(code: i64, addr: u64) -> i64 {
    unsafe { <Arch as Syscalls>::syscall2(SYS_ARCH_PRCTL, code, addr as i64) }
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn read_tp() -> usize {
    let tp: usize;
    core::arch::asm!("mov {}, fs:[0]", out(reg) tp);
    tp
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn read_tp() -> usize {
    let tp: usize;
    core::arch::asm!("mrs {}, tpidr_el0", out(reg) tp);
    tp
}

#[cfg(target_arch = "riscv64")]
#[inline(always)]
unsafe fn read_tp() -> usize {
    let tp: usize;
    core::arch::asm!("mv {}, tp", out(reg) tp);
    tp
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn write_tp(addr: usize) {
    sys_arch_prctl(0x1002, addr as u64);
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn write_tp(addr: usize) {
    core::arch::asm!("msr tpidr_el0, {}", in(reg) addr);
}

#[cfg(target_arch = "riscv64")]
#[inline(always)]
unsafe fn write_tp(addr: usize) {
    core::arch::asm!("mv tp, {}", in(reg) addr);
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
        buf[2 + i] = if nibble < 10 { b'0' + nibble } else { b'a' + nibble - 10 };
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

unsafe fn find_library_fd(
    lib_name: *const u8,
    lib_name_len: usize,
    ld_path: Option<*const u8>,
    parent: Option<usize>,
) -> i64 {
    if lib_name_len == 0 {
        return -1;
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
            return fd;
        }
    }

    if let Some(ldp) = ld_path {
        let ldp_len = str_len(ldp);
        let mut start = 0usize;
        while start < ldp_len {
            let mut end = start;
            while end < ldp_len && *ldp.add(end) != b':' {
                end += 1;
            }
            if end > start {
                let fd = try_open(&mut path_buf, ldp.add(start), end - start, lib_name, lib_name_len);
                if fd >= 0 {
                    return fd;
                }
            }
            if end >= ldp_len {
                break;
            }
            start = end + 1;
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
                if slash == 0 { 1 } else { slash }
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
                    return fd;
                }
            }
            if end >= rp_len {
                break;
            }
            start = end + 1;
        }
    }

    let defaults: &[(&[u8], usize)] = &[
        (b"/lib", 4),
        (b"/usr/lib", 8),
        (b"/usr/local/lib", 14),
    ];
    for &(dir_bytes, dir_len) in defaults {
        let fd = try_open(&mut path_buf, dir_bytes.as_ptr(), dir_len, lib_name, lib_name_len);
        if fd >= 0 {
            return fd;
        }
    }

    -1
}

// ============================================================
// DSO loading
// ============================================================

#[derive(Copy, Clone)]
struct FileIdentity {
    dev: u64,
    ino: u64,
}

/// Read the kernel file identity for an open DSO.  Symlink aliases resolve to
/// the same `(st_dev, st_ino)` pair, while distinct files remain distinct even
/// when their DT_NEEDED names happen to match.
fn file_identity(fd: i64) -> Option<FileIdentity> {
    // The first two fields of Linux's x86_64, AArch64, and RISC-V stat
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
    unsafe { <Arch as Syscalls>::syscall2(SYS_MUNMAP, addr as i64, length as i64) }
}

unsafe fn load_dso_from_fd(fd: i64, _desired_base: u64) -> Option<u64> {
    // The loaded-object array is the authoritative dependency graph.  Refuse
    // a new mapping before touching address space when its bounded capacity is
    // exhausted; returning a base without registering the object would leave
    // subsequent relocation and TLS passes with an incoherent graph.
    if LOADED_COUNT >= MAX_LOADED {
        return None;
    }
    let mut mapped: [(*mut u8, usize); 8] = [(core::ptr::null_mut(), 0); 8];
    let mut mapped_count = 0usize;
    macro_rules! fail_mapping {
        () => {{
            while mapped_count > 0 {
                mapped_count -= 1;
                let (addr, len) = mapped[mapped_count];
                if !addr.is_null() && len != 0 {
                    sys_munmap(addr, len);
                }
            }
            return None;
        }};
    }
    let identity = file_identity(fd);
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

    let mut segs: [LoadSeg; 8] = [LoadSeg { p_offset: 0, p_vaddr: 0, p_filesz: 0, p_memsz: 0, p_flags: 0 }; 8];
    let mut seg_count: usize = 0;
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
            tls_vaddr = u64::from_le_bytes(core::ptr::read_unaligned(ph.add(PH_VADDR) as *const [u8; 8]));
            tls_filesz = u64::from_le_bytes(core::ptr::read_unaligned(ph.add(PH_FILESZ) as *const [u8; 8]));
            tls_memsz = u64::from_le_bytes(core::ptr::read_unaligned(ph.add(PH_MEMSZ) as *const [u8; 8]));
            tls_align = u64::from_le_bytes(core::ptr::read_unaligned(ph.add(PH_ALIGN) as *const [u8; 8]));
            continue;
        }
        if p_type != PT_LOAD {
            continue;
        }
        if seg_count >= segs.len() {
            return None;
        }
        let p_flags = u32::from_le_bytes(core::ptr::read_unaligned(ph.add(PH_FLAGS) as *const [u8; 4]));
        let p_offset = u64::from_le_bytes(core::ptr::read_unaligned(ph.add(PH_OFFSET) as *const [u8; 8]));
        let p_vaddr = u64::from_le_bytes(core::ptr::read_unaligned(ph.add(PH_VADDR) as *const [u8; 8]));
        let p_filesz = u64::from_le_bytes(core::ptr::read_unaligned(ph.add(PH_FILESZ) as *const [u8; 8]));
        let p_memsz = u64::from_le_bytes(core::ptr::read_unaligned(ph.add(PH_MEMSZ) as *const [u8; 8]));
        segs[seg_count] = LoadSeg { p_offset, p_vaddr, p_filesz, p_memsz, p_flags };
        seg_count += 1;
        if p_vaddr < min_vaddr { min_vaddr = p_vaddr; }
        let end = p_vaddr + p_memsz;
        if end > max_vaddr_end { max_vaddr_end = end; }
    }

    if seg_count == 0 || min_vaddr == u64::MAX {
        return None;
    }

    const PAGE: u64 = 4096;
    let image_start = min_vaddr & !(PAGE - 1);
    let image_end = (max_vaddr_end + PAGE - 1) & !(PAGE - 1);
    let total_size = (image_end - image_start) as usize;

    // Ask the kernel for an unhinted temporary reservation. Releasing that
    // exact span before the MAP_FIXED segment overlays preserves the kernel's
    // per-process ASLR choice while still giving the ELF image one coherent
    // load bias. A fixed synthetic base made every process expose identical
    // dladdr addresses, which is neither musl-compatible nor safe.
    let reservation = sys_mmap(
        core::ptr::null_mut(),
        total_size,
        PROT_NONE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    if reservation as usize == MAP_FAILED {
        return None;
    }
    let actual_base = (reservation as u64).wrapping_sub(image_start);
    sys_munmap(reservation, total_size);

    let tls_image = (actual_base + tls_vaddr) as *const u8;

    for i in 0..seg_count {
        let seg = segs[i];
        let adj = seg.p_vaddr & (PAGE - 1);
        let map_addr = actual_base + seg.p_vaddr - adj;
        let map_off = seg.p_offset - adj;
        let map_len = ((seg.p_memsz + adj + PAGE - 1) & !(PAGE - 1)) as usize;
        let prot = prot_from_flags(seg.p_flags);

        // Map the whole segment anonymously first so the tail (bss) is backed
        // by zeroed anonymous pages, then overlay the file-backed portion.
        let ptr = sys_mmap(
            map_addr as *mut u8,
            map_len,
            prot,
            MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS,
            -1,
            0,
        );
        if ptr as usize == MAP_FAILED {
            fail_mapping!();
        }
        if mapped_count < mapped.len() {
            mapped[mapped_count] = (map_addr as *mut u8, map_len);
            mapped_count += 1;
        }

        let file_map_len = ((seg.p_filesz + adj + PAGE - 1) & !(PAGE - 1)) as usize;
        if file_map_len > 0 {
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
            dyn_vaddr = u64::from_le_bytes(core::ptr::read_unaligned(ph.add(PH_VADDR) as *const [u8; 8]));
            dyn_memsz = u64::from_le_bytes(core::ptr::read_unaligned(ph.add(PH_MEMSZ) as *const [u8; 8]));
        } else if p_type == PT_GNU_RELRO {
            relro_vaddr = u64::from_le_bytes(core::ptr::read_unaligned(ph.add(PH_VADDR) as *const [u8; 8]));
            relro_memsz = u64::from_le_bytes(core::ptr::read_unaligned(ph.add(PH_MEMSZ) as *const [u8; 8]));
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
            DT_INIT => { dt_init = d_val; dt_init_present = true; }
            DT_INIT_ARRAY => { dt_init_array = d_val; dt_init_array_present = true; }
            DT_INIT_ARRAYSZ => dt_init_array_sz = d_val,
            DT_FINI => { dt_fini = d_val; dt_fini_present = true; }
            DT_FINI_ARRAY => { dt_fini_array = d_val; dt_fini_array_present = true; }
            DT_FINI_ARRAYSZ => dt_fini_array_sz = d_val,
            DT_RUNPATH => { dt_runpath_off = d_val; dt_runpath_present = true; }
            DT_RPATH => { dt_rpath_off = d_val; dt_rpath_present = true; }
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

    LOADED[LOADED_COUNT] = LoadedObject {
        base: actual_base,
        map_start: actual_base.wrapping_add(image_start) as *mut u8,
        map_size: total_size,
        symtab: symtab_ptr,
        sym_count,
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
    let fd = find_library_fd(name, name_len, ld_path, parent);
    if fd < 0 {
        return None;
    }
    if let Some(identity) = file_identity(fd) {
        if let Some(idx) = loaded_object_by_identity(identity) {
            sys_close(fd);
            return Some(idx);
        }
    }
    let desired_base = DSO_BASE_START + (LOADED_COUNT as u64) * DSO_BASE_STRIDE;
    if load_dso_from_fd(fd, desired_base).is_none() {
        sys_close(fd);
        return None;
    }
    sys_close(fd);
    let idx = LOADED_COUNT - 1;
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
            let Some(child) = load_named_with_dependencies_from_parent(name, name_len, ld_path, Some(idx)) else {
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
    let st_name = u32::from_le_bytes(core::ptr::read_unaligned(sym_entry as *const [u8; 4])) as usize;
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
        #[cfg(all(not(test), target_arch = "aarch64"))]
        return (__ldso_dlstart as *const () as usize as u64, 0);
        #[cfg(not(all(not(test), target_arch = "aarch64")))]
        return (0, 0);
    }
    if str_eq(name, name_len, b"__tls_get_addr\0".as_ptr()) {
        // Prefer libc's public ABI shim once it is loaded.  This makes normal
        // GD-model relocations exercise the same registration bridge as a
        // direct libc caller.  The loader's implementation remains the
        // fallback for startup configurations that do not provide libc's
        // exported symbol (and is deliberately skipped here to avoid picking
        // the ldso self-image before libc).
        let internal = __tls_get_addr as *const () as usize;
        for i in 0..LOADED_COUNT {
            let candidate = lookup_symbol_in_object(i, name, name_len);
            if candidate != 0 && candidate as usize != internal {
                return (candidate, 0);
            }
        }
        return ((__tls_get_addr as *const () as usize) as u64, 0);
    }
    if str_eq(name, name_len, b"__rc_create_thread_tls\0".as_ptr()) {
        return ((__rc_create_thread_tls as *const () as usize) as u64, 0);
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
        if obj.symtab.is_null() || obj.strtab.is_null() {
            continue;
        }
        for j in 0..obj.sym_count {
            let sym_entry = obj.symtab.add(j * SYMTAB_ENT_SIZE);
            let st_name_off =
                u32::from_le_bytes(core::ptr::read_unaligned(sym_entry as *const [u8; 4])) as usize;
            let st_info = *sym_entry.add(4);
            if st_info >> 4 == 0 {
                continue;
            }
            let st_value = u64::from_le_bytes(core::ptr::read_unaligned(
                sym_entry.add(8) as *const [u8; 8],
            ));
            if st_value == 0 {
                continue;
            }
            if st_name_off >= obj.strsz {
                continue;
            }
            let sym_name = obj.strtab.add(st_name_off);
            if str_eq(name, name_len, sym_name) {
                let st_size = u64::from_le_bytes(core::ptr::read_unaligned(
                    sym_entry.add(16) as *const [u8; 8],
                ));
                return (obj.base + st_value, st_size as usize);
            }
        }
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
    for i in 0..LOADED_COUNT {
        let o = &LOADED[i];
        if o.symtab.is_null() || o.strtab.is_null() {
            continue;
        }
        for j in 0..o.sym_count {
            let se = o.symtab.add(j * SYMTAB_ENT_SIZE);
            let s_name =
                u32::from_le_bytes(core::ptr::read_unaligned(se as *const [u8; 4])) as usize;
            let s_value = u64::from_le_bytes(core::ptr::read_unaligned(
                se.add(8) as *const [u8; 8],
            ));
            if s_value == 0 {
                continue;
            }
            if s_name >= o.strsz {
                continue;
            }
            let sym_name = o.strtab.add(s_name);
            if str_eq(name, name_len, sym_name) {
                return i;
            }
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
    #[cfg(target_arch = "x86_64")]
    { 0 }
    #[cfg(target_arch = "aarch64")]
    { TLS_TP_OFFSET }
    #[cfg(target_arch = "riscv64")]
    { TCB_SIZE }
}

unsafe fn tls_tcb_offset_from_block() -> usize {
    #[cfg(target_arch = "x86_64")]
    { TLS_TOTAL_SIZE }
    #[cfg(target_arch = "aarch64")]
    { 0 }
    #[cfg(target_arch = "riscv64")]
    { 0 }
}

unsafe fn tls_tp_offset_from_block() -> usize {
    #[cfg(target_arch = "x86_64")]
    { TLS_TOTAL_SIZE }
    #[cfg(target_arch = "aarch64")]
    { TLS_TP_OFFSET }
    #[cfg(target_arch = "riscv64")]
    { TCB_SIZE }
}

/// Read the TP offset recorded in one allocation's TCB. AArch64 can raise
/// this offset when a late TLS module has a stronger alignment than the
/// initial image, so consulting the process-global value would mislocate an
/// older thread's TCB.
unsafe fn thread_tp_offset(fs_base: usize) -> usize {
    #[cfg(target_arch = "x86_64")]
    {
        let _ = fs_base;
        TLS_TOTAL_SIZE
    }
    #[cfg(target_arch = "aarch64")]
    {
        let recorded = core::ptr::read_unaligned((fs_base as *const usize).add(1));
        if recorded >= TCB_SIZE { recorded } else { TLS_TP_OFFSET }
    }
    #[cfg(target_arch = "riscv64")]
    {
        let _ = fs_base;
        TCB_SIZE
    }
}

unsafe fn tcb_for_thread(fs_base: usize) -> *mut u8 {
    #[cfg(target_arch = "x86_64")]
    { fs_base as *mut u8 }
    #[cfg(target_arch = "aarch64")]
    { (fs_base.wrapping_sub(thread_tp_offset(fs_base))) as *mut u8 }
    #[cfg(target_arch = "riscv64")]
    { fs_base.wrapping_sub(TCB_SIZE) as *mut u8 }
}

/// Return the TP-relative distance from a thread's allocation base.  x86_64
/// stores its TCB at TP and therefore uses the recorded variable-area size;
/// AArch64 records the TP offset in the otherwise-unused gap immediately
/// above TP, because late TLS can raise that offset for future allocations.
unsafe fn thread_block_tp_offset(fs_base: usize, data_size: usize) -> usize {
    #[cfg(target_arch = "x86_64")]
    { data_size }
    #[cfg(target_arch = "aarch64")]
    {
        let _ = data_size;
        thread_tp_offset(fs_base)
    }
    #[cfg(target_arch = "riscv64")]
    {
        let _ = (fs_base, data_size);
        TCB_SIZE
    }
}

/// Initialize loader-owned TCB metadata for one TLS allocation.  The
/// per-allocation TP offset is needed when a later dlopen introduces a more
/// strongly aligned TLS image: old threads remain on their old allocation
/// until their next TLS lookup and must still be unmapped from its true base.
unsafe fn initialize_tls_tcb(tcb: *mut u8, tp: *mut u8, data_size: usize) {
    #[cfg(not(target_arch = "aarch64"))]
    let _ = tp;
    core::ptr::write_unaligned(tcb as *mut u64, tcb as u64);
    core::ptr::write_unaligned(
        tcb.add(TCB_GENERATION_OFFSET) as *mut u64,
        TLS_GENERATION,
    );
    core::ptr::write_unaligned(
        tcb.add(TCB_BLOCK_SIZE_OFFSET) as *mut usize,
        data_size,
    );
    core::ptr::write_unaligned(
        tcb.add(TCB_TP_OFFSET_OFFSET) as *mut usize,
        tls_tp_offset_from_block(),
    );
    #[cfg(target_arch = "aarch64")]
    {
        // TP+8 is in the ABI-mandated gap before the first positive TLS
        // offset (GAP_ABOVE_TP is 16), so it is safe metadata storage even
        // when the TCB is below TP by several pages.
        core::ptr::write_unaligned(
            tp.add(TCB_GENERATION_OFFSET) as *mut usize,
            tls_tp_offset_from_block(),
        );
    }
}

unsafe fn tls_var_area_offset_from_tp() -> usize {
    #[cfg(target_arch = "x86_64")]
    { TLS_TOTAL_SIZE }
    #[cfg(target_arch = "aarch64")]
    { 0 }
    #[cfg(target_arch = "riscv64")]
    { 0 }
}

// ============================================================
// Relocation processing
// ============================================================

/// Process all relocations for every loaded object.
unsafe fn process_all_relocations() {
    // First pass: non-COPY relocations so source symbols have final values.
    for i in 0..LOADED_COUNT {
        if LOADED[i].relro_applied {
            continue;
        }
        let (base, rela_off, rela_sz, jmprel_off, jmprel_sz, relr_off, relr_sz, relr_ent) =
            relocation_info(i);
        apply_relr_table(i, base, relr_off, relr_sz, relr_ent);
        apply_rela_table(i, base, rela_off, rela_sz, false);
        apply_rela_table(i, base, jmprel_off, jmprel_sz, false);
    }
    // Second pass: COPY relocations copy initialized data into the executable.
    for i in 0..LOADED_COUNT {
        if LOADED[i].relro_applied {
            continue;
        }
        let (base, rela_off, rela_sz, _, _, _, _, _) = relocation_info(i);
        apply_rela_table(i, base, rela_off, rela_sz, true);
    }
}

/// Lock every mapped GNU_RELRO span after all relocations that may touch it.
/// A later `dlopen` only relocates newly mapped objects; applying RELRO also
/// makes prior objects ineligible for the relocation pass above.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
unsafe fn apply_relro() {
    const PAGE: u64 = 4096;
    for i in 0..LOADED_COUNT {
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
        base,
        rela_off,
        rela_sz,
        jmprel_off,
        jmprel_sz,
        relr_off,
        relr_sz,
        relr_ent,
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

        #[cfg(target_arch = "riscv64")]
        if r_type == R_RISCV_COPY {
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
        #[cfg(not(target_arch = "riscv64"))]
        if r_type == R_X86_64_COPY {
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
            R_X86_64_RELATIVE | R_AARCH64_RELATIVE | R_RISCV_RELATIVE => {
                *slot = (base as i64 + r_addend) as u64;
            }
            R_X86_64_64 | R_AARCH64_ABS64 | R_RISCV_64 => {
                let sym_value = resolve_symbol_from_index(obj_idx, r_sym_idx);
                *slot = (sym_value as i64 + r_addend) as u64;
            }
            #[cfg(target_arch = "riscv64")]
            R_RISCV_JUMP_SLOT => {
                let sym_value = resolve_symbol_from_index(obj_idx, r_sym_idx);
                *slot = sym_value;
            }
            #[cfg(target_arch = "riscv64")]
            R_RISCV_TLS_DTPMOD64 => {
                let module = if r_sym_idx == 0 {
                    obj_idx
                } else {
                    resolve_symbol_module(obj_idx, r_sym_idx)
                };
                *slot = (module + 1) as u64;
            }
            #[cfg(target_arch = "riscv64")]
            R_RISCV_TLS_DTPREL64 => {
                let off = (tls_sym_offset(obj_idx, r_sym_idx) as i64 + r_addend) as u64;
                *slot = off;
            }
            #[cfg(target_arch = "riscv64")]
            R_RISCV_TLS_TPREL64 => {
                let fs_off = tls_tprel_offset(obj_idx, r_sym_idx, r_addend);
                *slot = fs_off as u64;
            }
            #[cfg(not(target_arch = "riscv64"))]
            R_X86_64_GLOB_DAT | R_X86_64_JUMP_SLOT => {
                let sym_value = resolve_symbol_from_index(obj_idx, r_sym_idx);
                *slot = sym_value;
            }
            #[cfg(not(target_arch = "riscv64"))]
            R_AARCH64_GLOB_DAT | R_AARCH64_JUMP_SLOT => {
                let sym_value = resolve_symbol_from_index(obj_idx, r_sym_idx);
                *slot = sym_value;
            }
            R_X86_64_DTPMOD64 | R_AARCH64_TLS_DTPMOD64 => {
                let module = if r_sym_idx == 0 {
                    obj_idx
                } else {
                    resolve_symbol_module(obj_idx, r_sym_idx)
                };
                *slot = (module + 1) as u64;
            }
            R_X86_64_DTPOFF64 | R_AARCH64_TLS_DTPREL64 => {
                let off = (tls_sym_offset(obj_idx, r_sym_idx) as i64 + r_addend) as u64;
                *slot = off;
            }
            R_X86_64_TPOFF64 | R_AARCH64_TLS_TPREL64 => {
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
        } else if r_type == R_AARCH64_TLSLE_ADD_TPREL_LO12 || r_type == R_AARCH64_TLSLE_ADD_TPREL_LO12_NC {
            let fs_off = tls_tprel_offset(obj_idx, r_sym_idx, r_addend);
            let insn = core::ptr::read_unaligned(slot as *const u32);
            let imm = (fs_off & 0xFFF) as u32;
            let new_insn = (insn & !(0xFFFu32 << 10)) | (imm << 10);
            core::ptr::write_unaligned(slot as *mut u32, new_insn);
        } else if r_type == R_AARCH64_TLSDESC || r_type == R_RISCV_TLSDESC {
            let fs_off = tls_tprel_offset(obj_idx, r_sym_idx, r_addend);
            let desc = slot as *mut [u64; 2];
            #[cfg(target_arch = "aarch64")]
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

unsafe fn run_constructors() {
    // The executable records its preload and DT_NEEDED roots in loader search
    // order. Recursing from it gives every direct/transitive dependency a
    // chance to initialize before the consumer, without reversing unrelated
    // sibling objects merely because of their registration order.
    for i in 0..LOADED_COUNT {
        run_constructors_for(i);
    }
}

unsafe fn run_constructors_for(idx: usize) {
    if idx >= LOADED_COUNT || !LOADED[idx].active || LOADED[idx].constructed || LOADED[idx].constructing {
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

/// AArch64 TLS descriptor resolver for statically-linked modules. The descriptor
/// is a two-word structure: [0] = resolver, [1] = precomputed TP offset. This
/// resolver simply returns the offset stored in the second word.
#[no_mangle]
unsafe extern "C" fn __tlsdesc_static(desc: *const u64) -> u64 {
    let arg = core::ptr::read_unaligned(desc.add(1));
    arg
}

/// AArch64 stores the descriptor argument in one machine word. `MAX_LOADED`
/// is deliberately small, leaving 56 bits for a TLS symbol offset and making
/// this encoding lossless for every addressable TLS image in this loader.
const TLSDESC_MODULE_SHIFT: usize = 56;
const TLSDESC_OFFSET_MASK: usize = (1usize << TLSDESC_MODULE_SHIFT) - 1;

/// Resolve TLS from a DSO loaded after threads may already exist. The call to
/// `__tls_get_addr` expands an older thread's TLS block before the returned
/// address is converted back to the TP-relative value the AArch64 TLSDESC ABI
/// expects.
#[no_mangle]
unsafe extern "C" fn __tlsdesc_dynamic(desc: *const u64) -> u64 {
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

unsafe fn expand_thread_tls(old_total: usize, old_module_count: usize) -> bool {
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
    let old_fs = read_tp();
    let old_tcb = tcb_for_thread(old_fs);
    let recorded_data = core::ptr::read_unaligned(old_tcb.add(TCB_BLOCK_SIZE_OFFSET) as *const usize);
    let old_data = if recorded_data != 0 { recorded_data } else { old_total };
    let old_tp_offset = thread_block_tp_offset(old_fs, old_data);
    let old_block = (old_fs as usize).wrapping_sub(old_tp_offset) as *mut u8;
    let old_var_base = {
        #[cfg(target_arch = "x86_64")]
        { old_block }
        #[cfg(target_arch = "aarch64")]
        { old_fs as *mut u8 }
        #[cfg(target_arch = "riscv64")]
        { old_block }
    };
    if old_data > 0 {
        let copy_size = if old_data < TLS_TOTAL_SIZE { old_data } else { TLS_TOTAL_SIZE };
        core::ptr::copy_nonoverlapping(
            old_var_base,
            block.add(tls_var_area_offset_from_block()),
            copy_size,
        );
    }
    for i in old_module_count..TLS_MODULE_COUNT {
        if TLS_MEMSZ[i] == 0 {
            continue;
        }
        let dst = block.add(tls_var_area_offset_from_block()).add(TLS_LAYOUT_OFFSET[i]);
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
    let tcb = block.add(tls_tcb_offset_from_block());
    // Preserve libc's TCB fields (notably the x86_64 stack canary) while
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

/// Reserve a dynamic TLS module in the process layout. The caller holds the
/// resulting lock until its relocations have made its TLS image usable, then
/// completes the update with `initialize_new_module_tls`.
unsafe fn register_tls_for_new_module(idx: usize) -> Option<(usize, usize)> {
    let obj = &LOADED[idx];
    if obj.tls_memsz == 0 {
        return None;
    }
    tls_lock();
    let old_total = TLS_TOTAL_SIZE;
    let old_module_count = TLS_MODULE_COUNT;
    let align = if obj.tls_align > 0 { obj.tls_align as usize } else { 1 };

    // Existing modules retain their original alignments.  Reusing the new
    // module's alignment for every prior module could move their offsets;
    // replacing TLS_TOTAL_SIZE with that recomputed end then shrank the live
    // block to a few bytes during dlopen.  TLS_USED_SIZE is the monotonic
    // logical frontier, while TLS_TOTAL_SIZE remains its allocation capacity.
    if !align.is_power_of_two() {
        tls_unlock();
        return None;
    }
    #[cfg(target_arch = "aarch64")]
    if align > TLS_TP_OFFSET {
        // AArch64's TP is above the TCB and static TLS.  A late DSO with a
        // stronger PT_TLS alignment needs a correspondingly larger gap in
        // newly allocated blocks; existing threads retain their recorded
        // offset until they migrate on the next TLS lookup.
        TLS_TP_OFFSET = align;
    }
    let new_offset = (TLS_USED_SIZE + align - 1) & !(align - 1);
    let new_used = match new_offset.checked_add(obj.tls_memsz as usize) {
        Some(value) => value,
        None => {
            tls_unlock();
            return None;
        }
    };
    if new_used > TLS_TOTAL_SIZE {
        let doubled = new_used.saturating_mul(2);
        let minimum = if doubled < 4096 { 4096 } else { doubled };
        TLS_TOTAL_SIZE = (minimum + 4095) & !4095;
    }
    TLS_LAYOUT_OFFSET[idx] = new_offset;
    TLS_FILESZ[idx] = obj.tls_filesz;
    TLS_MEMSZ[idx] = obj.tls_memsz;
    TLS_IMAGE[idx] = obj.tls_image;
    TLS_USED_SIZE = new_used;
    TLS_MODULE_COUNT = LOADED_COUNT;
    TLS_GENERATION = TLS_GENERATION.wrapping_add(1);
    if TLS_GENERATION == 0 {
        TLS_GENERATION = 1;
    }

    Some((old_total, old_module_count))
}

/// Copy the relocated image of a newly registered TLS module into this
/// thread, then let other threads observe the new generation.
unsafe fn initialize_new_module_tls(old_total: usize, old_module_count: usize) {
    let _ = expand_thread_tls(old_total, old_module_count);
    TLS_OLD_TOTAL = old_total;
    TLS_OLD_MODULE_COUNT = old_module_count;
    tls_unlock();
}

unsafe fn lookup_symbol_in_object(obj_idx: usize, name: *const u8, name_len: usize) -> u64 {
    let obj = &LOADED[obj_idx];
    if obj.symtab.is_null() || obj.strtab.is_null() {
        return 0;
    }
    for j in 0..obj.sym_count {
        let sym_entry = obj.symtab.add(j * SYMTAB_ENT_SIZE);
        let st_name_off = u32::from_le_bytes(core::ptr::read_unaligned(sym_entry as *const [u8; 4])) as usize;
        let st_value = u64::from_le_bytes(core::ptr::read_unaligned(sym_entry.add(8) as *const [u8; 8]));
        if st_value == 0 {
            continue;
        }
        if st_name_off >= obj.strsz {
            continue;
        }
        let sym_name = obj.strtab.add(st_name_off);
        if str_eq(name, name_len, sym_name) {
            return obj.base + st_value;
        }
    }
    0
}

unsafe fn set_dlerror(msg: &[u8]) {
    dlerror_lock();
    let node = dlerror_node_locked(current_tid() as usize, read_tp());
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
    let node = dlerror_node_locked(current_tid() as usize, read_tp());
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

unsafe fn clear_dlerror() {
    dlerror_lock();
    let node = dlerror_node_locked(current_tid() as usize, read_tp());
    if !node.is_null() {
        (*node).set.store(false, Ordering::Release);
    }
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

}

#[no_mangle]
pub unsafe extern "C" fn __ldso_dlopen(filename: *const u8, flags: i32) -> *mut u8 {
    loader_lock();
    clear_dlerror();
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
    let tls_update = register_tls_for_new_module(idx);
    process_all_relocations();
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    apply_relro();
    if let Some((old_total, old_module_count)) = tls_update {
        initialize_new_module_tls(old_total, old_module_count);
    }
    run_constructors_for(idx);
    publish_debug_state(RT_CONSISTENT);
    loader_unlock();
    &mut LOADED[idx] as *mut LoadedObject as *mut u8
}

#[no_mangle]
pub unsafe extern "C" fn __ldso_dlsym(handle: *mut u8, symbol: *const u8) -> *mut u8 {
    loader_lock();
    clear_dlerror();
    if symbol.is_null() {
        set_dlerror(b"dlsym: null symbol\0");
        loader_unlock();
        return core::ptr::null_mut();
    }
    let name_len = str_len(symbol);
    if handle == DL_PRIVATE_SENTINEL {
        let private = if str_eq(symbol, name_len, b"__crabc_ldso_iterate_phdr\0".as_ptr()) {
            __ldso_dl_iterate_phdr as *mut u8
        } else if str_eq(symbol, name_len, b"__crabc_ldso_dladdr\0".as_ptr()) {
            __ldso_dladdr as *mut u8
        } else if str_eq(symbol, name_len, b"__crabc_ldso_dlinfo\0".as_ptr()) {
            __ldso_dlinfo as *mut u8
        } else if str_eq(symbol, name_len, b"__crabc_ldso_tls_get_addr\0".as_ptr()) {
            __ldso_tls_get_addr as *mut u8
        } else if str_eq(symbol, name_len, b"__crabc_ldso_loader_snapshot\0".as_ptr()) {
            __ldso_loader_snapshot as *mut u8
        } else if str_eq(symbol, name_len, b"__crabc_ldso_loader_information\0".as_ptr()) {
            __ldso_loader_information as *mut u8
        } else {
            core::ptr::null_mut()
        };
        if private.is_null() {
            set_dlsym_symbol_not_found(symbol, name_len);
        }
        loader_unlock();
        return private;
    }
    let mut result: u64 = 0;
    // dlfcn.h exposes RTLD_DEFAULT as a null handle.  The libc bridge uses
    // the private sentinel for dlopen(NULL), but direct callers must retain
    // the standard null-handle global lookup semantics as well.
    if handle.is_null() || handle == DL_GLOBAL_SENTINEL {
        for i in 0..LOADED_COUNT {
            if i == 0 || LOADED[i].global {
                result = lookup_symbol_in_object(i, symbol, name_len);
                if result != 0 {
                    break;
                }
            }
        }
    } else {
        if let Some(idx) = loaded_handle_index(handle) {
            result = lookup_symbol_in_object(idx, symbol, name_len);
            if result == 0 {
                for i in 0..LOADED_COUNT {
                    if i == 0 || LOADED[i].global {
                        result = lookup_symbol_in_object(i, symbol, name_len);
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
    loader_unlock();
    result as *mut u8
}

#[no_mangle]
pub unsafe extern "C" fn __ldso_dlclose(handle: *mut u8) -> i32 {
    loader_lock();
    clear_dlerror();
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
    let node = dlerror_node_locked(current_tid() as usize, read_tp());
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
    let phoff = u64::from_le_bytes(core::ptr::read_unaligned(ehdr.add(32) as *const [u8; 8])) as usize;
    let phentsize = u16::from_le_bytes(core::ptr::read_unaligned(ehdr.add(54) as *const [u8; 2])) as usize;
    let phnum = u16::from_le_bytes(core::ptr::read_unaligned(ehdr.add(56) as *const [u8; 2])) as usize;
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
        let vaddr = u64::from_le_bytes(core::ptr::read_unaligned(ph.add(PH_VADDR) as *const [u8; 8])) as usize;
        let memsz = u64::from_le_bytes(core::ptr::read_unaligned(ph.add(PH_MEMSZ) as *const [u8; 8])) as usize;
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
            .map_or((core::ptr::null(), 0), |(phdr, phnum)| (phdr as *const c_void, phnum));
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
    let main_index = if handle == DL_GLOBAL_SENTINEL
        && LOADED_COUNT != 0
        && LOADED[0].active
    {
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
pub unsafe extern "C" fn __ldso_dladdr(
    address: *const u8,
    result: *mut LdsoDladdrResult,
) -> i32 {
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
            let name_off = u32::from_le_bytes(core::ptr::read_unaligned(sym as *const [u8; 4])) as usize;
            let info = *sym.add(4);
            let shndx = u16::from_le_bytes(core::ptr::read_unaligned(sym.add(6) as *const [u8; 2]));
            let value = u64::from_le_bytes(core::ptr::read_unaligned(sym.add(8) as *const [u8; 8])) as usize;
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
    if idx < LOADED_COUNT { Some(idx) } else { None }
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
pub unsafe extern "C" fn __ldso_dlinfo(
    handle: *mut u8,
    request: i32,
    arg: *mut u8,
) -> i32 {
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
    #[cfg(target_arch = "aarch64")]
    let mut tp_alignment: usize = TCB_SIZE;
    for i in 0..LOADED_COUNT {
        let obj = &LOADED[i];
        let align = if obj.tls_align > 0 { obj.tls_align as usize } else { 1 };
        #[cfg(target_arch = "aarch64")]
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
    #[cfg(target_arch = "aarch64")]
    {
        TLS_TP_OFFSET = tp_alignment;
        // AArch64 uses TLS_ABOVE_TP: static TLS starts at a positive offset
        // from TP.  The static linker has already encoded those offsets in
        // local-exec instructions, so the first module must begin at the next
        // boundary of its PT_TLS alignment *relative to TP*.  Matching the
        // file-image address here is wrong when the TCB itself is not aligned
        // to that boundary (for example a 4 KiB-aligned TLS variable).
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
            let align = if obj.tls_align > 0 { obj.tls_align as usize } else { 1 };
            offset = (offset + align - 1) & !(align - 1);
            TLS_LAYOUT_OFFSET[i] = offset;
            TLS_FILESZ[i] = obj.tls_filesz;
            TLS_MEMSZ[i] = obj.tls_memsz;
            TLS_IMAGE[i] = obj.tls_image;
            let block_size = ((obj.tls_memsz as usize + align - 1) / align) * align;
            offset += block_size;
        }
        TLS_USED_SIZE = offset;
    }

    #[cfg(target_arch = "x86_64")]
    {
        // x86_64 places the variable area below TP; modules are laid out from the
        // end of the variable area (closest to TP) backwards.
        let mut end = TLS_TOTAL_SIZE;
        for i in 0..LOADED_COUNT {
            let obj = &LOADED[i];
            if obj.tls_memsz == 0 {
                TLS_LAYOUT_OFFSET[i] = 0;
                TLS_FILESZ[i] = 0;
                TLS_MEMSZ[i] = 0;
                TLS_IMAGE[i] = core::ptr::null();
                continue;
            }
            let align = if obj.tls_align > 0 { obj.tls_align as usize } else { 1 };
            let block_size = ((obj.tls_memsz as usize + align - 1) / align) * align;
            end -= block_size;
            end &= !(align - 1);
            TLS_LAYOUT_OFFSET[i] = end;
            TLS_FILESZ[i] = obj.tls_filesz;
            TLS_MEMSZ[i] = obj.tls_memsz;
            TLS_IMAGE[i] = obj.tls_image;
        }
        // Existing x86_64 modules are placed at the high end of the variable
        // area.  Late modules append after the capacity frontier; using
        // `TLS_TOTAL_SIZE - end` here would place the first late module over
        // the static images.
        TLS_USED_SIZE = TLS_TOTAL_SIZE;
    }

    #[cfg(target_arch = "riscv64")]
    {
        // RISC-V uses TLS_ABOVE_TP like aarch64 but with GAP_ABOVE_TP=0.
        let mut offset: usize = 0;
        for i in 0..LOADED_COUNT {
            let obj = &LOADED[i];
            if obj.tls_memsz == 0 {
                TLS_LAYOUT_OFFSET[i] = 0;
                TLS_FILESZ[i] = 0;
                TLS_MEMSZ[i] = 0;
                TLS_IMAGE[i] = core::ptr::null();
                continue;
            }
            let align = if obj.tls_align > 0 { obj.tls_align as usize } else { 1 };
            let image = obj.tls_image as usize;
            let var_base_mod = TCB_SIZE % align;
            let desired = image.wrapping_sub(var_base_mod).wrapping_sub(offset) & (align - 1);
            offset += desired;
            TLS_LAYOUT_OFFSET[i] = offset;
            TLS_FILESZ[i] = obj.tls_filesz;
            TLS_MEMSZ[i] = obj.tls_memsz;
            TLS_IMAGE[i] = obj.tls_image;
            let block_size = ((obj.tls_memsz as usize + align - 1) / align) * align;
            offset += block_size;
        }
        TLS_USED_SIZE = offset;
    }

    TLS_MODULE_COUNT = LOADED_COUNT;
}

unsafe fn init_tls_block(block: *mut u8) -> *mut u8 {
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
    let tcb = block.add(tls_tcb_offset_from_block());
    let tp = block.add(tls_tp_offset_from_block());
    initialize_tls_tcb(tcb, tp, TLS_TOTAL_SIZE);
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
    let thread_gen = core::ptr::read_unaligned(
        tcb.add(TCB_GENERATION_OFFSET) as *const u64,
    );
    if thread_gen != TLS_GENERATION {
        tls_lock();
        let fs_base_locked = read_tp();
        let tcb_locked = tcb_for_thread(fs_base_locked);
        let thread_gen2 = core::ptr::read_unaligned(
            tcb_locked.add(TCB_GENERATION_OFFSET) as *const u64,
        );
        if thread_gen2 != TLS_GENERATION {
            if !expand_thread_tls(TLS_OLD_TOTAL, TLS_OLD_MODULE_COUNT) {
                tls_unlock();
                return core::ptr::null_mut();
            }
        }
        tls_unlock();
    }
    let fs_base2 = read_tp();
    let tls_base = fs_base2 - tls_var_area_offset_from_tp();
    (tls_base as *mut u8).add(TLS_LAYOUT_OFFSET[module]).add(offset) as *mut u8
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
    let new_tp = init_tls_block(block);
    // New pthreads inherit the process's TCB ABI state (including the stack
    // protector) while receiving fresh TLS variable images.
    let old_fs = read_tp();
    if old_fs != 0 {
        let old_tcb = tcb_for_thread(old_fs) as *const u8;
        let new_tcb = tcb_for_thread(new_tp as usize);
        core::ptr::copy_nonoverlapping(old_tcb, new_tcb, TCB_SIZE);
        initialize_tls_tcb(new_tcb, new_tp, TLS_TOTAL_SIZE);
    }
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
    let e_phnum = u16::from_le_bytes(core::ptr::read_unaligned(ehdr.add(56) as *const [u8; 2])) as usize;
    let mut dyn_vaddr: u64 = 0;
    let mut dyn_memsz: u64 = 0;
    let mut relro_vaddr: u64 = 0;
    let mut relro_memsz: u64 = 0;
    for i in 0..e_phnum {
        let ph = ehdr.add(e_phoff as usize + i * PHDR_SIZE);
        let p_type = u32::from_le_bytes(core::ptr::read_unaligned(ph as *const [u8; 4]));
        if p_type == PT_DYNAMIC {
            dyn_vaddr = u64::from_le_bytes(core::ptr::read_unaligned(ph.add(PH_VADDR) as *const [u8; 8]));
            dyn_memsz = u64::from_le_bytes(core::ptr::read_unaligned(ph.add(PH_MEMSZ) as *const [u8; 8]));
        } else if p_type == PT_GNU_RELRO {
            relro_vaddr = u64::from_le_bytes(core::ptr::read_unaligned(ph.add(PH_VADDR) as *const [u8; 8]));
            relro_memsz = u64::from_le_bytes(core::ptr::read_unaligned(ph.add(PH_MEMSZ) as *const [u8; 8]));
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
            _ => {}
        }
        pos += 16;
    }
    if dt_symtab == 0 || dt_strtab == 0 {
        return;
    }
    let symtab_ptr = (ldso_base + dt_symtab) as *const u8;
    let strtab_ptr = (ldso_base + dt_strtab) as *const u8;
    let sym_count = ((dt_strtab - dt_symtab) / SYMTAB_ENT_SIZE as u64) as usize;
    if LOADED_COUNT < MAX_LOADED {
        LOADED[LOADED_COUNT] = LoadedObject {
            base: ldso_base,
            map_start: core::ptr::null_mut(),
            map_size: 0,
            symtab: symtab_ptr,
            sym_count,
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
    for i in 0..LOADED_COUNT {
        if !LOADED[i].active || LOADED[i].name[0] == 0 {
            continue;
        }
        if str_eq(name, name_len, LOADED[i].name.as_ptr()) {
            return Some(i);
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
    LD_LIBRARY_PATH = ld_path.unwrap_or(core::ptr::null());

    // 2. Open and read the executable (the PIE that invoked us as PT_INTERP)
    let proc_exe = b"/proc/self/exe\0";
    let fd = sys_open(proc_exe.as_ptr());
    if fd < 0 {
        die(99, b"open_exe", fd as usize);
    }
    let exec_identity = file_identity(fd);
    {
        let mut exe_path = [0u8; 256];
        let r = sys_readlink(proc_exe.as_ptr(), exe_path.as_mut_ptr(), exe_path.len());
        if r > 0 {
            let len = r as usize;
            let mut slash = len;
            while slash > 0 {
                slash -= 1;
                if exe_path[slash] == b'/' {
                    break;
                }
            }
            ORIGIN_LEN = slash;
            let mut i = 0;
            while i < slash {
                ORIGIN_DIR[i] = exe_path[i];
                i += 1;
            }
        }
    }

    let mut buf = [0u8; 4096];
    let n = sys_read(fd, buf.as_mut_ptr(), buf.len());
    if n < 64 {
        die(98, b"read_exe", n as usize);
    }

    if buf[0] != 0x7f || buf[1] != b'E' {
        die(97, b"elf_magic", u16::from_le_bytes([buf[0], buf[1]]) as usize);
    }

    let e_phoff = u64::from_le_bytes(buf[32..40].try_into().unwrap());
    let e_phnum = u16::from_le_bytes(buf[56..58].try_into().unwrap());
    let e_entry = u64::from_le_bytes(buf[24..32].try_into().unwrap());
    let mut exec_relro_vaddr = 0u64;
    let mut exec_relro_memsz = 0u64;
    for i in 0..e_phnum as usize {
        let ph = buf.as_ptr().add(e_phoff as usize + i * PHDR_SIZE);
        let p_type = u32::from_le_bytes(core::ptr::read_unaligned(ph as *const [u8; 4]));
        if p_type == PT_GNU_RELRO {
            exec_relro_vaddr = u64::from_le_bytes(core::ptr::read_unaligned(ph.add(PH_VADDR) as *const [u8; 8]));
            exec_relro_memsz = u64::from_le_bytes(core::ptr::read_unaligned(ph.add(PH_MEMSZ) as *const [u8; 8]));
            break;
        }
    }

    // 3. Map executable's PT_LOAD segments at a safe base address.
    //    PIE p_vaddr often starts at 0 which is below mmap_min_addr on CI.
    //    Pre-scan to find span, probe for free region, then MAP_FIXED there.
    let page = 4096u64;
    let mut min_vaddr = u64::MAX;
    let mut max_vaddr_end = 0u64;
    for i in 0..e_phnum as usize {
        let ph = buf.as_ptr().add(e_phoff as usize + i * PHDR_SIZE);
        let p_type = u32::from_le_bytes(core::ptr::read_unaligned(ph as *const [u8; 4]));
        if p_type != PT_LOAD {
            continue;
        }
        let p_vaddr = u64::from_le_bytes(core::ptr::read_unaligned(ph.add(PH_VADDR) as *const [u8; 8]));
        let p_memsz = u64::from_le_bytes(core::ptr::read_unaligned(ph.add(PH_MEMSZ) as *const [u8; 8]));
        if p_vaddr < min_vaddr { min_vaddr = p_vaddr; }
        let end = p_vaddr + p_memsz;
        if end > max_vaddr_end { max_vaddr_end = end; }
    }
    let image_start = min_vaddr & !(page - 1);
    let image_end = (max_vaddr_end + page - 1) & !(page - 1);
    let total_size = (image_end - image_start) as usize;
    // The main PIE deserves the same kernel-selected load bias as DSOs. The
    // old fixed low-address probe made its dladdr base repeat in every process
    // and bypassed normal Linux ASLR entirely.
    let reservation = sys_mmap(
        core::ptr::null_mut(),
        total_size,
        PROT_NONE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    if reservation as usize == MAP_FAILED {
        die(95, b"map_exec", total_size);
    }
    let exec_base = (reservation as u64).wrapping_sub(image_start);
    sys_munmap(reservation, total_size);

    for i in 0..e_phnum as usize {
        let ph = buf.as_ptr().add(e_phoff as usize + i * PHDR_SIZE);
        let p_type = u32::from_le_bytes(core::ptr::read_unaligned(ph as *const [u8; 4]));
        if p_type != PT_LOAD {
            continue;
        }
        let p_flags = u32::from_le_bytes(core::ptr::read_unaligned(ph.add(PH_FLAGS) as *const [u8; 4]));
        let p_offset = u64::from_le_bytes(core::ptr::read_unaligned(ph.add(PH_OFFSET) as *const [u8; 8]));
        let p_vaddr = u64::from_le_bytes(core::ptr::read_unaligned(ph.add(PH_VADDR) as *const [u8; 8]));
        let p_filesz = u64::from_le_bytes(core::ptr::read_unaligned(ph.add(PH_FILESZ) as *const [u8; 8]));
        let p_memsz = u64::from_le_bytes(core::ptr::read_unaligned(ph.add(PH_MEMSZ) as *const [u8; 8]));

        let adj = p_vaddr & (page - 1);
        let map_addr = exec_base + p_vaddr - adj;
        let map_off = p_offset - adj;
        let map_len = ((p_memsz + adj + page - 1) & !(page - 1)) as usize;
        let prot = prot_from_flags(p_flags);

        // Map the whole segment anonymously first so the tail (bss) is backed
        // by zeroed anonymous pages, then overlay the file-backed portion.
        let ptr = sys_mmap(
            map_addr as *mut u8,
            map_len,
            prot,
            MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS,
            -1,
            0,
        );
        if ptr as usize == MAP_FAILED {
            die(95, b"map_exec", map_addr as usize);
        }

        let file_map_len = ((p_filesz + adj + page - 1) & !(page - 1)) as usize;
        if file_map_len > 0 {
            let fptr = sys_mmap(
                map_addr as *mut u8,
                file_map_len,
                prot,
                MAP_PRIVATE | MAP_FIXED,
                fd as i32,
                map_off as i64,
            );
            if fptr as usize == MAP_FAILED {
                die(95, b"map_exec_file", map_addr as usize);
            }
        }

        if p_memsz > p_filesz {
            let bss_start = (exec_base + p_vaddr + p_filesz) as *mut u8;
            let bss_len = (p_memsz - p_filesz) as usize;
            core::ptr::write_bytes(bss_start, 0, bss_len);
        }
    }

    let mut exec_tls_image: *const u8 = core::ptr::null();
    let mut exec_tls_filesz: u64 = 0;
    let mut exec_tls_memsz: u64 = 0;
    let mut exec_tls_align: u64 = 0;
    for i in 0..e_phnum as usize {
        let ph = buf.as_ptr().add(e_phoff as usize + i * PHDR_SIZE);
        let p_type = u32::from_le_bytes(core::ptr::read_unaligned(ph as *const [u8; 4]));
        if p_type == PT_TLS {
            let p_vaddr = u64::from_le_bytes(core::ptr::read_unaligned(ph.add(PH_VADDR) as *const [u8; 8]));
            exec_tls_filesz = u64::from_le_bytes(core::ptr::read_unaligned(ph.add(PH_FILESZ) as *const [u8; 8]));
            exec_tls_memsz = u64::from_le_bytes(core::ptr::read_unaligned(ph.add(PH_MEMSZ) as *const [u8; 8]));
            exec_tls_align = u64::from_le_bytes(core::ptr::read_unaligned(ph.add(PH_ALIGN) as *const [u8; 8]));
            exec_tls_image = (exec_base + p_vaddr) as *const u8;
            break;
        }
    }

    sys_close(fd);

    // 4. Parse executable's PT_DYNAMIC (base = 0)
    let mut dyn_vaddr: u64 = 0;
    let mut dyn_memsz: u64 = 0;
    for i in 0..e_phnum as usize {
        let ph = buf.as_ptr().add(e_phoff as usize + i * PHDR_SIZE);
        let p_type = u32::from_le_bytes(core::ptr::read_unaligned(ph as *const [u8; 4]));
        if p_type == PT_DYNAMIC {
            dyn_vaddr = u64::from_le_bytes(core::ptr::read_unaligned(ph.add(PH_VADDR) as *const [u8; 8]));
            dyn_memsz = u64::from_le_bytes(core::ptr::read_unaligned(ph.add(PH_MEMSZ) as *const [u8; 8]));
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
                DT_INIT => { dt_init = d_val; dt_init_present = true; }
                DT_INIT_ARRAY => { dt_init_array = d_val; dt_init_array_present = true; }
                DT_INIT_ARRAYSZ => dt_init_array_sz = d_val,
                DT_RUNPATH => { dt_runpath_off = d_val; dt_runpath_present = true; }
                DT_RPATH => { dt_rpath_off = d_val; dt_rpath_present = true; }
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
    LOADED[0] = LoadedObject {
        base: exec_base,
        map_start: exec_base.wrapping_add(image_start) as *mut u8,
        map_size: total_size,
        symtab: (exec_base + dt_symtab) as *const u8,
        sym_count: exec_sym_count,
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
        file_identity_valid: exec_identity.is_some(),
        file_dev: exec_identity.map_or(0, |id| id.dev),
        file_ino: exec_identity.map_or(0, |id| id.ino),
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

    // `LD_PRELOAD` belongs ahead of the executable's DT_NEEDED graph: its
    // definitions must already be visible when the ordinary dependencies'
    // PLT/GOT relocations are resolved. Preserve the kernel envp pointer until
    // after this point; the replacement application stack is built later.
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

    compute_tls_layout();
    TLS_STATIC_MODULE_COUNT = TLS_MODULE_COUNT;
    TLS_OLD_TOTAL = TLS_TOTAL_SIZE;
    TLS_OLD_MODULE_COUNT = TLS_MODULE_COUNT;

    process_all_relocations();
    register_dlopen_callbacks();
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
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

    run_constructors();

    // Publish the complete post-relocation object graph.  This mirrors musl's
    // initial RT_CONSISTENT rendezvous and leaves `_dl_debug_addr` pointing at
    // the same map snapshot that runtime dl* queries use.
    publish_debug_state(RT_CONSISTENT);

    let phdr_addr = exec_base + e_phoff;
    build_and_jump(exec_base + e_entry, phdr_addr, e_phnum, sp, secure)
}

// ============================================================
// Build a fresh stack for the target program and jump
// ============================================================

unsafe fn build_and_jump(
    entry: u64,
    phdr_addr: u64,
    phnum: u16,
    orig_sp: usize,
    secure: bool,
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
    let requested_stack = if required > minimum_stack { required } else { minimum_stack };
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

    #[cfg(target_arch = "x86_64")]
    core::arch::asm!(
        "mov rsp, {sp}",
        "jmp {entry}",
        sp = in(reg) sp,
        entry = in(reg) entry,
        options(noreturn)
    );

    #[cfg(target_arch = "aarch64")]
    core::arch::asm!(
        "mov sp, {sp}",
        "br {entry}",
        sp = in(reg) sp,
        entry = in(reg) entry,
        options(noreturn)
    );

    #[cfg(target_arch = "riscv64")]
    {
        // Workaround: riscv64 compiler reuses entry register for other
        // calculations. Force a volatile reload right before the asm block.
        let entry_ref = &entry as *const u64;
        let entry_val = unsafe { core::ptr::read_volatile(entry_ref) };
        core::arch::asm!(
            "mv sp, {sp}",
            "jr {entry}",
            sp = in(reg) sp,
            entry = in(reg) entry_val,
            options(noreturn)
        );
    }
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
