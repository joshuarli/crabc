#![no_std]
#![no_main]
#![allow(unexpected_cfgs)]

//! A bounded Linux/x86-64 initial-interpreter graph.
//!
//! This is intentionally a separately-built bootstrap artifact, not the
//! `crabc-ldso` public target.  It proves the earliest x86-64 dynamic-loader
//! transaction against one ordinary shape: a kernel-mapped PIE, one direct
//! DSO, and that DSO's direct DSO.  `_start` performs *this interpreter's*
//! `R_X86_64_RELATIVE` relocations in assembly before entering Rust.  Rust
//! then discovers the two `DT_NEEDED` edges through absolute `DT_RUNPATH`
//! directories, maps the two ET_DYN images, and processes RELATIVE,
//! GLOB_DAT, JUMP_SLOT, and the GNU dynamic-TLS DTPMOD64/DTPOFF64 ELF64 RELA
//! records plus one bounded packed `DT_RELR` stream in the leaf dependency.
//! The TLS sibling graph first lays out every initial `PT_TLS` image below an
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
//! remains `DT_RELA`-only; the one-thread initial TLS slice accepts only GNU
//! DTPMOD64/DTPOFF64 plus `__tls_get_addr`, and rejects initial-exec/TPOFF,
//! TLSDESC, DTV growth, `DT_INIT`, main-image constructor dispatch (that
//! remains CRT-owned), preload/environment search, `dl*`, audit, secure-exec
//! filtering, symbolic versioning, or a general dependency graph.

#![allow(clippy::missing_safety_doc)]

use core::arch::global_asm;
use core::ffi::c_void;

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

const MAX_OBJECTS: usize = 3;
const MAX_PHDRS: usize = 32;
const MAX_NEEDED: usize = 2;
const MAX_PATH: usize = 512;
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

#[derive(Copy, Clone)]
struct Object {
    base: u64,
    phdr: *const u8,
    phnum: usize,
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
    init_array: *const usize,
    init_count: usize,
    relro_virtual_address: u64,
    relro_byte_len: u64,
    runpath: *const u8,
    runpath_len: usize,
    needed: [usize; MAX_NEEDED],
    needed_count: usize,
    mapped: bool,
    tls_image: *const u8,
    tls_filesz: usize,
    tls_memsz: usize,
    tls_align: usize,
    tls_offset_below_tp: usize,
    tls_module_id: usize,
}

const EMPTY_OBJECT: Object = Object {
    base: 0,
    phdr: core::ptr::null(),
    phnum: 0,
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
    init_array: core::ptr::null(),
    init_count: 0,
    relro_virtual_address: 0,
    relro_byte_len: 0,
    runpath: core::ptr::null(),
    runpath_len: 0,
    needed: [0; MAX_NEEDED],
    needed_count: 0,
    mapped: false,
    tls_image: core::ptr::null(),
    tls_filesz: 0,
    tls_memsz: 0,
    tls_align: 1,
    tls_offset_below_tp: 0,
    tls_module_id: 0,
};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    unsafe { die(b"panic\n") }
}

// The interpreter cannot rely on any relocated Rust address before this
// sequence.  Linux supplies AT_BASE for PT_INTERP; the loop finds this
// object's PT_DYNAMIC and applies only the linker's self-relative records.
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
        objects[0] = parse_mapped(main_base, main_phdr, main_phnum, false)
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
        // Keep module IDs stable in this fixed main -> mid -> leaf graph
        // before relocation writes their GNU-Dynamic DTPMOD/DTPOFF slots. The
        // no-TLS graph retains its old behavior: a layout with no PT_TLS image
        // does not install or modify `%fs`.
        let has_initial_tls = plan_initial_tls(&mut objects).unwrap_or_else(|| fail(b"tlsplan\n"));
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
            install_initial_tls(&objects).unwrap_or_else(|| fail(b"tlsinit\n"));
        }
        for object in &objects {
            apply_relro(object).unwrap_or_else(|| fail(b"relro\n"));
        }
        run_initializers(&objects[1..]).unwrap_or_else(|| fail(b"init\n"));
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

unsafe fn parse_mapped(base: u64, phdr: *const u8, phnum: usize, mapped: bool) -> Option<Object> {
    let mut dynamic_virtual_address = None;
    let mut dynamic_byte_len = None;
    let mut relro = None;
    #[cfg(crabc_initial_tls_graph)]
    let mut tls: Option<(u64, u64, u64, usize)> = None;
    #[cfg(not(crabc_initial_tls_graph))]
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
            #[cfg(not(crabc_initial_tls_graph))]
            PT_TLS => return None,
            #[cfg(crabc_initial_tls_graph)]
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
    let mut object = Object { base, phdr, phnum, mapped, relro_virtual_address, relro_byte_len, ..EMPTY_OBJECT };
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
            DT_INIT_ARRAY => { if init_array_virtual_address.replace(value).is_some() { return None; } }
            DT_INIT_ARRAYSZ => { if init_array_byte_len.replace(value).is_some() { return None; } }
            DT_RUNPATH => { if runpath_offset.replace(usize::try_from(value).ok()?).is_some() { return None; } }
            // The fixtures use eager relocation; only its corresponding flag
            // bits are inert here. Symbolic lookup, text relocations, and the
            // static-TLS admission bit would alter unsupported loader modes.
            // Initial-exec TLS needs a complete static-TLS admission policy,
            // so reject DF_STATIC_TLS rather than silently accepting a
            // TPOFF-encoded object under this GNU-Dynamic-only boundary.
            DT_FLAGS if value & DF_STATIC_TLS != 0 => return None,
            DT_FLAGS if value & !DF_BIND_NOW != 0 => return None,
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
        // The executable's constructors are deliberately CRT-owned.  A
        // main-image init tag is a malformed request for this handoff.
        (Some(_), Some(_)) if !mapped => return None,
        (Some(address), Some(byte_len)) if byte_len % 8 == 0 && virtual_range_in_load(phdr, phnum, address, byte_len) => {
            object.init_array = runtime_address(base, address)? as *const usize;
            object.init_count = usize::try_from(byte_len / 8).ok()?;
        }
        _ => return None,
    }
    if let Some(offset) = runpath_offset {
        if offset >= object.strsz { return None; }
        object.runpath = object.strtab.add(offset);
        object.runpath_len = bounded_nul(object.runpath, object.strsz - offset)?;
        if !is_fixture_absolute_runpath(object.runpath, object.runpath_len) { return None; }
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
    let result = map_elf(fd);
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

unsafe fn file_size_from_fd(fd: i64) -> Option<u64> {
    let mut stat = [0u8; X86_64_STAT_BYTE_LEN];
    if syscall2(SYS_FSTAT, fd, stat.as_mut_ptr() as i64) < 0 { return None; }
    u64::try_from(read_i64(stat.as_ptr().add(X86_64_STAT_SIZE_OFFSET))).ok()
}

unsafe fn map_elf(fd: i64) -> Option<Object> {
    let file_byte_len = file_size_from_fd(fd)?;
    if file_byte_len < 64 { return None; }
    let header_map_len = file_byte_len.min(PAGE);
    let first = syscall6(SYS_MMAP, 0, header_map_len as i64, PROT_READ, MAP_PRIVATE, fd, 0);
    if first < 0 { return None; }
    let header = first as *const u8;
    let valid = *header == 0x7f && *header.add(1) == b'E' && *header.add(2) == b'L' && *header.add(3) == b'F'
        && *header.add(4) == 2 && *header.add(5) == 1 && read_u16(header.add(16)) == 3 && read_u16(header.add(18)) == 62
        && read_u16(header.add(54)) == 56;
    let phoff = usize::try_from(read_u64(header.add(32))).ok()?;
    let phnum = read_u16(header.add(56)) as usize;
    let ph_table_len = phnum.checked_mul(56)?;
    let ph_file_end = phoff.checked_add(ph_table_len)?;
    if !valid || phnum == 0 || phnum > MAX_PHDRS || ph_file_end > header_map_len as usize {
        syscall2(SYS_MUNMAP, first, header_map_len as i64);
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
    if min == u64::MAX || max <= min { syscall2(SYS_MUNMAP, first, header_map_len as i64); return None; }
    let reserve = syscall6(SYS_MMAP, 0, (max - min) as i64, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if reserve < 0 { syscall2(SYS_MUNMAP, first, header_map_len as i64); return None; }
    let base = (reserve as u64).checked_sub(min)?;
    for index in 0..phnum {
        let p = header.add(phoff + index * 56);
        if read_u32(p) != PT_LOAD { continue; }
        let vaddr = read_u64(p.add(16));
        let offset = read_u64(p.add(8));
        let filesz = read_u64(p.add(32));
        let memsz = read_u64(p.add(40));
        let Some(file_end) = offset.checked_add(filesz) else {
            syscall2(SYS_MUNMAP, reserve, (max - min) as i64);
            syscall2(SYS_MUNMAP, first, header_map_len as i64);
            return None;
        };
        if filesz > memsz || file_end > file_byte_len || vaddr % PAGE != offset % PAGE {
            syscall2(SYS_MUNMAP, reserve, (max - min) as i64);
            syscall2(SYS_MUNMAP, first, header_map_len as i64);
            return None;
        }
        let page_vaddr = align_down(vaddr);
        let page_offset = align_down(offset);
        let delta = vaddr - page_vaddr;
        let map_len = align_up(filesz.checked_add(delta)?);
        if map_len != 0 && syscall6(SYS_MMAP, (base + page_vaddr) as i64, map_len as i64, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED, fd, page_offset as i64) < 0 { syscall2(SYS_MUNMAP, reserve, (max - min) as i64); syscall2(SYS_MUNMAP, first, header_map_len as i64); return None; }
        let zero_start = base.checked_add(vaddr)?.checked_add(filesz)?;
        let zero_end = base.checked_add(vaddr)?.checked_add(memsz)?;
        if zero_end > zero_start { core::ptr::write_bytes(zero_start as *mut u8, 0, (zero_end - zero_start) as usize); }
    }
    // The ELF header mapping is only provisional.  Retained PHDR metadata
    // must instead be reached through the PT_LOAD that owns the on-disk PHDR
    // bytes; `base + e_phoff` is not generally a valid ELF load-bias rule.
    let phoff_u64 = u64::try_from(phoff).ok()?;
    let ph_file_end_u64 = u64::try_from(ph_file_end).ok()?;
    let mut runtime_phdr = None;
    for index in 0..phnum {
        let p = header.add(phoff + index * 56);
        if read_u32(p) != PT_LOAD { continue; }
        let file_offset = read_u64(p.add(8));
        let file_end = file_offset.checked_add(read_u64(p.add(32)))?;
        if phoff_u64 < file_offset || ph_file_end_u64 > file_end { continue; }
        let virtual_address = read_u64(p.add(16)).checked_add(phoff_u64 - file_offset)?;
        if !virtual_range_in_load(header.add(phoff), phnum, virtual_address, ph_table_len as u64) { return None; }
        runtime_phdr = Some(runtime_address(base, virtual_address)? as *const u8);
        break;
    }
    let runtime_phdr = runtime_phdr?;
    syscall2(SYS_MUNMAP, first, header_map_len as i64);
    // The provisional header mapping is gone; the final PT_LOAD mapping owns
    // every object metadata pointer retained by the returned `Object`.
    parse_mapped(base, runtime_phdr, phnum, true)
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
    for object in objects {
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
        module_count = module_count.checked_add(1)?;
        if module_count >= TLS_DTV_WORDS {
            return None;
        }
        object.tls_module_id = module_count;
        object.tls_offset_below_tp = offset_below_tp;
    }
    Some(has_tls)
}

/// Materialize every fixed-graph initial TLS image and install its minimal
/// GNU-Dynamic x86 thread-pointer prefix.
///
/// This owns exactly one main-thread block. `%fs:0` is the self pointer and
/// `%fs:8` is a DTV with one count word followed by one one-based module slot
/// per TLS-bearing object. The prefix intentionally does not claim a full musl pthread
/// TCB, a DTV growth protocol, or a worker allocation interface.
unsafe fn install_initial_tls(objects: &[Object; MAX_OBJECTS]) -> Option<()> {
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
    if tls_start < block || dtv_end > mapping_end {
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
    if syscall2(SYS_ARCH_PRCTL, ARCH_SET_FS, thread_pointer as i64) < 0 {
        let _ = syscall2(SYS_MUNMAP, mapping, mapping_size as i64);
        return None;
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
    match kind {
        R_X86_64_RELATIVE if symbol == 0 => add_signed(requestor.base, addend),
        R_X86_64_GLOB_DAT | R_X86_64_JUMP_SLOT => {
            add_signed(resolve_symbol(requestor, objects, symbol)?, addend)
        }
        #[cfg(crabc_initial_tls_graph)]
        R_X86_64_DTPMOD64 => {
            if addend != 0 {
                return None;
            }
            let (module_id, _, _) = resolve_tls_symbol(requestor, objects, symbol)?;
            u64::try_from(module_id).ok()
        }
        #[cfg(crabc_initial_tls_graph)]
        R_X86_64_DTPOFF64 => {
            let (_, symbol_offset, module_memsz) = resolve_tls_symbol(requestor, objects, symbol)?;
            let offset = add_signed(symbol_offset, addend)?;
            if offset > module_memsz as u64 {
                return None;
            }
            Some(offset)
        }
        #[cfg(not(crabc_initial_tls_graph))]
        R_X86_64_DTPMOD64 | R_X86_64_DTPOFF64 => None,
        // Naming these rejected forms makes this source's boundary auditable:
        // no `DF_STATIC_TLS`/TPOFF admission and no TLSDESC resolver are
        // implied by the GNU-Dynamic DTV implementation above.
        R_X86_64_TPOFF64
        | R_X86_64_GOTTPOFF
        | R_X86_64_TPOFF32
        | R_X86_64_GOTPC32_TLSDESC
        | R_X86_64_TLSDESC_CALL
        | R_X86_64_TLSDESC => None,
        _ => None,
    }
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
    #[cfg(crabc_initial_tls_graph)]
    if len == b"__tls_get_addr".len() && bytes_eq(name, b"__tls_get_addr".as_ptr(), len) {
        return Some(__tls_get_addr as *const () as usize as u64);
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
#[cfg(crabc_initial_tls_graph)]
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

unsafe fn run_initializers(objects: &[Object]) -> Option<()> {
    // The closed dependency graph has already been mapped and relocated.
    // Walking this suffix in reverse produces leaf then mid. Main-image
    // constructor dispatch remains a future CRT handoff boundary.
    for object in objects.iter().rev() {
        for index in 0..object.init_count {
            let initializer = *object.init_array.add(index);
            if initializer == 0 { return None; }
            let initializer_virtual_address = initializer.checked_sub(object.base as usize)? as u64;
            if !virtual_range_in_executable_load(object.phdr, object.phnum, initializer_virtual_address, 1) { return None; }
            let initializer: unsafe extern "C" fn() = core::mem::transmute(initializer);
            initializer();
        }
    }
    Some(())
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

/// Require a PT_TLS initialized prefix to be backed by one readable file
/// segment. `p_memsz` may legitimately extend through BSS, but copying
/// `p_filesz` from that extension would turn a malformed ELF record into a
/// speculative read from whatever virtual mapping happens to follow it.
#[cfg(crabc_initial_tls_graph)]
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

unsafe fn jump(entry: usize, sp: usize) -> ! { core::arch::asm!("mov rsp, {stack}", "jmp {target}", stack = in(reg) sp, target = in(reg) entry, options(noreturn)); }
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
#[no_mangle]
pub extern "C" fn rust_eh_personality() {}
