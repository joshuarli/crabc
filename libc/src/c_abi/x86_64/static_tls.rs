//! Linux/x86-64 Static Initial TLS v1 owner.
//!
//! This module is the one libc-owned source of truth for the selected static
//! executable's initial TLS template.  The private x86 `rcrt1.o` startup
//! passes the untouched Linux initial stack through its hidden static-link
//! boundary to [`__crabc_x86_static_tls_bootstrap`] before any lifecycle hook or C ABI
//! entry can access `#[thread_local]` storage.  The bootstrap validates the
//! final executable's live `AT_PHDR` program-header table,
//! derives its one optional `PT_TLS` image, materializes that image below an
//! x86 Variant-II thread pointer, and installs the main thread's `%fs` base.
//! It retains the immutable template so the bounded pthread worker can
//! materialize the exact same initialized and TBSS image before it supplies
//! `CLONE_SETTLS` to Linux.
//!
//! Static Initial TLS v1 is deliberately narrower than general TLS: it admits
//! one final executable image with direct local-exec TPOFF accesses and one
//! self-word TCB at `%fs:0`.  It has no module registry, dynamic image growth,
//! loader handoff, or general TCB contract.  The hidden `rcrt1.o` static-link
//! handoff is a private static-PIE composition boundary, not general CRT,
//! loader, or public x86 runtime support.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("x86 Static Initial TLS v1 requires little-endian Linux/x86-64");

use core::ffi::c_int;
use core::sync::atomic::{AtomicU8, Ordering};

use super::raw_syscall;

const AT_NULL: usize = 0;
const AT_PHDR: usize = 3;
const AT_PHENT: usize = 4;
const AT_PHNUM: usize = 5;

const PT_LOAD: u32 = 1;
const PT_PHDR: u32 = 6;
const PT_TLS: u32 = 7;
const PF_R: u32 = 0x4;

const ET_EXEC: u16 = 2;
const EM_X86_64: u16 = 62;
const ELF64_CLASS: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const EV_CURRENT: u32 = 1;
const ELF64_HEADER_SIZE: usize = 64;
const ELF64_PROGRAM_HEADER_SIZE: usize = 56;
const MAX_PROGRAM_HEADERS: usize = 128;
const MAX_INITIAL_POINTERS: usize = 1 << 20;
const MAX_AUXV_ENTRIES: usize = 4_096;

const PROT_READ_WRITE: i64 = 0x3;
const MAP_PRIVATE_ANONYMOUS: i64 = 0x22;
const ARCH_SET_FS: i64 = 0x1002;
const LINUX_ERRNO_MAX: i64 = 4_095;

const TLS_STATE_EMPTY: u8 = 0;
const TLS_STATE_BOOTSTRAPPING: u8 = 1;
const TLS_STATE_READY: u8 = 2;
const TLS_STATE_FAILED: u8 = 3;

/// One validated program-header record from the live final executable.
#[derive(Clone, Copy)]
struct ProgramHeader {
    kind: u32,
    flags: u32,
    file_offset: usize,
    virtual_address: usize,
    file_size: usize,
    memory_size: usize,
    alignment: usize,
}

/// The immutable layout of the final executable's one initial TLS image.
///
/// This intentionally records only what is needed to materialize direct
/// local-exec storage and the concrete self-word TCB.  It is not a loader
/// record, module table, or public ABI type.
#[derive(Clone, Copy)]
struct StaticInitialTlsPlan {
    image: *const u8,
    filesz: usize,
    memsz: usize,
    image_offset_below_tp: usize,
    tp_alignment: usize,
    allocation_size: usize,
}

impl StaticInitialTlsPlan {
    const EMPTY: Self = Self {
        image: core::ptr::null(),
        filesz: 0,
        memsz: 0,
        image_offset_below_tp: 0,
        tp_alignment: 0,
        allocation_size: 0,
    };
}

/// One privately owned materialization of [`StaticInitialTlsPlan`].
///
/// The bounded pthread leaf gives `thread_pointer` to Linux through its
/// private clone seam and may release the mapping only after
/// `CLONE_CHILD_CLEARTID` proves the child cannot access it.
#[derive(Clone, Copy)]
pub(super) struct StaticInitialTlsBlock {
    mapping: *mut u8,
    mapping_size: usize,
    thread_pointer: *mut u8,
}

impl StaticInitialTlsBlock {
    /// Return the x86 Variant-II TP passed as the `CLONE_SETTLS` argument.
    #[inline]
    pub(super) const fn thread_pointer(self) -> *mut u8 {
        self.thread_pointer
    }
}

// The plan is written exactly once by the first-thread bootstrap, then read
// only after the release/acquire state transition below.  Raw pointer access
// deliberately avoids creating references to mutable static storage.
static STATIC_INITIAL_TLS_STATE: AtomicU8 = AtomicU8::new(TLS_STATE_EMPTY);
static mut STATIC_INITIAL_TLS_PLAN: StaticInitialTlsPlan = StaticInitialTlsPlan::EMPTY;

core::arch::global_asm!(
    ".hidden __crabc_x86_static_tls_bootstrap",
    ".section .note.GNU-stack,\"\",@progbits",
);

/// Bootstrap the main thread from the Linux initial stack and retain its TLS
/// template for selected child workers.
///
/// # Safety
///
/// `initial_stack` must designate the untouched Linux/x86-64 entry stack for
/// this final static executable.  The caller must invoke this exactly once,
/// before any code accesses direct TLS or starts another thread.  On success
/// this installs a new `%fs` base for the calling thread.
pub(super) unsafe fn bootstrap_initial_thread(initial_stack: *const usize) -> bool {
    if STATIC_INITIAL_TLS_STATE
        .compare_exchange(
            TLS_STATE_EMPTY,
            TLS_STATE_BOOTSTRAPPING,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        return false;
    }

    let Some(plan) = (unsafe { StaticInitialTlsPlan::from_initial_stack(initial_stack) }) else {
        STATIC_INITIAL_TLS_STATE.store(TLS_STATE_FAILED, Ordering::Release);
        return false;
    };
    let Some(block) = (unsafe { plan.materialize() }) else {
        STATIC_INITIAL_TLS_STATE.store(TLS_STATE_FAILED, Ordering::Release);
        return false;
    };
    if !unsafe { arch_set_fs(block.thread_pointer as usize) } {
        let _ = unsafe { release_thread(block) };
        STATIC_INITIAL_TLS_STATE.store(TLS_STATE_FAILED, Ordering::Release);
        return false;
    }

    // SAFETY: this is the only writer, guarded by the bootstrap state.  The
    // following release store publishes every plan field to child allocators.
    unsafe {
        core::ptr::write_volatile(core::ptr::addr_of_mut!(STATIC_INITIAL_TLS_PLAN), plan);
    }
    STATIC_INITIAL_TLS_STATE.store(TLS_STATE_READY, Ordering::Release);
    true
}

/// Private freestanding entry hook for Static Initial TLS v1.
///
/// It intentionally uses a plain zero/nonzero status instead of C `errno`:
/// this function is called before the initial TLS image exists.  It is hidden
/// from installed headers and is not a general CRT entry point.
///
/// # Safety
///
/// `initial_stack` must meet [`bootstrap_initial_thread`]'s entry-stack and
/// ordering requirements.
#[no_mangle]
pub unsafe extern "C" fn __crabc_x86_static_tls_bootstrap(initial_stack: *const usize) -> c_int {
    if unsafe { bootstrap_initial_thread(initial_stack) } {
        0
    } else {
        -1
    }
}

/// Whether a retained initial TLS template is ready for a selected child.
#[inline]
pub(super) fn is_ready() -> bool {
    STATIC_INITIAL_TLS_STATE.load(Ordering::Acquire) == TLS_STATE_READY
}

/// Materialize one independent child copy of the retained final-image TLS.
///
/// A caller must first observe [`is_ready`].  A failure represents exhausted
/// mapping resources or an impossible retained-plan invariant, never an
/// attempt to synthesize a fallback TLS layout.
pub(super) unsafe fn allocate_thread() -> Option<StaticInitialTlsBlock> {
    if !is_ready() {
        return None;
    }
    // SAFETY: bootstrap writes this immutable plain-Copy plan before the
    // release that `is_ready` acquired.  There is no later writer.
    let plan = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(STATIC_INITIAL_TLS_PLAN)) };
    unsafe { plan.materialize() }
}

/// Release one completed selected-child TLS mapping without changing `errno`.
///
/// # Safety
///
/// The caller must prove that no thread can retain `block.thread_pointer`.
/// For the selected pthread artifact that proof is the observed zero
/// `CLONE_CHILD_CLEARTID` word plus registry withdrawal before reclamation.
pub(super) unsafe fn release_thread(block: StaticInitialTlsBlock) -> i64 {
    unsafe {
        raw_syscall::syscall2(
            raw_syscall::SYS_MUNMAP,
            block.mapping as usize as i64,
            block.mapping_size as i64,
        )
    }
}

impl StaticInitialTlsPlan {
    /// Derive one static-only TLS template from the kernel's entry stack.
    unsafe fn from_initial_stack(initial_stack: *const usize) -> Option<Self> {
        let auxv = unsafe { auxiliary_vector_from_initial_stack(initial_stack) }?;
        unsafe { Self::from_auxv(auxv) }
    }

    /// Derive the plan from live main-executable metadata.
    ///
    /// Every arithmetic and mapped-source claim is checked locally.  In
    /// particular, a `PT_TLS` initialized prefix must be readable file-backed
    /// data rather than merely part of a BSS-expanded `PT_LOAD` mapping.
    unsafe fn from_auxv(auxv: *const usize) -> Option<Self> {
        let phdr_address = unsafe { auxiliary_value(auxv, AT_PHDR) }?;
        let phent = unsafe { auxiliary_value(auxv, AT_PHENT) }?;
        let phnum = unsafe { auxiliary_value(auxv, AT_PHNUM) }?;
        if phdr_address == 0
            || phent != ELF64_PROGRAM_HEADER_SIZE
            || phnum == 0
            || phnum > MAX_PROGRAM_HEADERS
        {
            return None;
        }
        let table_size = phent.checked_mul(phnum)?;
        phdr_address.checked_add(table_size)?;

        let mut program_header_virtual_address = None;
        let mut tls = None;
        for index in 0..phnum {
            let header = unsafe { program_header_at(phdr_address, index) }?;
            match header.kind {
                PT_PHDR => {
                    if program_header_virtual_address.replace(header.virtual_address).is_some() {
                        return None;
                    }
                }
                PT_TLS => {
                    if tls.replace(header).is_some() {
                        return None;
                    }
                }
                _ => {}
            }
        }

        let load_bias = match program_header_virtual_address {
            Some(program_header_virtual_address) => {
                if !unsafe {
                    virtual_range_within_readable_file_load(
                        phdr_address,
                        phnum,
                        program_header_virtual_address,
                        table_size,
                    )
                } {
                    return None;
                }
                phdr_address.checked_sub(program_header_virtual_address)?
            }
            None => unsafe {
                static_executable_load_bias_without_pt_phdr(
                    phdr_address,
                    phent,
                    phnum,
                )
            }?,
        };

        let (image, filesz, memsz, tls_alignment) = match tls {
            Some(header) => {
                let tls_alignment = if header.alignment == 0 { 1 } else { header.alignment };
                if header.file_size > header.memory_size
                    || !tls_alignment.is_power_of_two()
                    || (header.virtual_address & (tls_alignment - 1))
                        != (header.file_offset & (tls_alignment - 1))
                {
                    return None;
                }
                if header.memory_size == 0 {
                    (core::ptr::null(), 0, 0, core::mem::align_of::<usize>())
                } else {
                    if !unsafe {
                        virtual_range_within_load(
                            phdr_address,
                            phnum,
                            header.virtual_address,
                            header.memory_size,
                        )
                    } {
                        return None;
                    }
                    if header.file_size != 0
                        && !unsafe {
                            virtual_range_within_readable_file_load(
                                phdr_address,
                                phnum,
                                header.virtual_address,
                                header.file_size,
                            )
                        }
                    {
                        return None;
                    }
                    let image_address = load_bias.checked_add(header.virtual_address)?;
                    image_address.checked_add(header.file_size)?;
                    image_address.checked_add(header.memory_size)?;
                    (
                        image_address as *const u8,
                        header.file_size,
                        header.memory_size,
                        tls_alignment,
                    )
                }
            }
            None => (core::ptr::null(), 0, 0, core::mem::align_of::<usize>()),
        };

        let image_offset_below_tp = if memsz == 0 {
            0
        } else {
            variant_ii_image_offset(image as usize, memsz, tls_alignment)?
        };
        let tp_alignment = tls_alignment.max(core::mem::align_of::<usize>());
        let allocation_size = image_offset_below_tp
            .checked_add(tp_alignment.checked_sub(1)?)?
            .checked_add(core::mem::size_of::<usize>())?;

        Some(Self {
            image,
            filesz,
            memsz,
            image_offset_below_tp,
            tp_alignment,
            allocation_size,
        })
    }

    /// Allocate one exact image copy and one minimal Variant-II self word.
    unsafe fn materialize(self) -> Option<StaticInitialTlsBlock> {
        let mapping = unsafe { map_anonymous(self.allocation_size) }?;
        let mapping_address = mapping as usize;
        let mapping_end = match mapping_address.checked_add(self.allocation_size) {
            Some(value) => value,
            None => {
                let _ = unsafe { unmap(mapping, self.allocation_size) };
                return None;
            }
        };
        let tp = match mapping_address
            .checked_add(self.image_offset_below_tp)
            .and_then(|address| align_up(address, self.tp_alignment))
        {
            Some(value) => value,
            None => {
                let _ = unsafe { unmap(mapping, self.allocation_size) };
                return None;
            }
        };
        let image_destination = match tp.checked_sub(self.image_offset_below_tp) {
            Some(value) => value,
            None => {
                let _ = unsafe { unmap(mapping, self.allocation_size) };
                return None;
            }
        };
        let image_end = match image_destination.checked_add(self.memsz) {
            Some(value) => value,
            None => {
                let _ = unsafe { unmap(mapping, self.allocation_size) };
                return None;
            }
        };
        let tcb_end = match tp.checked_add(core::mem::size_of::<usize>()) {
            Some(value) => value,
            None => {
                let _ = unsafe { unmap(mapping, self.allocation_size) };
                return None;
            }
        };
        if image_destination < mapping_address || image_end > mapping_end || tcb_end > mapping_end {
            let _ = unsafe { unmap(mapping, self.allocation_size) };
            return None;
        }

        let destination = image_destination as *mut u8;
        if self.filesz != 0 {
            unsafe { copy_bytes(self.image, destination, self.filesz) };
        }
        if self.memsz > self.filesz {
            unsafe {
                zero_bytes(
                    destination.wrapping_add(self.filesz),
                    self.memsz - self.filesz,
                )
            };
        }
        // x86-64 Variant II starts the minimal TCB at TP.  Static Initial TLS
        // v1 owns only this self word, which lets the selected worker identity
        // check read `%fs:0`; a later full runtime owns all other TCB fields.
        unsafe { core::ptr::write_volatile(tp as *mut usize, tp) };

        Some(StaticInitialTlsBlock {
            mapping,
            mapping_size: self.allocation_size,
            thread_pointer: tp as *mut u8,
        })
    }
}

/// Accept the controlled ET_EXEC form that Linux supplies without `PT_PHDR`.
///
/// A freestanding static executable need not carry a `PT_PHDR` record even
/// though Linux still supplies `AT_PHDR`.  In that exact case, this private
/// v1 owner accepts only an ordinary ELF64 header immediately preceding the
/// table (`e_phoff == 64`) and only `ET_EXEC`, whose runtime load bias is
/// precisely zero.  It validates the header against the auxv table shape and
/// proves that header bytes are readable file-backed `PT_LOAD` data before it
/// uses that zero-bias rule.  A non-default header placement, ET_DYN image, or
/// generic no-`PT_PHDR` form remains rejected rather than guessed.
unsafe fn static_executable_load_bias_without_pt_phdr(
    phdr_address: usize,
    phent: usize,
    phnum: usize,
) -> Option<usize> {
    let header_address = phdr_address.checked_sub(ELF64_HEADER_SIZE)?;
    let header = header_address as *const u8;
    if unsafe { core::ptr::read(header) } != 0x7f
        || unsafe { core::ptr::read(header.wrapping_add(1)) } != b'E'
        || unsafe { core::ptr::read(header.wrapping_add(2)) } != b'L'
        || unsafe { core::ptr::read(header.wrapping_add(3)) } != b'F'
        || unsafe { core::ptr::read(header.wrapping_add(4)) } != ELF64_CLASS
        || unsafe { core::ptr::read(header.wrapping_add(5)) } != ELFDATA2LSB
        || unsafe { core::ptr::read(header.wrapping_add(6)) } != EV_CURRENT as u8
        || unsafe { core::ptr::read_unaligned(header.wrapping_add(16).cast::<u16>()) }
            != ET_EXEC
        || unsafe { core::ptr::read_unaligned(header.wrapping_add(18).cast::<u16>()) }
            != EM_X86_64
        || unsafe { core::ptr::read_unaligned(header.wrapping_add(20).cast::<u32>()) }
            != EV_CURRENT
        || unsafe { core::ptr::read_unaligned(header.wrapping_add(32).cast::<u64>()) }
            != ELF64_HEADER_SIZE as u64
        || unsafe { core::ptr::read_unaligned(header.wrapping_add(52).cast::<u16>()) }
            != ELF64_HEADER_SIZE as u16
        || unsafe { core::ptr::read_unaligned(header.wrapping_add(54).cast::<u16>()) }
            != phent as u16
        || unsafe { core::ptr::read_unaligned(header.wrapping_add(56).cast::<u16>()) }
            != phnum as u16
    {
        return None;
    }
    if !unsafe {
        virtual_range_within_readable_file_load(
            phdr_address,
            phnum,
            header_address,
            ELF64_HEADER_SIZE,
        )
    } {
        return None;
    }
    Some(0)
}

/// Locate the auxiliary vector after bounded argv and envp validation.
unsafe fn auxiliary_vector_from_initial_stack(initial_stack: *const usize) -> Option<*const usize> {
    if initial_stack.is_null() {
        return None;
    }
    let argc = unsafe { core::ptr::read(initial_stack) };
    if argc > MAX_INITIAL_POINTERS {
        return None;
    }
    let argv = initial_stack.wrapping_add(1).cast::<*const u8>();
    if !unsafe { core::ptr::read(argv.wrapping_add(argc)) }.is_null() {
        return None;
    }
    let envp = argv.wrapping_add(argc.checked_add(1)?);
    let mut environment_count = 0usize;
    loop {
        if environment_count == MAX_INITIAL_POINTERS {
            return None;
        }
        if unsafe { core::ptr::read(envp.wrapping_add(environment_count)) }.is_null() {
            return Some(envp.wrapping_add(environment_count.checked_add(1)?).cast());
        }
        environment_count += 1;
    }
}

/// Return one auxiliary-vector value, rejecting duplicate required records.
unsafe fn auxiliary_value(auxv: *const usize, wanted: usize) -> Option<usize> {
    if auxv.is_null() {
        return None;
    }
    let mut result = None;
    for index in 0..MAX_AUXV_ENTRIES {
        let entry = index.checked_mul(2)?;
        let address = auxv.wrapping_add(entry);
        let kind = unsafe { core::ptr::read(address) };
        if kind == AT_NULL {
            return result;
        }
        if kind == wanted {
            if result.is_some() {
                return None;
            }
            result = Some(unsafe { core::ptr::read(address.wrapping_add(1)) });
        }
    }
    None
}

/// Read one ELF64 program header from the kernel-designated live table.
unsafe fn program_header_at(table: usize, index: usize) -> Option<ProgramHeader> {
    let offset = index.checked_mul(ELF64_PROGRAM_HEADER_SIZE)?;
    let address = table.checked_add(offset)?;
    let header = address as *const u8;
    Some(ProgramHeader {
        kind: unsafe { core::ptr::read_unaligned(header.cast::<u32>()) },
        flags: unsafe { core::ptr::read_unaligned(header.wrapping_add(4).cast::<u32>()) },
        file_offset: unsafe { core::ptr::read_unaligned(header.wrapping_add(8).cast::<usize>()) },
        virtual_address: unsafe {
            core::ptr::read_unaligned(header.wrapping_add(16).cast::<usize>())
        },
        file_size: unsafe { core::ptr::read_unaligned(header.wrapping_add(32).cast::<usize>()) },
        memory_size: unsafe { core::ptr::read_unaligned(header.wrapping_add(40).cast::<usize>()) },
        alignment: unsafe { core::ptr::read_unaligned(header.wrapping_add(48).cast::<usize>()) },
    })
}

unsafe fn virtual_range_within_load(
    table: usize,
    phnum: usize,
    address: usize,
    length: usize,
) -> bool {
    unsafe { virtual_range_within_load_kind(table, phnum, address, length, false) }
}

unsafe fn virtual_range_within_readable_file_load(
    table: usize,
    phnum: usize,
    address: usize,
    length: usize,
) -> bool {
    unsafe { virtual_range_within_load_kind(table, phnum, address, length, true) }
}

unsafe fn virtual_range_within_load_kind(
    table: usize,
    phnum: usize,
    address: usize,
    length: usize,
    require_readable_file_data: bool,
) -> bool {
    let Some(end) = address.checked_add(length) else {
        return false;
    };
    for index in 0..phnum {
        let Some(header) = (unsafe { program_header_at(table, index) }) else {
            return false;
        };
        if header.kind != PT_LOAD || header.file_size > header.memory_size {
            continue;
        }
        if require_readable_file_data && header.flags & PF_R == 0 {
            continue;
        }
        let range_size = if require_readable_file_data {
            header.file_size
        } else {
            header.memory_size
        };
        let Some(load_end) = header.virtual_address.checked_add(range_size) else {
            return false;
        };
        if address >= header.virtual_address && end <= load_end {
            return true;
        }
    }
    false
}

/// Calculate the exact negative TP placement used by x86 Variant II.
const fn variant_ii_image_offset(
    image_address: usize,
    memory_size: usize,
    alignment: usize,
) -> Option<usize> {
    if alignment == 0 || !alignment.is_power_of_two() {
        return None;
    }
    let mask = alignment - 1;
    let residue = ((memory_size & mask).wrapping_add(image_address & mask)) & mask;
    let padding = alignment.wrapping_sub(residue) & mask;
    memory_size.checked_add(padding)
}

const fn align_up(address: usize, alignment: usize) -> Option<usize> {
    if alignment == 0 || !alignment.is_power_of_two() {
        return None;
    }
    let mask = alignment - 1;
    match address.checked_add(mask) {
        Some(value) => Some(value & !mask),
        None => None,
    }
}

/// Copy with volatile byte operations so bootstrap code cannot acquire an
/// implicit `memcpy` dependency before C startup exists.
unsafe fn copy_bytes(source: *const u8, destination: *mut u8, count: usize) {
    for index in 0..count {
        let byte = unsafe { core::ptr::read_volatile(source.wrapping_add(index)) };
        unsafe { core::ptr::write_volatile(destination.wrapping_add(index), byte) };
    }
}

/// Explicitly zero the TBSS tail after copying the initialized prefix.
unsafe fn zero_bytes(destination: *mut u8, count: usize) {
    for index in 0..count {
        unsafe { core::ptr::write_volatile(destination.wrapping_add(index), 0) };
    }
}

unsafe fn map_anonymous(length: usize) -> Option<*mut u8> {
    let result = unsafe {
        raw_syscall::syscall6(
            raw_syscall::SYS_MMAP,
            0,
            length as i64,
            PROT_READ_WRITE,
            MAP_PRIVATE_ANONYMOUS,
            -1,
            0,
        )
    };
    if is_linux_error(result) || result == 0 {
        None
    } else {
        Some(result as usize as *mut u8)
    }
}

unsafe fn unmap(address: *mut u8, length: usize) -> i64 {
    unsafe {
        raw_syscall::syscall2(
            raw_syscall::SYS_MUNMAP,
            address as usize as i64,
            length as i64,
        )
    }
}

unsafe fn arch_set_fs(thread_pointer: usize) -> bool {
    !is_linux_error(unsafe {
        raw_syscall::syscall2(
            raw_syscall::SYS_ARCH_PRCTL,
            ARCH_SET_FS,
            thread_pointer as i64,
        )
    })
}

#[inline]
fn is_linux_error(value: i64) -> bool {
    value < 0 && value >= -LINUX_ERRNO_MAX
}

// This compile-time witness protects the arithmetic form that a page-aligned
// final PT_TLS image cannot cover: a nonzero runtime image phase stays below
// an aligned Variant-II thread pointer.
const _: () = {
    let image = 0x10_003usize;
    let memsz = 0x20usize;
    let alignment = 0x1_000usize;
    let distance = match variant_ii_image_offset(image, memsz, alignment) {
        Some(distance) => distance,
        None => panic!("valid Variant-II layout rejected"),
    };
    let thread_pointer = match align_up(0x20_000usize + distance, alignment) {
        Some(thread_pointer) => thread_pointer,
        None => panic!("valid Variant-II TP alignment rejected"),
    };
    let destination = match thread_pointer.checked_sub(distance) {
        Some(destination) => destination,
        None => panic!("valid Variant-II image placement underflowed"),
    };

    assert!(distance == 0xffd);
    assert!(distance >= memsz);
    assert!(thread_pointer & (alignment - 1) == 0);
    assert!(destination & (alignment - 1) == image & (alignment - 1));
};
