//! Private Linux/x86-64 first-thread static-TLS bootstrap.
//!
//! `rcrt1.o` reaches this module only after it has relocated its own image
//! and before it enters any lifecycle hook.  The module materializes the main
//! executable's one `PT_TLS` image below an x86 Variant-II thread pointer,
//! writes the self word expected at `%fs:0`, then asks Linux to install that
//! pointer with `ARCH_SET_FS`.
//!
//! This is deliberately not an x86 pthread or dynamic-TLS ABI.  It owns no
//! DTV, module IDs, `__tls_get_addr`, clone-time TLS setup, dynamic growth, or
//! allocation reclamation.  Those contracts remain with the future libc and
//! loader runtime owners.

use core::arch::asm;

const AT_NULL: usize = 0;
const AT_PHDR: usize = 3;
const AT_PHENT: usize = 4;
const AT_PHNUM: usize = 5;

const PT_LOAD: u32 = 1;
const PT_PHDR: u32 = 6;
const PT_TLS: u32 = 7;
const PF_R: u32 = 0x4;

const ELF64_PROGRAM_HEADER_SIZE: usize = 56;
const MAX_PROGRAM_HEADERS: usize = 128;
const MAX_AUXV_ENTRIES: usize = 4_096;

const PROT_READ_WRITE: usize = 0x3;
const MAP_PRIVATE_ANONYMOUS: usize = 0x22;
const ARCH_SET_FS: usize = 0x1002;
const SYS_MMAP: usize = 9;
const SYS_MUNMAP: usize = 11;
const SYS_ARCH_PRCTL: usize = 158;
const LINUX_ERROR_COUNT: usize = 4_095;

/// One validated program-header record from the live main executable.
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

/// A private plan for exactly one initial static TLS image.
///
/// The plan has enough information to materialize the initial thread but is
/// intentionally not stored or published.  In particular it freezes neither
/// a general TCB size nor a loader-facing TLS record layout.
#[derive(Clone, Copy)]
struct StaticInitialTlsPlan {
    image: *const u8,
    filesz: usize,
    memsz: usize,
    image_offset_below_tp: usize,
    tp_alignment: usize,
    allocation_size: usize,
}

/// Install the executable's initial local-exec TLS image for this one thread.
///
/// # Safety
///
/// `auxv` must be the terminated Linux auxiliary vector belonging to the
/// untouched initial process stack.  On success this changes the current
/// thread's `%fs` base; no code that depends on an existing x86 TLS contract
/// may run concurrently with the call.
pub(super) unsafe fn install_initial_static_tls(auxv: *const usize) -> bool {
    let Some(plan) = (unsafe { StaticInitialTlsPlan::from_auxv(auxv) }) else {
        return false;
    };
    unsafe { plan.install() }
}

impl StaticInitialTlsPlan {
    /// Derive a static-only TLS plan from Linux's main-executable metadata.
    ///
    /// The auxiliary-vector and program-header table bounds are rechecked
    /// locally instead of relying on the earlier relocation bootstrap.  The
    /// TLS image must be wholly represented by one mapped `PT_LOAD` range;
    /// arithmetic alone would not prove the runtime source is readable.
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

        let program_header_virtual_address = program_header_virtual_address?;
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
        let load_bias = phdr_address.checked_sub(program_header_virtual_address)?;

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
                    (image_address as *const u8, header.file_size, header.memory_size, tls_alignment)
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

    /// Map, initialize, and install the one initial TLS allocation.
    unsafe fn install(self) -> bool {
        let mapping = unsafe { map_anonymous(self.allocation_size) };
        if mapping.is_null() {
            return false;
        }
        let mapping_address = mapping as usize;
        let Some(mapping_end) = mapping_address.checked_add(self.allocation_size) else {
            unsafe { unmap(mapping, self.allocation_size) };
            return false;
        };
        let Some(tp) = mapping_address
            .checked_add(self.image_offset_below_tp)
            .and_then(|address| align_up(address, self.tp_alignment))
        else {
            unsafe { unmap(mapping, self.allocation_size) };
            return false;
        };
        let Some(image_destination) = tp.checked_sub(self.image_offset_below_tp) else {
            unsafe { unmap(mapping, self.allocation_size) };
            return false;
        };
        let Some(image_end) = image_destination.checked_add(self.memsz) else {
            unsafe { unmap(mapping, self.allocation_size) };
            return false;
        };
        let Some(tcb_end) = tp.checked_add(core::mem::size_of::<usize>()) else {
            unsafe { unmap(mapping, self.allocation_size) };
            return false;
        };
        if image_destination < mapping_address || image_end > mapping_end || tcb_end > mapping_end {
            unsafe { unmap(mapping, self.allocation_size) };
            return false;
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
        // x86-64 Variant II starts the TCB at TP.  This deliberately supplies
        // only its self word; future libc/ldso work owns every other TCB field.
        unsafe { core::ptr::write_volatile(tp as *mut usize, tp) };

        if unsafe { arch_set_fs(tp) } {
            true
        } else {
            unsafe { unmap(mapping, self.allocation_size) };
            false
        }
    }
}

/// Return one auxiliary-vector value, rejecting duplicate required entries.
///
/// The kernel provides the initial vector, but a duplicate `AT_PHDR`,
/// `AT_PHENT`, or `AT_PHNUM` would make the bootstrap's source ambiguous, so
/// malformed input fails closed.
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
        virtual_address: unsafe { core::ptr::read_unaligned(header.wrapping_add(16).cast::<usize>()) },
        file_size: unsafe { core::ptr::read_unaligned(header.wrapping_add(32).cast::<usize>()) },
        memory_size: unsafe { core::ptr::read_unaligned(header.wrapping_add(40).cast::<usize>()) },
        alignment: unsafe { core::ptr::read_unaligned(header.wrapping_add(48).cast::<usize>()) },
    })
}

/// Check a virtual range against one valid `PT_LOAD` mapping in this image.
unsafe fn virtual_range_within_load(
    table: usize,
    phnum: usize,
    address: usize,
    length: usize,
) -> bool {
    unsafe { virtual_range_within_load_kind(table, phnum, address, length, false) }
}

/// Check a virtual source range against readable, file-backed `PT_LOAD` data.
///
/// The initialized portion of a TLS image must not be copied from a BSS tail
/// merely because that tail is mapped.  This check is separate from the
/// `p_memsz` check used for the complete TLS allocation range.
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
///
/// A local-exec `@tpoff` displacement is relative to a TP aligned to the
/// TLS segment's `p_align`.  The image begins below TP, but retains the same
/// alignment residue as its linked runtime image.  This is the bounded
/// one-module form of musl's x86 initial static-TLS placement rule.
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
    match memory_size.checked_add(padding) {
        Some(offset) => Some(offset),
        None => None,
    }
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

/// Copy with volatile byte operations so the CRT object cannot acquire an
/// implicit compiler `memcpy` runtime dependency before libc exists.
unsafe fn copy_bytes(source: *const u8, destination: *mut u8, count: usize) {
    for index in 0..count {
        let byte = unsafe { core::ptr::read_volatile(source.wrapping_add(index)) };
        unsafe { core::ptr::write_volatile(destination.wrapping_add(index), byte) };
    }
}

/// Zero with volatile byte operations for the same pre-libc reason as copy.
unsafe fn zero_bytes(destination: *mut u8, count: usize) {
    for index in 0..count {
        unsafe { core::ptr::write_volatile(destination.wrapping_add(index), 0) };
    }
}

unsafe fn map_anonymous(length: usize) -> *mut u8 {
    let result = unsafe {
        syscall6(
            SYS_MMAP,
            0,
            length,
            PROT_READ_WRITE,
            MAP_PRIVATE_ANONYMOUS,
            usize::MAX,
            0,
        )
    };
    let address = result as usize;
    if is_linux_error(address) {
        core::ptr::null_mut()
    } else {
        address as *mut u8
    }
}

unsafe fn unmap(address: *mut u8, length: usize) {
    let _ = unsafe { syscall2(SYS_MUNMAP, address as usize, length) };
}

unsafe fn arch_set_fs(thread_pointer: usize) -> bool {
    !is_linux_error(unsafe { syscall2(SYS_ARCH_PRCTL, ARCH_SET_FS, thread_pointer) } as usize)
}

fn is_linux_error(value: usize) -> bool {
    value >= usize::MAX - LINUX_ERROR_COUNT + 1
}

unsafe fn syscall2(number: usize, argument1: usize, argument2: usize) -> isize {
    let result: isize;
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") number as isize => result,
            in("rdi") argument1,
            in("rsi") argument2,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    result
}

unsafe fn syscall6(
    number: usize,
    argument1: usize,
    argument2: usize,
    argument3: usize,
    argument4: usize,
    argument5: usize,
    argument6: usize,
) -> isize {
    let result: isize;
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") number as isize => result,
            in("rdi") argument1,
            in("rsi") argument2,
            in("rdx") argument3,
            in("r10") argument4,
            in("r8") argument5,
            in("r9") argument6,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    result
}

// This compile-time witness protects the arithmetic form that the native
// fixture's page-aligned PT_TLS image cannot cover: a valid nonzero runtime
// image phase must be preserved below an aligned Variant-II thread pointer.
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
