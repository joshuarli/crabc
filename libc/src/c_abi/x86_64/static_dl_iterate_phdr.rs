//! Static main-image enumeration, translated from musl 1.2.6
//! `src/ldso/dl_iterate_phdr.c:static_dl_iterate_phdr` at release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417` (musl MIT license).
//!
//! Preserve the auxv scan, ordered PT_PHDR/PT_DYNAMIC load-bias selection,
//! /proc/self/exe name, zero generation counters, module-one caller TLS, and
//! direct callback result. The parent supplies musl's weak public entry.
//! Owned CRT's published auxv replaces `libc.auxv`; the immutable static TLS
//! plan replaces musl's DTV lookup. No loader record or dynamic graph is used.

use core::ffi::{c_int, c_void};
use core::{mem, ptr};
use super::DlPhdrInfo;
use super::super::{auxv_observation, static_tls};

// Musl declares _DYNAMIC weak hidden. Static ET_EXEC may have no definition;
// the self-relocating static PIE link supplies it. Keep the address local to
// this final executable and do not create an exported runtime helper.
core::arch::global_asm!(".weak _DYNAMIC", ".hidden _DYNAMIC");

#[repr(C)]
struct ProgramHeader {
    kind: u32,
    flags: u32,
    offset: u64,
    virtual_address: u64,
    physical_address: u64,
    file_size: u64,
    memory_size: u64,
    alignment: u64,
}

/// Visit the already validated main executable on the calling owned thread.
///
/// # Safety
/// Owned static startup must have completed, the caller must have its owned
/// TLS installed, and callback/data must obey the public dl_iterate_phdr ABI.
pub(super) unsafe fn iterate(
    callback: unsafe extern "C" fn(*mut DlPhdrInfo, usize, *mut c_void) -> c_int,
    data: *mut c_void,
) -> c_int {
    let Some(headers) = auxv_observation::initial_program_headers() else {
        return -1;
    };
    let dynamic: usize;
    unsafe {
        core::arch::asm!(
            "lea {dynamic}, [rip + _DYNAMIC]",
            dynamic = out(reg) dynamic,
            options(nostack, preserves_flags, readonly),
        );
    }
    let mut base = 0usize;
    let mut has_tls = false;
    for index in 0..headers.count {
        // SAFETY: static TLS bootstrap validated the complete main phdr table;
        // owned startup subsequently published its immutable kernel auxv.
        let header = unsafe { ptr::read_unaligned(headers.address.add(index * headers.entry_size).cast::<ProgramHeader>()) };
        match header.kind {
            6 => base = (headers.address as usize).wrapping_sub(header.virtual_address as usize), // PT_PHDR
            2 if dynamic != 0 => base = dynamic.wrapping_sub(header.virtual_address as usize), // PT_DYNAMIC
            7 => has_tls = true, // PT_TLS
            _ => {}
        }
    }
    let mut info = DlPhdrInfo {
        dlpi_addr: base,
        dlpi_name: b"/proc/self/exe\0".as_ptr().cast(),
        dlpi_phdr: headers.address.cast(),
        dlpi_phnum: headers.count as u16,
        dlpi_adds: 0,
        dlpi_subs: 0,
        dlpi_tls_modid: usize::from(has_tls),
        dlpi_tls_data: if has_tls { unsafe { static_tls::current_initial_image().cast() } } else { ptr::null_mut() },
    };
    unsafe { callback(&mut info, mem::size_of::<DlPhdrInfo>(), data) }
}

const _: () = assert!(mem::size_of::<ProgramHeader>() == 56);
