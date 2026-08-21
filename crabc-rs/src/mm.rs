//! Direct Linux virtual-memory mappings.
//!
//! These raw-pointer operations are intentionally unsafe. Mapping state has no
//! C-runtime identity, but callers must preserve pointer provenance and ensure
//! no Rust references outlive an `munmap` or incompatible `mprotect` call.

use bitflags::bitflags;

use crate::ffi::c_void;
use crate::Result;

bitflags! {
    /// Linux `PROT_*` flags for [`mmap`] and [`mmap_anonymous`].
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct ProtFlags: u32 {
        /// `PROT_READ`.
        const READ = 0x1;
        /// `PROT_WRITE`.
        const WRITE = 0x2;
        /// `PROT_EXEC`.
        const EXEC = 0x4;
        /// Preserve future Linux-defined bits.
        const _ = !0;
    }
}

bitflags! {
    /// Linux `PROT_*` flags for [`mprotect`].
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct MprotectFlags: u32 {
        /// `PROT_READ`.
        const READ = 0x1;
        /// `PROT_WRITE`.
        const WRITE = 0x2;
        /// `PROT_EXEC`.
        const EXEC = 0x4;
        /// `PROT_GROWSUP`.
        const GROWSUP = 0x0200_0000;
        /// `PROT_GROWSDOWN`.
        const GROWSDOWN = 0x0100_0000;
        /// `PROT_SEM`.
        const SEM = 0x8;
        /// `PROT_BTI` on Linux/AArch64.
        const BTI = 0x10;
        /// `PROT_MTE` on Linux/AArch64.
        const MTE = 0x20;
        /// Preserve future Linux-defined bits.
        const _ = !0;
    }
}

bitflags! {
    /// Linux `MAP_*` flags for [`mmap`] and [`mmap_anonymous`].
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct MapFlags: u32 {
        /// `MAP_SHARED`.
        const SHARED = 0x01;
        /// `MAP_PRIVATE`.
        const PRIVATE = 0x02;
        /// `MAP_FIXED`.
        const FIXED = 0x10;
        /// `MAP_FIXED_NOREPLACE`.
        const FIXED_NOREPLACE = 0x0010_0000;
        /// `MAP_GROWSDOWN`.
        const GROWSDOWN = 0x0100;
        /// `MAP_LOCKED`.
        const LOCKED = 0x2000;
        /// `MAP_NORESERVE`.
        const NORESERVE = 0x4000;
        /// `MAP_POPULATE`.
        const POPULATE = 0x8000;
        /// `MAP_STACK`.
        const STACK = 0x0002_0000;
        /// Preserve future Linux-defined bits.
        const _ = !0;
    }
}

/// Creates a file-backed Linux mapping.
///
/// # Safety
///
/// If `ptr` is non-null, it must be page-aligned and valid for the mapped
/// range's mutation requirements. The caller must preserve pointer provenance
/// and Rust reference invariants for the returned range, including when the
/// underlying file is concurrently changed. `offset` must meet the kernel's
/// page-alignment requirement for the selected mapping.
#[inline]
pub unsafe fn mmap<Fd: crate::AsFd>(
    ptr: *mut c_void,
    len: usize,
    prot: ProtFlags,
    flags: MapFlags,
    fd: Fd,
    offset: u64,
) -> Result<*mut c_void> {
    let fd = fd.as_fd();
    // SAFETY: The caller owns the mapping and pointer-provenance contract;
    // `fd` remains borrowed for the duration of the kernel call.
    unsafe {
        crabc_core::mm::mmap_raw(
            ptr.cast(),
            len,
            prot.bits(),
            flags.bits(),
            fd.as_raw_fd(),
            offset,
        )
        .map(|mapping| mapping.cast())
    }
}

/// Creates an anonymous Linux mapping.
///
/// # Safety
///
/// If `ptr` is non-null, it must be page-aligned and valid for the mapped
/// range's mutation requirements. The caller must uphold Rust pointer
/// provenance and reference invariants for the returned mapping.
#[inline]
pub unsafe fn mmap_anonymous(
    ptr: *mut c_void,
    len: usize,
    prot: ProtFlags,
    flags: MapFlags,
) -> Result<*mut c_void> {
    // SAFETY: The caller owns the mapping and pointer-provenance contract.
    unsafe {
        crabc_core::mm::mmap_raw(
            ptr.cast(),
            len,
            prot.bits(),
            flags.bits() | 0x20,
            -1,
            0,
        )
        .map(|mapping| mapping.cast())
    }
}

/// Removes a Linux mapping.
///
/// # Safety
///
/// `ptr..ptr+len` must be a valid mapping range and no Rust references may
/// remain into it.
#[inline]
pub unsafe fn munmap(ptr: *mut c_void, len: usize) -> Result<()> {
    // SAFETY: The caller owns the mapping-lifetime contract.
    unsafe { crabc_core::mm::munmap_raw(ptr.cast(), len) }
}

/// Changes a Linux mapping's protection.
///
/// # Safety
///
/// `ptr..ptr+len` must be a valid mapping range and the caller must preserve
/// Rust's reference invariants after its access permissions change.
#[inline]
pub unsafe fn mprotect(ptr: *mut c_void, len: usize, flags: MprotectFlags) -> Result<()> {
    // SAFETY: The caller owns the mapped-range and provenance contracts.
    unsafe { crabc_core::mm::mprotect_raw(ptr.cast(), len, flags.bits()) }
}
