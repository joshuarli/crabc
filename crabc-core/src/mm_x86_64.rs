//! Deliberately bounded Linux/x86-64 virtual-memory syscall seams.
//!
//! This module exposes only the raw mapping, bounded remapping, protection,
//! and unmapping calls used by the staged Rust facade. It intentionally does
//! not expose the broader AArch64 VM policy surface before each x86-specific
//! contract is admitted and proven.

use crate::syscall::{
    decode, syscall2, syscall3, syscall4, syscall5, syscall6, SYS_MMAP, SYS_MPROTECT,
    SYS_MREMAP, SYS_MUNMAP,
};
use crate::{RawFd, Result};

const MREMAP_FIXED: u32 = 0x2;

/// Creates a mapping with Linux/x86-64's six-word `mmap` syscall ABI.
///
/// # Safety
///
/// This is the unfiltered kernel boundary. The caller must supply Linux-valid
/// arguments: in particular, a nonzero range, page-aligned file offset, and a
/// live file descriptor for a file mapping. If `flags` selects a fixed
/// mapping, `address` must meet Linux's alignment requirements and the caller
/// must ensure that replacing an existing range cannot invalidate any Rust
/// reference. A successful result is usable only with the selected
/// permissions and until a later unmap or protection change. The backing file
/// must not be truncated below bytes that the caller accesses, because Linux
/// can otherwise raise `SIGBUS`.
#[inline]
pub unsafe fn mmap_raw(
    address: *mut u8,
    length: usize,
    protection: u32,
    flags: u32,
    fd: RawFd,
    offset: u64,
) -> Result<*mut u8> {
    // SAFETY: The caller owns the mapping contract. `decode` recognizes only
    // the Linux error range, so valid high-address mappings remain successful
    // pointer values.
    decode(unsafe {
        syscall6(
            SYS_MMAP,
            address as usize,
            length,
            protection as usize,
            flags as usize,
            fd as usize,
            offset as usize,
        )
    })
    .map(|address| address as *mut u8)
}

/// Removes a Linux/x86-64 mapping.
///
/// # Safety
///
/// `address..address + length` must identify a mapped Linux range. No Rust
/// references, slices, or aliases into that range may remain usable after a
/// successful call, including references held by another abstraction.
#[inline]
pub unsafe fn munmap_raw(address: *mut u8, length: usize) -> Result<()> {
    // SAFETY: The caller owns the mapping lifetime/provenance contract.
    decode(unsafe { syscall2(SYS_MUNMAP, address as usize, length) }).map(|_| ())
}

/// Resizes or moves a Linux/x86-64 mapping with the four-argument ABI.
///
/// The x86-64 syscall convention carries the fourth argument in `r10`, which
/// is handled by the generic `syscall4` instruction seam. The facade owns the
/// closed flag policy; this raw operation intentionally forwards the supplied
/// bits unchanged.
///
/// # Safety
///
/// `address` must be page-aligned, and the range beginning there and
/// extending for `old_length` bytes, rounded up to a page boundary, must be a
/// valid mapping owned by the caller. The caller must ensure that
/// `address + old_length` and `address + new_length` do not wrap. There must
/// be no Rust references into the old range when the operation may move it,
/// and callers must treat the old mapping as invalid after a successful call:
/// only the returned address may be used. If the call fails, Linux leaves the
/// old mapping available for cleanup.
#[inline]
pub unsafe fn mremap_raw(
    address: *mut u8,
    old_length: usize,
    new_length: usize,
    flags: u32,
) -> Result<*mut u8> {
    // SAFETY: The caller owns the mapping contract; Linux validates lengths,
    // flags, and the mapping itself.
    decode(unsafe {
        syscall4(
            SYS_MREMAP,
            address as usize,
            old_length,
            new_length,
            flags as usize,
        )
    })
    .map(|address| address as *mut u8)
}

/// Resizes or moves a Linux/x86-64 mapping to a selected destination.
///
/// The kernel receives `MREMAP_FIXED` in addition to `flags`; keeping this
/// constant private prevents the native facade from requesting fixed-address
/// behavior through its ordinary operation.
///
/// # Safety
///
/// `address` and `new_address` must be page-aligned. The old range, rounded
/// up to a page boundary, must be a valid mapping owned by the caller. The
/// destination range must contain no Rust references because Linux may
/// replace it, and neither range calculation may wrap. After success, both
/// input mappings are invalid; only the returned address may be used. If the
/// call fails, the old mapping remains available for cleanup.
#[inline]
pub unsafe fn mremap_fixed_raw(
    address: *mut u8,
    old_length: usize,
    new_length: usize,
    flags: u32,
    new_address: *mut u8,
) -> Result<*mut u8> {
    // SAFETY: The caller owns both mapping contracts; Linux validates the
    // fixed destination and mapping overlap rules.
    decode(unsafe {
        syscall5(
            SYS_MREMAP,
            address as usize,
            old_length,
            new_length,
            (flags | MREMAP_FIXED) as usize,
            new_address as usize,
        )
    })
    .map(|address| address as *mut u8)
}

/// Changes Linux/x86-64 mapping protection.
///
/// # Safety
///
/// `address..address + length` must identify a mapped Linux range. The caller
/// must ensure no live Rust reference is used with permissions incompatible
/// with `flags`; `PROT_NONE` makes every dereference invalid until a later
/// protection change restores access.
#[inline]
pub unsafe fn mprotect_raw(address: *mut u8, length: usize, flags: u32) -> Result<()> {
    // SAFETY: The caller owns the mapped-range and provenance contracts.
    decode(unsafe { syscall3(SYS_MPROTECT, address as usize, length, flags as usize) })
        .map(|_| ())
}
