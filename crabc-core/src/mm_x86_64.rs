//! Deliberately bounded Linux/x86-64 virtual-memory syscall seams.
//!
//! This module exposes only the raw mapping, protection, and unmapping calls
//! used by the staged Rust facade. It intentionally does not expose the
//! broader AArch64 VM policy surface before each x86-specific contract is
//! admitted and proven.

use crate::syscall::{decode, syscall2, syscall3, syscall6, SYS_MMAP, SYS_MPROTECT, SYS_MUNMAP};
use crate::{RawFd, Result};

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
