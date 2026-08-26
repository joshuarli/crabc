//! The deliberately bounded Linux/x86-64 mapping facade.
//!
//! This admission owns only ordinary anonymous/file mappings, protection
//! changes, and unmapping. It deliberately excludes remapping, residency,
//! memory-locking, advice, synchronization, and process-wide VM policy until
//! each has its own x86-64 contract and native evidence.

use bitflags::bitflags;

use crate::ffi::c_void;
use crate::{AsFd, Result};

const MAP_ANONYMOUS: u32 = 0x20;
const SUPPORTED_PROTECTION_BITS: u32 =
    ProtFlags::READ.bits() | ProtFlags::WRITE.bits() | ProtFlags::EXEC.bits();
const SUPPORTED_MAP_BITS: u32 = MapFlags::SHARED.bits() | MapFlags::PRIVATE.bits();

bitflags! {
    /// Linux/x86-64 `PROT_*` flags for [`mmap`] and [`mmap_anonymous`].
    ///
    /// The empty set is the admitted `PROT_NONE` value.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct ProtFlags: u32 {
        /// `PROT_READ`.
        const READ = 0x1;
        /// `PROT_WRITE`.
        const WRITE = 0x2;
        /// `PROT_EXEC`.
        const EXEC = 0x4;
    }
}

bitflags! {
    /// Linux/x86-64 `PROT_*` flags for [`mprotect`].
    ///
    /// The empty set is the admitted `PROT_NONE` value.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct MprotectFlags: u32 {
        /// `PROT_READ`.
        const READ = 0x1;
        /// `PROT_WRITE`.
        const WRITE = 0x2;
        /// `PROT_EXEC`.
        const EXEC = 0x4;
    }
}

bitflags! {
    /// Linux/x86-64 `MAP_*` flags for [`mmap`] and [`mmap_anonymous`].
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct MapFlags: u32 {
        /// `MAP_SHARED`.
        const SHARED = 0x01;
        /// `MAP_PRIVATE`.
        const PRIVATE = 0x02;
    }
}

#[inline]
fn checked_protection_bits(bits: u32) -> Result<u32> {
    if bits & !SUPPORTED_PROTECTION_BITS == 0 {
        Ok(bits)
    } else {
        Err(crate::Errno::INVAL)
    }
}

#[inline]
fn checked_map_bits(flags: MapFlags) -> Result<u32> {
    let bits = flags.bits();
    let kind = bits & SUPPORTED_MAP_BITS;
    if bits & !SUPPORTED_MAP_BITS != 0 || kind == 0 || kind == SUPPORTED_MAP_BITS {
        Err(crate::Errno::INVAL)
    } else {
        Ok(bits)
    }
}

/// Creates a file-backed Linux/x86-64 mapping.
///
/// # Safety
///
/// This facade rejects fixed-map flags, so `ptr` is only a kernel address hint;
/// it has no alignment, liveness, or dereference precondition. `offset` must
/// be page-aligned, and `fd` must name a file Linux can map for the duration
/// of this call. The caller owns the returned mapping's lifetime and must not
/// create Rust references that outlive an unmap or incompatible protection
/// change. The backing file must remain large enough for every accessed byte:
/// truncation can make a later access raise `SIGBUS`.
#[inline]
pub unsafe fn mmap<Fd: AsFd>(
    ptr: *mut c_void,
    len: usize,
    prot: ProtFlags,
    flags: MapFlags,
    fd: Fd,
    offset: u64,
) -> Result<*mut c_void> {
    let prot = checked_protection_bits(prot.bits())?;
    let flags = checked_map_bits(flags)?;
    let fd = fd.as_fd();
    // SAFETY: The caller owns the mapping and pointer-provenance contract;
    // `fd` remains borrowed for the duration of the kernel call.
    unsafe {
        crabc_core::mm::mmap_raw(
            ptr.cast(),
            len,
            prot,
            flags,
            fd.as_raw_fd(),
            offset,
        )
        .map(|mapping| mapping.cast())
    }
}

/// Creates an anonymous Linux/x86-64 mapping.
///
/// # Safety
///
/// This facade rejects fixed-map flags, so `ptr` is only a kernel address hint;
/// it has no alignment, liveness, or dereference precondition. The caller owns
/// the returned mapping's lifetime and must not create Rust references that
/// outlive an unmap or incompatible protection change. An empty `prot` is
/// `PROT_NONE` and must not be dereferenced until later protection restores
/// access.
#[inline]
pub unsafe fn mmap_anonymous(
    ptr: *mut c_void,
    len: usize,
    prot: ProtFlags,
    flags: MapFlags,
) -> Result<*mut c_void> {
    let prot = checked_protection_bits(prot.bits())?;
    let flags = checked_map_bits(flags)?;
    // SAFETY: The caller owns the mapping and pointer-provenance contract.
    unsafe {
        crabc_core::mm::mmap_raw(
            ptr.cast(),
            len,
            prot,
            flags | MAP_ANONYMOUS,
            -1,
            0,
        )
        .map(|mapping| mapping.cast())
    }
}

/// Removes a Linux/x86-64 mapping.
///
/// # Safety
///
/// `ptr..ptr + len` must identify a mapped range. No Rust references, slices,
/// or aliases into the range may remain usable after this call succeeds,
/// including values held by another abstraction.
#[inline]
pub unsafe fn munmap(ptr: *mut c_void, len: usize) -> Result<()> {
    // SAFETY: The caller owns the mapping-lifetime contract.
    unsafe { crabc_core::mm::munmap_raw(ptr.cast(), len) }
}

/// Changes a Linux/x86-64 mapping's protection.
///
/// # Safety
///
/// `ptr..ptr + len` must identify a mapped range. The caller must ensure that
/// no live Rust reference is used with permissions incompatible with `flags`;
/// an empty flag set is `PROT_NONE`, so every dereference is invalid until a
/// later protection change restores access.
#[inline]
pub unsafe fn mprotect(ptr: *mut c_void, len: usize, flags: MprotectFlags) -> Result<()> {
    let flags = checked_protection_bits(flags.bits())?;
    // SAFETY: The caller owns the mapped-range and provenance contracts.
    unsafe { crabc_core::mm::mprotect_raw(ptr.cast(), len, flags) }
}
