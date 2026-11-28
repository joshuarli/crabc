//! Darwin memory mappings over libSystem.
//!
//! The raw functions have the names and shapes of the `crabc-core` mapping
//! seam, so the facade module [`crate::mm`] keeps one body for each
//! operation both targets share and re-exports the Darwin vocabulary below.

use core::ffi::{c_int, c_void};

use super::errno::{self, Errno, Result};
use super::sys;
use crate::mm::{MapFlags, PosixAdvice, ProtFlags};
use crate::RawFd;

const _: () = {
    assert!(ProtFlags::READ.bits() == sys::PROT_READ.cast_unsigned());
    assert!(ProtFlags::WRITE.bits() == sys::PROT_WRITE.cast_unsigned());
    assert!(ProtFlags::EXEC.bits() == sys::PROT_EXEC.cast_unsigned());
    assert!(MapFlags::SHARED.bits() == sys::MAP_SHARED.cast_unsigned());
    assert!(MapFlags::PRIVATE.bits() == sys::MAP_PRIVATE.cast_unsigned());
    assert!(PosixAdvice::Normal as c_int == sys::POSIX_MADV_NORMAL);
    assert!(PosixAdvice::Random as c_int == sys::POSIX_MADV_RANDOM);
    assert!(PosixAdvice::Sequential as c_int == sys::POSIX_MADV_SEQUENTIAL);
    assert!(PosixAdvice::WillNeed as c_int == sys::POSIX_MADV_WILLNEED);
    assert!(PosixAdvice::DontNeed as c_int == sys::POSIX_MADV_DONTNEED);
};

/// `MAP_ANON`, which the facade adds for anonymous mappings.
pub(crate) const MAP_ANONYMOUS: u32 = sys::MAP_ANON.cast_unsigned();

bitflags::bitflags! {
    /// Darwin `MS_*` flags for [`crate::mm::msync`].
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct MsyncFlags: u32 {
        /// `MS_ASYNC`: schedule an update and return without waiting.
        const ASYNC = sys::MS_ASYNC.cast_unsigned();
        /// `MS_INVALIDATE`: invalidate other cached mappings of the file.
        const INVALIDATE = sys::MS_INVALIDATE.cast_unsigned();
        /// `MS_SYNC`: update the backing storage and wait for completion.
        const SYNC = sys::MS_SYNC.cast_unsigned();
        /// Preserve unknown bits for libSystem validation.
        const _ = !0;
    }
}

/// Darwin `madvise` policies exposed by this facade.
///
/// Linux's page-discarding `LinuxDontNeed` is absent: Darwin's
/// `MADV_DONTNEED` keeps page contents, so no Darwin policy matches it.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u32)]
pub enum Advice {
    /// `MADV_NORMAL`.
    Normal = sys::MADV_NORMAL as u32,
    /// `MADV_RANDOM`.
    Random = sys::MADV_RANDOM as u32,
    /// `MADV_SEQUENTIAL`.
    Sequential = sys::MADV_SEQUENTIAL as u32,
    /// `MADV_WILLNEED`.
    WillNeed = sys::MADV_WILLNEED as u32,
}

/// The base page size of an Apple Silicon process, 16 KiB, which sizes a
/// [`mincore`] output vector.
pub const MINCORE_PAGE_SIZE: usize = sys::PAGE_SIZE;

/// `mmap(address, length, protection, flags, fd, offset)`.
///
/// An offset above `i64::MAX` fails with [`Errno::INVAL`], as a negative
/// `off_t` does.
///
/// # Safety
///
/// The caller owns the mapping contract of [`crate::mm::mmap`].
#[inline]
pub(crate) unsafe fn mmap_raw(
    address: *mut u8,
    length: usize,
    protection: u32,
    flags: u32,
    fd: RawFd,
    offset: u64,
) -> Result<*mut u8> {
    let offset = sys::off_t::try_from(offset).map_err(|_| Errno::INVAL)?;
    // SAFETY: the caller owns the mapping contract; `address` is only a hint
    // because the facade admits no fixed-map flag.
    let mapping = unsafe {
        sys::mmap(
            address.cast(),
            length,
            protection.cast_signed(),
            flags.cast_signed(),
            fd,
            offset,
        )
    };
    if mapping.addr() == usize::MAX {
        return Err(errno::last());
    }
    Ok(mapping.cast())
}

/// `munmap(address, length)`.
///
/// # Safety
///
/// The caller owns the mapping-lifetime contract of [`crate::mm::munmap`].
#[inline]
pub(crate) unsafe fn munmap_raw(address: *mut u8, length: usize) -> Result<()> {
    // SAFETY: the caller owns the mapping-lifetime contract.
    errno::check(unsafe { sys::munmap(address.cast(), length) }).map(|_| ())
}

/// `mprotect(address, length, protection)`.
///
/// # Safety
///
/// The caller owns the mapped-range contract of [`crate::mm::mprotect`].
#[inline]
pub(crate) unsafe fn mprotect_raw(address: *mut u8, length: usize, flags: u32) -> Result<()> {
    // SAFETY: the caller owns the mapped-range and provenance contracts.
    errno::check(unsafe { sys::mprotect(address.cast(), length, flags.cast_signed()) }).map(|_| ())
}

/// `mlock(address, length)`.
///
/// # Safety
///
/// The caller owns the mapped-range contract of [`crate::mm::mlock`].
#[inline]
pub(crate) unsafe fn mlock_raw(address: *mut u8, length: usize) -> Result<()> {
    // SAFETY: the caller owns the mapped-range and provenance contract.
    errno::check(unsafe { sys::mlock(address.cast_const().cast(), length) }).map(|_| ())
}

/// `munlock(address, length)`.
///
/// # Safety
///
/// The caller owns the mapped-range contract of [`crate::mm::munlock`].
#[inline]
pub(crate) unsafe fn munlock_raw(address: *mut u8, length: usize) -> Result<()> {
    // SAFETY: the caller owns the mapped-range and provenance contract.
    errno::check(unsafe { sys::munlock(address.cast_const().cast(), length) }).map(|_| ())
}

/// `msync(address, length, flags)`.
///
/// # Safety
///
/// The caller owns the mapped-range contract of [`crate::mm::msync`].
#[inline]
pub(crate) unsafe fn msync_raw(address: *mut u8, length: usize, flags: u32) -> Result<()> {
    // SAFETY: the caller owns the mapped-range and provenance contracts.
    errno::check(unsafe { sys::msync(address.cast(), length, flags.cast_signed()) }).map(|_| ())
}

/// `madvise(address, length, advice)`.
///
/// # Safety
///
/// The caller owns the mapped-range contract of [`crate::mm::madvise`].
#[inline]
pub(crate) unsafe fn madvise_raw(address: *mut u8, length: usize, advice: u32) -> Result<()> {
    // SAFETY: the caller owns the mapped-range and provenance contract.
    errno::check(unsafe { sys::madvise(address.cast(), length, advice.cast_signed()) }).map(|_| ())
}

/// `posix_madvise(address, length, advice)`.
///
/// libSystem's `posix_madvise` reports failure through `errno`, not through
/// its return value as POSIX specifies.
///
/// # Safety
///
/// The caller owns the mapped-range contract of [`crate::mm::posix_madvise`].
#[inline]
pub(crate) unsafe fn posix_madvise_raw(
    address: *mut u8,
    length: usize,
    advice: u32,
) -> Result<()> {
    // SAFETY: the caller owns the mapped-range and provenance contract.
    let result = unsafe { sys::posix_madvise(address.cast(), length, advice.cast_signed()) };
    errno::check(result).map(|_| ())
}

/// Queries the residency of each page intersecting a mapped range.
///
/// XNU rounds `ptr` down and `ptr + len` up to page boundaries and writes one
/// byte per page in that span: bit zero reports whether the page is
/// resident, and the other `MINCORE_*` bits report reference, modification
/// and sharing state. `residency` must hold at least that many bytes, counted
/// with the process page size; bytes after them are left untouched. A short
/// output or a span that overflows fails with [`Errno::INVAL`] before the
/// call.
///
/// # Safety
///
/// The page-rounded span of `ptr..ptr + len` must remain mapped for the
/// duration of the call. `residency` must remain exclusively borrowed,
/// writable, and disjoint from the queried mapping for the duration of the
/// call, and the caller must not inspect it until this function returns.
#[inline]
pub unsafe fn mincore(ptr: *mut c_void, len: usize, residency: &mut [u8]) -> Result<()> {
    let page = usize::try_from(sys::getpagesize()).map_err(|_| Errno::IO)?;
    if !page.is_power_of_two() {
        return Err(Errno::IO);
    }
    let required = (ptr.addr() & (page - 1))
        .checked_add(len)
        .and_then(|span| span.checked_add(page - 1))
        .map(|rounded| rounded / page)
        .ok_or(Errno::INVAL)?;
    if residency.len() < required {
        return Err(Errno::INVAL);
    }
    // SAFETY: the length check covers every page XNU reports for the
    // page-rounded span, so it writes only inside `residency`; the caller
    // supplies the mapped-range contract.
    let result = unsafe { sys::mincore(ptr.cast_const(), len, residency.as_mut_ptr().cast()) };
    errno::check(result).map(|_| ())
}
