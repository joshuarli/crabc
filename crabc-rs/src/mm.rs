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
    /// Linux `MS_*` flags for [`msync`].
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct MsyncFlags: u32 {
        /// `MS_ASYNC`: schedule an update and return without waiting.
        const ASYNC = 0x1;
        /// `MS_INVALIDATE`: invalidate other cached mappings of the file.
        const INVALIDATE = 0x2;
        /// `MS_SYNC`: update the backing storage and wait for completion.
        const SYNC = 0x4;
        /// Preserve future Linux-defined bits; the kernel validates them.
        const _ = !0;
    }
}

bitflags! {
    /// Linux `MLOCK_*` flags for [`mlock_with`].
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct MlockFlags: u32 {
        /// `MLOCK_ONFAULT`: defer locking each page until its first fault.
        const ONFAULT = 0x1;
        /// Preserve future Linux-defined bits; the kernel validates them.
        const _ = !0;
    }
}

bitflags! {
    /// Linux `MCL_*` flags accepted by [`mlockall`].
    ///
    /// This operation changes process-global VM policy.  The flags remain a
    /// closed Rust value so an unrelated integer cannot silently request a
    /// different policy at the syscall boundary.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct MlockAllFlags: u32 {
        /// Lock pages currently mapped into the process.
        const CURRENT = 0x1;
        /// Lock pages mapped by the process in the future.
        const FUTURE = 0x2;
        /// Defer locking until pages are faulted in.
        const ONFAULT = 0x4;
    }
}

/// POSIX advisory policies accepted by [`posix_madvise`].
///
/// This is separate from [`Advice`]: Linux's `MADV_DONTNEED` can discard
/// private anonymous page contents, while POSIX `POSIX_MADV_DONTNEED` is only
/// an access-pattern advisory.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u32)]
pub enum PosixAdvice {
    /// `POSIX_MADV_NORMAL`.
    Normal = 0,
    /// `POSIX_MADV_RANDOM`.
    Random = 1,
    /// `POSIX_MADV_SEQUENTIAL`.
    Sequential = 2,
    /// `POSIX_MADV_WILLNEED`.
    WillNeed = 3,
    /// `POSIX_MADV_DONTNEED`.
    DontNeed = 4,
}

bitflags! {
    /// The bounded `MREMAP_*` flags accepted by [`mremap`] and
    /// [`mremap_fixed`].
    ///
    /// `MREMAP_FIXED` is deliberately not a value in this set: callers use
    /// [`mremap_fixed`] when they need a selected destination, and that
    /// operation adds the kernel's fixed-address bit at its syscall boundary.
    /// `MREMAP_DONTUNMAP` is also outside this first slice because it changes
    /// the ordinary mremap guarantee that the old range is invalid after a
    /// successful move.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct MremapFlags: u32 {
        /// `MREMAP_MAYMOVE`: permit Linux to relocate the mapping.
        const MAYMOVE = 0x1;
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

/// Closed Linux `madvise` policies exposed by this native facade.
///
/// `LinuxDontNeed` has Linux's page-discarding behavior; it is deliberately
/// named separately from POSIX's advisory `DONTNEED` policy.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u32)]
pub enum Advice {
    /// `MADV_NORMAL`.
    Normal = 0,
    /// `MADV_RANDOM`.
    Random = 1,
    /// `MADV_SEQUENTIAL`.
    Sequential = 2,
    /// `MADV_WILLNEED`.
    WillNeed = 3,
    /// `MADV_DONTNEED`: discard private anonymous pages on next access.
    LinuxDontNeed = 4,
}

/// The smallest Linux page size supported by the AArch64 ABI.
///
/// `mincore` writes one output byte per kernel page. Using the minimum page
/// size here makes [`mincore`]'s caller-owned output check a safe upper bound
/// on the supported AArch64 kernels; a kernel configured with larger pages
/// writes fewer bytes and leaves the remainder untouched.
pub const MINCORE_PAGE_SIZE: usize = 4096;

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
        crabc_core::mm::mmap_raw(ptr.cast(), len, prot.bits(), flags.bits() | 0x20, -1, 0)
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

#[inline]
fn checked_mremap_flags(flags: MremapFlags) -> Result<u32> {
    let bits = flags.bits();
    if bits & !MremapFlags::MAYMOVE.bits() != 0 {
        Err(crate::Errno::INVAL)
    } else {
        Ok(bits)
    }
}

/// Resizes or moves a Linux mapping.
///
/// This is the direct Rust counterpart of the ordinary Rustix `mremap`
/// operation. It returns the successor address rather than a C sentinel and
/// never reads or writes C thread-local `errno`.
///
/// # Safety
///
/// `ptr` must be page-aligned and identify a mapping owned by the caller. The
/// range beginning at `ptr` and extending for `old_len` bytes, rounded up to
/// a page boundary, must remain valid for the syscall; the address arithmetic
/// for both old and new ranges must not wrap. There must be no Rust references
/// into the old range while this operation runs. On success, the old mapping
/// is consumed: Linux may have moved it when [`MremapFlags::MAYMOVE`] is set,
/// and the caller must invalidate every use of `ptr` and use only the
/// returned address, even when the numeric address is unchanged. A failed
/// call leaves the old mapping available for cleanup.
#[inline]
pub unsafe fn mremap(
    ptr: *mut c_void,
    old_len: usize,
    new_len: usize,
    flags: MremapFlags,
) -> Result<*mut c_void> {
    let flags = checked_mremap_flags(flags)?;

    // SAFETY: The caller owns the mapping lifetime/provenance contract and
    // must invalidate the old pointer after a successful operation.
    unsafe {
        crabc_core::mm::mremap_raw(ptr.cast(), old_len, new_len, flags)
            .map(|mapping| mapping.cast())
    }
}

/// Resizes or moves a Linux mapping to a caller-selected address.
///
/// This is the fixed-address counterpart of [`mremap`]. The fixed-address
/// kernel flag is added only here, so [`MremapFlags`] remains a closed set for
/// the non-fixed operation.
///
/// # Safety
///
/// `ptr` and `new_ptr` must be page-aligned. The old range beginning at `ptr`,
/// rounded up to a page boundary, must be a valid mapping owned by the caller;
/// the destination range beginning at `new_ptr` must have valid pointer
/// provenance, must not overlap the old range, and must contain no Rust
/// references because Linux may replace it. Neither range calculation may
/// wrap, and no Rust references may point into either range during the call.
/// On success, the old mapping and any destination mapping replaced by Linux
/// are invalidated; the caller must discard both input pointers and use only
/// the returned address. A failed call leaves the old mapping available for
/// cleanup.
#[inline]
pub unsafe fn mremap_fixed(
    ptr: *mut c_void,
    old_len: usize,
    new_len: usize,
    flags: MremapFlags,
    new_ptr: *mut c_void,
) -> Result<*mut c_void> {
    let flags = checked_mremap_flags(flags)?;

    // SAFETY: The caller owns both mapping lifetime/provenance contracts and
    // must invalidate both input pointers after a successful operation.
    unsafe {
        crabc_core::mm::mremap_fixed_raw(ptr.cast(), old_len, new_len, flags, new_ptr.cast())
            .map(|mapping| mapping.cast())
    }
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

/// Locks a mapped range into memory with Linux `mlock`.
///
/// This native Rust operation returns the direct kernel [`Result`] and never
/// writes C thread-local `errno` or uses a C ABI sentinel return value. Linux
/// rounds an unaligned range down/up to page boundaries, so the caller must
/// account for the complete rounded range when establishing its mapping and
/// memlock budget.
///
/// # Safety
///
/// The range beginning at `ptr`, rounded down to the applicable page boundary
/// and extending for `len` bytes rounded up to a page boundary, must remain
/// mapped and readable for the duration of the call. The rounded address range
/// must not overflow. The caller must preserve pointer provenance and Rust
/// reference invariants for the mapped range. Linux may return
/// [`crate::Errno::AGAIN`] or [`crate::Errno::NOMEM`] when the process's
/// memlock limit cannot accommodate the range.
#[inline]
pub unsafe fn mlock(ptr: *mut c_void, len: usize) -> Result<()> {
    // SAFETY: The caller owns the mapped-range and provenance contract.
    unsafe { crabc_core::mm::mlock_raw(ptr.cast(), len) }
}

/// Locks a mapped range into memory with Linux `mlock2` flags.
///
/// `MlockFlags::ONFAULT` requests Linux's deferred page-locking policy. This
/// native Rust operation returns the direct kernel [`Result`] and never writes
/// C thread-local `errno` or uses a C ABI sentinel return value.
///
/// # Safety
///
/// The range beginning at `ptr`, rounded down to the applicable page boundary
/// and extending for `len` bytes rounded up to a page boundary, must remain
/// mapped and readable for the duration of the call. The rounded address range
/// must not overflow. The caller must preserve pointer provenance and Rust
/// reference invariants for the mapped range. Unsupported flags are returned
/// as [`crate::Errno::INVAL`] by Linux.
#[inline]
pub unsafe fn mlock_with(ptr: *mut c_void, len: usize, flags: MlockFlags) -> Result<()> {
    // SAFETY: The caller owns the mapped-range and provenance contract.
    unsafe { crabc_core::mm::mlock2_raw(ptr.cast(), len, flags.bits()) }
}

/// Unlocks a previously locked mapped range with Linux `munlock`.
///
/// This native Rust operation returns the direct kernel [`Result`] and never
/// writes C thread-local `errno` or uses a C ABI sentinel return value. Linux
/// rounds an unaligned range down/up to page boundaries.
///
/// # Safety
///
/// The range beginning at `ptr`, rounded down to the applicable page boundary
/// and extending for `len` bytes rounded up to a page boundary, must remain
/// mapped for the duration of the call. The rounded address range must not
/// overflow. The caller must preserve pointer provenance and Rust reference
/// invariants for the mapped range.
#[inline]
pub unsafe fn munlock(ptr: *mut c_void, len: usize) -> Result<()> {
    // SAFETY: The caller owns the mapped-range and provenance contract.
    unsafe { crabc_core::mm::munlock_raw(ptr.cast(), len) }
}

/// Locks all current and/or future mappings in the calling process.
///
/// This operation is process-global rather than tied to one mapping.  The
/// caller must account for its effect on every thread and mapping in the
/// process, and must expect Linux to reject the request when the memlock
/// budget or flag combination is unavailable.  It never calls the public C
/// ABI or writes C thread-local `errno`.
#[inline]
pub fn mlockall(flags: MlockAllFlags) -> Result<()> {
    crabc_core::mm::mlockall_raw(flags.bits())
}

/// Removes all process-wide memory-lock policy.
#[inline]
pub fn munlockall() -> Result<()> {
    crabc_core::mm::munlockall_raw()
}

/// Synchronizes a mapped range with its backing storage.
///
/// This native Rust operation returns the direct kernel [`Result`] and never
/// writes C thread-local `errno` or uses a C ABI sentinel return value.
/// `MsyncFlags::SYNC` waits for modified file-backed pages to reach storage;
/// `MsyncFlags::ASYNC` schedules the update, and `MsyncFlags::INVALIDATE`
/// requests invalidation of other cached mappings.
///
/// # Safety
///
/// `ptr` must be page-aligned and identify a valid mapped range of `len`
/// bytes. `len` must be non-zero, and the mapping must remain valid for the
/// duration of the call. The caller must preserve pointer provenance and Rust
/// reference invariants across an operation which may write mapped contents
/// back to its backing storage or invalidate cached data. Invalid flag
/// combinations are returned as [`crate::Errno::INVAL`].
#[inline]
pub unsafe fn msync(ptr: *mut c_void, len: usize, flags: MsyncFlags) -> Result<()> {
    // SAFETY: The caller owns the mapped-range and provenance contract.
    unsafe { crabc_core::mm::msync_raw(ptr.cast(), len, flags.bits()) }
}

/// Gives Linux an access-pattern or page-discarding advisory for a mapping.
///
/// # Safety
///
/// `ptr` must be page-aligned and identify the first byte of a valid mapped
/// range. `len` must be non-zero, and `ptr..ptr+len` must not overflow or
/// leave the mapping during the call. The caller must preserve pointer
/// provenance and must not rely on Rust references or typed contents across
/// advice that can discard or alter pages, including [`Advice::LinuxDontNeed`].
/// Linux rounds a final partial page according to its `madvise` ABI.
#[inline]
pub unsafe fn madvise(ptr: *mut c_void, len: usize, advice: Advice) -> Result<()> {
    // SAFETY: The caller owns the mapped-range and provenance contract.
    unsafe { crabc_core::mm::madvise_raw(ptr.cast(), len, advice as u32) }
}

/// Gives Linux the POSIX access-pattern advisory for a mapped range.
///
/// Unlike [`madvise`], this operation exposes only the POSIX policy set and
/// does not name Linux's page-discarding `MADV_DONTNEED` behavior.  The
/// operation remains unsafe because the pointer and mapped-range contract is
/// still supplied by the caller; errors are direct Linux [`crate::Errno`]
/// values rather than C `errno` state.
#[inline]
pub unsafe fn posix_madvise(ptr: *mut c_void, len: usize, advice: PosixAdvice) -> Result<()> {
    // SAFETY: The caller owns the mapped-range and pointer-provenance
    // contract. The typed advice is one of POSIX's five policies.
    unsafe { crabc_core::mm::posix_madvise_raw(ptr.cast(), len, advice as u32) }
}

/// Remaps pages in a legacy file-backed mapping.
///
/// The legacy C ABI carries protection and flags words, but the native
/// contract deliberately fixes both compatibility fields to zero.  The
/// operation can change which file pages a mapped address observes and is
/// therefore unsafe around outstanding Rust references.
///
/// # Safety
///
/// `ptr` must identify a page-aligned mapping whose range and file-page offset
/// satisfy Linux's `remap_file_pages(2)` contract.  No Rust references may be
/// retained across a call which changes the mapping's page association.
#[inline]
pub unsafe fn remap_file_pages(ptr: *mut c_void, len: usize, page_offset: usize) -> Result<()> {
    // SAFETY: The caller owns the mapping-lifetime and pointer-provenance
    // obligations; Linux validates the range and file-page offset.
    unsafe { crabc_core::mm::remap_file_pages_raw(ptr.cast(), len, page_offset) }
}

/// Queries Linux residency for each page intersecting a mapped range.
///
/// The first `ceil(len / 4096)` bytes of `residency` are the caller-owned
/// output area. Linux writes one byte per actual kernel page; bit zero reports
/// whether that page is resident and the other bits are unspecified. A
/// successful call returns `Ok(())`; bytes after the kernel's actual page
/// count are left untouched. The 4096-byte check is an upper bound for the
/// supported AArch64 page-size configurations.
///
/// This operation never enters the public C ABI and never reads or writes
/// thread-local `errno`.
///
/// # Safety
///
/// `ptr` must be page-aligned and identify the first byte of a range which
/// remains mapped for the duration of the call. `len` must not wrap the
/// `ptr..ptr+len` address range. `residency` must remain exclusively borrowed,
/// writable, and disjoint from the queried mapping for the duration of the
/// syscall; it must contain at least [`MINCORE_PAGE_SIZE`]-based
/// `ceil(len / 4096)` bytes. The caller must not inspect the output until this
/// function returns. For a zero-length range, an empty output slice is
/// sufficient, but Linux still validates `ptr` according to its syscall ABI.
#[inline]
pub unsafe fn mincore(ptr: *mut c_void, len: usize, residency: &mut [u8]) -> Result<()> {
    let required = len
        .checked_add(MINCORE_PAGE_SIZE - 1)
        .map(|rounded| rounded / MINCORE_PAGE_SIZE)
        .ok_or(crate::Errno::INVAL)?;
    if residency.len() < required {
        return Err(crate::Errno::INVAL);
    }

    // SAFETY: The caller owns the mapped-range and output-slice contracts;
    // the length check proves Linux cannot write beyond the supplied slice on
    // any supported AArch64 page-size configuration.
    unsafe { crabc_core::mm::mincore_raw(ptr.cast(), len, residency.as_mut_ptr()) }
}
