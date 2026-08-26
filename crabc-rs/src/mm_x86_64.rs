//! The deliberately bounded Linux/x86-64 mapping facade.
//!
//! This admission owns ordinary anonymous/file mappings, bounded remapping,
//! protection changes, unmapping, and per-range memory-locking. It deliberately
//! exposes bounded mapping synchronization, advice, and residency operations;
//! process-wide VM policy remains outside this staged x86-64 admission.

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

bitflags! {
    /// The bounded `MREMAP_*` flags accepted by [`mremap`] and
    /// [`mremap_fixed`].
    ///
    /// `MREMAP_FIXED` is deliberately not a value in this set: callers use
    /// [`mremap_fixed`] when they need a selected destination, and that
    /// operation adds the kernel's fixed-address bit at its syscall boundary.
    /// `MREMAP_DONTUNMAP` remains outside this slice because it changes the
    /// ordinary mremap guarantee that the old range is invalid after a
    /// successful move.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct MremapFlags: u32 {
        /// `MREMAP_MAYMOVE`: permit Linux to relocate the mapping.
        const MAYMOVE = 0x1;
    }
}

bitflags! {
    /// Linux/x86-64 `MLOCK_*` flags for [`mlock_with`].
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
    /// Linux/x86-64 `MS_*` flags for [`msync`].
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

/// The Linux/x86-64 base page size used to size a [`mincore`] output vector.
pub const MINCORE_PAGE_SIZE: usize = 4096;

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

#[inline]
fn checked_mremap_flags(flags: MremapFlags) -> Result<u32> {
    let bits = flags.bits();
    if bits & !MremapFlags::MAYMOVE.bits() != 0 {
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

/// Resizes or moves a Linux/x86-64 mapping.
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

/// Resizes or moves a Linux/x86-64 mapping to a caller-selected address.
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
/// [`crate::Errno::PERM`] when the caller lacks permission to lock memory, or
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
/// reference invariants for the mapped range. Linux may return
/// [`crate::Errno::PERM`] when the caller lacks permission to lock memory, or
/// [`crate::Errno::AGAIN`] or [`crate::Errno::NOMEM`] when the process's
/// memlock limit cannot accommodate the range. Unsupported flags are returned
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
/// `ptr` must be page-aligned. For a nonzero `len`, it must identify a valid
/// mapped range which remains valid for the duration of the call. A zero
/// length is a Linux no-op. The caller must preserve pointer provenance and
/// Rust reference invariants across an operation which may write mapped
/// contents back to its backing storage or invalidate cached data. Invalid
/// flag combinations are returned as [`crate::Errno::INVAL`].
#[inline]
pub unsafe fn msync(ptr: *mut c_void, len: usize, flags: MsyncFlags) -> Result<()> {
    // SAFETY: The caller owns the mapped-range and provenance contracts.
    unsafe { crabc_core::mm::msync_raw(ptr.cast(), len, flags.bits()) }
}

/// Gives Linux an access-pattern or page-discarding advisory for a mapping.
///
/// # Safety
///
/// `ptr` must be page-aligned. For a nonzero `len`, it must identify the first
/// byte of a valid mapped range whose address arithmetic does not overflow and
/// which remains mapped during the call. A zero length is a Linux no-op. The
/// caller must preserve pointer provenance and must not rely on Rust references
/// or typed contents across advice that can discard or alter pages, including
/// [`Advice::LinuxDontNeed`]. Linux rounds a final partial page according to
/// its `madvise` ABI.
#[inline]
pub unsafe fn madvise(ptr: *mut c_void, len: usize, advice: Advice) -> Result<()> {
    // SAFETY: The caller owns the mapped-range and provenance contract.
    unsafe { crabc_core::mm::madvise_raw(ptr.cast(), len, advice as u32) }
}

/// Gives Linux the POSIX access-pattern advisory for a mapped range.
///
/// Unlike [`madvise`], this operation exposes only the POSIX policy set and
/// does not name Linux's page-discarding `MADV_DONTNEED` behavior. The
/// operation remains unsafe because the pointer and mapped-range contract is
/// still supplied by the caller; errors are direct Linux [`crate::Errno`]
/// values rather than C `errno` state.
///
/// # Safety
///
/// For policies other than [`PosixAdvice::DontNeed`], `ptr` must be
/// page-aligned, identify the first byte of a valid mapped range, and have a
/// `ptr..ptr+len` range that remains valid for the duration of the call. POSIX
/// `DONTNEED` is a successful musl-compatible no-op on Linux, so it does not
/// access or validate the supplied range. The caller must preserve pointer
/// provenance and Rust reference invariants across every advisory operation
/// that reaches the kernel.
#[inline]
pub unsafe fn posix_madvise(
    ptr: *mut c_void,
    len: usize,
    advice: PosixAdvice,
) -> Result<()> {
    // SAFETY: The caller owns the mapped-range and pointer-provenance
    // contract. The typed advice is one of POSIX's five policies.
    unsafe { crabc_core::mm::posix_madvise_raw(ptr.cast(), len, advice as u32) }
}

/// Queries Linux residency for each page intersecting a mapped range.
///
/// The first `ceil(len / 4096)` bytes of `residency` are the caller-owned
/// output area. Linux writes one byte per actual kernel page; bit zero reports
/// whether that page is resident and the other bits are unspecified. Bytes
/// after the required page count are left untouched. This operation never
/// enters the public C ABI and never reads or writes thread-local `errno`.
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

    // SAFETY: The length check proves Linux cannot write beyond the supplied
    // slice on Linux/x86-64's 4096-byte base page ABI.
    unsafe { crabc_core::mm::mincore_raw(ptr.cast(), len, residency.as_mut_ptr()) }
}
