//! Stateless Linux/AArch64 virtual-memory operations.

use crate::{RawFd, Result};
use crate::syscall::{decode, syscall2, syscall3, syscall4, syscall5, syscall6, SYS_MADVISE, SYS_MBIND, SYS_MINCORE, SYS_MLOCK, SYS_MLOCK2, SYS_MLOCKALL, SYS_MMAP, SYS_MPROTECT, SYS_MREMAP, SYS_MSYNC, SYS_MUNLOCK, SYS_MUNLOCKALL, SYS_MUNMAP, SYS_REMAP_FILE_PAGES};

const MREMAP_FIXED: u32 = 0x2;

/// Creates a mapping with the Linux/AArch64 `mmap` ABI.
///
/// # Safety
///
/// The caller must uphold Linux mapping requirements and Rust pointer
/// provenance/reference invariants for `address` and the returned range.
#[inline]
pub unsafe fn mmap_raw(
    address: *mut u8,
    length: usize,
    protection: u32,
    flags: u32,
    fd: RawFd,
    offset: u64,
) -> Result<*mut u8> {
    // SAFETY: The caller owns the mapping contract. `decode` recognizes
    // only the Linux error range, so valid high-address mappings remain
    // successful pointer values.
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

/// Removes a Linux mapping.
///
/// # Safety
///
/// The mapped range must be valid for unmapping and have no remaining Rust
/// references.
#[inline]
pub unsafe fn munmap_raw(address: *mut u8, length: usize) -> Result<()> {
    // SAFETY: The caller owns the mapping lifetime/provenance contract.
    decode(unsafe { syscall2(SYS_MUNMAP, address as usize, length) }).map(|_| ())
}

/// Resizes or moves a Linux mapping with the AArch64 `mremap` ABI.
///
/// `flags` is passed to Linux unchanged. The native facade currently
/// exposes only `MREMAP_MAYMOVE`; this raw seam remains an ABI-level
/// operation so the facade can own its closed flag policy.
///
/// # Safety
///
/// `address` must be page-aligned, and the range beginning there and
/// extending for `old_length` bytes, rounded up to a page boundary, must
/// be a valid mapping owned by the caller. The caller must ensure that
/// `address + old_length` and `address + new_length` do not wrap. There
/// must be no Rust references into the old range when the operation may
/// move it, and callers must treat the old mapping as invalid after any
/// successful call: only the returned address may be used. If the call
/// fails, Linux leaves the old mapping available for cleanup.
#[inline]
pub unsafe fn mremap_raw(
    address: *mut u8,
    old_length: usize,
    new_length: usize,
    flags: u32,
) -> Result<*mut u8> {
    // SAFETY: The caller owns the mapping lifetime/provenance contract;
    // Linux validates lengths, flags, and the mapping itself.
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

/// Resizes or moves a Linux mapping to a caller-selected address.
///
/// This is the five-argument form of `mremap`. The kernel receives
/// `MREMAP_FIXED` in addition to `flags`; the constant is kept private so
/// the native facade cannot accidentally expose a fixed-address request
/// through its ordinary operation. The returned address is the only valid
/// successor of the old mapping after success.
///
/// # Safety
///
/// `address` and `new_address` must be page-aligned. The old range,
/// rounded up to a page boundary, must be a valid mapping owned by the
/// caller. The destination range must be valid for the destination
/// pointer's provenance and must contain no Rust references: Linux may
/// replace it. There must be no Rust references into the old range either.
/// The caller must ensure that neither range calculation wraps. After a
/// successful call, both the old mapping and any destination mapping
/// replaced by Linux are invalid; only the returned address may be used.
/// If the call fails, the old mapping remains available for cleanup.
#[inline]
pub unsafe fn mremap_fixed_raw(
    address: *mut u8,
    old_length: usize,
    new_length: usize,
    flags: u32,
    new_address: *mut u8,
) -> Result<*mut u8> {
    // SAFETY: The caller owns both mapping lifetime/provenance contracts;
    // Linux validates the fixed destination and mapping overlap rules.
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

/// Changes Linux mapping protection.
///
/// # Safety
///
/// The range must be a valid mapped range, and the caller must preserve
/// Rust's reference invariants after changing access permissions.
#[inline]
pub unsafe fn mprotect_raw(address: *mut u8, length: usize, flags: u32) -> Result<()> {
    // SAFETY: The caller owns the mapped-range and provenance contracts.
    decode(unsafe { syscall3(SYS_MPROTECT, address as usize, length, flags as usize) })
        .map(|_| ())
}

/// Locks a mapped range into memory with Linux `mlock`.
///
/// Linux rounds the range down/up to page boundaries. This is a direct
/// Linux/AArch64 syscall and does not use libc or thread-local `errno`.
///
/// # Safety
///
/// The range beginning at `address`, rounded down to the applicable page
/// boundary and extending for `length` bytes rounded up to a page
/// boundary, must remain mapped and readable for the duration of the
/// call. The rounded address range must not overflow. The caller must
/// preserve pointer provenance and Rust reference invariants for the
/// mapped range.
#[inline]
pub unsafe fn mlock_raw(address: *mut u8, length: usize) -> Result<()> {
    // SAFETY: The caller owns the mapped-range and provenance contract;
    // Linux validates the address, range, and process memlock limit.
    decode(unsafe { syscall2(SYS_MLOCK, address as usize, length) }).map(|_| ())
}

/// Locks a mapped range into memory with Linux `mlock2` flags.
///
/// `flags` is the Linux `MLOCK_*` bit set. The supported
/// `MLOCK_ONFAULT` bit requests that pages be locked when they are first
/// faulted instead of immediately. This is a direct Linux/AArch64 syscall
/// and does not use libc or thread-local `errno`.
///
/// # Safety
///
/// The range beginning at `address`, rounded down to the applicable page
/// boundary and extending for `length` bytes rounded up to a page
/// boundary, must remain mapped and readable for the duration of the
/// call. The rounded address range must not overflow. The caller must
/// preserve pointer provenance and Rust reference invariants for the
/// mapped range. Unsupported flag bits are reported by Linux as an
/// error.
#[inline]
pub unsafe fn mlock2_raw(address: *mut u8, length: usize, flags: u32) -> Result<()> {
    // SAFETY: The caller owns the mapped-range and provenance contract;
    // Linux validates the address, range, flags, and memlock limit.
    decode(unsafe { syscall3(SYS_MLOCK2, address as usize, length, flags as usize) })
        .map(|_| ())
}

/// Unlocks a previously locked mapped range with Linux `munlock`.
///
/// Linux rounds the range down/up to page boundaries. This is a direct
/// Linux/AArch64 syscall and does not use libc or thread-local `errno`.
///
/// # Safety
///
/// The range beginning at `address`, rounded down to the applicable page
/// boundary and extending for `length` bytes rounded up to a page
/// boundary, must remain mapped for the duration of the call. The rounded
/// address range must not overflow. The caller must preserve pointer
/// provenance and Rust reference invariants for the mapped range.
#[inline]
pub unsafe fn munlock_raw(address: *mut u8, length: usize) -> Result<()> {
    // SAFETY: The caller owns the mapped-range and provenance contract;
    // Linux validates the address and range.
    decode(unsafe { syscall2(SYS_MUNLOCK, address as usize, length) }).map(|_| ())
}

/// Synchronizes a mapped range with its backing storage.
///
/// This is the Linux/AArch64 `msync` syscall directly; it does not use
/// libc or thread-local `errno`.
///
/// # Safety
///
/// `address` must be page-aligned and identify a valid mapped range of
/// `length` bytes. `length` must be non-zero, and the mapping must remain
/// valid for the duration of the call. The caller must preserve pointer
/// provenance and Rust reference invariants across an operation which may
/// write mapped contents back to its backing storage or invalidate cached
/// data. `flags` must contain a Linux-supported synchronization mode;
/// invalid combinations are reported by the kernel as [`Errno::INVAL`].
#[inline]
pub unsafe fn msync_raw(address: *mut u8, length: usize, flags: u32) -> Result<()> {
    // SAFETY: The caller owns the mapped-range and provenance contracts;
    // Linux validates the synchronization flags and mapping.
    decode(unsafe { syscall3(SYS_MSYNC, address as usize, length, flags as usize) }).map(|_| ())
}

/// Advises Linux about access to a mapped range.
///
/// # Safety
///
/// `address` must be page-aligned and identify the first byte of a valid
/// mapped range. `length` must be non-zero, and `address..address+length`
/// must not overflow and must remain mapped for the duration of the call.
/// The caller must preserve pointer provenance and Rust reference
/// invariants across advice that can discard or alter page contents, such
/// as `MADV_DONTNEED`. Linux rounds the final partial page as specified by
/// the kernel ABI.
#[inline]
pub unsafe fn madvise_raw(address: *mut u8, length: usize, advice: u32) -> Result<()> {
    // SAFETY: The caller owns the mapped-range and provenance contracts;
    // Linux validates the advice value and mapping.
    decode(unsafe { syscall3(SYS_MADVISE, address as usize, length, advice as usize) })
        .map(|_| ())
}

/// Applies a Linux NUMA memory policy to an existing mapped range.
///
/// This is the exact Linux/AArch64 `mbind` ABI: `mode` is the kernel's
/// signed `int`, while `nodemask` points to `unsigned long` words. On the
/// supported AArch64 target `usize` is that unsigned-long word, so this seam
/// does not introduce a compatibility layout. It intentionally supplies no
/// memory-policy constants, NUMA discovery, huge-page allocation, retry, or
/// fallback policy; those decisions remain with the caller.
///
/// # Safety
///
/// `address..address + length` must not wrap and must identify a mapping that
/// remains valid for the syscall. For any `mode` that makes Linux inspect
/// `nodemask`, the pointer must be null only when that mode permits it;
/// otherwise it must be aligned and readable for enough `usize` words to
/// represent `maxnode` bits, rounded up to the word size. Any pointer-valued
/// policy argument must remain valid for the call, and the caller must uphold
/// the selected Linux memory-policy semantics for the mapping and concurrent
/// users of it.
#[inline]
pub unsafe fn mbind_raw(
    address: *mut u8,
    length: usize,
    mode: i32,
    nodemask: *const usize,
    maxnode: usize,
    flags: u32,
) -> Result<()> {
    // SAFETY: The caller owns the mapping and optional nodemask contracts;
    // all scalar words are passed unchanged to Linux for option-specific
    // validation.
    decode(unsafe {
        syscall6(
            SYS_MBIND,
            address as usize,
            length,
            mode as usize,
            nodemask as usize,
            maxnode,
            flags as usize,
        )
    })
    .map(|_| ())
}

/// Applies a POSIX memory-access advisory through Linux's `madvise` ABI.
///
/// The syscall is shared with [`madvise_raw`], but this separate seam is
/// intentional: POSIX `DONTNEED` has advisory semantics and must not be
/// confused with Linux's page-discarding `MADV_DONTNEED` policy in a
/// higher-level facade.
///
/// # Safety
///
/// `address..address+length` must satisfy the Linux advisory syscall's
/// mapped-range and pointer-validity requirements.
#[inline]
pub unsafe fn posix_madvise_raw(address: *mut u8, length: usize, advice: u32) -> Result<()> {
    // musl's POSIX_MADV_DONTNEED is intentionally a no-op on Linux:
    // issuing Linux MADV_DONTNEED here would discard private anonymous
    // contents and would silently change the POSIX contract.
    if advice == 4 {
        let _ = (address, length);
        return Ok(());
    }
    // SAFETY: The caller owns the mapped-range contract. Linux validates
    // the POSIX advice value and reports invalid values as EINVAL.
    decode(unsafe { syscall3(SYS_MADVISE, address as usize, length, advice as usize) })
        .map(|_| ())
}

/// Locks all current/future mappings in the calling process.
///
/// This operation changes process-global VM policy.  It is kept as a
/// direct raw seam so the native facade can expose that scope explicitly;
/// no C allocator or thread-local error state is involved.
#[inline]
pub fn mlockall_raw(flags: u32) -> Result<()> {
    // SAFETY: `flags` is an immediate Linux bit mask; Linux validates the
    // combinations and process memlock limit.
    decode(unsafe { crate::syscall::syscall1(SYS_MLOCKALL, flags as usize) }).map(|_| ())
}

/// Removes all process-wide memory-lock policy.
#[inline]
pub fn munlockall_raw() -> Result<()> {
    // SAFETY: The syscall has no pointer arguments and Linux validates the
    // calling process state.
    decode(unsafe { crate::syscall::syscall0(SYS_MUNLOCKALL) }).map(|_| ())
}

/// Re-maps pages in a legacy file mapping through Linux's
/// `remap_file_pages` syscall.
///
/// The protection and flags words are deliberately fixed to zero at this
/// native boundary.  They are C ABI compatibility fields rather than a
/// Rust policy surface for this legacy operation.
///
/// # Safety
///
/// The caller must provide the page-aligned mapped range and file-page
/// offset required by Linux, and must not retain Rust references whose
/// interpretation changes when the mapping is re-arranged.
#[inline]
pub unsafe fn remap_file_pages_raw(
    address: *mut u8,
    size: usize,
    page_offset: usize,
) -> Result<()> {
    // SAFETY: The caller owns the mapping and pointer-lifetime contract;
    // Linux validates the legacy remapping request.
    decode(unsafe {
        syscall5(
            SYS_REMAP_FILE_PAGES,
            address as usize,
            size,
            0,
            page_offset,
            0,
        )
    })
    .map(|_| ())
}

/// Queries Linux page residency for a mapped range.
///
/// Linux writes one byte per page of the range to `vector`; bit zero is
/// set when that page is resident and the remaining bits are unspecified.
/// The direct AArch64 syscall is number 232 and returns no count on
/// success.
///
/// # Safety
///
/// `address` must be page-aligned and identify the first byte of a range
/// which remains mapped for the duration of the call. `length` must not
/// make `address..address+length` wrap. `vector` must be writable for the
/// kernel's page count, namely `ceil(length / page_size)` bytes, and must
/// remain valid for that duration. The caller must keep this output
/// storage disjoint from the mapping being queried. A null `vector` is
/// permitted only when the kernel page count is zero.
#[inline]
pub unsafe fn mincore_raw(address: *mut u8, length: usize, vector: *mut u8) -> Result<()> {
    // SAFETY: The caller supplies the mapped-range and output-vector
    // validity contracts; Linux validates the address and range.
    decode(unsafe { syscall3(SYS_MINCORE, address as usize, length, vector as usize) })
        .map(|_| ())
}
