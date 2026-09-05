//! Selected static Linux/x86-64 C mapping-core boundary.
//!
//! This leaf owns one coherent caller-owned virtual-mapping lifecycle: C
//! `mmap`, `munmap`, `mprotect`, GNU `madvise`, POSIX `posix_madvise`, and
//! GNU `mincore`. It composes only the raw Linux syscall-register boundary and
//! the selected initial-TLS C `errno` publisher. It is not the whole
//! `<sys/mman.h>` declaration family, a general VM runtime, an allocator,
//! shared-memory service, libc.so, CRT, pthread/TLS lifecycle, dynamic TLS,
//! loader, sysroot, or public x86 support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/mman/mmap.c` maps to [`mmap`].
//! - `src/mman/munmap.c` maps to [`munmap`].
//! - `src/mman/mprotect.c` maps to [`mprotect`].
//! - `src/mman/madvise.c` maps to [`madvise`].
//! - `src/mman/posix_madvise.c` maps to [`posix_madvise`].
//! - `src/mman/mincore.c` maps to [`mincore`].
//!
//! In particular, musl rejects a non-page-aligned mapping offset and a length
//! at or above `PTRDIFF_MAX` before entering Linux, translates its anonymous
//! non-fixed `EPERM` fallback to `ENOMEM`, rounds the `mprotect` address/range
//! to page boundaries, and makes POSIX `DONTNEED` a no-op that returns zero
//! without changing `errno`. The selected archive preserves those rules.
//! Pinned musl calls its private `__vm_wait` before `MAP_FIXED` mappings and
//! unmaps. The frozen selected-static archive retains its established local
//! no-op because it has no selected shared VM lifetime owner. The owned
//! product instead waits through the existing source-ported
//! [`super::pthread_vmlock`] record. That record already guards the selected
//! process-shared barrier and robust-mutex pending-node transitions, so no new
//! global VM lock is introduced.
//!
//! A separate private direct `msync` artifact now owns only a no-cancellation
//! Linux request path; musl's cancellation-point semantics remain deferred.
//! `mremap` (variadic fixed-address form plus VM wait), `mlock*`,
//! `remap_file_pages`, `shm_*`, and `memfd_create` are likewise deliberately
//! outside this mapping-core artifact.

use core::ffi::{c_int, c_long, c_void};

use super::{c_pointer_status, c_status, errno, raw_syscall};

const EINVAL: c_int = 22;
const ENOMEM: c_int = 12;
const EPERM: i64 = 1;
const LINUX_ERRNO_MAX: i64 = 4_095;
const PAGE_SIZE: usize = 4_096;
const PAGE_MASK: usize = PAGE_SIZE - 1;
const MMAP_OFFSET_MASK: u64 = PAGE_MASK as u64;
const MAP_FIXED: c_int = 0x10;
const MAP_ANONYMOUS: c_int = 0x20;
const POSIX_MADV_DONTNEED: c_int = 4;

#[inline]
fn mapping_failed(error: c_int) -> *mut c_void {
    // SAFETY: this leaf has already selected a concrete C-visible errno.
    unsafe { errno::set_errno(error) };
    usize::MAX as *mut c_void
}

/// Enter the existing owned runtime's musl-compatible VM lifetime barrier.
///
/// The `pthread_vmlock` record is already the sole selected owner of musl's
/// `src/thread/vmlock.c` protocol. It prevents a fixed replacement or unmap
/// from racing a selected process-shared barrier/robust-mutex transition that
/// still holds a caller-owned public-object pointer. The frozen archive keeps
/// its prior no-op because it does not select that owned product contract.
#[cfg(feature = "x86-owned-static-runtime")]
#[inline]
fn selected_owned_vm_wait() {
    // SAFETY: the existing pthread vmlock owns the selected process-shared
    // object lifetime interval, and this source-shaped wait acquires no new
    // global VM ownership or C ABI state.
    unsafe { super::pthread_vmlock::wait() };
}

#[cfg(not(feature = "x86-owned-static-runtime"))]
#[inline]
fn selected_owned_vm_wait() {}

/// Create one virtual-memory mapping through Linux `mmap(2)`.
///
/// The selected pre-syscall offset/length validation and the anonymous
/// non-fixed `EPERM` to `ENOMEM` mapping are musl-visible C behavior. All
/// remaining flag, descriptor, address, lifetime, and file-offset semantics
/// stay Linux-owned.
///
/// # Safety
///
/// The caller owns every raw mapping contract: pointer/address meaning, range
/// validity, descriptor lifetime, file-offset semantics, concurrency, and the
/// later unmap/protection lifecycle. In the owned product, a fixed mapping
/// first waits for the existing selected pthread VM-lifetime interval; the
/// frozen archive retains its established no-op boundary.
#[no_mangle]
pub unsafe extern "C" fn mmap(
    address: *mut c_void,
    length: usize,
    protection: c_int,
    flags: c_int,
    file_descriptor: c_int,
    offset: c_long,
) -> *mut c_void {
    // x86-64 has the byte-offset mmap syscall, but musl still retains the
    // mmap2-unit alignment filter in its shared source. Preserve that visible
    // rejection before entering Linux.
    if (offset as u64) & MMAP_OFFSET_MASK != 0 {
        return mapping_failed(EINVAL);
    }
    if length >= isize::MAX as usize {
        return mapping_failed(ENOMEM);
    }

    if flags & MAP_FIXED != 0 {
        selected_owned_vm_wait();
    }

    // SAFETY: the caller owns the complete Linux mapping request; syscall6
    // maps C arguments one through six into rdi/rsi/rdx/r10/r8/r9.
    let mut result = unsafe {
        raw_syscall::syscall6(
            raw_syscall::SYS_MMAP,
            address as usize as i64,
            length as i64,
            i64::from(protection),
            i64::from(flags),
            i64::from(file_descriptor),
            offset,
        )
    };

    // Match musl's compatibility fallback for anonymous mappings that Linux
    // rejects with EPERM at an unspecified, non-fixed address.
    if result == -EPERM
        && address.is_null()
        && flags & MAP_ANONYMOUS != 0
        && flags & MAP_FIXED == 0
    {
        result = -i64::from(ENOMEM);
    }

    c_pointer_status(result)
}

/// Remove one virtual-memory mapping through Linux `munmap(2)`.
///
/// # Safety
///
/// `address` and `length` must designate a caller-owned mapping range, unless
/// deliberately exercising Linux's error path. Unmapping can invalidate every
/// pointer into the range; the caller owns all concurrent access and the
/// frozen archive supplies no process-wide VM synchronization. The owned
/// product waits for its existing selected pthread VM-lifetime interval before
/// making the kernel request.
#[no_mangle]
pub unsafe extern "C" fn munmap(address: *mut c_void, length: usize) -> c_int {
    selected_owned_vm_wait();
    // SAFETY: the caller owns the Linux mapping-range lifetime and aliasing
    // contract.
    let result = unsafe {
        raw_syscall::syscall2(
            raw_syscall::SYS_MUNMAP,
            address as usize as i64,
            length as i64,
        )
    };
    c_status(result)
}

/// Change protection after musl's page-rounded range translation.
///
/// # Safety
///
/// The caller owns the mapping range, its aliases, and all synchronization
/// around altered access permissions. This selected boundary intentionally
/// rounds the address and end exactly as pinned musl does.
#[no_mangle]
pub unsafe extern "C" fn mprotect(
    address: *mut c_void,
    length: usize,
    protection: c_int,
) -> c_int {
    let start = (address as usize) & !PAGE_MASK;
    let end = (address as usize)
        .wrapping_add(length)
        .wrapping_add(PAGE_MASK)
        & !PAGE_MASK;
    let rounded_length = end.wrapping_sub(start);

    // SAFETY: the caller owns the page-rounded mapping-range contract. The
    // wrapping arithmetic above deliberately mirrors musl's size_t path.
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_MPROTECT,
            start as i64,
            rounded_length as i64,
            i64::from(protection),
        )
    };
    c_status(result)
}

/// Give Linux one GNU virtual-memory advice request.
///
/// # Safety
///
/// The caller owns pointer validity, mapping lifetime, advice semantics, and
/// concurrent access for the raw Linux request.
#[no_mangle]
pub unsafe extern "C" fn madvise(address: *mut c_void, length: usize, advice: c_int) -> c_int {
    // SAFETY: the caller owns the complete raw Linux advice contract.
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_MADVISE,
            address as usize as i64,
            length as i64,
            i64::from(advice),
        )
    };
    c_status(result)
}

/// Give one POSIX memory-advice request its musl result convention.
///
/// Unlike `madvise`, failures return a positive errno value directly and do
/// not publish through C `errno`. Pinned musl makes `POSIX_MADV_DONTNEED` a
/// successful no-op rather than passing Linux `MADV_DONTNEED` through.
///
/// # Safety
///
/// The caller owns the raw mapping, lifetime, and concurrent-access contract
/// for every advice other than the selected `DONTNEED` no-op.
#[no_mangle]
pub unsafe extern "C" fn posix_madvise(
    address: *mut c_void,
    length: usize,
    advice: c_int,
) -> c_int {
    if advice == POSIX_MADV_DONTNEED {
        return 0;
    }

    // SAFETY: the caller owns the complete raw Linux advice contract.
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_MADVISE,
            address as usize as i64,
            length as i64,
            i64::from(advice),
        )
    };

    // `posix_madvise` is intentionally not a c_status caller: musl negates a
    // raw Linux errno into its direct-positive result and leaves errno stale.
    if (-LINUX_ERRNO_MAX..0).contains(&result) {
        result.wrapping_neg() as c_int
    } else {
        result as c_int
    }
}

/// Report Linux page residency for one caller-owned mapping range.
///
/// # Safety
///
/// `address` and `length` must describe a mapping range and `residency` must
/// provide writable storage for every page result, unless deliberately testing
/// Linux's validation errors. The caller owns mapping lifetime and races.
#[no_mangle]
pub unsafe extern "C" fn mincore(
    address: *mut c_void,
    length: usize,
    residency: *mut u8,
) -> c_int {
    // SAFETY: the caller owns the complete raw Linux mapping/vector contract.
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_MINCORE,
            address as usize as i64,
            length as i64,
            residency as usize as i64,
        )
    };
    c_status(result)
}
