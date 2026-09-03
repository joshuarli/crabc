// Copyright (c) 2018-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `include/mimalloc/prim.h`,
// `src/prim/prim.c`, `src/prim/unix/prim.c` (including the raw
// `_mi_prim_numa_node_count` observation), and the raw page-alignment and
// memory-transition portions of `src/os.c`, including `src/os.c:240-294`,
// `src/os.c:344-467`, `src/os.c:502-527`, `src/os.c:655-680`'s default
// `purge_decommits` branch for non-owning arena spans, and the fixed,
// no-option NUMA wrapper at `src/os.c:860-898`.

//! Private, allocation-free Linux virtual-memory primitives for the allocator
//! engine.
//!
//! This boundary now includes the pinned immutable OS-memory configuration and
//! ordinary mmap policy needed by the live page map: Linux overcommit/THP and
//! physical-memory observation, regular and guaranteed-aligned mappings,
//! commit/uncommit transitions, reset/purge, protection, and explicit release.
//! It does not select huge pages, mutate process THP policy, create randomized
//! aligned hints, parse allocator options, or create mimalloc random state.
//! Those upstream paths require state owned by later slices and are absent
//! rather than represented by a successful placeholder.
//!
//! `StartupInput` is supplied by a future runtime owner. In particular, this
//! module deliberately does not read `/proc/self/environ` or autonomously
//! dereference `AT_RANDOM`: `random::TheapRandomImage` now uses direct
//! `getrandom`, and startup material needs a separate lifetime/freshness
//! contract before a process owner can consume it. Tests may read `AT_PAGESZ`
//! only to construct a real kernel-compatible input for their local mapping
//! fixture.

use core::ffi::CStr;
use core::fmt;
use core::num::NonZeroUsize;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicUsize, Ordering};

use crabc_core::{Errno, Result};

use crate::config::ARENA_SLICE_SIZE;
use crate::invariants;
use crate::types::MemoryId;

// Linux values shared by the exact AArch64 and x86-64 Unix primitive paths.
// These are intentionally private: allocator policy does not receive an open
// mmap or madvise flag vocabulary from this module.
const PROT_NONE: u32 = 0;
const PROT_READ: u32 = 0x1;
const PROT_WRITE: u32 = 0x2;
const MAP_PRIVATE: u32 = 0x02;
const MAP_ANONYMOUS: u32 = 0x20;
const MAP_NORESERVE: u32 = 0x4000;
const MADV_DONTNEED: u32 = 4;
const MADV_FREE: u32 = 8;
const CLOCK_MONOTONIC: i32 = 1;
const GRND_NONBLOCK: u32 = 0x1;
const RUSAGE_SELF: i32 = 0;
const R_OK: u32 = 4;

// `src/prim/unix/prim.c:_mi_prim_numa_node_count` probes node entries one at
// a time instead of allocating or parsing a topology file. It starts after
// the implicit node zero, scans the source's half-open 1..256 range, and
// permits four absent entries before a fifth ends the observation.
const NUMA_NODE_SCAN_END: usize = 256;
const NUMA_NODE_MAX_MISSING_GAP: usize = 4;
const NUMA_NODE_PATH_PREFIX: &[u8] = b"/sys/devices/system/node/node";
const NUMA_NODE_DECIMAL_CAPACITY: usize = 3;
const NUMA_NODE_PATH_CAPACITY: usize =
    NUMA_NODE_PATH_PREFIX.len() + NUMA_NODE_DECIMAL_CAPACITY + 1;

// `src/os.c:860-898` caches the allocator-facing NUMA count separately from
// the raw Unix observations. This fixed profile omits
// `mi_option_use_numa_nodes`, so its first cache fill always normalizes the
// raw count. Keep the cache private and zero-initialized like the source:
// callers of the wrapper never own or reset process topology state.
const NUMA_NODE_INT_MAX: usize = i32::MAX as usize;
static OS_NUMA_NODE_COUNT: AtomicUsize = AtomicUsize::new(0);

// `src/prim/unix/prim.c:_mi_prim_reset` starts with MADV_FREE and permanently
// switches to MADV_DONTNEED only when Linux says MADV_FREE is unsupported.
// The frozen normal-release profile has no secure/debug mprotect transition
// after decommit, so this static is the only raw Unix reset policy retained.
static RESET_ADVICE: AtomicUsize = AtomicUsize::new(MADV_FREE as usize);

/// Drives one Unix reset advisory sequence without introducing an OS fallback.
///
/// Pinned `src/prim/unix/prim.c:_mi_prim_reset` snapshots the process-wide
/// advice before retrying `EAGAIN`. A concurrent caller can permanently change
/// the cache after its own `EINVAL`, but that must not change this in-flight
/// retry. The caller provides the one raw advisory edge so the production path
/// stays allocation-free and focused tests can exercise the advice-state
/// transition without requiring a kernel to produce a particular transient
/// errno.
#[inline]
fn reset_with_advice(
    advice_state: &AtomicUsize,
    mut madvise: impl FnMut(u32) -> Result<()>,
) -> Result<()> {
    let advice = advice_state.load(Ordering::Relaxed) as u32;
    loop {
        match madvise(advice) {
            Ok(()) => return Ok(()),
            Err(Errno::AGAIN) => continue,
            Err(Errno::INVAL) if advice == MADV_FREE => {
                advice_state.store(MADV_DONTNEED as usize, Ordering::Release);
                return madvise(MADV_DONTNEED);
            }
            Err(error) => return Err(error),
        }
    }
}

/// One configured Linux base-page size supplied by the process-start owner.
///
/// The AArch64 profile accepts 4, 16, and 64 KiB; the x86-64 profile accepts
/// only 4 KiB. Keeping the value typed prevents future page-map and OS paths
/// from accidentally relying on another profile's common configuration.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PageSize(NonZeroUsize);

impl PageSize {
    /// Validates one base-page size for the selected Linux target profile.
    #[inline]
    pub(crate) const fn new(bytes: usize) -> Option<Self> {
        match bytes {
            4_096 => {
                // SAFETY: The enumerated base-page size is non-zero.
                Some(Self(unsafe { NonZeroUsize::new_unchecked(bytes) }))
            }
            #[cfg(target_arch = "aarch64")]
            16_384 | 65_536 => {
                // SAFETY: Each enumerated base-page size is non-zero.
                Some(Self(unsafe { NonZeroUsize::new_unchecked(bytes) }))
            }
            _ => None,
        }
    }

    /// Returns the base-page byte size supplied at startup.
    #[inline]
    pub(crate) const fn bytes(self) -> usize {
        self.0.get()
    }
}

/// The allocation-free fragment of process-start information used here.
///
/// This carries only the verified kernel page size. `AT_RANDOM` is deliberately
/// not copied or exposed: the current random image initializes through direct
/// `getrandom`, while a future process owner must separately define startup
/// entropy lifetime and freshness before it may consume auxv material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StartupInput {
    page_size: PageSize,
}

impl StartupInput {
    /// Builds the direct primitive input from a runtime-owned page size.
    #[inline]
    pub(crate) const fn new(page_size: PageSize) -> Self {
        Self { page_size }
    }

    /// Returns the page-size contract used by mappings from this input.
    #[inline]
    pub(crate) const fn page_size(self) -> PageSize {
        self.page_size
    }
}

/// The pinned default Linux OS-memory policy after primitive probing.
///
/// This is the typed counterpart of `mi_os_mem_config_t`. It contains facts
/// observed during process initialization, not mutable allocator options.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MemoryConfig {
    page_size: PageSize,
    large_page_size: usize,
    alloc_granularity: usize,
    physical_memory_in_kib: usize,
    virtual_address_bits: usize,
    has_overcommit: bool,
    has_partial_free: bool,
    has_virtual_reserve: bool,
    has_transparent_huge_pages: bool,
    // Deterministic native fault tests must cover both partial-release edges
    // even when the kernel happens to hand a directly aligned address back.
    // This test-only input never enters the production memory configuration.
    #[cfg(test)]
    force_full_aligned_map_trim: bool,
}

impl MemoryConfig {
    const DEFAULT_PHYSICAL_MEMORY_IN_KIB: usize = 32 * 1024 * 1024;
    const LARGE_PAGE_SIZE: usize = 2 * 1024 * 1024;

    /// Probes the exact allocation-free Linux inputs used by
    /// `_mi_prim_mem_init`, retaining each source fallback on observation
    /// failure.
    pub(crate) fn detect(startup: StartupInput) -> Self {
        let page_size = startup.page_size();
        Self {
            page_size,
            large_page_size: Self::LARGE_PAGE_SIZE,
            alloc_granularity: page_size.bytes(),
            physical_memory_in_kib: detected_physical_memory_in_kib()
                .unwrap_or(Self::DEFAULT_PHYSICAL_MEMORY_IN_KIB),
            virtual_address_bits: crate::config::MAX_VABITS,
            has_overcommit: read_small_file(
                b"/proc/sys/vm/overcommit_memory\0",
                overcommit_from_bytes,
            )
            .unwrap_or(true),
            has_partial_free: true,
            has_virtual_reserve: true,
            has_transparent_huge_pages: read_small_file(
                b"/sys/kernel/mm/transparent_hugepage/enabled\0",
                transparent_huge_pages_from_bytes,
            )
            .unwrap_or(false),
            #[cfg(test)]
            force_full_aligned_map_trim: false,
        }
    }

    #[cfg(test)]
    pub(crate) const fn from_observations(
        page_size: PageSize,
        physical_memory_in_kib: usize,
        has_overcommit: bool,
        has_transparent_huge_pages: bool,
    ) -> Self {
        Self {
            page_size,
            large_page_size: Self::LARGE_PAGE_SIZE,
            alloc_granularity: page_size.bytes(),
            physical_memory_in_kib,
            virtual_address_bits: crate::config::MAX_VABITS,
            has_overcommit,
            has_partial_free: true,
            has_virtual_reserve: true,
            has_transparent_huge_pages,
            force_full_aligned_map_trim: false,
        }
    }

    /// Forces the private test-only aligned mapping path to execute its
    /// direct-candidate, prefix, and suffix cleanup edges.
    #[cfg(test)]
    #[inline]
    pub(crate) fn test_force_full_aligned_map_trim(&mut self) {
        self.force_full_aligned_map_trim = true;
    }

    #[inline]
    pub(crate) const fn page_size(self) -> PageSize { self.page_size }
    #[inline]
    pub(crate) const fn large_page_size(self) -> usize { self.large_page_size }
    #[inline]
    pub(crate) const fn alloc_granularity(self) -> usize { self.alloc_granularity }
    #[inline]
    pub(crate) const fn physical_memory_in_kib(self) -> usize { self.physical_memory_in_kib }
    #[inline]
    pub(crate) const fn virtual_address_bits(self) -> usize { self.virtual_address_bits }
    #[inline]
    pub(crate) const fn has_overcommit(self) -> bool { self.has_overcommit }
    #[inline]
    pub(crate) const fn has_partial_free(self) -> bool { self.has_partial_free }
    #[inline]
    pub(crate) const fn has_virtual_reserve(self) -> bool { self.has_virtual_reserve }
    #[inline]
    pub(crate) const fn has_transparent_huge_pages(self) -> bool {
        self.has_transparent_huge_pages
    }

    /// Implements `_mi_os_canuse_large_page` without consulting option state.
    #[inline]
    pub(crate) const fn can_use_large_page(self, size: usize, alignment: usize) -> bool {
        self.large_page_size != 0
            && size % self.large_page_size == 0
            && alignment % self.large_page_size == 0
    }

    /// Implements `_mi_os_good_alloc_size`, including its overflow fallback.
    pub(crate) fn good_alloc_size(self, size: usize) -> usize {
        let alignment = if size < 512 * 1024 {
            self.page_size.bytes()
        } else if size < 2 * 1024 * 1024 {
            64 * 1024
        } else if size < 8 * 1024 * 1024 {
            256 * 1024
        } else if size < 32 * 1024 * 1024 {
            1024 * 1024
        } else {
            4 * 1024 * 1024
        };
        if size >= usize::MAX - alignment {
            size
        } else {
            invariants::align_up(size, alignment).unwrap_or(size)
        }
    }
}

fn detected_physical_memory_in_kib() -> Option<usize> {
    let info = crabc_core::system::sysinfo().ok()?;
    physical_memory_in_kib(info.totalram, info.mem_unit)
}

fn physical_memory_in_kib(totalram: u64, mem_unit: u32) -> Option<usize> {
    if mem_unit == 0 {
        return None;
    }
    let totalram = usize::try_from(totalram).ok()?;
    if mem_unit == 1024 {
        Some(totalram)
    } else {
        totalram.checked_mul(mem_unit as usize).map(|bytes| bytes / 1024)
    }
}

#[inline]
fn overcommit_from_bytes(bytes: &[u8]) -> bool {
    bytes.first().map_or(true, |byte| matches!(byte, b'0' | b'1'))
}

#[inline]
fn transparent_huge_pages_from_bytes(bytes: &[u8]) -> bool {
    !contains_bytes(bytes, b"[never]")
}

fn read_small_file<T>(path: &'static [u8], interpret: impl FnOnce(&[u8]) -> T) -> Option<T> {
    let fd = unsafe { crabc_core::fs::openat_raw(crabc_core::AT_FDCWD, path.as_ptr(), 0, 0) }.ok()?;
    let mut buffer = [0u8; 64];
    let read = crabc_core::io::read(fd, &mut buffer);
    let _ = crabc_core::io::close(fd);
    let count = read.ok()?;
    if count == 0 { None } else { Some(interpret(&buffer[..count.min(buffer.len())])) }
}

#[inline]
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|window| window == needle)
}

/// Returns the source Linux primitive's observed logical NUMA-node count.
///
/// This is only `_mi_prim_numa_node_count` from
/// `src/prim/unix/prim.c:677-689`: an allocation-free `R_OK` probe over the
/// conventional sysfs node entries. It deliberately does not cache the
/// result, read `mi_option_use_numa_nodes`, normalize a current-node value,
/// or choose arena placement; those are separate `src/os.c` policy concerns.
///
/// The M1 raw C/Rust trace calls this primitive directly. The separately named
/// fixed [`os_numa_node_count`] wrapper consumes it only for the selected
/// cache, leaving this raw observation and its trace unchanged.
#[allow(dead_code)]
pub(crate) fn numa_node_count() -> usize {
    scan_linux_numa_node_count(linux_numa_node_path_is_readable)
}

/// Runs the exact sparse-node scan used by the pinned Linux primitive.
///
/// The predicate is evaluated before the gap decision for every scanned node,
/// including the fifth absent node that ends the scan. Keeping this pure
/// helper makes the source's sparse-topology boundary directly testable
/// without making test results depend on the host's sysfs topology.
fn scan_linux_numa_node_count(mut node_is_readable: impl FnMut(usize) -> bool) -> usize {
    let mut last_found = 0usize;
    for node in 1..NUMA_NODE_SCAN_END {
        if node_is_readable(node) {
            last_found = node;
        } else if node - last_found > NUMA_NODE_MAX_MISSING_GAP {
            break;
        }
    }
    // `last_found` is at most 255 in the source loop, so this also preserves
    // the source fallback of one logical node when every probe fails.
    last_found + 1
}

/// Tests one source-shaped sysfs topology entry without allocation or libc.
fn linux_numa_node_path_is_readable(node: usize) -> bool {
    let mut path = [0u8; NUMA_NODE_PATH_CAPACITY];
    let Some(path_length) = write_linux_numa_node_path(node, &mut path) else {
        return false;
    };
    let Ok(path) = CStr::from_bytes_with_nul(&path[..path_length]) else {
        return false;
    };
    crabc_core::fs::access(path, R_OK).is_ok()
}

/// Writes `/sys/devices/system/node/node<decimal>\\0` for one source scan
/// index and returns its byte length including the trailing NUL.
fn write_linux_numa_node_path(
    node: usize,
    path: &mut [u8; NUMA_NODE_PATH_CAPACITY],
) -> Option<usize> {
    if !(1..NUMA_NODE_SCAN_END).contains(&node) {
        return None;
    }

    let prefix_length = NUMA_NODE_PATH_PREFIX.len();
    path[..prefix_length].copy_from_slice(NUMA_NODE_PATH_PREFIX);

    let mut decimal = [0u8; NUMA_NODE_DECIMAL_CAPACITY];
    let decimal_length = write_decimal_node_index(node, &mut decimal);
    let decimal_end = prefix_length.checked_add(decimal_length)?;
    path[prefix_length..decimal_end].copy_from_slice(&decimal[..decimal_length]);
    path[decimal_end] = 0;
    decimal_end.checked_add(1)
}

/// Writes the source scan index's one-to-three decimal digits without a
/// formatter or allocator. Callers have already bounded it to `1..256`.
fn write_decimal_node_index(
    mut node: usize,
    output: &mut [u8; NUMA_NODE_DECIMAL_CAPACITY],
) -> usize {
    let digits = if node >= 100 {
        3
    } else if node >= 10 {
        2
    } else {
        1
    };
    for index in (0..digits).rev() {
        // The remainder is in 0..10, so the narrowing conversion is exact.
        output[index] = b'0' + (node % 10) as u8;
        node /= 10;
    }
    digits
}

/// The initial protection requested for a private anonymous mapping.
///
/// This maps directly onto `_mi_prim_alloc`'s `commit` boolean after the
/// upstream policy has selected the ordinary, non-huge mapping path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MapAccess {
    /// Reserve address space with no access until a later [`Mapping::commit`].
    Reserved,
    /// Create an immediately readable and writable anonymous mapping.
    Committed,
}

impl MapAccess {
    #[inline]
    const fn protection(self) -> u32 {
        match self {
            Self::Reserved => PROT_NONE,
            Self::Committed => PROT_READ | PROT_WRITE,
        }
    }
}

/// The known-zero outcome of one commit transition.
///
/// Unix `_mi_prim_commit` always reports false: a range may include already
/// accessible bytes, so `mprotect` cannot establish that its contents are
/// zero even when it originated from an anonymous reserved mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CommitOutcome {
    /// The mapping is accessible but the transition did not prove zero bytes.
    NotKnownZero,
}

/// The default-release decommit outcome on Linux.
///
/// `_mi_prim_decommit` uses `MADV_DONTNEED` and leaves the mapping accessible
/// for this profile, so a subsequent reuse does not require `mprotect`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DecommitOutcome {
    /// The range may be reused without a recommit transition.
    DoesNotNeedRecommit,
}

/// The fixed Linux `_mi_os_reuse` outcome.
///
/// Pinned `src/prim/unix/prim.c:_mi_prim_reuse` has no Linux VM operation:
/// its only non-no-op branch is Apple's `MADV_FREE_REUSE`. The explicit value
/// prevents a caller from mistaking this source-shaped success for a
/// recommit, reclamation, or access transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReuseOutcome {
    /// A complete contained page range was accepted without a Linux transition.
    NoOp,
}

/// Accepts one exact, non-owning arena-slice span for Linux `_mi_os_reuse`.
///
/// Pinned `src/os.c:643-653` first conservatively retains complete base pages,
/// then calls `src/prim/unix/prim.c:536-542`. The only caller is the
/// `src/arena.c:296-307` already-committed branch, where the source start is
/// `MI_ARENA_SLICE_SIZE` aligned and the checked length is a nonzero multiple
/// of that size. Every supported Linux/AArch64 base-page size (4, 16, or
/// 64 KiB) divides the fixed 64 KiB source slice, so conservative normalization
/// retains this whole span. Linux then has no primitive operation at all.
///
/// This deliberately takes neither a [`Mapping`] nor a raw release capability:
/// the arena's external backing owner remains responsible for its complete
/// mapping. It has no syscall, fault-injection edge, state mutation, or error
/// path, and therefore cannot turn a successfully claimed arena span into a
/// late allocation failure.
#[inline]
pub(crate) fn reuse_arena_range(address: NonNull<u8>, length: NonZeroUsize) -> ReuseOutcome {
    debug_assert_eq!(address.as_ptr().addr() % ARENA_SLICE_SIZE, 0);
    debug_assert_eq!(length.get() % ARENA_SLICE_SIZE, 0);
    let _ = (address, length);
    #[cfg(test)]
    observe_arena_reuse_for_test(address, length);
    ReuseOutcome::NoOp
}

#[cfg(test)]
static ARENA_REUSE_WITNESS_ADDRESS: AtomicUsize = AtomicUsize::new(0);
#[cfg(test)]
static ARENA_REUSE_WITNESS_LENGTH: AtomicUsize = AtomicUsize::new(0);
#[cfg(test)]
static ARENA_REUSE_WITNESS_CALLS: AtomicUsize = AtomicUsize::new(0);

/// Test-only exact-span witness for the otherwise intentionally invisible
/// Linux reuse call. It exposes no VM operation or production state.
#[cfg(test)]
pub(crate) struct ArenaReuseWitness {
    address: usize,
    length: usize,
}

#[cfg(test)]
impl ArenaReuseWitness {
    #[inline]
    pub(crate) fn calls(&self) -> usize {
        assert_eq!(
            ARENA_REUSE_WITNESS_ADDRESS.load(Ordering::Acquire),
            self.address,
            "the exact-span reuse witness remains installed"
        );
        assert_eq!(
            ARENA_REUSE_WITNESS_LENGTH.load(Ordering::Acquire),
            self.length,
            "the exact-span reuse witness retains its checked length"
        );
        ARENA_REUSE_WITNESS_CALLS.load(Ordering::Acquire)
    }
}

#[cfg(test)]
impl Drop for ArenaReuseWitness {
    fn drop(&mut self) {
        ARENA_REUSE_WITNESS_ADDRESS.store(0, Ordering::Release);
        ARENA_REUSE_WITNESS_LENGTH.store(0, Ordering::Release);
        ARENA_REUSE_WITNESS_CALLS.store(0, Ordering::Release);
    }
}

/// Installs one test-only exact-span observer for [`reuse_arena_range`].
///
/// Test arena regions stay live and disjoint, so matching the concrete start
/// and length isolates this assertion from unrelated parallel allocator tests.
#[cfg(test)]
#[inline]
pub(crate) fn test_install_arena_reuse_witness(
    address: NonNull<u8>,
    length: NonZeroUsize,
) -> ArenaReuseWitness {
    let address = address.as_ptr().addr();
    let length = length.get();
    ARENA_REUSE_WITNESS_CALLS.store(0, Ordering::Release);
    assert_eq!(
        ARENA_REUSE_WITNESS_ADDRESS.compare_exchange(
            0,
            address,
            Ordering::AcqRel,
            Ordering::Acquire,
        ),
        Ok(0),
        "one exact-span reuse witness may be active at a time"
    );
    ARENA_REUSE_WITNESS_LENGTH.store(length, Ordering::Release);
    ArenaReuseWitness { address, length }
}

#[cfg(test)]
#[inline]
fn observe_arena_reuse_for_test(address: NonNull<u8>, length: NonZeroUsize) {
    if ARENA_REUSE_WITNESS_ADDRESS.load(Ordering::Acquire) == address.as_ptr().addr()
        && ARENA_REUSE_WITNESS_LENGTH.load(Ordering::Acquire) == length.get()
    {
        ARENA_REUSE_WITNESS_CALLS.fetch_add(1, Ordering::AcqRel);
    }
}

/// Applies the pinned default arena-purge decommit to one non-owning span.
///
/// This is the `purge_decommits=1` arm of `_mi_os_purge_ex` used by
/// `mi_arena_purge`.  An arena intentionally retains only its external-memory
/// provenance, not the [`Mapping`] owner which must later unmap the complete
/// backing allocation.  Keeping this operation non-owning makes that boundary
/// explicit: it can discard physical contents but can neither shorten nor
/// release the external map. The separate [`FaultPoint::Purge`] seam belongs
/// to the alternate reset policy when `purge_decommits` is disabled; the
/// frozen default reaches only [`FaultPoint::Decommit`] here.
///
/// # Safety
///
/// `address..address + length` must remain within one live writable Linux
/// mapping for this call.  It must remain live and inaccessible through Rust
/// references while `MADV_DONTNEED` can discard its contents. `page_size`
/// must be the mapping's actual Linux base page size.
#[inline]
pub(crate) unsafe fn decommit_arena_range(
    page_size: PageSize,
    address: *mut u8,
    length: usize,
) -> Result<Option<DecommitOutcome>> {
    let Some((address, length)) = contained_unowned_page_range(page_size, address, length)? else {
        return Ok(None);
    };
    fault_before(FaultPoint::Decommit)?;
    // SAFETY: the caller proves that the conservatively page-contained range
    // stays within its live external mapping and carries no Rust references
    // across this raw Linux advisory.
    unsafe { crabc_core::mm::madvise_raw(address, length, MADV_DONTNEED) }?;
    Ok(Some(DecommitOutcome::DoesNotNeedRecommit))
}

/// One failed aligned-map attempt together with any still-live private mapping.
///
/// Pinned `mi_os_prim_alloc_aligned` treats its internal partial frees as
/// best-effort. Rust cannot let the corresponding non-RAII owner fall out of
/// scope: when a direct-candidate release or an overmap trim fails, this error
/// transfers the exact remaining contiguous mapping to its caller. A failure
/// before a mapping exists carries `None`.
#[must_use = "a retained aligned-map mapping must move into an explicit owner"]
pub(crate) struct AlignedMappingFailure {
    error: Errno,
    mapping: Option<Mapping>,
}

impl AlignedMappingFailure {
    #[inline]
    fn without_mapping(error: Errno) -> Self {
        Self {
            error,
            mapping: None,
        }
    }

    #[inline]
    fn with_mapping(error: Errno, mapping: Mapping) -> Self {
        Self {
            error,
            mapping: Some(mapping),
        }
    }

    /// Returns the operation error without consuming a retained mapping.
    #[inline]
    pub(crate) const fn error(&self) -> Errno { self.error }

    /// Transfers the exact live mapping, when cleanup failed after one existed.
    #[inline]
    pub(crate) fn into_mapping(self) -> Option<Mapping> { self.mapping }
}

impl fmt::Debug for AlignedMappingFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AlignedMappingFailure")
            .field("error", &self.error)
            .field("retains_mapping", &self.mapping.is_some())
            .finish()
    }
}

/// One private anonymous mapping with an explicit, non-RAII release edge.
///
/// `Mapping` intentionally has no `Drop` unmap. Upstream ownership and later
/// memory-ID accounting decide when a mapping is freed; an implicit release
/// here would hide an allocator policy transition and could double-unmap after
/// ownership moves. A successful [`Mapping::unmap`] records the closed state,
/// and all later range operations return `EINVAL` without crossing the kernel.
pub(crate) struct Mapping {
    address: *mut u8,
    length: usize,
    page_size: PageSize,
    initially_committed: bool,
    initially_zero: bool,
    is_mapped: bool,
}

impl Mapping {
    /// Maps one page-aligned-length private anonymous region.
    ///
    /// The current regular path is the final `unix_mmap` fallback from
    /// `src/prim/unix/prim.c`: `MAP_PRIVATE | MAP_ANONYMOUS`, no file
    /// descriptor, no address hint, and no `MAP_NORESERVE` selection. The
    /// latter, huge pages, and alignment hints need upstream option/startup
    /// policy and remain absent. Linux zero-initializes a new anonymous map,
    /// matching `_mi_prim_alloc`'s `is_zero = true` result.
    #[inline]
    pub(crate) fn map_anonymous(
        startup: StartupInput,
        length: usize,
        access: MapAccess,
    ) -> Result<Self> {
        Self::map_regular(startup, length, access, false)
    }

    /// Maps the pinned regular allocator path, including Linux overcommit's
    /// `MAP_NORESERVE` selection.
    pub(crate) fn map_for_allocator(
        config: MemoryConfig,
        length: usize,
        access: MapAccess,
    ) -> Result<Self> {
        Self::map_regular(
            StartupInput::new(config.page_size()),
            length,
            access,
            config.has_overcommit(),
        )
    }

    fn map_regular(
        startup: StartupInput,
        length: usize,
        access: MapAccess,
        no_reserve: bool,
    ) -> Result<Self> {
        validate_mapping_length(startup.page_size, length)?;
        fault_before(FaultPoint::Map)?;
        let mut flags = MAP_PRIVATE | MAP_ANONYMOUS;
        if no_reserve {
            flags |= MAP_NORESERVE;
        }

        // SAFETY: `length` is non-zero and a multiple of the startup-owned
        // kernel page size. A null hint and fd -1 are the Linux anonymous-map
        // ABI, and the returned pointer stays opaque inside `Mapping` until
        // the explicit release operation closes the mapping lifetime.
        let address = unsafe {
            crabc_core::mm::mmap_raw(
                core::ptr::null_mut(),
                length,
                access.protection(),
                flags,
                -1,
                0,
            )
        }?;

        Ok(Self {
            address,
            length,
            page_size: startup.page_size,
            initially_committed: matches!(access, MapAccess::Committed),
            initially_zero: true,
            is_mapped: true,
        })
    }

    /// Guarantees a power-of-two aligned regular mapping by overmapping and
    /// partially releasing the prefix and suffix when the direct map is not
    /// aligned. This is the active mmap branch of
    /// `mi_os_prim_alloc_aligned`.
    pub(crate) fn map_aligned_for_allocator(
        config: MemoryConfig,
        length: usize,
        alignment: usize,
        access: MapAccess,
    ) -> core::result::Result<Self, AlignedMappingFailure> {
        #[cfg(test)]
        let force_full_trim_for_test = config.force_full_aligned_map_trim;
        #[cfg(not(test))]
        let force_full_trim_for_test = false;
        Self::map_aligned_for_allocator_inner(
            config,
            length,
            alignment,
            access,
            force_full_trim_for_test,
        )
    }

    /// Exercises the complete direct-candidate, prefix, and suffix cleanup
    /// sequence under deterministic fault injection.
    ///
    /// The pinned production path requests exactly `length + alignment` bytes
    /// and naturally skips one partial trim when an unlikely mapping base is
    /// already aligned. This private test seam reserves one extra alignment
    /// unit and selects the following aligned boundary in that case, so every
    /// cleanup edge has a deterministic native test. It is not compiled into
    /// production behavior.
    #[cfg(test)]
    fn map_aligned_for_allocator_force_full_trim_for_test(
        config: MemoryConfig,
        length: usize,
        alignment: usize,
        access: MapAccess,
    ) -> core::result::Result<Self, AlignedMappingFailure> {
        Self::map_aligned_for_allocator_inner(config, length, alignment, access, true)
    }

    fn map_aligned_for_allocator_inner(
        config: MemoryConfig,
        length: usize,
        alignment: usize,
        access: MapAccess,
        force_full_trim_for_test: bool,
    ) -> core::result::Result<Self, AlignedMappingFailure> {
        let page_size = config.page_size().bytes();
        if alignment < page_size || !alignment.is_power_of_two() {
            return Err(AlignedMappingFailure::without_mapping(Errno::INVAL));
        }
        let mut direct = Self::map_for_allocator(config, length, access)
            .map_err(AlignedMappingFailure::without_mapping)?;
        let direct_base = match direct.base() {
            Ok(base) => base,
            Err(error) => return Err(AlignedMappingFailure::with_mapping(error, direct)),
        };
        if !force_full_trim_for_test && direct_base.addr() % alignment == 0 {
            return Ok(direct);
        }
        if let Err(error) = direct.unmap() {
            return Err(AlignedMappingFailure::with_mapping(error, direct));
        }

        let alignment_headroom = if force_full_trim_for_test {
            match alignment.checked_mul(2) {
                Some(headroom) => headroom,
                None => return Err(AlignedMappingFailure::without_mapping(Errno::NOMEM)),
            }
        } else {
            alignment
        };
        let over_length = match length.checked_add(alignment_headroom) {
            Some(over_length) => over_length,
            None => return Err(AlignedMappingFailure::without_mapping(Errno::NOMEM)),
        };
        let mut over = Self::map_for_allocator(config, over_length, access)
            .map_err(AlignedMappingFailure::without_mapping)?;
        let base = match over.base() {
            Ok(base) => base,
            Err(error) => return Err(AlignedMappingFailure::with_mapping(error, over)),
        };
        let aligned_address = if force_full_trim_for_test && base.addr() % alignment == 0 {
            match base.addr().checked_add(alignment) {
                Some(address) => address,
                None => return Err(AlignedMappingFailure::with_mapping(Errno::NOMEM, over)),
            }
        } else {
            match invariants::align_up(base.addr(), alignment) {
                Some(address) => address,
                None => return Err(AlignedMappingFailure::with_mapping(Errno::NOMEM, over)),
            }
        };
        let prefix = match aligned_address.checked_sub(base.addr()) {
            Some(prefix) => prefix,
            None => return Err(AlignedMappingFailure::with_mapping(Errno::NOMEM, over)),
        };
        let suffix = match over_length
            .checked_sub(prefix)
            .and_then(|remaining| remaining.checked_sub(length))
        {
            Some(suffix) => suffix,
            None => return Err(AlignedMappingFailure::with_mapping(Errno::NOMEM, over)),
        };
        let aligned = base.wrapping_add(prefix);

        if prefix != 0 {
            if let Err(error) = over.unmap_prefix(prefix) {
                return Err(AlignedMappingFailure::with_mapping(error, over));
            }
        }
        if suffix != 0 {
            if let Err(error) = over.unmap_suffix(suffix) {
                return Err(AlignedMappingFailure::with_mapping(error, over));
            }
        }
        debug_assert_eq!(over.address, aligned);
        debug_assert_eq!(over.length, length);
        Ok(over)
    }

    /// Transfers this non-RAII mapping into a published raw-pointer owner.
    ///
    /// The caller must arrange exactly one later [`Mapping::reclaim_published`]
    /// after all readers have quiesced. This narrow ownership handoff exists
    /// for page-map submaps whose base pointer is itself the published token.
    pub(crate) fn into_published(mut self) -> Result<*mut u8> {
        self.active()?;
        self.is_mapped = false;
        Ok(self.address)
    }

    /// Reclaims a mapping previously transferred by [`Mapping::into_published`].
    ///
    /// # Safety
    ///
    /// `address` must be the provenance-bearing base of one still-live mapping
    /// created by this module, `length` must be its exact current extent, and
    /// the caller must own the unique release right with no live accesses.
    pub(crate) unsafe fn reclaim_published(address: *mut u8, length: usize) -> Result<()> {
        if address.is_null() || length == 0 {
            return Err(Errno::INVAL);
        }
        fault_before(FaultPoint::Unmap)?;
        unsafe { crabc_core::mm::munmap_raw(address, length) }
    }

    /// Returns whether the original anonymous mapping was zero initialized.
    #[inline]
    pub(crate) const fn initially_zero(&self) -> bool {
        self.initially_zero
    }

    /// Returns whether the original map request made the full range accessible.
    #[inline]
    pub(crate) const fn initially_committed(&self) -> bool {
        self.initially_committed
    }

    /// Returns the actual Linux base-page size selected for this mapping.
    ///
    /// A source arena can be managed only under the same frozen page-size
    /// observation as its process page map. This value is immutable after
    /// creation and exposes no mapping ownership or raw memory access.
    #[inline]
    pub(crate) const fn page_size(&self) -> PageSize {
        self.page_size
    }

    /// Returns the provenance-bearing base pointer of the live mapping.
    ///
    /// The pointer is intentionally raw: later allocator policy must preserve
    /// its mapping lifetime, alignment, aliasing, and initialized-byte rules,
    /// and must never retain it after [`Mapping::unmap`] succeeds. This method
    /// creates no reference and is unavailable after the explicit release.
    #[inline]
    pub(crate) fn base(&self) -> Result<*mut u8> {
        self.active()?;
        Ok(self.address)
    }

    /// Returns the original mapping length while the mapping remains owned.
    #[inline]
    pub(crate) fn length(&self) -> Result<usize> {
        self.active()?;
        Ok(self.length)
    }

    /// Makes every page touched by `offset..offset + length` accessible.
    ///
    /// This is the liberal `mi_os_page_align_areax(false, ...)` path used by
    /// `_mi_os_commit_ex`: a non-page-aligned requested range expands to cover
    /// both straddling pages. `None` is the source's successful empty-range
    /// result. The mapping owner prevents that expansion from escaping the
    /// owned map.
    #[inline]
    pub(crate) fn commit(
        &self,
        offset: usize,
        length: usize,
    ) -> Result<Option<CommitOutcome>> {
        let Some(range) = self.page_range(offset, length, PageAlignment::Covering)? else {
            return Ok(None);
        };
        fault_before(FaultPoint::Commit)?;

        // SAFETY: `range` is derived from this still-live mapping, starts on
        // a startup-page boundary, and is contained entirely in the mapping.
        // No Rust references into it are created or retained by this raw
        // protection transition.
        unsafe {
            crabc_core::mm::mprotect_raw(range.address, range.length, PROT_READ | PROT_WRITE)
        }?;
        Ok(Some(CommitOutcome::NotKnownZero))
    }

    /// Releases physical contents for complete pages inside the requested range.
    ///
    /// This follows the conservative `mi_os_page_align_area_conservative`
    /// branch of `mi_os_decommit_ex`. The frozen normal-release Unix primitive
    /// uses `MADV_DONTNEED` and reports `needs_recommit = false`; it does not
    /// install `PROT_NONE` because `MI_DEBUG == 0` and `MI_SECURE <= 2`.
    #[inline]
    pub(crate) fn decommit(
        &self,
        offset: usize,
        length: usize,
    ) -> Result<Option<DecommitOutcome>> {
        let Some(range) = self.page_range(offset, length, PageAlignment::Contained)? else {
            return Ok(None);
        };
        fault_before(FaultPoint::Decommit)?;

        // SAFETY: `range` is a complete-page subrange of this live mapping.
        // `MADV_DONTNEED` may discard its bytes but creates no Rust reference
        // and does not change the mapping's ownership or accessibility.
        unsafe { crabc_core::mm::madvise_raw(range.address, range.length, MADV_DONTNEED) }?;
        Ok(Some(DecommitOutcome::DoesNotNeedRecommit))
    }

    /// Purges complete pages inside the requested range using the Unix reset path.
    ///
    /// This is `_mi_prim_reset` under the pinned default Linux profile. It
    /// retries only `EAGAIN`, and only an `EINVAL` from `MADV_FREE` switches
    /// the process-wide upstream cache to `MADV_DONTNEED`; every other error
    /// reaches the caller unchanged. No extra advisory or remapping fallback
    /// is attempted.
    #[inline]
    pub(crate) fn purge(&self, offset: usize, length: usize) -> Result<bool> {
        let Some(range) = self.page_range(offset, length, PageAlignment::Contained)? else {
            return Ok(true);
        };

        reset_with_advice(&RESET_ADVICE, |advice| {
            fault_before(FaultPoint::Purge)?;
            // SAFETY: `range` is a complete-page subrange of this live mapping.
            // The advisory may discard contents but does not yield references
            // or alter this boundary's ownership state.
            unsafe { crabc_core::mm::madvise_raw(range.address, range.length, advice) }
        })
        .map(|()| true)
    }

    /// Accepts a complete contained range for `_mi_os_reuse`.
    ///
    /// `src/os.c:643-653` applies conservative page normalization before
    /// calling the Unix primitive. On Linux that primitive is a no-op, so this
    /// method deliberately performs no syscall, fault-injection edge, or
    /// mapping-state mutation. `None` represents the source branch where that
    /// normalization contains no complete page.
    #[inline]
    pub(crate) fn reuse(
        &self,
        offset: usize,
        length: usize,
    ) -> Result<Option<ReuseOutcome>> {
        let Some(_range) = self.page_range(offset, length, PageAlignment::Contained)? else {
            return Ok(None);
        };
        Ok(Some(ReuseOutcome::NoOp))
    }

    /// Makes complete pages inside the requested range inaccessible.
    ///
    /// The boolean preserves `mi_os_protectx`: an empty conservative range is
    /// not a protection operation and returns false.
    #[inline]
    pub(crate) fn protect(&self, offset: usize, length: usize) -> Result<bool> {
        self.protect_with(offset, length, true)
    }

    /// Restores read/write access to complete pages inside the requested range.
    #[inline]
    pub(crate) fn unprotect(&self, offset: usize, length: usize) -> Result<bool> {
        self.protect_with(offset, length, false)
    }

    /// Explicitly releases the entire anonymous mapping.
    ///
    /// A failure leaves the mapping live so its owner can diagnose or retry;
    /// only successful `munmap` closes this object. A second successful release
    /// is therefore structurally impossible, and a second call returns
    /// `EINVAL` before a kernel syscall.
    #[inline]
    pub(crate) fn unmap(&mut self) -> Result<()> {
        self.active()?;
        fault_before(FaultPoint::Unmap)?;
        // SAFETY: `self.address..self.address + self.length` is precisely the
        // mapping created by `map_anonymous`, and no method exposes references
        // into it. The object remains live on error and closes only after the
        // successful kernel result below.
        unsafe { crabc_core::mm::munmap_raw(self.address, self.length) }?;
        self.is_mapped = false;
        Ok(())
    }

    /// Releases a nonempty page-aligned prefix while retaining the exact
    /// contiguous suffix on both syscall success and failure.
    #[inline]
    fn unmap_prefix(&mut self, prefix: usize) -> Result<()> {
        self.validate_partial_unmap(prefix)?;
        fault_before(FaultPoint::Unmap)?;
        // SAFETY: `prefix` is a nonempty, page-aligned strict prefix of this
        // live mapping. The state update below occurs only after Linux has
        // released exactly that prefix, leaving the represented suffix live.
        unsafe { crabc_core::mm::munmap_raw(self.address, prefix) }?;
        self.address = self.address.wrapping_add(prefix);
        self.length -= prefix;
        Ok(())
    }

    /// Releases a nonempty page-aligned suffix while retaining the exact
    /// contiguous prefix on both syscall success and failure.
    #[inline]
    fn unmap_suffix(&mut self, suffix: usize) -> Result<()> {
        self.validate_partial_unmap(suffix)?;
        let retained_length = self.length - suffix;
        let suffix_address = self.address.wrapping_add(retained_length);
        fault_before(FaultPoint::Unmap)?;
        // SAFETY: `suffix` is a nonempty, page-aligned strict suffix of this
        // live mapping. The state update below occurs only after Linux has
        // released exactly that suffix, leaving the represented prefix live.
        unsafe { crabc_core::mm::munmap_raw(suffix_address, suffix) }?;
        self.length = retained_length;
        Ok(())
    }

    #[inline]
    fn protect_with(&self, offset: usize, length: usize, protect: bool) -> Result<bool> {
        let Some(range) = self.page_range(offset, length, PageAlignment::Contained)? else {
            return Ok(false);
        };
        fault_before(if protect {
            FaultPoint::Protect
        } else {
            FaultPoint::Unprotect
        })?;
        let protection = if protect {
            PROT_NONE
        } else {
            PROT_READ | PROT_WRITE
        };

        // SAFETY: `range` is a complete-page subrange of this live mapping.
        // Callers receive no Rust reference from `Mapping`, so the boundary
        // cannot leave an existing reference usable across PROT_NONE.
        unsafe { crabc_core::mm::mprotect_raw(range.address, range.length, protection) }?;
        Ok(true)
    }

    #[inline]
    fn active(&self) -> Result<()> {
        if self.is_mapped {
            Ok(())
        } else {
            Err(Errno::INVAL)
        }
    }

    #[inline]
    fn validate_partial_unmap(&self, length: usize) -> Result<()> {
        self.active()?;
        if length == 0 || length >= self.length || length % self.page_size.bytes() != 0 {
            Err(Errno::INVAL)
        } else {
            Ok(())
        }
    }

    #[inline]
    fn page_range(
        &self,
        offset: usize,
        length: usize,
        alignment: PageAlignment,
    ) -> Result<Option<MappingRange>> {
        self.active()?;
        let end = offset.checked_add(length).ok_or(Errno::INVAL)?;
        if end > self.length {
            return Err(Errno::INVAL);
        }
        if length == 0 {
            return Ok(None);
        }

        let page_size = self.page_size.bytes();
        let (start, end) = match alignment {
            PageAlignment::Covering => (
                invariants::align_down(offset, page_size).ok_or(Errno::INVAL)?,
                invariants::align_up(end, page_size).ok_or(Errno::INVAL)?,
            ),
            PageAlignment::Contained => (
                invariants::align_up(offset, page_size).ok_or(Errno::INVAL)?,
                invariants::align_down(end, page_size).ok_or(Errno::INVAL)?,
            ),
        };
        if end <= start {
            return Ok(None);
        }
        if end > self.length {
            // The parent map is itself page-sized, so a valid source-aligned
            // range cannot escape it. Treat a mismatched startup page size as
            // invalid input rather than issuing a broader kernel operation.
            return Err(Errno::INVAL);
        }

        Ok(Some(MappingRange {
            // `wrapping_add` retains the kernel-returned mapping provenance and
            // does not manufacture a pointer from an integer. Bounds above
            // prove this is an address within the owned mapping.
            address: self.address.wrapping_add(start),
            length: end - start,
        }))
    }
}

/// One regular Linux OS allocation together with its exact release mapping.
///
/// This is the fixed normal, non-huge, non-hinted owner for
/// `_mi_os_alloc`, `_mi_os_alloc_aligned`, and
/// `_mi_os_alloc_aligned_at_offset` in pinned `src/os.c:438-527`. Its
/// [`MemoryId`] always describes the `Mapping` base and complete mapped
/// length, while `pointer` is the client result that can be interior after an
/// offset-aligned allocation. The owner deliberately has no huge-page, hint,
/// NUMA, option, or accounting policy: those source choices belong to later
/// runtime owners.
///
/// Like [`Mapping`], this type has no `Drop` release. The source allocation
/// pointer and copied `MemoryId` do not themselves own `munmap`; this value
/// retains the one explicit release right until [`Self::release`] succeeds.
#[must_use = "a normal OS allocation must be explicitly released or retained"]
pub(crate) struct NormalOsAllocation {
    mapping: Mapping,
    pointer: NonNull<u8>,
    memory: MemoryId,
}

/// A normal OS allocation attempt which may retain an untrimmed live map.
///
/// The regular direct map branch has no owner on failure. The aligned branch
/// can fail after `mi_os_prim_alloc_aligned` acquired a direct candidate or
/// overmap whose partial cleanup failed. Rust preserves that lower
/// [`AlignedMappingFailure`] as an explicit `Mapping` here rather than
/// collapsing it into an errno before a finished [`MemoryId`] exists.
#[must_use = "a retained normal OS allocation map must move into an explicit owner"]
pub(crate) struct NormalOsAllocationFailure {
    error: Errno,
    mapping: Option<Mapping>,
}

impl NormalOsAllocationFailure {
    #[inline]
    fn without_mapping(error: Errno) -> Self {
        Self {
            error,
            mapping: None,
        }
    }

    #[inline]
    fn with_mapping(error: Errno, mapping: Mapping) -> Self {
        Self {
            error,
            mapping: Some(mapping),
        }
    }

    #[inline]
    fn from_aligned_failure(failure: AlignedMappingFailure) -> Self {
        let error = failure.error();
        match failure.into_mapping() {
            Some(mapping) => Self::with_mapping(error, mapping),
            None => Self::without_mapping(error),
        }
    }

    /// Returns the Rust diagnostic for this failed allocation without
    /// consuming a map.
    #[inline]
    pub(crate) const fn error(&self) -> Errno { self.error }

    /// Transfers a still-live map when aligned cleanup failed after mapping.
    #[inline]
    pub(crate) fn into_mapping(self) -> Option<Mapping> { self.mapping }
}

impl fmt::Debug for NormalOsAllocationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NormalOsAllocationFailure")
            .field("error", &self.error)
            .field("retains_mapping", &self.mapping.is_some())
            .finish()
    }
}

/// One failed normal OS release which retains its exact allocation owner.
///
/// Pinned `_mi_os_free_ex` releases `memid.mem.os.base` and its full size
/// even when the client pointer is interior. A failed Linux `munmap` leaves
/// that complete mapping live, so this error returns the same typed owner for
/// a later explicit retry instead of losing the base/full-length provenance.
#[must_use = "a failed normal OS release retains an allocation that must be retried or parked"]
pub(crate) struct NormalOsAllocationReleaseFailure {
    error: Errno,
    allocation: NormalOsAllocation,
}

impl NormalOsAllocationReleaseFailure {
    /// Returns the failed exact Linux release error.
    #[inline]
    pub(crate) const fn error(&self) -> Errno { self.error }

    /// Transfers the still-live allocation back to its caller for retry.
    #[inline]
    pub(crate) fn into_allocation(self) -> NormalOsAllocation { self.allocation }
}

impl fmt::Debug for NormalOsAllocationReleaseFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NormalOsAllocationReleaseFailure")
            .field("error", &self.error)
            .field("retains_allocation", &true)
            .finish()
    }
}

#[allow(dead_code)]
impl NormalOsAllocation {
    /// Allocates the fixed normal committed `_mi_os_alloc` route.
    ///
    /// This applies the pinned `_mi_os_good_alloc_size` rule and selects only
    /// the existing regular `mmap` policy. In particular, it fixes
    /// `allow_large = false` and does not synthesize a source hint.
    pub(crate) fn allocate(
        config: MemoryConfig,
        size: usize,
    ) -> core::result::Result<Self, NormalOsAllocationFailure> {
        let length = Self::good_allocation_size(config, size)?;
        let mapping = Mapping::map_for_allocator(config, length, MapAccess::Committed)
            .map_err(NormalOsAllocationFailure::without_mapping)?;
        Self::from_mapping(mapping, 0)
    }

    /// Allocates the fixed normal `_mi_os_alloc_aligned` route.
    ///
    /// The `access` argument is the pinned source `commit` boolean. This
    /// boundary deliberately fixes its companion `allow_large` argument to
    /// false; huge-page policy is not implicit in an aligned allocation.
    pub(crate) fn allocate_aligned(
        config: MemoryConfig,
        size: usize,
        alignment: usize,
        access: MapAccess,
    ) -> core::result::Result<Self, NormalOsAllocationFailure> {
        let mapping = Self::allocate_aligned_mapping(config, size, alignment, access)?;
        Self::from_mapping(mapping, 0)
    }

    /// Allocates `_mi_os_alloc_aligned_at_offset` without source policy extras.
    ///
    /// For a nonzero offset, the returned client pointer is `extra` bytes
    /// after an aligned mapping base, where the source computes
    /// `extra = align_up(offset, alignment) - offset`. The copied
    /// [`MemoryId`] deliberately remains at that base with the complete map
    /// length, so later release cannot mistake the interior client pointer for
    /// the `munmap` address.
    pub(crate) fn allocate_aligned_at_offset(
        config: MemoryConfig,
        size: usize,
        alignment: usize,
        offset: usize,
        access: MapAccess,
    ) -> core::result::Result<Self, NormalOsAllocationFailure> {
        if offset > size {
            return Err(NormalOsAllocationFailure::without_mapping(Errno::INVAL));
        }

        if offset == 0 {
            // Pinned `src/os.c:507-510` delegates exactly to the ordinary
            // aligned path, including its size/alignment normalization.
            return Self::allocate_aligned(config, size, alignment, access);
        }

        let page_size = config.page_size().bytes();
        // `src/os.c:504` asserts this source precondition, but its zero-offset
        // return at `:507-510` still delegates before this branch computes
        // `extra`. Make the Rust boundary checked for this nonzero branch
        // instead of silently normalizing it; the delegation above retains
        // `_mi_os_alloc_aligned`'s own page rounding at `:458-461`.
        if alignment == 0 || alignment % page_size != 0 {
            return Err(NormalOsAllocationFailure::without_mapping(Errno::INVAL));
        }

        let extra = invariants::align_up(offset, alignment)
            .and_then(|aligned_offset| aligned_offset.checked_sub(offset))
            .ok_or_else(|| NormalOsAllocationFailure::without_mapping(Errno::NOMEM))?;
        // Keep the C comparison (`>=`) rather than relying only on checked
        // addition: equality cannot produce the source's `oversize` either.
        if size >= usize::MAX - extra {
            return Err(NormalOsAllocationFailure::without_mapping(Errno::NOMEM));
        }
        let oversize = size + extra;
        let mapping = Self::allocate_aligned_mapping(config, oversize, alignment, access)?;
        let allocation = Self::from_mapping(mapping, extra)?;

        if matches!(access, MapAccess::Committed) && extra >= page_size {
            // Pinned `src/os.c:521-525` intentionally ignores the result of
            // `_mi_os_decommit`: this is a best-effort prefix discard after a
            // successful allocation, not an allocation rollback. Preserve the
            // full owner and client pointer even when Linux rejects advice.
            let _ = allocation.mapping.decommit(0, extra);
        }
        Ok(allocation)
    }

    /// Returns the source client pointer while this exact allocation is live.
    #[inline]
    pub(crate) fn pointer(&self) -> Result<NonNull<u8>> {
        self.mapping.base()?;
        Ok(self.pointer)
    }

    /// Returns the full mapping base used by `_mi_os_free_ex`.
    #[inline]
    pub(crate) fn base(&self) -> Result<*mut u8> {
        self.mapping.base()
    }

    /// Returns the complete mapped extent rather than the client request.
    #[inline]
    pub(crate) fn full_size(&self) -> Result<usize> {
        self.mapping.length()
    }

    /// Returns the OS provenance bound to this exact live mapping.
    #[inline]
    pub(crate) fn memory_id(&self) -> Result<MemoryId> {
        let base = self.mapping.base()?;
        let length = self.mapping.length()?;
        debug_assert_eq!(self.memory.os_base().map(|address| address.value()), Some(base.addr()));
        debug_assert_eq!(self.memory.size(), Some(length));
        Ok(self.memory)
    }

    /// Releases the full mapping base/length exactly once.
    ///
    /// This represents the resource effect of `_mi_os_free_ex` for regular
    /// OS memory. The source accounting and huge-page branches are deliberately
    /// outside this owner; `Mapping` supplies the complete normal `munmap`.
    pub(crate) fn release(
        mut self,
    ) -> core::result::Result<(), NormalOsAllocationReleaseFailure> {
        match self.mapping.unmap() {
            Ok(()) => Ok(()),
            Err(error) => Err(NormalOsAllocationReleaseFailure {
                error,
                allocation: self,
            }),
        }
    }

    fn allocate_aligned_mapping(
        config: MemoryConfig,
        size: usize,
        alignment: usize,
        access: MapAccess,
    ) -> core::result::Result<Mapping, NormalOsAllocationFailure> {
        let length = Self::good_allocation_size(config, size)?;
        let alignment = Self::aligned_allocation_alignment(config, alignment)?;
        Mapping::map_aligned_for_allocator(config, length, alignment, access)
            .map_err(NormalOsAllocationFailure::from_aligned_failure)
    }

    #[cfg(test)]
    fn allocate_aligned_force_full_trim_for_test(
        config: MemoryConfig,
        size: usize,
        alignment: usize,
        access: MapAccess,
    ) -> core::result::Result<Self, NormalOsAllocationFailure> {
        let length = Self::good_allocation_size(config, size)?;
        let alignment = Self::aligned_allocation_alignment(config, alignment)?;
        let mapping = Mapping::map_aligned_for_allocator_force_full_trim_for_test(
            config,
            length,
            alignment,
            access,
        )
        .map_err(NormalOsAllocationFailure::from_aligned_failure)?;
        Self::from_mapping(mapping, 0)
    }

    fn good_allocation_size(
        config: MemoryConfig,
        size: usize,
    ) -> core::result::Result<usize, NormalOsAllocationFailure> {
        if size == 0 {
            return Err(NormalOsAllocationFailure::without_mapping(Errno::INVAL));
        }
        let length = config.good_alloc_size(size);
        if length < size || length == 0 || length % config.page_size().bytes() != 0 {
            return Err(NormalOsAllocationFailure::without_mapping(Errno::NOMEM));
        }
        Ok(length)
    }

    fn aligned_allocation_alignment(
        config: MemoryConfig,
        alignment: usize,
    ) -> core::result::Result<usize, NormalOsAllocationFailure> {
        let page_size = config.page_size().bytes();
        let alignment = invariants::align_up(alignment, page_size)
            .ok_or_else(|| NormalOsAllocationFailure::without_mapping(Errno::NOMEM))?;
        if alignment < page_size || !alignment.is_power_of_two() {
            return Err(NormalOsAllocationFailure::without_mapping(Errno::INVAL));
        }
        Ok(alignment)
    }

    fn from_mapping(
        mapping: Mapping,
        client_offset: usize,
    ) -> core::result::Result<Self, NormalOsAllocationFailure> {
        let base = match mapping.base() {
            Ok(base) => base,
            Err(error) => return Err(NormalOsAllocationFailure::with_mapping(error, mapping)),
        };
        let length = match mapping.length() {
            Ok(length) => length,
            Err(error) => return Err(NormalOsAllocationFailure::with_mapping(error, mapping)),
        };
        if client_offset >= length || base.addr().checked_add(client_offset).is_none() {
            return Err(NormalOsAllocationFailure::with_mapping(Errno::NOMEM, mapping));
        }
        // Bounds above prove the client pointer stays within the exact live
        // mapping; `wrapping_add` preserves the kernel mapping's provenance.
        let pointer = match NonNull::new(base.wrapping_add(client_offset)) {
            Some(pointer) => pointer,
            None => return Err(NormalOsAllocationFailure::with_mapping(Errno::NOMEM, mapping)),
        };
        let memory = MemoryId::os(
            base,
            length,
            mapping.initially_committed(),
            mapping.initially_zero(),
            false,
        );
        Ok(Self {
            mapping,
            pointer,
            memory,
        })
    }
}

#[derive(Clone, Copy)]
struct MappingRange {
    address: *mut u8,
    length: usize,
}

#[derive(Clone, Copy)]
enum PageAlignment {
    /// Expand over any partial first/last page, like `_mi_os_commit_ex`.
    Covering,
    /// Retain only full pages, like reset/decommit/protect in `src/os.c`.
    Contained,
}

/// Selects the complete base pages contained by one non-owning external span.
///
/// Unlike [`Mapping::page_range`], this cannot prove the input is within a
/// particular `Mapping` value because that value remains with the external
/// backing owner. The unsafe caller contract of [`decommit_arena_range`]
/// supplies that proof; this helper only preserves the source's conservative
/// page-alignment calculation and checked arithmetic.
fn contained_unowned_page_range(
    page_size: PageSize,
    address: *mut u8,
    length: usize,
) -> Result<Option<(*mut u8, usize)>> {
    if address.is_null() {
        return Err(Errno::INVAL);
    }
    if length == 0 {
        return Ok(None);
    }
    let start_address = address.addr();
    let end_address = start_address.checked_add(length).ok_or(Errno::INVAL)?;
    let page_size = page_size.bytes();
    let start = invariants::align_up(start_address, page_size).ok_or(Errno::INVAL)?;
    let end = invariants::align_down(end_address, page_size).ok_or(Errno::INVAL)?;
    if end <= start {
        return Ok(None);
    }
    let offset = start.checked_sub(start_address).ok_or(Errno::INVAL)?;
    let range_length = end.checked_sub(start).ok_or(Errno::INVAL)?;
    Ok(Some((address.wrapping_add(offset), range_length)))
}

#[inline]
fn validate_mapping_length(page_size: PageSize, length: usize) -> Result<()> {
    if length == 0 || length % page_size.bytes() != 0 {
        Err(Errno::INVAL)
    } else {
        Ok(())
    }
}

/// Reads monotonic time with the Unix primitive's millisecond truncation.
///
/// Linux 5.10 supplies `CLOCK_MONOTONIC`, so this keeps the upstream preferred
/// clock and intentionally omits the `clock()` low-resolution fallback. The
/// `i64` output is the pinned `mi_msecs_t` representation.
#[inline]
pub(crate) fn monotonic_milliseconds() -> Result<i64> {
    #[repr(C)]
    struct KernelTimespec {
        seconds: i64,
        nanoseconds: i64,
    }

    let mut time = core::mem::MaybeUninit::<KernelTimespec>::uninit();
    fault_before(FaultPoint::Clock)?;
    // SAFETY: `KernelTimespec` is the two-signed-word Linux 64-bit timespec
    // layout, and the kernel/vDSO initializes both words on success.
    unsafe { crabc_core::time::clock_gettime_raw(CLOCK_MONOTONIC, time.as_mut_ptr().cast()) }?;
    // SAFETY: the successful clock query initialized the exact output record.
    let time = unsafe { time.assume_init() };
    if time.seconds < 0 || !(0..1_000_000_000).contains(&time.nanoseconds) {
        return Err(Errno::RANGE);
    }
    time.seconds
        .checked_mul(1_000)
        .and_then(|seconds| seconds.checked_add(time.nanoseconds / 1_000_000))
        .ok_or(Errno::RANGE)
}

/// The source-complete `getrusage(RUSAGE_SELF)` portion of process statistics.
///
/// Unix mimalloc leaves current RSS and commit fields at the caller's default
/// values; this direct observation returns only the fields Linux populates in
/// `_mi_prim_process_info` rather than inventing a `/proc` parser.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProcessUsage {
    pub(crate) user_milliseconds: i64,
    pub(crate) system_milliseconds: i64,
    pub(crate) peak_resident_bytes: usize,
    pub(crate) major_page_faults: usize,
}

/// Reads the process observations used by the pinned Unix primitive.
#[inline]
pub(crate) fn process_usage() -> Result<ProcessUsage> {
    fault_before(FaultPoint::Process)?;
    let usage = crabc_core::process::getrusage_raw(RUSAGE_SELF)?;
    Ok(ProcessUsage {
        user_milliseconds: timeval_milliseconds(usage.ru_utime.tv_sec, usage.ru_utime.tv_usec)?,
        system_milliseconds: timeval_milliseconds(usage.ru_stime.tv_sec, usage.ru_stime.tv_usec)?,
        // Linux returns ru_maxrss in KiB. Reject impossible negative or
        // overflowing observations instead of silently wrapping a statistic.
        peak_resident_bytes: usize::try_from(usage.ru_maxrss)
            .ok()
            .and_then(|kibibytes| kibibytes.checked_mul(1024))
            .ok_or(Errno::RANGE)?,
        major_page_faults: usize::try_from(usage.ru_majflt).map_err(|_| Errno::RANGE)?,
    })
}

#[inline]
fn timeval_milliseconds(seconds: i64, microseconds: i64) -> Result<i64> {
    if seconds < 0 || !(0..1_000_000).contains(&microseconds) {
        return Err(Errno::RANGE);
    }
    seconds
        .checked_mul(1_000)
        .and_then(|seconds| seconds.checked_add(microseconds / 1_000))
        .ok_or(Errno::RANGE)
}

/// Returns the calling process's Linux process ID without libc state.
#[inline]
pub(crate) fn process_id() -> i32 {
    crabc_core::process::getpid()
}

/// Returns the calling Linux task ID without libc state.
#[inline]
pub(crate) fn thread_id() -> i32 {
    crabc_core::thread::gettid()
}

/// Returns the calling target TLS-register identity as an opaque value.
///
/// This is distinct from [`thread_id`]. It is suitable only for later
/// same-thread allocator ownership checks and is never dereferenced here.
#[inline]
pub(crate) fn thread_pointer_identity() -> usize {
    crabc_core::thread::thread_pointer_identity()
}

/// Returns the current NUMA node using the pinned Unix fallback convention.
///
/// `_mi_prim_numa_node` returns node zero when its `getcpu` syscall fails;
/// retain that source behavior rather than creating a topology policy here.
#[inline]
pub(crate) fn numa_node() -> usize {
    if fault_before(FaultPoint::Cpu).is_err() {
        return 0;
    }
    match crabc_core::thread::getcpu() {
        Ok(location) => location.numa_node as usize,
        Err(_) => 0,
    }
}

/// Returns the fixed allocator-facing cached NUMA-node count.
///
/// This is the no-option part of pinned `src/os.c:_mi_os_numa_node_count`.
/// It is intentionally distinct from [`numa_node_count`], which remains the
/// uncached Unix primitive used by the M1 raw C/Rust trace. The first wrapper
/// call uses that raw count, normalizes zero and values above `INT_MAX` to one,
/// and publishes the result with the source Release store.
#[allow(dead_code)]
#[inline]
pub(crate) fn os_numa_node_count() -> usize {
    os_numa_node_count_with_raw(&OS_NUMA_NODE_COUNT, numa_node_count)
}

/// Implements the fixed no-option count cache with injectable raw input.
///
/// The generic closure is statically dispatched in production and lets the
/// focused regression exercise cache and boundary behavior without changing
/// global process topology state. Deliberately retain the source's simple
/// load/fill/store shape: racing first callers may each observe the raw count;
/// this is not a CAS or once-initialization protocol.
#[inline]
fn os_numa_node_count_with_raw(
    cache: &AtomicUsize,
    mut raw_count: impl FnMut() -> usize,
) -> usize {
    let count = cache.load(Ordering::Acquire);
    let count = if count == 0 {
        let observed = raw_count();
        let normalized = if observed == 0 || observed > NUMA_NODE_INT_MAX {
            1
        } else {
            observed
        };
        cache.store(normalized, Ordering::Release);
        normalized
    } else {
        count
    };
    debug_assert!((1..=NUMA_NODE_INT_MAX).contains(&count));
    count
}

/// Returns the fixed allocator-facing current NUMA node.
///
/// This maps pinned `src/os.c:_mi_os_numa_node` and its private
/// `mi_os_numa_node_get` helper without options, diagnostics, arena placement,
/// or a caller integration. It keeps the raw [`numa_node`] observation intact
/// for the M1 trace and applies the source's cached-single-node shortcut,
/// strict `INT_MAX` current-node boundary, and modulo normalization only here.
#[allow(dead_code)]
#[inline]
pub(crate) fn os_numa_node() -> usize {
    os_numa_node_with_raw(&OS_NUMA_NODE_COUNT, numa_node_count, numa_node)
}

/// Implements the fixed cached current-node wrapper with injectable raw input.
#[inline]
fn os_numa_node_with_raw(
    cache: &AtomicUsize,
    raw_count: impl FnMut() -> usize,
    mut raw_current: impl FnMut() -> usize,
) -> usize {
    // `_mi_os_numa_node` uses a Relaxed fast path before it calls the helper
    // that performs the Acquire count load. A cached single-node process must
    // not perform either raw primitive observation.
    if cache.load(Ordering::Relaxed) == 1 {
        return 0;
    }

    let count = os_numa_node_count_with_raw(cache, raw_count);
    if count <= 1 {
        return 0;
    }

    // The source uses `n < INT_MAX`, deliberately excluding INT_MAX itself.
    let mut current = raw_current();
    if current >= NUMA_NODE_INT_MAX {
        current = 0;
    }
    if current >= count {
        current %= count;
    }
    current
}

/// Yields the calling task through Linux's direct scheduler primitive.
///
/// The Unix source's `sleep(0)` is only a best-effort yield request. Linux's
/// direct `sched_yield` is the corresponding no-libc kernel primitive and
/// preserves any kernel error for a later synchronization policy owner.
#[inline]
pub(crate) fn thread_yield() -> Result<()> {
    fault_before(FaultPoint::ThreadYield)?;
    crabc_core::thread::sched_yield()
}

/// Fills a caller-owned buffer through Linux `getrandom(GRND_NONBLOCK)`.
///
/// The boolean is `_mi_prim_random_buf`'s success predicate: a short success
/// is not enough. Linux 5.10 guarantees `getrandom`, so the historical
/// `/dev/urandom` fallback is intentionally absent. This is only raw entropy;
/// it does not instantiate or substitute for mimalloc's pinned random state.
#[inline]
pub(crate) fn entropy_fill(buffer: &mut [u8]) -> Result<bool> {
    fault_before(FaultPoint::Entropy)?;
    // SAFETY: `buffer` provides writable storage for exactly its supplied
    // length, including the zero-length case accepted by Linux getrandom.
    let count = unsafe {
        crabc_core::rand::getrandom_raw(buffer.as_mut_ptr(), buffer.len(), GRND_NONBLOCK)
    }?;
    Ok(count == buffer.len())
}

#[repr(u8)]
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum FaultPoint {
    Map = 1,
    Commit = 2,
    Decommit = 3,
    Purge = 4,
    Protect = 5,
    Unprotect = 6,
    Unmap = 7,
    Clock = 8,
    Process = 9,
    Cpu = 10,
    ThreadYield = 11,
    Entropy = 12,
}

#[cfg(not(any(test, feature = "native-runtime-test-fault")))]
#[inline]
fn fault_before(_point: FaultPoint) -> Result<()> {
    // Test-only injection compiles to this empty direct call in production;
    // no trait object, callback, or runtime dispatch is present.
    Ok(())
}

#[cfg(any(test, feature = "native-runtime-test-fault"))]
pub(crate) mod fault {
    use core::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};

    use crabc_core::{Errno, Result};

    pub(crate) use super::FaultPoint as Point;

    const ANY_POINT: usize = 0;
    static LOCKED: AtomicBool = AtomicBool::new(false);
    static SELECTED_POINT: AtomicUsize = AtomicUsize::new(ANY_POINT);
    static FAILURE_ORDINAL: AtomicUsize = AtomicUsize::new(0);
    static OBSERVED: AtomicUsize = AtomicUsize::new(0);
    static SECOND_SELECTED_POINT: AtomicUsize = AtomicUsize::new(ANY_POINT);
    static SECOND_FAILURE_ORDINAL: AtomicUsize = AtomicUsize::new(0);
    static SECOND_OBSERVED: AtomicUsize = AtomicUsize::new(0);
    // A paired rollback fault activates only after the primary operation has
    // failed. Setup `unmap`s before a later metadata `commit` must not
    // consume the cleanup `unmap` injection intended to follow that commit.
    static SECOND_ENABLED: AtomicBool = AtomicBool::new(false);
    static FAILURE_ERROR: AtomicI32 = AtomicI32::new(Errno::NOMEM.raw());

    /// An allocation-free deterministic failure plan for one serial test.
    #[derive(Clone, Copy)]
    pub(crate) struct Plan {
        point: usize,
        ordinal: usize,
        second_point: usize,
        second_ordinal: usize,
        error: Errno,
    }

    impl Plan {
        pub(crate) const fn disabled() -> Self {
            Self {
                point: ANY_POINT,
                ordinal: 0,
                second_point: ANY_POINT,
                second_ordinal: 0,
                error: Errno::NOMEM,
            }
        }

        pub(crate) const fn any_nth(ordinal: usize, error: Errno) -> Self {
            Self {
                point: ANY_POINT,
                ordinal,
                second_point: ANY_POINT,
                second_ordinal: 0,
                error,
            }
        }

        pub(crate) const fn at(point: Point, ordinal: usize, error: Errno) -> Self {
            Self {
                point: point as usize,
                ordinal,
                second_point: ANY_POINT,
                second_ordinal: 0,
                error,
            }
        }

        /// Fails a primary occurrence, then one rollback occurrence.
        ///
        /// The second point becomes active only after the first one fails.
        /// This stays allocation-free while testing a failed operation whose
        /// cleanup itself needs a second explicit release failure.
        pub(crate) const fn at_pair(
            point: Point,
            ordinal: usize,
            second_point: Point,
            second_ordinal: usize,
            error: Errno,
        ) -> Self {
            Self {
                point: point as usize,
                ordinal,
                second_point: second_point as usize,
                second_ordinal,
                error,
            }
        }
    }

    /// Serializes tests which exercise the process-global injection counters.
    ///
    /// This is test-only spin synchronization over static atomics; it neither
    /// allocates nor involves the allocator engine under test.
    pub(crate) struct Guard;

    pub(crate) fn install(plan: Plan) -> Guard {
        while LOCKED
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        set(plan);
        Guard
    }

    impl Guard {
        pub(crate) fn set(&self, plan: Plan) {
            set(plan);
        }

        pub(crate) fn observed(&self) -> usize {
            OBSERVED.load(Ordering::Acquire)
        }
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            set(Plan::disabled());
            LOCKED.store(false, Ordering::Release);
        }
    }

    #[inline]
    fn set(plan: Plan) {
        SELECTED_POINT.store(plan.point, Ordering::Relaxed);
        FAILURE_ORDINAL.store(plan.ordinal, Ordering::Relaxed);
        SECOND_SELECTED_POINT.store(plan.second_point, Ordering::Relaxed);
        SECOND_FAILURE_ORDINAL.store(plan.second_ordinal, Ordering::Relaxed);
        FAILURE_ERROR.store(plan.error.raw(), Ordering::Relaxed);
        OBSERVED.store(0, Ordering::Release);
        SECOND_OBSERVED.store(0, Ordering::Release);
        SECOND_ENABLED.store(false, Ordering::Release);
    }

    #[inline]
    pub(crate) fn before(point: Point) -> Result<()> {
        let selected = SELECTED_POINT.load(Ordering::Acquire);
        if selected == ANY_POINT || selected == point as usize {
            let ordinal = FAILURE_ORDINAL.load(Ordering::Acquire);
            if ordinal != 0 {
                let observed = OBSERVED.fetch_add(1, Ordering::AcqRel) + 1;
                if observed == ordinal {
                    SECOND_ENABLED.store(true, Ordering::Release);
                    let error = FAILURE_ERROR.load(Ordering::Acquire);
                    // SAFETY: `Plan` obtains `error` from a valid `Errno`, so
                    // the stored integer remains a positive Linux errno.
                    return Err(unsafe { Errno::from_raw(error).unwrap_unchecked() });
                }
            }
        }
        let second_selected = SECOND_SELECTED_POINT.load(Ordering::Acquire);
        if SECOND_ENABLED.load(Ordering::Acquire)
            && (second_selected == ANY_POINT || second_selected == point as usize)
        {
            let second_ordinal = SECOND_FAILURE_ORDINAL.load(Ordering::Acquire);
            if second_ordinal != 0 {
                let second_observed = SECOND_OBSERVED.fetch_add(1, Ordering::AcqRel) + 1;
                if second_observed == second_ordinal {
                    let error = FAILURE_ERROR.load(Ordering::Acquire);
                    // SAFETY: `Plan` obtains `error` from a valid `Errno`, so
                    // the stored integer remains a positive Linux errno.
                    return Err(unsafe { Errno::from_raw(error).unwrap_unchecked() });
                }
            }
        }
        Ok(())
    }
}

#[cfg(any(test, feature = "native-runtime-test-fault"))]
#[inline]
fn fault_before(point: FaultPoint) -> Result<()> {
    fault::before(point)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crabc_core::Errno;

    fn current_startup() -> StartupInput {
        let raw_page_size = crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
            .expect("the Linux test process must expose AT_PAGESZ");
        let page_size = PageSize::new(raw_page_size)
            .expect("AT_PAGESZ must be a valid Linux page size");
        StartupInput::new(page_size)
    }

    #[test]
    fn startup_page_size_represents_selected_linux_profile_granularities() {
        let _fault = fault::install(fault::Plan::disabled());
        assert!(PageSize::new(0).is_none());
        assert!(PageSize::new(3).is_none());
        assert_eq!(PageSize::new(4 * 1024).unwrap().bytes(), 4 * 1024);
        #[cfg(target_arch = "aarch64")]
        for bytes in [16 * 1024, 64 * 1024] {
            assert_eq!(PageSize::new(bytes).unwrap().bytes(), bytes);
        }
    }

    #[test]
    fn linux_numa_node_count_scan_preserves_sparse_gap_and_probe_order() {
        assert_eq!(scan_linux_numa_node_count(|_| false), 1);
        assert_eq!(scan_linux_numa_node_count(|node| node <= 3), 4);
        assert_eq!(
            scan_linux_numa_node_count(|node| node == 1 || node == 6),
            7,
            "four absent nodes remain sparse rather than ending the source scan",
        );

        let mut probed = [0usize; NUMA_NODE_SCAN_END - 1];
        let mut probe_count = 0;
        let observed_count = scan_linux_numa_node_count(|node| {
            probed[probe_count] = node;
            probe_count += 1;
            node == 1
        });
        assert_eq!(observed_count, 2);
        assert_eq!(
            &probed[..probe_count],
            &[1, 2, 3, 4, 5, 6],
            "the fifth absent node is probed before it ends the scan",
        );

        assert_eq!(
            scan_linux_numa_node_count(|node| node == 1 || node % 5 == 0),
            256,
            "the source scans node 255 and reports its index plus one",
        );
    }

    #[test]
    fn os_numa_wrapper_caches_and_normalizes_the_raw_primitives() {
        let cache = AtomicUsize::new(0);
        let mut raw_count_calls = 0;
        let mut raw_current_calls = 0;

        assert_eq!(
            os_numa_node_with_raw(
                &cache,
                || {
                    raw_count_calls += 1;
                    3
                },
                || {
                    raw_current_calls += 1;
                    8
                },
            ),
            2,
            "the source wrapper reduces the current node modulo its cached count",
        );
        assert_eq!(
            os_numa_node_count_with_raw(&cache, || panic!("the cached count must be reused")),
            3,
        );
        assert_eq!(raw_count_calls, 1, "the raw count is cached after its first probe");
        assert_eq!(raw_current_calls, 1);

        let cached_single_node = AtomicUsize::new(1);
        assert_eq!(
            os_numa_node_with_raw(
                &cached_single_node,
                || panic!("the relaxed single-node fast path must not probe a count"),
                || panic!("the relaxed single-node fast path must not probe a current node"),
            ),
            0,
        );

        let int_max = i32::MAX as usize;
        let accepted_maximum = AtomicUsize::new(0);
        assert_eq!(
            os_numa_node_count_with_raw(&accepted_maximum, || int_max),
            int_max,
            "the count condition accepts INT_MAX itself",
        );
        assert_eq!(accepted_maximum.load(Ordering::Relaxed), int_max);

        let oversized_count = AtomicUsize::new(0);
        assert_eq!(
            os_numa_node_count_with_raw(&oversized_count, || int_max + 1),
            1,
            "only counts above INT_MAX normalize to one",
        );
        let zero_count = AtomicUsize::new(0);
        assert_eq!(os_numa_node_count_with_raw(&zero_count, || 0), 1);

        let multi_node = AtomicUsize::new(5);
        assert_eq!(
            os_numa_node_with_raw(
                &multi_node,
                || panic!("a cached multi-node count must be reused"),
                || int_max - 1,
            ),
            (int_max - 1) % 5,
            "a current node below INT_MAX remains eligible for modulo normalization",
        );
        assert_eq!(
            os_numa_node_with_raw(
                &multi_node,
                || panic!("a cached multi-node count must be reused"),
                || int_max,
            ),
            0,
            "the current-node condition maps INT_MAX itself to zero",
        );
        assert_eq!(
            os_numa_node_with_raw(
                &multi_node,
                || panic!("a cached multi-node count must be reused"),
                || int_max + 1,
            ),
            0,
            "the current-node condition maps values above INT_MAX to zero",
        );
    }

    #[test]
    fn linux_numa_node_count_path_matches_source_sysfs_entries() {
        let mut path = [0u8; NUMA_NODE_PATH_CAPACITY];

        let one_length = write_linux_numa_node_path(1, &mut path).unwrap();
        assert_eq!(
            &path[..one_length],
            b"/sys/devices/system/node/node1\0",
        );

        let ten_length = write_linux_numa_node_path(10, &mut path).unwrap();
        assert_eq!(
            &path[..ten_length],
            b"/sys/devices/system/node/node10\0",
        );

        let last_length = write_linux_numa_node_path(255, &mut path).unwrap();
        assert_eq!(
            &path[..last_length],
            b"/sys/devices/system/node/node255\0",
        );
        assert!(write_linux_numa_node_path(0, &mut path).is_none());
        assert!(write_linux_numa_node_path(256, &mut path).is_none());
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn x86_64_startup_page_size_accepts_only_the_four_kib_profile() {
        assert_eq!(PageSize::new(4 * 1024).unwrap().bytes(), 4 * 1024);
        for bytes in [16 * 1024, 64 * 1024] {
            assert!(PageSize::new(bytes).is_none());
        }
    }

    #[test]
    fn memory_policy_parsers_preserve_linux_fallbacks_and_source_rounding() {
        let page_size = PageSize::new(4 * 1024).unwrap();
        let config = MemoryConfig::from_observations(page_size, 123_456, false, true);
        assert_eq!(config.page_size(), page_size);
        assert_eq!(config.large_page_size(), 2 * 1024 * 1024);
        assert_eq!(config.alloc_granularity(), page_size.bytes());
        assert_eq!(config.physical_memory_in_kib(), 123_456);
        assert_eq!(config.virtual_address_bits(), crate::config::MAX_VABITS);
        assert!(!config.has_overcommit());
        assert!(config.has_partial_free());
        assert!(config.has_virtual_reserve());
        assert!(config.has_transparent_huge_pages());

        assert!(overcommit_from_bytes(b"0\n"));
        assert!(overcommit_from_bytes(b"1\n"));
        assert!(!overcommit_from_bytes(b"2\n"));
        assert!(transparent_huge_pages_from_bytes(b"always [madvise] never\n"));
        assert!(!transparent_huge_pages_from_bytes(b"always madvise [never]\n"));
        assert_eq!(physical_memory_in_kib(17, 1024), Some(17));
        assert_eq!(physical_memory_in_kib(4097, 1), Some(4));
        assert_eq!(physical_memory_in_kib(1, 0), None);

        assert_eq!(config.good_alloc_size(1), 4 * 1024);
        assert_eq!(config.good_alloc_size(512 * 1024 + 1), 576 * 1024);
        assert_eq!(config.good_alloc_size(2 * 1024 * 1024 + 1), 2304 * 1024);
        assert_eq!(config.good_alloc_size(usize::MAX), usize::MAX);
        assert!(config.can_use_large_page(2 * 1024 * 1024, 2 * 1024 * 1024));
        assert!(!config.can_use_large_page(2 * 1024 * 1024, 4 * 1024));

        let detected = MemoryConfig::detect(current_startup());
        assert_eq!(detected.page_size(), current_startup().page_size());
        assert_eq!(detected.alloc_granularity(), detected.page_size().bytes());
        assert!(detected.physical_memory_in_kib() > 0);
        assert_eq!(detected.virtual_address_bits(), crate::config::MAX_VABITS);
        assert!(detected.has_partial_free());
        assert!(detected.has_virtual_reserve());
    }

    #[test]
    fn mapping_rejects_invalid_ranges_without_calling_a_kernel_fallback() {
        let fault = fault::install(fault::Plan::disabled());
        let startup = current_startup();
        let page = startup.page_size().bytes();
        let mut mapping = Mapping::map_anonymous(startup, page, MapAccess::Reserved)
            .expect("reserve one kernel page");
        assert!(mapping.base().is_ok());

        fault.set(fault::Plan::any_nth(1, Errno::NOMEM));
        assert_eq!(mapping.commit(1, page), Err(Errno::INVAL));
        assert_eq!(fault.observed(), 0, "invalid input must not reach an OS fallback");
        fault.set(fault::Plan::disabled());

        mapping.unmap().expect("release the valid mapping");
        assert_eq!(mapping.base(), Err(Errno::INVAL));
        assert_eq!(mapping.commit(0, page), Err(Errno::INVAL));
        assert_eq!(mapping.unmap(), Err(Errno::INVAL));
    }

    #[test]
    fn map_commit_protect_unprotect_and_unmap_have_an_explicit_lifecycle() {
        let _fault = fault::install(fault::Plan::disabled());
        let startup = current_startup();
        let page = startup.page_size().bytes();
        let mut mapping = Mapping::map_anonymous(startup, page, MapAccess::Reserved)
            .expect("reserve one kernel page");

        assert_eq!(mapping.commit(0, page), Ok(Some(CommitOutcome::NotKnownZero)));
        assert!(mapping.protect(0, page).expect("protect the committed page"));
        assert!(mapping.unprotect(0, page).expect("restore read/write access"));
        mapping.unmap().expect("release the mapped page");
    }

    #[test]
    fn decommit_and_purge_use_only_the_source_defined_page_transitions() {
        let _fault = fault::install(fault::Plan::disabled());
        let startup = current_startup();
        let page = startup.page_size().bytes();
        let mut mapping = Mapping::map_anonymous(startup, page, MapAccess::Committed)
            .expect("map one committed kernel page");

        assert!(mapping.initially_committed());
        assert!(mapping.initially_zero());
        assert_eq!(mapping.decommit(1, page - 1), Ok(None));
        assert_eq!(
            mapping.decommit(0, page),
            Ok(Some(DecommitOutcome::DoesNotNeedRecommit))
        );
        assert!(mapping.purge(0, page).expect("purge a full mapped page"));
        mapping.unmap().expect("release the mapped page");
    }

    #[test]
    fn reuse_is_a_contained_range_noop_on_linux() {
        let fault = fault::install(fault::Plan::disabled());
        let startup = current_startup();
        let page = startup.page_size().bytes();
        let length = page.checked_mul(2).expect("the selected two-page map fits");
        let mut mapping = Mapping::map_anonymous(startup, length, MapAccess::Committed)
            .expect("map two committed kernel pages");
        let base = mapping.base().expect("the mapping remains live");

        fault.set(fault::Plan::any_nth(1, Errno::NOMEM));
        assert_eq!(
            mapping.reuse(1, page - 1),
            Ok(None),
            "a source-conservative range with no complete page is a no-op"
        );
        assert_eq!(
            mapping.reuse(page, page),
            Ok(Some(ReuseOutcome::NoOp)),
            "Linux _mi_prim_reuse has no VM transition for a complete page"
        );
        assert_eq!(fault.observed(), 0, "Linux reuse does not enter a faultable VM edge");
        assert_eq!(mapping.base(), Ok(base));
        assert_eq!(mapping.length(), Ok(length));
        // SAFETY: Linux reuse leaves this owned committed mapping accessible.
        unsafe {
            core::ptr::write_volatile(base.wrapping_add(page), 0x6d);
            assert_eq!(core::ptr::read_volatile(base.wrapping_add(page)), 0x6d);
        }

        assert_eq!(mapping.reuse(length, 1), Err(Errno::INVAL));
        assert_eq!(fault.observed(), 0, "invalid input must not cross a VM edge");
        fault.set(fault::Plan::disabled());
        mapping.unmap().expect("release the exact mapping once");
        assert_eq!(mapping.reuse(0, page), Err(Errno::INVAL));
    }

    #[test]
    fn reset_retries_the_initial_advice_after_a_concurrent_global_fallback() {
        let advice_state = AtomicUsize::new(MADV_FREE as usize);
        let mut calls = [0u32; 2];
        let mut call_count = 0;

        let result = reset_with_advice(&advice_state, |advice| {
            calls[call_count] = advice;
            call_count += 1;
            if call_count == 1 {
                assert_eq!(advice, MADV_FREE);
                // Simulate a different reset caller discovering that
                // `MADV_FREE` is unsupported while this caller is retrying.
                advice_state.store(MADV_DONTNEED as usize, Ordering::Release);
                Err(Errno::AGAIN)
            } else {
                Ok(())
            }
        });

        assert_eq!(result, Ok(()));
        assert_eq!(call_count, 2);
        assert_eq!(calls, [MADV_FREE, MADV_FREE]);
        assert_eq!(
            advice_state.load(Ordering::Acquire),
            MADV_DONTNEED as usize,
            "the concurrent fallback remains visible to later reset callers"
        );
    }

    #[test]
    fn fault_injection_fails_the_selected_ordinal_without_a_hidden_retry() {
        let fault = fault::install(fault::Plan::disabled());
        let startup = current_startup();
        let page = startup.page_size().bytes();
        fault.set(fault::Plan::any_nth(2, Errno::NOMEM));

        let mut mapping = Mapping::map_anonymous(startup, page, MapAccess::Reserved)
            .expect("the first applicable operation must succeed");
        assert_eq!(mapping.commit(0, page), Err(Errno::NOMEM));
        assert_eq!(fault.observed(), 2, "the injected commit must not retry or fall back");
        fault.set(fault::Plan::disabled());

        mapping.unmap().expect("the failed commit leaves the reservation owned");
    }

    #[test]
    fn native_protection_failures_preserve_mapping_owner_and_retry() {
        let fault = fault::install(fault::Plan::disabled());
        let startup = current_startup();
        let page = startup.page_size().bytes();

        let mut protect_mapping = Mapping::map_anonymous(startup, page, MapAccess::Committed)
            .expect("map one committed page for the protect failure route");
        let protect_base = protect_mapping
            .base()
            .expect("the protect route starts with a live mapping owner");
        let protect_length = protect_mapping
            .length()
            .expect("the protect route starts with a live mapping extent");
        // SAFETY: this one committed page remains owned and accessible before
        // the selected test-only pre-syscall failure.
        unsafe {
            core::ptr::write_volatile(protect_base, 0x51);
            assert_eq!(core::ptr::read_volatile(protect_base), 0x51);
        }

        fault.set(fault::Plan::at(fault::Point::Protect, 1, Errno::NOMEM));
        assert_eq!(protect_mapping.protect(0, page), Err(Errno::NOMEM));
        assert_eq!(fault.observed(), 1, "the failed protect must not retry");
        assert_eq!(protect_mapping.base(), Ok(protect_base));
        assert_eq!(protect_mapping.length(), Ok(protect_length));
        // The injection occurs before `mprotect`, so a failed protect leaves
        // the page writable rather than creating an unobservable state.
        // SAFETY: the retained mapping is still committed, live, and writable.
        unsafe {
            core::ptr::write_volatile(protect_base, 0x52);
            assert_eq!(core::ptr::read_volatile(protect_base), 0x52);
        }

        fault.set(fault::Plan::disabled());
        assert_eq!(protect_mapping.protect(0, page), Ok(true));
        assert_eq!(protect_mapping.unprotect(0, page), Ok(true));
        // SAFETY: the successful retry restored read/write access before this
        // direct byte observation.
        unsafe {
            core::ptr::write_volatile(protect_base, 0x53);
            assert_eq!(core::ptr::read_volatile(protect_base), 0x53);
        }
        protect_mapping
            .unmap()
            .expect("the protect route releases its retained mapping once");

        let mut unprotect_mapping = Mapping::map_anonymous(startup, page, MapAccess::Committed)
            .expect("map one committed page for the unprotect failure route");
        let unprotect_base = unprotect_mapping
            .base()
            .expect("the unprotect route starts with a live mapping owner");
        let unprotect_length = unprotect_mapping
            .length()
            .expect("the unprotect route starts with a live mapping extent");
        assert_eq!(unprotect_mapping.protect(0, page), Ok(true));

        fault.set(fault::Plan::at(fault::Point::Unprotect, 1, Errno::NOMEM));
        assert_eq!(unprotect_mapping.unprotect(0, page), Err(Errno::NOMEM));
        assert_eq!(fault.observed(), 1, "the failed unprotect must not retry");
        assert_eq!(unprotect_mapping.base(), Ok(unprotect_base));
        assert_eq!(unprotect_mapping.length(), Ok(unprotect_length));
        // Do not dereference after the injected pre-syscall failure: the
        // preceding successful protect may still leave this page `PROT_NONE`.

        fault.set(fault::Plan::disabled());
        assert_eq!(unprotect_mapping.unprotect(0, page), Ok(true));
        // SAFETY: the successful retry restored read/write access to this
        // still-owned committed page.
        unsafe {
            core::ptr::write_volatile(unprotect_base, 0x54);
            assert_eq!(core::ptr::read_volatile(unprotect_base), 0x54);
        }
        unprotect_mapping
            .unmap()
            .expect("the unprotect route releases its retained mapping once");
    }

    #[test]
    fn normal_offset_os_allocation_retains_full_provenance_and_retries_release() {
        let fault = fault::install(fault::Plan::disabled());
        let config = MemoryConfig::detect(current_startup());
        let page = config.page_size().bytes();
        let size = page.checked_mul(2).expect("the selected allocation size fits");
        let alignment = page
            .checked_mul(4)
            .expect("the selected allocation alignment fits");
        let offset = page;
        let expected_extra = invariants::align_up(offset, alignment)
            .and_then(|aligned_offset| aligned_offset.checked_sub(offset))
            .expect("the selected source offset extra fits");

        // `_mi_os_alloc_aligned_at_offset` ignores a failed prefix decommit:
        // the returned allocation still owns the full mapping and client
        // pointer. The injected failure occurs before `madvise`, so the
        // committed client byte remains directly observable here.
        fault.set(fault::Plan::at(fault::Point::Decommit, 1, Errno::NOMEM));
        let allocation = NormalOsAllocation::allocate_aligned_at_offset(
            config,
            size,
            alignment,
            offset,
            MapAccess::Committed,
        )
        .expect("a failed best-effort prefix decommit must not discard the allocation");
        assert_eq!(fault.observed(), 1, "the prefix decommit was attempted once");

        let base = allocation
            .base()
            .expect("the allocation retains its full mapping base");
        let full_size = allocation
            .full_size()
            .expect("the allocation retains its full mapping length");
        let pointer = allocation
            .pointer()
            .expect("the allocation exposes its interior client pointer");
        let memory = allocation
            .memory_id()
            .expect("the allocation retains OS provenance for the full map");
        assert_eq!(pointer.as_ptr().addr() - base.addr(), expected_extra);
        assert_eq!((pointer.as_ptr().addr() + offset) % alignment, 0);
        assert_eq!(full_size, config.good_alloc_size(size + expected_extra));
        assert_eq!(memory.os_base().map(|address| address.value()), Some(base.addr()));
        assert_eq!(memory.size(), Some(full_size));
        assert!(memory.is_os());
        assert!(!memory.is_pinned());
        assert!(memory.initially_committed());
        assert!(memory.initially_zero());
        // SAFETY: the committed mapping remains live, and `pointer` is its
        // client start after the source-shaped reserved/decommitted prefix.
        unsafe {
            core::ptr::write_volatile(pointer.as_ptr(), 0x5a);
            assert_eq!(core::ptr::read_volatile(pointer.as_ptr()), 0x5a);
        }

        fault.set(fault::Plan::at(fault::Point::Unmap, 1, Errno::NOMEM));
        let failure = match allocation.release() {
            Ok(()) => panic!("the selected release must retain its owner on failure"),
            Err(failure) => failure,
        };
        assert_eq!(failure.error(), Errno::NOMEM);
        assert_eq!(fault.observed(), 1, "the failed release must not retry");

        let allocation = failure.into_allocation();
        assert_eq!(allocation.base(), Ok(base));
        assert_eq!(allocation.full_size(), Ok(full_size));
        assert_eq!(allocation.pointer(), Ok(pointer));
        assert_eq!(
            allocation.memory_id().unwrap().os_base().map(|address| address.value()),
            Some(base.addr()),
        );

        fault.set(fault::Plan::disabled());
        allocation
            .release()
            .expect("the retained exact mapping releases once after retry");
    }

    #[test]
    fn normal_os_allocation_uses_good_size_and_base_provenance() {
        let _fault = fault::install(fault::Plan::disabled());
        let config = MemoryConfig::detect(current_startup());
        let page = config.page_size().bytes();
        let requested_size = page
            .checked_add(1)
            .expect("the selected normal allocation size fits");

        let allocation = NormalOsAllocation::allocate(config, requested_size)
            .expect("the fixed normal OS route maps one committed owner");
        let base = allocation.base().expect("the normal mapping remains live");
        assert_eq!(allocation.pointer(), Ok(NonNull::new(base).unwrap()));
        assert_eq!(allocation.full_size(), Ok(config.good_alloc_size(requested_size)));
        let memory = allocation.memory_id().expect("the normal map has OS provenance");
        assert_eq!(memory.os_base().map(|address| address.value()), Some(base.addr()));
        assert_eq!(memory.size(), allocation.full_size().ok());
        assert!(memory.initially_committed());
        assert!(memory.initially_zero());
        allocation
            .release()
            .expect("the normal owner releases its exact mapping");
    }

    #[test]
    fn normal_offset_os_allocation_delegates_zero_and_rejects_invalid_geometry() {
        let fault = fault::install(fault::Plan::disabled());
        let config = MemoryConfig::detect(current_startup());
        let page = config.page_size().bytes();
        let size = page.checked_mul(2).expect("the selected allocation size fits");
        let alignment = page
            .checked_mul(4)
            .expect("the selected allocation alignment fits");

        // The zero-offset route is exactly the ordinary aligned-allocation
        // route: it has no interior client pointer or prefix decommit.
        let allocation = NormalOsAllocation::allocate_aligned_at_offset(
            config,
            size,
            alignment,
            0,
            MapAccess::Reserved,
        )
        .expect("zero offset delegates to the ordinary aligned mapping");
        let base = allocation.base().expect("the zero-offset base remains live");
        assert_eq!(allocation.pointer(), Ok(NonNull::new(base).unwrap()));
        assert_eq!(allocation.full_size(), Ok(config.good_alloc_size(size)));
        let memory = allocation.memory_id().expect("the zero-offset mapping has provenance");
        assert_eq!(memory.os_base().map(|address| address.value()), Some(base.addr()));
        assert_eq!(memory.size(), allocation.full_size().ok());
        assert!(!memory.initially_committed());
        allocation
            .release()
            .expect("the zero-offset owner releases its exact mapping");

        // The zero-offset delegate reaches `_mi_os_alloc_aligned`, which
        // rounds this source input up to the kernel page before its primitive
        // aligned-map check. The nonzero-offset branch must not preempt that
        // separate route with its own page-multiple input boundary.
        let sub_page_alignment = page
            .checked_sub(1)
            .expect("the Linux page size exceeds one byte");
        let allocation = NormalOsAllocation::allocate_aligned_at_offset(
            config,
            size,
            sub_page_alignment,
            0,
            MapAccess::Reserved,
        )
        .expect("zero offset delegates through source page alignment normalization");
        let base = allocation
            .base()
            .expect("the normalized zero-offset mapping remains live");
        assert_eq!(base.addr() % page, 0);
        assert_eq!(allocation.pointer(), Ok(NonNull::new(base).unwrap()));
        allocation
            .release()
            .expect("the normalized zero-offset owner releases its exact mapping");

        // The source only discards an offset prefix after a committed map.
        // A reserved interior allocation still carries its full base/length
        // owner, but it must not issue a decommit advisory.
        fault.set(fault::Plan::at(fault::Point::Decommit, 1, Errno::NOMEM));
        let allocation = NormalOsAllocation::allocate_aligned_at_offset(
            config,
            size,
            alignment,
            page,
            MapAccess::Reserved,
        )
        .expect("a reserved offset allocation does not decommit its prefix");
        assert_eq!(fault.observed(), 0, "reserved offset allocation must not decommit");
        let memory = allocation
            .memory_id()
            .expect("the reserved offset map retains OS provenance");
        assert!(!memory.initially_committed());
        allocation
            .release()
            .expect("the reserved offset owner releases its exact mapping");

        fault.set(fault::Plan::at(fault::Point::Map, 1, Errno::NOMEM));
        let invalid_offset = match NormalOsAllocation::allocate_aligned_at_offset(
            config,
            size,
            alignment,
            size.checked_add(1).expect("the selected invalid offset fits"),
            MapAccess::Committed,
        ) {
            Ok(allocation) => {
                let _ = allocation.release();
                panic!("an offset beyond the requested size must not map")
            }
            Err(failure) => failure,
        };
        assert_eq!(invalid_offset.error(), Errno::INVAL);
        assert!(invalid_offset.into_mapping().is_none());
        assert_eq!(fault.observed(), 0, "invalid geometry must not reach mmap");

        let extra = invariants::align_up(page, alignment)
            .and_then(|aligned_offset| aligned_offset.checked_sub(page))
            .expect("the selected source offset extra fits");
        let overflowing_size = usize::MAX - extra;
        fault.set(fault::Plan::at(fault::Point::Map, 1, Errno::NOMEM));
        let overflow = match NormalOsAllocation::allocate_aligned_at_offset(
            config,
            overflowing_size,
            alignment,
            page,
            MapAccess::Committed,
        ) {
            Ok(allocation) => {
                let _ = allocation.release();
                panic!("an overflowing source oversize must not map")
            }
            Err(failure) => failure,
        };
        assert_eq!(overflow.error(), Errno::NOMEM);
        assert!(overflow.into_mapping().is_none());
        assert_eq!(fault.observed(), 0, "overflow must not reach mmap");
    }

    #[test]
    fn normal_os_allocation_preserves_a_failed_aligned_map_owner() {
        let fault = fault::install(fault::Plan::at(
            fault::Point::Unmap,
            1,
            Errno::NOMEM,
        ));
        let config = MemoryConfig::detect(current_startup());
        let page = config.page_size().bytes();
        let size = page.checked_mul(2).expect("the selected allocation size fits");
        let alignment = page
            .checked_mul(2)
            .expect("the selected allocation alignment fits");

        let failure = match NormalOsAllocation::allocate_aligned_force_full_trim_for_test(
            config,
            size,
            alignment,
            MapAccess::Reserved,
        ) {
            Ok(allocation) => {
                let _ = allocation.release();
                panic!("a failed direct-candidate cleanup must retain its mapping")
            }
            Err(failure) => failure,
        };
        assert_eq!(failure.error(), Errno::NOMEM);
        let mut mapping = failure
            .into_mapping()
            .expect("the owner boundary must retain the failed aligned-map candidate");
        assert_eq!(mapping.length(), Ok(config.good_alloc_size(size)));

        fault.set(fault::Plan::disabled());
        mapping
            .unmap()
            .expect("the retained aligned-map candidate releases after retry");
    }

    #[test]
    fn aligned_mapping_retains_the_direct_candidate_when_its_cleanup_fails() {
        let fault = fault::install(fault::Plan::at(
            fault::Point::Unmap,
            1,
            Errno::NOMEM,
        ));
        let config = MemoryConfig::detect(current_startup());
        let page = config.page_size().bytes();
        let length = page.checked_mul(2).expect("the selected test length fits");
        let alignment = page.checked_mul(2).expect("the selected test alignment fits");

        let failure = match Mapping::map_aligned_for_allocator_force_full_trim_for_test(
            config,
            length,
            alignment,
            MapAccess::Reserved,
        ) {
            Ok(mut mapping) => {
                let _ = mapping.unmap();
                panic!("the first forced aligned-map cleanup must fail")
            }
            Err(failure) => failure,
        };
        assert_eq!(failure.error(), Errno::NOMEM);
        assert_eq!(fault.observed(), 1, "the failed direct cleanup stops before overmapping");
        let mut retained = failure
            .into_mapping()
            .expect("the failed direct cleanup retains its exact mapping");
        assert_eq!(retained.length(), Ok(length));

        fault.set(fault::Plan::disabled());
        retained
            .unmap()
            .expect("the retained direct candidate releases exactly once after retry");
    }

    #[test]
    fn aligned_mapping_retains_the_untrimmed_overmap_when_prefix_release_fails() {
        let fault = fault::install(fault::Plan::at(
            fault::Point::Unmap,
            2,
            Errno::NOMEM,
        ));
        let config = MemoryConfig::detect(current_startup());
        let page = config.page_size().bytes();
        let length = page.checked_mul(2).expect("the selected test length fits");
        let alignment = page.checked_mul(2).expect("the selected test alignment fits");
        let forced_over_length = length
            .checked_add(alignment.checked_mul(2).expect("the test headroom fits"))
            .expect("the forced overmap length fits");

        let failure = match Mapping::map_aligned_for_allocator_force_full_trim_for_test(
            config,
            length,
            alignment,
            MapAccess::Reserved,
        ) {
            Ok(mut mapping) => {
                let _ = mapping.unmap();
                panic!("the forced prefix cleanup must fail")
            }
            Err(failure) => failure,
        };
        assert_eq!(failure.error(), Errno::NOMEM);
        assert_eq!(fault.observed(), 2, "the prefix is the second release edge");
        let mut retained = failure
            .into_mapping()
            .expect("the failed prefix release retains the untouched overmap");
        assert_eq!(
            retained.length(),
            Ok(forced_over_length),
            "no successful partial release may be claimed after a failed prefix"
        );

        fault.set(fault::Plan::disabled());
        retained
            .unmap()
            .expect("the untrimmed retained overmap releases exactly once after retry");
    }

    #[test]
    fn aligned_mapping_retains_only_the_live_suffix_when_suffix_release_fails() {
        let fault = fault::install(fault::Plan::at(
            fault::Point::Unmap,
            3,
            Errno::NOMEM,
        ));
        let config = MemoryConfig::detect(current_startup());
        let page = config.page_size().bytes();
        let length = page.checked_mul(2).expect("the selected test length fits");
        let alignment = page.checked_mul(2).expect("the selected test alignment fits");

        let failure = match Mapping::map_aligned_for_allocator_force_full_trim_for_test(
            config,
            length,
            alignment,
            MapAccess::Reserved,
        ) {
            Ok(mut mapping) => {
                let _ = mapping.unmap();
                panic!("the forced suffix cleanup must fail")
            }
            Err(failure) => failure,
        };
        assert_eq!(failure.error(), Errno::NOMEM);
        assert_eq!(fault.observed(), 3, "the suffix is the third release edge");
        let mut retained = failure
            .into_mapping()
            .expect("the failed suffix release retains its exact remaining range");
        assert_eq!(
            retained.base().expect("the retained suffix range remains live").addr() % alignment,
            0,
            "the prefix was released before the suffix failure"
        );
        assert!(
            retained.length().expect("the retained suffix range remains live") > length,
            "the retained owner includes the live suffix rather than claiming it was released"
        );

        fault.set(fault::Plan::disabled());
        retained
            .unmap()
            .expect("the aligned-plus-suffix retained range releases exactly once after retry");
    }

    #[test]
    fn forced_aligned_mapping_exercises_all_three_release_edges_before_returning_the_exact_range() {
        let fault = fault::install(fault::Plan::at(
            fault::Point::Unmap,
            99,
            Errno::NOMEM,
        ));
        let config = MemoryConfig::detect(current_startup());
        let page = config.page_size().bytes();
        let length = page.checked_mul(2).expect("the selected test length fits");
        let alignment = page.checked_mul(2).expect("the selected test alignment fits");

        let mut mapping = Mapping::map_aligned_for_allocator_force_full_trim_for_test(
            config,
            length,
            alignment,
            MapAccess::Reserved,
        )
        .expect("the forced aligned mapping succeeds without an injected failure");
        assert_eq!(fault.observed(), 3, "direct, prefix, and suffix releases all ran");
        assert_eq!(
            mapping.base().expect("the aligned result remains live").addr() % alignment,
            0
        );
        assert_eq!(mapping.length(), Ok(length));

        fault.set(fault::Plan::disabled());
        mapping
            .unmap()
            .expect("the exact aligned result releases after its three trims");
    }

    #[test]
    fn purge_failure_does_not_substitute_an_unclaimed_memory_transition() {
        let fault = fault::install(fault::Plan::disabled());
        let startup = current_startup();
        let page = startup.page_size().bytes();
        let mut mapping = Mapping::map_anonymous(startup, page, MapAccess::Committed)
            .expect("map one committed kernel page");

        fault.set(fault::Plan::at(fault::Point::Purge, 1, Errno::NOMEM));
        assert_eq!(mapping.purge(0, page), Err(Errno::NOMEM));
        assert_eq!(fault.observed(), 1, "NOMEM must not trigger a second advisory");
        fault.set(fault::Plan::disabled());
        mapping.unmap().expect("the failed purge leaves the mapping owned");
    }

    #[test]
    fn direct_process_thread_clock_cpu_and_entropy_observations_stay_available() {
        let _fault = fault::install(fault::Plan::disabled());

        assert!(process_id() > 0);
        assert!(thread_id() > 0);
        assert_ne!(thread_pointer_identity(), 0);
        let before = monotonic_milliseconds().expect("CLOCK_MONOTONIC");
        thread_yield().expect("sched_yield");
        let after = monotonic_milliseconds().expect("CLOCK_MONOTONIC");
        assert!(after >= before);

        let usage = process_usage().expect("getrusage(RUSAGE_SELF)");
        assert!(usage.user_milliseconds >= 0);
        assert!(usage.system_milliseconds >= 0);
        let _peak_resident_bytes = usage.peak_resident_bytes;
        let _major_page_faults = usage.major_page_faults;
        let _numa_node = numa_node();
        assert!(
            numa_node_count() >= 1,
            "the raw NUMA-count observation preserves its one-node fallback",
        );

        let mut bytes = [0u8; 16];
        assert!(entropy_fill(&mut bytes).expect("Linux getrandom"));
    }

    /// Emits the finite, address-independent M1 raw primitive record.
    ///
    /// `compat/allocator/run.py` compares this one-test machine record to an
    /// executable built from the pinned C `src/os.c` and `src/prim/prim.c`.
    /// It deliberately covers only the frozen normal-success paths below;
    /// error/fallback paths, option mutation, hints, huge pages, and allocator
    /// lifecycle ownership remain separate source-map work.
    #[test]
    fn emit_m1_raw_c_rust_trace() {
        let _fault = fault::install(fault::Plan::disabled());
        let config = MemoryConfig::detect(current_startup());
        let page = config.page_size().bytes();
        let mut mapping = Mapping::map_for_allocator(config, page, MapAccess::Reserved)
            .expect("the selected one-page regular mapping succeeds");
        let initially_zero = mapping.initially_zero();
        let initially_committed = mapping.initially_committed();
        assert_eq!(
            mapping.commit(0, page),
            Ok(Some(CommitOutcome::NotKnownZero)),
            "the Unix commit path reports no known-zero guarantee"
        );
        assert_eq!(
            mapping.decommit(0, page),
            Ok(Some(DecommitOutcome::DoesNotNeedRecommit)),
            "the frozen release profile keeps a decommitted map accessible"
        );
        assert!(mapping.purge(0, page).expect("the selected reset succeeds"));
        assert!(mapping.protect(0, page).expect("the selected protect succeeds"));
        assert!(mapping
            .unprotect(0, page)
            .expect("the selected unprotect succeeds"));
        mapping.unmap().expect("the selected map is released explicitly");

        let clock_before = monotonic_milliseconds().expect("CLOCK_MONOTONIC");
        thread_yield().expect("the direct Linux yield succeeds");
        let clock_after = monotonic_milliseconds().expect("CLOCK_MONOTONIC");
        let mut zero_entropy = [0u8; 0];
        let mut sixteen_entropy = [0u8; 16];
        assert!(entropy_fill(&mut zero_entropy).expect("zero-byte getrandom"));
        assert!(entropy_fill(&mut sixteen_entropy).expect("sixteen-byte getrandom"));
        let numa_count = numa_node_count();
        let numa_current = numa_node();
        assert!(numa_count >= 1, "the source scan has a one-node fallback");

        macro_rules! emit {
            ($name:literal, $value:expr) => {
                std::println!("{}={}", $name, $value);
            };
        }

        std::println!("CRABC_MI_M1_RAW_TRACE_BEGIN");
        emit!("m1.raw.config.page_size", config.page_size().bytes());
        emit!("m1.raw.config.large_page_size", config.large_page_size());
        emit!("m1.raw.config.alloc_granularity", config.alloc_granularity());
        emit!(
            "m1.raw.config.physical_memory_in_kib",
            config.physical_memory_in_kib()
        );
        emit!("m1.raw.config.virtual_address_bits", config.virtual_address_bits());
        emit!("m1.raw.config.has_overcommit", u8::from(config.has_overcommit()));
        emit!("m1.raw.config.has_partial_free", u8::from(config.has_partial_free()));
        emit!("m1.raw.config.has_virtual_reserve", u8::from(config.has_virtual_reserve()));
        emit!(
            "m1.raw.config.has_transparent_huge_pages",
            u8::from(config.has_transparent_huge_pages())
        );

        emit!("m1.raw.good_alloc_size.zero", config.good_alloc_size(0));
        emit!("m1.raw.good_alloc_size.one", config.good_alloc_size(1));
        emit!(
            "m1.raw.good_alloc_size.512k_minus_one",
            config.good_alloc_size(512 * 1024 - 1)
        );
        emit!("m1.raw.good_alloc_size.512k", config.good_alloc_size(512 * 1024));
        emit!(
            "m1.raw.good_alloc_size.512k_plus_one",
            config.good_alloc_size(512 * 1024 + 1)
        );
        emit!(
            "m1.raw.good_alloc_size.2m_minus_one",
            config.good_alloc_size(2 * 1024 * 1024 - 1)
        );
        emit!("m1.raw.good_alloc_size.2m", config.good_alloc_size(2 * 1024 * 1024));
        emit!(
            "m1.raw.good_alloc_size.2m_plus_one",
            config.good_alloc_size(2 * 1024 * 1024 + 1)
        );
        emit!(
            "m1.raw.good_alloc_size.8m_minus_one",
            config.good_alloc_size(8 * 1024 * 1024 - 1)
        );
        emit!("m1.raw.good_alloc_size.8m", config.good_alloc_size(8 * 1024 * 1024));
        emit!(
            "m1.raw.good_alloc_size.8m_plus_one",
            config.good_alloc_size(8 * 1024 * 1024 + 1)
        );
        emit!(
            "m1.raw.good_alloc_size.32m_minus_one",
            config.good_alloc_size(32 * 1024 * 1024 - 1)
        );
        emit!("m1.raw.good_alloc_size.32m", config.good_alloc_size(32 * 1024 * 1024));
        emit!(
            "m1.raw.good_alloc_size.32m_plus_one",
            config.good_alloc_size(32 * 1024 * 1024 + 1)
        );
        emit!("m1.raw.good_alloc_size.size_max", config.good_alloc_size(usize::MAX));
        emit!(
            "m1.raw.can_use_large_page.aligned",
            u8::from(config.can_use_large_page(2 * 1024 * 1024, 2 * 1024 * 1024))
        );
        emit!(
            "m1.raw.can_use_large_page.page_aligned_only",
            u8::from(config.can_use_large_page(2 * 1024 * 1024, page))
        );

        emit!("m1.raw.map.request.no_hint", 1);
        emit!("m1.raw.map.request.allow_large", 0);
        emit!("m1.raw.map.reserved.success", 1);
        emit!("m1.raw.map.reserved.is_large", 0);
        emit!("m1.raw.map.reserved.is_zero", u8::from(initially_zero));
        emit!(
            "m1.raw.map.reserved.initially_committed",
            u8::from(initially_committed)
        );
        emit!("m1.raw.map.commit.success", 1);
        emit!("m1.raw.map.commit.is_zero", 0);
        emit!("m1.raw.map.decommit.success", 1);
        emit!("m1.raw.map.decommit.needs_recommit", 0);
        emit!("m1.raw.map.reset.success", 1);
        emit!("m1.raw.map.protect.success", 1);
        emit!("m1.raw.map.unprotect.success", 1);
        emit!("m1.raw.map.free.success", 1);

        emit!("m1.raw.numa.count", numa_count);
        emit!("m1.raw.numa.current_lt_count", u8::from(numa_current < numa_count));
        emit!(
            "m1.raw.clock.monotonic_after_yield",
            u8::from(clock_after >= clock_before)
        );
        emit!("m1.raw.yield.success", 1);
        emit!("m1.raw.entropy.zero_success", 1);
        emit!("m1.raw.entropy.sixteen_success", 1);
        emit!(
            "m1.raw.threadpool.false",
            u8::from(!crate::types::ThreadLocalData::detached().is_in_threadpool())
        );
        std::println!("CRABC_MI_M1_RAW_TRACE_END");
    }

    #[test]
    fn entropy_failure_is_direct_and_never_uses_a_secondary_source() {
        let fault = fault::install(fault::Plan::at(fault::Point::Entropy, 1, Errno::NOMEM));
        let mut bytes = [0u8; 16];

        assert_eq!(entropy_fill(&mut bytes), Err(Errno::NOMEM));
        assert_eq!(fault.observed(), 1);
    }
}
