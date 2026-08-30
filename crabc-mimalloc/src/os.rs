// Copyright (c) 2018-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `include/mimalloc/prim.h`,
// `src/prim/prim.c`, `src/prim/unix/prim.c`, and the raw page-alignment and
// memory-transition portions of `src/os.c`, including `src/os.c:655-680`'s
// default `purge_decommits` branch for non-owning arena spans.

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

use core::num::NonZeroUsize;
use core::sync::atomic::{AtomicUsize, Ordering};

use crabc_core::{Errno, Result};

use crate::invariants;

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

// `src/prim/unix/prim.c:_mi_prim_reset` starts with MADV_FREE and permanently
// switches to MADV_DONTNEED only when Linux says MADV_FREE is unsupported.
// The frozen normal-release profile has no secure/debug mprotect transition
// after decommit, so this static is the only raw Unix reset policy retained.
static RESET_ADVICE: AtomicUsize = AtomicUsize::new(MADV_FREE as usize);

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
        }
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
    ) -> Result<Self> {
        let page_size = config.page_size().bytes();
        if alignment < page_size || !alignment.is_power_of_two() {
            return Err(Errno::INVAL);
        }
        let mut direct = Self::map_for_allocator(config, length, access)?;
        let direct_base = direct.base()?;
        if direct_base.addr() % alignment == 0 {
            return Ok(direct);
        }
        direct.unmap()?;

        let over_length = length.checked_add(alignment).ok_or(Errno::NOMEM)?;
        let mut over = Self::map_for_allocator(config, over_length, access)?;
        let base = over.base()?;
        let aligned_address = invariants::align_up(base.addr(), alignment).ok_or(Errno::NOMEM)?;
        let prefix = aligned_address - base.addr();
        let suffix = over_length - prefix - length;
        let aligned = base.wrapping_add(prefix);

        if prefix != 0 {
            unsafe { crabc_core::mm::munmap_raw(base, prefix) }?;
        }
        if suffix != 0 {
            unsafe { crabc_core::mm::munmap_raw(aligned.wrapping_add(length), suffix) }?;
        }
        over.address = aligned;
        over.length = length;
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

        loop {
            let advice = RESET_ADVICE.load(Ordering::Relaxed) as u32;
            fault_before(FaultPoint::Purge)?;
            // SAFETY: `range` is a complete-page subrange of this live mapping.
            // The advisory may discard contents but does not yield references
            // or alter this boundary's ownership state.
            match unsafe { crabc_core::mm::madvise_raw(range.address, range.length, advice) } {
                Ok(()) => return Ok(true),
                Err(Errno::AGAIN) => continue,
                Err(Errno::INVAL) if advice == MADV_FREE => {
                    RESET_ADVICE.store(MADV_DONTNEED as usize, Ordering::Release);
                    fault_before(FaultPoint::Purge)?;
                    // SAFETY: The range contract is unchanged for the explicit
                    // source-defined MADV_DONTNEED fallback.
                    return unsafe {
                        crabc_core::mm::madvise_raw(range.address, range.length, MADV_DONTNEED)
                    }
                    .map(|_| true);
                }
                Err(error) => return Err(error),
            }
        }
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

        let mut bytes = [0u8; 16];
        assert!(entropy_fill(&mut bytes).expect("Linux getrandom"));
    }

    #[test]
    fn entropy_failure_is_direct_and_never_uses_a_secondary_source() {
        let fault = fault::install(fault::Plan::at(fault::Point::Entropy, 1, Errno::NOMEM));
        let mut bytes = [0u8; 16];

        assert_eq!(entropy_fill(&mut bytes), Err(Errno::NOMEM));
        assert_eq!(fault.observed(), 1);
    }
}
