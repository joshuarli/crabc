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
//! This boundary includes the pinned immutable OS-memory configuration and
//! ordinary mmap policy needed by the live page map: Linux overcommit/THP and
//! physical-memory observation, regular and guaranteed-aligned mappings,
//! commit/uncommit transitions, reset/purge, protection, and explicit release.
//! It also has a resolved, borrowed [`VmProcess`] boundary for source VM
//! options, randomized aligned hints, the process-local THP transition, and
//! the exact VM statistic fields that a source map/release mutates.
//!
//! That borrowed boundary deliberately does not create ambient environment or
//! random-state ownership. A process initializer must still retain the
//! resolved [`VmPolicy`], supply the real [`TheapRandomImage`] to the source
//! callers that consume it, and bind arena/metadata backing before those
//! callers can claim full process VM integration. One-GiB huge-page progress,
//! timeout, and release ownership remain unqualified until that owner exists;
//! this module never represents those missing paths as a successful fallback.
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
use core::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};

use crabc_core::{Errno, Result};

use crate::config::{ARENA_SLICE_SIZE, VmOption, VmOptionState, VmOptions};
#[cfg(test)]
use crate::config::VmOptionEnvironment;
use crate::invariants;
use crate::random::TheapRandomImage;
use crate::types::{MemoryId, MemoryKind};

// Linux values shared by the exact AArch64 and x86-64 Unix primitive paths.
// These are intentionally private: allocator policy does not receive an open
// mmap or madvise flag vocabulary from this module.
const PROT_NONE: u32 = 0;
const PROT_READ: u32 = 0x1;
const PROT_WRITE: u32 = 0x2;
const MAP_PRIVATE: u32 = 0x02;
const MAP_ANONYMOUS: u32 = 0x20;
const MAP_NORESERVE: u32 = 0x4000;
const MAP_HUGETLB: u32 = 0x40000;
const MAP_HUGE_SHIFT: u32 = 26;
const MAP_HUGE_2MB: u32 = 21 << MAP_HUGE_SHIFT;
const MAP_HUGE_1GB: u32 = 30 << MAP_HUGE_SHIFT;
const MADV_DONTNEED: u32 = 4;
const MADV_FREE: u32 = 8;
const MADV_HUGEPAGE: u32 = 14;
const PR_SET_THP_DISABLE: i32 = 41;
const PR_GET_THP_DISABLE: i32 = 42;
const MPOL_PREFERRED: i32 = 1;
const CLOCK_MONOTONIC: i32 = 1;
const CLOCK_PROCESS_CPUTIME_ID: i32 = 2;
// The pinned native musl oracle's `clock()` reports microsecond ticks.
const SOURCE_CLOCKS_PER_SECOND: i64 = 1_000_000;
const GRND_NONBLOCK: u32 = 0x1;
const RUSAGE_SELF: i32 = 0;
const R_OK: u32 = 4;

const MIB: usize = 1024 * 1024;
const GIB: usize = 1024 * MIB;
const HINT_BASE: usize = 2 << 40;
const HINT_AREA: usize = 4 << 40;
const HINT_MAX: usize = 30 << 40;
const HUGE_HINT_BASE: usize = 32 << 40;
const HUGE_PAGE_SIZE: usize = GIB;
const LARGE_PAGE_FAILED_RETRY_COUNT: usize = 8;

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

// Pinned `src/stats.c` calibrates this process-wide subtraction once through
// `_mi_clock_start` and applies it to every `_mi_clock_end`. Huge-page
// reservation is the first active caller of that source timer in this port;
// retain the same shared calibration rather than giving each reservation an
// independently invented timeout clock.
static SOURCE_CLOCK_DIFF_MILLISECONDS: AtomicI64 = AtomicI64::new(0);

// Linux's fixed two-signed-word 64-bit timespec ABI.  Both source clock
// paths use this exact raw record and never require a libc clock wrapper.
#[repr(C)]
struct KernelTimespec {
    seconds: i64,
    nanoseconds: i64,
}

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

    /// Applies the `mi_option_allow_thp == 0` source policy after Linux
    /// primitive probing. The pinned Unix code clears this fact before it
    /// attempts `PR_GET_THP_DISABLE`, so an unavailable or denied `prctl`
    /// never lets later allocation policy claim THP remains enabled.
    #[inline]
    fn disable_transparent_huge_pages(&mut self) {
        self.has_transparent_huge_pages = false;
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

/// A fully resolved VM option image cannot be manufactured from a partial
/// process-start observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum VmPolicyConfigurationError {
    UnresolvedOption(VmOption),
}

/// Observable result of the source's process-local THP disable attempt.
///
/// `_mi_prim_mem_init` deliberately continues after either `prctl` error. The
/// value records that fact for the native differential trace without turning a
/// best-effort source policy into a new allocation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ThpPolicyOutcome {
    Allowed,
    DisabledAlready(usize),
    DisabledSet,
    DisabledSetFailed(Errno),
    DisabledQueryFailed(Errno),
}

/// Process-owned state for the source VM option, hint, large-page retry, and
/// NUMA-count policy.
///
/// This deliberately receives a completed [`VmOptions`] image instead of
/// reading `environ`, creating random state, or allocating an owner itself.
/// The eventual process initializer must retain one `VmPolicy` beside the
/// source `MainSubprocess`; callers pass the already initialized
/// [`TheapRandomImage`] when a source path requires randomization. The old
/// fixed-default mapping APIs remain intact while that lifecycle wiring is
/// being introduced.
pub(crate) struct VmPolicy {
    options: VmOptions,
    // Pinned `src/init.c` keeps this true until the process-load owner has
    // left the C-runtime-unsafe preloading interval.  Only that one owner may
    // clear it; VM and arena callers receive a read-only view through their
    // borrowed `VmProcess` pair.
    preloading: AtomicBool,
    aligned_hint_base: AtomicUsize,
    huge_hint_start: AtomicUsize,
    large_page_try_ok: AtomicUsize,
    huge_one_gib_unavailable: AtomicBool,
    numa_node_count: AtomicUsize,
}

/// One borrowed source subprocess and its resolved VM policy.
///
/// This pair is deliberately non-owning: process initialization retains both
/// address-stable owners, while map/commit/free callers must present the same
/// pair for every accounting edge. It prevents an allocation path from
/// selecting options from one process image and statistics from another.
#[derive(Clone, Copy)]
pub(crate) struct VmProcess<'a> {
    policy: &'a VmPolicy,
    subprocess: &'a crate::subproc::MainSubprocess,
}

impl<'a> VmProcess<'a> {
    #[inline]
    pub(crate) const fn new(
        policy: &'a VmPolicy,
        subprocess: &'a crate::subproc::MainSubprocess,
    ) -> Self {
        Self { policy, subprocess }
    }

    #[inline]
    pub(crate) const fn policy(self) -> &'a VmPolicy { self.policy }

    #[inline]
    pub(crate) const fn subprocess(self) -> &'a crate::subproc::MainSubprocess {
        self.subprocess
    }

    /// Returns the source-selected current NUMA node for this exact policy
    /// and subprocess lifetime.  The option-aware count cache belongs to the
    /// policy, rather than the legacy fixed-default global cache.
    #[inline]
    pub(crate) fn current_numa_node(self) -> usize {
        self.policy.current_numa_node()
    }

    /// Reports whether this exact process pair is still in the source's
    /// C-runtime-unsafe preloading interval.  It grants no transition
    /// authority: only the process initialization owner may end that state.
    #[inline]
    pub(crate) fn is_preloading(self) -> bool { self.policy.is_preloading() }
}

impl VmPolicy {
    /// Admits only source options whose lazy environment phase has completed.
    pub(crate) fn new(options: VmOptions) -> core::result::Result<Self, VmPolicyConfigurationError> {
        for option in VmOption::ALL {
            if options.state(option) == VmOptionState::Uninitialized {
                return Err(VmPolicyConfigurationError::UnresolvedOption(option));
            }
        }
        Ok(Self {
            options,
            preloading: AtomicBool::new(true),
            aligned_hint_base: AtomicUsize::new(0),
            huge_hint_start: AtomicUsize::new(0),
            large_page_try_ok: AtomicUsize::new(0),
            huge_one_gib_unavailable: AtomicBool::new(false),
            numa_node_count: AtomicUsize::new(0),
        })
    }

    /// Starts a source-shaped resolved default policy for a caller which has
    /// explicitly observed every relevant environment name as absent.
    ///
    /// This is not a substitute for process environment ownership. It exists
    /// for direct native fixtures and for source callers whose startup contract
    /// has already made the seven absences explicit.
    #[cfg(test)]
    fn defaults_for_test() -> Self {
        let mut options = VmOptions::uninitialized();
        options.initialize_all(|_| VmOptionEnvironment::Absent);
        match Self::new(options) {
            Ok(policy) => {
                // Direct VM fixtures run after their source process-start
                // boundary, not in the C-runtime-unsafe preloading interval.
                policy.finish_preloading();
                policy
            }
            Err(_) => unreachable!("absent source options resolve every VM descriptor"),
        }
    }

    #[inline]
    pub(crate) const fn options(&self) -> &VmOptions { &self.options }

    /// Ends the one-way source preloading interval.
    ///
    /// This is intentionally crate-private and is called only by the
    /// process-start owner after it completed the C-runtime-unsafe phase.
    /// Repeating the store is harmless, matching source initialization's
    /// one-way `true -> false` state rather than reopening a preload path.
    #[inline]
    pub(crate) fn finish_preloading(&self) {
        self.preloading.store(false, Ordering::Release);
    }

    /// Reads the source preloading state without granting mutation authority.
    #[inline]
    pub(crate) fn is_preloading(&self) -> bool {
        self.preloading.load(Ordering::Acquire)
    }

    /// Mirrors a source `mi_option_set` performed by the unique process
    /// options owner. Rust's exclusive borrow makes a concurrent mutation
    /// impossible here; it does not claim that upstream's ambient global
    /// option API is generally thread-safe.
    #[inline]
    pub(crate) fn set_option(&mut self, option: VmOption, value: i64) {
        self.options.set(option, value);
    }

    #[inline]
    fn option_enabled(&self, option: VmOption) -> bool {
        self.options
            .value(option)
            .expect("VmPolicy accepts only resolved source options")
            != 0
    }

    #[inline]
    fn option_value(&self, option: VmOption) -> i64 {
        self.options
            .value(option)
            .expect("VmPolicy accepts only resolved source options")
    }

    /// Mirrors the `mi_option_allow_thp` branch in `_mi_prim_mem_init`.
    ///
    /// The caller must invoke this only in an isolated process-start child or
    /// under the eventual process-policy owner: `PR_SET_THP_DISABLE` changes
    /// the calling process. Native evidence always executes it in its own
    /// Rust/C fixture process, never in the runner process.
    pub(crate) fn apply_thp_process_policy(&self, config: &mut MemoryConfig) -> ThpPolicyOutcome {
        if self.option_enabled(VmOption::AllowThp) {
            return ThpPolicyOutcome::Allowed;
        }
        config.disable_transparent_huge_pages();
        // SAFETY: these two PR_* values take only scalar zero/one arguments.
        // The caller owns the process-local THP transition and its timing.
        match unsafe { crabc_core::process::prctl_raw(PR_GET_THP_DISABLE, 0, 0, 0, 0) } {
            Ok(0) => match unsafe { crabc_core::process::prctl_raw(PR_SET_THP_DISABLE, 1, 0, 0, 0) } {
                Ok(_) => ThpPolicyOutcome::DisabledSet,
                Err(error) => ThpPolicyOutcome::DisabledSetFailed(error),
            },
            Ok(value) => ThpPolicyOutcome::DisabledAlready(value),
            Err(error) => ThpPolicyOutcome::DisabledQueryFailed(error),
        }
    }

    /// Returns `_mi_os_get_aligned_hint`'s address-only result.
    ///
    /// The returned integer is an mmap hint, not a reservation or pointer
    /// owner. In the selected normal-release source branch a missing or
    /// uninitialized default Theap must return no hint after the source's
    /// initial atomic cursor increment; callers must pass that real M1 random
    /// image rather than supplying an ad-hoc generator.
    pub(crate) fn aligned_hint(
        &self,
        config: MemoryConfig,
        try_alignment: usize,
        size: usize,
        default_random: Option<&mut TheapRandomImage>,
    ) -> Option<usize> {
        if try_alignment <= config.alloc_granularity()
            || try_alignment > 16 * GIB
            || config.virtual_address_bits() < 46
        {
            return None;
        }
        let request_size = size
            .checked_add(config.page_size().bytes())?
            .checked_add(try_alignment.checked_sub(1)?)?;
        let request_size = invariants::align_up(request_size, config.large_page_size())?;
        let mut hint = self.aligned_hint_base.fetch_add(request_size, Ordering::AcqRel);
        if hint == 0 || hint > HINT_MAX {
            let random = default_random?;
            if !random.is_initialized() {
                return None;
            }
            let random_bits = (random.next() >> 17) & 0x3f_ffff;
            let initial = HINT_BASE.checked_add(MIB.checked_mul(random_bits as usize)? % HINT_AREA)?;
            let expected = hint.wrapping_add(request_size);
            let _ = self.aligned_hint_base.compare_exchange(
                expected,
                initial,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
            hint = self.aligned_hint_base.fetch_add(request_size, Ordering::AcqRel);
            if hint == 0 {
                return None;
            }
        }
        let aligned = invariants::align_up(hint, try_alignment)?;
        let request_end = hint.checked_add(request_size)?;
        if aligned.checked_add(size)? >= request_end {
            return None;
        }
        Some(aligned)
    }

    /// Claims the source high-address range used for one-or-more 1-GiB huge
    /// page attempts. Claiming advances the process cursor even when a later
    /// kernel map fails, exactly as `mi_os_claim_huge_pages` does.
    fn claim_huge_pages(
        &self,
        pages: usize,
        mut default_random: Option<&mut TheapRandomImage>,
    ) -> Option<(usize, usize)> {
        let size = pages.checked_mul(HUGE_PAGE_SIZE)?;
        let mut observed = self.huge_hint_start.load(Ordering::Relaxed);
        loop {
            let mut start = observed;
            if start == 0 {
                start = HUGE_HINT_BASE;
                if let Some(random) = default_random.as_deref_mut() {
                    if random.is_initialized() {
                        let random_bits = (random.next() >> 17) & 0x0fff;
                        start = start.checked_add(HUGE_PAGE_SIZE.checked_mul(random_bits as usize)?)?;
                    }
                }
            }
            let end = start.checked_add(size)?;
            match self.huge_hint_start.compare_exchange_weak(
                observed,
                end,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some((start, size)),
                Err(actual) => observed = actual,
            }
        }
    }

    #[inline]
    /// Returns the resolved `mi_option_allow_large_os_pages` setting.
    ///
    /// This is intentionally distinct from a caller's `allow_large` request:
    /// source arena eager-commit policy consults the process option before it
    /// decides which primitive call may request large pages.
    pub(crate) fn allow_large_os_pages(&self) -> bool {
        self.option_enabled(VmOption::AllowLargeOsPages)
    }

    #[inline]
    fn allow_thp(&self) -> bool { self.option_enabled(VmOption::AllowThp) }

    /// Returns the resolved source `purge_decommits` choice for this process.
    #[inline]
    pub(crate) fn purge_decommits(&self) -> bool {
        self.option_enabled(VmOption::PurgeDecommits)
    }

    /// Returns the resolved source `purge_delay` in milliseconds.
    ///
    /// Negative values intentionally remain visible: pinned `src/os.c`
    /// suppresses a purge when this option is below zero.
    #[inline]
    pub(crate) fn purge_delay_milliseconds(&self) -> i64 {
        self.option_value(VmOption::PurgeDelay)
    }

    #[inline]
    fn reserve_huge_os_pages(&self) -> i64 { self.option_value(VmOption::ReserveHugeOsPages) }

    #[inline]
    fn reserve_huge_os_pages_at(&self) -> i64 {
        self.option_value(VmOption::ReserveHugeOsPagesAt)
    }

    #[inline]
    fn configured_numa_nodes(&self) -> i64 { self.option_value(VmOption::UseNumaNodes) }

    /// The source `mi_option_get_size` view for the two arena size options.
    #[inline]
    fn option_size_bytes(&self, option: VmOption) -> usize {
        let kibibytes = self.option_value(option).max(0) as u64;
        usize::try_from(kibibytes)
            .ok()
            .and_then(|kibibytes| kibibytes.checked_mul(1024))
            .unwrap_or(crate::config::MAX_ALLOC_SIZE)
    }

    #[inline]
    pub(crate) fn arena_eager_commit(&self) -> i64 {
        self.option_value(VmOption::ArenaEagerCommit)
    }

    #[inline]
    pub(crate) fn arena_reserve_bytes(&self) -> usize {
        self.option_size_bytes(VmOption::ArenaReserve)
    }

    /// Returns the resolved source arena-purge delay multiplier unchanged.
    /// The arena owner applies the source multiplication at its purge
    /// scheduling edge, where it can retain the matching arena lifetime.
    #[inline]
    pub(crate) fn arena_purge_multiplier(&self) -> i64 {
        self.option_value(VmOption::ArenaPurgeMult)
    }

    #[inline]
    pub(crate) fn arena_max_object_size_bytes(&self) -> usize {
        self.option_size_bytes(VmOption::ArenaMaxObjectSize)
    }

    #[inline]
    pub(crate) fn disallow_arena_alloc(&self) -> bool {
        self.option_enabled(VmOption::DisallowArenaAlloc)
    }

    #[inline]
    pub(crate) fn disallow_os_alloc(&self) -> bool {
        self.option_enabled(VmOption::DisallowOsAlloc)
    }

    #[inline]
    pub(crate) fn page_commit_on_demand(&self) -> i64 {
        self.option_value(VmOption::PageCommitOnDemand)
    }

    /// Returns whether the source asks an initial arena allocation to use the
    /// current NUMA node. This is distinct from configuring the number of
    /// allocator regions.
    #[inline]
    pub(crate) fn arena_is_numa_local(&self) -> bool {
        self.option_enabled(VmOption::ArenaIsNumaLocal)
    }

    /// Returns `_mi_os_minimal_purge_size` for this policy/configuration.
    ///
    /// The option is a source KiB value. A nonzero value is aligned using the
    /// fixed source unsigned power-of-two expression, including its wrapping
    /// edge; otherwise transparent-huge-page mode two selects the configured
    /// large page size and every other case selects the base page size.
    #[inline]
    pub(crate) fn minimal_purge_size(&self, config: MemoryConfig) -> usize {
        let configured = self.option_size_bytes(VmOption::MinimalPurgeSize);
        if configured != 0 {
            let page_size = config.page_size().bytes();
            debug_assert!(page_size.is_power_of_two());
            return configured.wrapping_add(page_size - 1) & !(page_size - 1);
        }
        if config.has_transparent_huge_pages() && self.option_value(VmOption::AllowThp) == 2 {
            config.large_page_size()
        } else {
            config.page_size().bytes()
        }
    }

    /// Resolves the source option-aware NUMA-region count into this policy's
    /// private cache.  It deliberately preserves `src/os.c`'s simple
    /// load/fill/store shape rather than introducing a stronger once or CAS
    /// protocol for the first topology observation.
    #[inline]
    fn numa_node_count_with_raw(&self, mut raw_count: impl FnMut() -> usize) -> usize {
        let count = self.numa_node_count.load(Ordering::Acquire);
        let count = if count == 0 {
            let configured = self.configured_numa_nodes();
            let resolved = if configured > 0 && configured < i64::from(i32::MAX) {
                configured as usize
            } else {
                let observed = raw_count();
                if observed == 0 || observed > NUMA_NODE_INT_MAX {
                    1
                } else {
                    observed
                }
            };
            self.numa_node_count.store(resolved, Ordering::Release);
            resolved
        } else {
            count
        };
        debug_assert!((1..=NUMA_NODE_INT_MAX).contains(&count));
        count
    }

    /// Returns the selected policy's allocator-facing NUMA-region count.
    #[inline]
    pub(crate) fn numa_node_count(&self) -> usize {
        self.numa_node_count_with_raw(numa_node_count)
    }

    /// Returns the selected current NUMA node with the source strict
    /// `INT_MAX` boundary and modulo normalization.
    #[inline]
    fn current_numa_node_with_raw(
        &self,
        raw_count: impl FnMut() -> usize,
        mut raw_current: impl FnMut() -> usize,
    ) -> usize {
        if self.numa_node_count.load(Ordering::Relaxed) == 1 {
            return 0;
        }
        let count = self.numa_node_count_with_raw(raw_count);
        if count <= 1 {
            return 0;
        }
        let mut current = raw_current();
        if current >= NUMA_NODE_INT_MAX {
            current = 0;
        }
        if current >= count {
            current %= count;
        }
        current
    }

    /// Returns the current NUMA node through this policy's option-aware
    /// count cache, rather than the legacy fixed-default global cache.
    #[inline]
    pub(crate) fn current_numa_node(&self) -> usize {
        self.current_numa_node_with_raw(numa_node_count, numa_node)
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
    is_large: bool,
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

    /// Maps the source Unix allocation route with a process-owned policy.
    ///
    /// This additive counterpart of [`Self::map_for_allocator`] preserves the
    /// frozen default callers while admitting pinned aligned hints, huge-page
    /// retry, and THP advisory selection only with a resolved [`VmPolicy`].
    /// `allow_large` is a source caller argument, never an inferred default.
    pub(crate) fn map_for_allocator_with_policy(
        policy: &VmPolicy,
        config: MemoryConfig,
        length: usize,
        try_alignment: usize,
        access: MapAccess,
        allow_large: bool,
        default_random: Option<&mut TheapRandomImage>,
    ) -> Result<Self> {
        validate_mapping_length(config.page_size(), length)?;
        let try_alignment = if try_alignment == 0 { 1 } else { try_alignment };
        let try_alignment = if config.large_page_size() > 0
            && length >= 8 * config.large_page_size()
            && try_alignment.is_power_of_two()
            && try_alignment < config.large_page_size()
        {
            config.large_page_size()
        } else {
            try_alignment
        };
        Self::map_unix_policy(
            policy,
            config,
            length,
            try_alignment,
            access,
            matches!(access, MapAccess::Committed) && allow_large,
            false,
            None,
            default_random,
        )
    }

    /// Executes `mi_os_prim_alloc_at`'s VM/statistics effects through one
    /// source subprocess. The mmap-call counter advances even on primitive
    /// failure; reservation and initial commitment advance only after a
    /// successful map, matching `src/os.c:303-338`.
    pub(crate) fn map_for_process(
        process: VmProcess<'_>,
        config: MemoryConfig,
        length: usize,
        try_alignment: usize,
        access: MapAccess,
        allow_large: bool,
        default_random: Option<&mut TheapRandomImage>,
    ) -> Result<Self> {
        let mapping = Self::map_for_allocator_with_policy(
            process.policy,
            config,
            length,
            try_alignment,
            access,
            allow_large,
            default_random,
        );
        let stats = process.subprocess.vm_statistics();
        stats.mmap_call();
        if mapping.is_ok() {
            stats.reserve_increase(length);
            if matches!(access, MapAccess::Committed) {
                stats.committed_increase(length);
            }
        }
        mapping
    }

    /// Runs the Linux/x86-64 `mi_os_prim_alloc_aligned` mmap branch through a
    /// single process pair.
    ///
    /// On this 64-bit source profile the direct candidate is always tried.
    /// An unaligned successful candidate is explicitly released with
    /// adjustment accounting before the overmap attempt. A direct primitive
    /// failure does *not* skip that overmap attempt: upstream has the same
    /// fallback after either an unaligned pointer or a null pointer.
    fn map_aligned_for_process(
        process: VmProcess<'_>,
        config: MemoryConfig,
        length: usize,
        alignment: usize,
        access: MapAccess,
        allow_large: bool,
        mut default_random: Option<&mut TheapRandomImage>,
    ) -> core::result::Result<Self, AlignedMappingFailure> {
        let page_size = config.page_size().bytes();
        if alignment < page_size || !alignment.is_power_of_two() {
            return Err(AlignedMappingFailure::without_mapping(Errno::INVAL));
        }

        match Self::map_for_process(
            process,
            config,
            length,
            alignment,
            access,
            allow_large,
            default_random.as_deref_mut(),
        ) {
            Ok(mut direct) => {
                let base = match direct.base() {
                    Ok(base) => base,
                    Err(error) => return Err(AlignedMappingFailure::with_mapping(error, direct)),
                };
                if base.addr() % alignment == 0 {
                    return Ok(direct);
                }
                if let Err(error) = direct.unmap_for_process(
                    process,
                    if matches!(access, MapAccess::Committed) { length } else { 0 },
                    true,
                ) {
                    return Err(AlignedMappingFailure::with_mapping(error, direct));
                }
            }
            // The source deliberately continues into its overmap branch.
            Err(_) => {}
        }

        let over_length = match length.checked_add(alignment) {
            Some(length) => length,
            None => return Err(AlignedMappingFailure::without_mapping(Errno::NOMEM)),
        };
        let mut over = Self::map_for_process(
            process,
            config,
            over_length,
            1,
            access,
            allow_large,
            default_random.as_deref_mut(),
        )
        .map_err(AlignedMappingFailure::without_mapping)?;
        let base = match over.base() {
            Ok(base) => base,
            Err(error) => return Err(AlignedMappingFailure::with_mapping(error, over)),
        };
        let aligned_address = match invariants::align_up(base.addr(), alignment) {
            Some(address) => address,
            None => return Err(AlignedMappingFailure::with_mapping(Errno::NOMEM, over)),
        };
        let prefix = match aligned_address.checked_sub(base.addr()) {
            Some(size) => size,
            None => return Err(AlignedMappingFailure::with_mapping(Errno::NOMEM, over)),
        };
        let suffix = match over_length
            .checked_sub(prefix)
            .and_then(|remaining| remaining.checked_sub(length))
        {
            Some(size) => size,
            None => return Err(AlignedMappingFailure::with_mapping(Errno::NOMEM, over)),
        };

        if prefix != 0 {
            if let Err(error) = over.unmap_prefix_for_process(
                process,
                prefix,
                matches!(access, MapAccess::Committed),
            ) {
                return Err(AlignedMappingFailure::with_mapping(error, over));
            }
        }
        if suffix != 0 {
            if let Err(error) = over.unmap_suffix_for_process(
                process,
                suffix,
                matches!(access, MapAccess::Committed),
            ) {
                return Err(AlignedMappingFailure::with_mapping(error, over));
            }
        }
        debug_assert_eq!(over.address.addr(), aligned_address);
        debug_assert_eq!(over.length, length);
        Ok(over)
    }

    /// Attempts the exact one-GiB source huge-page primitive at a claimed
    /// high-address hint. There is no regular mmap fallback on this path.
    fn map_huge_page_at(policy: &VmPolicy, config: MemoryConfig, hint: usize) -> Result<Self> {
        Self::map_unix_policy(
            policy,
            config,
            HUGE_PAGE_SIZE,
            ARENA_SLICE_SIZE,
            MapAccess::Committed,
            true,
            true,
            Some(hint),
            None,
        )
    }

    /// Transfers one exact primitive huge-page mapping to the distinct
    /// [`HugeOsAllocation`] owner.
    ///
    /// A one-GiB reservation is assembled from independently mapped ranges.
    /// It must therefore not retain a `Mapping` and later pass the aggregate
    /// range to ordinary `munmap` ownership. This consumes only the normal
    /// mapping capability after its base, length, and huge-page result match
    /// the pinned `_mi_prim_alloc_huge_os_pages` success branch.
    fn into_huge_page_at(mut self, expected: *mut u8) -> Result<()> {
        self.active()?;
        if self.address != expected || self.length != HUGE_PAGE_SIZE || !self.is_large {
            return Err(Errno::INVAL);
        }
        self.is_mapped = false;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn map_unix_policy(
        policy: &VmPolicy,
        config: MemoryConfig,
        length: usize,
        try_alignment: usize,
        access: MapAccess,
        allow_large: bool,
        large_only: bool,
        explicit_hint: Option<usize>,
        default_random: Option<&mut TheapRandomImage>,
    ) -> Result<Self> {
        fault_before(FaultPoint::Map)?;
        let mut flags = MAP_PRIVATE | MAP_ANONYMOUS;
        if config.has_overcommit() {
            flags |= MAP_NORESERVE;
        }
        let protection = access.protection();
        let source_hint = match explicit_hint {
            Some(hint) => Some(hint),
            None => policy.aligned_hint(config, try_alignment, length, default_random),
        };
        let wants_large = allow_large
            && (large_only
                || (config.can_use_large_page(length, try_alignment)
                    && policy.allow_large_os_pages()));
        if wants_large {
            let retry_remaining = policy.large_page_try_ok.load(Ordering::Acquire);
            if large_only || retry_remaining == 0 {
                let mut large_flags = (flags & !MAP_NORESERVE) | MAP_HUGETLB;
                let one_gib = large_only
                    && length % HUGE_PAGE_SIZE == 0
                    && !policy.huge_one_gib_unavailable.load(Ordering::Relaxed);
                large_flags |= if one_gib { MAP_HUGE_1GB } else { MAP_HUGE_2MB };
                match Self::mmap_with_hint(source_hint, length, protection, large_flags) {
                    Ok(address) => return Ok(Self::policy_mapping(address, length, config, access, true)),
                    Err(first_error) if one_gib => {
                        policy.huge_one_gib_unavailable.store(true, Ordering::Relaxed);
                        let fallback_flags = (large_flags & !MAP_HUGE_1GB) | MAP_HUGE_2MB;
                        match Self::mmap_with_hint(source_hint, length, protection, fallback_flags) {
                            Ok(address) => return Ok(Self::policy_mapping(address, length, config, access, true)),
                            Err(error) if large_only => return Err(error),
                            Err(_) => {
                                let _ = first_error;
                            }
                        }
                    }
                    Err(error) if large_only => return Err(error),
                    Err(_) => {}
                }
                if large_only {
                    unreachable!("the large-only error paths returned above");
                }
                policy
                    .large_page_try_ok
                    .store(LARGE_PAGE_FAILED_RETRY_COUNT, Ordering::Release);
            } else {
                let _ = policy.large_page_try_ok.compare_exchange(
                    retry_remaining,
                    retry_remaining - 1,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                );
            }
        }
        let address = Self::mmap_with_hint(source_hint, length, protection, flags)?;
        if allow_large && policy.allow_thp() && config.can_use_large_page(length, try_alignment) {
            // The source ignores this advisory's errno and does not call the
            // resulting regular map a large-page mapping.
            // SAFETY: this function owns the just-created mapping until it
            // returns the explicit `Mapping` owner below.
            let _ = unsafe { crabc_core::mm::madvise_raw(address, length, MADV_HUGEPAGE) };
        }
        Ok(Self::policy_mapping(address, length, config, access, false))
    }

    #[inline]
    fn policy_mapping(
        address: *mut u8,
        length: usize,
        config: MemoryConfig,
        access: MapAccess,
        is_large: bool,
    ) -> Self {
        Self {
            address,
            length,
            page_size: config.page_size(),
            initially_committed: matches!(access, MapAccess::Committed),
            initially_zero: true,
            is_large,
            is_mapped: true,
        }
    }

    #[inline]
    fn mmap_with_hint(
        hint: Option<usize>,
        length: usize,
        protection: u32,
        flags: u32,
    ) -> Result<*mut u8> {
        // SAFETY: `length` is validated by the caller and the optional hint
        // is only an address suggestion. Linux validates the raw flags and
        // creates no Rust reference from the returned mapping address.
        unsafe {
            crabc_core::mm::mmap_raw(
                hint.map_or(core::ptr::null_mut(), |value| value as *mut u8),
                length,
                protection,
                flags,
                -1,
                0,
            )
        }
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
            is_large: false,
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

    /// Reclaims a published mapping through the same process pair that
    /// originally accounted for it.
    ///
    /// This is the paired published-page counterpart of
    /// [`Self::unmap_for_process`]. The source syscall runs before its named
    /// statistics transition, including when it fails. An error therefore
    /// leaves the published range live but already accounted; its exact owner
    /// must use [`Self::reclaim_published`] for an explicit raw retry instead
    /// of applying the process accounting edge twice.
    ///
    /// # Safety
    ///
    /// `address` and `length` must name the exact current extent transferred
    /// by [`Self::into_published`]. The caller must hold that token's unique
    /// release right, have quiesced every raw access and derived capability,
    /// and retain the token after an error. `commit_size` is the source
    /// caller's exact still-committed extent and cannot exceed `length`.
    pub(crate) unsafe fn reclaim_published_for_process(
        process: VmProcess<'_>,
        address: *mut u8,
        length: usize,
        commit_size: usize,
        adjust: bool,
    ) -> Result<()> {
        if address.is_null() || length == 0 || commit_size > length {
            return Err(Errno::INVAL);
        }
        // SAFETY: the caller supplies the exact published mapping and proves
        // it has the unique quiescent release capability. Retain the raw
        // syscall boundary rather than recreating a second Mapping owner.
        let result = match fault_before(FaultPoint::Unmap) {
            Ok(()) => unsafe { crabc_core::mm::munmap_raw(address, length) },
            Err(error) => Err(error),
        };
        let stats = process.subprocess.vm_statistics();
        if adjust {
            if commit_size != 0 {
                stats.committed_adjust_decrease(commit_size);
            }
            stats.reserved_adjust_decrease(length);
        } else {
            if commit_size != 0 {
                stats.committed_decrease(commit_size);
            }
            stats.reserve_decrease(length);
        }
        result
    }

    /// Commits one published reserved range through its original process pair.
    ///
    /// This is the post-publication counterpart of [`Self::commit_for_process`].
    /// Pinned `_mi_os_commit_ex` records `commit_calls` before liberal page
    /// normalization, and increases `committed` by the caller's requested
    /// span—not the possibly wider primitive range—only after the normalized
    /// commit succeeds. Keeping that sequence at this raw boundary lets a
    /// page owner commit a newly published prefix without reconstructing a
    /// second `Mapping` capability.
    ///
    /// # Safety
    ///
    /// `address..address + length` must be a live subrange of one reserved
    /// mapping originally accounted by `process`. The caller must exclusively
    /// own the source new-prefix transition and prove that its covering
    /// page-aligned range remains in that same mapping. No Rust reference or
    /// aliased mapping capability may observe the bytes during this raw
    /// protection change. The original published release token remains the
    /// sole release authority; this method creates neither a release token nor
    /// a second mapping owner.
    pub(crate) unsafe fn commit_published_for_process(
        process: VmProcess<'_>,
        config: MemoryConfig,
        address: *mut u8,
        length: usize,
    ) -> Result<Option<CommitOutcome>> {
        // `_mi_os_commit_ex` increments the named counter before it asks
        // `mi_os_page_align_areax` whether the source span has any pages.
        let statistics = process.subprocess.vm_statistics();
        statistics.commit_call();
        let Some((address, normalized_length)) =
            covering_unowned_page_range(config.page_size(), address, length)?
        else {
            return Ok(None);
        };
        fault_before(FaultPoint::Commit)?;
        // SAFETY: the caller's unsafe contract proves that this source-style
        // covering range stays in its live reserved mapping and is uniquely
        // transitioning from reserved to accessible bytes.
        unsafe {
            crabc_core::mm::mprotect_raw(address, normalized_length, PROT_READ | PROT_WRITE)
        }?;
        statistics.committed_increase(length);
        Ok(Some(CommitOutcome::NotKnownZero))
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

    /// Returns whether the successful source primitive used a huge-page mmap
    /// flag. Transparent-Huge-Page advice intentionally remains false here,
    /// matching the source's unknown-result representation.
    #[inline]
    pub(crate) const fn is_large(&self) -> bool { self.is_large }

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

    /// Runs `_mi_os_commit_ex` under the process owner that also owns this
    /// mapping's reservation accounting.
    ///
    /// `stat_already_committed` is deliberately an input rather than inferred
    /// from page protection: upstream accounts the caller's source span, not
    /// the page-rounded primitive span, and permits the latter to cover
    /// already committed bytes.
    pub(crate) fn commit_for_process(
        &self,
        process: VmProcess<'_>,
        offset: usize,
        length: usize,
        stat_already_committed: usize,
    ) -> Result<Option<CommitOutcome>> {
        if stat_already_committed > length {
            return Err(Errno::INVAL);
        }
        // `commit_calls` precedes source page normalization, including the
        // successful empty-range branch.
        process.subprocess.vm_statistics().commit_call();
        let outcome = self.commit(offset, length)?;
        if outcome.is_some() {
            process
                .subprocess
                .vm_statistics()
                .committed_increase(length - stat_already_committed);
        }
        Ok(outcome)
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

    /// Runs `mi_os_decommit_ex` with its explicit source statistic span.
    ///
    /// The frozen Linux primitive returns `DoesNotNeedRecommit`, so it does
    /// not lower committed statistics. A profile with a different primitive
    /// needs a separate qualified source boundary; this native x86 contract
    /// must not manufacture that outcome from a generic boolean.
    pub(crate) fn decommit_for_process(
        &self,
        _process: VmProcess<'_>,
        offset: usize,
        length: usize,
        _stat_size: usize,
    ) -> Result<Option<DecommitOutcome>> {
        let outcome = self.decommit(offset, length)?;
        Ok(outcome)
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

    /// Runs `_mi_os_reset` and its unconditional-for-a-nonempty-range source
    /// counters. The counters advance before the Unix advisory reports its
    /// result, exactly as `src/os.c:620-632` does.
    pub(crate) fn reset_for_process(
        &self,
        process: VmProcess<'_>,
        offset: usize,
        length: usize,
    ) -> Result<bool> {
        let Some(range) = self.page_range(offset, length, PageAlignment::Contained)? else {
            return Ok(true);
        };
        process.subprocess.vm_statistics().reset(range.length);
        reset_with_advice(&RESET_ADVICE, |advice| {
            fault_before(FaultPoint::Purge)?;
            // SAFETY: `range` is a complete-page subrange of this live
            // mapping. The advisory does not create aliases or change the
            // mapping's release owner.
            unsafe { crabc_core::mm::madvise_raw(range.address, range.length, advice) }
        })
        .map(|()| true)
    }

    /// Runs the no-callback `_mi_os_purge_ex` branch for one paired process
    /// owner. The callback form remains unavailable until its arena caller can
    /// supply a source-owned typed commit capability; silently treating it as
    /// reset/decommit would erase its failure ownership.
    pub(crate) fn purge_for_process(
        &self,
        process: VmProcess<'_>,
        offset: usize,
        length: usize,
        allow_reset: bool,
        stat_size: usize,
    ) -> Result<bool> {
        if process.policy.purge_delay_milliseconds() < 0 {
            return Ok(false);
        }
        process.subprocess.vm_statistics().purge(length);
        if process.policy.purge_decommits() {
            return self
                .decommit_for_process(process, offset, length, stat_size)
                .map(|_| false);
        }
        if allow_reset {
            let _ = self.reset_for_process(process, offset, length)?;
        }
        Ok(false)
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

    /// Executes `_mi_os_prim_free` through the same process pair that mapped
    /// this range. `commit_size` is the source caller's still-committed extent
    /// and `adjust` selects its partial-overmap accounting repair path.
    ///
    /// Source statistics move even when `munmap` reports an error; the error
    /// keeps this explicit owner live for retry, so a Rust caller cannot lose
    /// the mapping while still observing the pinned accounting sequence.
    pub(crate) fn unmap_for_process(
        &mut self,
        process: VmProcess<'_>,
        commit_size: usize,
        adjust: bool,
    ) -> Result<()> {
        self.active()?;
        if commit_size > self.length {
            return Err(Errno::INVAL);
        }
        // SAFETY: this is the exact current owner range; no method has
        // produced a reference into it. On error the owner remains live.
        // Keep the test fault in the same position as a failed primitive:
        // `_mi_os_prim_free` accounts after its primitive returns, whether
        // that primitive succeeded or failed.
        let result = match fault_before(FaultPoint::Unmap) {
            Ok(()) => unsafe { crabc_core::mm::munmap_raw(self.address, self.length) },
            Err(error) => Err(error),
        };
        let stats = process.subprocess.vm_statistics();
        if adjust {
            if commit_size != 0 {
                stats.committed_adjust_decrease(commit_size);
            }
            stats.reserved_adjust_decrease(self.length);
        } else {
            if commit_size != 0 {
                stats.committed_decrease(commit_size);
            }
            stats.reserve_decrease(self.length);
        }
        if result.is_ok() {
            self.is_mapped = false;
        }
        result
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

    /// Releases an aligned-map prefix with the source adjustment statistics.
    /// Failed cleanup retains this exact complete mapping owner unchanged.
    fn unmap_prefix_for_process(
        &mut self,
        process: VmProcess<'_>,
        prefix: usize,
        committed: bool,
    ) -> Result<()> {
        self.validate_partial_unmap(prefix)?;
        let result = match fault_before(FaultPoint::Unmap) {
            Ok(()) => unsafe { crabc_core::mm::munmap_raw(self.address, prefix) },
            Err(error) => Err(error),
        };
        let stats = process.subprocess.vm_statistics();
        if committed {
            stats.committed_adjust_decrease(prefix);
        }
        stats.reserved_adjust_decrease(prefix);
        if result.is_ok() {
            self.address = self.address.wrapping_add(prefix);
            self.length -= prefix;
        }
        result
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

    /// Releases an aligned-map suffix with the source adjustment statistics.
    /// The owner remains the exact retained prefix if this syscall fails.
    fn unmap_suffix_for_process(
        &mut self,
        process: VmProcess<'_>,
        suffix: usize,
        committed: bool,
    ) -> Result<()> {
        self.validate_partial_unmap(suffix)?;
        let retained_length = self.length - suffix;
        let suffix_address = self.address.wrapping_add(retained_length);
        let result = match fault_before(FaultPoint::Unmap) {
            Ok(()) => unsafe { crabc_core::mm::munmap_raw(suffix_address, suffix) },
            Err(error) => Err(error),
        };
        let stats = process.subprocess.vm_statistics();
        if committed {
            stats.committed_adjust_decrease(suffix);
        }
        stats.reserved_adjust_decrease(suffix);
        if result.is_ok() {
            self.length = retained_length;
        }
        result
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

/// One source `MI_MEM_OS_HUGE` allocation assembled from 1-GiB primitive maps.
///
/// Pinned `_mi_os_alloc_huge_os_pages` maps each range independently at a
/// claimed high-address hint, records one aggregate `MI_MEM_OS_HUGE` memory
/// ID only for the contiguous successful prefix, and later frees each 1-GiB
/// primitive map independently. This owner consequently cannot be represented
/// by a normal [`Mapping`], whose terminal release is one contiguous range.
/// It retains the exact process pair that selected options and received every
/// source statistic transition.
#[must_use = "a huge OS allocation must be installed in a multi-range owner or explicitly released"]
pub(crate) struct HugeOsAllocation<'a> {
    process: VmProcess<'a>,
    base: NonNull<u8>,
    page_count: usize,
    memory: MemoryId,
    stop: HugeOsAllocationStop,
}

/// Why the pinned huge-page loop returned its contiguous prefix.
///
/// This is a typed diagnostic of an already-completed source branch, not a
/// second allocation policy: `_mi_os_alloc_huge_os_pages` can return a valid
/// partial prefix after a timeout, primitive error, or rejected noncontiguous
/// result. Retaining that reason keeps those source warnings observable to
/// the later process/arena owner without making a partial result disappear.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HugeOsAllocationStop {
    Complete,
    NoPagesRequested,
    ClaimOverflow,
    PrimitiveMapFailed(Errno),
    NoncontiguousPrimitive,
    TimedOut,
}

/// The source-visible result of one huge-page reservation attempt.
///
/// Primitive map failure and zero requested pages both remain source-style
/// `Unavailable`; no regular mapping is substituted. A noncontiguous
/// primitive result is rejected after its source adjustment-accounted cleanup.
/// If that cleanup itself fails, its normal raw mapping is kept in a dedicated
/// terminal cleanup owner while any already-contiguous huge prefix remains a
/// valid distinct `MI_MEM_OS_HUGE` result.
#[must_use = "a retained rejected huge primitive map needs an explicit raw retry or parking owner"]
pub(crate) enum HugeOsAllocationOutcome<'a> {
    Unavailable(HugeOsAllocationStop),
    Allocated(HugeOsAllocation<'a>),
    AllocatedWithRejectedPrimitive {
        allocation: HugeOsAllocation<'a>,
        rejected: HugeOsRejectedPrimitive,
    },
    RejectedPrimitive(HugeOsRejectedPrimitive),
}

/// A noncontiguous huge primitive map whose source adjustment free failed.
///
/// This is deliberately not a `HugeOsAllocation` and cannot become a normal
/// allocation: it has no source `MI_MEM_OS_HUGE` provenance. Its adjustment
/// statistics already moved at the failed source free edge, so a later retry
/// is raw-only.
#[must_use = "a failed rejected-primitive cleanup retains one raw mapping"]
pub(crate) struct HugeOsRejectedPrimitive {
    error: Errno,
    mapping: Mapping,
}

impl HugeOsRejectedPrimitive {
    #[inline]
    pub(crate) const fn error(&self) -> Errno { self.error }

    /// Retries only the raw kernel release after the source adjustment edge
    /// has already run. It intentionally cannot re-enter normal mapping or
    /// process-accounting APIs.
    pub(crate) fn retry_raw_release(mut self) -> core::result::Result<(), Self> {
        match self.mapping.unmap() {
            Ok(()) => Ok(()),
            Err(error) => {
                self.error = error;
                Err(self)
            }
        }
    }
}

impl fmt::Debug for HugeOsRejectedPrimitive {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HugeOsRejectedPrimitive")
            .field("error", &self.error)
            .field("retains_mapping", &true)
            .finish()
    }
}

/// A source huge-page release that could not start because the caller did not
/// provide enough compact failure-state words. No primitive release has run
/// in this case, so the exact allocation remains available to retry with a
/// sufficiently sized buffer.
#[must_use = "a huge allocation remains live when its release tracker is too small"]
pub(crate) struct HugeOsReleaseTrackingFailure<'a> {
    allocation: HugeOsAllocation<'a>,
    required_words: usize,
}

impl<'a> HugeOsReleaseTrackingFailure<'a> {
    #[inline]
    pub(crate) const fn required_words(&self) -> usize { self.required_words }

    #[inline]
    pub(crate) fn into_allocation(self) -> HugeOsAllocation<'a> { self.allocation }
}

/// The exact failed primitive-page set after a full source huge-page free
/// pass. Every page was attempted and received its normal source statistics
/// transition; only set bits still name live mappings and may be retried.
#[must_use = "failed huge-page releases retain raw-only retry state"]
pub(crate) struct HugeOsRawReleaseRetry<'a, 'bits> {
    process: VmProcess<'a>,
    base: NonNull<u8>,
    page_count: usize,
    memory: MemoryId,
    source_error: Errno,
    failed_pages: &'bits mut [usize],
    failed_words: usize,
}

/// Error from a raw-only retry of a previously source-accounted huge page.
#[must_use = "a raw retry failure retains its exact failed-page set"]
pub(crate) struct HugeOsRawReleaseFailure<'a, 'bits> {
    error: Errno,
    retry: HugeOsRawReleaseRetry<'a, 'bits>,
}

impl<'a, 'bits> HugeOsRawReleaseFailure<'a, 'bits> {
    #[inline]
    pub(crate) const fn error(&self) -> Errno { self.error }

    #[inline]
    pub(crate) fn into_retry(self) -> HugeOsRawReleaseRetry<'a, 'bits> { self.retry }
}

impl<'a, 'bits> HugeOsRawReleaseRetry<'a, 'bits> {
    /// Returns the original aggregate huge-memory provenance. Individual
    /// failed pages remain the only live ranges represented by this retry
    /// token, but their source owner and original memory kind stay explicit.
    #[inline]
    pub(crate) const fn memory_id(&self) -> MemoryId { self.memory }

    /// Retries all and only the failed primitive unmaps. It keeps walking the
    /// complete failed set after an error just as the source free loop keeps
    /// walking later pages. No source statistic is repeated: the original
    /// process-accounted pass already performed it for every marked bit.
    pub(crate) fn retry_raw(self) -> core::result::Result<(), HugeOsRawReleaseFailure<'a, 'bits>> {
        let mut first_error = None;
        for page in 0..self.page_count {
            if !huge_release_bit_is_set(self.failed_pages, page) {
                continue;
            }
            let address = match huge_page_address(self.base, page) {
                Some(address) => address,
                None => {
                    first_error.get_or_insert(Errno::INVAL);
                    continue;
                }
            };
            let result = match fault_before(FaultPoint::Unmap) {
                Ok(()) => {
                    // SAFETY: only a set bit can reach this branch; it names
                    // a still-live exact one-GiB primitive map retained by
                    // the preceding source-accounted release pass.
                    unsafe { crabc_core::mm::munmap_raw(address.as_ptr(), HUGE_PAGE_SIZE) }
                }
                Err(error) => Err(error),
            };
            match result {
                Ok(()) => huge_release_bit_clear(self.failed_pages, page),
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }
        match first_error {
            Some(error) => Err(HugeOsRawReleaseFailure { error, retry: self }),
            None => Ok(()),
        }
    }

    #[cfg(test)]
    fn failed_page(&self, page: usize) -> bool {
        page < self.page_count && huge_release_bit_is_set(self.failed_pages, page)
    }
}

impl<'a, 'bits> fmt::Debug for HugeOsRawReleaseRetry<'a, 'bits> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HugeOsRawReleaseRetry")
            .field("base", &self.base)
            .field("page_count", &self.page_count)
            .field("failed_words", &self.failed_words)
            .finish()
    }
}

impl<'a> HugeOsAllocation<'a> {
    /// Allocates the source `_mi_os_alloc_huge_os_pages` primitive through
    /// one resolved process pair. It never falls back to a regular mapping.
    pub(crate) fn allocate_for_process(
        process: VmProcess<'a>,
        config: MemoryConfig,
        pages: usize,
        numa_node: i32,
        max_milliseconds: i64,
        default_random: Option<&mut TheapRandomImage>,
    ) -> HugeOsAllocationOutcome<'a> {
        allocate_huge_pages_with(
            process,
            pages,
            max_milliseconds,
            default_random,
            |hint| map_huge_page_for_process(process, config, hint, numa_node),
            source_clock_start,
            source_clock_end,
        )
    }

    #[inline]
    pub(crate) const fn page_count(&self) -> usize { self.page_count }

    #[inline]
    pub(crate) const fn size(&self) -> usize {
        self.page_count * HUGE_PAGE_SIZE
    }

    #[inline]
    pub(crate) const fn memory_id(&self) -> MemoryId { self.memory }

    /// Returns the source branch that ended the successful contiguous prefix.
    #[inline]
    pub(crate) const fn stop(&self) -> HugeOsAllocationStop { self.stop }

    #[inline]
    pub(crate) const fn base(&self) -> NonNull<u8> { self.base }

    /// Returns the caller storage needed to retain an exact failed-page set
    /// for one complete source free pass.
    #[inline]
    pub(crate) const fn release_tracking_words(&self) -> usize {
        huge_release_word_count(self.page_count)
    }

    /// Executes every pinned `mi_os_free_huge_os_pages` primitive free once.
    ///
    /// The source ignores individual primitive errors and continues. Rust
    /// keeps that sequence but records every failed page in the supplied
    /// compact bitset so later raw retries can neither unmap successful pages
    /// nor duplicate the source statistics edge. A tracker too small to make
    /// that guarantee fails before any syscall.
    pub(crate) fn release_for_process<'bits>(
        self,
        failed_pages: &'bits mut [usize],
    ) -> core::result::Result<(), HugeOsReleaseFailure<'a, 'bits>> {
        let required_words = self.release_tracking_words();
        if failed_pages.len() < required_words {
            return Err(HugeOsReleaseFailure::Tracking(
                HugeOsReleaseTrackingFailure {
                    allocation: self,
                    required_words,
                },
            ));
        }
        for word in &mut failed_pages[..required_words] {
            *word = 0;
        }
        let first_error = release_huge_pages_with(
            self.base,
            self.page_count,
            failed_pages,
            |address| free_huge_page_for_process(self.process, address),
        );
        match first_error {
            None => Ok(()),
            Some(error) => Err(HugeOsReleaseFailure::FailedPages(HugeOsRawReleaseRetry {
                process: self.process,
                base: self.base,
                page_count: self.page_count,
                memory: self.memory,
                source_error: error,
                failed_pages,
                failed_words: required_words,
            })),
        }
    }
}

/// A failed source huge-page release either still owns the full allocation
/// before any syscall (insufficient tracking) or owns precisely the compact
/// set of source-accounted raw retries.
#[must_use = "a failed huge release retains an explicit owner"]
pub(crate) enum HugeOsReleaseFailure<'a, 'bits> {
    Tracking(HugeOsReleaseTrackingFailure<'a>),
    FailedPages(HugeOsRawReleaseRetry<'a, 'bits>),
}

impl<'a, 'bits> HugeOsReleaseFailure<'a, 'bits> {
    #[inline]
    pub(crate) fn error(&self) -> Option<Errno> {
        match self {
            Self::Tracking(_) => None,
            Self::FailedPages(retry) => Some(retry.source_error),
        }
    }
}

fn allocate_huge_pages_with<'a>(
    process: VmProcess<'a>,
    pages: usize,
    max_milliseconds: i64,
    default_random: Option<&mut TheapRandomImage>,
    mut map_page: impl FnMut(usize) -> Result<Mapping>,
    mut clock_start: impl FnMut() -> i64,
    mut clock_end: impl FnMut(i64) -> i64,
) -> HugeOsAllocationOutcome<'a> {
    let Some((start, claimed_size)) = process.policy.claim_huge_pages(pages, default_random) else {
        return HugeOsAllocationOutcome::Unavailable(HugeOsAllocationStop::ClaimOverflow);
    };
    let start_time = clock_start();
    let mut page = 0usize;
    let mut all_zero = true;
    let mut rejected = None;
    let mut stop = if pages == 0 {
        HugeOsAllocationStop::NoPagesRequested
    } else {
        HugeOsAllocationStop::Complete
    };

    while page < pages {
        let Some(address) = page
            .checked_mul(HUGE_PAGE_SIZE)
            .and_then(|offset| start.checked_add(offset))
        else {
            stop = HugeOsAllocationStop::ClaimOverflow;
            break;
        };
        let expected = address as *mut u8;
        let mut mapping = match map_page(address) {
            Ok(mapping) => mapping,
            Err(error) => {
                stop = HugeOsAllocationStop::PrimitiveMapFailed(error);
                break;
            }
        };
        all_zero &= mapping.initially_zero();
        if mapping.base().ok() != Some(expected) {
            stop = HugeOsAllocationStop::NoncontiguousPrimitive;
            if let Err(error) = mapping.unmap_for_process(process, HUGE_PAGE_SIZE, true) {
                rejected = Some(HugeOsRejectedPrimitive { error, mapping });
            }
            break;
        }
        if mapping.length() != Ok(HUGE_PAGE_SIZE) || !mapping.is_large() {
            stop = HugeOsAllocationStop::NoncontiguousPrimitive;
            // The base was exact, so this can only reject a malformed
            // primitive result. Preserve it as a source-adjusted cleanup
            // owner rather than treating it as a huge allocation.
            if let Err(error) = mapping.unmap_for_process(process, HUGE_PAGE_SIZE, true) {
                rejected = Some(HugeOsRejectedPrimitive { error, mapping });
            }
            break;
        }
        // The preceding base/length/large checks establish this exact source
        // primitive result; moving it into the aggregate owner cannot fail.
        if mapping.into_huge_page_at(expected).is_err() {
            unreachable!("validated huge primitive mapping transfer must succeed");
        }
        page += 1;
        let statistics = process.subprocess.vm_statistics();
        statistics.committed_increase(HUGE_PAGE_SIZE);
        statistics.reserve_increase(HUGE_PAGE_SIZE);

        if max_milliseconds > 0 {
            let mut elapsed = clock_end(start_time);
            let estimate = (elapsed / page as i64).saturating_mul(pages as i64);
            if estimate > max_milliseconds.saturating_mul(2) {
                elapsed = max_milliseconds.saturating_add(1);
            }
            if elapsed > max_milliseconds {
                stop = HugeOsAllocationStop::TimedOut;
                break;
            }
        }
    }

    debug_assert!(page.saturating_mul(HUGE_PAGE_SIZE) <= claimed_size);
    let allocation = NonNull::new(start as *mut u8).and_then(|base| {
        let size = page.checked_mul(HUGE_PAGE_SIZE)?;
        (page != 0).then_some(HugeOsAllocation {
            process,
            base,
            page_count: page,
            memory: MemoryId::os_huge(base.as_ptr(), size, true, all_zero),
            stop,
        })
    });
    match (allocation, rejected) {
        (Some(allocation), Some(rejected)) => {
            HugeOsAllocationOutcome::AllocatedWithRejectedPrimitive { allocation, rejected }
        }
        (Some(allocation), None) => HugeOsAllocationOutcome::Allocated(allocation),
        (None, Some(rejected)) => HugeOsAllocationOutcome::RejectedPrimitive(rejected),
        (None, None) => HugeOsAllocationOutcome::Unavailable(stop),
    }
}

fn map_huge_page_for_process(
    process: VmProcess<'_>,
    config: MemoryConfig,
    hint: usize,
    numa_node: i32,
) -> Result<Mapping> {
    let mapping = Mapping::map_huge_page_at(process.policy, config, hint)?;
    if numa_node >= 0 && numa_node < usize::BITS as i32 - 1 {
        let mask = 1usize << numa_node as u32;
        let address = mapping.base()?;
        // SAFETY: `mapping` owns this whole live primitive mapping; the
        // source accepts `mbind` failure as a best-effort NUMA preference and
        // supplies exactly one native unsigned-long mask word.
        let _ = unsafe {
            crabc_core::mm::mbind_raw(
                address,
                HUGE_PAGE_SIZE,
                MPOL_PREFERRED,
                &mask,
                usize::BITS as usize,
                0,
            )
        };
    }
    Ok(mapping)
}

fn free_huge_page_for_process(process: VmProcess<'_>, address: NonNull<u8>) -> Result<()> {
    let result = match fault_before(FaultPoint::Unmap) {
        Ok(()) => {
            // SAFETY: the caller supplies one exact still-live primitive huge
            // mapping. The outer huge owner never reuses an address after a
            // successful source free and retains failed addresses separately.
            unsafe { crabc_core::mm::munmap_raw(address.as_ptr(), HUGE_PAGE_SIZE) }
        }
        Err(error) => Err(error),
    };
    let statistics = process.subprocess.vm_statistics();
    statistics.committed_decrease(HUGE_PAGE_SIZE);
    statistics.reserve_decrease(HUGE_PAGE_SIZE);
    result
}

/// Walks every primitive page in the source free order while retaining a
/// compact exact record of only the failed raw ranges. The caller validates
/// and clears the supplied bitset before entering this helper.
fn release_huge_pages_with(
    base: NonNull<u8>,
    page_count: usize,
    failed_pages: &mut [usize],
    mut release: impl FnMut(NonNull<u8>) -> Result<()>,
) -> Option<Errno> {
    let mut first_error = None;
    for page in 0..page_count {
        let Some(address) = huge_page_address(base, page) else {
            huge_release_bit_set(failed_pages, page);
            first_error.get_or_insert(Errno::INVAL);
            continue;
        };
        if let Err(error) = release(address) {
            huge_release_bit_set(failed_pages, page);
            first_error.get_or_insert(error);
        }
    }
    first_error
}

#[inline]
const fn huge_release_word_count(page_count: usize) -> usize {
    let bits = usize::BITS as usize;
    page_count.saturating_add(bits - 1) / bits
}

#[inline]
fn huge_release_bit_is_set(bits: &[usize], page: usize) -> bool {
    let word = page / usize::BITS as usize;
    let bit = page % usize::BITS as usize;
    bits.get(word).is_some_and(|value| value & (1usize << bit) != 0)
}

#[inline]
fn huge_release_bit_set(bits: &mut [usize], page: usize) {
    let word = page / usize::BITS as usize;
    let bit = page % usize::BITS as usize;
    bits[word] |= 1usize << bit;
}

#[inline]
fn huge_release_bit_clear(bits: &mut [usize], page: usize) {
    let word = page / usize::BITS as usize;
    let bit = page % usize::BITS as usize;
    bits[word] &= !(1usize << bit);
}

#[inline]
fn huge_page_address(base: NonNull<u8>, page: usize) -> Option<NonNull<u8>> {
    let offset = page.checked_mul(HUGE_PAGE_SIZE)?;
    NonNull::new(base.as_ptr().wrapping_add(offset))
}

#[inline]
fn source_clock_now() -> i64 {
    source_clock_now_with(monotonic_milliseconds, source_clock_now_lowres)
}

/// Preserves `_mi_prim_clock_now`'s preferred-clock/fallback transition.
///
/// Pinned `src/prim/unix/prim.c:742-775` falls through to `clock()` after a
/// failed `clock_gettime(CLOCK_MONOTONIC)`.  This selector remains explicit
/// so a faulted preferred query cannot turn a bounded huge-page reservation
/// into a zero-time, potentially unbounded loop.
#[inline]
fn source_clock_now_with(
    preferred: impl FnOnce() -> Result<i64>,
    low_resolution: impl FnOnce() -> i64,
) -> i64 {
    preferred().unwrap_or_else(|_| low_resolution())
}

/// Reads the pinned `clock()` fallback without a libc dependency.
///
/// Native musl defines `CLOCKS_PER_SEC` as one million and implements
/// `clock()` from `CLOCK_PROCESS_CPUTIME_ID`; the source fallback then
/// converts those ticks to milliseconds. A raw CPU-clock error produces the
/// source `clock()` failure value of `-1`, whose C signed integer division by
/// 1000 truncates to zero.
#[inline]
fn source_clock_now_lowres() -> i64 {
    let mut time = core::mem::MaybeUninit::<KernelTimespec>::uninit();
    // Do not consult `fault_before(FaultPoint::Clock)` here: this is the
    // source fallback reached precisely after that preferred observation was
    // rejected, and it must still issue its own primitive query.
    let result = unsafe {
        crabc_core::time::clock_gettime_raw(
            CLOCK_PROCESS_CPUTIME_ID,
            time.as_mut_ptr().cast(),
        )
    };
    if result.is_err() {
        return source_clock_lowres_milliseconds_from_ticks(-1);
    }
    // SAFETY: a successful kernel/vDSO query initialized the fixed record.
    let time = unsafe { time.assume_init() };
    if time.seconds < 0 || !(0..1_000_000_000).contains(&time.nanoseconds) {
        return source_clock_lowres_milliseconds_from_ticks(-1);
    }
    let Some(ticks) = time
        .seconds
        .checked_mul(SOURCE_CLOCKS_PER_SECOND)
        .and_then(|seconds| seconds.checked_add(time.nanoseconds / 1_000))
    else {
        return source_clock_lowres_milliseconds_from_ticks(-1);
    };
    source_clock_lowres_milliseconds_from_ticks(ticks)
}

/// Applies the selected musl `clock()` tick-to-millisecond conversion.
#[inline]
fn source_clock_lowres_milliseconds_from_ticks(ticks: i64) -> i64 {
    // `SOURCE_CLOCKS_PER_SECOND > 1000` selects the final source branch.
    ticks / (SOURCE_CLOCKS_PER_SECOND / 1_000)
}

fn source_clock_start() -> i64 {
    if SOURCE_CLOCK_DIFF_MILLISECONDS.load(Ordering::Relaxed) == 0 {
        let before = source_clock_now();
        let after = source_clock_now();
        SOURCE_CLOCK_DIFF_MILLISECONDS.store(after.wrapping_sub(before), Ordering::Relaxed);
    }
    source_clock_now()
}

#[inline]
fn source_clock_end(start: i64) -> i64 {
    source_clock_now()
        .wrapping_sub(start)
        .wrapping_sub(SOURCE_CLOCK_DIFF_MILLISECONDS.load(Ordering::Relaxed))
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

/// A zero-offset regular-OS aligned allocation that may become one arena
/// backing.
///
/// This is deliberately distinct from [`NormalOsAllocation`]: the latter can
/// represent `_mi_os_alloc_aligned_at_offset` and therefore carry an interior
/// client pointer. Only [`NormalOsAllocation::allocate_aligned_base`] builds
/// this type, by consuming the ordinary `_mi_os_alloc_aligned` result whose
/// client pointer is the complete mapping base. The process arena may transfer
/// its exact [`MemoryId`] and [`Mapping`] together, whether it is a normal or
/// pinned regular-large OS map; no offset allocation can enter that handoff.
#[must_use = "a normal OS base allocation must move into an arena owner or an explicit release owner"]
pub(crate) struct NormalOsBaseAllocation {
    mapping: Mapping,
    memory: MemoryId,
}

impl NormalOsBaseAllocation {
    /// Borrows the exact regular mapping while the base-only handoff remains
    /// unconsumed.
    #[inline]
    pub(crate) const fn mapping(&self) -> &Mapping { &self.mapping }

    /// Returns the original normal OS provenance after verifying the mapping
    /// remains live.
    #[inline]
    pub(crate) fn memory_id(&self) -> Result<MemoryId> {
        let base = self.mapping.base()?;
        let length = self.mapping.length()?;
        debug_assert_eq!(self.memory.kind(), MemoryKind::Os);
        debug_assert_eq!(self.memory.os_memory().map(|memory| memory.base), Some(base));
        debug_assert_eq!(self.memory.os_memory().map(|memory| memory.size), Some(length));
        debug_assert_eq!(self.memory.initially_committed(), self.mapping.initially_committed());
        debug_assert_eq!(self.memory.initially_zero(), self.mapping.initially_zero());
        Ok(self.memory)
    }

    /// Moves the one normal base mapping and its source memory ID into the
    /// caller that owns the matching arena-management/release transition.
    #[inline]
    pub(crate) fn into_mapping_and_memory(self) -> (Mapping, MemoryId) {
        (self.mapping, self.memory)
    }
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

impl NormalOsAllocation {
    /// Allocates the fixed `_mi_os_alloc` route through the supplied process
    /// pair. This is the live source counterpart of [`Self::allocate`]: it
    /// preserves the fixed `allow_large = false` call argument while recording
    /// the primitive's map/reserved/committed events on that subprocess.
    pub(crate) fn allocate_for_process(
        process: VmProcess<'_>,
        config: MemoryConfig,
        size: usize,
    ) -> core::result::Result<Self, NormalOsAllocationFailure> {
        let length = Self::good_allocation_size(config, size)?;
        let mapping = Mapping::map_for_process(
            process,
            config,
            length,
            0,
            MapAccess::Committed,
            false,
            None,
        )
        .map_err(NormalOsAllocationFailure::without_mapping)?;
        Self::from_mapping(mapping, 0)
    }

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

    /// Allocates `_mi_os_alloc_aligned` through the source process pair.
    ///
    /// `allow_large` is the exact caller argument from the source call site;
    /// it remains separate from [`VmPolicy::allow_large_os_pages`], which
    /// controls source arena selection before this primitive is reached.
    pub(crate) fn allocate_aligned_for_process(
        process: VmProcess<'_>,
        config: MemoryConfig,
        size: usize,
        alignment: usize,
        access: MapAccess,
        allow_large: bool,
        default_random: Option<&mut TheapRandomImage>,
    ) -> core::result::Result<Self, NormalOsAllocationFailure> {
        let mapping = Self::allocate_aligned_mapping_for_process(
            process,
            config,
            size,
            alignment,
            access,
            allow_large,
            default_random,
        )?;
        Self::from_mapping(mapping, 0)
    }

    /// Allocates the ordinary aligned normal-OS route for a complete arena
    /// backing, retaining only its zero-offset/base-equals-client form.
    ///
    /// This is the typed handoff from pinned `_mi_os_alloc_aligned` into the
    /// selected `mi_reserve_os_memory_ex2` caller. It intentionally has no
    /// offset argument and cannot be constructed from
    /// `_mi_os_alloc_aligned_at_offset`'s interior-client result.
    pub(crate) fn allocate_aligned_base(
        config: MemoryConfig,
        size: usize,
        alignment: usize,
        access: MapAccess,
    ) -> core::result::Result<NormalOsBaseAllocation, NormalOsAllocationFailure> {
        let allocation = Self::allocate_aligned(config, size, alignment, access)?;
        let Self {
            mapping,
            pointer,
            memory,
        } = allocation;
        let base = match mapping.base() {
            Ok(base) => base,
            Err(error) => return Err(NormalOsAllocationFailure::with_mapping(error, mapping)),
        };
        let length = match mapping.length() {
            Ok(length) => length,
            Err(error) => return Err(NormalOsAllocationFailure::with_mapping(error, mapping)),
        };
        let Some(os_memory) = memory.os_memory() else {
            return Err(NormalOsAllocationFailure::with_mapping(Errno::INVAL, mapping));
        };
        if pointer.as_ptr() != base
            || memory.kind() != MemoryKind::Os
            || os_memory.base != base
            || os_memory.size != length
            || memory.initially_committed() != mapping.initially_committed()
            || memory.initially_zero() != mapping.initially_zero()
        {
            return Err(NormalOsAllocationFailure::with_mapping(Errno::INVAL, mapping));
        }
        Ok(NormalOsBaseAllocation { mapping, memory })
    }

    /// Builds the zero-offset arena-backing form of
    /// `_mi_os_alloc_aligned` through one paired process owner.
    pub(crate) fn allocate_aligned_base_for_process(
        process: VmProcess<'_>,
        config: MemoryConfig,
        size: usize,
        alignment: usize,
        access: MapAccess,
        allow_large: bool,
        default_random: Option<&mut TheapRandomImage>,
    ) -> core::result::Result<NormalOsBaseAllocation, NormalOsAllocationFailure> {
        let allocation = Self::allocate_aligned_for_process(
            process,
            config,
            size,
            alignment,
            access,
            allow_large,
            default_random,
        )?;
        Self::into_base_allocation(allocation)
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

    /// Allocates `_mi_os_alloc_aligned_at_offset` through the paired process
    /// owner, retaining source accounting for both its overmap and optional
    /// best-effort prefix decommit.
    pub(crate) fn allocate_aligned_at_offset_for_process(
        process: VmProcess<'_>,
        config: MemoryConfig,
        size: usize,
        alignment: usize,
        offset: usize,
        access: MapAccess,
        allow_large: bool,
        mut default_random: Option<&mut TheapRandomImage>,
    ) -> core::result::Result<Self, NormalOsAllocationFailure> {
        if offset > size {
            return Err(NormalOsAllocationFailure::without_mapping(Errno::INVAL));
        }
        if offset == 0 {
            return Self::allocate_aligned_for_process(
                process,
                config,
                size,
                alignment,
                access,
                allow_large,
                default_random.as_deref_mut(),
            );
        }
        let page_size = config.page_size().bytes();
        if alignment == 0 || alignment % page_size != 0 {
            return Err(NormalOsAllocationFailure::without_mapping(Errno::INVAL));
        }
        let extra = invariants::align_up(offset, alignment)
            .and_then(|aligned_offset| aligned_offset.checked_sub(offset))
            .ok_or_else(|| NormalOsAllocationFailure::without_mapping(Errno::NOMEM))?;
        if size >= usize::MAX - extra {
            return Err(NormalOsAllocationFailure::without_mapping(Errno::NOMEM));
        }
        let oversize = size + extra;
        let mapping = Self::allocate_aligned_mapping_for_process(
            process,
            config,
            oversize,
            alignment,
            access,
            allow_large,
            default_random.as_deref_mut(),
        )?;
        let allocation = Self::from_mapping(mapping, extra)?;
        if matches!(access, MapAccess::Committed) && extra >= page_size {
            // Just as in `src/os.c:521-525`, prefix decommit is best-effort
            // after the allocation is already live. Keep the owner/pointer
            // even if Linux rejects the advisory.
            let _ = allocation.mapping.decommit_for_process(process, 0, extra, extra);
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

    /// Releases this regular mapping with `_mi_os_free_ex`'s paired source
    /// statistics. A failed `munmap` returns the same exact allocation owner
    /// for a later retry; it cannot be mistaken for a finished release.
    pub(crate) fn release_for_process(
        mut self,
        process: VmProcess<'_>,
        still_committed: bool,
    ) -> core::result::Result<(), NormalOsAllocationReleaseFailure> {
        let commit_size = if still_committed {
            let base = match self.mapping.base() {
                Ok(base) => base,
                Err(error) => {
                    return Err(NormalOsAllocationReleaseFailure {
                        error,
                        allocation: self,
                    });
                }
            };
            let length = match self.mapping.length() {
                Ok(length) => length,
                Err(error) => {
                    return Err(NormalOsAllocationReleaseFailure {
                        error,
                        allocation: self,
                    });
                }
            };
            // `_mi_os_free_ex` frees the full `mem.os` base/size but removes
            // a previously decommitted interior-allocation prefix from the
            // final committed count. `pointer` is exactly that source `addr`.
            match self.pointer.as_ptr().addr().checked_sub(base.addr()) {
                Some(prefix) => match length.checked_sub(prefix) {
                    Some(committed) => committed,
                    None => {
                        return Err(NormalOsAllocationReleaseFailure {
                            error: Errno::INVAL,
                            allocation: self,
                        });
                    }
                },
                None => {
                    return Err(NormalOsAllocationReleaseFailure {
                        error: Errno::INVAL,
                        allocation: self,
                    });
                }
            }
        } else {
            0
        };
        match self.mapping.unmap_for_process(process, commit_size, false) {
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

    fn allocate_aligned_mapping_for_process(
        process: VmProcess<'_>,
        config: MemoryConfig,
        size: usize,
        alignment: usize,
        access: MapAccess,
        allow_large: bool,
        default_random: Option<&mut TheapRandomImage>,
    ) -> core::result::Result<Mapping, NormalOsAllocationFailure> {
        let length = Self::good_allocation_size(config, size)?;
        let alignment = Self::aligned_allocation_alignment(config, alignment)?;
        Mapping::map_aligned_for_process(
            process,
            config,
            length,
            alignment,
            access,
            allow_large,
            default_random,
        )
        .map_err(NormalOsAllocationFailure::from_aligned_failure)
    }

    fn into_base_allocation(
        allocation: Self,
    ) -> core::result::Result<NormalOsBaseAllocation, NormalOsAllocationFailure> {
        let Self {
            mapping,
            pointer,
            memory,
        } = allocation;
        let base = match mapping.base() {
            Ok(base) => base,
            Err(error) => return Err(NormalOsAllocationFailure::with_mapping(error, mapping)),
        };
        let length = match mapping.length() {
            Ok(length) => length,
            Err(error) => return Err(NormalOsAllocationFailure::with_mapping(error, mapping)),
        };
        let Some(os_memory) = memory.os_memory() else {
            return Err(NormalOsAllocationFailure::with_mapping(Errno::INVAL, mapping));
        };
        if pointer.as_ptr() != base
            || memory.kind() != MemoryKind::Os
            || os_memory.base != base
            || os_memory.size != length
            || memory.initially_committed() != mapping.initially_committed()
            || memory.initially_zero() != mapping.initially_zero()
        {
            return Err(NormalOsAllocationFailure::with_mapping(Errno::INVAL, mapping));
        }
        Ok(NormalOsBaseAllocation { mapping, memory })
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
            mapping.is_large(),
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

/// Selects every base page touched by one non-owning external span.
///
/// Unlike [`Mapping::page_range`], this cannot prove the input is within a
/// particular `Mapping` value because publication moved that capability to an
/// external owner. The unsafe caller of
/// [`Mapping::commit_published_for_process`] supplies the containment and
/// unique-transition proof; this helper only preserves `_mi_os_commit_ex`'s
/// liberal source page normalization.
fn covering_unowned_page_range(
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
    let start = invariants::align_down(start_address, page_size).ok_or(Errno::INVAL)?;
    let end = invariants::align_up(end_address, page_size).ok_or(Errno::INVAL)?;
    if end <= start {
        return Ok(None);
    }
    let prefix = start_address.checked_sub(start).ok_or(Errno::INVAL)?;
    let range_length = end.checked_sub(start).ok_or(Errno::INVAL)?;
    Ok(Some((address.wrapping_sub(prefix), range_length)))
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
/// This is only `_mi_prim_clock_now`'s preferred raw observation. Its caller
/// owns the source `clock()` low-resolution fallback. The `i64` output is the
/// pinned `mi_msecs_t` representation.
#[inline]
pub(crate) fn monotonic_milliseconds() -> Result<i64> {
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
/// `mi_os_numa_node_get` helper without options, diagnostics, or arena
/// placement. It keeps the raw [`numa_node`] observation intact for the M1
/// trace; the selected static ticket-zero caller consumes this wrapper and its
/// cached-single-node shortcut, strict `INT_MAX` current-node boundary, and
/// modulo normalization.
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

/// Test-only local-cache entry for an integration witness.
///
/// Production callers always use [`os_numa_node`] and its process cache. This
/// adapter lets the selected static-TLD regression exercise source-shaped raw
/// inputs without resetting or polluting that global topology state.
#[cfg(test)]
#[inline]
pub(crate) fn test_os_numa_node_with_raw(
    cache: &AtomicUsize,
    raw_count: impl FnMut() -> usize,
    raw_current: impl FnMut() -> usize,
) -> usize {
    os_numa_node_with_raw(cache, raw_count, raw_current)
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
    fn thp_allow_option_preserves_the_detected_memory_configuration() {
        let mut options = VmOptions::uninitialized();
        options.set(VmOption::AllowThp, 1);
        options.initialize_all(|_| VmOptionEnvironment::Absent);
        let policy = VmPolicy::new(options).expect("the source option image is resolved");
        let mut config = MemoryConfig::from_observations(
            PageSize::new(4 * 1024).expect("four KiB is a selected Linux page size"),
            0,
            true,
            true,
        );

        assert_eq!(
            policy.apply_thp_process_policy(&mut config),
            ThpPolicyOutcome::Allowed,
            "an enabled source option must not query or change this process's THP policy"
        );
        assert!(config.has_transparent_huge_pages());
    }

    #[cfg(not(miri))]
    fn disabled_thp_policy_child_observation() -> (bool, bool) {
        // `PR_SET_THP_DISABLE` is process-local. Run the exact source branch
        // after a raw fork and send its two address-free observations through
        // a pre-fork pipe. The child allocates no Rust state after the fork
        // and exits through the raw Linux boundary.
        let (reader, writer) = crabc_core::pipe::pipe2(0).expect("create THP policy pipe");
        let parent_before = unsafe { crabc_core::process::prctl_raw(PR_GET_THP_DISABLE, 0, 0, 0, 0) };
        let child = crabc_core::process::fork_raw().expect("fork THP policy child");
        if child == 0 {
            let _ = crabc_core::io::close(reader);
            let mut options = VmOptions::uninitialized();
            options.initialize_all(|option| {
                if option == VmOption::AllowThp {
                    VmOptionEnvironment::Value(b"0")
                } else {
                    VmOptionEnvironment::Absent
                }
            });
            let policy = match VmPolicy::new(options) {
                Ok(policy) => policy,
                Err(_) => crabc_core::process::exit_immediately(1),
            };
            let mut config = MemoryConfig::detect(current_startup());
            let _outcome = policy.apply_thp_process_policy(&mut config);
            let observations = [
                u8::from(!config.has_transparent_huge_pages()),
                u8::from(matches!(
                    unsafe { crabc_core::process::prctl_raw(PR_GET_THP_DISABLE, 0, 0, 0, 0) },
                    Ok(1)
                )),
            ];
            let wrote = unsafe {
                crabc_core::io::write_raw(writer, observations.as_ptr(), observations.len())
            };
            let _ = crabc_core::io::close(writer);
            crabc_core::process::exit_immediately(if wrote == Ok(observations.len()) { 0 } else { 1 });
        }

        crabc_core::io::close(writer).expect("close the parent write end");
        let mut observations = [0_u8; 2];
        assert_eq!(
            unsafe {
                crabc_core::io::read_raw(reader, observations.as_mut_ptr(), observations.len())
            },
            Ok(observations.len()),
            "the THP policy child must write both source observations"
        );
        crabc_core::io::close(reader).expect("close the parent read end");
        let mut status = 0;
        assert_eq!(
            unsafe { crabc_core::process::wait4_raw(child, &mut status, 0) },
            Ok(child),
            "the parent must reap the exact THP policy child"
        );
        assert_eq!(status, 0, "the THP policy child must complete its raw report");
        assert_eq!(
            unsafe { crabc_core::process::prctl_raw(PR_GET_THP_DISABLE, 0, 0, 0, 0) },
            parent_before,
            "the test runner process must retain its original THP setting"
        );
        (observations[0] != 0, observations[1] != 0)
    }

    #[cfg(not(miri))]
    #[test]
    fn thp_disable_policy_runs_only_in_an_isolated_child_process() {
        let (configuration_disabled, _process_disabled) = disabled_thp_policy_child_observation();
        assert!(
            configuration_disabled,
            "the source branch must clear its allocation-policy THP observation even if prctl fails"
        );
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

        let initially_empty_single_node = AtomicUsize::new(0);
        assert_eq!(
            os_numa_node_with_raw(
                &initially_empty_single_node,
                || 0,
                || panic!("a slow-path count normalized to one must not probe a current node"),
            ),
            0,
        );
        assert_eq!(initially_empty_single_node.load(Ordering::Relaxed), 1);

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
    fn vm_policy_keeps_arena_options_and_numa_cache_with_the_process_pair() {
        let mut unresolved_lifecycle = VmOptions::uninitialized();
        unresolved_lifecycle.initialize_all(|_| VmOptionEnvironment::Absent);
        let lifecycle = VmPolicy::new(unresolved_lifecycle)
            .expect("the source-absent image resolves every VM descriptor");
        assert!(lifecycle.is_preloading());
        lifecycle.finish_preloading();
        assert!(!lifecycle.is_preloading());

        let mut policy = VmPolicy::defaults_for_test();
        assert_eq!(policy.arena_purge_multiplier(), 4);
        assert!(!policy.arena_is_numa_local());
        assert_eq!(policy.purge_delay_milliseconds(), 1_000);
        assert!(policy.purge_decommits());

        policy.set_option(VmOption::ArenaPurgeMult, -2);
        policy.set_option(VmOption::ArenaIsNumaLocal, 1);
        policy.set_option(VmOption::PurgeDelay, -1);
        policy.set_option(VmOption::PurgeDecommits, 0);
        assert_eq!(policy.arena_purge_multiplier(), -2);
        assert!(policy.arena_is_numa_local());
        assert_eq!(policy.purge_delay_milliseconds(), -1);
        assert!(!policy.purge_decommits());

        let thp_config = MemoryConfig::from_observations(
            PageSize::new(4 * 1024).expect("four KiB is one selected Linux page size"),
            0,
            true,
            true,
        );
        policy.set_option(VmOption::AllowThp, 2);
        assert_eq!(
            policy.minimal_purge_size(thp_config),
            thp_config.large_page_size(),
            "source allow_thp=2 uses the selected transparent huge-page size"
        );
        policy.set_option(VmOption::MinimalPurgeSize, 5);
        assert_eq!(
            policy.minimal_purge_size(thp_config),
            8 * 1024,
            "an explicit five-KiB source value rounds up to a base-page multiple"
        );

        let mut configured = VmPolicy::defaults_for_test();
        configured.set_option(VmOption::UseNumaNodes, 3);
        assert_eq!(
            configured.current_numa_node_with_raw(
                || panic!("a positive configured NUMA count must skip raw topology"),
                || 8,
            ),
            2,
            "the source normalizes the current node against the configured count"
        );
        assert_eq!(
            configured.numa_node_count_with_raw(|| panic!("the resolved cache must be reused")),
            3
        );

        let mut int_max = VmPolicy::defaults_for_test();
        int_max.set_option(VmOption::UseNumaNodes, i64::from(i32::MAX));
        assert_eq!(
            int_max.numa_node_count_with_raw(|| 5),
            5,
            "the source rejects INT_MAX itself as an explicit option and probes the primitive"
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
    fn vm_process_normal_allocation_retains_source_statistics_on_failed_release() {
        let fault = fault::install(fault::Plan::disabled());
        let config = MemoryConfig::detect(current_startup());
        let page = config.page_size().bytes();
        let policy = VmPolicy::defaults_for_test();
        let subprocess = crate::subproc::MainSubprocess::test_static_owner();
        let process = VmProcess::new(&policy, subprocess);

        let allocation = NormalOsAllocation::allocate_for_process(process, config, page)
            .expect("the paired source process maps one regular committed range");
        let full_size = allocation.full_size().expect("the regular mapping stays live");
        let after_map = subprocess.vm_statistics().snapshot();
        assert_eq!(after_map.mmap_calls, 1);
        assert_eq!(after_map.reserved_total, full_size as i64);
        assert_eq!(after_map.reserved_current, full_size as i64);
        assert_eq!(after_map.committed_total, full_size as i64);
        assert_eq!(after_map.committed_current, full_size as i64);

        // `_mi_os_prim_free` updates source counters after the primitive
        // reports an error. Its retained owner is still live, but there is no
        // invented statistic rollback before an explicit retry.
        fault.set(fault::Plan::at(fault::Point::Unmap, 1, Errno::NOMEM));
        let retained = match allocation.release_for_process(process, true) {
            Ok(()) => panic!("the injected release failure must retain its mapping"),
            Err(failure) => failure,
        };
        assert_eq!(retained.error(), Errno::NOMEM);
        let retained = retained.into_allocation();
        assert!(retained.base().is_ok());
        let after_failed_release = subprocess.vm_statistics().snapshot();
        assert_eq!(after_failed_release.reserved_current, 0);
        assert_eq!(after_failed_release.committed_current, 0);

        // Retrying the same explicit source free decrements its statistics a
        // second time: there is deliberately no bookkeeping rollback tied to
        // a failed kernel release. The owner remains the only reliable retry
        // token, so preserve that observable source consequence.
        fault.set(fault::Plan::disabled());
        retained
            .release_for_process(process, true)
            .expect("the retained exact owner releases successfully");
        let after_retry = subprocess.vm_statistics().snapshot();
        assert_eq!(after_retry.reserved_current, -(full_size as i64));
        assert_eq!(after_retry.committed_current, -(full_size as i64));
    }

    #[test]
    fn published_mapping_process_release_accounts_once_before_a_raw_retry() {
        let fault = fault::install(fault::Plan::disabled());
        let config = MemoryConfig::detect(current_startup());
        let page = config.page_size().bytes();
        let policy = VmPolicy::defaults_for_test();
        let subprocess = crate::subproc::MainSubprocess::test_static_owner();
        let process = VmProcess::new(&policy, subprocess);
        let mapping = Mapping::map_for_process(
            process,
            config,
            page,
            1,
            MapAccess::Committed,
            false,
            None,
        )
        .expect("the paired process maps one published-page range");
        let address = mapping
            .into_published()
            .expect("the mapping transfers one exact raw publication token");

        fault.set(fault::Plan::at(fault::Point::Unmap, 1, Errno::NOMEM));
        assert_eq!(
            unsafe {
                Mapping::reclaim_published_for_process(process, address, page, page, false)
            },
            Err(Errno::NOMEM),
        );
        let after_failed_release = subprocess.vm_statistics().snapshot();
        assert_eq!(after_failed_release.reserved_current, 0);
        assert_eq!(after_failed_release.committed_current, 0);

        // A second process-aware release would duplicate the pinned source
        // statistics transition. The retained published token deliberately
        // uses the raw exact release edge for a later explicit retry.
        fault.set(fault::Plan::disabled());
        unsafe { Mapping::reclaim_published(address, page) }
            .expect("the failed published mapping remains live for one raw retry");
        let after_raw_retry = subprocess.vm_statistics().snapshot();
        assert_eq!(after_raw_retry.reserved_current, 0);
        assert_eq!(after_raw_retry.committed_current, 0);
    }

    #[test]
    fn published_mapping_process_commit_counts_before_normalization_and_only_after_success() {
        let fault = fault::install(fault::Plan::disabled());
        let config = MemoryConfig::detect(current_startup());
        let page = config.page_size().bytes();
        let policy = VmPolicy::defaults_for_test();
        let subprocess = crate::subproc::MainSubprocess::test_static_owner();
        let process = VmProcess::new(&policy, subprocess);

        let mapping = Mapping::map_for_process(
            process,
            config,
            2 * page,
            1,
            MapAccess::Reserved,
            false,
            None,
        )
        .expect("the paired process reserves two source pages");
        let base = mapping.into_published().expect("the mapping transfers its publication token");
        let before = subprocess.vm_statistics().snapshot();
        // SAFETY: this published token names a live two-page reservation; the
        // one-page interior request has a unique new-prefix transition and
        // its covering page range remains within that reservation.
        assert_eq!(
            unsafe {
                Mapping::commit_published_for_process(
                    process,
                    config,
                    base.wrapping_add(page / 2),
                    page,
                )
            },
            Ok(Some(CommitOutcome::NotKnownZero)),
        );
        let after_commit = subprocess.vm_statistics().snapshot();
        assert_eq!(after_commit.commit_calls, before.commit_calls + 1);
        assert_eq!(after_commit.committed_current, before.committed_current + page as i64);
        assert_eq!(after_commit.committed_total, before.committed_total + page as i64);
        // SAFETY: the original token retains the full two-page release right;
        // the source caller records only its one-page committed prefix.
        unsafe { Mapping::reclaim_published_for_process(process, base, 2 * page, page, false) }
            .expect("the published reservation releases with its exact source statistics");

        let empty = Mapping::map_for_process(
            process,
            config,
            page,
            1,
            MapAccess::Reserved,
            false,
            None,
        )
        .expect("the paired process reserves one empty-range fixture page");
        let empty_base = empty.into_published().unwrap();
        let before_empty = subprocess.vm_statistics().snapshot();
        // SAFETY: the live token remains exclusively owned; zero length is the
        // source's normalized empty commit branch.
        assert_eq!(
            unsafe { Mapping::commit_published_for_process(process, config, empty_base, 0) },
            Ok(None),
        );
        let after_empty = subprocess.vm_statistics().snapshot();
        assert_eq!(after_empty.commit_calls, before_empty.commit_calls + 1);
        assert_eq!(after_empty.committed_current, before_empty.committed_current);
        unsafe { Mapping::reclaim_published_for_process(process, empty_base, page, 0, false) }
            .expect("the empty-range fixture retains its release right");

        let failed = Mapping::map_for_process(
            process,
            config,
            page,
            1,
            MapAccess::Reserved,
            false,
            None,
        )
        .expect("the paired process reserves one failure fixture page");
        let failed_base = failed.into_published().unwrap();
        let before_failure = subprocess.vm_statistics().snapshot();
        fault.set(fault::Plan::at(fault::Point::Commit, 1, Errno::NOMEM));
        // SAFETY: this token names a still-reserved page and no alias can
        // observe the failed source transition.
        assert_eq!(
            unsafe { Mapping::commit_published_for_process(process, config, failed_base, page) },
            Err(Errno::NOMEM),
        );
        let after_failure = subprocess.vm_statistics().snapshot();
        assert_eq!(after_failure.commit_calls, before_failure.commit_calls + 1);
        assert_eq!(after_failure.committed_current, before_failure.committed_current);
        fault.set(fault::Plan::disabled());
        unsafe { Mapping::reclaim_published_for_process(process, failed_base, page, 0, false) }
            .expect("the failed commit retains its published release token");
    }

    fn synthetic_huge_mapping(config: MemoryConfig, address: usize) -> Mapping {
        Mapping {
            address: address as *mut u8,
            length: HUGE_PAGE_SIZE,
            page_size: config.page_size(),
            initially_committed: true,
            initially_zero: true,
            is_large: true,
            is_mapped: true,
        }
    }

    #[test]
    fn source_huge_clock_uses_the_low_resolution_clock_after_monotonic_failure() {
        // `src/prim/unix/prim.c:_mi_prim_clock_now` does not substitute zero
        // when its preferred CLOCK_MONOTONIC query fails: it calls `clock()`.
        // Keep this selector independent from host timing and fault-plan
        // serialization so a timed huge reservation cannot silently fail open.
        assert_eq!(source_clock_lowres_milliseconds_from_ticks(1_234_567), 1_234);
        assert_eq!(source_clock_lowres_milliseconds_from_ticks(-1), 0);

        // This is the production fault edge: fault the real preferred raw
        // query, then require its transition to a nonzero fallback value.
        // This avoids coupling the regression to how much CPU time an
        // unusually fast test process happened to consume.
        let fault = fault::install(fault::Plan::at(fault::Point::Clock, 1, Errno::NOMEM));
        let after_forced_monotonic_failure = source_clock_now_with(
            monotonic_milliseconds,
            || 47,
        );
        assert_eq!(fault.observed(), 1);
        assert_eq!(after_forced_monotonic_failure, 47);
        drop(fault);
        assert!(source_clock_now_lowres() >= 0);
    }

    #[test]
    fn huge_os_allocation_records_the_contiguous_prefix_and_os_huge_provenance() {
        let _fault = fault::install(fault::Plan::disabled());
        let config = MemoryConfig::detect(current_startup());
        let policy = VmPolicy::defaults_for_test();
        let subprocess = crate::subproc::MainSubprocess::test_static_owner();
        let process = VmProcess::new(&policy, subprocess);
        let mut mapped = 0;

        let allocation = match allocate_huge_pages_with(
            process,
            2,
            0,
            None,
            |hint| {
                mapped += 1;
                Ok(synthetic_huge_mapping(config, hint))
            },
            || 0,
            |_| 0,
        ) {
            HugeOsAllocationOutcome::Allocated(allocation) => allocation,
            _ => panic!("two exact primitive maps must produce one huge owner"),
        };

        assert_eq!(mapped, 2);
        assert_eq!(allocation.page_count(), 2);
        assert_eq!(allocation.size(), 2 * HUGE_PAGE_SIZE);
        assert_eq!(allocation.stop(), HugeOsAllocationStop::Complete);
        let memory = allocation.memory_id();
        assert_eq!(memory.kind(), MemoryKind::OsHuge);
        assert_eq!(
            memory.os_base().map(|address| address.value()),
            Some(allocation.base().as_ptr().addr()),
        );
        assert_eq!(memory.size(), Some(2 * HUGE_PAGE_SIZE));
        assert!(memory.is_pinned());
        assert!(memory.initially_committed());
        assert!(memory.initially_zero());
        let statistics = subprocess.vm_statistics().snapshot();
        assert_eq!(statistics.mmap_calls, 0, "the huge primitive does not use mi_os_prim_alloc");
        assert_eq!(statistics.reserved_current, (2 * HUGE_PAGE_SIZE) as i64);
        assert_eq!(statistics.committed_current, (2 * HUGE_PAGE_SIZE) as i64);
    }

    #[test]
    fn huge_os_allocation_times_out_after_recording_the_completed_prefix() {
        let _fault = fault::install(fault::Plan::disabled());
        let config = MemoryConfig::detect(current_startup());
        let policy = VmPolicy::defaults_for_test();
        let subprocess = crate::subproc::MainSubprocess::test_static_owner();
        let process = VmProcess::new(&policy, subprocess);
        let mut mapped = 0;

        let allocation = match allocate_huge_pages_with(
            process,
            3,
            10,
            None,
            |hint| {
                mapped += 1;
                Ok(synthetic_huge_mapping(config, hint))
            },
            || 0,
            |_| 11,
        ) {
            HugeOsAllocationOutcome::Allocated(allocation) => allocation,
            _ => panic!("the first source huge primitive completes before timeout evaluation"),
        };

        assert_eq!(mapped, 1, "the source estimate forces the timeout after one page");
        assert_eq!(allocation.page_count(), 1);
        assert_eq!(allocation.stop(), HugeOsAllocationStop::TimedOut);
        assert_eq!(subprocess.vm_statistics().snapshot().reserved_current, HUGE_PAGE_SIZE as i64);
    }

    #[test]
    fn huge_os_allocation_never_substitutes_a_regular_map_after_primitive_failure() {
        let fault = fault::install(fault::Plan::at(fault::Point::Map, 1, Errno::NOMEM));
        let config = MemoryConfig::detect(current_startup());
        let policy = VmPolicy::defaults_for_test();
        let subprocess = crate::subproc::MainSubprocess::test_static_owner();
        let process = VmProcess::new(&policy, subprocess);

        assert!(matches!(
            HugeOsAllocation::allocate_for_process(process, config, 1, -1, 0, None),
            HugeOsAllocationOutcome::Unavailable(HugeOsAllocationStop::PrimitiveMapFailed(
                Errno::NOMEM
            ))
        ));
        assert_eq!(fault.observed(), 1, "one failed huge primitive ends the source loop");
        assert_ne!(policy.huge_hint_start.load(Ordering::Acquire), 0);
        let statistics = subprocess.vm_statistics().snapshot();
        assert_eq!(statistics.mmap_calls, 0);
        assert_eq!(statistics.reserved_current, 0);
        assert_eq!(statistics.committed_current, 0);
    }

    #[test]
    fn huge_os_noncontiguous_primitive_retains_only_its_adjusted_cleanup_owner() {
        let fault = fault::install(fault::Plan::at(fault::Point::Unmap, 1, Errno::NOMEM));
        let config = MemoryConfig::detect(current_startup());
        let policy = VmPolicy::defaults_for_test();
        let subprocess = crate::subproc::MainSubprocess::test_static_owner();
        let process = VmProcess::new(&policy, subprocess);

        let rejected = match allocate_huge_pages_with(
            process,
            1,
            0,
            None,
            |hint| Ok(synthetic_huge_mapping(config, hint + HUGE_PAGE_SIZE)),
            || 0,
            |_| 0,
        ) {
            HugeOsAllocationOutcome::RejectedPrimitive(rejected) => rejected,
            _ => panic!("a noncontiguous source primitive cannot become MI_MEM_OS_HUGE"),
        };

        assert_eq!(rejected.error(), Errno::NOMEM);
        let statistics = subprocess.vm_statistics().snapshot();
        assert_eq!(statistics.reserved_current, -(HUGE_PAGE_SIZE as i64));
        assert_eq!(statistics.committed_current, -(HUGE_PAGE_SIZE as i64));
        assert_eq!(fault.observed(), 1, "the adjustment cleanup was attempted once");
    }

    #[test]
    fn huge_os_release_walks_after_failures_and_records_exact_page_bits() {
        let base = NonNull::new(HUGE_HINT_BASE as *mut u8).unwrap();
        let mut failed = [0usize; 1];
        let mut observed = [usize::MAX; 3];
        let mut count = 0;
        let first = release_huge_pages_with(base, 3, &mut failed, |address| {
            let page = (address.as_ptr().addr() - base.as_ptr().addr()) / HUGE_PAGE_SIZE;
            observed[count] = page;
            count += 1;
            if page == 0 || page == 2 {
                Err(Errno::NOMEM)
            } else {
                Ok(())
            }
        });

        assert_eq!(first, Some(Errno::NOMEM));
        assert_eq!(count, 3, "source free continues after the first primitive error");
        assert_eq!(observed, [0, 1, 2]);
        assert_eq!(failed[0], 0b101, "only still-live primitive mappings are retained");
    }

    #[test]
    fn huge_os_raw_retry_never_repeats_source_statistics() {
        let fault = fault::install(fault::Plan::at(fault::Point::Unmap, 1, Errno::NOMEM));
        let policy = VmPolicy::defaults_for_test();
        let subprocess = crate::subproc::MainSubprocess::test_static_owner();
        let process = VmProcess::new(&policy, subprocess);
        let base = NonNull::dangling();

        assert_eq!(free_huge_page_for_process(process, base), Err(Errno::NOMEM));
        let after_source_free = subprocess.vm_statistics().snapshot();
        assert_eq!(after_source_free.reserved_current, -(HUGE_PAGE_SIZE as i64));
        assert_eq!(after_source_free.committed_current, -(HUGE_PAGE_SIZE as i64));

        let mut failed = [1usize];
        let retry = HugeOsRawReleaseRetry {
            process,
            base,
            page_count: 1,
            memory: MemoryId::os_huge(base.as_ptr(), HUGE_PAGE_SIZE, true, true),
            source_error: Errno::NOMEM,
            failed_pages: &mut failed,
            failed_words: 1,
        };
        fault.set(fault::Plan::at(fault::Point::Unmap, 1, Errno::NOMEM));
        let failure = match retry.retry_raw() {
            Ok(()) => panic!("the injected raw retry must retain its one failed page"),
            Err(failure) => failure,
        };
        assert_eq!(failure.error(), Errno::NOMEM);
        let retry = failure.into_retry();
        assert!(retry.failed_page(0));
        assert_eq!(
            subprocess.vm_statistics().snapshot(),
            after_source_free,
            "raw retries must not repeat a source-accounted free event",
        );
    }

    #[test]
    fn huge_os_release_requires_complete_failure_tracking_before_any_free() {
        let _fault = fault::install(fault::Plan::disabled());
        let config = MemoryConfig::detect(current_startup());
        let policy = VmPolicy::defaults_for_test();
        let subprocess = crate::subproc::MainSubprocess::test_static_owner();
        let process = VmProcess::new(&policy, subprocess);
        let allocation = match allocate_huge_pages_with(
            process,
            1,
            0,
            None,
            |hint| Ok(synthetic_huge_mapping(config, hint)),
            || 0,
            |_| 0,
        ) {
            HugeOsAllocationOutcome::Allocated(allocation) => allocation,
            _ => panic!("the synthetic source primitive produces one huge owner"),
        };

        let mut no_tracking = [];
        let failure = match allocation.release_for_process(&mut no_tracking) {
            Ok(()) => panic!("release must not start without exact failed-page storage"),
            Err(HugeOsReleaseFailure::Tracking(failure)) => failure,
            Err(HugeOsReleaseFailure::FailedPages(_)) => {
                panic!("no primitive free may run before tracker validation")
            }
        };
        assert_eq!(failure.required_words(), 1);
        let _allocation = failure.into_allocation();
        assert_eq!(subprocess.vm_statistics().snapshot().reserved_current, HUGE_PAGE_SIZE as i64);
    }

    #[test]
    fn vm_process_purge_counts_before_a_failed_reset_primitive() {
        let fault = fault::install(fault::Plan::disabled());
        let config = MemoryConfig::detect(current_startup());
        let page = config.page_size().bytes();
        let mut policy = VmPolicy::defaults_for_test();
        policy.set_option(VmOption::PurgeDecommits, 0);
        let subprocess = crate::subproc::MainSubprocess::test_static_owner();
        let process = VmProcess::new(&policy, subprocess);
        let mut mapping = Mapping::map_for_process(
            process,
            config,
            page,
            1,
            MapAccess::Committed,
            false,
            None,
        )
        .expect("the paired source process maps one purge range");

        fault.set(fault::Plan::at(fault::Point::Purge, 1, Errno::NOMEM));
        assert_eq!(mapping.purge_for_process(process, 0, page, true, page), Err(Errno::NOMEM));
        let after_failed_reset = subprocess.vm_statistics().snapshot();
        assert_eq!(after_failed_reset.purge_calls, 1);
        assert_eq!(after_failed_reset.purged, page as i64);
        assert_eq!(after_failed_reset.reset_calls, 1);
        assert_eq!(after_failed_reset.reset, page as i64);
        assert_eq!(after_failed_reset.committed_current, page as i64);

        fault.set(fault::Plan::disabled());
        mapping
            .unmap_for_process(process, page, false)
            .expect("the exact retained mapping releases after a reset failure");
    }

    #[test]
    fn vm_process_offset_release_subtracts_the_decommitted_client_prefix() {
        let _fault = fault::install(fault::Plan::disabled());
        let config = MemoryConfig::detect(current_startup());
        let page = config.page_size().bytes();
        let policy = VmPolicy::defaults_for_test();
        let subprocess = crate::subproc::MainSubprocess::test_static_owner();
        let process = VmProcess::new(&policy, subprocess);
        let size = page.checked_mul(2).expect("the source span fits");
        let alignment = page.checked_mul(4).expect("the source alignment fits");
        let offset = page;
        let prefix = invariants::align_up(offset, alignment)
            .and_then(|aligned| aligned.checked_sub(offset))
            .expect("the source prefix geometry fits");

        let allocation = NormalOsAllocation::allocate_aligned_at_offset_for_process(
            process,
            config,
            size,
            alignment,
            offset,
            MapAccess::Committed,
            false,
            None,
        )
        .expect("the paired offset allocation maps one retained full owner");
        let full_size = allocation.full_size().expect("the full source map is live");
        assert_eq!(
            allocation.pointer().unwrap().as_ptr().addr() - allocation.base().unwrap().addr(),
            prefix
        );
        allocation
            .release_for_process(process, true)
            .expect("the interior source pointer still releases the mapping base");
        let statistics = subprocess.vm_statistics().snapshot();
        assert_eq!(statistics.reserved_current, 0);
        assert_eq!(
            statistics.committed_current,
            prefix as i64,
            "source release subtracts the decommitted prefix from its final committed edge"
        );
        assert_eq!(statistics.reserved_total, full_size as i64);
    }

    #[test]
    fn normal_os_base_handoff_preserves_full_mapping_and_memid() {
        let _fault = fault::install(fault::Plan::disabled());
        let config = MemoryConfig::detect(current_startup());
        let page = config.page_size().bytes();
        let size = page
            .checked_mul(2)
            .expect("the selected base-only allocation size fits");
        let alignment = page
            .checked_mul(4)
            .expect("the selected base-only allocation alignment fits");

        let allocation = NormalOsAllocation::allocate_aligned_base(
            config,
            size,
            alignment,
            MapAccess::Reserved,
        )
        .expect("the aligned base-only route maps one normal OS owner");
        let base = allocation
            .mapping()
            .base()
            .expect("the base-only handoff retains its mapping base");
        let length = allocation
            .mapping()
            .length()
            .expect("the base-only handoff retains its full mapped extent");
        let memory = allocation
            .memory_id()
            .expect("the base-only handoff retains its OS provenance");
        assert_eq!(base.addr() % alignment, 0);
        assert_eq!(length, config.good_alloc_size(size));
        assert_eq!(memory.kind(), MemoryKind::Os);
        assert!(!memory.is_pinned());
        assert!(!memory.initially_committed());
        assert!(memory.initially_zero());
        assert_eq!(memory.os_memory().unwrap().base, base);
        assert_eq!(memory.os_memory().unwrap().size, length);

        let (mut mapping, handed_memory) = allocation.into_mapping_and_memory();
        assert_eq!(mapping.base(), Ok(base));
        assert_eq!(mapping.length(), Ok(length));
        assert_eq!(handed_memory.kind(), MemoryKind::Os);
        assert_eq!(handed_memory.os_memory().unwrap().base, base);
        assert_eq!(handed_memory.os_memory().unwrap().size, length);
        mapping
            .unmap()
            .expect("the consumed base-only mapping releases its exact full extent");
    }

    #[test]
    fn normal_os_base_handoff_accepts_pinned_regular_large_provenance() {
        let _fault = fault::install(fault::Plan::disabled());
        let config = MemoryConfig::detect(current_startup());
        let page = config.page_size().bytes();
        let allocation = NormalOsAllocation::allocate(config, page)
            .expect("one regular mapping supplies the isolated provenance fixture");
        // A successful `MAP_HUGETLB` regular allocation retains the ordinary
        // `MI_MEM_OS` kind but marks its `MemoryId` pinned. The mapping remains
        // one range and is therefore valid arena-backing input; only
        // `MI_MEM_OS_HUGE` has its distinct one-GiB release owner.
        let mut allocation = allocation;
        let mapping_base = allocation.mapping.base().expect("the map remains live");
        let mapping_size = allocation.mapping.length().expect("the map remains live");
        allocation.mapping.is_large = true;
        allocation.memory = MemoryId::os(mapping_base, mapping_size, true, true, true);
        let base = NormalOsAllocation::into_base_allocation(allocation)
            .expect("a pinned regular-large map is valid base-only backing");
        let memory = base.memory_id().expect("the base handoff stays live");
        assert_eq!(memory.kind(), MemoryKind::Os);
        assert!(memory.is_pinned());
        let (mut mapping, _) = base.into_mapping_and_memory();
        mapping
            .unmap()
            .expect("the regular-large provenance fixture releases one mapping");
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

    /// Emits the native M2 fixed-profile VM lifecycle record.
    ///
    /// This test deliberately follows every VM transition that the current
    /// typed Linux owner can perform: reserved and committed mappings,
    /// covering commit, contained decommit/reset/reuse/protection, ordinary,
    /// aligned, and offset-aligned normal OS ownership, and the normalized
    /// NUMA observation.  The companion pinned-C fixture calls the matching
    /// `src/os.c` private helpers in one process and compares only stable
    /// ownership and transition facts, never virtual addresses or allocator
    /// statistics.
    ///
    /// It also compares the selected `allow_thp=0` source configuration and
    /// process-policy observation. The Rust side executes that `prctl`
    /// transition only in its child and imports its address-free result, so
    /// the native test runner never inherits the allocator policy.
    ///
    /// It is not a claim for unowned source policy branches. In particular,
    /// ambient option discovery, random aligned hints, large/1-GiB huge-page
    /// reservation, diagnostics, and arena placement require their actual
    /// owners before the VM component can close.
    #[cfg(not(miri))]
    #[test]
    fn emit_m2_vm_primitives_c_rust_trace() {
        let _fault = fault::install(fault::Plan::disabled());
        let mut config = MemoryConfig::detect(current_startup());
        let (thp_configuration_disabled, thp_process_disabled) =
            disabled_thp_policy_child_observation();
        assert!(
            thp_configuration_disabled,
            "the isolated source policy must clear the derived configuration"
        );
        // The source configuration field is the observable result of the
        // child-owned transaction. Copy that result into this fixed lifecycle
        // record without issuing `PR_SET_THP_DISABLE` in the parent.
        config.disable_transparent_huge_pages();
        let page = config.page_size().bytes();
        let alignment = page
            .checked_mul(16)
            .expect("the fixed trace alignment fits");

        let mut reserved = Mapping::map_for_allocator(config, page, MapAccess::Reserved)
            .expect("the fixed trace reserves one page");
        let reserved_initially_zero = reserved.initially_zero();
        let reserved_initially_committed = reserved.initially_committed();
        assert_eq!(
            reserved.commit(0, page),
            Ok(Some(CommitOutcome::NotKnownZero)),
            "the source commit covers the complete one-page reservation"
        );
        assert_eq!(
            reserved.decommit(0, page),
            Ok(Some(DecommitOutcome::DoesNotNeedRecommit)),
            "the default Linux source decommit keeps the mapping accessible"
        );
        assert!(reserved.purge(0, page).expect("the source reset succeeds"));
        assert_eq!(
            reserved.reuse(0, page),
            Ok(Some(ReuseOutcome::NoOp)),
            "Linux reuse has no VM syscall after conservative page normalization"
        );
        assert!(reserved.protect(0, page).expect("the source protect succeeds"));
        assert!(reserved
            .unprotect(0, page)
            .expect("the source unprotect succeeds"));
        reserved
            .unmap()
            .expect("the fixed trace releases the reserved owner once");

        let normal = NormalOsAllocation::allocate(
            config,
            page.checked_add(1).expect("the fixed normal request fits"),
        )
        .expect("the source normal OS allocation succeeds");
        let normal_base = normal.base().expect("normal owner remains live");
        let normal_pointer = normal.pointer().expect("normal client pointer is live");
        let normal_size = normal.full_size().expect("normal owner has its full extent");
        let normal_memory = normal.memory_id().expect("normal owner retains provenance");
        assert_eq!(normal_pointer.as_ptr(), normal_base);
        assert_eq!(normal_size, config.good_alloc_size(page + 1));
        assert_eq!(normal_memory.os_base().map(|base| base.value()), Some(normal_base.addr()));
        assert_eq!(normal_memory.size(), Some(normal_size));
        assert!(normal_memory.initially_committed());
        assert!(normal_memory.initially_zero());
        normal.release().expect("normal owner releases its exact mapping");

        let aligned = NormalOsAllocation::allocate_aligned(
            config,
            page,
            alignment,
            MapAccess::Committed,
        )
        .expect("the source aligned normal allocation succeeds");
        let aligned_base = aligned.base().expect("aligned owner remains live");
        let aligned_size = aligned.full_size().expect("aligned owner has its full extent");
        let aligned_memory = aligned.memory_id().expect("aligned owner retains provenance");
        assert_eq!(aligned_base.addr() % alignment, 0);
        assert_eq!(aligned_size, config.good_alloc_size(page));
        assert_eq!(aligned_memory.os_base().map(|base| base.value()), Some(aligned_base.addr()));
        assert_eq!(aligned_memory.size(), Some(aligned_size));
        aligned
            .release()
            .expect("aligned owner releases its exact mapping");

        let offset = page;
        let offset_allocation = NormalOsAllocation::allocate_aligned_at_offset(
            config,
            page.checked_mul(2).expect("the fixed offset request fits"),
            alignment,
            offset,
            MapAccess::Committed,
        )
        .expect("the source offset-aligned allocation succeeds");
        let offset_base = offset_allocation
            .base()
            .expect("offset owner retains its mapping base");
        let offset_pointer = offset_allocation
            .pointer()
            .expect("offset client pointer remains live");
        let offset_size = offset_allocation
            .full_size()
            .expect("offset owner retains its full extent");
        let offset_memory = offset_allocation
            .memory_id()
            .expect("offset owner retains base provenance");
        assert_eq!((offset_pointer.as_ptr().addr() + offset) % alignment, 0);
        assert!(offset_pointer.as_ptr().addr() > offset_base.addr());
        assert_eq!(
            offset_size,
            config.good_alloc_size(
                page.checked_mul(2)
                    .and_then(|size| size.checked_add(alignment - offset))
                    .expect("the source offset overmap request fits")
            )
        );
        assert_eq!(offset_memory.os_base().map(|base| base.value()), Some(offset_base.addr()));
        assert_eq!(offset_memory.size(), Some(offset_size));
        offset_allocation
            .release()
            .expect("offset owner releases its full mapping rather than its client pointer");

        let numa_count = os_numa_node_count();
        let numa_current = os_numa_node();
        assert!(numa_count >= 1, "the allocator-facing NUMA cache normalizes to one");
        assert!(numa_current < numa_count, "the source current-node route normalizes modulo count");

        macro_rules! emit {
            ($name:literal, $value:expr) => {
                std::println!("{}={}", $name, $value);
            };
        }

        std::println!("CRABC_MI_M2_VM_TRACE_BEGIN");
        emit!("m2.vm.config.page_size", page);
        emit!("m2.vm.config.large_page_size", config.large_page_size());
        emit!("m2.vm.config.alloc_granularity", config.alloc_granularity());
        emit!("m2.vm.config.has_overcommit", u8::from(config.has_overcommit()));
        emit!("m2.vm.config.has_partial_free", u8::from(config.has_partial_free()));
        emit!("m2.vm.config.has_virtual_reserve", u8::from(config.has_virtual_reserve()));
        emit!(
            "m2.vm.config.has_transparent_huge_pages",
            u8::from(config.has_transparent_huge_pages())
        );
        emit!("m2.vm.thp.process_disabled", u8::from(thp_process_disabled));
        emit!("m2.vm.reserved.initially_zero", u8::from(reserved_initially_zero));
        emit!(
            "m2.vm.reserved.initially_committed",
            u8::from(reserved_initially_committed)
        );
        emit!("m2.vm.reserved.commit_not_known_zero", 1);
        emit!("m2.vm.reserved.decommit_no_recommit", 1);
        emit!("m2.vm.reserved.reset_success", 1);
        emit!("m2.vm.reserved.reuse_linux_noop", 1);
        emit!("m2.vm.reserved.protect_success", 1);
        emit!("m2.vm.reserved.unprotect_success", 1);
        emit!("m2.vm.reserved.release_success", 1);
        emit!("m2.vm.normal.client_is_base", 1);
        emit!("m2.vm.normal.good_size", normal_size);
        emit!("m2.vm.normal.memid_base_and_size", 1);
        emit!("m2.vm.normal.initially_committed", 1);
        emit!("m2.vm.normal.initially_zero", 1);
        emit!("m2.vm.normal.release_success", 1);
        emit!("m2.vm.aligned.alignment", alignment);
        emit!("m2.vm.aligned.client_is_aligned", 1);
        emit!("m2.vm.aligned.good_size", aligned_size);
        emit!("m2.vm.aligned.memid_base_and_size", 1);
        emit!("m2.vm.aligned.release_success", 1);
        emit!("m2.vm.offset.client_offset_nonzero", 1);
        emit!("m2.vm.offset.client_plus_offset_is_aligned", 1);
        emit!("m2.vm.offset.good_size", offset_size);
        emit!("m2.vm.offset.memid_base_and_size", 1);
        emit!("m2.vm.offset.release_full_mapping_success", 1);
        emit!("m2.vm.numa.count_at_least_one", u8::from(numa_count >= 1));
        emit!("m2.vm.numa.current_lt_count", u8::from(numa_current < numa_count));
        std::println!("CRABC_MI_M2_VM_TRACE_END");
    }

    #[test]
    fn entropy_failure_is_direct_and_never_uses_a_secondary_source() {
        let fault = fault::install(fault::Plan::at(fault::Point::Entropy, 1, Errno::NOMEM));
        let mut bytes = [0u8; 16];

        assert_eq!(entropy_fill(&mut bytes), Err(Errno::NOMEM));
        assert_eq!(fault.observed(), 1);
    }
}
