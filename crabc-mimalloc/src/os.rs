// Copyright (c) 2018-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `include/mimalloc/prim.h`,
// `src/prim/prim.c`, `src/prim/unix/prim.c` (including the raw
// `_mi_prim_numa_node_count` observation and the bounded
// `_mi_prim_mem_init` THP-disable branch at lines 250-277), and the raw page-alignment and
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
//! timeout, and release ownership have a staged retaining primitive, but no
//! live arena/request dispatch selects it yet; that process path remains
//! unqualified, and this module never represents it as a successful fallback.
//!
//! `StartupInput` is supplied by a future runtime owner. In particular, this
//! module deliberately does not read `/proc/self/environ` or autonomously
//! dereference `AT_RANDOM`: `random::TheapRandomImage` now uses direct
//! `getrandom`, and startup material needs a separate lifetime/freshness
//! contract before a process owner can consume it. Tests may read `AT_PAGESZ`
//! only to construct a real kernel-compatible input for their local mapping
//! fixture.

use core::cell::UnsafeCell;
use core::ffi::CStr;
use core::fmt;
use core::num::NonZeroUsize;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};

use crabc_core::{Errno, Result};

#[cfg(target_arch = "x86_64")]
use crate::diagnostic_output::MbindWarningRoute;
use crate::config::{
    ARENA_SLICE_SIZE, VmOption, VmOptionEnvironmentReader, VmOptionState, VmOptions,
};
#[cfg(test)]
use crate::config::VmOptionEnvironment;
use crate::invariants;
use crate::random::TheapRandomImage;

/// Existing source random state for OS hint draws. This interface generates
/// no independent stream: both implementations use the approved Theap image.
pub(crate) trait OsRandomSource {
    fn next_if_initialized(&mut self) -> Option<u64>;
}

pub(crate) type OsRandom<'a> = Option<&'a mut (dyn OsRandomSource + 'static)>;

impl OsRandomSource for TheapRandomImage {
    fn next_if_initialized(&mut self) -> Option<u64> {
        self.is_initialized().then(|| self.next())
    }
}

/// A thread-confined source default-Theap lookup at each OS draw. It keeps no
/// owner, Theap, random-field reference, copied state, or prefetched word.
pub(crate) struct CurrentDefaultTheapRandom(core::marker::PhantomData<*mut ()>);

impl CurrentDefaultTheapRandom {
    /// # Safety
    /// Through every use, the current compiler-TLS default must remain a live
    /// source Theap (or the immutable empty image). No whole-Theap or random
    /// field reference may overlap a draw. The caller owns the current thread
    /// source operation; teardown/default replacement may occur only between
    /// draws and must preserve compiler-TLS root lifetime rules.
    pub(crate) unsafe fn new() -> Self { Self(core::marker::PhantomData) }
}

impl OsRandomSource for CurrentDefaultTheapRandom {
    fn next_if_initialized(&mut self) -> Option<u64> {
        // `default_theap` is a direct ELF compiler-TLS pointer load: it has
        // no initialization, allocation, lock, or callback path. Lookup ends
        // before the short exclusive random-field projection below.
        let pointer = crate::compiler_tls::default_theap();
        // SAFETY: the constructor's operation/lifetime contract retains this
        // current source image and excludes overlapping random access. The
        // helper invokes only the existing generator, with no user callback.
        unsafe { crate::types::Theap::next_os_reservation_random_at(pointer) }
    }
}
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

/// The two compile-time predicates selected by
/// `src/os.c:_mi_os_get_aligned_hint`.
///
/// The port has one fixed normal-release production profile. This private
/// value keeps that selection adjacent to the translated function while
/// letting source-profile tests name the two unselected C preprocessor
/// branches without turning them into allocator options or a runtime
/// configuration surface.
#[derive(Clone, Copy)]
struct AlignedHintSourceProfile {
    secure: bool,
    debug: bool,
}

impl AlignedHintSourceProfile {
    const FIXED_NORMAL_RELEASE: Self = Self {
        secure: crate::config::SECURE_LEVEL >= 1,
        debug: crate::config::DEBUG_LEVEL != 0,
    };

    #[inline]
    const fn requires_default_random(self) -> bool { self.secure || !self.debug }

    #[inline]
    const fn rejects_request_size(self, request_size: usize) -> bool {
        self.secure && request_size > 32 * GIB
    }

    #[cfg(test)]
    const fn source_test(secure: bool, debug: bool) -> Self { Self { secure, debug } }
}

/// Mirrors `include/mimalloc/internal.h:_mi_align_up`'s unsigned arithmetic.
///
/// The aligned-hint source computes this request before a raw mmap rejects an
/// oversized client length. Keep it distinct from the checked alignment
/// helpers used by Rust-owned ranges: this function produces only an opaque
/// mmap hint and cannot establish an owned address range.
#[inline]
fn source_align_up_wrapping(value: usize, alignment: usize) -> Option<usize> {
    if alignment == 0 {
        return None;
    }
    let mask = alignment - 1;
    let sum = value.wrapping_add(mask);
    if alignment & mask == 0 {
        Some(sum & !mask)
    } else {
        Some((sum / alignment).wrapping_mul(alignment))
    }
}

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

/// An explicit, reader-free VM policy cannot be manufactured from a partial
/// process-start observation.
///
/// The dedicated Unix process path retains its raw-environment reader and can
/// instead mirror `mi_option_get`'s default-value-and-later-retry behavior.
/// This error keeps the ordinary fixture and explicit-owner constructors from
/// silently inventing that ambient source capability.
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

#[cfg(not(test))]
#[inline]
unsafe fn thp_policy_prctl_raw(
    option: i32, argument0: usize, argument1: usize, argument2: usize, argument3: usize,
) -> Result<usize> {
    // SAFETY: the sole production callers below use the two Linux THP
    // constants with their source scalar zero/one tuples.
    unsafe { crabc_core::process::prctl_raw(option, argument0, argument1, argument2, argument3) }
}

#[cfg(test)]
#[inline]
unsafe fn thp_policy_prctl_raw(
    option: i32, argument0: usize, argument1: usize, argument2: usize, argument3: usize,
) -> Result<usize> {
    fault::thp_policy_prctl_raw(option, argument0, argument1, argument2, argument3)
}

/// Process-owned state for the source VM option, hint, large-page retry, and
/// NUMA-count policy.
///
/// An explicit fixture policy receives a completed [`VmOptions`] image. The
/// Unix process initializer may instead retain an incomplete image plus the
/// raw source environment reader that initialized it: each unresolved
/// descriptor returns its pinned current default for that call and retries on
/// a later source option read. The policy itself creates neither an ambient
/// environment reader nor random state; the process initializer retains that
/// capability beside the source `MainSubprocess`. Callers pass the already
/// initialized [`TheapRandomImage`] when a source path requires
/// randomization. The old fixed-default mapping APIs remain intact while that
/// lifecycle wiring is being introduced.
pub(crate) struct VmPolicy {
    /// The fixed descriptor image is immutable after ordinary source startup.
    /// A rare `_mi_getenv` failure leaves individual slots lazy-uninitialized,
    /// in which case the retained process reader mutates only that slot under
    /// `options_access` before returning its source default for the current
    /// query.
    options: UnsafeCell<VmOptions>,
    /// Release-published only after every selected descriptor is terminal.
    /// The normal source startup path reaches this state before any allocator
    /// caller, keeping option reads a lock-free immutable snapshot.
    options_resolved: AtomicBool,
    /// Serializes the exceptional per-descriptor retry path. This is not an
    /// allocator lock: it protects only the small copied option image while a
    /// raw `environ` observation resolves one source descriptor.
    options_access: AtomicBool,
    /// Present only for the actual Unix process source path. Reader-free
    /// fixture construction rejects unresolved slots instead of creating a
    /// hidden ambient environment dependency.
    option_environment: Option<VmOptionEnvironmentReader>,
    // Pinned `src/init.c` initializes this true, has the unique process-start
    // owner clear it, and makes it true again as the final effect of
    // `mi_process_done_once`. The existing runtime process state owns both
    // transitions: this scalar has no startup or finalization authority of
    // its own. VM and arena callers receive a read-only view through their
    // borrowed `VmProcess` pair.
    preloading: AtomicBool,
    aligned_hint_base: AtomicUsize,
    // This schedule exists only in the direct source-policy tests. It pauses
    // the exact `_mi_os_get_aligned_hint` translation after its first AcqRel
    // fetch-add so one real competing AcqRel fetch-add can make the pinned
    // strong CAS fail. No production policy contains a scheduler, hook, or
    // alternate atomic operation.
    #[cfg(test)]
    aligned_hint_test_phase: AtomicUsize,
    huge_hint_start: AtomicUsize,
    // This second test-only schedule pauses only the selected source
    // prim/unix/prim.c:409 suppression CAS after its Acquire load. One helper
    // performs the exact competing AcqRel CAS before the source operation
    // continues, proving its ignored failure without a production hook.
    #[cfg(test)]
    large_page_retry_test_phase: AtomicUsize,
    large_page_try_ok: AtomicUsize,
    huge_one_gib_unavailable: AtomicBool,
    numa_node_count: AtomicUsize,
}

// SAFETY: normal source startup resolves every descriptor before publication,
// after which `options` is read immutably. If an environment primitive leaves
// a descriptor unresolved, `options_access` serializes every mutation and its
// corresponding current-value read; the constructor's raw-reader safety
// contract supplies the external `environ` lifetime/mutation precondition.
unsafe impl Sync for VmPolicy {}

/// One serialized read or retry of [`VmPolicy`]'s copied source descriptor
/// image. Dropping it always reopens the exceptional path, including if a
/// test assertion panics while inspecting an option.
struct VmPolicyOptionAccess<'policy> {
    policy: &'policy VmPolicy,
}

impl<'policy> VmPolicyOptionAccess<'policy> {
    /// Copies an image which became complete while this stale slow-path reader
    /// waited for the retry gate.
    ///
    /// The caller must have observed `options_resolved` with Acquire while it
    /// holds this gate. The final writer ends its exclusive projection before
    /// that Release publication; subsequent fast-path readers have only
    /// shared snapshots, so this raw copied read never creates a competing
    /// mutable borrow.
    #[inline]
    fn resolved_snapshot(&self) -> VmOptions {
        // SAFETY: the documented Acquire/Release transition proves the final
        // mutation completed. The gate excludes an unresolved retry writer,
        // while post-publication readers are shared copied snapshots.
        unsafe { *self.policy.options.get() }
    }

    /// Projects the copied descriptor image only while it remains unresolved.
    ///
    /// Callers must recheck `options_resolved` after acquiring the gate and
    /// before calling this method. A stale reader can otherwise wait while
    /// the final writer publishes completion, then form an exclusive borrow
    /// concurrently with the now-valid shared fast path.
    #[inline]
    fn unresolved_options(&mut self) -> &mut VmOptions {
        // SAFETY: `VmPolicy::acquire_option_access` holds the one atomic
        // mutation gate, and the required post-acquisition resolution check
        // proves no resolved fast-path reader can exist yet.
        unsafe { &mut *self.policy.options.get() }
    }
}

impl Drop for VmPolicyOptionAccess<'_> {
    fn drop(&mut self) {
        self.policy.options_access.store(false, Ordering::Release);
    }
}

/// One borrowed source subprocess and its source VM policy.
///
/// This pair is deliberately non-owning: process initialization retains both
/// address-stable owners, while map/commit/free callers must present the same
/// pair for every accounting edge. It prevents an allocation path from
/// selecting options from one process image and statistics from another.
#[derive(Clone, Copy)]
pub(crate) struct VmProcess<'a> {
    policy: &'a VmPolicy,
    subprocess: &'a crate::subproc::SubprocessIdentity,
}

impl<'a> VmProcess<'a> {
    #[inline]
    pub(crate) const fn new(
        policy: &'a VmPolicy,
        subprocess: &'a crate::subproc::SubprocessIdentity,
    ) -> Self {
        Self { policy, subprocess }
    }

    #[inline]
    pub(crate) const fn policy(self) -> &'a VmPolicy { self.policy }

    #[inline]
    pub(crate) const fn subprocess(self) -> &'a crate::subproc::SubprocessIdentity {
        self.subprocess
    }

    /// Projects the surrounding process-main owner only for source paths
    /// whose contract explicitly owns its static TLD/metadata engine.
    /// Ordinary VM and arena operations use `subprocess()` so a reclaimable
    /// child identity is never widened to the process wrapper.
    #[inline]
    pub(crate) fn main_subprocess(self) -> Option<&'a crate::subproc::MainSubprocess> {
        if !self.subprocess.is_process_main() { return None; }
        // SAFETY: `MainSubprocess::identity` is the first repr(C) field and
        // the compile-time offset assertion in subproc.rs fixes that address
        // relation. The role check excludes child images, which must never
        // be projected as a main owner.
        Some(unsafe {
            &*core::ptr::from_ref(self.subprocess)
                .cast::<crate::subproc::MainSubprocess>()
        })
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

    /// Runs the custom callback arm of the source purge policy.
    ///
    /// This boundary deliberately accepts an already validated arena span. The
    /// callback receives that raw span unchanged: source checks only negative
    /// purge delay before advancing purge statistics and invoking it. Ordinary
    /// mapping normalization, reset/decommit choice, preloading, allow-reset,
    /// and decommit statistic size belong to the mutually exclusive
    /// no-callback branch.
    #[inline]
    pub(crate) fn purge_with_callback(
        self,
        size: usize,
        callback: impl FnOnce() -> Option<bool>,
    ) -> Option<bool> {
        if self.policy.purge_delay_milliseconds() < 0 {
            return Some(false);
        }
        self.subprocess.vm_statistics().purge(size);
        callback()
    }

    /// Commits one source-owned direct page area through `_mi_os_commit`.
    ///
    /// This is deliberately a process operation rather than a [`Mapping`]
    /// method. `mi_page_extend_free` may extend an externally supplied arena
    /// page after its first prefix used `mi_arena_commit`; source then calls
    /// `_mi_os_commit` directly and does not possess a Rust mapping owner.
    /// As in `_mi_os_commit_ex`, the commit-call counter precedes liberal
    /// floor/ceil page coverage, while committed bytes use the requested span
    /// and increase only after the raw protection transition succeeds.
    ///
    /// # Safety
    ///
    /// `address..address + length` is one live, exclusively owned page-area
    /// transition. Its whole covering base-page range must remain within one
    /// live reservation until this call returns; no Rust reference or alias
    /// that can observe the transition may exist. That reservation may be an
    /// externally supplied, page-aligned owned span which this process did
    /// not create or account as an OS [`Mapping`]. This operation creates no
    /// release token and grants no unmap authority.
    pub(crate) unsafe fn commit_direct_page_area(
        self,
        page_size: PageSize,
        address: *mut u8,
        length: usize,
    ) -> Result<Option<CommitOutcome>> {
        // `_mi_os_commit_ex` increments the named counter before it asks
        // `mi_os_page_align_areax` whether the source span has any pages.
        let statistics = self.subprocess.vm_statistics();
        statistics.commit_call();
        let Some((address, normalized_length)) =
            covering_direct_page_area_range(page_size, address, length)?
        else {
            return Ok(None);
        };
        fault_before(FaultPoint::Commit)?;
        // SAFETY: the caller's unsafe contract proves that this source-style
        // covering range stays in its live reservation and is uniquely
        // transitioning from reserved to accessible bytes.
        unsafe {
            crabc_core::mm::mprotect_raw(address, normalized_length, PROT_READ | PROT_WRITE)
        }?;
        statistics.committed_increase(length);
        Ok(Some(CommitOutcome::NotKnownZero))
    }
}

/// Borrowed VM view for one registered child subprocess.
///
/// The policy comes from the owning process, while accounting, arena
/// ownership, and source sequence selection use the pinned child identity.
/// This is deliberately distinct from `VmProcess<'static>` process-main
/// bindings: the child image remains reclaimable and may only be used while
/// this pin-derived borrow is live.
#[derive(Clone, Copy)]
pub(crate) struct ChildVmProcess<'child> {
    process: VmProcess<'child>,
    child: core::pin::Pin<&'child crate::subproc::ChildSubprocessImage>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ChildVmProcessError {
    NotRegisteredChild,
}

impl<'child> ChildVmProcess<'child> {
    /// Binds the exact process policy to a registered, address-stable child.
    pub(crate) fn new(
        policy: &'child VmPolicy,
        child: core::pin::Pin<&'child crate::subproc::ChildSubprocessImage>,
        parent: &crate::subproc::SubprocessIdentity,
    ) -> core::result::Result<Self, ChildVmProcessError> {
        let image: &'child crate::subproc::ChildSubprocessImage = core::pin::Pin::get_ref(child);
        let identity: &'child crate::subproc::SubprocessIdentity = image.identity();
        if !identity.is_registered_child_of(parent) {
            return Err(ChildVmProcessError::NotRegisteredChild);
        }
        Ok(Self {
            process: VmProcess::new(policy, identity),
            child,
        })
    }

    #[inline]
    pub(crate) const fn process(self) -> VmProcess<'child> { self.process }

    #[inline]
    pub(crate) fn child(self) -> core::pin::Pin<&'child crate::subproc::ChildSubprocessImage> {
        self.child
    }

    #[inline]
    pub(crate) fn identity(self) -> &'child crate::subproc::SubprocessIdentity {
        let image: &'child crate::subproc::ChildSubprocessImage = core::pin::Pin::get_ref(self.child);
        image.identity()
    }
}

impl VmPolicy {
    /// Admits only source options whose lazy environment phase has completed.
    ///
    /// This reader-free constructor remains the only route for fixtures and
    /// explicit callers. Use [`Self::new_with_source_environment`] only from
    /// the process owner that has the pinned raw Unix environment capability.
    pub(crate) fn new(options: VmOptions) -> core::result::Result<Self, VmPolicyConfigurationError> {
        for option in VmOption::ALL {
            if options.state(option) == VmOptionState::Uninitialized {
                return Err(VmPolicyConfigurationError::UnresolvedOption(option));
            }
        }
        Ok(Self::from_options(options, None))
    }

    /// Retains the source environment reader needed to retry lazy descriptors
    /// after process initialization.
    ///
    /// Pinned `_mi_options_init` can leave one or more descriptors in
    /// `MI_OPTION_UNINIT` when `_mi_getenv` is temporarily unavailable. A
    /// later `mi_option_get` retries just that descriptor and returns its
    /// current default even if the retry still cannot observe `environ`.
    /// Keeping that behavior in the real process policy avoids turning an
    /// unavailable canonical value into a terminal shadow-runtime failure.
    ///
    /// # Safety
    ///
    /// `environment_reader` must uphold [`VmOptionEnvironmentReader`]'s
    /// validity and direct-environment mutation obligations for every later
    /// policy option read. The caller must retain this policy for the same
    /// process lifetime that owns the reader.
    pub(crate) unsafe fn new_with_source_environment(
        options: VmOptions,
        environment_reader: VmOptionEnvironmentReader,
    ) -> core::result::Result<Self, VmPolicyConfigurationError> {
        Ok(Self::from_options(options, Some(environment_reader)))
    }

    #[inline]
    fn from_options(
        options: VmOptions,
        option_environment: Option<VmOptionEnvironmentReader>,
    ) -> Self {
        let options_resolved = options.all_resolved();
        Self {
            options: UnsafeCell::new(options),
            options_resolved: AtomicBool::new(options_resolved),
            options_access: AtomicBool::new(false),
            option_environment,
            preloading: AtomicBool::new(true),
            aligned_hint_base: AtomicUsize::new(0),
            #[cfg(test)]
            aligned_hint_test_phase: AtomicUsize::new(0),
            huge_hint_start: AtomicUsize::new(0),
            #[cfg(test)]
            large_page_retry_test_phase: AtomicUsize::new(0),
            large_page_try_ok: AtomicUsize::new(0),
            huge_one_gib_unavailable: AtomicBool::new(false),
            numa_node_count: AtomicUsize::new(0),
        }
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

    /// Arms one test-only competing source-cursor increment.
    ///
    /// The caller must arrange for exactly one helper thread to call
    /// [`Self::test_complete_aligned_hint_competitor`] while the source caller
    /// is in [`Self::aligned_hint`]. The schedule has no production analogue:
    /// it only makes the source's ignored strong-CAS failure reproducible.
    #[cfg(test)]
    fn test_arm_aligned_hint_competitor(&self) {
        assert_eq!(
            self.aligned_hint_test_phase.swap(1, Ordering::AcqRel),
            0,
            "the aligned-hint test schedule is single-use"
        );
    }

    /// Performs the one actual competing AcqRel source-cursor increment.
    ///
    /// The helper may call this only after [`Self::test_arm_aligned_hint_competitor`]
    /// and while the source caller is paused after its first fetch-add. It
    /// returns the actual old cursor so the receiver can prove the CAS saw a
    /// competing advance instead of a fabricated expected value.
    #[cfg(test)]
    fn test_complete_aligned_hint_competitor(&self, request_size: usize) -> usize {
        while self.aligned_hint_test_phase.load(Ordering::Acquire) != 2 {
            core::hint::spin_loop();
        }
        let observed = self
            .aligned_hint_base
            .fetch_add(request_size, Ordering::AcqRel);
        self.aligned_hint_test_phase.store(3, Ordering::Release);
        observed
    }

    #[cfg(test)]
    #[inline]
    fn test_aligned_hint_cursor(&self) -> usize {
        self.aligned_hint_base.load(Ordering::Acquire)
    }

    /// Arms one test-only competitor for the exact retry-suppression CAS in
    /// pinned source prim/unix/prim.c:409.
    ///
    /// The caller must arrange one helper invocation while the normal policy
    /// call has observed a nonzero retry count. The source CAS itself still
    /// executes unchanged and continues to discard its result.
    #[cfg(test)]
    fn test_arm_large_page_retry_competitor(&self) {
        assert_eq!(
            self.large_page_retry_test_phase.swap(1, Ordering::AcqRel),
            0,
            "the large-page retry test schedule is single-use"
        );
    }

    /// Performs the one real competing AcqRel decrement between the source
    /// retry counter load and its strong CAS. It returns whether that exact
    /// competitor won; the caller separately checks that the source CAS then
    /// failed and its regular mapping owner remained valid.
    #[cfg(test)]
    fn test_complete_large_page_retry_competitor(&self, expected: usize) -> bool {
        tests::wait_for_large_page_retry_phase(self, 2, "source retry-count load");
        let swapped = self
            .large_page_try_ok
            .compare_exchange(
                expected,
                expected - 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok();
        self.large_page_retry_test_phase.store(3, Ordering::Release);
        swapped
    }

    #[cfg(test)]
    #[inline]
    fn test_large_page_retry_source_cas_failed(&self) -> bool {
        self.large_page_retry_test_phase.load(Ordering::Acquire) == 4
    }

    #[cfg(test)]
    #[inline]
    fn test_aligned_hint_request_size(
        config: MemoryConfig,
        try_alignment: usize,
        size: usize,
    ) -> Option<usize> {
        let request_size = size
            .checked_add(config.page_size().bytes())?
            .checked_add(try_alignment.checked_sub(1)?)?;
        invariants::align_up(request_size, config.large_page_size())
    }

    /// Returns a copied descriptor image for source-policy diagnostics.
    ///
    /// A partially initialized process image is observed under its retry gate;
    /// once every descriptor is terminal this is an immutable lock-free copy.
    #[inline]
    pub(crate) fn options(&self) -> VmOptions {
        if self.options_resolved.load(Ordering::Acquire) {
            return self.resolved_options_snapshot();
        }
        self.options_after_unresolved_observation()
    }

    /// Completes a diagnostic snapshot after the caller initially observed an
    /// unresolved image.
    ///
    /// A slow reader can wait behind the final retry writer. Recheck the
    /// one-way completion flag after taking the gate, before making any
    /// exclusive `UnsafeCell` projection, so that stale observation is only a
    /// shared snapshot once the writer has published completion.
    #[inline]
    fn options_after_unresolved_observation(&self) -> VmOptions {
        let mut access = self.acquire_option_access();
        if self.options_resolved.load(Ordering::Acquire) {
            return access.resolved_snapshot();
        }
        *access.unresolved_options()
    }

    /// Ends the source process-start preloading interval.
    ///
    /// This is intentionally crate-private and is called only by the
    /// process-start owner after it completed the C-runtime-unsafe phase.
    /// The selected runtime's once-only process state prevents this startup
    /// owner from running after its logical process-done transition. Pinned
    /// `mi_process_done_once` has a distinct terminal `false -> true` effect,
    /// modeled by [`Self::enter_process_done_preloading`].
    #[inline]
    pub(crate) fn finish_preloading(&self) {
        self.preloading.store(false, Ordering::Release);
    }

    /// Restores the source terminal preloading value after logical process
    /// done, so late source purge avoids C-runtime-unsafe decommit.
    ///
    /// Pinned `src/init.c:595-648` performs this as the final
    /// `mi_process_done_once` effect. The caller must already hold the
    /// selected runtime's `PROCESS_DONE_OPEN -> PROCESS_DONE_TRANSITION`
    /// claim; this policy scalar deliberately cannot reopen or initialize a
    /// process by itself.
    #[inline]
    pub(crate) fn enter_process_done_preloading(&self) {
        self.preloading.store(true, Ordering::Release);
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
        let options = self.options.get_mut();
        options.set(option, value);
        if options.all_resolved() {
            self.options_resolved.store(true, Ordering::Release);
        }
    }

    #[inline]
    fn option_enabled(&self, option: VmOption) -> bool {
        self.option_value(option) != 0
    }

    #[inline]
    fn option_value(&self, option: VmOption) -> i64 {
        if self.options_resolved.load(Ordering::Acquire) {
            return self.resolved_options_snapshot().current_value(option);
        }
        self.option_value_after_unresolved_observation(option)
    }

    /// Completes a source option read after its initial incomplete-image
    /// observation. See [`Self::options_after_unresolved_observation`] for
    /// why the gate must recheck completion before it projects mutably.
    #[inline]
    fn option_value_after_unresolved_observation(&self, option: VmOption) -> i64 {
        let mut access = self.acquire_option_access();
        if self.options_resolved.load(Ordering::Acquire) {
            return access.resolved_snapshot().current_value(option);
        }
        let (value, resolved) = {
            let options = access.unresolved_options();
            if options.state(option) == VmOptionState::Uninitialized {
                if let Some(environment_reader) = self.option_environment {
                    // SAFETY: `new_with_source_environment` retains the source
                    // reader's raw-vector lifetime and mutation contract for the
                    // whole policy lifetime. The retry gate serializes this exact
                    // descriptor observation with every other policy query.
                    unsafe {
                        options.initialize_one_from_source_environment(option, environment_reader());
                    }
                }
            }
            (options.current_value(option), options.all_resolved())
        };
        // The exclusive projection ends with the inner scope before this
        // Release publication makes lock-free shared snapshots permissible.
        if resolved {
            self.options_resolved.store(true, Ordering::Release);
        }
        value
    }

    /// Copies a terminal source descriptor image for the lock-free fast path.
    #[inline]
    fn resolved_options_snapshot(&self) -> VmOptions {
        // SAFETY: every final mutation ends before the Release publication of
        // `options_resolved`; this method is reached only through an Acquire
        // observation of that one-way state. No shared-policy method mutates
        // a completed image.
        unsafe { *self.options.get() }
    }

    fn acquire_option_access(&self) -> VmPolicyOptionAccess<'_> {
        while self
            .options_access
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        VmPolicyOptionAccess { policy: self }
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
        match unsafe { thp_policy_prctl_raw(PR_GET_THP_DISABLE, 0, 0, 0, 0) } {
            Ok(0) => match unsafe { thp_policy_prctl_raw(PR_SET_THP_DISABLE, 1, 0, 0, 0) } {
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
        default_random: OsRandom<'_>,
    ) -> Option<usize> {
        self.aligned_hint_for_source_profile(
            config,
            try_alignment,
            size,
            default_random,
            AlignedHintSourceProfile::FIXED_NORMAL_RELEASE,
        )
    }

    /// Translates the selected source body after its compile-time predicates
    /// have been fixed. The sole production caller supplies
    /// [`AlignedHintSourceProfile::FIXED_NORMAL_RELEASE`]; test-only source
    /// profile records use the same body to compare the debug and secure C
    /// preprocessor branches without creating a mutable runtime setting.
    fn aligned_hint_for_source_profile(
        &self,
        config: MemoryConfig,
        try_alignment: usize,
        size: usize,
        mut default_random: OsRandom<'_>,
        source_profile: AlignedHintSourceProfile,
    ) -> Option<usize> {
        if try_alignment <= config.alloc_granularity()
            || try_alignment > 16 * GIB
            || config.virtual_address_bits() < 46
        {
            return None;
        }
        // `src/os.c:134-136` uses unsigned `size_t` addition and
        // `_mi_align_up`, both of which wrap. This helper runs before the raw
        // mmap attempt, so preserving that cursor/random side effect matters
        // even when Linux later rejects the supplied mapping length.
        let request_size = source_align_up_wrapping(
            size.wrapping_add(config.page_size().bytes())
                .wrapping_add(try_alignment.wrapping_sub(1)),
            config.large_page_size(),
        )?;
        if source_profile.rejects_request_size(request_size) {
            return None;
        }
        let mut hint = self.aligned_hint_base.fetch_add(request_size, Ordering::AcqRel);
        if hint == 0 || hint > HINT_MAX {
            let initial = if source_profile.requires_default_random() {
                let random = default_random.as_deref_mut()?;
                let random_bits = (random.next_if_initialized()? >> 17) & 0x3f_ffff;
                HINT_BASE.wrapping_add(MIB.wrapping_mul(random_bits as usize) % HINT_AREA)
            } else {
                HINT_BASE
            };
            let expected = hint.wrapping_add(request_size);
            #[cfg(test)]
            if self.aligned_hint_test_phase.load(Ordering::Acquire) == 1 {
                // The source first fetch-add already completed. Publish that
                // exact point, then wait for the test helper's real AcqRel
                // fetch-add before executing the unchanged strong CAS.
                self.aligned_hint_test_phase.store(2, Ordering::Release);
                while self.aligned_hint_test_phase.load(Ordering::Acquire) != 3 {
                    core::hint::spin_loop();
                }
            }
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
        // The source's final relation is `mi_assert_internal` only. In the
        // fixed release profile it returns the wrapped aligned pointer, whose
        // null representation remains the caller's no-hint result.
        let aligned = source_align_up_wrapping(hint, try_alignment)?;
        (aligned != 0).then_some(aligned)
    }

    /// Claims the source high-address range used for one-or-more 1-GiB huge
    /// page attempts. Claiming advances the process cursor even when a later
    /// kernel map fails, exactly as `mi_os_claim_huge_pages` does.
    fn claim_huge_pages(
        &self,
        pages: usize,
        mut default_random: OsRandom<'_>,
    ) -> Option<(usize, usize)> {
        let size = pages.checked_mul(HUGE_PAGE_SIZE)?;
        let mut observed = self.huge_hint_start.load(Ordering::Relaxed);
        loop {
            let mut start = observed;
            if start == 0 {
                start = HUGE_HINT_BASE;
                if let Some(random) = default_random.as_deref_mut() {
                    if let Some(word) = random.next_if_initialized() {
                        let random_bits = (word >> 17) & 0x0fff;
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
    pub(crate) fn reserve_huge_os_pages(&self) -> i64 { self.option_value(VmOption::ReserveHugeOsPages) }

    #[inline]
    pub(crate) fn reserve_huge_os_pages_at(&self) -> i64 {
        self.option_value(VmOption::ReserveHugeOsPagesAt)
    }

    /// Source startup reads the signed KiB option, then performs its unsigned
    /// byte multiplication. Keep that distinct from option_get_size callers.
    pub(crate) fn reserve_os_memory_kib(&self) -> i64 {
        self.option_value(VmOption::ReserveOsMemory)
    }

    /// Returns the signed source `destroy_on_exit` descriptor unchanged.
    ///
    /// Pinned `src/init.c` distinguishes zero, nonzero explicit destruction,
    /// and values at least two for automatic-finalization suppression. The
    /// process finalization owner therefore receives this raw value; this VM
    /// policy does not select, run, or register any finalization path.
    #[inline]
    pub(crate) fn destroy_on_exit_raw(&self) -> i64 {
        self.option_value(VmOption::DestroyOnExit)
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

    /// Copies this policy's NUMA-count cache without resolving topology.
    ///
    /// This test-only observation distinguishes a source arena initialization
    /// that reached `src/arena.c:1735-1740` from a failed map or metadata
    /// commit that must leave the retained policy untouched. It does not read
    /// the raw Linux topology primitives or mutate the policy.
    #[cfg(test)]
    #[inline]
    pub(crate) fn test_numa_node_count_cache(&self) -> usize {
        self.numa_node_count.load(Ordering::Acquire)
    }

    /// Copies the policy-local NUMA-count cache without resolving it.
    ///
    /// This default-off native runtime audit distinguishes a count resolved by
    /// the actual ticket-zero TLD initialization from a later diagnostic
    /// observation. It neither queries the raw topology primitives nor changes
    /// the selected source policy.
    #[cfg(feature = "native-runtime-test-audit")]
    #[inline]
    pub(crate) fn native_runtime_test_numa_node_count_cache(&self) -> usize {
        self.numa_node_count.load(Ordering::Acquire)
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

/// The two source meanings of an mmap address argument.
///
/// `_mi_prim_alloc` can receive a caller-owned address for the explicit
/// huge-page claim, while `unix_mmap_prim_aligned` independently derives a
/// high aligned hint for ordinary mappings. Unix retries only the latter with
/// a null address after `mmap` fails; replacing a caller's explicit huge-page
/// claim with a null map would lose its claimed-range ownership.
///
/// A [`MmapHint::SourceAligned`] value belongs to one
/// `unix_mmap_prim_aligned` invocation. Pinned `src/prim/unix/prim.c` invokes
/// that helper once for the large-page attempt and again for the ordinary
/// fallback after both large maps fail. Each helper call reaches
/// `_mi_os_get_aligned_hint`, which advances `aligned_base`; reusing the
/// failed large-map hint for the ordinary map would erase that source cursor
/// transition.
#[derive(Clone, Copy)]
enum MmapHint {
    Explicit(usize),
    SourceAligned(usize),
}

impl MmapHint {
    #[inline]
    const fn address(self) -> usize {
        match self {
            Self::Explicit(address) | Self::SourceAligned(address) => address,
        }
    }

    #[inline]
    const fn retries_without_hint(self) -> bool {
        matches!(self, Self::SourceAligned(_))
    }
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
        default_random: OsRandom<'_>,
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
        default_random: OsRandom<'_>,
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
        mut default_random: OsRandom<'_>,
    ) -> core::result::Result<Self, AlignedMappingFailure> {
        let page_size = config.page_size().bytes();
        if alignment < page_size || !alignment.is_power_of_two() {
            return Err(AlignedMappingFailure::without_mapping(Errno::INVAL));
        }
        // Native maps naturally exercise either one of the source's direct
        // or overmap paths, depending on the kernel-selected address. Keep a
        // private deterministic test switch so a process-bound reservation
        // can prove the retained-owner path after a failed direct cleanup.
        // It only changes the test fixture's chosen address geometry; the
        // production process path still follows the source kernel result.
        #[cfg(test)]
        let force_full_trim_for_test = config.force_full_aligned_map_trim;
        #[cfg(not(test))]
        let force_full_trim_for_test = false;

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
                if !force_full_trim_for_test && base.addr() % alignment == 0 {
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

        let alignment_headroom = if force_full_trim_for_test {
            match alignment.checked_mul(2) {
                Some(headroom) => headroom,
                None => return Err(AlignedMappingFailure::without_mapping(Errno::NOMEM)),
            }
        } else {
            alignment
        };
        let over_length = match length.checked_add(alignment_headroom) {
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
        fault_before(FaultPoint::HugeMap)?;
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
        default_random: OsRandom<'_>,
    ) -> Result<Self> {
        fault_before(FaultPoint::Map)?;
        let mut flags = MAP_PRIVATE | MAP_ANONYMOUS;
        if config.has_overcommit() {
            flags |= MAP_NORESERVE;
        }
        let protection = access.protection();
        let mut default_random = default_random;
        // This is a source `unix_mmap_prim_aligned` call boundary, rather
        // than a reusable allocation-wide hint. In particular, the ordinary
        // fallback below calls it again after a failed large-page attempt.
        let mut source_hint = || match explicit_hint {
            Some(hint) => Some(MmapHint::Explicit(hint)),
            None => policy
                .aligned_hint(
                    config,
                    try_alignment,
                    length,
                    default_random.as_deref_mut(),
                )
                .map(MmapHint::SourceAligned),
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
                match Self::mmap_with_hint(source_hint(), length, protection, large_flags) {
                    Ok(address) => return Ok(Self::policy_mapping(address, length, config, access, true)),
                    Err(first_error) if one_gib => {
                        policy.huge_one_gib_unavailable.store(true, Ordering::Relaxed);
                        let fallback_flags = (large_flags & !MAP_HUGE_1GB) | MAP_HUGE_2MB;
                        match Self::mmap_with_hint(
                            source_hint(),
                            length,
                            protection,
                            fallback_flags,
                        ) {
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
                #[cfg(test)]
                if policy.large_page_retry_test_phase.load(Ordering::Acquire) == 1 {
                    // The source already completed its Acquire load. Pause
                    // only this test witness until one helper has made the
                    // competing exact AcqRel decrement, then run the same
                    // source CAS and continue regardless of its result.
                    policy.large_page_retry_test_phase.store(2, Ordering::Release);
                    tests::wait_for_large_page_retry_phase(
                        policy,
                        3,
                        "competing retry-count decrement",
                    );
                }
                let source_cas = policy.large_page_try_ok.compare_exchange(
                    retry_remaining,
                    retry_remaining - 1,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                );
                #[cfg(test)]
                if policy.large_page_retry_test_phase.load(Ordering::Acquire) == 3 {
                    policy.large_page_retry_test_phase.store(
                        if source_cas.is_ok() { 5 } else { 4 },
                        Ordering::Release,
                    );
                }
                let _ = source_cas;
            }
        }
        let address = Self::mmap_with_hint(source_hint(), length, protection, flags)?;
        if allow_large && policy.allow_thp() && config.can_use_large_page(length, try_alignment) {
            // The source ignores this advisory's errno and does not call the
            // resulting regular map a large-page mapping.
            // SAFETY: this function owns the just-created mapping until it
            // returns the explicit `Mapping` owner below.
            let _ = match fault_before(FaultPoint::Madvise) {
                Ok(()) => {
                    // SAFETY: this function owns the just-created mapping
                    // until it returns the explicit Mapping owner below.
                    unsafe { crabc_core::mm::madvise_raw(address, length, MADV_HUGEPAGE) }
                }
                Err(error) => Err(error),
            };
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
        hint: Option<MmapHint>,
        length: usize,
        protection: u32,
        flags: u32,
    ) -> Result<*mut u8> {
        let map_once = |address: Option<usize>| {
            #[cfg(any(test, feature = "native-runtime-test-fault"))]
            fault::record_policy_mmap(address, length, protection, flags);
            if flags & MAP_HUGETLB != 0 {
                fault_before(FaultPoint::LargeMap)?;
            }
            // SAFETY: `length` is validated by the caller and the optional
            // address is only an mmap hint. Linux validates raw flags and
            // creates no Rust reference from the returned mapping address.
            unsafe {
                crabc_core::mm::mmap_raw(
                    address.map_or(core::ptr::null_mut(), |value| value as *mut u8),
                    length,
                    protection,
                    flags,
                    -1,
                    0,
                )
            }
        };
        match map_once(hint.map(MmapHint::address)) {
            Ok(address) => Ok(address),
            Err(_) if hint.is_some_and(MmapHint::retries_without_hint) => map_once(None),
            Err(error) => Err(error),
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
        #[cfg(test)]
        fault::record_advice_range(range.address, range.length, MADV_DONTNEED);
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
            // SAFETY: `range` is a complete-page subrange of this live mapping.
            // The advisory may discard contents but does not yield references
            // or alter this boundary's ownership state.
            #[cfg(test)]
            fault::record_advice_range(range.address, range.length, advice);
            // Keep this test-only record at the imported-primitive boundary:
            // a C link wrapper observes an injected failure attempt before
            // the syscall returns. The production fault seam remains empty.
            fault_before(FaultPoint::Purge)?;
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
            // SAFETY: `range` is a complete-page subrange of this live
            // mapping. The advisory does not create aliases or change the
            // mapping's release owner.
            #[cfg(test)]
            fault::record_advice_range(range.address, range.length, advice);
            // Keep the test-only observation at the same import boundary as
            // the C oracle's `madvise` wrapper, including injected errors.
            fault_before(FaultPoint::Purge)?;
            unsafe { crabc_core::mm::madvise_raw(range.address, range.length, advice) }
        })
        .map(|()| true)
    }

    /// Runs the no-callback `_mi_os_purge_ex` branch for one paired process
    /// owner. The callback form remains unavailable until its arena caller can
    /// supply a source-owned typed commit capability; silently treating it as
    /// reset/decommit would erase its failure ownership.
    ///
    /// Pinned `src/os.c:663-679` intentionally consumes an advisory failure
    /// here. The normal Unix `_mi_prim_decommit` stores `needs_recommit =
    /// false` after its `madvise` result, including an error; only a
    /// conservative empty range retains `_mi_os_purge_ex`'s initial true.
    /// A failed reset also reports false. Those result values drive the arena
    /// commitment bitmap; the retained [`Mapping`] remains the only retry
    /// owner in every case. Do not surface the primitive error through this
    /// source-shaped policy result.
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
        if process.policy.purge_decommits() && !process.is_preloading() {
            // Preserve the typed mapping boundary before consuming the raw
            // primitive error below. The second source-shaped range query
            // cannot now hide an inactive or out-of-bounds owner violation.
            if self
                .page_range(offset, length, PageAlignment::Contained)?
                .is_none()
            {
                return Ok(true);
            }
            return match self.decommit_for_process(process, offset, length, stat_size) {
                // `src/prim/unix/prim.c:544-548` assigns false after the
                // `MADV_DONTNEED` call even when that call returned an error.
                // `_mi_os_purge_ex` returns that source output while retaining
                // this mapping for the caller's later retry or release.
                Ok(Some(DecommitOutcome::DoesNotNeedRecommit)) | Err(_) => Ok(false),
                // The preflight above normally makes this unreachable, but
                // keep the source's initialized local result if the mapping
                // can produce a conservative empty range again.
                Ok(None) => Ok(true),
            };
        }
        if allow_reset {
            // The source has no typed owner boundary. Validate this exact
            // Rust mapping range before consuming only the reset advisory
            // error, while retaining its empty-range no-recommit result.
            if self
                .page_range(offset, length, PageAlignment::Contained)?
                .is_none()
            {
                return Ok(false);
            }
            // `_mi_os_purge_ex` ignores `_mi_os_reset`'s advisory error and
            // returns its fixed no-recommit outcome. The mapping remains live
            // for the caller's later policy-selected transition or release.
            let _ = self.reset_for_process(process, offset, length);
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
        #[cfg(any(test, feature = "native-runtime-test-fault"))]
        fault::record_unmap_range(self.address, self.length);
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
    /// Builds a real mapped, source-accounted cleanup failure for the upper
    /// owner tests. The caller arms the exact Unmap failure before entering.
    #[cfg(test)]
    pub(crate) fn test_rejected_cleanup_for_process(process: VmProcess<'_>, config: MemoryConfig) -> Self {
        let mut mapping = Mapping::map_for_process(process, config, HUGE_PAGE_SIZE, 1,
            MapAccess::Committed, false, None).unwrap();
        let error = mapping.unmap_for_process(process, HUGE_PAGE_SIZE, true)
            .expect_err("test source adjustment-free must fail");
        Self { error, mapping }
    }

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
pub(crate) struct HugeOsReleaseTrackingFailure<'a, Tracker> {
    allocation: HugeOsAllocation<'a>,
    tracker: Tracker,
    required_words: usize,
}

impl<'a, Tracker> HugeOsReleaseTrackingFailure<'a, Tracker> {
    #[inline]
    pub(crate) const fn required_words(&self) -> usize { self.required_words }

    #[inline]
    pub(crate) fn into_parts(self) -> (HugeOsAllocation<'a>, Tracker) { (self.allocation, self.tracker) }
}

/// The exact failed primitive-page set after a full source huge-page free
/// pass. Every page was attempted and received its normal source statistics
/// transition; only set bits still name live mappings and may be retried.
#[must_use = "failed huge-page releases retain raw-only retry state"]
pub(crate) struct HugeOsRawReleaseRetry<'a, Tracker> {
    process: VmProcess<'a>,
    base: NonNull<u8>,
    page_count: usize,
    memory: MemoryId,
    source_error: Errno,
    failed_pages: Tracker,
    failed_words: usize,
}

/// Error from a raw-only retry of a previously source-accounted huge page.
#[must_use = "a raw retry failure retains its exact failed-page set"]
pub(crate) struct HugeOsRawReleaseFailure<'a, Tracker> {
    error: Errno,
    retry: HugeOsRawReleaseRetry<'a, Tracker>,
}

impl<'a, Tracker> HugeOsRawReleaseFailure<'a, Tracker> {
    #[inline]
    pub(crate) const fn error(&self) -> Errno { self.error }

    #[inline]
    pub(crate) fn into_retry(self) -> HugeOsRawReleaseRetry<'a, Tracker> { self.retry }
}

impl<'a, Tracker: AsRef<[usize]> + AsMut<[usize]>> HugeOsRawReleaseRetry<'a, Tracker> {
    /// Returns the original aggregate huge-memory provenance. Individual
    /// failed pages remain the only live ranges represented by this retry
    /// token, but their source owner and original memory kind stay explicit.
    #[inline]
    pub(crate) const fn memory_id(&self) -> MemoryId { self.memory }

    pub(crate) const fn source_error(&self) -> Errno { self.source_error }

    /// Retries all and only the failed primitive unmaps. It keeps walking the
    /// complete failed set after an error just as the source free loop keeps
    /// walking later pages. No source statistic is repeated: the original
    /// process-accounted pass already performed it for every marked bit.
    pub(crate) fn retry_raw(mut self) -> core::result::Result<Tracker, HugeOsRawReleaseFailure<'a, Tracker>> {
        let mut first_error = None;
        for page in 0..self.page_count {
            if !huge_release_bit_is_set(self.failed_pages.as_ref(), page) {
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
                Ok(()) => huge_release_bit_clear(self.failed_pages.as_mut(), page),
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }
        match first_error {
            Some(error) => Err(HugeOsRawReleaseFailure { error, retry: self }),
            None => Ok(self.failed_pages),
        }
    }

    #[cfg(test)]
    pub(crate) fn failed_page(&self, page: usize) -> bool {
        page < self.page_count && huge_release_bit_is_set(self.failed_pages.as_ref(), page)
    }
}

impl<'a, Tracker> fmt::Debug for HugeOsRawReleaseRetry<'a, Tracker> {
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
    pub(crate) const fn process(&self) -> VmProcess<'a> { self.process }

    /// Test storage for registry ownership only; anonymous pages stand in for
    /// successful huge primitives. This never proves kernel huge-page support.
    #[cfg(test)]
    pub(crate) fn test_registry_allocation(process: VmProcess<'a>, config: MemoryConfig,
        pages: usize) -> Self {
        let size = pages.checked_mul(HUGE_PAGE_SIZE).unwrap();
        let mut mapping = Mapping::map_aligned_for_allocator(config, size,
            HUGE_PAGE_SIZE, MapAccess::Committed).unwrap();
        let base = NonNull::new(mapping.base().unwrap()).unwrap();
        mapping.is_mapped = false;
        Self { process, base, page_count: pages,
            memory: MemoryId::os_huge(base.as_ptr(), size, true, true),
            stop: HugeOsAllocationStop::Complete }
    }

    /// Allocates the source `_mi_os_alloc_huge_os_pages` primitive through
    /// one resolved process pair. It never falls back to a regular mapping.
    pub(crate) fn allocate_for_process(
        process: VmProcess<'a>,
        config: MemoryConfig,
        pages: usize,
        numa_node: i32,
        max_milliseconds: i64,
        default_random: OsRandom<'_>,
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

    #[cfg(target_arch = "x86_64")]
    /// The selected source-startup huge primitive with its already-retained
    /// diagnostic route. This never changes mapping ownership or falls back to
    /// a regular primitive: it differs only at the failed valid-node `mbind`
    /// call site.
    pub(crate) fn allocate_for_process_with_mbind_warning(
        process: VmProcess<'a>,
        config: MemoryConfig,
        pages: usize,
        numa_node: i32,
        max_milliseconds: i64,
        default_random: OsRandom<'_>,
        warning: MbindWarningRoute<'_>,
    ) -> HugeOsAllocationOutcome<'a> {
        allocate_huge_pages_with(
            process,
            pages,
            max_milliseconds,
            default_random,
            |hint| map_huge_page_for_process_with_mbind_warning(
                process, config, hint, numa_node, warning,
            ),
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
    ) -> core::result::Result<(), HugeOsReleaseFailure<'a, &'bits mut [usize]>> {
        // SAFETY: this exclusive borrowed slice is stable for the retry token's lifetime.
        unsafe { self.release_with_tracker(failed_pages) }.map(|_| ())
    }

    /// Runs the source free pass while moving the failed-page storage into
    /// any retry owner. Success returns storage only after all pages are gone.
    ///
    /// # Safety
    /// The tracker's AsRef/AsMut projections must name the same exclusive,
    /// initialized buffer at every call, including after moving the tracker.
    /// Its size and contents may not change except through the returned
    /// mutable projection until this method or retry_raw returns the tracker.
    pub(crate) unsafe fn release_with_tracker<Tracker: AsRef<[usize]> + AsMut<[usize]>>(
        self, mut tracker: Tracker,
    ) -> core::result::Result<Tracker, HugeOsReleaseFailure<'a, Tracker>> {
        let required_words = self.release_tracking_words();
        if tracker.as_ref().len() < required_words {
            return Err(HugeOsReleaseFailure::Tracking(
                HugeOsReleaseTrackingFailure {
                    allocation: self,
                    tracker,
                    required_words,
                },
            ));
        }
        for word in &mut tracker.as_mut()[..required_words] {
            *word = 0;
        }
        let first_error = release_huge_pages_with(
            self.base,
            self.page_count,
            tracker.as_mut(),
            |address| free_huge_page_for_process(self.process, address),
        );
        match first_error {
            None => Ok(tracker),
            Some(error) => Err(HugeOsReleaseFailure::FailedPages(HugeOsRawReleaseRetry {
                process: self.process,
                base: self.base,
                page_count: self.page_count,
                memory: self.memory,
                source_error: error,
                failed_pages: tracker,
                failed_words: required_words,
            })),
        }
    }
}

/// A failed source huge-page release either still owns the full allocation
/// before any syscall (insufficient tracking) or owns precisely the compact
/// set of source-accounted raw retries.
#[must_use = "a failed huge release retains an explicit owner"]
pub(crate) enum HugeOsReleaseFailure<'a, Tracker> {
    Tracking(HugeOsReleaseTrackingFailure<'a, Tracker>),
    FailedPages(HugeOsRawReleaseRetry<'a, Tracker>),
}

impl<'a, Tracker> HugeOsReleaseFailure<'a, Tracker> {
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
    default_random: OsRandom<'_>,
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
    apply_huge_page_numa_preference(mapping.base()?, numa_node);
    Ok(mapping)
}

#[cfg(target_arch = "x86_64")]
fn map_huge_page_for_process_with_mbind_warning(
    process: VmProcess<'_>,
    config: MemoryConfig,
    hint: usize,
    numa_node: i32,
    warning: MbindWarningRoute<'_>,
) -> Result<Mapping> {
    let mapping = Mapping::map_huge_page_at(process.policy, config, hint)?;
    apply_huge_page_numa_preference_with_mbind_warning(mapping.base()?, numa_node, warning);
    Ok(mapping)
}

/// Applies the source's best-effort one-word NUMA preference after a huge
/// primitive map. Its result has no ownership meaning: the mapping stays live
/// whether the kernel accepts the preference or returns an error.
#[inline]
fn apply_huge_page_numa_preference(address: *mut u8, numa_node: i32) {
    if numa_node < 0 || numa_node >= usize::BITS as i32 - 1 {
        return;
    }
    let mask = 1usize << numa_node as u32;
    let _ = huge_page_numa_bind(address, &mask);
}

/// The selected private startup receiver for `prim.c:630-645`: a valid NUMA
/// node attempts one `mbind`, formats the captured errno on failure, delivers
/// its warning, and preserves the complete mapping either way. Node 63 on
/// 64-bit Linux remains an invalid source input: it neither calls nor emits.
#[inline]
#[cfg(target_arch = "x86_64")]
fn apply_huge_page_numa_preference_with_mbind_warning(
    address: *mut u8,
    numa_node: i32,
    warning: MbindWarningRoute<'_>,
) {
    if numa_node < 0 || numa_node >= usize::BITS as i32 - 1 {
        return;
    }
    let mask = 1usize << numa_node as u32;
    if let Err(error) = huge_page_numa_bind(address, &mask) {
        // SAFETY: the source startup owner serialized this one mapping attempt
        // with output registration and retains its borrowed route/callback.
        unsafe { warning.mbind_failure(numa_node, error) };
    }
}

#[inline]
fn huge_page_numa_bind(address: *mut u8, mask: &usize) -> Result<()> {
    fault_before(FaultPoint::NumaBind)?;
    // SAFETY: `address` names the caller's full huge primitive mapping and
    // `mask` provides exactly one native unsigned-long NUMA bitmask word.
    unsafe {
        crabc_core::mm::mbind_raw(
            address,
            HUGE_PAGE_SIZE,
            MPOL_PREFERRED,
            mask,
            usize::BITS as usize,
            0,
        )
    }
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

/// Starts the one source-calibrated clock used by process statistics.
///
/// This exposes the already-selected `_mi_clock_start` equivalent for the
/// process statistics owner. It shares the same `SOURCE_CLOCK_DIFF_MILLISECONDS`
/// calibration as the established huge-page timeout path; it adds no clock
/// fallback, storage, or policy.
#[inline]
pub(crate) fn source_process_clock_start() -> i64 {
    source_clock_start()
}

/// Ends one source-calibrated process-statistics interval.
///
/// This is the existing `_mi_clock_end` equivalent and therefore retains the
/// source's wrapping subtraction and shared clock-difference compensation.
#[inline]
pub(crate) fn source_process_clock_end(start: i64) -> i64 {
    source_clock_end(start)
}

#[inline]
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
        default_random: OsRandom<'_>,
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
        default_random: OsRandom<'_>,
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
        mut default_random: OsRandom<'_>,
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
        default_random: OsRandom<'_>,
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

/// Selects every base page touched by one direct source page area.
///
/// Unlike [`Mapping::page_range`], this cannot prove the input is within a
/// particular mapping: an external arena's caller retains terminal release
/// ownership. [`VmProcess::commit_direct_page_area`] requires its caller to
/// prove containment and unique transition; this helper only preserves
/// `_mi_os_commit_ex`'s liberal source page normalization.
fn covering_direct_page_area_range(
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
    HugeMap = 13,
    /// One raw `MAP_HUGETLB` attempt inside the source aligned Unix mapper.
    /// This stays distinct from `Map`, which names the enclosing
    /// `_mi_os_prim_alloc_at` transition and its paired statistics update.
    LargeMap = 14,
    /// The best-effort `MADV_HUGEPAGE` advisory after a regular source map.
    Madvise = 15,
    /// The one-word best-effort NUMA preference after a successful huge map.
    /// It remains distinct from HugeMap: its error is deliberately ignored by
    /// the source and cannot change the completed mapping owner.
    NumaBind = 16,
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
    // A fault plan is process-global because it observes raw Unix seams, but
    // installing one admits only the installer thread. A distinct test worker
    // needs a scoped `FaultPermit`; an unrelated worker must execute its real
    // primitive instead of consuming a one-shot ordinal from another test's
    // plan. The epoch also makes a stale TLS marker harmless after a guard is
    // dropped on a different test thread.
    static NEXT_EPOCH: AtomicUsize = AtomicUsize::new(1);
    static ACTIVE_EPOCH: AtomicUsize = AtomicUsize::new(0);
    #[thread_local]
    static mut CURRENT_EPOCH: usize = 0;
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
    // The bounded option/hint/large/THP witness needs two source large-map
    // failures followed by one independent best-effort THP advisory failure.
    // Keep that third edge explicit rather than letting an unrelated map
    // counter stand in for the source's `madvise` error disposition.
    static THIRD_SELECTED_POINT: AtomicUsize = AtomicUsize::new(ANY_POINT);
    static THIRD_FAILURE_ORDINAL: AtomicUsize = AtomicUsize::new(0);
    static THIRD_OBSERVED: AtomicUsize = AtomicUsize::new(0);
    static THIRD_ENABLED: AtomicBool = AtomicBool::new(false);
    static FAILURE_ERROR: AtomicI32 = AtomicI32::new(Errno::NOMEM.raw());
    static SECOND_FAILURE_ERROR: AtomicI32 = AtomicI32::new(Errno::NOMEM.raw());
    static THIRD_FAILURE_ERROR: AtomicI32 = AtomicI32::new(Errno::NOMEM.raw());
    // The M2 native release-failure differential captures only the two
    // selected `_mi_os_free_ex` primitive arguments. This is separate from
    // `OBSERVED`: a count alone cannot prove that an interior client pointer
    // did not leak into `munmap` instead of the retained full MemoryId.
    static UNMAP_RANGE_CAPTURE_ACTIVE: AtomicBool = AtomicBool::new(false);
    static UNMAP_RANGE_CAPTURE_COUNT: AtomicUsize = AtomicUsize::new(0);
    static UNMAP_RANGE_CAPTURE_ADDRESSES: [AtomicUsize; 2] = [
        AtomicUsize::new(0),
        AtomicUsize::new(0),
    ];
    static UNMAP_RANGE_CAPTURE_LENGTHS: [AtomicUsize; 2] = [
        AtomicUsize::new(0),
        AtomicUsize::new(0),
    ];
    // The normal no-callback purge matrix needs the source-normalized raw
    // advisory range, not just its call count. It captures one selected
    // mapping-owned advice sequence at a time, so an unnormalized whole span
    // cannot pass by reaching the same Unix primitive once. Four edges cover
    // the complete pinned reset state machine: EAGAIN, EINVAL, and one
    // `MADV_DONTNEED` fallback, with one spare bounded edge for a receiver.
    const ADVICE_RANGE_CAPTURE_CAPACITY: usize = 4;
    static ADVICE_RANGE_CAPTURE_ACTIVE: AtomicBool = AtomicBool::new(false);
    static ADVICE_RANGE_CAPTURE_COUNT: AtomicUsize = AtomicUsize::new(0);
    static ADVICE_RANGE_CAPTURE_ADDRESSES: [AtomicUsize; ADVICE_RANGE_CAPTURE_CAPACITY] = [
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
    ];
    static ADVICE_RANGE_CAPTURE_LENGTHS: [AtomicUsize; ADVICE_RANGE_CAPTURE_CAPACITY] = [
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
    ];
    static ADVICE_RANGE_CAPTURE_ADVICES: [AtomicUsize; ADVICE_RANGE_CAPTURE_CAPACITY] = [
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
    ];
    // The option/hint/large/THP policy slice has a small, source-bounded
    // raw mmap sequence: a high aligned hint can fail and retry at null, and
    // a large-page attempt can precede the regular mapping. Keep those raw
    // arguments visible only while a serial test explicitly captures them.
    // This is evidence for the branch order, never a production callback.
    const POLICY_MMAP_CAPTURE_CAPACITY: usize = 4;
    static POLICY_MMAP_CAPTURE_ACTIVE: AtomicBool = AtomicBool::new(false);
    static POLICY_MMAP_CAPTURE_COUNT: AtomicUsize = AtomicUsize::new(0);
    static POLICY_MMAP_CAPTURE_HINTS: [AtomicUsize; POLICY_MMAP_CAPTURE_CAPACITY] = [
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
    ];
    static POLICY_MMAP_CAPTURE_LENGTHS: [AtomicUsize; POLICY_MMAP_CAPTURE_CAPACITY] = [
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
    ];
    static POLICY_MMAP_CAPTURE_PROTECTIONS: [AtomicUsize; POLICY_MMAP_CAPTURE_CAPACITY] = [
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
    ];
    static POLICY_MMAP_CAPTURE_FLAGS: [AtomicUsize; POLICY_MMAP_CAPTURE_CAPACITY] = [
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
    ];
    // The THP process-policy matrix is intentionally narrower than the generic
    // fault plan. It selects one named direct source case at a time, accepts
    // only GET(0,0,0,0)/SET(1,0,0,0), and otherwise falls through to the real
    // primitive when no token is active. It is test-only evidence, not a
    // programmable production policy receiver.
    const THP_DIRECT_POLICY_CAPTURE_CAPACITY: usize = 2;
    static THP_DIRECT_POLICY_CAPTURE_ACTIVE: AtomicBool = AtomicBool::new(false);
    static THP_DIRECT_POLICY_CAPTURE_VALID: AtomicBool = AtomicBool::new(false);
    static THP_DIRECT_POLICY_CAPTURE_CASE: AtomicUsize = AtomicUsize::new(0);
    static THP_DIRECT_POLICY_CAPTURE_COUNT: AtomicUsize = AtomicUsize::new(0);
    static THP_DIRECT_POLICY_CAPTURE_OPTIONS: [AtomicI32; THP_DIRECT_POLICY_CAPTURE_CAPACITY] = [
        AtomicI32::new(0),
        AtomicI32::new(0),
    ];
    static THP_DIRECT_POLICY_CAPTURE_ARGUMENTS: [AtomicUsize; THP_DIRECT_POLICY_CAPTURE_CAPACITY * 4] = [
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
    ];

    /// The finite direct control-flow cases from `prim.c:267-274`.
    ///
    /// `QueryNonzeroThree` is deliberately a raw nonzero return-class witness,
    /// not a claim that Linux 5.10 documents `3` as a kernel result. The two
    /// fixed errno variants prove Rust's typed payload preservation while the
    /// C source itself only branches on query success versus nonzero/error.
    #[repr(usize)]
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) enum ThpDirectPolicyCase {
        AllowEnabled = 1,
        QueryPerm,
        QueryInval,
        QueryNonzeroOne,
        QueryNonzeroThree,
        SetSuccess,
        SetPerm,
        SetInval,
    }

    impl ThpDirectPolicyCase {
        #[inline]
        const fn expected_calls(self) -> usize {
            match self {
                Self::AllowEnabled => 0,
                Self::QueryPerm | Self::QueryInval | Self::QueryNonzeroOne | Self::QueryNonzeroThree => 1,
                Self::SetSuccess | Self::SetPerm | Self::SetInval => 2,
            }
        }

        #[inline]
        pub(crate) const fn allow_enabled(self) -> bool {
            matches!(self, Self::AllowEnabled)
        }

        #[inline]
        fn from_raw(raw: usize) -> Option<Self> {
            match raw {
                raw if raw == Self::AllowEnabled as usize => Some(Self::AllowEnabled),
                raw if raw == Self::QueryPerm as usize => Some(Self::QueryPerm),
                raw if raw == Self::QueryInval as usize => Some(Self::QueryInval),
                raw if raw == Self::QueryNonzeroOne as usize => Some(Self::QueryNonzeroOne),
                raw if raw == Self::QueryNonzeroThree as usize => Some(Self::QueryNonzeroThree),
                raw if raw == Self::SetSuccess as usize => Some(Self::SetSuccess),
                raw if raw == Self::SetPerm as usize => Some(Self::SetPerm),
                raw if raw == Self::SetInval as usize => Some(Self::SetInval),
                _ => None,
            }
        }
    }

    /// An allocation-free deterministic failure plan for one serial test.
    #[derive(Clone, Copy)]
    pub(crate) struct Plan {
        point: usize,
        ordinal: usize,
        second_point: usize,
        second_ordinal: usize,
        third_point: usize,
        third_ordinal: usize,
        error: Errno,
        second_error: Errno,
        third_error: Errno,
    }

    impl Plan {
        pub(crate) const fn disabled() -> Self {
            Self {
                point: ANY_POINT,
                ordinal: 0,
                second_point: ANY_POINT,
                second_ordinal: 0,
                third_point: ANY_POINT,
                third_ordinal: 0,
                error: Errno::NOMEM,
                second_error: Errno::NOMEM,
                third_error: Errno::NOMEM,
            }
        }

        pub(crate) const fn any_nth(ordinal: usize, error: Errno) -> Self {
            Self {
                point: ANY_POINT,
                ordinal,
                second_point: ANY_POINT,
                second_ordinal: 0,
                third_point: ANY_POINT,
                third_ordinal: 0,
                error,
                second_error: error,
                third_error: error,
            }
        }

        pub(crate) const fn at(point: Point, ordinal: usize, error: Errno) -> Self {
            Self {
                point: point as usize,
                ordinal,
                second_point: ANY_POINT,
                second_ordinal: 0,
                third_point: ANY_POINT,
                third_ordinal: 0,
                error,
                second_error: error,
                third_error: error,
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
                third_point: ANY_POINT,
                third_ordinal: 0,
                error,
                second_error: error,
                third_error: error,
            }
        }

        /// Fails two ordered edges with their own Linux errors.
        ///
        /// This stays test-only. The reset trace needs `EAGAIN` before the
        /// source's `MADV_FREE`/`EINVAL` state transition, rather than one
        /// repeated synthetic error standing in for both source edges.
        pub(crate) const fn at_pair_with_errors(
            point: Point,
            ordinal: usize,
            error: Errno,
            second_point: Point,
            second_ordinal: usize,
            second_error: Errno,
        ) -> Self {
            Self {
                point: point as usize,
                ordinal,
                second_point: second_point as usize,
                second_ordinal,
                third_point: ANY_POINT,
                third_ordinal: 0,
                error,
                second_error,
                third_error: second_error,
            }
        }

        /// Fails two ordered source edges, then one final independent edge.
        ///
        /// This represents the fixed policy witness's two `MAP_HUGETLB`
        /// failures and its later ignored `MADV_HUGEPAGE` error. The third
        /// point remains disabled until the second failure has occurred.
        pub(crate) const fn at_triple(
            point: Point,
            ordinal: usize,
            second_point: Point,
            second_ordinal: usize,
            third_point: Point,
            third_ordinal: usize,
            error: Errno,
        ) -> Self {
            Self {
                point: point as usize,
                ordinal,
                second_point: second_point as usize,
                second_ordinal,
                third_point: third_point as usize,
                third_ordinal,
                error,
                second_error: error,
                third_error: error,
            }
        }

        /// Fails three ordered edges with their own Linux errors.
        ///
        /// The bounded normal-release reset witness uses this for its exact
        /// `EAGAIN`, `EINVAL`, then fallback-`EAGAIN` sequence.
        pub(crate) const fn at_triple_with_errors(
            point: Point,
            ordinal: usize,
            error: Errno,
            second_point: Point,
            second_ordinal: usize,
            second_error: Errno,
            third_point: Point,
            third_ordinal: usize,
            third_error: Errno,
        ) -> Self {
            Self {
                point: point as usize,
                ordinal,
                second_point: second_point as usize,
                second_ordinal,
                third_point: third_point as usize,
                third_ordinal,
                error,
                second_error,
                third_error,
            }
        }
    }

    /// Serializes tests which exercise the process-global injection counters.
    ///
    /// This is test-only spin synchronization over static atomics; it neither
    /// allocates nor involves the allocator engine under test. The installing
    /// thread is the sole implicit plan consumer. Tests that deliberately
    /// inject into a worker must borrow a [`FaultPermit`] from this guard.
    pub(crate) struct Guard {
        epoch: usize,
    }

    /// Scoped admission for one deliberate cross-thread fault injection.
    ///
    /// The lifetime keeps the plan guard installed while the worker runs. It
    /// contains no allocator or mapping capability; it only marks the worker
    /// as an allowed consumer of this test-only plan.
    pub(crate) struct FaultPermit<'guard> {
        epoch: usize,
        _guard: core::marker::PhantomData<&'guard Guard>,
    }

    struct CurrentThreadEpochReset {
        previous: usize,
    }

    impl Drop for CurrentThreadEpochReset {
        fn drop(&mut self) {
            set_current_epoch(self.previous);
        }
    }

    /// Test-only capture token for two selected `munmap` argument pairs.
    ///
    /// It is constructed only from the serial global fault guard, so the
    /// fixed M2 trace cannot confuse an unrelated test's map release with
    /// the selected normal-offset failure/retry pair.
    pub(crate) struct UnmapRangeCapture<'guard> {
        _guard: core::marker::PhantomData<&'guard Guard>,
    }

    /// Test-only bounded capture token for source-normalized `madvise`
    /// arguments from one mapping-owned transition.
    pub(crate) struct AdviceRangeCapture<'guard> {
        _guard: core::marker::PhantomData<&'guard Guard>,
    }

    /// One raw mmap argument tuple from the bounded process-policy route.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) struct PolicyMmapAttempt {
        pub(crate) hint: Option<usize>,
        pub(crate) length: usize,
        pub(crate) protection: u32,
        pub(crate) flags: u32,
    }

    impl PolicyMmapAttempt {
        /// Distinguishes the source's `MAP_HUGETLB` retry from its ordinary
        /// fallback without exposing a raw platform flag outside this
        /// test-only capture module.
        #[inline]
        pub(crate) const fn uses_huge_page_flag(self) -> bool {
            self.flags & super::MAP_HUGETLB != 0
        }
    }

    /// A serial capture of the finite raw mmap sequence selected by one test.
    pub(crate) struct PolicyMmapCapture<'guard> {
        _guard: core::marker::PhantomData<&'guard Guard>,
    }

    /// A serial capture of one named direct THP policy case.
    pub(crate) struct ThpDirectPolicyCapture<'guard> {
        selected_case: ThpDirectPolicyCase,
        _guard: core::marker::PhantomData<&'guard Guard>,
    }

    pub(crate) fn install(plan: Plan) -> Guard {
        while LOCKED
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        set(plan);
        let epoch = next_epoch();
        set_current_epoch(epoch);
        ACTIVE_EPOCH.store(epoch, Ordering::Release);
        Guard { epoch }
    }

    impl Guard {
        pub(crate) fn set(&self, plan: Plan) {
            // `set` is an explicit test action. Existing worker fixtures that
            // select their plan inside the worker remain deliberately
            // admitted without granting unrelated workers access.
            set_current_epoch(self.epoch);
            set(plan);
        }

        /// Borrows this serial plan for a worker whose first selected raw
        /// operation happens before it can call [`Guard::set`].
        #[inline]
        pub(crate) fn permit(&self) -> FaultPermit<'_> {
            FaultPermit {
                epoch: self.epoch,
                _guard: core::marker::PhantomData,
            }
        }

        pub(crate) fn observed(&self) -> usize {
            OBSERVED.load(Ordering::Acquire)
        }

        pub(crate) fn secondary_observed(&self) -> usize {
            SECOND_OBSERVED.load(Ordering::Acquire)
        }

        #[inline]
        pub(crate) fn third_observed(&self) -> usize {
            THIRD_OBSERVED.load(Ordering::Acquire)
        }

        /// Starts a fresh capture of exactly two subsequent process-owned
        /// unmap ranges. More or fewer calls are visible as `None` instead of
        /// becoming a partial address/length assertion.
        pub(crate) fn capture_unmap_ranges(&self) -> UnmapRangeCapture<'_> {
            UNMAP_RANGE_CAPTURE_ACTIVE.store(false, Ordering::Release);
            UNMAP_RANGE_CAPTURE_COUNT.store(0, Ordering::Release);
            for address in &UNMAP_RANGE_CAPTURE_ADDRESSES {
                address.store(0, Ordering::Release);
            }
            for length in &UNMAP_RANGE_CAPTURE_LENGTHS {
                length.store(0, Ordering::Release);
            }
            UNMAP_RANGE_CAPTURE_ACTIVE.store(true, Ordering::Release);
            UnmapRangeCapture {
                _guard: core::marker::PhantomData,
            }
        }

        /// Starts a fresh bounded capture of subsequent mapping-owned advice
        /// tuples. Callers that require one tuple retain [`AdviceRangeCapture::range`];
        /// reset callers use the ordered sequence to preserve retry/fallback
        /// ownership.
        pub(crate) fn capture_advice_range(&self) -> AdviceRangeCapture<'_> {
            ADVICE_RANGE_CAPTURE_ACTIVE.store(false, Ordering::Release);
            ADVICE_RANGE_CAPTURE_COUNT.store(0, Ordering::Release);
            for address in &ADVICE_RANGE_CAPTURE_ADDRESSES {
                address.store(0, Ordering::Release);
            }
            for length in &ADVICE_RANGE_CAPTURE_LENGTHS {
                length.store(0, Ordering::Release);
            }
            for advice in &ADVICE_RANGE_CAPTURE_ADVICES {
                advice.store(0, Ordering::Release);
            }
            ADVICE_RANGE_CAPTURE_ACTIVE.store(true, Ordering::Release);
            AdviceRangeCapture {
                _guard: core::marker::PhantomData,
            }
        }

        /// Captures at most four immediately following policy mmap calls.
        /// More calls deliberately invalidate the record rather than making a
        /// partial branch-order assertion look complete.
        pub(crate) fn capture_policy_mmaps(&self) -> PolicyMmapCapture<'_> {
            POLICY_MMAP_CAPTURE_ACTIVE.store(false, Ordering::Release);
            POLICY_MMAP_CAPTURE_COUNT.store(0, Ordering::Release);
            for hint in &POLICY_MMAP_CAPTURE_HINTS {
                hint.store(0, Ordering::Release);
            }
            for length in &POLICY_MMAP_CAPTURE_LENGTHS {
                length.store(0, Ordering::Release);
            }
            for protection in &POLICY_MMAP_CAPTURE_PROTECTIONS {
                protection.store(0, Ordering::Release);
            }
            for flags in &POLICY_MMAP_CAPTURE_FLAGS {
                flags.store(0, Ordering::Release);
            }
            POLICY_MMAP_CAPTURE_ACTIVE.store(true, Ordering::Release);
            PolicyMmapCapture {
                _guard: core::marker::PhantomData,
            }
        }

        /// Selects one exact source case. More, fewer, or different calls
        /// invalidate this fixed witness instead of becoming a prefix.
        pub(crate) fn capture_thp_direct_policy_case(
            &self, selected_case: ThpDirectPolicyCase,
        ) -> ThpDirectPolicyCapture<'_> {
            THP_DIRECT_POLICY_CAPTURE_ACTIVE.store(false, Ordering::Release);
            THP_DIRECT_POLICY_CAPTURE_VALID.store(true, Ordering::Release);
            THP_DIRECT_POLICY_CAPTURE_CASE.store(selected_case as usize, Ordering::Release);
            THP_DIRECT_POLICY_CAPTURE_COUNT.store(0, Ordering::Release);
            for option in &THP_DIRECT_POLICY_CAPTURE_OPTIONS {
                option.store(0, Ordering::Release);
            }
            for argument in &THP_DIRECT_POLICY_CAPTURE_ARGUMENTS {
                argument.store(0, Ordering::Release);
            }
            THP_DIRECT_POLICY_CAPTURE_ACTIVE.store(true, Ordering::Release);
            ThpDirectPolicyCapture {
                selected_case,
                _guard: core::marker::PhantomData,
            }
        }
    }

    impl FaultPermit<'_> {
        /// Runs one deliberate worker operation with this guard's fault plan.
        #[inline]
        pub(crate) fn run<T>(&self, operation: impl FnOnce() -> T) -> T {
            let previous = current_epoch();
            set_current_epoch(self.epoch);
            let _reset = CurrentThreadEpochReset { previous };
            operation()
        }
    }

    impl UnmapRangeCapture<'_> {
        /// Returns both exact syscall argument pairs only when the selected
        /// trace observed exactly two process-owned unmap operations.
        pub(crate) fn ranges(&self) -> Option<[(usize, usize); 2]> {
            if UNMAP_RANGE_CAPTURE_COUNT.load(Ordering::Acquire) != 2 {
                return None;
            }
            Some([
                (
                    UNMAP_RANGE_CAPTURE_ADDRESSES[0].load(Ordering::Acquire),
                    UNMAP_RANGE_CAPTURE_LENGTHS[0].load(Ordering::Acquire),
                ),
                (
                    UNMAP_RANGE_CAPTURE_ADDRESSES[1].load(Ordering::Acquire),
                    UNMAP_RANGE_CAPTURE_LENGTHS[1].load(Ordering::Acquire),
                ),
            ])
        }
    }

    impl Drop for UnmapRangeCapture<'_> {
        fn drop(&mut self) {
            UNMAP_RANGE_CAPTURE_ACTIVE.store(false, Ordering::Release);
        }
    }

    impl AdviceRangeCapture<'_> {
        /// Reports every observed mapping-owned advice call so a source policy
        /// cell which should skip advice cannot pass merely because no fault
        /// plan was armed for it.
        #[inline]
        pub(crate) fn count(&self) -> usize {
            ADVICE_RANGE_CAPTURE_COUNT.load(Ordering::Acquire)
        }

        /// Returns the exact raw tuple only if the selected branch made one
        /// mapping-owned advisory call.
        pub(crate) fn range(&self) -> Option<(usize, usize, u32)> {
            if self.count() != 1 {
                return None;
            }
            Some((
                ADVICE_RANGE_CAPTURE_ADDRESSES[0].load(Ordering::Acquire),
                ADVICE_RANGE_CAPTURE_LENGTHS[0].load(Ordering::Acquire),
                ADVICE_RANGE_CAPTURE_ADVICES[0].load(Ordering::Acquire) as u32,
            ))
        }

        /// Returns the complete ordered bounded sequence, together with its
        /// length. More than the fixed capacity invalidates the witness.
        pub(crate) fn ranges(
            &self,
        ) -> Option<([(usize, usize, u32); ADVICE_RANGE_CAPTURE_CAPACITY], usize)> {
            let count = self.count();
            if count > ADVICE_RANGE_CAPTURE_CAPACITY {
                return None;
            }
            Some((
                core::array::from_fn(|index| {
                    (
                        ADVICE_RANGE_CAPTURE_ADDRESSES[index].load(Ordering::Acquire),
                        ADVICE_RANGE_CAPTURE_LENGTHS[index].load(Ordering::Acquire),
                        ADVICE_RANGE_CAPTURE_ADVICES[index].load(Ordering::Acquire) as u32,
                    )
                }),
                count,
            ))
        }
    }

    impl Drop for AdviceRangeCapture<'_> {
        fn drop(&mut self) {
            ADVICE_RANGE_CAPTURE_ACTIVE.store(false, Ordering::Release);
        }
    }

    impl PolicyMmapCapture<'_> {
        /// Returns every selected raw call only when it fits the fixed
        /// bounded capture. A zero stored hint is the source null address.
        pub(crate) fn attempts(&self) -> Option<([PolicyMmapAttempt; POLICY_MMAP_CAPTURE_CAPACITY], usize)> {
            let count = POLICY_MMAP_CAPTURE_COUNT.load(Ordering::Acquire);
            if count > POLICY_MMAP_CAPTURE_CAPACITY {
                return None;
            }
            let attempts = core::array::from_fn(|index| PolicyMmapAttempt {
                hint: match POLICY_MMAP_CAPTURE_HINTS[index].load(Ordering::Acquire) {
                    0 => None,
                    hint => Some(hint),
                },
                length: POLICY_MMAP_CAPTURE_LENGTHS[index].load(Ordering::Acquire),
                protection: POLICY_MMAP_CAPTURE_PROTECTIONS[index].load(Ordering::Acquire) as u32,
                flags: POLICY_MMAP_CAPTURE_FLAGS[index].load(Ordering::Acquire) as u32,
            });
            Some((attempts, count))
        }
    }

    impl ThpDirectPolicyCapture<'_> {
        /// Returns the fixed two-slot record and its exact selected count.
        pub(crate) fn attempts(
            &self,
        ) -> Option<([(i32, [usize; 4]); THP_DIRECT_POLICY_CAPTURE_CAPACITY], usize)> {
            let count = THP_DIRECT_POLICY_CAPTURE_COUNT.load(Ordering::Acquire);
            if !THP_DIRECT_POLICY_CAPTURE_VALID.load(Ordering::Acquire)
                || count != self.selected_case.expected_calls()
            {
                return None;
            }
            Some((
                core::array::from_fn(|index| {
                    (
                        THP_DIRECT_POLICY_CAPTURE_OPTIONS[index].load(Ordering::Acquire),
                        core::array::from_fn(|argument| {
                            THP_DIRECT_POLICY_CAPTURE_ARGUMENTS[index * 4 + argument]
                                .load(Ordering::Acquire)
                        }),
                    )
                }),
                count,
            ))
        }
    }

    impl Drop for PolicyMmapCapture<'_> {
        fn drop(&mut self) {
            POLICY_MMAP_CAPTURE_ACTIVE.store(false, Ordering::Release);
        }
    }

    impl Drop for ThpDirectPolicyCapture<'_> {
        fn drop(&mut self) {
            THP_DIRECT_POLICY_CAPTURE_ACTIVE.store(false, Ordering::Release);
            THP_DIRECT_POLICY_CAPTURE_CASE.store(0, Ordering::Release);
        }
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            ACTIVE_EPOCH.store(0, Ordering::Release);
            UNMAP_RANGE_CAPTURE_ACTIVE.store(false, Ordering::Release);
            ADVICE_RANGE_CAPTURE_ACTIVE.store(false, Ordering::Release);
            POLICY_MMAP_CAPTURE_ACTIVE.store(false, Ordering::Release);
            THP_DIRECT_POLICY_CAPTURE_ACTIVE.store(false, Ordering::Release);
            THP_DIRECT_POLICY_CAPTURE_CASE.store(0, Ordering::Release);
            set(Plan::disabled());
            if current_epoch() == self.epoch {
                set_current_epoch(0);
            }
            LOCKED.store(false, Ordering::Release);
        }
    }

    #[inline]
    fn next_epoch() -> usize {
        let mut epoch = NEXT_EPOCH.fetch_add(1, Ordering::Relaxed);
        if epoch == 0 {
            epoch = NEXT_EPOCH.fetch_add(1, Ordering::Relaxed);
        }
        epoch
    }

    #[inline]
    fn current_epoch() -> usize {
        // SAFETY: this `#[thread_local]` cell is read and written only by its
        // current thread through the helpers in this module.
        unsafe { CURRENT_EPOCH }
    }

    #[inline]
    fn set_current_epoch(epoch: usize) {
        // SAFETY: as above, each thread owns its TLS cell exclusively.
        unsafe { CURRENT_EPOCH = epoch; }
    }

    #[inline]
    fn authorized() -> bool {
        let active = ACTIVE_EPOCH.load(Ordering::Acquire);
        active != 0 && current_epoch() == active
    }

    #[inline]
    fn set(plan: Plan) {
        SELECTED_POINT.store(plan.point, Ordering::Relaxed);
        FAILURE_ORDINAL.store(plan.ordinal, Ordering::Relaxed);
        SECOND_SELECTED_POINT.store(plan.second_point, Ordering::Relaxed);
        SECOND_FAILURE_ORDINAL.store(plan.second_ordinal, Ordering::Relaxed);
        THIRD_SELECTED_POINT.store(plan.third_point, Ordering::Relaxed);
        THIRD_FAILURE_ORDINAL.store(plan.third_ordinal, Ordering::Relaxed);
        FAILURE_ERROR.store(plan.error.raw(), Ordering::Relaxed);
        SECOND_FAILURE_ERROR.store(plan.second_error.raw(), Ordering::Relaxed);
        THIRD_FAILURE_ERROR.store(plan.third_error.raw(), Ordering::Relaxed);
        OBSERVED.store(0, Ordering::Release);
        SECOND_OBSERVED.store(0, Ordering::Release);
        THIRD_OBSERVED.store(0, Ordering::Release);
        SECOND_ENABLED.store(false, Ordering::Release);
        THIRD_ENABLED.store(false, Ordering::Release);
    }

    #[inline]
    pub(crate) fn before(point: Point) -> Result<()> {
        if !authorized() {
            return Ok(());
        }
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
                    THIRD_ENABLED.store(true, Ordering::Release);
                    let error = SECOND_FAILURE_ERROR.load(Ordering::Acquire);
                    // SAFETY: `Plan` obtains `error` from a valid `Errno`, so
                    // the stored integer remains a positive Linux errno.
                    return Err(unsafe { Errno::from_raw(error).unwrap_unchecked() });
                }
            }
        }
        let third_selected = THIRD_SELECTED_POINT.load(Ordering::Acquire);
        if THIRD_ENABLED.load(Ordering::Acquire)
            && (third_selected == ANY_POINT || third_selected == point as usize)
        {
            let third_ordinal = THIRD_FAILURE_ORDINAL.load(Ordering::Acquire);
            if third_ordinal != 0 {
                let third_observed = THIRD_OBSERVED.fetch_add(1, Ordering::AcqRel) + 1;
                if third_observed == third_ordinal {
                    let error = THIRD_FAILURE_ERROR.load(Ordering::Acquire);
                    // SAFETY: `Plan` obtains `error` from a valid `Errno`, so
                    // the stored integer remains a positive Linux errno.
                    return Err(unsafe { Errno::from_raw(error).unwrap_unchecked() });
                }
            }
        }
        Ok(())
    }

    /// Records the exact arguments that would reach the source Unix free
    /// primitive. This runs before injected failure, matching the C link-wrap
    /// boundary where `__wrap_munmap` sees both the failing call and retry.
    #[inline]
    pub(crate) fn record_unmap_range(address: *mut u8, length: usize) {
        if !authorized() || !UNMAP_RANGE_CAPTURE_ACTIVE.load(Ordering::Acquire) {
            return;
        }
        let index = UNMAP_RANGE_CAPTURE_COUNT.fetch_add(1, Ordering::AcqRel);
        if index < 2 {
            UNMAP_RANGE_CAPTURE_ADDRESSES[index].store(address.addr(), Ordering::Release);
            UNMAP_RANGE_CAPTURE_LENGTHS[index].store(length, Ordering::Release);
        }
    }

    /// Records the source-normalized raw `madvise` arguments before the Unix
    /// primitive. This remains a serial test seam beside the existing unmap
    /// capture; it is not a production callback or policy interface.
    #[inline]
    pub(crate) fn record_advice_range(address: *mut u8, length: usize, advice: u32) {
        if !authorized() || !ADVICE_RANGE_CAPTURE_ACTIVE.load(Ordering::Acquire) {
            return;
        }
        let index = ADVICE_RANGE_CAPTURE_COUNT.fetch_add(1, Ordering::AcqRel);
        if index < ADVICE_RANGE_CAPTURE_CAPACITY {
            ADVICE_RANGE_CAPTURE_ADDRESSES[index].store(address.addr(), Ordering::Release);
            ADVICE_RANGE_CAPTURE_LENGTHS[index].store(length, Ordering::Release);
            ADVICE_RANGE_CAPTURE_ADVICES[index].store(advice as usize, Ordering::Release);
        }
    }

    /// Records one raw Unix mmap edge before a controlled injected result.
    #[inline]
    pub(crate) fn record_policy_mmap(
        hint: Option<usize>, length: usize, protection: u32, flags: u32,
    ) {
        if !authorized() || !POLICY_MMAP_CAPTURE_ACTIVE.load(Ordering::Acquire) {
            return;
        }
        let index = POLICY_MMAP_CAPTURE_COUNT.fetch_add(1, Ordering::AcqRel);
        if index < POLICY_MMAP_CAPTURE_CAPACITY {
            POLICY_MMAP_CAPTURE_HINTS[index].store(hint.unwrap_or(0), Ordering::Release);
            POLICY_MMAP_CAPTURE_LENGTHS[index].store(length, Ordering::Release);
            POLICY_MMAP_CAPTURE_PROTECTIONS[index].store(protection as usize, Ordering::Release);
            POLICY_MMAP_CAPTURE_FLAGS[index].store(flags as usize, Ordering::Release);
        }
    }

    /// Test-only raw THP policy receiver for the finite direct source matrix.
    /// It uses no generic answer callback: each case accepts only its literal
    /// GET/SET tuple and directly returns the one fixed result.
    #[inline]
    pub(crate) fn thp_policy_prctl_raw(
        option: i32, argument0: usize, argument1: usize, argument2: usize, argument3: usize,
    ) -> Result<usize> {
        if !authorized() || !THP_DIRECT_POLICY_CAPTURE_ACTIVE.load(Ordering::Acquire) {
            // SAFETY: callers use only the two Linux THP constants with their
            // source scalar zero/one arguments.
            return unsafe {
                crabc_core::process::prctl_raw(option, argument0, argument1, argument2, argument3)
            };
        }

        let selected_case = ThpDirectPolicyCase::from_raw(
            THP_DIRECT_POLICY_CAPTURE_CASE.load(Ordering::Acquire),
        );
        let index = THP_DIRECT_POLICY_CAPTURE_COUNT.fetch_add(1, Ordering::AcqRel);
        if index < THP_DIRECT_POLICY_CAPTURE_CAPACITY {
            THP_DIRECT_POLICY_CAPTURE_OPTIONS[index].store(option, Ordering::Release);
            let arguments = [argument0, argument1, argument2, argument3];
            for (argument_index, argument) in arguments.into_iter().enumerate() {
                THP_DIRECT_POLICY_CAPTURE_ARGUMENTS[index * 4 + argument_index]
                    .store(argument, Ordering::Release);
            }
        }
        let get_tuple = option == super::PR_GET_THP_DISABLE
            && argument0 == 0 && argument1 == 0 && argument2 == 0 && argument3 == 0;
        let set_tuple = option == super::PR_SET_THP_DISABLE
            && argument0 == 1 && argument1 == 0 && argument2 == 0 && argument3 == 0;
        match (selected_case, index, get_tuple, set_tuple) {
            (Some(ThpDirectPolicyCase::QueryPerm), 0, true, _) => Err(Errno::PERM),
            (Some(ThpDirectPolicyCase::QueryInval), 0, true, _) => Err(Errno::INVAL),
            (Some(ThpDirectPolicyCase::QueryNonzeroOne), 0, true, _) => Ok(1),
            (Some(ThpDirectPolicyCase::QueryNonzeroThree), 0, true, _) => Ok(3),
            (Some(ThpDirectPolicyCase::SetSuccess), 0, true, _) => Ok(0),
            (Some(ThpDirectPolicyCase::SetPerm), 0, true, _) => Ok(0),
            (Some(ThpDirectPolicyCase::SetInval), 0, true, _) => Ok(0),
            (Some(ThpDirectPolicyCase::SetSuccess), 1, _, true) => Ok(0),
            (Some(ThpDirectPolicyCase::SetPerm), 1, _, true) => Err(Errno::PERM),
            (Some(ThpDirectPolicyCase::SetInval), 1, _, true) => Err(Errno::INVAL),
            _ => {
                THP_DIRECT_POLICY_CAPTURE_VALID.store(false, Ordering::Release);
                Err(Errno::INVAL)
            }
        }
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
    #[cfg(target_arch = "x86_64")]
    use crate::diagnostic_output::{
        MbindWarningRoute, OutputCallback, OutputOwner, RuntimeStderrOutput,
    };
    #[cfg(target_arch = "x86_64")]
    use core::cell::UnsafeCell;
    #[cfg(target_arch = "x86_64")]
    use core::ffi::{c_char, c_void, CStr};
    #[cfg(target_arch = "x86_64")]
    use core::sync::atomic::{AtomicBool, AtomicUsize};

    /* This deadline exists only in the native test schedule. The production
     * source CAS never waits; a missed helper handoff must fail the witness
     * instead of leaving an exact unit selection running indefinitely. */
    pub(super) fn wait_for_large_page_retry_phase(
        policy: &VmPolicy, expected: usize, boundary: &str,
    ) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            if policy.large_page_retry_test_phase.load(Ordering::Acquire) == expected {
                return;
            }
            if std::time::Instant::now() >= deadline {
                panic!("large-page retry test schedule timed out at {boundary}");
            }
            std::thread::yield_now();
        }
    }

    static VM_POLICY_SOURCE_ENVIRONMENT_TEST_LOCK: std::sync::Mutex<()> =
        std::sync::Mutex::new(());
    static VM_POLICY_SOURCE_ENVIRONMENT: core::sync::atomic::AtomicPtr<*const core::ffi::c_char> =
        core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

    unsafe fn vm_policy_source_environment_for_test() -> *const *const core::ffi::c_char {
        // The test lock holds the selected vector stable for every option
        // observation. This is the same borrowed-vector shape as the native
        // reader, without changing this test process's real environment.
        VM_POLICY_SOURCE_ENVIRONMENT
            .load(Ordering::Acquire)
            .cast_const()
    }

    struct VmPolicySourceEnvironmentReset;

    impl Drop for VmPolicySourceEnvironmentReset {
        fn drop(&mut self) {
            VM_POLICY_SOURCE_ENVIRONMENT.store(core::ptr::null_mut(), Ordering::Release);
        }
    }

    #[cfg(target_arch = "x86_64")]
    struct MbindDiagnosticCapture {
        count: AtomicUsize,
        expected_body: AtomicBool,
        _no_alias: UnsafeCell<()>,
    }

    #[cfg(target_arch = "x86_64")]
    unsafe impl Sync for MbindDiagnosticCapture {}

    #[cfg(target_arch = "x86_64")]
    unsafe extern "C" fn capture_mbind_diagnostic(message: *const c_char, argument: *mut c_void) {
        // SAFETY: the source test registers one live capture and serializes
        // this receiver call with the route under test.
        let capture = unsafe { &*(argument as *const MbindDiagnosticCapture) };
        let bytes = unsafe { CStr::from_ptr(message) }.to_bytes();
        if bytes == b"failed to bind huge (1GiB) pages to numa node 62 (error: 4095 (0xFFF))\n" {
            capture.expected_body.store(true, Ordering::Release);
        }
        capture.count.fetch_add(1, Ordering::AcqRel);
    }

    #[cfg(target_arch = "x86_64")]
    unsafe extern "C" fn unexpected_default_diagnostic_output(_: *const c_char) {
        unreachable!("the actual mbind receiver test registers its custom route before emission")
    }

    #[cfg(target_arch = "x86_64")]
    struct FaultDiagnosticRelationCapture {
        count: AtomicUsize,
        lengths: UnsafeCell<[usize; 2]>,
        fragments: UnsafeCell<[[u8; 192]; 2]>,
    }

    #[cfg(target_arch = "x86_64")]
    unsafe impl Sync for FaultDiagnosticRelationCapture {}

    #[cfg(target_arch = "x86_64")]
    impl FaultDiagnosticRelationCapture {
        const fn new() -> Self {
            Self {
                count: AtomicUsize::new(0),
                lengths: UnsafeCell::new([0; 2]),
                fragments: UnsafeCell::new([[0; 192]; 2]),
            }
        }

        fn reset(&self) {
            self.count.store(0, Ordering::Release);
            // SAFETY: this source witness resets only between serialized
            // callback deliveries and before its next observation.
            unsafe {
                *self.lengths.get() = [0; 2];
                *self.fragments.get() = [[0; 192]; 2];
            }
        }

        fn fragment(&self, index: usize) -> &[u8] {
            assert!(index < self.count.load(Ordering::Acquire));
            // SAFETY: the selected callback has completed before this
            // single-threaded source witness reads its fixed capture slots.
            unsafe { &(&*self.fragments.get())[index][..(&*self.lengths.get())[index]] }
        }
    }

    #[cfg(target_arch = "x86_64")]
    unsafe extern "C" fn capture_fault_diagnostic_relation(
        message: *const c_char, argument: *mut c_void,
    ) {
        if message.is_null() || argument.is_null() {
            return;
        }
        // SAFETY: this fixture registers its address-stable capture once and
        // serializes every selected source delivery on this test thread.
        let capture = unsafe { &*(argument as *const FaultDiagnosticRelationCapture) };
        let bytes = unsafe { CStr::from_ptr(message) }.to_bytes();
        let index = capture.count.fetch_add(1, Ordering::AcqRel);
        if index >= 2 || bytes.len() > 192 {
            return;
        }
        // SAFETY: `index` is this callback's unique bounded fixed slot and
        // reads happen only after the callback route returns.
        unsafe {
            (&mut *capture.fragments.get())[index][..bytes.len()].copy_from_slice(bytes);
            (&mut *capture.lengths.get())[index] = bytes.len();
        }
    }

    #[cfg(target_arch = "x86_64")]
    unsafe extern "C" {
        fn fputs(message: *const c_char, stream: *mut c_void) -> i32;
        static mut stderr: *mut c_void;
    }

    /// Test-only explicit bridge for the selected native musl FILE primitive.
    /// It intentionally ignores `fputs`'s result, as pinned
    /// `_mi_prim_out_stderr` does. It is not an ambient production lookup or
    /// a FILE transport qualification claim.
    #[cfg(target_arch = "x86_64")]
    unsafe extern "C" fn m2_fault_diagnostic_musl_stderr(message: *const c_char) {
        // SAFETY: the x86 native test binary links the pinned musl `stderr`
        // object and `fputs`; `RuntimeStderrOutput` guarantees a non-null
        // source NUL-terminated fragment for this test's process lifetime.
        unsafe { let _ = fputs(message, stderr); }
    }

    fn current_startup() -> StartupInput {
        let raw_page_size = crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
            .expect("the Linux test process must expose AT_PAGESZ");
        let page_size = PageSize::new(raw_page_size)
            .expect("AT_PAGESZ must be a valid Linux page size");
        StartupInput::new(page_size)
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn failed_valid_mbind_uses_the_actual_receiver_and_invalid_node_does_not_attempt_or_emit() {
        let _environment_serial = VM_POLICY_SOURCE_ENVIRONMENT_TEST_LOCK
            .lock()
            .expect("source environment test lock is not poisoned");
        let _environment_reset = VmPolicySourceEnvironmentReset;
        let show_errors = b"mimalloc_show_errors=1\0";
        let verbose = b"mimalloc_verbose=0\0";
        let max_warnings = b"mimalloc_max_warnings=32\0";
        let mut environment = [
            show_errors.as_ptr().cast(),
            verbose.as_ptr().cast(),
            max_warnings.as_ptr().cast(),
            core::ptr::null(),
        ];
        VM_POLICY_SOURCE_ENVIRONMENT.store(environment.as_mut_ptr(), Ordering::Release);

        let mut output = OutputOwner::new(unexpected_default_diagnostic_output);
        // SAFETY: this test holds the raw vector stable while it performs the
        // process-shaped selected descriptor initialization before borrowing
        // the mbind receiver route.
        unsafe { output.initialize_source_options(vm_policy_source_environment_for_test) };
        let capture = MbindDiagnosticCapture {
            count: AtomicUsize::new(0),
            expected_body: AtomicBool::new(false),
            _no_alias: UnsafeCell::new(()),
        };
        // SAFETY: the test retains the capture and serializes this one custom
        // registration/delivery sequence.
        unsafe {
            output.register_output(
                Some(capture_mbind_diagnostic as OutputCallback),
                &capture as *const MbindDiagnosticCapture as *mut c_void,
            )
        };
        // Source custom registration flushes even its empty delayed image.
        // Count only the physical failed-mbind route below.
        capture.count.store(0, Ordering::Release);
        capture.expected_body.store(false, Ordering::Release);

        let fault = fault::install(fault::Plan::at(fault::Point::NumaBind, 1, Errno::from_raw(4095).unwrap()));
        let policy = VmPolicy::defaults_for_test();
        let subprocess = crate::subproc::MainSubprocess::test_static_owner();
        let process = VmProcess::new(&policy, subprocess);
        let config = MemoryConfig::from_observations(
            PageSize::new(4096).unwrap(), 1 << 20, true, false,
        );
        let page = config.page_size().bytes();
        let mut mapping = Mapping::map_for_process(
            process, config, page, 1, MapAccess::Committed, false, None,
        ).expect("receiver witness begins with one live mapping");
        let base = mapping.base().expect("mapping remains live before mbind");

        apply_huge_page_numa_preference_with_mbind_warning(base, 62, MbindWarningRoute::new(&output));
        assert_eq!(fault.observed(), 1, "the valid source node attempts exactly one mbind");
        assert_eq!(mapping.base(), Ok(base), "failed mbind leaves the mapping owner intact");
        assert_eq!(capture.count.load(Ordering::Acquire), 2, "warning prefix and source body stay separate deliveries");
        assert!(capture.expected_body.load(Ordering::Acquire));

        capture.count.store(0, Ordering::Release);
        fault.set(fault::Plan::at(fault::Point::NumaBind, 1, Errno::PERM));
        apply_huge_page_numa_preference_with_mbind_warning(base, 63, MbindWarningRoute::new(&output));
        assert_eq!(fault.observed(), 0, "node 63 is outside the 64-bit source receiver domain");
        assert_eq!(capture.count.load(Ordering::Acquire), 0, "invalid node has no output delivery");
        assert_eq!(mapping.base(), Ok(base));
        drop(fault);
        mapping.unmap_for_process(process, page, true).expect("the retained owner still releases normally");
    }

    /// Drives the actual private `prim.c:630-645` receiver with one live
    /// source-owned mapping. The selected fault seam supplies the syscall
    /// failure; this helper preserves the mapping and statistic observations
    /// around that exact call instead of synthesizing a warning directly.
    #[cfg(target_arch = "x86_64")]
    fn m2_fault_diagnostic_relation_mapping(
        output: &OutputOwner,
        numa_node: i32,
    ) -> bool {
        let policy = VmPolicy::defaults_for_test();
        let subprocess = crate::subproc::MainSubprocess::test_static_owner();
        let process = VmProcess::new(&policy, subprocess);
        let config = MemoryConfig::from_observations(
            PageSize::new(4096).unwrap(), 1 << 20, true, false,
        );
        let page = config.page_size().bytes();
        let mut mapping = Mapping::map_for_process(
            process, config, page, 1, MapAccess::Committed, false, None,
        ).expect("fault-diagnostic relation begins with one explicit mapping owner");
        let base = mapping.base().expect("fault-diagnostic mapping is live before mbind");
        let before = subprocess.vm_statistics().snapshot();
        apply_huge_page_numa_preference_with_mbind_warning(
            base, numa_node, MbindWarningRoute::new(output),
        );
        let survives = mapping.base() == Ok(base) && subprocess.vm_statistics().snapshot() == before;
        mapping.unmap_for_process(process, page, true)
            .expect("best-effort mbind leaves the mapping owner releasable");
        survives
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

    /// Executes one finite direct source case without mutating the test process.
    /// C observes continuation from void `_mi_prim_mem_init`; Rust separately
    /// exposes its typed outcome before the production owner discards it.
    fn thp_direct_policy_case_witness(
        selected_case: fault::ThpDirectPolicyCase, initial_thp: bool,
    ) -> bool {
        let fault = fault::install(fault::Plan::disabled());
        let mut options = VmOptions::uninitialized();
        options.set(
            VmOption::AllowThp,
            if selected_case.allow_enabled() { 1 } else { 0 },
        );
        options.initialize_all(|_| VmOptionEnvironment::Absent);
        let policy = VmPolicy::new(options).expect("the selected source option image resolves");
        let mut config = MemoryConfig::from_observations(
            PageSize::new(4 * 1024).expect("four KiB is the selected Linux page size"),
            0,
            true,
            initial_thp,
        );
        let capture = fault.capture_thp_direct_policy_case(selected_case);
        let outcome = policy.apply_thp_process_policy(&mut config);
        let attempts = capture.attempts();
        drop(capture);

        let exact_attempts = match (selected_case, attempts) {
            (fault::ThpDirectPolicyCase::AllowEnabled, Some((_, 0))) => true,
            (fault::ThpDirectPolicyCase::QueryPerm, Some((attempts, 1)))
            | (fault::ThpDirectPolicyCase::QueryInval, Some((attempts, 1)))
            | (fault::ThpDirectPolicyCase::QueryNonzeroOne, Some((attempts, 1)))
            | (fault::ThpDirectPolicyCase::QueryNonzeroThree, Some((attempts, 1))) => {
                attempts[0] == (PR_GET_THP_DISABLE, [0, 0, 0, 0])
            }
            (fault::ThpDirectPolicyCase::SetSuccess, Some((attempts, 2)))
            | (fault::ThpDirectPolicyCase::SetPerm, Some((attempts, 2)))
            | (fault::ThpDirectPolicyCase::SetInval, Some((attempts, 2))) => {
                attempts
                    == [
                        (PR_GET_THP_DISABLE, [0, 0, 0, 0]),
                        (PR_SET_THP_DISABLE, [1, 0, 0, 0]),
                    ]
            }
            _ => false,
        };
        let exact_outcome = matches!(
            (selected_case, outcome),
            (fault::ThpDirectPolicyCase::AllowEnabled, ThpPolicyOutcome::Allowed)
                | (fault::ThpDirectPolicyCase::QueryPerm, ThpPolicyOutcome::DisabledQueryFailed(Errno::PERM))
                | (fault::ThpDirectPolicyCase::QueryInval, ThpPolicyOutcome::DisabledQueryFailed(Errno::INVAL))
                | (fault::ThpDirectPolicyCase::QueryNonzeroOne, ThpPolicyOutcome::DisabledAlready(1))
                | (fault::ThpDirectPolicyCase::QueryNonzeroThree, ThpPolicyOutcome::DisabledAlready(3))
                | (fault::ThpDirectPolicyCase::SetSuccess, ThpPolicyOutcome::DisabledSet)
                | (fault::ThpDirectPolicyCase::SetPerm, ThpPolicyOutcome::DisabledSetFailed(Errno::PERM))
                | (fault::ThpDirectPolicyCase::SetInval, ThpPolicyOutcome::DisabledSetFailed(Errno::INVAL))
        );
        exact_attempts
            && exact_outcome
            && if selected_case.allow_enabled() {
                config.has_transparent_huge_pages() == initial_thp
            } else {
                !config.has_transparent_huge_pages()
            }
    }

    fn thp_direct_policy_outcome_trace() -> [bool; 8] {
        use fault::ThpDirectPolicyCase as Case;
        [
            thp_direct_policy_case_witness(Case::AllowEnabled, true)
                && thp_direct_policy_case_witness(Case::AllowEnabled, false),
            thp_direct_policy_case_witness(Case::QueryPerm, true),
            thp_direct_policy_case_witness(Case::QueryInval, true),
            thp_direct_policy_case_witness(Case::QueryNonzeroOne, true),
            thp_direct_policy_case_witness(Case::QueryNonzeroThree, true),
            thp_direct_policy_case_witness(Case::SetSuccess, true),
            thp_direct_policy_case_witness(Case::SetPerm, true),
            thp_direct_policy_case_witness(Case::SetInval, true),
        ]
    }

    #[test]
    fn thp_direct_policy_outcome_matrix() {
        assert_eq!(thp_direct_policy_outcome_trace(), [true; 8]);
    }

    #[test]
    fn thp_direct_policy_allow_enabled_preserves_both_synthetic_configurations() {
        use fault::ThpDirectPolicyCase as Case;
        assert!(thp_direct_policy_case_witness(Case::AllowEnabled, true));
        assert!(thp_direct_policy_case_witness(Case::AllowEnabled, false));
    }

    #[test]
    fn thp_direct_policy_query_perm_has_no_set_and_preserves_errno() {
        assert!(thp_direct_policy_case_witness(fault::ThpDirectPolicyCase::QueryPerm, true));
    }

    #[test]
    fn thp_direct_policy_query_inval_has_no_set_and_preserves_errno() {
        assert!(thp_direct_policy_case_witness(fault::ThpDirectPolicyCase::QueryInval, true));
    }

    #[test]
    fn thp_direct_policy_query_nonzero_one_has_no_set() {
        assert!(thp_direct_policy_case_witness(
            fault::ThpDirectPolicyCase::QueryNonzeroOne,
            true,
        ));
    }

    #[test]
    fn thp_direct_policy_query_nonzero_three_is_raw_return_class_only() {
        assert!(thp_direct_policy_case_witness(
            fault::ThpDirectPolicyCase::QueryNonzeroThree,
            true,
        ));
    }

    #[test]
    fn thp_direct_policy_set_success_uses_exact_get_set_pair() {
        assert!(thp_direct_policy_case_witness(fault::ThpDirectPolicyCase::SetSuccess, true));
    }

    #[test]
    fn thp_direct_policy_set_perm_preserves_errno() {
        assert!(thp_direct_policy_case_witness(fault::ThpDirectPolicyCase::SetPerm, true));
    }

    #[test]
    fn thp_direct_policy_set_inval_preserves_errno() {
        assert!(thp_direct_policy_case_witness(fault::ThpDirectPolicyCase::SetInval, true));
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
    fn vm_policy_exposes_destroy_on_exit_raw_for_the_process_finalization_owner() {
        for raw in [0, 1, 2, 9, -7] {
            let mut options = VmOptions::uninitialized();
            options.initialize_all(|_| VmOptionEnvironment::Absent);
            options.set(VmOption::DestroyOnExit, raw);
            let policy = VmPolicy::new(options)
                .expect("the selected source option image resolves before finalization observes it");

            assert_eq!(
                policy.destroy_on_exit_raw(),
                raw,
                "the policy must not flatten source zero, nonzero, or automatic-finalization values"
            );
        }
    }

    #[test]
    fn process_done_preloading_keeps_a_live_mapping_and_selects_reset_purge() {
        let fault = fault::install(fault::Plan::disabled());
        let config = MemoryConfig::detect(current_startup());
        let page = config.page_size().bytes();
        let mut options = VmOptions::uninitialized();
        options.initialize_all(|_| VmOptionEnvironment::Absent);
        options.set(VmOption::PurgeDelay, 0);
        options.set(VmOption::PurgeDecommits, 1);
        let policy = VmPolicy::new(options)
            .expect("the process-done purge receiver owns a resolved source option image");
        policy.finish_preloading();
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
        .expect("the process-done receiver begins with one live mapping");
        let base = mapping.base().expect("the receiver mapping is live before process done");
        let before = subprocess.vm_statistics().snapshot();

        policy.enter_process_done_preloading();

        assert!(policy.is_preloading(), "process-done re-enters source preloading");
        assert_eq!(
            mapping.purge_for_process(process, 0, page, true, page),
            Ok(false),
            "post-process-done source purge reports no recommit requirement"
        );
        let after = subprocess.vm_statistics().snapshot();
        assert_eq!(mapping.base(), Ok(base), "reset retains the source mapping owner");
        assert_eq!(after.purge_calls, before.purge_calls + 1);
        assert_eq!(after.purged, before.purged + page as i64);
        assert_eq!(after.reset_calls, before.reset_calls + 1,
            "terminal preloading selects the reset arm instead of decommit");
        assert_eq!(after.reset, before.reset + page as i64);
        mapping
            .unmap_for_process(process, page, false)
            .expect("the reset mapping remains releasable");
        drop(fault);
    }

    /// Exercises the selected normal-release `_mi_os_get_aligned_hint` matrix
    /// through the real typed policy cursor and initialized Theap random
    /// image. The C companion uses the same geometry and emits these five
    /// address-free relations from its direct source body.
    #[cfg(not(miri))]
    fn normal_release_aligned_hint_matrix() -> [bool; 5] {
        std::thread::spawn(|| {
            let config = MemoryConfig::from_observations(
                PageSize::new(4 * 1024).expect("four KiB is the selected Linux page size"),
                0,
                true,
                false,
            );
            let page = config.page_size().bytes();
            let alignment = 2 * MIB;
            let request = VmPolicy::test_aligned_hint_request_size(config, alignment, page)
                .expect("the bounded source request fits");

            // Preserve the source-valid cold state. `TheapRandomImage::empty_weak`
            // represents `_mi_theap_empty.random`; no initializer, status write,
            // or deterministic output staging occurs before these two calls. The
            // source refuses that default image only on its zero-cursor first
            // fetch: its second fetch returns the already advanced raw hint.
            let cold = VmPolicy::defaults_for_test();
            let mut cold_random = TheapRandomImage::empty_weak();
            let cold_first = cold.aligned_hint(config, alignment, page, Some(&mut cold_random));
            let cold_cursor_after_first = cold.test_aligned_hint_cursor();
            let cold_second = cold.aligned_hint(config, alignment, page, Some(&mut cold_random));
            let cold_cursor_after_second = cold.test_aligned_hint_cursor();
            let cold_missing_default_advances = !cold_random.is_initialized()
                && cold_first.is_none()
                && cold_cursor_after_first == request
                && cold_second == Some(request)
                && cold_cursor_after_second == request * 2;

            // Construct the actual initialized default Theap through its existing
            // process-static attachment receiver. The dedicated thread owns its
            // compiler-TLS roots through teardown, while each policy below owns
            // an independent source cursor. No bare test random image represents
            // the normal initialized branch.
            let storage = crate::main_theap::MainStaticAttachmentStorage::test_static_owner();
            let subprocess = crate::subproc::MainSubprocess::test_static_owner();
            let mut attachment = unsafe {
                crate::main_theap::MainStaticTheapAttachment::begin_with_test_storage(
                    storage, subprocess,
                )
            }
            .expect("the isolated main attachment initializes its source random image");
            // SAFETY: this direct attachment just completed on its dedicated
            // test thread. No READY/page session/later attachment exists, the
            // closure cannot retain the random borrow, and teardown follows.
            let [eligible_geometry, initialized_first_start, strict_threshold_and_one_draw, ignored_cas_failure] = unsafe {
                attachment.with_startup_vm_random(|random| {
                    let random = random.expect("the attached source Theap owns initialized random state");

                    // This ordinary initialized Theap is deliberately not staged.
                    // Its first source call begins at cursor zero, consumes its live
                    // random image, and chooses a start in the normal 2--6 TiB range.
                    let initialized = VmPolicy::defaults_for_test();
                    let initialized_first = initialized.aligned_hint(
                        config,
                        alignment,
                        page,
                        Some(random),
                    );
                    let initialized_cursor = initialized.test_aligned_hint_cursor();
                    let initialized_first_start = initialized_first
                        .map(|hint| {
                            let source_start = initialized_cursor.checked_sub(request);
                            source_start
                                .map(|start| {
                                    start >= HINT_BASE
                                        && start < HINT_BASE + HINT_AREA
                                        && invariants::align_up(start, alignment) == Some(hint)
                                })
                                .unwrap_or(false)
                        })
                        .unwrap_or(false);

                    // Every source eligibility rejection returns before the atomic
                    // cursor. Capture that zero state before the eligible boundary
                    // call, which separately consumes the same live source image.
                    let eligibility = VmPolicy::defaults_for_test();
                    let low_alignment = eligibility.aligned_hint(
                        config,
                        config.alloc_granularity(),
                        page,
                        Some(random),
                    );
                    let excessive_alignment = eligibility.aligned_hint(
                        config,
                        16 * GIB + page,
                        page,
                        Some(random),
                    );
                    let low_vbits_config = MemoryConfig {
                        virtual_address_bits: 45,
                        ..config
                    };
                    let low_vbits = eligibility.aligned_hint(
                        low_vbits_config,
                        alignment,
                        page,
                        Some(random),
                    );
                    let cursor_after_rejections = eligibility.test_aligned_hint_cursor();
                    let exact_max_alignment = eligibility.aligned_hint(
                        config,
                        16 * GIB,
                        page,
                        Some(random),
                    );
                    let eligible_geometry = low_alignment.is_none()
                        && excessive_alignment.is_none()
                        && low_vbits.is_none()
                        && cursor_after_rejections == 0
                        && exact_max_alignment.is_some();

                    // Only after a real initialized-Theap first consumption and
                    // eligibility record, stage that same source image's output
                    // buffer. `1` and `2` make these two one-draw paths exact.
                    random.test_stage_buffered_nexts(1, 2);
                    let threshold = VmPolicy::defaults_for_test();
                    let initial = threshold
                        .aligned_hint(config, alignment, page, Some(random))
                        .expect("the staged initialized source image chooses its initial hint");
                    let cursor_after_initial = threshold.test_aligned_hint_cursor();
                    let to_exact_max = HINT_MAX
                        .checked_sub(cursor_after_initial)
                        .expect("the initialized normal hint begins below the max cursor");
                    let exact_max_size = to_exact_max
                        .checked_sub(page)
                        .and_then(|size| size.checked_sub(alignment - 1))
                        .expect("the bounded source request can reach the strict max cursor");
                    assert_eq!(
                        VmPolicy::test_aligned_hint_request_size(config, alignment, exact_max_size),
                        Some(to_exact_max),
                        "the source request reaches exactly MI_HINT_MAX without a direct cursor write"
                    );
                    let advance_to_max = threshold.aligned_hint(
                        config,
                        alignment,
                        exact_max_size,
                        Some(random),
                    );
                    let cursor_at_max = threshold.test_aligned_hint_cursor();
                    let equality_hint = threshold.aligned_hint(
                        config,
                        alignment,
                        page,
                        Some(random),
                    );
                    let cursor_after_equality = threshold.test_aligned_hint_cursor();
                    let wrapped_hint = threshold.aligned_hint(
                        config,
                        alignment,
                        page,
                        Some(random),
                    );
                    let strict_threshold_and_one_draw = initial == HINT_BASE
                        && advance_to_max.is_some()
                        && cursor_at_max == HINT_MAX
                        && equality_hint == Some(HINT_MAX)
                        && cursor_after_equality == HINT_MAX + request
                        && wrapped_hint == Some(HINT_BASE)
                        && random.test_output_available() == 12;

                    // The source deliberately ignores the result of its one strong
                    // CAS. Reset only this actual initialized image's consumed
                    // output buffer, then let one helper make the real competing
                    // AcqRel increment between source fetch and CAS.
                    random.test_stage_buffered_nexts(1, 2);
                    let contested = VmPolicy::defaults_for_test();
                    contested.test_arm_aligned_hint_competitor();
                    let (contested_hint, competitor_old) = std::thread::scope(|scope| {
                        let helper = scope.spawn(|| {
                            contested.test_complete_aligned_hint_competitor(request)
                        });
                        let hint = contested.aligned_hint(
                            config,
                            alignment,
                            page,
                            Some(random),
                        );
                        (hint, helper.join().expect("the controlled cursor competitor completes"))
                    });
                    let ignored_cas_failure = competitor_old == request
                        && contested_hint == Some(request * 2)
                        && contested.test_aligned_hint_cursor() == request * 3
                        && random.test_output_available() == 14;

                    [
                        eligible_geometry,
                        initialized_first_start,
                        strict_threshold_and_one_draw,
                        ignored_cas_failure,
                    ]
                })
            };
            attachment
                .teardown()
                .expect("the dedicated source attachment tears down after the matrix");

            [
                cold_missing_default_advances,
                eligible_geometry,
                initialized_first_start,
                strict_threshold_and_one_draw,
                ignored_cas_failure,
            ]
        })
        .join()
        .expect("the isolated aligned-hint matrix thread completes")
    }

    #[cfg(not(miri))]
    #[test]
    fn normal_release_aligned_hint_matrix_preserves_source_cursor_random_and_cas_rules() {
        assert_eq!(normal_release_aligned_hint_matrix(), [true; 5]);
    }

    /// Covers the two compile-time source selections that the fixed release
    /// build does not execute. They remain private source-profile evidence:
    /// this crate neither exposes nor claims a secure/debug runtime mode.
    #[cfg(not(miri))]
    fn aligned_hint_source_profile_matrix() -> [bool; 4] {
        std::thread::spawn(|| {
            let config = MemoryConfig::from_observations(
                PageSize::new(4 * 1024).expect("four KiB is the selected Linux page size"),
                0,
                true,
                false,
            );
            let page = config.page_size().bytes();
            let alignment = 2 * MIB;
            let request = VmPolicy::test_aligned_hint_request_size(config, alignment, page)
                .expect("the selected profile request fits");

            // `MI_SECURE=0, MI_DEBUG=1` compiles out the source's default
            // Theap/random block. It still makes the first atomic initialize
            // at HINT_BASE, so supplying no image is an observable contract.
            let debug = VmPolicy::defaults_for_test();
            let debug_hint = debug.aligned_hint_for_source_profile(
                config,
                alignment,
                page,
                None,
                AlignedHintSourceProfile::source_test(false, true),
            );
            let fixed_debug_without_random = debug_hint == Some(HINT_BASE)
                && debug.test_aligned_hint_cursor() == HINT_BASE + request;

            // Security overrides debug: an uninitialized/missing default
            // image consumes the first cursor increment then returns no hint,
            // just like the normal release random branch.
            let secure_cold = VmPolicy::defaults_for_test();
            let secure_cold_hint = secure_cold.aligned_hint_for_source_profile(
                config,
                alignment,
                page,
                None,
                AlignedHintSourceProfile::source_test(true, true),
            );
            let secure_debug_requires_random = secure_cold_hint.is_none()
                && secure_cold.test_aligned_hint_cursor() == request;

            // The secure bound is before the atomic/random branch. Choose
            // exact inputs for which source wrapping/alignment produces the
            // 32-GiB boundary and then exceeds it by one base page.
            let secure_boundary_size = 32 * GIB - alignment - page;
            let secure_boundary_request = VmPolicy::test_aligned_hint_request_size(
                config,
                alignment,
                secure_boundary_size,
            );
            let secure_oversized = VmPolicy::defaults_for_test();
            let secure_oversized_hint = secure_oversized.aligned_hint_for_source_profile(
                config,
                alignment,
                secure_boundary_size + page,
                None,
                AlignedHintSourceProfile::source_test(true, false),
            );
            let secure_oversized_skips_cursor_and_random = secure_boundary_request == Some(32 * GIB)
                && secure_oversized_hint.is_none()
                && secure_oversized.test_aligned_hint_cursor() == 0;

            let storage = crate::main_theap::MainStaticAttachmentStorage::test_static_owner();
            let subprocess = crate::subproc::MainSubprocess::test_static_owner();
            let mut attachment = unsafe {
                crate::main_theap::MainStaticTheapAttachment::begin_with_test_storage(
                    storage, subprocess,
                )
            }
            .expect("the isolated main attachment initializes its source random image");
            // SAFETY: the dedicated thread owns this just-created attachment,
            // has not published READY/page state, retains no random alias,
            // and tears the attachment down immediately after this operation.
            let secure_boundary_randomizes = unsafe {
                attachment.with_startup_vm_random(|random| {
                    let random = random.expect("the source attachment owns initialized random state");
                    random.test_stage_buffered_nexts(1, 2);
                    let secure = VmPolicy::defaults_for_test();
                    let hint = secure.aligned_hint_for_source_profile(
                        config,
                        alignment,
                        secure_boundary_size,
                        Some(random),
                        AlignedHintSourceProfile::source_test(true, true),
                    );
                    hint == Some(HINT_BASE)
                        && secure.test_aligned_hint_cursor() == HINT_BASE + 32 * GIB
                        && random.test_output_available() == 14
                })
            };
            attachment
                .teardown()
                .expect("the source-profile attachment tears down on its dedicated thread");

            [
                fixed_debug_without_random,
                secure_debug_requires_random,
                secure_oversized_skips_cursor_and_random,
                secure_boundary_randomizes,
            ]
        })
        .join()
        .expect("the isolated source-profile matrix thread completes")
    }

    #[cfg(not(miri))]
    #[test]
    fn aligned_hint_source_profiles_preserve_debug_and_secure_compile_predicates() {
        assert_eq!(aligned_hint_source_profile_matrix(), [true; 4]);
        assert!(AlignedHintSourceProfile::FIXED_NORMAL_RELEASE.requires_default_random());
        assert!(!AlignedHintSourceProfile::FIXED_NORMAL_RELEASE.rejects_request_size(usize::MAX));
    }

    /// A normal typed map admits a page-multiple length whose source hint
    /// request wraps. The source still advances/randomizes and hands its
    /// opaque hint to Unix mmap before Linux rejects that impossible map.
    /// Keep that pre-mmap cursor behavior instead of treating checked Rust
    /// arithmetic as proof that the direct source caller rejected the input.
    #[cfg(not(miri))]
    fn aligned_hint_wrapped_direct_caller_matrix() -> bool {
        std::thread::spawn(|| {
            let fault = fault::install(fault::Plan::disabled());
            let config = MemoryConfig::from_observations(
                PageSize::new(4 * 1024).expect("four KiB is the selected Linux page size"),
                0,
                true,
                false,
            );
            let page = config.page_size().bytes();
            let alignment = 2 * MIB;
            let length = usize::MAX & !(page - 1);
            assert_eq!(length.wrapping_add(page), 0, "the direct caller receives a page-multiple wrap witness");
            assert_eq!(
                source_align_up_wrapping(
                    length.wrapping_add(page).wrapping_add(alignment - 1),
                    config.large_page_size(),
                ),
                Some(alignment),
                "the source request wraps to one large-page cursor increment"
            );

            let policy = VmPolicy::defaults_for_test();
            let subprocess = crate::subproc::MainSubprocess::test_static_owner();
            let process = VmProcess::new(&policy, subprocess);
            let storage = crate::main_theap::MainStaticAttachmentStorage::test_static_owner();
            let mut attachment = unsafe {
                crate::main_theap::MainStaticTheapAttachment::begin_with_test_storage(
                    storage, subprocess,
                )
            }
            .expect("the isolated attachment owns the direct caller random image");
            // SAFETY: this direct source attachment is current on the test
            // thread and has not reached READY/page publication. The closure
            // retains no random alias; the map has no owner on its expected
            // raw mmap failure and teardown follows immediately.
            let (mapping_failed, cursor, output_available, attempts) = unsafe {
                attachment.with_startup_vm_random(|random| {
                    let random = random.expect("the attached default Theap is initialized");
                    random.test_stage_buffered_nexts(1, 2);
                    let capture = fault.capture_policy_mmaps();
                    let result = Mapping::map_for_process(
                        process,
                        config,
                        length,
                        alignment,
                        MapAccess::Reserved,
                        false,
                        Some(random),
                    );
                    let attempts = capture.attempts();
                    (
                        result.is_err(),
                        policy.test_aligned_hint_cursor(),
                        random.test_output_available(),
                        attempts,
                    )
                })
            };
            attachment
                .teardown()
                .expect("the direct caller attachment tears down after raw mmap failure");

            let (attempts, count) = attempts.expect("the bounded Unix mmap capture stays complete");
            assert!(mapping_failed, "Linux rejects the impossible mapping after the source hint side effect");
            assert_eq!(cursor, HINT_BASE + alignment);
            assert_eq!(output_available, 14, "one source public random draw feeds the wrapped initial cursor");
            assert_eq!(count, 2, "a failed source-hinted mmap retries the pinned null-address mmap");
            assert_eq!(attempts[0].hint, Some(HINT_BASE));
            assert_eq!(attempts[1].hint, None);
        })
        .join()
        .expect("the wrapped direct-caller fixture remains current-thread local");
        true
    }

    #[cfg(not(miri))]
    #[test]
    fn aligned_hint_wrapping_request_reaches_the_typed_unix_caller_before_map_failure() {
        assert!(aligned_hint_wrapped_direct_caller_matrix());
    }

    /// Emits the finite preprocessor-selected aligned-hint source profile
    /// records. The private profile predicate above is only a translation
    /// seam: this test does not enable a debug or secure runtime mode.
    #[cfg(not(miri))]
    #[test]
    fn emit_m2_aligned_hint_source_profile_c_rust_trace() {
        let [
            debug_without_default_random,
            secure_requires_default_random,
            secure_oversized_skips_cursor_and_random,
            secure_exact_boundary_randomizes,
        ] = aligned_hint_source_profile_matrix();
        let wrapped_direct_caller_hint_then_null_without_owner =
            aligned_hint_wrapped_direct_caller_matrix();
        assert!(
            debug_without_default_random
                && secure_requires_default_random
                && secure_oversized_skips_cursor_and_random
                && secure_exact_boundary_randomizes
                && wrapped_direct_caller_hint_then_null_without_owner,
            "the C/Rust source-profile matrix requires every selected source relation"
        );
        macro_rules! emit {
            ($key:literal, $value:expr) => {
                std::println!("{}={}", $key, u8::from($value));
            };
        }
        std::println!("CRABC_MI_M2_ALIGNED_HINT_SOURCE_PROFILE_TRACE_BEGIN");
        emit!(
            "m2.vm.aligned_hint.profile.debug_without_default_random",
            debug_without_default_random
        );
        emit!(
            "m2.vm.aligned_hint.profile.secure_requires_default_random",
            secure_requires_default_random
        );
        emit!(
            "m2.vm.aligned_hint.profile.secure_oversized_skips_cursor_and_random",
            secure_oversized_skips_cursor_and_random
        );
        emit!(
            "m2.vm.aligned_hint.profile.secure_exact_boundary_randomizes",
            secure_exact_boundary_randomizes
        );
        emit!(
            "m2.vm.aligned_hint.profile.wrapped_direct_caller_hint_then_null_without_owner",
            wrapped_direct_caller_hint_then_null_without_owner
        );
        std::println!("CRABC_MI_M2_ALIGNED_HINT_SOURCE_PROFILE_TRACE_END");
    }

    #[cfg(not(miri))]
    #[test]
    fn source_aligned_hint_retries_failed_large_mmap_at_null_before_fresh_regular_fallback() {
        let fault = fault::install(fault::Plan::at_pair(
            fault::Point::LargeMap,
            1,
            fault::Point::LargeMap,
            1,
            Errno::NOMEM,
        ));
        let config = MemoryConfig::from_observations(
            PageSize::new(4 * 1024).expect("four KiB is one selected Linux page size"),
            0,
            true,
            true,
        );
        let mut policy = VmPolicy::defaults_for_test();
        policy.set_option(VmOption::AllowLargeOsPages, 1);
        policy.set_option(VmOption::AllowThp, 1);
        let subprocess = crate::subproc::MainSubprocess::test_static_owner();
        let process = VmProcess::new(&policy, subprocess);
        let mut random = TheapRandomImage::empty_weak();
        random.initialize_weak();
        let length = 8 * config.large_page_size();
        let capture = fault.capture_policy_mmaps();

        let mut mapping = Mapping::map_for_process(
            process,
            config,
            length,
            config.large_page_size(),
            MapAccess::Committed,
            true,
            Some(&mut random),
        )
        .expect("two failed huge attempts fall through to one regular source map");
        let (attempts, count) = capture
            .attempts()
            .expect("the three bounded source mmap attempts fit the capture");
        assert_eq!(count, 3);
        assert!(attempts[0].hint.is_some(), "the first huge map uses the source high hint");
        assert_ne!(attempts[0].flags & MAP_HUGETLB, 0);
        assert_eq!(attempts[1].hint, None, "a failed source aligned hint retries at null");
        assert_eq!(attempts[1].flags, attempts[0].flags);
        let first_hint = attempts[0]
            .hint
            .expect("the first large map retains its source-aligned hint");
        let regular_hint = attempts[2]
            .hint
            .expect("the regular fallback derives a fresh source-aligned hint");
        assert_ne!(regular_hint, first_hint);
        assert_eq!(attempts[2].flags & MAP_HUGETLB, 0);
        assert_eq!(fault.observed(), 2);
        assert_eq!(fault.secondary_observed(), 1);
        assert!(!mapping.is_large());
        drop(capture);
        mapping
            .unmap_for_process(process, length, false)
            .expect("the regular fallback retains its complete process owner");
    }

    /// Runs one normal-release `unix_mmap` policy call through the typed
    /// owner and checks the raw source selection sequence before the owner is
    /// explicitly released. A selected large-page failure is injected only at
    /// the raw huge-map import, so the pinned policy still chooses its
    /// ordinary fallback and no successful hardware huge-page claim is
    /// represented by this test. The initialized random image is a direct VM
    /// policy input for this fixture, never a claim about a runtime
    /// default-Theap caller or attachment owner.
    #[cfg(not(miri))]
    fn large_page_retry_regular_owner(
        fault: &fault::Guard,
        policy: &VmPolicy,
        config: MemoryConfig,
        length: usize,
        try_alignment: usize,
        allow_large: bool,
        random: &mut TheapRandomImage,
        expected_huge_attempts: usize,
    ) -> bool {
        let capture = fault.capture_policy_mmaps();
        let mut mapping = match Mapping::map_for_allocator_with_policy(
            policy,
            config,
            length,
            try_alignment,
            MapAccess::Committed,
            allow_large,
            Some(random),
        ) {
            Ok(mapping) => mapping,
            Err(_) => return false,
        };
        let Some((attempts, count)) = capture.attempts() else {
            return false;
        };
        let huge_attempts = attempts[..count]
            .iter()
            .filter(|attempt| attempt.uses_huge_page_flag())
            .count();
        let regular_attempts = count.checked_sub(huge_attempts);
        let source_huge_then_null = expected_huge_attempts == 0
            || (count == 3
                && attempts[0].uses_huge_page_flag()
                && attempts[0].hint.is_some()
                && attempts[1].uses_huge_page_flag()
                && attempts[1].hint.is_none()
                && !attempts[2].uses_huge_page_flag());
        let has_regular_owner = mapping.base().is_ok()
            && mapping.length() == Ok(length)
            && !mapping.is_large();
        drop(capture);
        let released = mapping.unmap().is_ok() && mapping.base().is_err();
        huge_attempts == expected_huge_attempts
            && regular_attempts == Some(1)
            && source_huge_then_null
            && has_regular_owner
            && released
    }

    /// Covers the normal-release retry-suppression lifetime in pinned
    /// `src/prim/unix/prim.c:401-486`: one failed large attempt stores eight,
    /// each eligible ordinary call consumes one count while still returning a
    /// regular owner, and the ninth call retries the large map. The three
    /// excluded predicates below must not read or decrement that state.
    #[cfg(not(miri))]
    fn normal_release_large_page_retry_suppression_matrix() -> [bool; 6] {
        let fault = fault::install(fault::Plan::disabled());
        let config = MemoryConfig::from_observations(
            PageSize::new(4 * 1024).expect("four KiB is one selected Linux page size"),
            0,
            true,
            true,
        );
        let large = config.large_page_size();
        let length = 8 * large;
        let mut policy = VmPolicy::defaults_for_test();
        policy.set_option(VmOption::AllowLargeOsPages, 1);
        policy.set_option(VmOption::AllowThp, 0);
        let mut random = TheapRandomImage::empty_weak();
        random.initialize_weak();

        fault.set(fault::Plan::at_pair(
            fault::Point::LargeMap,
            1,
            fault::Point::LargeMap,
            1,
            Errno::NOMEM,
        ));
        let initial_failure_starts_suppression = large_page_retry_regular_owner(
            &fault,
            &policy,
            config,
            length,
            large,
            true,
            &mut random,
            2,
        ) && fault.observed() == 2
            && fault.secondary_observed() == 1
            && policy.large_page_try_ok.load(Ordering::Acquire)
                == LARGE_PAGE_FAILED_RETRY_COUNT;
        fault.set(fault::Plan::disabled());

        let caller_disables_large_without_consuming_suppression = large_page_retry_regular_owner(
            &fault,
            &policy,
            config,
            length,
            large,
            false,
            &mut random,
            0,
        ) && policy.large_page_try_ok.load(Ordering::Acquire)
                == LARGE_PAGE_FAILED_RETRY_COUNT;

        let ineligible_geometry_without_consuming_suppression = large_page_retry_regular_owner(
            &fault,
            &policy,
            config,
            large,
            config.page_size().bytes(),
            true,
            &mut random,
            0,
        ) && policy.large_page_try_ok.load(Ordering::Acquire)
                == LARGE_PAGE_FAILED_RETRY_COUNT;

        policy.set_option(VmOption::AllowLargeOsPages, 0);
        let option_disables_large_without_consuming_suppression = large_page_retry_regular_owner(
            &fault,
            &policy,
            config,
            length,
            large,
            true,
            &mut random,
            0,
        ) && policy.large_page_try_ok.load(Ordering::Acquire)
                == LARGE_PAGE_FAILED_RETRY_COUNT;
        policy.set_option(VmOption::AllowLargeOsPages, 1);

        let mut eight_suppressed_regular_owners = true;
        for remaining in (0..LARGE_PAGE_FAILED_RETRY_COUNT).rev() {
            eight_suppressed_regular_owners &= large_page_retry_regular_owner(
                &fault,
                &policy,
                config,
                length,
                large,
                true,
                &mut random,
                0,
            ) && policy.large_page_try_ok.load(Ordering::Acquire) == remaining;
        }

        fault.set(fault::Plan::at_pair(
            fault::Point::LargeMap,
            1,
            fault::Point::LargeMap,
            1,
            Errno::NOMEM,
        ));
        let ninth_reopens_large_and_returns_regular_owner = large_page_retry_regular_owner(
            &fault,
            &policy,
            config,
            length,
            large,
            true,
            &mut random,
            2,
        ) && fault.observed() == 2
            && fault.secondary_observed() == 1
            && policy.large_page_try_ok.load(Ordering::Acquire)
                == LARGE_PAGE_FAILED_RETRY_COUNT;

        [
            initial_failure_starts_suppression,
            caller_disables_large_without_consuming_suppression,
            ineligible_geometry_without_consuming_suppression,
            option_disables_large_without_consuming_suppression,
            eight_suppressed_regular_owners,
            ninth_reopens_large_and_returns_regular_owner,
        ]
    }

    /// Repeats the bounded normal sequence with one actual competitor between
    /// the source retry-count load and its ignored strong CAS. The winning
    /// competitor leaves seven source decrements before the next large retry;
    /// every selected mapping remains a regular owner until explicit release.
    #[cfg(not(miri))]
    fn normal_release_large_page_retry_competing_cas_matrix() -> [bool; 2] {
        let fault = fault::install(fault::Plan::disabled());
        let config = MemoryConfig::from_observations(
            PageSize::new(4 * 1024).expect("four KiB is one selected Linux page size"),
            0,
            true,
            true,
        );
        let large = config.large_page_size();
        let length = 8 * large;
        let mut policy = VmPolicy::defaults_for_test();
        policy.set_option(VmOption::AllowLargeOsPages, 1);
        policy.set_option(VmOption::AllowThp, 0);
        let mut random = TheapRandomImage::empty_weak();
        random.initialize_weak();

        fault.set(fault::Plan::at_pair(
            fault::Point::LargeMap,
            1,
            fault::Point::LargeMap,
            1,
            Errno::NOMEM,
        ));
        let initial_failure = large_page_retry_regular_owner(
            &fault,
            &policy,
            config,
            length,
            large,
            true,
            &mut random,
            2,
        ) && policy.large_page_try_ok.load(Ordering::Acquire)
                == LARGE_PAGE_FAILED_RETRY_COUNT;
        fault.set(fault::Plan::disabled());
        assert!(
            initial_failure
                && policy.large_page_try_ok.load(Ordering::Acquire)
                    == LARGE_PAGE_FAILED_RETRY_COUNT,
            "the competing-CAS schedule requires the source failed-large setup"
        );

        policy.test_arm_large_page_retry_competitor();
        let (competing_regular_owner, competitor_won) = std::thread::scope(|scope| {
            let helper = scope.spawn(|| {
                policy.test_complete_large_page_retry_competitor(
                    LARGE_PAGE_FAILED_RETRY_COUNT,
                )
            });
            let owner = large_page_retry_regular_owner(
                &fault,
                &policy,
                config,
                length,
                large,
                true,
                &mut random,
                0,
            );
            (owner, helper.join().expect("the retry competitor completes"))
        });
        let source_cas_failure_keeps_regular_owner = initial_failure
            && competing_regular_owner
            && competitor_won
            && policy.test_large_page_retry_source_cas_failed()
            && policy.large_page_try_ok.load(Ordering::Acquire)
                == LARGE_PAGE_FAILED_RETRY_COUNT - 1;

        let mut seven_suppressed_regular_owners = true;
        for remaining in (0..LARGE_PAGE_FAILED_RETRY_COUNT - 1).rev() {
            seven_suppressed_regular_owners &= large_page_retry_regular_owner(
                &fault,
                &policy,
                config,
                length,
                large,
                true,
                &mut random,
                0,
            ) && policy.large_page_try_ok.load(Ordering::Acquire) == remaining;
        }

        fault.set(fault::Plan::at_pair(
            fault::Point::LargeMap,
            1,
            fault::Point::LargeMap,
            1,
            Errno::NOMEM,
        ));
        let retry_reopens_after_competing_decrement = seven_suppressed_regular_owners
            && large_page_retry_regular_owner(
                &fault,
                &policy,
                config,
                length,
                large,
                true,
                &mut random,
                2,
            ) && fault.observed() == 2
                && fault.secondary_observed() == 1
                && policy.large_page_try_ok.load(Ordering::Acquire)
                    == LARGE_PAGE_FAILED_RETRY_COUNT;

        [
            source_cas_failure_keeps_regular_owner,
            retry_reopens_after_competing_decrement,
        ]
    }

    #[cfg(not(miri))]
    #[test]
    fn normal_release_large_page_retry_suppression_reopens_after_eight_regular_owners() {
        assert_eq!(normal_release_large_page_retry_suppression_matrix(), [true; 6]);
        assert_eq!(normal_release_large_page_retry_competing_cas_matrix(), [true; 2]);
    }

    /// Covers the terminal large-only source route in
    /// `src/prim/unix/prim.c:401-449` and `src/os.c:771-841`. The first
    /// claimed one-GiB page retries its same explicit claim as a two-MiB
    /// huge map after ENOMEM. The source then retains its unavailable bit, so
    /// the next upper huge allocation attempts only two MiB at its next claim.
    /// Neither upper allocation may create a regular mapping or an ownership
    /// token, and the observed subprocess statistics remain unchanged.
    #[cfg(not(miri))]
    fn large_only_one_gib_failure_terminal_matrix() -> [bool; 4] {
        let fault = fault::install(fault::Plan::at_triple(
            fault::Point::LargeMap,
            1,
            fault::Point::LargeMap,
            1,
            fault::Point::LargeMap,
            1,
            Errno::NOMEM,
        ));
        let config = MemoryConfig::from_observations(
            PageSize::new(4 * 1024).expect("four KiB is one selected Linux page size"),
            0,
            true,
            true,
        );
        let policy = VmPolicy::defaults_for_test();
        let subprocess = crate::subproc::MainSubprocess::test_static_owner();
        let process = VmProcess::new(&policy, subprocess);
        let before = subprocess.vm_statistics().snapshot();
        let capture = fault.capture_policy_mmaps();

        let first = HugeOsAllocation::allocate_for_process(process, config, 1, -1, 0, None);
        let first_fault_observations = (
            fault.observed(),
            fault.secondary_observed(),
            fault.third_observed(),
        );
        let Some((first_attempts, first_count)) = capture.attempts() else {
            return [false; 4];
        };
        let second = HugeOsAllocation::allocate_for_process(process, config, 1, -1, 0, None);
        let Some((attempts, count)) = capture.attempts() else {
            return [false; 4];
        };
        drop(capture);
        let after = subprocess.vm_statistics().snapshot();

        let first_terminal_enomem = matches!(
            first,
            HugeOsAllocationOutcome::Unavailable(HugeOsAllocationStop::PrimitiveMapFailed(
                Errno::NOMEM
            ))
        );
        let second_terminal_enomem = matches!(
            second,
            HugeOsAllocationOutcome::Unavailable(HugeOsAllocationStop::PrimitiveMapFailed(
                Errno::NOMEM
            ))
        );
        let huge_flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB;
        let huge_protection = PROT_READ | PROT_WRITE;
        let first_one_gib_then_two_mib_same_claim = first_count == 2
            && first_attempts[0].hint.is_some()
            && first_attempts[1].hint == first_attempts[0].hint
            && first_attempts[0].length == HUGE_PAGE_SIZE
            && first_attempts[0].protection == huge_protection
            && first_attempts[0].flags == (huge_flags | MAP_HUGE_1GB)
            && first_attempts[1].length == HUGE_PAGE_SIZE
            && first_attempts[1].protection == huge_protection
            && first_attempts[1].flags == (huge_flags | MAP_HUGE_2MB);
        let second_only_two_mib_after_sticky_unavailable = count == 3
            && attempts[2].hint.is_some()
            && attempts[2].hint != attempts[0].hint
            && attempts[2].length == HUGE_PAGE_SIZE
            && attempts[2].protection == huge_protection
            && attempts[2].flags == (huge_flags | MAP_HUGE_2MB);
        let all_raw_maps_are_huge = attempts[..count]
            .iter()
            .all(|attempt| attempt.uses_huge_page_flag());

        [
            first_terminal_enomem
                && first_one_gib_then_two_mib_same_claim
                && first_fault_observations == (2, 1, 0),
            second_terminal_enomem
                && second_only_two_mib_after_sticky_unavailable
                && (fault.observed(), fault.secondary_observed(), fault.third_observed())
                    == (3, 2, 1),
            all_raw_maps_are_huge,
            after == before,
        ]
    }

    #[cfg(not(miri))]
    #[test]
    fn large_only_one_gib_failure_retries_two_mib_once_then_stays_terminal() {
        assert_eq!(large_only_one_gib_failure_terminal_matrix(), [true; 4]);
    }

    #[cfg(not(miri))]
    #[test]
    fn source_thp_advice_failure_does_not_reject_the_regular_policy_mapping() {
        let fault = fault::install(fault::Plan::at(
            fault::Point::Madvise,
            1,
            Errno::NOMEM,
        ));
        let config = MemoryConfig::from_observations(
            PageSize::new(4 * 1024).expect("four KiB is one selected Linux page size"),
            0,
            true,
            true,
        );
        let mut policy = VmPolicy::defaults_for_test();
        policy.set_option(VmOption::AllowLargeOsPages, 0);
        policy.set_option(VmOption::AllowThp, 1);
        let subprocess = crate::subproc::MainSubprocess::test_static_owner();
        let process = VmProcess::new(&policy, subprocess);
        let mut random = TheapRandomImage::empty_weak();
        random.initialize_weak();
        let length = 8 * config.large_page_size();

        let mut mapping = Mapping::map_for_process(
            process,
            config,
            length,
            config.large_page_size(),
            MapAccess::Committed,
            true,
            Some(&mut random),
        )
        .expect("the source ignores a best-effort MADV_HUGEPAGE error");
        assert_eq!(fault.observed(), 1);
        assert!(!mapping.is_large());
        fault.set(fault::Plan::disabled());
        mapping
            .unmap_for_process(process, length, false)
            .expect("the retained regular policy map releases through its process pair");
    }

    #[test]
    fn process_vm_policy_retries_only_unavailable_source_environment_descriptors() {
        let _serial = VM_POLICY_SOURCE_ENVIRONMENT_TEST_LOCK
            .lock()
            .expect("the isolated raw-environment reader test lock is not poisoned");
        let _reset = VmPolicySourceEnvironmentReset;

        const NAME: &[u8] = b"mimalloc_allow_large_os_pages=";
        let mut overlong = [0u8; NAME.len() + 66];
        overlong[..NAME.len()].copy_from_slice(NAME);
        overlong[NAME.len()..NAME.len() + 65].fill(b'1');
        let initial_environment: [*const core::ffi::c_char; 2] = [
            overlong.as_ptr().cast(),
            core::ptr::null(),
        ];
        VM_POLICY_SOURCE_ENVIRONMENT.store(
            initial_environment.as_ptr().cast_mut(),
            Ordering::Release,
        );

        let mut options = VmOptions::uninitialized();
        // SAFETY: the locked test owns a null-terminated stable vector and
        // all selected C strings through this initial source observation.
        unsafe { options.initialize_from_source_environment(initial_environment.as_ptr()) };
        assert_eq!(
            options.state(VmOption::AllowLargeOsPages),
            VmOptionState::Uninitialized,
            "a 65-byte canonical value is the source unavailable result"
        );
        assert_eq!(
            options.state(VmOption::PurgeDelay),
            VmOptionState::Defaulted,
            "the initially absent descriptor must stay terminal across retry"
        );

        // SAFETY: the serialized test reader returns the selected stable
        // environment vector for every policy option read below.
        let policy = unsafe {
            VmPolicy::new_with_source_environment(options, vm_policy_source_environment_for_test)
        }
        .expect("the real source policy retains unresolved raw-environment descriptors");
        assert!(
            !policy.allow_large_os_pages(),
            "an unavailable source read returns its pinned default for this call"
        );
        assert_eq!(
            policy.options().state(VmOption::AllowLargeOsPages),
            VmOptionState::Uninitialized,
            "a repeated unavailable canonical value remains lazy"
        );

        let retry_environment: [*const core::ffi::c_char; 3] = [
            b"mimalloc_allow_large_os_pages=1\0".as_ptr().cast(),
            b"mimalloc_purge_delay=7\0".as_ptr().cast(),
            core::ptr::null(),
        ];
        VM_POLICY_SOURCE_ENVIRONMENT.store(
            retry_environment.as_ptr().cast_mut(),
            Ordering::Release,
        );

        assert_eq!(
            policy.purge_delay_milliseconds(),
            1_000,
            "a descriptor defaulted by the first source read must not observe a later environment mutation"
        );
        assert!(
            policy.allow_large_os_pages(),
            "only the unavailable canonical descriptor retries through the retained source reader"
        );
        let final_options = policy.options();
        assert!(final_options.all_resolved());
        assert_eq!(
            final_options.value(VmOption::AllowLargeOsPages),
            Some(1),
        );
        assert_eq!(final_options.value(VmOption::PurgeDelay), Some(1_000));
    }

    #[test]
    fn process_vm_policy_serializes_concurrent_source_descriptor_retry() {
        let _serial = VM_POLICY_SOURCE_ENVIRONMENT_TEST_LOCK
            .lock()
            .expect("the isolated raw-environment reader test lock is not poisoned");
        let _reset = VmPolicySourceEnvironmentReset;

        const NAME: &[u8] = b"mimalloc_allow_large_os_pages=";
        let mut overlong = [0u8; NAME.len() + 66];
        overlong[..NAME.len()].copy_from_slice(NAME);
        overlong[NAME.len()..NAME.len() + 65].fill(b'1');
        let unavailable_environment: [*const core::ffi::c_char; 2] = [
            overlong.as_ptr().cast(),
            core::ptr::null(),
        ];
        VM_POLICY_SOURCE_ENVIRONMENT.store(
            unavailable_environment.as_ptr().cast_mut(),
            Ordering::Release,
        );

        let mut options = VmOptions::uninitialized();
        // SAFETY: the test lock retains this null-terminated source vector.
        unsafe { options.initialize_from_source_environment(unavailable_environment.as_ptr()) };
        assert_eq!(
            options.state(VmOption::AllowLargeOsPages),
            VmOptionState::Uninitialized
        );
        // SAFETY: every concurrent policy read below observes the selected
        // stable vector while the test lock remains held.
        let policy = unsafe {
            VmPolicy::new_with_source_environment(options, vm_policy_source_environment_for_test)
        }
        .expect("the source policy retains its lazy descriptor");

        let retry_environment: [*const core::ffi::c_char; 2] = [
            b"mimalloc_allow_large_os_pages=1\0".as_ptr().cast(),
            core::ptr::null(),
        ];
        VM_POLICY_SOURCE_ENVIRONMENT.store(
            retry_environment.as_ptr().cast_mut(),
            Ordering::Release,
        );
        std::thread::scope(|scope| {
            let readers = [
                scope.spawn(|| policy.allow_large_os_pages()),
                scope.spawn(|| policy.allow_large_os_pages()),
                scope.spawn(|| policy.allow_large_os_pages()),
                scope.spawn(|| policy.allow_large_os_pages()),
                scope.spawn(|| policy.allow_large_os_pages()),
                scope.spawn(|| policy.allow_large_os_pages()),
                scope.spawn(|| policy.allow_large_os_pages()),
                scope.spawn(|| policy.allow_large_os_pages()),
            ];
            for reader in readers {
                assert!(
                    reader.join().expect("the source-policy reader does not panic"),
                    "each reader observes the one terminal source retry"
                );
            }
        });
        assert!(
            policy.options().all_resolved(),
            "the serialized retry publishes a complete immutable option image"
        );
    }

    #[test]
    fn stale_source_option_read_rechecks_completion_before_exclusive_projection() {
        let policy = VmPolicy::defaults_for_test();
        // SAFETY: this exact policy has Release-published its complete image,
        // so an ordinary fast-path reader may retain this shared snapshot.
        // Keep it live while manually driving the slow branch which a caller
        // reached after an earlier false completion observation. Under Miri,
        // the former stale path's `&mut` projection would overlap this reader.
        let established_reader = unsafe { &*policy.options.get() };
        assert!(established_reader.all_resolved());

        let stale_snapshot = policy.options_after_unresolved_observation();
        let stale_value =
            policy.option_value_after_unresolved_observation(VmOption::AllowLargeOsPages);
        assert_eq!(stale_snapshot, *established_reader);
        assert_eq!(
            stale_value,
            established_reader.current_value(VmOption::AllowLargeOsPages),
            "a stale source-option reader must remain a shared terminal snapshot"
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
    fn fault_plan_requires_worker_admission_before_it_can_consume_an_ordinal() {
        let fault = fault::install(fault::Plan::at(fault::Point::Unmap, 1, Errno::NOMEM));
        let startup = current_startup();
        let page = startup.page_size().bytes();

        // A concurrent ordinary mapping operation reaches the same raw
        // `munmap` seam, but it has no permit from this plan guard. It must
        // release normally and leave the selected ordinal for the owner.
        let unrelated = std::thread::spawn(move || {
            let mut mapping = Mapping::map_anonymous(startup, page, MapAccess::Reserved)
                .expect("the unrelated worker maps one page normally");
            mapping.unmap()
        });
        assert_eq!(
            unrelated.join().expect("the unrelated worker does not panic"),
            Ok(())
        );
        assert_eq!(fault.observed(), 0, "an unpermitted worker cannot steal the plan");

        let mut selected = Mapping::map_anonymous(startup, page, MapAccess::Reserved)
            .expect("the selected owner maps one page normally");
        assert_eq!(selected.unmap(), Err(Errno::NOMEM));
        assert_eq!(fault.observed(), 1, "the installing thread keeps its selected ordinal");
        fault.set(fault::Plan::disabled());
        selected
            .unmap()
            .expect("the selected owner releases after its injected failure");

        // A test that intentionally exercises a worker can grant precisely
        // that scoped operation a permit. The worker reaches the selected map
        // seam before it owns a Mapping, so failure leaves no cleanup owner.
        fault.set(fault::Plan::at(fault::Point::Map, 1, Errno::NOMEM));
        std::thread::scope(|scope| {
            let permit = fault.permit();
            let selected = scope.spawn(move || {
                permit.run(|| Mapping::map_anonymous(startup, page, MapAccess::Reserved).map(|_| ()))
            });
            assert_eq!(
                selected.join().expect("the permitted worker does not panic"),
                Err(Errno::NOMEM)
            );
        });
        assert_eq!(fault.observed(), 1, "the explicit permit admits the selected worker");
        fault.set(fault::Plan::disabled());
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
                process.commit_direct_page_area(
                    config.page_size(),
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
            unsafe { process.commit_direct_page_area(config.page_size(), empty_base, 0) },
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
            unsafe { process.commit_direct_page_area(config.page_size(), failed_base, page) },
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

    /// Runs only when the hardware qualification collector supplies two
    /// source-valid NUMA node numbers.  It is deliberately not a general
    /// topology test: each row calls the existing one-GiB
    /// `HugeOsAllocation::allocate_for_process` primitive and records the
    /// kernel's own `/proc/self/numa_maps` observation while that exact
    /// mapping remains owned.  The collector first proves that the dedicated
    /// host has one free one-GiB page for each requested node.
    ///
    /// The pinned C counterpart calls `mi_reserve_huge_os_pages_at` for the
    /// same node list.  Existing source-policy, registry, and cleanup
    /// evidence remains separate; this bounded witness is only the missing
    /// hardware-success and physical-placement observation.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn hardware_huge_page_numa_qualification_workload() {
        const ENVIRONMENT: &str = "CRABC_MIMALLOC_HUGE_NUMA_NODES";
        const HUGE_PAGE_KIB: usize = 1024 * 1024;

        // The normal unit suite has no entitlement to consume a hardware
        // huge-page pool.  The qualification collector supplies this exact
        // environment variable and rejects a missing trace, so an ordinary
        // unit invocation remains a no-op while the named hardware job cannot
        // silently pass without running this workload.
        if std::env::var_os(ENVIRONMENT).is_none() {
            return;
        }

        fn qualification_nodes() -> core::result::Result<[i32; 2], std::string::String> {
            let raw = std::env::var(ENVIRONMENT)
                .map_err(|_| std::format!("{ENVIRONMENT} must name two comma-separated NUMA nodes"))?;
            let mut values = raw.split(',');
            let first = values.next().ok_or_else(|| std::format!("{ENVIRONMENT} is empty"))?;
            let second = values.next().ok_or_else(|| std::format!("{ENVIRONMENT} lacks a second node"))?;
            if values.next().is_some() {
                return Err(std::format!("{ENVIRONMENT} must contain exactly two nodes"));
            }
            let parse = |value: &str| {
                value.parse::<i32>().ok().filter(|node| (0..=62).contains(node))
                    .ok_or_else(|| std::format!("{ENVIRONMENT} contains an invalid source NUMA node"))
            };
            let nodes = [parse(first)?, parse(second)?];
            if nodes[0] == nodes[1] {
                return Err(std::format!("{ENVIRONMENT} requires two distinct nodes"));
            }
            Ok(nodes)
        }

        fn observed_huge_node(base: *mut u8) -> core::result::Result<usize, std::string::String> {
            let address = std::format!("{:x}", base.addr());
            let maps = std::fs::read_to_string("/proc/self/numa_maps")
                .map_err(|error| std::format!("cannot read /proc/self/numa_maps: {error}"))?;
            let line = maps.lines().find(|line| {
                line.split_ascii_whitespace().next() == Some(address.as_str())
            }).ok_or_else(|| std::format!("numa_maps has no live huge mapping at {address}"))?;
            if !line.split_ascii_whitespace().any(|field| field == "kernelpagesize_kB=1048576") {
                return Err(std::format!("huge mapping at {address} lacks a one-GiB kernel page record"));
            }
            let mut observed = None;
            for field in line.split_ascii_whitespace() {
                let Some(node) = field.strip_prefix('N') else { continue; };
                let Some((node, pages)) = node.split_once('=') else { continue; };
                let node = node.parse::<usize>()
                    .map_err(|_| std::format!("numa_maps has an invalid node field {field}"))?;
                let pages = pages.parse::<usize>()
                    .map_err(|_| std::format!("numa_maps has an invalid page count {field}"))?;
                if pages == 0 { continue; }
                if observed.replace(node).is_some() {
                    return Err(std::format!("huge mapping at {address} spans multiple NUMA nodes"));
                }
            }
            observed.ok_or_else(|| std::format!("huge mapping at {address} has no physical NUMA node"))
        }

        let nodes = qualification_nodes().expect("hardware qualification node contract");
        let _fault = fault::install(fault::Plan::disabled());
        let config = MemoryConfig::detect(current_startup());
        let policy = VmPolicy::defaults_for_test();
        let subprocess = crate::subproc::MainSubprocess::test_static_owner();
        let process = VmProcess::new(&policy, subprocess);
        let mut allocations = std::vec::Vec::new();
        let observation = (|| -> core::result::Result<(), std::string::String> {
            std::println!("CRABC_MI_HUGE_NUMA_RUST_TRACE_BEGIN");
            for (index, requested_node) in nodes.into_iter().enumerate() {
                let allocation = match HugeOsAllocation::allocate_for_process(
                    process, config, 1, requested_node, 0, None,
                ) {
                    HugeOsAllocationOutcome::Allocated(allocation)
                        if allocation.page_count() == 1
                            && allocation.stop() == HugeOsAllocationStop::Complete => allocation,
                    _ => return Err("source huge primitive did not complete".into()),
                };
                let mapping_address = allocation.base().as_ptr();
                // Retain ownership before observing.  Thus an observation
                // failure still takes the explicit cleanup path below rather
                // than leaving a source allocation only for process exit.
                allocations.push(allocation);
                let observed_node = observed_huge_node(mapping_address)?;
                if observed_node != requested_node as usize {
                    return Err(std::format!(
                        "source huge primitive requested NUMA node {requested_node}, observed {observed_node}"
                    ));
                }
                std::println!("CRABC_MI_HUGE_NUMA_RUST_MAP.{index}.requested_node={requested_node}");
                std::println!("CRABC_MI_HUGE_NUMA_RUST_MAP.{index}.observed_node={observed_node}");
                std::println!("CRABC_MI_HUGE_NUMA_RUST_MAP.{index}.kernel_page_kib={HUGE_PAGE_KIB}");
                std::println!("CRABC_MI_HUGE_NUMA_RUST_MAP.{index}.mapping_address={}", mapping_address.addr());
            }
            std::println!("CRABC_MI_HUGE_NUMA_RUST_TRACE_END");
            Ok(())
        })();
        let mut cleanup: core::result::Result<(), std::string::String> = Ok(());
        while let Some(allocation) = allocations.pop() {
            let mut tracker = [0usize; 1];
            if allocation.release_for_process(&mut tracker).is_err() {
                cleanup = Err("source huge primitive cleanup failed".into());
                break;
            }
        }
        observation.expect("hardware huge-page and NUMA placement observation");
        cleanup.expect("hardware huge-page cleanup");
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
            std::println!("m2.huge.free.{count}={page}");
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
        let mut wide = [0usize; 2];
        let mut calls = 0;
        let error = release_huge_pages_with(base, 65, &mut wide, |address| {
            let page = (address.as_ptr().addr() - base.as_ptr().addr()) / HUGE_PAGE_SIZE;
            calls += 1;
            if page == 1 || page == 64 { Err(Errno::NOMEM) } else { Ok(()) }
        });
        assert_eq!(error, Some(Errno::NOMEM));
        assert_eq!(calls, 65);
        assert_eq!(wide, [2, 1], "failed ownership spans tracker words without a page cap");
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
            Ok(_) => panic!("the injected raw retry must retain its one failed page"),
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

    /// Emits the fixed Rust half of the fault-inventory huge-page branch
    /// receipt.  The map closure supplies anonymous test mappings only: it
    /// proves source control-flow and retained-owner accounting, never Linux
    /// huge-page provisioning or a NUMA placement result.
    #[test]
    fn emit_m2_fault_seam_inventory_c_rust_trace() {
        let config = MemoryConfig::detect(current_startup());

        let partial_policy = VmPolicy::defaults_for_test();
        let partial_subprocess = crate::subproc::MainSubprocess::test_static_owner();
        let partial_process = VmProcess::new(&partial_policy, partial_subprocess);
        let partial_before = partial_subprocess.vm_statistics().snapshot();
        let mut partial_maps = 0;
        let partial = match allocate_huge_pages_with(
            partial_process,
            2,
            0,
            None,
            |hint| {
                partial_maps += 1;
                if partial_maps == 2 {
                    Err(Errno::NOMEM)
                } else {
                    Ok(synthetic_huge_mapping(config, hint))
                }
            },
            || 0,
            |_| 0,
        ) {
            HugeOsAllocationOutcome::Allocated(allocation) => allocation,
            _ => panic!("one completed primitive page retains a partial huge owner"),
        };
        let partial_after = partial_subprocess.vm_statistics().snapshot();
        let partial_relation = partial_maps == 2
            && partial.page_count() == 1
            && partial.size() == HUGE_PAGE_SIZE
            && partial.memory_id().kind() == MemoryKind::OsHuge
            && matches!(partial.stop(), HugeOsAllocationStop::PrimitiveMapFailed(Errno::NOMEM))
            && partial_after.reserved_current
                == partial_before.reserved_current + HUGE_PAGE_SIZE as i64
            && partial_after.committed_current
                == partial_before.committed_current + HUGE_PAGE_SIZE as i64;

        let timeout_policy = VmPolicy::defaults_for_test();
        let timeout_subprocess = crate::subproc::MainSubprocess::test_static_owner();
        let timeout_process = VmProcess::new(&timeout_policy, timeout_subprocess);
        let timeout_before = timeout_subprocess.vm_statistics().snapshot();
        let mut timeout_maps = 0;
        let timeout = match allocate_huge_pages_with(
            timeout_process,
            2,
            1,
            None,
            |hint| {
                timeout_maps += 1;
                Ok(synthetic_huge_mapping(config, hint))
            },
            || 0,
            |_| 2,
        ) {
            HugeOsAllocationOutcome::Allocated(allocation) => allocation,
            _ => panic!("the first primitive page precedes the source timeout check"),
        };
        let timeout_after = timeout_subprocess.vm_statistics().snapshot();
        let timeout_relation = timeout_maps == 1
            && timeout.page_count() == 1
            && matches!(timeout.stop(), HugeOsAllocationStop::TimedOut)
            && timeout_after.reserved_current
                == timeout_before.reserved_current + HUGE_PAGE_SIZE as i64
            && timeout_after.committed_current
                == timeout_before.committed_current + HUGE_PAGE_SIZE as i64;

        let noncontiguous_fault = fault::install(fault::Plan::at(
            fault::Point::Unmap,
            1,
            Errno::NOMEM,
        ));
        let noncontiguous_policy = VmPolicy::defaults_for_test();
        let noncontiguous_subprocess = crate::subproc::MainSubprocess::test_static_owner();
        let noncontiguous_process = VmProcess::new(&noncontiguous_policy, noncontiguous_subprocess);
        let noncontiguous_before = noncontiguous_subprocess.vm_statistics().snapshot();
        let rejected = match allocate_huge_pages_with(
            noncontiguous_process,
            1,
            0,
            None,
            |hint| Ok(synthetic_huge_mapping(config, hint + HUGE_PAGE_SIZE)),
            || 0,
            |_| 0,
        ) {
            HugeOsAllocationOutcome::RejectedPrimitive(rejected) => rejected,
            _ => panic!("a noncontiguous primitive result must retain its adjustment owner"),
        };
        let noncontiguous_after = noncontiguous_subprocess.vm_statistics().snapshot();
        let noncontiguous_relation = rejected.error() == Errno::NOMEM
            && noncontiguous_fault.observed() == 1
            && noncontiguous_after.reserved_current
                == noncontiguous_before.reserved_current - HUGE_PAGE_SIZE as i64
            && noncontiguous_after.committed_current
                == noncontiguous_before.committed_current - HUGE_PAGE_SIZE as i64;
        drop(noncontiguous_fault);

        #[cfg(target_arch = "x86_64")]
        let fault_diagnostic_relation = {
            let _environment_serial = VM_POLICY_SOURCE_ENVIRONMENT_TEST_LOCK
                .lock()
                .expect("fault-diagnostic source environment lock is not poisoned");
            let _environment_reset = VmPolicySourceEnvironmentReset;
            let show_errors_on = b"mimalloc_show_errors=1\0";
            let show_errors_off = b"mimalloc_show_errors=0\0";
            let verbose = b"mimalloc_verbose=0\0";
            let max_warnings = b"mimalloc_max_warnings=32\0";
            let mut enabled_environment = [
                show_errors_on.as_ptr().cast(), verbose.as_ptr().cast(),
                max_warnings.as_ptr().cast(), core::ptr::null(),
            ];
            let mut disabled_environment = [
                show_errors_off.as_ptr().cast(), verbose.as_ptr().cast(),
                max_warnings.as_ptr().cast(), core::ptr::null(),
            ];

            VM_POLICY_SOURCE_ENVIRONMENT.store(enabled_environment.as_mut_ptr(), Ordering::Release);
            // SAFETY: the source-test lock and stable vector meet the reader
            // and process-lifetime FILE capability obligations for this
            // single-threaded native target witness.
            let capability = unsafe { RuntimeStderrOutput::new(m2_fault_diagnostic_musl_stderr) };
            let mut default_output = OutputOwner::new(capability.into_default_stderr_output());
            unsafe { default_output.initialize_source_options(vm_policy_source_environment_for_test) };
            let default_fault = fault::install(fault::Plan::at(
                fault::Point::NumaBind, 1, Errno::PERM,
            ));
            let default_mapping_survives = m2_fault_diagnostic_relation_mapping(&default_output, 62);
            let default_mbind = default_fault.observed() == 1;
            drop(default_fault);
            // Keep the complete raw native `fputs(stderr)` payload between
            // literal markers. `post_init` itself retains the source's
            // delayed warning image plus its continuation LF for a later
            // registration, outside this frame.
            std::eprintln!("CRABC_MI_M2_FAULT_DIAGNOSTIC_RELATION_RUST_DEFAULT_BEGIN");
            unsafe { default_output.post_init() };
            std::eprintln!("CRABC_MI_M2_FAULT_DIAGNOSTIC_RELATION_RUST_DEFAULT_END");
            // Pinned `mi_out_buf_flush(..., false)` retains the flushed
            // warning and adds one final LF in the delayed buffer. The next
            // registration observes that exact image outside the default
            // `fputs(stderr)` frame.
            let default_continuation_capture = FaultDiagnosticRelationCapture::new();
            let default_thread_identity = thread_pointer_identity();
            let expected_default_continuation = std::format!(
                "mimalloc: warning: thread 0x{default_thread_identity:X}: \
                 failed to bind huge (1GiB) pages to numa node 62 (error: 1 (0x01))\n\n"
            );
            unsafe {
                default_output.register_output(
                    Some(capture_fault_diagnostic_relation as OutputCallback),
                    &default_continuation_capture as *const FaultDiagnosticRelationCapture
                        as *mut c_void,
                )
            };
            let default_continuation_flush = default_continuation_capture.count.load(Ordering::Acquire) == 1
                && default_continuation_capture.fragment(0)
                    == expected_default_continuation.as_bytes();

            VM_POLICY_SOURCE_ENVIRONMENT.store(disabled_environment.as_mut_ptr(), Ordering::Release);
            let mut gate_off_output = OutputOwner::new(unexpected_default_diagnostic_output);
            unsafe { gate_off_output.initialize_source_options(vm_policy_source_environment_for_test) };
            let gate_off_capture = FaultDiagnosticRelationCapture::new();
            unsafe {
                gate_off_output.register_output(
                    Some(capture_fault_diagnostic_relation as OutputCallback),
                    &gate_off_capture as *const FaultDiagnosticRelationCapture as *mut c_void,
                )
            };
            gate_off_capture.reset();
            let gate_off_fault = fault::install(fault::Plan::at(
                fault::Point::NumaBind, 1, Errno::PERM,
            ));
            let gate_off_mapping_survives =
                m2_fault_diagnostic_relation_mapping(&gate_off_output, 62);
            let gate_off_mbind = gate_off_fault.observed() == 1;
            drop(gate_off_fault);
            let gate_off_no_output = gate_off_capture.count.load(Ordering::Acquire) == 0;

            VM_POLICY_SOURCE_ENVIRONMENT.store(enabled_environment.as_mut_ptr(), Ordering::Release);
            let mut custom_output = OutputOwner::new(unexpected_default_diagnostic_output);
            unsafe { custom_output.initialize_source_options(vm_policy_source_environment_for_test) };
            let custom_capture = FaultDiagnosticRelationCapture::new();
            unsafe {
                custom_output.register_output(
                    Some(capture_fault_diagnostic_relation as OutputCallback),
                    &custom_capture as *const FaultDiagnosticRelationCapture as *mut c_void,
                )
            };
            // Custom registration flushes its empty delayed image. The next
            // capture contains only the selected valid-node source warning.
            custom_capture.reset();
            let custom_fault = fault::install(fault::Plan::at(
                fault::Point::NumaBind, 1, Errno::PERM,
            ));
            let custom_mapping_survives = m2_fault_diagnostic_relation_mapping(&custom_output, 62);
            let custom_mbind = custom_fault.observed() == 1;
            drop(custom_fault);
            let custom_thread_identity = thread_pointer_identity();
            let custom_fragments = custom_capture.count.load(Ordering::Acquire) == 2
                && custom_capture.fragment(0) == std::format!(
                    "mimalloc: warning: thread 0x{custom_thread_identity:X}: "
                ).as_bytes()
                && custom_capture.fragment(1)
                    == b"failed to bind huge (1GiB) pages to numa node 62 (error: 1 (0x01))\n";

            let mut invalid_output = OutputOwner::new(unexpected_default_diagnostic_output);
            unsafe { invalid_output.initialize_source_options(vm_policy_source_environment_for_test) };
            let invalid_capture = FaultDiagnosticRelationCapture::new();
            unsafe {
                invalid_output.register_output(
                    Some(capture_fault_diagnostic_relation as OutputCallback),
                    &invalid_capture as *const FaultDiagnosticRelationCapture as *mut c_void,
                )
            };
            invalid_capture.reset();
            let invalid_fault = fault::install(fault::Plan::at(
                fault::Point::NumaBind, 1, Errno::PERM,
            ));
            let invalid_mapping_survives = m2_fault_diagnostic_relation_mapping(&invalid_output, 63);
            let invalid_no_mbind = invalid_fault.observed() == 0;
            drop(invalid_fault);
            let invalid_no_output = invalid_capture.count.load(Ordering::Acquire) == 0;

            // libtest prefixes the first uncaptured stdout write with its test
            // label. Emit one LF first so the retained receipt marker remains
            // a complete literal-LF line rather than a substring of that
            // harness status text.
            std::println!();
            std::println!("CRABC_MI_M2_FAULT_DIAGNOSTIC_RELATION_RUST_TRACE_BEGIN");
            for (name, value) in [
                ("default_mbind", default_mbind),
                ("default_mapping_survives", default_mapping_survives),
                ("default_stats_survive", default_mapping_survives),
                ("default_continuation_flush", default_continuation_flush),
                ("gate_off_mbind", gate_off_mbind),
                ("gate_off_no_output", gate_off_no_output),
                ("gate_off_mapping_survives", gate_off_mapping_survives),
                ("gate_off_stats_survive", gate_off_mapping_survives),
                ("custom_mbind", custom_mbind),
                ("custom_fragments", custom_fragments),
                ("custom_mapping_survives", custom_mapping_survives),
                ("custom_stats_survive", custom_mapping_survives),
                ("invalid_no_mbind", invalid_no_mbind),
                ("invalid_no_output", invalid_no_output),
                ("invalid_mapping_survives", invalid_mapping_survives),
                ("invalid_stats_survive", invalid_mapping_survives),
            ] {
                std::println!("{name}={}", usize::from(value));
            }
            std::println!("custom_thread_identity={custom_thread_identity}");
            std::print!("default_continuation_hex=");
            if default_continuation_capture.count.load(Ordering::Acquire) == 1 {
                for byte in default_continuation_capture.fragment(0) {
                    std::print!("{byte:02x}");
                }
            }
            std::println!();
            std::print!("custom_prefix_hex=");
            for byte in custom_capture.fragment(0) { std::print!("{byte:02x}"); }
            std::println!();
            std::print!("custom_body_hex=");
            for byte in custom_capture.fragment(1) { std::print!("{byte:02x}"); }
            std::println!();
            std::println!("CRABC_MI_M2_FAULT_DIAGNOSTIC_RELATION_RUST_TRACE_END");
            default_mbind && default_mapping_survives && default_continuation_flush
                && gate_off_mbind && gate_off_no_output
                && gate_off_mapping_survives && custom_mbind && custom_fragments
                && custom_mapping_survives && invalid_no_mbind && invalid_no_output
                && invalid_mapping_survives
        };
        #[cfg(not(target_arch = "x86_64"))]
        let fault_diagnostic_relation = true;
        assert!(
            fault_diagnostic_relation,
            "the selected source mbind receiver preserves its gate, mapping, and two-fragment delivery relation",
        );

        let placement_fault = fault::install(fault::Plan::at(
            fault::Point::NumaBind,
            1,
            Errno::PERM,
        ));
        let placement_policy = VmPolicy::defaults_for_test();
        let placement_subprocess = crate::subproc::MainSubprocess::test_static_owner();
        let placement_process = VmProcess::new(&placement_policy, placement_subprocess);
        let page = config.page_size().bytes();
        let mut placement_mapping = Mapping::map_for_process(
            placement_process,
            config,
            page,
            1,
            MapAccess::Committed,
            false,
            None,
        )
        .expect("the placement witness begins with one explicit mapping owner");
        let placement_base = placement_mapping.base().expect("the placement mapping is live");
        let placement_before = placement_subprocess.vm_statistics().snapshot();
        apply_huge_page_numa_preference(placement_base, 0);
        let placement_after = placement_subprocess.vm_statistics().snapshot();
        let placement_relation = placement_fault.observed() == 1
            && placement_mapping.base() == Ok(placement_base)
            && placement_after == placement_before;
        drop(placement_fault);
        placement_mapping
            .unmap_for_process(placement_process, page, true)
            .expect("the best-effort placement result cannot consume its mapping owner");

        let base = NonNull::new(HUGE_HINT_BASE as *mut u8).unwrap();
        let mut failed = [0usize; 1];
        let mut release_calls = 0;
        let source_free = release_huge_pages_with(base, 2, &mut failed, |address| {
            let page = (address.as_ptr().addr() - base.as_ptr().addr()) / HUGE_PAGE_SIZE;
            release_calls += 1;
            if page == 0 { Err(Errno::NOMEM) } else { Ok(()) }
        });
        let source_free_relation = source_free == Some(Errno::NOMEM)
            && release_calls == 2
            && failed == [1];

        let release_fault = fault::install(fault::Plan::at(
            fault::Point::Unmap,
            1,
            Errno::NOMEM,
        ));
        let release_policy = VmPolicy::defaults_for_test();
        let release_subprocess = crate::subproc::MainSubprocess::test_static_owner();
        let release_process = VmProcess::new(&release_policy, release_subprocess);
        assert_eq!(free_huge_page_for_process(release_process, base), Err(Errno::NOMEM));
        let after_source_free = release_subprocess.vm_statistics().snapshot();
        let mut failed_page = [1usize];
        let retry = HugeOsRawReleaseRetry {
            process: release_process,
            base,
            page_count: 1,
            memory: MemoryId::os_huge(base.as_ptr(), HUGE_PAGE_SIZE, true, true),
            source_error: Errno::NOMEM,
            failed_pages: &mut failed_page,
            failed_words: 1,
        };
        release_fault.set(fault::Plan::at(fault::Point::Unmap, 1, Errno::NOMEM));
        let retry_failure = match retry.retry_raw() {
            Ok(_) => panic!("the selected raw retry must retain its failed source page"),
            Err(failure) => failure,
        };
        let retry = retry_failure.into_retry();
        let continued_free_relation = source_free_relation
            && retry.source_error() == Errno::NOMEM
            && retry.failed_page(0)
            && release_subprocess.vm_statistics().snapshot() == after_source_free;
        drop(release_fault);

        std::println!("CRABC_MI_M2_FAULT_SEAM_INVENTORY_RUST_TRACE_BEGIN");
        std::println!(
            "m2.fault.rust.huge.partial_primitive_failure_retains_one_os_huge_owner_and_stats={}",
            usize::from(partial_relation),
        );
        std::println!(
            "m2.fault.rust.huge.timeout_after_progress_retains_one_os_huge_owner_and_stats={}",
            usize::from(timeout_relation),
        );
        std::println!(
            "m2.fault.rust.huge.noncontiguous_adjustment_retains_rejected_cleanup_owner={}",
            usize::from(noncontiguous_relation),
        );
        std::println!(
            "m2.fault.rust.huge.placement_failure_is_best_effort_and_retains_mapping_owner={}",
            usize::from(placement_relation),
        );
        std::println!(
            "m2.fault.rust.huge.free_continues_after_failed_page_and_records_retry_bits={}",
            usize::from(continued_free_relation),
        );
        std::println!("CRABC_MI_M2_FAULT_SEAM_INVENTORY_RUST_TRACE_END");
    }

    #[test]
    fn huge_release_moves_owned_tracking_with_the_exact_failed_page_set() {
        let fault = fault::install(fault::Plan::disabled());
        let policy = VmPolicy::defaults_for_test();
        let subprocess = crate::subproc::MainSubprocess::test_static_owner();
        let process = VmProcess::new(&policy, subprocess);
        let config = MemoryConfig::detect(current_startup());
        let allocation = HugeOsAllocation::test_registry_allocation(process, config, 3);
        let tracker = std::vec![0usize; 1].into_boxed_slice();
        let tracker_address = tracker.as_ptr();
        fault.set(fault::Plan::at(fault::Point::Unmap, 2, Errno::NOMEM));
        // SAFETY: Box owns one stable exclusive word buffer until it is
        // returned by the successful release/retry transition.
        let failure = match unsafe { allocation.release_with_tracker(tracker) } {
            Err(failure) => failure, Ok(_) => panic!("second primitive release fails"),
        };
        let HugeOsReleaseFailure::FailedPages(retry) = failure else { panic!("failed page owner"); };
        assert!(!retry.failed_page(0));
        assert!(retry.failed_page(1));
        assert!(!retry.failed_page(2));
        let source_statistics = subprocess.vm_statistics().snapshot();
        let moved = std::boxed::Box::new(retry);
        fault.set(fault::Plan::disabled());
        let tracker = (*moved).retry_raw().unwrap_or_else(|_| panic!("raw retry"));
        assert_eq!(tracker.as_ptr(), tracker_address);
        assert_eq!(&*tracker, &[0]);
        assert_eq!(subprocess.vm_statistics().snapshot(), source_statistics);
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
        let _allocation = failure.into_parts().0;
        assert_eq!(subprocess.vm_statistics().snapshot().reserved_current, HUGE_PAGE_SIZE as i64);
    }

    #[test]
    fn vm_process_purge_consumes_a_failed_reset_primitive_with_source_counters() {
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
        assert_eq!(
            mapping.purge_for_process(process, 0, page, true, page),
            Ok(false),
            "_mi_os_purge_ex consumes the reset advisory error and reports no recommit",
        );
        let after_failed_reset = subprocess.vm_statistics().snapshot();
        assert_eq!(after_failed_reset.purge_calls, 1);
        assert_eq!(after_failed_reset.purged, page as i64);
        assert_eq!(after_failed_reset.reset_calls, 1);
        assert_eq!(after_failed_reset.reset, page as i64);
        assert_eq!(after_failed_reset.committed_current, page as i64);

        fault.set(fault::Plan::disabled());
        mapping
            .unmap_for_process(process, page, false)
            .expect("the owned mapping releases after the consumed reset advisory failure");
    }

    #[test]
    fn vm_process_purge_reset_does_not_consume_invalid_owner_errors() {
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
        .expect("the reset-purge owner starts with one complete mapped page");
        let before = subprocess.vm_statistics().snapshot();

        // Rust's typed mapping boundary has no C analogue to consume: the
        // source-style reset advisory policy begins only after this exact
        // owner has accepted the requested range.
        assert_eq!(
            mapping.purge_for_process(process, page, page, true, page),
            Err(Errno::INVAL),
        );
        let after_invalid_range = subprocess.vm_statistics().snapshot();
        assert_eq!(after_invalid_range.purge_calls, before.purge_calls + 1);
        assert_eq!(after_invalid_range.purged, before.purged + page as i64);
        assert_eq!(after_invalid_range.reset_calls, before.reset_calls);

        mapping
            .unmap_for_process(process, page, false)
            .expect("the live reset-purge owner releases once");
        assert_eq!(
            mapping.purge_for_process(process, 0, page, true, page),
            Err(Errno::INVAL),
        );
        let after_released_mapping = subprocess.vm_statistics().snapshot();
        assert_eq!(after_released_mapping.purge_calls, before.purge_calls + 2);
        assert_eq!(after_released_mapping.purged, before.purged + 2 * page as i64);
        assert_eq!(after_released_mapping.reset_calls, before.reset_calls);
    }

    #[test]
    fn vm_process_purge_decommit_failure_reports_source_no_recommit_and_retains_mapping() {
        let fault = fault::install(fault::Plan::disabled());
        let config = MemoryConfig::detect(current_startup());
        let page = config.page_size().bytes();
        let mut policy = VmPolicy::defaults_for_test();
        policy.set_option(VmOption::PurgeDecommits, 1);
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
        .expect("the paired source process maps one decommit-purge range");
        let base = mapping.base().expect("the purge owner starts live");
        let before = subprocess.vm_statistics().snapshot();

        // Pinned `_mi_os_purge_ex` starts `needs_recommit` as true, but the
        // normal Unix `_mi_prim_decommit` writes false after its madvise
        // result, including an error. The caller keeps its mapping owner and
        // follows that source result instead of replacing it with an error.
        fault.set(fault::Plan::at(fault::Point::Decommit, 1, Errno::NOMEM));
        assert_eq!(
            mapping.purge_for_process(process, 0, page, true, page),
            Ok(false),
        );
        assert_eq!(fault.observed(), 1, "the selected decommit has no hidden retry");
        assert_eq!(mapping.base(), Ok(base), "the failed advisory retains its mapping owner");
        let after_failure = subprocess.vm_statistics().snapshot();
        assert_eq!(after_failure.purge_calls, before.purge_calls + 1);
        assert_eq!(after_failure.purged, before.purged + page as i64);
        assert_eq!(after_failure.reset_calls, before.reset_calls);
        assert_eq!(after_failure.committed_current, before.committed_current);

        fault.set(fault::Plan::disabled());
        assert_eq!(
            mapping.purge_for_process(process, 0, page, true, page),
            Ok(false),
            "a later source decommit success does not need recommit on this Linux profile",
        );
        mapping
            .unmap_for_process(process, page, false)
            .expect("the retained mapping releases after the decommit-purge retry");
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

    /// Drives the exact process-paired `src/os.c:502-527` receiver through
    /// its best-effort offset-prefix decommit. The success plan faults on a
    /// later ordinal to prove the raw primitive ran; the failure plan faults
    /// its one attempt. Both preserve the full mapping and source release
    /// counters because prefix advice is never an allocation rollback.
    fn process_offset_prefix_decommit_receiver(
        config: MemoryConfig,
        fault: &fault::Guard,
        inject_decommit_failure: bool,
    ) -> bool {
        let page = config.page_size().bytes();
        let size = page.checked_mul(2).expect("the selected source span fits");
        let alignment = page.checked_mul(16).expect("the selected source alignment fits");
        let offset = page;
        let prefix = invariants::align_up(offset, alignment)
            .and_then(|aligned| aligned.checked_sub(offset))
            .expect("the selected source prefix geometry fits");
        assert!(prefix >= page, "the selected source geometry reaches the prefix decommit");

        let policy = VmPolicy::defaults_for_test();
        let subprocess = crate::subproc::MainSubprocess::test_static_owner();
        let process = VmProcess::new(&policy, subprocess);
        let before = subprocess.vm_statistics().snapshot();
        // Ordinal two reaches the real advice after proving one selected raw
        // call; ordinal one injects the advisory failure that source ignores.
        fault.set(fault::Plan::at(
            fault::Point::Decommit,
            if inject_decommit_failure { 1 } else { 2 },
            Errno::NOMEM,
        ));
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
        .expect("a prefix decommit advisory never discards its successful source allocation");
        let base = allocation.base().expect("the full source owner remains live");
        let pointer = allocation.pointer().expect("the source client pointer remains live");
        let full_size = allocation.full_size().expect("the source owner retains its full extent");
        let memory = allocation.memory_id().expect("the source owner retains full provenance");
        let after_allocate = subprocess.vm_statistics().snapshot();
        assert_eq!(fault.observed(), 1, "the selected prefix primitive has one source attempt");
        assert_eq!(pointer.as_ptr().addr() - base.addr(), prefix);
        assert_eq!(memory.os_base().map(|address| address.value()), Some(base.addr()));
        assert_eq!(memory.size(), Some(full_size));
        assert_eq!(after_allocate.reserved_current, before.reserved_current + full_size as i64);
        assert_eq!(after_allocate.committed_current, before.committed_current + full_size as i64);

        fault.set(fault::Plan::disabled());
        allocation
            .release_for_process(process, true)
            .expect("the retained full owner releases after either prefix-advice outcome");
        let after_release = subprocess.vm_statistics().snapshot();
        assert_eq!(after_release.reserved_current, before.reserved_current);
        assert_eq!(
            after_release.committed_current,
            before.committed_current + prefix as i64,
            "pinned source frees the client extent after its prefix-decommit accounting edge"
        );
        true
    }

    #[test]
    fn vm_process_offset_prefix_decommit_keeps_full_owner_after_success_and_failure() {
        let fault = fault::install(fault::Plan::disabled());
        let config = MemoryConfig::detect(current_startup());
        assert!(process_offset_prefix_decommit_receiver(config, &fault, false));
        assert!(process_offset_prefix_decommit_receiver(config, &fault, true));
    }

    /// Executes the finite normal Linux no-callback `_mi_os_purge_ex` policy
    /// matrix from `src/os.c:655-679`. It keeps source option resolution,
    /// preloading, conservative normalization, raw advisory selection, and
    /// typed mapping ownership in the same receiver instead of treating a
    /// counter-only fixture as a policy result.
    fn normal_no_callback_purge_policy_range_matrix(
        config: MemoryConfig,
        fault: &fault::Guard,
    ) -> bool {
        let page = config.page_size().bytes();
        let matrix_length = page.checked_mul(3).expect("the selected three-page matrix owner fits");
        for delay in [-1_i64, 0, 1] {
            for purge_decommits in [false, true] {
                for preloading in [false, true] {
                    for allow_reset in [false, true] {
                        for (offset, length, contains_page, advice_offset) in [
                            (0, 0, false, 0),
                            (1, page - 1, false, 0),
                            (0, page, true, 0),
                            // Source conservative alignment discards the
                            // partial first and last pages, retaining only
                            // this live mapping's middle page for advice.
                            (1, matrix_length - 2, true, page),
                        ]
                        {
                            let mut options = VmOptions::uninitialized();
                            options.initialize_all(|_| VmOptionEnvironment::Absent);
                            options.set(VmOption::PurgeDelay, delay);
                            options.set(VmOption::PurgeDecommits, i64::from(purge_decommits));
                            let policy = VmPolicy::new(options)
                                .expect("the direct matrix owns one complete source option image");
                            if !preloading {
                                policy.finish_preloading();
                            }
                            let subprocess = crate::subproc::MainSubprocess::test_static_owner();
                            let process = VmProcess::new(&policy, subprocess);
                            let mut mapping = Mapping::map_for_process(
                                process,
                                config,
                                matrix_length,
                                1,
                                MapAccess::Committed,
                                false,
                                None,
                            )
                            .expect("each source-policy cell starts with one typed page owner");
                            let base = mapping.base().expect("the matrix owner starts live");
                            let before = subprocess.vm_statistics().snapshot();
                            let negative_delay = delay < 0;
                            let decommit_branch = !negative_delay && purge_decommits && !preloading;
                            let reset_branch = !negative_delay && !decommit_branch
                                && allow_reset && contains_page;
                            let primitive_expected = !negative_delay && contains_page
                                && (decommit_branch || allow_reset);
                            let expected_recommit = decommit_branch && !contains_page;
                            // Pinned Unix decommit always selects
                            // `MADV_DONTNEED`. The reset branch must instead
                            // use the source-global cache value that it reads
                            // before this exact call: standalone tests may
                            // begin at `MADV_FREE`, while the M2 differential
                            // has already observed the source EINVAL fallback
                            // and therefore expects `MADV_DONTNEED`.
                            let expected_advice = primitive_expected.then(|| {
                                if decommit_branch {
                                    MADV_DONTNEED
                                } else {
                                    RESET_ADVICE.load(Ordering::Acquire) as u32
                                }
                            });
                            if primitive_expected {
                                fault.set(fault::Plan::at(
                                    if decommit_branch {
                                        fault::Point::Decommit
                                    } else {
                                        fault::Point::Purge
                                    },
                                    2,
                                    Errno::NOMEM,
                                ));
                            } else {
                                fault.set(fault::Plan::disabled());
                            }
                            // Capture every cell, including source decisions
                            // that must not reach a raw advice. A disabled
                            // fault plan alone cannot distinguish that branch
                            // from an unexpected successful primitive call.
                            let advice_capture = fault.capture_advice_range();

                            assert_eq!(
                                mapping.purge_for_process(process, offset, length, allow_reset, length),
                                Ok(expected_recommit),
                                "source policy result for delay={delay}, purge_decommits={purge_decommits}, preloading={preloading}, allow_reset={allow_reset}, offset={offset}, length={length}"
                            );
                            assert_eq!(
                                fault.observed(),
                                usize::from(primitive_expected),
                                "raw advice selection for delay={delay}, purge_decommits={purge_decommits}, preloading={preloading}, allow_reset={allow_reset}, offset={offset}, length={length}"
                            );
                            assert_eq!(
                                advice_capture.count(),
                                usize::from(primitive_expected),
                                "raw advice count for delay={delay}, purge_decommits={purge_decommits}, preloading={preloading}, allow_reset={allow_reset}, offset={offset}, length={length}"
                            );
                            if primitive_expected {
                                let (address, advised_length, advice) = advice_capture
                                    .range()
                                    .expect("the selected source policy reaches one normalized raw advice");
                                assert_eq!(address, base.addr() + advice_offset);
                                assert_eq!(advised_length, page);
                                assert_eq!(Some(advice), expected_advice);
                            }
                            assert_eq!(mapping.base(), Ok(base), "the policy result retains its typed mapping owner");
                            let after = subprocess.vm_statistics().snapshot();
                            assert_eq!(
                                after.purge_calls,
                                before.purge_calls + i64::from(!negative_delay),
                                "source purge counter timing for this policy cell"
                            );
                            assert_eq!(
                                after.purged,
                                before.purged + if negative_delay { 0 } else { length as i64 },
                                "source purged-byte timing for this policy cell"
                            );
                            assert_eq!(
                                after.reset_calls,
                                before.reset_calls + i64::from(reset_branch),
                                "source reset-call timing for this policy cell"
                            );
                            assert_eq!(
                                after.reset,
                                before.reset + if reset_branch { page as i64 } else { 0 },
                                "source reset-byte timing for this policy cell"
                            );
                            assert_eq!(
                                after.committed_current, before.committed_current,
                                "normal Linux advisory policy does not move source committed bytes"
                            );

                            fault.set(fault::Plan::disabled());
                            drop(advice_capture);
                            mapping
                                .unmap_for_process(process, matrix_length, false)
                                .expect("each typed matrix owner releases after its policy observation");
                        }
                    }
                }
            }
        }
        true
    }

    #[test]
    fn vm_process_purge_normal_no_callback_policy_range_matrix_matches_source() {
        let fault = fault::install(fault::Plan::disabled());
        assert!(normal_no_callback_purge_policy_range_matrix(
            MemoryConfig::detect(current_startup()),
            &fault,
        ));
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

    /// Returns one isolated paired source process and a deliberately small
    /// aligned-map geometry.  These witnesses use the existing test-only
    /// full-trim input solely to make every cleanup edge deterministic; the
    /// pinned C oracle keeps its literal `size + alignment` geometry.
    fn m2_aligned_overmap_process_fixture() -> (MemoryConfig, VmProcess<'static>, usize, usize) {
        let mut config = MemoryConfig::from_observations(
            PageSize::new(4 * 1024).expect("four KiB is one selected Linux page size"),
            1024 * 1024,
            true,
            false,
        );
        config.test_force_full_aligned_map_trim();
        let page = config.page_size().bytes();
        let length = page.checked_mul(2).expect("the selected map length fits");
        let alignment = page.checked_mul(2).expect("the selected alignment fits");
        let policy = std::boxed::Box::leak(std::boxed::Box::new(VmPolicy::defaults_for_test()));
        let subprocess = crate::subproc::MainSubprocess::test_static_owner();
        (config, VmProcess::new(policy, subprocess), length, alignment)
    }

    fn m2_aligned_overmap_counter_delta_is(
        before: crate::statistics::VmStatisticsSnapshot,
        after: crate::statistics::VmStatisticsSnapshot,
        maps: i64,
        reserved: i64,
        committed: i64,
    ) {
        assert_eq!(after.mmap_calls - before.mmap_calls, maps);
        assert_eq!(after.reserved_total - before.reserved_total, reserved);
        assert_eq!(after.reserved_current - before.reserved_current, reserved);
        assert_eq!(after.committed_total - before.committed_total, committed);
        assert_eq!(after.committed_current - before.committed_current, committed);
    }

    fn m2_aligned_overmap_direct_aligned_process_witness() {
        let fault = fault::install(fault::Plan::disabled());
        let (mut config, process, length, _alignment) = m2_aligned_overmap_process_fixture();
        // A Linux mmap is page aligned, so the source direct candidate is
        // already aligned at this one-page request alignment. Do not use the
        // full-trim seam for this normal direct-success row.
        config.force_full_aligned_map_trim = false;
        let before = process.subprocess().vm_statistics().snapshot();
        let mut mapping = Mapping::map_aligned_for_process(
            process,
            config,
            length,
            config.page_size().bytes(),
            MapAccess::Reserved,
            false,
            None,
        )
        .expect("the direct page-aligned process mapping succeeds");
        let after = process.subprocess().vm_statistics().snapshot();
        m2_aligned_overmap_counter_delta_is(before, after, 1, length as i64, 0);
        assert_eq!(mapping.base().unwrap().addr() % config.page_size().bytes(), 0);
        assert_eq!(mapping.length(), Ok(length));
        mapping
            .unmap_for_process(process, 0, false)
            .expect("the direct process owner releases once");
        assert_eq!(fault.observed(), 0);
    }

    fn m2_aligned_overmap_direct_map_failure_prefix_zero_witness() {
        let fault = fault::install(fault::Plan::at(
            fault::Point::Map,
            1,
            Errno::NOMEM,
        ));
        let (mut config, process, length, _alignment) = m2_aligned_overmap_process_fixture();
        // This is the normal source geometry, not the forced three-cleanup
        // geometry: a one-page alignment makes the successful overmap's
        // prefix zero and leaves only its suffix to trim.
        config.force_full_aligned_map_trim = false;
        let page = config.page_size().bytes();
        let before = process.subprocess().vm_statistics().snapshot();
        let mut mapping = Mapping::map_aligned_for_process(
            process,
            config,
            length,
            page,
            MapAccess::Reserved,
            false,
            None,
        )
        .expect("a failed direct primitive falls through to the source overmap");
        let after = process.subprocess().vm_statistics().snapshot();
        m2_aligned_overmap_counter_delta_is(before, after, 2, length as i64, 0);
        assert_eq!(fault.observed(), 2, "one failed and one successful map edge run");
        assert_eq!(mapping.base().unwrap().addr() % page, 0);
        assert_eq!(mapping.length(), Ok(length));
        fault.set(fault::Plan::disabled());
        mapping
            .unmap_for_process(process, 0, false)
            .expect("the suffix-only aligned result retains one exact process owner");
    }

    fn m2_aligned_overmap_complete_cleanup_process_witness() {
        let fault = fault::install(fault::Plan::at(
            fault::Point::Unmap,
            99,
            Errno::NOMEM,
        ));
        let (config, process, length, alignment) = m2_aligned_overmap_process_fixture();
        let before = process.subprocess().vm_statistics().snapshot();
        let mut mapping = Mapping::map_aligned_for_process(
            process,
            config,
            length,
            alignment,
            MapAccess::Reserved,
            false,
            None,
        )
        .expect("the forced direct, prefix, and suffix cleanup sequence succeeds");
        let after = process.subprocess().vm_statistics().snapshot();
        m2_aligned_overmap_counter_delta_is(before, after, 2, length as i64, 0);
        assert_eq!(fault.observed(), 3, "direct, prefix, and suffix frees all ran");
        assert_eq!(mapping.base().unwrap().addr() % alignment, 0);
        assert_eq!(mapping.length(), Ok(length));
        fault.set(fault::Plan::disabled());
        mapping
            .unmap_for_process(process, 0, false)
            .expect("the fully trimmed process owner releases once");
    }

    fn m2_aligned_overmap_cleanup_failure_process_witness(
        access: MapAccess,
        cleanup_ordinal: usize,
    ) {
        let fault = fault::install(fault::Plan::at(
            fault::Point::Unmap,
            cleanup_ordinal,
            Errno::NOMEM,
        ));
        let (config, process, length, alignment) = m2_aligned_overmap_process_fixture();
        let over_length = length
            .checked_add(alignment.checked_mul(2).expect("the test headroom fits"))
            .expect("the forced overmap length fits");
        let before = process.subprocess().vm_statistics().snapshot();
        let failure = match Mapping::map_aligned_for_process(
            process,
            config,
            length,
            alignment,
            access,
            false,
            None,
        ) {
            Ok(mut mapping) => {
                let _ = mapping.unmap();
                panic!("the selected cleanup edge must transfer its live owner")
            }
            Err(failure) => failure,
        };
        assert_eq!(failure.error(), Errno::NOMEM);
        assert_eq!(fault.observed(), cleanup_ordinal);
        let mut retained = failure
            .into_mapping()
            .expect("a failed aligned cleanup retains its exact mapping");
        let after = process.subprocess().vm_statistics().snapshot();
        let committed_delta = |bytes: usize| {
            if matches!(access, MapAccess::Committed) {
                bytes as i64
            } else {
                0
            }
        };

        match cleanup_ordinal {
            // Rust stops at the failed direct cleanup and retains that direct
            // map. Pinned C instead keeps going into an overmap, which is the
            // deliberate owner-boundary difference recorded by the native
            // companion trace.
            1 => {
                m2_aligned_overmap_counter_delta_is(before, after, 1, 0, committed_delta(0));
                assert_eq!(retained.length(), Ok(length));
            }
            // The failed prefix is still part of source adjustment accounting,
            // but Rust preserves the complete overmap and does not attempt the
            // later suffix release after this error.
            2 => {
                let base = retained.base().expect("the retained overmap remains live").addr();
                let aligned = if base % alignment == 0 {
                    base.checked_add(alignment).expect("the forced aligned boundary fits")
                } else {
                    invariants::align_up(base, alignment).expect("the aligned boundary fits")
                };
                let prefix = aligned - base;
                assert!(prefix != 0 && prefix < over_length);
                m2_aligned_overmap_counter_delta_is(
                    before,
                    after,
                    2,
                    (over_length - prefix) as i64,
                    committed_delta(over_length - prefix),
                );
                assert_eq!(retained.length(), Ok(over_length));
            }
            // The successful prefix changes the Rust owner before the suffix
            // failure. Its accounting has already reached the aligned middle,
            // while the returned owner still includes the live suffix.
            3 => {
                m2_aligned_overmap_counter_delta_is(
                    before,
                    after,
                    2,
                    length as i64,
                    committed_delta(length),
                );
                assert_eq!(retained.base().unwrap().addr() % alignment, 0);
                assert!(retained.length().unwrap() > length);
            }
            _ => panic!("the finite aligned-overmap matrix has three cleanup edges"),
        }

        // The error carries a terminal, already-adjusted owner. A test-only
        // raw teardown must not replay a full source counter transition; this
        // confirms the retained mapping can be released without double
        // accounting while production leaves recovery to its named owner.
        fault.set(fault::Plan::disabled());
        retained
            .unmap()
            .expect("the retained aligned-map owner releases through one raw edge");
        assert_eq!(process.subprocess().vm_statistics().snapshot(), after);
    }

    #[cfg(not(miri))]
    #[test]
    fn emit_m2_aligned_overmap_cleanup_c_rust_boundary_trace() {
        // This finite matrix intentionally does not compare C and Rust values
        // as equal. `src/os.c:382,418-423` continues after a void cleanup
        // failure; Rust returns `AlignedMappingFailure` with the exact live
        // owner. The native producer validates both side-specific traces and
        // records that accepted safety strengthening explicitly.
        m2_aligned_overmap_direct_aligned_process_witness();
        m2_aligned_overmap_direct_map_failure_prefix_zero_witness();
        m2_aligned_overmap_complete_cleanup_process_witness();
        for access in [MapAccess::Reserved, MapAccess::Committed] {
            for cleanup_ordinal in 1..=3 {
                m2_aligned_overmap_cleanup_failure_process_witness(access, cleanup_ordinal);
            }
        }

        macro_rules! emit {
            ($name:literal) => {
                std::println!("{}=1", $name);
            };
        }

        std::println!("CRABC_MI_M2_ALIGNED_OVERMAP_TRACE_BEGIN");
        emit!("m2.vm.aligned_overmap.rust.normal_direct_aligned_owner_and_stats");
        emit!("m2.vm.aligned_overmap.rust.direct_map_failure_fallback_prefix_zero_suffix_only");
        emit!("m2.vm.aligned_overmap.rust.complete_direct_prefix_suffix_cleanup_owner_and_stats");
        emit!("m2.vm.aligned_overmap.rust.direct_cleanup_failure_reserved_retains_owner_once");
        emit!("m2.vm.aligned_overmap.rust.direct_cleanup_failure_committed_retains_owner_once");
        emit!("m2.vm.aligned_overmap.rust.prefix_cleanup_failure_reserved_retains_full_overmap_once");
        emit!("m2.vm.aligned_overmap.rust.prefix_cleanup_failure_committed_retains_full_overmap_once");
        emit!("m2.vm.aligned_overmap.rust.suffix_cleanup_failure_reserved_retains_suffix_once");
        emit!("m2.vm.aligned_overmap.rust.suffix_cleanup_failure_committed_retains_suffix_once");
        std::println!("CRABC_MI_M2_ALIGNED_OVERMAP_TRACE_END");
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
    /// ownership and transition facts, never virtual addresses. It also
    /// records one direct offset-release error/retry: the pinned-C side
    /// intercepts only that `munmap` import, while this side uses the
    /// test-only syscall seam before the same typed release owner. Both
    /// records require the full base/length owner to remain live and source
    /// statistics to apply again when the caller retries.
    ///
    /// It also compares the selected `allow_thp=0` source configuration and
    /// process-policy observation. The Rust side executes that `prctl`
    /// transition only in its child and imports its address-free result, so
    /// the native test runner never inherits the allocator policy. A separate
    /// bounded record then routes a resolved policy and live ticket-zero
    /// random image through the first-arena owner, forcing the source-aligned
    /// large-map retry and ignored THP-advice error.
    ///
    /// It is not a claim for unowned source policy branches. In particular,
    /// ambient option discovery, random aligned hints, large/1-GiB huge-page
    /// reservation, diagnostics, and arena placement require their actual
    /// owners before the VM component can close.
    #[cfg(not(miri))]
    #[test]
    fn emit_m2_vm_primitives_c_rust_trace() {
        let fault = fault::install(fault::Plan::disabled());
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
        let [
            aligned_hint_cold_missing_default_advances,
            aligned_hint_eligibility_geometry,
            aligned_hint_initialized_first_start,
            aligned_hint_strict_threshold_and_one_draw,
            aligned_hint_ignored_cas_failure,
        ] = normal_release_aligned_hint_matrix();
        assert!(
            aligned_hint_cold_missing_default_advances
                && aligned_hint_eligibility_geometry
                && aligned_hint_initialized_first_start
                && aligned_hint_strict_threshold_and_one_draw
                && aligned_hint_ignored_cas_failure,
            "the finite normal-release aligned-hint source matrix must remain complete"
        );

        // Keep the ordinary transition source pair alive through every
        // operation. The C companion drives the same `mi_subproc_t` through
        // `_mi_os_*`; this receiver proves a failed raw primitive cannot
        // discard or replace the typed Rust mapping that owns its retry.
        let transition_policy = VmPolicy::defaults_for_test();
        assert!(
            transition_policy.purge_decommits(),
            "the selected fixed source profile starts in its decommit purge arm"
        );
        let transition_subprocess = crate::subproc::MainSubprocess::test_static_owner();
        let transition_process = VmProcess::new(&transition_policy, transition_subprocess);
        let mut reserved = Mapping::map_for_process(
            transition_process,
            config,
            page,
            1,
            MapAccess::Reserved,
            false,
            None,
        )
        .expect("the fixed trace reserves one process-owned page");
        let reserved_initially_zero = reserved.initially_zero();
        let reserved_initially_committed = reserved.initially_committed();
        let reserved_base = reserved.base().expect("the reserved transition owner starts live");

        let before_failed_commit = transition_subprocess.vm_statistics().snapshot();
        fault.set(fault::Plan::at(fault::Point::Commit, 1, Errno::NOMEM));
        let commit_failure_returns_false = matches!(
            reserved.commit_for_process(transition_process, 0, page, 0),
            Err(Errno::NOMEM)
        );
        let after_failed_commit = transition_subprocess.vm_statistics().snapshot();
        let commit_failure_is_one_source_attempt_and_counters_unchanged =
            fault.observed() == 1
            && reserved.base() == Ok(reserved_base)
            && after_failed_commit.commit_calls == before_failed_commit.commit_calls + 1
            && after_failed_commit.committed_current == before_failed_commit.committed_current;
        fault.set(fault::Plan::disabled());
        assert_eq!(
            reserved.commit_for_process(transition_process, 0, page, 0),
            Ok(Some(CommitOutcome::NotKnownZero)),
            "the source commit covers the complete one-page reservation"
        );
        let commit_retry_is_one_additional_source_attempt =
            transition_subprocess.vm_statistics().snapshot().commit_calls
                == after_failed_commit.commit_calls + 1;

        fault.set(fault::Plan::at(fault::Point::Decommit, 1, Errno::NOMEM));
        let decommit_failure_returns_false = matches!(
            reserved.decommit_for_process(transition_process, 0, page, page),
            Err(Errno::NOMEM)
        );
        let decommit_failure_is_one_source_attempt =
            fault.observed() == 1 && reserved.base() == Ok(reserved_base);
        fault.set(fault::Plan::disabled());
        let decommit_retry_is_one_additional_source_attempt = matches!(
            reserved.decommit_for_process(transition_process, 0, page, page),
            Ok(Some(DecommitOutcome::DoesNotNeedRecommit))
        );
        assert!(
            decommit_retry_is_one_additional_source_attempt,
            "the default Linux source decommit retry keeps the mapping accessible"
        );

        // The following bounded record is the entire normal-release source
        // state machine from `src/prim/unix/prim.c:581-593`. It keeps the
        // direct `_mi_os_reset` receiver distinct from the later no-callback
        // `_mi_os_purge_ex` receiver, while the test-only import seam records
        // every attempted advice just as the C link wrapper does.
        RESET_ADVICE.store(MADV_FREE as usize, Ordering::Release);
        let before_reset_eagain = transition_subprocess.vm_statistics().snapshot();
        let reset_eagain_capture = fault.capture_advice_range();
        fault.set(fault::Plan::at(fault::Point::Purge, 1, Errno::AGAIN));
        let reset_eagain_succeeds =
            reserved.reset_for_process(transition_process, 0, page) == Ok(true);
        let after_reset_eagain = transition_subprocess.vm_statistics().snapshot();
        let reset_eagain_ranges = reset_eagain_capture.ranges();
        drop(reset_eagain_capture);
        let reset_eagain_retries_initial_madv_free = reset_eagain_succeeds
            && fault.observed() == 2
            && RESET_ADVICE.load(Ordering::Acquire) == MADV_FREE as usize
            && matches!(
                reset_eagain_ranges,
                Some((ranges, 2))
                    if ranges[0] == (reserved_base.addr(), page, MADV_FREE)
                        && ranges[1] == (reserved_base.addr(), page, MADV_FREE)
            )
            && after_reset_eagain.reset_calls == before_reset_eagain.reset_calls + 1
            && after_reset_eagain.reset == before_reset_eagain.reset + page as i64
            && reserved.base() == Ok(reserved_base);

        let before_fallback_eagain = transition_subprocess.vm_statistics().snapshot();
        let fallback_eagain_capture = fault.capture_advice_range();
        fault.set(fault::Plan::at_triple_with_errors(
            fault::Point::Purge,
            1,
            Errno::AGAIN,
            fault::Point::Purge,
            1,
            Errno::INVAL,
            fault::Point::Purge,
            1,
            Errno::AGAIN,
        ));
        let fallback_eagain_reports_error = matches!(
            reserved.reset_for_process(transition_process, 0, page),
            Err(Errno::AGAIN)
        );
        let after_fallback_eagain = transition_subprocess.vm_statistics().snapshot();
        let fallback_eagain_ranges = fallback_eagain_capture.ranges();
        drop(fallback_eagain_capture);
        let reset_fallback_eagain_returns_error_after_one_fallback_attempt =
            fallback_eagain_reports_error
                && fault.observed() == 3
                && fault.secondary_observed() == 2
                && fault.third_observed() == 1
                && RESET_ADVICE.load(Ordering::Acquire) == MADV_DONTNEED as usize
                && matches!(
                    fallback_eagain_ranges,
                    Some((ranges, 3))
                        if ranges[0] == (reserved_base.addr(), page, MADV_FREE)
                            && ranges[1] == (reserved_base.addr(), page, MADV_FREE)
                            && ranges[2] == (reserved_base.addr(), page, MADV_DONTNEED)
                )
                && after_fallback_eagain.reset_calls
                    == before_fallback_eagain.reset_calls + 1
                && after_fallback_eagain.reset == before_fallback_eagain.reset + page as i64
                && reserved.base() == Ok(reserved_base);

        // The prior error has permanently changed this test process's source
        // cache. Reinitialize only the test static to model the independent
        // source process that the C fixture forks for the fallback-error row;
        // the succeeding row below remains the live parent state used by the
        // later no-callback purge receiver.
        RESET_ADVICE.store(MADV_FREE as usize, Ordering::Release);
        let before_reset_fallback = transition_subprocess.vm_statistics().snapshot();
        let reset_fallback_capture = fault.capture_advice_range();
        fault.set(fault::Plan::at_pair_with_errors(
            fault::Point::Purge,
            1,
            Errno::AGAIN,
            fault::Point::Purge,
            1,
            Errno::INVAL,
        ));
        let reset_fallback_succeeds =
            reserved.reset_for_process(transition_process, 0, page) == Ok(true);
        let after_reset_fallback = transition_subprocess.vm_statistics().snapshot();
        let reset_fallback_ranges = reset_fallback_capture.ranges();
        drop(reset_fallback_capture);
        let reset_madv_free_einval_falls_back_to_dontneed = reset_fallback_succeeds
            && fault.observed() == 3
            && fault.secondary_observed() == 2
            && RESET_ADVICE.load(Ordering::Acquire) == MADV_DONTNEED as usize
            && matches!(
                reset_fallback_ranges,
                Some((ranges, 3))
                    if ranges[0] == (reserved_base.addr(), page, MADV_FREE)
                        && ranges[1] == (reserved_base.addr(), page, MADV_FREE)
                        && ranges[2] == (reserved_base.addr(), page, MADV_DONTNEED)
            )
            && after_reset_fallback.reset_calls == before_reset_fallback.reset_calls + 1
            && after_reset_fallback.reset == before_reset_fallback.reset + page as i64
            && reserved.base() == Ok(reserved_base);

        fault.set(fault::Plan::at(fault::Point::Decommit, 1, Errno::NOMEM));
        let purge_decommit_failure_no_recommit =
            reserved.purge_for_process(transition_process, 0, page, true, page) == Ok(false)
                && fault.observed() == 1
                && reserved.base() == Ok(reserved_base);
        // Keep a later failure ordinal armed so this successful retry still
        // proves exactly one Decommit primitive attempt without turning it
        // into another synthetic failure.
        fault.set(fault::Plan::at(fault::Point::Decommit, 2, Errno::NOMEM));
        let purge_decommit_retry_no_recommit =
            reserved.purge_for_process(transition_process, 0, page, true, page) == Ok(false)
                && fault.observed() == 1
                && reserved.base() == Ok(reserved_base);
        fault.set(fault::Plan::disabled());
        let reuse_linux_noop = matches!(
            reserved.reuse(0, page),
            Ok(Some(ReuseOutcome::NoOp))
        );
        assert!(
            reuse_linux_noop,
            "Linux reuse has no VM syscall after conservative page normalization"
        );

        fault.set(fault::Plan::at(fault::Point::Protect, 1, Errno::NOMEM));
        let protect_failure_returns_false_and_one_source_attempt = matches!(
            reserved.protect(0, page),
            Err(Errno::NOMEM)
        ) && fault.observed() == 1 && reserved.base() == Ok(reserved_base);
        fault.set(fault::Plan::disabled());
        let protect_retry_is_one_additional_source_attempt =
            reserved.protect(0, page).expect("the source protect retry succeeds");
        assert!(protect_retry_is_one_additional_source_attempt);

        fault.set(fault::Plan::at(fault::Point::Unprotect, 1, Errno::NOMEM));
        let unprotect_failure_returns_false_and_one_source_attempt = matches!(
            reserved.unprotect(0, page),
            Err(Errno::NOMEM)
        ) && fault.observed() == 1 && reserved.base() == Ok(reserved_base);
        fault.set(fault::Plan::disabled());
        let unprotect_retry_is_one_additional_source_attempt = reserved
            .unprotect(0, page)
            .expect("the source unprotect retry succeeds");
        assert!(unprotect_retry_is_one_additional_source_attempt);
        reserved
            .unmap_for_process(transition_process, page, false)
            .expect("the fixed trace releases the reserved source owner once");

        let mut reset_policy = VmPolicy::defaults_for_test();
        reset_policy.set_option(VmOption::PurgeDecommits, 0);
        let reset_subprocess = crate::subproc::MainSubprocess::test_static_owner();
        let reset_process = VmProcess::new(&reset_policy, reset_subprocess);
        let mut reset_mapping = Mapping::map_for_process(
            reset_process,
            config,
            page,
            1,
            MapAccess::Committed,
            false,
            None,
        )
        .expect("the reset-purge option arm receives one owned mapping");
        let reset_mapping_base = reset_mapping.base().expect("the reset-purge owner starts live");
        let before_purge_reset_failure = reset_subprocess.vm_statistics().snapshot();
        let purge_reset_capture = fault.capture_advice_range();
        fault.set(fault::Plan::at_pair_with_errors(
            fault::Point::Purge,
            1,
            Errno::AGAIN,
            fault::Point::Purge,
            1,
            Errno::NOMEM,
        ));
        let purge_reset_failure_is_consumed = reset_mapping
            .purge_for_process(reset_process, 0, page, true, page) == Ok(false);
        let after_purge_reset_failure = reset_subprocess.vm_statistics().snapshot();
        let purge_reset_ranges = purge_reset_capture.ranges();
        drop(purge_reset_capture);
        let reset_dontneed_persists_to_no_callback_purge = matches!(
            purge_reset_ranges,
            Some((ranges, 2))
                if ranges[0] == (reset_mapping_base.addr(), page, MADV_DONTNEED)
                    && ranges[1] == (reset_mapping_base.addr(), page, MADV_DONTNEED)
        );
        let purge_reset_eagain_then_error_is_consumed_and_owner_retained =
            purge_reset_failure_is_consumed
                && fault.observed() == 2
                && fault.secondary_observed() == 1
                && reset_dontneed_persists_to_no_callback_purge
                && reset_mapping.base() == Ok(reset_mapping_base)
                && after_purge_reset_failure.purge_calls
                    == before_purge_reset_failure.purge_calls + 1
                && after_purge_reset_failure.purged
                    == before_purge_reset_failure.purged + page as i64
                && after_purge_reset_failure.reset_calls
                    == before_purge_reset_failure.reset_calls + 1
                && after_purge_reset_failure.reset
                    == before_purge_reset_failure.reset + page as i64
                && after_purge_reset_failure.committed_current
                    == before_purge_reset_failure.committed_current;
        fault.set(fault::Plan::disabled());
        reset_mapping
            .unmap_for_process(reset_process, page, false)
            .expect("the reset-purge owner releases after its consumed advisory failure");

        let normal_no_callback_purge_matrix =
            normal_no_callback_purge_policy_range_matrix(config, &fault);
        let offset_prefix_decommit_success_attempt_and_full_owner =
            process_offset_prefix_decommit_receiver(config, &fault, false);
        let offset_prefix_decommit_failure_attempt_consumed_and_full_owner =
            process_offset_prefix_decommit_receiver(config, &fault, true);

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

        // The C companion forces the next source `_mi_prim_free` import to
        // return ENOMEM while `_mi_os_free_ex` releases this same interior
        // offset shape. Its source statistics still move before the caller
        // gets another chance to free the full MemoryId. Keep the typed Rust
        // owner and the identical counter timing visible in this finite
        // differential without making a test seam part of the production VM
        // interface.
        let subprocess = crate::subproc::MainSubprocess::test_static_owner();
        let process_policy = VmPolicy::defaults_for_test();
        let process = VmProcess::new(&process_policy, subprocess);
        let failed_release = NormalOsAllocation::allocate_aligned_at_offset_for_process(
            process,
            config,
            page.checked_mul(2).expect("the fixed failure request fits"),
            alignment,
            offset,
            MapAccess::Committed,
            false,
            None,
        )
        .expect("the fixed failure record acquires one offset owner");
        let failed_release_base = failed_release
            .base()
            .expect("the failure record retains its full base");
        let failed_release_pointer = failed_release
            .pointer()
            .expect("the failure record retains its interior client pointer");
        let failed_release_size = failed_release
            .full_size()
            .expect("the failure record retains its full mapping size");
        let failed_release_memory = failed_release
            .memory_id()
            .expect("the failure record retains full source provenance");
        let failed_release_prefix = failed_release_pointer.as_ptr().addr() - failed_release_base.addr();
        let failed_release_commit_size = failed_release_size
            .checked_sub(failed_release_prefix)
            .expect("the interior client prefix is within the exact map");
        assert!(failed_release_prefix != 0, "the selected client pointer is interior");
        assert_eq!(
            failed_release_memory.os_base().map(|base| base.value()),
            Some(failed_release_base.addr())
        );
        assert_eq!(failed_release_memory.size(), Some(failed_release_size));

        let statistics_before_failure = subprocess.vm_statistics().snapshot();
        fault.set(fault::Plan::at(fault::Point::Unmap, 1, Errno::NOMEM));
        let failed_release_unmap_ranges = fault.capture_unmap_ranges();
        let retained = match failed_release.release_for_process(process, true) {
            Ok(()) => panic!("the selected source release must retain its owner on error"),
            Err(failure) => failure,
        };
        assert_eq!(retained.error(), Errno::NOMEM);
        let failed_release_one_primitive_attempt = fault.observed() == 1;
        let statistics_after_failure = subprocess.vm_statistics().snapshot();
        let failed_release_source_counters_apply =
            statistics_after_failure.reserved_current
                == statistics_before_failure.reserved_current - failed_release_size as i64
                && statistics_after_failure.committed_current
                    == statistics_before_failure.committed_current
                        - failed_release_commit_size as i64;
        assert!(failed_release_source_counters_apply);

        let retained = retained.into_allocation();
        assert_eq!(retained.base(), Ok(failed_release_base));
        assert_eq!(retained.full_size(), Ok(failed_release_size));
        assert_eq!(retained.pointer(), Ok(failed_release_pointer));
        assert_eq!(
            retained.memory_id().unwrap().os_base().map(|base| base.value()),
            Some(failed_release_base.addr())
        );
        // SAFETY: the injected fault occurs before `munmap`, and the retained
        // owner still proves that its client pointer names writable memory.
        unsafe {
            core::ptr::write_volatile(failed_release_pointer.as_ptr(), 0x7c);
            assert_eq!(core::ptr::read_volatile(failed_release_pointer.as_ptr()), 0x7c);
        }
        let failed_release_mapping_live = true;

        // Keep the one-shot plan installed. The first selected Unmap failed;
        // its second observation reaches the actual syscall and therefore
        // mirrors the C wrapper's exact one additional primitive invocation.
        retained
            .release_for_process(process, true)
            .expect("the retained offset owner releases on its explicit retry");
        let failed_release_retry_one_additional_primitive_attempt = fault.observed() == 2;
        let statistics_after_retry = subprocess.vm_statistics().snapshot();
        let failed_release_retry_source_counters_reapply =
            statistics_after_retry.reserved_current
                == statistics_after_failure.reserved_current - failed_release_size as i64
                && statistics_after_retry.committed_current
                    == statistics_after_failure.committed_current
                        - failed_release_commit_size as i64;
        assert!(failed_release_retry_source_counters_reapply);
        let [(failure_address, failure_length), (retry_address, retry_length)] =
            failed_release_unmap_ranges
                .ranges()
                .expect("the selected failure and retry each reach one full-map unmap boundary");
        let failed_release_failure_uses_full_memid =
            failure_address == failed_release_base.addr() && failure_length == failed_release_size;
        let failed_release_retry_uses_full_memid =
            retry_address == failed_release_base.addr() && retry_length == failed_release_size;
        assert!(
            failed_release_failure_uses_full_memid,
            "the injected normal-offset failure must call munmap with the retained MemoryId base and full size"
        );
        assert!(
            failed_release_retry_uses_full_memid,
            "the explicit retry must reuse the retained MemoryId base and full size"
        );

        let numa_count = os_numa_node_count();
        let numa_current = os_numa_node();
        assert!(numa_count >= 1, "the allocator-facing NUMA cache normalizes to one");
        assert!(numa_current < numa_count, "the source current-node route normalizes modulo count");

        // The release record used the serial injection guard above. Its exact
        // full-range capture is complete now; release it before the separate
        // policy witness takes the same serial source-fault boundary.
        drop(failed_release_unmap_ranges);
        let external_callback_trace = crate::arena::m2_external_callback_trace(&fault);
        drop(fault);
        let thp_direct_policy_trace = thp_direct_policy_outcome_trace();
        let large_page_retry_trace = normal_release_large_page_retry_suppression_matrix();
        let large_page_retry_cas_trace = normal_release_large_page_retry_competing_cas_matrix();
        let large_only_trace = large_only_one_gib_failure_terminal_matrix();
        assert_eq!(thp_direct_policy_trace, [true; 8]);
        assert_eq!(large_page_retry_trace, [true; 6]);
        assert_eq!(large_page_retry_cas_trace, [true; 2]);
        assert_eq!(large_only_trace, [true; 4]);
        let policy_trace = crate::process_arena::m2_vm_policy_first_arena_trace();

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
        emit!(
            "m2.vm.thp_direct.allow_enabled_zero_calls_and_continues",
            u8::from(thp_direct_policy_trace[0])
        );
        emit!(
            "m2.vm.thp_direct.query_perm_get_only_disabled_and_continues",
            u8::from(thp_direct_policy_trace[1])
        );
        emit!(
            "m2.vm.thp_direct.query_inval_get_only_disabled_and_continues",
            u8::from(thp_direct_policy_trace[2])
        );
        emit!(
            "m2.vm.thp_direct.query_nonzero_one_get_only_disabled_and_continues",
            u8::from(thp_direct_policy_trace[3])
        );
        emit!(
            "m2.vm.thp_direct.query_nonzero_three_get_only_disabled_and_continues",
            u8::from(thp_direct_policy_trace[4])
        );
        emit!(
            "m2.vm.thp_direct.set_success_exact_get_set_disabled_and_continues",
            u8::from(thp_direct_policy_trace[5])
        );
        emit!(
            "m2.vm.thp_direct.set_perm_exact_get_set_disabled_and_continues",
            u8::from(thp_direct_policy_trace[6])
        );
        emit!(
            "m2.vm.thp_direct.set_inval_exact_get_set_disabled_and_continues",
            u8::from(thp_direct_policy_trace[7])
        );
        emit!("m2.vm.reserved.initially_zero", u8::from(reserved_initially_zero));
        emit!(
            "m2.vm.reserved.initially_committed",
            u8::from(reserved_initially_committed)
        );
        emit!(
            "m2.vm.reserved.commit.failure_returns_false",
            u8::from(commit_failure_returns_false)
        );
        emit!(
            "m2.vm.reserved.commit.failure.one_source_attempt_and_counters_unchanged",
            u8::from(commit_failure_is_one_source_attempt_and_counters_unchanged)
        );
        emit!(
            "m2.vm.reserved.commit.retry.one_additional_source_attempt",
            u8::from(commit_retry_is_one_additional_source_attempt)
        );
        emit!("m2.vm.reserved.commit_not_known_zero", 1);
        emit!(
            "m2.vm.reserved.decommit.failure_returns_false",
            u8::from(decommit_failure_returns_false)
        );
        emit!(
            "m2.vm.reserved.decommit.failure.one_source_attempt",
            u8::from(decommit_failure_is_one_source_attempt)
        );
        emit!(
            "m2.vm.reserved.decommit.retry.one_additional_source_attempt",
            u8::from(decommit_retry_is_one_additional_source_attempt)
        );
        emit!("m2.vm.reserved.decommit_no_recommit", 1);
        emit!(
            "m2.vm.reserved.reset.madv_free_einval_falls_back_to_dontneed",
            u8::from(reset_madv_free_einval_falls_back_to_dontneed)
        );
        emit!(
            "m2.vm.reserved.reset.eagain_retries_initial_madv_free",
            u8::from(reset_eagain_retries_initial_madv_free)
        );
        emit!(
            "m2.vm.reserved.reset.fallback_eagain_returns_error_after_one_fallback_attempt",
            u8::from(reset_fallback_eagain_returns_error_after_one_fallback_attempt)
        );
        emit!("m2.vm.reserved.reset_success", 1);
        emit!(
            "m2.vm.reserved.purge.decommit_failure_no_recommit",
            u8::from(purge_decommit_failure_no_recommit)
        );
        emit!(
            "m2.vm.reserved.purge.decommit_retry_no_recommit",
            u8::from(purge_decommit_retry_no_recommit)
        );
        emit!(
            "m2.vm.reserved.purge.reset_failure_is_consumed",
            u8::from(purge_reset_failure_is_consumed)
        );
        emit!(
            "m2.vm.reserved.reset.dontneed_persists_to_no_callback_purge",
            u8::from(reset_dontneed_persists_to_no_callback_purge)
        );
        emit!(
            "m2.vm.reserved.purge.reset_eagain_then_error_is_consumed_and_owner_retained",
            u8::from(purge_reset_eagain_then_error_is_consumed_and_owner_retained)
        );
        emit!(
            "m2.vm.reserved.purge.normal_no_callback_policy_range_matrix",
            u8::from(normal_no_callback_purge_matrix)
        );
        emit!("m2.vm.reserved.reuse_linux_noop", u8::from(reuse_linux_noop));
        emit!(
            "m2.vm.reserved.protect.failure_returns_false_and_one_source_attempt",
            u8::from(protect_failure_returns_false_and_one_source_attempt)
        );
        emit!(
            "m2.vm.reserved.protect.retry.one_additional_source_attempt",
            u8::from(protect_retry_is_one_additional_source_attempt)
        );
        emit!("m2.vm.reserved.protect_success", 1);
        emit!(
            "m2.vm.reserved.unprotect.failure_returns_false_and_one_source_attempt",
            u8::from(unprotect_failure_returns_false_and_one_source_attempt)
        );
        emit!(
            "m2.vm.reserved.unprotect.retry.one_additional_source_attempt",
            u8::from(unprotect_retry_is_one_additional_source_attempt)
        );
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
        emit!(
            "m2.vm.offset.prefix_decommit.success_attempt_and_full_owner",
            u8::from(offset_prefix_decommit_success_attempt_and_full_owner)
        );
        emit!(
            "m2.vm.offset.prefix_decommit.failure_attempt_consumed_and_full_owner",
            u8::from(offset_prefix_decommit_failure_attempt_consumed_and_full_owner)
        );
        emit!("m2.vm.release.offset_owner_interior", 1);
        emit!(
            "m2.vm.release.failure.one_primitive_attempt",
            u8::from(failed_release_one_primitive_attempt)
        );
        emit!(
            "m2.vm.release.failure.full_memid_base_and_size",
            u8::from(failed_release_failure_uses_full_memid)
        );
        emit!(
            "m2.vm.release.failure.mapping_live",
            u8::from(failed_release_mapping_live)
        );
        emit!(
            "m2.vm.release.failure.source_counters_apply",
            u8::from(failed_release_source_counters_apply)
        );
        emit!(
            "m2.vm.release.retry.one_additional_primitive_attempt",
            u8::from(failed_release_retry_one_additional_primitive_attempt)
        );
        emit!(
            "m2.vm.release.retry.full_memid_base_and_size",
            u8::from(failed_release_retry_uses_full_memid)
        );
        emit!(
            "m2.vm.release.retry.source_counters_reapply",
            u8::from(failed_release_retry_source_counters_reapply)
        );
        emit!("m2.vm.release.retry.real_munmap_success", 1);
        emit!("m2.vm.external.callback.managed_typed_owner", external_callback_trace[0]);
        emit!("m2.vm.external.callback.commit_zero_propagated", external_callback_trace[1]);
        emit!("m2.vm.external.callback.purge_raw_span_null_zero_and_statistics", external_callback_trace[2]);
        emit!("m2.vm.external.callback.purge_true_clears_commit", external_callback_trace[3]);
        emit!("m2.vm.external.callback.recommit_reinvokes_callback", external_callback_trace[4]);
        emit!("m2.vm.external.callback.purge_false_preserves_commit", external_callback_trace[5]);
        emit!("m2.vm.external.callback.purge_mixed_clears_commit", external_callback_trace[6]);
        emit!("m2.vm.external.callback.negative_delay_skips_callback_and_statistics", external_callback_trace[7]);
        emit!("m2.vm.external.callback.no_normal_advice", external_callback_trace[8]);
        emit!("m2.vm.external.callback.one_published_owner_per_registry", external_callback_trace[9]);
        emit!(
            "m2.vm.external.page_extension.direct_commit_fault_bypasses_callback",
            external_callback_trace[10]
        );
        emit!(
            "m2.vm.external.page_extension.failure_preserves_unpublished_state",
            external_callback_trace[11]
        );
        emit!(
            "m2.vm.external.page_extension.retry_commits_without_callback",
            external_callback_trace[12]
        );
        emit!("m2.vm.numa.count_at_least_one", u8::from(numa_count >= 1));
        emit!("m2.vm.numa.current_lt_count", u8::from(numa_current < numa_count));
        emit!(
            "m2.vm.aligned_hint.cold_missing_default_advances_cursor",
            u8::from(aligned_hint_cold_missing_default_advances)
        );
        emit!(
            "m2.vm.aligned_hint.eligibility_and_geometry",
            u8::from(aligned_hint_eligibility_geometry)
        );
        emit!(
            "m2.vm.aligned_hint.initialized_first_randomized_start",
            u8::from(aligned_hint_initialized_first_start)
        );
        emit!(
            "m2.vm.aligned_hint.strict_max_then_wrap_one_draw",
            u8::from(aligned_hint_strict_threshold_and_one_draw)
        );
        emit!(
            "m2.vm.aligned_hint.ignored_cas_failure_second_fetch",
            u8::from(aligned_hint_ignored_cas_failure)
        );
        emit!(
            "m2.vm.policy.source_options_applied",
            u8::from(policy_trace.source_options_applied)
        );
        emit!("m2.vm.policy.first_arena_size", policy_trace.first_arena_size);
        emit!(
            "m2.vm.policy.first_arena_initially_committed",
            u8::from(policy_trace.first_arena_initially_committed)
        );
        emit!(
            "m2.vm.policy.large_high_hint_failed",
            u8::from(policy_trace.large_high_hint_failed)
        );
        emit!(
            "m2.vm.policy.large_null_hint_retry_failed",
            u8::from(policy_trace.large_null_hint_retry_failed)
        );
        emit!(
            "m2.vm.policy.regular_hinted_map_after_large_fallback",
            u8::from(policy_trace.regular_hinted_map_after_large_fallback)
        );
        emit!(
            "m2.vm.policy.thp_advice_failure_ignored",
            u8::from(policy_trace.thp_advice_failure_ignored)
        );
        emit!(
            "m2.vm.large_retry.initial_failed_large_regular_owner",
            u8::from(large_page_retry_trace[0])
        );
        emit!(
            "m2.vm.large_retry.allow_large_false_preserves_counter",
            u8::from(large_page_retry_trace[1])
        );
        emit!(
            "m2.vm.large_retry.ineligible_geometry_preserves_counter",
            u8::from(large_page_retry_trace[2])
        );
        emit!(
            "m2.vm.large_retry.option_disabled_preserves_counter",
            u8::from(large_page_retry_trace[3])
        );
        emit!(
            "m2.vm.large_retry.eight_suppressed_regular_owners",
            u8::from(large_page_retry_trace[4])
        );
        emit!(
            "m2.vm.large_retry.ninth_reopens_large_regular_owner",
            u8::from(large_page_retry_trace[5])
        );
        emit!(
            "m2.vm.large_retry.competing_cas_failure_regular_owner",
            u8::from(large_page_retry_cas_trace[0])
        );
        emit!(
            "m2.vm.large_retry.competing_cas_seven_then_reopens",
            u8::from(large_page_retry_cas_trace[1])
        );
        emit!(
            "m2.vm.large_only.first_one_gib_then_two_mib_same_claim_terminal_enomem",
            u8::from(large_only_trace[0])
        );
        emit!(
            "m2.vm.large_only.second_only_two_mib_after_sticky_unavailable",
            u8::from(large_only_trace[1])
        );
        emit!(
            "m2.vm.large_only.all_raw_maps_are_huge_and_no_regular_owner",
            u8::from(large_only_trace[2])
        );
        emit!(
            "m2.vm.large_only.terminal_failures_leave_statistics_and_owners_unpublished",
            u8::from(large_only_trace[3])
        );
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
