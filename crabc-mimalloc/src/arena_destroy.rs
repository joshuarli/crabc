// Copyright (c) 2018-2026 Microsoft Research, Daan Leijen
// SPDX-License-Identifier: MIT
// Source: mimalloc v3.5.0 src/arena.c:1542-1565, src/os.c:258-284.

//! Quiescent destruction of the persistent subprocess arena group.
//!
//! Snapshot only ownership facts before releasing memory: a parent OS memid
//! can cover later subarena headers. Reading those headers after the parent's
//! free would violate Rust lifetime rules. Registry clears and primitive frees
//! still occur in source index order; snapshots cause no observable VM action.

use super::{ProcessArenaBacking, ARENA_SLOT_COUNT};
use crate::config::MAX_ARENAS;
use crate::os::{HugeOsAllocation, HugeOsRawReleaseRetry, HugeOsReleaseFailure, Mapping};
use core::sync::atomic::Ordering;
use crabc_core::Errno;
use crate::types::{MemoryId, MemoryKind};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ArenaDestroyError {
    AlreadyDestroyed,
    InvalidOwnership,
    TrackingCapacity { required_words: usize },
    TrackingInsideArena,
}

enum FailedArenaRelease<'tracking> {
    Regular(Mapping),
    Huge(HugeOsRawReleaseRetry<'static, &'tracking mut [usize]>),
}

/// Linear owner of failed releases after the registry has been retired.
/// Dropping this value never retries syscalls; callers must retain it until
/// explicit raw retry succeeds. Its huge-page bitmaps borrow storage supplied
/// before destruction, so no metadata allocation/free can recurse into a
/// retiring allocator. The fixed array is indexed by the first source registry entry for each allocation.
#[must_use = "retain failed arena releases until explicit raw retry succeeds"]
pub(crate) struct DestroyedArenas<'tracking> {
    failures: [Option<FailedArenaRelease<'tracking>>; ARENA_SLOT_COUNT],
}

impl DestroyedArenas<'_> {
    pub(crate) fn is_released(&self) -> bool {
        self.failures.iter().all(Option::is_none)
    }

    /// Retries only ranges still owned after the initial source-accounted
    /// pass. No registry state or source statistics are changed again.
    pub(crate) fn retry_raw(&mut self) -> Result<(), Errno> {
        let mut first_error = None;
        for failure in &mut self.failures {
            let Some(pending) = failure.take() else { continue; };
            match pending {
                FailedArenaRelease::Regular(mut mapping) => {
                    if let Err(error) = mapping.unmap() {
                        first_error.get_or_insert(error);
                        *failure = Some(FailedArenaRelease::Regular(mapping));
                    }
                }
                FailedArenaRelease::Huge(retry) => {
                    if let Err(error) = retry.retry_raw() {
                        first_error.get_or_insert(error.error());
                        *failure = Some(FailedArenaRelease::Huge(error.into_retry()));
                    }
                }
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

impl ProcessArenaBacking {
    /// Sizes external huge-release ownership bits before destructive work.
    /// Only published source owners contribute; the consuming pass still
    /// validates complete registry/owner correspondence before any mutation.
    ///
    /// # Safety
    /// The process is permanently quiescent; no arena owner can publish,
    /// disappear, or change between this observation and `destroy_all`.
    pub(crate) unsafe fn terminal_tracking_words(&self) -> Result<usize, ArenaDestroyError> {
        if self.destroyed.load(Ordering::Acquire) { return Err(ArenaDestroyError::AlreadyDestroyed); }
        if self.huge_cleanup_retained.load(Ordering::Acquire) { return Err(ArenaDestroyError::InvalidOwnership); }
        if self.preparing.load(Ordering::Acquire) != 0
            || self.preparation_retained.load(Ordering::Acquire) { return Err(ArenaDestroyError::InvalidOwnership); }
        let mut words = 0usize;
        for index in 0..self.registry.count() {
            let Some(arena) = (unsafe { self.registry.arena_at(index) }) else { continue; };
            if !arena.parent.is_null() { continue; }
            words = words.checked_add(huge_tracking_words(arena.memid)?)
                .ok_or(ArenaDestroyError::InvalidOwnership)?;
        }
        Ok(words)
    }

    /// Destroys the published arena registry in source order and permanently
    /// retires this group. External memory is only unpublished, never freed.
    /// Failure tracking is supplied before the first registry mutation; an
    /// admission error leaves the group and all mappings intact.
    ///
    /// # Safety
    /// The caller has exclusive process/subprocess shutdown authority, has
    /// stopped every allocation, publication, purge, page/claim reader and
    /// remote producer, and has invalidated all pointers into owned arenas.
    /// No operation may subsequently use this group except read-only count
    /// observations. All callbacks and installations have returned. Pending
    /// unpublished cleanup must already be resolved. `self` and its subprocess
    /// statistics must live outside every retiring mapping. Tracking overlap
    /// is rejected before mutation. Retain the returned failure owner until
    /// its releases succeed; it grants no use of old allocations or arena IDs.
    pub(crate) unsafe fn destroy_all<'tracking>(
        &self,
        tracking: &'tracking mut [usize],
    ) -> Result<DestroyedArenas<'tracking>, ArenaDestroyError> {
        unsafe { self.destroy_all_with_huge_process(tracking, self.process_lived_projection()) }
    }

    /// Retire this exact child arena group under its actual context owner.
    /// A retained failed huge release carries a non-owning VM projection;
    /// the caller retains the child image until every such release ends.
    ///
    /// # Safety
    /// The caller meets `destroy_all`'s exclusive shutdown obligations and
    /// owns the pinned child context containing this arena group. It must
    /// retain that exact context, its immutable VM policy and its statistics
    /// through the returned failure owner's final successful raw release.
    /// The child metadata allocator has already stopped and no callback or
    /// member may resume allocation after this transition.
    pub(crate) unsafe fn destroy_all_retained_child<'tracking>(
        &self, tracking: &'tracking mut [usize],
    ) -> Result<DestroyedArenas<'tracking>, ArenaDestroyError> {
        let binding = unsafe { *self.binding.get() };
        let process = match binding {
            None => None,
            Some(binding) => {
                if binding.process.main_subprocess.is_some() {
                    return Err(ArenaDestroyError::InvalidOwnership);
                }
                // SAFETY: the caller retains the exact child context and
                // immutable policy through every returned raw failure. This
                // spelling grants no process-lived publication marker.
                let identity = unsafe { binding.process.subprocess.as_ref() };
                if !core::ptr::eq(identity.arena_backing(), self) {
                    return Err(ArenaDestroyError::InvalidOwnership);
                }
                Some(crate::os::VmProcess::new(unsafe { binding.process.policy.as_ref() }, identity))
            }
        };
        unsafe { self.destroy_all_with_huge_process(tracking, process) }
    }

    unsafe fn destroy_all_with_huge_process<'tracking>(
        &self, mut tracking: &'tracking mut [usize],
        huge_process: Option<crate::os::VmProcess<'static>>,
    ) -> Result<DestroyedArenas<'tracking>, ArenaDestroyError> {
        if self.destroyed.load(Ordering::Acquire) {
            return Err(ArenaDestroyError::AlreadyDestroyed);
        }
        if self.huge_cleanup_retained.load(Ordering::Acquire) {
            return Err(ArenaDestroyError::InvalidOwnership);
        }
        if self.preparing.load(Ordering::Acquire) != 0
            || self.preparation_retained.load(Ordering::Acquire) { return Err(ArenaDestroyError::InvalidOwnership); }
        let count = self.registry.count();
        if count > MAX_ARENAS { return Err(ArenaDestroyError::InvalidOwnership); }
        let mut releases = [None; MAX_ARENAS];
        let mut required_words = 0usize;
        let tracking_start = tracking.as_ptr().addr();
        let tracking_end = tracking_start.checked_add(core::mem::size_of_val(tracking))
            .ok_or(ArenaDestroyError::InvalidOwnership)?;
        for index in 0..count {
            let Some(arena) = (unsafe { self.registry.arena_at(index) }) else { continue; };
            let owner = unsafe { self.allocation_for_arena(arena) }
                .ok_or(ArenaDestroyError::InvalidOwnership)?;
            let span = owner.memory.os_memory().ok_or(ArenaDestroyError::InvalidOwnership)?;
            let duplicate = releases[..index].iter().flatten().any(|memory: &MemoryId|
                memory.os_memory().is_some_and(|previous| previous.base == span.base && previous.size == span.size));
            if duplicate { continue; }
            let end = span.base.addr().checked_add(span.size).ok_or(ArenaDestroyError::InvalidOwnership)?;
            if tracking_start < end && span.base.addr() < tracking_end {
                return Err(ArenaDestroyError::TrackingInsideArena);
            }
            if owner.memory.kind() == MemoryKind::OsHuge
                && huge_process.is_none() { return Err(ArenaDestroyError::InvalidOwnership); }
            required_words = required_words.checked_add(huge_tracking_words(owner.memory)?)
                .ok_or(ArenaDestroyError::InvalidOwnership)?;
            releases[index] = Some(owner.memory);
        }
        if tracking.len() < required_words {
            return Err(ArenaDestroyError::TrackingCapacity { required_words });
        }
        self.destroyed.store(true, Ordering::Release);
        let mut destroyed = DestroyedArenas { failures: [const { None }; ARENA_SLOT_COUNT] };
        // Snapshot before the first free: subarena headers can reside inside
        // a parent released at an earlier source registry index.
        let binding = unsafe { *self.binding.get() };
        for (index, memory) in releases.into_iter().enumerate().take(count) {
            self.registry.arenas[index].store(core::ptr::null_mut(), Ordering::Release);
            let Some(memory) = memory else { continue; };
            let binding = binding.ok_or(ArenaDestroyError::InvalidOwnership)?;
            match memory.kind() {
                MemoryKind::Os => {
                    // SAFETY: this exact published token is recovered once,
                    // after all source readers and callbacks have ended.
                    let mut mapping = unsafe { Mapping::recover_published(memory, binding.config.page_size()) }
                        .map_err(|_| ArenaDestroyError::InvalidOwnership)?;
                    let size = mapping.length().expect("preflight validated live mapping");
                    if mapping.unmap_for_process_with_warning(binding.process.project(), size, false, true).is_err() {
                        destroyed.failures[index] = Some(FailedArenaRelease::Regular(mapping));
                    }
                }
                MemoryKind::OsHuge => {
                    let process = huge_process.ok_or(ArenaDestroyError::InvalidOwnership)?;
                    // SAFETY: the selected process is permanently live or
                    // retained by the exact child context owner through all
                    // raw failures. The snapshot uniquely owns every primitive
                    // and all derived readers have become quiescent.
                    let allocation = unsafe { HugeOsAllocation::recover_published(process, memory) }
                        .ok_or(ArenaDestroyError::InvalidOwnership)?;
                    let (words, rest) = tracking.split_at_mut(allocation.release_tracking_words());
                    tracking = rest;
                    match allocation.release_for_process(words) {
                        Ok(()) => {}
                        Err(HugeOsReleaseFailure::FailedPages(retry)) => {
                            destroyed.failures[index] = Some(FailedArenaRelease::Huge(retry));
                        }
                        Err(HugeOsReleaseFailure::Tracking(_)) => unreachable!("preflight checked exact tracking capacity"),
                    }
                }
                MemoryKind::External => {}
                _ => unreachable!("preflight checked published provenance"),
            }
        }
        let _ = self.registry.count.compare_exchange(count, 0, Ordering::AcqRel, Ordering::Acquire);
        Ok(destroyed)
    }
}

fn huge_tracking_words(memory: MemoryId) -> Result<usize, ArenaDestroyError> {
    if memory.kind() != MemoryKind::OsHuge { return Ok(0); }
    let span = memory.os_memory().ok_or(ArenaDestroyError::InvalidOwnership)?;
    if !memory.is_pinned() || !memory.initially_committed() || span.size == 0
        || span.size % crate::config::GIB != 0 { return Err(ArenaDestroyError::InvalidOwnership); }
    let pages = span.size / crate::config::GIB;
    pages.checked_add(usize::BITS as usize - 1).map(|pages| pages / usize::BITS as usize)
        .ok_or(ArenaDestroyError::InvalidOwnership)
}
