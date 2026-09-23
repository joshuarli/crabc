// Copyright (c) 2018-2026 Microsoft Research, Daan Leijen
// SPDX-License-Identifier: MIT
// Source: mimalloc v3.5.0 src/arena.c:1542-1565, src/os.c:258-284.

//! Quiescent destruction of the persistent subprocess arena group.
//!
//! Snapshot only ownership facts before releasing memory: a parent OS memid
//! can cover later subarena headers. Reading those headers after the parent's
//! free would violate Rust lifetime rules. Registry clears and primitive frees
//! still occur in source index order; snapshots cause no observable VM action.

use super::{ArenaBacking, OwnedArenaAllocation, ProcessArenaBacking, DESTROYED, PUBLISHED};
use crate::config::MAX_ARENAS;
use crate::os::{HugeOsRawReleaseRetry, HugeOsReleaseFailure, Mapping};
use core::sync::atomic::Ordering;
use crabc_core::Errno;

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
/// retiring allocator. The fixed array is bounded by the source MAX_ARENAS.
#[must_use = "retain failed arena releases until explicit raw retry succeeds"]
pub(crate) struct DestroyedArenas<'tracking> {
    failures: [Option<FailedArenaRelease<'tracking>>; MAX_ARENAS],
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
        let mut words = 0usize;
        for slot in &self.slots {
            match slot.state.load(Ordering::Acquire) {
                super::EMPTY => {}
                PUBLISHED => {
                    let owner = unsafe { (&*slot.value.get()).assume_init_ref() };
                    if let ArenaBacking::Huge(allocation) = &owner.allocation {
                        words = words.checked_add(allocation.release_tracking_words())
                            .ok_or(ArenaDestroyError::InvalidOwnership)?;
                    }
                }
                _ => return Err(ArenaDestroyError::InvalidOwnership),
            }
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
        mut tracking: &'tracking mut [usize],
    ) -> Result<DestroyedArenas<'tracking>, ArenaDestroyError> {
        if self.destroyed.load(Ordering::Acquire) {
            return Err(ArenaDestroyError::AlreadyDestroyed);
        }
        if self.huge_cleanup_retained.load(Ordering::Acquire) {
            return Err(ArenaDestroyError::InvalidOwnership);
        }
        let count = self.registry.count();
        let mut release_slots = [None; MAX_ARENAS];
        let mut seen = [false; MAX_ARENAS];
        let mut required_words = 0usize;
        let tracking_start = tracking.as_ptr().addr();
        let tracking_end = tracking_start + core::mem::size_of_val(tracking);
        for index in 0..count {
            let Some(arena) = (unsafe { self.registry.arena_at(index) }) else { continue; };
            let owner = unsafe { self.allocation_for_arena(arena) }
                .ok_or(ArenaDestroyError::InvalidOwnership)?;
            let slot_index = self.slots.iter().position(|slot| {
                slot.state.load(Ordering::Acquire) == PUBLISHED
                    && core::ptr::eq(unsafe { (&*slot.value.get()).assume_init_ref() }, owner)
            }).ok_or(ArenaDestroyError::InvalidOwnership)?;
            if seen[slot_index] { continue; }
            seen[slot_index] = true;
            release_slots[index] = Some(slot_index);
            let start = owner.allocation.base().map_err(|_| ArenaDestroyError::InvalidOwnership)?.addr();
            let end = start.checked_add(owner.allocation.length().map_err(|_| ArenaDestroyError::InvalidOwnership)?)
                .ok_or(ArenaDestroyError::InvalidOwnership)?;
            if tracking_start < end && start < tracking_end {
                return Err(ArenaDestroyError::TrackingInsideArena);
            }
            if let ArenaBacking::Huge(allocation) = &owner.allocation {
                required_words = required_words.checked_add(allocation.release_tracking_words())
                    .ok_or(ArenaDestroyError::InvalidOwnership)?;
            }
        }
        // Unpublished/retained owners have a different source cleanup edge.
        // They cannot disappear into this published-registry destruction.
        for (index, slot) in self.slots.iter().enumerate() {
            let state = slot.state.load(Ordering::Acquire);
            if state != super::EMPTY && (state != PUBLISHED || !seen[index]) {
                return Err(ArenaDestroyError::InvalidOwnership);
            }
        }
        if tracking.len() < required_words {
            return Err(ArenaDestroyError::TrackingCapacity { required_words });
        }
        self.destroyed.store(true, Ordering::Release);
        let mut destroyed = DestroyedArenas { failures: [const { None }; MAX_ARENAS] };
        for (index, slot_index) in release_slots.into_iter().enumerate().take(count) {
            self.registry.arenas[index].store(core::ptr::null_mut(), Ordering::Release);
            let Some(slot_index) = slot_index else { continue; };
            let slot = &self.slots[slot_index];
            // Exclusive shutdown transfers the final owner out exactly once.
            slot.state.store(DESTROYED, Ordering::Release);
            let owner = unsafe { (*slot.value.get()).assume_init_read() };
            let OwnedArenaAllocation { allocation, process, .. } = owner;
            match allocation {
                ArenaBacking::Regular(mut mapping) => {
                    // Source passes still_committed=true even for reserved
                    // arenas. The OS memid retains the full reservation size.
                    let size = mapping.length().expect("preflight validated live mapping");
                    if mapping.unmap_for_process(process.project(), size, false).is_err() {
                        destroyed.failures[slot_index] = Some(FailedArenaRelease::Regular(mapping));
                    }
                }
                ArenaBacking::Huge(allocation) => {
                    let (words, rest) = tracking.split_at_mut(allocation.release_tracking_words());
                    tracking = rest;
                    match allocation.release_for_process(words) {
                        Ok(()) => {}
                        Err(HugeOsReleaseFailure::FailedPages(retry)) => {
                            destroyed.failures[slot_index] = Some(FailedArenaRelease::Huge(retry));
                        }
                        Err(HugeOsReleaseFailure::Tracking(_)) => unreachable!("preflight checked exact tracking capacity"),
                    }
                }
                ArenaBacking::External(_) => {}
            }
        }
        let _ = self.registry.count.compare_exchange(count, 0, Ordering::AcqRel, Ordering::Acquire);
        Ok(destroyed)
    }
}
