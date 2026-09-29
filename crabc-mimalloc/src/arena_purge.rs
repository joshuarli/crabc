// Copyright (c) 2018-2026 Microsoft Research, Daan Leijen
// SPDX-License-Identifier: MIT
// Source: pinned mimalloc v3.5.0 src/arena.c:1430-1494,2242-2435.

//! Source policy-aware release, delayed purge and subprocess purge traversal.
//! The arena owner retains both the bitmap range and its exact VM pair; it
//! does not route ordinary OS backing through an external callback policy.

use super::{ArenaBacking, OwnedArenaAllocation, ProcessArenaBacking};
use crate::arena::{ArenaView, arena_slice_range_is_usable};
use crate::atomic::{AtomicGuardWord, i64_cas_strong_acq_rel, i64_load_relaxed,
    i64_store_release, try_atomic_guard};
use crate::config::ARENA_SLICE_SIZE;
use crate::invariants;
use crate::os::{self, MemoryConfig, VmProcess};
use crate::types::MemoryId;
use core::sync::atomic::Ordering;

// Source mi_arenas_try_purge has one process-global, nonblocking guard, not
// one blocking purge mutex per subprocess or per arena.
pub(super) static PURGE_GUARD: AtomicGuardWord = AtomicGuardWord::new(0);

/// `mi_arena_purge_delay` (`src/arena.c:2243-2252`): the delay every arena
/// purge schedules with, from the policy's live `purge_delay` and
/// `arena_purge_mult` descriptors at this read point.
pub(crate) fn arena_purge_delay(policy: &crate::os::VmPolicy) -> i64 {
    purge_delay(policy.purge_delay_milliseconds(), policy.arena_purge_multiplier())
}

fn purge_delay(delay: i64, multiplier: i64) -> i64 {
    if delay < 0 || multiplier < 0 { return -1; }
    if delay == 0 || multiplier == 0 { return 0; }
    match (delay as usize).checked_mul(multiplier as usize) {
        Some(total) if total <= i64::MAX as usize => total as i64,
        _ => delay,
    }
}

#[cfg(test)]
mod tests {
    use super::purge_delay;

    #[test]
    fn source_purge_delay_retains_disabled_immediate_and_overflow_fallbacks() {
        assert_eq!(purge_delay(1000, 4), 4000);
        assert_eq!(purge_delay(-1, 0), -1);
        assert_eq!(purge_delay(0, -1), -1);
        assert_eq!(purge_delay(0, 4), 0);
        assert_eq!(purge_delay(1000, 0), 0);
        assert_eq!(purge_delay(i64::MAX, 2), i64::MAX);
        assert_eq!(purge_delay(i64::MAX, i64::MAX), i64::MAX);
        assert_eq!(purge_delay(i64::MAX / 4, 4), (i64::MAX / 4) * 4);
    }

    /// A scheduled arena range waits through the last preceding millisecond,
    /// then its due visit clears the range while preserving its live neighbor.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn emit_m2_delayed_purge_expiry_c_rust_trace() {
        delayed_purge_expiry_trace(false);
    }

    /// A failed decommit at expiry consumes the scheduled purge while the
    /// fully committed slice remains reusable beside a live neighbor.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn emit_m2_delayed_purge_fault_c_rust_trace() {
        delayed_purge_expiry_trace(true);
    }

    #[cfg(target_arch = "x86_64")]
    fn delayed_purge_expiry_trace(fail_due_advice: bool) {
        use super::*;
        use crate::arena::{ArenaId, ArenaSearch, ArenaView};
        use crate::diagnostic_output::{OutputCallback, OutputOwner};
        use crate::os::{PageSize, VmPolicy, fault};
        use crate::subproc::MainSubprocess;
        use crate::types::MemoryKind;
        use core::ffi::{c_char, c_void, CStr};
        use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};
        use std::boxed::Box;

        static ENVIRONMENT: AtomicPtr<*const c_char> = AtomicPtr::new(core::ptr::null_mut());
        unsafe fn environment() -> *const *const c_char {
            ENVIRONMENT.load(Ordering::Acquire).cast_const()
        }
        unsafe extern "C" fn default_output(_message: *const c_char) {}
        unsafe extern "C" fn capture(message: *const c_char, argument: *mut c_void) {
            // SAFETY: registration stays live during synchronous diagnostics,
            // and the stack counter is removed before this test returns.
            let warnings = unsafe { &*(argument as *const AtomicUsize) };
            let bytes = unsafe { CStr::from_ptr(message) }.to_bytes();
            if bytes.windows(b"cannot decommit OS memory".len())
                .any(|part| part == b"cannot decommit OS memory") {
                warnings.fetch_add(1, Ordering::Relaxed);
            }
        }

        let entries = Box::leak(Box::new([
            b"mimalloc_arena_reserve=32M\0".as_ptr().cast(),
            b"mimalloc_arena_eager_commit=0\0".as_ptr().cast(),
            b"mimalloc_arena_is_numa_local=0\0".as_ptr().cast(),
            b"mimalloc_allow_large_os_pages=0\0".as_ptr().cast(),
            b"mimalloc_allow_thp=0\0".as_ptr().cast(),
            b"mimalloc_purge_delay=100000\0".as_ptr().cast(),
            b"mimalloc_arena_purge_mult=1\0".as_ptr().cast(),
            b"mimalloc_purge_decommits=1\0".as_ptr().cast(),
            b"mimalloc_show_errors=1\0".as_ptr().cast(),
            b"mimalloc_max_warnings=100\0".as_ptr().cast(),
            core::ptr::null(),
        ]));
        ENVIRONMENT.store(entries.as_mut_ptr(), Ordering::Release);
        let output = Box::leak(Box::new(OutputOwner::new(default_output)));
        // SAFETY: source options are initialized from a process-lived image.
        unsafe { output.initialize_source_options(environment) };
        let subprocess = MainSubprocess::test_static_owner();
        let warning_count = AtomicUsize::new(0);
        // SAFETY: callback removal below precedes the stack counter's end.
        unsafe { output.register_output(Some(capture as OutputCallback),
            &warning_count as *const AtomicUsize as *mut c_void) };
        // SAFETY: option initialization completed and output stays live.
        let policy = Box::leak(Box::new(
            unsafe { VmPolicy::from_process_options(output) }));
        policy.finish_preloading();
        let process = VmProcess::new(policy, subprocess);
        let config = MemoryConfig::from_observations(
            PageSize::new(4096).unwrap(), 1 << 20, true, false,
        );
        let backing = subprocess.arena_backing();
        let search = ArenaSearch { heap_sequence: 0, heap_count: 1,
            thread_sequence: 0, numa_node: -1, requested: ArenaId::none(),
            allow_pinned: true };
        let fault = fault::install(fault::Plan::disabled());
        // SAFETY: this isolated backing has no concurrent publisher, claim,
        // or purge visitor for the duration of its process-owned claims.
        let released = unsafe { backing.try_allocate_slices(
            process, config, search, 1, ARENA_SLICE_SIZE, true,
        ) }.expect("first committed arena slice");
        let arena_id = released.memory_id().arena_memory().unwrap().arena;
        // SAFETY: the first claim pins this published parent arena.
        let requested = ArenaSearch { requested: unsafe { ArenaId::from_arena(arena_id) }.unwrap(), ..search };
        let neighbor = unsafe { backing.try_allocate_slices(
            process, config, requested, 1, ARENA_SLICE_SIZE, true,
        ) }.expect("live neighboring slice");
        let released_slice = released.slice_index();
        let neighbor_slice = neighbor.slice_index();
        let released_address = released.start();
        let neighbor_address = neighbor.start();
        // SAFETY: both claims pin the arena and its bitmap storage.
        let view = unsafe { ArenaView::from_ptr(arena_id) }.unwrap();
        let arena = view.arena();
        let free = unsafe { view.slices_free() }.unwrap();
        let committed = unsafe { view.slices_committed() }.unwrap();
        let purge = unsafe { view.slices_purge() }.unwrap();
        let mut residency = 0u8;
        // SAFETY: these page-aligned addresses remain mapped under live claims.
        let setup = backing.registry().count() == 1
            && arena.memid.kind() == MemoryKind::Os
            && released_slice == 9 && neighbor_slice == 10
            && unsafe { crabc_core::mm::mincore_raw(arena.start, 4096, &mut residency) }.is_ok()
            && unsafe { crabc_core::mm::mincore_raw(released_address, 4096, &mut residency) }.is_ok()
            && unsafe { crabc_core::mm::mincore_raw(neighbor_address, 4096, &mut residency) }.is_ok();
        // SAFETY: the live neighboring claim uniquely owns this byte.
        unsafe { neighbor_address.write_volatile(0x7b) };
        let before_vm = subprocess.vm_statistics().snapshot();
        let before_arena = subprocess.arena_statistics().snapshot();
        assert!(released.release());
        let scheduled = purge.is_set_range(released_slice, 1) == Some(true)
            && committed.is_set_range(released_slice, 1) == Some(true)
            && free.is_set_range(released_slice, 1) == Some(true)
            && free.is_clear_range(neighbor_slice, 1) == Some(true)
            && i64_load_relaxed(&arena.purge_expire) > 0
            && i64_load_relaxed(&backing.purge_expire) > 0;
        // The isolated fixture is the sole visitor of both scheduled expiry
        // atomics; matching values make the boundary independent of wall time.
        i64_store_release(&arena.purge_expire, 10000);
        i64_store_release(&backing.purge_expire, 10000);
        let advice = fault.capture_advice_range();
        let delay = arena_purge_delay(process.policy());
        assert_eq!(delay, 100000);
        assert!(backing.collect_purge_at(process, config, false, true, 0, 9999, delay));
        let before_quiet = advice.count() == 0
            && warning_count.load(Ordering::Relaxed) == 0
            && subprocess.vm_statistics().snapshot().purge_calls == before_vm.purge_calls
            && subprocess.vm_statistics().snapshot().purged == before_vm.purged
            && subprocess.arena_statistics().snapshot().arena_purges == before_arena.arena_purges;
        let before_pending = purge.is_set_range(released_slice, 1) == Some(true)
            && committed.is_set_range(released_slice, 1) == Some(true)
            && i64_load_relaxed(&arena.purge_expire) == 10000;
        let before_global = i64_load_relaxed(&backing.purge_expire);
        if fail_due_advice {
            fault.set(fault::Plan::at(fault::Point::Decommit, 1,
                crabc_core::Errno::from_raw(5).unwrap()));
        }
        assert!(backing.collect_purge_at(process, config, false, true, 0, 10000, delay));
        let due_advice = advice.count();
        let due_exact = usize::from(advice.range() == Some((
            released_address as usize, ARENA_SLICE_SIZE, 4,
        )));
        let due_bits = purge.is_clear_range(released_slice, 1) == Some(true)
            && committed.is_set_range(released_slice, 1) == Some(true)
            && free.is_set_range(released_slice, 1) == Some(true)
            && free.is_clear_range(neighbor_slice, 1) == Some(true);
        let due_expiry = i64_load_relaxed(&arena.purge_expire);
        let due_global = i64_load_relaxed(&backing.purge_expire);
        let due_vm = subprocess.vm_statistics().snapshot();
        let due_arena = subprocess.arena_statistics().snapshot();
        let due_calls = due_vm.purge_calls - before_vm.purge_calls;
        let due_bytes = due_vm.purged - before_vm.purged;
        let due_visits = due_arena.arena_purges - before_arena.arena_purges;
        let due_committed = due_vm.committed_current - before_vm.committed_current;
        assert!(backing.collect_purge_at(process, config, false, true, 0, 10001, delay));
        let after_vm = subprocess.vm_statistics().snapshot();
        let after_arena = subprocess.arena_statistics().snapshot();
        let after_no_retry = advice.count() == 1
            && warning_count.load(Ordering::Relaxed) == usize::from(fail_due_advice)
            && after_vm.purge_calls - before_vm.purge_calls == due_calls
            && after_arena.arena_purges - before_arena.arena_purges == due_visits;
        let after_global = i64_load_relaxed(&backing.purge_expire);
        drop(advice);
        fault.set(fault::Plan::disabled());
        let later = unsafe { backing.try_allocate_slices(
            process, config, requested, 1, ARENA_SLICE_SIZE, true,
        ) }.expect("released slice can be reclaimed");
        let later_same = later.start() == released_address
            && later.slice_index() == released_slice;
        assert!(later.release());
        let later_pending = purge.is_set_range(released_slice, 1) == Some(true);
        // SAFETY: the live neighboring claim still owns its exact mapped byte.
        let survivor = unsafe { crabc_core::mm::mincore_raw(
            arena.start, 4096, &mut residency,
        ) }.is_ok() && unsafe { crabc_core::mm::mincore_raw(
            neighbor_address, 4096, &mut residency,
        ) }.is_ok() && unsafe { neighbor_address.read_volatile() } == 0x7b
            && free.is_clear_range(neighbor_slice, 1) == Some(true);
        assert!(neighbor.release());
        // SAFETY: releasing the last slice preserves its process-owned arena.
        let terminal = unsafe { crabc_core::mm::mincore_raw(
            arena.start, 4096, &mut residency,
        ) }.is_ok() && backing.registry().count() == 1
            && free.is_set_range(neighbor_slice, 1) == Some(true)
            && subprocess.vm_statistics().snapshot().reserved_current == before_vm.reserved_current;
        let final_vm = subprocess.vm_statistics().snapshot();
        let final_arena = subprocess.arena_statistics().snapshot();
        let profile = if fail_due_advice { "delayed_purge_fault" } else { "delayed_purge_expiry" };
        for (field, value) in [
            ("setup", i64::from(setup)), ("scheduled", i64::from(scheduled)),
            ("before_quiet", i64::from(before_quiet)),
            ("before_pending", i64::from(before_pending)),
            ("before_global", before_global), ("due_advice", due_advice as i64),
            ("due_exact", due_exact as i64), ("due_bits", i64::from(due_bits)),
            ("due_expiry", due_expiry), ("due_global", due_global),
            ("due_calls", due_calls), ("due_bytes", due_bytes),
            ("due_visits", due_visits), ("due_committed", due_committed),
            ("after_no_retry", i64::from(after_no_retry)),
            ("after_global", after_global), ("later_same", i64::from(later_same)),
            ("later_pending", i64::from(later_pending)),
            ("survivor", i64::from(survivor)), ("terminal", i64::from(terminal)),
            ("released_slice", released_slice as i64),
            ("neighbor_slice", neighbor_slice as i64),
            ("registry", backing.registry().count() as i64),
            ("reserved_delta", final_vm.reserved_current - before_vm.reserved_current),
            ("purge_calls", final_vm.purge_calls - before_vm.purge_calls),
            ("purged_bytes", final_vm.purged - before_vm.purged),
            ("arena_purges", final_arena.arena_purges - before_arena.arena_purges),
            ("warnings", warning_count.load(Ordering::Relaxed) as i64),
        ] {
            std::println!("m2.{profile}.{field}={value}");
        }
        assert!(setup && scheduled && before_quiet && before_pending && due_bits
            && after_no_retry && later_same && later_pending && survivor && terminal);
        drop(fault);
        // SAFETY: callback removal prevents future use of its stack counter.
        unsafe { output.register_output(None, core::ptr::null_mut()) };
    }
}

impl ProcessArenaBacking {
    /// Returns an exact process-owned slice span through `_mi_arenas_free`.
    /// The optional purge precedes the free-bitmap set, including immediate
    /// purging while the caller still owns the range.
    ///
    /// # Safety
    ///
    /// `memory` must represent this process owner's one outstanding arena
    /// claim. All page aliases, PageMap readers and producers must already be
    /// quiescent for that span. No second release may overlap this one.
    pub(crate) unsafe fn release_slices(&self, memory: MemoryId) -> bool {
        let Some(memory) = memory.arena_memory() else { return false; };
        let Some(view) = (unsafe { ArenaView::from_ptr(memory.arena) }) else { return false; };
        let arena = view.arena();
        let start = memory.slice_index as usize;
        let count = memory.slice_count as usize;
        if !arena_slice_range_is_usable(arena, start, count) { return false; }
        let Some(owner) = (unsafe { self.allocation_for_arena(arena) }) else { return false; };
        if !self.schedule_purge(&view, owner, start, count) { return false; }
        unsafe { view.slices_free() }.and_then(|free| free.set_range(start, count)) == Some(true)
    }

    fn schedule_purge(&self, view: &ArenaView<'_>, owner: &OwnedArenaAllocation,
        start: usize, count: usize) -> bool {
        let process = owner.process();
        let delay = arena_purge_delay(process.policy());
        if view.arena().memid.is_pinned() || delay < 0 || process.is_preloading() { return true; }
        if delay == 0 { return purge_claimed(view, owner, start, count).is_some(); }
        let now = os::source_clock_now();
        // A failed monotonic query uses the source low-resolution clock.
        // An overflowing deadline must not turn optional purge into
        // ownership loss.
        let Some(expire) = now.checked_add(delay) else { return true; };
        let mut expected = 0;
        if i64_cas_strong_acq_rel(&view.arena().purge_expire, &mut expected, expire) {
            let mut global_expected = 0;
            let _ = i64_cas_strong_acq_rel(&self.purge_expire, &mut global_expected, expire);
        }
        unsafe { view.slices_purge() }.and_then(|purge| purge.set_range(start, count)).is_some()
    }

    /// Runs `mi_arenas_try_purge` with its nonblocking global guard, source
    /// traversal rotation, visit budget and subprocess expiration state.
    /// Returning false reports a violated internal bitmap/backing invariant;
    /// advisory VM failures retain source scheduling behavior, not a new
    /// retry schedule or a second statistics update.
    ///
    /// # Safety
    ///
    /// `process` and `config` must be this owner's fixed binding, and every
    /// published arena must remain live throughout the traversal. Outstanding
    /// allocations obey the source atomic free-bitmap ownership protocol.
    pub(crate) unsafe fn collect_purge(&self, process: VmProcess<'_>, config: MemoryConfig,
        force: bool, visit_all: bool, thread_sequence: usize) -> bool {
        let delay = arena_purge_delay(process.policy());
        if process.is_preloading() || delay <= 0 { return true; }
        let now = os::source_clock_now();
        self.collect_purge_at(process, config, force, visit_all, thread_sequence, now, delay)
    }

    fn collect_purge_at(&self, process: VmProcess<'_>, config: MemoryConfig,
        force: bool, visit_all: bool, thread_sequence: usize, now: i64, delay: i64) -> bool {
        let global_expire = self.purge_expire.load(Ordering::Acquire);
        if !visit_all && !force && (global_expire == 0 || global_expire > now) { return true; }
        let count = self.registry.count();
        if count == 0 { return true; }
        let Some(_guard) = try_atomic_guard(&PURGE_GUARD) else { return true; };
        if global_expire > now {
            if let Some(next) = now.checked_add(delay / 10) { i64_store_release(&self.purge_expire, next); }
        }
        let start = thread_sequence % count;
        let mut budget = if visit_all { count } else { count / 4 + 1 };
        let mut all_visited = true;
        let mut any_pending_or_purged = false;
        for turn in 0..count {
            let candidate = turn + start;
            let index = if candidate >= count { candidate - count } else { candidate };
            let Some(arena) = (unsafe { self.registry.arena_at(index) }) else { continue; };
            let Some(view) = (unsafe { ArenaView::from_ptr(core::ptr::from_ref(arena).cast_mut()) }) else { return false; };
            let Some(owner) = (unsafe { self.allocation_for_arena(arena) }) else { return false; };
            if !core::ptr::eq(owner.process().policy(), process.policy()) || owner.config != config { return false; }
            let Some(purged) = self.try_purge_arena(&view, owner, now, force) else { return false; };
            if purged >= 0 {
                any_pending_or_purged = true;
                if purged >= 1 {
                    if budget <= 1 { all_visited = false; break; }
                    budget -= 1;
                }
            }
        }
        if all_visited && !any_pending_or_purged { i64_store_release(&self.purge_expire, 0); }
        true
    }

    fn try_purge_arena(&self, view: &ArenaView<'_>, owner: &OwnedArenaAllocation,
        now: i64, force: bool) -> Option<i8> {
        let arena = view.arena();
        if arena.memid.is_pinned() { return Some(-1); }
        let expire = i64_load_relaxed(&arena.purge_expire);
        if expire == 0 { return Some(-1); }
        if !force && expire > now { return Some(0); }
        i64_store_release(&arena.purge_expire, 0);
        // Pinned `mi_arena_try_purge` updates `arena->subproc->stats` after
        // the Release expiry clear and before inspecting any purge range.
        // `owner` is the same process-bound source arena allocation selected
        // for this traversal, so its subprocess owns this event rather than
        // the backing-local state.
        owner
            .process()
            .subprocess()
            .arena_statistics()
            .arena_purge_expiry_consumed();
        let purge = unsafe { view.slices_purge() }?;
        let minimum = invariants::slice_count_of_size(owner.process().policy().minimal_purge_size(owner.config))?;
        let mut any_purged = false;
        let mut valid = true;
        let visited = purge.visit_set_ranges_clear_aligned(minimum, |start, count| {
            match try_purge_range(view, owner, start, count) {
                Some(true) => any_purged = true,
                Some(false) if count > 1 => {
                    for offset in 0..count {
                        match try_purge_range(view, owner, start + offset, 1) {
                            Some(purged) => any_purged |= purged,
                            None => { valid = false; return false; }
                        }
                    }
                }
                Some(false) => {}
                None => { valid = false; return false; }
            }
            true
        });
        (visited && valid).then_some(if any_purged { 1 } else { -1 })
    }
}

/// Purges only after successful free-bitmap exclusion, then restores the
/// exact source availability range irrespective of advisory VM success.
fn try_purge_range(view: &ArenaView<'_>, owner: &OwnedArenaAllocation,
    start: usize, count: usize) -> Option<bool> {
    let free = unsafe { view.slices_free() }?;
    if !free.try_clear_within_chunk(start, count)? { return Some(false); }
    let result = purge_claimed(view, owner, start, count);
    let restored = free.set_range(start, count) == Some(true);
    if result.is_none() || !restored { return None; }
    Some(true)
}

/// Source `mi_arena_purge`: count the mixed commitment observation before
/// calling the exact paired VM policy; preserve Linux's no-recommit outcome
/// even when MADV_DONTNEED reports an advisory error.
fn purge_claimed(view: &ArenaView<'_>, owner: &OwnedArenaAllocation,
    start: usize, count: usize) -> Option<bool> {
    let committed = unsafe { view.slices_committed() }?;
    let transition = committed.set_range(start, count)?;
    let all_committed = transition.already_set() == count;
    let address = view.slice_start(start)?;
    let offset = (address as usize).checked_sub(owner.allocation.base().ok()? as usize)?;
    let size = count.checked_mul(ARENA_SLICE_SIZE)?;
    let stat_size = transition.already_set().checked_mul(ARENA_SLICE_SIZE)?;
    let needs_recommit = if owner.has_external_callback() {
        // Pinned src/os.c calls a custom callback before every ordinary
        // no-callback choice. Its raw arena span has already been formed from
        // the claimed source slices; do not page-normalize or invoke any
        // mapping advice here.
        owner.process().purge_with_callback(size, || {
            owner.invoke_external_purge(address, size)
        })?
    } else if let ArenaBacking::ExternalOs(lease) = &owner.allocation {
        if !lease.contains_covering_page_area(owner.config.page_size(), address, size) {
            return None;
        }
        // SAFETY: the caller-owned external lease retains the complete
        // covering base pages and the claimed bitmap span is quiescent for
        // this ordinary no-callback source purge.
        unsafe { owner.process().purge_external_arena_range(
            owner.config.page_size(), address, size, all_committed, stat_size,
        ) }.unwrap_or(false)
    } else {
        owner.allocation.regular()?.purge_for_process(owner.process(), offset, size,
            all_committed, stat_size).unwrap_or(false)
    };
    if needs_recommit || !all_committed { committed.clear_range(start, count)?; }
    Some(needs_recommit)
}
