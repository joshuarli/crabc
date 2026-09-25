//! One debugger rendezvous over the canonical native runtime registry.
//!
//! musl 1.2.6 ldso/dynlink.c (MIT), revision
//! 9fa28ece75d8a2191de7c5bb53bed224c5947417: struct debug, _dl_debug_addr,
//! dl_debug_state, __dls3 DT_DEBUG/initial publication, and dlopen's
//! RT_ADD/RT_CONSISTENT notifications. The split runtime publishes the same
//! loader-owned pointer through libc and DT_DEBUG; it never copies the graph.
//! Notifications are debugger breakpoint sites, never application callbacks.

use super::*;
use core::cell::UnsafeCell;
use super::x86_64_runtime_lock::RuntimeGuard;

#[cfg(test)]
#[path = "x86_64_debugger_tests.rs"]
mod tests;

const DT_DEBUG: u64 = 21;
const RT_CONSISTENT: i32 = 0;
const RT_ADD: i32 = 1;

#[repr(C)]
struct Rendezvous {
    version: i32,
    map: *mut c_void,
    breakpoint: usize,
    state: i32,
    loader_base: usize,
}
struct RendezvousCell(UnsafeCell<Rendezvous>);
// Initial publication is single-threaded; subsequent state changes require
// the existing graph lock. Debuggers suspend the process before reading it.
unsafe impl Sync for RendezvousCell {}
static RENDEZVOUS: RendezvousCell = RendezvousCell(UnsafeCell::new(Rendezvous {
    version: 0, map: core::ptr::null_mut(), breakpoint: 0,
    state: RT_CONSISTENT, loader_base: 0,
}));

const _: () = {
    assert!(core::mem::size_of::<Rendezvous>() == 40);
    assert!(core::mem::offset_of!(Rendezvous, map) == 8);
    assert!(core::mem::offset_of!(Rendezvous, breakpoint) == 16);
    assert!(core::mem::offset_of!(Rendezvous, state) == 24);
    assert!(core::mem::offset_of!(Rendezvous, loader_base) == 32);
};

// Keep an actual callable breakpoint site and a compiler memory boundary.
// An empty Rust function alone could have its calls optimized away.
// The interpreter's existing -Bsymbolic link binds every notification and
// r_brk to this definition even when an application exports the same name.
#[inline(never)]
#[no_mangle]
#[linkage = "weak"]
pub(super) extern "C" fn _dl_debug_state() {
    unsafe { core::arch::asm!("", options(nostack, preserves_flags)); }
}

fn address() -> usize { RENDEZVOUS.0.get() as usize }

/// Validated initial data destinations. Their mappings remain owned by the
/// initial graph transaction until publication or rollback. The main COPY
/// phase receives libc's already initialized pointer through ordinary lookup.
pub(super) struct PreparedInitialDebugger {
    libc_slot: *mut usize,
    dynamic_slot: Option<*mut usize>,
}

impl PreparedInitialDebugger {
    /// # Safety
    /// Objects are the complete, parsed initial graph, including the one libc
    /// receiver selected by opened-file identity. No relocation has run yet.
    pub(super) unsafe fn prepare(objects: &[Object]) -> Option<Self> {
        let mut receivers = objects.iter().filter(|object| object.canonical_libc_identity.is_some());
        let libc = receivers.next()?;
        if receivers.next().is_some() { return None; }
        let libc_slot = unsafe { super::x86_64_general_relocation::debugger_pointer_slot(libc) }?;
        let main = objects.first()?;
        let mut dynamic_slot = None;
        for index in 0..main.phnum {
            let header = unsafe { main.phdr.add(index.checked_mul(56)?) };
            if unsafe { read_u32(header) } != PT_DYNAMIC { continue; }
            let start = unsafe { read_u64(header.add(16)) };
            let bytes = unsafe { read_u64(header.add(40)) };
            if bytes == 0 || bytes % 16 != 0
                || runtime_address(main.base, start)? != main.dynamic as u64
                || !unsafe { virtual_range_in_load(main.phdr, main.phnum, start, bytes) }
            { return None; }
            for offset in 0..usize::try_from(bytes / 16).ok()? {
                let entry = unsafe { main.dynamic.add(offset.checked_mul(16)?) };
                let tag = unsafe { read_u64(entry) };
                if tag == 0 { break; }
                if tag != DT_DEBUG { continue; }
                let destination = (entry as u64).checked_add(8)?;
                if dynamic_slot.is_some() || destination & 7 != 0
                    || !unsafe { virtual_range_in_writable_load(main.phdr, main.phnum,
                        destination.checked_sub(main.base)?, 8) }
                { return None; }
                dynamic_slot = Some(destination as *mut usize);
            }
        }
        Some(Self { libc_slot, dynamic_slot })
    }

    /// The published 8-byte slot addresses [`Self::overlaps`] protects.
    pub(super) fn slots(&self) -> impl Iterator<Item = u64> {
        [Some(self.libc_slot), self.dynamic_slot].into_iter().flatten().map(|slot| slot as u64)
    }

    pub(super) fn overlaps(&self, start: u64, length: u64) -> Option<bool> {
        let end = start.checked_add(length)?;
        for slot in [Some(self.libc_slot), self.dynamic_slot].into_iter().flatten() {
            let slot = slot as u64;
            if length != 0 && start < slot.checked_add(8)? && slot < end { return Some(true); }
        }
        Some(false)
    }

    /// # Safety
    /// Full graph relocation preflight proved these slots disjoint from every
    /// relocation write. Word relocation is complete, main COPY is next, and
    /// both mappings are still writable before protection/RELRO publication.
    pub(super) unsafe fn relocate(&self) {
        unsafe { self.libc_slot.write(address()); }
        if let Some(slot) = self.dynamic_slot { unsafe { slot.write(address()); } }
    }
}

/// # Safety
/// The process-lifetime registry has just been committed and owns `map`.
/// Initial publication is unique and precedes every application callback.
pub(super) unsafe fn publish_initial(map: *mut c_void, loader_base: usize) {
    unsafe {
        RENDEZVOUS.0.get().write(Rendezvous { version: 1, map,
            breakpoint: _dl_debug_state as *const () as usize,
            state: RT_CONSISTENT, loader_base });
    }
    _dl_debug_state();
}

/// A named dlopen transaction reports ADD before mutation and CONSISTENT on
/// every exit, while the same graph lock still excludes another transaction.
/// Constructors execute only after this guard and then the graph lock drop.
pub(super) struct AddNotification<'a> { _guard: &'a RuntimeGuard }
impl<'a> AddNotification<'a> {
    pub(super) fn begin(guard: &'a RuntimeGuard) -> Self {
        unsafe { core::ptr::addr_of_mut!((*RENDEZVOUS.0.get()).state).write_volatile(RT_ADD); }
        _dl_debug_state();
        Self { _guard: guard }
    }
}
impl Drop for AddNotification<'_> {
    fn drop(&mut self) {
        unsafe { core::ptr::addr_of_mut!((*RENDEZVOUS.0.get()).state).write_volatile(RT_CONSISTENT); }
        _dl_debug_state();
    }
}
