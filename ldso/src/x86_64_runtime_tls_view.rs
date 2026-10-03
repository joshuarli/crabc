//! Coherent loader-owned DTV generations for retained runtime modules.
//!
//! FS+8 and FS+16 remain the immutable initial attachment described by
//! RuntimeV1. FS+24 is a single atomic pointer to this current descriptor, so
//! readers can never pair a new DTV with an old size table. A growth
//! transaction prepares every thread before it publishes new module scope.
//! Old descriptors and the TLS images they contain remain mapped until the
//! thread allocation's clear-child-TID/reader-quiescence release boundary.
//!
//! Musl 1.2.6 `ldso/dynlink.c::install_new_tls` likewise prepares every live
//! thread's DTV before exposing newly loaded TLS modules. The descriptor and
//! retained-generation memory scheme here are crabc ownership machinery, not
//! a claim to translate musl's internal pthread layout or signal barrier.

use super::*;
use core::sync::atomic::{AtomicPtr, Ordering};
use super::x86_64_runtime_lock::RuntimeGuard;
use super::x86_64_runtime_memory::LoaderBuffer;

pub(super) const CURRENT_VIEW_TCB_OFFSET: usize = 24;

#[repr(C)]
pub(super) struct RuntimeTlsView {
    mapping_bytes: usize,
    previous: *mut RuntimeTlsView,
    module_count: usize,
    dtv: *mut usize,
    sizes: *mut usize,
}

/// An unpublished generation owns only its own mapping. Dropping preparation
/// never follows `previous`, which still belongs to the live thread.
pub(super) struct PreparedTlsView { view: *mut RuntimeTlsView }

#[derive(Clone, Copy)]
struct ThreadView { tp: *mut u8, view: *mut RuntimeTlsView }

/// All-thread preparation retains the mutation guard's borrow until publish
/// or rollback. No new thread can register and no token can be released while
/// these unpublished descriptors refer to its TP.
pub(super) struct PreparedAllThreads<'a> {
    _guard: &'a RuntimeGuard,
    threads: LoaderBuffer<ThreadView>,
}
impl<'a> PreparedAllThreads<'a> {
    pub(super) unsafe fn prepare(guard: &'a RuntimeGuard, modules: &[Object]) -> Option<Self> {
        let mut count = 0usize;
        unsafe { x86_64_initial_worker_tls::visit_registered_threads(guard, |_| { count = count.checked_add(1)?; Some(()) }) }?;
        let mut prepared = Self { _guard: guard, threads: LoaderBuffer::new(count,
            ThreadView { tp: core::ptr::null_mut(), view: core::ptr::null_mut() })? };
        let mut index = 0;
        unsafe { x86_64_initial_worker_tls::visit_registered_threads(guard, |tp| {
            let view = PreparedTlsView::prepare(tp, modules)?;
            *prepared.threads.as_mut_slice().get_mut(index)? = ThreadView { tp, view: view.view };
            core::mem::forget(view);
            index += 1;
            Some(())
        }) }?;
        (index == count).then_some(prepared)
    }

    /// # Safety
    /// Every graph/relocation/protection/callback check has completed. New
    /// object scope must be published non-fallibly immediately afterward under
    /// this same mutation guard. All individual publications are infallible.
    pub(super) unsafe fn publish(mut self) {
        for thread in self.threads.as_mut_slice() {
            unsafe { PreparedTlsView { view: thread.view }.publish(thread.tp); }
            thread.view = core::ptr::null_mut();
        }
    }
}
impl Drop for PreparedAllThreads<'_> {
    fn drop(&mut self) {
        for thread in self.threads.as_slice() {
            if !thread.view.is_null() { drop(PreparedTlsView { view: thread.view }); }
        }
    }
}

impl PreparedTlsView {
    /// # Safety
    /// `tp` is exclusively registered loader TCB storage; `modules` describes
    /// the complete monotonic module-ID population under the loader mutation
    /// lock. Every template remains readable and relocated throughout copying.
    pub(super) unsafe fn prepare(tp: *mut u8, modules: &[Object]) -> Option<Self> {
        if tp.is_null() || tp as usize % core::mem::align_of::<usize>() != 0 { return None; }
        let previous = unsafe { current(tp) };
        let (old_dtv, old_sizes, old_count) = if previous.is_null() {
            let dtv = unsafe { *tp.add(8).cast::<*mut usize>() };
            let sizes = unsafe { *tp.add(TLS_TCB_MODULE_SIZE_TABLE_OFFSET).cast::<*mut usize>() };
            if dtv.is_null() || sizes.is_null() { return None; }
            (dtv, sizes, unsafe { *dtv })
        } else {
            unsafe { ((*previous).dtv, (*previous).sizes, (*previous).module_count) }
        };
        let count = modules.iter().map(|object| object.tls_module_id).max().unwrap_or(0);
        if count < old_count { return None; }
        let words = count.checked_add(1)?;
        let header_bytes = core::mem::size_of::<RuntimeTlsView>();
        let table_bytes = words.checked_mul(core::mem::size_of::<usize>())?;
        let mut bytes = header_bytes.checked_add(table_bytes.checked_mul(2)?)?;
        for module in modules.iter().filter(|module| module.tls_module_id > old_count) {
            if module.tls_memsz == 0 || module.tls_filesz > module.tls_memsz
                || !module.tls_align.is_power_of_two()
                || (module.tls_filesz != 0 && module.tls_image.is_null())
            { return None; }
            bytes = bytes.checked_add(module.tls_align - 1)?.checked_add(module.tls_memsz)?;
        }
        if bytes > isize::MAX as usize { return None; }
        let mapped = unsafe { syscall6(SYS_MMAP, 0, bytes as i64,
            PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) };
        if is_linux_error(mapped) { return None; }
        let view = mapped as *mut RuntimeTlsView;
        let dtv = unsafe { (mapped as *mut u8).add(header_bytes).cast::<usize>() };
        let sizes = unsafe { (mapped as *mut u8).add(header_bytes + table_bytes).cast::<usize>() };
        unsafe { core::ptr::write(view, RuntimeTlsView { mapping_bytes: bytes, previous, module_count: count, dtv, sizes }); }
        let prepared = Self { view };
        unsafe {
            core::ptr::copy_nonoverlapping(old_dtv, dtv, old_count + 1);
            core::ptr::copy_nonoverlapping(old_sizes, sizes, old_count + 1);
            *dtv = count;
        }
        let mut cursor = (mapped as usize).checked_add(header_bytes)?.checked_add(table_bytes.checked_mul(2)?)?;
        for module in modules.iter().filter(|module| module.tls_module_id > old_count) {
            let id = module.tls_module_id;
            if unsafe { *dtv.add(id) } != 0 { return None; }
            // Preserve the ELF TLS image's alignment phase, as for the
            // canonical Variant-II initial materializer.
            let phase = module.tls_image as usize & (module.tls_align - 1);
            let delta = phase.wrapping_sub(cursor) & (module.tls_align - 1);
            cursor = cursor.checked_add(delta)?;
            let end = cursor.checked_add(module.tls_memsz)?;
            if end > (mapped as usize).checked_add(bytes)? { return None; }
            unsafe {
                if module.tls_filesz != 0 { core::ptr::copy_nonoverlapping(module.tls_image, cursor as *mut u8, module.tls_filesz); }
                *dtv.add(id) = cursor;
                *sizes.add(id) = module.tls_memsz;
            }
            cursor = end;
        }
        for id in 1..=count {
            if unsafe { *dtv.add(id) } == 0 || unsafe { *sizes.add(id) } == 0 { return None; }
        }
        Some(prepared)
    }

    /// # Safety
    /// The same registered TP and mutation lock used for preparation remain
    /// exclusively held; no other writer changed its current view. Scope
    /// publication must follow publication to every registered thread.
    pub(super) unsafe fn publish(self, tp: *mut u8) {
        unsafe { slot(tp).store(self.view, Ordering::Release); }
        core::mem::forget(self);
    }
}

impl Drop for PreparedTlsView {
    fn drop(&mut self) {
        unsafe { syscall2(SYS_MUNMAP, self.view as i64, (*self.view).mapping_bytes as i64); }
    }
}

unsafe fn slot<'a>(tp: *mut u8) -> &'a AtomicPtr<RuntimeTlsView> {
    unsafe { &*tp.add(CURRENT_VIEW_TCB_OFFSET).cast::<AtomicPtr<RuntimeTlsView>>() }
}

pub(super) unsafe fn current(tp: *mut u8) -> *mut RuntimeTlsView {
    unsafe { slot(tp).load(Ordering::Acquire) }
}

/// Resolve from one coherent descriptor; a null view means use generation1.
/// # Safety
/// `view` is an acquire-loaded retained descriptor on the current live TP.
pub(super) unsafe fn resolve(view: *mut RuntimeTlsView, id: usize, offset: usize) -> *mut c_void {
    if view.is_null() || id == 0 || id > unsafe { (*view).module_count } { return core::ptr::null_mut(); }
    let base = unsafe { *(*view).dtv.add(id) };
    let size = unsafe { *(*view).sizes.add(id) };
    if base == 0 || size == 0 || offset > size { return core::ptr::null_mut(); }
    base.checked_add(offset).map_or(core::ptr::null_mut(), |address| address as *mut c_void)
}

/// Release all generations after the worker's external quiescence proof.
/// # Safety
/// The allocation registry lock is held; no kernel/thread/DTV reader may
/// retain the TP. A failed unmap leaves its still-live head available to retry.
pub(super) unsafe fn release(tp: *mut u8) -> i64 {
    loop {
        let view = unsafe { current(tp) };
        if view.is_null() { return 0; }
        let previous = unsafe { (*view).previous };
        let result = unsafe { syscall2(SYS_MUNMAP, view as i64, (*view).mapping_bytes as i64) };
        if result != 0 { return result; }
        unsafe { slot(tp).store(previous, Ordering::Release); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;

    #[test]
    fn valid_population_allocation_refusal_reclaims_partial_preparation() {
        unsafe fn probe(guard: &RuntimeGuard) -> bool { unsafe { (|| -> Option<bool> {
            let image = [31u8];
            let mut initial = [EMPTY_OBJECT; 32];
            initial[0] = Object { tls_image: image.as_ptr(), tls_filesz: 1, tls_memsz: 16,
                tls_align: 16, tls_module_id: 1, tls_offset_below_tp: 16, ..EMPTY_OBJECT };
            let first = materialize_initial_tls(&initial, 0)?;
            let second = materialize_initial_tls(&initial, 0)?;
            *(*first.dtv.add(1) as *mut u8) = 97;
            *(*second.dtv.add(1) as *mut u8) = 101;
            let modules = [initial[0], Object { tls_image: image.as_ptr(), tls_filesz: 1,
                tls_memsz: 33, tls_align: 64, tls_module_id: 2, ..EMPTY_OBJECT }];
            let view = PreparedTlsView::prepare(first.thread_pointer, &modules)?;
            let address = view.view;
            let mut prepared = PreparedAllThreads { _guard: guard, threads: LoaderBuffer::new(2,
                ThreadView { tp: core::ptr::null_mut(), view: core::ptr::null_mut() })? };
            prepared.threads.as_mut_slice()[0] = ThreadView { tp: first.thread_pointer, view: view.view };
            core::mem::forget(view);
            let mut original_limit = [0u64; 2];
            if syscall4(302, 0, 9, 0, original_limit.as_mut_ptr() as i64) != 0 { return None; }
            // Refuse new mappings only in this isolated child. Existing TLS
            // remains accessible and the hard limit remains unchanged.
            let restricted = [0, original_limit[1]];
            if syscall4(302, 0, 9, restricted.as_ptr() as i64, 0) != 0 { return None; }
            let refused = PreparedTlsView::prepare(second.thread_pointer, &modules).is_none();
            if syscall4(302, 0, 9, original_limit.as_ptr() as i64, 0) != 0 || !refused { return None; }
            drop(prepared);
            let mut residency = 0u8;
            if syscall3(27, address as i64, 1, core::ptr::addr_of_mut!(residency) as i64) != -12 { return None; }
            for (block, value) in [(first, 97), (second, 101)] {
                if !current(block.thread_pointer).is_null() || *block.dtv != 1
                    || *(*block.dtv.add(1) as *const u8) != value
                    || syscall2(SYS_MUNMAP, block.mapping as i64, block.mapping_byte_len as i64) != 0
                { return None; }
            }
            Some(true)
        })().unwrap_or(false) } }
        unsafe { x86_64_runtime_lock::isolated_mapping_probe(probe); }
    }

    #[test]
    fn abandoning_partial_all_thread_preparation_preserves_every_live_view() {
        unsafe fn probe(guard: &RuntimeGuard) -> bool { (|| -> Option<bool> {
        let image = [31u8];
        let mut initial = [EMPTY_OBJECT; 32];
        initial[0] = Object { tls_image: image.as_ptr(), tls_filesz: 1, tls_memsz: 16,
            tls_align: 16, tls_module_id: 1, tls_offset_below_tp: 16, ..EMPTY_OBJECT };
        let first = unsafe { materialize_initial_tls(&initial, 0) }?;
        let second = unsafe { materialize_initial_tls(&initial, 0) }?;
        let modules = [initial[0], Object { tls_image: image.as_ptr(), tls_filesz: 1,
            tls_memsz: 33, tls_align: 64, tls_module_id: 2, ..EMPTY_OBJECT }];
        let view = unsafe { PreparedTlsView::prepare(first.thread_pointer, &modules) }?;
        let address = view.view;
        let mut prepared = PreparedAllThreads { _guard: guard, threads: LoaderBuffer::new(2,
            ThreadView { tp: core::ptr::null_mut(), view: core::ptr::null_mut() })? };
        prepared.threads.as_mut_slice()[0] = ThreadView { tp: first.thread_pointer, view: view.view };
        core::mem::forget(view);
        // The second registered thread rejects a truncated population. Drop
        // must reclaim the first prepared view without publishing either TP.
        if unsafe { PreparedTlsView::prepare(second.thread_pointer, &[]) }.is_some() { return None; }
        drop(prepared);
        let mut residency = 0u8;
        if unsafe { syscall3(27, address as i64, 1, core::ptr::addr_of_mut!(residency) as i64) } != -12 { return None; }
        for block in [first, second] {
            if !unsafe { current(block.thread_pointer) }.is_null()
                || unsafe { *block.dtv } != 1 || unsafe { *(*block.dtv.add(1) as *const u8) } != 31
                || unsafe { syscall2(SYS_MUNMAP, block.mapping as i64, block.mapping_byte_len as i64) } != 0
            { return None; }
        }
        Some(true)
        })().unwrap_or(false) }
        unsafe { x86_64_runtime_lock::isolated_mapping_probe(probe); }
    }

    #[test]
    fn acquire_readers_keep_valid_old_generations_during_repeated_publication() {
        use core::sync::atomic::{AtomicBool, AtomicUsize};
        let image = [23u8, 29];
        let mut modules = [EMPTY_OBJECT; 32];
        modules[0] = Object { tls_image: image.as_ptr(), tls_filesz: 2, tls_memsz: 16,
            tls_align: 16, tls_module_id: 1, tls_offset_below_tp: 16, ..EMPTY_OBJECT };
        let block = unsafe { materialize_initial_tls(&modules, 0) }.unwrap();
        unsafe { PreparedTlsView::prepare(block.thread_pointer, &modules).unwrap().publish(block.thread_pointer); }
        let tp = block.thread_pointer as usize;
        let stop = AtomicBool::new(false);
        let observations = AtomicUsize::new(0);
        self::std::thread::scope(|threads| {
            threads.spawn(|| {
                while !stop.load(Ordering::Acquire) {
                    let view = unsafe { current(tp as *mut u8) };
                    let address = unsafe { resolve(view, 1, 0) };
                    assert!(!address.is_null());
                    assert_eq!(unsafe { *(address as *const u8) }, 23);
                    assert!(unsafe { resolve(view, 1, 17) }.is_null());
                    observations.fetch_add(1, Ordering::Relaxed);
                }
            });
            while observations.load(Ordering::Relaxed) == 0 { core::hint::spin_loop(); }
            for _ in 0..64 {
                unsafe { PreparedTlsView::prepare(block.thread_pointer, &modules).unwrap().publish(block.thread_pointer); }
            }
            stop.store(true, Ordering::Release);
        });
        assert!(observations.load(Ordering::Relaxed) != 0);
        assert_eq!(unsafe { release(block.thread_pointer) }, 0);
        assert_eq!(unsafe { syscall2(SYS_MUNMAP, block.mapping as i64, block.mapping_byte_len as i64) }, 0);
    }

    #[test]
    fn malformed_new_population_fails_without_replacing_the_live_view() {
        let image = [1u8];
        let mut initial = [EMPTY_OBJECT; 32];
        initial[0] = Object { tls_image: image.as_ptr(), tls_filesz: 1, tls_memsz: 16,
            tls_align: 16, tls_module_id: 1, tls_offset_below_tp: 16, ..EMPTY_OBJECT };
        let block = unsafe { materialize_initial_tls(&initial, 0) }.unwrap();
        let module = Object { tls_image: image.as_ptr(), tls_filesz: 1, tls_memsz: 32,
            tls_align: 64, tls_module_id: 2, ..EMPTY_OBJECT };
        for malformed in [Object { tls_module_id: 3, ..module },
            Object { tls_filesz: 33, ..module }, Object { tls_align: 3, ..module },
            Object { tls_module_id: usize::MAX, ..module }] {
            assert!(unsafe { PreparedTlsView::prepare(block.thread_pointer, &[initial[0], malformed]) }.is_none());
            assert!(unsafe { current(block.thread_pointer) }.is_null());
            assert_eq!(unsafe { *block.dtv }, 1);
        }
        assert!(unsafe { PreparedTlsView::prepare(block.thread_pointer, &[initial[0], module, module]) }.is_none());
        assert!(unsafe { current(block.thread_pointer) }.is_null());
        assert_eq!(unsafe { syscall2(SYS_MUNMAP, block.mapping as i64, block.mapping_byte_len as i64) }, 0);
    }

    #[test]
    fn independent_worker_views_keep_mutations_and_late_worker_receives_fresh_templates() {
        let _guard = RuntimeGuard::acquire();
        let initial_image = [11u8, 13];
        let runtime_image = [17u8, 19, 23];
        let later_image = [29u8, 31];
        let mut initial = [EMPTY_OBJECT; 32];
        initial[0] = Object { tls_image: initial_image.as_ptr(), tls_filesz: 2,
            tls_memsz: 32, tls_align: 16, tls_module_id: 1,
            tls_offset_below_tp: 32, ..EMPTY_OBJECT };
        let runtime = Object { tls_image: runtime_image.as_ptr(), tls_filesz: 3,
            tls_memsz: 129, tls_align: 4096, tls_module_id: 2, ..EMPTY_OBJECT };
        let later = Object { tls_image: later_image.as_ptr(), tls_filesz: 2,
            tls_memsz: 67, tls_align: 64, tls_module_id: 3, ..EMPTY_OBJECT };
        let modules = [initial[0], runtime, later];
        // SAFETY: these complete module records borrow local templates that
        // outlive every owned initial mapping and runtime descriptor below.
        let first = unsafe { materialize_initial_tls(&initial, 0) }.unwrap();
        let second = unsafe { materialize_initial_tls(&initial, 0) }.unwrap();
        let mut original_addresses = [0usize; 2];
        let mut runtime_addresses = [0usize; 2];
        for (index, block) in [first, second].iter().enumerate() {
            // Each offline worker owns its initialized TCB and TLS mappings.
            // The graph guard excludes any other generation writer.
            unsafe {
                original_addresses[index] = *block.dtv.add(1);
                (original_addresses[index] as *mut u8).write(71 + index as u8);
                PreparedTlsView::prepare(block.thread_pointer, &modules[..2]).unwrap()
                    .publish(block.thread_pointer);
                let view = current(block.thread_pointer);
                let address = resolve(view, 2, 0).cast::<u8>();
                runtime_addresses[index] = address as usize;
                assert_eq!(core::slice::from_raw_parts(address, 3), runtime_image);
                assert_eq!(address.add(128).read(), 0);
                address.write(81 + index as u8);
                address.add(128).write(91 + index as u8);
            }
        }
        assert_ne!(original_addresses[0], original_addresses[1]);
        assert_ne!(runtime_addresses[0], runtime_addresses[1]);
        for (index, block) in [first, second].iter().enumerate() {
            // SAFETY: both worker mappings remain live and uniquely owned;
            // retained old descriptors keep their TLS blocks through growth.
            unsafe {
                let old = current(block.thread_pointer);
                PreparedTlsView::prepare(block.thread_pointer, &modules).unwrap()
                    .publish(block.thread_pointer);
                let new = current(block.thread_pointer);
                assert_ne!(old, new);
                for view in [old, new] {
                    assert_eq!(resolve(view, 1, 0) as usize, original_addresses[index]);
                    assert_eq!(resolve(view, 2, 0) as usize, runtime_addresses[index]);
                    assert_eq!(resolve(view, 1, 0).cast::<u8>().read(), 71 + index as u8);
                    assert_eq!(resolve(view, 2, 0).cast::<u8>().read(), 81 + index as u8);
                    assert_eq!(resolve(view, 2, 128).cast::<u8>().read(), 91 + index as u8);
                }
                assert_eq!(core::slice::from_raw_parts(resolve(new, 3, 0).cast::<u8>(), 2), later_image);
                assert_eq!(resolve(new, 3, 66).cast::<u8>().read(), 0);
            }
        }
        // SAFETY: the same retained templates initialize a fresh, separate
        // worker mapping; none of the earlier workers owns its TLS bytes.
        let late = unsafe { materialize_initial_tls(&initial, 0) }.unwrap();
        // SAFETY: every generation reader is quiescent before release. Each
        // thread mapping is unmapped only after its descriptor chain is gone.
        unsafe {
            PreparedTlsView::prepare(late.thread_pointer, &modules).unwrap().publish(late.thread_pointer);
            let view = current(late.thread_pointer);
            assert_eq!(resolve(view, 1, 0).cast::<u8>().read(), initial_image[0]);
            assert_eq!(resolve(view, 2, 0).cast::<u8>().read(), runtime_image[0]);
            assert_eq!(resolve(view, 2, 128).cast::<u8>().read(), 0);
            // Releasing one joined worker cannot reclaim another worker's
            // initial image, runtime blocks, or retained descriptors.
            assert_eq!(release(first.thread_pointer), 0);
            assert_eq!(syscall2(SYS_MUNMAP, first.mapping as i64, first.mapping_byte_len as i64), 0);
            assert_eq!(resolve(current(second.thread_pointer), 2, 128).cast::<u8>().read(), 92);
            assert_eq!(resolve(view, 2, 0).cast::<u8>().read(), runtime_image[0]);
            for block in [second, late] {
                assert_eq!(release(block.thread_pointer), 0);
                assert_eq!(syscall2(SYS_MUNMAP, block.mapping as i64, block.mapping_byte_len as i64), 0);
            }
        }
    }

    #[test]
    fn generations_preserve_live_addresses_and_publish_dtv_sizes_together() {
        let image = [17u8, 19];
        let mut initial = [EMPTY_OBJECT; 32];
        initial[0] = Object { tls_image: image.as_ptr(), tls_filesz: 2, tls_memsz: 16,
            tls_align: 16, tls_module_id: 1, tls_offset_below_tp: 16, ..EMPTY_OBJECT };
        let block = unsafe { materialize_initial_tls(&initial, 0) }.unwrap();
        let original = unsafe { *block.dtv.add(1) };
        unsafe { *(original as *mut u8) = 99; }
        // The adjacent opaque cancellation-state slot belongs to libc, not to
        // a DTV descriptor or the loader's allocation token.
        unsafe { *block.thread_pointer.add(TLS_TCB_LIBC_CANCELLATION_STATE_OFFSET).cast::<usize>() = 0x12345; }
        let runtime_image = [41u8, 43, 47];
        let mut modules = [initial[0], Object { tls_image: runtime_image.as_ptr(), tls_filesz: 3,
            tls_memsz: 127, tls_align: 4096, tls_module_id: 2, ..EMPTY_OBJECT }, EMPTY_OBJECT];
        let prepared = unsafe { PreparedTlsView::prepare(block.thread_pointer, &modules[..2]) }.unwrap();
        assert!(unsafe { current(block.thread_pointer) }.is_null());
        unsafe { prepared.publish(block.thread_pointer); }
        let first = unsafe { current(block.thread_pointer) };
        assert_eq!(unsafe { resolve(first, 1, 0) } as usize, original);
        assert_eq!(unsafe { *(resolve(first, 1, 0) as *const u8) }, 99);
        let runtime_address = unsafe { resolve(first, 2, 0) } as usize;
        assert_eq!(runtime_address & 4095, runtime_image.as_ptr() as usize & 4095);
        assert_eq!(unsafe { core::slice::from_raw_parts(runtime_address as *const u8, 3) }, runtime_image);
        assert!(unsafe { core::slice::from_raw_parts((runtime_address + 3) as *const u8, 124) }.iter().all(|byte| *byte == 0));
        assert!(unsafe { resolve(first, 2, 128) }.is_null());
        unsafe { *(runtime_address as *mut u8) = 71; }
        modules[2] = Object { tls_image: image.as_ptr(), tls_filesz: 2,
            tls_memsz: 24, tls_align: 64, tls_module_id: 3, ..EMPTY_OBJECT };
        let abandoned = unsafe { PreparedTlsView::prepare(block.thread_pointer, &modules) }.unwrap();
        drop(abandoned);
        assert_eq!(unsafe { current(block.thread_pointer) }, first);
        unsafe { PreparedTlsView::prepare(block.thread_pointer, &modules).unwrap().publish(block.thread_pointer); }
        let second = unsafe { current(block.thread_pointer) };
        assert_ne!(first, second);
        assert_eq!(unsafe { resolve(second, 2, 0) } as usize, runtime_address);
        assert_eq!(unsafe { *(resolve(second, 2, 0) as *const u8) }, 71);
        assert_eq!(unsafe { resolve(first, 2, 0) } as usize, runtime_address);
        assert!(unsafe { resolve(first, 3, 0) }.is_null());
        assert_eq!(unsafe { *block.dtv }, 1, "RuntimeV1 generation1 must not be rewritten");
        assert_eq!(unsafe { *block.thread_pointer.add(TLS_TCB_LIBC_CANCELLATION_STATE_OFFSET).cast::<usize>() }, 0x12345);
        assert_eq!(unsafe { release(block.thread_pointer) }, 0);
        assert_eq!(unsafe { release(block.thread_pointer) }, 0);
        assert_eq!(unsafe { syscall2(SYS_MUNMAP, block.mapping as i64, block.mapping_byte_len as i64) }, 0);
    }
}

/// An exact current-thread TLS object whose bytes remain live across a timer
/// callback's application-image reset.
#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct TimerTlsPreservedSpan {
    pub(super) start: usize,
    pub(super) byte_len: usize,
}

/// Validate one module image and project its current-thread address range.
/// An empty image has the empty range; every nonempty range is backed by the
/// current DTV and has the admitted module's exact size.
pub(super) unsafe fn module_image_bounds(tp: *mut u8, object: &Object) -> Option<(usize, usize)> {
    if object.tls_memsz == 0 { return Some((0, 0)); }
    if object.tls_module_id == 0 || object.tls_filesz > object.tls_memsz
        || (object.tls_filesz != 0 && object.tls_image.is_null()) { return None; }
    let view = unsafe { current(tp) };
    let (destination, size) = if view.is_null() {
        let dtv = unsafe { *tp.add(8).cast::<*const usize>() };
        let sizes = unsafe { *tp.add(TLS_TCB_MODULE_SIZE_TABLE_OFFSET).cast::<*const usize>() };
        if dtv.is_null() || sizes.is_null() || object.tls_module_id > unsafe { *dtv } { return None; }
        unsafe { (*dtv.add(object.tls_module_id) as *mut u8, *sizes.add(object.tls_module_id)) }
    } else {
        if object.tls_module_id > unsafe { (*view).module_count } { return None; }
        unsafe { (*(*view).dtv.add(object.tls_module_id) as *mut u8, *(*view).sizes.add(object.tls_module_id)) }
    };
    if destination.is_null() || size != object.tls_memsz { return None; }
    let start = destination as usize;
    Some((start, start.checked_add(size)?))
}

/// Validate/reset a retained module's image on one exclusively borrowed TP.
/// The caller holds the loader mutation guard and application TLS is quiescent.
/// A current DTV generation covers both initial and dlopen-added modules.
/// The false pass validates the entire population before any bytes are reset.
pub(super) unsafe fn reset_module_image(tp: *mut u8, object: &Object, write: bool) -> bool {
    unsafe { reset_module_image_preserving(tp, object, &[], write) }
}

/// Reset only gaps between already validated, nonoverlapping runtime spans.
/// The owner validates the complete module population before its first write.
pub(super) unsafe fn reset_module_image_preserving(
    tp: *mut u8,
    object: &Object,
    preserved: &[TimerTlsPreservedSpan],
    write: bool,
) -> bool {
    let Some((start, end)) = (unsafe { module_image_bounds(tp, object) }) else { return false; };
    if !write || start == end { return true; }
    let destination = start as *mut u8;
    let mut cursor = start;
    while cursor < end {
        let mut next = end;
        let mut protected_end = end;
        for span in preserved {
            let Some(stop) = span.start.checked_add(span.byte_len) else { return false; };
            if span.start < end && stop > start {
                if span.start < start || stop > end || span.byte_len == 0 { return false; }
                if span.start >= cursor && span.start < next {
                    next = span.start;
                    protected_end = stop;
                }
            }
        }
        let offset = cursor - start;
        let gap_end = next - start;
        let initialized_end = gap_end.min(object.tls_filesz);
        if offset < initialized_end {
            unsafe { core::ptr::copy_nonoverlapping(
                object.tls_image.add(offset), destination.add(offset), initialized_end - offset,
            ); }
        }
        let zero_start = offset.max(object.tls_filesz);
        if zero_start < gap_end {
            unsafe { core::ptr::write_bytes(destination.add(zero_start), 0, gap_end - zero_start); }
        }
        if next == end { break; }
        cursor = protected_end;
    }
    true
}

#[cfg(test)]
mod timer_reset_tests {
    use super::*;

    #[test]
    fn timer_reset_keeps_one_live_runtime_tls_object_and_resets_its_neighbors() {
        let image = [11u8, 13, 17, 19];
        let mut initial = [EMPTY_OBJECT; 32];
        initial[0] = Object { tls_image: image.as_ptr(), tls_filesz: image.len(),
            tls_memsz: 32, tls_align: 16, tls_module_id: 1,
            tls_offset_below_tp: 32, ..EMPTY_OBJECT };
        let block = unsafe { materialize_initial_tls(&initial, 0) }.unwrap();
        let tp = block.thread_pointer;
        let current = unsafe { *block.dtv.add(1) } as *mut u8;
        let retained = TimerTlsPreservedSpan { start: current as usize + 8, byte_len: 4 };
        unsafe {
            current.write(99);
            core::ptr::write_bytes(current.add(8), 77, 4);
            current.add(20).write(99);
        }
        assert!(unsafe { reset_module_image_preserving(tp, &initial[0], &[retained], false) });
        assert!(unsafe { reset_module_image_preserving(tp, &initial[0], &[retained], true) });
        assert_eq!(unsafe { current.read() }, 11);
        assert_eq!(unsafe { core::slice::from_raw_parts(current.add(8), 4) }, &[77; 4]);
        assert_eq!(unsafe { current.add(20).read() }, 0);
        let crossing = TimerTlsPreservedSpan { start: current as usize + 31, byte_len: 2 };
        assert!(!unsafe { reset_module_image_preserving(tp, &initial[0], &[crossing], true) });
        assert_eq!(unsafe { release(tp) }, 0);
        assert_eq!(unsafe { syscall2(SYS_MUNMAP, block.mapping as i64, block.mapping_byte_len as i64) }, 0);
    }

    #[test]
    fn timer_reset_restores_initial_and_runtime_images_without_replacing_tcb_or_dtv() {
        let first_image = [11u8, 13];
        let later_image = [17u8, 19, 23];
        let mut initial = [EMPTY_OBJECT; 32];
        initial[0] = Object { tls_image: first_image.as_ptr(), tls_filesz: 2,
            tls_memsz: 32, tls_align: 16, tls_module_id: 1,
            tls_offset_below_tp: 32, ..EMPTY_OBJECT };
        let block = unsafe { materialize_initial_tls(&initial, 0) }.unwrap();
        let tp = block.thread_pointer;
        let first = unsafe { *block.dtv.add(1) } as *mut u8;
        unsafe {
            first.write(99);
            first.add(20).write(99);
            *tp.add(TLS_TCB_LIBC_CANCELLATION_STATE_OFFSET).cast::<usize>() = 0x12345;
        }
        assert!(unsafe { reset_module_image(tp, &initial[0], false) });
        assert_eq!(unsafe { first.read() }, 99);
        assert!(unsafe { reset_module_image(tp, &initial[0], true) });
        assert_eq!(unsafe { first.read() }, 11);
        assert_eq!(unsafe { first.add(20).read() }, 0);
        let later = Object { tls_image: later_image.as_ptr(), tls_filesz: 3,
            tls_memsz: 4097, tls_align: 4096, tls_module_id: 2, ..EMPTY_OBJECT };
        let modules = [initial[0], later];
        unsafe { PreparedTlsView::prepare(tp, &modules).unwrap().publish(tp); }
        let view = unsafe { current(tp) };
        let second = unsafe { resolve(view, 2, 0) }.cast::<u8>();
        unsafe { first.write(77); second.write(77); second.add(4096).write(77); }
        let malformed = Object { tls_memsz: 4098, ..later };
        assert!(!unsafe { reset_module_image(tp, &malformed, true) });
        assert_eq!(unsafe { second.read() }, 77);
        for module in &modules { assert!(unsafe { reset_module_image(tp, module, true) }); }
        assert_eq!(unsafe { core::slice::from_raw_parts(second, 3) }, later_image);
        assert_eq!(unsafe { second.add(4096).read() }, 0);
        assert_eq!(unsafe { first.read() }, 11);
        assert_eq!(unsafe { current(tp) }, view);
        assert_eq!(unsafe { *block.dtv }, 1);
        assert_eq!(unsafe { *tp.add(TLS_TCB_LIBC_CANCELLATION_STATE_OFFSET).cast::<usize>() }, 0x12345);
        assert_eq!(unsafe { release(tp) }, 0);
        assert_eq!(unsafe { syscall2(SYS_MUNMAP, block.mapping as i64, block.mapping_byte_len as i64) }, 0);
    }
}
