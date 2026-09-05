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
    fn abandoning_partial_all_thread_preparation_preserves_every_live_view() {
        unsafe fn probe(guard: &RuntimeGuard) -> bool { (|| -> Option<bool> {
        let image = [31u8];
        let mut initial = [EMPTY_OBJECT; MAX_OBJECTS];
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
        let mut modules = [EMPTY_OBJECT; MAX_OBJECTS];
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
        let mut initial = [EMPTY_OBJECT; MAX_OBJECTS];
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
    fn generations_preserve_live_addresses_and_publish_dtv_sizes_together() {
        let image = [17u8, 19];
        let mut initial = [EMPTY_OBJECT; MAX_OBJECTS];
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
