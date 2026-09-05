//! Musl 1.2.6 dynlink.c::{prepare_lazy,do_relocs,redo_lazy_relocs} ownership.
//! Deferred means retry at later dlopen admission, not a first-call resolver.
//! The pending queue owns only validated relocation coordinates. It never owns
//! ELF mappings, and it is replaced only when its graph transaction commits.
//!
//! Unlike pinned musl's unconditional retry write into already sealed RELRO,
//! the owned retry uses a permission journal. All allocation and validation
//! precedes temporary RW permissions; old GOT pointers are published only
//! after every registered thread's new TLS view. RELRO is restored before
//! callbacks or return. Restoration failure terminates the process rather
//! than returning a partially protected runtime.

use super::*;
use super::super::x86_64_runtime_memory::LoaderBuffer;
use super::super::x86_64_runtime_lock::RuntimeGuard;
use core::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone, Copy)]
struct DeferredRelocation { owner: usize, offset: u64, kind: u32, symbol: usize, addend: i64 }
const EMPTY: DeferredRelocation = DeferredRelocation { owner: 0, offset: 0, kind: 0, symbol: 0, addend: 0 };

pub(in super::super) struct PendingRelocations { records: LoaderBuffer<DeferredRelocation>, count: usize }
impl PendingRelocations {
    fn new(capacity: usize) -> Option<Self> { Some(Self { records: LoaderBuffer::new(capacity, EMPTY)?, count: 0 }) }
    fn entries(&self) -> &[DeferredRelocation] { &self.records.as_slice()[..self.count] }
    fn push(&mut self, record: DeferredRelocation) -> Option<()> {
        *self.records.as_mut_slice().get_mut(self.count)? = record;
        self.count += 1;
        Some(())
    }
}

/// # Safety
/// Caller exclusively owns all new mappings and holds the loader lock for
/// every borrowed old record. Table bounds were parsed; scope indices are
/// valid. Only initial modules have retained initial-exec TLS placement.
pub(in super::super) unsafe fn relocate_new(objects: &[Object], indices: &[usize], first_new: usize,
    static_tls_count: usize, lazy: bool,
) -> Option<PendingRelocations> {
    if first_new == 0 || first_new > objects.len() || indices.iter().any(|index| *index >= objects.len()) { return None; }
    let scope = SymbolScope { indices, module_count: objects.iter().map(|object| object.tls_module_id).max().unwrap_or(0),
        static_tls_count, initial: false };
    let mut capacity = 0usize;
    for owner in first_new..objects.len() {
        let object = &objects[owner];
        unsafe { preflight_object_binding(&scope, objects, owner, lazy && !object.bind_now) }?;
        capacity = capacity.checked_add(object.relasz / ELF64_RELA_SIZE)?.checked_add(object.pltrelsz / ELF64_RELA_SIZE)?;
    }
    let mut pending = PendingRelocations::new(capacity)?;
    // Complete graph preflight precedes any new destination write, including
    // deferred spans in the same metadata/overlap proof as immediate writes.
    for owner in first_new..objects.len() {
        let object = &objects[owner];
        for (table, bytes) in [(object.rela, object.relasz), (object.jmprel, object.pltrelsz)] {
            for index in 0..bytes / ELF64_RELA_SIZE {
                let entry = unsafe { table.add(index * ELF64_RELA_SIZE) };
                let info = unsafe { read_u64(entry.add(8)) };
                let kind = info as u32;
                if kind == R_NONE { continue; }
                let record = DeferredRelocation { owner, offset: unsafe { read_u64(entry) },
                    kind, symbol: (info >> 32) as usize, addend: unsafe { read_i64(entry.add(16)) } };
                match unsafe { word_resolution(&scope, objects, owner, kind, record.symbol, record.addend, lazy && !object.bind_now) }? {
                    Some(value) => unsafe { core::ptr::write_unaligned(runtime_address(object.base, record.offset)? as *mut u64, value); },
                    None => pending.push(record)?,
                }
            }
        }
        unsafe { apply_relr_table(object) }?;
    }
    Some(pending)
}

#[derive(Clone, Copy)]
struct ResolvedWrite { address: u64, value: u64 }

pub(in super::super) struct PreparedRetry {
    pending: PendingRelocations,
    writes: LoaderBuffer<ResolvedWrite>, write_count: usize,
    pages: LoaderBuffer<u64>, page_count: usize,
}
impl PreparedRetry {
    /// # Safety
    /// Old/new pending records belong to this retained object snapshot and
    /// loader lock. `indices` is the prospective final global scope, excluding
    /// RTLD_LOCAL additions. All maps are retained and already protected.
    pub(in super::super) unsafe fn prepare(objects: &[Object], indices: &[usize], static_tls_count: usize,
        old: Option<&PendingRelocations>, new: &PendingRelocations,
    ) -> Option<Self> {
        if indices.iter().any(|index| *index >= objects.len()) { return None; }
        let capacity = old.map_or(0, |old| old.count).checked_add(new.count)?;
        let mut prepared = Self { pending: PendingRelocations::new(capacity)?,
            writes: LoaderBuffer::new(capacity, ResolvedWrite { address: 0, value: 0 })?, write_count: 0,
            pages: LoaderBuffer::new(capacity, 0)?, page_count: 0 };
        let scope = SymbolScope { indices, module_count: objects.iter().map(|object| object.tls_module_id).max().unwrap_or(0),
            static_tls_count, initial: false };
        for &record in old.map_or(&[][..], |old| old.entries()).iter().chain(new.entries()) {
            let object = objects.get(record.owner)?;
            if !matches!(record.kind, R_X86_64_GLOB_DAT | R_X86_64_JUMP_SLOT) || record.symbol == 0 { return None; }
            unsafe { write_span(object, record.offset, 8, true) }?;
            match unsafe { word_resolution(&scope, objects, record.owner, record.kind, record.symbol, record.addend, true) }? {
                None => prepared.pending.push(record)?,
                Some(value) => {
                    let address = runtime_address(object.base, record.offset)?;
                    if address & 7 != 0 { return None; }
                    prepared.writes.as_mut_slice()[prepared.write_count] = ResolvedWrite { address, value };
                    prepared.write_count += 1;
                    if object.relro_byte_len != 0 {
                        let start = align_down(object.base.checked_add(object.relro_virtual_address)?);
                        let end = align_up(object.base.checked_add(object.relro_virtual_address)?.checked_add(object.relro_byte_len)?);
                        if end <= start { return None; }
                        if address >= start && address < end {
                            prepared.pages.as_mut_slice()[prepared.page_count] = align_down(address);
                            prepared.page_count += 1;
                        }
                    }
                }
            }
        }
        let pages = &mut prepared.pages.as_mut_slice()[..prepared.page_count];
        pages.sort_unstable();
        let mut count = 0;
        for index in 0..pages.len() {
            if count == 0 || pages[index] != pages[count - 1] { pages[count] = pages[index]; count += 1; }
        }
        prepared.page_count = count;
        Some(prepared)
    }

    /// Last fallible admission step. A failed mprotect restores every earlier
    /// page while mappings and pending records still have their old owners.
    /// # Safety
    /// Caller holds the same loader lock/snapshot as prepare; no callback or
    /// pthread-list lock may occur until commit or drop restores permissions.
    pub(in super::super) unsafe fn make_writable(self, guard: &RuntimeGuard) -> Option<WritableRetry<'_>> {
        let mut writable = WritableRetry { prepared: Some(self), changed: 0, _guard: guard };
        let prepared = writable.prepared.as_ref()?;
        for &page in &prepared.pages.as_slice()[..prepared.page_count] {
            if unsafe { syscall3(SYS_MPROTECT, page as i64, PAGE as i64, PROT_READ | PROT_WRITE) } < 0 { return None; }
            writable.changed += 1;
        }
        Some(writable)
    }
}

pub(in super::super) struct WritableRetry<'guard> { prepared: Option<PreparedRetry>, changed: usize, _guard: &'guard RuntimeGuard }
impl WritableRetry<'_> {
    fn restore(&mut self) {
        if let Some(prepared) = &self.prepared {
            for &page in prepared.pages.as_slice()[..self.changed].iter().rev() {
                if unsafe { syscall3(SYS_MPROTECT, page as i64, PAGE as i64, PROT_READ) } < 0 {
                    fail(b"deferred RELRO restoration failed\n");
                }
            }
        }
        self.changed = 0;
    }

    /// # Safety
    /// The new graph and all registered TLS views have been published while
    /// holding this guard. No fallible admission step remains. Readers may use
    /// retained GOT slots without taking the loader lock, so stores are aligned
    /// atomic Release writes and never expose torn addresses.
    pub(in super::super) unsafe fn commit(mut self) -> PendingRelocations {
        let prepared = self.prepared.as_ref().unwrap();
        for write in &prepared.writes.as_slice()[..prepared.write_count] {
            unsafe { (&*(write.address as *const AtomicU64)).store(write.value, Ordering::Release); }
        }
        self.restore();
        self.prepared.take().unwrap().pending
    }
}
impl Drop for WritableRetry<'_> { fn drop(&mut self) { self.restore(); } }

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::tests::Image;

    #[test]
    fn deferred_strong_plt_got_wait_for_final_global_scope_but_weak_binds_zero() {
        let _guard = RuntimeGuard::acquire();
        let main = Image::new();
        let mut plugin = Image::new();
        let mut provider = Image::new();
        plugin.data[0] = 0xfeed;
        plugin.data[1] = 0xbeef;
        plugin.symbol(1, 2, 1, 0, 0, 0, 0);
        plugin.symbol(2, 2, 2, 0, 0, 0, 0);
        plugin.rela(0x1000, R_X86_64_JUMP_SLOT, 1, 0);
        plugin.rela(0x1008, R_X86_64_GLOB_DAT, 2, 0);
        provider.symbol(1, 2, 1, 0, 1, 0x1010, 1);
        let objects = [main.object(false), plugin.object(true), provider.object(true)];
        let pending = unsafe { relocate_new(&objects[..2], &[0, 1], 1, 0, true) }.unwrap();
        assert_eq!(pending.count, 1);
        assert_eq!(plugin.data[0], 0xfeed);
        assert_eq!(plugin.data[1], 0);
        let empty = PendingRelocations::new(0).unwrap();
        let local = unsafe { PreparedRetry::prepare(&objects, &[0], 0, Some(&pending), &empty) }.unwrap();
        assert_eq!(local.write_count, 0);
        assert_eq!(local.pending.count, 1);
        let global = unsafe { PreparedRetry::prepare(&objects, &[0, 2], 0, Some(&pending), &empty) }.unwrap();
        assert_eq!(global.write_count, 1);
        assert_eq!(plugin.data[0], 0xfeed);
        let remaining = unsafe { global.make_writable(&_guard).unwrap().commit() };
        assert_eq!(remaining.count, 0);
        assert_eq!(plugin.data[0], provider.data.as_ptr() as u64 + 16);
    }

    #[test]
    fn lazy_mode_does_not_defer_bad_shape_now_tls_absolute_or_overlapping_writes() {
        for (kind, binding, visibility, section, bind_now, overlap) in [
            (R_64, 1, 0, 0, false, false),
            (R_X86_64_GLOB_DAT, 1, 0, 0, true, false),
            (R_X86_64_GLOB_DAT, 1, 2, 0, false, false),
            (R_X86_64_GLOB_DAT, 0, 0, 0, false, false),
            (R_X86_64_TPOFF64, 1, 0, 0, false, false),
            (R_X86_64_GLOB_DAT, 1, 0, 0, false, true),
        ] {
            let main = Image::new();
            let mut plugin = Image::new();
            plugin.data[0] = 0xfeed;
            plugin.symbol(1, 2, binding, visibility, section, 0, 0);
            plugin.rela(0x1000, R_X86_64_RELATIVE, 0, 0x1000);
            plugin.rela(if overlap { 0x1000 } else { 0x1008 }, kind, 1, 0);
            let objects = [main.object(false), Object { bind_now, ..plugin.object(true) }];
            assert!(unsafe { relocate_new(&objects, &[0, 1], 1, 0, true) }.is_none());
            assert_eq!(plugin.data[0], 0xfeed);
        }
    }

    unsafe fn write_faults(address: *mut u64) -> bool {
        // Only a raw store and SYS_exit in the child; no inherited libc/TLS
        // owner is entered. Its parent retains the loader lock and mapping.
        let child = unsafe { syscall1(57, 0) };
        if child == 0 {
            let no_core = [0u64; 2];
            unsafe { syscall2(160, 4, no_core.as_ptr() as i64); }
            unsafe { core::ptr::write_volatile(address, 0); syscall1(60, 90); core::hint::unreachable_unchecked(); }
        }
        let mut status = 0i32;
        let waited = if child > 0 {
            loop {
                let result = unsafe { syscall4(61, child, core::ptr::addr_of_mut!(status) as i64, 0, 0) };
                if result != -4 { break result; }
            }
        } else { child };
        child > 0 && waited == child && status & 127 == 11
    }

    #[test]
    fn relro_retry_abandonment_and_late_permission_failure_restore_without_pointer_writes() {
        let guard = RuntimeGuard::acquire();
        let mut mapping = LoaderBuffer::new(PAGE as usize / 8, 0xfeedu64).unwrap();
        let address = mapping.as_mut_slice().as_mut_ptr();
        let main = Image::new();
        let mut plugin = Image::new();
        let mut provider = Image::new();
        plugin.symbol(1, 1, 1, 0, 0, 0, 0);
        plugin.rela(0x1000, R_X86_64_GLOB_DAT, 1, 0);
        provider.symbol(1, 1, 1, 0, 1, 0x1010, 8);
        let objects = [main.object(false), Object { base: address as u64 - 0x1000,
            relro_virtual_address: 0x1000, relro_byte_len: PAGE, ..plugin.object(true) }, provider.object(true)];
        let pending = unsafe { relocate_new(&objects[..2], &[0, 1], 1, 0, true) }.unwrap();
        assert!(unsafe { apply_relro(&objects[1]) }.is_some());
        assert!(unsafe { write_faults(address) });
        let empty = PendingRelocations::new(0).unwrap();
        let prepare = || unsafe { PreparedRetry::prepare(&objects, &[0, 2], 0, Some(&pending), &empty) }.unwrap();
        let abandoned = unsafe { prepare().make_writable(&guard) }.unwrap();
        assert_eq!(unsafe { *address }, 0xfeed);
        drop(abandoned);
        assert!(unsafe { write_faults(address) });
        let mut failing = prepare();
        failing.pages = LoaderBuffer::new(2, u64::MAX & !(PAGE - 1)).unwrap();
        failing.pages.as_mut_slice()[0] = address as u64;
        failing.page_count = 2;
        assert!(unsafe { failing.make_writable(&guard) }.is_none());
        assert_eq!(unsafe { *address }, 0xfeed);
        assert!(unsafe { write_faults(address) });
        let remaining = unsafe { prepare().make_writable(&guard).unwrap().commit() };
        assert_eq!(remaining.count, 0);
        assert_eq!(unsafe { *address }, provider.data.as_ptr() as u64 + 16);
        assert!(unsafe { write_faults(address) });
    }
}
