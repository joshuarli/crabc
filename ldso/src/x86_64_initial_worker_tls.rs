//! Ownership of worker allocations and registered runtime TLS views.
//!
//! Initial materialization uses the startup allocator and retained relocated templates,
//! without installing FS or calling libc. A generation-tagged token identifies
//! exactly one live mapping. Unmapping and successful registry withdrawal are
//! serialized; failure retains the node. Wrong, stale and duplicate tokens
//! cannot unmap another allocation. The libc caller
//! must separately prove kernel clear-child-TID and reader quiescence.

use super::*;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicUsize, Ordering};
use super::x86_64_general_initial_loader_state::GeneralInitialLoaderState;
use super::x86_64_runtime_lock::RuntimeGuard as Guard;

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct WorkerTlsAllocation {
    mapping: *mut u8,
    mapping_size: usize,
    thread_pointer: *mut u8,
    allocation_id: usize,
}

const _: () = assert!(core::mem::size_of::<WorkerTlsAllocation>() == 32);

// The registry node lives in a reserved prefix of its own TLS mapping, never
// in libc heap storage. There is no second fixed thread/allocation ceiling.
#[repr(C)]
struct AllocationNode { token: WorkerTlsAllocation, next: *mut AllocationNode }
struct AllocationRegistry(UnsafeCell<*mut AllocationNode>);
// Access is serialized by RuntimeGuard; no pointer/reference escapes the lock.
unsafe impl Sync for AllocationRegistry {}
static REGISTRY: AllocationRegistry = AllocationRegistry(UnsafeCell::new(core::ptr::null_mut()));
static NEXT_ID: AtomicUsize = AtomicUsize::new(1);
// RuntimeV1 is immutable initial-image provenance. A fork-adopted worker is
// instead the active process-lifetime TLS root for future all-thread growth.
static ADOPTED_MAIN: AtomicUsize = AtomicUsize::new(0);

fn active_main_thread_pointer() -> Option<*mut u8> {
    let adopted = ADOPTED_MAIN.load(Ordering::Acquire);
    if adopted != 0 { Some(adopted as *mut u8) }
    else { x86_64_general_initial_tls_state::retained_initial_thread_pointer() }
}

/// Called under the copied loader fork locks after Linux leaves one task.
/// Withdraw all inherited tokens without unmapping stack-reachable TLS/control
/// storage. The surviving TP and its complete runtime-view chain remain live;
/// future workers receive new tokens and fresh relocated ELF templates.
pub(super) unsafe fn adopt_after_fork(thread_pointer: *mut u8) {
    ADOPTED_MAIN.store(thread_pointer as usize, Ordering::Release);
    unsafe { *REGISTRY.0.get() = core::ptr::null_mut(); }
}

/// The mutation guard excludes withdrawal while fork validates its caller.
pub(super) unsafe fn contains_thread(_guard: &Guard, thread_pointer: *mut u8) -> bool {
    if active_main_thread_pointer() == Some(thread_pointer) { return true; }
    let mut node = unsafe { *REGISTRY.0.get() };
    while !node.is_null() {
        if unsafe { (*node).token.thread_pointer } == thread_pointer { return true; }
        node = unsafe { (*node).next };
    }
    false
}

/// # Safety
/// The shared mutation guard excludes allocation/release and runtime growth.
/// Each TP is borrowed only for this call; callbacks must not reenter loader
/// mutation or retain an unprotected allocation-registry pointer.
pub(super) unsafe fn visit_registered_threads(
    _guard: &Guard, mut visit: impl FnMut(*mut u8) -> Option<()>,
) -> Option<()> {
    let main = active_main_thread_pointer()?;
    visit(main)?;
    let mut node = unsafe { *REGISTRY.0.get() };
    while !node.is_null() {
        visit(unsafe { (*node).token.thread_pointer })?;
        node = unsafe { (*node).next };
    }
    Some(())
}

pub(super) fn runtime_function(name: &[u8]) -> Option<u64> {
    match name {
        b"__crabc_x86_64_initial_tls_allocate" => Some(allocate as *const () as usize as u64),
        b"__crabc_x86_64_initial_tls_release" => Some(release as *const () as usize as u64),
        b"__crabc_x86_64_resolve_initial_tls" => Some(__tls_get_addr as *const () as usize as u64),
        _ => x86_64_runtime_registry::runtime_function(name),
    }
}

/// `output` must be writable/aligned for one token and disjoint from loader
/// state. The caller is the installed libc pthread owner, not a signal handler.
unsafe extern "C" fn allocate(output: *mut WorkerTlsAllocation) -> i32 {
    if output.is_null() || output as usize % core::mem::align_of::<WorkerTlsAllocation>() != 0 { return -1; }
    let Some(state) = GeneralInitialLoaderState::retained() else { return -1; };
    if !state.has_initial_tls_attachment() { return -1; }
    let Some(objects) = state.ready_objects() else { return -1; };
    let _guard = Guard::acquire();
    let Ok(id) = NEXT_ID.try_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1)) else { return -1; };
    let Some(block) = (unsafe { materialize_initial_tls(objects, core::mem::size_of::<AllocationNode>()) }) else { return -1; };
    if unsafe { x86_64_runtime_registry::attach_worker_tls(&_guard, block.thread_pointer) }.is_none() {
        unsafe { syscall2(SYS_MUNMAP, block.mapping as i64, block.mapping_byte_len as i64); }
        return -1;
    }
    // GCC's guard is process entropy, not a per-thread generator. Copy only
    // this reserved TCB field; initialized TLS always comes from ELF templates.
    let guard: usize;
    unsafe { core::arch::asm!("mov {}, fs:[40]", out(reg) guard, options(nostack, readonly)); }
    unsafe { core::ptr::write(block.thread_pointer.add(40).cast::<usize>(), guard); }
    let token = WorkerTlsAllocation { mapping: block.mapping, mapping_size: block.mapping_byte_len,
        thread_pointer: block.thread_pointer, allocation_id: id };
    let node = block.mapping.cast::<AllocationNode>();
    unsafe {
        register_allocation(node, token);
        core::ptr::write(output, token);
    }
    0
}

/// RuntimeGuard is held; `node` is writable mapping-prefix storage, disjoint from
/// every live registered node and the TLS/TCB/DTV ranges.
unsafe fn register_allocation(node: *mut AllocationNode, token: WorkerTlsAllocation) {
    unsafe {
        core::ptr::write(node, AllocationNode { token, next: *REGISTRY.0.get() });
        *REGISTRY.0.get() = node;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_materialization_preserves_fs_and_copies_initial_images_not_live_tls() {
        let image = [11u8, 12, 13, 14];
        let aligned_image = [21u8, 22, 23];
        let mut objects = [EMPTY_OBJECT; 32];
        objects[0] = Object { tls_image: image.as_ptr(), tls_filesz: image.len(),
            tls_memsz: 32, tls_align: 16, tls_module_id: 1, tls_offset_below_tp: 32,
            ..EMPTY_OBJECT };
        // A TLS-free object between providers must not consume a DTV ID.
        objects[2] = Object { tls_image: aligned_image.as_ptr(), tls_filesz: aligned_image.len(),
            tls_memsz: 129, tls_align: 4096, tls_module_id: 2, tls_offset_below_tp: 4096,
            ..EMPTY_OBJECT };
        let before = unsafe { read_thread_pointer() };
        let first = unsafe { materialize_initial_tls(&objects, core::mem::size_of::<AllocationNode>()) }.unwrap();
        unsafe { *first.thread_pointer.sub(32) = 99; }
        let second = unsafe { materialize_initial_tls(&objects, core::mem::size_of::<AllocationNode>()) }.unwrap();
        assert_eq!(unsafe { read_thread_pointer() }, before);
        assert_ne!(first.thread_pointer, second.thread_pointer);
        for block in [first, second] {
            assert_eq!(unsafe { *block.thread_pointer.add(TLS_TCB_LIBC_CANCELLATION_STATE_OFFSET).cast::<usize>() }, 0);
            assert_eq!(block.thread_pointer as usize % 4096, 0);
            assert!(block.mapping as usize + core::mem::size_of::<AllocationNode>()
                <= block.thread_pointer as usize - 4096);
            assert_eq!(unsafe { *block.dtv }, 2);
            assert_eq!(unsafe { *block.dtv.add(1) }, block.thread_pointer as usize - 32);
            assert_eq!(unsafe { *block.dtv.add(2) }, block.thread_pointer as usize - 4096);
            assert_eq!(unsafe { core::slice::from_raw_parts(block.thread_pointer.sub(4096), 3) }, aligned_image);
            assert!(unsafe { core::slice::from_raw_parts(block.thread_pointer.sub(4096).add(3), 126) }.iter().all(|byte| *byte == 0));
            let sizes = unsafe { *block.thread_pointer.add(TLS_TCB_MODULE_SIZE_TABLE_OFFSET).cast::<*const usize>() };
            assert_eq!(unsafe { *sizes.add(1) }, 32);
            assert_eq!(unsafe { *sizes.add(2) }, 129);
        }
        assert_eq!(unsafe { core::slice::from_raw_parts(second.thread_pointer.sub(32), 4) }, image);
        for block in [first, second] {
            assert_eq!(unsafe { syscall2(SYS_MUNMAP, block.mapping as i64, block.mapping_byte_len as i64) }, 0);
        }
    }

    #[test]
    fn retired_worker_generations_are_reclaimed_before_survivor_and_late_worker_growth() {
        unsafe fn resident(address: usize) -> bool {
            let mut residency = 0u8;
            unsafe { syscall3(27, address as i64, 1,
                core::ptr::addr_of_mut!(residency) as i64) == 0 }
        }
        unsafe fn register(block: InstalledInitialTls) -> WorkerTlsAllocation {
            let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
            let token = WorkerTlsAllocation { mapping: block.mapping,
                mapping_size: block.mapping_byte_len, thread_pointer: block.thread_pointer,
                allocation_id: id };
            // The materializer reserved an exclusive registry-node prefix,
            // disjoint from the owned TCB/DTV/images, just as allocate does.
            unsafe { register_allocation(block.mapping.cast(), token); }
            token
        }
        unsafe fn probe(guard: &Guard) -> bool { unsafe { (|| -> Option<bool> {
            let image = [11u8, 13];
            let runtime_image = [17u8, 19];
            let mut initial = [EMPTY_OBJECT; 32];
            initial[0] = Object { tls_image: image.as_ptr(), tls_filesz: 2,
                tls_memsz: 32, tls_align: 16, tls_module_id: 1,
                tls_offset_below_tp: 32, ..EMPTY_OBJECT };
            let runtime = Object { tls_image: runtime_image.as_ptr(), tls_filesz: 2,
                tls_memsz: 97, tls_align: 64, tls_module_id: 2, ..EMPTY_OBJECT };
            let modules = [initial[0], runtime,
                Object { tls_module_id: 3, ..runtime }, Object { tls_module_id: 4, ..runtime }];
            let main = materialize_initial_tls(&initial, 0)?;
            let first = materialize_initial_tls(&initial, core::mem::size_of::<AllocationNode>())?;
            let second = materialize_initial_tls(&initial, core::mem::size_of::<AllocationNode>())?;
            adopt_after_fork(main.thread_pointer);
            let first_token = register(first);
            let second_token = register(second);
            x86_64_runtime_tls_view::PreparedAllThreads::prepare(guard, &modules[..2])?.publish();
            let old = x86_64_runtime_tls_view::current(first.thread_pointer) as usize;
            let first_address = x86_64_runtime_tls_view::resolve(old as *mut _, 2, 0).cast::<u8>();
            let second_address = x86_64_runtime_tls_view::resolve(
                x86_64_runtime_tls_view::current(second.thread_pointer), 2, 0).cast::<u8>();
            *first_address = 71;
            *second_address = 73;
            x86_64_runtime_tls_view::PreparedAllThreads::prepare(guard, &modules[..3])?.publish();
            let latest = x86_64_runtime_tls_view::current(first.thread_pointer) as usize;
            if old == latest || !resident(old) || !resident(latest) { return None; }
            // All worker users are quiescent. Release reacquires the same
            // graph lock through the exact runtime token release entry point.
            Guard::complete_fork();
            if release(&first_token) != 0 || resident(old) || resident(latest)
                || resident(first.mapping as usize) { return None; }
            {
                let next_guard = Guard::acquire();
                let mut count = 0;
                visit_registered_threads(&next_guard, |_| { count += 1; Some(()) })?;
                if count != 2 || !contains_thread(&next_guard, main.thread_pointer)
                    || !contains_thread(&next_guard, second.thread_pointer) { return None; }
                // Retired registry nodes are absent before the next growth;
                // it publishes only to the main and surviving worker TCBs.
                x86_64_runtime_tls_view::PreparedAllThreads::prepare(&next_guard, &modules)?.publish();
                let second_view = x86_64_runtime_tls_view::current(second.thread_pointer);
                if x86_64_runtime_tls_view::resolve(second_view, 2, 0).cast::<u8>() != second_address
                    || *second_address != 73
                    || *x86_64_runtime_tls_view::resolve(second_view, 4, 0).cast::<u8>() != 17
                { return None; }
            }
            let late = materialize_initial_tls(&initial, core::mem::size_of::<AllocationNode>())?;
            let late_token;
            {
                let next_guard = Guard::acquire();
                late_token = register(late);
                // A new worker uses the retained templates, not another
                // worker's mutated live image, for all current modules.
                x86_64_runtime_tls_view::PreparedTlsView::prepare(late.thread_pointer, &modules)?
                    .publish(late.thread_pointer);
                let view = x86_64_runtime_tls_view::current(late.thread_pointer);
                if *x86_64_runtime_tls_view::resolve(view, 2, 0).cast::<u8>() != 17
                    || *x86_64_runtime_tls_view::resolve(view, 4, 96).cast::<u8>() != 0
                    || *second_address != 73 { return None; }
                let mut count = 0;
                visit_registered_threads(&next_guard, |_| { count += 1; Some(()) })?;
                if count != 3 { return None; }
            }
            if release(&second_token) != 0 || release(&late_token) != 0 { return None; }
            {
                let next_guard = Guard::acquire();
                let mut count = 0;
                visit_registered_threads(&next_guard, |_| { count += 1; Some(()) })?;
                if count != 1 || x86_64_runtime_tls_view::release(main.thread_pointer) != 0
                    || syscall2(SYS_MUNMAP, main.mapping as i64, main.mapping_byte_len as i64) != 0
                { return None; }
            }
            Some(true)
        })().unwrap_or(false) } }
        // Isolated address-space reclamation keeps mincore observations from
        // racing unrelated harness mappings that reuse a released address.
        unsafe { super::super::x86_64_runtime_lock::isolated_mapping_probe(probe); }
    }

    /// Exercise the actual release boundary against owned native mappings,
    /// including forged spans, duplicate release and a reused-address stale ID.
    #[test]
    fn worker_tls_release_requires_exact_live_generation_and_mapping() {
        let mapping = unsafe { syscall6(SYS_MMAP, 0, PAGE as i64, PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) };
        assert!(!is_linux_error(mapping));
        let mut token = WorkerTlsAllocation { mapping: mapping as *mut u8, mapping_size: PAGE as usize,
            thread_pointer: (mapping as usize + 128) as *mut u8, allocation_id: usize::MAX - 1 };
        {
            let _guard = Guard::acquire();
            unsafe { register_allocation(token.mapping.cast(), token); }
        }
        let stale = token;
        let mut forged = token;
        forged.mapping_size += PAGE as usize;
        assert_eq!(unsafe { release(&forged) }, -22);
        forged = token;
        forged.thread_pointer = token.mapping;
        assert_eq!(unsafe { release(&forged) }, -22);
        // Model exact address reuse with a different generation while retaining
        // this mapped node. Stale tokens must not withdraw the new owner.
        token.allocation_id += 1;
        {
            let _guard = Guard::acquire();
            unsafe { (*token.mapping.cast::<AllocationNode>()).token = token; }
        }
        assert_eq!(unsafe { release(&stale) }, -22);
        assert_eq!(unsafe { release(&token) }, 0);
        assert_eq!(unsafe { release(&token) }, -22);
        assert_eq!(unsafe { release(core::ptr::null()) }, -22);
    }
}

/// `token` must designate readable aligned token storage. All users of its TP
/// must have quiesced, including the kernel clear-child-TID operation. Tokens
/// are exact-once ownership, not permission to unmap arbitrary address ranges.
unsafe extern "C" fn release(token: *const WorkerTlsAllocation) -> i64 {
    if token.is_null() || token as usize % core::mem::align_of::<WorkerTlsAllocation>() != 0 { return -22; }
    let token = unsafe { core::ptr::read(token) };
    if token.allocation_id == 0 { return -22; }
    let _guard = Guard::acquire();
    let mut link = REGISTRY.0.get();
    loop {
        let node = unsafe { *link };
        if node.is_null() { return -22; }
        if unsafe { (*node).token } == token {
            let views = unsafe { x86_64_runtime_tls_view::release(token.thread_pointer) };
            if views != 0 { return views; }
            let next = unsafe { (*node).next };
            let result = syscall2(SYS_MUNMAP, token.mapping as i64, token.mapping_size as i64);
            if result == 0 { unsafe { *link = next; } }
            return result;
        }
        link = unsafe { core::ptr::addr_of_mut!((*node).next) };
    }
}
