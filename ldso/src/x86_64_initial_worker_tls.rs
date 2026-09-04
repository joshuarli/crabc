//! Ownership of worker allocations for the immutable initial module graph.
//!
//! Materialization uses the startup allocator and retained relocated templates,
//! without installing FS or calling libc. A generation-tagged token identifies
//! exactly one live mapping. Registry withdrawal precedes unmapping; wrong,
//! stale and duplicate tokens cannot unmap another allocation. The libc caller
//! must separately prove kernel clear-child-TID and reader quiescence.

use super::*;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use super::x86_64_general_initial_loader_state::GeneralInitialLoaderState;

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
// Access is serialized by LOCK; no pointer/reference escapes the lock.
unsafe impl Sync for AllocationRegistry {}
static REGISTRY: AllocationRegistry = AllocationRegistry(UnsafeCell::new(core::ptr::null_mut()));
static LOCK: AtomicBool = AtomicBool::new(false);
static NEXT_ID: AtomicUsize = AtomicUsize::new(1);

struct Guard;
impl Guard {
    fn acquire() -> Self {
        while LOCK.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
            core::hint::spin_loop();
        }
        Self
    }
}
impl Drop for Guard { fn drop(&mut self) { LOCK.store(false, Ordering::Release); } }

pub(super) fn runtime_function(name: &[u8]) -> Option<u64> {
    match name {
        b"__crabc_x86_64_initial_tls_allocate" => Some(allocate as *const () as usize as u64),
        b"__crabc_x86_64_initial_tls_release" => Some(release as *const () as usize as u64),
        b"__crabc_x86_64_resolve_initial_tls" => Some(__tls_get_addr as *const () as usize as u64),
        _ => None,
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

/// LOCK is held; `node` is writable mapping-prefix storage, disjoint from
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
            let next = unsafe { (*node).next };
            let result = syscall2(SYS_MUNMAP, token.mapping as i64, token.mapping_size as i64);
            if result == 0 { unsafe { *link = next; } }
            return result;
        }
        link = unsafe { core::ptr::addr_of_mut!((*node).next) };
    }
}
