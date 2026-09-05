extern crate std;
use super::*;
use core::sync::atomic::{AtomicPtr, AtomicUsize};

#[test]
fn source_test_harness_keeps_its_own_tls_resolver() {
    extern "C" {
        #[link_name = "__tls_get_addr"]
        fn harness_tls_resolver(index: *const TlsIndex) -> *mut c_void;
    }
    assert_ne!(harness_tls_resolver as *const () as usize,
        super::super::__tls_get_addr as *const () as usize,
        "the owned resolver must not interpret the host test harness TCB");
}

unsafe fn page() -> Option<*mut u8> {
    let result = unsafe { syscall6(SYS_MMAP, 0, PAGE as i64, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) };
    (!is_linux_error(result)).then_some(result as *mut u8)
}

unsafe fn mapped(address: *mut u8) -> bool {
    let mut residency = 0u8;
    unsafe { syscall3(27, address as i64, PAGE as i64, core::ptr::addr_of_mut!(residency) as i64) == 0 }
}

fn identity(number: u64) -> ObjectIdentity { ObjectIdentity { device: 1, inode: number } }

#[test]
fn abandoned_registry_nodes_unmap_only_transaction_owned_images() {
    unsafe fn probe(_: &RuntimeGuard) -> bool { unsafe { (|| -> Option<bool> {
        let borrowed_image = page()?;
        let new_image = page()?;
        let mut nodes = UnpublishedObjects::new();
        let initial = RuntimeObject::allocate(ObjectStorage::Initial(0), identity(1), 0, b"main", false)?;
        nodes.append(initial)?;
        let runtime = RuntimeObject::allocate(ObjectStorage::Runtime(Object {
            map_span_start: new_image as u64, map_span_byte_len: PAGE, ..EMPTY_OBJECT
        }), identity(2), 1, b"runtime", true)?;
        nodes.append(runtime)?;
        if !mapped(new_image) || !mapped(borrowed_image) { return None; }
        drop(nodes);
        let result = !mapped(new_image) && mapped(borrowed_image);
        Some(syscall2(SYS_MUNMAP, borrowed_image as i64, PAGE as i64) == 0 && result)
    })().unwrap_or(false) } }
    unsafe { super::super::x86_64_runtime_lock::isolated_mapping_probe(probe); }
}

#[test]
fn runtime_scope_and_constructor_queue_are_resource_sized_and_cycle_safe() {
    unsafe {
        let mut nodes = UnpublishedObjects::new();
        let mut pointers = std::vec::Vec::new();
        for index in 0..65 {
            let node = RuntimeObject::allocate(ObjectStorage::Runtime(EMPTY_OBJECT), identity(index as u64), index, b"object", true).unwrap();
            nodes.append(node).unwrap();
            pointers.push(node);
        }
        // Main globally sees its first dependency; the remaining runtime
        // chain is a local closure ending in a harmless dependency cycle.
        (*pointers[0]).needed[0] = pointers[1];
        (*pointers[0]).needed_count = 1;
        for index in 2..64 {
            (*pointers[index]).needed[0] = pointers[index + 1];
            (*pointers[index]).needed_count = 1;
        }
        (*pointers[64]).needed[0] = pointers[2];
        (*pointers[64]).needed_count = 1;
        let mut registry = RuntimeRegistry::empty();
        registry.head = nodes.head;
        registry.tail = nodes.tail;
        registry.count = nodes.count;
        add_global(&mut registry, pointers[0]);
        add_global(&mut registry, pointers[1]);
        let snapshot = ObjectSnapshot::collect(&registry, &UnpublishedObjects::new()).unwrap();
        let local = breadth_first_scope(&snapshot, &registry, pointers[2], false).unwrap();
        assert_eq!(local.as_slice(), &(2..65).collect::<std::vec::Vec<_>>());
        let relocations = breadth_first_scope(&snapshot, &registry, pointers[2], true).unwrap();
        assert_eq!(relocations.as_slice(), &(0..65).collect::<std::vec::Vec<_>>());
        let callbacks = constructor_order(&snapshot, pointers[2]).unwrap();
        assert_eq!(callbacks.as_slice(), &(2..65).rev().collect::<std::vec::Vec<_>>());
        for &index in local.as_slice() { add_global(&mut registry, pointers[index]); }
        // Promotion must neither duplicate existing links nor lose ordering.
        add_global(&mut registry, pointers[2]);
        let mut current = registry.symbols_head;
        for pointer in pointers { assert_eq!(current, pointer); current = (*current).symbol_next; }
        assert!(current.is_null());
    }
}

static CALLBACK_NODE: AtomicPtr<RuntimeObject> = AtomicPtr::new(core::ptr::null_mut());
static INITIALIZATIONS: AtomicUsize = AtomicUsize::new(0);
static FINALIZATIONS: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" fn recursive_initializer() {
    INITIALIZATIONS.fetch_add(1, Ordering::SeqCst);
    unsafe { initialize_object(CALLBACK_NODE.load(Ordering::SeqCst)); }
    std::thread::sleep(std::time::Duration::from_millis(10));
}
unsafe extern "C" fn recursive_finalizer() {
    FINALIZATIONS.fetch_add(1, Ordering::SeqCst);
    unsafe { finalize_process(); }
}

#[test]
fn shared_callback_owner_claims_once_across_recursive_and_concurrent_calls() {
    unsafe {
        let mut nodes = UnpublishedObjects::new();
        let node = RuntimeObject::allocate(ObjectStorage::Runtime(EMPTY_OBJECT), identity(9), 0, b"callbacks", true).unwrap();
        nodes.append(node).unwrap();
        (*node).callbacks(&[recursive_initializer as *const () as usize], &[recursive_finalizer as *const () as usize]).unwrap();
        let saved = {
            let _guard = RuntimeGuard::acquire();
            core::mem::replace(&mut *REGISTRY.0.get(), RuntimeRegistry::empty())
        };
        CALLBACK_NODE.store(node, Ordering::SeqCst);
        let address = node as usize;
        let threads: std::vec::Vec<_> = (0..8).map(|_| std::thread::spawn(move || {
            initialize_object(address as *mut RuntimeObject);
        })).collect();
        for thread in threads { thread.join().unwrap(); }
        assert_eq!(INITIALIZATIONS.load(Ordering::SeqCst), 1);
        assert_eq!((*node).callback_state.load(Ordering::SeqCst), INITIALIZED);
        finalize_process();
        finalize_process();
        assert_eq!(FINALIZATIONS.load(Ordering::SeqCst), 1);
        assert_eq!((*node).callback_state.load(Ordering::SeqCst), FINALIZED);
        let _guard = RuntimeGuard::acquire();
        *REGISTRY.0.get() = saved;
        CALLBACK_NODE.store(core::ptr::null_mut(), Ordering::SeqCst);
    }
}
