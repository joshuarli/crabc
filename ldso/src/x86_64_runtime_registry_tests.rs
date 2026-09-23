extern crate std;
use super::*;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering};

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
        CallbackGuard::reset_finalized_fixture();
        CALLBACK_NODE.store(core::ptr::null_mut(), Ordering::SeqCst);
    }
}

#[test]
fn foreign_loader_read_waits_for_open_batch_constructor_and_owner_can_reenter() {
    use std::sync::mpsc;
    use std::time::Duration;

    unsafe {
        let mut nodes = UnpublishedObjects::new();
        let node = RuntimeObject::allocate(ObjectStorage::Runtime(EMPTY_OBJECT), identity(90), 0,
            b"opening", true).unwrap();
        nodes.append(node).unwrap();
        let pending_node = RuntimeObject::allocate(ObjectStorage::Runtime(EMPTY_OBJECT), identity(91), 1,
            b"later-opening", true).unwrap();
        nodes.append(pending_node).unwrap();
        let release_constructor = std::sync::Arc::new(AtomicBool::new(false));
        let owner_release = release_constructor.clone();
        let (constructor_started_tx, constructor_started_rx) = mpsc::channel();
        let owner_address = node as usize;
        let pending_address = pending_node as usize;
        let owner = std::thread::spawn(move || {
            let node = owner_address as *mut RuntimeObject;
            let pending_node = pending_address as *mut RuntimeObject;
            let tid = syscall1(186, 0) as i32;
            (*node).initialization_owner.store(tid, Ordering::Relaxed);
            (*pending_node).initialization_owner.store(tid, Ordering::Relaxed);
            (*node).callback_state.store(tid, Ordering::Release);
            // This is the constructor owner's same-thread dlsym/iteration
            // admission. It passes for both the active callback and a later
            // zero-state node in this same unpublished callback batch.
            assert_eq!(wait_for_readable_node(node), Ok(()));
            assert_eq!(wait_for_readable_node(pending_node), Ok(()));
            constructor_started_tx.send(()).unwrap();
            while !owner_release.load(Ordering::Acquire) { core::hint::spin_loop(); }
            (*node).callback_state.store(INITIALIZED, Ordering::Release);
            wake_initialization(&(*node).callback_state);
            (*pending_node).callback_state.store(INITIALIZED, Ordering::Release);
            wake_initialization(&(*pending_node).callback_state);
        });
        constructor_started_rx.recv().unwrap();

        READERS_WAITING_FOR_CONSTRUCTOR.store(0, Ordering::Release);
        let (reader_started_tx, reader_started_rx) = mpsc::channel();
        let (reader_done_tx, reader_done_rx) = mpsc::channel();
        let reader_address = node as usize;
        let reader = std::thread::spawn(move || {
            reader_started_tx.send(()).unwrap();
            let result = wait_for_readable_node(reader_address as *mut RuntimeObject);
            reader_done_tx.send(result).unwrap();
        });
        reader_started_rx.recv().unwrap();
        for _ in 0..1_000_000 {
            if READERS_WAITING_FOR_CONSTRUCTOR.load(Ordering::Acquire) != 0 { break; }
            core::hint::spin_loop();
        }
        assert_ne!(READERS_WAITING_FOR_CONSTRUCTOR.load(Ordering::Acquire), 0,
            "foreign loader read did not enter the constructor wait");
        assert!(reader_done_rx.recv_timeout(Duration::from_millis(10)).is_err(),
            "foreign loader read escaped before constructor completion");

        release_constructor.store(true, Ordering::Release);
        assert_eq!(reader_done_rx.recv_timeout(Duration::from_secs(1)).unwrap(), Ok(()));
        owner.join().unwrap();
        reader.join().unwrap();
    }
}

#[test]
fn opening_owner_does_not_bypass_a_foreign_constructor_claim() {
    let opening_tid = 41;
    let constructor_tid = 42;
    assert!(node_is_readable_to(0, opening_tid, opening_tid),
        "the opener may reenter a later zero-state node in its batch");
    assert!(!node_is_readable_to(0, 0, opening_tid),
        "a published zero-state node without an owner must not be admitted as ready");
    assert!(!node_is_readable_to(constructor_tid, opening_tid, opening_tid),
        "a positive state claimed by another thread must take precedence over stale owner metadata");
    assert!(node_is_readable_to(constructor_tid, opening_tid, constructor_tid),
        "the active constructor owner may reenter its own node");
}

#[test]
fn completed_cycle_root_skips_an_inherited_abandoned_constructor_queue() {
    unsafe {
        let mut nodes = UnpublishedObjects::new();
        let root = RuntimeObject::allocate(ObjectStorage::Runtime(EMPTY_OBJECT), identity(501), 0, b"cycle-root", true).unwrap();
        let dependency = RuntimeObject::allocate(ObjectStorage::Runtime(EMPTY_OBJECT), identity(502), 1, b"cycle-dependency", true).unwrap();
        nodes.append(root).unwrap();
        nodes.append(dependency).unwrap();
        (*root).needed[0] = dependency;
        (*root).needed_count = 1;
        (*dependency).needed[0] = root;
        (*dependency).needed_count = 1;
        // Recursive loading can complete one cycle member while its caller's
        // constructor is still active. Fork invalidates the vanished caller;
        // musl dlopen still bypasses queue_ctors for the constructed member.
        (*root).callback_state.store(INITIALIZED, Ordering::Release);
        (*dependency).callback_state.store(CONSTRUCTOR_ABANDONED, Ordering::Release);
        let snapshot = ObjectSnapshot::collect(&RuntimeRegistry::empty(), &nodes).unwrap();
        assert!(constructor_order(&snapshot, root).unwrap().as_slice().is_empty());
        let pending = constructor_order(&snapshot, dependency).unwrap();
        assert!(pending.as_slice().iter().any(|&index|
            (*snapshot.nodes.as_slice()[index]).callback_state.load(Ordering::Acquire) == CONSTRUCTOR_ABANDONED));
    }
}
