extern crate std;
use super::*;
use core::sync::atomic::{AtomicPtr, AtomicUsize};

#[test]
fn timer_tls_reset_versions_resolve_to_distinct_private_targets() {
    let v1 = runtime_function(b"__crabc_x86_64_reset_current_tls_v1").unwrap();
    let v2 = runtime_function(b"__crabc_x86_64_reset_current_tls_v2").unwrap();
    assert_eq!(v1, reset_current_tls as *const () as usize as u64);
    assert_eq!(v2, reset_current_tls_preserving_allocator as *const () as usize as u64);
    assert_ne!(v1, v2);
    assert!(runtime_function(b"__crabc_x86_64_reset_current_tls_v3").is_none());
}

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
fn local_dependency_scope_promotes_without_repeating_reentrant_constructor() {
    static ROOT_PATH: AtomicPtr<u8> = AtomicPtr::new(core::ptr::null_mut());

    fn compile(source: &str, output: &std::path::Path, arguments: &[&str]) {
        let status = std::process::Command::new("/usr/local/bin/crabc-x86_64-musl-gcc")
            .args(["-O0", "-nostdlib", "-fPIC", "-shared", "-Wl,--hash-style=sysv"])
            .arg(source).args(arguments).arg("-o").arg(output).status().unwrap();
        assert!(status.success(), "scope fixture compilation failed");
    }

    unsafe fn probe(_: &RuntimeGuard) -> bool { unsafe { (|| -> Option<bool> {
        let main = RuntimeObject::allocate(ObjectStorage::Runtime(Object {
            role: ObjectRole::Main, ..EMPTY_OBJECT }), identity(1), 0,
            LoadedName::new(b"main"), false)?;
        (*main).callback_state.store(INITIALIZED, Ordering::Release);
        (*REGISTRY.0.get()).head = main;
        (*REGISTRY.0.get()).tail = main;
        (*REGISTRY.0.get()).count = 1;
        add_global(&mut *REGISTRY.0.get(), main);
        // The child owns its copied graph and invokes ABI entries that acquire
        // their own mutation lock. No installed-FS TLS operations are needed.
        RuntimeGuard::complete_fork();
        let mut diagnostic: RuntimeDiagnostic = core::mem::zeroed();
        let root = runtime_open(ROOT_PATH.load(Ordering::Acquire), 2, &mut diagnostic);
        if root.is_null() || diagnostic.kind != 0 || (*REGISTRY.0.get()).count != 4 { return None; }
        let mut error = 0;
        let caller = runtime_symbol(root, b"loader110_next_from_caller\0".as_ptr(), 0, &mut error);
        let calls = runtime_symbol(root, b"loader110_constructor_calls\0".as_ptr(), 0, &mut error).cast::<i32>();
        let reentry = runtime_symbol(root, b"loader110_constructor_reentry\0".as_ptr(), 0, &mut error).cast::<i32>();
        let value = runtime_symbol(root, b"loader110_next_value\0".as_ptr(), 0, &mut error).cast::<i32>();
        if error != 0 || caller.is_null() || calls.is_null() || reentry.is_null()
            || value.is_null() || *calls != 1 || *reentry != 1 || *value != 73 { return None; }
        let next = usize::MAX as *mut c_void;
        if !runtime_symbol(next, b"loader110_next_value\0".as_ptr(), caller as usize, &mut error).is_null()
            || error != ERROR_SYMBOL
            || !runtime_symbol(core::ptr::null_mut(), b"loader110_next_value\0".as_ptr(),
                0, &mut error).is_null() || error != ERROR_SYMBOL { return None; }
        let promoted = runtime_open(ROOT_PATH.load(Ordering::Acquire), 2 | 4 | 256, &mut diagnostic);
        if promoted != root || *calls != 1 || (*REGISTRY.0.get()).count != 4 { return None; }
        let global = runtime_symbol(core::ptr::null_mut(), b"loader110_next_value\0".as_ptr(),
            0, &mut error);
        let following = runtime_symbol(next, b"loader110_next_value\0".as_ptr(),
            caller as usize, &mut error);
        if error != 0 || global != value.cast() || following != value.cast()
            || runtime_close(root) != 0 { return None; }
        let retained = runtime_open(ROOT_PATH.load(Ordering::Acquire), 2 | 4, &mut diagnostic);
        Some(retained == root && *calls == 1 && *reentry == 1 && *value == 73)
    })().unwrap_or(false) } }

    let directory = std::path::Path::new(".work/loader110/fixtures");
    std::fs::create_dir_all(directory).unwrap();
    compile("compat/x86_64/tests/loader110_scope_first.c", &directory.join("libloader110-first.so"),
        &["-Wl,-soname,libloader110-first.so"]);
    compile("compat/x86_64/tests/loader110_scope_last.c", &directory.join("libloader110-last.so"),
        &["-Wl,-soname,libloader110-last.so"]);
    let root = directory.join("libloader110-root.so");
    compile("compat/x86_64/tests/loader110_scope_root.c", &root,
        &["-DLOADER110_SOURCE_PROBE", "-L.work/loader110/fixtures", "-l:libloader110-first.so",
          "-l:libloader110-last.so", "-Wl,-rpath,$ORIGIN"]);
    let root = std::ffi::CString::new(std::fs::canonicalize(root).unwrap().as_os_str()
        .as_encoded_bytes()).unwrap();
    ROOT_PATH.store(root.as_ptr().cast_mut().cast(), Ordering::Release);
    unsafe { super::super::x86_64_runtime_lock::isolated_mapping_probe(probe); }
    ROOT_PATH.store(core::ptr::null_mut(), Ordering::Release);
}

#[test]
fn failed_tls_load_rolls_back_before_successful_growth_and_retained_reopen() {
    static PROVIDER: AtomicPtr<u8> = AtomicPtr::new(core::ptr::null_mut());
    static MISSING: AtomicPtr<u8> = AtomicPtr::new(core::ptr::null_mut());

    fn compile(source: &str, output: &std::path::Path) {
        let status = std::process::Command::new("/usr/local/bin/crabc-x86_64-musl-gcc")
            .args(["-O0", "-nostdlib", "-fPIC", "-shared", "-Wl,--hash-style=sysv"])
            .arg(source).arg("-o").arg(output).status().unwrap();
        assert!(status.success(), "TLS fixture compilation failed");
    }

    unsafe fn mapped_file(needle: &[u8]) -> Option<bool> {
        let fd = unsafe { syscall4(257, -100, b"/proc/self/maps\0".as_ptr() as i64, 0, 0) };
        if fd < 0 { return None; }
        let mut bytes = [0u8; 65536];
        let mut used = 0;
        let result = loop {
            if used == bytes.len() { break None; }
            let count = unsafe { syscall3(0, fd, bytes.as_mut_ptr().add(used) as i64,
                (bytes.len() - used) as i64) };
            if count < 0 { break None; }
            if count == 0 { break Some(bytes[..used].windows(needle.len()).any(|part| part == needle)); }
            used += count as usize;
        };
        unsafe { syscall1(SYS_CLOSE, fd); }
        result
    }

    unsafe fn probe(_: &RuntimeGuard) -> bool { unsafe { (|| -> Option<bool> {
        let image = [31u8];
        let mut initial = [EMPTY_OBJECT; 32];
        initial[0] = Object { role: ObjectRole::Main, tls_image: image.as_ptr(),
            tls_filesz: 1, tls_memsz: 16, tls_align: 16, tls_module_id: 1,
            tls_offset_below_tp: 16, ..EMPTY_OBJECT };
        let block = materialize_initial_tls(&initial, 0)?;
        let original = *block.dtv.add(1) as *mut u8;
        *original = 97;
        let root = RuntimeObject::allocate(ObjectStorage::Runtime(initial[0]), identity(1), 0,
            LoadedName::new(b"main"), false)?;
        (*root).callback_state.store(INITIALIZED, Ordering::Release);
        (*REGISTRY.0.get()).head = root;
        (*REGISTRY.0.get()).tail = root;
        (*REGISTRY.0.get()).count = 1;
        (*REGISTRY.0.get()).tls_count = 1;
        (*REGISTRY.0.get()).initial_tls_count = 1;
        add_global(&mut *REGISTRY.0.get(), root);
        x86_64_initial_worker_tls::adopt_after_fork(block.thread_pointer);
        // This isolated child uses offline owned TCB storage. Keep host FS
        // intact; constructors access only their ordinary non-TLS counter.
        RuntimeGuard::complete_fork();
        let mut diagnostic: RuntimeDiagnostic = core::mem::zeroed();
        let failed = runtime_open(MISSING.load(Ordering::Acquire), 2, &mut diagnostic);
        if !failed.is_null() || diagnostic.kind != DIAGNOSTIC_SYMBOL
            || (*REGISTRY.0.get()).count != 1 || (*REGISTRY.0.get()).tls_count != 1
            || !x86_64_runtime_tls_view::current(block.thread_pointer).is_null()
            || *original != 97 || mapped_file(b"loader109_failed_tls.so")? { return None; }
        if !diagnostic.text.is_null() {
            syscall2(SYS_MUNMAP, diagnostic.text as i64, diagnostic.text_len as i64);
        }
        let provider = runtime_open(PROVIDER.load(Ordering::Acquire), 2, &mut diagnostic);
        if provider.is_null() || diagnostic.kind != 0 || (*REGISTRY.0.get()).count != 2
            || (*REGISTRY.0.get()).tls_count != 2 { return None; }
        let view = x86_64_runtime_tls_view::current(block.thread_pointer);
        let address = x86_64_runtime_tls_view::resolve(view, 2, 0).cast::<i32>();
        if address.is_null() || *address != 41
            || x86_64_runtime_tls_view::resolve(view, 1, 0).cast::<u8>() != original
            || *original != 97 || *block.dtv != 1 { return None; }
        *address = 73;
        let mut error = 0;
        let counter = runtime_symbol(provider, b"loader109_constructor_calls\0".as_ptr(),
            0, &mut error).cast::<i32>();
        if error != 0 || counter.is_null() || *counter != 1 || runtime_close(provider) != 0 { return None; }
        let reopened = runtime_open(PROVIDER.load(Ordering::Acquire), 2 | 4, &mut diagnostic);
        if reopened != provider || *counter != 1 || *address != 73
            || x86_64_runtime_tls_view::current(block.thread_pointer) != view
            || (*REGISTRY.0.get()).count != 2 || (*REGISTRY.0.get()).tls_count != 2
            || !mapped_file(b"loader109_provider_tls.so")? { return None; }
        if x86_64_runtime_tls_view::release(block.thread_pointer) != 0
            || syscall2(SYS_MUNMAP, block.mapping as i64, block.mapping_byte_len as i64) != 0
        { return None; }
        Some(true)
    })().unwrap_or(false) } }

    let directory = std::path::Path::new(".work/loader109/fixtures");
    std::fs::create_dir_all(directory).unwrap();
    let provider = directory.join("loader109_provider_tls.so");
    let missing = directory.join("loader109_failed_tls.so");
    compile("compat/x86_64/tests/loader109_tls_provider.c", &provider);
    compile("compat/x86_64/tests/loader109_tls_missing.c", &missing);
    let provider = std::ffi::CString::new(std::fs::canonicalize(provider).unwrap().as_os_str()
        .as_encoded_bytes()).unwrap();
    let missing = std::ffi::CString::new(std::fs::canonicalize(missing).unwrap().as_os_str()
        .as_encoded_bytes()).unwrap();
    PROVIDER.store(provider.as_ptr().cast_mut().cast(), Ordering::Release);
    MISSING.store(missing.as_ptr().cast_mut().cast(), Ordering::Release);
    unsafe { super::super::x86_64_runtime_lock::isolated_mapping_probe(probe); }
    PROVIDER.store(core::ptr::null_mut(), Ordering::Release);
    MISSING.store(core::ptr::null_mut(), Ordering::Release);
}

#[test]
fn allocated_common_storage_is_reported_by_dladdr() {
    unsafe fn probe(_: &RuntimeGuard) -> bool { unsafe { (|| -> Option<bool> {
        // The isolated fork child has no other threads. Release its inherited
        // graph lock before the ABI entry acquires that same lock.
        RuntimeGuard::complete_fork();
        let storage = page()?;
        core::ptr::write_bytes(storage, 0, PAGE as usize);
        core::ptr::write_unaligned(storage.cast::<u32>(), PT_LOAD);
        core::ptr::write_unaligned(storage.add(4).cast::<u32>(), PF_R | PF_W);
        core::ptr::write_unaligned(storage.add(32).cast::<u64>(), PAGE as u64);
        core::ptr::write_unaligned(storage.add(40).cast::<u64>(), PAGE as u64);
        let symbol = storage.add(256 + 24);
        core::ptr::write_unaligned(symbol.cast::<u32>(), 1);
        symbol.add(4).write(0x15);
        core::ptr::write_unaligned(symbol.add(6).cast::<u16>(), 1);
        core::ptr::write_unaligned(symbol.add(8).cast::<u64>(), 512);
        core::ptr::write_unaligned(symbol.add(16).cast::<u64>(), 4);
        core::ptr::copy_nonoverlapping(b"\0value\0".as_ptr(), storage.add(384), 7);
        let object = Object { base: storage as u64, phdr: storage, phnum: 1,
            symtab: storage.add(256), symcount: 2, strtab: storage.add(384), strsz: 7,
            map_span_start: storage as u64, map_span_byte_len: PAGE,
            ..EMPTY_OBJECT };
        let mut nodes = UnpublishedObjects::new();
        let node = RuntimeObject::allocate(ObjectStorage::Runtime(object), identity(1), 0,
            LoadedName::new(b"common"), true)?;
        nodes.append(node)?;
        (*REGISTRY.0.get()).head = node;
        (*REGISTRY.0.get()).tail = node;
        (*REGISTRY.0.get()).count = 1;
        let mut output: AddressInfo = core::mem::zeroed();
        let address = storage.add(512);
        let found = runtime_address_info(address as usize, &mut output);
        let result = found == 1 && output.symbol_name == storage.add(385)
            && output.symbol_address == address.cast();
        *REGISTRY.0.get() = RuntimeRegistry::empty();
        drop(nodes);
        Some(result)
    })().unwrap_or(false) } }
    unsafe { super::super::x86_64_runtime_lock::isolated_mapping_probe(probe); }
}

#[test]
fn abandoned_registry_nodes_unmap_only_transaction_owned_images() {
    unsafe fn probe(_: &RuntimeGuard) -> bool { unsafe { (|| -> Option<bool> {
        let borrowed_image = page()?;
        let new_image = page()?;
        let mut nodes = UnpublishedObjects::new();
        let initial = RuntimeObject::allocate(ObjectStorage::Initial(0), identity(1), 0, LoadedName::new(b"main"), false)?;
        nodes.append(initial)?;
        let runtime = RuntimeObject::allocate(ObjectStorage::Runtime(Object {
            map_span_start: new_image as u64, map_span_byte_len: PAGE, ..EMPTY_OBJECT
        }), identity(2), 1, LoadedName::new(b"runtime"), true)?;
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
            let node = RuntimeObject::allocate(ObjectStorage::Runtime(EMPTY_OBJECT), identity(index as u64), index, LoadedName::new(b"object"), true).unwrap();
            nodes.append(node).unwrap();
            pointers.push(node);
        }
        // Main globally sees its first dependency; the remaining runtime
        // chain is a local closure ending in a harmless dependency cycle.
        (*pointers[0]).needed.push(pointers[1]).unwrap();
        for index in 2..64 {
            (*pointers[index]).needed.push(pointers[index + 1]).unwrap();
        }
        (*pointers[64]).needed.push(pointers[2]).unwrap();
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
static CALLBACK_ORDER: AtomicUsize = AtomicUsize::new(0);

#[test]
fn initial_constructor_tid_consumes_handoff_once_and_repairs_a_fork_child() {
    let absent = InitialConstructorTid::new();
    let queries = core::cell::Cell::new(0);
    assert_eq!(absent.consume_with(|| { queries.set(queries.get() + 1); 41 }), 41);
    assert_eq!(queries.get(), 1);
    assert!(!absent.publish(42));

    let handed_off = InitialConstructorTid::new();
    assert!(!handed_off.publish(0));
    assert!(!handed_off.publish(-1));
    assert!(handed_off.publish(43));
    assert!(!handed_off.publish(44));
    assert_eq!(handed_off.consume_with(|| panic!("published TID queried again")), 43);
    assert!(!handed_off.publish(45));

    let inherited = InitialConstructorTid::new();
    assert!(inherited.publish(46));
    inherited.adopt_fork_child(47);
    assert_eq!(inherited.consume_with(|| panic!("fork child queried again")), 47);
}

#[test]
fn finalizer_tid_is_queried_only_for_an_active_constructor() {
    unsafe {
        let mut nodes = UnpublishedObjects::new();
        let finished = RuntimeObject::allocate(ObjectStorage::Runtime(EMPTY_OBJECT), identity(27),
            0, LoadedName::new(b"finished"), true).unwrap();
        nodes.append(finished).unwrap();
        let active = RuntimeObject::allocate(ObjectStorage::Runtime(EMPTY_OBJECT), identity(28),
            1, LoadedName::new(b"active"), true).unwrap();
        nodes.append(active).unwrap();
        (*finished).callback_state.store(INITIALIZED, Ordering::Release);
        (*active).callback_state.store(28, Ordering::Release);

        let calls = core::cell::Cell::new(0);
        let mut query = || { calls.set(calls.get() + 1); 27 };
        assert_eq!(finalizer_tid(core::ptr::null_mut(), &mut query), 0);
        assert_eq!(finalizer_tid(finished, &mut query), 0);
        assert_eq!(calls.get(), 0);

        (*finished).fini_next = active;
        assert_eq!(finalizer_tid(finished, &mut query), 27);
        assert_eq!(calls.get(), 1);
    }
}

unsafe extern "C" fn recursive_initializer() {
    INITIALIZATIONS.fetch_add(1, Ordering::SeqCst);
    record_callback(1);
    unsafe { initialize_object(CALLBACK_NODE.load(Ordering::SeqCst)); }
    std::thread::sleep(std::time::Duration::from_millis(10));
}
unsafe extern "C" fn recursive_finalizer() {
    FINALIZATIONS.fetch_add(1, Ordering::SeqCst);
    record_callback(3);
    unsafe { finalize_process(); }
}

fn record_callback(digit: usize) {
    let _ = CALLBACK_ORDER.fetch_update(Ordering::SeqCst, Ordering::SeqCst,
        |order| Some(order.wrapping_mul(10).wrapping_add(digit)));
}

unsafe extern "C" fn following_initializer() { record_callback(2); }
unsafe extern "C" fn following_finalizer() { record_callback(4); }

#[test]
fn shared_callback_owner_claims_once_across_recursive_and_concurrent_calls() {
    unsafe {
        let mut nodes = UnpublishedObjects::new();
        let node = RuntimeObject::allocate(ObjectStorage::Runtime(EMPTY_OBJECT), identity(9), 0, LoadedName::new(b"callbacks"), true).unwrap();
        nodes.append(node).unwrap();
        (*node).callbacks(
            &[recursive_initializer as *const () as usize, following_initializer as *const () as usize],
            &[recursive_finalizer as *const () as usize, following_finalizer as *const () as usize]).unwrap();
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
        assert_eq!(CALLBACK_ORDER.load(Ordering::SeqCst), 12);
        assert_eq!((*node).callback_state.load(Ordering::SeqCst), INITIALIZED);
        finalize_process();
        finalize_process();
        assert_eq!(FINALIZATIONS.load(Ordering::SeqCst), 1);
        assert_eq!(CALLBACK_ORDER.load(Ordering::SeqCst), 1234);
        assert_eq!((*node).callback_state.load(Ordering::SeqCst), FINALIZED);
        let _guard = RuntimeGuard::acquire();
        *REGISTRY.0.get() = saved;
        CallbackGuard::reset_finalized_fixture();
        CALLBACK_NODE.store(core::ptr::null_mut(), Ordering::SeqCst);
    }
}

#[test]
fn completed_cycle_root_skips_an_inherited_abandoned_constructor_queue() {
    unsafe {
        let mut nodes = UnpublishedObjects::new();
        let root = RuntimeObject::allocate(ObjectStorage::Runtime(EMPTY_OBJECT), identity(501), 0, LoadedName::new(b"cycle-root"), true).unwrap();
        let dependency = RuntimeObject::allocate(ObjectStorage::Runtime(EMPTY_OBJECT), identity(502), 1, LoadedName::new(b"cycle-dependency"), true).unwrap();
        nodes.append(root).unwrap();
        nodes.append(dependency).unwrap();
        (*root).needed.push(dependency).unwrap();
        (*dependency).needed.push(root).unwrap();
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

#[test]
fn iteration_callbacks_open_close_reopen_and_extend_retained_object_traversal() {
    static FIRST: AtomicPtr<u8> = AtomicPtr::new(core::ptr::null_mut());
    static LAST: AtomicPtr<u8> = AtomicPtr::new(core::ptr::null_mut());
    struct Observation {
        visits: usize,
        first: *mut c_void,
        last: *mut c_void,
        retained_name: *const u8,
        retained_headers: *const u8,
    }
    unsafe extern "C" fn stop(_: *mut ProgramHeaderInfo, size: usize, _: *mut c_void) -> i32 {
        if size == core::mem::size_of::<ProgramHeaderInfo>() { 37 } else { -1 }
    }
    unsafe extern "C" fn visit(info: *mut ProgramHeaderInfo, size: usize, data: *mut c_void) -> i32 {
        // The outer iterator owns info for this call; data remains this
        // child's observation record until the complete traversal returns.
        unsafe { (|| -> Option<i32> {
            let observed = &mut *data.cast::<Observation>();
            if size != core::mem::size_of::<ProgramHeaderInfo>() || (*info).removals != 0
                || (*info).tls_module != 0 || !(*info).tls_data.is_null() { return None; }
            let mut diagnostic: RuntimeDiagnostic = core::mem::zeroed();
            match observed.visits {
                0 => {
                    if (*info).additions != 0 { return None; }
                    observed.first = runtime_open(FIRST.load(Ordering::Acquire), 2, &mut diagnostic);
                    if observed.first.is_null() || diagnostic.kind != 0
                        || runtime_close(observed.first) != 0
                        || runtime_open(FIRST.load(Ordering::Acquire), 2 | 4, &mut diagnostic) != observed.first
                        || runtime_iterate(stop, core::ptr::null_mut()) != 37 { return None; }
                }
                1 => {
                    if (*info).additions != 2 || (*info).headers.is_null() { return None; }
                    observed.retained_name = (*info).name;
                    observed.retained_headers = (*info).headers;
                    observed.last = runtime_open(LAST.load(Ordering::Acquire), 2, &mut diagnostic);
                    if observed.last.is_null() || diagnostic.kind != 0
                        || runtime_close(observed.first) != 0
                        || !mapped(((*info).headers as usize & !(PAGE as usize - 1)) as *mut u8)
                        || (*info).name != observed.retained_name { return None; }
                }
                2 => {
                    if (*info).additions != 3 || runtime_close(observed.last) != 0 { return None; }
                }
                _ => return None,
            }
            observed.visits += 1;
            Some(0)
        })().unwrap_or(-1) }
    }
    unsafe fn probe(_: &RuntimeGuard) -> bool { unsafe { (|| -> Option<bool> {
        let main = RuntimeObject::allocate(ObjectStorage::Runtime(Object {
            role: ObjectRole::Main, ..EMPTY_OBJECT }), identity(1), 0,
            LoadedName::new(b"main"), false)?;
        (*main).callback_state.store(INITIALIZED, Ordering::Release);
        (*REGISTRY.0.get()).head = main;
        (*REGISTRY.0.get()).tail = main;
        (*REGISTRY.0.get()).count = 1;
        add_global(&mut *REGISTRY.0.get(), main);
        // Each public loader entry acquires its own graph lock. This sole
        // child retains all object mappings and never changes the host TCB.
        RuntimeGuard::complete_fork();
        let mut observed = Observation { visits: 0, first: core::ptr::null_mut(),
            last: core::ptr::null_mut(), retained_name: core::ptr::null(),
            retained_headers: core::ptr::null() };
        if runtime_iterate(visit, core::ptr::from_mut(&mut observed).cast()) != 0
            || observed.visits != 3 || !mapped((observed.retained_headers as usize & !(PAGE as usize - 1)) as *mut u8)
            || (*REGISTRY.0.get()).count != 3 { return None; }
        let first = observed.first.cast::<RuntimeObject>();
        if (*first).link_map.name != observed.retained_name
            || (*first).object()?.phdr != observed.retained_headers
            || node_name(first).is_empty() { return None; }
        let mut error = 0;
        let anchor = runtime_symbol(observed.first, b"loader110_first_anchor\0".as_ptr(), 0, &mut error);
        if anchor.is_null() || error != 0 { return None; }
        let call: unsafe extern "C" fn() -> i32 = core::mem::transmute(anchor);
        Some(call() == 1)
    })().unwrap_or(false) } }
    let directory = std::path::Path::new(".work/runtime-iteration/fixtures");
    std::fs::create_dir_all(directory).unwrap();
    let compile = |source: &str, file: &str| {
        let output = directory.join(file);
        assert!(std::process::Command::new("/usr/local/bin/crabc-x86_64-musl-gcc")
            .args(["-O0", "-nostdlib", "-fPIC", "-shared", "-Wl,--hash-style=sysv"])
            .arg(source).arg("-o").arg(&output).status().unwrap().success());
        std::ffi::CString::new(std::fs::canonicalize(output).unwrap().as_os_str()
            .as_encoded_bytes()).unwrap()
    };
    let first = compile("compat/x86_64/tests/loader110_scope_first.c", "libfirst.so");
    let last = compile("compat/x86_64/tests/loader110_scope_last.c", "liblast.so");
    FIRST.store(first.as_ptr().cast_mut().cast(), Ordering::Release);
    LAST.store(last.as_ptr().cast_mut().cast(), Ordering::Release);
    unsafe { super::super::x86_64_runtime_lock::isolated_mapping_probe(probe); }
    FIRST.store(core::ptr::null_mut(), Ordering::Release);
    LAST.store(core::ptr::null_mut(), Ordering::Release);
}
