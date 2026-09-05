//! Stable process-lifetime objects for the installed general runtime loader.
//!
//! Initial maps remain borrowed from their canonical immutable owner. Runtime
//! maps and metadata nodes are owned by an unpublished transaction until its
//! relocation, callback, protection and all-thread TLS preparation completes.
//! Only then does one lock-protected publication append them to the registry.
//! No libc allocation or pthread-list operation is called while locked.
//!
//! Compatibility provenance: musl 1.2.6, MIT, revision
//! 9fa28ece75d8a2191de7c5bb53bed224c5947417. `ldso/dynlink.c` owns the
//! load_library/dlopen identity and scope transaction, queue_ctors/do_init_fini
//! callback ordering, __libc_exit_fini retained finalization, do_dlsym,
//! dladdr and dl_iterate_phdr behavior; src/ldso/dlclose.c retains maps and
//! src/ldso/dlinfo.c admits LINKMAP only. Stable raw nodes, typed rollback and
//! coherent retained TLS views and deferred relocation journals are crabc
//! ownership machinery. Shared library search is source-mapped separately;
//! see compat/x86_64/runtime-dynamic-loader.md for source mapping and evidence.

use super::*;
use super::x86_64_general_initial_loader_state::GeneralInitialLoaderState;
use super::x86_64_general_initial_lifecycle::GeneralInitialLifecycle;
use super::x86_64_initial_graph_state::InitialGraphState;
use super::x86_64_runtime_memory::LoaderBuffer;
use super::x86_64_runtime_lock::{RuntimeGuard, wait_initialization, wake_initialization};
use super::x86_64_general_relocation::deferred::{self, PendingRelocations, PreparedRetry};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicI32, Ordering};

#[cfg(test)]
#[path = "x86_64_runtime_registry_tests.rs"]
mod tests;

const CALLBACKS: usize = MAX_GENERAL_INITIAL_DEPENDENCY_INIT_ARRAY_ENTRIES + 1;
const INITIALIZED: i32 = -1;
const FINALIZING: i32 = -2;
const FINALIZED: i32 = -3;

// Public LP64 C layouts, passed only through private address-resolved calls.
// Borrowed strings, program headers and link maps have process lifetime;
// traversal of mutable link-map links still requires caller synchronization.
#[repr(C)]
struct LinkMap {
    address: usize,
    name: *const u8,
    dynamic: *const u8,
    next: *mut LinkMap,
    previous: *mut LinkMap,
}
#[repr(C)]
struct AddressInfo {
    name: *const u8,
    base: *mut c_void,
    symbol_name: *const u8,
    symbol_address: *mut c_void,
}
#[repr(C)]
struct ProgramHeaderInfo {
    address: usize,
    name: *const u8,
    headers: *const u8,
    count: u16,
    additions: u64,
    removals: u64,
    tls_module: usize,
    tls_data: *mut c_void,
}
type ProgramHeaderCallback = unsafe extern "C" fn(*mut ProgramHeaderInfo, usize, *mut c_void) -> i32;

enum ObjectStorage { Initial(usize), Runtime(Object) }

struct RuntimeObject {
    link_map: LinkMap,
    storage: ObjectStorage,
    identity: ObjectIdentity,
    index: usize,
    next: *mut RuntimeObject,
    previous: *mut RuntimeObject,
    symbol_next: *mut RuntimeObject,
    fini_next: *mut RuntimeObject,
    needed_by: *mut RuntimeObject,
    global: bool,
    short_name: bool,
    needed: [*mut RuntimeObject; MAX_NEEDED],
    needed_count: usize,
    name: [u8; MAX_PATH],
    initializers: [usize; CALLBACKS],
    initializer_count: usize,
    finalizers: [usize; CALLBACKS],
    finalizer_count: usize,
    // Zero is queued, a positive kernel TID owns an executing constructor,
    // and negative values are terminal initialization/finalization phases.
    callback_state: AtomicI32,
}

impl RuntimeObject {
    unsafe fn allocate(storage: ObjectStorage, identity: ObjectIdentity, index: usize, name: &[u8], short_name: bool) -> Option<*mut Self> {
        if name.len() >= MAX_PATH { return None; }
        let address = unsafe { syscall6(SYS_MMAP, 0, core::mem::size_of::<Self>() as i64,
            PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) };
        if is_linux_error(address) { return None; }
        let node = address as *mut Self;
        unsafe { core::ptr::write(node, Self { link_map: LinkMap { address: 0, name: core::ptr::null(), dynamic: core::ptr::null(), next: core::ptr::null_mut(), previous: core::ptr::null_mut() }, storage, identity, index,
            next: core::ptr::null_mut(), previous: core::ptr::null_mut(), symbol_next: core::ptr::null_mut(), fini_next: core::ptr::null_mut(), needed_by: core::ptr::null_mut(), global: false, short_name,
            needed: [core::ptr::null_mut(); MAX_NEEDED], needed_count: 0, name: [0; MAX_PATH],
            initializers: [0; CALLBACKS], initializer_count: 0, finalizers: [0; CALLBACKS], finalizer_count: 0,
            callback_state: AtomicI32::new(0) });
            core::ptr::copy_nonoverlapping(name.as_ptr(), (*node).name.as_mut_ptr(), name.len());
            (*node).link_map.name = (*node).name.as_ptr();
            if let ObjectStorage::Runtime(object) = &(*node).storage {
                (*node).link_map.address = object.base as usize;
                (*node).link_map.dynamic = object.dynamic;
            }
        }
        Some(node)
    }

    unsafe fn object(&self) -> Option<&Object> {
        match &self.storage {
            ObjectStorage::Initial(index) => GeneralInitialLoaderState::retained()?.ready_objects()?.get(*index),
            ObjectStorage::Runtime(object) => Some(object),
        }
    }

    unsafe fn callbacks(&mut self, initializers: &[usize], finalizers: &[usize]) -> Option<()> {
        if initializers.len() > CALLBACKS || finalizers.len() > CALLBACKS { return None; }
        self.initializers[..initializers.len()].copy_from_slice(initializers);
        self.finalizers[..finalizers.len()].copy_from_slice(finalizers);
        self.initializer_count = initializers.len();
        self.finalizer_count = finalizers.len();
        Some(())
    }
}

/// Owns unpublished nodes and only their runtime-created ELF maps. It cannot
/// destroy kernel/initial maps even when preparation fails after many nodes.
struct UnpublishedObjects { head: *mut RuntimeObject, tail: *mut RuntimeObject, count: usize }
impl UnpublishedObjects {
    const fn new() -> Self { Self { head: core::ptr::null_mut(), tail: core::ptr::null_mut(), count: 0 } }
    unsafe fn append(&mut self, node: *mut RuntimeObject) -> Option<()> {
        let count = self.count.checked_add(1)?;
        unsafe { (*node).previous = self.tail;
            if !self.tail.is_null() {
                (*node).link_map.previous = core::ptr::addr_of_mut!((*self.tail).link_map);
                (*self.tail).link_map.next = core::ptr::addr_of_mut!((*node).link_map);
            }
        }
        if self.tail.is_null() { self.head = node; }
        else { unsafe { (*self.tail).next = node; } }
        self.tail = node;
        self.count = count;
        Some(())
    }
    fn relinquish(&mut self) { self.head = core::ptr::null_mut(); self.tail = core::ptr::null_mut(); self.count = 0; }
}
impl Drop for UnpublishedObjects {
    fn drop(&mut self) {
        let mut node = self.tail;
        while !node.is_null() {
            unsafe {
                let previous = (*node).previous;
                if let ObjectStorage::Runtime(object) = &(*node).storage {
                    syscall2(SYS_MUNMAP, object.map_span_start as i64, object.map_span_byte_len as i64);
                }
                syscall2(SYS_MUNMAP, node as i64, core::mem::size_of::<RuntimeObject>() as i64);
                node = previous;
            }
        }
    }
}

struct RuntimeRegistry {
    head: *mut RuntimeObject,
    tail: *mut RuntimeObject,
    symbols_head: *mut RuntimeObject,
    symbols_tail: *mut RuntimeObject,
    fini_head: *mut RuntimeObject,
    count: usize,
    initial_count: usize,
    initial_tls_count: usize,
    tls_count: usize,
    additions: u64,
    shutting_down: bool,
    finalizing: bool,
    initial_order: Option<LoaderBuffer<*mut RuntimeObject>>,
    deferred: Option<PendingRelocations>,
}
impl RuntimeRegistry {
    const fn empty() -> Self { Self { head: core::ptr::null_mut(), tail: core::ptr::null_mut(),
        symbols_head: core::ptr::null_mut(), symbols_tail: core::ptr::null_mut(), fini_head: core::ptr::null_mut(),
        count: 0, initial_count: 0, initial_tls_count: 0, tls_count: 0, additions: 0, shutting_down: false, finalizing: false,
        initial_order: None, deferred: None } }
}
struct RegistryCell(UnsafeCell<RuntimeRegistry>);
unsafe impl Sync for RegistryCell {}
static REGISTRY: RegistryCell = RegistryCell(UnsafeCell::new(RuntimeRegistry::empty()));

pub(super) struct PreparedInitialRegistry { nodes: UnpublishedObjects, registry: RuntimeRegistry }
impl PreparedInitialRegistry {
    /// # Safety
    /// The canonical initial transaction exclusively owns these already
    /// relocated/preflighted records. Preparation precedes ARCH_SET_FS and
    /// every application callback; no pointer to stack records is retained.
    pub(super) unsafe fn prepare(graph: &InitialGraphState, objects: &[Object; MAX_OBJECTS], lifecycle: &GeneralInitialLifecycle) -> Option<Self> {
        let mut nodes = UnpublishedObjects::new();
        let mut by_index = LoaderBuffer::new(graph.object_count(), core::ptr::null_mut::<RuntimeObject>())?;
        for index in 0..graph.object_count() {
            let node = unsafe { RuntimeObject::allocate(ObjectStorage::Initial(index), graph.identity(index)?, index, b"", objects[index].search_short_name) }?;
            unsafe { nodes.append(node) }?;
            by_index.as_mut_slice()[index] = node;
            unsafe {
                (*node).link_map.address = objects[index].base as usize;
                (*node).link_map.dynamic = objects[index].dynamic;
            }
            if index == 0 { unsafe { (*node).callback_state.store(INITIALIZED, Ordering::Relaxed); } }
            else {
                let (init, fini) = lifecycle.callback_plan(index)?;
                unsafe { (*node).callbacks(init, fini) }?;
            }
        }
        for index in 0..graph.object_count() {
            let node = by_index.as_slice()[index];
            if let Some(parent) = objects[index].needed_by {
                unsafe { (*node).needed_by = by_index.as_slice()[parent]; }
            }
            let length = unsafe { bounded_nul(objects[index].search_name.as_ptr(), MAX_PATH) }?;
            unsafe { (&mut (*node).name)[..length].copy_from_slice(&objects[index].search_name[..length]); }
            let edges = graph.edges(index)?;
            for (slot, child) in edges.iter().enumerate() {
                unsafe { (*node).needed[slot] = by_index.as_slice()[*child]; }
                let child_node = by_index.as_slice()[*child];
                if unsafe { (*child_node).name[0] } == 0 {
                    let object = &objects[index];
                    let offset = object.needed[slot];
                    let name = unsafe { object.strtab.add(offset) };
                    let length = unsafe { bounded_nul(name, object.strsz.checked_sub(offset)?) }?;
                    if length >= MAX_PATH { return None; }
                    unsafe { core::ptr::copy_nonoverlapping(name, (*child_node).name.as_mut_ptr(), length); }
                }
            }
            unsafe { (*node).needed_count = edges.len(); }
        }
        let mut registry = RuntimeRegistry::empty();
        registry.head = nodes.head;
        registry.tail = nodes.tail;
        registry.count = nodes.count;
        registry.initial_count = nodes.count;
        registry.initial_tls_count = objects.iter().map(|object| object.tls_module_id).max().unwrap_or(0);
        registry.tls_count = registry.initial_tls_count;
        let plan = graph.dependency_first_plan().ok()?;
        let mut initial_order = LoaderBuffer::new(plan.indices().len(), core::ptr::null_mut::<RuntimeObject>())?;
        for (slot, &index) in plan.indices().iter().enumerate() {
            initial_order.as_mut_slice()[slot] = by_index.as_slice()[index];
        }
        registry.initial_order = Some(initial_order);
        // Initial symbol scope is breadth-first, not depth-first map order.
        let mut order = LoaderBuffer::new(nodes.count, core::ptr::null_mut::<RuntimeObject>())?;
        order.as_mut_slice()[0] = nodes.head;
        let mut count = 1;
        let mut next = 0;
        while next < count {
            let node = order.as_slice()[next];
            for &child in unsafe { &(&(*node).needed)[..(*node).needed_count] } {
                if !order.as_slice()[..count].contains(&child) {
                    *order.as_mut_slice().get_mut(count)? = child;
                    count += 1;
                }
            }
            next += 1;
        }
        if count != nodes.count { return None; }
        for &node in order.as_slice() { unsafe { add_global(&mut registry, node); } }
        Some(Self { nodes, registry })
    }

    /// # Safety
    /// Initial publication is still single-threaded and unique. The canonical
    /// graph and RuntimeV1 are already release-published; no fallible work or
    /// application callback may occur between that commit and this handoff.
    pub(super) unsafe fn publish(mut self) {
        let registry = core::mem::replace(&mut self.registry, RuntimeRegistry::empty());
        unsafe { core::ptr::write(REGISTRY.0.get(), registry); }
        self.nodes.relinquish();
    }
}

unsafe fn add_global(registry: &mut RuntimeRegistry, node: *mut RuntimeObject) {
    if unsafe { (*node).global } { return; }
    unsafe { (*node).global = true; }
    if registry.symbols_tail.is_null() { registry.symbols_head = node; }
    else { unsafe { (*registry.symbols_tail).symbol_next = node; } }
    registry.symbols_tail = node;
}

struct ObjectSnapshot { objects: LoaderBuffer<Object>, nodes: LoaderBuffer<*mut RuntimeObject> }
impl ObjectSnapshot {
    unsafe fn collect(registry: &RuntimeRegistry, new: &UnpublishedObjects) -> Option<Self> {
        let count = registry.count.checked_add(new.count)?;
        let mut snapshot = Self { objects: LoaderBuffer::new(count, EMPTY_OBJECT)?,
            nodes: LoaderBuffer::new(count, core::ptr::null_mut())? };
        let mut cursor = 0;
        for head in [registry.head, new.head] {
            let mut node = head;
            while !node.is_null() {
                if unsafe { (*node).index } != cursor { return None; }
                snapshot.nodes.as_mut_slice()[cursor] = node;
                snapshot.objects.as_mut_slice()[cursor] = *unsafe { (*node).object() }?;
                cursor += 1;
                node = unsafe { (*node).next };
            }
        }
        (cursor == count).then_some(snapshot)
    }
}

struct ObjectOrder { indices: LoaderBuffer<usize>, count: usize }
impl ObjectOrder {
    fn as_slice(&self) -> &[usize] { &self.indices.as_slice()[..self.count] }
}

unsafe fn breadth_first_scope(snapshot: &ObjectSnapshot, registry: &RuntimeRegistry, root: *mut RuntimeObject, include_globals: bool) -> Option<ObjectOrder> {
    let count = snapshot.nodes.as_slice().len();
    let mut order = ObjectOrder { indices: LoaderBuffer::new(count, 0)?, count: 0 };
    let mut seen = LoaderBuffer::new(count, false)?;
    let mut add = |node: *mut RuntimeObject| -> Option<()> {
        let index = unsafe { (*node).index };
        if *snapshot.nodes.as_slice().get(index)? != node { return None; }
        if !seen.as_slice()[index] {
            *order.indices.as_mut_slice().get_mut(order.count)? = index;
            order.count += 1;
            seen.as_mut_slice()[index] = true;
        }
        Some(())
    };
    if include_globals {
        let mut node = registry.symbols_head;
        while !node.is_null() { add(node)?; node = unsafe { (*node).symbol_next }; }
    }
    add(root)?;
    drop(add);
    let mut cursor = 0;
    while cursor < order.count {
        let node = snapshot.nodes.as_slice()[order.indices.as_slice()[cursor]];
        for &child in unsafe { &(&(*node).needed)[..(*node).needed_count] } {
            let index = unsafe { (*child).index };
            if *snapshot.nodes.as_slice().get(index)? != child { return None; }
            if !seen.as_slice()[index] {
                *order.indices.as_mut_slice().get_mut(order.count)? = index;
                order.count += 1;
                seen.as_mut_slice()[index] = true;
            }
        }
        cursor += 1;
    }
    Some(order)
}

unsafe fn constructor_order(snapshot: &ObjectSnapshot, root: *mut RuntimeObject) -> Option<ObjectOrder> {
    let count = snapshot.nodes.as_slice().len();
    let mut order = ObjectOrder { indices: LoaderBuffer::new(count, 0)?, count: 0 };
    let mut marked = LoaderBuffer::new(count, false)?;
    let mut stack = LoaderBuffer::new(count, (0usize, 0usize))?;
    let root_index = unsafe { (*root).index };
    *marked.as_mut_slice().get_mut(root_index)? = true;
    stack.as_mut_slice()[0] = (root_index, 0);
    let mut depth = 1;
    while depth != 0 {
        let (index, next) = stack.as_slice()[depth - 1];
        let node = snapshot.nodes.as_slice()[index];
        if next == unsafe { (*node).needed_count } {
            *order.indices.as_mut_slice().get_mut(order.count)? = index;
            order.count += 1;
            depth -= 1;
        } else {
            stack.as_mut_slice()[depth - 1].1 += 1;
            let child = unsafe { (*node).needed[next] };
            let child_index = unsafe { (*child).index };
            if !*marked.as_slice().get(child_index)? {
                marked.as_mut_slice()[child_index] = true;
                *stack.as_mut_slice().get_mut(depth)? = (child_index, 0);
                depth += 1;
            }
        }
    }
    Some(order)
}

unsafe fn initialize_object(node: *mut RuntimeObject) {
    let tid = unsafe { syscall1(186, 0) } as i32;
    loop {
        let guard = RuntimeGuard::acquire();
        let registry = unsafe { &mut *REGISTRY.0.get() };
        let state = unsafe { (*node).callback_state.load(Ordering::Acquire) };
        if state < 0 || state == tid { return; }
        if state > 0 || registry.shutting_down {
            drop(guard);
            unsafe { wait_initialization(&(*node).callback_state, state); }
            continue;
        }
        unsafe { (*node).callback_state.store(tid, Ordering::Release); }
        if unsafe { (*node).finalizer_count } != 0 {
            unsafe { (*node).fini_next = registry.fini_head; }
            registry.fini_head = node;
        }
        drop(guard);
        for &address in unsafe { &(&(*node).initializers)[..(*node).initializer_count] } {
            let callback: unsafe extern "C" fn() = unsafe { core::mem::transmute(address) };
            unsafe { callback(); }
        }
        let _guard = RuntimeGuard::acquire();
        unsafe {
            let _ = (*node).callback_state.compare_exchange(tid, INITIALIZED, Ordering::AcqRel, Ordering::Acquire);
            wake_initialization(&(*node).callback_state);
        }
        return;
    }
}

pub(super) unsafe fn initialize_initial() {
    let (order, count) = {
        let _guard = RuntimeGuard::acquire();
        let registry = unsafe { &*REGISTRY.0.get() };
        let order = registry.initial_order.as_ref().unwrap().as_slice();
        (order.as_ptr(), order.len())
    };
    // This immutable queue was allocated/preflighted before ARCH_SET_FS.
    // Runtime growth cannot replace it; no fallible work follows preinit.
    for index in 0..count { unsafe { initialize_object(*order.add(index)); } }
}

pub(super) unsafe fn finalize_process() {
    let mut node = {
        let _guard = RuntimeGuard::acquire();
        let registry = unsafe { &mut *REGISTRY.0.get() };
        if registry.finalizing { return; }
        registry.shutting_down = true;
        registry.finalizing = true;
        registry.fini_head
    };
    let tid = unsafe { syscall1(186, 0) } as i32;
    while !node.is_null() {
        let guard = RuntimeGuard::acquire();
        let state = unsafe { (*node).callback_state.load(Ordering::Acquire) };
        if state > 0 && state != tid {
            drop(guard);
            unsafe { wait_initialization(&(*node).callback_state, state); }
            continue;
        }
        let next = unsafe { (*node).fini_next };
        // The fini-list is registered before the constructor, but musl's
        // `constructed` flag is set only after all its callbacks return.
        // exit from this same constructor skips the incomplete object.
        if state == INITIALIZED {
            unsafe { (*node).callback_state.store(FINALIZING, Ordering::Release); }
            drop(guard);
            for &address in unsafe { &(&(*node).finalizers)[..(*node).finalizer_count] } {
                let callback: unsafe extern "C" fn() = unsafe { core::mem::transmute(address) };
                unsafe { callback(); }
            }
            unsafe { (*node).callback_state.store(FINALIZED, Ordering::Release); wake_initialization(&(*node).callback_state); }
        }
        node = next;
    }
}

const ERROR_BAD_ELF: i32 = 10001;
const ERROR_RELOCATION: i32 = 10002;
const ERROR_TLS: i32 = 10003;
const ERROR_NOLOAD: i32 = 10004;
const ERROR_SHUTDOWN: i32 = 10005;
const ERROR_HANDLE: i32 = 10006;
const ERROR_SYMBOL: i32 = 10007;

unsafe fn node_name(node: *mut RuntimeObject) -> &'static [u8] {
    let name = unsafe { (*node).name.as_ptr() };
    let length = unsafe { bounded_nul(name, MAX_PATH) }.unwrap();
    unsafe { core::slice::from_raw_parts(name, length) }
}

unsafe fn find_identity(registry: &RuntimeRegistry, new: &UnpublishedObjects, identity: ObjectIdentity) -> *mut RuntimeObject {
    for head in [registry.head, new.head] {
        let mut node = head;
        while !node.is_null() {
            if unsafe { (*node).identity } == identity { return node; }
            node = unsafe { (*node).next };
        }
    }
    core::ptr::null_mut()
}

unsafe fn find_short_name(registry: &RuntimeRegistry, new: &UnpublishedObjects, name: &[u8]) -> *mut RuntimeObject {
    for head in [registry.head, new.head] {
        let mut node = head;
        while !node.is_null() {
            if unsafe { (*node).short_name } {
                let stored = unsafe { node_name(node) };
                let start = stored.iter().rposition(|byte| *byte == b'/').map_or(0, |index| index + 1);
                if &stored[start..] == name { return node; }
            }
            node = unsafe { (*node).next };
        }
    }
    core::ptr::null_mut()
}

unsafe fn open_runtime_file(parent: *mut RuntimeObject, name: &[u8]) -> Result<x86_64_library_search::Opened, i32> {
    let mut node = parent;
    let chain = core::iter::from_fn(|| {
        if node.is_null() { return None; }
        let object = unsafe { (*node).object() };
        node = unsafe { (*node).needed_by };
        object
    });
    unsafe { x86_64_library_search::open(name, chain) }
}

unsafe fn load_one(
    registry: &RuntimeRegistry, new: &mut UnpublishedObjects, parent: *mut RuntimeObject,
    name: &[u8], no_load: bool, tls_count: &mut usize,
) -> Result<*mut RuntimeObject, i32> {
    let short_name = !name.contains(&b'/');
    if short_name {
        let existing = unsafe { find_short_name(registry, new, name) };
        if !existing.is_null() { return Ok(existing); }
    }
    let (fd, path, length) = unsafe { open_runtime_file(parent, name) }?;
    let identity = unsafe { file_identity_from_fd(fd) };
    let Some(identity) = identity else { unsafe { syscall1(SYS_CLOSE, fd); } return Err(ERROR_BAD_ELF); };
    let existing = unsafe { find_identity(registry, new, identity) };
    if !existing.is_null() {
        unsafe { syscall1(SYS_CLOSE, fd); }
        if short_name { unsafe { (*existing).short_name = true; } }
        return Ok(existing);
    }
    if no_load { unsafe { syscall1(SYS_CLOSE, fd); } return Err(ERROR_NOLOAD); }
    let mapped = unsafe { map_elf(fd, false, true) };
    unsafe { syscall1(SYS_CLOSE, fd); }
    let mut object = mapped.ok_or(ERROR_BAD_ELF)?;
    object.search_name = path;
    object.search_short_name = short_name;
    let index = match registry.count.checked_add(new.count).and_then(|index| index.checked_add(1)).map(|next| next - 1) {
        Some(index) => index,
        None => { unsafe { syscall2(SYS_MUNMAP, object.map_span_start as i64, object.map_span_byte_len as i64); } return Err(12); }
    };
    if object.tls_memsz != 0 {
        let Some(id) = tls_count.checked_add(1) else {
            unsafe { syscall2(SYS_MUNMAP, object.map_span_start as i64, object.map_span_byte_len as i64); }
            return Err(12);
        };
        object.tls_module_id = id;
        object.tls_offset_below_tp = 0;
        *tls_count = id;
    }
    let node = unsafe { RuntimeObject::allocate(ObjectStorage::Runtime(object), identity, index, &path[..length], short_name) };
    let Some(node) = node else {
        unsafe { syscall2(SYS_MUNMAP, object.map_span_start as i64, object.map_span_byte_len as i64); }
        return Err(12);
    };
    unsafe { (*node).needed_by = parent; }
    if unsafe { new.append(node) }.is_none() {
        drop(UnpublishedObjects { head: node, tail: node, count: 1 });
        return Err(12);
    }
    Ok(node)
}

unsafe fn preflight_runtime_callbacks(node: *mut RuntimeObject) -> Option<()> {
    let object = *unsafe { (*node).object() }?;
    let mut init = [0usize; CALLBACKS];
    let mut fini = [0usize; CALLBACKS];
    let mut init_count = 0;
    let mut fini_count = 0;
    if object.general_init != 0 { init[0] = object.general_init; init_count = 1; }
    for index in 0..object.init_count {
        *init.get_mut(init_count)? = unsafe { *object.init_array.add(index) };
        init_count += 1;
    }
    for index in (0..object.general_fini_count).rev() {
        *fini.get_mut(fini_count)? = unsafe { *object.general_fini_array.add(index) };
        fini_count += 1;
    }
    if object.general_fini != 0 { *fini.get_mut(fini_count)? = object.general_fini; fini_count += 1; }
    for &address in init[..init_count].iter().chain(&fini[..fini_count]) {
        let offset = (address as u64).checked_sub(object.base)?;
        if address == 0 || !unsafe { virtual_range_in_executable_load(object.phdr, object.phnum, offset, 1) } { return None; }
    }
    unsafe { (*node).callbacks(&init[..init_count], &fini[..fini_count]) }
}

unsafe fn open_transaction(guard: &RuntimeGuard, filename: &[u8], flags: i32) -> Result<(*mut RuntimeObject, ObjectSnapshot, ObjectOrder), i32> {
    let registry = unsafe { &mut *REGISTRY.0.get() };
    if registry.head.is_null() { return Err(ERROR_HANDLE); }
    if registry.shutting_down { return Err(ERROR_SHUTDOWN); }
    let binding = flags & 3;
    if !matches!(binding, 1 | 2) || flags & !(3 | 4 | 256 | 4096) != 0 { return Err(22); }
    let mut new = UnpublishedObjects::new();
    let mut tls_count = registry.tls_count;
    let root = unsafe { load_one(registry, &mut new, registry.head, filename, flags & 4 != 0, &mut tls_count) }?;
    let mut node = new.head;
    while !node.is_null() {
        let object = *unsafe { (*node).object() }.ok_or(ERROR_BAD_ELF)?;
        for index in 0..object.needed_count {
            let offset = object.needed[index];
            let name = unsafe { object.strtab.add(offset) };
            let length = unsafe { bounded_nul(name, object.strsz.checked_sub(offset).ok_or(ERROR_BAD_ELF)?) }.ok_or(ERROR_BAD_ELF)?;
            let name = unsafe { core::slice::from_raw_parts(name, length) };
            if name.is_empty() { return Err(ERROR_BAD_ELF); }
            let child = unsafe { load_one(registry, &mut new, node, name, false, &mut tls_count) }?;
            unsafe { (*node).needed[index] = child; }
        }
        unsafe { (*node).needed_count = object.needed_count; }
        node = unsafe { (*node).next };
    }
    let snapshot = unsafe { ObjectSnapshot::collect(registry, &new) }.ok_or(12)?;
    let scope = unsafe { breadth_first_scope(&snapshot, registry, root, true) }.ok_or(12)?;
    let dependencies = unsafe { breadth_first_scope(&snapshot, registry, root, false) }.ok_or(12)?;
    let constructors = unsafe { constructor_order(&snapshot, root) }.ok_or(12)?;
    let deferred = unsafe { deferred::relocate_new(snapshot.objects.as_slice(), scope.as_slice(), registry.count,
        registry.initial_tls_count, binding == 1) }.ok_or(ERROR_RELOCATION)?;
    for index in registry.count..snapshot.objects.as_slice().len() {
        let object = &snapshot.objects.as_slice()[index];
        unsafe { preflight_runtime_callbacks(snapshot.nodes.as_slice()[index]) }.ok_or(ERROR_BAD_ELF)?;
        unsafe { protect_segments(object) }.ok_or(ERROR_BAD_ELF)?;
        unsafe { apply_relro(object) }.ok_or(ERROR_BAD_ELF)?;
    }
    let tls = if tls_count != registry.tls_count {
        Some(unsafe { x86_64_runtime_tls_view::PreparedAllThreads::prepare(guard, snapshot.objects.as_slice()) }.ok_or(ERROR_TLS)?)
    } else { None };
    // Retry against the final global scope, not the temporary local dependency
    // scope used above. Promoting an already retained provider is sufficient.
    let mut final_scope = ObjectOrder { indices: LoaderBuffer::new(scope.count, 0).ok_or(12)?, count: 0 };
    for &index in scope.as_slice() {
        if flags & 256 != 0 || unsafe { (*snapshot.nodes.as_slice()[index]).global } {
            final_scope.indices.as_mut_slice()[final_scope.count] = index;
            final_scope.count += 1;
        }
    }
    let retry = unsafe { PreparedRetry::prepare(snapshot.objects.as_slice(), final_scope.as_slice(),
        registry.initial_tls_count, registry.deferred.as_ref(), &deferred) }.ok_or(ERROR_RELOCATION)?;
    let retry = unsafe { retry.make_writable(guard) }.ok_or(ERROR_RELOCATION)?;
    // No fallible work remains. Worker allocation/release shares this guard;
    // every TP receives its coherent view before the new scope is visible.
    if let Some(tls) = tls { unsafe { tls.publish(); } }
    if !new.head.is_null() {
        unsafe {
            (*registry.tail).next = new.head;
            (*new.head).previous = registry.tail;
            (*registry.tail).link_map.next = core::ptr::addr_of_mut!((*new.head).link_map);
            (*new.head).link_map.previous = core::ptr::addr_of_mut!((*registry.tail).link_map);
        }
        registry.tail = new.tail;
        registry.count = snapshot.objects.as_slice().len();
        registry.tls_count = tls_count;
        new.relinquish();
    }
    if flags & 256 != 0 {
        for &index in dependencies.as_slice() { unsafe { add_global(registry, snapshot.nodes.as_slice()[index]); } }
    }
    registry.deferred = Some(unsafe { retry.commit() });
    registry.additions = registry.additions.wrapping_add(1);
    Ok((root, snapshot, constructors))
}

pub(super) unsafe fn attach_worker_tls(guard: &RuntimeGuard, tp: *mut u8) -> Option<()> {
    let registry = unsafe { &*REGISTRY.0.get() };
    if registry.head.is_null() { return None; }
    if registry.tls_count == registry.initial_tls_count { return Some(()); }
    let snapshot = unsafe { ObjectSnapshot::collect(registry, &UnpublishedObjects::new()) }?;
    unsafe { x86_64_runtime_tls_view::PreparedTlsView::prepare(tp, snapshot.objects.as_slice())?.publish(tp); }
    let _ = guard;
    Some(())
}

pub(super) fn runtime_function(name: &[u8]) -> Option<u64> {
    match name {
        b"__crabc_x86_64_runtime_open" => Some(runtime_open as *const () as usize as u64),
        b"__crabc_x86_64_runtime_symbol" => Some(runtime_symbol as *const () as usize as u64),
        b"__crabc_x86_64_runtime_close" => Some(runtime_close as *const () as usize as u64),
        b"__crabc_x86_64_runtime_address" => Some(runtime_address_info as *const () as usize as u64),
        b"__crabc_x86_64_runtime_information" => Some(runtime_information as *const () as usize as u64),
        b"__crabc_x86_64_runtime_iterate" => Some(runtime_iterate as *const () as usize as u64),
        _ => None,
    }
}

/// Private libc calls provide valid C strings, writable error storage and
/// disable deferred cancellation over loader mutation and callback execution.
unsafe extern "C" fn runtime_open(filename: *const u8, flags: i32, error: *mut i32) -> *mut c_void {
    if error.is_null() { return core::ptr::null_mut(); }
    unsafe { *error = 0; }
    if filename.is_null() {
        let _guard = RuntimeGuard::acquire();
        return unsafe { (*REGISTRY.0.get()).head.cast() };
    }
    let Some(length) = (unsafe { bounded_nul(filename, MAX_PATH) }) else { unsafe { *error = 36; } return core::ptr::null_mut(); };
    let filename = unsafe { core::slice::from_raw_parts(filename, length) };
    let result = {
        let guard = RuntimeGuard::acquire();
        unsafe { open_transaction(&guard, filename, flags) }
    };
    match result {
        Ok((root, snapshot, constructors)) => {
            for &index in constructors.as_slice() { unsafe { initialize_object(snapshot.nodes.as_slice()[index]); } }
            root.cast()
        }
        Err(code) => { unsafe { *error = code; } core::ptr::null_mut() }
    }
}

unsafe fn validated_handle(registry: &RuntimeRegistry, handle: *mut c_void) -> Option<*mut RuntimeObject> {
    let mut node = registry.head;
    while !node.is_null() {
        if node.cast::<c_void>() == handle { return Some(node); }
        node = unsafe { (*node).next };
    }
    None
}

unsafe extern "C" fn runtime_close(handle: *mut c_void) -> i32 {
    let _guard = RuntimeGuard::acquire();
    let registry = unsafe { &*REGISTRY.0.get() };
    if unsafe { validated_handle(registry, handle) }.is_some() { 0 } else { 1 }
}

unsafe extern "C" fn runtime_symbol(handle: *mut c_void, name: *const u8, caller: usize, error: *mut i32) -> *mut c_void {
    if error.is_null() || name.is_null() { return core::ptr::null_mut(); }
    unsafe { *error = 0; }
    let Some(length) = (unsafe { bounded_nul(name, MAX_PATH) }) else { unsafe { *error = ERROR_SYMBOL; } return core::ptr::null_mut(); };
    let name = unsafe { core::slice::from_raw_parts(name, length) };
    let result = (|| -> Result<_, i32> {
        let _guard = RuntimeGuard::acquire();
        let registry = unsafe { &*REGISTRY.0.get() };
        let snapshot = unsafe { ObjectSnapshot::collect(registry, &UnpublishedObjects::new()) }.ok_or(12)?;
        let mut order = ObjectOrder { indices: LoaderBuffer::new(registry.count, 0).ok_or(12)?, count: 0 };
        if handle.is_null() || handle.cast::<RuntimeObject>() == registry.head || handle as usize == usize::MAX {
            let mut node = registry.symbols_head;
            if handle as usize == usize::MAX {
                let mut owner = registry.head;
                for candidate in snapshot.nodes.as_slice() {
                    let object = unsafe { (**candidate).object() }.ok_or(ERROR_HANDLE)?;
                    if let Some(offset) = (caller as u64).checked_sub(object.base) {
                        if unsafe { virtual_range_in_load(object.phdr, object.phnum, offset, 1) } { owner = *candidate; break; }
                    }
                }
                // Musl starts at the caller's physical successor, then
                // traverses that object's symbol-scope links.
                node = unsafe { (*owner).next };
            }
            while !node.is_null() {
                order.indices.as_mut_slice()[order.count] = unsafe { (*node).index };
                order.count += 1;
                node = unsafe { (*node).symbol_next };
            }
        } else {
            let root = unsafe { validated_handle(registry, handle) }.ok_or(ERROR_HANDLE)?;
            order = unsafe { breadth_first_scope(&snapshot, registry, root, false) }.ok_or(12)?;
        }
        unsafe { x86_64_general_relocation::find_runtime_symbol(snapshot.objects.as_slice(), order.as_slice(), name) }.ok_or(ERROR_SYMBOL)
    })();
    match result {
        Ok(x86_64_general_relocation::RuntimeSymbol::Address(address)) => address as *mut c_void,
        Ok(x86_64_general_relocation::RuntimeSymbol::Tls { module, offset }) => {
            let index = TlsIndex { ti_module: module, ti_offset: offset };
            unsafe { __tls_get_addr(&index) }
        }
        Err(code) => { unsafe { *error = code; } core::ptr::null_mut() }
    }
}

unsafe fn address_owner(registry: &RuntimeRegistry, address: usize) -> Option<*mut RuntimeObject> {
    let mut node = registry.head;
    while !node.is_null() {
        let object = unsafe { (*node).object() }?;
        if let Some(offset) = (address as u64).checked_sub(object.base) {
            if unsafe { virtual_range_in_load(object.phdr, object.phnum, offset, 1) } { return Some(node); }
        }
        node = unsafe { (*node).next };
    }
    None
}

/// The libc bridge supplies writable ABI-sized result storage. Unknown
/// addresses leave it unchanged. ELF symbol/string bounds were admitted by
/// the canonical mapper; returned pointers borrow retained mappings.
unsafe extern "C" fn runtime_address_info(address: usize, output: *mut AddressInfo) -> i32 {
    if output.is_null() { return 0; }
    let _guard = RuntimeGuard::acquire();
    let registry = unsafe { &*REGISTRY.0.get() };
    let Some(node) = (unsafe { address_owner(registry, address) }) else { return 0; };
    let Some(object) = (unsafe { (*node).object() }) else { return 0; };
    // Musl's kernel_mapped_dso/dladdr reports the first mapped page, not
    // the load bias (which is zero for ET_EXEC). Derive it from admitted
    // PT_LOAD records: the rollback span is empty for the kernel-owned main.
    let mut first_load = u64::MAX;
    for index in 0..object.phnum {
        let header = unsafe { object.phdr.add(index * 56) };
        if unsafe { read_u32(header) } == PT_LOAD {
            first_load = first_load.min(unsafe { read_u64(header.add(16)) });
        }
    }
    let Some(mapping_base) = object.base.checked_add(align_down(first_load)) else { return 0; };
    let mut best = 0usize;
    let mut best_symbol = core::ptr::null();
    for index in 0..object.symcount {
        let symbol = unsafe { object.symtab.add(index * 24) };
        let info = unsafe { *symbol.add(4) };
        let value = unsafe { read_u64(symbol.add(8)) };
        if value == 0 || !matches!(info >> 4, 1 | 2) || !matches!(info & 15, 0 | 1 | 2 | 6) { continue; }
        let Some(candidate) = object.base.checked_add(value).and_then(|v| usize::try_from(v).ok()) else { continue; };
        if candidate > address || candidate <= best { continue; }
        best = candidate;
        best_symbol = symbol;
        if candidate == address { break; }
    }
    let mut name = core::ptr::null();
    if best != 0 {
        // Musl's unsigned size-1 admits an exact zero-sized symbol and does
        // not pretend that every nearest-lower nonzero-sized symbol covers
        // arbitrary later addresses.
        let size = unsafe { read_u64(best_symbol.add(16)) };
        let offset = unsafe { read_u32(best_symbol) } as usize;
        if (address - best) as u64 <= size.wrapping_sub(1) && offset < object.strsz
            && unsafe { bounded_nul(object.strtab.add(offset), object.strsz - offset) }.is_some()
        { name = unsafe { object.strtab.add(offset) }; }
        else { best = 0; }
    }
    unsafe { core::ptr::write(output, AddressInfo { name: (*node).name.as_ptr(),
        base: mapping_base as *mut c_void, symbol_name: name, symbol_address: best as *mut c_void }); }
    1
}

unsafe extern "C" fn runtime_information(handle: *mut c_void, output: *mut *mut c_void) -> i32 {
    if output.is_null() { return ERROR_HANDLE; }
    let _guard = RuntimeGuard::acquire();
    let registry = unsafe { &*REGISTRY.0.get() };
    let Some(node) = (unsafe { validated_handle(registry, handle) }) else { return ERROR_HANDLE; };
    unsafe { *output = core::ptr::addr_of_mut!((*node).link_map).cast(); }
    0
}

/// Calls application code without the loader lock. Like musl, the next link
/// is read after each callback, so a nested dlopen can extend this traversal.
/// Retained dlclose mappings make the current node safe across that callback.
unsafe extern "C" fn runtime_iterate(callback: ProgramHeaderCallback, data: *mut c_void) -> i32 {
    let mut node = {
        let _guard = RuntimeGuard::acquire();
        unsafe { (*REGISTRY.0.get()).head }
    };
    while !node.is_null() {
        let mut info = {
            let _guard = RuntimeGuard::acquire();
            let Some(object) = (unsafe { (*node).object() }) else { return 0; };
            let tls_data = if object.tls_module_id == 0 { core::ptr::null_mut() }
                else { unsafe { __tls_get_addr(&TlsIndex { ti_module: object.tls_module_id, ti_offset: 0 }) } };
            ProgramHeaderInfo { address: object.base as usize, name: unsafe { (*node).name.as_ptr() },
                headers: object.phdr, count: object.phnum as u16, additions: unsafe { (*REGISTRY.0.get()).additions },
                removals: 0, tls_module: object.tls_module_id, tls_data }
        };
        let result = unsafe { callback(&mut info, core::mem::size_of::<ProgramHeaderInfo>(), data) };
        if result != 0 { return result; }
        let _guard = RuntimeGuard::acquire();
        node = unsafe { (*node).next };
    }
    0
}
