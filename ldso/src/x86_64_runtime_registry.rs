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
use super::x86_64_runtime_memory::{LoaderBuffer, LoaderVec};
use super::x86_64_library_search::{LoadedName, ObjectName};
use super::x86_64_runtime_lock::{RuntimeGuard, CallbackGuard, wait_initialization, wake_initialization};
use super::x86_64_general_relocation::deferred::{self, PendingRelocations, PreparedRetry};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicI32, Ordering};

#[cfg(test)]
#[path = "x86_64_runtime_registry_tests.rs"]
mod tests;

const INITIALIZED: i32 = -1;
const FINALIZING: i32 = -2;
const FINALIZED: i32 = -3;
// Musl queue_ctors rejects a visitor whose pthread TID was invalidated by
// multithreaded fork. Keep this separate from completed initialization.
const CONSTRUCTOR_ABANDONED: i32 = -4;

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

// Musl's dlopen handle is its `struct dso`, whose leading fields are the
// public link map; RTLD_DI_LINKMAP returns that same address. Keep the link
// map first in a C layout so applications may use either spelling.
#[repr(C)]
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
    // Ordered DT_NEEDED nodes, in a loader mapping sized to the object.
    needed: LoaderVec<*mut RuntimeObject>,
    // Lazily retained dlsym dependency order; see `dependency_scope`.
    dependency_scope: Option<LoaderBuffer<*mut RuntimeObject>>,
    // The stored pathname every public view shows: a runtime object's own
    // exact-size mapping, released with the node on rollback, or an initial
    // object's name retained by the initial object table.
    name: ObjectName,
    owned_name: Option<LoadedName>,
    // Initializers then finalizers, copied once before the node can run
    // either. Musl's ELF arrays have no length bound, so this is sized to the
    // object; rollback releases it with the node and published nodes retain it.
    callbacks: Option<LoaderBuffer<usize>>,
    initializer_count: usize,
    finalizer_count: usize,
    // Zero is queued, a positive kernel TID owns an executing constructor,
    // and negative values are terminal initialization/finalization phases.
    callback_state: AtomicI32,
    // Set under the callback lock by a thread about to sleep on
    // `callback_state`; every state change a sleeper waits for is also made
    // under that lock, so the changer issues FUTEX_WAKE only when this was
    // set. Uncontended constructors and finalizers then make no futex call.
    callback_waiters: AtomicBool,
}

impl RuntimeObject {
    unsafe fn allocate(storage: ObjectStorage, identity: ObjectIdentity, index: usize, name: Option<LoadedName>, short_name: bool) -> Option<*mut Self> {
        let address = unsafe { syscall6(SYS_MMAP, 0, core::mem::size_of::<Self>() as i64,
            PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) };
        if is_linux_error(address) { return None; }
        let node = address as *mut Self;
        unsafe { core::ptr::write(node, Self { link_map: LinkMap { address: 0, name: core::ptr::null(), dynamic: core::ptr::null(), next: core::ptr::null_mut(), previous: core::ptr::null_mut() }, storage, identity, index,
            next: core::ptr::null_mut(), previous: core::ptr::null_mut(), symbol_next: core::ptr::null_mut(), fini_next: core::ptr::null_mut(), needed_by: core::ptr::null_mut(), global: false, short_name,
            needed: LoaderVec::new(), dependency_scope: None, name: name.as_ref().map_or(ObjectName::EMPTY, LoadedName::view), owned_name: name,
            callbacks: None, initializer_count: 0, finalizer_count: 0,
            callback_state: AtomicI32::new(0), callback_waiters: AtomicBool::new(false) });
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

    /// Copy one validated plan. A node receives its callbacks exactly once.
    unsafe fn callbacks(&mut self, initializers: &[usize], finalizers: &[usize]) -> Option<()> {
        let length = initializers.len().checked_add(finalizers.len())?;
        let buffer = if length == 0 { None } else {
            let mut buffer = LoaderBuffer::new(length, 0)?;
            let (first, second) = buffer.as_mut_slice().split_at_mut(initializers.len());
            first.copy_from_slice(initializers);
            second.copy_from_slice(finalizers);
            Some(buffer)
        };
        self.adopt_callbacks(buffer, initializers.len())
    }

    /// Take ownership of `initializers ++ finalizers` split at `initializer_count`.
    fn adopt_callbacks(&mut self, buffer: Option<LoaderBuffer<usize>>, initializer_count: usize) -> Option<()> {
        let length = buffer.as_ref().map_or(0, |buffer| buffer.as_slice().len());
        if self.callbacks.is_some() || initializer_count > length { return None; }
        self.callbacks = buffer;
        self.initializer_count = initializer_count;
        self.finalizer_count = length - initializer_count;
        Some(())
    }

    fn initializers(&self) -> &[usize] {
        self.callbacks.as_ref().map_or(&[], |buffer| &buffer.as_slice()[..self.initializer_count])
    }

    fn finalizers(&self) -> &[usize] {
        self.callbacks.as_ref().map_or(&[], |buffer| &buffer.as_slice()[self.initializer_count..])
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
                // The node is raw loader memory, never dropped as a whole;
                // release its one owned callback mapping explicitly.
                core::ptr::drop_in_place(core::ptr::addr_of_mut!((*node).callbacks));
                core::ptr::drop_in_place(core::ptr::addr_of_mut!((*node).needed));
                core::ptr::drop_in_place(core::ptr::addr_of_mut!((*node).owned_name));
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
    pub(super) unsafe fn prepare(graph: &InitialGraphState, objects: &[Object], lifecycle: &GeneralInitialLifecycle) -> Option<Self> {
        let mut nodes = UnpublishedObjects::new();
        let mut by_index = LoaderBuffer::new(graph.object_count(), core::ptr::null_mut::<RuntimeObject>())?;
        for index in 0..graph.object_count() {
            let node = unsafe { RuntimeObject::allocate(ObjectStorage::Initial(index), graph.identity(index)?, index, None, objects[index].search_short_name) }?;
            unsafe { nodes.append(node) }?;
            by_index.as_mut_slice()[index] = node;
            unsafe {
                (*node).link_map.address = objects[index].base as usize;
                (*node).link_map.dynamic = objects[index].dynamic;
                (*node).name = objects[index].search_name;
                (*node).link_map.name = (*node).name.as_ptr();
            }
            if objects[index].map_provenance == ObjectMapProvenance::KernelMain {
                // Only the public name changes. The empty search name keeps
                // the kernel image out of short-name and $ORIGIN selection.
                unsafe { (*node).link_map.name = x86_64_library_search::application_name(); }
            }
            // Every admitted object, including the main image in both CRT
            // modes, must have a preflighted plan: the registry alone claims
            // its construction and its reverse-construction finalization.
            let (init, fini) = lifecycle.callback_plan(index)?;
            unsafe { (*node).callbacks(init, fini) }?;
        }
        for index in 0..graph.object_count() {
            let node = by_index.as_slice()[index];
            if let Some(parent) = objects[index].needed_by {
                unsafe { (*node).needed_by = by_index.as_slice()[parent]; }
            }
            let edges = graph.edges(index)?;
            unsafe { (*node).needed.reserve(edges.len()) }?;
            for child in edges {
                unsafe { (*node).needed.push(by_index.as_slice()[*child]) }?;
            }
        }
        let mut registry = RuntimeRegistry::empty();
        registry.head = nodes.head;
        registry.tail = nodes.tail;
        registry.count = nodes.count;
        registry.initial_count = nodes.count;
        registry.initial_tls_count = objects.iter().map(|object| object.tls_module_id).max().unwrap_or(0);
        registry.tls_count = registry.initial_tls_count;
        // Musl's main_ctor_queue: the dependency postorder, then main last.
        let plan = graph.dependency_first_plan().ok()?;
        let initial_count = plan.indices().len().checked_add(1)?;
        let mut initial_order = LoaderBuffer::new(initial_count, core::ptr::null_mut::<RuntimeObject>())?;
        for (slot, &index) in plan.indices().iter().enumerate() {
            initial_order.as_mut_slice()[slot] = by_index.as_slice()[index];
        }
        *initial_order.as_mut_slice().last_mut()? = by_index.as_slice()[0];
        registry.initial_order = Some(initial_order);
        // Initial symbol scope is breadth-first, not depth-first map order.
        let mut order = LoaderBuffer::new(nodes.count, core::ptr::null_mut::<RuntimeObject>())?;
        order.as_mut_slice()[0] = nodes.head;
        let mut count = 1;
        let mut next = 0;
        while next < count {
            let node = order.as_slice()[next];
            for &child in unsafe { &(&(*node).needed)[..] } {
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
    pub(super) unsafe fn publish(mut self, loader_base: usize) {
        let registry = core::mem::replace(&mut self.registry, RuntimeRegistry::empty());
        unsafe { core::ptr::write(REGISTRY.0.get(), registry); }
        self.nodes.relinquish();
        unsafe { super::x86_64_debugger::publish_initial(
            core::ptr::addr_of_mut!((*(*REGISTRY.0.get()).head).link_map).cast(), loader_base); }
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
        for &child in unsafe { &(&(*node).needed)[..] } {
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
    // Musl dlopen calls queue_ctors only for an unconstructed root. In a
    // recursive cycle this member may be complete even though another visitor
    // was invalidated by fork; reopening the completed member remains valid.
    if unsafe { (*root).callback_state.load(Ordering::Acquire) } == INITIALIZED { return Some(order); }
    let mut marked = LoaderBuffer::new(count, false)?;
    let mut stack = LoaderBuffer::new(count, (0usize, 0usize))?;
    let root_index = unsafe { (*root).index };
    *marked.as_mut_slice().get_mut(root_index)? = true;
    stack.as_mut_slice()[0] = (root_index, 0);
    let mut depth = 1;
    while depth != 0 {
        let (index, next) = stack.as_slice()[depth - 1];
        let node = snapshot.nodes.as_slice()[index];
        if next == unsafe { (*node).needed.len() } {
            *order.indices.as_mut_slice().get_mut(order.count)? = index;
            order.count += 1;
            depth -= 1;
        } else {
            stack.as_mut_slice()[depth - 1].1 += 1;
            let child = unsafe { (&(*node).needed)[next] };
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
        let callbacks = CallbackGuard::acquire();
        let registry = unsafe { &mut *REGISTRY.0.get() };
        let state = unsafe { (*node).callback_state.load(Ordering::Acquire) };
        if state < 0 || state == tid { return; }
        if state > 0 || registry.shutting_down {
            unsafe { (*node).callback_waiters.store(true, Ordering::Relaxed); }
            drop(callbacks);
            drop(guard);
            unsafe { wait_initialization(&(*node).callback_state, state); }
            continue;
        }
        unsafe { (*node).callback_state.store(tid, Ordering::Release); }
        if unsafe { (*node).finalizer_count } != 0 {
            unsafe { (*node).fini_next = registry.fini_head; }
            registry.fini_head = node;
        }
        drop(callbacks);
        drop(guard);
        for &address in unsafe { (*node).initializers() } {
            let callback: unsafe extern "C" fn() = unsafe { core::mem::transmute(address) };
            unsafe { callback(); }
        }
        let _callbacks = CallbackGuard::acquire();
        // A constructor may fork recursively. The child translated its visitor
        // identity while this callback stack was suspended at the raw syscall.
        let current_tid = unsafe { syscall1(186, 0) } as i32;
        unsafe {
            let _ = (*node).callback_state.compare_exchange(current_tid, INITIALIZED, Ordering::AcqRel, Ordering::Acquire);
            wake_callback_waiters(node);
        }
        return;
    }
}

/// Wake every sleeper on `node`'s callback state after a change made under
/// the callback lock; see `RuntimeObject::callback_waiters`.
unsafe fn wake_callback_waiters(node: *mut RuntimeObject) {
    if unsafe { (*node).callback_waiters.swap(false, Ordering::Relaxed) } {
        unsafe { wake_initialization(&(*node).callback_state); }
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
    let guard = RuntimeGuard::acquire();
    let registry = unsafe { &mut *REGISTRY.0.get() };
    if registry.finalizing { return; }
    let mut callbacks = CallbackGuard::acquire();
    registry.shutting_down = true;
    registry.finalizing = true;
    let mut node = registry.fini_head;
    drop(guard);
    let tid = unsafe { syscall1(186, 0) } as i32;
    while !node.is_null() {
        let state = unsafe { (*node).callback_state.load(Ordering::Acquire) };
        if (state > 0 && state != tid) || state == CONSTRUCTOR_ABANDONED {
            unsafe { (*node).callback_waiters.store(true, Ordering::Relaxed); }
            drop(callbacks);
            unsafe { wait_initialization(&(*node).callback_state, state); }
            callbacks = CallbackGuard::acquire();
            continue;
        }
        let next = unsafe { (*node).fini_next };
        // Musl holds init_fini_lock throughout finalizer callbacks, but releases
        // it while waiting for a constructor. Same-thread constructor exit
        // skips the incomplete object; a vanished constructor cannot finish.
        if state == INITIALIZED {
            unsafe { (*node).callback_state.store(FINALIZING, Ordering::Release); }
            for &address in unsafe { (*node).finalizers() } {
                let callback: unsafe extern "C" fn() = unsafe { core::mem::transmute(address) };
                unsafe { callback(); }
            }
            unsafe { (*node).callback_state.store(FINALIZED, Ordering::Release); wake_callback_waiters(node); }
        }
        node = next;
    }
    // Musl __libc_exit_fini retains init_fini_lock until the process exits.
    // A concurrent fork must not slip through after the last callback returns.
    core::mem::forget(callbacks);
}

/// Acquire musl's graph -> init/fini lock order before libc's internal fork
/// owners. No callback runs under the graph lock. A successful positive TID
/// is the private transaction token; exactly one completion must follow.
unsafe extern "C" fn runtime_fork_prepare(callback_lock: i32) -> i32 {
    let guard = RuntimeGuard::acquire();
    let thread_pointer = unsafe { read_thread_pointer() } as *mut u8;
    if !unsafe { x86_64_initial_worker_tls::contains_thread(&guard, thread_pointer) } { return -1; }
    let callbacks = (callback_lock != 0).then(CallbackGuard::acquire);
    let tid = unsafe { syscall1(186, 0) } as i32;
    if tid <= 0 { return -1; }
    core::mem::forget(callbacks);
    core::mem::forget(guard);
    tid
}

/// Complete the exact lock pair retained by runtime_fork_prepare. Child repair
/// changes only copied process ownership: immutable graph/TLS provenance and
/// every surviving FS-relative field remain untouched.
unsafe extern "C" fn runtime_fork_complete(parent_tid: i32, child: i32, callback_lock: i32) {
    if child != 0 {
        let tid = unsafe { syscall1(186, 0) } as i32;
        let thread_pointer = unsafe { read_thread_pointer() } as *mut u8;
        let registry = unsafe { &mut *REGISTRY.0.get() };
        let mut node = registry.head;
        while !node.is_null() {
            let visitor = unsafe { (*node).callback_state.load(Ordering::Acquire) };
            if visitor > 0 {
                unsafe { (*node).callback_state.store(
                    if visitor == parent_tid { tid } else { CONSTRUCTOR_ABANDONED },
                    Ordering::Release,
                ); }
            }
            node = unsafe { (*node).next };
        }
        unsafe { x86_64_initial_worker_tls::adopt_after_fork(thread_pointer); }
    }
    unsafe {
        if callback_lock != 0 { CallbackGuard::complete_fork(); }
        RuntimeGuard::complete_fork();
    }
}

const ERROR_NOLOAD: i32 = 10004;
const ERROR_HANDLE: i32 = 10006;
const ERROR_SYMBOL: i32 = 10007;
const ENOMEM: i32 = 12;
const EINVAL: i32 = 22;

/// Private dlopen failure record shared only with the installed libc bridge.
/// The loader classifies the first failure in musl's dlopen order and copies
/// up to three NUL-terminated names before rollback unmaps their storage;
/// libc owns the pinned-musl `dlerror` text for each kind. `number` is a
/// Linux errno, or the relocation type for `DIAGNOSTIC_RELOCATION_TYPE`.
#[repr(C)]
struct RuntimeDiagnostic { kind: i32, number: i32, text: [u8; DIAGNOSTIC_TEXT] }
const DIAGNOSTIC_TEXT: usize = 1024;
const _: () = assert!(core::mem::size_of::<RuntimeDiagnostic>() == 1032);
/// `Error loading shared library <dlopen name>: %m`
const DIAGNOSTIC_LOAD: i32 = 1;
/// `Error loading shared library <needed>: %m (needed by <requester>)`
const DIAGNOSTIC_NEEDED: i32 = 2;
/// `Library <dlopen name> is not already loaded`
const DIAGNOSTIC_NOT_LOADED: i32 = 3;
/// `Cannot dlopen while program is exiting.`
const DIAGNOSTIC_EXITING: i32 = 4;
/// `Error relocating <object>: <symbol>: symbol not found`
const DIAGNOSTIC_SYMBOL: i32 = 5;
/// `Error relocating <object>: <symbol>: initial-exec TLS resolves to dynamic definition in <definer>`
const DIAGNOSTIC_INITIAL_EXEC: i32 = 6;
/// `Error relocating <object>: unsupported relocation type <number>`
const DIAGNOSTIC_RELOCATION_TYPE: i32 = 7;
/// `Error relocating <object>: RELRO protection failed: %m`
const DIAGNOSTIC_RELRO: i32 = 8;
/// `State of <object> is inconsistent due to multithreaded fork\n`
const DIAGNOSTIC_FORK: i32 = 9;

/// Record one failure. Every part keeps its terminator; a long earlier part
/// is truncated rather than displacing later terminators.
fn report(output: &mut RuntimeDiagnostic, kind: i32, number: i32, parts: &[&[u8]]) {
    output.kind = kind;
    output.number = number;
    let mut used = 0;
    for (index, part) in parts.iter().enumerate() {
        let room = DIAGNOSTIC_TEXT - used - (parts.len() - index);
        let length = part.len().min(room);
        output.text[used..used + length].copy_from_slice(&part[..length]);
        used += length;
        output.text[used] = 0;
        used += 1;
    }
}

unsafe fn node_name(node: *mut RuntimeObject) -> &'static [u8] {
    unsafe { (*node).name.bytes() }
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
    let (fd, path) = unsafe { open_runtime_file(parent, name) }?;
    let identity = unsafe { file_identity_from_fd(fd) };
    let Some(identity) = identity else {
        // Report fstat's errno as musl load_library does; a zero identity
        // has no musl analogue and is rejected as a non-loadable image.
        let mut stat = [0u8; X86_64_STAT_BYTE_LEN];
        let status = unsafe { syscall2(SYS_FSTAT, fd, stat.as_mut_ptr() as i64) };
        unsafe { syscall1(SYS_CLOSE, fd); }
        return Err(if is_linux_error(status) { (-status) as i32 } else { ENOEXEC });
    };
    let existing = unsafe { find_identity(registry, new, identity) };
    if !existing.is_null() {
        unsafe { syscall1(SYS_CLOSE, fd); }
        if short_name { unsafe { (*existing).short_name = true; } }
        return Ok(existing);
    }
    if no_load { unsafe { syscall1(SYS_CLOSE, fd); } return Err(ERROR_NOLOAD); }
    let mapped = unsafe { map_elf_reporting_error(fd, false, true, ObjectRole::Library) };
    unsafe { syscall1(SYS_CLOSE, fd); }
    let mut object = mapped?;
    object.search_name = path.view();
    object.search_short_name = short_name;
    let index = match registry.count.checked_add(new.count).and_then(|index| index.checked_add(1)).map(|next| next - 1) {
        Some(index) => index,
        None => { unsafe { syscall2(SYS_MUNMAP, object.map_span_start as i64, object.map_span_byte_len as i64); } return Err(ENOMEM); }
    };
    if object.tls_memsz != 0 {
        let Some(id) = tls_count.checked_add(1) else {
            unsafe { syscall2(SYS_MUNMAP, object.map_span_start as i64, object.map_span_byte_len as i64); }
            return Err(ENOMEM);
        };
        object.tls_module_id = id;
        object.tls_offset_below_tp = 0;
        *tls_count = id;
    }
    let node = unsafe { RuntimeObject::allocate(ObjectStorage::Runtime(object), identity, index, Some(path), short_name) };
    let Some(node) = node else {
        unsafe { syscall2(SYS_MUNMAP, object.map_span_start as i64, object.map_span_byte_len as i64); }
        return Err(ENOMEM);
    };
    unsafe { (*node).needed_by = parent; }
    if unsafe { new.append(node) }.is_none() {
        drop(UnpublishedObjects { head: node, tail: node, count: 1 });
        return Err(ENOMEM);
    }
    Ok(node)
}

unsafe fn preflight_runtime_callbacks(node: *mut RuntimeObject) -> Option<()> {
    let object = *unsafe { (*node).object() }?;
    let init_count = object.init_count.checked_add(usize::from(object.general_init != 0))?;
    let fini_count = object.general_fini_count.checked_add(usize::from(object.general_fini != 0))?;
    let length = init_count.checked_add(fini_count)?;
    if length == 0 { return unsafe { (*node).adopt_callbacks(None, 0) }; }
    let mut callbacks = LoaderBuffer::new(length, 0usize)?;
    {
        let (init, fini) = callbacks.as_mut_slice().split_at_mut(init_count);
        let mut next = 0;
        if object.general_init != 0 { init[0] = object.general_init; next = 1; }
        for index in 0..object.init_count { init[next + index] = unsafe { *object.init_array.add(index) }; }
        // ELF fini arrays execute backwards, followed by legacy DT_FINI.
        for (slot, index) in (0..object.general_fini_count).rev().enumerate() {
            fini[slot] = unsafe { *object.general_fini_array.add(index) };
        }
        if object.general_fini != 0 { fini[object.general_fini_count] = object.general_fini; }
    }
    for &address in callbacks.as_slice() {
        let offset = (address as u64).checked_sub(object.base)?;
        if address == 0 || !unsafe { virtual_range_in_executable_load(object.phdr, object.phnum, offset, 1) } { return None; }
    }
    unsafe { (*node).adopt_callbacks(Some(callbacks), init_count) }
}

/// Admit one dlopen request. On failure `diagnostic` names the first failure
/// musl's dlopen would report, then the unpublished suffix is rolled back.
unsafe fn open_transaction(guard: &RuntimeGuard, filename: &[u8], flags: i32, diagnostic: &mut RuntimeDiagnostic)
    -> Result<(*mut RuntimeObject, ObjectSnapshot, ObjectOrder), ()>
{
    let registry = unsafe { &mut *REGISTRY.0.get() };
    let load_failure = |diagnostic: &mut RuntimeDiagnostic, errno: i32| report(diagnostic, DIAGNOSTIC_LOAD, errno, &[]);
    if registry.head.is_null() { load_failure(diagnostic, EINVAL); return Err(()); }
    if registry.shutting_down { report(diagnostic, DIAGNOSTIC_EXITING, 0, &[]); return Err(()); }
    // Musl dlopen interprets only RTLD_LAZY, RTLD_NOLOAD and RTLD_GLOBAL. A
    // mode without RTLD_LAZY binds now; RTLD_NODELETE and unknown bits have no
    // effect because successful objects are never unloaded.
    let lazy = flags & 1 != 0;
    let no_load = flags & 4 != 0;
    let mut new = UnpublishedObjects::new();
    let mut tls_count = registry.tls_count;
    let root = match unsafe { load_one(registry, &mut new, registry.head, filename, no_load, &mut tls_count) } {
        Ok(root) => root,
        // Musl selects the NOLOAD text for every root failure in that mode.
        Err(_) if no_load => { report(diagnostic, DIAGNOSTIC_NOT_LOADED, 0, &[]); return Err(()); }
        Err(errno) => { load_failure(diagnostic, errno); return Err(()); }
    };
    let mut node = new.head;
    while !node.is_null() {
        let Some(object) = (unsafe { (*node).object() }).copied() else { load_failure(diagnostic, ENOEXEC); return Err(()); };
        if unsafe { (*node).needed.reserve(object.needed_count) }.is_none() { load_failure(diagnostic, ENOMEM); return Err(()); }
        for index in 0..object.needed_count {
            let Some(offset) = (unsafe { needed_name_offset(&object, index) }) else {
                load_failure(diagnostic, ENOEXEC);
                return Err(());
            };
            let name = unsafe { object.strtab.add(offset) };
            let Some(length) = object.strsz.checked_sub(offset).and_then(|limit| unsafe { bounded_nul(name, limit) }) else {
                load_failure(diagnostic, ENOEXEC);
                return Err(());
            };
            let name = unsafe { core::slice::from_raw_parts(name, length) };
            let child = match unsafe { load_one(registry, &mut new, node, name, false, &mut tls_count) } {
                Ok(child) => child,
                Err(errno) => {
                    report(diagnostic, DIAGNOSTIC_NEEDED, errno, &[name, unsafe { node_name(node) }]);
                    return Err(());
                }
            };
            // Reserved above for exactly this object's DT_NEEDED count.
            if unsafe { (*node).needed.push(child) }.is_none() { load_failure(diagnostic, ENOMEM); return Err(()); }
        }
        node = unsafe { (*node).next };
    }
    let memory = |diagnostic: &mut RuntimeDiagnostic| load_failure(diagnostic, ENOMEM);
    let Some(snapshot) = (unsafe { ObjectSnapshot::collect(registry, &new) }) else { memory(diagnostic); return Err(()); };
    let Some(scope) = (unsafe { breadth_first_scope(&snapshot, registry, root, true) }) else { memory(diagnostic); return Err(()); };
    let Some(dependencies) = (unsafe { breadth_first_scope(&snapshot, registry, root, false) }) else { memory(diagnostic); return Err(()); };
    let Some(constructors) = (unsafe { constructor_order(&snapshot, root) }) else { memory(diagnostic); return Err(()); };
    if let Some(&abandoned) = constructors.as_slice().iter().find(|&&index| unsafe {
        (*snapshot.nodes.as_slice()[index]).callback_state.load(Ordering::Acquire) == CONSTRUCTOR_ABANDONED
    }) {
        report(diagnostic, DIAGNOSTIC_FORK, 0, &[unsafe { node_name(snapshot.nodes.as_slice()[abandoned]) }]);
        return Err(());
    }
    let deferred = match unsafe { deferred::relocate_new(snapshot.objects.as_slice(), scope.as_slice(), registry.count,
        registry.initial_tls_count, lazy) } {
        Some(deferred) => deferred,
        None => {
            unsafe { report_relocation_failure(diagnostic, &snapshot, scope.as_slice(), registry.count,
                registry.initial_tls_count, lazy); }
            return Err(());
        }
    };
    for index in registry.count..snapshot.objects.as_slice().len() {
        let object = &snapshot.objects.as_slice()[index];
        if unsafe { preflight_runtime_callbacks(snapshot.nodes.as_slice()[index]) }.is_none()
            || unsafe { protect_segments(object) }.is_none()
        {
            load_failure(diagnostic, ENOEXEC);
            return Err(());
        }
        if unsafe { apply_relro(object) }.is_none() {
            report(diagnostic, DIAGNOSTIC_RELRO, ENOMEM, &[unsafe { node_name(snapshot.nodes.as_slice()[index]) }]);
            return Err(());
        }
    }
    let tls = if tls_count != registry.tls_count {
        let Some(tls) = (unsafe { x86_64_runtime_tls_view::PreparedAllThreads::prepare(guard, snapshot.objects.as_slice()) }) else {
            memory(diagnostic);
            return Err(());
        };
        Some(tls)
    } else { None };
    // Retry against the final global scope, not the temporary local dependency
    // scope used above. Promoting an already retained provider is sufficient.
    let Some(indices) = LoaderBuffer::new(scope.count, 0) else { memory(diagnostic); return Err(()); };
    let mut final_scope = ObjectOrder { indices, count: 0 };
    for &index in scope.as_slice() {
        if flags & 256 != 0 || unsafe { (*snapshot.nodes.as_slice()[index]).global } {
            final_scope.indices.as_mut_slice()[final_scope.count] = index;
            final_scope.count += 1;
        }
    }
    let Some(retry) = (unsafe { PreparedRetry::prepare(snapshot.objects.as_slice(), final_scope.as_slice(),
        registry.initial_tls_count, registry.deferred.as_ref(), &deferred) }) else { memory(diagnostic); return Err(()); };
    let Some(retry) = (unsafe { retry.make_writable(guard) }) else { memory(diagnostic); return Err(()); };
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

/// Name the relocation musl would reject first. Structural crabc rejections
/// with no musl counterpart report the image as not loadable.
unsafe fn report_relocation_failure(diagnostic: &mut RuntimeDiagnostic, snapshot: &ObjectSnapshot,
    scope: &[usize], first_new: usize, static_tls_count: usize, lazy: bool,
) {
    use x86_64_general_relocation::deferred::RelocationFailure;
    let objects = snapshot.objects.as_slice();
    let name = |owner: usize| unsafe { node_name(snapshot.nodes.as_slice()[owner]) };
    match unsafe { deferred::diagnose_new(objects, scope, first_new, static_tls_count, lazy) } {
        Some(RelocationFailure::MissingSymbol { owner, symbol }) =>
            report(diagnostic, DIAGNOSTIC_SYMBOL, 0, &[name(owner), symbol]),
        Some(RelocationFailure::InitialExecTls { owner, symbol, definer }) =>
            report(diagnostic, DIAGNOSTIC_INITIAL_EXEC, 0, &[name(owner), symbol, name(definer)]),
        Some(RelocationFailure::UnsupportedType { owner, kind }) =>
            report(diagnostic, DIAGNOSTIC_RELOCATION_TYPE, kind as i32, &[name(owner)]),
        None => report(diagnostic, DIAGNOSTIC_LOAD, ENOEXEC, &[]),
    }
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
        b"__crabc_x86_64_reset_current_tls_v1" => Some(reset_current_tls as *const () as usize as u64),
        b"__crabc_x86_64_runtime_open" => Some(runtime_open as *const () as usize as u64),
        b"__crabc_x86_64_runtime_symbol" => Some(runtime_symbol as *const () as usize as u64),
        b"__crabc_x86_64_runtime_close" => Some(runtime_close as *const () as usize as u64),
        b"__crabc_x86_64_runtime_address" => Some(runtime_address_info as *const () as usize as u64),
        b"__crabc_x86_64_runtime_fork_prepare" => Some(runtime_fork_prepare as *const () as usize as u64),
        b"__crabc_x86_64_runtime_fork_complete" => Some(runtime_fork_complete as *const () as usize as u64),
        b"__crabc_x86_64_runtime_information" => Some(runtime_information as *const () as usize as u64),
        b"__crabc_x86_64_runtime_iterate" => Some(runtime_iterate as *const () as usize as u64),
        _ => None,
    }
}

/// Private libc calls provide valid C strings, a writable diagnostic record and
/// disable deferred cancellation over loader mutation and callback execution.
/// A null result with a zero diagnostic kind cannot occur for a named file.
unsafe extern "C" fn runtime_open(filename: *const u8, flags: i32, diagnostic: *mut RuntimeDiagnostic) -> *mut c_void {
    if diagnostic.is_null() { return core::ptr::null_mut(); }
    let diagnostic = unsafe { &mut *diagnostic };
    diagnostic.kind = 0;
    if filename.is_null() {
        let _guard = RuntimeGuard::acquire();
        return unsafe { (*REGISTRY.0.get()).head.cast() };
    }
    // The caller's C string is opened as given, as musl does; only the
    // kernel limits a pathname's length.
    let Some(length) = (unsafe { bounded_nul(filename, isize::MAX as usize) }) else { return core::ptr::null_mut(); };
    let filename = unsafe { core::slice::from_raw_parts(filename, length) };
    let result = {
        let guard = RuntimeGuard::acquire();
        let _notification = super::x86_64_debugger::AddNotification::begin(&guard);
        unsafe { open_transaction(&guard, filename, flags, diagnostic) }
    };
    match result {
        Ok((root, snapshot, constructors)) => {
            for &index in constructors.as_slice() { unsafe { initialize_object(snapshot.nodes.as_slice()[index]); } }
            root.cast()
        }
        Err(()) => core::ptr::null_mut(),
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

/// Return `root`'s breadth-first dependency scope (musl's `p->deps`), built
/// on first use and retained with the published node. A committed object's
/// `needed` edges never change, so the cached order stays exact.
/// # Safety
/// The caller holds the runtime guard and `root` is a published registry node.
unsafe fn dependency_scope<'a>(registry: &RuntimeRegistry, root: *mut RuntimeObject) -> Option<&'a [*mut RuntimeObject]> {
    if unsafe { (*root).dependency_scope.is_none() } {
        let snapshot = unsafe { ObjectSnapshot::collect(registry, &UnpublishedObjects::new()) }?;
        let order = unsafe { breadth_first_scope(&snapshot, registry, root, false) }?;
        let mut scope = LoaderBuffer::new(order.count, core::ptr::null_mut())?;
        for (slot, &index) in scope.as_mut_slice().iter_mut().zip(order.as_slice()) {
            *slot = snapshot.nodes.as_slice()[index];
        }
        unsafe { (*root).dependency_scope = Some(scope); }
    }
    unsafe { (*root).dependency_scope.as_ref() }.map(LoaderBuffer::as_slice)
}

unsafe extern "C" fn runtime_symbol(handle: *mut c_void, name: *const u8, caller: usize, error: *mut i32) -> *mut c_void {
    if error.is_null() || name.is_null() { return core::ptr::null_mut(); }
    unsafe { *error = 0; }
    let Some(length) = (unsafe { bounded_nul(name, MAX_PATH) }) else { unsafe { *error = ERROR_SYMBOL; } return core::ptr::null_mut(); };
    let name = unsafe { core::slice::from_raw_parts(name, length) };
    // Musl's dlsym performs no allocation: it walks the global symbol list or
    // the handle's load-time dependency list under its loader lock. Resolve
    // over the retained records directly, and derive a handle's (immutable)
    // breadth-first dependency scope once, rather than copying a registry
    // snapshot and ordering buffers into fresh mappings on every call.
    let result = (|| -> Result<_, i32> {
        let _guard = RuntimeGuard::acquire();
        let registry = unsafe { &*REGISTRY.0.get() };
        let found = if handle.is_null() || handle.cast::<RuntimeObject>() == registry.head || handle as usize == usize::MAX {
            let mut first = registry.symbols_head;
            if handle as usize == usize::MAX {
                let mut owner = registry.head;
                let mut candidate = registry.head;
                while !candidate.is_null() {
                    let object = unsafe { (*candidate).object() }.ok_or(ERROR_HANDLE)?;
                    if let Some(offset) = (caller as u64).checked_sub(object.base) {
                        if unsafe { virtual_range_in_load(object.phdr, object.phnum, offset, 1) } { owner = candidate; break; }
                    }
                    candidate = unsafe { (*candidate).next };
                }
                // Musl starts at the caller's physical successor, then
                // traverses that object's symbol-scope links.
                first = unsafe { (*owner).next };
            }
            let scope = core::iter::successors((!first.is_null()).then_some(first), |&node| {
                let next = unsafe { (*node).symbol_next };
                (!next.is_null()).then_some(next)
            });
            unsafe { x86_64_general_relocation::find_runtime_symbol(scope.map(|node| (*node).object()), name) }
        } else {
            let root = unsafe { validated_handle(registry, handle) }.ok_or(ERROR_HANDLE)?;
            let scope = unsafe { dependency_scope(registry, root) }.ok_or(12)?;
            unsafe { x86_64_general_relocation::find_runtime_symbol(scope.iter().map(|&node| (*node).object()), name) }
        };
        found.ok_or(ERROR_SYMBOL)
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
        #[cfg(feature = "x86_64-owned-dynamic-runtime")]
        let symbol = unsafe { direct_symbol(object, index) }.unwrap_or(core::ptr::null());
        #[cfg(not(feature = "x86_64-owned-dynamic-runtime"))]
        let symbol = unsafe { object.symtab.add(index * 24) };
        if symbol.is_null() { return 0; }
        let info = unsafe { *symbol.add(4) };
        let value = unsafe { read_u64(symbol.add(8)) };
        if value == 0 || !matches!(info >> 4, 1 | 2 | x86_64_general_relocation::STB_GNU_UNIQUE)
            || !matches!(info & 15, 0 | 1 | 2 | 6) { continue; }
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
    unsafe { core::ptr::write(output, AddressInfo { name: (*node).link_map.name,
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
/// The approved unwinder also borrows FDE/LSDA/text after this function returns:
/// published nodes have relinquished their UnpublishedObjects rollback owner,
/// and runtime_close never unlinks, unmaps, or rewrites their names. Initial
/// objects borrow the permanent GeneralInitialLoaderState. The stack info is
/// callback-local; its thread-owned TLS pointer has a separate lifetime.
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
            ProgramHeaderInfo { address: object.base as usize, name: unsafe { (*node).link_map.name },
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

/// Private owned-libc timer cleanup boundary v1, source-mapped to musl
/// src/env/__reset_tls.c (1.2.6, MIT). The loader owns templates and current
/// module publication. Reset touches only calling-task ELF TLS bytes, never
/// its TCB, cancellation cache, DTV descriptors, allocation token or stack.
/// Application signals are blocked by the caller after TSD cleanup. This is
/// not a signal-handler entry point. No allocation or application call occurs.
unsafe extern "C" fn reset_current_tls() -> i32 {
    let guard = RuntimeGuard::acquire();
    let tp = unsafe { read_thread_pointer() } as *mut u8;
    if !unsafe { x86_64_initial_worker_tls::contains_thread(&guard, tp) } { return -22; }
    let registry = unsafe { &*REGISTRY.0.get() };
    let mut node = registry.head;
    // Validate every module before the first write; malformed private state
    // must not leave some images reset and others carrying callback state.
    for write in [false, true] {
        while !node.is_null() {
            let Some(object) = (unsafe { (*node).object() }) else { return -22; };
            if !unsafe { x86_64_runtime_tls_view::reset_module_image(tp, object, write) } { return -22; }
            node = unsafe { (*node).next };
        }
        node = registry.head;
    }
    0
}
