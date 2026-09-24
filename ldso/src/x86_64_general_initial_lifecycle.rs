//! Process-lifetime dependency callbacks for the general initial graph.
//!
//! Graph discovery, callback storage validation, relocation, protections and
//! RELRO finish before this plan is attached to the canonical graph owner.
//! Callback addresses are copied, so finalization never rereads ELF arrays.
//! Immutable plans and atomic execution states share that owner's lifetime;
//! no lock is held across foreign code. Legacy private roots keep the main
//! image outside this plan for their CRT-owned array walk. The installed
//! runtime puts the main object last after the dependency postorder for both
//! the owned Rust CRT and the conventional musl CRT, as musl dynlink.c's
//! main_ctor_queue does.
//!
//! This is process finalization, not dlclose: all initial mappings remain
//! resident. Recursive or repeated finalization is a no-op once claimed.
//! Finalization before all initializers return is not admitted and leaves
//! the eventual finalization claim available. Runtime loading, exit from a
//! constructor, and concurrent startup are not provided by this boundary.
//! The installed owned feature uses this immutable preflight plan but hands
//! execution to x86_64_runtime_registry before any application callback; that
//! owner composes initial and runtime-loaded callback lifecycle.

use super::*;
#[cfg(any(test, not(feature = "x86_64-owned-dynamic-runtime")))]
use super::x86_64_general_initial_loader_state::GeneralInitialLoaderState;
use super::x86_64_initial_graph_state::InitialGraphState;
use core::sync::atomic::{AtomicU8, Ordering};

const QUEUED: u8 = 0;
const INITIALIZING: u8 = 1;
const INITIALIZED: u8 = 2;
const FINALIZING: u8 = 3;
const FINALIZED: u8 = 4;
#[cfg(not(feature = "x86_64-owned-dynamic-runtime"))]
const CALLBACK_CAPACITY: usize = MAX_GENERAL_INITIAL_DEPENDENCY_INIT_ARRAY_ENTRIES + 1;

// The existing 32-byte owned CRT record carries the dependency callback; TLS
// coordinates remain in the separate, unchanged 72-byte RuntimeV1 record.
// The finalizer field also authenticates the address transported in rdx.
#[cfg(crabc_dynamic_main_thread_runtime_v1)]
static OWNED_CRT_HANDOFF: OwnedCrtHandoffV1 = OwnedCrtHandoffV1 {
    magic: OWNED_CRT_HANDOFF_MAGIC,
    version: OWNED_CRT_HANDOFF_VERSION,
    abi_size: core::mem::size_of::<OwnedCrtHandoffV1>() as u32,
    dependency_constructors: owned_dependency_constructors,
    process_fini: process_finalizer,
};

#[cfg(crabc_dynamic_main_thread_runtime_v1)]
pub(super) fn owned_crt_handoff_address() -> u64 {
    core::ptr::addr_of!(OWNED_CRT_HANDOFF) as usize as u64
}

/// Called by the owned CRT only after libc state and executable preinit.
/// The installed runtime constructs every initial dependency and then the
/// main image; legacy private roots construct dependencies only.
#[cfg(crabc_dynamic_main_thread_runtime_v1)]
unsafe extern "C" fn owned_dependency_constructors() {
    #[cfg(feature = "x86_64-owned-dynamic-runtime")]
    unsafe { super::x86_64_runtime_registry::initialize_initial(); }
    #[cfg(not(feature = "x86_64-owned-dynamic-runtime"))]
    unsafe { GeneralInitialLoaderState::retained().unwrap().lifecycle().unwrap().initialize() };
}

/// Conventional musl CRT dispatches this only after libc has acquired the
/// separate READY snapshot. Keep the exported callback at the C ABI boundary;
/// [`x86_64_runtime_registry::initialize_initial`] remains an internal Rust
/// implementation detail shared with the owned CRT adapter above.
#[cfg(feature = "x86_64-owned-dynamic-runtime")]
pub(super) unsafe extern "C" fn conventional_dependency_constructors() {
    unsafe { super::x86_64_runtime_registry::initialize_initial(); }
}

/// One mapped object's callbacks in forward execution order. Object index
/// preserves the connection to canonical map/TLS ownership without pointers
/// into the movable startup transaction. Its initializers and then its
/// finalizers occupy `first..` of the plan's [`CallbackStore`].
struct ObjectLifecycle {
    object_index: usize,
    first: usize,
    initializer_count: usize,
    finalizer_count: usize,
    state: AtomicU8,
}

impl ObjectLifecycle {
    const fn empty() -> Self {
        Self {
            object_index: 0,
            first: 0,
            initializer_count: 0,
            finalizer_count: 0,
            state: AtomicU8::new(QUEUED),
        }
    }
}

/// Copied callback addresses for a whole plan.
///
/// The installed runtime admits ELF arrays of any valid length, as pinned
/// musl does, so it sizes one loader mapping from the preflighted counts.
/// Legacy private roots keep their bounded parser shape and inline storage.
#[cfg(feature = "x86_64-owned-dynamic-runtime")]
struct CallbackStore(Option<super::x86_64_runtime_memory::LoaderBuffer<usize>>);
#[cfg(not(feature = "x86_64-owned-dynamic-runtime"))]
struct CallbackStore([usize; MAX_OBJECTS * 2 * CALLBACK_CAPACITY]);

// SAFETY: the mapping is exclusively owned by one plan and written only by
// `preflight` through `&mut self`; after that the addresses are immutable and
// shared readers only copy them, exactly like the legacy inline array.
#[cfg(feature = "x86_64-owned-dynamic-runtime")]
unsafe impl Sync for CallbackStore {}

impl CallbackStore {
    const fn empty() -> Self {
        #[cfg(feature = "x86_64-owned-dynamic-runtime")]
        { Self(None) }
        #[cfg(not(feature = "x86_64-owned-dynamic-runtime"))]
        { Self([0; MAX_OBJECTS * 2 * CALLBACK_CAPACITY]) }
    }

    fn with_len(length: usize) -> Option<Self> {
        #[cfg(feature = "x86_64-owned-dynamic-runtime")]
        {
            if length == 0 { return Some(Self(None)); }
            Some(Self(Some(super::x86_64_runtime_memory::LoaderBuffer::new(length, 0)?)))
        }
        #[cfg(not(feature = "x86_64-owned-dynamic-runtime"))]
        {
            (length <= MAX_OBJECTS * 2 * CALLBACK_CAPACITY).then(Self::empty)
        }
    }

    fn as_slice(&self) -> &[usize] {
        #[cfg(feature = "x86_64-owned-dynamic-runtime")]
        { self.0.as_ref().map_or(&[], |buffer| buffer.as_slice()) }
        #[cfg(not(feature = "x86_64-owned-dynamic-runtime"))]
        { &self.0 }
    }

    fn as_mut_slice(&mut self) -> &mut [usize] {
        #[cfg(feature = "x86_64-owned-dynamic-runtime")]
        { self.0.as_mut().map_or(&mut [], |buffer| buffer.as_mut_slice()) }
        #[cfg(not(feature = "x86_64-owned-dynamic-runtime"))]
        { &mut self.0 }
    }
}

/// The sole execution owner for every selected initial process lifecycle.
/// Atomic claims permit recursive finalizer calls without borrowing mutable
/// graph state or redispatching a callback already on the stack.
pub(super) struct GeneralInitialLifecycle {
    objects: [ObjectLifecycle; MAX_OBJECTS],
    callbacks: CallbackStore,
    count: usize,
    state: AtomicU8,
}

impl GeneralInitialLifecycle {
    // The installed runtime copies this already checked immutable plan into
    // its stable initial-object nodes before FS publication. Those nodes own
    // all actual callback claims thereafter, including later dlopen reentry.
    // This plan's original execution state remains for legacy private roots;
    // the two cfg-disjoint dispatchers never execute the same callback twice.
    #[cfg(feature = "x86_64-owned-dynamic-runtime")]
    pub(super) fn callback_plan(&self, index: usize) -> Option<(&[usize], &[usize])> {
        let object = self.objects[..self.count].iter().find(|object| object.object_index == index)?;
        Some((self.initializers(object), self.finalizers(object)))
    }

    fn initializers(&self, object: &ObjectLifecycle) -> &[usize] {
        &self.callbacks.as_slice()[object.first..object.first + object.initializer_count]
    }

    fn finalizers(&self, object: &ObjectLifecycle) -> &[usize] {
        let start = object.first + object.initializer_count;
        &self.callbacks.as_slice()[start..start + object.finalizer_count]
    }
    /// # Safety
    /// Every object must remain mapped and fully relocated with protections
    /// and RELRO sealed. Its array storage must have been parser-validated.
    pub(super) unsafe fn preflight(
        graph: &InitialGraphState,
        objects: &[Object; MAX_OBJECTS],
    ) -> Option<Self> {
        let order = graph.dependency_first_plan().ok()?;
        // The installed runtime owns main DT_INIT/DT_INIT_ARRAY/DT_FINI_ARRAY
        // and DT_FINI in both CRT modes; the owned CRT runs only preinit.
        #[cfg(feature = "x86_64-owned-dynamic-runtime")]
        let main = Some(0);
        #[cfg(not(feature = "x86_64-owned-dynamic-runtime"))]
        let main = None;
        let planned = || order.indices().iter().map(|&index| (index, false)).chain(main.map(|index| (index, true)));
        // Validate every callback and size the copy before writing any of it.
        let mut length = 0usize;
        for (index, is_main) in planned() {
            let (initializers, finalizers) = unsafe { object_callback_counts(objects.get(index)?, index, is_main) }?;
            length = length.checked_add(initializers)?.checked_add(finalizers)?;
        }
        let mut plan = Self {
            objects: [const { ObjectLifecycle::empty() }; MAX_OBJECTS],
            callbacks: CallbackStore::with_len(length)?,
            count: 0,
            state: AtomicU8::new(QUEUED),
        };
        let mut first = 0;
        for (index, _) in planned() {
            first = unsafe { append_object_lifecycle(&mut plan, objects.get(index)?, index, first) }?;
        }
        Some(plan)
    }

    /// # Safety
    /// The plan must be retained with its mapped graph, and startup must
    /// remain single-threaded until this method returns. Callback code must
    /// obey its C ABI and may not unload the retained initial objects.
    pub(super) unsafe fn initialize(&self) {
        self.initialize_with(|address| unsafe { invoke(address) });
    }

    fn initialize_with(&self, mut invoke: impl FnMut(usize)) {
        if self.state.compare_exchange(QUEUED, INITIALIZING, Ordering::AcqRel, Ordering::Acquire).is_err() {
            return;
        }
        for object in &self.objects[..self.count] {
            object.state.store(INITIALIZING, Ordering::Release);
            for &address in self.initializers(object) {
                invoke(address);
            }
            object.state.store(INITIALIZED, Ordering::Release);
        }
        self.state.store(INITIALIZED, Ordering::Release);
    }

    fn finalize_with(&self, mut invoke: impl FnMut(usize)) {
        if self.state.compare_exchange(INITIALIZED, FINALIZING, Ordering::AcqRel, Ordering::Acquire).is_err() {
            return;
        }
        for object in self.objects[..self.count].iter().rev() {
            // The global initialization publication makes all object states
            // visible. Claim before calling foreign code: recursive process
            // finalization can never reenter this object's destructor list.
            if object.state.compare_exchange(INITIALIZED, FINALIZING, Ordering::AcqRel, Ordering::Acquire).is_err() {
                continue;
            }
            for &address in self.finalizers(object) {
                invoke(address);
            }
            object.state.store(FINALIZED, Ordering::Release);
        }
        self.state.store(FINALIZED, Ordering::Release);
    }
}

/// Validate one object's lifecycle shape and every callback address, and
/// return its initializer and finalizer counts. `main` is explicit so a
/// conventional CRT cannot accidentally be selected merely by dynamic tags.
unsafe fn object_callback_counts(object: &Object, index: usize, main: bool) -> Option<(usize, usize)> {
    if (!main && (object.role == ObjectRole::Main || index == 0))
        || (main && (object.role != ObjectRole::Main || index != 0))
        || (object.init_count != 0 && object.init_array.is_null())
        || (object.general_fini_count != 0 && object.general_fini_array.is_null())
    {
        return None;
    }
    #[cfg(not(feature = "x86_64-owned-dynamic-runtime"))]
    if object.init_count > MAX_GENERAL_INITIAL_DEPENDENCY_INIT_ARRAY_ENTRIES
        || object.general_fini_count > MAX_GENERAL_INITIAL_DEPENDENCY_INIT_ARRAY_ENTRIES
    {
        return None;
    }
    let mut initializers = object.init_count;
    if object.general_init != 0 {
        unsafe { checked_callback(object, object.general_init)? };
        initializers = initializers.checked_add(1)?;
    }
    for offset in 0..object.init_count {
        unsafe { checked_callback(object, *object.init_array.add(offset))? };
    }
    for offset in 0..object.general_fini_count {
        unsafe { checked_callback(object, *object.general_fini_array.add(offset))? };
    }
    let mut finalizers = object.general_fini_count;
    if object.general_fini != 0 {
        unsafe { checked_callback(object, object.general_fini)? };
        finalizers = finalizers.checked_add(1)?;
    }
    Some((initializers, finalizers))
}

/// Copy one object lifecycle already validated by [`object_callback_counts`]
/// into `first..` of the plan store and return the next free position.
unsafe fn append_object_lifecycle(
    plan: &mut GeneralInitialLifecycle,
    object: &Object,
    index: usize,
    first: usize,
) -> Option<usize> {
    let store = plan.callbacks.as_mut_slice();
    let mut next = first;
    let mut push = |next: &mut usize, address: usize| -> Option<()> {
        *store.get_mut(*next)? = address;
        *next += 1;
        Some(())
    };
    if object.general_init != 0 {
        push(&mut next, object.general_init)?;
    }
    for offset in 0..object.init_count {
        push(&mut next, unsafe { *object.init_array.add(offset) })?;
    }
    let initializer_count = next - first;
    // ELF fini arrays execute backwards, followed by legacy DT_FINI.
    for offset in (0..object.general_fini_count).rev() {
        push(&mut next, unsafe { *object.general_fini_array.add(offset) })?;
    }
    if object.general_fini != 0 {
        push(&mut next, object.general_fini)?;
    }
    let lifecycle = plan.objects.get_mut(plan.count)?;
    *lifecycle = ObjectLifecycle {
        object_index: index,
        first,
        initializer_count,
        finalizer_count: next - first - initializer_count,
        state: AtomicU8::new(QUEUED),
    };
    plan.count += 1;
    Some(next)
}

unsafe fn checked_callback(object: &Object, address: usize) -> Option<()> {
    let virtual_address = address.checked_sub(object.base as usize)? as u64;
    if address == 0 || !unsafe {
        virtual_range_in_executable_load(object.phdr, object.phnum, virtual_address, 1)
    } {
        return None;
    }
    Some(())
}

unsafe fn invoke(address: usize) {
    let callback: unsafe extern "C" fn() = unsafe { core::mem::transmute(address) };
    unsafe { callback() };
}

/// Conventional x86-64 rtld_fini address, passed in rdx at application entry.
/// It is private, does not unmap initial objects, and claims exactly once
/// before foreign callbacks. The CRT/libc must call it after main finalizers.
///
/// # Safety
/// The CRT/libc must preserve the initial mappings and call this address
/// using the C ABI only after initializers return. Foreign callbacks must
/// not unload the retained objects. Repeated and recursive calls are allowed.
pub(super) unsafe extern "C" fn process_finalizer() {
    #[cfg(feature = "x86_64-owned-dynamic-runtime")]
    unsafe { super::x86_64_runtime_registry::finalize_process(); }
    #[cfg(not(feature = "x86_64-owned-dynamic-runtime"))]
    if let Some(lifecycle) = GeneralInitialLoaderState::retained().and_then(|state| state.lifecycle()) {
        lifecycle.finalize_with(|address| unsafe { invoke(address) });
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use self::std::vec::Vec;

    fn plan() -> GeneralInitialLifecycle {
        let mut plan = GeneralInitialLifecycle {
            objects: [const { ObjectLifecycle::empty() }; MAX_OBJECTS],
            callbacks: CallbackStore::with_len(6).unwrap(),
            count: 3,
            state: AtomicU8::new(QUEUED),
        };
        for index in 0..3 {
            plan.objects[index].object_index = index + 1;
            plan.objects[index].first = index * 2;
            plan.objects[index].initializer_count = 1;
            plan.objects[index].finalizer_count = 1;
            plan.callbacks.as_mut_slice()[index * 2] = index + 10;
            plan.callbacks.as_mut_slice()[index * 2 + 1] = index + 20;
        }
        plan
    }

    #[test]
    fn completed_dependencies_finalize_once_in_reverse_initialization_order() {
        let plan = plan();
        let mut observed = Vec::new();
        plan.finalize_with(|_| panic!("uninitialized object finalized"));
        plan.initialize_with(|address| {
            observed.push(address);
            plan.initialize_with(|_| panic!("recursive initialization"));
            plan.finalize_with(|_| panic!("finalization during initialization"));
        });
        plan.initialize_with(|_| panic!("repeated initialization"));
        plan.finalize_with(|address| {
            observed.push(address);
            plan.finalize_with(|_| panic!("recursive finalization"));
        });
        plan.finalize_with(|_| panic!("repeated finalization"));
        assert_eq!(observed, [10, 11, 12, 22, 21, 20]);
        assert!(plan.objects[..3].iter().all(|object| object.state.load(Ordering::Acquire) == FINALIZED));
    }

    #[test]
    fn concurrent_finalization_has_one_callback_owner() {
        let plan = plan();
        plan.initialize_with(|_| {});
        let calls = core::sync::atomic::AtomicUsize::new(0);
        self::std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| plan.finalize_with(|_| { calls.fetch_add(1, Ordering::Relaxed); }));
            }
        });
        assert_eq!(calls.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn preflight_copies_callback_addresses_and_attaches_to_the_canonical_owner() {
        use super::super::x86_64_initial_graph_state::{ObjectAdmission, ObjectIdentity};
        // A synthetic executable PT_LOAD lets the test inspect addresses as
        // data without executing arbitrary memory or replacing process TLS.
        let phdr = [1u64 | (5u64 << 32), 0, 0x1000, 0, 0x1000, 0x1000, 0x1000];
        let mut init = [0x1010usize, 0x1020];
        let mut fini = [0x1030usize, 0x1040];
        // Legacy private roots keep main callbacks CRT-owned and outside this
        // plan; the invalid main fini count proves they are never copied.
        #[cfg(not(feature = "x86_64-owned-dynamic-runtime"))]
        let main = Object { general_fini_count: usize::MAX, ..EMPTY_OBJECT };
        // The installed runtime queues the owned-CRT main last, exactly like
        // the conventional CRT, so it is finalized before its dependencies.
        #[cfg(feature = "x86_64-owned-dynamic-runtime")]
        let mut main_init = [0x1060usize];
        #[cfg(feature = "x86_64-owned-dynamic-runtime")]
        let mut main_fini = [0x1070usize];
        #[cfg(feature = "x86_64-owned-dynamic-runtime")]
        let main = Object {
            phdr: phdr.as_ptr().cast(),
            phnum: 1,
            init_array: main_init.as_ptr(),
            init_count: main_init.len(),
            general_init: 0x1002,
            general_fini_array: main_fini.as_ptr(),
            general_fini_count: main_fini.len(),
            general_fini: 0x1080,
            main_crt_mode: MainCrtMode::Owned,
            ..EMPTY_OBJECT
        };
        let mut state = GeneralInitialLoaderState::new(ObjectIdentity { device: 1, inode: 1 }, main);
        {
            let (graph, objects) = state.discovery_mut().unwrap();
            let ObjectAdmission::New { index } = graph.admit_mapped(
                ObjectIdentity { device: 1, inode: 2 },
            ).unwrap() else { panic!("new object required") };
            graph.attach_needed(0, index).unwrap();
            objects[index] = Object {
                role: ObjectRole::Library,
                phdr: phdr.as_ptr().cast(),
                phnum: 1,
                init_array: init.as_ptr(),
                init_count: init.len(),
                general_init: 0x1001,
                general_fini_array: fini.as_ptr(),
                general_fini_count: fini.len(),
                general_fini: 0x1050,
                ..EMPTY_OBJECT
            };
            graph.finish_discovery(index).unwrap();
        }
        state.finish_discovery().unwrap();
        assert_eq!(state.prepare(), Err(super::super::x86_64_general_initial_loader_state::GeneralInitialLoaderStateError::LifecycleIncomplete));
        let plan = unsafe { GeneralInitialLifecycle::preflight(
            state.graph_during_transaction().unwrap(),
            state.objects_during_transaction().unwrap(),
        ) }.unwrap();
        assert_eq!(plan.objects[0].object_index, 1);
        #[cfg(not(feature = "x86_64-owned-dynamic-runtime"))]
        assert_eq!(plan.count, 1);
        #[cfg(feature = "x86_64-owned-dynamic-runtime")]
        {
            assert_eq!(plan.count, 2);
            assert_eq!(plan.objects[1].object_index, 0);
            main_init.fill(0);
            main_fini.fill(0);
        }
        // Neither init nor fini dispatch may read the ELF arrays again.
        init.fill(0);
        fini.fill(0);
        assert_eq!(init, [0, 0]);
        assert_eq!(fini, [0, 0]);
        state.attach_lifecycle(plan).unwrap();
        assert!(state.discovery_mut().is_err()); // the copied plan seals mutation
        assert!(state.attach_lifecycle(self::plan()).is_err());
        assert!(state.lifecycle().is_none()); // private until graph publication
        let _guard = GeneralInitialLoaderState::test_publication_guard();
        unsafe { GeneralInitialLoaderState::reset_publication_for_test() };
        state.prepare().unwrap();
        state.reserve_publication().unwrap();
        unsafe { state.commit() };
        let retained = GeneralInitialLoaderState::retained().unwrap();
        assert_eq!(retained.ready_graph().unwrap().object_count(), 2);
        let plan = retained.lifecycle().unwrap();
        let mut observed = Vec::new();
        plan.initialize_with(|address| observed.push(address));
        plan.finalize_with(|address| observed.push(address));
        #[cfg(not(feature = "x86_64-owned-dynamic-runtime"))]
        assert_eq!(observed, [0x1001, 0x1010, 0x1020, 0x1040, 0x1030, 0x1050]);
        #[cfg(feature = "x86_64-owned-dynamic-runtime")]
        assert_eq!(observed, [
            0x1001, 0x1010, 0x1020, 0x1002, 0x1060,
            0x1070, 0x1080, 0x1040, 0x1030, 0x1050,
        ]);
        assert_eq!(retained.ready_objects().unwrap()[0].map_provenance, ObjectMapProvenance::KernelMain);
        unsafe { GeneralInitialLoaderState::reset_publication_for_test() };
    }
}
