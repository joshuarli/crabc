//! Process-lifetime dependency callbacks for the general initial graph.
//!
//! Graph discovery, callback storage validation, relocation, protections and
//! RELRO finish before this plan is attached to the canonical graph owner.
//! Callback addresses are copied, so finalization never rereads ELF arrays.
//! Immutable plans and atomic execution states share that owner's lifetime;
//! no lock is held across foreign code. The main image remains CRT-owned.
//!
//! This is process finalization, not dlclose: all initial mappings remain
//! resident. Recursive or repeated finalization is a no-op once claimed.
//! Finalization before all initializers return is not admitted and leaves
//! the eventual finalization claim available. Runtime loading, exit from a
//! constructor, and concurrent startup are not provided by this boundary.

use super::*;
use super::x86_64_general_initial_loader_state::GeneralInitialLoaderState;
use super::x86_64_initial_graph_state::InitialGraphState;
use core::sync::atomic::{AtomicU8, Ordering};

const QUEUED: u8 = 0;
const INITIALIZING: u8 = 1;
const INITIALIZED: u8 = 2;
const FINALIZING: u8 = 3;
const FINALIZED: u8 = 4;
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
#[cfg(crabc_dynamic_main_thread_runtime_v1)]
unsafe extern "C" fn owned_dependency_constructors() {
    unsafe { GeneralInitialLoaderState::retained().unwrap().lifecycle().unwrap().initialize() };
}

/// One mapped object's callbacks in forward execution order. Object index
/// preserves the connection to canonical map/TLS ownership without pointers
/// into the movable startup transaction.
struct ObjectLifecycle {
    object_index: usize,
    initializers: [usize; CALLBACK_CAPACITY],
    initializer_count: usize,
    finalizers: [usize; CALLBACK_CAPACITY],
    finalizer_count: usize,
    state: AtomicU8,
}

impl ObjectLifecycle {
    const fn empty() -> Self {
        Self {
            object_index: 0,
            initializers: [0; CALLBACK_CAPACITY],
            initializer_count: 0,
            finalizers: [0; CALLBACK_CAPACITY],
            finalizer_count: 0,
            state: AtomicU8::new(QUEUED),
        }
    }
}

/// The sole execution owner for every dependency's initial process lifecycle.
/// Atomic claims permit recursive finalizer calls without borrowing mutable
/// graph state or redispatching a callback already on the stack.
pub(super) struct GeneralInitialLifecycle {
    objects: [ObjectLifecycle; MAX_OBJECTS],
    count: usize,
    state: AtomicU8,
}

impl GeneralInitialLifecycle {
    /// # Safety
    /// Every object must remain mapped and fully relocated with protections
    /// and RELRO sealed. Its array storage must have been parser-validated.
    pub(super) unsafe fn preflight(
        graph: &InitialGraphState,
        objects: &[Object; MAX_OBJECTS],
    ) -> Option<Self> {
        let order = graph.dependency_first_plan().ok()?;
        let mut plan = Self {
            objects: [const { ObjectLifecycle::empty() }; MAX_OBJECTS],
            count: 0,
            state: AtomicU8::new(QUEUED),
        };
        for &index in order.indices() {
            let object = objects.get(index)?;
            if !object.mapped || index == 0
                || object.init_count > MAX_GENERAL_INITIAL_DEPENDENCY_INIT_ARRAY_ENTRIES
                || object.general_fini_count > MAX_GENERAL_INITIAL_DEPENDENCY_INIT_ARRAY_ENTRIES
                || (object.init_count != 0 && object.init_array.is_null())
                || (object.general_fini_count != 0 && object.general_fini_array.is_null())
            {
                return None;
            }
            let lifecycle = plan.objects.get_mut(plan.count)?;
            lifecycle.object_index = index;
            if object.general_init != 0 {
                unsafe { checked_callback(object, object.general_init)? };
                lifecycle.initializers[0] = object.general_init;
                lifecycle.initializer_count = 1;
            }
            for offset in 0..object.init_count {
                let address = unsafe { *object.init_array.add(offset) };
                unsafe { checked_callback(object, address)? };
                lifecycle.initializers[lifecycle.initializer_count] = address;
                lifecycle.initializer_count += 1;
            }
            // ELF fini arrays execute backwards, followed by legacy DT_FINI.
            for offset in (0..object.general_fini_count).rev() {
                let address = unsafe { *object.general_fini_array.add(offset) };
                unsafe { checked_callback(object, address)? };
                lifecycle.finalizers[lifecycle.finalizer_count] = address;
                lifecycle.finalizer_count += 1;
            }
            if object.general_fini != 0 {
                unsafe { checked_callback(object, object.general_fini)? };
                lifecycle.finalizers[lifecycle.finalizer_count] = object.general_fini;
                lifecycle.finalizer_count += 1;
            }
            plan.count += 1;
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
            for &address in &object.initializers[..object.initializer_count] {
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
            for &address in &object.finalizers[..object.finalizer_count] {
                invoke(address);
            }
            object.state.store(FINALIZED, Ordering::Release);
        }
        self.state.store(FINALIZED, Ordering::Release);
    }
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
            count: 3,
            state: AtomicU8::new(QUEUED),
        };
        for (index, object) in plan.objects[..3].iter_mut().enumerate() {
            object.object_index = index + 1;
            object.initializers[0] = index + 10;
            object.initializer_count = 1;
            object.finalizers[0] = index + 20;
            object.finalizer_count = 1;
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
        let mut state = GeneralInitialLoaderState::new(
            ObjectIdentity { device: 1, inode: 1 },
            // Main callbacks are CRT-owned and never examined by this plan.
            Object { general_fini_count: usize::MAX, ..EMPTY_OBJECT },
        );
        {
            let (graph, objects) = state.discovery_mut().unwrap();
            let ObjectAdmission::New { index } = graph.admit_mapped(
                ObjectIdentity { device: 1, inode: 2 },
            ).unwrap() else { panic!("new object required") };
            graph.attach_needed(0, index).unwrap();
            objects[index] = Object {
                mapped: true,
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
        assert_eq!(observed, [0x1001, 0x1010, 0x1020, 0x1040, 0x1030, 0x1050]);
        assert_eq!(retained.ready_objects().unwrap()[0].map_provenance, ObjectMapProvenance::KernelMain);
        unsafe { GeneralInitialLoaderState::reset_publication_for_test() };
    }
}
