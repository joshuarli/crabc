//! General x86-64 initial `DT_NEEDED` graph transaction.
//!
//! This private package deliberately uses the checked ELF/parser/mapper and
//! mapping primitives in its parent module, but owns no fixed
//! object shape. `x86_64_initial_graph_state.rs` defines identity/topology;
//! `x86_64_general_initial_loader_state.rs` is the one durable graph/object/
//! map-provenance owner for both roots. The older fixed graph remains a
//! separate regression root. The default general root remains non-TLS. Its
//! separate `crabc_general_initial_tls_materialization_v1` sibling attaches
//! one initial Variant-II TLS population to that same owner. Its ordinary cfg
//! is not a RuntimeV1 producer; the separately cfg-selected general RuntimeV1
//! handoff excludes runtime DSO mapping. The
//! optional general lifecycle feature retains dependency initialization and
//! process-finalization plans in the same owner and passes x86 rtld_fini;
//! its dynamic-main-thread composition integrates owned executable lifecycle.
//! `x86_64_general_relocation.rs` owns whole-graph relocation preflight,
//! breadth-first symbol scope, deferred COPY, and retained initial-TLS offsets.

use super::*;
use super::x86_64_general_initial_loader_state::{
    GeneralInitialLoaderState, GeneralInitialPreparationStage,
};
use super::x86_64_initial_graph_state::{InitialGraphState, ObjectAdmission, ObjectIdentity};
#[cfg(crabc_general_initial_tls_materialization_v1)]
use super::x86_64_general_initial_tls_state::GeneralInitialTlsState;

/// Starts the topology-independent initial dependency transaction.
///
/// # Safety
///
/// `_start` must supply the untouched Linux initial stack and this
/// interpreter's already self-relocated base. A successful initial graph is
/// moved into the private process-lifetime owner before any constructor runs.
pub(super) unsafe fn run(sp: usize, ldso_base: usize) -> ! {
    // SAFETY: `_start` supplies the unchanged kernel stack and a self-relocated
    // interpreter base. Every object pointer below comes from a checked
    // program-header/dynamic-table parse or a successfully mapped ET_DYN.
    unsafe {
        #[cfg(feature = "x86_64-owned-dynamic-runtime")]
        x86_64_library_search::initialize(sp);
        let (main_phdr, main_phnum, main_entry) = auxv_main(sp).unwrap_or_else(|| fail(b"auxv\n"));
        let main_base = main_load_bias(main_phdr, main_phnum).unwrap_or_else(|| fail(b"mainbase\n"));
        let main = parse_mapped(main_base, main_phdr, main_phnum, false, false, true)
            .unwrap_or_else(|| fail(b"mainelf\n"));

        #[cfg(crabc_general_initial_tls_materialization_v1)]
        {
            if let Err(message) = run_with_initial_tls(main, main_entry, sp, ldso_base) {
                fail(message);
            }
            // `run_with_initial_tls` transfers directly to the application
            // after its private commit. A normal return would violate that
            // no-CRT-handoff boundary.
            fail(b"tlsreturn\n");
        }

        #[cfg(not(crabc_general_initial_tls_materialization_v1))]
        {
            run_without_tls(main, main_entry, sp, ldso_base)
        }
    }
}

#[cfg(not(crabc_general_initial_tls_materialization_v1))]
unsafe fn run_without_tls(main: Object, main_entry: u64, sp: usize, ldso_base: usize) -> ! {
    // `u64::MAX` cannot be a Linux device number. The kernel-owned main
    // mapping therefore cannot alias an fstat-derived DSO identity.
    let mut state = GeneralInitialLoaderState::new(ObjectIdentity {
        device: u64::MAX,
        inode: u64::MAX,
    }, main);
    let discovered = {
        let (graph, objects) = state
            .discovery_mut()
            .unwrap_or_else(|_| fail(b"state\n"));
        unsafe { discover_needed(graph, objects, 0) }
    };
    if discovered.is_none() {
        rollback_general_initial_state(&mut state, GeneralInitialPreparationStage::Discovery);
        fail(b"graph\n");
    }
    if state.finish_discovery().is_err() {
        rollback_general_initial_state(&mut state, GeneralInitialPreparationStage::Discovery);
        fail(b"graph\n");
    }

    let object_count = state.object_count();
    {
        let objects = state
            .objects_during_transaction()
            .unwrap_or_else(|_| fail(b"state\n"));
        let graph = state.graph_during_transaction().unwrap_or_else(|_| fail(b"state\n"));
        if super::x86_64_general_relocation::relocate_initial_graph(graph, objects).is_none() {
            rollback_general_initial_state(&mut state, GeneralInitialPreparationStage::Relocation);
            fail(b"reloc\n");
        }
    }
    for object in &state
        .objects_during_transaction()
        .unwrap_or_else(|_| fail(b"state\n"))[1..object_count]
    {
        if protect_segments(object).is_none() {
            rollback_general_initial_state(&mut state, GeneralInitialPreparationStage::Protection);
            fail(b"protect\n");
        }
    }
    for object in &state
        .objects_during_transaction()
        .unwrap_or_else(|_| fail(b"state\n"))[..object_count]
    {
        if apply_relro(object).is_none() {
            rollback_general_initial_state(&mut state, GeneralInitialPreparationStage::Relro);
            fail(b"relro\n");
        }
    }
    if apply_self_relro(ldso_base as u64).is_none() {
        rollback_general_initial_state(&mut state, GeneralInitialPreparationStage::SelfRelro);
        fail(b"selfrelro\n");
    }
    #[allow(unused_mut)]
    let mut initializers = match preflight_dependency_initializers(
        state
            .graph_during_transaction()
            .unwrap_or_else(|_| fail(b"state\n")),
        state
            .objects_during_transaction()
            .unwrap_or_else(|_| fail(b"state\n")),
    ) {
        Some(plan) => plan,
        None => {
            rollback_general_initial_state(
                &mut state,
                GeneralInitialPreparationStage::InitializerPreflight,
            );
            fail(b"ctorplan\n");
        }
    };
    #[cfg(crabc_general_initial_lifecycle)]
    if state.attach_lifecycle(initializers.lifecycle.take().unwrap()).is_err() {
        rollback_general_initial_state(&mut state, GeneralInitialPreparationStage::InitializerPreflight);
        fail(b"state\n");
    }
    if state.prepare().is_err() {
        rollback_general_initial_state(&mut state, GeneralInitialPreparationStage::InitializerPreflight);
        fail(b"state\n");
    }
    if state.reserve_publication().is_err() {
        rollback_general_initial_state(
            &mut state,
            GeneralInitialPreparationStage::PublicationReservation,
        );
        fail(b"publish\n");
    }
    // All fallible graph work completed before this move. The retained common
    // owner is therefore visible before any dependency constructor runs.
    unsafe { state.commit() };
    // `preflight_dependency_initializers` has read and checked every
    // relocated entry after all object and interpreter RELRO ranges were
    // sealed. Dispatch is consequently an infallible first callback step.
    #[cfg(not(all(crabc_general_initial_lifecycle, crabc_dynamic_main_thread_runtime_v1)))]
    unsafe { dispatch_dependency_initializers(&initializers) };
    jump(main_entry as usize, sp)
}

/// Runs the bounded general graph's initial TLS materialization transaction.
///
/// Both roots commit the same common graph/object owner. This sibling cannot
/// jump until it has attached its generation-one TLS facts to that owner, so
/// a direct `__tls_get_addr` call after entry reaches the same stable module
/// IDs and DTV slots used for the initial relocations.
#[cfg(crabc_general_initial_tls_materialization_v1)]
unsafe fn run_with_initial_tls(
    main: Object,
    main_entry: u64,
    sp: usize,
    ldso_base: usize,
) -> Result<(), &'static [u8]> {
    let mut state = GeneralInitialTlsState::new(
        ObjectIdentity {
            device: u64::MAX,
            inode: u64::MAX,
        },
        main,
    );
    let discovered = {
        let (graph, objects) = match state.graph_and_objects_mut() {
            Ok(parts) => parts,
            Err(_) => return Err(b"state\n"),
        };
        unsafe { discover_needed(graph, objects, 0) }
    };
    if discovered.is_none() || state.finish_discovery().is_err() {
        rollback_initial_tls_state(&mut state, GeneralInitialPreparationStage::Discovery);
        return Err(b"graph\n");
    }
    // This is an initial-TLS root, not a second spelling for the non-TLS
    // general graph. Mixed graphs may contain TLS-free objects, but at least
    // one admitted initial PT_TLS image must own the generation-one state.
    match state.plan_initial_tls() {
        Ok(true) => {}
        Ok(false) | Err(_) => {
            rollback_initial_tls_state(&mut state, GeneralInitialPreparationStage::TlsPlanning);
            return Err(b"tlsplan\n");
        }
    }

    {
        let objects = match state.objects() {
            Ok(objects) => objects,
            Err(_) => {
                rollback_initial_tls_state(&mut state, GeneralInitialPreparationStage::TlsRegistry);
                return Err(b"tlsstate\n");
            }
        };
        let graph = match state.graph() {
            Ok(graph) => graph,
            Err(_) => {
                rollback_initial_tls_state(&mut state, GeneralInitialPreparationStage::TlsRegistry);
                return Err(b"tlsstate\n");
            }
        };
        if unsafe { super::x86_64_general_relocation::relocate_initial_graph(graph, objects) }.is_none() {
            rollback_initial_tls_state(&mut state, GeneralInitialPreparationStage::Relocation);
            return Err(b"reloc\n");
        }
    }
    if state.mark_relocated().is_err() {
        rollback_initial_tls_state(&mut state, GeneralInitialPreparationStage::TlsRegistry);
        return Err(b"tlsstate\n");
    }
    for index in 1..state.object_count() {
        let objects = match state.objects() {
            Ok(objects) => objects,
            Err(_) => {
                rollback_initial_tls_state(&mut state, GeneralInitialPreparationStage::TlsRegistry);
                return Err(b"tlsstate\n");
            }
        };
        if unsafe { protect_segments(&objects[index]) }.is_none() {
            rollback_initial_tls_state(&mut state, GeneralInitialPreparationStage::Protection);
            return Err(b"protect\n");
        }
    }
    for index in 0..state.object_count() {
        let objects = match state.objects() {
            Ok(objects) => objects,
            Err(_) => {
                rollback_initial_tls_state(&mut state, GeneralInitialPreparationStage::TlsRegistry);
                return Err(b"tlsstate\n");
            }
        };
        if unsafe { apply_relro(&objects[index]) }.is_none() {
            rollback_initial_tls_state(&mut state, GeneralInitialPreparationStage::Relro);
            return Err(b"relro\n");
        }
    }
    if unsafe { apply_self_relro(ldso_base as u64) }.is_none() {
        rollback_initial_tls_state(&mut state, GeneralInitialPreparationStage::SelfRelro);
        return Err(b"selfrelro\n");
    }

    // The actual dispatch must follow initial TLS publication. Build and
    // validate the complete once-only plan now, while every error can still
    // roll back mappings and preserve the incoming FS base. In particular,
    // do not discover a cycle, a zero entry, or a non-executable target after
    // `ARCH_SET_FS`: `commit` deliberately has no fallible successor.
    let (graph, objects) = match (state.graph(), state.objects()) {
        (Ok(graph), Ok(objects)) => (graph, objects),
        _ => {
            rollback_initial_tls_state(&mut state, GeneralInitialPreparationStage::TlsRegistry);
            return Err(b"tlsstate\n");
        }
    };
    #[allow(unused_mut)]
    let mut initializers = match preflight_dependency_initializers(graph, objects) {
        Some(plan) => plan,
        None => {
            rollback_initial_tls_state(
                &mut state,
                GeneralInitialPreparationStage::InitializerPreflight,
            );
            return Err(b"ctorplan\n");
        }
    };

    #[cfg(feature = "x86_64-owned-dynamic-runtime")]
    let runtime_registry = match unsafe {
        super::x86_64_runtime_registry::PreparedInitialRegistry::prepare(
            graph, objects, initializers.lifecycle.as_ref().unwrap())
    } {
        Some(registry) => registry,
        None => {
            rollback_initial_tls_state(&mut state, GeneralInitialPreparationStage::RuntimeRegistry);
            return Err(b"runtime-registry\n");
        }
    };

    #[cfg(crabc_general_initial_lifecycle)]
    if state.attach_lifecycle(initializers.lifecycle.take().unwrap()).is_err() {
        rollback_initial_tls_state(&mut state, GeneralInitialPreparationStage::InitializerPreflight);
        return Err(b"state\n");
    }

    // A runtime module request has no map path in this package.  Keep the
    // typed DTV-growth rejection explicit before `ARCH_SET_FS`; any failure
    // above has already rolled back mappings and left the incoming FS base
    // untouched.
    if state.reject_runtime_tls_growth(state.object_count()).is_ok() {
        rollback_initial_tls_state(&mut state, GeneralInitialPreparationStage::TlsRegistry);
        return Err(b"tlsgrowth\n");
    }
    // Reserve the one private committed-state slot before the installer can
    // change `%fs`. A failed reservation and every later pre-FS error release
    // through `rollback_initial_tls_state`; after a successful installer the
    // commit below has no fallible arbitration left to perform.
    if state.reserve_publication().is_err() {
        rollback_initial_tls_state(
            &mut state,
            GeneralInitialPreparationStage::PublicationReservation,
        );
        return Err(b"tlspublish\n");
    }

    // General RuntimeV1 reserves its descriptor together with the retained
    // loader state while rollback can still restore both PUBLISHING words and
    // the incoming FS base. The fixed RuntimeV1 path intentionally is not
    // reused here: it performs a descriptor CAS after ARCH_SET_FS.
    #[cfg(crabc_general_loader_libc_tls_runtime_v1)]
    if state.reserve_runtime_v1_publication().is_err() {
        rollback_initial_tls_state(
            &mut state,
            GeneralInitialPreparationStage::RuntimeV1Reservation,
        );
        return Err(b"tlsruntimev1\n");
    }

    let installed = match unsafe { state.materialize_initial_tls() } {
        Ok(installed) => installed,
        Err(_) => {
            // `materialize_initial_tls` returns an error only before it can
            // install %fs. Once it returns the coordinates below, commit has
            // no fallible predecessor or rollback path.
            rollback_initial_tls_state(&mut state, GeneralInitialPreparationStage::TlsMaterialization);
            return Err(b"tlsinit\n");
        }
    };

    // The state installer has performed the sole fallible `ARCH_SET_FS`
    // transition. Publication was already reserved, so commit only writes and
    // release-publishes the common graph/object owner; the RuntimeV1 sibling
    // writes its descriptor fields and release-publishes READY last. No error
    // path remains that could leave a changed FS base without its retained
    // owner.
    #[cfg(not(crabc_general_loader_libc_tls_runtime_v1))]
    unsafe { state.commit(installed) };
    #[cfg(crabc_general_loader_libc_tls_runtime_v1)]
    unsafe { state.commit_runtime_v1(installed) };
    #[cfg(feature = "x86_64-owned-dynamic-runtime")]
    unsafe { runtime_registry.publish(); }
    // Publication made the TLS snapshot durable before the first dependency
    // constructor can observe it. The plan was fully preflighted above, so
    // this is the non-fallible post-publication callback phase.
    // The owned dynamic startup composition invokes this retained plan only
    // after libc startup and executable preinit. Other roots preserve their
    // established interpreter-side dependency initialization boundary.
    #[cfg(not(all(crabc_general_initial_lifecycle, crabc_dynamic_main_thread_runtime_v1)))]
    unsafe { dispatch_dependency_initializers(&initializers) };
    unsafe { jump(main_entry as usize, sp) }
}

/// The complete prevalidated constructor call list for one initial graph.
///
/// The established roots retain a transient init-array list. The lifecycle
/// feature instead transfers the complete per-object callback owner into the
/// canonical graph before publication. Both copy from RELRO-sealed arrays,
/// avoiding further fallible ELF reads after TLS installation.
struct DependencyInitializerPlan {
    #[cfg(not(crabc_general_initial_lifecycle))]
    callbacks: [usize; MAX_OBJECTS * MAX_GENERAL_INITIAL_DEPENDENCY_INIT_ARRAY_ENTRIES],
    #[cfg(not(crabc_general_initial_lifecycle))]
    count: usize,
    #[cfg(crabc_general_initial_lifecycle)]
    lifecycle: Option<super::x86_64_general_initial_lifecycle::GeneralInitialLifecycle>,
}

impl DependencyInitializerPlan {
    const fn empty() -> Self {
        Self {
            #[cfg(not(crabc_general_initial_lifecycle))]
            callbacks: [0; MAX_OBJECTS * MAX_GENERAL_INITIAL_DEPENDENCY_INIT_ARRAY_ENTRIES],
            #[cfg(not(crabc_general_initial_lifecycle))]
            count: 0,
            #[cfg(crabc_general_initial_lifecycle)]
            lifecycle: None,
        }
    }

    #[cfg(not(crabc_general_initial_lifecycle))]
    fn push(&mut self, callback: usize) -> Option<()> {
        let destination = self.callbacks.get_mut(self.count)?;
        *destination = callback;
        self.count += 1;
        Some(())
    }
}

/// Builds the sole accepted initial-lifecycle action from graph edges.
///
/// Without the lifecycle feature the parser admits only a dependency's
/// bounded `DT_INIT_ARRAY` pair. The lifecycle feature adds dependency legacy
/// init/fini and fini arrays. Preflight adds runtime facts after relocation:
/// every dependency is present once in graph-derived postorder and every
/// pointer is nonzero and contained in that dependency's executable load.
/// No constructor is called until the entire plan succeeds.
unsafe fn preflight_dependency_initializers(
    graph: &InitialGraphState,
    objects: &[Object; MAX_OBJECTS],
) -> Option<DependencyInitializerPlan> {
    #[cfg(not(crabc_general_initial_lifecycle))]
    let graph_plan = graph.dependency_first_plan().ok()?;
    let mut plan = DependencyInitializerPlan::empty();
    #[cfg(crabc_general_initial_lifecycle)]
    {
        plan.lifecycle = Some(unsafe {
            super::x86_64_general_initial_lifecycle::GeneralInitialLifecycle::preflight(graph, objects)?
        });
    }
    #[cfg(not(crabc_general_initial_lifecycle))]
    for &index in graph_plan.indices() {
        let object = objects.get(index)?;
        if !object.mapped
            || object.init_count > MAX_GENERAL_INITIAL_DEPENDENCY_INIT_ARRAY_ENTRIES
            || (object.init_count != 0 && object.init_array.is_null())
        {
            return None;
        }
        for entry_index in 0..object.init_count {
            let callback = *object.init_array.add(entry_index);
            if callback == 0 {
                return None;
            }
            let virtual_address = callback.checked_sub(object.base as usize)? as u64;
            if !virtual_range_in_executable_load(object.phdr, object.phnum, virtual_address, 1) {
                return None;
            }
            plan.push(callback)?;
        }
    }
    Some(plan)
}

/// Calls an already complete dependency-only initial constructor plan.
///
/// # Safety
///
/// `plan` must originate from `preflight_dependency_initializers` for the
/// currently retained graph. Its entries then designate executable addresses
/// in mapped dependencies, and the caller must be in the single initial
/// startup transaction before application control transfers.
unsafe fn dispatch_dependency_initializers(plan: &DependencyInitializerPlan) {
    #[cfg(crabc_general_initial_lifecycle)]
    {
        let _ = plan;
        // Both initial transaction routes attach the complete lifecycle
        // before reserving publication. No mapped callback runs until the
        // canonical owner (and any initial TLS attachment) is retained.
        unsafe { GeneralInitialLoaderState::retained().unwrap().lifecycle().unwrap().initialize() };
    }
    #[cfg(not(crabc_general_initial_lifecycle))]
    for &callback in &plan.callbacks[..plan.count] {
        let callback: unsafe extern "C" fn() = unsafe { core::mem::transmute(callback) };
        unsafe { callback() };
    }
}

#[cfg(crabc_general_initial_tls_materialization_v1)]
unsafe fn rollback_initial_tls_state(
    state: &mut GeneralInitialTlsState,
    stage: GeneralInitialPreparationStage,
) {
    state.abort(stage, |object| unsafe { unmap_object(object) });
}

/// Discover every initial dependency edge in linker encounter order.
///
/// A child is identified from the opened descriptor before it is mapped. If
/// that identity already appears in the transaction, this records an edge and
/// deliberately does not recurse; that one rule handles both diamonds and
/// cycles without a topology-specific condition. New objects are mapped,
/// parsed and admitted before its dependencies. The installed runtime walks
/// admitted objects breadth-first, as musl load_deps does: a main dependency
/// must win first-load identity before any grandchild with the same name.
unsafe fn discover_needed(
    graph: &mut InitialGraphState,
    objects: &mut [Object; MAX_OBJECTS],
    parent_index: usize,
) -> Option<()> {
    #[cfg(feature = "x86_64-owned-dynamic-runtime")]
    {
        if parent_index != 0 { return None; }
        let mut index = 0;
        while index < graph.object_count() {
            discover_object_needed(graph, objects, index)?;
            // Main's completion is owned by finish_discovery on the state.
            if index != 0 { graph.finish_discovery(index).ok()?; }
            index += 1;
        }
        Some(())
    }
    #[cfg(not(feature = "x86_64-owned-dynamic-runtime"))]
    unsafe { discover_object_needed(graph, objects, parent_index) }
}

unsafe fn discover_object_needed(
    graph: &mut InitialGraphState,
    objects: &mut [Object; MAX_OBJECTS],
    parent_index: usize,
) -> Option<()> {
    let parent = *objects.get(parent_index)?;
    #[cfg(not(feature = "x86_64-owned-dynamic-runtime"))]
    if parent.runpath.is_null() && parent.needed_count != 0 {
        return None;
    }
    for needed_index in 0..parent.needed_count {
        let name_offset = parent.needed[needed_index];
        if name_offset >= parent.strsz {
            return None;
        }
        let name = parent.strtab.add(name_offset);
        let name_len = bounded_nul(name, parent.strsz - name_offset)?;
        #[cfg(not(feature = "x86_64-owned-dynamic-runtime"))]
        if !selected_needed_name(name, name_len) {
            return None;
        }
        #[cfg(feature = "x86_64-owned-dynamic-runtime")]
        {
            let requested = core::slice::from_raw_parts(name, name_len);
            if !requested.contains(&b'/') {
                if let Some(index) = objects[..graph.object_count()].iter().position(|object| {
                    if !object.search_short_name { return false; }
                    let length = bounded_nul(object.search_name.as_ptr(), MAX_PATH).unwrap_or(0);
                    let stored = &object.search_name[..length];
                    let start = stored.iter().rposition(|byte| *byte == b'/').map_or(0, |n| n + 1);
                    &stored[start..] == requested
                }) {
                    graph.attach_needed(parent_index, index).ok()?;
                    continue;
                }
            }
        }
        #[cfg(not(feature = "x86_64-owned-dynamic-runtime"))]
        let fd = open_from_runpath(parent.runpath, parent.runpath_len, name, name_len)?;
        #[cfg(feature = "x86_64-owned-dynamic-runtime")]
        let (fd, search_name, _) = {
            let mut ancestor = Some(parent_index);
            let chain = core::iter::from_fn(|| {
                let object = objects.get(ancestor?)?;
                ancestor = object.needed_by;
                Some(object)
            });
            x86_64_library_search::open(core::slice::from_raw_parts(name, name_len), chain).ok()?
        };
        let identity = match file_identity_from_fd(fd) {
            Some(identity) => identity,
            None => {
                let _ = syscall1(SYS_CLOSE, fd);
                return None;
            }
        };
        if let Some(existing) = graph.find(identity) {
            let _ = syscall1(SYS_CLOSE, fd);
            #[cfg(feature = "x86_64-owned-dynamic-runtime")]
            { objects[existing].search_short_name |= !core::slice::from_raw_parts(name, name_len).contains(&b'/'); }
            graph.attach_needed(parent_index, existing).ok()?;
            continue;
        }

        let child = map_elf(fd, false, true);
        let _ = syscall1(SYS_CLOSE, fd);
        let child = child?;
        let child_index = match graph.admit_mapped(identity) {
            Ok(ObjectAdmission::New { index }) => index,
            // The find above and one-threaded initial transaction make this
            // unreachable. Keep it fail-closed rather than creating a second
            // mapping with an unowned lifetime.
            Ok(ObjectAdmission::Existing { .. }) | Err(_) => {
                unmap_object(&child);
                return None;
            }
        };
        objects[child_index] = child;
        #[cfg(feature = "x86_64-owned-dynamic-runtime")]
        {
            objects[child_index].search_name = search_name;
            objects[child_index].search_short_name = !core::slice::from_raw_parts(name, name_len).contains(&b'/');
            objects[child_index].needed_by = Some(parent_index);
        }
        graph.attach_needed(parent_index, child_index).ok()?;
        #[cfg(not(feature = "x86_64-owned-dynamic-runtime"))]
        {
            discover_needed(graph, objects, child_index)?;
            graph.finish_discovery(child_index).ok()?;
        }
    }
    Some(())
}

unsafe fn selected_needed_name(name: *const u8, name_len: usize) -> bool {
    if name_len == 0 {
        return false;
    }
    for index in 0..name_len {
        let byte = *name.add(index);
        // A slash changes DT_NEEDED from a RUNPATH lookup into a pathname
        // policy. That policy (and `$ORIGIN`) has not been selected here.
        if byte == b'/' || byte == 0 {
            return false;
        }
    }
    true
}

unsafe fn rollback_general_initial_state(
    state: &mut GeneralInitialLoaderState,
    stage: GeneralInitialPreparationStage,
) {
    state.abort(stage, |object| unsafe { unmap_object(object) });
}

unsafe fn unmap_object(object: &Object) {
    if object.map_provenance != ObjectMapProvenance::Transaction
        || !object.mapped
        || object.map_span_byte_len == 0
    {
        return;
    }
    // `map_elf` retained this exact anonymous reservation span at admission.
    // Do not reparse mutable mapped ELF headers for a lifetime operation and
    // never infer a span for the kernel-owned main image.
    let _ = syscall2(
        SYS_MUNMAP,
        object.map_span_start as i64,
        object.map_span_byte_len as i64,
    );
}
