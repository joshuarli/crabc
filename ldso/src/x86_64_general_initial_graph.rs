//! General x86-64 initial `DT_NEEDED` graph transaction.
//!
//! This private package deliberately uses the checked ELF/parser/mapper and
//! non-TLS relocation primitives in its parent module, but owns no fixed
//! object shape. Its state and identity rules live in
//! `x86_64_initial_graph_state.rs`; the older fixed graph remains a separate
//! regression root.  The default general root remains non-TLS.  Its separate
//! `crabc_general_initial_tls_materialization_v1` sibling adds only an
//! initial Variant-II TLS population and retains it in loader-owned state. Its
//! ordinary cfg is not a RuntimeV1 producer; the separately cfg-selected
//! general RuntimeV1 handoff still excludes dynamic CRT handoff, general
//! process/DSO lifecycle ownership, and runtime DSO mapping.

use super::*;
use super::x86_64_initial_graph_state::{InitialGraphState, ObjectAdmission, ObjectIdentity};
#[cfg(crabc_general_initial_tls_materialization_v1)]
use super::x86_64_general_initial_tls_state::GeneralInitialTlsState;

/// Starts the topology-independent initial dependency transaction.
///
/// # Safety
///
/// `_start` must supply the untouched Linux initial stack and this
/// interpreter's already self-relocated base. All returned ELF metadata is
/// retained only while the corresponding mapping remains live.
pub(super) unsafe fn run(sp: usize, ldso_base: usize) -> ! {
    // SAFETY: `_start` supplies the unchanged kernel stack and a self-relocated
    // interpreter base. Every object pointer below comes from a checked
    // program-header/dynamic-table parse or a successfully mapped ET_DYN.
    unsafe {
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
    let mut objects = [EMPTY_OBJECT; MAX_OBJECTS];
    objects[0] = main;

    // `u64::MAX` cannot be a Linux device number. The kernel-owned main
    // mapping therefore cannot alias an fstat-derived DSO identity.
    let mut graph = InitialGraphState::new(ObjectIdentity {
        device: u64::MAX,
        inode: u64::MAX,
    });
    if discover_needed(&mut graph, &mut objects, 0).is_none() {
        rollback(&mut graph, &mut objects);
        fail(b"graph\n");
    }
    if graph.finish_discovery(0).is_err() {
        rollback(&mut graph, &mut objects);
        fail(b"graph\n");
    }

    let object_count = graph.object_count();
    for index in 0..object_count {
        if relocate(&objects[index], &objects).is_none() {
            rollback(&mut graph, &mut objects);
            fail(b"reloc\n");
        }
    }
    for object in &objects[1..object_count] {
        if protect_segments(object).is_none() {
            rollback(&mut graph, &mut objects);
            fail(b"protect\n");
        }
    }
    for object in &objects[..object_count] {
        if apply_relro(object).is_none() {
            rollback(&mut graph, &mut objects);
            fail(b"relro\n");
        }
    }
    if apply_self_relro(ldso_base as u64).is_none() {
        rollback(&mut graph, &mut objects);
        fail(b"selfrelro\n");
    }
    let initializers = match preflight_dependency_initializers(&graph, &objects) {
        Some(plan) => plan,
        None => {
            rollback(&mut graph, &mut objects);
            fail(b"ctorplan\n");
        }
    };
    // `preflight_dependency_initializers` has read and checked every
    // relocated entry after all object and interpreter RELRO ranges were
    // sealed. Dispatch is consequently an infallible first callback step.
    unsafe { dispatch_dependency_initializers(&initializers) };
    jump(main_entry as usize, sp)
}

/// Runs the bounded general graph's initial TLS materialization transaction.
///
/// The no-TLS sibling above keeps its stack-only ownership.  This sibling
/// cannot jump until it has committed a loader-owned snapshot, so a direct
/// `__tls_get_addr` call after entry reaches the same stable module IDs and
/// DTV slots used for the initial relocations.
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
        let (graph, objects) = state.graph_and_objects_mut();
        unsafe { discover_needed(graph, objects, 0) }
    };
    if discovered.is_none() || state.finish_discovery().is_err() {
        rollback_initial_tls_state(&mut state);
        return Err(b"graph\n");
    }
    // This is an initial-TLS root, not a second spelling for the non-TLS
    // general graph. Mixed graphs may contain TLS-free objects, but at least
    // one admitted initial PT_TLS image must own the generation-one state.
    match state.plan_initial_tls() {
        Ok(true) => {}
        Ok(false) | Err(_) => {
            rollback_initial_tls_state(&mut state);
            return Err(b"tlsplan\n");
        }
    }

    for index in 0..state.object_count() {
        let objects = state.objects();
        if unsafe { relocate(&objects[index], objects) }.is_none() {
            rollback_initial_tls_state(&mut state);
            return Err(b"reloc\n");
        }
    }
    if state.mark_relocated().is_err() {
        rollback_initial_tls_state(&mut state);
        return Err(b"tlsstate\n");
    }
    for index in 1..state.object_count() {
        if unsafe { protect_segments(&state.objects()[index]) }.is_none() {
            rollback_initial_tls_state(&mut state);
            return Err(b"protect\n");
        }
    }
    for index in 0..state.object_count() {
        if unsafe { apply_relro(&state.objects()[index]) }.is_none() {
            rollback_initial_tls_state(&mut state);
            return Err(b"relro\n");
        }
    }
    if unsafe { apply_self_relro(ldso_base as u64) }.is_none() {
        rollback_initial_tls_state(&mut state);
        return Err(b"selfrelro\n");
    }

    // The actual dispatch must follow initial TLS publication. Build and
    // validate the complete once-only plan now, while every error can still
    // roll back mappings and preserve the incoming FS base. In particular,
    // do not discover a cycle, a zero entry, or a non-executable target after
    // `ARCH_SET_FS`: `commit` deliberately has no fallible successor.
    let initializers = match preflight_dependency_initializers(state.graph(), state.objects()) {
        Some(plan) => plan,
        None => {
            rollback_initial_tls_state(&mut state);
            return Err(b"ctorplan\n");
        }
    };

    // A runtime module request has no map path in this package.  Keep the
    // typed DTV-growth rejection explicit before `ARCH_SET_FS`; any failure
    // above has already rolled back mappings and left the incoming FS base
    // untouched.
    if state.reject_runtime_tls_growth(state.object_count()).is_ok() {
        rollback_initial_tls_state(&mut state);
        return Err(b"tlsgrowth\n");
    }
    // Reserve the one private committed-state slot before the installer can
    // change `%fs`. A failed reservation and every later pre-FS error release
    // through `rollback_initial_tls_state`; after a successful installer the
    // commit below has no fallible arbitration left to perform.
    if state.reserve_publication().is_err() {
        rollback_initial_tls_state(&mut state);
        return Err(b"tlspublish\n");
    }

    // General RuntimeV1 reserves its descriptor together with the retained
    // loader state while rollback can still restore both PUBLISHING words and
    // the incoming FS base. The fixed RuntimeV1 path intentionally is not
    // reused here: it performs a descriptor CAS after ARCH_SET_FS.
    #[cfg(crabc_general_loader_libc_tls_runtime_v1)]
    if state.reserve_runtime_v1_publication().is_err() {
        rollback_initial_tls_state(&mut state);
        return Err(b"tlsruntimev1\n");
    }

    let installed = match unsafe { state.materialize_initial_tls() } {
        Ok(installed) => installed,
        Err(_) => {
            // `materialize_initial_tls` returns an error only before it can
            // install %fs. Once it returns the coordinates below, commit has
            // no fallible predecessor or rollback path.
            rollback_initial_tls_state(&mut state);
            return Err(b"tlsinit\n");
        }
    };

    // The state installer has performed the sole fallible `ARCH_SET_FS`
    // transition. Publication was already reserved, so commit only writes the
    // private snapshot and release-publishes it; the RuntimeV1 sibling writes
    // its descriptor fields and release-publishes READY last. No error path
    // remains that could leave a changed FS base without its retained owner.
    #[cfg(not(crabc_general_loader_libc_tls_runtime_v1))]
    unsafe { state.commit(installed) };
    #[cfg(crabc_general_loader_libc_tls_runtime_v1)]
    unsafe { state.commit_runtime_v1(installed) };
    // Publication made the TLS snapshot durable before the first dependency
    // constructor can observe it. The plan was fully preflighted above, so
    // this is the non-fallible post-publication callback phase.
    unsafe { dispatch_dependency_initializers(&initializers) };
    unsafe { jump(main_entry as usize, sp) }
}

/// The complete prevalidated constructor call list for one initial graph.
///
/// It has no object pointers or mutable lifecycle state. Once the values are
/// copied from RELRO-sealed arrays, dispatch can happen after TLS publication
/// without another fallible read from the object graph.
struct DependencyInitializerPlan {
    callbacks: [usize; MAX_OBJECTS * MAX_GENERAL_INITIAL_DEPENDENCY_INIT_ARRAY_ENTRIES],
    count: usize,
}

impl DependencyInitializerPlan {
    const fn empty() -> Self {
        Self {
            callbacks: [0; MAX_OBJECTS * MAX_GENERAL_INITIAL_DEPENDENCY_INIT_ARRAY_ENTRIES],
            count: 0,
        }
    }

    fn push(&mut self, callback: usize) -> Option<()> {
        let destination = self.callbacks.get_mut(self.count)?;
        *destination = callback;
        self.count += 1;
        Some(())
    }
}

/// Builds the sole accepted initial-lifecycle action from graph edges.
///
/// The parser admits only a mapped dependency's bounded `DT_INIT_ARRAY` tag
/// pair. This preflight adds the remaining runtime facts after relocation:
/// every dependency is present once in graph-derived postorder and every
/// pointer is nonzero and contained in that dependency's executable load.
/// No constructor is called until the entire plan succeeds.
unsafe fn preflight_dependency_initializers(
    graph: &InitialGraphState,
    objects: &[Object; MAX_OBJECTS],
) -> Option<DependencyInitializerPlan> {
    let graph_plan = graph.dependency_first_plan().ok()?;
    let mut plan = DependencyInitializerPlan::empty();
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
    for &callback in &plan.callbacks[..plan.count] {
        let callback: unsafe extern "C" fn() = unsafe { core::mem::transmute(callback) };
        unsafe { callback() };
    }
}

#[cfg(crabc_general_initial_tls_materialization_v1)]
unsafe fn rollback_initial_tls_state(state: &mut GeneralInitialTlsState) {
    state.rollback(|object| unsafe { unmap_object(object) });
}

/// Discover every initial dependency edge in linker encounter order.
///
/// A child is identified from the opened descriptor before it is mapped. If
/// that identity already appears in the transaction, this records an edge and
/// deliberately does not recurse; that one rule handles both diamonds and
/// cycles without a topology-specific condition. New objects are mapped,
/// parsed, admitted, then recursed before being marked ready.
unsafe fn discover_needed(
    graph: &mut InitialGraphState,
    objects: &mut [Object; MAX_OBJECTS],
    parent_index: usize,
) -> Option<()> {
    let parent = *objects.get(parent_index)?;
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
        if !selected_needed_name(name, name_len) {
            return None;
        }
        let fd = open_from_runpath(parent.runpath, parent.runpath_len, name, name_len)?;
        let identity = match file_identity_from_fd(fd) {
            Some(identity) => identity,
            None => {
                let _ = syscall1(SYS_CLOSE, fd);
                return None;
            }
        };
        if let Some(existing) = graph.find(identity) {
            let _ = syscall1(SYS_CLOSE, fd);
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
        graph.attach_needed(parent_index, child_index).ok()?;
        discover_needed(graph, objects, child_index)?;
        graph.finish_discovery(child_index).ok()?;
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

unsafe fn rollback(graph: &mut InitialGraphState, objects: &mut [Object; MAX_OBJECTS]) {
    graph.rollback_to_main(|index| unsafe { unmap_object(&objects[index]) });
    for object in objects.iter_mut().skip(1) {
        *object = EMPTY_OBJECT;
    }
}

unsafe fn unmap_object(object: &Object) {
    if !object.mapped || object.phdr.is_null() || object.phnum == 0 {
        return;
    }
    let mut minimum = u64::MAX;
    let mut maximum = 0u64;
    for index in 0..object.phnum {
        let header = object.phdr.add(index * 56);
        if read_u32(header) != PT_LOAD {
            continue;
        }
        let start = align_down(read_u64(header.add(16)));
        let Some(end) = read_u64(header.add(16)).checked_add(read_u64(header.add(40))) else {
            return;
        };
        minimum = minimum.min(start);
        maximum = maximum.max(align_up(end));
    }
    if minimum != u64::MAX && maximum > minimum {
        let _ = syscall2(
            SYS_MUNMAP,
            object.base.wrapping_add(minimum) as i64,
            (maximum - minimum) as i64,
        );
    }
}
