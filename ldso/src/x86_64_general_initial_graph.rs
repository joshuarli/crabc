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
    GeneralInitialLoaderState, GeneralInitialPreparationStage, ObjectTable,
};
use super::x86_64_initial_graph_state::{InitialGraphState, ObjectAdmission, ObjectIdentity};
#[cfg(feature = "x86_64-owned-dynamic-runtime")]
use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};
#[cfg(crabc_general_initial_tls_materialization_v1)]
use super::x86_64_general_initial_tls_state::{
    GeneralInitialTlsState, GeneralInitialTlsTransaction,
};

/// Adopt the main image's PT_INTERP path as the installed interpreter name.
#[cfg(feature = "x86_64-owned-dynamic-runtime")]
unsafe fn set_main_interpreter(base: u64, phdr: *const u8, phnum: usize) {
    for index in 0..phnum {
        let header = unsafe { phdr.add(index * 56) };
        if unsafe { read_u32(header) } != 3 { continue; }
        let address = unsafe { read_u64(header.add(16)) };
        let size = unsafe { read_u64(header.add(32)) };
        if size < 2 || !unsafe { virtual_range_in_load(phdr, phnum, address, size) } { return; }
        let name = (base + address) as *const u8;
        if unsafe { *name.add(size as usize - 1) } != 0 { return; }
        unsafe { x86_64_library_search::main_interpreter(name); }
        return;
    }
}

/// A deferred placeholder for the kernel-mapped interpreter's file identity.
/// No real file has both fields maximized; the identity is resolved on the
/// first opened duplicate candidate, not during the startup fast path.
#[cfg(feature = "x86_64-owned-dynamic-runtime")]
const DEFERRED_SELF_IDENTITY: ObjectIdentity =
    ObjectIdentity { device: u64::MAX, inode: u64::MAX - 1 };

#[cfg(feature = "x86_64-owned-dynamic-runtime")]
const SELF_IDENTITY_UNKNOWN: u8 = 0;
#[cfg(feature = "x86_64-owned-dynamic-runtime")]
const SELF_IDENTITY_RESOLVING: u8 = 1;
#[cfg(feature = "x86_64-owned-dynamic-runtime")]
const SELF_IDENTITY_READY: u8 = 2;
#[cfg(feature = "x86_64-owned-dynamic-runtime")]
static SELF_IDENTITY_DEVICE: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "x86_64-owned-dynamic-runtime")]
static SELF_IDENTITY_INODE: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "x86_64-owned-dynamic-runtime")]
static SELF_IDENTITY_STATE: AtomicU8 = AtomicU8::new(SELF_IDENTITY_UNKNOWN);

/// Resolve the interpreter's file identity only when a duplicate candidate is
/// actually opened. The installed fast path recognizes self by PT_INTERP,
/// reserved names or the canonical alias and never stats its own file.
#[cfg(feature = "x86_64-owned-dynamic-runtime")]
pub(crate) unsafe fn lazy_self_identity() -> Option<ObjectIdentity> {
    loop {
        match SELF_IDENTITY_STATE.load(Ordering::Acquire) {
            SELF_IDENTITY_READY => {
                return Some(ObjectIdentity {
                    device: SELF_IDENTITY_DEVICE.load(Ordering::Relaxed),
                    inode: SELF_IDENTITY_INODE.load(Ordering::Relaxed),
                });
            }
            SELF_IDENTITY_UNKNOWN => {
                if SELF_IDENTITY_STATE.compare_exchange(
                    SELF_IDENTITY_UNKNOWN, SELF_IDENTITY_RESOLVING,
                    Ordering::AcqRel, Ordering::Acquire,
                ).is_ok() {
                    let interpreter = unsafe { x86_64_library_search::self_path() };
                    let identity = match unsafe { FileStatus::of_path(interpreter) } {
                        Ok(status) => status.identity(),
                        Err(_) => None,
                    };
                    if let Some(identity) = identity {
                        SELF_IDENTITY_DEVICE.store(identity.device, Ordering::Relaxed);
                        SELF_IDENTITY_INODE.store(identity.inode, Ordering::Relaxed);
                        SELF_IDENTITY_STATE.store(SELF_IDENTITY_READY, Ordering::Release);
                        return Some(identity);
                    }
                    SELF_IDENTITY_STATE.store(SELF_IDENTITY_UNKNOWN, Ordering::Release);
                    return None;
                }
            }
            SELF_IDENTITY_RESOLVING => core::hint::spin_loop(),
            _ => return None,
        }
    }
}

/// Compare one opened candidate identity to the lazily resolved self identity.
#[cfg(feature = "x86_64-owned-dynamic-runtime")]
pub(crate) unsafe fn self_identity_matches(candidate: ObjectIdentity) -> bool {
    unsafe { lazy_self_identity() == Some(candidate) }
}

/// The installed interpreter's canonical libc alias without a startup stat.
/// A copied loader under another basename falls back to identity resolution.
#[cfg(feature = "x86_64-owned-dynamic-runtime")]
unsafe fn installed_self_canonical_name() -> Option<super::x86_64_library_search::LoadedName> {
    if !unsafe { installed_self_name_is_canonical() } {
        return None;
    }
    let prefix = unsafe { x86_64_library_search::installation_prefix() };
    let suffix = b"/usr/lib/libc.so";
    let length = prefix.len().checked_add(suffix.len())?;
    let mut path = [0u8; 4096];
    if length >= path.len() { return None; }
    path[..prefix.len()].copy_from_slice(prefix);
    path[prefix.len()..length].copy_from_slice(suffix);
    super::x86_64_library_search::LoadedName::new(&path[..length])
}

/// Whether the interpreter's own name is the installed canonical one, so its
/// libc alias needs no stat and no search. A copied or renamed loader fails
/// this structural proof and keeps the conservative override probe below.
#[cfg(feature = "x86_64-owned-dynamic-runtime")]
unsafe fn installed_self_name_is_canonical() -> bool {
    let name = unsafe { x86_64_library_search::self_name() };
    let prefix = unsafe { x86_64_library_search::installation_prefix() };
    let lib = b"/lib/";
    if name.len() <= prefix.len() + lib.len()
        || !name.starts_with(prefix)
        || &name[prefix.len()..prefix.len() + lib.len()] != lib
    { return false; }
    let basename = &name[prefix.len() + lib.len()..];
    basename == b"ld-crabc-x86_64.so.1"
        || basename == b"ld-crabc-x86_64-hardened.so.1"
        || basename == b"ld-musl-x86_64.so.1"
}

/// Starts the topology-independent initial dependency transaction.
///
/// # Safety
///
/// `_start` must supply the untouched Linux initial stack and this
/// interpreter's already self-relocated base. A successful initial graph is
/// moved into the private process-lifetime owner before any constructor runs.
pub(super) unsafe fn run(sp: usize, ldso_base: usize) -> ! {
    #[cfg(feature = "x86_64-owned-dynamic-runtime")]
    super::set_interpreter_base(ldso_base);
    // SAFETY: `_start` supplies the unchanged kernel stack and a self-relocated
    // interpreter base. Every object pointer below comes from a checked
    // program-header/dynamic-table parse or a successfully mapped ET_DYN.
    unsafe {
        #[cfg(feature = "x86_64-owned-dynamic-runtime")]
        x86_64_library_search::initialize(sp);
        let (main_phdr, main_phnum, main_entry) = auxv_main(sp).unwrap_or_else(|| fail(b"auxv\n"));
        // The interpreter itself need not carry PT_PHDR. Compare the kernel
        // table with our own ELF header before applying the main-image parser.
        let own_phdr = (ldso_base + read_u64((ldso_base + 32) as *const u8) as usize) as *const u8;
        let main_base = if main_phdr == own_phdr { ldso_base as u64 } else {
            main_load_bias(main_phdr, main_phnum).unwrap_or_else(|| fail(b"mainbase\n"))
        };
        #[cfg(feature = "x86_64-owned-dynamic-runtime")]
        let (main, sp, main_entry) = if main_base as usize == ldso_base {
            let (main, sp) = x86_64_direct_entry::prepare(sp, ldso_base);
            let entry = main.entry;
            (main, sp, entry)
        } else {
            if cfg!(crabc_hardened) && !hardened_main_identity(main_base, main_phdr, main_phnum) { fail(b"mainelf\n"); }
            let main = parse_mapped(main_base, main_phdr, main_phnum, ObjectRole::Main, false, true)
                .unwrap_or_else(|| fail(b"mainelf\n"));
            set_main_interpreter(main.base, main.phdr, main.phnum);
            (main, sp, main_entry)
        };
        #[cfg(not(feature = "x86_64-owned-dynamic-runtime"))]
        let main = parse_mapped(main_base, main_phdr, main_phnum, ObjectRole::Main, false, true)
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
    // As in musl __dls3, main admission does not assign the file identity
    // used to deduplicate library admissions, for either entry mode.
    let mut state = GeneralInitialLoaderState::new(ObjectIdentity {
        device: u64::MAX,
        inode: u64::MAX,
    }, main).unwrap_or_else(|| fail(b"state\n"));
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
    let mut state = match GeneralInitialTlsTransaction::allocate(
        ObjectIdentity {
            device: u64::MAX,
            inode: u64::MAX,
        },
        main,
    ) {
        Some(state) => state,
        None => return Err(b"tlsstorage\n"),
    };
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
    #[cfg(feature = "x86_64-owned-dynamic-runtime")]
    {
        let selected = match state.graph_and_objects_mut() {
            Ok((graph, objects)) => unsafe { select_canonical_initial_libc(graph, objects) },
            Err(_) => None,
        };
        if selected.is_none() {
            rollback_initial_tls_state(&mut state, GeneralInitialPreparationStage::Discovery);
            return Err(b"libcidentity\n");
        }
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

    #[cfg(feature = "x86_64-owned-dynamic-runtime")]
    let conventional_main = match state.objects() {
        Ok(objects) => objects[0].main_crt_mode == MainCrtMode::Conventional,
        Err(_) => return Err(b"tlsstate\n"),
    };
    #[cfg(feature = "x86_64-owned-dynamic-runtime")]
    let owned_startup = if conventional_main {
        None
    } else {
        match super::x86_64_conventional_startup_v1::reserve_owned() {
            Some(reservation) => Some(reservation),
            None => {
                rollback_initial_tls_state(&mut state, GeneralInitialPreparationStage::ConventionalStartupReservation);
                return Err(b"conventionalstartup\n");
            }
        }
    };
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
        #[cfg(feature = "x86_64-owned-dynamic-runtime")]
        let debugger = match unsafe { super::x86_64_debugger::PreparedInitialDebugger::prepare(
            &objects[..graph.object_count()]) } {
            Some(debugger) => debugger,
            None => fail(b"debugger\n"),
        };
        #[cfg(feature = "x86_64-owned-dynamic-runtime")]
        let relocation = unsafe {
            super::x86_64_general_relocation::relocate_initial_graph_with_debugger(graph, objects, &debugger)
        };
        #[cfg(not(feature = "x86_64-owned-dynamic-runtime"))]
        let relocation = unsafe { super::x86_64_general_relocation::relocate_initial_graph(graph, objects) };
        if relocation.is_none() {
            rollback_initial_tls_state(&mut state, GeneralInitialPreparationStage::Relocation);
            return Err(b"reloc\n");
        }
    }
    if state.mark_relocated().is_err() {
        rollback_initial_tls_state(&mut state, GeneralInitialPreparationStage::TlsRegistry);
        return Err(b"tlsstate\n");
    }
    for index in 0..state.object_count() {
        let objects = match state.objects() {
            Ok(objects) => objects,
            Err(_) => {
                rollback_initial_tls_state(&mut state, GeneralInitialPreparationStage::TlsRegistry);
                return Err(b"tlsstate\n");
            }
        };
        #[cfg(feature = "x86_64-owned-dynamic-runtime")]
        if objects[index].interpreter_self { continue; }
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
        #[cfg(feature = "x86_64-owned-dynamic-runtime")]
        if objects[index].interpreter_self { continue; }
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
    unsafe { x86_64_direct_entry::list_and_exit(&objects[..state.object_count()], ldso_base); }

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

    // The installed shared libc imports this record in both CRT modes. Only
    // a conventional main reserves/publishes it; the owned mode resolves the
    // same exact weak relocation to null and retains its existing handoff.
    #[cfg(feature = "x86_64-owned-dynamic-runtime")]
    if conventional_main && state.reserve_conventional_startup_publication().is_err() {
        rollback_initial_tls_state(
            &mut state,
            GeneralInitialPreparationStage::ConventionalStartupReservation,
        );
        return Err(b"conventionalstartup\n");
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
    #[cfg(all(crabc_general_loader_libc_tls_runtime_v1, not(feature = "x86_64-owned-dynamic-runtime")))]
    unsafe { state.commit_runtime_v1(installed) };
    #[cfg(all(crabc_general_loader_libc_tls_runtime_v1, feature = "x86_64-owned-dynamic-runtime"))]
    let conventional_startup = unsafe { state.commit_runtime_v1(installed) };
    #[cfg(feature = "x86_64-owned-dynamic-runtime")]
    unsafe { runtime_registry.publish(ldso_base); }
    #[cfg(feature = "x86_64-owned-dynamic-runtime")]
    if let Some(reservation) = conventional_startup {
        unsafe { super::x86_64_conventional_startup_v1::publish(reservation, installed); }
    }
    #[cfg(feature = "x86_64-owned-dynamic-runtime")]
    if let Some(reservation) = owned_startup {
        super::x86_64_conventional_startup_v1::publish_owned(reservation);
    }
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
    callbacks: super::x86_64_runtime_memory::LoaderVec<usize>,
    #[cfg(crabc_general_initial_lifecycle)]
    lifecycle: Option<super::x86_64_general_initial_lifecycle::GeneralInitialLifecycle>,
}

impl DependencyInitializerPlan {
    const fn empty() -> Self {
        Self {
            #[cfg(not(crabc_general_initial_lifecycle))]
            callbacks: super::x86_64_runtime_memory::LoaderVec::new(),
            #[cfg(crabc_general_initial_lifecycle)]
            lifecycle: None,
        }
    }

    #[cfg(not(crabc_general_initial_lifecycle))]
    fn push(&mut self, callback: usize) -> Option<()> {
        self.callbacks.push(callback)
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
    objects: &[Object],
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
        if object.role == ObjectRole::Main
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
    for &callback in plan.callbacks.iter() {
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

/// The conventional libc startup receiver is never selected by a symbol name
/// or a mutable first-load pathname. These are the two declared aliases of
/// the selected installed product: normal materialization uses
/// `/usr/lib/libc.so`; the finite package corpus copies those same bytes to
/// musl's ABI name at `/lib/libc.musl-x86_64.so.1`. Both the process root and
/// the direct interpreter's installation prefix may contain these aliases.
/// Moving the interpreter changes its path-file lookup without requiring the
/// configured absolute library paths to move with it.
#[cfg(feature = "x86_64-owned-dynamic-runtime")]
const CANONICAL_LIBC_ALIAS_SUFFIXES: [&[u8]; 2] = [
    b"/usr/lib/libc.so",
    b"/lib/libc.musl-x86_64.so.1",
];

#[cfg(feature = "x86_64-owned-dynamic-runtime")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CanonicalInitialLibc {
    index: usize,
    identity: ObjectIdentity,
}

/// Select an opened canonical alias directly when it is the graph's only
/// library. Otherwise resolve every declared root/prefix alias and reduce the
/// complete set to stable library identities already retained by the graph.
/// An absent alias or an identity outside the graph has no startup authority.
/// Neither root takes priority. Two loaded libc identities fail closed even
/// when one matches the invocation prefix. Mark the receiver only after the
/// selection succeeds.
#[cfg(feature = "x86_64-owned-dynamic-runtime")]
unsafe fn select_canonical_initial_libc(
    graph: &InitialGraphState,
    objects: &mut ObjectTable,
) -> Option<CanonicalInitialLibc> {
    // A merged interpreter/libc image is the canonical libc by construction:
    // its identity is the interpreter's own kernel mapping, not an opened
    // pathname. Mark that one object and skip every alias open/stat.
    if let Some(index) = objects[..graph.object_count()]
        .iter()
        .position(|object| object.interpreter_self)
    {
        for (other, object) in objects[..graph.object_count()].iter().enumerate() {
            if other == index { continue; }
            let stored = object.search_name.bytes();
            let basename = stored.iter().rposition(|byte| *byte == b'/').map_or(stored, |at| &stored[at + 1..]);
            if reserved_runtime_name(basename) || basename == b"libc.so" {
                return None;
            }
        }
        let object = objects.get_mut(index)?;
        if object.role != ObjectRole::Library || object.canonical_libc_identity.is_some() {
            return None;
        }
        let identity = graph.identity(index)?;
        object.canonical_libc_identity = Some(identity);
        return Some(CanonicalInitialLibc { index, identity });
    }
    let invocation_prefix = unsafe { x86_64_library_search::installation_prefix() };
    let selected = if let Some(selected) = single_library_opened_canonical_alias(graph, objects, invocation_prefix) {
        selected
    } else {
        let mut aliases = [None; 2 * CANONICAL_LIBC_ALIAS_SUFFIXES.len()];
        for (root_index, prefix) in [b"".as_slice(), invocation_prefix].into_iter().enumerate() {
            if root_index == 1 && prefix.is_empty() {
                continue;
            }
            for (alias_index, suffix) in CANONICAL_LIBC_ALIAS_SUFFIXES.into_iter().enumerate() {
                aliases[root_index * CANONICAL_LIBC_ALIAS_SUFFIXES.len() + alias_index] =
                    match opened_alias_identity(graph, objects, prefix, suffix) {
                        Some(identity) => Some(identity),
                        None => unsafe { canonical_libc_alias_identity(prefix, suffix) }.ok()?,
                    };
            }
        }
        canonical_initial_libc_from_aliases(graph, &aliases)?
    };
    if objects[..graph.object_count()]
        .iter()
        .any(|object| object.canonical_libc_identity.is_some())
    {
        return None;
    }
    let object = objects.get_mut(selected.index)?;
    if object.role != ObjectRole::Library {
        return None;
    }
    object.canonical_libc_identity = Some(selected.identity);
    Some(selected)
}

/// A graph with only one admitted library cannot contain a conflicting libc
/// receiver. If its opened path is a declared alias, the descriptor's fstat
/// already supplies the only identity an alias scan could select. Other alias
/// paths may name this library, the main image, or an unloaded file, none of
/// which changes that selection.
#[cfg(feature = "x86_64-owned-dynamic-runtime")]
fn single_library_opened_canonical_alias(
    graph: &InitialGraphState,
    objects: &[Object],
    invocation_prefix: &[u8],
) -> Option<CanonicalInitialLibc> {
    if graph.object_count() != 2 || objects.get(1)?.role != ObjectRole::Library {
        return None;
    }
    let identity = graph.identity(1)?;
    for prefix in [b"".as_slice(), invocation_prefix] {
        for suffix in CANONICAL_LIBC_ALIAS_SUFFIXES {
            if opened_alias_identity(graph, objects, prefix, suffix) == Some(identity) {
                return Some(CanonicalInitialLibc { index: 1, identity });
            }
        }
    }
    None
}

/// The identity of a graph library this transaction opened by exactly the
/// alias path `prefix`+`suffix`: its descriptor's fstat already named the
/// file that path resolved to, so no second stat is needed. Any other alias
/// is still resolved by [`canonical_libc_alias_identity`].
#[cfg(feature = "x86_64-owned-dynamic-runtime")]
fn opened_alias_identity(
    graph: &InitialGraphState,
    objects: &[Object],
    prefix: &[u8],
    suffix: &[u8],
) -> Option<ObjectIdentity> {
    (1..graph.object_count()).find_map(|index| {
        let object = objects.get(index)?;
        if object.role != ObjectRole::Library { return None; }
        // SAFETY: the graph object owns its search name for the transaction.
        let name = unsafe { object.search_name.bytes() };
        (name.len() == prefix.len() + suffix.len() && name.starts_with(prefix) && name.ends_with(suffix))
            .then(|| graph.identity(index))
            .flatten()
    })
}

#[cfg(feature = "x86_64-owned-dynamic-runtime")]
unsafe fn canonical_libc_alias_identity(
    prefix: &[u8],
    suffix: &[u8],
) -> Result<Option<ObjectIdentity>, ()> {
    let length = prefix.len().checked_add(suffix.len()).ok_or(())?;
    let mut path = super::x86_64_runtime_memory::LoaderBuffer::new(length.checked_add(1).ok_or(())?, 0u8).ok_or(())?;
    path.as_mut_slice()[..prefix.len()].copy_from_slice(prefix);
    path.as_mut_slice()[prefix.len()..length].copy_from_slice(suffix);
    // One stat names the same file an open would (symlinks followed, the
    // same search permissions) without the open/fstat/close round trip. Only
    // an identity already in the graph grants authority, and such a file is
    // readable by construction; an unreadable alias outside the graph is
    // ignored like an absent one. Any other failure still fails closed.
    match unsafe { FileStatus::of_path(path.as_slice().as_ptr()) } {
        Ok(status) => status.identity().map(Some).ok_or(()),
        Err(2) => Ok(None), // ENOENT
        Err(_) => Err(()),
    }
}

#[cfg(feature = "x86_64-owned-dynamic-runtime")]
fn canonical_initial_libc_from_aliases(
    graph: &InitialGraphState,
    aliases: &[Option<ObjectIdentity>],
) -> Option<CanonicalInitialLibc> {
    let mut selected = None;
    for identity in aliases.iter().copied().flatten() {
        let Some(index) = graph.find(identity) else {
            // A compatibility alias may exist in the installation without
            // being loaded by this process. Only a retained graph identity
            // can authorize this private libc receiver.
            continue;
        };
        if index == 0 {
            // A canonical alias that names the main executable cannot grant
            // that executable the private shared-libc receiver role.
            continue;
        }
        let candidate = CanonicalInitialLibc { index, identity };
        match selected {
            None => selected = Some(candidate),
            Some(existing) if existing == candidate => {}
            Some(_) => return None,
        }
    }
    selected
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
    objects: &mut ObjectTable,
    parent_index: usize,
) -> Option<()> {
    #[cfg(feature = "x86_64-owned-dynamic-runtime")]
    {
        if parent_index != 0 { return None; }
        // Musl load_preload has no requesting DSO. Successfully admitted
        // preloads become main pseudo-dependencies before ordinary NEEDED
        // edges, preserving main-first global scope and constructor order.
        let preloads = x86_64_library_search::preloads();
        // C isspace includes vertical tab; Rust ASCII whitespace does not.
        for name in preloads.split(|byte| matches!(byte, b':' | b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)).filter(|name| !name.is_empty()) {
            if let Some(index) = load_initial_library(graph, objects, None, name).ok()? {
                if !graph.edges(0)?.contains(&index) { graph.attach_needed(0, index).ok()?; }
            }
        }
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

#[cfg(feature = "x86_64-owned-dynamic-runtime")]
unsafe fn discover_object_needed(
    graph: &mut InitialGraphState,
    objects: &mut ObjectTable,
    parent_index: usize,
) -> Option<()> {
    let parent = *objects.get(parent_index)?;
    for needed_index in 0..parent.needed_count {
        let offset = needed_name_offset(&parent, needed_index)?;
        let name = parent.strtab.add(offset);
        let length = bounded_nul(name, parent.strsz.checked_sub(offset)?)?;
        let child = load_initial_library(graph, objects, Some(parent_index),
            core::slice::from_raw_parts(name, length)).ok()??;
        graph.attach_needed(parent_index, child).ok()?;
    }
    Some(())
}

/// Whether this interpreter is also the libc half: the merged link carries
/// `SONAME libc.so`. The split loader has no SONAME, so the same source keeps
/// its existing open-a-second-image path.
#[cfg(feature = "x86_64-owned-dynamic-runtime")]
unsafe fn interpreter_soname_is_libc() -> bool {
    let base = super::interpreter_base();
    if base == 0 { return false; }
    let header = base as *const u8;
    let Some(phoff) = usize::try_from(unsafe { read_u64(header.add(32)) }).ok() else { return false; };
    let phnum = unsafe { read_u16(header.add(56)) } as usize;
    let Some(phdr_base) = base.checked_add(phoff) else { return false; };
    let mut dynamic = core::ptr::null::<u8>();
    let mut dynamic_bytes = 0usize;
    for index in 0..phnum {
        let phdr = (phdr_base + index * 56) as *const u8;
        if unsafe { read_u32(phdr) } != 2 { continue; }
        let Some(address) = usize::try_from(unsafe { read_u64(phdr.add(16)) }).ok() else { return false; };
        let Some(bytes) = usize::try_from(unsafe { read_u64(phdr.add(40)) }).ok() else { return false; };
        let Some(pointer) = base.checked_add(address) else { return false; };
        dynamic = pointer as *const u8;
        dynamic_bytes = bytes;
        break;
    }
    if dynamic.is_null() || dynamic_bytes % 16 != 0 { return false; }
    let (mut strtab, mut strsz, mut soname) = (0usize, 0usize, None);
    for index in 0..dynamic_bytes / 16 {
        let entry = unsafe { dynamic.add(index * 16) };
        let tag = unsafe { read_i64(entry) };
        if tag == 0 { break; }
        let Some(value) = usize::try_from(unsafe { read_u64(entry.add(8)) }).ok() else { return false; };
        match tag {
            5 => strtab = value,
            10 => strsz = value,
            14 => soname = Some(value),
            _ => {}
        }
    }
    let Some(offset) = soname else { return false; };
    let Some(start) = base.checked_add(strtab).and_then(|table| table.checked_add(offset)) else { return false; };
    let Some(available) = strsz.checked_sub(offset) else { return false; };
    let name = start as *const u8;
    let Some(length) = (unsafe { bounded_nul(name, available) }) else { return false; };
    let found = unsafe { core::slice::from_raw_parts(name, length) };
    found == b"libc.so"
}

/// Admit the kernel-mapped interpreter as graph object 1 for its own
/// `DT_NEEDED` name. The image is already mapped at `AT_BASE`; discovery must
/// not open, stat, pread or map a second copy of it.
#[cfg(feature = "x86_64-owned-dynamic-runtime")]
unsafe fn admit_interpreter_self(
    graph: &mut InitialGraphState,
    objects: &mut ObjectTable,
    requester: Option<usize>,
    name: &[u8],
    short_name: bool,
) -> Result<Option<usize>, ()> {
    if let Some(index) = objects[..graph.object_count()]
        .iter()
        .position(|object| object.interpreter_self)
    {
        objects[index].search_short_name |= short_name;
        return Ok(Some(index));
    }
    if !unsafe { interpreter_soname_is_libc() } { return Ok(None); }
    let base = super::interpreter_base();
    let header = base as *const u8;
    let phoff = usize::try_from(unsafe { read_u64(header.add(32)) }).ok().ok_or(())?;
    let phnum = unsafe { read_u16(header.add(56)) } as usize;
    let phdr = base.checked_add(phoff).ok_or(())? as *const u8;
    let mut object = match unsafe {
        parse_mapped(base as u64, phdr, phnum, ObjectRole::Library, false, true)
    } {
        Some(object) => object,
        None => fail(b"selfparse\n"),
    };
    object.interpreter_self = true;
    // `_start` has already applied the merged image's packed RELR records.
    object.relr = core::ptr::null();
    object.relrsz = 0;
    let index = match unsafe { graph.admit_interpreter(DEFERRED_SELF_IDENTITY) } {
        Ok(ObjectAdmission::New { index }) => index,
        Ok(ObjectAdmission::Existing { .. }) | Err(_) => fail(b"selfadmit\n"),
    };
    let fallback = super::x86_64_library_search::LoadedName::new(name);
    let Some(search_name) = unsafe { installed_self_canonical_name() }
        .or_else(|| unsafe { lazy_self_identity().and_then(|identity| canonical_self_name(identity)) })
        .or(fallback)
    else { return Err(()); };
    let Some(search_name) = objects.retain_name(search_name) else { return Err(()); };
    object.search_name = search_name;
    object.search_short_name = true;
    object.initial_load_name_is_short = short_name;
    object.needed_by = requester;
    if objects.set(index, object).is_none() { return Err(()); }
    Ok(Some(index))
}

/// The canonical installed libc path whose identity matches this interpreter.
/// A normal installation hardlinks the interpreter and `usr/lib/libc.so`, so
/// `dladdr`/`dl_iterate_phdr` name the self by the libc alias rather than the
/// interpreter path.
#[cfg(feature = "x86_64-owned-dynamic-runtime")]
unsafe fn canonical_self_name(identity: ObjectIdentity) -> Option<super::x86_64_library_search::LoadedName> {
    let prefix = unsafe { x86_64_library_search::installation_prefix() };
    let suffix = b"/usr/lib/libc.so";
    let mut path = [0u8; 4096];
    for candidate_prefix in [prefix, b"".as_slice()] {
        let length = candidate_prefix.len().checked_add(suffix.len())?;
        if length >= path.len() { continue; }
        path[..candidate_prefix.len()].copy_from_slice(candidate_prefix);
        path[candidate_prefix.len()..length].copy_from_slice(suffix);
        let Ok(status) = (unsafe { FileStatus::of_path(path.as_ptr()) }) else { continue; };
        if status.identity() == Some(identity) {
            return super::x86_64_library_search::LoadedName::new(&path[..length]);
        }
    }
    None
}

/// The declared installed libc aliases, under the process root or the
/// interpreter's installation prefix. A search override that resolves a
/// reserved name elsewhere is a second identity and fails closed.
#[cfg(feature = "x86_64-owned-dynamic-runtime")]
pub(crate) unsafe fn canonical_libc_path(path: &[u8]) -> bool {
    const SUFFIXES: [&[u8]; 2] = [b"/usr/lib/libc.so", b"/lib/libc.musl-x86_64.so.1"];
    let prefix = unsafe { x86_64_library_search::installation_prefix() };
    for root in [b"".as_slice(), prefix] {
        for suffix in SUFFIXES {
            if path.len() == root.len() + suffix.len()
                && path.starts_with(root) && path.ends_with(suffix)
            {
                return true;
            }
        }
    }
    false
}

/// A missing/unmappable library is optional only for load_preload. Structural
/// transaction failures cannot be mistaken for an ignored preload. Every
/// admitted map immediately enters the common rollback owner before more I/O.
#[cfg(feature = "x86_64-owned-dynamic-runtime")]
unsafe fn load_initial_library(
    graph: &mut InitialGraphState,
    objects: &mut ObjectTable,
    requester: Option<usize>,
    name: &[u8],
) -> Result<Option<usize>, ()> {
    if cfg!(crabc_hardened) && name.contains(&b'/') && !name.starts_with(b"/") { return Err(()); }
    let short_name = !name.contains(&b'/');
    if short_name {
        if let Some(index) = objects[..graph.object_count()].iter().position(|object| {
            if !object.search_short_name { return false; }
            let stored = object.search_name.bytes();
            loaded_path_matches_short_name(stored, name)
        }) { return Ok(Some(index)); }
    }
    let self_name = reserved_runtime_name(name)
        || name == unsafe { x86_64_library_search::interpreter_name() }
        || unsafe { canonical_libc_path(name) };
    if self_name {
        // Reserved names, the interpreter's own path and the installed libc
        // aliases name this image by construction. The installed product's
        // canonical path is its structural identity, so startup admits it
        // without a search or a stat, as musl's load_library returns `ldso`
        // for a reserved name. A copied or renamed interpreter has no such
        // proof and keeps the conservative override probe.
        if let Some(index) = unsafe { admit_interpreter_self(graph, objects, requester, name, short_name) }? {
            if !unsafe { installed_self_name_is_canonical() } {
                let override_active = x86_64_library_search::search_path_override()
                    || objects.get(0).is_some_and(|object| !object.runpath.is_null());
                if override_active {
                    let mut ancestor = requester;
                    let chain = core::iter::from_fn(|| {
                        let object = objects.get(ancestor?)?;
                        ancestor = object.needed_by;
                        Some(object)
                    });
                    if let Ok((fd, path)) = x86_64_library_search::open(name, chain) {
                        let status = FileStatus::of_fd(fd).ok();
                        syscall1(SYS_CLOSE, fd);
                        if let Some(probe) = status.and_then(|status| status.identity()) {
                            let canonical = canonical_libc_path(path.view().bytes());
                            if !unsafe { self_identity_matches(probe) } && !canonical {
                                fail(b"libcidentity\n");
                            }
                            if canonical {
                                if let Some(retained) = objects.retain_name(path) {
                                    objects[index].search_name = retained;
                                }
                            }
                        }
                    }
                }
            }
            return Ok(Some(index));
        }
    }
    let mut ancestor = requester;
    let chain = core::iter::from_fn(|| {
        let object = objects.get(ancestor?)?;
        ancestor = object.needed_by;
        Some(object)
    });
    let (fd, search_name) = match x86_64_library_search::open(name, chain) {
        Ok(opened) => opened,
        Err(_) => return Ok(None),
    };
    let Some((status, identity)) = FileStatus::of_fd(fd).ok()
        .and_then(|status| status.identity().map(|identity| (status, identity)))
    else { syscall1(SYS_CLOSE, fd); return Ok(None); };
    if let Some(self_index) = objects[..graph.object_count()]
        .iter().position(|object| object.interpreter_self)
    {
        if unsafe { self_identity_matches(identity) } {
            syscall1(SYS_CLOSE, fd);
            objects[self_index].search_short_name |= short_name;
            return Ok(Some(self_index));
        }
    }
    if let Some(index) = graph.find(identity) {
        syscall1(SYS_CLOSE, fd);
        objects[index].search_short_name |= short_name;
        return Ok(Some(index));
    }
    let object = map_elf_with_status(fd, &status, false, true, ObjectRole::Library).ok();
    syscall1(SYS_CLOSE, fd);
    let Some(mut object) = object else {
        return if cfg!(crabc_hardened) { Err(()) } else { Ok(None) };
    };
    if unsafe { mapped_soname_is_libc(&object) } {
        if objects[..graph.object_count()].iter().any(|object| object.interpreter_self) {
            if !unsafe { self_identity_matches(identity) } {
                unmap_object(&object);
                fail(b"libcidentity\n");
            }
        } else if unsafe { interpreter_soname_is_libc() } {
            unmap_object(&object);
            fail(b"libcidentity\n");
        }
    }
    let index = match graph.admit_mapped(identity) {
        Ok(ObjectAdmission::New { index }) => index,
        Ok(ObjectAdmission::Existing { .. }) | Err(_) => {
            unmap_object(&object);
            return Err(());
        }
    };
    let Some(search_name) = objects.retain_name(search_name) else {
        unmap_object(&object);
        return Err(());
    };
    object.search_name = search_name;
    object.search_short_name = short_name;
    object.initial_load_name_is_short = short_name;
    object.needed_by = requester;
    if objects.set(index, object).is_none() {
        unmap_object(&object);
        return Err(());
    }
    Ok(Some(index))
}

/// Compare a slash-free requested name with a retained path's final component.
/// The caller has already excluded slashes from `name`, so its length locates
/// the only possible component boundary without searching the whole path.
#[cfg(feature = "x86_64-owned-dynamic-runtime")]
fn loaded_path_matches_short_name(path: &[u8], name: &[u8]) -> bool {
    let Some(prefix_len) = path.len().checked_sub(name.len()) else { return false; };
    (prefix_len == 0 || path[prefix_len - 1] == b'/') && &path[prefix_len..] == name
}

#[cfg(all(test, feature = "x86_64-owned-dynamic-runtime"))]
mod short_name_tests {
    use super::loaded_path_matches_short_name;

    #[test]
    fn retained_path_matches_only_its_final_short_component() {
        for (path, name, expected) in [
            (b"/app/lib/libfoo.so".as_slice(), b"libfoo.so".as_slice(), true),
            (b"libfoo.so", b"libfoo.so", true),
            (b"/app/lib//libfoo.so", b"libfoo.so", true),
            (b"/app/lib/libfoo.so", b"foo.so", false),
            (b"/app/lib/libfoo.so", b"libfoo.s", false),
            (b"/app/lib/libfoo.so", b"libfoobar.so", false),
            (b"/app/lib/other.so", b"libfoo.so", false),
        ] {
            assert_eq!(loaded_path_matches_short_name(path, name), expected);
        }
    }
}

// Legacy source roots retain their original depth-first, explicit-RUNPATH
// graph proof. They do not capture preload or system policy from the host.
#[cfg(not(feature = "x86_64-owned-dynamic-runtime"))]
unsafe fn discover_object_needed(
    graph: &mut InitialGraphState,
    objects: &mut ObjectTable,
    parent_index: usize,
) -> Option<()> {
    let parent = *objects.get(parent_index)?;
    if parent.runpath.is_null() && parent.needed_count != 0 {
        return None;
    }
    for needed_index in 0..parent.needed_count {
        let name_offset = needed_name_offset(&parent, needed_index)?;
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
        if objects.set(child_index, child).is_none() {
            unmap_object(&child);
            return None;
        }
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

unsafe fn rollback_general_initial_state(
    state: &mut GeneralInitialLoaderState,
    stage: GeneralInitialPreparationStage,
) {
    state.abort(stage, |object| unsafe { unmap_object(object) });
}

unsafe fn unmap_object(object: &Object) {
    if object.map_provenance != ObjectMapProvenance::Transaction
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

#[cfg(all(test, feature = "x86_64-owned-dynamic-runtime"))]
mod canonical_libc_tests {
    use super::*;

    const MAIN: ObjectIdentity = ObjectIdentity { device: 1, inode: 1 };
    const LIBC: ObjectIdentity = ObjectIdentity { device: 1, inode: 2 };
    const OTHER: ObjectIdentity = ObjectIdentity { device: 1, inode: 3 };

    fn graph() -> InitialGraphState {
        let mut graph = InitialGraphState::new(MAIN);
        assert!(matches!(
            graph.admit_mapped(LIBC),
            Ok(ObjectAdmission::New { index: 1 })
        ));
        assert!(matches!(
            graph.admit_mapped(OTHER),
            Ok(ObjectAdmission::New { index: 2 })
        ));
        graph
    }

    fn opened_library(path: &[u8], second_library: bool) -> GeneralInitialLoaderState {
        let mut state = GeneralInitialLoaderState::new(MAIN, EMPTY_OBJECT).unwrap();
        let (graph, objects) = state.discovery_mut().unwrap();
        assert!(matches!(graph.admit_mapped(LIBC), Ok(ObjectAdmission::New { index: 1 })));
        let name = objects.retain_name(x86_64_library_search::LoadedName::new(path).unwrap()).unwrap();
        objects.set(1, Object { role: ObjectRole::Library, search_name: name, ..EMPTY_OBJECT }).unwrap();
        if second_library {
            assert!(matches!(graph.admit_mapped(OTHER), Ok(ObjectAdmission::New { index: 2 })));
            objects.set(2, Object { role: ObjectRole::Library, ..EMPTY_OBJECT }).unwrap();
        }
        state
    }

    #[test]
    fn single_opened_canonical_libc_needs_no_second_alias_lookup() {
        let state = opened_library(b"/usr/lib/libc.so", false);
        let graph = state.graph_during_transaction().unwrap();
        let objects = state.objects_during_transaction().unwrap();
        let selected = Some(CanonicalInitialLibc { index: 1, identity: LIBC });
        assert_eq!(single_library_opened_canonical_alias(graph, objects, b""), selected);
        for other_alias in [None, Some(MAIN), Some(LIBC), Some(OTHER)] {
            assert_eq!(canonical_initial_libc_from_aliases(graph, &[Some(LIBC), other_alias]), selected);
        }
    }

    #[test]
    fn canonical_alias_shortcut_requires_one_opened_library() {
        for (path, prefix, second_library, admitted) in [
            (b"/usr/lib/libc.so".as_slice(), b"".as_slice(), true, false),
            (b"/app/lib/libc.so", b"".as_slice(), false, false),
            (b"/opt/crabc/usr/lib/libc.so", b"/opt/crabc".as_slice(), false, true),
        ] {
            let state = opened_library(path, second_library);
            assert_eq!(
                single_library_opened_canonical_alias(
                    state.graph_during_transaction().unwrap(),
                    state.objects_during_transaction().unwrap(),
                    prefix,
                ).is_some(),
                admitted,
            );
        }
    }

    #[test]
    fn canonical_libc_aliases_unify_only_one_retained_identity() {
        let graph = graph();
        assert_eq!(
            canonical_initial_libc_from_aliases(&graph, &[Some(LIBC), Some(LIBC)]),
            Some(CanonicalInitialLibc { index: 1, identity: LIBC }),
        );
        assert_eq!(
            canonical_initial_libc_from_aliases(&graph, &[Some(LIBC), Some(OTHER)]),
            None,
        );
        assert_eq!(
            canonical_initial_libc_from_aliases(
                &graph,
                &[Some(LIBC), Some(ObjectIdentity { device: 9, inode: 9 })],
            ),
            Some(CanonicalInitialLibc { index: 1, identity: LIBC }),
        );
        assert_eq!(
            canonical_initial_libc_from_aliases(
                &graph,
                &[Some(ObjectIdentity { device: 9, inode: 9 }), None],
            ),
            None,
        );
        assert_eq!(canonical_initial_libc_from_aliases(&graph, &[None, None]), None);
    }

    #[test]
    fn canonical_libc_root_and_invocation_aliases_have_no_priority() {
        let graph = graph();
        let expected = Some(CanonicalInitialLibc { index: 1, identity: LIBC });
        let unloaded = ObjectIdentity { device: 9, inode: 9 };
        for aliases in [
            [Some(LIBC), None, None, None],
            [Some(unloaded), None, Some(LIBC), None],
            [Some(LIBC), None, Some(LIBC), Some(LIBC)],
            [Some(MAIN), None, Some(LIBC), None],
        ] {
            assert_eq!(canonical_initial_libc_from_aliases(&graph, &aliases), expected);
        }
        for aliases in [
            [Some(LIBC), None, Some(OTHER), None],
            [Some(OTHER), None, Some(LIBC), None],
            [Some(MAIN), None, Some(unloaded), None],
        ] {
            assert_eq!(canonical_initial_libc_from_aliases(&graph, &aliases), None);
        }
    }
}
