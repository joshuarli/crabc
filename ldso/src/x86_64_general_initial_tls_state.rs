//! Loader-owned state for one x86-64 general initial TLS population.
//!
//! The general initial graph discovers an arbitrary bounded `DT_NEEDED`
//! topology through `x86_64_general_initial_loader_state.rs`, which is the
//! sole durable owner of graph identity, object metadata, map spans, and TLS
//! attachment fields. This sidecar plans the initial module registry and
//! Variant-II allocation against that same object store; it never owns a
//! duplicate graph or object array.
//!
//! The ordinary general-initial-TLS cfg is deliberately not a RuntimeV1
//! producer. Its explicitly separate `crabc_general_loader_libc_tls_runtime_v1`
//! sibling adds one private libc attachment record, but still owns no worker
//! materialization, runtime map entry point, DTV replacement, CRT lifecycle,
//! or module unload operation. In particular, every runtime TLS request is
//! rejected through the typed registry before it could create a mapping or
//! mutate a DTV slot.

#![allow(dead_code, unexpected_cfgs)]

use super::*;
use super::x86_64_general_initial_loader_state::{
    GeneralInitialLoaderPhase, GeneralInitialLoaderState, GeneralInitialLoaderStateError,
    GeneralInitialPreparationStage,
};
use super::x86_64_initial_graph_state::ObjectIdentity;
use super::x86_64_initial_tls_registry::{
    InitialTlsGeneration, InitialTlsRegistry, RegistryPhase, RuntimeTlsGrowthError, TlsModuleId,
};
use core::mem::MaybeUninit;
#[cfg(crabc_general_loader_libc_tls_runtime_v1)]
use core::sync::atomic::{AtomicU8, Ordering};

type GeneralInitialTlsRegistry = InitialTlsRegistry<MAX_OBJECTS, MAX_OBJECTS>;

/// The one-way lifecycle of a general initial TLS transaction.
///
/// The only terminal successful phase is [`Committed`].  [`RolledBack`]
/// records that the graph's transaction-created mappings and all uncommitted
/// TLS bookkeeping have been discarded before `%fs` was installed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GeneralInitialTlsPhase {
    Discovery,
    Planned,
    Relocated,
    PublicationReserved,
    RuntimeV1PublicationReserved,
    Materialized,
    Committed,
    RolledBack,
}

/// Fail-closed reasons this bounded materialization cannot proceed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GeneralInitialTlsStateError {
    InvalidPhase,
    GraphIncomplete,
    InvalidTemplate,
    LayoutOverflow,
    ModuleCapacity,
    Registry,
    Materialization,
    PublicationUnavailable,
    RuntimeV1PublicationUnavailable,
    #[cfg(crabc_general_initial_lifecycle)]
    LifecycleIncomplete,
}

fn map_loader_state_error(error: GeneralInitialLoaderStateError) -> GeneralInitialTlsStateError {
    match error {
        GeneralInitialLoaderStateError::InvalidPhase => GeneralInitialTlsStateError::InvalidPhase,
        GeneralInitialLoaderStateError::GraphIncomplete => GeneralInitialTlsStateError::GraphIncomplete,
        #[cfg(crabc_general_initial_lifecycle)]
        GeneralInitialLoaderStateError::LifecycleIncomplete => GeneralInitialTlsStateError::LifecycleIncomplete,
        GeneralInitialLoaderStateError::PublicationUnavailable => {
            GeneralInitialTlsStateError::PublicationUnavailable
        }
    }
}

/// Exact main-thread coordinates retained by the loader after `ARCH_SET_FS`.
///
/// The mapping remains process-lifetime state in this slice. These fields are
/// private loader state; the cfg-isolated RuntimeV1 producer below copies only
/// the ABI-required main-thread coordinates into its distinct descriptor.
#[derive(Clone, Copy)]
struct GeneralInitialTlsAllocation {
    mapping: *mut u8,
    mapping_byte_len: usize,
    thread_pointer: *mut u8,
    dtv: *mut usize,
    dtv_words: usize,
    module_count: usize,
}

/// One bounded general initial-TLS planner.
///
/// Its `loader` field is the common graph/object owner until commit; the
/// registry/allocation become a TLS-only sidecar attached to that same owner.
/// Object indices are graph-order identities. A TLS-free object owns no
/// module ID, so the registry is the only mapping from object identity/order
/// to a one-based ELF TLS module number.
pub(crate) struct GeneralInitialTlsState {
    phase: GeneralInitialTlsPhase,
    loader: GeneralInitialLoaderState,
    registry: GeneralInitialTlsRegistry,
}

/// TLS-specific retained coordinates attached to the canonical loader state.
///
/// This record deliberately contains no `InitialGraphState` or `[Object; _]`:
/// those facts are immutable members of `GeneralInitialLoaderState`. Its
/// visibility is guarded by that owner's acquire/release `Ready` word.
struct GeneralInitialTlsAttachment {
    registry: GeneralInitialTlsRegistry,
    allocation: GeneralInitialTlsAllocation,
}

// `#[used]` is intentional: the direct resolver uses the TCB/DTV
// coordinates, while this sidecar retains their generation-one registry and
// allocation under the common loader owner's publication boundary.
#[used]
#[link_section = ".bss.crabc_general_initial_tls_attachment"]
static mut GENERAL_INITIAL_TLS_ATTACHMENT: MaybeUninit<GeneralInitialTlsAttachment> =
    MaybeUninit::uninit();

/// Writes the TLS-only sidecar before the common loader state becomes Ready.
///
/// # Safety
///
/// The caller must hold the common loader owner's `Reserved` slot and must
/// call this exactly once in the non-fallible post-`ARCH_SET_FS` tail.
unsafe fn publish_initial_tls_attachment(
    registry: GeneralInitialTlsRegistry,
    installed: InstalledInitialTls,
) {
    let attachment = GeneralInitialTlsAttachment {
        registry,
        allocation: GeneralInitialTlsAllocation {
            mapping: installed.mapping,
            mapping_byte_len: installed.mapping_byte_len,
            thread_pointer: installed.thread_pointer,
            dtv: installed.dtv,
            dtv_words: installed.dtv_words,
            module_count: installed.module_count,
        },
    };
    // SAFETY: common-state publication remains `Reserved`, so no reader can
    // observe this sidecar until its later release store to `Ready`.
    unsafe {
        core::ptr::write(
            core::ptr::addr_of_mut!(GENERAL_INITIAL_TLS_ATTACHMENT)
                .cast::<GeneralInitialTlsAttachment>(),
            attachment,
        );
    }
}

// -------------------------------------------------------------------------
// Private general loader/libc RuntimeV1 descriptor
// -------------------------------------------------------------------------
//
// This descriptor mirrors the fixed RuntimeV1 ABI, but it deliberately has
// separate storage and a separate cfg. Reusing the fixed producer would put a
// fallible descriptor reservation after ARCH_SET_FS, which is not a rollback-
// safe transaction for the arbitrary initial graph. The general state reserves
// this record while the incoming FS base is still intact, then commits the
// retained graph state and descriptor with no fallible successor.
#[cfg(crabc_general_loader_libc_tls_runtime_v1)]
const GENERAL_LOADER_TLS_RUNTIME_V1_MAGIC: u64 =
    if cfg!(crabc_general_loader_libc_tls_runtime_v1_bad_magic) {
        0
    } else {
        0x4352_4142_435f_5451
    };
#[cfg(crabc_general_loader_libc_tls_runtime_v1)]
const GENERAL_LOADER_TLS_RUNTIME_V1_VERSION: u32 =
    if cfg!(crabc_general_loader_libc_tls_runtime_v1_bad_version) {
        0
    } else {
        1
    };
#[cfg(crabc_general_loader_libc_tls_runtime_v1)]
const GENERAL_LOADER_TLS_RUNTIME_V1_PROCESS_MODE_DYNAMIC: u32 =
    if cfg!(crabc_general_loader_libc_tls_runtime_v1_bad_mode) {
        0
    } else {
        2
    };
#[cfg(crabc_general_loader_libc_tls_runtime_v1)]
const GENERAL_LOADER_TLS_RUNTIME_V1_OWNER_LDSO: u32 =
    if cfg!(crabc_general_loader_libc_tls_runtime_v1_bad_owner) {
        0
    } else {
        1
    };
#[cfg(crabc_general_loader_libc_tls_runtime_v1)]
const GENERAL_LOADER_TLS_RUNTIME_V1_GENERATION_INITIAL: u64 =
    if cfg!(crabc_general_loader_libc_tls_runtime_v1_bad_generation) {
        0
    } else {
        1
    };
#[cfg(crabc_general_loader_libc_tls_runtime_v1)]
const GENERAL_LOADER_TLS_RUNTIME_V1_STATE_UNPUBLISHED: u8 = 0;
#[cfg(crabc_general_loader_libc_tls_runtime_v1)]
const GENERAL_LOADER_TLS_RUNTIME_V1_STATE_PUBLISHING: u8 = 1;
#[cfg(crabc_general_loader_libc_tls_runtime_v1)]
const GENERAL_LOADER_TLS_RUNTIME_V1_STATE_READY: u8 = 2;

/// Exact 72-byte private loader/libc ABI for the general initial-TLS graph.
///
/// `state` is the one acquire/release publication word. Its coordinates are
/// written only after the graph registry and fixed DTV geometry were checked
/// before ARCH_SET_FS, and `READY` is the final store after the retained
/// loader state has been written. This is not a public ELF interface.
#[cfg(crabc_general_loader_libc_tls_runtime_v1)]
#[repr(C)]
struct GeneralLoaderLibcTlsRuntimeV1 {
    magic: u64,
    version: u32,
    abi_size: u32,
    process_mode: u32,
    owner: u32,
    state: AtomicU8,
    reserved: [u8; 7],
    thread_pointer: *const u8,
    dtv: *const usize,
    dtv_words: usize,
    module_count: usize,
    generation: u64,
}

#[cfg(crabc_general_loader_libc_tls_runtime_v1)]
const _: () = assert!(core::mem::size_of::<GeneralLoaderLibcTlsRuntimeV1>() == 72);

// The general graph seals the interpreter's own PT_GNU_RELRO before it can
// install %fs. Keep this mutable one-shot record in an explicit writable data
// section rather than allowing a linker to co-locate it with `.data.rel.ro`.
// The native direct and Cargo-root runners reject even page-rounded overlap
// with PT_GNU_RELRO before executing the post-FS commit.
#[cfg(crabc_general_loader_libc_tls_runtime_v1)]
#[used]
#[no_mangle]
#[link_section = ".data.crabc_general_loader_tls_runtime_v1"]
static mut __crabc_x86_64_loader_tls_runtime_v1: GeneralLoaderLibcTlsRuntimeV1 =
    GeneralLoaderLibcTlsRuntimeV1 {
        magic: GENERAL_LOADER_TLS_RUNTIME_V1_MAGIC,
        version: GENERAL_LOADER_TLS_RUNTIME_V1_VERSION,
        abi_size: if cfg!(crabc_general_loader_libc_tls_runtime_v1_bad_abi_size) {
            0
        } else {
            core::mem::size_of::<GeneralLoaderLibcTlsRuntimeV1>() as u32
        },
        process_mode: GENERAL_LOADER_TLS_RUNTIME_V1_PROCESS_MODE_DYNAMIC,
        owner: GENERAL_LOADER_TLS_RUNTIME_V1_OWNER_LDSO,
        state: AtomicU8::new(GENERAL_LOADER_TLS_RUNTIME_V1_STATE_UNPUBLISHED),
        reserved: [0; 7],
        thread_pointer: core::ptr::null(),
        dtv: core::ptr::null(),
        dtv_words: 0,
        module_count: 0,
        generation: GENERAL_LOADER_TLS_RUNTIME_V1_GENERATION_INITIAL,
    };

#[cfg(feature = "x86_64-owned-dynamic-runtime")]
pub(super) fn retained_initial_thread_pointer() -> Option<*mut u8> {
    let record = core::ptr::addr_of!(__crabc_x86_64_loader_tls_runtime_v1);
    if unsafe { (*record).state.load(Ordering::Acquire) } != GENERAL_LOADER_TLS_RUNTIME_V1_STATE_READY { return None; }
    let pointer = unsafe { (*record).thread_pointer } as *mut u8;
    (!pointer.is_null()).then_some(pointer)
}

/// Returns the private static record only for the exact weak main-image
/// relocation exception in `resolve_symbol`.
#[cfg(crabc_general_loader_libc_tls_runtime_v1)]
pub(super) fn loader_tls_runtime_v1_record_address() -> u64 {
    core::ptr::addr_of!(__crabc_x86_64_loader_tls_runtime_v1) as usize as u64
}

#[cfg(crabc_general_loader_libc_tls_runtime_v1)]
fn reserve_loader_tls_runtime_v1_descriptor() -> Result<(), GeneralInitialTlsStateError> {
    let record = core::ptr::addr_of_mut!(__crabc_x86_64_loader_tls_runtime_v1);
    // SAFETY: this is the one initial interpreter transaction and the state
    // owner calls it before ARCH_SET_FS. The paired TLS-state reservation
    // prevents a second successful transaction from reaching this point.
    unsafe {
        (*record).state.compare_exchange(
            GENERAL_LOADER_TLS_RUNTIME_V1_STATE_UNPUBLISHED,
            GENERAL_LOADER_TLS_RUNTIME_V1_STATE_PUBLISHING,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
    }
    .map(|_| ())
    .map_err(|_| GeneralInitialTlsStateError::RuntimeV1PublicationUnavailable)
}

#[cfg(crabc_general_loader_libc_tls_runtime_v1)]
fn release_loader_tls_runtime_v1_descriptor_reservation() {
    let record = core::ptr::addr_of_mut!(__crabc_x86_64_loader_tls_runtime_v1);
    // SAFETY: only the owning pre-FS transaction can still be in PUBLISHING.
    // A release store is the exact rollback for its successful CAS.
    unsafe {
        (*record)
            .state
            .store(GENERAL_LOADER_TLS_RUNTIME_V1_STATE_UNPUBLISHED, Ordering::Release);
    }
}

/// Performs the descriptor half of the non-fallible post-FS commit.
///
/// All graph/registry/DTV-shape validation and both publication CASes happened
/// before ARCH_SET_FS. The malformed test cfgs alter only static metadata or
/// the final DTV pointer so the libc observer can independently reject them;
/// this function intentionally has no validation, allocation, CAS, or error
/// path after the thread pointer changed.
#[cfg(crabc_general_loader_libc_tls_runtime_v1)]
unsafe fn publish_reserved_loader_tls_runtime_v1(installed: InstalledInitialTls) {
    let record = core::ptr::addr_of_mut!(__crabc_x86_64_loader_tls_runtime_v1);
    #[cfg(crabc_general_loader_libc_tls_runtime_v1_poisoned_dtv)]
    let descriptor_dtv = 1usize as *const usize;
    #[cfg(not(crabc_general_loader_libc_tls_runtime_v1_poisoned_dtv))]
    let descriptor_dtv = installed.dtv.cast_const();
    // SAFETY: the descriptor's PUBLISHING ownership was reserved before the
    // sole ARCH_SET_FS transition. `installed` is its successful immutable
    // result, so these field writes cannot fail. READY is intentionally last.
    unsafe {
        (*record).thread_pointer = installed.thread_pointer.cast_const();
        (*record).dtv = descriptor_dtv;
        (*record).dtv_words = installed.dtv_words;
        (*record).module_count = installed.module_count;
        (*record)
            .state
            .store(GENERAL_LOADER_TLS_RUNTIME_V1_STATE_READY, Ordering::Release);
    }
}

impl GeneralInitialTlsState {
    /// Begins a TLS planner against the canonical general loader transaction.
    pub(crate) fn new(main_identity: ObjectIdentity, main: Object) -> Self {
        Self {
            phase: GeneralInitialTlsPhase::Discovery,
            loader: GeneralInitialLoaderState::new(main_identity, main),
            registry: GeneralInitialTlsRegistry::new(),
        }
    }

    pub(crate) const fn phase(&self) -> GeneralInitialTlsPhase {
        self.phase
    }

    pub(crate) fn object_count(&self) -> usize {
        self.loader.object_count()
    }

    pub(crate) fn graph_and_objects_mut(
        &mut self,
    ) -> Result<
        (&mut super::x86_64_initial_graph_state::InitialGraphState, &mut [Object; MAX_OBJECTS]),
        GeneralInitialTlsStateError,
    > {
        if self.phase != GeneralInitialTlsPhase::Discovery {
            return Err(GeneralInitialTlsStateError::InvalidPhase);
        }
        self.loader
            .discovery_mut()
            .map_err(map_loader_state_error)
    }

    /// Returns the sealed initial dependency graph for post-relocation
    /// startup planning. Callers receive no mutation path after discovery.
    pub(crate) fn graph(
        &self,
    ) -> Result<&super::x86_64_initial_graph_state::InitialGraphState, GeneralInitialTlsStateError>
    {
        self.loader
            .graph_during_transaction()
            .map_err(map_loader_state_error)
    }

    pub(crate) fn objects(&self) -> Result<&[Object; MAX_OBJECTS], GeneralInitialTlsStateError> {
        self.loader
            .objects_during_transaction()
            .map_err(map_loader_state_error)
    }

    #[cfg(crabc_general_initial_lifecycle)]
    pub(crate) fn attach_lifecycle(
        &mut self,
        lifecycle: super::x86_64_general_initial_lifecycle::GeneralInitialLifecycle,
    ) -> Result<(), GeneralInitialTlsStateError> {
        self.loader.attach_lifecycle(lifecycle).map_err(map_loader_state_error)
    }

    /// Marks the root graph ready once its recursive discovery completed.
    pub(crate) fn finish_discovery(&mut self) -> Result<(), GeneralInitialTlsStateError> {
        if self.phase != GeneralInitialTlsPhase::Discovery {
            return Err(GeneralInitialTlsStateError::InvalidPhase);
        }
        self.loader.finish_discovery().map_err(map_loader_state_error)
    }

    /// Plans every initial `PT_TLS` image before a relocation can write a
    /// DTPMOD64/DTPOFF64 value.
    ///
    /// The complete plan is first built in local values.  Only after every
    /// descriptor, arithmetic operation, and one-based ID succeeds do the
    /// object records and registry become visible in this state.  A failure
    /// therefore cannot leave a partial DTV geometry for rollback to erase.
    pub(crate) fn plan_initial_tls(&mut self) -> Result<bool, GeneralInitialTlsStateError> {
        if self.phase != GeneralInitialTlsPhase::Discovery {
            return Err(GeneralInitialTlsStateError::InvalidPhase);
        }
        let object_count = self.loader.object_count();
        let graph = self
            .loader
            .graph_during_transaction()
            .map_err(map_loader_state_error)?;
        if object_count == 0
            || (0..object_count).any(|index| {
                graph.state(index) != Some(super::x86_64_initial_graph_state::ObjectState::Ready)
            })
        {
            return Err(GeneralInitialTlsStateError::GraphIncomplete);
        }

        let mut planned_offsets = [0usize; MAX_OBJECTS];
        let mut planned_ids = [0usize; MAX_OBJECTS];
        let mut offset_below_tp = 0usize;
        let mut registry = GeneralInitialTlsRegistry::new();
        let mut has_tls = false;

        let objects = self
            .loader
            .objects_during_transaction()
            .map_err(map_loader_state_error)?;
        for index in 0..object_count {
            let object = &objects[index];
            if object.tls_memsz == 0 {
                continue;
            }
            has_tls = true;
            if object.tls_image.is_null()
                || object.tls_filesz > object.tls_memsz
                || object.tls_align == 0
                || !object.tls_align.is_power_of_two()
            {
                return Err(GeneralInitialTlsStateError::InvalidTemplate);
            }
            let with_alignment_slack = offset_below_tp
                .checked_add(object.tls_memsz)
                .and_then(|value| value.checked_add(object.tls_align - 1))
                .ok_or(GeneralInitialTlsStateError::LayoutOverflow)?;
            let source_phase = object.tls_image as usize & (object.tls_align - 1);
            let placement_phase = with_alignment_slack
                .checked_add(source_phase)
                .ok_or(GeneralInitialTlsStateError::LayoutOverflow)?
                & (object.tls_align - 1);
            offset_below_tp = with_alignment_slack
                .checked_sub(placement_phase)
                .ok_or(GeneralInitialTlsStateError::LayoutOverflow)?;
            if offset_below_tp < object.tls_memsz {
                return Err(GeneralInitialTlsStateError::LayoutOverflow);
            }
            let module_id = registry
                .assign_initial(index)
                .map_err(|_| GeneralInitialTlsStateError::Registry)?;
            if module_id.get() >= TLS_DTV_WORDS {
                return Err(GeneralInitialTlsStateError::ModuleCapacity);
            }
            planned_offsets[index] = offset_below_tp;
            planned_ids[index] = module_id.get();
        }
        registry
            .seal()
            .map_err(|_| GeneralInitialTlsStateError::Registry)?;
        if registry.phase() != RegistryPhase::Sealed || registry.generation().get() != 1 {
            return Err(GeneralInitialTlsStateError::Registry);
        }

        {
            let (_, objects) = self
                .loader
                .discovery_mut()
                .map_err(map_loader_state_error)?;
            for index in 0..object_count {
                objects[index].tls_offset_below_tp = planned_offsets[index];
                objects[index].tls_module_id = planned_ids[index];
            }
        }
        self.loader.attach_initial_tls().map_err(map_loader_state_error)?;
        self.registry = registry;
        self.phase = GeneralInitialTlsPhase::Planned;
        Ok(has_tls)
    }

    /// Records that every admitted object was fully relocated before copying
    /// any TLS template into the main thread.
    pub(crate) fn mark_relocated(&mut self) -> Result<(), GeneralInitialTlsStateError> {
        if self.phase != GeneralInitialTlsPhase::Planned {
            return Err(GeneralInitialTlsStateError::InvalidPhase);
        }
        self.validate_registry_bindings()?;
        self.phase = GeneralInitialTlsPhase::Relocated;
        Ok(())
    }

    /// Seals and reserves the common loader-owned graph before `%fs` can
    /// change.
    ///
    /// The reservation is deliberately separate from [`materialize_initial_tls`]
    /// so a competing/previous publication fails while every transaction
    /// mapping is still rollback-safe.  `rollback` releases `PUBLISHING` back
    /// to `UNPUBLISHED` for every pre-FS error path; a successful materializer
    /// consumes this reservation with the non-fallible commit below.
    pub(crate) fn reserve_publication(&mut self) -> Result<(), GeneralInitialTlsStateError> {
        if self.phase != GeneralInitialTlsPhase::Relocated {
            return Err(GeneralInitialTlsStateError::InvalidPhase);
        }
        self.validate_registry_bindings()?;
        match self.loader.phase() {
            GeneralInitialLoaderPhase::Discovering => {
                self.loader.prepare().map_err(map_loader_state_error)?;
            }
            // A competing transaction can make the first reservation attempt
            // fail after this state has already sealed its graph. Keep that
            // local Prepared state retryable; no graph/object mutation occurs
            // between attempts.
            GeneralInitialLoaderPhase::Prepared => {}
            _ => return Err(GeneralInitialTlsStateError::InvalidPhase),
        }
        self.loader
            .reserve_publication()
            .map_err(map_loader_state_error)?;
        self.phase = GeneralInitialTlsPhase::PublicationReserved;
        Ok(())
    }

    /// Reserves the private RuntimeV1 descriptor while `%fs` is still the
    /// incoming kernel value.
    ///
    /// This is intentionally a second reservation, not a post-install
    /// convenience call. The loader first proves the retained graph's sealed
    /// IDs and fixed DTV geometry, then owns both `PUBLISHING` words before
    /// `ARCH_SET_FS`. Every pre-FS error therefore has an exact paired undo.
    #[cfg(crabc_general_loader_libc_tls_runtime_v1)]
    pub(crate) fn reserve_runtime_v1_publication(
        &mut self,
    ) -> Result<(), GeneralInitialTlsStateError> {
        if self.phase != GeneralInitialTlsPhase::PublicationReserved {
            return Err(GeneralInitialTlsStateError::InvalidPhase);
        }
        self.validate_runtime_v1_preflight()?;
        reserve_loader_tls_runtime_v1_descriptor()?;
        self.phase = GeneralInitialTlsPhase::RuntimeV1PublicationReserved;
        Ok(())
    }

    /// Materializes the completed initial population after every fallible
    /// object mapping, relocation, protection, and RELRO transition has
    /// succeeded and exclusive private-state publication has been reserved.
    /// The only remaining operation after a successful `ARCH_SET_FS` is the
    /// non-fallible private-state commit below.
    pub(crate) unsafe fn materialize_initial_tls(
        &mut self,
    ) -> Result<InstalledInitialTls, GeneralInitialTlsStateError> {
        #[cfg(not(crabc_general_loader_libc_tls_runtime_v1))]
        if self.phase != GeneralInitialTlsPhase::PublicationReserved {
            return Err(GeneralInitialTlsStateError::InvalidPhase);
        }
        #[cfg(crabc_general_loader_libc_tls_runtime_v1)]
        if self.phase != GeneralInitialTlsPhase::RuntimeV1PublicationReserved {
            return Err(GeneralInitialTlsStateError::InvalidPhase);
        }
        self.validate_registry_bindings()?;
        if self
            .registry
            .reject_runtime_tls_growth(self.object_count())
            != Err(RuntimeTlsGrowthError::DtvGrowthProtocolUnavailable)
        {
            return Err(GeneralInitialTlsStateError::Registry);
        }
        if self.registry.module_count() == 0 {
            return Err(GeneralInitialTlsStateError::Materialization);
        }

        // SAFETY: `validate_registry_bindings` proves the object records carry
        // exactly the sealed initial IDs and layout.  All prior graph work is
        // complete; the installer either leaves `%fs` untouched or returns a
        // fully installed, process-lifetime mapping.
        let installed = unsafe {
            install_initial_tls(
                self.loader
                    .objects_during_transaction()
                    .map_err(map_loader_state_error)?,
            )
        }
        .ok_or(GeneralInitialTlsStateError::Materialization)?;
        // `install_initial_tls` validates every input and either returns
        // before `ARCH_SET_FS` or returns these coordinates by construction.
        // Do not add a fallible check after that syscall: a later failure
        // could not safely restore the incoming FS base in this initial-only
        // foundation.
        self.phase = GeneralInitialTlsPhase::Materialized;
        Ok(installed)
    }

    /// Commits this immutable initial-only state to the x86 loader.
    ///
    /// # Safety
    ///
    /// The caller must run in the one initial interpreter transaction.  After
    /// this returns, no caller may retain a mutable reference to `self`; the
    /// committed object mappings and initial TLS allocation become
    /// process-lifetime state until a separately designed loader lifecycle
    /// exists.
    #[cfg(not(crabc_general_loader_libc_tls_runtime_v1))]
    pub(crate) unsafe fn commit(mut self, installed: InstalledInitialTls) {
        // SAFETY: `run_with_initial_tls` obtains the common loader owner's
        // `PublicationReserved` state before it invokes the sole
        // `ARCH_SET_FS` path. `materialize_initial_tls` moves this exact
        // state to `Materialized` only after successful installation, so all
        // input validation and publication arbitration have already
        // completed. This method intentionally contains no branch or
        // fallible operation after `%fs` changes.
        self.phase = GeneralInitialTlsPhase::Committed;
        // SAFETY: the common loader owner is still Reserved, so this sidecar
        // is initialized before the release-published graph/object state.
        unsafe { publish_initial_tls_attachment(self.registry, installed) };
        // SAFETY: all fallible work and the sole FS transition completed; the
        // shared state is now the immutable graph/object/TLS attachment owner.
        unsafe { self.loader.commit() };
    }

    /// Completes the paired general RuntimeV1 handoff after `ARCH_SET_FS`.
    ///
    /// # Safety
    ///
    /// The caller must have reserved both publication words and received this
    /// exact successful `InstalledInitialTls` result. This method deliberately
    /// has no error return, validation branch, or CAS: such a successor could
    /// not safely undo the installed `%fs` base.
    #[cfg(crabc_general_loader_libc_tls_runtime_v1)]
    pub(crate) unsafe fn commit_runtime_v1(mut self, installed: InstalledInitialTls) {
        self.phase = GeneralInitialTlsPhase::Committed;
        // SAFETY: both pre-FS reservations succeeded. Attach TLS metadata to
        // the common graph/object owner before that owner becomes Ready.
        unsafe { publish_initial_tls_attachment(self.registry, installed) };
        // SAFETY: the common state reservation was obtained before ARCH_SET_FS
        // and this is the one process-lifetime retained graph/object snapshot.
        unsafe { self.loader.commit() };
        // SAFETY: the descriptor reservation and every graph/DTV check were
        // complete before ARCH_SET_FS. The descriptor READY store remains
        // intentionally last, after the shared graph owner is Ready.
        unsafe { publish_reserved_loader_tls_runtime_v1(installed) };
    }

    /// Rolls back the map-owned portion of an unsuccessful transaction.
    ///
    /// This function is intentionally unavailable after commit: a general
    /// runtime must first establish reference, thread, and DTV-lifetime rules
    /// before it can ever unmap an initial object or free its TLS storage.
    pub(crate) fn abort(
        &mut self,
        stage: GeneralInitialPreparationStage,
        unmap: impl FnMut(&Object),
    ) {
        // No caller may roll back after materialization: a successful install
        // has changed `%fs`, and the only permitted next transition is the
        // non-fallible commit. All actual error paths remain before that
        // syscall in `PublicationReserved` or an earlier phase.
        if matches!(
            self.phase,
            GeneralInitialTlsPhase::Materialized | GeneralInitialTlsPhase::Committed
        ) {
            return;
        }
        #[cfg(crabc_general_loader_libc_tls_runtime_v1)]
        if self.phase == GeneralInitialTlsPhase::RuntimeV1PublicationReserved {
            release_loader_tls_runtime_v1_descriptor_reservation();
        }
        // The common owner performs the exact reverse-order object rollback
        // and, when Reserved, restores its one shared publication word to
        // Vacant. Slot zero remains kernel-owned and is never presented to
        // `unmap`.
        self.loader.abort(stage, unmap);
        self.registry = GeneralInitialTlsRegistry::new();
        self.phase = GeneralInitialTlsPhase::RolledBack;
    }

    /// Rolls back a TLS planner failure that occurred before the exact stage
    /// was classified by its caller. Production entry code uses [`abort`] so
    /// each mapping/relocation/protection/RELRO/preflight path remains named;
    /// this convenience preserves the narrow unit-test harness.
    pub(crate) fn rollback(&mut self, unmap: impl FnMut(&Object)) {
        self.abort(GeneralInitialPreparationStage::TlsPlanning, unmap);
    }

    pub(crate) fn module_id(&self, object_index: usize) -> Option<TlsModuleId> {
        self.registry.module_id(object_index)
    }

    pub(crate) const fn generation(&self) -> InitialTlsGeneration {
        self.registry.generation()
    }

    /// Makes the absent runtime TLS/DTV-growth protocol explicit at the state
    /// owner.  No map or registry mutation happens before this rejection.
    pub(crate) fn reject_runtime_tls_growth(
        &self,
        object_index: usize,
    ) -> Result<TlsModuleId, RuntimeTlsGrowthError> {
        self.registry.reject_runtime_tls_growth(object_index)
    }

    fn validate_registry_bindings(&self) -> Result<(), GeneralInitialTlsStateError> {
        if self.registry.phase() != RegistryPhase::Sealed
            || self.registry.generation() != InitialTlsGeneration::initial()
        {
            return Err(GeneralInitialTlsStateError::Registry);
        }
        let mut expected_module = 0usize;
        let graph = self
            .loader
            .graph_during_transaction()
            .map_err(map_loader_state_error)?;
        let objects = self
            .loader
            .objects_during_transaction()
            .map_err(map_loader_state_error)?;
        for index in 0..graph.object_count() {
            let object = &objects[index];
            let registry_id = self.registry.module_id(index);
            if object.tls_memsz == 0 {
                if registry_id.is_some() || object.tls_module_id != 0 {
                    return Err(GeneralInitialTlsStateError::Registry);
                }
                continue;
            }
            expected_module = expected_module
                .checked_add(1)
                .ok_or(GeneralInitialTlsStateError::ModuleCapacity)?;
            if expected_module >= TLS_DTV_WORDS
                || registry_id.map(TlsModuleId::get) != Some(expected_module)
                || object.tls_module_id != expected_module
                || object.tls_offset_below_tp < object.tls_memsz
            {
                return Err(GeneralInitialTlsStateError::Registry);
            }
        }
        if self.registry.module_count() != expected_module {
            return Err(GeneralInitialTlsStateError::Registry);
        }
        Ok(())
    }

    /// Validates the complete loader-owned RuntimeV1 geometry before `%fs`
    /// changes. The descriptor receives no graph pointer or mutable registry;
    /// these checks establish that its generation-one module count exactly
    /// fits the installer's fixed DTV prefix before either publication can be
    /// committed.
    #[cfg(crabc_general_loader_libc_tls_runtime_v1)]
    fn validate_runtime_v1_preflight(&self) -> Result<(), GeneralInitialTlsStateError> {
        self.validate_registry_bindings()?;
        let object_count = self.loader.object_count();
        let graph = self
            .loader
            .graph_during_transaction()
            .map_err(map_loader_state_error)?;
        if object_count == 0
            || (0..object_count).any(|index| {
                graph.state(index) != Some(super::x86_64_initial_graph_state::ObjectState::Ready)
            })
        {
            return Err(GeneralInitialTlsStateError::GraphIncomplete);
        }
        let module_count = self.registry.module_count();
        let required_dtv_words = module_count
            .checked_add(1)
            .ok_or(GeneralInitialTlsStateError::ModuleCapacity)?;
        if module_count == 0
            || required_dtv_words > TLS_DTV_WORDS
            || self.registry.generation() != InitialTlsGeneration::initial()
            || self
                .registry
                .reject_runtime_tls_growth(object_count)
                != Err(RuntimeTlsGrowthError::DtvGrowthProtocolUnavailable)
        {
            return Err(GeneralInitialTlsStateError::Registry);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAIN: ObjectIdentity = ObjectIdentity { device: 1, inode: 1 };

    fn tls_object(image: &[u8], memsz: usize, align: usize) -> Object {
        Object {
            tls_image: image.as_ptr(),
            tls_filesz: image.len(),
            tls_memsz: memsz,
            tls_align: align,
            ..EMPTY_OBJECT
        }
    }

    fn relocated_single_tls_state(image: &[u8]) -> GeneralInitialTlsState {
        let mut state = GeneralInitialTlsState::new(MAIN, tls_object(image, image.len(), 4));
        state.finish_discovery().unwrap();
        assert!(state.plan_initial_tls().unwrap());
        state.mark_relocated().unwrap();
        #[cfg(crabc_general_initial_lifecycle)]
        {
            let plan = unsafe { super::super::x86_64_general_initial_lifecycle::GeneralInitialLifecycle::preflight(
                state.graph().unwrap(), state.objects().unwrap(),
            ) }.unwrap();
            state.attach_lifecycle(plan).unwrap();
        }
        state
    }

    #[test]
    fn planning_attaches_tls_to_the_canonical_loader_objects() {
        let main_image = [1u8, 2, 3, 4];
        let dso_image = [5u8, 6, 7, 8];
        let mut state = GeneralInitialTlsState::new(MAIN, tls_object(&main_image, 16, 8));
        let (graph, objects) = state.graph_and_objects_mut().unwrap();
        let tls_free = match graph.admit_mapped(ObjectIdentity { device: 1, inode: 2 }).unwrap() {
            super::super::x86_64_initial_graph_state::ObjectAdmission::New { index } => index,
            other => panic!("unexpected admission: {other:?}"),
        };
        graph.attach_needed(0, tls_free).unwrap();
        graph.finish_discovery(tls_free).unwrap();
        let dso = match graph.admit_mapped(ObjectIdentity { device: 1, inode: 3 }).unwrap() {
            super::super::x86_64_initial_graph_state::ObjectAdmission::New { index } => index,
            other => panic!("unexpected admission: {other:?}"),
        };
        graph.attach_needed(0, dso).unwrap();
        objects[dso] = tls_object(&dso_image, 32, 16);
        graph.finish_discovery(dso).unwrap();
        state.finish_discovery().unwrap();

        assert!(state.plan_initial_tls().unwrap());
        assert_eq!(state.phase(), GeneralInitialTlsPhase::Planned);
        assert!(state.loader.has_initial_tls_attachment());
        let objects = state.objects().unwrap();
        assert_eq!(objects[0].tls_module_id, 1);
        assert_eq!(objects[tls_free].tls_module_id, 0);
        assert_eq!(objects[dso].tls_module_id, 2);
        assert_eq!(state.module_id(0).map(TlsModuleId::get), Some(1));
        assert_eq!(state.module_id(tls_free), None);
        assert_eq!(state.module_id(dso).map(TlsModuleId::get), Some(2));
        assert_eq!(state.generation().get(), 1);
        let phase_before_growth_rejection = state.phase();
        let object_count_before_growth_rejection = state.object_count();
        assert_eq!(
            state.reject_runtime_tls_growth(MAX_OBJECTS),
            Err(RuntimeTlsGrowthError::DtvGrowthProtocolUnavailable)
        );
        assert_eq!(state.phase(), phase_before_growth_rejection);
        assert_eq!(state.object_count(), object_count_before_growth_rejection);
        assert_eq!(state.module_id(0).map(TlsModuleId::get), Some(1));
        assert_eq!(state.module_id(tls_free), None);
        assert_eq!(state.module_id(dso).map(TlsModuleId::get), Some(2));
    }

    #[test]
    fn failed_plan_can_rollback_without_retaining_tls_ids_or_mappings() {
        let main_image = [9u8; 4];
        let malformed_image = [8u8; 4];
        let mut malformed = tls_object(&malformed_image, 4, 3);
        malformed.tls_align = 3;
        let mut state = GeneralInitialTlsState::new(MAIN, tls_object(&main_image, 4, 4));
        let (graph, objects) = state.graph_and_objects_mut().unwrap();
        let malformed_child = match graph.admit_mapped(ObjectIdentity { device: 1, inode: 2 }).unwrap() {
            super::super::x86_64_initial_graph_state::ObjectAdmission::New { index } => index,
            other => panic!("unexpected admission: {other:?}"),
        };
        graph.attach_needed(0, malformed_child).unwrap();
        objects[malformed_child] = malformed;
        graph.finish_discovery(malformed_child).unwrap();
        state.finish_discovery().unwrap();

        assert_eq!(
            state.plan_initial_tls(),
            Err(GeneralInitialTlsStateError::InvalidTemplate)
        );
        let mut unmapped = 0usize;
        state.rollback(|_| unmapped += 1);
        assert_eq!(unmapped, 1);
        assert_eq!(state.phase(), GeneralInitialTlsPhase::RolledBack);
        assert_eq!(state.module_id(0), None);
        assert_eq!(state.module_id(malformed_child), None);
        assert_eq!(state.generation().get(), 1);
    }

    #[test]
    fn pre_fs_publication_reservation_rolls_back_and_allows_retry() {
        let _publication_guard = GeneralInitialLoaderState::test_publication_guard();
        let image = [7u8; 4];
        let mut first = relocated_single_tls_state(&image);
        first.reserve_publication().unwrap();
        #[cfg(crabc_general_loader_libc_tls_runtime_v1)]
        first.reserve_runtime_v1_publication().unwrap();
        #[cfg(crabc_general_loader_libc_tls_runtime_v1)]
        assert_eq!(
            first.phase(),
            GeneralInitialTlsPhase::RuntimeV1PublicationReserved
        );
        #[cfg(not(crabc_general_loader_libc_tls_runtime_v1))]
        assert_eq!(first.phase(), GeneralInitialTlsPhase::PublicationReserved);

        let mut retry = relocated_single_tls_state(&image);
        assert_eq!(
            retry.reserve_publication(),
            Err(GeneralInitialTlsStateError::PublicationUnavailable)
        );

        first.rollback(|_| panic!("single-object reservation has no DSO map"));
        assert_eq!(first.phase(), GeneralInitialTlsPhase::RolledBack);
        assert!(GeneralInitialLoaderState::retained().is_none());
        #[cfg(crabc_general_loader_libc_tls_runtime_v1)]
        assert_eq!(
            unsafe {
                (*core::ptr::addr_of!(__crabc_x86_64_loader_tls_runtime_v1))
                    .state
                    .load(Ordering::Acquire)
            },
            GENERAL_LOADER_TLS_RUNTIME_V1_STATE_UNPUBLISHED
        );

        retry.reserve_publication().unwrap();
        #[cfg(crabc_general_loader_libc_tls_runtime_v1)]
        retry.reserve_runtime_v1_publication().unwrap();
        #[cfg(crabc_general_loader_libc_tls_runtime_v1)]
        assert_eq!(
            retry.phase(),
            GeneralInitialTlsPhase::RuntimeV1PublicationReserved
        );
        #[cfg(not(crabc_general_loader_libc_tls_runtime_v1))]
        assert_eq!(retry.phase(), GeneralInitialTlsPhase::PublicationReserved);
        retry.rollback(|_| panic!("single-object retry has no DSO map"));
        assert!(GeneralInitialLoaderState::retained().is_none());
        #[cfg(crabc_general_loader_libc_tls_runtime_v1)]
        assert_eq!(
            unsafe {
                (*core::ptr::addr_of!(__crabc_x86_64_loader_tls_runtime_v1))
                    .state
                    .load(Ordering::Acquire)
            },
            GENERAL_LOADER_TLS_RUNTIME_V1_STATE_UNPUBLISHED
        );
    }
}
