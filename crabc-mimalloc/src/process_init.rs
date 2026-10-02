// Copyright (c) 2018-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// `LICENSE` at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `src/init.c:184-214,305-360,505-592`
// (`mi_heap_main_init_once`, `_mi_thread_init_with_heap`, and
// `mi_process_init_once`), `src/libc.c:115-140`
// (`_mi_atomic_once_enter`/`_mi_atomic_once_release` through `once.rs`), and
// `src/subproc.c:29-46,95-101`.

//! Source-ordered main-process initialization.
//!
//! Preparation initializes source policy and main Heap, binds metadata,
//! publishes the canonical PageMap, and installs the ticket-zero TLD/Theap
//! and compiler-TLS roots. `ProcessMainAllocationLease` exposes exactly that
//! initialized subset to its owning thread. The native runtime moves the
//! owner into its final slot before `ProcessMainStartup` resumes source huge
//! then regular reservations and diagnostic post-init. No mutable owner or
//! random projection spans a callback. Process readiness and its once release
//! precede the loader diagnostic/reseed tail, as the two source entries require.
//! Dropping an unfinished continuation retains source
//! state rather than reopening initialization. Historical explicit-config
//! fixtures remain policy-unbound; they do not manufacture ambient defaults.
//! Pthread lifetime-hook integration and process shutdown belong to the
//! runtime lifecycle owner, not this initialization coordinator.

#[cfg(test)]
extern crate std;

use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::mem::MaybeUninit;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicPtr, AtomicU8, AtomicUsize, Ordering};

use crate::compiler_tls::current_thread_identity;
use crate::arena::{ArenaId, ArenaView, FirstRegularStartupArenaSelection};
use crate::main_theap::{
    MainStaticAttachmentStorage, MainStaticHeapFoundation,
    MainStaticHeapFoundationError, MainStaticHeapLease, MainStaticTheapAttachment,
    MainStaticPageSessionError, MainStaticProcessPageSession,
    MainStaticProcessPageSessionError, MainStaticTheapError,
};
use crate::main_static_page::MainStaticFirstArenaPageAllocatorBeginError;
#[cfg(any(test, not(target_arch = "x86_64")))]
use crate::main_static_page::MainStaticFirstArenaPageAllocator;
use crate::meta::{MetaAllocator, MetaError};
use crate::once::{AllocatorOnce, AllocatorOnceCompletion, OnceThreadId};
use crate::config::{VmOptionEnvironmentReader, VmOptions};
#[cfg(target_arch = "x86_64")]
use crate::diagnostic_output::{MbindWarningRoute, OutputOwner, ProcessDiagnosticInputs};
use crate::os::{MemoryConfig, VmPolicy, VmPolicyConfigurationError, VmProcess};
use crate::page_map::PageMapHeader;
#[cfg(any(test, feature = "native-runtime-test-audit", not(target_arch = "x86_64")))]
use crate::process_arena::{ProcessPageArenaLeaseError, ProcessSharedArenaError, ProcessSharedArenaStorage};
#[cfg(any(test, feature = "native-runtime-test-audit", not(target_arch = "x86_64")))]
use crate::process_arena::ProcessPageArenaLease;
use crate::process_page_map::{
    ProcessPageMapError, ProcessPageMapRoot, ProcessPageMapStorage,
};
use crate::subproc::{
    MainStaticBootstrapSelectionError, MainSubprocess,
};

const COLD: u8 = 0;
const INITIALIZING: u8 = 1;
const READY: u8 = 2;
const RETAINED: u8 = 3;
// Default Theap/TLD and the allocation tuple exist; source startup
// reservations and their completed receipt do not yet exist.
const SOURCE_ATTACHED: u8 = 4;
const TERMINAL_CLOSED: u8 = 5;

/// How this source-startup call owns an optional source VM policy.
///
/// The production path must execute the pinned Unix process-memory policy
/// before it publishes any heap, metadata, or PageMap state. Ordinary
/// in-process Rust fixtures retain the same policy image but deliberately do
/// not alter the test runner's THP setting; the one native fixture that
/// exercises this transition runs its `ApplyProcessMemoryPolicy` branch only
/// in a dedicated child process. Keeping the cases typed here prevents a test
/// helper from silently claiming it performed a process-wide policy change.
enum VmPolicyStartup {
    None,
    RetainOnly(VmPolicy),
    ApplyProcessMemoryPolicy(VmPolicy),
    // The only selected x86 raw-source construction joins the policy and
    // mandatory diagnostic inputs in one variant; no caller can represent a
    // VM-backed selected diagnostic owner without its process policy.
    // Its policy is built from the process descriptor table after
    // `_mi_options_init`, so it carries no separately resolved image.
    #[cfg(target_arch = "x86_64")]
    ApplyProcessMemoryPolicyWithDiagnostics(ProcessDiagnosticInputs, ProcessStartEntry),
}

/// Which pinned `src/init.c` entry reached the one `mi_process_init` body.
///
/// The source distinguishes the two by `os_preloading`, not by a separate
/// startup routine. `_mi_auto_process_init` clears it before calling
/// `mi_process_init`, then completes the loader tail (`_mi_options_post_init`
/// and the weak-random reseeds). A first allocation that reaches
/// `_mi_thread_init` before the runtime's startup call runs only the once
/// body: the policy stays preloading, delayed output stays buffered, and a
/// later runtime startup completes the tail. See
/// [`ProcessMainInitializationStorage::complete_runtime_startup_after_first_allocation`].
#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProcessStartEntry {
    /// `_mi_auto_process_init`: the embedding runtime's explicit startup.
    RuntimeStartup,
    /// `mi_process_init` from `_mi_thread_init` on a process's first
    /// allocation before any runtime startup call.
    FirstAllocation,
}

#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy)]
enum ProcessStartupDiagnostics<'owner> {
    Unconnected,
    Selected(&'owner OutputOwner),
}

/// Separates explicit configuration fixtures from selected source startup.
/// A selected route always retains its winning output capability; it cannot
/// fall back to a configuration-only initializer after admission fails.
#[cfg(target_arch = "x86_64")]
enum ProcessBootstrapOutput<'startup> {
    LegacyExplicitConfiguration,
    Selected(ScopedBootstrapOutput<'startup>),
}

/// Failure to admit or retain the actual source startup diagnostic owner.
#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BootstrapOutputAdmissionError {
    Unavailable,
    Invalid,
}

/// A borrowed diagnostic owner inside the winning process initialization.
/// The completion token and retained VM pair remain live through delivery;
/// this grants no published Heap, allocation, or process-readiness authority.
#[cfg(target_arch = "x86_64")]
pub(crate) struct ScopedBootstrapOutput<'startup> {
    storage: &'startup ProcessMainInitializationStorage,
    completion: &'startup AllocatorOnceCompletion<'static>,
    output: &'startup OutputOwner,
    process: &'startup VmProcess<'static>,
    subprocess: &'startup MainSubprocess,
    _not_send_or_sync: PhantomData<*mut ()>,
}

#[cfg(target_arch = "x86_64")]
impl ScopedBootstrapOutput<'_> {
    fn validate(&self) -> Result<(), BootstrapOutputAdmissionError> {
        let current_thread = current_thread_identity()
            .ok_or(BootstrapOutputAdmissionError::Invalid)?;
        let once_thread = OnceThreadId::new(current_thread.get())
            .ok_or(BootstrapOutputAdmissionError::Invalid)?;
        if self.storage.state.load(Ordering::Acquire) != INITIALIZING
            || current_thread.get() != self.storage.initializing_thread.load(Ordering::Relaxed)
            || !self.completion.matches_active_owner(&self.storage.process_once, once_thread)
            || !core::ptr::eq(self.storage.diagnostic_output_ptr.load(Ordering::Acquire), self.output)
            || !core::ptr::eq(self.storage.vm_policy_ptr.load(Ordering::Acquire), self.process.policy())
            || !self.process.main_subprocess().is_some_and(|owner| core::ptr::eq(owner, self.subprocess))
        {
            return Err(BootstrapOutputAdmissionError::Invalid);
        }
        Ok(())
    }

    /// Reborrows this admitted coordinator's initialized source option table.
    /// The reference cannot outlive the actual startup capability.
    pub(crate) fn output(&self) -> Result<&OutputOwner, BootstrapOutputAdmissionError> {
        self.validate()?;
        Ok(self.output)
    }

    /// Reborrows the actual VM pair retained by the winning startup owner.
    /// Metadata initialization precedes process PageMap publication, so this
    /// projection neither requires a published map nor grants backing access.
    pub(crate) fn process(&self) -> Result<&VmProcess<'static>, BootstrapOutputAdmissionError> {
        self.validate()?;
        Ok(self.process)
    }

    /// Refuses a diagnostic origin that differs from this retained VM pair.
    /// Matching identities grant no allocation, Heap, or PageMap authority;
    /// the caller must separately retain the original backing issuer.
    pub(crate) fn matches_process(&self, process: &VmProcess<'_>) -> bool {
        self.validate().is_ok()
            && core::ptr::eq(self.process.policy(), process.policy())
            && core::ptr::eq(self.process.subprocess(), process.subprocess())
            && process.main_subprocess().is_some_and(|owner| core::ptr::eq(owner, self.subprocess))
    }

    pub(crate) fn matches_subprocess(&self, subprocess: &MainSubprocess) -> bool {
        self.validate().is_ok() && core::ptr::eq(self.subprocess, subprocess)
    }

    /// Delivers normal entropy refusal before making initialization material.
    ///
    /// # Safety
    /// The caller has ended every Heap, Theap, TLD, random, and metadata-entry
    /// projection or guard. It retains the pending allocation and its original
    /// initialization phase throughout possible synchronous callback reentry.
    pub(crate) unsafe fn deliver_prepared_random_warning(
        &self,
        prepared: crate::random::PreparedRandomInitialization,
    ) -> Result<crate::random::RandomInitializationMaterial, BootstrapOutputAdmissionError> {
        self.validate()?;
        // SAFETY: this actual startup owner retains its route and completion,
        // and the caller ended all allocator projections before delivery.
        let material = unsafe { deliver_prepared_random_warning_core(self.output, prepared) };
        self.validate()?;
        Ok(material)
    }
}

#[cfg(target_arch = "x86_64")]
impl crate::runtime_lifecycle::NativeAllocationOwner<'_> {
    /// Completes normal entropy preparation through this admitted owner.
    ///
    /// # Safety
    /// The caller has ended every Heap, Theap, TLD, random, and metadata-entry
    /// projection or guard. The actual selected owner and pending allocation
    /// remain retained by the enclosing admission throughout callback reentry.
    pub(crate) unsafe fn deliver_prepared_random_warning(
        &self,
        prepared: crate::random::PreparedRandomInitialization,
    ) -> crate::random::RandomInitializationMaterial {
        // SAFETY: the enclosing factory retains actual ready and child-record
        // admission; this reborrow cannot extend either beyond that scope.
        unsafe { deliver_prepared_random_warning_core(self.output(), prepared) }
    }
}

/// Completes only an already-admitted diagnostic owner's random transition.
#[cfg(target_arch = "x86_64")]
unsafe fn deliver_prepared_random_warning_core(
    output: &OutputOwner,
    prepared: crate::random::PreparedRandomInitialization,
) -> crate::random::RandomInitializationMaterial {
    if prepared.requires_warning() {
        // SAFETY: the typed caller retains the actual admitted route, and no
        // allocator projection or record guard spans its callback delivery.
        unsafe { output.warning_from_source_options(
            crate::diagnostic_output::SourceFormattedMessage::from_source_formatted(
                c"unable to use secure randomness\n",
            ),
        ) };
    }
    // SAFETY: a refused fill completed its admitted warning above; a strong
    // fill has no warning obligation and reads no diagnostic source option.
    unsafe { prepared.after_warning() }
}

/// Final process-lifetime state for the bounded source main-process startup.
///
/// `READY` is published after the `mi_process_init_once` body has completed,
/// before its once release and the separate loader diagnostic/reseed tail.
/// `RETAINED` is terminal: a failure after the coordinator wins
/// the static ticket-zero selection may leave a static Heap, detached metadata
/// image, PageMap, TLD, or TLS root live, so retrying as if the process were
/// cold would invent an unsafe second startup branch.
pub(crate) struct ProcessMainInitializationStorage {
    source_subprocesses: crate::subproc::registry::SourceSubprocessRegistry,
    /// The source-shaped once gate retains its private lock from the winning
    /// COLD claim until this coordinator has Release-published READY or
    /// RETAINED.  A different caller therefore waits as pinned
    /// `_mi_atomic_once_enter` does, while the stored source thread identity
    /// lets a recursive caller decline without waiting on itself.
    process_once: AllocatorOnce,
    state: AtomicU8,
    initializing_thread: AtomicUsize,
    config: UnsafeCell<MaybeUninit<MemoryConfig>>,
    // A resolved source option image belongs to this exact process lifetime,
    // not to a caller-local VM helper. The pointer is null for the preserved
    // legacy explicit-config path; otherwise READY Release-publishes this
    // permanent inline owner before any ready lease can borrow a VmProcess.
    vm_policy: UnsafeCell<MaybeUninit<VmPolicy>>,
    vm_policy_ptr: AtomicPtr<VmPolicy>,
    subprocess: AtomicPtr<MainSubprocess>,
    page_map_storage: AtomicPtr<ProcessPageMapStorage>,
    startup_reservations: UnsafeCell<MaybeUninit<crate::arena::StartupArenaReservationOutcomes>>,
    // This is process-lifetime allocator diagnostic state, deliberately
    // beside rather than inside VmPolicy/VmProcess. It is written before any
    // VM/OS/arena operation and never moved or replaced.
    #[cfg(target_arch = "x86_64")]
    diagnostic_output: UnsafeCell<MaybeUninit<OutputOwner>>,
    // Null on legacy fixture paths without a diagnostic owner. Publication
    // follows option initialization; READY separately gates normal capture.
    #[cfg(target_arch = "x86_64")]
    diagnostic_output_ptr: AtomicPtr<OutputOwner>,
    // One-way claim of the `_mi_auto_process_init` tail after the once body.
    // Source calls that routine once from the loader; a repeated runtime
    // startup therefore observes the claim and performs no second flush.
    #[cfg(target_arch = "x86_64")]
    runtime_startup_tail: core::sync::atomic::AtomicBool,
}

// SAFETY: `process_once` makes COLD -> INITIALIZING exclusive and retains its
// private lock until the final state is Release-published. The final
// configuration, optional VM policy, subprocess, and PageMap-storage pointer
// and startup reservation outcomes are written before READY's Release
// publication and never replaced. A live
// `ProcessMainThread` remains current-thread-only through its contained main
// attachment; READY leases are immutable process-root witnesses only.
unsafe impl Sync for ProcessMainInitializationStorage {}

impl ProcessMainInitializationStorage {
    const fn new() -> Self {
        Self {
            source_subprocesses: crate::subproc::registry::SourceSubprocessRegistry::new(),
            process_once: AllocatorOnce::new(),
            state: AtomicU8::new(COLD),
            initializing_thread: AtomicUsize::new(0),
            config: UnsafeCell::new(MaybeUninit::uninit()),
            vm_policy: UnsafeCell::new(MaybeUninit::uninit()),
            vm_policy_ptr: AtomicPtr::new(core::ptr::null_mut()),
            subprocess: AtomicPtr::new(core::ptr::null_mut()),
            page_map_storage: AtomicPtr::new(core::ptr::null_mut()),
            startup_reservations: UnsafeCell::new(MaybeUninit::uninit()),
            #[cfg(target_arch = "x86_64")]
            diagnostic_output: UnsafeCell::new(MaybeUninit::uninit()),
            #[cfg(target_arch = "x86_64")]
            diagnostic_output_ptr: AtomicPtr::new(core::ptr::null_mut()),
            #[cfg(target_arch = "x86_64")]
            runtime_startup_tail: core::sync::atomic::AtomicBool::new(false),
        }
    }

    // This private issuer is reached only with the completion returned by
    // this coordinator's winning once entry and its initialized Selected route.
    #[cfg(target_arch = "x86_64")]
    fn scoped_bootstrap_output<'startup>(
        &'startup self,
        completion: &'startup AllocatorOnceCompletion<'static>,
        diagnostics: &'startup ProcessStartupDiagnostics<'static>,
        process: &'startup VmProcess<'static>,
        subprocess: &'startup MainSubprocess,
    ) -> Result<ScopedBootstrapOutput<'startup>, BootstrapOutputAdmissionError> {
        let ProcessStartupDiagnostics::Selected(output) = diagnostics else {
            return Err(BootstrapOutputAdmissionError::Unavailable);
        };
        let scope = ScopedBootstrapOutput {
            storage: self, completion, output, process, subprocess,
            _not_send_or_sync: PhantomData,
        };
        scope.validate()?;
        Ok(scope)
    }

    /// Returns the one production process coordinator. It remains cold until
    /// a future runtime startup path supplies the frozen memory configuration.
    #[inline]
    pub(crate) fn global() -> &'static Self {
        &PROCESS_MAIN_INITIALIZATION
    }

    /// The published process descriptor table, once `_mi_options_init` ran.
    #[cfg(target_arch = "x86_64")]
    #[inline]
    fn published_source_options(&self) -> Option<&'static OutputOwner> {
        // SAFETY: the inline owner is written and its table installed before
        // this pointer's Release publication, and it is never moved or
        // reclaimed for the process lifetime.
        unsafe { self.diagnostic_output_ptr.load(Ordering::Acquire).as_ref() }
    }

    /// Builds an isolated leaked process-lifetime startup fixture.
    #[cfg(test)]
    pub(crate) fn test_static_owner() -> &'static Self {
        std::boxed::Box::leak(std::boxed::Box::new(Self::new()))
    }

    /// Whether no source startup has claimed this coordinator.
    #[cfg(test)]
    pub(crate) fn test_is_cold(&self) -> bool {
        self.state.load(Ordering::Acquire) == COLD
    }

    /// Runs the bounded source startup path over the process-static owners.
    ///
    /// # Safety
    ///
    /// The caller must own this thread's allocator startup/teardown lifecycle
    /// and must retain the returned `ProcessMainThread` until its explicit
    /// teardown or terminal retention. It must not concurrently construct a
    /// generic ticket-zero TLD, mutate compiler-TLS roots, or independently
    /// initialize the same source-main storage. The coordinator blocks a
    /// distinct racing caller until its source-shaped once release, while a
    /// recursive caller deliberately receives the explicit reentry refusal.
    pub(crate) unsafe fn initialize(
        &'static self,
        config: MemoryConfig,
    ) -> Result<ProcessMainThread, ProcessMainInitError> {
        // SAFETY: the process statics all have process lifetime and the
        // caller upholds the current-thread lifecycle contract above.
        unsafe {
            self.initialize_with_components_after_claim(
                config,
                VmPolicyStartup::None,
                MainStaticAttachmentStorage::global(),
                MainSubprocess::global(),
                MetaAllocator::global(),
                ProcessPageMapStorage::global(),
                || {},
                || {},
            )
        }
    }

    /// Runs process startup with the one resolved source VM option image.
    ///
    /// Unlike [`Self::initialize`], this path retains the exact policy beside
    /// the process configuration and subprocess before any source main-heap,
    /// metadata, PageMap, or arena client may borrow it. The caller owns the
    /// bounded environment-observation phase that resolved `options`; this
    /// allocation-free crate never reads ambient `environ` itself.
    ///
    /// # Safety
    ///
    /// The safety requirements are the same as [`Self::initialize`]. In
    /// addition, `options` must be the one source image selected for this
    /// process lifetime and must not be reused to initialize another owner.
    pub(crate) unsafe fn initialize_with_vm_options(
        &'static self,
        config: MemoryConfig,
        options: VmOptions,
    ) -> Result<ProcessMainThread, ProcessMainInitError> {
        let policy = VmPolicy::new(options).map_err(ProcessMainInitError::VmPolicy)?;
        // SAFETY: the caller upholds the same process-static lifecycle
        // requirements as `initialize`; `policy` is moved into this storage.
        unsafe {
            self.initialize_with_components_after_claim(
                config,
                VmPolicyStartup::ApplyProcessMemoryPolicy(policy),
                MainStaticAttachmentStorage::global(),
                MainSubprocess::global(),
                MetaAllocator::global(),
                ProcessPageMapStorage::global(),
                || {},
                || {},
            )
        }
    }

    /// Runs production source startup with the raw Unix environment reader
    /// retained for lazy option retries.
    ///
    /// Pinned `_mi_options_init` does not make a temporarily unavailable
    /// `_mi_getenv` result terminal: a later `mi_option_get` retries only the
    /// unresolved descriptor while returning its current default meanwhile.
    /// This route keeps that precise capability beside the permanent process
    /// policy instead of rejecting the whole native shadow before any source
    /// process owner exists.
    ///
    /// # Safety
    ///
    /// The requirements of [`Self::initialize_with_vm_options`] apply. In
    /// addition, `environment_reader` must satisfy
    /// [`VmOptionEnvironmentReader`] for every future policy option read and
    /// remain associated with this exact process lifetime.
    #[cfg(target_arch = "aarch64")]
    pub(crate) unsafe fn initialize_with_vm_options_from_source_environment(
        &'static self,
        config: MemoryConfig,
        options: VmOptions,
        environment_reader: VmOptionEnvironmentReader,
    ) -> Result<ProcessMainThread, ProcessMainInitError> {
        // SAFETY: forwarded from this process-owner boundary; `VmPolicy`
        // retains the reader only beside the same permanent process policy.
        let policy = unsafe { VmPolicy::new_with_source_environment(options, environment_reader) }
            .map_err(ProcessMainInitError::VmPolicy)?;
        // SAFETY: the caller upholds the same process-static lifecycle
        // requirements as `initialize_with_vm_options`; `policy` is moved
        // into this storage before any source root becomes visible.
        unsafe {
            self.initialize_with_components_after_claim(
                config,
                VmPolicyStartup::ApplyProcessMemoryPolicy(policy),
                MainStaticAttachmentStorage::global(),
                MainSubprocess::global(),
                MetaAllocator::global(),
                ProcessPageMapStorage::global(),
                || {},
                || {},
            )
        }
    }

    /// Runs the selected x86 raw-source startup with its mandatory private
    /// FILE capability. This is the only x86 runtime route that retains an
    /// OutputOwner before source VM/OS/arena work.
    ///
    /// # Safety
    ///
    /// The `environment_reader` and output primitive obligations of
    /// [`ProcessDiagnosticInputs`] apply for this complete process lifetime,
    /// in addition to the source startup ownership requirements above.
    #[cfg(target_arch = "x86_64")]
    pub(crate) unsafe fn initialize_from_source_environment(
        &'static self,
        config: MemoryConfig,
        diagnostics: ProcessDiagnosticInputs,
    ) -> Result<ProcessMainThread, ProcessMainInitError> {
        unsafe {
            self.initialize_with_components_after_claim(
                config,
                VmPolicyStartup::ApplyProcessMemoryPolicyWithDiagnostics(
                    diagnostics, ProcessStartEntry::RuntimeStartup,
                ),
                MainStaticAttachmentStorage::global(),
                MainSubprocess::global(),
                MetaAllocator::global(),
                ProcessPageMapStorage::global(),
                || {},
                || {},
            )
        }
    }

    /// Prepares the selected source owner for publication in its final
    /// runtime slot before any post-attachment VM/output callback.
    ///
    /// # Safety
    /// The caller owns source startup and all `ProcessDiagnosticInputs`
    /// lifetime obligations. It must retain the returned owner in final
    /// process storage before completing the linear continuation.
    #[cfg(target_arch = "x86_64")]
    pub(crate) unsafe fn prepare_from_source_environment(
        &'static self, config: MemoryConfig,
        diagnostics: ProcessDiagnosticInputs, entry: ProcessStartEntry,
    ) -> Result<(ProcessMainThread, ProcessMainStartup), ProcessMainInitError> {
        unsafe { self.prepare_with_components_after_claim(
            config, VmPolicyStartup::ApplyProcessMemoryPolicyWithDiagnostics(diagnostics, entry),
            MainStaticAttachmentStorage::global(), MainSubprocess::global(),
            MetaAllocator::global(), ProcessPageMapStorage::global(), || {},
        ) }
    }

    /// Runs the same transition against isolated process-lifetime owners.
    ///
    /// # Safety
    ///
    /// Test callers retain every supplied final static owner, own the current
    /// thread's roots/TLD lifecycle, and do not introduce a competing source
    /// ticket-zero constructor.
    #[cfg(test)]
    pub(crate) unsafe fn initialize_with_test_components(
        &'static self,
        config: MemoryConfig,
        main_static: &'static MainStaticAttachmentStorage,
        subprocess: &'static MainSubprocess,
        metadata: core::pin::Pin<&'static MetaAllocator>,
        page_map_storage: &'static ProcessPageMapStorage,
    ) -> Result<ProcessMainThread, ProcessMainInitError> {
        // SAFETY: forwarded unchanged to the common source-order transition.
        unsafe {
            self.initialize_with_components_after_claim(
                config,
                VmPolicyStartup::None,
                main_static,
                subprocess,
                metadata,
                page_map_storage,
                || {},
                || {},
            )
        }
    }

    /// Runs the isolated source-order transition with one completed VM policy
    /// retained in this test process lifetime.
    ///
    /// # Safety
    /// Test callers retain every supplied final static owner and the selected
    /// options image belongs solely to this isolated process coordinator.
    #[cfg(test)]
    pub(crate) unsafe fn initialize_with_test_components_and_vm_options(
        &'static self,
        config: MemoryConfig,
        options: VmOptions,
        main_static: &'static MainStaticAttachmentStorage,
        subprocess: &'static MainSubprocess,
        metadata: core::pin::Pin<&'static MetaAllocator>,
        page_map_storage: &'static ProcessPageMapStorage,
    ) -> Result<ProcessMainThread, ProcessMainInitError> {
        let policy = VmPolicy::new(options).map_err(ProcessMainInitError::VmPolicy)?;
        // SAFETY: forwarded to the shared one-time source transition.
        unsafe {
            self.initialize_with_components_after_claim(
                config,
                VmPolicyStartup::RetainOnly(policy),
                main_static,
                subprocess,
                metadata,
                page_map_storage,
                || {},
                || {},
            )
        }
    }

    /// Initializes a complete test process with a caller-owned source option
    /// table so its page and OS warnings use the same callback path as the
    /// ordinary process policy. The supplied owner stays live after READY.
    ///
    /// # Safety
    /// The output table has completed source-option initialization and all
    /// supplied final owners remain live for this isolated process lifetime.
    #[cfg(all(test, target_arch = "x86_64"))]
    pub(crate) unsafe fn initialize_with_test_components_and_source_output(
        &'static self,
        config: MemoryConfig,
        output: &'static OutputOwner,
        main_static: &'static MainStaticAttachmentStorage,
        subprocess: &'static MainSubprocess,
        metadata: core::pin::Pin<&'static MetaAllocator>,
        page_map_storage: &'static ProcessPageMapStorage,
    ) -> Result<ProcessMainThread, ProcessMainInitError> {
        // SAFETY: the caller retains the initialized output table and its
        // callback for every policy read and warning in this process.
        let policy = unsafe { VmPolicy::from_process_options(output) };
        // SAFETY: forwarded process-static owners satisfy the same isolated
        // source transition as the image-policy test constructor above.
        unsafe {
            self.initialize_with_components_after_claim(
                config,
                VmPolicyStartup::RetainOnly(policy),
                main_static,
                subprocess,
                metadata,
                page_map_storage,
                || {},
                || {},
            )
        }
    }

    /// # Safety
    /// The isolated test retains every final process owner and owns the
    /// current roots until the returned source continuation finishes.
    #[cfg(all(test, target_arch = "x86_64"))]
    pub(crate) unsafe fn prepare_with_test_components_and_vm_options(
        &'static self, config: MemoryConfig, options: VmOptions,
        main_static: &'static MainStaticAttachmentStorage, subprocess: &'static MainSubprocess,
        metadata: core::pin::Pin<&'static MetaAllocator>, page_map_storage: &'static ProcessPageMapStorage,
        diagnostics: Option<&'static OutputOwner>,
    ) -> Result<(ProcessMainThread, ProcessMainStartup), ProcessMainInitError> {
        let policy = VmPolicy::new(options).map_err(ProcessMainInitError::VmPolicy)?;
        let (owner, mut startup) = unsafe {
            self.prepare_with_components_after_claim(config, VmPolicyStartup::RetainOnly(policy),
                main_static, subprocess, metadata, page_map_storage, || {})
        }?;
        if let Some(output) = diagnostics {
            startup.diagnostics = ProcessStartupDiagnostics::Selected(output);
        }
        Ok((owner, startup))
    }

    /// Runs the VM-aware transition in a process that the caller has already
    /// isolated with `fork`.
    ///
    /// This is deliberately narrower than the ordinary VM fixture above:
    /// source `_mi_os_init` can invoke `PR_SET_THP_DISABLE`, which must never
    /// affect an in-process Rust test runner.
    ///
    /// # Safety
    ///
    /// The caller must meet the ordinary isolated-component requirements and
    /// additionally run in a disposable process with no post-fork Rust
    /// allocation or synchronization dependency after this transition.
    #[cfg(all(test, not(miri)))]
    unsafe fn initialize_with_test_components_and_process_memory_policy(
        &'static self,
        config: MemoryConfig,
        options: VmOptions,
        main_static: &'static MainStaticAttachmentStorage,
        subprocess: &'static MainSubprocess,
        metadata: core::pin::Pin<&'static MetaAllocator>,
        page_map_storage: &'static ProcessPageMapStorage,
    ) -> Result<ProcessMainThread, ProcessMainInitError> {
        let policy = VmPolicy::new(options).map_err(ProcessMainInitError::VmPolicy)?;
        // SAFETY: the caller has isolated the process-local kernel transition
        // and retains every supplied final source owner.
        unsafe {
            self.initialize_with_components_after_claim(
                config,
                VmPolicyStartup::ApplyProcessMemoryPolicy(policy),
                main_static,
                subprocess,
                metadata,
                page_map_storage,
                || {},
                || {},
            )
        }
    }

    /// Runs the isolated source-order transition and pauses after it claims
    /// the process-once state, before any source image is touched.
    ///
    /// This exists solely to let the process coordinator's race regression
    /// hold the exact pre-publication interval. Production callers always use
    /// the no-op hook through [`Self::initialize`].
    #[cfg(test)]
    unsafe fn initialize_with_test_components_after_claim(
        &'static self,
        config: MemoryConfig,
        main_static: &'static MainStaticAttachmentStorage,
        subprocess: &'static MainSubprocess,
        metadata: core::pin::Pin<&'static MetaAllocator>,
        page_map_storage: &'static ProcessPageMapStorage,
        after_claim: impl FnOnce(),
    ) -> Result<ProcessMainThread, ProcessMainInitError> {
        // SAFETY: forwarded unchanged to the common source-order transition.
        unsafe {
            self.initialize_with_components_after_claim(
                config,
                VmPolicyStartup::None,
                main_static,
                subprocess,
                metadata,
                page_map_storage,
                after_claim,
                || {},
            )
        }
    }

    /// Runs the isolated source-order transition and pauses after it
    /// Release-publishes its terminal state but before it releases the source
    /// once lock. This exists solely for the terminal-publication race
    /// regression; production callers always use a no-op hook.
    #[cfg(test)]
    unsafe fn initialize_with_test_components_before_release(
        &'static self,
        config: MemoryConfig,
        main_static: &'static MainStaticAttachmentStorage,
        subprocess: &'static MainSubprocess,
        metadata: core::pin::Pin<&'static MetaAllocator>,
        page_map_storage: &'static ProcessPageMapStorage,
        before_release: impl FnOnce(),
    ) -> Result<ProcessMainThread, ProcessMainInitError> {
        // SAFETY: forwarded unchanged to the common source-order transition.
        unsafe {
            self.initialize_with_components_after_claim(
                config,
                VmPolicyStartup::None,
                main_static,
                subprocess,
                metadata,
                page_map_storage,
                || {},
                before_release,
            )
        }
    }

    unsafe fn initialize_with_components_after_claim<F, G>(
        &'static self,
        mut config: MemoryConfig,
        vm_policy: VmPolicyStartup,
        main_static: &'static MainStaticAttachmentStorage,
        subprocess: &'static MainSubprocess,
        metadata: core::pin::Pin<&'static MetaAllocator>,
        page_map_storage: &'static ProcessPageMapStorage,
        after_claim: F,
        before_release: G,
    ) -> Result<ProcessMainThread, ProcessMainInitError>
    where
        F: FnOnce(),
        G: FnOnce(),
    {
        unsafe {
            self.initialize_with_components_at_attachment(
                config, vm_policy, main_static, subprocess, metadata, page_map_storage,
                after_claim, || {}, before_release,
            )
        }
    }

    unsafe fn initialize_with_components_at_attachment<F, H, G>(
        &'static self,
        mut config: MemoryConfig,
        vm_policy: VmPolicyStartup,
        main_static: &'static MainStaticAttachmentStorage,
        subprocess: &'static MainSubprocess,
        metadata: core::pin::Pin<&'static MetaAllocator>,
        page_map_storage: &'static ProcessPageMapStorage,
        after_claim: F,
        after_attachment: H,
        before_release: G,
    ) -> Result<ProcessMainThread, ProcessMainInitError>
    where
        F: FnOnce(),
        H: FnOnce(),
        G: FnOnce(),
    {
        // The synchronous fixture API uses the same split transition as the
        // runtime, with no owner reference spanning the callback or tail.
        let (owner, startup) = unsafe { self.prepare_with_components_after_claim(
            config, vm_policy, main_static, subprocess, metadata, page_map_storage, after_claim,
        ) }?;
        after_attachment();
        startup.complete_with_hook(before_release)?;
        Ok(owner)
    }

    unsafe fn prepare_with_components_after_claim<F>(
        &'static self,
        mut config: MemoryConfig,
        vm_policy: VmPolicyStartup,
        main_static: &'static MainStaticAttachmentStorage,
        subprocess: &'static MainSubprocess,
        metadata: core::pin::Pin<&'static MetaAllocator>,
        page_map_storage: &'static ProcessPageMapStorage,
        after_claim: F,
    ) -> Result<(ProcessMainThread, ProcessMainStartup), ProcessMainInitError>
    where
        F: FnOnce(),
    {
        let observed = self.state.load(Ordering::Acquire);
        let current_thread = match current_thread_identity() {
            Some(identity) => identity,
            // The selected native compiler-TLS path always supplies an
            // identity. Without one, a COLD caller cannot join the once
            // protocol and an in-flight caller cannot be classified as the
            // owner, so preserve the existing fail-closed responses. A
            // terminal observation can still be reported: it grants no
            // source capability and is the only no-identity fast path around
            // the once release envelope.
            None => match observed {
                COLD => {
                    return Err(ProcessMainInitError::Preflight(
                        MainStaticTheapError::InvalidCurrentThread,
                    ));
                }
                INITIALIZING | SOURCE_ATTACHED => return Err(ProcessMainInitError::Initializing),
                READY => return Err(ProcessMainInitError::AlreadyInitialized),
                RETAINED | _ => return Err(ProcessMainInitError::Retained),
            },
        };
        let once_thread = OnceThreadId::new(current_thread.get()).ok_or(
            ProcessMainInitError::Preflight(MainStaticTheapError::InvalidCurrentThread),
        )?;

        let Some(completion) = self
            .process_once
            .enter(once_thread)
            .map_err(ProcessMainInitError::Lock)?
        else {
            return self.outcome_after_process_once();
        };

        // `AllocatorOnce::enter` won its 0 -> current-thread transition while
        // retaining the private lock. That is the source-equivalent exclusive
        // process claim: a distinct racer now blocks before it can preflight
        // or touch the source body.
        debug_assert_eq!(self.state.load(Ordering::Acquire), COLD);

        // This Rust-only preflight remains retryable, so it must happen while
        // the source once envelope is held but before the body selects any
        // static source state. A rejection therefore reopens the once state
        // and leaves this coordinator COLD exactly as it did before the once
        // gate existed; a waiting distinct caller can then become the next
        // serialized preflight owner.
        if let Err(error) = MainStaticTheapAttachment::preflight_current_roots() {
            // SAFETY: preflight ran before static selection, heap foundation,
            // metadata readiness, PageMap creation, or TLS-root publication,
            // so no part of the guarded source body has started.
            unsafe { completion.cancel_before_body() }.map_err(ProcessMainInitError::Lock)?;
            return Err(ProcessMainInitError::Preflight(error));
        }

        self.initializing_thread.store(current_thread.get(), Ordering::Relaxed);
        self.state.store(INITIALIZING, Ordering::Release);
        after_claim();

        #[cfg(target_arch = "x86_64")]
        let (policy, apply_process_memory_policy, diagnostics, entry) = {
            // Source options precede `_mi_os_init`. The sole selected x86
            // policy variant writes the process-lifetime owner here,
            // initializes its three descriptors (including delayed invalid
            // output), and retains the borrowed route before VM/OS/arena work.
            match vm_policy {
                // Fixture routes model only the post-preloading loader edge.
                VmPolicyStartup::None => (
                    None, false, ProcessStartupDiagnostics::Unconnected, ProcessStartEntry::RuntimeStartup,
                ),
                VmPolicyStartup::RetainOnly(policy) => (
                    Some(policy), false, ProcessStartupDiagnostics::Unconnected,
                    ProcessStartEntry::RuntimeStartup,
                ),
                VmPolicyStartup::ApplyProcessMemoryPolicy(policy) => (
                    Some(policy), true, ProcessStartupDiagnostics::Unconnected,
                    ProcessStartEntry::RuntimeStartup,
                ),
                VmPolicyStartup::ApplyProcessMemoryPolicyWithDiagnostics(inputs, entry) => {
                    let source_errno_store = inputs.source_errno_store();
                    let (environment_reader, default_stderr_output) = inputs.into_parts();
                    let output = OutputOwner::new(default_stderr_output);
                    unsafe { (*self.diagnostic_output.get()).write(output) };
                    let output = unsafe { (&mut *self.diagnostic_output.get()).assume_init_mut() };
                    unsafe { output.initialize_source_options(environment_reader) };
                    let pointer: *mut OutputOwner = output;
                    self.diagnostic_output_ptr.store(pointer, Ordering::Release);
                    // SAFETY: the exclusive startup projection ended above;
                    // the process-static owner is only shared from here on.
                    let output: &'static OutputOwner = unsafe { &*pointer };
                    // SAFETY: `_mi_options_init` just installed this process
                    // table, and the owner lives in this process-static slot.
                    // Every VM read point is a source `mi_option_get`.
                    let policy = unsafe { VmPolicy::from_process_options(output) }
                        .with_source_errno_store(source_errno_store);
                    (Some(policy), true, ProcessStartupDiagnostics::Selected(output), entry)
                }
            }
        };
        #[cfg(target_arch = "aarch64")]
        let (policy, apply_process_memory_policy) = match vm_policy {
            VmPolicyStartup::None => (None, false),
            VmPolicyStartup::RetainOnly(policy) => (Some(policy), false),
            VmPolicyStartup::ApplyProcessMemoryPolicy(policy) => (Some(policy), true),
        };
        // Source init.c initializes its statistics clock after options and
        // before `_mi_os_init`, including process memory-policy operations.
        #[cfg(target_arch = "x86_64")]
        crate::statistics::initialize_process_clock();
        // `_mi_auto_process_init` clears `os_preloading` before its
        // option/OS/main-heap work; a first allocation that reaches
        // `mi_process_init` earlier leaves it set until that runtime call.
        #[cfg(target_arch = "x86_64")]
        let finish_preloading = entry == ProcessStartEntry::RuntimeStartup;
        #[cfg(target_arch = "aarch64")]
        let finish_preloading = true;
        let vm_process = if let Some(policy) = policy {
            // Retain this policy first, then expose its source preloading
            // state to every later source owner. A later startup failure is
            // terminal and deliberately leaves this exact policy image
            // retained with its process.
            match unsafe {
                self.retain_vm_process(
                    policy,
                    subprocess,
                    &mut config,
                    apply_process_memory_policy,
                    finish_preloading,
                )
            } {
                Ok(process) => Some(process),
                Err(error) => {
                    self.publish_terminal_state_and_release(completion, RETAINED);
                    return Err(error);
                }
            }
        } else {
            None
        };

        #[cfg(target_arch = "x86_64")]
        let bootstrap_output = match &diagnostics {
            ProcessStartupDiagnostics::Unconnected => ProcessBootstrapOutput::LegacyExplicitConfiguration,
            ProcessStartupDiagnostics::Selected(_) => {
                let Some(process) = vm_process.as_ref() else {
                    self.publish_terminal_state_and_release(completion, RETAINED);
                    return Err(ProcessMainInitError::BootstrapOutput(
                        BootstrapOutputAdmissionError::Invalid,
                    ));
                };
                match self.scoped_bootstrap_output(&completion, &diagnostics, process, subprocess) {
                    Ok(output) => ProcessBootstrapOutput::Selected(output),
                    Err(error) => {
                        self.publish_terminal_state_and_release(completion, RETAINED);
                        return Err(ProcessMainInitError::BootstrapOutput(error));
                    }
                }
            }
        };

        if vm_process.is_some() {
            // SAFETY: the source once gate exclusively owns both final static
            // images. Canonical main joins the source subprocess list before
            // `_mi_heap_main_init` publishes and initializes its main Heap.
            if let Err(error) = unsafe { self.source_subprocesses.initialize_main(subprocess) } {
                self.publish_terminal_state_and_release(completion, RETAINED);
                return Err(ProcessMainInitError::SubprocessRegistry(error));
            }
        }

        let mut selection = match subprocess.reserve_static_bootstrap() {
            Ok(selection) => selection,
            Err(error) => {
                self.publish_terminal_state_and_release(completion, RETAINED);
                return Err(ProcessMainInitError::BootstrapSelection(error));
            }
        };
        let foundation = match MainStaticHeapFoundation::initialize(
            main_static,
            subprocess,
            &mut selection,
        ) {
            Ok(foundation) => foundation,
            Err(error) => {
                selection.retain();
                self.publish_terminal_state_and_release(completion, RETAINED);
                return Err(ProcessMainInitError::HeapFoundation(error));
            }
        };
        // The production policy-bound process uses the canonical source
        // Heap. Historical explicit-config fixtures keep their visibly
        // separate private metadata backing and bootstrap ownership.
        #[cfg(target_arch = "x86_64")]
        let metadata_prepared = match &bootstrap_output {
            ProcessBootstrapOutput::Selected(output) => {
                // SAFETY: the winning startup completion and its actual
                // output/VM pair remain borrowed through this entry. Static
                // foundation setup has ended its projections; no Heap, TLD,
                // Theap, engine projection or metadata guard crosses the
                // source getters and warning windows inside this entry.
                unsafe {
                    metadata.prepare_for_main_heap_with_bootstrap_output(
                        config, subprocess, foundation, output,
                    )
                }
            }
            ProcessBootstrapOutput::LegacyExplicitConfiguration if vm_process.is_some() => {
                metadata.prepare_for_main_heap(config, subprocess, foundation)
            }
            ProcessBootstrapOutput::LegacyExplicitConfiguration => {
                metadata.prepare_for_main_subprocess(config, subprocess)
            }
        };
        #[cfg(target_arch = "aarch64")]
        let metadata_prepared = if vm_process.is_some() {
            metadata.prepare_for_main_heap(config, subprocess, foundation)
        } else {
            metadata.prepare_for_main_subprocess(config, subprocess)
        };
        let metadata_bound = match metadata_prepared {
            Ok(bound) => bound,
            Err(error) => {
                selection.retain();
                self.publish_terminal_state_and_release(completion, RETAINED);
                return Err(ProcessMainInitError::Metadata(error));
            }
        };
        debug_assert!(metadata_bound.matches(metadata));
        debug_assert!(core::ptr::eq(metadata_bound.subprocess().as_ptr(), subprocess.as_ptr()));
        debug_assert_eq!(metadata_bound.memory_config(), config);

        // The policy-bound process maps through its source aligned OS
        // sequence; explicit-config fixtures keep their direct private map.
        let page_map = match vm_process {
            Some(process) => page_map_storage.initialize_for_process(config, subprocess, process),
            None => page_map_storage.initialize(config, subprocess),
        };
        let page_map = match page_map {
            Ok(page_map) => page_map,
            Err(error) => {
                selection.retain();
                self.publish_terminal_state_and_release(completion, RETAINED);
                return Err(ProcessMainInitError::PageMap(error));
            }
        };
        // SAFETY: this CAS winner still owns the source once envelope and
        // state is INITIALIZING, so no READY lease can observe these final
        // slots. Record the one retained policy/subprocess/PageMap tuple
        // before metadata receives its canonical pre-READY binding; a later
        // failure retains this exact selected image instead of letting a
        // receiver reason only from caller-local copies.
        unsafe { (*self.config.get()).write(config) };
        self.subprocess.store(subprocess.owner_ptr(), Ordering::Release);
        self.page_map_storage
            .store(core::ptr::from_ref(page_map_storage).cast_mut(), Ordering::Release);
        if let Some(process) = vm_process {
            // The policy-aware path has now published every predecessor that
            // metadata needs: its detached Theap identity is bound and the
            // selected global PageMap has one stable root. Bind the exact
            // process pair before any metadata demand or READY publication;
            // a legacy explicit-config startup intentionally cannot invent
            // this policy-bound backing route.
            if let Err(error) = metadata.bind_process_backing(ProcessMainBackingBinding::new(
                self, process, page_map,
            )) {
                selection.retain();
                self.publish_terminal_state_and_release(completion, RETAINED);
                return Err(ProcessMainInitError::Metadata(error));
            }
        }

        // SAFETY: preflight established current-thread/root ownership; the
        // source-shaped once claim and selected linear token exclude another
        // ticket-zero route; `foundation` exists in its final static slot;
        // detached metadata identity is bound but has no backing; and the
        // exact selected PageMap has
        // been initialized before compiler-TLS root publication.
        let mut attachment = match unsafe {
            match vm_process {
                // This is the source `mi_tld_init` NUMA observation after
                // `_mi_os_init` has resolved and retained this process's
                // option image. Do not collapse it into the global wrapper:
                // the retained policy owns `mimalloc_use_numa_nodes`'s cache.
                Some(process) => {
                    #[cfg(target_arch = "x86_64")]
                    if let ProcessBootstrapOutput::Selected(output) = &bootstrap_output {
                        MainStaticTheapAttachment::begin_after_heap_foundation_with_bootstrap_output(
                            foundation, selection, process, output,
                        )
                    } else {
                        MainStaticTheapAttachment::begin_after_heap_foundation_with_vm_process(
                            foundation, selection, process,
                        )
                    }
                    #[cfg(not(target_arch = "x86_64"))]
                    MainStaticTheapAttachment::begin_after_heap_foundation_with_vm_process(
                        foundation,
                        selection,
                        process,
                    )
                }
                // The preserved explicit-config route has no source option
                // image and therefore retains the historical fixed-wrapper
                // observation.
                None => MainStaticTheapAttachment::begin_after_heap_foundation(foundation, selection),
            }
        } {
            Ok(attachment) => attachment,
            Err(error) => {
                self.publish_terminal_state_and_release(completion, RETAINED);
                return Err(ProcessMainInitError::InitialThread(error));
            }
        };

        // Pinned init.c publishes the default Theap before TLS setup and
        // source startup reservation calls can reenter allocation. This state
        // publishes only the initialized tuple, never reservation outcomes.
        subprocess.record_statistics_thread_attached();
        self.state.store(SOURCE_ATTACHED, Ordering::Release);

        let allocation = ProcessMainAllocationLease {
            storage: self,
            page_map,
            config,
            subprocess,
        };
        #[cfg(target_arch = "x86_64")]
        let startup_owner = match attachment.startup_owner_binding() {
            Ok(binding) => binding,
            Err(error) => {
                self.publish_terminal_state_and_release(completion, RETAINED);
                return Err(ProcessMainInitError::InitialThread(error));
            }
        };
        let owner = ProcessMainThread {
            storage: self,
            attachment: Some(attachment),
            allocation,
            state: ProcessMainThreadState::Attached,
            _not_send_or_sync: PhantomData,
        };
        let startup = ProcessMainStartup {
            storage: self, completion: Some(completion), config, vm_process, metadata,
            #[cfg(target_arch = "x86_64")]
            subprocess,
            #[cfg(target_arch = "x86_64")]
            startup_owner,
            #[cfg(target_arch = "x86_64")]
            diagnostics,
            #[cfg(target_arch = "x86_64")]
            entry,
            _not_send_or_sync: PhantomData,
        };
        Ok((owner, startup))
    }

    /// The coordinator-issued process backing binding and the source
    /// subprocess registry once startup is `READY`: the inputs of production
    /// child subprocess creation (`mi_subproc_new`), which may run on any
    /// thread after startup.
    pub(crate) fn ready_child_subprocess_inputs(
        &'static self,
    ) -> Option<(ProcessMainBackingBinding, &'static crate::subproc::registry::SourceSubprocessRegistry)> {
        if self.state.load(Ordering::Acquire) != READY {
            return None;
        }
        // SAFETY: READY Release-publishes the process-lifetime subprocess.
        let subprocess = unsafe { self.subprocess.load(Ordering::Acquire).as_ref() }?;
        let binding = self.ready_lease(self.config(), subprocess).ok()?.process_backing().ok()?;
        Some((binding, &self.source_subprocesses))
    }

    /// Reobtains the immutable process-ready witness for the same frozen
    /// process inputs. It never creates a second ticket-zero attachment.
    pub(crate) fn ready_lease(
        &'static self,
        config: MemoryConfig,
        subprocess: &'static MainSubprocess,
    ) -> Result<ProcessMainReadyLease, ProcessMainInitError> {
        if self.state.load(Ordering::Acquire) != READY {
            return Err(ProcessMainInitError::Retained);
        }
        let stored_config = self.config();
        if stored_config != config {
            return Err(ProcessMainInitError::ConfigurationMismatch);
        }
        if !core::ptr::eq(self.subprocess.load(Ordering::Acquire), subprocess.owner_ptr()) {
            return Err(ProcessMainInitError::SubprocessMismatch);
        }
        let page_map_storage = NonNull::new(self.page_map_storage.load(Ordering::Acquire))
            .ok_or(ProcessMainInitError::Retained)?;
        // SAFETY: READY Release-publishes the exact process-lifetime storage
        // pointer. It is never replaced or destroyed in this bounded owner.
        let page_map = unsafe { page_map_storage.as_ref() }
            .initialize(config, subprocess)
            .map_err(ProcessMainInitError::PageMap)?;
        Ok(ProcessMainReadyLease {
            storage: self,
            page_map,
            config,
            subprocess,
        })
    }

    /// Returns only the initialized allocation tuple. This capability never
    /// reads or attests to the later startup-reservation outcomes.
    pub(crate) fn allocation_lease(
        &'static self,
        config: MemoryConfig,
        subprocess: &'static MainSubprocess,
    ) -> Result<ProcessMainAllocationLease, ProcessMainInitError> {
        self.ensure_allocation_ready()?;
        if self.config() != config {
            return Err(ProcessMainInitError::ConfigurationMismatch);
        }
        if self.subprocess.load(Ordering::Acquire) != subprocess.owner_ptr() {
            return Err(ProcessMainInitError::SubprocessMismatch);
        }
        let page_map_storage = NonNull::new(self.page_map_storage.load(Ordering::Acquire))
            .ok_or(ProcessMainInitError::Retained)?;
        // SAFETY: the allocation-ready publication follows this immutable
        // storage pointer and its fully initialized canonical PageMap.
        let page_map = unsafe { page_map_storage.as_ref() }
            .initialize(config, subprocess).map_err(ProcessMainInitError::PageMap)?;
        Ok(ProcessMainAllocationLease { storage: self, config, subprocess, page_map })
    }

    fn ensure_allocation_ready(&self) -> Result<(), ProcessMainInitError> {
        match self.state.load(Ordering::Acquire) {
            READY => Ok(()),
            SOURCE_ATTACHED if current_thread_identity().is_some_and(|thread| {
                thread.get() == self.initializing_thread.load(Ordering::Relaxed)
            }) => Ok(()),
            COLD | INITIALIZING | SOURCE_ATTACHED => Err(ProcessMainInitError::Initializing),
            _ => Err(ProcessMainInitError::Retained),
        }
    }

    /// Completes pinned `_mi_auto_process_init` for a process whose
    /// `mi_process_init` body already ran from a first allocation.
    ///
    /// That earlier entry left `os_preloading` set, its delayed output
    /// buffered, and any weak random state unreseeded. This clears
    /// preloading, then runs the same loader tail as a runtime-first startup.
    /// Returns `Ok(false)` when the tail already ran, whether from a
    /// runtime-first startup or an earlier call; it never repeats the flush.
    ///
    /// # Safety
    ///
    /// The caller is the initial source thread, owning no attachment, Theap,
    /// or random projection, and serializes this call against every other
    /// diagnostic dispatch as `_mi_options_post_init` requires: no other
    /// attached thread may emit allocator diagnostics until it returns.
    #[cfg(target_arch = "x86_64")]
    pub(crate) unsafe fn complete_runtime_startup_after_first_allocation(
        &'static self,
    ) -> Result<bool, ProcessMainInitError> {
        if self.state.load(Ordering::Acquire) != READY {
            return Err(ProcessMainInitError::Retained);
        }
        if self.runtime_startup_tail.swap(true, Ordering::AcqRel) {
            return Ok(false);
        }
        let subprocess = NonNull::new(self.subprocess.load(Ordering::Acquire))
            .ok_or(ProcessMainInitError::Retained)?;
        // SAFETY: READY Release-published this permanent subprocess owner.
        let subprocess = unsafe { subprocess.as_ref() };
        if let Some(policy) = NonNull::new(self.vm_policy_ptr.load(Ordering::Acquire)) {
            // SAFETY: READY published this permanent inline policy image;
            // the preloading scalar is atomic and never moved.
            unsafe { policy.as_ref() }.finish_preloading();
        }
        let output = NonNull::new(self.diagnostic_output_ptr.load(Ordering::Acquire));
        // SAFETY: the permanent diagnostic owner was published before READY;
        // the caller supplies the tail's serialization obligations.
        unsafe {
            run_runtime_startup_tail(
                output.map(|output| &*output.as_ptr()), subprocess.metadata_allocator(), subprocess,
            )
        }?;
        Ok(true)
    }

    /// `_mi_auto_process_init`'s loader tail for a process whose startup
    /// failed only at its page map (`src/page-map.c:302-305`; `src/init.c:549`
    /// ignores the result and the process continues without a page map).
    ///
    /// Clears `os_preloading` and runs `_mi_options_post_init`, flushing the
    /// delayed output that holds the page-map error, exactly once across
    /// both startup entries. The weak-random reseed has no receiver: no
    /// Theap was attached, and the process can never allocate.
    ///
    /// # Safety
    ///
    /// The caller is the initial source thread and owns
    /// `_mi_options_post_init`'s serialization against every other diagnostic
    /// dispatch, as for [`Self::complete_runtime_startup_after_first_allocation`].
    #[cfg(target_arch = "x86_64")]
    pub(crate) unsafe fn complete_runtime_startup_without_page_map(&'static self) {
        if self.runtime_startup_tail.swap(true, Ordering::AcqRel) {
            return;
        }
        if let Some(policy) = NonNull::new(self.vm_policy_ptr.load(Ordering::Acquire)) {
            // SAFETY: `retain_vm_process` bound this permanent inline policy
            // image before the page map was attempted; its preloading scalar
            // is atomic and never moved.
            unsafe { policy.as_ref() }.finish_preloading();
        }
        if let Some(output) = self.published_source_options() {
            // SAFETY: forwarded; `runtime_startup_tail` was claimed above.
            unsafe { output.post_init() };
        }
    }

    #[inline]
    fn config(&self) -> MemoryConfig {
        // SAFETY: callers first observed allocation-ready with Acquire, whose Release
        // publication follows this final-slot write.
        unsafe { *(*self.config.get()).assume_init_ref() }
    }

    /// Retains one resolved policy beside its exact source subprocess before
    /// the process coordinator creates a metadata or PageMap consumer.
    ///
    /// The caller holds the source main-process claim and supplies the one
    /// final process configuration. The returned pair remains valid through
    /// the process lifetime even if a later source startup step is retained.
    unsafe fn retain_vm_process(
        &'static self,
        policy: VmPolicy,
        subprocess: &'static MainSubprocess,
        config: &mut MemoryConfig,
        apply_process_memory_policy: bool,
        finish_preloading: bool,
    ) -> Result<VmProcess<'static>, ProcessMainInitError> {
        let policy = unsafe { self.bind_vm_policy(policy) }?;
        if finish_preloading {
            policy.finish_preloading();
        }
        if apply_process_memory_policy {
            // Pinned `mi_process_init_once` invokes `_mi_os_init` after
            // options/statistics initialization and before heap/PageMap
            // initialization. The Linux primitive may change only this
            // process's THP state; its result is intentionally best-effort,
            // just as the source ignores `prctl` failures.
            #[cfg(not(miri))]
            let _outcome = policy.apply_thp_process_policy(config);
            #[cfg(miri)]
            let _ = (&policy, config);
        }
        Ok(VmProcess::new_main(policy, subprocess))
    }

    /// Builds the canonical VM/PageMap backing proof for one deliberately
    /// incomplete isolated metadata fixture.
    ///
    /// This exists only because metadata's direct allocation/failure tests
    /// must exercise its process-backing boundary before a full ticket-zero
    /// Heap/TLS startup can occur. It retains the supplied options in this
    /// isolated coordinator, initializes the exact supplied PageMap storage,
    /// and returns the same non-forgeable pre-READY binding that production
    /// creates immediately before its metadata bind. It never publishes a
    /// source main thread, metadata backing, or READY process state.
    ///
    /// # Safety
    ///
    /// All supplied owners must be isolated, process-lifetime test statics.
    /// The caller must make this the sole setup attempt and retain them for
    /// every use of the returned binding.
    #[cfg(test)]
    pub(crate) unsafe fn test_prepare_vm_process_backing_binding(
        &'static self,
        config: MemoryConfig,
        options: VmOptions,
        subprocess: &'static MainSubprocess,
        page_map_storage: &'static ProcessPageMapStorage,
    ) -> Result<ProcessMainBackingBinding, ProcessMainInitError> {
        if self
            .state
            .compare_exchange(COLD, INITIALIZING, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(ProcessMainInitError::AlreadyInitialized);
        }
        let policy = match VmPolicy::new(options) {
            Ok(policy) => policy,
            Err(error) => {
                self.mark_retained();
                return Err(ProcessMainInitError::VmPolicy(error));
            }
        };
        unsafe { self.test_prepare_vm_process_backing_binding_after_claim(
            config, policy, subprocess, page_map_storage,
        ) }
    }

    /// Binds a captured source-option output owner to the same isolated
    /// process/PageMap proof used by policy-aware arena reservations.
    ///
    /// # Safety
    /// The supplied owners have isolated process lifetime. `output` has
    /// completed source-option initialization, remains live for every policy
    /// read, and owns its registered callback through those reads.
    #[cfg(test)]
    pub(crate) unsafe fn test_prepare_vm_process_backing_binding_with_source_output(
        &'static self,
        config: MemoryConfig,
        output: &'static OutputOwner,
        subprocess: &'static MainSubprocess,
        page_map_storage: &'static ProcessPageMapStorage,
    ) -> Result<ProcessMainBackingBinding, ProcessMainInitError> {
        if self.state.compare_exchange(COLD, INITIALIZING, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(ProcessMainInitError::AlreadyInitialized);
        }
        // SAFETY: the caller retains the initialized source-option owner for
        // every later policy read and warning delivery.
        let policy = unsafe { VmPolicy::from_process_options(output) };
        unsafe { self.test_prepare_vm_process_backing_binding_after_claim(
            config, policy, subprocess, page_map_storage,
        ) }
    }

    /// Continues the test-only backing proof after claiming this coordinator.
    ///
    /// # Safety
    /// `self` owns INITIALIZING and all supplied owners have isolated process
    /// lifetime. No other caller may initialize this coordinator.
    #[cfg(test)]
    unsafe fn test_prepare_vm_process_backing_binding_after_claim(
        &'static self,
        mut config: MemoryConfig,
        policy: VmPolicy,
        subprocess: &'static MainSubprocess,
        page_map_storage: &'static ProcessPageMapStorage,
    ) -> Result<ProcessMainBackingBinding, ProcessMainInitError> {
        // SAFETY: this test-only method owns the successful COLD ->
        // INITIALIZING transition and the supplied owners are all static.
        let process = match unsafe {
            self.retain_vm_process(policy, subprocess, &mut config, false, true)
        } {
            Ok(process) => process,
            Err(error) => {
                self.mark_retained();
                return Err(error);
            }
        };
        let page_map = match page_map_storage.initialize(config, subprocess) {
            Ok(page_map) => page_map,
            Err(error) => {
                self.mark_retained();
                return Err(ProcessMainInitError::PageMap(error));
            }
        };
        // SAFETY: the test owns this INITIALIZING storage and supplies final
        // static owners. These are the same final tuple slots production
        // records before it issues its metadata-binding capability.
        unsafe { (*self.config.get()).write(config) };
        self.subprocess.store(subprocess.owner_ptr(), Ordering::Release);
        self.page_map_storage
            .store(core::ptr::from_ref(page_map_storage).cast_mut(), Ordering::Release);
        Ok(ProcessMainBackingBinding::new(self, process, page_map))
    }

    /// Test counterpart that binds a fresh process-policy coordinator to an
    /// already initialized map lease after a source main attachment exists.
    /// This lets child-page tests share the exact process-global map used by
    /// their parent Heap fixture instead of constructing a second map that
    /// only looks equivalent.
    ///
    /// # Safety
    /// `self` and all pointed-to owners are isolated leaked test statics; this
    /// is their sole binding attempt. The supplied map remains live for every
    /// use of the returned binding.
    #[cfg(test)]
    pub(crate) unsafe fn test_bind_vm_process_to_existing_page_map(
        &'static self,
        mut config: MemoryConfig,
        options: VmOptions,
        subprocess: &'static MainSubprocess,
        page_map: ProcessPageMapRoot,
    ) -> Result<ProcessMainBackingBinding, ProcessMainInitError> {
        if self
            .state
            .compare_exchange(COLD, INITIALIZING, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(ProcessMainInitError::AlreadyInitialized);
        }
        let map_config = match page_map.memory_config() {
            Ok(config) => config,
            Err(error) => {
                self.mark_retained();
                return Err(ProcessMainInitError::PageMap(error));
            }
        };
        let map_subprocess = match page_map.subprocess() {
            Ok(subprocess) => subprocess,
            Err(error) => {
                self.mark_retained();
                return Err(ProcessMainInitError::PageMap(error));
            }
        };
        if map_config != config {
            self.mark_retained();
            return Err(ProcessMainInitError::ConfigurationMismatch);
        }
        if !core::ptr::eq(map_subprocess, subprocess) {
            self.mark_retained();
            return Err(ProcessMainInitError::SubprocessMismatch);
        }
        let policy = match VmPolicy::new(options) {
            Ok(policy) => policy,
            Err(error) => {
                self.mark_retained();
                return Err(ProcessMainInitError::VmPolicy(error));
            }
        };
        // SAFETY: this helper owns INITIALIZING and the explicit isolated test
        // coordinator is the sole writer of the policy slot.
        let process = match unsafe { self.retain_vm_process(policy, subprocess, &mut config, false, true) } {
            Ok(process) => process,
            Err(error) => {
                self.mark_retained();
                return Err(error);
            }
        };
        unsafe { (*self.config.get()).write(config) };
        self.subprocess.store(subprocess.owner_ptr(), Ordering::Release);
        self.page_map_storage.store(page_map.storage_pointer(), Ordering::Release);
        let Some(thread) = current_thread_identity() else {
            self.mark_retained();
            return Err(ProcessMainInitError::Preflight(MainStaticTheapError::InvalidCurrentThread));
        };
        self.initializing_thread.store(thread.get(), Ordering::Relaxed);
        self.state.store(SOURCE_ATTACHED, Ordering::Release);
        Ok(ProcessMainBackingBinding::new(self, process, page_map))
    }

    /// Moves one resolved policy into its permanent process slot and returns
    /// the address-stable owner.  The source once claim is held by the caller;
    /// this method refuses an unexpected second slot instead of overwriting a
    /// policy that a retained process may still have exposed.
    unsafe fn bind_vm_policy(
        &'static self,
        policy: VmPolicy,
    ) -> Result<&'static VmPolicy, ProcessMainInitError> {
        if !self.vm_policy_ptr.load(Ordering::Acquire).is_null() {
            return Err(ProcessMainInitError::VmPolicyAlreadyBound);
        }
        // SAFETY: the source once claimant is the sole writer before READY;
        // this inline slot has process lifetime and is never replaced.
        unsafe { (*self.vm_policy.get()).write(policy) };
        let pointer = self.vm_policy.get().cast::<VmPolicy>();
        // SAFETY: the previous write initialized this exact inline slot, and
        // it remains alive until process termination.
        let policy = unsafe { &*pointer };
        self.vm_policy_ptr.store(pointer, Ordering::Release);
        Ok(policy)
    }

    #[inline]
    fn mark_retained(&self) {
        self.state.store(RETAINED, Ordering::Release);
    }

    /// Classifies a caller that did not receive the source once completion
    /// token.
    ///
    /// A distinct caller can reach this only after `AllocatorOnce` releases
    /// its retained private lock, and `publish_terminal_state_and_release`
    /// stores READY or RETAINED before that release. Therefore INITIALIZING
    /// here is specifically the same-thread recursive/reentry refusal, not a
    /// transient result for a racing caller. `COLD` can occur in the small
    /// interval after a once claim but before this coordinator records
    /// INITIALIZING, or during the documented pre-body cancellation handoff;
    /// both retain the same safe reentry meaning.
    #[inline]
    fn outcome_after_process_once<T>(&self) -> Result<T, ProcessMainInitError> {
        match self.state.load(Ordering::Acquire) {
            COLD | INITIALIZING | SOURCE_ATTACHED => Err(ProcessMainInitError::Initializing),
            READY => Err(ProcessMainInitError::AlreadyInitialized),
            RETAINED | _ => Err(ProcessMainInitError::Retained),
        }
    }

    /// Publishes one terminal process result before releasing the retained
    /// source-shaped once lock.
    ///
    /// `AllocatorOnceCompletion::complete` stores its source `tid = 1` with
    /// Release ordering and then unlocks. Keeping the process state store
    /// before that operation gives a blocked nonrecursive caller one complete
    /// release chain: it cannot return until both the final state and all
    /// preceding source-root writes are visible. Its possible futex-wake error
    /// occurs after that atomic unlock; as in the C void release, it cannot
    /// revoke an already-published terminal result or reopen/retry startup.
    fn publish_terminal_state_and_release(
        &self,
        completion: AllocatorOnceCompletion<'_>,
        terminal_state: u8,
    ) {
        self.publish_terminal_state_and_release_with_hook(completion, terminal_state, || {});
    }

    fn publish_terminal_state_and_release_with_hook<F>(
        &self,
        completion: AllocatorOnceCompletion<'_>,
        terminal_state: u8,
        before_release: F,
    ) where
        F: FnOnce(),
    {
        debug_assert!(matches!(terminal_state, READY | RETAINED));
        self.state.store(terminal_state, Ordering::Release);
        before_release();
        // The source macro's release is void. `AllocatorOnceCompletion` has
        // already published and atomically unlocked before a wake error can
        // be reported, so changing READY to RETAINED here would race an
        // awakened caller and falsely imply a retry boundary. Preserve the
        // immutable terminal result and intentionally mirror the source's
        // no-retry release policy.
        let _completion_result = completion.complete();
    }
}

/// Linear remainder of pinned process startup after the default Theap is
/// valid. It owns the source once completion and immutable VM inputs, never
/// an attachment/Theap/random borrow. Dropping it retains the published owner.
#[must_use = "source startup must complete or retain its already-published owner"]
pub(crate) struct ProcessMainStartup {
    storage: &'static ProcessMainInitializationStorage,
    completion: Option<AllocatorOnceCompletion<'static>>,
    config: MemoryConfig,
    vm_process: Option<VmProcess<'static>>,
    metadata: core::pin::Pin<&'static MetaAllocator>,
    #[cfg(target_arch = "x86_64")]
    subprocess: &'static MainSubprocess,
    #[cfg(target_arch = "x86_64")]
    startup_owner: crate::main_theap::MainStaticStartupOwnerBinding,
    #[cfg(target_arch = "x86_64")]
    diagnostics: ProcessStartupDiagnostics<'static>,
    #[cfg(target_arch = "x86_64")]
    entry: ProcessStartEntry,
    _not_send_or_sync: PhantomData<*mut ()>,
}

/// Output authority for an allocation issued by the ordinary initial
/// Theap after attachment and before the winning startup completes. The
/// borrowed completion and original owner binding remain live through the
/// synchronous callback; no Heap, Theap, or random reference crosses output.
#[cfg(target_arch = "x86_64")]
pub(crate) struct SourceAttachedRuntimeOutputWitness<'startup> {
    startup: &'startup ProcessMainStartup,
    process: VmProcess<'static>,
    output: &'static OutputOwner,
    page_map: ProcessPageMapRoot,
    _not_send_or_sync: PhantomData<*mut ()>,
}

#[cfg(target_arch = "x86_64")]
impl SourceAttachedRuntimeOutputWitness<'_> {
    fn validate(&self) -> Result<(), BootstrapOutputAdmissionError> {
        let startup = self.startup;
        let thread = current_thread_identity().ok_or(BootstrapOutputAdmissionError::Invalid)?;
        let once_thread = OnceThreadId::new(thread.get()).ok_or(BootstrapOutputAdmissionError::Invalid)?;
        if startup.storage.state.load(Ordering::Acquire) != SOURCE_ATTACHED
            || thread.get() != startup.storage.initializing_thread.load(Ordering::Relaxed)
            || !startup.completion.as_ref().is_some_and(|completion|
                completion.matches_active_owner(&startup.storage.process_once, once_thread))
            || !core::ptr::eq(startup.storage.diagnostic_output_ptr.load(Ordering::Acquire), self.output)
            || !core::ptr::eq(startup.storage.vm_policy_ptr.load(Ordering::Acquire), self.process.policy())
            || !self.process.main_subprocess().is_some_and(|owner| core::ptr::eq(owner, startup.subprocess))
            || startup.storage.page_map_storage.load(Ordering::Acquire).is_null()
            // SAFETY: the factory caller retains the actual attachment and
            // excludes teardown throughout this synchronous witness scope.
            || !unsafe { startup.startup_owner.validate(startup.subprocess) }
        { return Err(BootstrapOutputAdmissionError::Invalid); }
        Ok(())
    }

    pub(crate) fn selected_theap(&self) -> NonNull<crate::types::Theap> { self.startup.startup_owner.theap }
    pub(crate) fn heap(&self) -> NonNull<crate::types::Heap> { self.startup.startup_owner.heap }
    pub(crate) fn process(&self) -> Result<VmProcess<'_>, BootstrapOutputAdmissionError> {
        self.validate()?; Ok(self.process)
    }
    pub(crate) fn output(&self) -> Result<&OutputOwner, BootstrapOutputAdmissionError> {
        self.validate()?; Ok(self.output)
    }
    pub(crate) fn page_map(&self) -> Result<ProcessPageMapRoot, BootstrapOutputAdmissionError> {
        self.validate()?; Ok(self.page_map)
    }
    pub(crate) fn matches_theap(&self, theap: NonNull<crate::types::Theap>) -> bool {
        self.validate().is_ok() && self.selected_theap() == theap
    }
    pub(crate) fn matches_subprocess(&self, subprocess: &crate::subproc::SubprocessIdentity) -> bool {
        self.validate().is_ok() && core::ptr::eq(self.process.subprocess(), subprocess)
    }
}

impl ProcessMainStartup {
    /// Runs one synchronous operation with the original ordinary startup
    /// issuer and the winning completion. Refusal never falls back to a
    /// completed-process owner or to the current TLS default Theap.
    ///
    /// # Safety
    /// The exact ProcessMainThread produced with this startup is already in
    /// its final runtime owner slot and remains retained throughout callback.
    /// The caller holds actual process/initial-thread admission and excludes
    /// attachment teardown, selected Heap deletion, and client reuse. The
    /// callback holds no image projections across output and cannot persist
    /// this witness or consume the startup completion.
    #[cfg(target_arch = "x86_64")]
    pub(crate) unsafe fn with_source_attached_runtime_output<R>(
        &self,
        callback: impl for<'scope> FnOnce(&SourceAttachedRuntimeOutputWitness<'scope>) -> R,
    ) -> Result<R, BootstrapOutputAdmissionError> {
        let process = self.vm_process.ok_or(BootstrapOutputAdmissionError::Unavailable)?;
        let output = match self.diagnostics {
            ProcessStartupDiagnostics::Selected(output) => output,
            ProcessStartupDiagnostics::Unconnected => return Err(BootstrapOutputAdmissionError::Unavailable),
        };
        let page_map = self.storage.allocation_lease(self.config, self.subprocess)
            .and_then(|lease| lease.page_map()).map_err(|_| BootstrapOutputAdmissionError::Invalid)?;
        let witness = SourceAttachedRuntimeOutputWitness {
            startup: self, process, output, page_map, _not_send_or_sync: PhantomData,
        };
        witness.validate()?;
        Ok(callback(&witness))
    }

    pub(crate) fn complete(self) -> Result<(), ProcessMainInitError> {
        self.complete_with_hook(|| {})
    }

    fn complete_with_hook(self, before_release: impl FnOnce()) -> Result<(), ProcessMainInitError> {
        self.complete_once_body_with_hook(before_release)?.complete()
    }

    /// Completes `mi_process_init` and releases its once envelope, returning
    /// the separate `_mi_auto_process_init` diagnostic/reseed continuation.
    /// The embedding runtime must publish its completed process owner and
    /// release any outer initialization-once claim before completing the tail.
    pub(crate) fn complete_once_body(self) -> Result<ProcessMainRuntimeStartupTail, ProcessMainInitError> {
        self.complete_once_body_with_hook(|| {})
    }

    fn complete_once_body_with_hook(self, before_release: impl FnOnce()) -> Result<ProcessMainRuntimeStartupTail, ProcessMainInitError> {
        self.complete_once_body_inner_with_hook(before_release, false)
    }

    /// Completes source reservations with the original ordinary startup
    /// output issuer installed only for their synchronous callback scope.
    ///
    /// # Safety
    /// The paired initial ProcessMainThread is retained in its final runtime
    /// slot. Its actual process and thread admission exclude teardown while
    /// reservations and their callbacks run. No owner/image projections are
    /// held across this call.
    #[cfg(target_arch = "x86_64")]
    pub(crate) unsafe fn complete_once_body_with_runtime_output(self) -> Result<ProcessMainRuntimeStartupTail, ProcessMainInitError> {
        self.complete_once_body_inner_with_hook(|| {}, true)
    }

    fn complete_once_body_inner_with_hook(mut self, before_release: impl FnOnce(), runtime_output: bool) -> Result<ProcessMainRuntimeStartupTail, ProcessMainInitError> {
        #[cfg(not(target_arch = "x86_64"))]
        let _ = runtime_output;
        self.storage.ensure_allocation_ready()?;
        if self.storage.state.load(Ordering::Acquire) != SOURCE_ATTACHED {
            return Err(ProcessMainInitError::Retained);
        }
        let config = self.config;
        let vm_process = self.vm_process;
        let metadata = self.metadata;
        #[cfg(target_arch = "x86_64")]
        let diagnostics = self.diagnostics;
        // Source startup reserves huge memory first and regular memory next,
        // after the default Theap/TLS attachment exists. Failed reservations
        // do not prevent READY; their exact cleanup owners remain retained.
        // SAFETY: the source startup owner retains the current default root;
        // this value holds no attachment/Theap borrow across VM callbacks.
        let mut random = unsafe { crate::os::CurrentDefaultTheapRandom::new() };
        #[cfg(target_arch = "x86_64")]
        let reservations = match (vm_process, diagnostics) {
            (Some(process), ProcessStartupDiagnostics::Selected(output)) => {
                // SAFETY: this source once winner still owns startup; the
                // retained output owner predates VM/OS/arena work. Initial-thread
                // callback allocation is admitted without borrowing this owner.
                let mut reserve = || unsafe { process.subprocess().arena_backing().reserve_startup_options_with_mbind_warning(
                    process, config, metadata, Some(&mut random), MbindWarningRoute::new(output),
                ) };
                if runtime_output {
                    // SAFETY: the runtime-specific entry retains the paired
                    // published owner and excludes teardown; the installer
                    // holds its actual admission until this callback returns.
                    unsafe { self.with_source_attached_runtime_output(|witness| {
                        crate::runtime_lifecycle::with_source_attached_runtime_allocation_output(witness, reserve)
                    }) }.map_err(|_| ProcessMainInitError::Retained)?
                        .map_err(|_| ProcessMainInitError::Retained)?
                } else {
                    reserve()
                }
            }
            (Some(process), ProcessStartupDiagnostics::Unconnected) => {
                unsafe { process.subprocess().arena_backing().reserve_startup_options(process,
                    config, metadata, Some(&mut random)) }
            }
            (None, ProcessStartupDiagnostics::Unconnected) => {
                crate::arena::StartupArenaReservationOutcomes::empty()
            }
            (None, ProcessStartupDiagnostics::Selected(_)) => unreachable!(
                "mandatory diagnostic startup always owns one source VM process"
            ),
        };
        #[cfg(target_arch = "aarch64")]
        let reservations = if let Some(process) = vm_process {
            unsafe { process.subprocess().arena_backing().reserve_startup_options(process,
                config, metadata, Some(&mut random)) }
        } else { crate::arena::StartupArenaReservationOutcomes::empty() };
        unsafe { (*self.storage.startup_reservations.get()).write(reservations) };

        if self.storage.state.load(Ordering::Acquire) != SOURCE_ATTACHED {
            return Err(ProcessMainInitError::Retained);
        }
        let completion = self.completion.take().ok_or(ProcessMainInitError::Retained)?;
        self.storage.publish_terminal_state_and_release_with_hook(completion, READY, before_release);
        Ok(ProcessMainRuntimeStartupTail {
            #[cfg(target_arch = "x86_64")]
            storage: self.storage,
            #[cfg(target_arch = "x86_64")]
            metadata,
            #[cfg(target_arch = "x86_64")]
            subprocess: self.subprocess,
            #[cfg(target_arch = "x86_64")]
            diagnostics,
            #[cfg(target_arch = "x86_64")]
            entry: self.entry,
            _not_send_or_sync: PhantomData,
        })
    }
}

/// The loader-only remainder after `mi_process_init` has published readiness
/// and released once. It carries immutable process inputs, so synchronous
/// diagnostic reentry cannot borrow or hold an initializing owner. A
/// first-allocation entry deliberately leaves this tail for runtime startup.
#[must_use = "runtime startup must complete its diagnostic and random-reseed tail"]
pub(crate) struct ProcessMainRuntimeStartupTail {
    #[cfg(target_arch = "x86_64")]
    storage: &'static ProcessMainInitializationStorage,
    #[cfg(target_arch = "x86_64")]
    metadata: core::pin::Pin<&'static MetaAllocator>,
    #[cfg(target_arch = "x86_64")]
    subprocess: &'static MainSubprocess,
    #[cfg(target_arch = "x86_64")]
    diagnostics: ProcessStartupDiagnostics<'static>,
    #[cfg(target_arch = "x86_64")]
    entry: ProcessStartEntry,
    _not_send_or_sync: PhantomData<*mut ()>,
}

impl ProcessMainRuntimeStartupTail {
    pub(crate) fn complete(self) -> Result<(), ProcessMainInitError> {
        #[cfg(target_arch = "x86_64")]
        if self.entry == ProcessStartEntry::RuntimeStartup {
            // Loader startup is serialized by its caller. Claim before
            // delivery so recursive runtime entry never repeats the flush.
            if self.storage.runtime_startup_tail.swap(true, Ordering::AcqRel) {
                return Ok(());
            }
            let output = match self.diagnostics {
                ProcessStartupDiagnostics::Selected(output) => Some(output),
                ProcessStartupDiagnostics::Unconnected => None,
            };
            // SAFETY: the original initial thread owns this loader tail and
            // no attachment/Theap/random projection spans output delivery.
            unsafe { run_runtime_startup_tail(output, self.metadata, self.subprocess) }?;
        }
        Ok(())
    }
}

impl Drop for ProcessMainStartup {
    fn drop(&mut self) {
        if let Some(completion) = self.completion.take() {
            self.storage.publish_terminal_state_and_release(completion, RETAINED);
        }
    }
}

/// `mi_option_get(option)` at an engine read point with no [`VmProcess`] in
/// scope, such as `mi_theap_options_init` (`src/theap.c:228-233`).
///
/// C reads the one global `mi_options[]`; this reads the process table of
/// the production coordinator once x86 startup has installed it. Before
/// then, on isolated fixture coordinators, and on the paused AArch64
/// process (which has no table), the read returns the pinned release
/// default, which is what every such read point used before the table
/// existed.
#[inline]
pub(crate) fn process_source_option(option: crate::config::SourceOption) -> i64 {
    #[cfg(target_arch = "x86_64")]
    if let Some(output) = ProcessMainInitializationStorage::global().published_source_options() {
        // SAFETY: a published owner has an installed table, and every lazy
        // retry delivers through the process output route as C's
        // `mi_option_get` does.
        return unsafe { output.option_value(option) };
    }
    option.default_value()
}

/// `_mi_warning_message(...)` for one source warning site, delivered through
/// the process output owner's `verbose`/`show_errors`/`max_warnings` gate.
/// Before x86 startup has installed the table (and on the paused AArch64
/// process) no output owner exists and the release defaults suppress it.
///
/// The caller must hold no page-engine, owner, TLD, or Theap projection: a
/// registered output callback may reenter the allocator, as it may in C.
pub(crate) fn process_warning_message(message: crate::diagnostic_output::SourceFormattedMessage) {
    #[cfg(target_arch = "x86_64")]
    if let Some(output) = ProcessMainInitializationStorage::global().published_source_options() {
        // SAFETY: a published owner has an installed table; the caller holds
        // no allocator projection across this warning's delivery.
        unsafe { output.warning_from_source_options(message) };
    }
    #[cfg(not(target_arch = "x86_64"))]
    let _ = message;
}

/// `_mi_error_message(err, ...)` for one release-live allocation site,
/// reported through the process output owner's `show_errors`/`verbose`/
/// `max_errors` gate and error handler.
///
/// The caller must hold no page-engine, owner, TLD, or Theap projection: a
/// registered output or error callback may reenter the allocator, as it may
/// in C. Before x86 startup has installed the table (and on the paused
/// AArch64 process) no output owner exists; the source default disposition
/// is returned without output, as C's gate is closed by its release option
/// defaults.
pub(crate) fn process_error_message(
    report: crate::diagnostic_output::SourceErrorReport,
) -> crate::diagnostic_output::SourceErrorDisposition {
    #[cfg(target_arch = "x86_64")]
    let disposition = match ProcessMainInitializationStorage::global().published_source_options() {
        // SAFETY: a published owner has an installed table; the caller holds
        // no allocator projection across this report's deliveries.
        Some(output) => unsafe { output.error_message(report.error(), report.message()) },
        None => report.default_disposition(),
    };
    #[cfg(not(target_arch = "x86_64"))]
    let disposition = report.default_disposition();
    #[cfg(feature = "native-runtime-test-audit")]
    record_source_error_for_test_audit(report, disposition);
    disposition
}

#[cfg(feature = "native-runtime-test-audit")]
static SOURCE_ERROR_AUDIT_CODE: AtomicUsize = AtomicUsize::new(0);
#[cfg(feature = "native-runtime-test-audit")]
static SOURCE_ERROR_AUDIT_ERRNO: AtomicUsize = AtomicUsize::new(0);

/// Records the errno C's `mi_error_default` would leave: it writes only
/// while errno is still zero, so the first default report since the last
/// take wins.
#[cfg(feature = "native-runtime-test-audit")]
fn record_source_error_for_test_audit(
    report: crate::diagnostic_output::SourceErrorReport,
    disposition: crate::diagnostic_output::SourceErrorDisposition,
) {
    if let crate::diagnostic_output::SourceErrorDisposition::DefaultErrno(errno) = disposition {
        if SOURCE_ERROR_AUDIT_ERRNO
            .compare_exchange(0, errno.raw() as usize, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            SOURCE_ERROR_AUDIT_CODE.store(report.error().raw() as usize, Ordering::Release);
        }
    }
}

/// The first defaulted `_mi_error_message` report since the previous take.
#[cfg(feature = "native-runtime-test-audit")]
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeSourceErrorAudit {
    pub code: i32,
    pub default_errno: i32,
}

/// Takes and clears the first defaulted source error report.
#[cfg(feature = "native-runtime-test-audit")]
#[doc(hidden)]
pub fn native_runtime_take_source_error_test_audit() -> Option<NativeSourceErrorAudit> {
    let errno = SOURCE_ERROR_AUDIT_ERRNO.swap(0, Ordering::AcqRel);
    let code = SOURCE_ERROR_AUDIT_CODE.swap(0, Ordering::AcqRel);
    (errno != 0).then_some(NativeSourceErrorAudit { code: code as i32, default_errno: errno as i32 })
}

/// The process diagnostic output owner and its option table, once x86
/// startup has published them.
#[cfg(target_arch = "x86_64")]
#[inline]
pub(crate) fn process_output_owner() -> Option<&'static OutputOwner> {
    ProcessMainInitializationStorage::global().published_source_options()
}

/// `_mi_option_get_fast(option)` counterpart of [`process_source_option`].
#[inline]
pub(crate) fn process_source_option_fast(option: crate::config::SourceOption) -> i64 {
    #[cfg(target_arch = "x86_64")]
    if let Some(output) = ProcessMainInitializationStorage::global().published_source_options() {
        // SAFETY: a published owner has an installed table.
        return unsafe { output.option_get_fast(option) };
    }
    option.default_value()
}

static PROCESS_MAIN_INITIALIZATION: ProcessMainInitializationStorage =
    ProcessMainInitializationStorage::new();

/// The shared tail of pinned `_mi_auto_process_init` (`src/init.c:506-533`)
/// after its `mi_process_init`: `_mi_options_post_init`, then
/// `_mi_random_reinit_if_weak` for the caller's default Theap and, under
/// `theap_meta_lock`, for the subprocess metadata Theap.
///
/// `mi_process_setup_auto_thread_done` has no receiver here: the embedding
/// runtime owns pthread-exit hooks. The redirect message is inapplicable
/// because this engine is linked, never interposed. A private-lock or
/// metadata-binding failure is reported rather than skipping the reseed.
///
/// # Safety
///
/// The caller is the initial source thread, holds no attachment, Theap, or
/// random projection, and owns `_mi_options_post_init`'s one-time
/// serialization against every other diagnostic dispatch.
#[cfg(target_arch = "x86_64")]
unsafe fn run_runtime_startup_tail(
    output: Option<&'static OutputOwner>,
    metadata: core::pin::Pin<&'static MetaAllocator>,
    subprocess: &'static MainSubprocess,
) -> Result<(), ProcessMainInitError> {
    if let Some(output) = output {
        // SAFETY: forwarded; the delayed buffer is flushed exactly once
        // because both callers first claim `runtime_startup_tail`.
        unsafe { output.post_init() };
    }
    let report_retry = |result: crate::random::RandomReinitialization| {
        if result.attempted && result.remains_weak {
            if let Some(output) = output {
                // SAFETY: the startup caller retains this output route; both
                // the random projection and any metadata entry lock ended
                // before delivery, so a foreign callback may reenter.
                unsafe { output.warning_from_source_options(
                    crate::diagnostic_output::SourceFormattedMessage::from_source_formatted(
                        c"unable to use secure randomness\n",
                    ),
                ) };
            }
        }
    };
    // SAFETY: the current default Theap belongs to this initial source
    // thread, and no projection of it is live across this field access.
    let current = unsafe { crate::types::Theap::reinitialize_random_if_weak_at(crate::compiler_tls::default_theap()) };
    report_retry(current);
    let detached = metadata
        .reinitialize_detached_metadata_random_if_weak(subprocess)
        .map_err(ProcessMainInitError::Metadata)?;
    report_retry(detached);
    Ok(())
}

/// Embedding-owned writer for the calling thread's C errno slot.
///
/// This capability carries no borrowed TLS reference. Each invocation resolves
/// the slot on the calling thread, so retained process policy can publish a
/// captured syscall error before a diagnostic callback observes it.
#[cfg(target_arch = "x86_64")]
#[doc(hidden)]
#[derive(Clone, Copy)]
pub struct SourceErrnoStore {
    store: unsafe fn(core::ffi::c_int),
    default_store: Option<unsafe fn(core::ffi::c_int)>,
}

#[cfg(target_arch = "x86_64")]
impl SourceErrnoStore {
    /// Retains an embedding's current-thread errno writer.
    ///
    /// # Safety
    /// The function must remain callable for the process lifetime. It must
    /// write only the calling thread's C errno slot, retain no TLS reference,
    /// and neither allocate through this engine nor unwind. Startup must have
    /// installed that thread's TLS before any policy using this capability.
    pub const unsafe fn new(store: unsafe fn(core::ffi::c_int)) -> Self {
        Self { store, default_store: None }
    }

    /// Adds the embedding's writer for default, unhandled source errors.
    ///
    /// # Safety
    /// The function must remain callable for the process lifetime and write
    /// the supplied value only when the calling thread's current C errno is
    /// zero. It must retain no TLS reference and never allocate or unwind.
    /// Every invoking thread must have installed TLS.
    pub const unsafe fn with_default_store(mut self, store: unsafe fn(core::ffi::c_int)) -> Self {
        self.default_store = Some(store);
        self
    }

    /// Invokes the optional conditional writer after source diagnostics.
    ///
    /// `None` reports that no default writer was supplied. `Some(())` means
    /// the provider was invoked, not that errno changed: a nonzero value left
    /// by a warning or error callback must remain authoritative.
    #[inline]
    pub fn store_default(self, errno: crabc_core::Errno) -> Option<()> {
        let store = self.default_store?;
        // SAFETY: adoption retains a process-lifetime current-thread provider
        // that checks its own TLS slot without exporting a borrow or value.
        unsafe { store(errno.raw()) };
        Some(())
    }

    /// Publishes a captured positive Linux error on the calling thread.
    #[inline]
    pub fn store(self, errno: crabc_core::Errno) {
        // SAFETY: construction retains the embedding's process-lifetime,
        // current-thread writer; no TLS reference crosses this call.
        unsafe { (self.store)(errno.raw()) };
    }
}

/// Raw, nonowning process-start facts for the selected x86 native runtime.
///
/// Pinned mimalloc's Unix primitives observe the kernel base page size, the C
/// `environ` vector (`src/prim/unix/prim.c:874-905`), and the process
/// `stderr` FILE directly. This engine may not reach public libc, `/proc`, or
/// `getauxval` for those observations, so the embedding runtime publishes
/// them once, before any allocation can reach the engine. Explicit runtime
/// startup and a lazy first allocation then consume this same image.
///
/// Nothing here is owned. The environment reader borrows the embedding
/// runtime's current environment on each call, including later lazy option
/// retries after a coordinated environment mutation, and the output
/// primitive borrows its FILE provider. An optional errno writer lets guarded
/// protection failures publish their captured error before warning delivery;
/// embeddings without C errno leave that capability absent. `AT_RANDOM` and
/// the remaining auxiliary vector are intentionally absent: pinned v3.5.0 draws
/// `_mi_prim_random_buf` from `getrandom` directly and reads no other auxv
/// entry, so copying the startup key would add an unused, lifetime-sensitive
/// secret rather than a source input.
#[cfg(target_arch = "x86_64")]
#[doc(hidden)]
#[derive(Clone, Copy)]
pub struct NativeProcessStartupFacts {
    page_size: crate::os::PageSize,
    environment_reader: VmOptionEnvironmentReader,
    stderr_output: crate::diagnostic_output::RuntimeStderrOutput,
    source_errno_store: Option<SourceErrnoStore>,
}

#[cfg(target_arch = "x86_64")]
impl NativeProcessStartupFacts {
    /// Builds one startup image from runtime-validated `AT_PAGESZ`, the
    /// runtime's source environment reader, and its selected FILE output.
    ///
    /// Returns `None` when `page_size_bytes` is not a supported Linux/x86-64
    /// base page size; no image with an invalid page geometry can exist.
    ///
    /// # Safety
    ///
    /// For the complete process lifetime, every call to `environment_reader`
    /// must return null or a NUL-terminated C environment vector whose
    /// non-null entries remain valid NUL-terminated strings for the duration
    /// of that observation, with the direct-mutation coordination pinned
    /// `_mi_prim_getenv` requires of `environ`. The reader must not allocate
    /// through this engine or unwind. `stderr_output` carries the obligations
    /// documented on [`crate::diagnostic_output::RuntimeStderrOutput::new`].
    #[inline]
    pub unsafe fn new(
        page_size_bytes: usize,
        environment_reader: unsafe fn() -> *const *const core::ffi::c_char,
        stderr_output: crate::diagnostic_output::RuntimeStderrOutput,
    ) -> Option<Self> {
        Some(Self {
            page_size: crate::os::PageSize::new(page_size_bytes)?,
            environment_reader,
            stderr_output,
            source_errno_store: None,
        })
    }

    /// Adds the embedding's explicit current-thread errno writer.
    #[inline]
    pub const fn with_source_errno_store(mut self, store: SourceErrnoStore) -> Self {
        self.source_errno_store = Some(store);
        self
    }

    /// Returns the optional embedding-owned writer without borrowing TLS.
    #[inline]
    pub const fn source_errno_store(&self) -> Option<SourceErrnoStore> {
        self.source_errno_store
    }

    #[inline]
    pub(crate) const fn page_size(&self) -> crate::os::PageSize {
        self.page_size
    }

    #[inline]
    pub(crate) const fn environment_reader(&self) -> VmOptionEnvironmentReader {
        self.environment_reader
    }

    #[inline]
    pub(crate) const fn stderr_output(&self) -> crate::diagnostic_output::RuntimeStderrOutput {
        self.stderr_output
    }
}

#[cfg(target_arch = "x86_64")]
const STARTUP_FACTS_ABSENT: u8 = 0;
#[cfg(target_arch = "x86_64")]
const STARTUP_FACTS_WRITING: u8 = 1;
#[cfg(target_arch = "x86_64")]
const STARTUP_FACTS_PUBLISHED: u8 = 2;

/// One-way, allocation-free publication slot for [`NativeProcessStartupFacts`].
///
/// The first publisher alone moves ABSENT -> WRITING, writes the image, and
/// Release-publishes PUBLISHED. The image is never replaced, so a reader that
/// Acquire-observes PUBLISHED may copy it at any later time. A reader that
/// races the single write observes no facts, which is the same allocation-free
/// refusal as a process whose runtime has not published them yet.
#[cfg(target_arch = "x86_64")]
pub(crate) struct ProcessStartupFactsCell {
    state: AtomicU8,
    facts: UnsafeCell<MaybeUninit<NativeProcessStartupFacts>>,
}

// SAFETY: the ABSENT -> WRITING CAS grants one writer exclusive access to the
// inline image before its Release publication; afterwards the image is only
// copied out and never mutated.
#[cfg(target_arch = "x86_64")]
unsafe impl Sync for ProcessStartupFactsCell {}

#[cfg(target_arch = "x86_64")]
impl ProcessStartupFactsCell {
    pub(crate) const fn new() -> Self {
        Self {
            state: AtomicU8::new(STARTUP_FACTS_ABSENT),
            facts: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    /// The one production slot consumed by the runtime process owner.
    #[inline]
    pub(crate) fn global() -> &'static Self {
        &PROCESS_STARTUP_FACTS
    }

    /// Publishes `facts` unless an earlier image already fixed this process.
    /// A refused later image is dropped without touching the published one.
    pub(crate) fn publish(&self, facts: NativeProcessStartupFacts) -> bool {
        if self
            .state
            .compare_exchange(
                STARTUP_FACTS_ABSENT,
                STARTUP_FACTS_WRITING,
                Ordering::Acquire,
                Ordering::Relaxed,
            )
            .is_err()
        {
            return false;
        }
        // SAFETY: the successful CAS above made this caller the sole writer,
        // and no reader copies the slot before the Release store below.
        unsafe { (*self.facts.get()).write(facts) };
        self.state.store(STARTUP_FACTS_PUBLISHED, Ordering::Release);
        true
    }

    /// Copies the published image, or reports that none is visible yet.
    #[inline]
    pub(crate) fn published(&self) -> Option<NativeProcessStartupFacts> {
        if self.state.load(Ordering::Acquire) != STARTUP_FACTS_PUBLISHED {
            return None;
        }
        // SAFETY: PUBLISHED is Release-stored after the only write and the
        // image is never mutated again; `NativeProcessStartupFacts` is Copy.
        Some(unsafe { (*self.facts.get()).assume_init_read() })
    }
}

#[cfg(target_arch = "x86_64")]
static PROCESS_STARTUP_FACTS: ProcessStartupFactsCell = ProcessStartupFactsCell::new();

/// A process-main startup failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProcessMainInitError {
    /// The current thread or compiler-TLS roots were not eligible before any
    /// process source state was selected.
    Preflight(MainStaticTheapError),
    /// The source-shaped once gate could not acquire its private futex lock.
    /// Terminal-completion wake failures are intentionally handled like C's
    /// void release: their atomic publication/unlock already happened, so
    /// they preserve the existing terminal result rather than creating a
    /// retry. A pre-body cancellation wake failure reaches this variant after
    /// it atomically reopens the retryable COLD state.
    Lock(crabc_core::Errno),
    Initializing,
    AlreadyInitialized,
    Retained,
    ConfigurationMismatch,
    SubprocessMismatch,
    /// The supplied source option image still had a lazy unresolved slot.
    VmPolicy(VmPolicyConfigurationError),
    /// A terminal process image already retains a different policy slot.
    VmPolicyAlreadyBound,
    /// The preserved legacy explicit-config startup path reached READY
    /// without a resolved VM policy owner.
    VmPolicyUnavailable,
    SubprocessRegistry(crate::subproc::registry::SourceSubprocessRegistryError),
    BootstrapSelection(MainStaticBootstrapSelectionError),
    HeapFoundation(MainStaticHeapFoundationError),
    #[cfg(target_arch = "x86_64")]
    BootstrapOutput(BootstrapOutputAdmissionError),
    Metadata(MetaError),
    PageMap(ProcessPageMapError),
    InitialThread(MainStaticTheapError),
}

/// Coordinator-issued proof for one canonical VM-backed process root.
///
/// This is deliberately not reconstructible from a [`VmProcess`] and a
/// [`ProcessPageMapRoot`].  Independent test or future process coordinators
/// can legitimately form matching-looking pairs for the same subprocess;
/// only this source-order coordinator proves that the retained policy and
/// PageMap root were selected together before its sole `READY` publication.
/// Metadata and arena backing consumers use this capability instead of
/// accepting an arbitrary pair of copyable witnesses.
#[derive(Clone, Copy)]
pub(crate) struct ProcessMainBackingBinding {
    storage: &'static ProcessMainInitializationStorage,
    process: VmProcess<'static>,
    page_map: ProcessPageMapRoot,
}

/// Source-start regular-arena admission for the bounded ticket-zero bridge.
///
/// This is intentionally not a general process arena enumeration.  It tells
/// the first ordinary page owner whether startup left no published arena, one
/// exact regular parent that it may search, or source state outside the
/// supported first-regular shape.  The final case is fail-closed so a huge or
/// multi-arena startup image cannot be relabeled as an absent option.
#[derive(Clone, Copy)]
pub(crate) enum ProcessStartupRegularArenaSelection {
    Absent,
    Eligible(ProcessStartupRegularArenaLease),
    ExistingOutsideFirstRegularCapability,
    Retained,
}

/// Copyable immutable proof of one source-start regular parent selected with
/// the canonical process policy and PageMap root.
///
/// It exposes neither mapping release nor PageMap mutation.  Each arena view
/// revalidates the process-owned registry/owner admission before use, while
/// the consuming page backing still performs the source search and claim.
#[derive(Clone, Copy)]
pub(crate) struct ProcessStartupRegularArenaLease {
    binding: ProcessMainBackingBinding,
    arena: ArenaId,
}

impl ProcessStartupRegularArenaLease {
    #[inline]
    pub(crate) const fn process(self) -> VmProcess<'static> { self.binding.process() }

    #[inline]
    pub(crate) const fn page_map(self) -> ProcessPageMapRoot { self.binding.page_map() }

    /// Returns the exact published regular parent only while the process
    /// binding remains `READY` and its backing repeats the finite admission.
    #[inline]
    pub(crate) fn arena(self) -> Option<ArenaView<'static>> {
        let config = self.binding.page_map().memory_config().ok()?;
        self.binding
            .process()
            .subprocess()
            .arena_backing()
            .first_regular_startup_arena_view(self.binding.process(), config, self.arena)
    }
}

impl ProcessMainBackingBinding {
    #[inline]
    fn new(
        storage: &'static ProcessMainInitializationStorage,
        process: VmProcess<'static>,
        page_map: ProcessPageMapRoot,
    ) -> Self {
        debug_assert!(matches!(storage.state.load(Ordering::Acquire), INITIALIZING | SOURCE_ATTACHED | READY));
        debug_assert!(core::ptr::eq(
            storage.subprocess.load(Ordering::Acquire),
            process.main_subprocess().expect("process binding is main").owner_ptr(),
        ));
        debug_assert!(!storage.page_map_storage.load(Ordering::Acquire).is_null());
        Self {
            storage,
            process,
            page_map,
        }
    }

    /// Returns the policy/subprocess pair that the process coordinator
    /// retained before forming its canonical PageMap root.
    #[inline]
    pub(crate) const fn process(self) -> VmProcess<'static> { self.process }

    /// Returns the canonical PageMap witness selected with [`Self::process`].
    #[inline]
    pub(crate) const fn page_map(self) -> ProcessPageMapRoot { self.page_map }

    /// Confirms that this capability still names the coordinator's one
    /// retained policy/root pair. Production metadata binding occurs before
    /// READY, while later idempotent consumers see READY; neither state lets
    /// an arbitrary raw pair/map input become a binding capability.
    #[inline]
    pub(crate) fn is_active(self) -> bool {
        matches!(self.storage.state.load(Ordering::Acquire), INITIALIZING | SOURCE_ATTACHED | READY)
    }

    /// Application page ownership requires the source attachment publication;
    /// metadata construction alone does not grant this authority.
    pub(crate) fn is_allocation_ready(self) -> bool {
        self.storage.ensure_allocation_ready().is_ok()
    }

    /// Completes an isolated test binding's startup (`SOURCE_ATTACHED` to
    /// `READY`) so threads other than the binding thread may own pages, as
    /// they may after production startup. Any other state is left unchanged.
    #[cfg(test)]
    pub(crate) fn test_publish_ready(self) -> bool {
        self.storage.state
            .compare_exchange(SOURCE_ATTACHED, READY, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    /// Classifies source startup's regular arena outcome for its one bounded
    /// ticket-zero consumer.  The immutable outcome is written before the
    /// coordinator's `READY` Release; an initializing process cannot expose
    /// it to a page owner.
    pub(crate) fn startup_regular_arena_selection(self) -> ProcessStartupRegularArenaSelection {
        if self.storage.state.load(Ordering::Acquire) != READY {
            return ProcessStartupRegularArenaSelection::Retained;
        }
        let Ok(config) = self.page_map.memory_config() else {
            return ProcessStartupRegularArenaSelection::Retained;
        };
        // SAFETY: READY Release follows the immutable source startup outcome
        // write, and this binding proves the same retained process pair.
        let outcomes = unsafe { (*self.storage.startup_reservations.get()).assume_init() };
        match self.process.subprocess().arena_backing().first_regular_startup_arena_selection(
            self.process,
            config,
            outcomes.regular_arena(),
        ) {
            FirstRegularStartupArenaSelection::Absent => {
                ProcessStartupRegularArenaSelection::Absent
            }
            FirstRegularStartupArenaSelection::Eligible(arena) => {
                ProcessStartupRegularArenaSelection::Eligible(ProcessStartupRegularArenaLease {
                    binding: self,
                    arena,
                })
            }
            FirstRegularStartupArenaSelection::ExistingOutsideFirstRegularCapability => {
                ProcessStartupRegularArenaSelection::ExistingOutsideFirstRegularCapability
            }
        }
    }
}

/// The frozen allocation inputs, separately represented from completed
/// startup. It grants no thread attachment or reservation-outcome access.
#[derive(Clone, Copy)]
pub(crate) struct ProcessMainAllocationLease {
    storage: &'static ProcessMainInitializationStorage,
    config: MemoryConfig,
    subprocess: &'static MainSubprocess,
    page_map: ProcessPageMapRoot,
}

impl ProcessMainAllocationLease {
    /// Rechecks only the storage's allocation-ready state.
    ///
    /// Both constructors bind the lease to the exact configuration,
    /// subprocess, and PageMap tuple that `storage` records before its
    /// allocation-ready Release publication, and the storage never replaces
    /// that tuple afterward (see the `Sync` justification above). Comparing
    /// the multi-word `MemoryConfig` and subprocess again on every use (twice
    /// per free through `page_map`) could not observe a different value; the
    /// state load is the part that can change, to `RETAINED`.
    #[inline]
    fn ensure_valid(self) -> Result<(), ProcessMainInitError> {
        self.storage.ensure_allocation_ready()
    }

    pub(crate) fn memory_config(self) -> Result<MemoryConfig, ProcessMainInitError> {
        self.ensure_valid()?;
        Ok(self.config)
    }

    pub(crate) fn page_map(self) -> Result<ProcessPageMapRoot, ProcessMainInitError> {
        self.ensure_valid()?;
        Ok(self.page_map)
    }

    pub(crate) fn vm_process(self) -> Result<VmProcess<'static>, ProcessMainInitError> {
        self.ensure_valid()?;
        let policy = NonNull::new(self.storage.vm_policy_ptr.load(Ordering::Acquire))
            .ok_or(ProcessMainInitError::VmPolicyUnavailable)?;
        // SAFETY: allocation-ready publishes the already initialized policy
        // before any Theap publication; its slot is immutable and process-lived.
        Ok(VmProcess::new_main(unsafe { policy.as_ref() }, self.subprocess))
    }

    pub(crate) fn process_backing(self) -> Result<ProcessMainBackingBinding, ProcessMainInitError> {
        Ok(ProcessMainBackingBinding::new(self.storage, self.vm_process()?, self.page_map()?))
    }

    fn ready(self) -> Result<ProcessMainReadyLease, ProcessMainInitError> {
        self.ensure_valid()?;
        if self.storage.state.load(Ordering::Acquire) != READY {
            return Err(ProcessMainInitError::Initializing);
        }
        Ok(ProcessMainReadyLease {
            storage: self.storage, config: self.config,
            subprocess: self.subprocess, page_map: self.page_map,
        })
    }
}

/// A copyable immutable witness that the bounded source process startup
/// reached `READY` for one frozen main-subprocess/configuration/PageMap tuple.
///
/// It does not expose a PageMap mutation lease, an arena, the detached
/// metadata map/arena, a thread attachment, or process shutdown authority.
#[derive(Clone, Copy)]
pub(crate) struct ProcessMainReadyLease {
    storage: &'static ProcessMainInitializationStorage,
    page_map: ProcessPageMapRoot,
    config: MemoryConfig,
    subprocess: &'static MainSubprocess,
}

// SAFETY: this lease only carries process-lifetime immutable witnesses. Page
// mutations remain gated by `ProcessPageMapMutationLease`, and thread state is
// deliberately absent.
unsafe impl Send for ProcessMainReadyLease {}
// SAFETY: see the Send justification above.
unsafe impl Sync for ProcessMainReadyLease {}

/// Destruction-only witnesses after the canonical coordinator has closed.
/// All owners are in final process-static storage, outside retiring arenas.
pub(crate) struct ProcessMainTerminalState {
    pub(crate) process: VmProcess<'static>,
    pub(crate) registry: &'static crate::subproc::registry::SourceSubprocessRegistry,
    pub(crate) page_map_storage: &'static ProcessPageMapStorage,
    pub(crate) config: MemoryConfig,
}

impl ProcessMainReadyLease {
    pub(crate) fn subprocess_sequence(self) -> Result<usize, ProcessMainInitError> {
        self.ensure_ready()?;
        // SAFETY: READY follows canonical subprocess initialization, which
        // assigns the immutable source sequence before main Heap publication.
        Ok(unsafe { self.storage.source_subprocesses.initialized_main_sequence(self.subprocess) })
    }

    /// Captures the permanent output owner before coordinator sealing. This
    /// identity grants no callback authority: callers must separately hold
    /// ordinary entry or the transferred terminal writer's diagnostic scope.
    #[cfg(target_arch = "x86_64")]
    pub(crate) fn diagnostic_output(self) -> Result<Option<&'static OutputOwner>, ProcessMainInitError> {
        self.ensure_ready()?;
        let pointer = self.storage.diagnostic_output_ptr.load(Ordering::Acquire);
        // SAFETY: the inline owner is initialized once before publication and
        // never moved or reclaimed, including when allocator backing retires.
        Ok(unsafe { pointer.as_ref() })
    }

    /// Removes the exact canonical source subprocess before Heap destruction.
    ///
    /// # Safety
    /// Permanent process exclusion and source-owner transfer are complete.
    /// Metadata still uses this ready binding until its subsequent close.
    pub(crate) unsafe fn unlink_terminal_subprocess(self) -> Result<(), ProcessMainInitError> {
        self.ensure_ready()?;
        unsafe {
            self.storage.source_subprocesses.unlink_main_terminal(
                self.vm_process()?.main_subprocess().ok_or(ProcessMainInitError::SubprocessMismatch)?,
            )
        }
            .map_err(ProcessMainInitError::SubprocessRegistry)
    }

    /// Revokes future safe coordinator/binding projections before physical
    /// source retirement. Existing references require separate exclusion.
    ///
    /// # Safety
    /// Permanent terminal admission has consumed every native TLS engine and
    /// source observer. No existing ready/binding reference may be used again
    /// except the explicit witnesses returned for source-ordered destruction.
    pub(crate) unsafe fn seal_terminal(self) -> Result<ProcessMainTerminalState, ProcessMainInitError> {
        self.ensure_ready()?;
        let process = self.vm_process()?;
        let page_map_storage = NonNull::new(self.storage.page_map_storage.load(Ordering::Acquire))
            .ok_or(ProcessMainInitError::Retained)?;
        self.storage.state.compare_exchange(READY, TERMINAL_CLOSED, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| ProcessMainInitError::Retained)?;
        Ok(ProcessMainTerminalState {
            process,
            registry: &self.storage.source_subprocesses,
            // SAFETY: READY published this exact process-static map owner;
            // only its normal entry is revoked, not the owner storage itself.
            page_map_storage: unsafe { page_map_storage.as_ref() },
            config: self.config,
        })
    }

    pub(crate) fn startup_reservation_outcomes(self)
        -> Result<crate::arena::StartupArenaReservationOutcomes, ProcessMainInitError> {
        self.ensure_ready()?;
        // SAFETY: READY Release follows the immutable startup outcome write.
        Ok(unsafe { (*self.storage.startup_reservations.get()).assume_init() })
    }

    #[inline]
    pub(crate) fn root(self) -> Result<NonNull<PageMapHeader>, ProcessMainInitError> {
        self.ensure_ready()?;
        self.page_map.root().map_err(ProcessMainInitError::PageMap)
    }

    #[inline]
    pub(crate) fn page_map(self) -> Result<ProcessPageMapRoot, ProcessMainInitError> {
        self.ensure_ready()?;
        Ok(self.page_map)
    }

    #[inline]
    pub(crate) fn memory_config(self) -> Result<MemoryConfig, ProcessMainInitError> {
        self.ensure_ready()?;
        Ok(self.config)
    }

    #[inline]
    pub(crate) fn subprocess(self) -> Result<&'static MainSubprocess, ProcessMainInitError> {
        self.ensure_ready()?;
        Ok(self.subprocess)
    }

    /// Borrows the exact policy/subprocess pair retained by explicit VM-aware
    /// process startup.
    ///
    /// A successful legacy explicit-config startup intentionally returns
    /// [`ProcessMainInitError::VmPolicyUnavailable`] here: it does not invent
    /// a default policy or let a later caller attach a different option image.
    #[inline]
    pub(crate) fn vm_process(self) -> Result<VmProcess<'static>, ProcessMainInitError> {
        self.ensure_ready()?;
        let policy = NonNull::new(self.storage.vm_policy_ptr.load(Ordering::Acquire))
            .ok_or(ProcessMainInitError::VmPolicyUnavailable)?;
        // SAFETY: READY Acquire follows the inline policy write and pointer
        // Release store; the one source process lifetime never replaces or
        // destroys this slot.
        let policy = unsafe { policy.as_ref() };
        Ok(VmProcess::new_main(policy, self.subprocess))
    }

    /// Returns the exact coordinator-issued policy/PageMap binding for a
    /// process backing consumer. This proves that both copyable witnesses
    /// originate from the same source main-process transition.
    #[inline]
    pub(crate) fn process_backing(self) -> Result<ProcessMainBackingBinding, ProcessMainInitError> {
        self.ensure_ready()?;
        Ok(ProcessMainBackingBinding::new(
            self.storage,
            self.vm_process()?,
            self.page_map,
        ))
    }

    /// Borrows the source normal-arena backing group of this VM-aware process.
    ///
    /// This is intentionally unavailable from legacy explicit-config startup:
    /// a caller must first prove the matching retained VM policy/process pair,
    /// so it cannot publish an arena against an invented default policy.
    #[inline]
    pub(crate) fn arena_backing(
        self,
    ) -> Result<&'static crate::arena::ProcessArenaBacking, ProcessMainInitError> {
        let _process = self.vm_process()?;
        Ok(self.subprocess.arena_backing())
    }

    #[inline]
    fn ensure_ready(self) -> Result<(), ProcessMainInitError> {
        if self.storage.state.load(Ordering::Acquire) != READY {
            return Err(ProcessMainInitError::Retained);
        }
        if self.storage.config() != self.config
            || !core::ptr::eq(
                self.storage.subprocess.load(Ordering::Acquire),
                self.subprocess.owner_ptr(),
            )
        {
            return Err(ProcessMainInitError::Retained);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProcessMainThreadState {
    Attached,
    /// Sole-child repair retired the vanished initial TLD/Theap. The process
    /// coordinator and canonical main Heap still serve surviving workers.
    MainThreadDetached,
    TornDown,
    Retained,
}

/// Current-thread owner of the source ticket-zero TLD/Theap after a successful
/// process-main startup transition.
#[must_use = "a process-main thread owner must explicitly tear down or retain its ticket-zero attachment"]
pub(crate) struct ProcessMainThread {
    storage: &'static ProcessMainInitializationStorage,
    attachment: Option<MainStaticTheapAttachment>,
    allocation: ProcessMainAllocationLease,
    state: ProcessMainThreadState,
    _not_send_or_sync: PhantomData<*mut ()>,
}

/// A refusal while turning the retained source-order process-main owner into
/// its one bounded first-arena page owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProcessMainFirstArenaPageAllocatorError {
    Process(ProcessMainInitError),
    PageOwner(MainStaticFirstArenaPageAllocatorBeginError),
}

/// A refusal while converting the retained ticket-zero attachment into its
/// one permanent page-session owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProcessMainProcessPageSessionError {
    Process(ProcessMainInitError),
    PageSession(MainStaticProcessPageSessionError),
}

/// A refusal while deriving the already-published process arena from the
/// immutable source-order process-ready witness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProcessMainReadySharedArenaError {
    Process(ProcessMainInitError),
    #[cfg(any(test, feature = "native-runtime-test-audit", not(target_arch = "x86_64")))]
    Arena(ProcessSharedArenaError),
    #[cfg(any(test, feature = "native-runtime-test-audit", not(target_arch = "x86_64")))]
    Pair(ProcessPageArenaLeaseError),
}

impl ProcessMainThread {
    /// Returns the immutable ready witness while the process coordinator is
    /// live, including after child repair detached its vanished initial thread.
    pub(crate) fn ready(&self) -> Result<ProcessMainReadyLease, ProcessMainInitError> {
        if !matches!(self.state, ProcessMainThreadState::Attached | ProcessMainThreadState::MainThreadDetached) {
            return Err(ProcessMainInitError::Retained);
        }
        self.allocation.ready()
    }

    pub(crate) fn allocation(&self) -> Result<ProcessMainAllocationLease, ProcessMainInitError> {
        if !matches!(self.state, ProcessMainThreadState::Attached | ProcessMainThreadState::MainThreadDetached) {
            return Err(ProcessMainInitError::Retained);
        }
        self.allocation.ensure_valid()?;
        Ok(self.allocation)
    }

    /// Borrows the ticket-zero attachment for an existing bounded page owner
    /// or later-main attachment. The process coordinator remains the only
    /// constructor for this owner in production.
    pub(crate) fn attachment_mut(
        &mut self,
    ) -> Result<&mut MainStaticTheapAttachment, ProcessMainInitError> {
        if self.state != ProcessMainThreadState::Attached {
            return Err(ProcessMainInitError::Retained);
        }
        self.attachment.as_mut().ok_or(ProcessMainInitError::Retained)
    }

    /// Converts the ticket-zero page authority into its one permanent static
    /// page session.
    ///
    /// The returned owner has no Rust borrow of this coordinator. Instead it
    /// permanently closes `teardown`, so its explicitly derived shared-main
    /// Heap lease can drive later no-page thread lifecycle work while ticket
    /// zero retains the static page state. This is an ownership transition,
    /// not a general allocator start or a C ABI/backend selection.
    pub(crate) fn begin_process_lifetime_page_session(
        &self,
    ) -> Result<MainStaticProcessPageSession, ProcessMainProcessPageSessionError> {
        if self.state != ProcessMainThreadState::Attached {
            return Err(ProcessMainProcessPageSessionError::Process(
                ProcessMainInitError::Retained,
            ));
        }
        let attachment = self.attachment.as_ref().ok_or(
            ProcessMainProcessPageSessionError::Process(ProcessMainInitError::Retained),
        )?;
        attachment
            .begin_process_lifetime_page_session()
            .map_err(ProcessMainProcessPageSessionError::PageSession)
    }

    /// Reconstructs the one immutable process map/arena pair after a bounded
    /// source reservation has already published it.
    ///
    /// This is not an arena search or a reservation policy. The pair is
    /// available only while this ticket-zero owner remains live and the
    /// process-shared sidecar is already READY; joining its two immutable
    /// witnesses rejects a root, configuration, or subprocess mismatch before
    /// any page lifecycle can begin.
    #[cfg(any(test, feature = "native-runtime-test-audit", not(target_arch = "x86_64")))]
    pub(crate) fn ready_shared_arena_pair(
        &self,
    ) -> Result<ProcessPageArenaLease, ProcessMainReadySharedArenaError> {
        self.ready_shared_arena_pair_with_storage(ProcessSharedArenaStorage::global())
    }

    #[cfg(any(test, feature = "native-runtime-test-audit", not(target_arch = "x86_64")))]
    fn ready_shared_arena_pair_with_storage(
        &self,
        arena_storage: &'static ProcessSharedArenaStorage,
    ) -> Result<ProcessPageArenaLease, ProcessMainReadySharedArenaError> {
        let page_map = self
            .ready()
            .and_then(ProcessMainReadyLease::page_map)
            .map_err(ProcessMainReadySharedArenaError::Process)?;
        let arena = arena_storage
            .ready_lease()
            .map_err(ProcessMainReadySharedArenaError::Arena)?;
        ProcessPageArenaLease::join(page_map, arena).map_err(ProcessMainReadySharedArenaError::Pair)
    }

    /// Test-only injection of an isolated process-lifetime arena sidecar.
    #[cfg(test)]
    fn ready_shared_arena_pair_with_test_storage(
        &self,
        arena_storage: &'static ProcessSharedArenaStorage,
    ) -> Result<ProcessPageArenaLease, ProcessMainReadySharedArenaError> {
        self.ready_shared_arena_pair_with_storage(arena_storage)
    }

    /// Borrows this retained ticket-zero owner as the one private lazy
    /// first-arena page engine.
    ///
    /// The source-order coordinator provides the only valid process-ready map
    /// witness and ticket-zero attachment. This factory exposes neither raw
    /// static storage nor arena ownership; the returned owner remains bounded
    /// to its first ordinary fresh-page miss and the global one-arena policy.
    #[cfg(any(test, not(target_arch = "x86_64")))]
    pub(crate) fn begin_first_arena_page_allocator(
        &mut self,
    ) -> Result<MainStaticFirstArenaPageAllocator<'_>, ProcessMainFirstArenaPageAllocatorError> {
        self.begin_first_arena_page_allocator_with_storage(ProcessSharedArenaStorage::global())
    }

    #[cfg(any(test, not(target_arch = "x86_64")))]
    fn begin_first_arena_page_allocator_with_storage(
        &mut self,
        arena_storage: &'static ProcessSharedArenaStorage,
    ) -> Result<MainStaticFirstArenaPageAllocator<'_>, ProcessMainFirstArenaPageAllocatorError> {
        let page_map = self
            .ready()
            .and_then(ProcessMainReadyLease::page_map)
            .map_err(ProcessMainFirstArenaPageAllocatorError::Process)?;
        let attachment = self
            .attachment_mut()
            .map_err(ProcessMainFirstArenaPageAllocatorError::Process)?;
        MainStaticFirstArenaPageAllocator::begin(attachment, page_map, arena_storage)
            .map_err(ProcessMainFirstArenaPageAllocatorError::PageOwner)
    }

    /// Test-only injection of an isolated process-lifetime arena sidecar.
    #[cfg(test)]
    fn begin_first_arena_page_allocator_with_test_storage(
        &mut self,
        arena_storage: &'static ProcessSharedArenaStorage,
    ) -> Result<MainStaticFirstArenaPageAllocator<'_>, ProcessMainFirstArenaPageAllocatorError> {
        self.begin_first_arena_page_allocator_with_storage(arena_storage)
    }

    /// Mints the live static main-Heap lease on the ticket-zero thread.
    ///
    /// The private libc bridge calls this during process initialization and
    /// retains the Copy process-lifetime witness for later pthread workers.
    /// A worker must never mint the lease itself: this method verifies the
    /// initial attachment's current-thread identity. The caller must keep the
    /// ticket-zero owner alive and must not begin its teardown while the
    /// returned lease or any attachment made from it exists.
    #[inline]
    pub(crate) fn shared_main_heap_lease(
        &self,
    ) -> Result<MainStaticHeapLease<'_>, ProcessMainInitError> {
        if self.state != ProcessMainThreadState::Attached {
            return Err(ProcessMainInitError::Retained);
        }
        self.attachment
            .as_ref()
            .ok_or(ProcessMainInitError::Retained)?
            .shared_main_heap_lease()
            .map_err(ProcessMainInitError::InitialThread)
    }

    /// Consumes only the vanished initial attachment under the allocator's
    /// child-repair capability; the canonical ready process survives.
    ///
    /// # Safety
    /// The child continuation retains all copied source lifetimes after libc
    /// released its registry/outer locks. Signals and user hooks remain
    /// excluded. Initial collect-abandon is complete, no initial session or
    /// observation survives, and the caller is a later-worker survivor. Main
    /// Heap leases remain valid; no initial-thread lease may be minted again.
    pub(crate) unsafe fn detach_vanished_initial_thread_after_fork(
        &mut self,
        _child: &crate::runtime_lifecycle::NativeAllocatorForkChildContinuation,
    ) -> Result<(), ProcessMainInitError> {
        if self.state != ProcessMainThreadState::Attached {
            return Err(ProcessMainInitError::Retained);
        }
        let attachment = self.attachment.as_mut().ok_or(ProcessMainInitError::Retained)?;
        match unsafe { attachment.detach_vanished_initial_thread_after_fork() } {
            Ok(()) => {
                drop(self.attachment.take());
                self.state = ProcessMainThreadState::MainThreadDetached;
                Ok(())
            }
            Err(error) => {
                self.state = ProcessMainThreadState::Retained;
                self.storage.mark_retained();
                Err(ProcessMainInitError::InitialThread(error))
            }
        }
    }

    /// Performs the existing bounded main-thread TLD/Theap teardown. Process
    /// startup itself remains terminal afterward: the static source TLD slot
    /// is never reused and this coordinator deliberately has no process
    /// destruction/restart protocol.
    pub(crate) fn teardown(&mut self) -> Result<(), MainStaticTheapError> {
        if self.state != ProcessMainThreadState::Attached {
            return Err(MainStaticTheapError::TornDown);
        }
        let result = self
            .attachment
            .as_mut()
            .ok_or(MainStaticTheapError::Poisoned)?
            .teardown();
        self.storage.mark_retained();
        self.state = if result.is_ok() {
            ProcessMainThreadState::TornDown
        } else {
            ProcessMainThreadState::Retained
        };
        result
    }
}

impl Drop for ProcessMainThread {
    fn drop(&mut self) {
        if matches!(self.state, ProcessMainThreadState::Attached | ProcessMainThreadState::MainThreadDetached) {
            // A dropped process owner can leave roots, TLD registration,
            // or page state live. Retain the process rather than letting a
            // later caller receive a fresh-looking startup capability.
            self.storage.mark_retained();
            self.state = ProcessMainThreadState::Retained;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arena::ArenaId;
    use crate::bootstrap::empty_default_theap_ptr;
    use crate::compiler_tls::{
        default_theap, fast_slot_peek, roots_are_pristine_for_main_static_attachment,
        set_default_theap,
    };
    use crate::main_heap_page::MainHeapThreadProcessPageAllocator;
    use crate::main_heap_thread::MainHeapThreadAttachment;
    use crate::meta::{MetaAllocator, MetaError};
    use crate::os::{fault, MapAccess, PageSize};
    use crate::process_arena::{ProcessPageArenaLease, ProcessSharedArenaStorage};
    use crate::single_thread::PageAllocatorEngine;
    use crate::subproc::GenericThreadTicketError;
    use crate::tld::{ThreadLocalDataError, ThreadLocalDataOwner};
    use crate::types::Theap;
    use std::ptr::NonNull;
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant};

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn native_startup_errno_capability_resolves_calling_thread_tls() {
        unsafe extern "C" { fn __errno_location() -> *mut core::ffi::c_int; }
        unsafe fn store_errno(value: core::ffi::c_int) {
            // SAFETY: the pinned native test runtime installed musl TLS;
            // this immediate store never retains its resolved pointer.
            unsafe { *__errno_location() = value };
        }
        unsafe fn store_default_errno(value: core::ffi::c_int) {
            // SAFETY: this immediate projection names only this thread's
            // installed musl TLS and never escapes the provider call.
            let slot = unsafe { __errno_location() };
            unsafe { if *slot == 0 { *slot = value; } };
        }
        unsafe fn environment() -> *const *const core::ffi::c_char {
            core::ptr::null()
        }
        unsafe extern "C" fn stderr(_: *const core::ffi::c_char) {}
        // SAFETY: permanent, nonallocating providers; a null environment is
        // valid and the output provider ignores its borrowed fragment.
        let facts = unsafe { NativeProcessStartupFacts::new(
            4096, environment, crate::diagnostic_output::RuntimeStderrOutput::new(stderr),
        ) }.unwrap();
        assert!(facts.source_errno_store().is_none());
        // SAFETY: this process-lifetime writer accesses only calling-thread
        // TLS and cannot allocate, retain its pointer, or unwind.
        let unconditional = unsafe { SourceErrnoStore::new(store_errno) };
        // SAFETY: this thread's musl runtime installed its exclusive TLS slot.
        unsafe { *__errno_location() = 34 };
        assert_eq!(unconditional.store_default(crabc_core::Errno::INVAL), None);
        assert_eq!(unsafe { *__errno_location() }, 34);
        unsafe { *__errno_location() = 0 };
        assert_eq!(unconditional.store_default(crabc_core::Errno::INVAL), None);
        assert_eq!(unsafe { *__errno_location() }, 0);
        // SAFETY: the added provider has the same lifetime and TLS boundary,
        // and writes its supplied value only when that slot is zero.
        let facts = facts.with_source_errno_store(unsafe {
            unconditional.with_default_store(store_default_errno)
        });
        let cell = std::sync::Arc::new(ProcessStartupFactsCell::new());
        assert!(cell.publish(facts));
        assert!(!cell.publish(facts));
        // SAFETY: the native test thread has installed, exclusively owned TLS.
        unsafe { *__errno_location() = 34 };
        let other = cell.clone();
        std::thread::spawn(move || {
            // SAFETY: this worker's runtime installed its distinct TLS slot.
            unsafe { *__errno_location() = 0 };
            let writer = other.published().unwrap().source_errno_store().unwrap();
            assert_eq!(writer.store_default(crabc_core::Errno::INVAL), Some(()));
            assert_eq!(unsafe { *__errno_location() }, 22);
            writer.store(crabc_core::Errno::PERM);
            assert_eq!(unsafe { *__errno_location() }, 1);
        }).join().unwrap();
        assert_eq!(unsafe { *__errno_location() }, 34);
        let writer = cell.published().unwrap().source_errno_store().unwrap();
        assert_eq!(writer.store_default(crabc_core::Errno::INVAL), Some(()));
        assert_eq!(unsafe { *__errno_location() }, 34);
        writer.store(crabc_core::Errno::NOMEM);
        assert_eq!(unsafe { *__errno_location() }, 12);
        assert_eq!(writer.store_default(crabc_core::Errno::INVAL), Some(()));
        assert_eq!(unsafe { *__errno_location() }, 12);
        // A warning callback may clear errno; the subsequent default error
        // then installs EINVAL. Nonzero callback effects remain authoritative.
        unsafe { *__errno_location() = 0 };
        assert_eq!(writer.store_default(crabc_core::Errno::INVAL), Some(()));
        assert_eq!(unsafe { *__errno_location() }, 22);
        writer.store(crabc_core::Errno::INTR);
        assert_eq!(writer.store_default(crabc_core::Errno::INVAL), Some(()));
        assert_eq!(unsafe { *__errno_location() }, 4);
        unsafe { *__errno_location() = 34 };
        assert_eq!(writer.store_default(crabc_core::Errno::INVAL), Some(()));
        assert_eq!(unsafe { *__errno_location() }, 34);
    }

    // Linux's process-local THP query/set selectors used only by child-isolated
    // ProcessMain policy witnesses.
    const PR_SET_THP_DISABLE: i32 = 41;
    const PR_GET_THP_DISABLE: i32 = 42;

    fn memory_config() -> MemoryConfig {
        MemoryConfig::from_observations(
            PageSize::new(4096).expect("the native page size is valid"),
            1024 * 1024,
            false,
            false,
        )
    }

    fn resolved_vm_options() -> VmOptions {
        let mut options = VmOptions::uninitialized();
        options.initialize_all(|_| crate::config::VmOptionEnvironment::Absent);
        options
    }

    fn wait_for_process_once_contender(storage: &ProcessMainInitializationStorage) {
        let deadline = Instant::now() + Duration::from_secs(2);
        while !storage.process_once.test_is_contended() {
            assert!(
                Instant::now() < deadline,
                "the distinct caller must reach the retained source once gate before release"
            );
            thread::yield_now();
        }
    }

    fn fixture() -> (
        &'static ProcessMainInitializationStorage,
        &'static MainStaticAttachmentStorage,
        &'static MainSubprocess,
        core::pin::Pin<&'static MetaAllocator>,
        &'static ProcessPageMapStorage,
    ) {
        (
            ProcessMainInitializationStorage::test_static_owner(),
            MainStaticAttachmentStorage::test_static_owner(),
            MainSubprocess::test_static_owner(),
            MetaAllocator::test_static_owner(),
            ProcessPageMapStorage::test_static_owner(),
        )
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn source_attached_allocation_lease_does_not_release_process_once_to_a_racer() {
        let config = memory_config();
        let (storage, main_static, subprocess, metadata, page_map_storage) = fixture();
        let (attached_tx, attached_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (observed_tx, observed_rx) = mpsc::channel();
        let (teardown_tx, teardown_rx) = mpsc::channel();
        let initializer = thread::spawn(move || {
            let (mut owner, startup) = unsafe {
                storage.prepare_with_test_components_and_vm_options(
                    config, resolved_vm_options(), main_static, subprocess,
                    metadata, page_map_storage, None,
                )
            }.expect("the source default Theap is attached before reservations");
            assert!(owner.allocation().is_ok(),
                "the source owner can allocate through its initialized tuple");
            assert!(owner.ready().is_err(),
                "an allocation lease does not publish completed process readiness");
            assert!(matches!(unsafe { storage.initialize_with_test_components(
                config, main_static, subprocess, metadata, page_map_storage,
            ) }, Err(ProcessMainInitError::Initializing)),
                "same-thread source reentry cannot wait on its own once lock");
            attached_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            startup.complete().expect("source startup completes after the callback interval");
            teardown_rx.recv().unwrap();
            owner.teardown().expect("the bounded source owner finishes");
        });
        attached_rx.recv_timeout(Duration::from_secs(2)).unwrap();

        let contender = thread::spawn(move || {
            let result = unsafe { storage.initialize_with_test_components(
                config, main_static, subprocess, metadata, page_map_storage,
            ) };
            observed_tx.send(matches!(result, Err(ProcessMainInitError::AlreadyInitialized))).unwrap();
        });
        wait_for_process_once_contender(storage);
        assert!(observed_rx.recv_timeout(Duration::from_millis(50)).is_err(),
            "a distinct caller remains blocked while only the owner allocation lease exists");
        release_tx.send(()).unwrap();
        assert!(observed_rx.recv_timeout(Duration::from_secs(2)).unwrap());
        teardown_tx.send(()).unwrap();
        contender.join().unwrap();
        initializer.join().unwrap();
    }

    #[cfg(all(target_arch = "x86_64", not(miri)))]
    #[test]
    fn worker_child_detaches_empty_initial_owner_but_keeps_process_ready() {
        use crate::runtime_lifecycle::{
            NativeAllocatorPinnedThreadRegistry, NativeAllocatorThreadDescriptor,
            begin_native_allocator_fork_quiescence,
            current_native_allocator_thread_descriptor,
            register_current_native_allocator_worker_descriptor,
        };
        struct Registry([NonNull<NativeAllocatorThreadDescriptor>; 2]);
        // The scoped worker and its waiting parent keep both exact TLS images
        // live. Their only source work is the explicitly sequenced fixture;
        // no descriptor publication/removal occurs during the raw interval.
        unsafe impl NativeAllocatorPinnedThreadRegistry for Registry {
            fn visit_descriptors(&self, visitor: &mut dyn FnMut(NonNull<NativeAllocatorThreadDescriptor>)) {
                for descriptor in self.0 { visitor(descriptor); }
            }
        }
        thread::spawn(|| {
            let (storage, main_static, subprocess, metadata, page_map_storage) = fixture();
            let mut owner = unsafe {
                storage.initialize_with_test_components(memory_config(), main_static,
                    subprocess, metadata, page_map_storage)
            }.expect("isolated initial source owner");
            let initial = current_native_allocator_thread_descriptor();
            assert!(unsafe { register_current_native_allocator_worker_descriptor(initial) });
            let initial_address = initial.as_ptr() as usize;
            // No parent projection survives the worker's fork. Only the
            // separate child address space may access this owner while the
            // parent waits; after join the original parent resumes ownership.
            let owner_address = core::ptr::from_mut(&mut owner) as usize;
            thread::scope(|scope| {
                scope.spawn(move || {
                    let survivor = current_native_allocator_thread_descriptor();
                    assert!(unsafe { register_current_native_allocator_worker_descriptor(survivor) });
                    let registry = Registry([
                        NonNull::new(initial_address as *mut NativeAllocatorThreadDescriptor).unwrap(),
                        survivor,
                    ]);
                    let blocked = u64::MAX;
                    let mut previous_mask = 0u64;
                    unsafe { crabc_core::signal::rt_sigprocmask_raw(0, &blocked, &mut previous_mask) }
                        .expect("exclude signal reentry during child source repair");
                    let interval = unsafe { begin_native_allocator_fork_quiescence(&registry) }
                        .expect("empty source owners admit the copied interval");
                    let child = crabc_core::process::fork_raw().expect("isolated worker-origin child");
                    if child == 0 {
                        let repair = unsafe { interval.into_child_repair() };
                        let continuation = match unsafe { repair.into_unlocked_continuation() } {
                            Ok(value) => value,
                            Err(_) => crabc_core::process::exit_immediately(1),
                        };
                        // The fixture has no libc locks, handlers or source
                        // pages. The sole child retains both inherited TLS
                        // images and the empty initial queues need no drain.
                        let copied_owner = unsafe { &mut *(owner_address as *mut ProcessMainThread) };
                        // The direct prerequisite fixture supplies the same
                        // init.c:471 prefix as the full child controller.
                        subprocess.record_statistics_thread_detached();
                        let detached = unsafe {
                            copied_owner.detach_vanished_initial_thread_after_fork(&continuation)
                        }.is_ok();
                        let ready = copied_owner.ready().is_ok() && copied_owner.allocation().is_ok();
                        let initial_denied = copied_owner.attachment_mut().is_err()
                            && copied_owner.begin_process_lifetime_page_session().is_err()
                            && copied_owner.shared_main_heap_lease().is_err();
                        let counts = subprocess.live_thread_count() == 0
                            && subprocess.statistics().source_snapshot().threads_current == 0;
                        // This bounded prerequisite intentionally does not
                        // reopen: full vanished-worker page repair owns that
                        // successor. Dropping an unfinished continuation seals.
                        drop(continuation);
                        crabc_core::process::exit_immediately(
                            if detached && ready && initial_denied && counts { 0 } else { 2 });
                    }
                    unsafe { interval.resume_parent() }.expect("parent retains exact source owner");
                    unsafe { crabc_core::signal::rt_sigprocmask_raw(2, &previous_mask, core::ptr::null_mut()) }
                        .expect("restore the original parent mask after epoch completion");
                    let mut status = 0;
                    assert_eq!(unsafe { crabc_core::process::wait4_raw(child, &mut status, 0) }, Ok(child));
                    assert_eq!(status, 0, "child detaches initial ownership without retiring the process");
                }).join().expect("worker-origin source-state fixture");
            });
            assert!(owner.ready().is_ok());
            assert!(owner.attachment_mut().is_ok(), "parent initial attachment is unchanged");
            assert_eq!(subprocess.live_thread_count(), 1);
            owner.teardown().expect("parent completes its original initial attachment");
        }).join().expect("isolated source initialization thread");
    }

    #[test]
    fn source_attachment_publishes_allocation_inputs_before_startup_completion() {
        thread::spawn(|| {
            let config = memory_config();
            let (storage, main_static, subprocess, metadata, page_map_storage) = fixture();
            let mut owner = unsafe {
                storage.initialize_with_components_at_attachment(
                    config, VmPolicyStartup::None, main_static, subprocess,
                    metadata, page_map_storage, || {},
                    || {
                        assert!(storage.ready_lease(config, subprocess).is_err(),
                            "startup outcomes are unavailable before source reservation completion");
                        let allocation = storage.allocation_lease(config, subprocess)
                            .expect("the source default Theap already permits allocation");
                        assert_eq!(allocation.config, config);
                        assert!(core::ptr::eq(allocation.subprocess, subprocess));
                        assert!(allocation.page_map.root().is_ok());
                        assert!(thread::spawn(move || storage.allocation_lease(config, subprocess).is_err())
                            .join().expect("a distinct thread cannot consume staged initialization"));
                    }, || {},
                )
            }.expect("source startup completes after the staged callback returns");
            assert!(owner.ready().is_ok());
            owner.teardown().expect("the isolated ticket-zero owner tears down");
        }).join().expect("staged allocation inputs remain bound to the initializing thread");
    }

    #[test]
    fn process_main_initialization_orders_heap_metadata_map_then_ticket_zero_roots() {
        thread::spawn(|| {
            let config = memory_config();
            let (storage, main_static, subprocess, metadata, page_map_storage) = fixture();
            let mut owner = unsafe {
                storage.initialize_with_test_components(
                    config,
                    main_static,
                    subprocess,
                    metadata,
                    page_map_storage,
                )
            }
            .expect("the selected process-main source sequence initializes");
            let ready = owner.ready().expect("only the completed startup publishes ready");

            assert!(matches!(
                ready.vm_process(),
                Err(ProcessMainInitError::VmPolicyUnavailable)
            ));
            assert!(matches!(
                ready.arena_backing(),
                Err(ProcessMainInitError::VmPolicyUnavailable)
            ));

            assert_eq!(subprocess.total_thread_count(), 1);
            assert_eq!(subprocess.live_thread_count(), 1);
            assert_eq!(ready.memory_config().unwrap(), config);
            assert_eq!(ready.subprocess().unwrap().as_ptr(), subprocess.as_ptr());
            assert_eq!(
                ready.root().unwrap(),
                ready.page_map().unwrap().root().unwrap(),
                "the coordinator publishes the exact process PageMap root"
            );
            assert!(metadata.test_is_bound_for(config, subprocess));
            assert!(
                metadata.test_private_page_map_address().is_none(),
                "source startup binds the detached metadata Theap but does not map its first arena"
            );
            assert!(
                ProcessSharedArenaStorage::global().test_is_cold(),
                "process startup does not reserve or manage an arena"
            );

            let attachment = owner.attachment_mut().unwrap();
            let theap = attachment.test_theap_pointer();
            assert_eq!(default_theap().as_ptr(), theap);
            assert_eq!(fast_slot_peek().unwrap().as_ptr().cast::<Theap>(), theap);

            owner.teardown().expect("the bounded ticket-zero owner tears down");
            assert!(matches!(ready.root(), Err(ProcessMainInitError::Retained)));
        })
        .join()
        .expect("process-main initialization test thread completes");
    }

    #[test]
    fn huge_failed_startup_reservation_preserves_the_later_regular_option() {
        thread::spawn(|| {
            let fault = crate::os::fault::install(crate::os::fault::Plan::at(
                crate::os::fault::Point::HugeMap, 1, crabc_core::Errno::NOMEM));
            let config = memory_config();
            let (storage, main_static, subprocess, metadata, page_map_storage) = fixture();
            let mut options = resolved_vm_options();
            options.set(crate::config::VmOption::ReserveHugeOsPages, 1);
            options.set(crate::config::VmOption::ReserveHugeOsPagesAt, 0);
            options.set(crate::config::VmOption::UseNumaNodes, 1);
            options.set(crate::config::VmOption::ReserveOsMemory,
                (crate::config::ARENA_MIN_SIZE / crate::config::KIB) as i64);
            let mut owner = unsafe { storage.initialize_with_test_components_and_vm_options(config,
                options, main_static, subprocess, metadata, page_map_storage) }.unwrap();
            let ready = owner.ready().unwrap();
            let results = ready.startup_reservation_outcomes().unwrap();
            assert_eq!(results.huge, Some(Err(crabc_core::Errno::NOMEM)));
            assert_eq!(results.regular, Some(Ok(())));
            assert_eq!(fault.observed(), 1);
            assert_eq!(subprocess.arena_backing().registry().count(), 1);
            assert!(!subprocess.arena_backing().huge_cleanup_pending());
            owner.teardown().unwrap();
        }).join().unwrap();
    }

    #[test]
    fn huge_startup_attempt_precedes_the_explicit_regular_reservation() {
        thread::spawn(|| {
            let fault = crate::os::fault::install(crate::os::fault::Plan::at_pair(
                crate::os::fault::Point::HugeMap, 1, crate::os::fault::Point::Map, 1,
                crabc_core::Errno::NOMEM));
            let config = memory_config();
            let (storage, main_static, subprocess, metadata, page_map_storage) = fixture();
            let mut options = resolved_vm_options();
            options.set(crate::config::VmOption::ReserveHugeOsPages, 1);
            options.set(crate::config::VmOption::ReserveHugeOsPagesAt, 0);
            options.set(crate::config::VmOption::UseNumaNodes, 1);
            options.set(crate::config::VmOption::ReserveOsMemory,
                (crate::config::ARENA_MIN_SIZE / crate::config::KIB) as i64);
            let mut owner = unsafe { storage.initialize_with_test_components_and_vm_options(config,
                options, main_static, subprocess, metadata, page_map_storage) }.unwrap();
            let results = owner.ready().unwrap().startup_reservation_outcomes().unwrap();
            assert_eq!(results.huge, Some(Err(crabc_core::Errno::NOMEM)));
            assert_eq!(results.regular, Some(Ok(())),
                "source aligned allocation retries by overmapping after its direct candidate fails");
            assert_eq!(fault.secondary_observed(), 2,
                "the direct failure and overmap retry both occur after the huge attempt");
            assert_eq!(subprocess.arena_backing().registry().count(), 1);
            fault.set(crate::os::fault::Plan::disabled());
            owner.teardown().unwrap();
        }).join().unwrap();
    }

    #[test]
    fn process_main_vm_options_publish_one_post_preloading_pair() {
        thread::spawn(|| {
            let config = memory_config();
            let (storage, main_static, subprocess, metadata, page_map_storage) = fixture();
            let mut owner = unsafe {
                storage.initialize_with_test_components_and_vm_options(
                    config,
                    resolved_vm_options(),
                    main_static,
                    subprocess,
                    metadata,
                    page_map_storage,
                )
            }
            .expect("the resolved source option image initializes one process owner");
            let ready = owner.ready().expect("the VM-aware source startup publishes ready");
            let process = ready
                .vm_process()
                .expect("the ready lease borrows the retained exact VM pair");
            assert_eq!(process.subprocess().as_ptr(), subprocess.as_ptr());
            assert!(!process.is_preloading());
            assert_eq!(process.policy().arena_purge_multiplier(), 4);
            assert_eq!(process.policy().minimal_purge_size(config), config.page_size().bytes());
            assert!(core::ptr::eq(
                ready.arena_backing().expect("the VM-ready lease exposes its subprocess arena group"),
                subprocess.arena_backing(),
            ));
            let mut allocation = metadata
                .zalloc_for_main_subprocess(config, subprocess, 64)
                .expect("the policy-aware startup selects the shared process metadata backing");
            assert!(
                metadata.test_private_page_map_address().is_none(),
                "the first metadata demand must use the already-bound process PageMap, not create the legacy private map",
            );
            metadata
                .free(&mut allocation)
                .expect("the process-backed metadata allocation releases through its selected owner");

            owner.teardown().expect("the selected ticket-zero owner tears down");
            assert!(matches!(
                ready.vm_process(),
                Err(ProcessMainInitError::Retained)
            ));
        })
        .join()
        .expect("VM-aware process-main test thread completes");
    }

    #[test]
    fn process_main_pre_ready_binding_issues_only_its_retained_policy_and_page_map() {
        let config = memory_config();
        let storage = ProcessMainInitializationStorage::test_static_owner();
        let subprocess = MainSubprocess::test_static_owner();
        let page_map_storage = ProcessPageMapStorage::test_static_owner();
        // SAFETY: these leaked test owners are used for this one isolated
        // pre-READY binding preparation and remain alive for the test.
        let binding = unsafe {
            storage.test_prepare_vm_process_backing_binding(
                config,
                resolved_vm_options(),
                subprocess,
                page_map_storage,
            )
        }
        .expect("the isolated coordinator retains one canonical VM/PageMap tuple");

        assert!(binding.is_active());
        assert_eq!(binding.process().subprocess().as_ptr(), subprocess.as_ptr());
        assert_eq!(
            binding.page_map().root().unwrap(),
            page_map_storage.initialize(config, subprocess).unwrap().root().unwrap(),
            "the non-forgeable binding retains the one PageMap root selected by its coordinator"
        );
        assert!(matches!(
            storage.ready_lease(config, subprocess),
            Err(ProcessMainInitError::Retained)
        ));
    }

    /// Runs one exact direct policy case through the bounded ProcessMain owner.
    ///
    /// Every owner, completed option/configuration image, serial guard, and
    /// finite capture is constructed before the raw fork. The child performs
    /// only the existing isolated owner transition and fixed witness checks;
    /// the parent compares real THP queries before capture and after dropping
    /// the inherited capture.
    #[cfg(not(miri))]
    fn process_main_thp_policy_owner_case_witness(
        selected_case: fault::ThpDirectPolicyCase,
        expected_transparent_huge_pages: bool,
    ) -> bool {
        let (storage, main_static, subprocess, metadata, page_map_storage) = fixture();
        let mut options = VmOptions::uninitialized();
        options.set(
            crate::config::VmOption::AllowThp,
            if selected_case.allow_enabled() { 1 } else { 0 },
        );
        options.initialize_all(|_| crate::config::VmOptionEnvironment::Absent);
        let config = MemoryConfig::from_observations(
            PageSize::new(4096).expect("the selected native page size is valid"),
            1024 * 1024,
            false,
            true,
        );
        let parent_before = unsafe {
            crabc_core::process::prctl_raw(PR_GET_THP_DISABLE, 0, 0, 0, 0)
        };
        let guard = fault::install(fault::Plan::disabled());
        let capture = guard.capture_thp_direct_policy_case(selected_case);

        let child = crabc_core::process::fork_raw().expect("fork isolated ProcessMain policy");
        if child == 0 {
            let result = unsafe {
                storage.initialize_with_test_components_and_process_memory_policy(
                    config,
                    options,
                    main_static,
                    subprocess,
                    metadata,
                    page_map_storage,
                )
            };
            let status = match result {
                Ok(owner) => {
                    let ready = owner.ready();
                    let ready_witnesses_match = match (
                        ready.and_then(ProcessMainReadyLease::memory_config),
                        ready.and_then(ProcessMainReadyLease::vm_process),
                        ready.and_then(ProcessMainReadyLease::process_backing),
                    ) {
                        (Ok(ready_config), Ok(process), Ok(backing)) => {
                            ready_config.has_transparent_huge_pages()
                                == expected_transparent_huge_pages
                                && backing.is_active()
                                && core::ptr::eq(process.subprocess().as_ptr(), subprocess.identity_ptr())
                                && core::ptr::eq(backing.process().subprocess(), process.subprocess())
                                && core::ptr::eq(backing.process().policy(), process.policy())
                                && matches!(
                                    backing.page_map().subprocess(),
                                    Ok(backing_subprocess)
                                        if core::ptr::eq(backing_subprocess.identity_ptr(), process.subprocess().as_ptr())
                                )
                        }
                        _ => false,
                    };
                    let calls_match = match (selected_case, capture.attempts()) {
                        (fault::ThpDirectPolicyCase::AllowEnabled, Some((_, 0))) => true,
                        (
                            fault::ThpDirectPolicyCase::QueryNonzeroOne,
                            Some((attempts, 1)),
                        ) => attempts[0] == (PR_GET_THP_DISABLE, [0, 0, 0, 0]),
                        (fault::ThpDirectPolicyCase::SetPerm, Some((attempts, 2))) => {
                            attempts
                                == [
                                    (PR_GET_THP_DISABLE, [0, 0, 0, 0]),
                                    (PR_SET_THP_DISABLE, [1, 0, 0, 0]),
                                ]
                        }
                        _ => false,
                    };
                    if ready_witnesses_match && calls_match { 0 } else { 1 }
                }
                Err(_) => 1,
            };
            crabc_core::process::exit_immediately(status);
        }

        let mut status = 0;
        let reaped = unsafe { crabc_core::process::wait4_raw(child, &mut status, 0) }
            == Ok(child)
            && status == 0;
        drop(capture);
        drop(guard);
        let parent_after = unsafe {
            crabc_core::process::prctl_raw(PR_GET_THP_DISABLE, 0, 0, 0, 0)
        };
        reaped && parent_after == parent_before
    }

    #[cfg(not(miri))]
    #[test]
    fn process_main_thp_policy_owner_traversal() {
        use fault::ThpDirectPolicyCase as Case;

        assert!(
            process_main_thp_policy_owner_case_witness(Case::AllowEnabled, true),
            "the enabled source option bypasses PRCTL while retaining a ready VM/backing pair"
        );
        assert!(
            process_main_thp_policy_owner_case_witness(Case::QueryNonzeroOne, false),
            "a nonzero GET disables ready configuration without issuing SET"
        );
        assert!(
            process_main_thp_policy_owner_case_witness(Case::SetPerm, false),
            "a failed best-effort SET still reaches READY with the retained VM/backing pair"
        );
    }

    #[cfg(not(miri))]
    #[test]
    fn process_main_vm_policy_disables_thp_only_in_its_isolated_child() {
        // Build every static owner before `fork`; the child only performs the
        // source startup transition then crosses the raw exit boundary.
        let (storage, main_static, subprocess, metadata, page_map_storage) = fixture();
        let mut options = VmOptions::uninitialized();
        options.set(crate::config::VmOption::AllowThp, 0);
        options.initialize_all(|_| crate::config::VmOptionEnvironment::Absent);
        let config = MemoryConfig::from_observations(
            PageSize::new(4096).expect("the selected native page size is valid"),
            1024 * 1024,
            false,
            true,
        );
        let parent_before = unsafe {
            crabc_core::process::prctl_raw(PR_GET_THP_DISABLE, 0, 0, 0, 0)
        };

        let child = crabc_core::process::fork_raw().expect("fork isolated process startup");
        if child == 0 {
            let result = unsafe {
                storage.initialize_with_test_components_and_process_memory_policy(
                    config,
                    options,
                    main_static,
                    subprocess,
                    metadata,
                    page_map_storage,
                )
            };
            let status = match result {
                Ok(owner) => match owner.ready().and_then(ProcessMainReadyLease::memory_config) {
                    Ok(ready_config) if !ready_config.has_transparent_huge_pages() => 0,
                    _ => 1,
                },
                Err(_) => 1,
            };
            crabc_core::process::exit_immediately(status);
        }

        let mut status = 0;
        assert_eq!(
            unsafe { crabc_core::process::wait4_raw(child, &mut status, 0) },
            Ok(child),
            "the parent must reap its process-policy child"
        );
        assert_eq!(
            status, 0,
            "source process initialization must retain a THP-disabled memory configuration"
        );
        assert_eq!(
            unsafe { crabc_core::process::prctl_raw(PR_GET_THP_DISABLE, 0, 0, 0, 0) },
            parent_before,
            "the process-policy fixture must not alter the test runner"
        );
    }

    #[test]
    fn process_main_once_blocks_a_distinct_racer_until_release_and_refuses_reentry() {
        let config = memory_config();
        let (storage, main_static, subprocess, metadata, page_map_storage) = fixture();
        let (claimed_sender, claimed_receiver) = mpsc::channel();
        let (release_sender, release_receiver) = mpsc::channel();
        let (initialized_sender, initialized_receiver) = mpsc::channel();
        let (teardown_sender, teardown_receiver) = mpsc::channel();

        let initializer = thread::spawn(move || {
            let mut owner = unsafe {
                storage.initialize_with_test_components_after_claim(
                    config,
                    main_static,
                    subprocess,
                    metadata,
                    page_map_storage,
                    || {
                        assert!(matches!(
                            storage.initialize_with_test_components(
                                config,
                                main_static,
                                subprocess,
                                metadata,
                                page_map_storage,
                            ),
                            Err(ProcessMainInitError::Initializing)
                        ));
                        claimed_sender
                            .send(())
                            .expect("the race witness remains live");
                        release_receiver
                            .recv()
                            .expect("the race witness releases the initializer");
                    },
                )
            }
            .expect("the selected process-main source sequence initializes");
            initialized_sender
                .send(())
                .expect("the race witness remains live");
            teardown_receiver
                .recv()
                .expect("the race witness requests ticket-zero teardown");
            owner
                .teardown()
                .expect("the bounded ticket-zero owner tears down");
        });

        claimed_receiver
            .recv_timeout(Duration::from_secs(2))
            .expect("the first caller holds the source once state before publication");

        let (racer_started_sender, racer_started_receiver) = mpsc::channel();
        let (racer_result_sender, racer_result_receiver) = mpsc::channel();
        let racer = thread::spawn(move || {
            let mut foreign = Theap::empty();
            set_default_theap(NonNull::from(&mut foreign));
            racer_started_sender
                .send(())
                .expect("the race witness remains live");
            let result = unsafe {
                storage.initialize_with_test_components(
                    config,
                    main_static,
                    subprocess,
                    metadata,
                    page_map_storage,
                )
            };
            set_default_theap(NonNull::new(empty_default_theap_ptr()).unwrap());
            racer_result_sender
                .send(matches!(result, Err(ProcessMainInitError::AlreadyInitialized)))
                .expect("the race witness remains live");
        });
        racer_started_receiver
            .recv_timeout(Duration::from_secs(2))
            .expect("the distinct caller begins while initialization is held");
        wait_for_process_once_contender(storage);
        assert!(
            racer_result_receiver
                .recv_timeout(Duration::from_millis(50))
                .is_err(),
            "a distinct caller must remain blocked until the source once release"
        );
        release_sender
            .send(())
            .expect("the initializer remains held at the source once boundary");
        initialized_receiver
            .recv_timeout(Duration::from_secs(2))
            .expect("the initializer publishes its final source roots");
        let racer_observed_ready = racer_result_receiver
            .recv_timeout(Duration::from_secs(2))
            .expect("the blocked distinct caller observes the released process state");

        teardown_sender
            .send(())
            .expect("the initialized ticket-zero owner remains live");
        racer.join().expect("the distinct caller completes");
        initializer
            .join()
            .expect("the source initializer completes teardown");

        assert!(
            racer_observed_ready,
            "a foreign-root caller returns only after the initializer release-publishes READY"
        );
    }

    #[test]
    fn process_main_once_blocks_a_terminal_ready_observer_until_once_release() {
        let config = memory_config();
        let (storage, main_static, subprocess, metadata, page_map_storage) = fixture();
        let (published_sender, published_receiver) = mpsc::channel();
        let (release_sender, release_receiver) = mpsc::channel();
        let (initialized_sender, initialized_receiver) = mpsc::channel();
        let (teardown_sender, teardown_receiver) = mpsc::channel();

        let initializer = thread::spawn(move || {
            let mut owner = unsafe {
                storage.initialize_with_test_components_before_release(
                    config,
                    main_static,
                    subprocess,
                    metadata,
                    page_map_storage,
                    || {
                        published_sender
                            .send(())
                            .expect("the terminal-release witness remains live");
                        release_receiver
                            .recv()
                            .expect("the terminal-release witness releases the initializer");
                    },
                )
            }
            .expect("the selected process-main source sequence initializes");
            initialized_sender
                .send(())
                .expect("the terminal-release witness remains live");
            teardown_receiver
                .recv()
                .expect("the terminal-release witness requests ticket-zero teardown");
            owner
                .teardown()
                .expect("the bounded ticket-zero owner tears down");
        });

        published_receiver
            .recv_timeout(Duration::from_secs(2))
            .expect("the initializer publishes READY before releasing the source once gate");
        assert_eq!(storage.state.load(Ordering::Acquire), READY);

        let (racer_result_sender, racer_result_receiver) = mpsc::channel();
        let racer = thread::spawn(move || {
            let result = unsafe {
                storage.initialize_with_test_components(
                    config,
                    main_static,
                    subprocess,
                    metadata,
                    page_map_storage,
                )
            };
            racer_result_sender
                .send(matches!(result, Err(ProcessMainInitError::AlreadyInitialized)))
                .expect("the terminal-release witness remains live");
        });

        wait_for_process_once_contender(storage);
        assert!(
            racer_result_receiver
                .recv_timeout(Duration::from_millis(50))
                .is_err(),
            "READY alone must not let a caller bypass the retained source once lock"
        );
        release_sender
            .send(())
            .expect("the initializer remains held at the terminal source once boundary");
        initialized_receiver
            .recv_timeout(Duration::from_secs(2))
            .expect("the initializer returns only after releasing the source once gate");
        assert!(
            racer_result_receiver
                .recv_timeout(Duration::from_secs(2))
                .expect("the terminal observer wakes after the source once release"),
            "the terminal observer receives the immutable READY outcome"
        );

        teardown_sender
            .send(())
            .expect("the initialized ticket-zero owner remains live");
        racer.join().expect("the terminal observer completes");
        initializer
            .join()
            .expect("the terminal-release initializer completes teardown");
    }

    #[test]
    fn process_main_once_wakes_a_distinct_racer_with_retained_after_failure() {
        let fault = fault::install(fault::Plan::at(
            fault::Point::Map,
            1,
            crabc_core::Errno::NOMEM,
        ));
        let config = memory_config();
        let (storage, main_static, subprocess, metadata, page_map_storage) = fixture();
        let (claimed_sender, claimed_receiver) = mpsc::channel();
        let (release_sender, release_receiver) = mpsc::channel();
        let (initializer_result_sender, initializer_result_receiver) = mpsc::channel();

        let racer_observed_retained = thread::scope(|scope| {
            // The initializer's first selected operation is the PageMap map
            // itself, so it needs an explicit scoped permit from the parent
            // test's plan. The racing observer stays unpermitted.
            let permit = fault.permit();
            let initializer = scope.spawn(move || permit.run(|| {
                let result = unsafe {
                    storage.initialize_with_test_components_after_claim(
                        config,
                        main_static,
                        subprocess,
                        metadata,
                        page_map_storage,
                        || {
                            claimed_sender
                                .send(())
                                .expect("the failure-race witness remains live");
                            release_receiver
                                .recv()
                                .expect("the failure-race witness releases the initializer");
                        },
                    )
                };
                initializer_result_sender
                    .send(matches!(
                        result,
                        Err(ProcessMainInitError::PageMap(
                            ProcessPageMapError::Initialization(crabc_core::Errno::NOMEM)
                        ))
                    ))
                    .expect("the failure-race witness remains live");
            }));

            claimed_receiver
                .recv_timeout(Duration::from_secs(2))
                .expect("the failing caller holds the source once state before publication");

            let (racer_started_sender, racer_started_receiver) = mpsc::channel();
            let (racer_result_sender, racer_result_receiver) = mpsc::channel();
            let racer = scope.spawn(move || {
                racer_started_sender
                    .send(())
                    .expect("the failure-race witness remains live");
                let result = unsafe {
                    storage.initialize_with_test_components(
                        config,
                        main_static,
                        subprocess,
                        metadata,
                        page_map_storage,
                    )
                };
                racer_result_sender
                    .send(matches!(result, Err(ProcessMainInitError::Retained)))
                    .expect("the failure-race witness remains live");
            });
            racer_started_receiver
                .recv_timeout(Duration::from_secs(2))
                .expect("the distinct caller begins while failure initialization is held");
            wait_for_process_once_contender(storage);
            assert!(
                racer_result_receiver
                    .recv_timeout(Duration::from_millis(50))
                    .is_err(),
                "a distinct caller must remain blocked until the source once release"
            );
            release_sender
                .send(())
                .expect("the failing initializer remains held at the source once boundary");
            assert!(
                initializer_result_receiver
                    .recv_timeout(Duration::from_secs(2))
                    .expect("the initializer reaches its injected terminal failure"),
                "the injected source-order global PageMap failure remains observable"
            );
            let racer_observed_retained = racer_result_receiver
                .recv_timeout(Duration::from_secs(2))
                .expect("the blocked distinct caller observes the retained process state");

            racer.join().expect("the distinct failing caller completes");
            initializer
                .join()
                .expect("the failing source initializer completes");
            racer_observed_retained
        });
        fault.set(fault::Plan::disabled());

        assert!(
            racer_observed_retained,
            "a distinct caller returns only after the initializer release-publishes RETAINED"
        );
    }

    #[test]
    fn preflight_rejection_leaves_process_startup_cold_and_ticket_zero_unselected() {
        thread::spawn(|| {
            let config = memory_config();
            let (storage, main_static, subprocess, metadata, page_map_storage) = fixture();
            let mut foreign = Theap::empty();
            set_default_theap(NonNull::from(&mut foreign));
            assert!(matches!(
                unsafe {
                    storage.initialize_with_test_components(
                        config,
                        main_static,
                        subprocess,
                        metadata,
                        page_map_storage,
                    )
                },
                Err(ProcessMainInitError::Preflight(MainStaticTheapError::RootsNotPristine))
            ));
            assert_eq!(storage.state.load(Ordering::Acquire), COLD);
            assert_eq!(subprocess.total_thread_count(), 0);
            assert_eq!(subprocess.live_thread_count(), 0);
            assert!(!page_map_storage.test_has_published_root());
            set_default_theap(NonNull::new(empty_default_theap_ptr()).unwrap());

            let mut retry = unsafe {
                storage.initialize_with_test_components(
                    config,
                    main_static,
                    subprocess,
                    metadata,
                    page_map_storage,
                )
            }
            .expect("a preflight-only rejection leaves the process once state retryable");
            retry
                .teardown()
                .expect("the retried ticket-zero owner tears down");
        })
        .join()
        .expect("preflight-rejection test thread completes");
    }

    #[test]
    fn process_main_binds_metadata_before_global_page_map_failure() {
        thread::spawn(|| {
            let config = memory_config();
            let (storage, main_static, subprocess, metadata, page_map_storage) = fixture();
            let fault = fault::install(fault::Plan::at(
                fault::Point::Map,
                1,
                crabc_core::Errno::NOMEM,
            ));

            assert!(matches!(
                unsafe {
                    storage.initialize_with_test_components(
                        config,
                        main_static,
                        subprocess,
                        metadata,
                        page_map_storage,
                    )
                },
                Err(ProcessMainInitError::PageMap(
                    ProcessPageMapError::Initialization(crabc_core::Errno::NOMEM)
                ))
            ));
            assert_eq!(fault.observed(), 1);
            fault.set(fault::Plan::disabled());

            assert!(
                metadata.test_is_bound_for(config, subprocess),
                "the source-static detached image binds before the global PageMap attempt"
            );
            assert!(
                subprocess.test_has_published_metadata_theap(),
                "the initialized detached Theap is published through the selected source subprocess before the global PageMap attempt",
            );
            assert!(
                metadata.test_private_page_map_address().is_none(),
                "the failed global PageMap attempt cannot have formed metadata backing"
            );
            assert_eq!(storage.state.load(Ordering::Acquire), RETAINED);
            assert_eq!(subprocess.total_thread_count(), 0);
            assert_eq!(subprocess.live_thread_count(), 0);
            assert!(!page_map_storage.test_has_published_root());
            assert!(roots_are_pristine_for_main_static_attachment());
            assert!(matches!(
                subprocess.issue_generic_thread_ticket(),
                Err(GenericThreadTicketError::BootstrapRetained)
            ));
        })
        .join()
        .expect("global-PageMap-ordering test thread completes");
    }

    #[test]
    fn process_main_defers_private_metadata_backing_until_first_demand() {
        thread::spawn(|| {
            let config = memory_config();
            let (storage, main_static, subprocess, metadata, page_map_storage) = fixture();
            let mut owner = unsafe {
                storage.initialize_with_test_components(
                    config,
                    main_static,
                    subprocess,
                    metadata,
                    page_map_storage,
                )
            }
            .expect("the source-order process startup binds empty detached metadata");

            assert!(metadata.test_is_bound_for(config, subprocess));
            assert!(
                metadata.test_private_page_map_address().is_none(),
                "process startup must not form detached metadata backing before its first request"
            );

            let fault = fault::install(fault::Plan::at(
                fault::Point::Map,
                1,
                crabc_core::Errno::NOMEM,
            ));
            assert!(matches!(
                metadata.zalloc_for_main_subprocess(config, subprocess, 8),
                Err(MetaError::InitializationFailed)
            ));
            assert_eq!(fault.observed(), 1);
            assert!(
                metadata.test_private_page_map_address().is_none(),
                "an unpublished first-backing failure leaves no private PageMap"
            );
            fault.set(fault::Plan::disabled());

            let mut allocation = metadata
                .zalloc_for_main_subprocess(config, subprocess, 8)
                .expect("the first detached metadata request creates its private backing");
            assert!(metadata.test_private_page_map_address().is_some());
            metadata
                .free(&mut allocation)
                .expect("the first metadata capability releases through its detached owner");

            owner
                .teardown()
                .expect("the bounded ticket-zero owner tears down");
        })
        .join()
        .expect("deferred-metadata-backing test thread completes");
    }

    #[test]
    fn rejected_page_map_after_heap_and_metadata_retains_ticket_zero_without_tls_publication() {
        thread::spawn(|| {
            let config = memory_config();
            let (storage, main_static, subprocess, metadata, page_map_storage) = fixture();
            // First consume this isolated global-map owner without publishing
            // a root. The coordinator must encounter that retained source
            // boundary only after its Heap and detached-metadata predecessors;
            // it must not publish ticket-zero TLS roots as a fallback.
            let fault = fault::install(fault::Plan::at(
                fault::Point::Map,
                1,
                crabc_core::Errno::NOMEM,
            ));
            assert!(matches!(
                page_map_storage.initialize(config, subprocess),
                Err(ProcessPageMapError::Initialization(crabc_core::Errno::NOMEM))
            ));
            fault.set(fault::Plan::disabled());

            assert!(matches!(
                unsafe {
                    storage.initialize_with_test_components(
                        config,
                        main_static,
                        subprocess,
                        metadata,
                        page_map_storage,
                    )
                },
                Err(ProcessMainInitError::PageMap(ProcessPageMapError::Poisoned))
            ));
            assert_eq!(storage.state.load(Ordering::Acquire), RETAINED);
            assert_eq!(subprocess.total_thread_count(), 0);
            assert_eq!(subprocess.live_thread_count(), 0);
            assert!(roots_are_pristine_for_main_static_attachment());
            assert!(matches!(
                subprocess.issue_generic_thread_ticket(),
                Err(GenericThreadTicketError::BootstrapRetained)
            ));
            assert!(matches!(
                unsafe {
                    ThreadLocalDataOwner::begin_with_test_metadata(subprocess, metadata, config)
                },
                Err(ThreadLocalDataError::BootstrapRetained)
            ));
        })
        .join()
        .expect("page-map-failure test thread completes");
    }

    #[test]
    fn ready_process_rejects_a_second_thread_owner_but_reissues_its_immutable_matching_lease() {
        thread::spawn(|| {
            let config = memory_config();
            let (storage, main_static, subprocess, metadata, page_map_storage) = fixture();
            let mut owner = unsafe {
                storage.initialize_with_test_components(
                    config,
                    main_static,
                    subprocess,
                    metadata,
                    page_map_storage,
                )
            }
            .expect("the first source startup succeeds");
            let first = owner.ready().unwrap();
            let second = storage.ready_lease(config, subprocess).unwrap();
            assert_eq!(first.root().unwrap(), second.root().unwrap());
            assert!(matches!(
                unsafe {
                    storage.initialize_with_test_components(
                        config,
                        main_static,
                        subprocess,
                        metadata,
                        page_map_storage,
                    )
                },
                Err(ProcessMainInitError::AlreadyInitialized)
            ));
            let different_config = MemoryConfig::from_observations(
                PageSize::new(4_096).expect("the selected native page size is valid"),
                1024 * 1024 + 1,
                false,
                false,
            );
            assert!(matches!(
                storage.ready_lease(different_config, subprocess),
                Err(ProcessMainInitError::ConfigurationMismatch)
            ));
            assert_eq!(subprocess.total_thread_count(), 1);
            owner.teardown().expect("the first owner still owns teardown");
        })
        .join()
        .expect("ready-process reuse test thread completes");
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn emit_m2_repeated_explicit_process_init_c_rust_trace() {
        thread::spawn(|| {
            let config = memory_config();
            let (storage, main_static, subprocess, metadata, page_map_storage) = fixture();
            let mut owner = unsafe {
                storage.initialize_with_test_components(
                    config, main_static, subprocess, metadata, page_map_storage,
                )
            }.expect("the first explicit process initialization succeeds");
            let first_default = default_theap();
            let first_total = subprocess.total_thread_count();
            let first_live = subprocess.live_thread_count();
            let repeated = unsafe {
                storage.initialize_with_test_components(
                    config, main_static, subprocess, metadata, page_map_storage,
                )
            };
            let second_default = default_theap();
            // SAFETY: the live current-thread owner retains both observed TLS
            // roots through this trace; repeated initialization cannot detach it.
            let first_initialized = unsafe { first_default.as_ref().is_initialized() };
            let second_initialized = unsafe { second_default.as_ref().is_initialized() };
            let trace = [
                ("first_default_initialized", first_initialized),
                ("first_thread_counts_registered", first_total == 1 && first_live == 1),
                ("repeated_call_keeps_initialized", matches!(repeated, Err(ProcessMainInitError::AlreadyInitialized))
                    && second_initialized),
                ("default_identity_preserved", first_default == second_default),
                ("thread_counts_preserved", first_total == subprocess.total_thread_count()
                    && first_live == subprocess.live_thread_count()),
            ];
            std::println!("CRABC_MI_PROCESS_INIT_IDEMPOTENCE_RUST_TRACE_BEGIN");
            for (key, value) in trace {
                std::println!("trace.process_init_idempotence.{key}={}", usize::from(value));
                assert!(value, "repeated explicit process initialization changes {key}");
            }
            std::println!("CRABC_MI_PROCESS_INIT_IDEMPOTENCE_RUST_TRACE_END");
            owner.teardown().expect("the original owner retains teardown");
        }).join().expect("the process-init trace thread completes");
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn emit_m2_concurrent_process_init_callback_c_rust_trace() {
        let config = memory_config();
        let (storage, main_static, subprocess, metadata, page_map_storage) = fixture();
        let (attached_tx, attached_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (result_tx, result_rx) = mpsc::channel();
        let (teardown_tx, teardown_rx) = mpsc::channel();

        let initializer = thread::spawn(move || {
            let (mut owner, startup) = unsafe {
                storage.prepare_with_test_components_and_vm_options(
                    config, resolved_vm_options(), main_static, subprocess,
                    metadata, page_map_storage, None,
                )
            }.expect("the source default owner is attached before the callback interval");
            let first_default = default_theap();
            let initialized_at_callback = unsafe { first_default.as_ref().is_initialized() }
                && storage.state.load(Ordering::Acquire) == SOURCE_ATTACHED;
            let recursive = unsafe { storage.initialize_with_test_components(
                config, main_static, subprocess, metadata, page_map_storage,
            ) };
            let reentry_preserves_owner = matches!(recursive, Err(ProcessMainInitError::Initializing))
                && default_theap() == first_default;
            attached_tx.send((initialized_at_callback, reentry_preserves_owner, first_default.as_ptr() as usize))
                .expect("the callback observer remains live");
            release_rx.recv().expect("the callback interval is released");
            startup.complete().expect("source startup completes after the callback interval");
            let ready_owner_stable = default_theap().as_ptr() as usize == first_default.as_ptr() as usize
                && owner.ready().is_ok();
            result_tx.send(ready_owner_stable).expect("the final observer remains live");
            teardown_rx.recv().expect("the original owner retains teardown");
            owner.teardown().expect("the original owner tears down");
        });

        let (initialized_at_callback, reentry_preserves_owner, first_default) = attached_rx
            .recv_timeout(Duration::from_secs(2)).expect("the owner reaches the callback interval");
        let (contender_tx, contender_rx) = mpsc::channel();
        let contender = thread::spawn(move || {
            let initially_empty = unsafe { !default_theap().as_ref().is_initialized() };
            let result = unsafe { storage.initialize_with_test_components(
                config, main_static, subprocess, metadata, page_map_storage,
            ) };
            let still_empty = unsafe { !default_theap().as_ref().is_initialized() };
            contender_tx.send((matches!(result, Err(ProcessMainInitError::AlreadyInitialized)),
                initially_empty && still_empty)).expect("the contender observer remains live");
        });
        wait_for_process_once_contender(storage);
        let contender_waits = contender_rx.recv_timeout(Duration::from_millis(50)).is_err();
        release_tx.send(()).expect("the owner retains its callback interval");
        let ready_owner_stable = result_rx.recv_timeout(Duration::from_secs(2))
            .expect("the original owner publishes READY");
        let (contender_observed_ready, contender_no_tld) = contender_rx
            .recv_timeout(Duration::from_secs(2)).expect("the contender observes the released state");
        let counters_preserved = subprocess.total_thread_count() == 1
            && subprocess.live_thread_count() == 1;
        let trace = [
            ("initialized_at_callback", initialized_at_callback),
            ("reentry_preserves_owner", reentry_preserves_owner),
            ("contender_waits", contender_waits),
            ("ready_owner_stable", ready_owner_stable),
            ("contender_observed_ready", contender_observed_ready),
            ("contender_no_tld", contender_no_tld),
            ("counters_preserved", counters_preserved),
            ("owner_identity_preserved", first_default != 0),
        ];
        std::println!("CRABC_MI_CONCURRENT_INIT_RUST_TRACE_BEGIN");
        for (key, value) in trace {
            std::println!("trace.concurrent_init.{key}={}", usize::from(value));
            assert!(value, "concurrent process initialization changes {key}");
        }
        std::println!("CRABC_MI_CONCURRENT_INIT_RUST_TRACE_END");
        teardown_tx.send(()).expect("the original owner still owns teardown");
        contender.join().expect("the contender finishes");
        initializer.join().expect("the original owner finishes");
    }

    #[cfg(target_arch = "x86_64")]
    struct LoaderTailObservation {
        storage: &'static ProcessMainInitializationStorage,
        main_static: &'static MainStaticAttachmentStorage,
        subprocess: &'static MainSubprocess,
        metadata: core::pin::Pin<&'static MetaAllocator>,
        page_map: &'static ProcessPageMapStorage,
        entered: mpsc::Sender<()>,
        returned: mpsc::Receiver<bool>,
        observed: core::cell::Cell<Option<(bool, bool, bool)>>,
    }

    #[cfg(target_arch = "x86_64")]
    std::thread_local! {
        static LOADER_TAIL_OBSERVATION: core::cell::Cell<*const LoaderTailObservation> =
            const { core::cell::Cell::new(core::ptr::null()) };
    }

    #[cfg(target_arch = "x86_64")]
    unsafe extern "C" fn observe_loader_tail(_message: *const core::ffi::c_char) {
        LOADER_TAIL_OBSERVATION.with(|slot| {
            // SAFETY: the initializer installs its stack-local observation
            // only for the synchronous startup flush and clears it afterward.
            let Some(observation) = (unsafe { slot.get().as_ref() }) else { return; };
            if observation.observed.get().is_some() { return; }
            let ready = observation.storage.state.load(Ordering::Acquire) == READY;
            let recursive = unsafe { observation.storage.initialize_with_test_components(
                memory_config(), observation.main_static, observation.subprocess,
                observation.metadata, observation.page_map,
            ) };
            let recursive_complete = matches!(recursive, Err(ProcessMainInitError::AlreadyInitialized));
            let _ = observation.entered.send(());
            let contender_completed = observation.returned.recv_timeout(Duration::from_secs(2))
                .unwrap_or(false);
            observation.observed.set(Some((ready, recursive_complete, contender_completed)));
        });
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn emit_m2_loader_tail_once_release_c_rust_trace() {
        let config = memory_config();
        let (storage, main_static, subprocess, metadata, page_map_storage) = fixture();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (returned_tx, returned_rx) = mpsc::channel();
        let (finished_tx, finished_rx) = mpsc::channel();
        let contender = thread::spawn(move || {
            entered_rx.recv_timeout(Duration::from_secs(5)).expect("the loader flush is reached");
            let empty_before = unsafe { !default_theap().as_ref().is_initialized() };
            let result = unsafe { storage.initialize_with_test_components(
                config, main_static, subprocess, metadata, page_map_storage,
            ) };
            let empty_after = unsafe { !default_theap().as_ref().is_initialized() };
            let complete = matches!(result, Err(ProcessMainInitError::AlreadyInitialized));
            let _ = returned_tx.send(complete);
            let _ = finished_tx.send(());
            empty_before && empty_after && complete
        });
        let trace = thread::spawn(move || {
            let output = std::boxed::Box::leak(std::boxed::Box::new(OutputOwner::new(observe_loader_tail)));
            // SAFETY: the null environment means unavailable reads; this
            // isolated source table and delayed output have a single caller.
            unsafe {
                output.initialize_source_options(|| core::ptr::null());
                output.raw_message(crate::diagnostic_output::SourceFormattedMessage::from_source_formatted(
                    c"loader startup delayed diagnostic\n",
                ));
            }
            let observation = LoaderTailObservation {
                storage, main_static, subprocess, metadata, page_map: page_map_storage,
                entered: entered_tx, returned: returned_rx, observed: core::cell::Cell::new(None),
            };
            let (mut owner, startup) = unsafe {
                storage.prepare_with_test_components_and_vm_options(
                    config, resolved_vm_options(), main_static, subprocess, metadata,
                    page_map_storage, Some(output),
                )
            }.expect("the isolated source body attaches its owner");
            let first = default_theap();
            LOADER_TAIL_OBSERVATION.with(|slot| slot.set(&observation));
            let completed = startup.complete();
            LOADER_TAIL_OBSERVATION.with(|slot| slot.set(core::ptr::null()));
            completed.expect("the loader startup tail completes");
            let (ready, recursive_complete, contender_completed) = observation.observed.get()
                .expect("the real delayed flush delivered to the default stderr primitive");
            let trace = [
                ("ready_before_tail_output", ready),
                ("recursive_init_complete", recursive_complete),
                ("contender_completes_during_tail", contender_completed),
                ("default_owner_preserved", first == default_theap()),
                ("counters_preserved", subprocess.total_thread_count() == 1 && subprocess.live_thread_count() == 1),
                ("tail_claim_not_repeated", !unsafe { storage.complete_runtime_startup_after_first_allocation() }
                    .expect("the completed runtime tail remains claimed")),
            ];
            finished_rx.recv_timeout(Duration::from_secs(5))
                .expect("the original owner stays attached until its contender returns");
            owner.teardown().expect("the initial source owner retains teardown");
            trace
        }).join().expect("the loader-tail initializer completes");
        assert!(contender.join().expect("the process-init contender completes"));
        std::println!("CRABC_MI_LOADER_TAIL_RUST_TRACE_BEGIN");
        for (key, value) in trace {
            std::println!("trace.loader_tail.{key}={}", usize::from(value));
        }
        std::println!("CRABC_MI_LOADER_TAIL_RUST_TRACE_END");
        assert!(trace.iter().all(|(_, value)| *value),
            "process initialization must release once before loader-tail output: {trace:?}");
    }

    #[cfg(target_arch = "x86_64")]
    fn bootstrap_output_prefix(
        stderr: crate::diagnostic_output::DefaultStderrOutput,
    ) -> (
        &'static ProcessMainInitializationStorage,
        AllocatorOnceCompletion<'static>,
        ProcessStartupDiagnostics<'static>,
        VmProcess<'static>,
        &'static MainSubprocess,
    ) {
        let storage = ProcessMainInitializationStorage::test_static_owner();
        let subprocess = MainSubprocess::test_static_owner();
        let thread = current_thread_identity().unwrap();
        let completion = storage.process_once.enter(OnceThreadId::new(thread.get()).unwrap())
            .unwrap().unwrap();
        storage.initializing_thread.store(thread.get(), Ordering::Relaxed);
        storage.state.store(INITIALIZING, Ordering::Release);
        // SAFETY: the actual winning once token owns this isolated inline
        // output slot; its exclusive initialization ends before publication.
        let pointer = unsafe {
            (*storage.diagnostic_output.get()).write(OutputOwner::new(stderr));
            let output = (&mut *storage.diagnostic_output.get()).assume_init_mut();
            output.initialize_source_options(|| core::ptr::null());
            output.option_set(crate::config::SourceOption::ShowErrors, 1).unwrap();
            core::ptr::from_mut(output)
        };
        storage.diagnostic_output_ptr.store(pointer, Ordering::Release);
        // SAFETY: the permanent initialized slot is shared only from here.
        let output = unsafe { &*pointer };
        let policy = unsafe { VmPolicy::from_process_options(output) };
        let process = unsafe { storage.retain_vm_process(
            policy, subprocess, &mut memory_config(), false, false,
        ) }.unwrap();
        (storage, completion, ProcessStartupDiagnostics::Selected(output), process, subprocess)
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn selected_static_theap_is_counted_after_tld_link_before_heap_publication() {
        crate::test_process::run_in_fresh_process(
            "process_init::tests::selected_static_theap_is_counted_after_tld_link_before_heap_publication",
            || {
                #[derive(Default)]
                struct Observation {
                    calls: usize,
                    theaps: (i64, i64, i64),
                    tld_linked: bool,
                    heap_member_absent: bool,
                    heap_head_is_metadata: bool,
                    initialized: bool,
                    heap_unpublished: bool,
                    refcount: usize,
                    subprocess_matches: bool,
                    theap: *mut Theap,
                    heap: *mut crate::types::Heap,
                }
                unsafe fn observe(
                    theap: NonNull<Theap>, heap: NonNull<crate::types::Heap>,
                    tld: NonNull<crate::types::ThreadLocalData>, subprocess: &MainSubprocess,
                    argument: *mut core::ffi::c_void,
                ) {
                    // SAFETY: the winning startup retains these exact images;
                    // all mutable projections and list guards have ended. The
                    // stack observation remains exclusively borrowed until the
                    // synchronous operation returns, and no reference escapes.
                    let observation = unsafe { &mut *argument.cast::<Observation>() };
                    let theaps = subprocess.identity().statistics().final_output_snapshot().theaps;
                    observation.calls += 1;
                    observation.theaps = (theaps.current, theaps.peak, theaps.total);
                    observation.tld_linked = unsafe { tld.as_ref() }.test_theap_head_is(theap.as_ptr());
                    observation.heap_member_absent = unsafe { heap.as_ref() }
                        .has_shared_theap_member_blocking(theap.as_ptr()) == Ok(false);
                    let metadata = subprocess.identity().test_published_metadata_theap();
                    observation.heap_head_is_metadata = !metadata.is_null()
                        && unsafe { heap.as_ref() }.test_theap_head_is(metadata);
                    observation.initialized = unsafe { theap.as_ref() }.is_initialized();
                    observation.heap_unpublished = unsafe { theap.as_ref() }.heap().is_null();
                    observation.refcount = unsafe { theap.as_ref() }.refcount();
                    observation.subprocess_matches = unsafe { theap.as_ref() }
                        .is_bound_to_main_subprocess(subprocess);
                    observation.theap = theap.as_ptr();
                    observation.heap = heap.as_ptr();
                }
                unsafe extern "C" fn stderr_output(message: *const core::ffi::c_char) {
                    unsafe extern "C" {
                        fn fputs(message: *const core::ffi::c_char, stream: *mut core::ffi::c_void)
                            -> core::ffi::c_int;
                        static mut stderr: *mut core::ffi::c_void;
                    }
                    // SAFETY: normal source output supplies a terminated fragment
                    // and the pinned native runtime retains its actual stderr FILE.
                    unsafe { let _ = fputs(message, stderr); }
                }
                let mut observation = Observation::default();
                // SAFETY: this fresh process enters its actual winning startup
                // with valid host environment and FILE providers. The callback
                // only reads retained images and writes bounded stack fields.
                let started = unsafe {
                    crate::main_theap::with_static_theap_publication_observer_for_test(
                        observe, core::ptr::from_mut(&mut observation).cast(), || {
                            crate::runtime_lifecycle::test_initialize_process_from_host_environment(
                                4096, crate::diagnostic_output::RuntimeStderrOutput::new(stderr_output),
                            )
                        },
                    )
                };
                assert!(started);
                assert_eq!(observation.calls, 1, "only the winning static startup is observed");
                assert_eq!(observation.theaps, (1, 1, 1),
                    "static Theap accounting precedes Heap publication");
                assert!(observation.tld_linked, "the actual TLD already links its static Theap");
                assert!(observation.heap_member_absent, "the ordinary Theap is not linked into its Heap yet");
                assert!(observation.heap_head_is_metadata,
                    "the actual Heap still retains only its earlier detached metadata head");
                assert!(!observation.initialized);
                assert!(observation.heap_unpublished);
                assert_eq!(observation.refcount, 1);
                assert!(observation.subprocess_matches);
                assert_eq!(default_theap().as_ptr(), observation.theap);
                // SAFETY: successful startup retains the same actual static
                // images, and this thread only reads them after publication.
                assert!(unsafe { &*observation.theap }.is_initialized());
                assert_eq!(unsafe { &*observation.theap }.heap(), observation.heap);
                assert!(unsafe { &*observation.heap }.test_theap_head_is(observation.theap));
                assert!(crate::runtime_lifecycle::initialize_process());
                assert_eq!(MainSubprocess::global().identity().statistics()
                    .final_output_snapshot().theaps.current, 1,
                    "ordinary repeated startup does not count the owner twice");
            },
        );
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn first_allocation_metadata_entropy_refusal_buffers_normal_warning_until_runtime_tail() {
        crate::test_process::run_in_fresh_process(
            "process_init::tests::first_allocation_metadata_entropy_refusal_buffers_normal_warning_until_runtime_tail",
            || {
                std::thread_local! {
                    static WARNINGS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
                    static FLUSH_SAW_WEAK_METADATA: core::cell::Cell<bool> =
                        const { core::cell::Cell::new(false) };
                }
                unsafe extern "C" fn stderr_output(message: *const core::ffi::c_char) {
                    unsafe extern "C" {
                        fn fputs(message: *const core::ffi::c_char, stream: *mut core::ffi::c_void)
                            -> core::ffi::c_int;
                        static mut stderr: *mut core::ffi::c_void;
                    }
                    // SAFETY: the source FILE route supplies a live terminated
                    // fragment; its observation neither allocates nor registers
                    // an early callback or changes the output phase.
                    let bytes = unsafe { core::ffi::CStr::from_ptr(message) }.to_bytes();
                    if bytes.windows(b"unable to use secure randomness\n".len())
                        .any(|window| window == b"unable to use secure randomness\n") {
                        WARNINGS.with(|slot| slot.set(slot.get() + 1));
                        FLUSH_SAW_WEAK_METADATA.with(|slot| slot.set(
                            MetaAllocator::global().test_detached_metadata_random_is_weak(
                                MainSubprocess::global(),
                            ) == Some(true),
                        ));
                    }
                    // SAFETY: the pinned native test runtime retains its actual
                    // musl stderr FILE for the source process's lifetime.
                    unsafe { let _ = fputs(message, stderr); }
                }
                // SAFETY: the newly exec'd process has not started its source
                // initialization or exposed an environment reader. This actual
                // source option selects warning output before table capture.
                unsafe { std::env::set_var("mimalloc_show_errors", "1") };
                // SAFETY: the host environment and FILE provider stay valid for
                // this fresh process; no selected or ready process is fabricated.
                let facts = unsafe { NativeProcessStartupFacts::new(
                    4096, crate::runtime_lifecycle::test_host_process_environment,
                    crate::diagnostic_output::RuntimeStderrOutput::new(stderr_output),
                ) }.unwrap();
                assert!(crate::runtime_lifecycle::publish_native_process_startup_facts(facts));
                let injection = fault::install(fault::Plan::at(
                    fault::Point::Entropy, 1, crabc_core::Errno::AGAIN,
                ));
                let crate::runtime_lifecycle::NativePageAllocationResult::Allocated(client) =
                    crate::runtime_lifecycle::native_allocate(48, false)
                    else { panic!("normal entropy refusal must not fail first allocation"); };
                assert_eq!(injection.observed(), 2,
                    "the metadata and ordinary main source images each draw entropy once");
                assert_eq!(MetaAllocator::global().test_detached_metadata_random_is_weak(
                    MainSubprocess::global(),
                ), Some(true));
                // SAFETY: the source initial thread retains this initialized
                // default owner and ends its field projection immediately.
                assert_eq!(unsafe { Theap::test_random_is_weak_at(default_theap()) }, Some(false));
                WARNINGS.with(|slot| assert_eq!(slot.get(), 0,
                    "first allocation keeps source output delayed before its loader tail"));
                injection.set(fault::Plan::disabled());
                assert!(crate::runtime_lifecycle::initialize_process());
                WARNINGS.with(|slot| assert_eq!(slot.get(), 1,
                    "the normal first metadata warning must already be queued before reseeding"));
                FLUSH_SAW_WEAK_METADATA.with(|slot| assert!(slot.get(),
                    "post-init flush precedes the separate weak metadata retry"));
                assert_eq!(MetaAllocator::global().test_detached_metadata_random_is_weak(
                    MainSubprocess::global(),
                ), Some(false));
                assert!(crate::runtime_lifecycle::initialize_process());
                WARNINGS.with(|slot| assert_eq!(slot.get(), 1,
                    "the runtime tail and normal warning are not repeated"));
                drop(injection);
                // SAFETY: this fixture exclusively retains the exact client
                // across both startup entries and releases it only afterwards.
                assert_eq!(unsafe { crate::runtime_lifecycle::native_free(client) },
                    crate::runtime_lifecycle::NativePageFreeResult::Freed);
            },
        );
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn bootstrap_entropy_warning_is_buffered_before_weak_expansion() {
        std::thread_local! {
            static WARNINGS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
        }
        unsafe extern "C" fn observe(message: *const core::ffi::c_char) {
            // SAFETY: the source route supplies a live terminated fragment.
            let bytes = unsafe { core::ffi::CStr::from_ptr(message) }.to_bytes();
            if bytes.windows(b"unable to use secure randomness\n".len())
                .any(|window| window == b"unable to use secure randomness\n") {
                WARNINGS.with(|slot| slot.set(slot.get() + 1));
            }
        }
        unsafe extern "C" fn registered(
            message: *const core::ffi::c_char, _: *mut core::ffi::c_void,
        ) {
            // SAFETY: registration supplies the same live terminated fragment.
            unsafe { observe(message) };
        }
        thread::spawn(|| {
            let (storage, completion, diagnostics, process, subprocess) = bootstrap_output_prefix(observe);
            let ProcessStartupDiagnostics::Selected(output) = diagnostics else { unreachable!() };
            let scope = storage.scoped_bootstrap_output(&completion, &diagnostics, &process, subprocess).unwrap();
            let injection = fault::install(fault::Plan::at_pair(
                fault::Point::Entropy, 1, fault::Point::Clock, 1, crabc_core::Errno::NOMEM,
            ));
            let mut context = crate::random::TheapRandomImage::empty_weak();
            let prepared = crate::random::PreparedRandomInitialization::prepare_normal();
            assert!(prepared.requires_warning());
            // SAFETY: the actual completion and inline output remain live;
            // no random projection or metadata entry spans warning admission.
            let material = unsafe { scope.deliver_prepared_random_warning(prepared) }.unwrap();
            WARNINGS.with(|slot| assert_eq!(slot.get(), 0));
            assert!(!context.is_initialized());
            assert_eq!(injection.secondary_observed(), 0);
            context.initialize_prepared(material);
            assert!(context.is_initialized() && context.is_weak());
            assert_eq!(injection.observed(), 1);
            assert_eq!(injection.secondary_observed(), 1);
            assert_eq!(storage.state.load(Ordering::Acquire), INITIALIZING);
            drop(injection);
            drop(scope);
            storage.publish_terminal_state_and_release(completion, RETAINED);
            // SAFETY: this isolated output owner has no concurrent dispatch.
            // Actual registration flushes its queued warning; this does not
            // pretend that the incomplete startup prefix reached its tail.
            unsafe { output.register_output(Some(registered), core::ptr::null_mut()) };
            WARNINGS.with(|slot| assert_eq!(slot.get(), 1));
        }).join().unwrap();
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn published_owner_entropy_warning_precedes_expansion_and_allows_allocation_reentry() {
        crate::test_process::run_in_fresh_process(
            "process_init::tests::published_owner_entropy_warning_precedes_expansion_and_allows_allocation_reentry",
            || {
                std::thread_local! {
                    static CONTEXT: core::cell::Cell<*const crate::random::TheapRandomImage> =
                        const { core::cell::Cell::new(core::ptr::null()) };
                    static FAULT: core::cell::Cell<*const fault::Guard> =
                        const { core::cell::Cell::new(core::ptr::null()) };
                    static OBSERVED: core::cell::Cell<(usize, bool, bool, bool)> =
                        const { core::cell::Cell::new((0, false, false, false)) };
                }
                unsafe extern "C" fn stderr_output(message: *const core::ffi::c_char) {
                    unsafe extern "C" {
                        fn fputs(message: *const core::ffi::c_char, stream: *mut core::ffi::c_void)
                            -> core::ffi::c_int;
                        static mut stderr: *mut core::ffi::c_void;
                    }
                    // SAFETY: the pinned native test runtime retains its actual
                    // musl FILE transport for this fresh process's lifetime.
                    unsafe { let _ = fputs(message, stderr); }
                }
                unsafe extern "C" fn observe(
                    message: *const core::ffi::c_char, _: *mut core::ffi::c_void,
                ) {
                    // SAFETY: actual synchronous output supplies a live fragment.
                    let bytes = unsafe { core::ffi::CStr::from_ptr(message) }.to_bytes();
                    if bytes != b"unable to use secure randomness\n" { return; }
                    // SAFETY: stack owners remain live and their mutable
                    // projections end before the admitted callback begins.
                    let inert = CONTEXT.with(|slot| !unsafe { &*slot.get() }.is_initialized());
                    let before_clock = FAULT.with(|slot| unsafe { &*slot.get() }.secondary_observed() == 0);
                    let crate::runtime_lifecycle::NativePageAllocationResult::Allocated(nested) =
                        crate::runtime_lifecycle::native_allocate(96, false)
                        else { panic!("the actual published owner permits warning reentry"); };
                    // SAFETY: this callback exclusively owns its nested client.
                    let freed = unsafe { crate::runtime_lifecycle::native_free(nested) }
                        == crate::runtime_lifecycle::NativePageFreeResult::Freed;
                    OBSERVED.with(|slot| slot.set((slot.get().0 + 1, inert, before_clock, freed)));
                }
                // SAFETY: this newly exec'd fixture has not initialized its
                // process or exposed an environment reader. The actual source
                // option enables warning output before its table is captured.
                unsafe { std::env::set_var("mimalloc_show_errors", "1") };
                // SAFETY: the fresh process retains the exact FILE transport.
                let transport = unsafe { crate::diagnostic_output::RuntimeStderrOutput::new(stderr_output) };
                assert!(crate::runtime_lifecycle::test_initialize_process_from_host_environment(4096, transport));
                let crate::runtime_lifecycle::NativePageAllocationResult::Allocated(seed) =
                    crate::runtime_lifecycle::native_allocate(32, false)
                    else { panic!("the real initialized owner retains its selected Theap"); };
                let output = process_output_owner().unwrap();
                // SAFETY: startup completed its output tail, and this process
                // retains its single callback until synchronous delivery ends.
                unsafe { output.register_output(Some(observe), core::ptr::null_mut()) };
                let injection = fault::install(fault::Plan::at_pair(
                    fault::Point::Entropy, 1, fault::Point::Clock, 1, crabc_core::Errno::NOMEM,
                ));
                let mut context = crate::random::TheapRandomImage::empty_weak();
                CONTEXT.with(|slot| slot.set(core::ptr::from_ref(&context)));
                FAULT.with(|slot| slot.set(core::ptr::from_ref(&injection)));
                // SAFETY: the seed retains the actual selected owner and no
                // metadata or allocator projection crosses factory entry.
                let material = unsafe { crate::runtime_lifecycle::with_native_allocation_owner(
                    default_theap(), |owner| {
                        let prepared = crate::random::PreparedRandomInitialization::prepare_normal();
                        assert!(prepared.requires_warning());
                        // SAFETY: actual admission remains held and all image
                        // projections ended before the source warning route.
                        owner.deliver_prepared_random_warning(prepared)
                    },
                ) }.unwrap();
                OBSERVED.with(|slot| assert_eq!(slot.get(), (1, true, true, true)));
                assert!(!context.is_initialized());
                context.initialize_prepared(material);
                assert!(context.is_initialized() && context.is_weak());
                assert_eq!(injection.observed(), 1);
                CONTEXT.with(|slot| slot.set(core::ptr::null()));
                FAULT.with(|slot| slot.set(core::ptr::null()));
                drop(injection);
                // SAFETY: delivery ended before reset; the original seed is
                // still this fixture's exclusively owned live client.
                unsafe { output.register_output(None, core::ptr::null_mut()) };
                assert_eq!(unsafe { crate::runtime_lifecycle::native_free(seed) },
                    crate::runtime_lifecycle::NativePageFreeResult::Freed);
            },
        );
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn bootstrap_output_admission_rejects_unconnected_crossed_and_terminal_owners() {
        unsafe extern "C" fn discard(_: *const core::ffi::c_char) {}
        thread::spawn(|| {
            let (storage, completion, diagnostics, process, subprocess) = bootstrap_output_prefix(discard);
            assert!(matches!(storage.scoped_bootstrap_output(
                &completion, &ProcessStartupDiagnostics::Unconnected, &process, subprocess,
            ), Err(BootstrapOutputAdmissionError::Unavailable)));
            assert!(matches!(storage.scoped_bootstrap_output(
                &completion, &diagnostics, &process, MainSubprocess::test_static_owner(),
            ), Err(BootstrapOutputAdmissionError::Invalid)));
            let other_gate = std::boxed::Box::leak(std::boxed::Box::new(AllocatorOnce::new()));
            let other_completion = other_gate.enter(OnceThreadId::new(
                current_thread_identity().unwrap().get(),
            ).unwrap()).unwrap().unwrap();
            assert!(matches!(storage.scoped_bootstrap_output(
                &other_completion, &diagnostics, &process, subprocess,
            ), Err(BootstrapOutputAdmissionError::Invalid)));
            other_completion.complete().unwrap();
            let other_policy = std::boxed::Box::leak(std::boxed::Box::new(
                VmPolicy::new(resolved_vm_options()).unwrap(),
            ));
            let crossed = VmProcess::new_main(other_policy, subprocess);
            assert!(matches!(storage.scoped_bootstrap_output(
                &completion, &diagnostics, &crossed, subprocess,
            ), Err(BootstrapOutputAdmissionError::Invalid)));
            for state in [COLD, SOURCE_ATTACHED, READY, RETAINED, TERMINAL_CLOSED] {
                storage.state.store(state, Ordering::Release);
                assert!(matches!(storage.scoped_bootstrap_output(
                    &completion, &diagnostics, &process, subprocess,
                ), Err(BootstrapOutputAdmissionError::Invalid)));
            }
            storage.state.store(INITIALIZING, Ordering::Release);
            let owner = storage.initializing_thread.load(Ordering::Relaxed);
            storage.initializing_thread.store(owner.wrapping_add(8), Ordering::Relaxed);
            assert!(matches!(storage.scoped_bootstrap_output(
                &completion, &diagnostics, &process, subprocess,
            ), Err(BootstrapOutputAdmissionError::Invalid)));
            storage.initializing_thread.store(owner, Ordering::Relaxed);
            let pointer = storage.diagnostic_output_ptr.load(Ordering::Acquire);
            storage.diagnostic_output_ptr.store(core::ptr::null_mut(), Ordering::Release);
            assert!(matches!(storage.scoped_bootstrap_output(
                &completion, &diagnostics, &process, subprocess,
            ), Err(BootstrapOutputAdmissionError::Invalid)));
            storage.diagnostic_output_ptr.store(pointer, Ordering::Release);
            let scope = storage.scoped_bootstrap_output(&completion, &diagnostics, &process, subprocess).unwrap();
            assert!(scope.matches_subprocess(subprocess));
            assert!(core::ptr::eq(scope.output().unwrap(), pointer));
            assert!(storage.page_map_storage.load(Ordering::Acquire).is_null(),
                "metadata startup precedes process PageMap publication");
            assert!(core::ptr::eq(scope.process().unwrap(), &process));
            assert!(scope.matches_process(&process));
            assert!(scope.matches_process(&VmProcess::new_main(process.policy(), subprocess)));
            assert!(!scope.matches_process(&crossed));
            assert!(!scope.matches_process(&VmProcess::new_main(
                process.policy(), MainSubprocess::test_static_owner(),
            )));
            assert!(!scope.matches_process(&VmProcess::new(process.policy(), subprocess.identity())));
            storage.state.store(RETAINED, Ordering::Release);
            assert!(!scope.matches_subprocess(subprocess));
            assert!(!scope.matches_process(&process));
            assert!(matches!(scope.process(), Err(BootstrapOutputAdmissionError::Invalid)));
            assert!(matches!(scope.output(), Err(BootstrapOutputAdmissionError::Invalid)));
            storage.publish_terminal_state_and_release(completion, RETAINED);
        }).join().unwrap();
    }

    #[cfg(all(target_arch = "x86_64", not(miri), feature = "mi-debug-3"))]
    fn with_startup_metadata_output_fixture<R>(
        operation: impl FnOnce(
            &ScopedBootstrapOutput<'_>, crate::meta::MetaAllocatorBound<'static>,
            core::pin::Pin<&'static MetaAllocator>, &'static ProcessMainInitializationStorage,
            &'static MainSubprocess,
        ) -> R,
    ) -> R {
        unsafe extern "C" fn discard(_: *const core::ffi::c_char) {}
        let (storage, completion, diagnostics, process, subprocess) = bootstrap_output_prefix(discard);
        let scope = storage.scoped_bootstrap_output(&completion, &diagnostics, &process, subprocess).unwrap();
        let metadata = MetaAllocator::test_static_owner();
        let mut selection = subprocess.reserve_static_bootstrap().unwrap();
        let foundation = MainStaticHeapFoundation::initialize(
            MainStaticAttachmentStorage::test_static_owner(), subprocess, &mut selection,
        ).unwrap();
        // SAFETY: these actual pinned owners and the original winning scope
        // remain retained throughout source initialization and its callbacks.
        let bound = unsafe { metadata.prepare_for_main_heap_with_bootstrap_output(
            memory_config(), subprocess, foundation, &scope,
        ) }.unwrap();
        let map_storage = ProcessPageMapStorage::test_static_owner();
        let map = map_storage.initialize_for_process(memory_config(), subprocess, process).unwrap();
        // SAFETY: the winning completion excludes every process-ready reader
        // while these final slots select the original backing tuple.
        unsafe { (*storage.config.get()).write(memory_config()) };
        storage.subprocess.store(subprocess.owner_ptr(), Ordering::Release);
        storage.page_map_storage.store(core::ptr::from_ref(map_storage).cast_mut(), Ordering::Release);
        metadata.bind_process_backing(ProcessMainBackingBinding::new(storage, process, map)).unwrap();
        let result = operation(&scope, bound, metadata, storage, subprocess);
        selection.retain();
        storage.publish_terminal_state_and_release(completion, RETAINED);
        result
    }

    #[cfg(all(target_arch = "x86_64", not(miri), feature = "mi-debug-3"))]
    #[test]
    fn startup_fresh_page_assertion_dispatch_retains_original_source_candidate() {
        const CHILD: &str = "CRABC_MI_STARTUP_PAGE_ASSERTION_CHILD";
        const TEST: &str = "process_init::tests::startup_fresh_page_assertion_dispatch_retains_original_source_candidate";
        struct Audit<'witness, 'scope, 'startup> {
            witness: &'witness crate::meta::SourceInitializationOutputWitness<'scope, 'startup, 'static>,
            metadata: core::pin::Pin<&'static MetaAllocator>,
            storage: &'static ProcessMainInitializationStorage,
            subprocess: &'static MainSubprocess,
            theap: NonNull<Theap>,
            initial_pages: i64,
            observed: core::cell::Cell<Option<crate::types::PageValiditySnapshot>>,
            observations: core::cell::Cell<usize>,
            in_callback: core::cell::Cell<bool>,
        }
        unsafe fn corrupt(state: &crate::types::PageValiditySnapshot,
            page: NonNull<crate::types::Page>, argument: *mut core::ffi::c_void) {
            // SAFETY: the scoped observer retains this live stack audit. The
            // actual fresh claim owns this committed byte before list/client
            // publication, and no allocation or output occurs in this observer.
            let audit = unsafe { &*argument.cast::<Audit<'_, '_, '_>>() };
            assert_eq!(state.page, page);
            assert_eq!((state.used, state.capacity), (0, 0));
            assert!(state.free.is_null() && state.local_free.is_null() && state.remote.is_null());
            audit.observed.set(Some(*state));
            audit.observations.set(audit.observations.get() + 1);
            unsafe { state.area.as_ptr().write(0x5a) };
        }
        unsafe extern "C" fn output(message: *const core::ffi::c_char, argument: *mut core::ffi::c_void) {
            // SAFETY: registration retains this exact stack audit and the
            // output owner supplies a live NUL-terminated source fragment.
            let audit = unsafe { &*argument.cast::<Audit<'_, '_, '_>>() };
            let bytes = unsafe { core::ffi::CStr::from_ptr(message) }.to_bytes();
            if !bytes.windows(b"assertion failed".len()).any(|part| part == b"assertion failed")
                || audit.in_callback.replace(true) { return; }
            let Some(original) = audit.observed.get() else { return; };
            // SAFETY: the original task still retains its registered claim;
            // no page, engine or queue projection survives this scalar audit.
            let (registered, unfinished, statistics) = unsafe {
                let state = crate::types::Page::validity_snapshot_at(original.page);
                let registered = audit.witness.page_map().is_ok_and(|map|
                    map.checked_lookup(original.area.as_ptr()) == original.page.as_ptr());
                let unfinished = state.area == original.area && state.used == 0 && state.capacity == 0
                    && state.free.is_null() && state.local_free.is_null() && state.remote.is_null()
                    && state.area.as_ptr().read() == 0x5a
                    && Theap::local_page_count_at(audit.theap) == 0;
                let statistics = Theap::final_statistics_at(audit.theap)
                    .is_some_and(|(_, stats)| stats.pages.current == audit.initial_pages + 1);
                (registered, unfinished, statistics)
            };
            let origin = audit.storage.state.load(Ordering::Acquire) == INITIALIZING
                && audit.witness.matches_theap(audit.theap)
                && audit.witness.process().is_ok_and(|process|
                    core::ptr::eq(process.subprocess(), audit.subprocess.identity()));
            // The observer ended before dispatch. This different request may
            // allocate through the original issuer but cannot reuse the task's
            // unpublished registered candidate or its uninitialized free list.
            let nested = audit.metadata.zalloc_for_main_subprocess(memory_config(), audit.subprocess, 32)
                .and_then(|mut allocation| audit.metadata.free(&mut allocation));
            std::println!("startup.assertion.audit registered={registered} unfinished={unfinished} statistics={statistics} origin={origin} nested={nested:?}");
            std::println!("{}", std::string::String::from_utf8_lossy(bytes));
            audit.in_callback.set(false);
        }
        if let Some(mode) = std::env::var_os(CHILD) {
            with_startup_metadata_output_fixture(|scope, bound, metadata, storage, subprocess| {
                // SAFETY: this actual scope and issuer precede the first
                // candidate, and remain retained through fatal source output.
                let witness = unsafe { bound.capture_startup_source_initialization_output(scope) }.unwrap();
                let source_output = witness.output().unwrap();
                unsafe { source_output.option_set(crate::config::SourceOption::ShowErrors,
                    if mode == "quiet" { 0 } else { 1 }).unwrap(); }
                let theap = NonNull::new(subprocess.identity().test_published_metadata_theap()).unwrap();
                let audit = Audit { witness: &witness, metadata, storage, subprocess, theap,
                    initial_pages: unsafe { Theap::final_statistics_at(theap) }.unwrap().1.pages.current,
                    observed: core::cell::Cell::new(None), observations: core::cell::Cell::new(0),
                    in_callback: core::cell::Cell::new(false) };
                let argument = core::ptr::from_ref(&audit).cast_mut().cast();
                // SAFETY: registration and observation stay on this original
                // source thread; the audit outlives every synchronous callback.
                unsafe { source_output.register_output(Some(output), argument) };
                let allocation = unsafe { crate::page_validity::with_fresh_page_initialization_observer_for_test(
                    corrupt, argument, || metadata.zalloc_aligned_for_main_subprocess(
                        memory_config(), subprocess, 7, 128 * 1024,
                    ),
                ) };
                assert!(matches!(allocation, Err(MetaError::AllocationUnavailable)));
                assert_eq!(audit.observations.get(), 1);
                let task = witness.take_retained_initialization_task().unwrap().unwrap();
                assert_eq!(task.failure(), crate::single_thread::FreshOsPageInitializationFailure::SourceObservation(
                    crate::page_validity::SourcePageInvariant::InitiallyZero));
                assert!(task.matches_theap(theap) && task.belongs_to_subprocess(subprocess.identity()));
                let task = with_startup_metadata_output_fixture(|foreign_scope, foreign_bound, _, _, _| {
                    let foreign = unsafe { foreign_bound.capture_startup_source_initialization_output(foreign_scope) }.unwrap();
                    // SAFETY: both genuine startup issuers remain retained.
                    // Foreign admission must return the original task intact.
                    unsafe { task.dispatch_source_initialization(&foreign) }.unwrap_err()
                });
                assert!(task.matches_theap(theap) && task.belongs_to_subprocess(subprocess.identity()));
                assert_eq!(storage.state.load(Ordering::Acquire), INITIALIZING);
                std::println!("startup.assertion.original-task-ready mode={}", mode.to_string_lossy());
                // SAFETY: the exact retained Registered source-observation
                // task and its preallocation witness remain live; no allocator
                // projection or guard spans the source's fatal callback.
                let refused = unsafe { task.dispatch_source_initialization(&witness) };
                panic!("actual original source dispatch refused: {refused:?}");
            });
            return;
        }
        use std::os::unix::process::ExitStatusExt;
        for mode in ["quiet", "loud"] {
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            command.args(["--exact", TEST, "--nocapture", "--test-threads=1"])
                .env(CHILD, mode)
                .current_dir(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().join(".work/tmp"));
            for (name, _) in std::env::vars_os() {
                if name.to_string_lossy().starts_with("mimalloc_") { command.env_remove(name); }
            }
            let result = command.output().unwrap();
            let stdout = std::string::String::from_utf8_lossy(&result.stdout);
            let stderr = std::string::String::from_utf8_lossy(&result.stderr);
            std::println!("{stdout}{stderr}");
            assert_eq!(result.status.signal(), Some(6), "{stdout}{stderr}");
            assert!(stdout.contains("startup.assertion.original-task-ready"), "{stdout}{stderr}");
            assert!(stdout.contains("registered=true unfinished=true statistics=true origin=true nested=Ok(())"), "{stdout}{stderr}");
            assert!(stdout.contains("src/page.c\":729, _mi_page_init"), "{stdout}{stderr}");
            assert!(stdout.contains("mi_mem_is_zero(page_start, mi_page_committed(page))"), "{stdout}{stderr}");
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn startup_failed_entropy_retry_warns_after_random_projection_ends() {
        std::thread_local! {
            static RETRY_FAULT: core::cell::Cell<*const fault::Guard> = const { core::cell::Cell::new(core::ptr::null()) };
            static CLOCK_AT_WARNING: core::cell::Cell<Option<usize>> = const { core::cell::Cell::new(None) };
            static WARNINGS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
            static METADATA: core::cell::Cell<Option<(core::pin::Pin<&'static MetaAllocator>, &'static MainSubprocess)>> =
                const { core::cell::Cell::new(None) };
        }
        unsafe extern "C" fn observe(message: *const core::ffi::c_char) {
            // SAFETY: the output owner supplies a live NUL-terminated fragment.
            let bytes = unsafe { core::ffi::CStr::from_ptr(message) }.to_bytes();
            if bytes.windows(b"unable to use secure randomness\n".len())
                .any(|window| window == b"unable to use secure randomness\n")
            {
                RETRY_FAULT.with(|slot| {
                    // SAFETY: the test retains this stack guard throughout
                    // synchronous startup output and clears the pointer afterward.
                    CLOCK_AT_WARNING.with(|clock| clock.set(Some(unsafe { &*slot.get() }.secondary_observed())));
                });
                // SAFETY: the callback runs on the source initial thread;
                // warning delivery must have ended its random projection.
                let draw = unsafe { Theap::next_os_reservation_random_at(default_theap()) };
                assert!(draw.is_some_and(|value| value != 0));
                METADATA.with(|slot| {
                    let (metadata, subprocess) = slot.get().unwrap();
                    assert!(metadata.test_detached_metadata_random_is_weak(subprocess).is_some(),
                        "the source metadata entry lock ends before warning callback reentry");
                });
                WARNINGS.with(|count| count.set(count.get() + 1));
            }
        }
        for detached in [false, true] {
            thread::spawn(move || {
                let (storage, main_static, subprocess, metadata, page_map) = fixture();
                let output = std::boxed::Box::leak(std::boxed::Box::new(OutputOwner::new(observe)));
                // SAFETY: this thread retains the isolated option table and its
                // callback; an absent environment leaves no foreign borrow.
                unsafe {
                    output.initialize_source_options(|| core::ptr::null());
                    output.option_set(crate::config::SourceOption::ShowErrors, 1).unwrap();
                }
                let (mut owner, startup) = unsafe {
                    storage.prepare_with_test_components_and_vm_options(
                        memory_config(), resolved_vm_options(), main_static, subprocess,
                        metadata, page_map, Some(output),
                    )
                }.expect("the actual source owner attaches before the loader tail");
                METADATA.with(|slot| slot.set(Some((metadata, subprocess))));
                if detached {
                    let _guard = subprocess.identity().lock_metadata_theap().unwrap();
                    let pointer = NonNull::new(subprocess.identity().test_published_metadata_theap()).unwrap();
                    // SAFETY: the source metadata lock retains exclusive access
                    // to this initialized detached image until the block ends.
                    unsafe { Theap::with_os_reservation_random_at(pointer, |random| {
                        random.unwrap().initialize_weak();
                    }) };
                } else {
                    // SAFETY: this source initial thread owns the random field,
                    // and its projection ends before startup completion.
                    unsafe { Theap::with_os_reservation_random_at(default_theap(), |random| {
                        random.unwrap().initialize_weak();
                    }) };
                }
                let fault = fault::install(fault::Plan::at_pair(
                    fault::Point::Entropy, 1, fault::Point::Clock, 1, crabc_core::Errno::NOMEM,
                ));
                RETRY_FAULT.with(|slot| slot.set(&fault));
                startup.complete().expect("failed entropy continues through weak initialization");
                assert!(fault.observed() >= 1, "the source retry reaches the entropy fault");
                WARNINGS.with(|count| assert_eq!(count.get(), 1));
                CLOCK_AT_WARNING.with(|clock| assert_eq!(clock.get(), Some(0),
                    "entropy refusal must warn before weak-key clock observations"));
                assert_eq!(fault.secondary_observed(), 1);
                RETRY_FAULT.with(|slot| slot.set(core::ptr::null()));
                if detached {
                    assert_eq!(metadata.test_detached_metadata_random_is_weak(subprocess), Some(true));
                } else {
                    assert_eq!(unsafe { Theap::test_random_is_weak_at(default_theap()) }, Some(true));
                }
                METADATA.with(|slot| slot.set(None));
                drop(fault);
                owner.teardown().expect("the source owner retains normal teardown");
            }).join().expect("the entropy warning source control completes");
        }
    }

    #[test]
    fn process_main_owner_opens_the_ticket_zero_first_arena_page_owner() {
        thread::spawn(|| {
            let config = memory_config();
            let (storage, main_static, subprocess, metadata, page_map_storage) = fixture();
            let arena_storage = ProcessSharedArenaStorage::test_static_owner();
            let mut owner = unsafe {
                storage.initialize_with_test_components(
                    config,
                    main_static,
                    subprocess,
                    metadata,
                    page_map_storage,
                )
            }
            .expect("source-order startup creates the retained ticket-zero owner");

            let mut page_owner = owner
                .begin_first_arena_page_allocator_with_test_storage(arena_storage)
                .expect("the process owner supplies its exact ready map and ticket-zero attachment");
            assert!(arena_storage.test_is_cold(), "the factory itself makes no startup reservation");
            let block = page_owner
                .allocate(37, false)
                .expect("the first ticket-zero request reaches the bounded default arena");
            assert!(
                !arena_storage.test_is_cold(),
                "the process-owned page route reserves only after its first fresh page miss"
            );
            // SAFETY: `block` is the exact active allocation returned above
            // and has not escaped the process-main page owner.
            unsafe { page_owner.free(block) }
                .expect("the process-owned first-arena block frees normally");
            assert!(matches!(page_owner.finish(), Ok(())));
            owner
                .teardown()
                .expect("the released page owner returns ticket-zero teardown authority");
        })
        .join()
        .expect("process-main first-arena page-owner fixture completes");
    }

    #[test]
    fn process_ready_first_arena_pair_reuses_the_published_default_arena_for_one_later_owner() {
        thread::spawn(|| {
            let config = memory_config();
            let (storage, main_static, subprocess, metadata, page_map_storage) = fixture();
            let arena_storage = ProcessSharedArenaStorage::test_static_owner();
            let mut owner = unsafe {
                storage.initialize_with_test_components(
                    config,
                    main_static,
                    subprocess,
                    metadata,
                    page_map_storage,
                )
            }
            .expect("source-order startup creates the ticket-zero owner");

            assert!(matches!(
                owner.ready_shared_arena_pair_with_test_storage(arena_storage),
                Err(ProcessMainReadySharedArenaError::Arena(ProcessSharedArenaError::Retained))
            ), "a cold arena sidecar cannot become a process-ready page pair");

            let mut first = owner
                .begin_first_arena_page_allocator_with_test_storage(arena_storage)
                .expect("the ticket-zero owner opens its first default arena route");
            let block = first
                .allocate(37, false)
                .expect("the first fresh page publishes the default arena");
            // SAFETY: `block` is the exact still-live allocation returned by
            // this first owner and has not escaped it.
            unsafe { first.free(block) }.expect("the first owner releases its only block");
            assert!(matches!(
                first.finish(),
                Ok(())
            ), "the empty first owner releases its map lifecycle");

            let pair = owner
                .ready_shared_arena_pair_with_test_storage(arena_storage)
                .expect("the ready process derives the exact published first-arena pair");
            assert_eq!(
                pair.page_map_root().unwrap(),
                owner.ready().unwrap().root().unwrap(),
                "the reuse pair retains the coordinator's release-published map root"
            );
            let main_heap = owner
                .shared_main_heap_lease()
                .expect("ticket zero mints the later-owner heap witness");

            thread::scope(|scope| {
                scope
                    .spawn(move || {
                        let mut later = match unsafe {
                            MainHeapThreadAttachment::begin_with_test_metadata(
                                main_heap, metadata, config,
                            )
                        } {
                            Ok(attachment) => attachment,
                            Err(_) => panic!("the later source attachment must publish"),
                        };
                        let mut allocator = MainHeapThreadProcessPageAllocator::begin(&mut later, pair)
                            .expect("the published first arena is reusable by the selected later owner");
                        let block = allocator
                            .allocate(37, false)
                            .expect("the later owner allocates through the reused arena");
                        for index in 0..37 {
                            // SAFETY: `block` is uniquely live and has its
                            // complete requested 37-byte extent.
                            unsafe { block.as_ptr().add(index).write((index as u8).wrapping_add(19)) };
                        }
                        // SAFETY: `block` is the exact current allocation of
                        // this live later-thread engine and remains exclusive.
                        let replacement = unsafe {
                            allocator.reallocate(Some(block), crate::config::SMALL_MAX_OBJ_SIZE + 1)
                        }
                        .expect("the later owner exposes ordinary realloc through the reused arena");
                        for index in 0..37 {
                            // SAFETY: the successful replacement is uniquely
                            // live and preserves the initialized old prefix.
                            assert_eq!(
                                unsafe { replacement.as_ptr().add(index).read() },
                                (index as u8).wrapping_add(19)
                            );
                        }
                        // SAFETY: `replacement` is the sole current allocation
                        // returned by the successful reallocation.
                        unsafe { allocator.free(replacement) }
                            .expect("the later owner releases its only allocation");
                        assert!(matches!(
                            allocator.finish(),
                            Ok(())
                        ), "the later page engine drains cleanly");
                        later
                            .finish_after_user_destructors()
                            .expect("the later attachment completes after its empty page engine");
                    })
                    .join()
                    .expect("the later source owner remains current-thread-local");
            });

            owner
                .teardown()
                .expect("the reused first arena leaves ticket-zero teardown authority intact");
        })
        .join()
        .expect("process-ready first-arena reuse fixture completes");
    }

    #[test]
    fn process_lifetime_static_page_session_keeps_ticket_zero_pages_sound_with_a_later_main_lease() {
        thread::spawn(|| {
            let config = memory_config();
            let (storage, main_static, subprocess, metadata, page_map_storage) = fixture();
            let arena_storage = ProcessSharedArenaStorage::test_static_owner();
            let mut owner = unsafe {
                storage.initialize_with_test_components(
                    config,
                    main_static,
                    subprocess,
                    metadata,
                    page_map_storage,
                )
            }
            .expect("source-order startup creates ticket zero before the permanent session");

            let session = owner
                .begin_process_lifetime_page_session()
                .expect("the empty ticket-zero image converts to one permanent page owner");
            let main_heap = session.shared_main_heap_lease();
            assert!(matches!(
                owner
                    .attachment_mut()
                    .expect("the permanent session retains the ticket-zero attachment")
                    .page_session(),
                Err(MainStaticPageSessionError::ProcessPageSessionLive)
            ), "the permanent session excludes a second borrowed static page owner");

            thread::scope(|scope| {
                scope
                    .spawn(move || {
                        let mut later = match unsafe {
                            MainHeapThreadAttachment::begin_with_test_metadata(
                                main_heap, metadata, config,
                            )
                        } {
                            Ok(attachment) => attachment,
                            Err(_) => panic!("the persistent static lease admits one later no-page owner"),
                        };
                        later
                            .finish_after_user_destructors()
                            .expect("the later no-page owner detaches before ticket-zero page use");
                    })
                    .join()
                    .expect("the later no-page lifecycle stays current-thread local");
            });

            let page_map = owner
                .ready()
                .and_then(ProcessMainReadyLease::page_map)
                .expect("the permanent session keeps the process map witness ready");
            let arena = match arena_storage.reserve_one_os_arena(
                page_map,
                crate::config::ARENA_MIN_SIZE,
                MapAccess::Committed,
            ) {
                Ok(arena) => arena,
                Err(_) => panic!("one explicit process arena is available for the static page proof"),
            };
            let pair = ProcessPageArenaLease::join(page_map, arena)
                .expect("the static page engine receives its exact map/arena pair");
            let lifecycle = pair
                .begin_page_lifecycle()
                .expect("the static process page lifecycle claims the plain map boundary");
            let arena = pair
                .arena()
                .expect("the paired source arena remains published");
            let page_map = lifecycle
                .page_map()
                .expect("the page lifecycle grants the static engine its map view");
            // SAFETY: `session` is the one permanent ticket-zero page owner,
            // and `lifecycle` remains live beside the exact paired arena for
            // this complete ordinary allocation/free engine.
            let mut engine = unsafe {
                PageAllocatorEngine::activate_main_static(session, arena, ArenaId::none(), page_map)
            };
            let block = engine
                .allocate(37, false)
                .expect("ticket zero allocates after the later no-page owner detached");
            // SAFETY: `block` is the one live allocation from this exact
            // static engine and has not escaped the test.
            unsafe { engine.free(block) }
                .expect("the ticket-zero page lifecycle frees its allocation");
            assert!(matches!(
                engine.finish(),
                Ok(())
            ), "the static page engine releases every page before its session is retained");
            lifecycle
                .finish()
                .expect("the empty static page engine releases the map lifecycle");
            assert!(matches!(
                owner.teardown(),
                Err(MainStaticTheapError::ProcessPageSessionLive)
            ), "the copied permanent shared-main lease cannot be followed by main-image teardown");
        })
        .join()
        .expect("process-lifetime ticket-zero/static-main ownership fixture completes");
    }
}
