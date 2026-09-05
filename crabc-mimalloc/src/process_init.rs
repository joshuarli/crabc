// Copyright (c) 2018-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// `LICENSE` at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `src/init.c:184-214,305-360,536-592`
// (`mi_heap_main_init_once`, `_mi_thread_init_with_heap`, and
// `mi_process_init_once`), `src/libc.c:115-140`
// (`_mi_atomic_once_enter`/`_mi_atomic_once_release` through `once.rs`), and
// `src/subproc.c:29-46,95-101`.

//! Source-ordered main-process initialization.
//!
//! The current port has one deliberately bounded process-startup transition:
//! select the ticket-zero static branch, initialize the source static main
//! Heap, ready the detached metadata route, publish the process PageMap, and
//! only then attach the ticket-zero TLD/Theap and compiler-TLS roots. This is
//! an ordering and ownership coordinator, not a general allocator startup:
//! it does not choose options, reserve or manage the process-shared arena,
//! initialize pthread keys, route allocations/frees, run process shutdown,
//! or expose the metadata allocator's private map/arena as process-global
//! state. The explicit `initialize_with_vm_options` route additionally
//! retains one resolved source VM-policy image beside the source subprocess;
//! the older explicit-config route remains policy-unbound rather than
//! manufacturing ambient defaults. Its one page-bearing factory only creates
//! a private first-fresh-page owner; that owner remains arena-free until a
//! valid allocation miss.

#[cfg(test)]
extern crate std;

use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::mem::MaybeUninit;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicPtr, AtomicU8, Ordering};

use crate::compiler_tls::current_thread_identity;
use crate::main_theap::{
    MainStaticAttachmentStorage, MainStaticHeapFoundation,
    MainStaticHeapFoundationError, MainStaticHeapLease, MainStaticTheapAttachment,
    MainStaticPageSessionError, MainStaticProcessPageSession,
    MainStaticProcessPageSessionError, MainStaticTheapError,
};
use crate::main_static_page::{
    MainStaticFirstArenaPageAllocator, MainStaticFirstArenaPageAllocatorBeginError,
};
use crate::meta::{MetaAllocator, MetaError};
use crate::once::{AllocatorOnce, AllocatorOnceCompletion, OnceThreadId};
use crate::config::VmOptions;
use crate::os::{MemoryConfig, VmPolicy, VmPolicyConfigurationError, VmProcess};
use crate::page_map::PageMapHeader;
use crate::process_arena::{
    ProcessPageArenaLease, ProcessPageArenaLeaseError, ProcessSharedArenaError,
    ProcessSharedArenaStorage,
};
use crate::process_page_map::{
    ProcessPageMapError, ProcessPageMapLease, ProcessPageMapStorage,
};
use crate::subproc::{
    MainStaticBootstrapSelectionError, MainSubprocess,
};

const COLD: u8 = 0;
const INITIALIZING: u8 = 1;
const READY: u8 = 2;
const RETAINED: u8 = 3;

/// How this source-startup call owns an optional resolved VM policy.
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
}

/// Final process-lifetime state for the bounded source main-process startup.
///
/// `READY` is published only after every predecessor in the source order has
/// completed. `RETAINED` is terminal: a failure after the coordinator wins
/// the static ticket-zero selection may leave a static Heap, detached metadata
/// image, PageMap, TLD, or TLS root live, so retrying as if the process were
/// cold would invent an unsafe second startup branch.
pub(crate) struct ProcessMainInitializationStorage {
    /// The source-shaped once gate retains its private lock from the winning
    /// COLD claim until this coordinator has Release-published READY or
    /// RETAINED.  A different caller therefore waits as pinned
    /// `_mi_atomic_once_enter` does, while the stored source thread identity
    /// lets a recursive caller decline without waiting on itself.
    process_once: AllocatorOnce,
    state: AtomicU8,
    config: UnsafeCell<MaybeUninit<MemoryConfig>>,
    // A resolved source option image belongs to this exact process lifetime,
    // not to a caller-local VM helper. The pointer is null for the preserved
    // legacy explicit-config path; otherwise READY Release-publishes this
    // permanent inline owner before any ready lease can borrow a VmProcess.
    vm_policy: UnsafeCell<MaybeUninit<VmPolicy>>,
    vm_policy_ptr: AtomicPtr<VmPolicy>,
    subprocess: AtomicPtr<MainSubprocess>,
    page_map_storage: AtomicPtr<ProcessPageMapStorage>,
}

// SAFETY: `process_once` makes COLD -> INITIALIZING exclusive and retains its
// private lock until the final state is Release-published. The final
// configuration, optional VM policy, subprocess, and PageMap-storage pointer
// are written before READY's Release publication and never replaced. A live
// `ProcessMainThread` remains current-thread-only through its contained main
// attachment; READY leases are immutable process-root witnesses only.
unsafe impl Sync for ProcessMainInitializationStorage {}

impl ProcessMainInitializationStorage {
    const fn new() -> Self {
        Self {
            process_once: AllocatorOnce::new(),
            state: AtomicU8::new(COLD),
            config: UnsafeCell::new(MaybeUninit::uninit()),
            vm_policy: UnsafeCell::new(MaybeUninit::uninit()),
            vm_policy_ptr: AtomicPtr::new(core::ptr::null_mut()),
            subprocess: AtomicPtr::new(core::ptr::null_mut()),
            page_map_storage: AtomicPtr::new(core::ptr::null_mut()),
        }
    }

    /// Returns the one production process coordinator. It remains cold until
    /// a future runtime startup path supplies the frozen memory configuration.
    #[inline]
    pub(crate) fn global() -> &'static Self {
        &PROCESS_MAIN_INITIALIZATION
    }

    /// Builds an isolated leaked process-lifetime startup fixture.
    #[cfg(test)]
    pub(crate) fn test_static_owner() -> &'static Self {
        std::boxed::Box::leak(std::boxed::Box::new(Self::new()))
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

    /// Runs the isolated source-order transition with one resolved VM policy
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
                INITIALIZING => return Err(ProcessMainInitError::Initializing),
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

        self.state.store(INITIALIZING, Ordering::Release);
        after_claim();

        let (policy, apply_process_memory_policy) = match vm_policy {
            VmPolicyStartup::None => (None, false),
            VmPolicyStartup::RetainOnly(policy) => (Some(policy), false),
            VmPolicyStartup::ApplyProcessMemoryPolicy(policy) => (Some(policy), true),
        };
        let vm_process = if let Some(policy) = policy {
            // The source process-load edge clears `os_preloading` before its
            // option/OS/main-heap work. Retain this policy first, then expose
            // only its post-preloading read state to every later source
            // owner. A later startup failure is terminal and deliberately
            // leaves this exact policy image retained with its process.
            match unsafe {
                self.retain_vm_process(
                    policy,
                    subprocess,
                    &mut config,
                    apply_process_memory_policy,
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
        let metadata_bound = match metadata.prepare_for_main_subprocess(config, subprocess) {
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

        let page_map = match page_map_storage.initialize(config, subprocess) {
            Ok(page_map) => page_map,
            Err(error) => {
                selection.retain();
                self.publish_terminal_state_and_release(completion, RETAINED);
                return Err(ProcessMainInitError::PageMap(error));
            }
        };
        if let Some(process) = vm_process {
            // The policy-aware path has now published every predecessor that
            // metadata needs: its detached Theap identity is bound and the
            // selected global PageMap has one stable root. Bind the exact
            // process pair before any metadata demand or READY publication;
            // a legacy explicit-config startup intentionally cannot invent
            // this policy-bound backing route.
            if let Err(error) = metadata.bind_process_backing(process, page_map) {
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
        let attachment = match unsafe {
            MainStaticTheapAttachment::begin_after_heap_foundation(foundation, selection)
        } {
            Ok(attachment) => attachment,
            Err(error) => {
                self.publish_terminal_state_and_release(completion, RETAINED);
                return Err(ProcessMainInitError::InitialThread(error));
            }
        };

        // SAFETY: this CAS winner owns every final startup slot; no READY
        // reader can observe any field before the Release store below.
        unsafe { (*self.config.get()).write(config) };
        self.subprocess.store(subprocess.as_ptr(), Ordering::Release);
        self.page_map_storage
            .store(core::ptr::from_ref(page_map_storage).cast_mut(), Ordering::Release);
        self.publish_terminal_state_and_release_with_hook(completion, READY, before_release);

        let ready = ProcessMainReadyLease {
            storage: self,
            page_map,
            config,
            subprocess,
        };
        Ok(ProcessMainThread {
            storage: self,
            attachment: Some(attachment),
            ready,
            state: ProcessMainThreadState::Attached,
            _not_send_or_sync: PhantomData,
        })
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
        if !core::ptr::eq(self.subprocess.load(Ordering::Acquire), subprocess.as_ptr()) {
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

    #[inline]
    fn config(&self) -> MemoryConfig {
        // SAFETY: callers first observed READY with Acquire, whose Release
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
    ) -> Result<VmProcess<'static>, ProcessMainInitError> {
        let policy = unsafe { self.bind_vm_policy(policy) }?;
        policy.finish_preloading();
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
        Ok(VmProcess::new(policy, subprocess))
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
        mut config: MemoryConfig,
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
        // SAFETY: this test-only method owns the successful COLD ->
        // INITIALIZING transition and the supplied owners are all static.
        let process = match unsafe {
            self.retain_vm_process(policy, subprocess, &mut config, false)
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
    fn outcome_after_process_once(&self) -> Result<ProcessMainThread, ProcessMainInitError> {
        match self.state.load(Ordering::Acquire) {
            COLD | INITIALIZING => Err(ProcessMainInitError::Initializing),
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

static PROCESS_MAIN_INITIALIZATION: ProcessMainInitializationStorage =
    ProcessMainInitializationStorage::new();

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
    BootstrapSelection(MainStaticBootstrapSelectionError),
    HeapFoundation(MainStaticHeapFoundationError),
    Metadata(MetaError),
    PageMap(ProcessPageMapError),
    InitialThread(MainStaticTheapError),
}

/// Coordinator-issued proof for one canonical VM-backed process root.
///
/// This is deliberately not reconstructible from a [`VmProcess`] and a
/// [`ProcessPageMapLease`].  Independent test or future process coordinators
/// can legitimately form matching-looking pairs for the same subprocess;
/// only this source-order coordinator proves that the retained policy and
/// PageMap root were selected together before its sole `READY` publication.
/// Metadata and arena backing consumers use this capability instead of
/// accepting an arbitrary pair of copyable witnesses.
#[derive(Clone, Copy)]
pub(crate) struct ProcessMainBackingBinding {
    storage: &'static ProcessMainInitializationStorage,
    process: VmProcess<'static>,
    page_map: ProcessPageMapLease,
}

impl ProcessMainBackingBinding {
    #[inline]
    fn new(
        storage: &'static ProcessMainInitializationStorage,
        process: VmProcess<'static>,
        page_map: ProcessPageMapLease,
    ) -> Self {
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
    pub(crate) const fn page_map(self) -> ProcessPageMapLease { self.page_map }

    /// Confirms that this capability still names the coordinator's one
    /// retained policy/root pair. Production metadata binding occurs before
    /// READY, while later idempotent consumers see READY; neither state lets
    /// an arbitrary raw pair/map input become a binding capability.
    #[inline]
    pub(crate) fn is_active(self) -> bool {
        matches!(self.storage.state.load(Ordering::Acquire), INITIALIZING | READY)
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
    page_map: ProcessPageMapLease,
    config: MemoryConfig,
    subprocess: &'static MainSubprocess,
}

// SAFETY: this lease only carries process-lifetime immutable witnesses. Page
// mutations remain gated by `ProcessPageMapMutationLease`, and thread state is
// deliberately absent.
unsafe impl Send for ProcessMainReadyLease {}
// SAFETY: see the Send justification above.
unsafe impl Sync for ProcessMainReadyLease {}

impl ProcessMainReadyLease {
    #[inline]
    pub(crate) fn root(self) -> Result<NonNull<PageMapHeader>, ProcessMainInitError> {
        self.ensure_ready()?;
        self.page_map.root().map_err(ProcessMainInitError::PageMap)
    }

    #[inline]
    pub(crate) fn page_map(self) -> Result<ProcessPageMapLease, ProcessMainInitError> {
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
        Ok(VmProcess::new(policy, self.subprocess))
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
                self.subprocess.as_ptr(),
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
    TornDown,
    Retained,
}

/// Current-thread owner of the source ticket-zero TLD/Theap after a successful
/// process-main startup transition.
#[must_use = "a process-main thread owner must explicitly tear down or retain its ticket-zero attachment"]
pub(crate) struct ProcessMainThread {
    storage: &'static ProcessMainInitializationStorage,
    attachment: Option<MainStaticTheapAttachment>,
    ready: ProcessMainReadyLease,
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
    Arena(ProcessSharedArenaError),
    Pair(ProcessPageArenaLeaseError),
}

impl ProcessMainThread {
    /// Returns the immutable process-ready witness only while the ticket-zero
    /// attachment is still live and current.
    pub(crate) fn ready(&self) -> Result<ProcessMainReadyLease, ProcessMainInitError> {
        if self.state != ProcessMainThreadState::Attached {
            return Err(ProcessMainInitError::Retained);
        }
        self.ready.ensure_ready()?;
        Ok(self.ready)
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
    pub(crate) fn ready_shared_arena_pair(
        &self,
    ) -> Result<ProcessPageArenaLease, ProcessMainReadySharedArenaError> {
        self.ready_shared_arena_pair_with_storage(ProcessSharedArenaStorage::global())
    }

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
    pub(crate) fn begin_first_arena_page_allocator(
        &mut self,
    ) -> Result<MainStaticFirstArenaPageAllocator<'_>, ProcessMainFirstArenaPageAllocatorError> {
        self.begin_first_arena_page_allocator_with_storage(ProcessSharedArenaStorage::global())
    }

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
        if self.state == ProcessMainThreadState::Attached {
            // A dropped ticket-zero owner can leave roots, TLD registration,
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

    // Linux's process-local THP query used by the child-only startup test.
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

        let initializer = thread::spawn(move || {
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
        });

        claimed_receiver
            .recv_timeout(Duration::from_secs(2))
            .expect("the failing caller holds the source once state before publication");

        let (racer_started_sender, racer_started_receiver) = mpsc::channel();
        let (racer_result_sender, racer_result_receiver) = mpsc::channel();
        let racer = thread::spawn(move || {
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
