//! Durable owner for one x86-64 general initial loader graph.
//!
//! Both private general-initial roots start with a stack-local transaction,
//! because mapping, relocation, protection, RELRO sealing, and TLS planning
//! can still fail there. This module is the one place that can reserve and
//! publish the successful transaction. It retains the graph identity/edges,
//! complete [`Object`] records, and each transaction map's exact reserved
//! span for process life. The kernel-mapped main image is retained as graph
//! root metadata but is never rollback or `munmap` eligible.
//!
//! The lifecycle is deliberately small and one-way:
//!
//! ```text
//! Vacant -> Discovering -> Prepared -> Reserved -> Ready
//! ```
//!
//! `Prepared` is reached only after all fallible graph work and constructor
//! preflight. TLS keeps its `ARCH_SET_FS` operation after `Reserved`, where
//! the only successor is the non-fallible `Ready` publication. No public
//! loader view is exposed here; a later private facade must copy from the
//! acquire-published immutable state rather than borrow transaction storage.

#![allow(dead_code)]

use super::*;
use super::x86_64_initial_graph_state::{InitialGraphState, ObjectIdentity, ObjectState};
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicU8, Ordering};
#[cfg(test)]
use core::sync::atomic::AtomicBool;

const GENERAL_INITIAL_LOADER_VACANT: u8 = 0;
const GENERAL_INITIAL_LOADER_RESERVED: u8 = 1;
const GENERAL_INITIAL_LOADER_READY: u8 = 2;

/// The lifecycle of the one general initial graph owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GeneralInitialLoaderPhase {
    /// No transaction has a publishable owner.
    Vacant,
    /// Graph/object discovery and all pre-publication mutation are allowed.
    Discovering,
    /// The graph is complete and all fallible preparation is finished.
    Prepared,
    /// The process-lifetime slot is exclusively reserved before publication.
    Reserved,
    /// The immutable state is release-published for process life.
    Ready,
}

/// Fail-closed errors at the general initial-owner boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GeneralInitialLoaderStateError {
    InvalidPhase,
    GraphIncomplete,
    PublicationUnavailable,
}

/// Names every pre-publication failure path that uses the common rollback.
///
/// The stage is deliberately recorded at the call site rather than inferred
/// from a syscall result: a future loader facade must not turn one of these
/// rollback-safe failures into a post-publication mutation path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GeneralInitialPreparationStage {
    Discovery,
    Relocation,
    Protection,
    Relro,
    SelfRelro,
    InitializerPreflight,
    TlsPlanning,
    TlsRegistry,
    PublicationReservation,
    RuntimeV1Reservation,
    TlsMaterialization,
}

/// The canonical graph/object store for a successful general initial load.
///
/// Slot zero is the kernel-owned main image. Every later slot was admitted by
/// this transaction, carries its map provenance/span in [`Object`], and can
/// be rolled back in reverse admission order before [`Ready`]. TLS module IDs
/// and offsets live in these same object records, so the TLS route cannot
/// acquire a duplicate graph just to retain its attachment.
pub(crate) struct GeneralInitialLoaderState {
    phase: GeneralInitialLoaderPhase,
    graph: InitialGraphState,
    objects: [Object; MAX_OBJECTS],
    initial_tls_attached: bool,
}

// The startup transaction is single-threaded. This word nevertheless makes
// the lifetime boundary explicit: readers acquire only `Ready`, and a failed
// pre-publication transaction restores `Vacant` exactly once.
static GENERAL_INITIAL_LOADER_PUBLICATION: AtomicU8 =
    AtomicU8::new(GENERAL_INITIAL_LOADER_VACANT);

// The native test harness runs unit tests concurrently, while the real
// initial transaction is necessarily process-unique. Serialize only the
// tests that exercise this one global publication slot.
#[cfg(test)]
static GENERAL_INITIAL_LOADER_TEST_LOCK: AtomicBool = AtomicBool::new(false);

// `#[used]` keeps the source of truth alive even if no current private
// observer consumes it. The state is intentionally x86-private loader data,
// not a RuntimeV1 record and not an ELF/public `dl*` interface.
#[used]
#[link_section = ".bss.crabc_general_initial_loader_state"]
static mut GENERAL_INITIAL_LOADER_STATE: MaybeUninit<GeneralInitialLoaderState> =
    MaybeUninit::uninit();

#[cfg(test)]
pub(crate) struct GeneralInitialLoaderTestPublicationGuard;

#[cfg(test)]
impl Drop for GeneralInitialLoaderTestPublicationGuard {
    fn drop(&mut self) {
        GENERAL_INITIAL_LOADER_TEST_LOCK.store(false, Ordering::Release);
    }
}

impl GeneralInitialLoaderState {
    /// Starts the stack-local part of one initial transaction.
    pub(crate) fn new(main_identity: ObjectIdentity, mut main: Object) -> Self {
        main.map_provenance = ObjectMapProvenance::KernelMain;
        main.map_span_start = 0;
        main.map_span_byte_len = 0;
        let mut objects = [EMPTY_OBJECT; MAX_OBJECTS];
        objects[0] = main;
        Self {
            phase: GeneralInitialLoaderPhase::Discovering,
            graph: InitialGraphState::new(main_identity),
            objects,
            initial_tls_attached: false,
        }
    }

    pub(crate) const fn phase(&self) -> GeneralInitialLoaderPhase {
        self.phase
    }

    pub(crate) fn object_count(&self) -> usize {
        self.graph.object_count()
    }

    /// Gives discovery code the only mutable graph/object view.
    ///
    /// Mapping, graph-edge attachment, and TLS module-ID attachment must all
    /// finish before `Prepared`; no caller receives a mutable view afterward.
    pub(crate) fn discovery_mut(
        &mut self,
    ) -> Result<(&mut InitialGraphState, &mut [Object; MAX_OBJECTS]), GeneralInitialLoaderStateError>
    {
        if self.phase != GeneralInitialLoaderPhase::Discovering {
            return Err(GeneralInitialLoaderStateError::InvalidPhase);
        }
        Ok((&mut self.graph, &mut self.objects))
    }

    /// Completes recursive graph discovery while retaining the mutable
    /// transaction phase for relocation, TLS planning, and RELRO work.
    pub(crate) fn finish_discovery(&mut self) -> Result<(), GeneralInitialLoaderStateError> {
        if self.phase != GeneralInitialLoaderPhase::Discovering {
            return Err(GeneralInitialLoaderStateError::InvalidPhase);
        }
        self.graph
            .finish_discovery(0)
            .map_err(|_| GeneralInitialLoaderStateError::GraphIncomplete)
    }

    /// Returns graph facts for a still-private transaction.
    pub(crate) fn graph_during_transaction(
        &self,
    ) -> Result<&InitialGraphState, GeneralInitialLoaderStateError> {
        if self.phase == GeneralInitialLoaderPhase::Vacant {
            return Err(GeneralInitialLoaderStateError::InvalidPhase);
        }
        Ok(&self.graph)
    }

    /// Returns object metadata for relocation/protection/preflight while the
    /// transaction is private. It intentionally has no mutable counterpart
    /// outside [`discovery_mut`].
    pub(crate) fn objects_during_transaction(
        &self,
    ) -> Result<&[Object; MAX_OBJECTS], GeneralInitialLoaderStateError> {
        if self.phase == GeneralInitialLoaderPhase::Vacant {
            return Err(GeneralInitialLoaderStateError::InvalidPhase);
        }
        Ok(&self.objects)
    }

    /// Records that the object store contains generation-one TLS attachment.
    ///
    /// The IDs and offsets themselves are written through [`discovery_mut`]
    /// while the graph is still private. This marker lets a later private
    /// facade distinguish a TLS-free ready graph without inventing a second
    /// graph store.
    pub(crate) fn attach_initial_tls(
        &mut self,
    ) -> Result<(), GeneralInitialLoaderStateError> {
        if self.phase != GeneralInitialLoaderPhase::Discovering {
            return Err(GeneralInitialLoaderStateError::InvalidPhase);
        }
        self.initial_tls_attached = true;
        Ok(())
    }

    /// Seals graph/object mutation after all pre-publication work succeeds.
    pub(crate) fn prepare(&mut self) -> Result<(), GeneralInitialLoaderStateError> {
        if self.phase != GeneralInitialLoaderPhase::Discovering {
            return Err(GeneralInitialLoaderStateError::InvalidPhase);
        }
        if self.graph.object_count() == 0
            || (0..self.graph.object_count())
                .any(|index| self.graph.state(index) != Some(ObjectState::Ready))
        {
            return Err(GeneralInitialLoaderStateError::GraphIncomplete);
        }
        self.phase = GeneralInitialLoaderPhase::Prepared;
        Ok(())
    }

    /// Exclusively reserves the process-lifetime store before an x86 TLS
    /// installer can change `%fs`.
    pub(crate) fn reserve_publication(
        &mut self,
    ) -> Result<(), GeneralInitialLoaderStateError> {
        if self.phase != GeneralInitialLoaderPhase::Prepared {
            return Err(GeneralInitialLoaderStateError::InvalidPhase);
        }
        GENERAL_INITIAL_LOADER_PUBLICATION
            .compare_exchange(
                GENERAL_INITIAL_LOADER_VACANT,
                GENERAL_INITIAL_LOADER_RESERVED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|_| GeneralInitialLoaderStateError::PublicationUnavailable)?;
        self.phase = GeneralInitialLoaderPhase::Reserved;
        Ok(())
    }

    /// Applies the shared reverse-order rollback for a named failed stage.
    pub(crate) fn abort(
        &mut self,
        _stage: GeneralInitialPreparationStage,
        unmap: impl FnMut(&Object),
    ) {
        self.rollback(unmap);
    }

    /// Rolls back only transaction-created mappings before publication.
    ///
    /// `Ready` has no rollback path. The caller owns the physical `munmap`
    /// operation and receives only the retained transaction-created object
    /// records in exact reverse map/admission order; slot zero is excluded.
    pub(crate) fn rollback(&mut self, mut unmap: impl FnMut(&Object)) {
        if self.phase == GeneralInitialLoaderPhase::Ready
            || self.phase == GeneralInitialLoaderPhase::Vacant
        {
            return;
        }
        if self.phase == GeneralInitialLoaderPhase::Reserved {
            GENERAL_INITIAL_LOADER_PUBLICATION
                .store(GENERAL_INITIAL_LOADER_VACANT, Ordering::Release);
        }
        let (graph, objects) = (&mut self.graph, &mut self.objects);
        graph.rollback_to_main(|index| unmap(&objects[index]));
        for object in objects.iter_mut().skip(1) {
            *object = EMPTY_OBJECT;
        }
        self.initial_tls_attached = false;
        self.phase = GeneralInitialLoaderPhase::Vacant;
    }

    /// Writes and release-publishes the immutable process-lifetime owner.
    ///
    /// # Safety
    ///
    /// The caller must own the one initial transaction, have completed all
    /// fallible preparation, and have successfully called
    /// [`reserve_publication`]. For the TLS route this is called only after
    /// the sole successful `ARCH_SET_FS`, so no code may add a fallible
    /// successor before this publication.
    pub(crate) unsafe fn commit(mut self) {
        debug_assert_eq!(self.phase, GeneralInitialLoaderPhase::Reserved);
        self.phase = GeneralInitialLoaderPhase::Ready;
        // SAFETY: `Reserved` is an exclusive CAS-held startup slot. The
        // complete value is written before its release publication below.
        unsafe {
            core::ptr::write(
                core::ptr::addr_of_mut!(GENERAL_INITIAL_LOADER_STATE)
                    .cast::<GeneralInitialLoaderState>(),
                self,
            );
        }
        GENERAL_INITIAL_LOADER_PUBLICATION.store(GENERAL_INITIAL_LOADER_READY, Ordering::Release);
    }

    /// Returns an acquire-published immutable state, never transaction data.
    pub(crate) fn retained() -> Option<&'static GeneralInitialLoaderState> {
        if GENERAL_INITIAL_LOADER_PUBLICATION.load(Ordering::Acquire)
            != GENERAL_INITIAL_LOADER_READY
        {
            return None;
        }
        // SAFETY: `READY` is release-stored only after the complete static
        // value above. The state has no mutation path after that store.
        unsafe {
            Some(
                &*core::ptr::addr_of!(GENERAL_INITIAL_LOADER_STATE)
                    .cast::<GeneralInitialLoaderState>(),
            )
        }
    }

    /// Reads graph metadata only after this owner reached `Ready`.
    pub(crate) fn ready_graph(&self) -> Option<&InitialGraphState> {
        (self.phase == GeneralInitialLoaderPhase::Ready).then_some(&self.graph)
    }

    /// Reads complete object/provenance metadata only after `Ready`.
    pub(crate) fn ready_objects(&self) -> Option<&[Object; MAX_OBJECTS]> {
        (self.phase == GeneralInitialLoaderPhase::Ready).then_some(&self.objects)
    }

    pub(crate) const fn has_initial_tls_attachment(&self) -> bool {
        self.initial_tls_attached
    }

    #[cfg(test)]
    pub(crate) fn test_publication_guard() -> GeneralInitialLoaderTestPublicationGuard {
        while GENERAL_INITIAL_LOADER_TEST_LOCK
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        GeneralInitialLoaderTestPublicationGuard
    }

    #[cfg(test)]
    unsafe fn reset_publication_for_test() {
        // SAFETY: the test guard excludes all readers/reservers. The stored
        // types have no drop ownership; this only restores the empty process
        // image model for the next isolated unit test.
        unsafe {
            core::ptr::write(
                core::ptr::addr_of_mut!(GENERAL_INITIAL_LOADER_STATE),
                MaybeUninit::uninit(),
            );
        }
        GENERAL_INITIAL_LOADER_PUBLICATION.store(GENERAL_INITIAL_LOADER_VACANT, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::x86_64_initial_graph_state::{GraphStateError, ObjectAdmission};

    const MAIN: ObjectIdentity = ObjectIdentity { device: 1, inode: 1 };
    const LEFT: ObjectIdentity = ObjectIdentity { device: 1, inode: 2 };
    const RIGHT: ObjectIdentity = ObjectIdentity { device: 1, inode: 3 };
    const SHARED: ObjectIdentity = ObjectIdentity { device: 1, inode: 4 };

    fn transaction_object(span_start: u64, span_len: u64) -> Object {
        Object {
            mapped: true,
            map_provenance: ObjectMapProvenance::Transaction,
            map_span_start: span_start,
            map_span_byte_len: span_len,
            ..EMPTY_OBJECT
        }
    }

    fn diamond_state() -> (GeneralInitialLoaderState, usize, usize, usize) {
        let mut state = GeneralInitialLoaderState::new(MAIN, EMPTY_OBJECT);
        let (left, right, shared) = {
            let (graph, objects) = state.discovery_mut().unwrap();
            let left = match graph.admit_mapped(LEFT).unwrap() {
                ObjectAdmission::New { index } => index,
                other => panic!("unexpected admission: {other:?}"),
            };
            objects[left] = transaction_object(0x1000, 0x2000);
            graph.attach_needed(0, left).unwrap();

            let shared = match graph.admit_mapped(SHARED).unwrap() {
                ObjectAdmission::New { index } => index,
                other => panic!("unexpected admission: {other:?}"),
            };
            objects[shared] = transaction_object(0x3000, 0x2000);
            graph.attach_needed(left, shared).unwrap();
            graph.finish_discovery(shared).unwrap();
            graph.finish_discovery(left).unwrap();

            let right = match graph.admit_mapped(RIGHT).unwrap() {
                ObjectAdmission::New { index } => index,
                other => panic!("unexpected admission: {other:?}"),
            };
            objects[right] = transaction_object(0x5000, 0x2000);
            graph.attach_needed(0, right).unwrap();
            assert_eq!(
                graph.admit_mapped(SHARED).unwrap(),
                ObjectAdmission::Existing {
                    index: shared,
                    state: ObjectState::Ready,
                }
            );
            graph.attach_needed(right, shared).unwrap();
            graph.finish_discovery(right).unwrap();
            (left, right, shared)
        };
        state.finish_discovery().unwrap();
        (state, left, right, shared)
    }

    #[test]
    fn persistent_diamond_retains_one_identity_edges_and_map_provenance() {
        let (mut state, left, right, shared) = diamond_state();
        let graph = state.graph_during_transaction().unwrap();
        let objects = state.objects_during_transaction().unwrap();

        assert_eq!(graph.object_count(), 4);
        assert_eq!(graph.edges(0), Some(&[left, right][..]));
        assert_eq!(graph.edges(left), Some(&[shared][..]));
        assert_eq!(graph.edges(right), Some(&[shared][..]));
        assert_eq!(graph.identity(shared), Some(SHARED));
        assert_eq!(objects[0].map_provenance, ObjectMapProvenance::KernelMain);
        assert_eq!(objects[shared].map_provenance, ObjectMapProvenance::Transaction);
        assert_eq!(objects[shared].map_span_start, 0x3000);
        assert_eq!(objects[shared].map_span_byte_len, 0x2000);

        state.prepare().unwrap();
        state.rollback(|_| {});
    }

    #[test]
    fn cycle_is_retained_for_identity_but_rejected_by_initializer_preflight() {
        let mut state = GeneralInitialLoaderState::new(MAIN, EMPTY_OBJECT);
        let (left, right) = {
            let (graph, objects) = state.discovery_mut().unwrap();
            let left = match graph.admit_mapped(LEFT).unwrap() {
                ObjectAdmission::New { index } => index,
                other => panic!("unexpected admission: {other:?}"),
            };
            let right = match graph.admit_mapped(RIGHT).unwrap() {
                ObjectAdmission::New { index } => index,
                other => panic!("unexpected admission: {other:?}"),
            };
            objects[left] = transaction_object(0x1000, 0x1000);
            objects[right] = transaction_object(0x2000, 0x1000);
            graph.attach_needed(0, left).unwrap();
            graph.attach_needed(left, right).unwrap();
            graph.attach_needed(right, left).unwrap();
            graph.finish_discovery(right).unwrap();
            graph.finish_discovery(left).unwrap();
            (left, right)
        };
        state.finish_discovery().unwrap();
        assert_eq!(
            state
                .graph_during_transaction()
                .unwrap()
                .dependency_first_plan(),
            Err(GraphStateError::DependencyCycle)
        );
        let mut unmapped = [usize::MAX; 2];
        let mut count = 0;
        state.abort(GeneralInitialPreparationStage::InitializerPreflight, |object| {
            unmapped[count] = object.map_span_start as usize;
            count += 1;
        });
        assert_eq!(unmapped, [0x2000, 0x1000]);
        assert_eq!(state.phase(), GeneralInitialLoaderPhase::Vacant);
        assert_eq!(left, 1);
        assert_eq!(right, 2);
    }

    #[test]
    fn every_prepublication_failure_rolls_back_only_new_maps_in_reverse_order() {
        let stages = [
            GeneralInitialPreparationStage::Discovery,
            GeneralInitialPreparationStage::Relocation,
            GeneralInitialPreparationStage::Protection,
            GeneralInitialPreparationStage::Relro,
            GeneralInitialPreparationStage::InitializerPreflight,
        ];
        for stage in stages {
            let (mut state, _, _, _) = diamond_state();
            let mut spans = [usize::MAX; 3];
            let mut count = 0;
            state.abort(stage, |object| {
                spans[count] = object.map_span_start as usize;
                count += 1;
            });
            assert_eq!(spans, [0x5000, 0x3000, 0x1000], "stage: {stage:?}");
            assert_eq!(count, 3, "stage: {stage:?}");
            assert_eq!(state.phase(), GeneralInitialLoaderPhase::Vacant);
            assert_eq!(state.object_count(), 1, "stage: {stage:?}");
            assert!(
                matches!(
                    state.objects_during_transaction(),
                    Err(GeneralInitialLoaderStateError::InvalidPhase)
                ),
                "stage: {stage:?}"
            );
        }
    }

    #[test]
    fn main_image_is_never_rollback_eligible() {
        let (mut state, _, _, _) = diamond_state();
        let mut saw_kernel_main = false;
        state.rollback(|object| {
            saw_kernel_main |= object.map_provenance == ObjectMapProvenance::KernelMain;
        });
        assert!(!saw_kernel_main);
    }

    #[test]
    fn state_is_unreadable_before_release_and_immutable_after_ready() {
        let _publication_guard = GeneralInitialLoaderState::test_publication_guard();
        let (mut state, _, _, _) = diamond_state();
        assert_eq!(state.phase(), GeneralInitialLoaderPhase::Discovering);
        assert!(state.ready_graph().is_none());
        assert!(state.ready_objects().is_none());
        assert!(GeneralInitialLoaderState::retained().is_none());
        state.prepare().unwrap();
        assert_eq!(state.phase(), GeneralInitialLoaderPhase::Prepared);
        assert!(matches!(
            state.discovery_mut(),
            Err(GeneralInitialLoaderStateError::InvalidPhase)
        ));
        state.reserve_publication().unwrap();
        assert_eq!(state.phase(), GeneralInitialLoaderPhase::Reserved);
        // SAFETY: this test owns the serialized Reserved slot and has no TLS
        // installation boundary to cross.
        unsafe { state.commit() };
        {
            let ready = GeneralInitialLoaderState::retained().unwrap();
            assert_eq!(ready.phase(), GeneralInitialLoaderPhase::Ready);
            assert!(ready.ready_graph().is_some());
            assert!(ready.ready_objects().is_some());
        }
        let (mut replacement, _, _, _) = diamond_state();
        replacement.prepare().unwrap();
        assert!(matches!(
            replacement.reserve_publication(),
            Err(GeneralInitialLoaderStateError::PublicationUnavailable)
        ));
        // SAFETY: the acquired reference above has ended and the test guard
        // excludes all other users of the process-unique publication slot.
        unsafe { GeneralInitialLoaderState::reset_publication_for_test() };
    }
}
