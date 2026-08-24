// SPDX-License-Identifier: MIT
//
// Feature-gated, allocation-backed private process context for the future
// prefixed C adapter.
//
// This is deliberately not an allocator backend or process singleton.  Each
// context owns one stable bootstrap, page map, arena registry, and external
// arena mapping.  `SingleThreadAllocator` borrows those components through
// an audited `'static` extension: the pointees are separately heap allocated,
// the mapping address is stable, and shutdown drops the allocator before it
// destroys either mapping.  The enclosing context can consequently move
// without becoming self-referential.

use core::marker::PhantomData;
use core::pin::Pin;
use core::ptr::{self, NonNull};

use crate::arena::{manage_external_in_place, ArenaId, ArenaRegistry, ArenaView};
use crate::bootstrap::DefaultSingleThreadBootstrap;
use crate::config::{ARENA_ALIGNMENT, ARENA_MIN_SIZE};
use crate::os::{MapAccess, Mapping, MemoryConfig, PageSize, StartupInput};
use crate::page_map::{PageMap, PageMapRoot};
use crate::rust_alloc::boxed::Box;
use crate::single_thread::{FreeError, SingleThreadAllocator};
use crate::types::{LiveThreadId, PAGE_FLAG_BITS};

/// Construction failed before a private test-adapter context became usable.
///
/// This deliberately does not expose libc `errno`: callers need only know
/// which owned setup boundary failed. Every partially acquired VM object is
/// driven through its explicit release operation; no `Drop` path changes VM
/// state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TestContextInitError {
    /// Linux did not provide `AT_PAGESZ` to this process.
    PageSizeUnavailable,
    /// The process supplied a base page size outside the Linux/AArch64 set.
    InvalidPageSize,
    /// Initializing the owned source page map failed.
    PageMapInitialization,
    /// Mapping the aligned external arena failed.
    ArenaMapping,
    /// In-place external-arena management failed.
    ArenaManagement,
    /// The registered arena could not form a live arena view.
    ArenaView,
    /// The running Linux thread ID could not form a source-shaped identity.
    ThreadIdentity,
    /// Pinning and activating the default single-thread bootstrap failed.
    Bootstrap,
}

/// One allocation request could not be completed by an active context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TestContextAllocationError {
    /// Shutdown has started or completed, so no new allocation is admitted.
    Closing,
    /// The requested size, alignment, or backing allocation was unavailable.
    AllocationFailed,
}

/// Pointer inspection or reallocation could not be completed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TestContextPointerError {
    /// Shutdown has started or completed, so pointer operations are closed.
    Closing,
    /// The pointer was not a current allocation from this exact context.
    InvalidPointer,
    /// A replacement allocation could not be made and the old block remains live.
    AllocationFailed,
}

/// Returning one allocation to this context failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TestContextFreeError {
    /// Shutdown has started or completed, so frees are no longer admitted.
    Closing,
    /// The pointer was not a current allocation from this exact context.
    InvalidPointer,
    /// A source queue, page-map, or arena ownership transition could not be
    /// preserved. The caller must not treat this as an invalid-pointer result.
    Lifecycle,
}

/// A context shutdown did not complete and may be retried when documented.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TestContextShutdownError {
    /// Live blocks remain.  The context stays active and accepts their frees.
    OutstandingAllocations(usize),
    /// Forced retirement did not finish.  No new operations are accepted, but
    /// this exact shutdown operation may be retried.
    CollectionFailed,
    /// Explicit page-map destruction failed and retains its exact mapping for
    /// a subsequent shutdown call.
    PageMapDestroyFailed,
    /// Explicit external-arena unmapping failed and retains its exact mapping
    /// for a subsequent shutdown call.
    ArenaUnmapFailed,
    /// Every owned object has already been released.
    AlreadyShutdown,
}

/// The private context's explicit, retryable terminal ownership states.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ShutdownStage {
    Active,
    Collect,
    ClearRoot,
    DropAllocator,
    DestroyPageMap,
    UnmapArena,
    Complete,
}

/// One feature-gated, single-thread process context for the standalone
/// prefixed test adapter.
///
/// The context owns no global state, TLS slot, remote-free path, public malloc
/// symbol, or errno.  It is intentionally bounded to operations accepted by
/// [`SingleThreadAllocator`], including OS-aligned singleton blocks below the
/// metadata-alignment limit.  It must stay on its creating thread and must be
/// shut down explicitly after every returned allocation is freed.
pub struct TestAllocatorContext {
    // This must be dropped before any stable pointee below.  Its borrows are
    // extended only after all four owners have their final addresses.
    allocator: Option<SingleThreadAllocator<'static, 'static, 'static>>,
    _bootstrap: Pin<Box<DefaultSingleThreadBootstrap>>,
    page_map: Option<Box<PageMap>>,
    // The registry stores raw addresses inside `arena_mapping`; its leading
    // underscore marks this intentionally lifetime-only ownership edge.
    _registry: Box<ArenaRegistry>,
    arena_mapping: Option<Mapping>,
    root: PageMapRoot,
    outstanding: usize,
    stage: ShutdownStage,
    // The context derives one `mi_threadid_t`-shaped identity from the creating
    // thread and carries no remote-free/TLS synchronization protocol. Keep the
    // public feature surface structurally !Send and !Sync even if a future
    // private owner changes one of the fields above.
    _creating_thread_only: PhantomData<*mut ()>,
    #[cfg(test)]
    fail_shutdown_once_at: Option<ShutdownStage>,
}

impl TestAllocatorContext {
    /// Creates one isolated context over a committed, `ARENA_ALIGNMENT`-
    /// aligned `ARENA_MIN_SIZE` external arena.
    ///
    /// The process page size comes directly from Linux `AT_PAGESZ`; no libc
    /// startup state, TLS, or global allocator lifecycle is used.  Publication
    /// of `PageMapRoot` occurs last, after the bootstrap and allocator are
    /// already live.
    pub fn new() -> Result<Self, TestContextInitError> {
        Self::new_with_thread_source(live_thread_id)
    }

    /// Returns the exact number of currently live blocks delegated by this
    /// context.  A successful reallocation preserves this count.
    #[inline]
    pub fn outstanding_allocations(&self) -> usize {
        self.outstanding
    }

    /// Reports whether ordinary allocation and free operations remain open.
    #[inline]
    pub fn is_active(&self) -> bool {
        self.stage == ShutdownStage::Active
    }

    /// Allocates one ordinary block without clearing its source block size.
    #[inline]
    pub fn alloc(
        &mut self,
        request: usize,
    ) -> Result<NonNull<u8>, TestContextAllocationError> {
        self.allocate_with(|allocator| allocator.allocate(request, false))
    }

    /// Allocates one ordinary block and clears its full source block size.
    #[inline]
    pub fn alloc_zeroed(
        &mut self,
        request: usize,
    ) -> Result<NonNull<u8>, TestContextAllocationError> {
        self.allocate_with(|allocator| allocator.allocate_zeroed(request))
    }

    /// Performs checked `count * size` zero allocation.
    ///
    /// An overflowing product returns [`TestContextAllocationError::AllocationFailed`]
    /// before any allocation state changes.
    #[inline]
    pub fn calloc(
        &mut self,
        count: usize,
        size: usize,
    ) -> Result<NonNull<u8>, TestContextAllocationError> {
        self.allocate_with(|allocator| allocator.allocate_zeroed_count(count, size))
    }

    /// Allocates an aligned block with zero offset.
    ///
    /// Valid alignment is the private engine's power-of-two range through but
    /// excluding its 256-MiB metadata alignment boundary.
    #[inline]
    pub fn alloc_aligned(
        &mut self,
        request: usize,
        alignment: usize,
    ) -> Result<NonNull<u8>, TestContextAllocationError> {
        self.allocate_with(|allocator| allocator.allocate_aligned(request, alignment))
    }

    /// Allocates a block for which `pointer + offset` is aligned.
    ///
    /// Offset alignment is available only through the arena-bounded alignment
    /// path; OS-aligned singleton blocks require offset zero.
    #[inline]
    pub fn alloc_aligned_at(
        &mut self,
        request: usize,
        alignment: usize,
        offset: usize,
    ) -> Result<NonNull<u8>, TestContextAllocationError> {
        self.allocate_with(|allocator| {
            allocator.allocate_aligned_at(request, alignment, offset)
        })
    }

    /// Allocates one zero-filled aligned block with zero offset.
    #[inline]
    pub fn alloc_aligned_zeroed(
        &mut self,
        request: usize,
        alignment: usize,
    ) -> Result<NonNull<u8>, TestContextAllocationError> {
        self.allocate_with(|allocator| allocator.allocate_aligned_zeroed(request, alignment))
    }

    /// Allocates one zero-filled block for which `pointer + offset` is aligned.
    #[inline]
    pub fn alloc_aligned_zeroed_at(
        &mut self,
        request: usize,
        alignment: usize,
        offset: usize,
    ) -> Result<NonNull<u8>, TestContextAllocationError> {
        self.allocate_with(|allocator| {
            allocator.allocate_aligned_zeroed_at(request, alignment, offset)
        })
    }

    /// Performs checked counted zero allocation with zero-offset alignment.
    #[inline]
    pub fn calloc_aligned(
        &mut self,
        count: usize,
        size: usize,
        alignment: usize,
    ) -> Result<NonNull<u8>, TestContextAllocationError> {
        self.allocate_with(|allocator| {
            allocator.allocate_aligned_zeroed_count(count, size, alignment)
        })
    }

    /// Performs checked counted zero allocation for `pointer + offset`.
    #[inline]
    pub fn calloc_aligned_at(
        &mut self,
        count: usize,
        size: usize,
        alignment: usize,
        offset: usize,
    ) -> Result<NonNull<u8>, TestContextAllocationError> {
        self.allocate_with(|allocator| {
            allocator.allocate_aligned_zeroed_count_at(count, size, alignment, offset)
        })
    }

    /// Reallocates an ordinary context allocation.
    ///
    /// # Safety
    ///
    /// When present, `block` must be exactly one still-live allocation returned
    /// by this context, not be aliased for access during the call, and not have
    /// been passed to any other allocator.  `None` is the null allocation case.
    /// On failure, a present old block remains live and unchanged.
    pub unsafe fn realloc(
        &mut self,
        block: Option<NonNull<u8>>,
        new_size: usize,
    ) -> Result<NonNull<u8>, TestContextPointerError> {
        // SAFETY: this method repeats the inner allocator's current-block
        // contract in its public safety documentation.
        unsafe { self.reallocate_with(block, |allocator, block| allocator.reallocate(block, new_size)) }
    }

    /// Reallocates an ordinary context allocation and clears replacement bytes
    /// according to the source `rezalloc` extent.
    ///
    /// # Safety
    ///
    /// `block` has the same current-allocation and exclusive-access obligations
    /// as [`Self::realloc`].  A failed replacement preserves the old block.
    pub unsafe fn realloc_zeroed(
        &mut self,
        block: Option<NonNull<u8>>,
        new_size: usize,
    ) -> Result<NonNull<u8>, TestContextPointerError> {
        // SAFETY: this method repeats the inner allocator's current-block
        // contract in its public safety documentation.
        unsafe {
            self.reallocate_with(block, |allocator, block| {
                allocator.reallocate_zeroed(block, new_size)
            })
        }
    }

    /// Reallocates a zero-offset aligned context allocation.
    ///
    /// # Safety
    ///
    /// `block`, when present, must be exactly one live allocation from this
    /// context with the stated alignment and no aliased access during the call.
    /// `None` is the null allocation case; failure preserves a present block.
    pub unsafe fn realloc_aligned(
        &mut self,
        block: Option<NonNull<u8>>,
        new_size: usize,
        alignment: usize,
    ) -> Result<NonNull<u8>, TestContextPointerError> {
        // SAFETY: this method repeats the inner allocator's current-block
        // contract in its public safety documentation.
        unsafe {
            self.reallocate_with(block, |allocator, block| {
                allocator.reallocate_aligned(block, new_size, alignment)
            })
        }
    }

    /// Reallocates an offset-aligned context allocation.
    ///
    /// # Safety
    ///
    /// `block`, when present, must be exactly one live allocation from this
    /// context satisfying `pointer + offset` for the stated alignment.  It may
    /// not be aliased, freed, or passed to another allocator during this call.
    /// `None` is the null allocation case; failure preserves a present block.
    pub unsafe fn realloc_aligned_at(
        &mut self,
        block: Option<NonNull<u8>>,
        new_size: usize,
        alignment: usize,
        offset: usize,
    ) -> Result<NonNull<u8>, TestContextPointerError> {
        // SAFETY: this method repeats the inner allocator's current-block
        // contract in its public safety documentation.
        unsafe {
            self.reallocate_with(block, |allocator, block| {
                allocator.reallocate_aligned_at(block, new_size, alignment, offset)
            })
        }
    }

    /// Reallocates and zeroes a zero-offset aligned context allocation.
    ///
    /// # Safety
    ///
    /// `block`, when present, must be exactly one live allocation from this
    /// context with the stated alignment and no aliased access during the call.
    /// `None` is the null allocation case; failure preserves a present block.
    pub unsafe fn realloc_aligned_zeroed(
        &mut self,
        block: Option<NonNull<u8>>,
        new_size: usize,
        alignment: usize,
    ) -> Result<NonNull<u8>, TestContextPointerError> {
        // SAFETY: this method repeats the inner allocator's current-block
        // contract in its public safety documentation.
        unsafe {
            self.reallocate_with(block, |allocator, block| {
                allocator.reallocate_aligned_zeroed(block, new_size, alignment)
            })
        }
    }

    /// Reallocates and zeroes an offset-aligned context allocation.
    ///
    /// # Safety
    ///
    /// `block`, when present, must be exactly one live allocation from this
    /// context satisfying `pointer + offset` for the stated alignment.  It may
    /// not be aliased, freed, or passed to another allocator during this call.
    /// `None` is the null allocation case; failure preserves a present block.
    pub unsafe fn realloc_aligned_zeroed_at(
        &mut self,
        block: Option<NonNull<u8>>,
        new_size: usize,
        alignment: usize,
        offset: usize,
    ) -> Result<NonNull<u8>, TestContextPointerError> {
        // SAFETY: this method repeats the inner allocator's current-block
        // contract in its public safety documentation.
        unsafe {
            self.reallocate_with(block, |allocator, block| {
                allocator.reallocate_aligned_zeroed_at(block, new_size, alignment, offset)
            })
        }
    }

    /// Returns the source usable size for one live allocation.
    ///
    /// # Safety
    ///
    /// `block` must be exactly one current allocation returned by this context
    /// and must not have been freed, moved by reallocation, or passed to any
    /// other allocator.  This does not validate arbitrary pointers.
    pub unsafe fn usable_size(
        &self,
        block: NonNull<u8>,
    ) -> Result<usize, TestContextPointerError> {
        let allocator = self.allocator_if_active()?;
        // SAFETY: this method repeats the inner allocator's live-block
        // inspection obligations in its public safety documentation.
        unsafe { allocator.usable_size(block) }.ok_or(TestContextPointerError::InvalidPointer)
    }

    /// Returns one live allocation to this exact context.
    ///
    /// # Safety
    ///
    /// `block` must be exactly one still-live allocation returned by this
    /// context, may be passed exactly once, must not be aliased for later
    /// access, and must never be supplied to another allocator.
    pub unsafe fn free(&mut self, block: NonNull<u8>) -> Result<(), TestContextFreeError> {
        if self.stage != ShutdownStage::Active {
            return Err(TestContextFreeError::Closing);
        }
        if self.outstanding == 0 {
            return Err(TestContextFreeError::InvalidPointer);
        }
        let allocator = self.allocator_mut_if_active().map_err(|_| TestContextFreeError::Closing)?;
        // SAFETY: this method repeats the inner allocator's exact-current-block
        // ownership contract in its public safety documentation.
        unsafe { allocator.free(block) }.map_err(map_free_error)?;
        // The precondition above and the successful current-allocation free
        // preserve the context's exact allocation-count invariant.
        self.outstanding -= 1;
        Ok(())
    }

    /// Performs the explicit terminal lifecycle after all delegated blocks
    /// have been returned.
    ///
    /// If blocks remain, this returns their exact count and leaves the context
    /// active so they can still be freed.  Once teardown starts, no operation
    /// is admitted.  A collection, page-map-destroy, or arena-unmap failure
    /// retains the remaining owner and this method may be called again.
    pub fn shutdown(&mut self) -> Result<(), TestContextShutdownError> {
        loop {
            match self.stage {
                ShutdownStage::Active => {
                    if self.outstanding != 0 {
                        return Err(TestContextShutdownError::OutstandingAllocations(self.outstanding));
                    }
                    self.stage = ShutdownStage::Collect;
                }
                ShutdownStage::Collect => {
                    if self.test_fail_shutdown_once(ShutdownStage::Collect) {
                        return Err(TestContextShutdownError::CollectionFailed);
                    }
                    let allocator = self
                        .allocator
                        .as_mut()
                        .ok_or(TestContextShutdownError::CollectionFailed)?;
                    if !allocator.collect_retired(true) {
                        return Err(TestContextShutdownError::CollectionFailed);
                    }
                    self.stage = ShutdownStage::ClearRoot;
                }
                ShutdownStage::ClearRoot => {
                    // Root publication is deliberately cleared before the
                    // allocator borrow, page-map mapping, or arena bytes end.
                    let _ = self.root.clear();
                    self.stage = ShutdownStage::DropAllocator;
                }
                ShutdownStage::DropAllocator => {
                    drop(self.allocator.take());
                    self.stage = ShutdownStage::DestroyPageMap;
                }
                ShutdownStage::DestroyPageMap => {
                    if self.test_fail_shutdown_once(ShutdownStage::DestroyPageMap) {
                        return Err(TestContextShutdownError::PageMapDestroyFailed);
                    }
                    let page_map = self
                        .page_map
                        .as_mut()
                        .ok_or(TestContextShutdownError::PageMapDestroyFailed)?;
                    // SAFETY: root is clear, allocator is gone, this context
                    // never published another reader, and `&mut self` owns the
                    // sole remaining page-map release right.
                    if unsafe { page_map.destroy() }.is_err() {
                        return Err(TestContextShutdownError::PageMapDestroyFailed);
                    }
                    drop(self.page_map.take());
                    self.stage = ShutdownStage::UnmapArena;
                }
                ShutdownStage::UnmapArena => {
                    if self.test_fail_shutdown_once(ShutdownStage::UnmapArena) {
                        return Err(TestContextShutdownError::ArenaUnmapFailed);
                    }
                    let mapping = self
                        .arena_mapping
                        .as_mut()
                        .ok_or(TestContextShutdownError::ArenaUnmapFailed)?;
                    if mapping.unmap().is_err() {
                        return Err(TestContextShutdownError::ArenaUnmapFailed);
                    }
                    drop(self.arena_mapping.take());
                    self.stage = ShutdownStage::Complete;
                    return Ok(());
                }
                ShutdownStage::Complete => return Err(TestContextShutdownError::AlreadyShutdown),
            }
        }
    }

    fn new_with_thread_source(
        thread_source: fn() -> Option<LiveThreadId>,
    ) -> Result<Self, TestContextInitError> {
        let raw_page_size = crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
            .ok_or(TestContextInitError::PageSizeUnavailable)?;
        let page_size = PageSize::new(raw_page_size).ok_or(TestContextInitError::InvalidPageSize)?;
        let config = MemoryConfig::detect(StartupInput::new(page_size));
        let mut page_map = Box::new(
            PageMap::initialize(config, 0, true)
                .map_err(|_| TestContextInitError::PageMapInitialization)?,
        );
        let mut arena_mapping = match Mapping::map_aligned_for_allocator(
            config,
            ARENA_MIN_SIZE,
            ARENA_ALIGNMENT,
            MapAccess::Committed,
        ) {
            Ok(mapping) => mapping,
            Err(_) => {
                // SAFETY: no root or allocator was published, so this newly
                // initialized page map has no readers and is ours to release.
                let _ = unsafe { page_map.destroy() };
                return Err(TestContextInitError::ArenaMapping);
            }
        };
        let registry = Box::new(ArenaRegistry::new(ptr::null_mut()));
        let arena_start = match arena_mapping.base() {
            Ok(start) => start,
            Err(_) => {
                Self::rollback_initialization(&mut page_map, Some(&mut arena_mapping));
                return Err(TestContextInitError::ArenaMapping);
            }
        };
        let arena_initially_committed = arena_mapping.initially_committed();
        let arena_initially_zero = arena_mapping.initially_zero();
        let managed = match unsafe {
            manage_external_in_place(
                &registry,
                arena_start,
                ARENA_MIN_SIZE,
                page_size,
                arena_initially_committed,
                // This is a normal anonymous mapping, not an OS-large-page
                // mapping. `mi_manage_os_memory_ex` receives `is_pinned`
                // from its caller, and the source's regular reserve path only
                // propagates a true value for the large-page provenance.
                false,
                arena_initially_zero,
                -1,
                false,
                None,
            )
        } {
            Ok(managed) => managed,
            Err(_) => {
                Self::rollback_initialization(&mut page_map, Some(&mut arena_mapping));
                return Err(TestContextInitError::ArenaManagement);
            }
        };
        let arena = match unsafe { ArenaView::from_ptr(managed.arena_id().as_ptr()) } {
            Some(arena) => arena,
            None => {
                Self::rollback_initialization(&mut page_map, Some(&mut arena_mapping));
                return Err(TestContextInitError::ArenaView);
            }
        };
        // Request the source-shaped Linux identity after both address-stable
        // owners and the in-place arena exist, immediately before activation.
        let thread_id = match thread_source() {
            Some(thread_id) => thread_id,
            None => {
                Self::rollback_initialization(&mut page_map, Some(&mut arena_mapping));
                return Err(TestContextInitError::ThreadIdentity);
            }
        };
        let mut bootstrap = Box::pin(DefaultSingleThreadBootstrap::new());
        let allocator = {
            let page_map_ptr: *mut PageMap = &mut *page_map;
            // SAFETY: `bootstrap` and `page_map` are distinct Boxes whose
            // pointee addresses remain stable while this context owns them;
            // `arena` borrows bytes in `arena_mapping`, which likewise remains
            // mapped. Shutdown clears the root, drops `allocator`, destroys
            // the page map, and only then unmaps arena storage. No safe context
            // operation can move any pointee behind these extended borrows.
            let bootstrap: Pin<&'static mut DefaultSingleThreadBootstrap> = unsafe {
                core::mem::transmute(bootstrap.as_mut())
            };
            // SAFETY: see the shared stable-owner proof immediately above.
            let page_map: &'static mut PageMap = unsafe { core::mem::transmute(&mut *page_map_ptr) };
            // SAFETY: see the shared stable-owner proof immediately above.
            let arena: ArenaView<'static> = unsafe { core::mem::transmute(arena) };
            match SingleThreadAllocator::activate(
                bootstrap,
                thread_id,
                arena,
                ArenaId::none(),
                page_map,
                0,
            ) {
                Ok(allocator) => allocator,
                Err(_) => {
                    // SAFETY: a failed `activate` returns no session and
                    // retains neither the page-map borrow nor any allocator
                    // owner. The raw pointer still denotes the same stable
                    // Box pointee, so this is the only pre-publication
                    // cleanup path after the lifetime extension above.
                    let _ = arena_mapping.unmap();
                    let _ = unsafe { (&mut *page_map_ptr).destroy() };
                    return Err(TestContextInitError::Bootstrap);
                }
            }
        };
        let root = PageMapRoot::empty();
        // SAFETY: `page_map` is fully initialized and the Box retains its
        // header until shutdown first clears this root.
        unsafe { root.publish(&page_map) };

        Ok(Self {
            allocator: Some(allocator),
            _bootstrap: bootstrap,
            page_map: Some(page_map),
            _registry: registry,
            arena_mapping: Some(arena_mapping),
            root,
            outstanding: 0,
            stage: ShutdownStage::Active,
            _creating_thread_only: PhantomData,
            #[cfg(test)]
            fail_shutdown_once_at: None,
        })
    }

    /// Attempts every explicit pre-publication release in strict reverse
    /// acquisition order.  There is no `Drop`-based VM transition here.
    fn rollback_initialization(page_map: &mut PageMap, arena_mapping: Option<&mut Mapping>) {
        if let Some(mapping) = arena_mapping {
            let _ = mapping.unmap();
        }
        // SAFETY: this helper is called only before root publication and before
        // an allocator escapes, so the page map has no reader or page entry.
        let _ = unsafe { page_map.destroy() };
    }

    fn allocate_with(
        &mut self,
        allocate: impl FnOnce(&mut SingleThreadAllocator<'static, 'static, 'static>) -> Option<NonNull<u8>>,
    ) -> Result<NonNull<u8>, TestContextAllocationError> {
        if self.stage != ShutdownStage::Active {
            return Err(TestContextAllocationError::Closing);
        }
        let next_outstanding = self
            .outstanding
            .checked_add(1)
            .ok_or(TestContextAllocationError::AllocationFailed)?;
        let allocator = self
            .allocator
            .as_mut()
            .ok_or(TestContextAllocationError::Closing)?;
        let block = allocate(allocator).ok_or(TestContextAllocationError::AllocationFailed)?;
        self.outstanding = next_outstanding;
        Ok(block)
    }

    unsafe fn reallocate_with(
        &mut self,
        block: Option<NonNull<u8>>,
        reallocate: impl FnOnce(
            &mut SingleThreadAllocator<'static, 'static, 'static>,
            Option<NonNull<u8>>,
        ) -> Option<NonNull<u8>>,
    ) -> Result<NonNull<u8>, TestContextPointerError> {
        if self.stage != ShutdownStage::Active {
            return Err(TestContextPointerError::Closing);
        }
        let creates_new_count = block.is_none();
        let next_outstanding = if creates_new_count {
            Some(
                self.outstanding
                    .checked_add(1)
                    .ok_or(TestContextPointerError::AllocationFailed)?,
            )
        } else {
            None
        };
        let allocator = self
            .allocator
            .as_mut()
            .ok_or(TestContextPointerError::Closing)?;
        let replacement = reallocate(allocator, block).ok_or(TestContextPointerError::AllocationFailed)?;
        if let Some(next_outstanding) = next_outstanding {
            self.outstanding = next_outstanding;
        }
        Ok(replacement)
    }

    fn allocator_if_active(
        &self,
    ) -> Result<&SingleThreadAllocator<'static, 'static, 'static>, TestContextPointerError> {
        if self.stage != ShutdownStage::Active {
            return Err(TestContextPointerError::Closing);
        }
        self.allocator.as_ref().ok_or(TestContextPointerError::Closing)
    }

    fn allocator_mut_if_active(
        &mut self,
    ) -> Result<&mut SingleThreadAllocator<'static, 'static, 'static>, TestContextPointerError> {
        if self.stage != ShutdownStage::Active {
            return Err(TestContextPointerError::Closing);
        }
        self.allocator.as_mut().ok_or(TestContextPointerError::Closing)
    }

    #[cfg(test)]
    fn fail_shutdown_once_at(&mut self, stage: ShutdownStage) {
        self.fail_shutdown_once_at = Some(stage);
    }

    #[cfg(test)]
    fn test_fail_shutdown_once(&mut self, stage: ShutdownStage) -> bool {
        if self.fail_shutdown_once_at == Some(stage) {
            self.fail_shutdown_once_at = None;
            true
        } else {
            false
        }
    }

    #[cfg(not(test))]
    #[inline]
    fn test_fail_shutdown_once(&mut self, _stage: ShutdownStage) -> bool {
        false
    }
}

fn live_thread_id() -> Option<LiveThreadId> {
    let thread_id = usize::try_from(crabc_core::thread::gettid()).ok()?;
    let flag_scale = 1usize << PAGE_FLAG_BITS;
    let raw = thread_id.checked_mul(flag_scale)?;
    LiveThreadId::new(raw)
}

fn map_free_error(error: FreeError) -> TestContextFreeError {
    match error {
        FreeError::Unmapped | FreeError::ForeignPage | FreeError::InvalidBlock(_) => {
            TestContextFreeError::InvalidPointer
        }
        FreeError::Lifecycle => TestContextFreeError::Lifecycle,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{KIB, MIB};

    #[test]
    fn context_initializes_delegates_and_shutdowns_once() {
        let mut context = TestAllocatorContext::new().unwrap();
        let allocation = context.alloc(37).unwrap();
        assert!(unsafe { context.usable_size(allocation) }.unwrap() >= 37);
        unsafe { context.free(allocation) }.unwrap();
        assert_eq!(context.outstanding_allocations(), 0);
        assert_eq!(context.shutdown(), Ok(()));
        assert_eq!(context.shutdown(), Err(TestContextShutdownError::AlreadyShutdown));
    }

    #[test]
    fn context_calloc_aligned_os_aligned_and_reallocation_preserve_contracts() {
        let mut context = TestAllocatorContext::new().unwrap();
        let zeroed = context.calloc(3, 17).unwrap();
        let zeroed_usable = unsafe { context.usable_size(zeroed) }.unwrap();
        for index in 0..zeroed_usable {
            assert_eq!(unsafe { zeroed.as_ptr().add(index).read() }, 0);
        }

        let offset = context.alloc_aligned_at(17, 64, 7).unwrap();
        assert_eq!(offset.as_ptr().addr().wrapping_add(7) & 63, 0);
        assert!(unsafe { context.usable_size(offset) }.unwrap() >= 17);
        let offset_zeroed = context.calloc_aligned_at(2, 19, 128, 3).unwrap();
        assert_eq!(offset_zeroed.as_ptr().addr().wrapping_add(3) & 127, 0);
        let offset_zeroed_usable = unsafe { context.usable_size(offset_zeroed) }.unwrap();
        for index in 0..offset_zeroed_usable {
            assert_eq!(unsafe { offset_zeroed.as_ptr().add(index).read() }, 0);
        }
        let os_aligned = context.alloc_aligned(7, 128 * KIB).unwrap();
        assert_eq!(os_aligned.as_ptr().addr() & (128 * KIB - 1), 0);
        assert!(context.alloc_aligned(7, 256 * MIB).is_err());

        unsafe { core::ptr::write_bytes(offset.as_ptr(), 0xa5, 17) };
        let offset = unsafe { context.realloc_aligned_at(Some(offset), 65, 64, 7) }.unwrap();
        assert_eq!(offset.as_ptr().addr().wrapping_add(7) & 63, 0);
        for index in 0..17 {
            assert_eq!(unsafe { offset.as_ptr().add(index).read() }, 0xa5);
        }

        unsafe { context.free(zeroed) }.unwrap();
        unsafe { context.free(offset) }.unwrap();
        unsafe { context.free(offset_zeroed) }.unwrap();
        unsafe { context.free(os_aligned) }.unwrap();
        assert_eq!(context.shutdown(), Ok(()));
    }

    #[test]
    fn context_calloc_overflow_and_rezalloc_expansion_leave_exact_state() {
        let mut context = TestAllocatorContext::new().unwrap();
        assert_eq!(
            context.calloc(usize::MAX, 2),
            Err(TestContextAllocationError::AllocationFailed),
        );
        assert_eq!(context.outstanding_allocations(), 0);

        let allocation = context.alloc(23).unwrap();
        let old_usable = unsafe { context.usable_size(allocation) }.unwrap();
        unsafe { core::ptr::write_bytes(allocation.as_ptr(), 0x5a, old_usable) };
        let replacement = unsafe {
            context.realloc_zeroed(Some(allocation), old_usable.checked_add(2048).unwrap())
        }
        .unwrap();
        let new_usable = unsafe { context.usable_size(replacement) }.unwrap();
        assert!(new_usable >= old_usable + 2048);
        for index in 0..old_usable {
            assert_eq!(unsafe { replacement.as_ptr().add(index).read() }, 0x5a);
        }
        for index in old_usable..new_usable {
            assert_eq!(unsafe { replacement.as_ptr().add(index).read() }, 0);
        }
        assert_eq!(context.outstanding_allocations(), 1);
        unsafe { context.free(replacement) }.unwrap();
        assert_eq!(context.shutdown(), Ok(()));
    }

    #[test]
    fn context_refuses_shutdown_with_live_allocations_but_keeps_free_available() {
        let mut context = TestAllocatorContext::new().unwrap();
        let allocation = context.alloc_zeroed(19).unwrap();
        assert_eq!(
            context.shutdown(),
            Err(TestContextShutdownError::OutstandingAllocations(1)),
        );
        unsafe { context.free(allocation) }.unwrap();
        assert_eq!(context.shutdown(), Ok(()));
    }

    #[test]
    fn context_rolls_back_post_mapping_initialization_failure() {
        fn no_live_thread_id() -> Option<LiveThreadId> {
            None
        }

        assert!(matches!(
            TestAllocatorContext::new_with_thread_source(no_live_thread_id),
            Err(TestContextInitError::ThreadIdentity),
        ));

        // The failed construction already explicitly destroyed the independent
        // page map and unmapped its arena. A fresh context must still initialize
        // and release normally without inheriting any published root or owner.
        let mut context = TestAllocatorContext::new().unwrap();
        assert_eq!(context.shutdown(), Ok(()));
    }

    #[test]
    fn context_retries_partial_shutdown_without_reopening_operations() {
        let mut context = TestAllocatorContext::new().unwrap();
        context.fail_shutdown_once_at(ShutdownStage::DestroyPageMap);
        assert_eq!(
            context.shutdown(),
            Err(TestContextShutdownError::PageMapDestroyFailed),
        );
        assert!(!context.is_active());
        assert_eq!(
            context.alloc(1),
            Err(TestContextAllocationError::Closing),
        );
        assert_eq!(context.shutdown(), Ok(()));
        assert_eq!(context.shutdown(), Err(TestContextShutdownError::AlreadyShutdown));
    }

    #[test]
    fn context_retries_arena_unmap_without_reopening_operations() {
        let mut context = TestAllocatorContext::new().unwrap();
        context.fail_shutdown_once_at(ShutdownStage::UnmapArena);
        assert_eq!(
            context.shutdown(),
            Err(TestContextShutdownError::ArenaUnmapFailed),
        );
        assert!(!context.is_active());
        assert_eq!(context.alloc(1), Err(TestContextAllocationError::Closing));
        assert_eq!(context.shutdown(), Ok(()));
        assert_eq!(context.shutdown(), Err(TestContextShutdownError::AlreadyShutdown));
    }
}
