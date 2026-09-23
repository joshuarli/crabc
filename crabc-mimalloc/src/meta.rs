// Copyright (c) 2018-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `src/subproc.c:19-81`
// (`_mi_meta_zalloc`, `_mi_meta_zalloc_aligned`, `_mi_meta_rezalloc`, the
// selected Malloc branch of `_mi_meta_free`) with bootstrap ordering from
// `src/init.c:15-145,184-208`, plus `src/arena.c:1433-1490` for selected
// regular-OS release and the separate typed `MI_MEM_ARENA` identity-gated
// release witness in `ArenaSliceClaim`, and `src/arena.c:674-723,1613-1673`
// for the typed non-main `mi_arena_pages_t` metadata image. The detached owner uses
// the already-portioned `src/arena.c`/`src/page-map.c`/`src/page.c` ordinary
// page lifecycle rather than a bespoke metadata allocator.

//! Process-lived detached metadata-theap ownership.
//!
//! Pinned mimalloc uses a statically allocated detached theap for allocator
//! control objects because normal thread initialization may itself require
//! metadata allocation. This bounded port preserves that shape: the control
//! fields and private lock are static, while the first ordinary pages come
//! from the existing direct Linux mapping, page-map, arena, and page-lifecycle
//! substrate. It does not use `alloc`, libc, public pthread APIs, compiler TLS,
//! or a separate slab/mmap-per-block algorithm.
//!
//! The metadata theap is not a thread cache. Every operation is serialized by
//! [`PrivateLock`], its source TLD identity stays `THREAD_ID_DETACHED`, and
//! its pages never enter abandonment or remote-free routing. The mapping,
//! page map, arena, bootstrap, and allocator all reside in final static slots
//! before the initialized state is Release-published; none is destroyed or
//! moved for the process lifetime.

#[cfg(test)]
extern crate std;

use core::cell::UnsafeCell;
use core::marker::{PhantomData, PhantomPinned};
use core::mem::{MaybeUninit, align_of, size_of};
use core::pin::Pin;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU8, AtomicUsize, Ordering};

use crabc_core::Errno;

use crate::arena::{
    ArenaId, ArenaPagesLayout, ArenaRegistry, ArenaView, manage_external_in_place,
};
use crate::bitmap::{BCHUNK_SIZE, BitmapLayout, BitmapView};
use crate::bootstrap::{BootstrapError, ExclusiveTheapBootstrap};
use crate::compiler_tls::DynamicThreadLocalBacking;
use crate::config::{ARENA_ALIGNMENT, ARENA_BIN_COUNT, ARENA_MIN_SIZE, MAX_VABITS};
use crate::lock::{PrivateLock, PrivateLockGuard};
use crate::os::{MapAccess, Mapping, MemoryConfig};
use crate::page_map::{PageMap, PageMapInitializationError};
use crate::single_thread::{FreeError, SingleThreadAllocator, ProcessMetadataPageAllocator, CanonicalProcessMetadataPageAllocator};
use crate::size_class;
use crate::types::{
    ArenaPages, Heap, LiveThreadId, MemoryId, MemoryKind, Page, Theap, ThreadLocalData,
    ThreadSequence,
};
use crate::subproc::MainSubprocess;

const COLD: u8 = 0;
/// The process-static detached metadata image names one immutable source
/// subprocess/configuration tuple but has not taken a first backing map.
const BOUND: u8 = 1;
/// The detached image has its bounded private backing and may service metadata
/// allocation/free operations.
const READY: u8 = 2;
const FAILED: u8 = 3;
// Both terminal states forbid new entries and safe capability projections.
// RETAINED preserves an engine whose exact unfinished ownership could not end.
const CLOSED: u8 = 4;
const CLOSE_RETAINED: u8 = 5;

const ALLOCATION_LIVE: u8 = 0;
const ALLOCATION_MOVING: u8 = 1;
const ALLOCATION_RELEASING: u8 = 2;
const ALLOCATION_RELEASED: u8 = 3;
const ALLOCATION_REJECTED: u8 = 4;

/// The source allocation route that formed a metadata capability.
///
/// Typed TLD initialization accepts only the direct `_mi_meta_zalloc` path:
/// its bytes are known to be a fresh zero image. A replacement may have been
/// source-copied and an aligned request follows a different source call, so
/// neither may masquerade as a fresh-zeroed `mi_tld_t` initialization image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MetaAllocationOrigin {
    DirectZeroed,
    AlignedZeroed,
    Replacement,
}

/// The one-way lifecycle of an aligned metadata allocation when, and only
/// when, it is projected as the allocator-owned regular TLS-key bitmap.
///
/// This state is deliberately independent from [`MetaAllocationOrigin`]. The
/// origin proves that the allocation started as an aligned zero image; this
/// state proves whether that particular image was initialized directly,
/// copied from an already-published prefix, or made observable as a bitmap.
/// Non-bitmap metadata never consults this field. Its own exact typed-role
/// marker prevents a TLS backing or dynamic arena image from later taking the
/// bitmap role merely because a future flexible layout has the same size.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BitmapImageState {
    Fresh,
    CopiedPrefix,
    Published,
}

/// One private metadata allocation error.
///
/// The engine has no `errno` policy. Callers receive a precise internal
/// outcome and must translate it at a later public boundary if one exists.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MetaError {
    /// The direct target thread pointer was zero or not a valid live source
    /// identity, so entering the process lock would not be recursion-safe.
    InvalidEntryThread,
    /// Permanent process teardown has sealed this metadata owner.
    Closed,
    /// This thread already owns the metadata lock; waiting would deadlock the
    /// source nonrecursive lock.
    RecursiveEntry,
    /// The private futex operation itself failed unexpectedly.
    Lock(Errno),
    /// The supplied immutable OS-memory observations differ from the values
    /// that bound this process-lived detached metadata image.
    ConfigurationMismatch,
    /// This metadata owner was initialized for a different bounded
    /// process-main identity. One owner may not silently serve two
    /// subprocesses in this slice.
    SubprocessMismatch,
    /// The source process has not yet published its detached `theap_meta`
    /// identity. Rust refuses the metadata route before it enters the private
    /// lock; this is a safety strengthening of the pinned C non-null
    /// assertion.
    TheapMetaUnpublished,
    /// The source process's one-way `theap_meta` identity did not name this
    /// allocator's exact detached static Theap. Rust refuses to take the
    /// metadata lock or create backing through an unselected image; this is a
    /// safety strengthening of the pinned C non-null assertion.
    TheapMetaMismatch,
    /// A prior initialization cleanup could not release a partially owned
    /// mapping, so retrying would overwrite live process state.
    InitializationRetained,
    /// Direct OS/page-map/arena bootstrap could not complete but left no
    /// published private metadata backing. The detached-Theap identity remains
    /// bound, and a later demand may retry that backing path.
    InitializationFailed,
    /// Backing has already been selected; a metadata owner cannot swap its
    /// process policy/PageMap or migrate outstanding legacy private pages.
    BackingAlreadySelected,
    /// The source allocation route returned null for this request.
    AllocationUnavailable,
    /// The source alignment contract rejected this request before it reached
    /// an allocation or page publication path.
    InvalidAlignment,
    /// The allocation capability belongs to a different detached metadata
    /// owner. The capability remains live and may be retried through its
    /// recorded owner.
    ForeignOwner,
    /// A consumed or stale metadata capability was used again.
    ReleasedOrStale,
    /// The already-validated detached local free could not preserve a source
    /// page lifecycle invariant. This is not a public invalid-free policy.
    Free(FreeError),
}

/// Failure while attaching or detaching a child subprocess's metadata Theap
/// through the parent's detached metadata TLD.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ChildMetadataTheapError {
    Metadata(MetaError),
    Theap(crate::types::TheapMainStaticInitError),
    TheapList(crate::types::ChildTheapDetachError),
}

/// Rejection from one typed allocator-owned ordinary-bitmap projection.
///
/// A dynamic bitmap stays owned by its [`MetaAllocation`] capability; this
/// boundary prevents a caller from falling back to raw ownership when image
/// size, alignment, provenance, or detached-owner identity is wrong.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MetaBitmapProjectionError {
    ForeignOwner,
    InvalidImage,
}

/// One non-Copy, provenance-bearing metadata allocation capability.
///
/// Moving this value transfers its one private release capability. It may be
/// freed on another thread through [`MetaAllocator::free`], but callers must
/// not dereference the raw bytes concurrently with that operation. The state
/// atomically rejects a second release or a release while rezalloc owns the
/// source replacement transition. Its lifetime and recorded process-owner
/// address prevent it being released through a different detached metadata
/// theap. A later TLD/theap lifecycle owner that needs to retain metadata
/// must store and move this exact capability with its owner; it must not
/// reconstruct ownership from an arbitrary raw pointer. Process-done
/// retention has a separate role-specific consume/recover boundary for TLD
/// and Theap images; its unsafe inverse requires an earlier explicit transfer
/// and exclusive source ownership, never just a matching pointer or memory ID.
#[must_use = "metadata allocation capabilities must be released through their owning MetaAllocator"]
pub(crate) struct MetaAllocation<'owner> {
    pointer: NonNull<u8>,
    memory: MemoryId,
    requested_size: usize,
    owner: NonNull<MetadataEngine<'owner>>,
    state: AtomicU8,
    origin: MetaAllocationOrigin,
    bitmap_image_state: BitmapImageState,
    // The first dynamic TLS backing projection permanently selects the
    // flexible `mi_thread_locals_t` role. Repeated TLS projections remain
    // valid through this same linear capability, but no other typed role may
    // reinterpret its bytes even if its request happens to coincide.
    dynamic_thread_local_backing_projected: bool,
    thread_local_data_initialized: bool,
    dynamic_theap_initialized: bool,
    child_subprocess_image_initialized: bool,
    dynamic_arena_pages_initialized: bool,
    _owner: PhantomData<Pin<&'owner MetadataEngine<'owner>>>,
}

// SAFETY: the capability is linear and all allocator mutation is serialized
// by `MetaAllocator::lock`. Moving it to another thread transfers, rather
// than aliases, the release right. Byte access remains the caller's separate
// raw-pointer synchronization obligation.
unsafe impl Send for MetaAllocation<'_> {}

impl<'owner> MetaAllocation<'owner> {
    #[inline]
    fn new(
        owner: Pin<&'owner MetadataEngine<'owner>>,
        pointer: NonNull<u8>,
        requested_size: usize,
        origin: MetaAllocationOrigin,
    ) -> Self {
        Self {
            pointer,
            memory: MemoryId::malloc(pointer.as_ptr(), requested_size, true),
            requested_size,
            owner: NonNull::from(owner.get_ref()),
            state: AtomicU8::new(ALLOCATION_LIVE),
            origin,
            bitmap_image_state: BitmapImageState::Fresh,
            dynamic_thread_local_backing_projected: false,
            thread_local_data_initialized: false,
            dynamic_theap_initialized: false,
            child_subprocess_image_initialized: false,
            dynamic_arena_pages_initialized: false,
            _owner: PhantomData,
        }
    }

    #[inline]
    pub(crate) const fn pointer(&self) -> NonNull<u8> {
        self.pointer
    }

    #[inline]
    pub(crate) const fn memory_id(&self) -> MemoryId {
        self.memory
    }

    /// Initializes this exact fresh parent-issued capability as the distinct
    /// child subprocess image. The linear release right stays external.
    #[inline]
    pub(crate) fn initialize_child_subprocess_image(
        &mut self,
    ) -> Option<Pin<&mut crate::subproc::ChildSubprocessImage>> {
        type Image = crate::subproc::ChildSubprocessImage;
        if !self.is_live()
            || self.origin != MetaAllocationOrigin::DirectZeroed
            || self.child_subprocess_image_initialized
            || self.dynamic_theap_initialized
            || self.thread_local_data_initialized
            || self.dynamic_thread_local_backing_projected
            || self.dynamic_arena_pages_initialized
            || self.requested_size != size_of::<Image>()
            || self.pointer.as_ptr().addr() % align_of::<Image>() != 0
        {
            return None;
        }
        // SAFETY: the exact direct-zeroed capability is uniquely borrowed,
        // has the image's exact size/alignment, and has no prior role. `new`
        // writes every field before the pinned view is formed.
        unsafe { self.pointer.as_ptr().cast::<Image>().write(Image::new()); }
        self.child_subprocess_image_initialized = true;
        // SAFETY: the external capability owns this stable address until
        // release and the image is `!Unpin` after this projection.
        Some(unsafe {
            Pin::new_unchecked(&mut *self.pointer.as_ptr().cast::<Image>())
        })
    }

    /// Short mutable projection of an initialized child image. Its external
    /// `MetaAllocation` must remain live for the complete borrow.
    #[inline]
    pub(crate) fn child_subprocess_image_mut(
        &mut self,
    ) -> Option<Pin<&mut crate::subproc::ChildSubprocessImage>> {
        type Image = crate::subproc::ChildSubprocessImage;
        if !self.is_live()
            || !self.child_subprocess_image_initialized
            || self.dynamic_theap_initialized
            || self.thread_local_data_initialized
            || self.dynamic_thread_local_backing_projected
            || self.dynamic_arena_pages_initialized
        {
            return None;
        }
        // SAFETY: only the exact initializer sets this marker; `&mut self`
        // uniquely borrows the capability and its bytes.
        Some(unsafe { Pin::new_unchecked(&mut *self.pointer.as_ptr().cast::<Image>()) })
    }

    /// Whether `memory` is the exact Malloc provenance recorded by this
    /// capability, including the source-visible allocation attributes.
    #[inline]
    pub(crate) fn matches_memory_id(&self, memory: MemoryId) -> bool {
        let Some(expected) = self.memory.malloc_memory() else {
            return false;
        };
        let Some(actual) = memory.malloc_memory() else {
            return false;
        };
        expected.base == actual.base
            && expected.size == actual.size
            && self.memory.kind() == memory.kind()
            && self.memory.is_pinned() == memory.is_pinned()
            && self.memory.initially_committed() == memory.initially_committed()
            && self.memory.initially_zero() == memory.initially_zero()
    }

    /// Calls `operation` with a transient typed view of this initialized
    /// allocator-owned ordinary bitmap. The view cannot escape the retained
    /// metadata capability or become separately stored ownership.
    #[inline]
    pub(crate) fn with_bitmap_view<R>(
        &self,
        owner: Pin<&MetadataEngine<'owner>>,
        layout: BitmapLayout,
        operation: impl FnOnce(&BitmapView<'_>) -> R,
    ) -> Result<R, MetaBitmapProjectionError> {
        self.validate_bitmap_image(owner, layout)?;
        self.require_bitmap_image_state(BitmapImageState::Published)?;
        // SAFETY: validation proves the exact typed capability extent,
        // BCHUNK alignment, Malloc provenance, live owner identity, and
        // Release-published layout. The registry's outer lock excludes a
        // competing image replacement for this capability.
        let view = unsafe { BitmapView::attach(self.pointer.as_ptr(), self.requested_size, layout) }
            .ok_or(MetaBitmapProjectionError::InvalidImage)?;
        Ok(operation(&view))
    }

    /// Initializes one fresh aligned-zeroed allocation as an ordinary bitmap
    /// and exposes it only for the duration of `operation`.
    #[inline]
    pub(crate) fn initialize_zeroed_bitmap<R>(
        &mut self,
        owner: Pin<&MetadataEngine<'owner>>,
        layout: BitmapLayout,
        operation: impl FnOnce(&mut BitmapView<'_>) -> R,
    ) -> Result<R, MetaBitmapProjectionError> {
        self.validate_bitmap_image(owner, layout)?;
        self.require_bitmap_image_state(BitmapImageState::Fresh)?;
        // SAFETY: aligned metadata zalloc supplied the exact all-zero image;
        // the unique capability and outer registry lock establish the source
        // initialization exclusivity before any view can be attached.
        let mut view = unsafe {
            BitmapView::initialize_zeroed(self.pointer.as_ptr(), self.requested_size, layout)
        }
        .ok_or(MetaBitmapProjectionError::InvalidImage)?;
        // The complete zero image and its Release-published chunk count now
        // exist before the callback can obtain the transient view.
        self.bitmap_image_state = BitmapImageState::Published;
        Ok(operation(&mut view))
    }

    /// Publishes a copied bitmap image without clearing its old prefix, then
    /// exposes it only for appended-range setup.
    #[inline]
    pub(crate) fn publish_preserved_bitmap<R>(
        &mut self,
        owner: Pin<&MetadataEngine<'owner>>,
        layout: BitmapLayout,
        operation: impl FnOnce(&mut BitmapView<'_>) -> R,
    ) -> Result<R, MetaBitmapProjectionError> {
        self.validate_bitmap_image(owner, layout)?;
        self.require_bitmap_image_state(BitmapImageState::CopiedPrefix)?;
        // SAFETY: the registry copied exactly the old image into fresh zeroed
        // storage while holding its outer lock. This source branch only
        // publishes the larger count.
        let mut view = unsafe {
            BitmapView::publish_preserved(self.pointer.as_ptr(), self.requested_size, layout)
        }
        .ok_or(MetaBitmapProjectionError::InvalidImage)?;
        // Only the copied prefix branch may publish a nonzero image, and it
        // becomes observable before the appended-range callback runs.
        self.bitmap_image_state = BitmapImageState::Published;
        Ok(operation(&mut view))
    }

    /// Copies exactly one published bitmap image into this fresh aligned-zeroed
    /// capability without reconstructing ownership from either raw pointer.
    #[inline]
    pub(crate) fn copy_bitmap_image_from(
        &mut self,
        owner: Pin<&MetadataEngine<'owner>>,
        target_layout: BitmapLayout,
        source: &MetaAllocation<'owner>,
        source_layout: BitmapLayout,
    ) -> Result<(), MetaBitmapProjectionError> {
        self.validate_bitmap_image(owner, target_layout)?;
        self.require_bitmap_image_state(BitmapImageState::Fresh)?;
        source.with_bitmap_view(owner, source_layout, |_| ())?;
        if source_layout.byte_size() > self.requested_size {
            return Err(MetaBitmapProjectionError::InvalidImage);
        }
        // SAFETY: both exact typed capabilities have validated distinct
        // Malloc provenance. The replacement is fresh and cannot overlap the
        // live source allocation; the registry lock excludes mutation during
        // this source-sized byte copy.
        unsafe {
            core::ptr::copy_nonoverlapping(
                source.pointer.as_ptr(),
                self.pointer.as_ptr(),
                source_layout.byte_size(),
            );
        }
        self.bitmap_image_state = BitmapImageState::CopiedPrefix;
        Ok(())
    }

    /// Initializes this exact aligned metadata capability as one private
    /// dynamic `mi_arena_pages_t` image.
    ///
    /// The fixed pointer header and every ordinary bitmap are formed from the
    /// source-sized [`ArenaPagesLayout`] before a Heap can Release-publish the
    /// header pointer. The individual bitmap views never escape this linear
    /// allocation capability.
    #[inline]
    pub(crate) fn initialize_dynamic_arena_pages(
        &mut self,
        owner: Pin<&MetadataEngine<'owner>>,
        layout: ArenaPagesLayout,
    ) -> bool {
        if !self.validate_dynamic_arena_pages_image(owner, layout)
            || self.dynamic_arena_pages_initialized
        {
            return false;
        }

        let mut pointers = [core::ptr::null_mut(); ARENA_BIN_COUNT + 1];
        for (index, slot) in pointers.iter_mut().enumerate() {
            let Some(offset) = layout.bitmap_offset(index) else {
                return false;
            };
            // SAFETY: validation proves the exact aligned source layout fits
            // this fresh zeroed allocation. Each source bitmap owns its
            // distinct fixed subrange and is initialized before publication.
            let pointer = unsafe { self.pointer.as_ptr().add(offset) };
            let initialized = unsafe {
                BitmapView::initialize_zeroed(
                    pointer,
                    layout.bitmap_layout().byte_size(),
                    layout.bitmap_layout(),
                )
            };
            if initialized.is_none() {
                return false;
            }
            *slot = pointer;
        }

        // SAFETY: the fixed header lies at the allocation start and every
        // flexible-tail pointer above names one initialized, Release-published
        // bitmap image. No typed header reference escaped before this write.
        unsafe {
            self.pointer.as_ptr().cast::<ArenaPages>().write(ArenaPages {
                pages: pointers[0],
                pages_abandoned: core::array::from_fn(|bin| pointers[bin + 1]),
            });
        }
        self.dynamic_arena_pages_initialized = true;
        true
    }

    /// Returns the exact typed header pointer for Heap publication.
    ///
    /// This is intentionally not a raw-parts escape hatch: the header stays
    /// owned by this capability, and ordinary bitmap access below requires a
    /// transient closure tied to the same capability and source layout.
    #[inline]
    pub(crate) fn dynamic_arena_pages_pointer(
        &self,
        owner: Pin<&MetadataEngine<'owner>>,
        layout: ArenaPagesLayout,
    ) -> Option<NonNull<ArenaPages>> {
        if !self.dynamic_arena_pages_initialized
            || !self.validate_dynamic_arena_pages_image(owner, layout)
        {
            return None;
        }
        NonNull::new(self.pointer.as_ptr().cast::<ArenaPages>())
    }

    /// Borrows the one private heap-local ordinary-pages bitmap transiently.
    #[inline]
    pub(crate) fn with_dynamic_arena_pages<R>(
        &self,
        owner: Pin<&MetadataEngine<'owner>>,
        layout: ArenaPagesLayout,
        operation: impl FnOnce(&BitmapView<'_>) -> R,
    ) -> Option<R> {
        self.with_dynamic_arena_pages_bitmap(owner, layout, 0, operation)
    }

    /// Borrows one private heap-local abandoned-pages bitmap transiently.
    #[inline]
    pub(crate) fn with_dynamic_arena_abandoned_pages<R>(
        &self,
        owner: Pin<&MetadataEngine<'owner>>,
        layout: ArenaPagesLayout,
        bin: usize,
        operation: impl FnOnce(&BitmapView<'_>) -> R,
    ) -> Option<R> {
        if bin >= ARENA_BIN_COUNT {
            return None;
        }
        self.with_dynamic_arena_pages_bitmap(owner, layout, bin + 1, operation)
    }

    #[inline]
    fn with_dynamic_arena_pages_bitmap<R>(
        &self,
        owner: Pin<&MetadataEngine<'owner>>,
        layout: ArenaPagesLayout,
        bitmap: usize,
        operation: impl FnOnce(&BitmapView<'_>) -> R,
    ) -> Option<R> {
        if !self.dynamic_arena_pages_initialized
            || !self.validate_dynamic_arena_pages_image(owner, layout)
        {
            return None;
        }
        let offset = layout.bitmap_offset(bitmap)?;
        // SAFETY: the initialized marker and exact layout validation prove
        // this one bitmap's bounded, Release-published image. The view is
        // transient and cannot outlive the retained metadata capability.
        let view = unsafe {
            BitmapView::attach(
                self.pointer.as_ptr().add(offset),
                layout.bitmap_layout().byte_size(),
                layout.bitmap_layout(),
            )
        }?;
        Some(operation(&view))
    }

    /// Projects this capability as the one source-shaped dynamic TLS backing.
    ///
    /// This is deliberately the only typed flexible-allocation projection.
    /// It accepts precisely `sizeof(mi_thread_locals_t) + count *
    /// sizeof(mi_tls_slot_t)`, requires the backing's native alignment, and
    /// borrows through the existing owner-bound capability. There is no
    /// generic raw-parts or arbitrary-type cast API: a future metadata user
    /// needs its own audited typed projection and source layout proof. The
    /// first projection claims the durable dynamic-TLS role; a later TLS
    /// projection through the same linear capability is allowed, while every
    /// other typed role rejects this capability.
    #[inline]
    pub(crate) fn dynamic_thread_local_backing_mut(
        &mut self,
        count: usize,
    ) -> Option<&mut DynamicThreadLocalBacking> {
        let required = DynamicThreadLocalBacking::allocation_size(count)?;
        if !self.is_live()
            || self.bitmap_image_state != BitmapImageState::Fresh
            || self.thread_local_data_initialized
            || self.dynamic_theap_initialized
            || self.dynamic_arena_pages_initialized
            || self.requested_size != required
            || self.pointer.as_ptr().addr() % align_of::<DynamicThreadLocalBacking>() != 0
        {
            return None;
        }
        self.dynamic_thread_local_backing_projected = true;
        // SAFETY: the exact source flexible request is checked above. The
        // metadata allocation is zeroed when fresh and source-copied when
        // replaced, both valid representations of the fixed header; `&mut
        // MetaAllocation` is the unique capability for these bytes.
        Some(unsafe { &mut *self.pointer.as_ptr().cast::<DynamicThreadLocalBacking>() })
    }

    /// Initializes this direct-zeroed capability as one complete
    /// source-ordered, subprocess-attached/no-theap `mi_tld_t`.
    ///
    /// The bounded TLD lifecycle has no generic metadata cast: it may only
    /// initialize exactly one aligned [`ThreadLocalData`] request from the
    /// direct `_mi_meta_zalloc` route and must retain this capability through
    /// source-ordered invalidation and release. The Rust TLD's private-lock
    /// field is a documented Linux futex boundary, so this proves the
    /// translated layout request rather than asserting a C
    /// `sizeof(mi_tld_t)` ABI identity. Replacements and aligned requests are
    /// rejected before a TLD reference can form.
    #[inline]
    pub(crate) fn initialize_thread_local_data_subprocess_attached_no_theap(
        &mut self,
        thread_id: LiveThreadId,
        thread_sequence: ThreadSequence,
        numa_node: i32,
        subprocess: &'static MainSubprocess,
    ) -> bool {
        if !self.is_live()
            || self.origin != MetaAllocationOrigin::DirectZeroed
            || self.thread_local_data_initialized
            || self.dynamic_theap_initialized
            || self.dynamic_thread_local_backing_projected
            || self.dynamic_arena_pages_initialized
            || self.requested_size != size_of::<ThreadLocalData>()
            || self.pointer.as_ptr().addr() % align_of::<ThreadLocalData>() != 0
        {
            return false;
        }
        // SAFETY: direct `zalloc` reaches `allocate_zeroed`, so this exact
        // typed request has the all-zero representation. That is valid for
        // every represented TLD field before initialization: null pointers,
        // false booleans, zero atomics in `PrivateLock`, and
        // `MemoryKind::None`'s zero discriminant in `MemoryId`. The exact
        // size/alignment proof above permits the temporary reference, and the
        // complete image is written before it can escape this method.
        let tld = unsafe { &mut *self.pointer.as_ptr().cast::<ThreadLocalData>() };
        // SAFETY: this method retains the unique fresh-zeroed capability and
        // writes every source-ordered field before publishing the initialized
        // projection below.
        unsafe {
            tld.initialize_subprocess_attached_no_theap(
                thread_id,
                thread_sequence,
                numa_node,
                subprocess,
                self.memory,
            );
        }
        self.thread_local_data_initialized = true;
        true
    }

    /// Projects an already initialized bounded `mi_tld_t` image.
    ///
    /// Only [`Self::initialize_thread_local_data_subprocess_attached_no_theap`] can set this
    /// marker, and it rejects replacement/non-zero metadata routes. The
    /// projection therefore cannot accidentally form a TLD reference over a
    /// `rezalloc` image or arbitrary metadata bytes.
    #[inline]
    pub(crate) fn thread_local_data_mut(&mut self) -> Option<&mut ThreadLocalData> {
        if !self.is_live()
            || !self.thread_local_data_initialized
            || self.dynamic_theap_initialized
            || self.dynamic_thread_local_backing_projected
            || self.dynamic_arena_pages_initialized
            || self.requested_size != size_of::<ThreadLocalData>()
            || self.pointer.as_ptr().addr() % align_of::<ThreadLocalData>() != 0
        {
            return None;
        }
        // SAFETY: the initialized-only marker is set immediately after the
        // complete write above, and this unique capability keeps the typed
        // image live.
        Some(unsafe { &mut *self.pointer.as_ptr().cast::<ThreadLocalData>() })
    }

    /// Returns the TLD immediately after this capability's successful typed
    /// initialization.
    ///
    /// This deliberately has no fallible projection: the same exclusive
    /// capability just established every predicate checked by
    /// [`Self::thread_local_data_mut`], and no code can mutate its private
    /// origin, request size, pointer, or initialized marker in between. The
    /// private TLD constructor uses it to make ticket-to-lease activation
    /// structurally paired with a completed image rather than an error path
    /// that could orphan a metadata capability.
    ///
    /// # Safety
    ///
    /// The caller must have received `true` from
    /// [`Self::initialize_thread_local_data_subprocess_attached_no_theap`]
    /// on this exact, still-live, exclusively-borrowed capability immediately
    /// before this call. No concurrent or intervening `MetaAllocator::free`
    /// may consume it, and no safe caller may manufacture a typed TLD from
    /// arbitrary metadata bytes.
    #[inline]
    pub(crate) unsafe fn newly_initialized_thread_local_data_mut(&mut self) -> &mut ThreadLocalData {
        debug_assert!(self.thread_local_data_initialized);
        debug_assert!(self.is_live());
        debug_assert_eq!(self.requested_size, size_of::<ThreadLocalData>());
        debug_assert_eq!(self.pointer.as_ptr().addr() % align_of::<ThreadLocalData>(), 0);
        // SAFETY: the caller's explicit contract establishes that the
        // successful typed initializer immediately before this call wrote a
        // complete TLD at this exact checked pointer; the unique `&mut
        // MetaAllocation` excludes another mutable projection.
        unsafe { &mut *self.pointer.as_ptr().cast::<ThreadLocalData>() }
    }

    /// Initializes and projects one exact direct-zeroed dynamic Theap image.
    ///
    /// The full Rust `Theap` image is written from its source empty image;
    /// this validates the metadata allocation/provenance boundary without
    /// asserting that it equals the complete C `mi_theap_t` size. The caller
    /// retains this linear capability through `_mi_theap_init` and final
    /// metadata release, and no general raw Theap cast is exposed.
    #[inline]
    pub(crate) fn initialize_dynamic_theap_metadata(&mut self) -> Option<&mut Theap> {
        if !self.is_live()
            || self.origin != MetaAllocationOrigin::DirectZeroed
            || self.thread_local_data_initialized
            || self.dynamic_theap_initialized
            || self.dynamic_thread_local_backing_projected
            || self.dynamic_arena_pages_initialized
            || self.requested_size != size_of::<Theap>()
            || self.pointer.as_ptr().addr() % align_of::<Theap>() != 0
            || self.memory.kind() != MemoryKind::Malloc
            || !self.has_consistent_malloc_provenance()
        {
            return None;
        }
        // SAFETY: the exact direct-zeroed Malloc capability has the Rust
        // Theap request size/alignment and is exclusively retained here. A
        // complete empty source image is written before its typed projection
        // can escape.
        unsafe { self.pointer.as_ptr().cast::<Theap>().write(Theap::empty()) };
        let theap = unsafe { &mut *self.pointer.as_ptr().cast::<Theap>() };
        if !theap.set_dynamic_metadata_memid(self.memory) {
            return None;
        }
        self.dynamic_theap_initialized = true;
        Some(theap)
    }

    /// Projects a prior exact dynamic-Theap initialization while its linear
    /// metadata capability remains live.
    #[inline]
    pub(crate) fn dynamic_theap_mut(&mut self) -> Option<&mut Theap> {
        if !self.is_live()
            || !self.dynamic_theap_initialized
            || self.thread_local_data_initialized
            || self.dynamic_thread_local_backing_projected
            || self.dynamic_arena_pages_initialized
            || self.requested_size != size_of::<Theap>()
            || self.pointer.as_ptr().addr() % align_of::<Theap>() != 0
            || self.memory.kind() != MemoryKind::Malloc
            || !self.has_consistent_malloc_provenance()
        {
            return None;
        }
        // SAFETY: only the initializer above can set this marker, and the
        // unique capability keeps the exact dynamic image alive.
        Some(unsafe { &mut *self.pointer.as_ptr().cast::<Theap>() })
    }

    /// True only while this capability owns an unlinked dynamic Theap image.
    /// It gates pre-registry rollback and the final post-detach release; a
    /// Theap with either intrusive membership must remain retained.
    #[inline]
    unsafe fn is_unlinked_dynamic_theap(&mut self) -> bool {
        self.dynamic_theap_mut()
            .is_some_and(|theap| unsafe { theap.is_unlinked_dynamic_metadata() })
    }

    /// Immutably projects a prior exact dynamic-Theap image while its retained
    /// metadata capability is still live. The page-session boundary needs only
    /// source queue/direct inspection through this reference; mutation remains
    /// gated by the owner's unique mutable capability above.
    #[inline]
    pub(crate) fn dynamic_theap(&self) -> Option<&Theap> {
        if !self.is_live()
            || !self.dynamic_theap_initialized
            || self.thread_local_data_initialized
            || self.dynamic_thread_local_backing_projected
            || self.dynamic_arena_pages_initialized
            || self.requested_size != size_of::<Theap>()
            || self.pointer.as_ptr().addr() % align_of::<Theap>() != 0
            || self.memory.kind() != MemoryKind::Malloc
            || !self.has_consistent_malloc_provenance()
        {
            return None;
        }
        // SAFETY: the exact initialized image remains live through this
        // capability. This shared projection does not permit mutation.
        Some(unsafe { &*self.pointer.as_ptr().cast::<Theap>() })
    }

    /// Returns only the identity pointer for an initialized dynamic Theap.
    /// No Rust reference is formed, so callers can pass it to the raw
    /// source-list detach operation after typed projections have ended.
    #[inline]
    pub(crate) fn dynamic_theap_pointer(&self) -> Option<NonNull<Theap>> {
        if !self.is_live()
            || !self.dynamic_theap_initialized
            || self.thread_local_data_initialized
            || self.dynamic_thread_local_backing_projected
            || self.dynamic_arena_pages_initialized
            || self.requested_size != size_of::<Theap>()
            || self.pointer.as_ptr().addr() % align_of::<Theap>() != 0
            || self.memory.kind() != MemoryKind::Malloc
            || !self.has_consistent_malloc_provenance()
        {
            return None;
        }
        NonNull::new(self.pointer.as_ptr().cast::<Theap>())
    }

    #[inline]
    fn claim(&self, expected: u8, next: u8) -> bool {
        self.state
            .compare_exchange(expected, next, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    /// Typed safe projections may dereference the allocation bytes only while
    /// the linear capability still owns a live metadata allocation.
    #[inline]
    fn is_live(&self) -> bool {
        self.state.load(Ordering::Acquire) == ALLOCATION_LIVE
            // SAFETY: the capability retains the pinned owner lifetime even
            // when its allocation backing has been terminally revoked.
            && !matches!(unsafe { self.owner.as_ref() }.status.load(Ordering::Acquire),
                CLOSED | CLOSE_RETAINED)
    }

    #[inline]
    fn restore_live(&self) {
        self.state.store(ALLOCATION_LIVE, Ordering::Release);
    }

    #[inline]
    fn reject(&self) {
        self.state.store(ALLOCATION_REJECTED, Ordering::Release);
    }

    #[inline]
    fn release(&self) {
        self.state.store(ALLOCATION_RELEASED, Ordering::Release);
    }

    #[inline]
    fn belongs_to(&self, owner: Pin<&MetadataEngine<'owner>>) -> bool {
        core::ptr::eq(self.owner.as_ptr(), owner.get_ref())
    }

    #[inline]
    fn has_consistent_malloc_provenance(&self) -> bool {
        let Some(memory) = self.memory.malloc_memory() else {
            return false;
        };
        memory.base == self.pointer.as_ptr()
            && memory.size == self.requested_size
            && self.memory.size() == Some(self.requested_size)
    }

    #[inline]
    fn validate_bitmap_image(
        &self,
        owner: Pin<&MetadataEngine<'owner>>,
        layout: BitmapLayout,
    ) -> Result<(), MetaBitmapProjectionError> {
        if !self.belongs_to(owner) {
            return Err(MetaBitmapProjectionError::ForeignOwner);
        }
        if !self.is_live()
            || self.origin != MetaAllocationOrigin::AlignedZeroed
            || self.dynamic_arena_pages_initialized
            || self.dynamic_thread_local_backing_projected
            || self.requested_size != layout.byte_size()
            || self.pointer.as_ptr().addr() % BCHUNK_SIZE != 0
            || self.memory.kind() != MemoryKind::Malloc
            || !self.has_consistent_malloc_provenance()
        {
            return Err(MetaBitmapProjectionError::InvalidImage);
        }
        Ok(())
    }

    #[inline]
    fn validate_dynamic_arena_pages_image(
        &self,
        owner: Pin<&MetadataEngine<'owner>>,
        layout: ArenaPagesLayout,
    ) -> bool {
        self.belongs_to(owner)
            && self.is_live()
            && self.origin == MetaAllocationOrigin::AlignedZeroed
            && self.bitmap_image_state == BitmapImageState::Fresh
            && !self.dynamic_thread_local_backing_projected
            && !self.thread_local_data_initialized
            && !self.dynamic_theap_initialized
            && self.requested_size == layout.byte_size()
            && self.pointer.as_ptr().addr() % BCHUNK_SIZE == 0
            && self.memory.kind() == MemoryKind::Malloc
            && self.has_consistent_malloc_provenance()
    }

    #[inline]
    fn require_bitmap_image_state(
        &self,
        expected: BitmapImageState,
    ) -> Result<(), MetaBitmapProjectionError> {
        if self.bitmap_image_state != expected {
            return Err(MetaBitmapProjectionError::InvalidImage);
        }
        Ok(())
    }
}

impl MetaAllocation<'static> {
    /// Whether the exact initialized dynamic-Theap capability can transfer
    /// into its source image. This preflight does not consume ownership.
    pub(crate) fn can_transfer_source_retained_theap(&self) -> bool {
        self.dynamic_theap().is_some_and(|theap| self.matches_memory_id(theap.memory_id()))
    }

    /// Whether the exact initialized TLD capability can transfer into its
    /// source image. This preflight does not consume ownership.
    pub(crate) fn can_transfer_source_retained_tld(&self) -> bool {
        if !self.is_live()
            || !self.thread_local_data_initialized
            || self.dynamic_theap_initialized
            || self.dynamic_thread_local_backing_projected
            || self.dynamic_arena_pages_initialized
            || self.requested_size != size_of::<ThreadLocalData>()
            || self.pointer.as_ptr().addr() % align_of::<ThreadLocalData>() != 0
            || !self.has_consistent_malloc_provenance()
        {
            return false;
        }
        // SAFETY: the private initialized-role marker and exact extent prove
        // this source image. The capability retains its allocation lifetime.
        let tld = unsafe { self.pointer.cast::<ThreadLocalData>().as_ref() };
        self.matches_memory_id(tld.memory_id())
    }

    /// Consumes the Rust capability into the existing source Theap image.
    ///
    /// This is the ownership transfer used before the departing thread's TLS
    /// wrapper disappears after process done. The image's unchanged Malloc
    /// memory ID retains base/extent/provenance; the surrounding lifecycle
    /// retains its selected metadata-owner identity. No allocation is freed,
    /// no source list is mutated, and the live-allocation audit is unchanged.
    /// The returned pointer is not a second allocation capability. Recovery
    /// is possible only through the unsafe, role-specific inverse below.
    pub(crate) fn into_source_retained_theap(self) -> Result<NonNull<Theap>, Self> {
        if !self.can_transfer_source_retained_theap() { return Err(self); }
        let pointer = self.pointer.cast();
        core::mem::forget(self);
        Ok(pointer)
    }

    /// Consumes the Rust capability into the existing source TLD image.
    /// Source registration, live-thread count, and Theap links remain intact.
    /// The lifecycle must disable its TLS owner before the TLS mapping is
    /// released and retain the source image for the eventual terminal owner.
    pub(crate) fn into_source_retained_tld(self) -> Result<NonNull<ThreadLocalData>, Self> {
        if !self.can_transfer_source_retained_tld() { return Err(self); }
        let pointer = self.pointer.cast();
        core::mem::forget(self);
        Ok(pointer)
    }

    /// Recovers only a previously transferred dynamic-Theap capability.
    ///
    /// # Safety
    ///
    /// `pointer` must be the still-live image returned by exactly one prior
    /// `into_source_retained_theap` on an allocation belonging to `owner`.
    /// Its stored memory ID must remain unchanged and its typed image valid;
    /// source-ordered list/invalidation changes are preserved, never reset.
    /// That transfer must not already have been recovered; no Rust wrapper,
    /// page session, callback, or other reference may access the image during
    /// recovery. The caller must have whole-process quiescence and exclusive
    /// source-list authority, and must preserve the source lifetime through
    /// eventual release. Source-list membership alone does not prove transfer.
    /// A rejected image remains source-owned; rejection grants no raw-free
    /// authority and must not discard its source owner.
    pub(crate) unsafe fn recover_source_retained_theap(
        owner: Pin<&'static MetaAllocator>, pointer: NonNull<Theap>,
    ) -> Option<Self> {
        if pointer.as_ptr().addr() % align_of::<Theap>() != 0 { return None; }
        // SAFETY: the caller proves this exact source image remains valid
        // and exclusively retained after its explicit capability transfer.
        let memory = unsafe { pointer.as_ref().memory_id() };
        let mut allocation = Self::new(owner, pointer.cast(), size_of::<Theap>(),
            MetaAllocationOrigin::DirectZeroed);
        if !allocation.matches_memory_id(memory) { return None; }
        allocation.dynamic_theap_initialized = true;
        Some(allocation)
    }

    /// Recovers only a previously transferred TLD capability.
    ///
    /// # Safety
    ///
    /// `pointer` must be the still-live, valid typed image returned by one prior
    /// `into_source_retained_tld` belonging to `owner`, never yet recovered.
    /// The caller must prove whole-process quiescence, exclusive source TLD
    /// ownership, no surviving TLS wrapper or aliases accessing this image,
    /// and valid unchanged source memory ID and backing. Source registration
    /// alone is insufficient. Retain the recovered capability while any
    /// source Theap still references the TLD; recovery itself does not change
    /// source registration or counts. A rejected image stays source-owned.
    pub(crate) unsafe fn recover_source_retained_tld(
        owner: Pin<&'static MetaAllocator>, pointer: NonNull<ThreadLocalData>,
    ) -> Option<Self> {
        if pointer.as_ptr().addr() % align_of::<ThreadLocalData>() != 0 { return None; }
        // SAFETY: the caller supplies the same explicit-transfer proof as
        // the Theap inverse, for the separately typed TLD image.
        let memory = unsafe { pointer.as_ref().memory_id() };
        let mut allocation = Self::new(owner, pointer.cast(), size_of::<ThreadLocalData>(),
            MetaAllocationOrigin::DirectZeroed);
        if !allocation.matches_memory_id(memory) { return None; }
        allocation.thread_local_data_initialized = true;
        Some(allocation)
    }
}

/// A selected owned branch of source metadata release.
///
/// This deliberately covers only the source `MI_MEM_MALLOC` branch and the
/// regular anonymous-OS release shape reached through `_mi_arenas_free`.  It
/// is constructed from an already-owned capability, never from a raw pointer
/// and copied [`MemoryId`]. The regular-OS form is currently a stand-alone
/// retry witness, not a metadata caller: pinned `_mi_meta_zalloc` forms
/// `MI_MEM_MALLOC`, while a real `_mi_arenas_free` OS owner needs the broader
/// memory-ID/subprocess contract that this value intentionally does not hold.
/// A source `needs_no_free` branch creates no value: it has no release
/// authority to transfer. This enum deliberately does not carry arena
/// release: the separate
/// [`crate::arena::ArenaSliceClaim::release_for_subprocess`] now proves one
/// typed arena claim and its source registry/subprocess identity gate without
/// pretending to be a general metadata dispatcher.
///
/// Consequently this is not a general `_mi_meta_free` dispatcher.  It proves
/// only that the two represented owners cannot select a release algorithm by
/// forging or misinterpreting provenance bits.
#[must_use = "selected metadata release owners must be released or retained explicitly"]
pub(crate) enum MetaRelease {
    Malloc(MetaAllocation<'static>),
    RegularOs(Mapping),
}

/// One failed selected metadata release.
///
/// An eligible exact-owner Malloc entry-acquisition failure before its live
/// capability is claimed leaves that capability retryable. This is limited to
/// [`MetaError::InvalidEntryThread`], [`MetaError::RecursiveEntry`], and
/// [`MetaError::Lock`]: no local allocator mutation has begun. Once the
/// capability is claimed, local free may already have changed page or queue
/// state before it reports [`MetaError::Free`]; that rejected capability is
/// terminal and remains only for diagnosis. A regular OS mapping, in contrast,
/// remains live when [`Mapping::unmap`] reports a kernel error, so its exact
/// owner is returned for an explicit retry.
pub(crate) enum MetaReleaseFailure {
    /// Entering the exact owner's backing lock failed before this Malloc
    /// capability changed state, so the caller may retry this exact value.
    MallocRetryable {
        error: MetaError,
        allocation: MetaAllocation<'static>,
    },
    /// The Malloc capability was claimed before its failure and cannot be
    /// retried, even though it is retained for diagnosis.
    MallocTerminal {
        error: MetaError,
        allocation: MetaAllocation<'static>,
    },
    RegularOs {
        error: Errno,
        mapping: Mapping,
    },
}

impl MetaRelease {
    /// Releases the exact owner carried by this selected branch.
    ///
    /// The Malloc branch recovers only the private, process-lived owner
    /// recorded when the capability was created; it never lets a caller
    /// nominate a different metadata allocator. An entry failure before it
    /// claims the Malloc capability returns that live exact value for retry;
    /// a failure after the claim is terminal as documented on
    /// [`MetaReleaseFailure`]. The regular OS branch retains the mapping on a
    /// failed kernel unmap, so its failure returns that exact mapping for
    /// explicit retry.
    pub(crate) fn release(self) -> Result<(), MetaReleaseFailure> {
        match self {
            Self::Malloc(mut allocation) => {
                // SAFETY: `MetaAllocation::new` records only a pinned,
                // process-lived `MetaAllocator`; its lifetime parameter is
                // `static` for this release boundary.  The capability keeps
                // that owner identity exact and does not form a mutable alias.
                let owner = unsafe { Pin::new_unchecked(allocation.owner.as_ref()) };
                match owner.release_selected_malloc(&mut allocation) {
                    Ok(()) => Ok(()),
                    Err(
                        error @ (MetaError::InvalidEntryThread
                        | MetaError::RecursiveEntry
                        | MetaError::Lock(_)),
                    ) => {
                        debug_assert!(
                            allocation.is_live(),
                            "an entry failure must preserve its exact Malloc capability"
                        );
                        Err(MetaReleaseFailure::MallocRetryable { error, allocation })
                    }
                    Err(error) => {
                        debug_assert!(
                            !allocation.is_live(),
                            "only an entry failure may retain a live exact-owner Malloc capability"
                        );
                        // `MetaRelease` reconstructs the owner only from this
                        // capability, so a live non-entry error is unreachable
                        // without an internal invariant violation. Fail closed
                        // rather than exposing an unclassified retry token.
                        if allocation.is_live() {
                            allocation.reject();
                        }
                        Err(MetaReleaseFailure::MallocTerminal { error, allocation })
                    }
                }
            }
            Self::RegularOs(mut mapping) => match mapping.unmap() {
                Ok(()) => Ok(()),
                Err(error) => Err(MetaReleaseFailure::RegularOs { error, mapping }),
            },
        }
    }
}

/// One pinned metadata engine whose page allocator borrows its final
/// bootstrap image for `'owner`.
///
/// `Self` is `!Unpin`: after initialization, the page engine contains
/// references to the final bootstrap and either the shared process map or the
/// historical private PageMap slot. `'owner` describes those backing
/// capabilities; an entry borrows this pinned image only for the entry's
/// shorter lifetime. [`MetaAllocator`] fixes `'owner` to `'static` for the
/// process-main singleton. A reclaimable child owner must still ensure that
/// every capability minted for its engine is retired before its image is
/// released.
pub(crate) struct MetadataEngine<'owner> {
    lock: PrivateLock,
    active_entry_thread: AtomicUsize,
    status: AtomicU8,
    config: UnsafeCell<MaybeUninit<MemoryConfig>>,
    mapping: UnsafeCell<MaybeUninit<Mapping>>,
    page_map: UnsafeCell<MaybeUninit<PageMap>>,
    /// The exact private PageMap mapping retained if page-map bootstrap's
    /// cleanup release fails. This is not the later detached arena `mapping`:
    /// no PageMap or arena was formed on this branch, so it needs its own
    /// final owner before the metadata allocator enters FAILED.
    retained_page_map_initialization_mapping: UnsafeCell<MaybeUninit<Mapping>>,
    has_retained_page_map_initialization_mapping: AtomicBool,
    bootstrap: UnsafeCell<MaybeUninit<ExclusiveTheapBootstrap>>,
    allocator: UnsafeCell<MaybeUninit<MetadataPageAllocator<'owner>>>,
    process_backing: UnsafeCell<Option<MetadataProcessBacking>>,
    canonical_heap: UnsafeCell<Option<crate::main_theap::MainStaticMetadataHeapLease>>,
    /// Common source identity for the process-only binding path. Child engine
    /// binding will use this identity directly without fabricating a
    /// `MainSubprocess` wrapper or its static TLD slot.
    subprocess: AtomicPtr<crate::subproc::SubprocessIdentity>,
    /// The exact detached static Theap address successfully published through
    /// `subprocess->theap_meta`. This is identity-only: the allocator never
    /// dereferences it through this slot. Keeping it separate from the
    /// mutable bootstrap lets a later `_mi_meta_zalloc` precondition compare
    /// stable atomics before taking the metadata lock.
    detached_metadata_theap: AtomicPtr<Theap>,
    /// Each leaked metadata test fixture owns its own source-main identity.
    /// Production has no alternate default: a null test pointer selects the
    /// one process-global `MainSubprocess` below.
    #[cfg(test)]
    test_default_subprocess: AtomicPtr<MainSubprocess>,
    registry: ArenaRegistry,
    #[cfg(test)]
    fail_next_direct_zeroed_size: AtomicUsize,
    #[cfg(test)]
    fail_next_rezalloc_size: AtomicUsize,
    #[cfg(test)]
    fail_next_aligned_zeroed_size: AtomicUsize,
    #[cfg(test)]
    fail_aligned_zeroed_size_attempts: AtomicUsize,
    #[cfg(test)]
    test_entry_attempt_count: AtomicUsize,
    #[cfg(any(test, feature = "native-runtime-test-audit"))]
    test_live_allocation_count: AtomicUsize,
    #[cfg(any(test, feature = "native-runtime-test-audit"))]
    test_allocation_high_water: AtomicUsize,
    _pin: PhantomPinned,
}

/// Process-main spelling. Child subprocesses use the same private metadata
/// engine with a shorter owner lifetime in their reclaimable context.
pub(crate) type MetaAllocator = MetadataEngine<'static>;

/// Exact parent-issued storage for one reclaimable child source context.
///
/// The parent metadata engine and process-main identity are process-lived;
/// this owner value and both child allocations are not. The capabilities stay
/// outside the allocated child image, so releasing the context can never
/// invalidate the value that authorizes that release. Child Heap creation
/// and its own metadata engine are later source transitions and are not
/// represented by this owner yet.
/// This deliberately covers only a root child allocated by the process-main
/// metadata engine; nested-child parent metadata and user-Heap allocation are
/// not accepted by this API.
///
/// The production API stops at the unregistered preparation stage. The
/// lifecycle regression may drive the exact later intrusive transitions
/// through a lease to prove the retained allocations survive them, but this
/// type does not yet construct a child Heap or publish child readiness.
#[must_use = "a child context owner must be retained through child teardown"]
pub(crate) struct ChildContextOwner {
    parent_metadata: Pin<&'static MetaAllocator>,
    parent_subprocess: &'static MainSubprocess,
    // `'static` describes the process-lived allocator that minted this
    // capability, not the child bytes' validity. The capability's live state
    // and this owner's borrow-gated projections end at explicit release.
    context: MetaAllocation<'static>,
    metadata_theap: Option<MetaAllocation<'static>>,
    image_initialized: bool,
    terminal: bool,
}

/// Creation can fail after the first parent allocation. In that case the
/// exact remaining capabilities travel with the error instead of being
/// dropped or reconstructed.
#[must_use = "a retained child context owner must remain owned after creation failure"]
pub(crate) enum ChildContextCreateFailure {
    Allocation {
        stage: ChildContextCreateStage,
        error: MetaError,
    },
    Retained {
        owner: ChildContextOwner,
        stage: ChildContextCreateStage,
        error: MetaError,
        rollback_error: Option<MetaError>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ChildContextCreateStage {
    AllocateContext,
    InitializeImage,
    AllocateMetadataTheap,
    InitializeMetadataTheap,
    RollbackContext,
    ReleaseMetadataTheap,
    UnlinkRegistry,
    ReleaseContext,
}

/// Mutable child-image access is bounded by this lease. No raw image pointer
/// or metadata release capability escapes it.
pub(crate) struct ChildContextLease<'lease> {
    owner: &'lease mut ChildContextOwner,
}

impl ChildContextOwner {
    /// Allocates the child context and metadata-Theap images through the
    /// parent's exact metadata owner. This is the source creation prefix:
    /// both allocations precede registry publication. A failed second
    /// allocation releases the first capability; if that release fails, the
    /// owner is returned intact for terminal retention.
    pub(crate) fn allocate(
        parent_metadata: Pin<&'static MetaAllocator>,
        parent_subprocess: &'static MainSubprocess,
        config: MemoryConfig,
    ) -> Result<Self, ChildContextCreateFailure> {
        let mut context = parent_metadata
            .zalloc_for_main_subprocess(
                config,
                parent_subprocess,
                size_of::<crate::subproc::ChildSubprocessImage>(),
            )
            .map_err(|error| ChildContextCreateFailure::Allocation {
                stage: ChildContextCreateStage::AllocateContext,
                error,
            })?;
        let initialized = context.initialize_child_subprocess_image().is_some();
        let mut owner = Self {
            parent_metadata,
            parent_subprocess,
            context,
            metadata_theap: None,
            image_initialized: initialized,
            terminal: false,
        };
        if !initialized {
            return Err(ChildContextCreateFailure::Retained {
                owner,
                stage: ChildContextCreateStage::InitializeImage,
                error: MetaError::InitializationRetained,
                rollback_error: None,
            });
        }

        let metadata_theap = match parent_metadata.zalloc_for_main_subprocess(
            config,
            parent_subprocess,
            size_of::<Theap>(),
        ) {
            Ok(allocation) => allocation,
            Err(error) => {
                return match parent_metadata.free(&mut owner.context) {
                    Ok(()) => Err(ChildContextCreateFailure::Allocation {
                        stage: ChildContextCreateStage::AllocateMetadataTheap,
                        error,
                    }),
                    Err(rollback_error) => Err(ChildContextCreateFailure::Retained {
                        owner,
                        stage: ChildContextCreateStage::RollbackContext,
                        error,
                        rollback_error: Some(rollback_error),
                    }),
                };
            }
        };
        owner.metadata_theap = Some(metadata_theap);
        let theap_initialized = owner
            .metadata_theap
            .as_mut()
            .and_then(MetaAllocation::initialize_dynamic_theap_metadata)
            .is_some();
        if !theap_initialized {
            return Err(ChildContextCreateFailure::Retained {
                owner,
                stage: ChildContextCreateStage::InitializeMetadataTheap,
                error: MetaError::InitializationRetained,
                rollback_error: None,
            });
        }
        Ok(owner)
    }

    /// Borrows the child image and its metadata-Theap capability for one
    /// operation. The higher-ranked closure prevents either projection from
    /// escaping the owner borrow.
    pub(crate) fn with_lease<R>(
        &mut self,
        operation: impl for<'lease> FnOnce(ChildContextLease<'lease>) -> R,
    ) -> R {
        operation(ChildContextLease { owner: self })
    }

    /// Projects the initialized child image only for the duration of the
    /// closure. Its exact allocation capability remains external and live.
    pub(crate) fn with_image<R>(
        &mut self,
        operation: impl for<'image> FnOnce(
            Pin<&'image mut crate::subproc::ChildSubprocessImage>,
        ) -> R,
    ) -> Option<R> {
        if self.terminal || !self.image_initialized { return None; }
        self.with_lease(|mut lease| lease.with_image(operation))
    }

    /// Frees a never-published child context in source reverse-allocation
    /// order. Once registry or intrusive membership has been published,
    /// callers must use the terminal source teardown path before release.
    pub(crate) fn release_unpublished(
        mut self,
    ) -> Result<(), ChildContextReleaseFailure> {
        if self.terminal {
            return Err(ChildContextReleaseFailure {
                owner: self,
                stage: ChildContextCreateStage::RollbackContext,
                error: MetaError::InitializationRetained,
            });
        }
        let pristine = self.with_image(|image| {
            let identity = image.identity();
            !identity.is_registered()
                && identity.main_heap_publication_state()
                    == crate::subproc::MainHeapPublicationState::Absent
                && !identity.has_published_metadata_theap()
        }).unwrap_or(!self.image_initialized);
        if !pristine {
            return Err(ChildContextReleaseFailure {
                owner: self,
                stage: ChildContextCreateStage::RollbackContext,
                error: MetaError::InitializationRetained,
            });
        }
        if let Some(metadata_theap) = self.metadata_theap.as_mut() {
            // SAFETY: unpublished state above plus exclusive ownership of
            // both caps proves no Heap/TLD list operation can be concurrent.
            if !unsafe { metadata_theap.is_unlinked_dynamic_theap() } {
                return Err(ChildContextReleaseFailure {
                    owner: self,
                    stage: ChildContextCreateStage::ReleaseMetadataTheap,
                    error: MetaError::InitializationRetained,
                });
            }
            if let Err(error) = self.parent_metadata.free(metadata_theap) {
                self.terminal = true;
                return Err(ChildContextReleaseFailure {
                    owner: self,
                    stage: ChildContextCreateStage::ReleaseMetadataTheap,
                    error,
                });
            }
            self.metadata_theap = None;
        }
        if let Err(error) = self.parent_metadata.free(&mut self.context) {
            self.terminal = true;
            return Err(ChildContextReleaseFailure {
                owner: self,
                stage: ChildContextCreateStage::ReleaseContext,
                error,
            });
        }
        Ok(())
    }

    /// Rolls back the source path where the child was registered but its
    /// parent-user-Heap allocation failed. Pinned `mi_subproc_new` releases
    /// the still-unattached metadata Theap first, then `mi_subproc_destroy`
    /// unlinks the child and releases its context image.
    ///
    /// # Safety
    /// The caller has observed failure before any child Heap allocation or
    /// Heap publication, no child operation can race this rollback, and this
    /// exact child is the only registration being retired. A registry error
    /// may follow list mutation; every failure retains the context owner and
    /// forbids retry or capability release.
    pub(crate) unsafe fn rollback_after_child_heap_allocation_failure(
        mut self,
        registry: &'static crate::subproc::registry::SourceSubprocessRegistry,
    ) -> Result<(), ChildContextReleaseFailure> {
        if self.terminal {
            return Err(ChildContextReleaseFailure {
                owner: self,
                stage: ChildContextCreateStage::RollbackContext,
                error: MetaError::InitializationRetained,
            });
        }
        let parent = self.parent_subprocess;
        let valid = self.with_image(|image| {
            let identity = image.identity();
            identity.is_registered_child_of(parent)
                && identity.main_heap_publication_state()
                    == crate::subproc::MainHeapPublicationState::Absent
                && !identity.has_published_metadata_theap()
        }).unwrap_or(false);
        if !valid {
            return Err(ChildContextReleaseFailure {
                owner: self,
                stage: ChildContextCreateStage::RollbackContext,
                error: MetaError::InitializationRetained,
            });
        }
        if let Some(metadata_theap) = self.metadata_theap.as_mut() {
            // SAFETY: the Heap allocation failed before Theap initialization,
            // so this exact parent-issued Theap image has no intrusive edge.
            if !unsafe { metadata_theap.is_unlinked_dynamic_theap() } {
                return Err(ChildContextReleaseFailure {
                    owner: self,
                    stage: ChildContextCreateStage::ReleaseMetadataTheap,
                    error: MetaError::InitializationRetained,
                });
            }
            if let Err(error) = self.parent_metadata.free(metadata_theap) {
                self.terminal = true;
                return Err(ChildContextReleaseFailure {
                    owner: self,
                    stage: ChildContextCreateStage::ReleaseMetadataTheap,
                    error,
                });
            }
            self.metadata_theap = None;
        }
        // SAFETY: source rollback frees the unused Theap before destroy
        // removes registry membership; no Heap or metadata observer remains.
        if let Err(_error) = unsafe {
            registry.unlink_child_terminal(
                self.context
                    .child_subprocess_image_mut()
                    .expect("the retained context image remains initialized")
                    .as_ref()
                    .get_ref(),
            )
        } {
            self.terminal = true;
            return Err(ChildContextReleaseFailure {
                owner: self,
                stage: ChildContextCreateStage::UnlinkRegistry,
                error: MetaError::InitializationRetained,
            });
        }
        if let Err(error) = self.parent_metadata.free(&mut self.context) {
            self.terminal = true;
            return Err(ChildContextReleaseFailure {
                owner: self,
                stage: ChildContextCreateStage::ReleaseContext,
                error,
            });
        }
        Ok(())
    }
}

/// A child context whose main Heap image is retained by the exact parent
/// user-Heap allocation token. This owner spans registry admission through
/// the represented Heap/Theap list transitions; it does not claim page
/// destruction or child MetadataEngine readiness.
#[must_use = "a parent-allocated child Heap owner must remain through terminal release"]
pub(crate) struct ChildMainHeapContextOwner<'heap> {
    context: ChildContextOwner,
    heap_storage: Option<crate::main_heap_page::ParentHeapAllocation<'heap>>,
    stage: ChildMainHeapStage,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ChildMainHeapStage {
    Registered,
    HeapReady,
    RegistryUnlinked,
    TheapDetached,
    MetadataTheapReleased,
    HeapListRemoved,
    ArenaBackingDestroyed,
    Terminal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ChildMainHeapBindError {
    ChildNotRegistered,
    ParentMismatch,
    InvalidHeapAllocation,
}

#[must_use = "a failed child Heap bind retains both exact owners"]
pub(crate) struct ChildMainHeapBindFailure<'heap> {
    pub(crate) context: ChildContextOwner,
    pub(crate) heap: crate::main_heap_page::ParentHeapAllocation<'heap>,
    pub(crate) error: ChildMainHeapBindError,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ChildMainHeapReleaseStage {
    Validate,
    ArenaBacking,
    ParentHeap,
    Context,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ChildMainHeapReleaseError {
    InvalidTransition,
    Metadata(MetaError),
    ArenaDestroy(crate::arena::ArenaDestroyError),
    ArenaReleaseRetained,
    ParentHeap(crate::main_heap_page::ParentHeapAllocationReleaseError),
}

#[must_use = "a failed child Heap release retains its context and allocation state"]
pub(crate) enum ChildMainHeapReleaseFailure<'heap, 'tracking> {
    Retained {
        owner: ChildMainHeapContextOwner<'heap>,
        stage: ChildMainHeapReleaseStage,
        error: ChildMainHeapReleaseError,
    },
    ArenaBacking {
        owner: ChildMainHeapContextOwner<'heap>,
        destroyed: crate::arena::DestroyedArenas<'tracking>,
    },
    Terminal {
        owner: ChildMainHeapContextOwner<'heap>,
        allocation: crate::main_heap_page::ParentHeapAllocationTerminal<'heap>,
    },
}

impl ChildContextOwner {
    /// Binds the real parent-user-Heap allocation after source child registry
    /// admission. The token is consumed by the new aggregate owner, so neither
    /// a raw owner pointer nor a release capability escapes separately.
    pub(crate) fn bind_parent_heap_storage<'heap>(
        mut self,
        mut heap: crate::main_heap_page::ParentHeapAllocation<'heap>,
    ) -> Result<ChildMainHeapContextOwner<'heap>, ChildMainHeapBindFailure<'heap>> {
        let parent = self.parent_subprocess;
        let registered = self.with_image(|image| {
            let identity = image.identity();
            identity.is_registered_child_of(parent)
                && identity.main_heap_publication_state()
                    == crate::subproc::MainHeapPublicationState::Absent
                && !identity.has_published_metadata_theap()
        }).unwrap_or(false);
        let error = if self.terminal || !registered {
            Some(ChildMainHeapBindError::ChildNotRegistered)
        } else if !heap.was_allocated_by(self.parent_subprocess.identity()) {
            Some(ChildMainHeapBindError::ParentMismatch)
        } else if !heap.initialize_empty_image() {
            Some(ChildMainHeapBindError::InvalidHeapAllocation)
        } else {
            None
        };
        if let Some(error) = error {
            return Err(ChildMainHeapBindFailure { context: self, heap, error });
        }
        Ok(ChildMainHeapContextOwner {
            context: self,
            heap_storage: Some(heap),
            stage: ChildMainHeapStage::Registered,
        })
    }
}

impl<'heap> ChildMainHeapContextOwner<'heap> {
    /// Projects the child context and its parent-allocated Heap together for
    /// one source transition. Both references are bounded by the closure.
    pub(crate) fn with_child_heap<R>(
        &mut self,
        operation: impl for<'context, 'heap_view> FnOnce(
            Pin<&'context mut crate::subproc::ChildSubprocessImage>,
            Pin<&'heap_view mut Heap>,
            MemoryId,
        ) -> R,
    ) -> Option<R> {
        if self.stage != ChildMainHeapStage::HeapReady { return None; }
        let Self { context, heap_storage, .. } = self;
        let heap = heap_storage.as_mut()?;
        let memory = heap.memory_id();
        heap.with_heap(|heap_image| {
            context.with_image(|child_image| operation(child_image, heap_image, memory))
        }).flatten()
    }

    /// Borrows the child context's Theap capability before it is released.
    /// This is not available after the source Theap free transition.
    pub(crate) fn with_metadata_theap<R>(
        &mut self,
        operation: impl for<'theap> FnOnce(&'theap mut Theap) -> R,
    ) -> Option<R> {
        if self.stage != ChildMainHeapStage::HeapReady { return None; }
        self.context.with_lease(|mut lease| lease.with_metadata_theap(operation))
    }

    /// Initializes the source child main Heap against its parent-issued
    /// storage, then attaches the parent's metadata Theap and publishes its
    /// identity. This represents the creation suffix following the source
    /// registry and `_mi_heap_new_for_subproc` transitions.
    ///
    /// # Safety
    /// This child is registered, no child Heap/Theap initializer or user is
    /// concurrent, and the parent metadata engine is the same owner that
    /// issued both metadata capabilities.
    pub(crate) unsafe fn initialize_heap_and_metadata_theap(
        &mut self,
        config: MemoryConfig,
    ) -> Result<(), ChildMetadataTheapError> {
        if self.stage != ChildMainHeapStage::Registered || self.heap_storage.is_none() {
            return Err(ChildMetadataTheapError::Metadata(MetaError::InitializationRetained));
        }
        let parent = self.context.parent_subprocess;
        let parent_metadata = self.context.parent_metadata;
        let Self { context, heap_storage, .. } = self;
        let heap = heap_storage.as_mut().expect("checked child Heap allocation");
        let memory = heap.memory_id();
        let initialized = heap.with_heap(|mut heap_image| {
            context.with_image(|mut child_image| unsafe {
                heap_image.as_mut().initialize_child_main(child_image.as_mut(), memory)
            })
        }).flatten();
        match initialized {
            Some(Ok(())) => {}
            Some(Err(_)) => {
                self.stage = ChildMainHeapStage::Terminal;
                return Err(ChildMetadataTheapError::Metadata(MetaError::InitializationRetained));
            }
            None => return Err(ChildMetadataTheapError::Metadata(MetaError::InitializationRetained)),
        }
        let attached = heap.with_heap(|mut heap_image| {
            context.with_lease(|mut lease| {
                lease.with_metadata_theap(|theap| unsafe {
                    parent_metadata.initialize_child_metadata_theap(
                        config,
                        parent,
                        heap_image.as_mut().get_unchecked_mut(),
                        theap,
                    )
                })
            })
        }).flatten();
        match attached {
            Some(Ok(())) => {}
            Some(Err(error)) => {
                self.stage = ChildMainHeapStage::Terminal;
                return Err(error);
            }
            None => {
                self.stage = ChildMainHeapStage::Terminal;
                return Err(ChildMetadataTheapError::Metadata(MetaError::InitializationRetained));
            }
        }
        let Some(theap) = context.metadata_theap.as_ref()
            .and_then(MetaAllocation::dynamic_theap_pointer) else {
            self.stage = ChildMainHeapStage::Terminal;
            return Err(ChildMetadataTheapError::Metadata(MetaError::InitializationRetained));
        };
        let published = context.with_image(|child| unsafe {
            child.identity().publish_detached_metadata_theap(theap)
        }).unwrap_or(false);
        if !published {
            self.stage = ChildMainHeapStage::Terminal;
            return Err(ChildMetadataTheapError::Metadata(MetaError::InitializationRetained));
        }
        self.stage = ChildMainHeapStage::HeapReady;
        Ok(())
    }

    /// Removes this child from the source registry as the first destruction
    /// step. Any lock-release error is terminal because the list may already
    /// have changed.
    ///
    /// # Safety
    /// All child threads/users are quiescent and no concurrent registry or
    /// child operation can race terminal destruction.
    pub(crate) unsafe fn unlink_registry(
        &mut self,
        registry: &'static crate::subproc::registry::SourceSubprocessRegistry,
    ) -> Result<(), crate::subproc::registry::SourceSubprocessRegistryError> {
        if self.stage != ChildMainHeapStage::HeapReady {
            return Err(crate::subproc::registry::SourceSubprocessRegistryError::InvalidMembership);
        }
        let result = self.context.with_image(|child| unsafe {
            registry.unlink_child_terminal(child.as_ref().get_ref())
        }).unwrap_or(Err(crate::subproc::registry::SourceSubprocessRegistryError::InvalidMembership));
        self.stage = if result.is_ok() {
            ChildMainHeapStage::RegistryUnlinked
        } else {
            ChildMainHeapStage::Terminal
        };
        result
    }

    /// Detaches the child metadata Theap using the parent's actual detached
    /// TLD while the metadata-engine entry is held. The raw Theap pointer is
    /// obtained from its capability without retaining an `&mut Theap` across
    /// the raw intrusive-list mutation.
    ///
    /// # Safety
    /// Registry unlink succeeded, all child threads are quiescent, and the
    /// exact parent metadata engine is the allocator that attached this Theap.
    pub(crate) unsafe fn detach_metadata_theap(
        &mut self,
        parent_metadata: Pin<&'static MetaAllocator>,
        config: MemoryConfig,
    ) -> Result<(), ChildMetadataTheapError> {
        if self.stage != ChildMainHeapStage::RegistryUnlinked {
            return Err(ChildMetadataTheapError::Metadata(MetaError::InitializationRetained));
        }
        let parent = self.context.parent_subprocess;
        let Some(heap_storage) = self.heap_storage.as_mut() else {
            return Err(ChildMetadataTheapError::Metadata(MetaError::InitializationRetained));
        };
        let Some(metadata_theap) = self.context.metadata_theap.as_ref()
            .and_then(MetaAllocation::dynamic_theap_pointer) else {
            return Err(ChildMetadataTheapError::Metadata(MetaError::InitializationRetained));
        };
        let result = heap_storage.with_heap(|mut heap| unsafe {
            parent_metadata.detach_child_metadata_theap(
                config,
                parent,
                heap.as_mut().get_unchecked_mut(),
                metadata_theap,
            )
        }).unwrap_or(Err(ChildMetadataTheapError::Metadata(MetaError::InitializationRetained)));
        self.stage = if result.is_ok() {
            ChildMainHeapStage::TheapDetached
        } else {
            ChildMainHeapStage::Terminal
        };
        result
    }

    /// Releases the detached metadata-Theap allocation at the source point
    /// between `_mi_heap_free_theaps` and `mi_heap_free`.
    ///
    /// # Safety
    /// Registry unlink and TLD-first/Heap-list Theap detach both completed;
    /// no source identity observer remains. The Heap allocation stays live.
    pub(crate) unsafe fn release_metadata_theap_after_detach(
        &mut self,
    ) -> Result<(), ChildMainHeapReleaseError> {
        if self.stage != ChildMainHeapStage::TheapDetached {
            return Err(ChildMainHeapReleaseError::InvalidTransition);
        }
        let Some(heap) = self.heap_storage.as_ref() else {
            return Err(ChildMainHeapReleaseError::InvalidTransition);
        };
        let metadata_pointer = self.context.metadata_theap.as_ref()
            .and_then(MetaAllocation::dynamic_theap_pointer);
        let metadata_matches = metadata_pointer.is_some_and(|theap| {
            self.context.with_image(|child| {
                let identity = child.identity();
                identity.matches_published_detached_metadata_theap(theap)
                    && identity.matches_ready_main_heap(heap.pointer_for_identity())
            }).unwrap_or(false)
        });
        if !metadata_matches {
            return Err(ChildMainHeapReleaseError::InvalidTransition);
        }
        let Some(metadata_theap) = self.context.metadata_theap.as_mut() else {
            return Err(ChildMainHeapReleaseError::InvalidTransition);
        };
        // SAFETY: caller proves source-order detach and exclusive no-observer
        // teardown; this checks every TLD/Heap intrusive edge before free.
        if !unsafe { metadata_theap.is_unlinked_dynamic_theap() } {
            return Err(ChildMainHeapReleaseError::InvalidTransition);
        }
        if let Err(error) = self.context.parent_metadata.free(metadata_theap) {
            self.stage = ChildMainHeapStage::Terminal;
            return Err(ChildMainHeapReleaseError::Metadata(error));
        }
        self.context.metadata_theap = None;
        self.stage = ChildMainHeapStage::MetadataTheapReleased;
        Ok(())
    }

    /// Removes the child's Heap-list/count edge after the completed Theap
    /// teardown. Errors may follow counter/list mutation and terminalize the
    /// owner.
    ///
    /// # Safety
    /// Registry unlink and complete child Heap page teardown have already
    /// completed; no Heap-list observer can race this removal.
    pub(crate) unsafe fn unlink_child_heap(
        &mut self,
    ) -> Result<(), crate::types::heap_registry::SourceHeapRegistryError> {
        if self.stage != ChildMainHeapStage::MetadataTheapReleased {
            return Err(crate::types::heap_registry::SourceHeapRegistryError::InvalidImage);
        }
        // `with_child_heap` is intentionally restricted to HeapReady. Use
        // the same short projections internally at this later exact stage;
        // do not reopen the public child-use projection during teardown.
        let result = {
            let Self { context, heap_storage, .. } = self;
            heap_storage
                .as_mut()
                .and_then(|heap| {
                    heap.with_heap(|mut heap_image| {
                        context.with_image(|child_image| unsafe {
                            child_image.as_ref().get_ref().identity().heap_list().free_child_main(
                                heap_image.as_mut().get_unchecked_mut(),
                                child_image.as_ref().get_ref().identity(),
                            )
                        })
                    })
                })
                .flatten()
                .unwrap_or(Err(crate::types::heap_registry::SourceHeapRegistryError::InvalidImage))
        };
        match result {
            Ok(()) => { self.stage = ChildMainHeapStage::HeapListRemoved; Ok(()) }
            Err(error) => { self.stage = ChildMainHeapStage::Terminal; Err(error) }
        }
    }

    /// Completes the represented no-page source child teardown: free the
    /// parent-owned Heap image after its list edge is gone, clear the stale
    /// child metadata-Theap identity, then free the context allocation last.
    /// It does not implement source page or full Heap destruction.
    ///
    /// # Safety
    /// Every child client and page is gone; registry unlink, TLD-first Theap
    /// detach, metadata-Theap free, and Heap-list removal succeeded; all Heap
    /// projections ended; and the supplied current parent attachment is the
    /// exact allocator owner that minted this token.
    pub(crate) unsafe fn release_after_empty_heap_teardown<'tracking>(
        mut self,
        tracking: &'tracking mut [usize],
        heap_owner: &mut crate::main_heap_page::MainHeapThreadOwnerLocalPageEngine<'heap>,
        attachment: &mut crate::main_heap_thread::MainHeapThreadAttachment<'heap>,
    ) -> Result<(), ChildMainHeapReleaseFailure<'heap, 'tracking>> {
        if !matches!(self.stage, ChildMainHeapStage::HeapListRemoved | ChildMainHeapStage::ArenaBackingDestroyed) {
            return Err(ChildMainHeapReleaseFailure::Retained {
                owner: self,
                stage: ChildMainHeapReleaseStage::Validate,
                error: ChildMainHeapReleaseError::InvalidTransition,
            });
        }
        let heap_pointer = self.heap_storage.as_ref()
            .map(crate::main_heap_page::ParentHeapAllocation::pointer_for_identity);
        let matches = self.context.with_image(|child| {
            let identity = child.identity();
            identity.has_published_metadata_theap()
                && heap_pointer.is_some_and(|heap| identity.matches_ready_main_heap(heap))
        }).unwrap_or(false);
        if !matches {
            return Err(ChildMainHeapReleaseFailure::Retained {
                owner: self,
                stage: ChildMainHeapReleaseStage::Validate,
                error: ChildMainHeapReleaseError::InvalidTransition,
            });
        }
        if self.stage == ChildMainHeapStage::HeapListRemoved {
            let destroyed = self.context.with_image(|child| unsafe {
                child.identity().arena_backing().destroy_all(tracking)
            }).unwrap_or(Err(crate::arena::ArenaDestroyError::InvalidOwnership));
            match destroyed {
                Err(error) => {
                    return Err(ChildMainHeapReleaseFailure::Retained {
                        owner: self,
                        stage: ChildMainHeapReleaseStage::ArenaBacking,
                        error: ChildMainHeapReleaseError::ArenaDestroy(error),
                    });
                }
                Ok(destroyed) if !destroyed.is_released() => {
                    return Err(ChildMainHeapReleaseFailure::ArenaBacking { owner: self, destroyed });
                }
                Ok(destroyed) => {
                    drop(destroyed);
                    self.stage = ChildMainHeapStage::ArenaBackingDestroyed;
                }
            }
        }
        let allocation = self.heap_storage.take().expect("validated child Heap capability");
        match unsafe { heap_owner.release_child_heap_storage_after_teardown(attachment, allocation) } {
            Ok(()) => {}
            Err(crate::main_heap_page::ParentHeapAllocationReleaseFailure::Retained { allocation, error }) => {
                self.heap_storage = Some(allocation);
                return Err(ChildMainHeapReleaseFailure::Retained {
                    owner: self,
                    stage: ChildMainHeapReleaseStage::ParentHeap,
                    error: ChildMainHeapReleaseError::ParentHeap(error),
                });
            }
            Err(crate::main_heap_page::ParentHeapAllocationReleaseFailure::Terminal(allocation)) => {
                self.stage = ChildMainHeapStage::Terminal;
                return Err(ChildMainHeapReleaseFailure::Terminal { owner: self, allocation });
            }
        }
        self.context.with_image(|child| unsafe {
            child.identity().clear_metadata_identity_terminal();
        });
        if let Err(error) = self.context.parent_metadata.free(&mut self.context.context) {
            self.stage = ChildMainHeapStage::Terminal;
            return Err(ChildMainHeapReleaseFailure::Retained {
                owner: self,
                stage: ChildMainHeapReleaseStage::Context,
                error: ChildMainHeapReleaseError::Metadata(error),
            });
        }
        Ok(())
    }
}

impl<'heap, 'tracking> ChildMainHeapReleaseFailure<'heap, 'tracking> {
    /// Retries raw unmaps retained by the completed child arena teardown.
    /// The parent-issued context and its child identity stay inside this
    /// failure value until every transferred raw release succeeds.
    pub(crate) fn retry_arena_backing(
        self,
    ) -> Result<ChildMainHeapContextOwner<'heap>, Self> {
        let Self::ArenaBacking { mut owner, mut destroyed } = self else {
            return Err(self);
        };
        if destroyed.retry_raw().is_err() || !destroyed.is_released() {
            return Err(Self::ArenaBacking { owner, destroyed });
        }
        owner.stage = ChildMainHeapStage::ArenaBackingDestroyed;
        drop(destroyed);
        Ok(owner)
    }
}

impl ChildContextLease<'_> {
    #[inline]
    pub(crate) const fn context_memory_id(&self) -> MemoryId {
        self.owner.context.memory_id()
    }

    #[inline]
    pub(crate) fn with_image<R>(
        &mut self,
        operation: impl for<'image> FnOnce(
            Pin<&'image mut crate::subproc::ChildSubprocessImage>,
        ) -> R,
    ) -> Option<R> {
        if self.owner.terminal { return None; }
        let image = self
            .owner
            .context
            .child_subprocess_image_mut()?;
        Some(operation(image))
    }

    #[inline]
    pub(crate) fn with_metadata_theap<R>(
        &mut self,
        operation: impl for<'theap> FnOnce(&'theap mut Theap) -> R,
    ) -> Option<R> {
        if self.owner.terminal { return None; }
        self.owner
            .metadata_theap
            .as_mut()
            .and_then(MetaAllocation::dynamic_theap_mut)
            .map(operation)
    }

    #[inline]
    pub(crate) const fn parent_subprocess(&self) -> &'static MainSubprocess {
        self.owner.parent_subprocess
    }
}

#[must_use = "a failed child context release retains its exact owner"]
pub(crate) struct ChildContextReleaseFailure {
    pub(crate) owner: ChildContextOwner,
    pub(crate) stage: ChildContextCreateStage,
    pub(crate) error: MetaError,
}

#[derive(Clone, Copy)]
struct MetadataProcessBacking {
    binding: crate::process_init::ProcessMainBackingBinding,
    page_map: &'static PageMap,
}

/// Legacy explicit-config callers remain visibly separate until their
/// process coordinator supplies the real pair/map. The selected production
/// path never obtains capacity by enlarging that legacy private arena.
enum MetadataPageAllocator<'owner> {
    LegacySelectedArena(SingleThreadAllocator<'owner, 'static, 'static>),
    Process(ProcessMetadataPageAllocator<'owner, 'static>),
    CanonicalProcess(CanonicalProcessMetadataPageAllocator<'static>),
}

impl MetadataPageAllocator<'_> {
    unsafe fn initialize_child_metadata_theap(
        &mut self,
        parent: &'static MainSubprocess,
        child_heap: &mut Heap,
        child_theap: &mut Theap,
    ) -> Result<(), crate::types::TheapMainStaticInitError> {
        match self {
            Self::LegacySelectedArena(engine) => unsafe {
                engine.initialize_child_metadata_theap(parent, child_heap, child_theap)
            },
            Self::Process(engine) => unsafe {
                engine.initialize_child_metadata_theap(parent, child_heap, child_theap)
            },
            Self::CanonicalProcess(engine) => unsafe {
                engine.initialize_child_metadata_theap(child_heap, child_theap)
            },
        }
    }

    unsafe fn detach_child_metadata_theap(
        &mut self,
        parent: &'static MainSubprocess,
        child_heap: &mut Heap,
        child_theap: NonNull<Theap>,
    ) -> Result<(), crate::types::ChildTheapDetachError> {
        match self {
            Self::LegacySelectedArena(engine) => unsafe {
                engine.detach_child_metadata_theap(parent, child_heap, child_theap)
            },
            Self::Process(engine) => unsafe {
                engine.detach_child_metadata_theap(parent, child_heap, child_theap)
            },
            Self::CanonicalProcess(engine) => unsafe {
                engine.detach_child_metadata_theap(child_heap, child_theap)
            },
        }
    }

    unsafe fn retire_process_quiescent(self) -> Result<(), Self> {
        match self {
            Self::Process(engine) => unsafe { engine.retire_process_metadata_quiescent() }
                .map_err(Self::Process),
            Self::CanonicalProcess(engine) => unsafe { engine.retire_process_metadata_quiescent() }
                .map_err(Self::CanonicalProcess),
            other => Err(other),
        }
    }

    fn allocate_zeroed(&mut self, size: usize) -> Option<NonNull<u8>> {
        match self { Self::LegacySelectedArena(engine) => engine.allocate_zeroed(size),
            Self::Process(engine) => engine.allocate_zeroed(size),
            Self::CanonicalProcess(engine) => engine.allocate_zeroed(size) }
    }
    fn allocate_aligned_zeroed(&mut self, size: usize, alignment: usize) -> Option<NonNull<u8>> {
        match self { Self::LegacySelectedArena(engine) => engine.allocate_aligned_zeroed(size, alignment),
            Self::Process(engine) => engine.allocate_aligned_zeroed(size, alignment),
            Self::CanonicalProcess(engine) => engine.allocate_aligned_zeroed(size, alignment) }
    }
    unsafe fn usable_size(&self, pointer: NonNull<u8>) -> Option<usize> {
        match self { Self::LegacySelectedArena(engine) => unsafe { engine.usable_size(pointer) },
            Self::Process(engine) => unsafe { engine.usable_size(pointer) },
            Self::CanonicalProcess(engine) => unsafe { engine.usable_size(pointer) } }
    }
    unsafe fn free(&mut self, pointer: NonNull<u8>) -> Result<(), FreeError> {
        match self { Self::LegacySelectedArena(engine) => unsafe { engine.free(pointer) },
            Self::Process(engine) => unsafe { engine.free(pointer) },
            Self::CanonicalProcess(engine) => unsafe { engine.free(pointer) } }
    }
}

/// Exact reason why terminal metadata engine retirement retained its owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MetaCloseError {
    Entry(MetaError),
    NotProcessBacking,
    UnfinishedEngine,
}

/// Read-only test audit of caller-visible metadata capabilities.
///
/// This deliberately counts only live [`MetaAllocation`] capabilities, not
/// the detached allocator's own permanent bootstrap mapping or a raw block
/// inside its reusable page. It lets lifecycle regressions prove that repeated
/// TLD/Theap construction returns every explicit metadata capability and that
/// the maximum concurrent capability count plateaus after warmup.
#[cfg(any(test, feature = "native-runtime-test-audit"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MetaAllocationAudit {
    pub(crate) live_capability_count: usize,
    pub(crate) high_water_capability_count: usize,
}

/// An opaque binding witness for the detached source metadata route.
///
/// It intentionally exposes neither the metadata PageMap nor its private
/// arena/registry. `mi_process_theap_meta` is initialized while forming the
/// source main Heap, before the source process-global PageMap and before any
/// first metadata allocation. It is not a candidate
/// `ProcessPageArenaLease` backing.
#[derive(Clone, Copy)]
pub(crate) struct MetaAllocatorBound<'owner> {
    allocator: Pin<&'owner MetadataEngine<'owner>>,
    config: MemoryConfig,
    subprocess: &'static MainSubprocess,
}

impl<'owner> MetaAllocatorBound<'owner> {
    #[inline]
    pub(crate) const fn subprocess(self) -> &'static MainSubprocess {
        self.subprocess
    }

    #[inline]
    pub(crate) const fn memory_config(self) -> MemoryConfig {
        self.config
    }

    #[inline]
    pub(crate) fn matches(self, allocator: Pin<&MetadataEngine<'owner>>) -> bool {
        core::ptr::eq(self.allocator.get_ref(), allocator.get_ref())
    }
}

// SAFETY: no safe method exposes a reference into an uninitialized slot. Once
// ready, every mutable access to the allocator/page-map/theap happens under
// `lock`; the process-lived mapping pins all raw targets. `registry` uses its
// own source atomics but is initialized and thereafter reached only beneath
// this same metadata lock in this bounded owner.
unsafe impl Sync for MetaAllocator {}

impl<'owner> MetadataEngine<'owner> {
    pub(crate) const fn new() -> Self {
        Self {
            lock: PrivateLock::new(),
            active_entry_thread: AtomicUsize::new(0),
            status: AtomicU8::new(COLD),
            config: UnsafeCell::new(MaybeUninit::uninit()),
            mapping: UnsafeCell::new(MaybeUninit::uninit()),
            page_map: UnsafeCell::new(MaybeUninit::uninit()),
            retained_page_map_initialization_mapping: UnsafeCell::new(MaybeUninit::uninit()),
            has_retained_page_map_initialization_mapping: AtomicBool::new(false),
            bootstrap: UnsafeCell::new(MaybeUninit::uninit()),
            allocator: UnsafeCell::new(MaybeUninit::uninit()),
            process_backing: UnsafeCell::new(None),
            canonical_heap: UnsafeCell::new(None),
            subprocess: AtomicPtr::new(core::ptr::null_mut()),
            detached_metadata_theap: AtomicPtr::new(core::ptr::null_mut()),
            #[cfg(test)]
            test_default_subprocess: AtomicPtr::new(core::ptr::null_mut()),
            registry: ArenaRegistry::new(core::ptr::null_mut()),
            #[cfg(test)]
            fail_next_direct_zeroed_size: AtomicUsize::new(0),
            #[cfg(test)]
            fail_next_rezalloc_size: AtomicUsize::new(0),
            #[cfg(test)]
            fail_next_aligned_zeroed_size: AtomicUsize::new(0),
            #[cfg(test)]
            fail_aligned_zeroed_size_attempts: AtomicUsize::new(0),
            #[cfg(test)]
            test_entry_attempt_count: AtomicUsize::new(0),
            #[cfg(any(test, feature = "native-runtime-test-audit"))]
            test_live_allocation_count: AtomicUsize::new(0),
            #[cfg(any(test, feature = "native-runtime-test-audit"))]
            test_allocation_high_water: AtomicUsize::new(0),
            _pin: PhantomPinned,
        }
    }

    /// Returns the one process metadata owner. Runtime integration supplies a
    /// frozen [`MemoryConfig`] before its first allocation; this accessor does
    /// not itself discover a page size or touch TLS.
    #[inline]
    pub(crate) fn global() -> Pin<&'static Self> {
        MainSubprocess::global().metadata_allocator()
    }

    #[cfg(not(test))]
    #[inline]
    fn default_subprocess(self: Pin<&'owner Self>) -> &'static MainSubprocess {
        let _ = self;
        MainSubprocess::global()
    }

    #[cfg(test)]
    #[inline]
    fn default_subprocess(self: Pin<&'owner Self>) -> &'static MainSubprocess {
        let pointer = self
            .get_ref()
            .test_default_subprocess
            .load(Ordering::Acquire);
        let Some(pointer) = NonNull::new(pointer) else {
            return MainSubprocess::global();
        };
        // SAFETY: `test_static_owner` stores exactly one separately leaked
        // subprocess before returning this metadata fixture and never
        // replaces it. The production singleton retains the null sentinel and
        // takes the process-global branch above instead.
        unsafe { pointer.as_ref() }
    }

    /// Builds an isolated process-lifetime owner for tests that must inject a
    /// first-allocation failure without depending on singleton test ordering.
    /// Production lifecycle code must use [`Self::global`] exclusively.
    #[cfg(test)]
    pub(crate) fn test_static_owner() -> Pin<&'static Self> {
        let owner: &'static MetaAllocator =
            std::boxed::Box::leak(std::boxed::Box::new(MetaAllocator::new()));
        let subprocess = MainSubprocess::test_static_owner();
        owner
            .test_default_subprocess
            .store(subprocess.owner_ptr(), Ordering::Release);
        // SAFETY: the deliberately leaked test fixture has a process-lifetime
        // address, and its test-only default subprocess is separately leaked
        // before this owner is returned. That matches the static-reference
        // requirement of its detached page-map/bootstrap/allocator slots
        // without sharing another fixture's one-way source publication slot.
        unsafe { Pin::new_unchecked(owner) }
    }

    /// Returns this test fixture's isolated source-main identity. It exposes
    /// no metadata or Theap capability and exists only so an explicit
    /// test-only caller can keep its allocator/subprocess pair coherent.
    #[cfg(test)]
    #[inline]
    pub(crate) fn test_default_subprocess(
        self: Pin<&'static Self>,
    ) -> &'static MainSubprocess {
        self.default_subprocess()
    }

    /// Observes only whether this detached metadata owner bound one exact
    /// process tuple. It deliberately exposes no allocator/map capability and
    /// is used to prove process-startup ordering in isolated regressions.
    #[cfg(test)]
    pub(crate) fn test_is_bound_for(
        self: Pin<&'static Self>,
        config: MemoryConfig,
        subprocess: &'static MainSubprocess,
    ) -> bool {
        let Ok(entry) = self.enter() else {
            return false;
        };
        let this = self.get_ref();
        if !matches!(entry.status(), BOUND | READY) {
            return false;
        }
        // SAFETY: BOUND Release-publishes this immutable final slot before the
        // held private lock observes it. READY retains that same tuple. The
        // same lock excludes the mutable detached session from racing this
        // bootstrap-image observation.
        let stored_config = unsafe { *(*this.config.get()).assume_init_ref() };
        stored_config == config
            && core::ptr::eq(this.subprocess.load(Ordering::Acquire), subprocess.identity_ptr())
            && self
                .validate_bound_detached_metadata_theap(subprocess)
                .is_ok()
    }

    /// Test-only observation of the PageMap bootstrap mapping retained before
    /// this metadata allocator formed any PageMap or arena owner.
    #[cfg(test)]
    pub(crate) fn test_has_retained_page_map_initialization_mapping(
        self: Pin<&'static Self>,
    ) -> bool {
        self.get_ref()
            .has_retained_page_map_initialization_mapping
            .load(Ordering::Acquire)
    }

    /// Releases the exact retained bootstrap mapping after a test removes its
    /// injected cleanup fault. A failed retry puts the same live owner back.
    #[cfg(test)]
    pub(crate) fn test_release_retained_page_map_initialization_mapping(
        self: Pin<&'static Self>,
    ) -> Result<(), Errno> {
        let this = self.get_ref();
        let guard = this.lock.lock()?;
        if !this
            .has_retained_page_map_initialization_mapping
            .load(Ordering::Acquire)
        {
            return match guard.unlock() {
                Ok(()) => Err(Errno::INVAL),
                Err(error) => Err(error),
            };
        }
        // SAFETY: this private lock serializes retained-slot access, and the
        // Acquire flag follows the initialization path's final-slot write.
        let mut mapping = unsafe {
            (*this.retained_page_map_initialization_mapping.get()).assume_init_read()
        };
        let release = match mapping.unmap() {
            Ok(()) => {
                this.has_retained_page_map_initialization_mapping
                    .store(false, Ordering::Release);
                Ok(())
            }
            Err(error) => {
                // SAFETY: failed `unmap` preserves this exact Mapping, and
                // the private lock still excludes another retained owner.
                unsafe { this.write_retained_page_map_initialization_mapping(mapping) };
                Err(error)
            }
        };
        let unlock = guard.unlock();
        match (release, unlock) {
            (Err(error), _) => Err(error),
            (Ok(()), Err(error)) => Err(error),
            (Ok(()), Ok(())) => Ok(()),
        }
    }

    /// Returns the final private PageMap slot address after first metadata
    /// backing readiness without turning it into a usable map reference. This
    /// proves process startup did not take that backing and that the
    /// process-global map stays a distinct owner.
    #[cfg(test)]
    pub(crate) fn test_private_page_map_address(self: Pin<&'static Self>) -> Option<usize> {
        let this = self.get_ref();
        if this.status.load(Ordering::Acquire) != READY { return None; }
        // READY publishes the final backing selection; neither binding nor
        // engine initialization can mutate it after this acquire observation.
        unsafe { (*this.process_backing.get()).is_none() }.then(|| this.page_map.get().addr())
    }

    /// Returns the capability-level metadata lifetime audit used by bounded
    /// worker-churn regressions. The atomics are diagnostic only: they grant
    /// no dereference, allocation, or release authority.
    #[cfg(any(test, feature = "native-runtime-test-audit"))]
    #[inline]
    pub(crate) fn test_allocation_audit(self: Pin<&'static Self>) -> MetaAllocationAudit {
        let this = self.get_ref();
        MetaAllocationAudit {
            live_capability_count: this.test_live_allocation_count.load(Ordering::Acquire),
            high_water_capability_count: this.test_allocation_high_water.load(Ordering::Acquire),
        }
    }

    /// Returns how often a test reached the metadata private-lock entry
    /// boundary. This exposes no lock capability and lets the source-shaped
    /// `theap_meta` regression prove rejection occurs before C's lock site.
    #[cfg(test)]
    #[inline]
    pub(crate) fn test_entry_attempt_count(self: Pin<&'static Self>) -> usize {
        self.get_ref().test_entry_attempt_count.load(Ordering::Acquire)
    }

    /// Runs one test operation while this allocator's backing entry is held.
    ///
    /// This keeps the private entry guard unobservable while letting a
    /// caller-level regression exercise the same-thread rejection that occurs
    /// before an exact-owner Malloc release can claim its capability. It is
    /// deliberately test-only: production callers must never receive or
    /// manufacture a metadata-entry capability.
    #[cfg(test)]
    pub(crate) fn test_with_held_backing_entry<R>(
        self: Pin<&'static Self>,
        operation: impl FnOnce() -> R,
    ) -> Result<R, MetaError> {
        let entry = self.enter()?;
        let result = operation();
        drop(entry);
        Ok(result)
    }

    /// Binds the detached metadata Theap/image for one selected source main
    /// subprocess without allocating a caller-visible metadata block or its
    /// backing. This is the source `mi_process_theap_meta` ordering seam used
    /// by process initialization. The policy-bound path subsequently calls
    /// `bind_process_backing` with the real shared map; historical explicit-
    /// config callers retain their separate selected-arena backing. Neither
    /// path takes its first page before a metadata caller requests one.
    pub(crate) fn prepare_for_main_subprocess(
        self: Pin<&'owner Self>,
        config: MemoryConfig,
        subprocess: &'static MainSubprocess,
    ) -> Result<MetaAllocatorBound<'owner>, MetaError> {
        if !subprocess.is_process_main() {
            return Err(MetaError::SubprocessMismatch);
        }
        let mut entry = self.enter()?;
        entry.ensure_bound(config, subprocess)?;
        Ok(MetaAllocatorBound {
            allocator: self,
            config,
            subprocess,
        })
    }

    /// Source process-done metadata-Theap merge, before the default Theap and
    /// main Heap merge. Entry and source metadata locks exclude metadata
    /// engine mutation; the nested canonical Heap lock scopes only fieldwise
    /// statistics access. Every lock ends before final output can call libc.
    pub(crate) fn merge_process_done_metadata_statistics(
        self: Pin<&'static Self>, subprocess: &'static MainSubprocess,
    ) -> Result<(), MetaError> {
        let _entry = self.enter_for_main_subprocess(subprocess)?;
        self.validate_bound_detached_metadata_theap(subprocess)?;
        let heap = unsafe { *self.get_ref().canonical_heap.get() }
            .ok_or(MetaError::InitializationRetained)?;
        let pointer = NonNull::new(self.get_ref().detached_metadata_theap.load(Ordering::Acquire))
            .ok_or(MetaError::InitializationRetained)?;
        heap.with_heap(|canonical| {
            // SAFETY: canonical binding and metadata entry retain the exact
            // source member; with_heap owns its Heap lock through this merge.
            unsafe { canonical.merge_attached_theap_statistics_at(pointer); }
        }).map_err(|_| MetaError::InitializationRetained)
    }

    #[cfg(test)]
    pub(crate) fn test_canonical_metadata_heap_membership(self: Pin<&'static Self>) -> bool {
        let Ok(_entry) = self.enter() else { return false; };
        let Some(heap) = (unsafe { *self.get_ref().canonical_heap.get() }) else { return false; };
        let pointer = self.get_ref().detached_metadata_theap.load(Ordering::Acquire);
        heap.with_heap(|canonical| {
            !pointer.is_null()
                && core::ptr::eq(unsafe { (*pointer).heap() }, core::ptr::from_mut(canonical))
                && canonical.has_shared_theap_member_blocking(pointer) == Ok(true)
        }) == Ok(true)
    }

    /// Binds the actual source static metadata Theap to the startup-selected
    /// canonical main Heap before metadata allocation can begin.
    pub(crate) fn prepare_for_main_heap(
        self: Pin<&'owner Self>, config: MemoryConfig, subprocess: &'static MainSubprocess,
        foundation: crate::main_theap::MainStaticHeapFoundation,
    ) -> Result<MetaAllocatorBound<'owner>, MetaError> {
        if !core::ptr::eq(foundation.subprocess(), subprocess) { return Err(MetaError::SubprocessMismatch); }
        let mut entry = self.enter()?;
        if entry.status() != COLD { return Err(MetaError::BackingAlreadySelected); }
        // Startup owns the final source image; no prior metadata allocation
        // or source identity is silently migrated to the canonical Heap.
        unsafe { *self.get_ref().canonical_heap.get() = Some(foundation.metadata_heap()); }
        entry.ensure_bound(config, subprocess)?;
        Ok(MetaAllocatorBound { allocator: self, config, subprocess })
    }

    /// Permanently seals the metadata allocation boundary and ends the
    /// process engine's exclusive bootstrap and shared PageMap borrows.
    ///
    /// This is the Rust ownership prerequisite for `subproc.c`'s destruction
    /// after main-Heap Theap retirement and before clearing `theap_meta` and
    /// releasing arenas. It does not perform those later source transitions.
    /// Live TLD capabilities remain external obligations; their safe typed
    /// projections reject after sealing. Static bootstrap source page images
    /// remain in this pinned owner. In particular, direct OS pages are not
    /// falsely claimed to have been released by arena bulk destruction.
    ///
    /// An unfinished engine remains in its exact slot under CLOSE_RETAINED;
    /// no partially consumed ownership is discarded and entry never reopens.
    ///
    /// # Safety
    ///
    /// The caller has permanently stopped every metadata user and all page
    /// readers, ended every previously returned typed reference, and sealed
    /// every runtime admission path. All live metadata capabilities must be
    /// retained outside backing that will be released. Ending this engine's
    /// borrows does not revoke any external reference. The caller must retain
    /// this pinned owner, the process, and all backing on failure, and must
    /// separately retire the detached bootstrap image before physical release.
    pub(crate) unsafe fn close_process_engine_quiescent(
        self: Pin<&'static Self>,
    ) -> Result<(), MetaCloseError> {
        let entry = self.enter().map_err(MetaCloseError::Entry)?;
        let this = self.get_ref();
        let status = entry.status();
        // SAFETY: permanent caller quiescence and the backing entry exclude
        // every observation of these process-owned mutable slots.
        if !matches!(status, BOUND | READY)
            || unsafe { (*this.process_backing.get()).is_none() }
        {
            return Err(MetaCloseError::NotProcessBacking);
        }
        this.status.store(CLOSE_RETAINED, Ordering::Release);
        if status == READY {
            let allocator = unsafe { (*this.allocator.get()).assume_init_read() };
            // SAFETY: permanent process quiescence ends only engine-held
            // session/Map authority and retains all represented source pages.
            if let Err(allocator) = unsafe { allocator.retire_process_quiescent() } {
                unsafe { (*this.allocator.get()).write(allocator); }
                return Err(MetaCloseError::UnfinishedEngine);
            }
        }
        unsafe { *this.process_backing.get() = None; }
        this.status.store(CLOSED, Ordering::Release);
        Ok(())
    }

    /// Selects the actual process VM/arena owner and shared PageMap after
    /// source detached-Theap identity publication but before first metadata
    /// demand. A later identical binding is idempotent; changing either
    /// identity or migrating an already active private engine is rejected.
    /// The coordinator-issued capability proves that the policy and PageMap
    /// root were selected together; raw copyable pair/map witnesses are not
    /// accepted at this safe boundary.
    /// All resulting engine operations remain under the metadata lock and
    /// own disjoint PageMap ranges until their aliases/pages are retired.
    pub(crate) fn bind_process_backing(
        self: Pin<&'static Self>, binding: crate::process_init::ProcessMainBackingBinding,
    ) -> Result<(), MetaError> {
        if !binding.is_active() { return Err(MetaError::InitializationRetained); }
        let process = binding.process();
        let page_map = binding.page_map();
        if !core::ptr::eq(
            page_map.subprocess().map_err(|_| MetaError::InitializationFailed)?.identity_ptr(),
            process.subprocess().as_ptr(),
        ) {
            return Err(MetaError::SubprocessMismatch);
        }
        let config = page_map.memory_config().map_err(|_| MetaError::InitializationFailed)?;
        let mut entry = self.enter()?;
        entry.ensure_bound(
            config,
            process.main_subprocess().ok_or(MetaError::SubprocessMismatch)?,
        )?;
        // SAFETY: this owner creates only disjoint fresh page ranges and
        // serializes their map accesses and terminal removals under `entry`.
        // The retained process lease excludes safe root replacement.
        let map = unsafe { page_map.page_map_for_owned_ranges() }.map_err(|_| MetaError::InitializationFailed)?;
        let slot = self.get_ref().process_backing.get();
        // Once READY is published, read-only witnesses may inspect this
        // immutable selection. Even idempotent rebinding must not create a
        // whole-slot mutable reference that overlaps those observations.
        if let Some(selected) = unsafe { *slot } {
            return if core::ptr::eq(selected.binding.process().policy(), process.policy())
                && core::ptr::eq(selected.page_map, map) { Ok(()) }
                else { Err(MetaError::BackingAlreadySelected) };
        }
        if entry.status() != BOUND { return Err(MetaError::BackingAlreadySelected); }
        if !process.subprocess().arena_backing().matches_existing_process_binding(process, config)
            .map_err(MetaError::Lock)? { return Err(MetaError::BackingAlreadySelected); }
        unsafe { *slot = Some(MetadataProcessBacking { binding, page_map: map }); }
        Ok(())
    }

    /// Initializes one already allocated child metadata Theap against the
    /// exact detached TLD owned by this parent metadata engine.
    ///
    /// The engine entry is held while `ExclusiveTheapBootstrap` lends its
    /// TLD to the source `_mi_theap_init` transition. The operation cannot
    /// escape a TLD reference or recurse into metadata allocation.
    ///
    /// # Safety
    /// `child_heap` and `child_theap` must be pinned in stable storage until
    /// both resulting list memberships are removed. `child_theap` must name
    /// the still-live exact parent `MetaAllocation`; the caller excludes all
    /// concurrent child Heap/Theap lifecycle operations.
    /// An initialization error may follow TLD-list attachment and Release
    /// publication, so retain the child owner and do not retry from the error
    /// alone.
    pub(crate) unsafe fn initialize_child_metadata_theap(
        self: Pin<&Self>,
        config: MemoryConfig,
        parent: &'static MainSubprocess,
        child_heap: &mut Heap,
        child_theap: &mut Theap,
    ) -> Result<(), ChildMetadataTheapError> {
        let mut entry = self.enter().map_err(ChildMetadataTheapError::Metadata)?;
        entry
            .ensure_existing_ready(config, parent)
            .map_err(ChildMetadataTheapError::Metadata)?;
        // SAFETY: `allocator()` mutably borrows the existing page session
        // stored inside the engine. It never reprojects the bootstrap from
        // `MetadataEngine::bootstrap`; the session retains the sole pin.
        unsafe {
            entry
                .allocator()
                .initialize_child_metadata_theap(parent, child_heap, child_theap)
        }
        .map_err(ChildMetadataTheapError::Theap)
    }

    /// Detaches a child metadata Theap from the child Heap and actual parent
    /// metadata TLD while the owning engine entry excludes all other metadata
    /// projections. The linear allocation must be released separately only
    /// after this source-ordered unlink succeeds.
    ///
    /// # Safety
    /// The caller has exclusive teardown authority over the pinned child
    /// Heap and Theap, no child clients or producers remain, and the exact
    /// metadata allocation stays live until this operation succeeds. Any
    /// Rust reference or typed projection to the child Theap must have ended
    /// before calling: this transition mutates that image through `child_theap`
    /// while holding its intrusive-list locks. Reborrow it from the still-live
    /// `MetaAllocation` only after this method returns. Any
    /// error retains both child images and their allocation capabilities. A
    /// `TheapList` error identifies the unlink stage, but that stage may have
    /// mutated its list before reporting an unlock error. Keep the child owner
    /// terminally retained; this combined operation is not retryable from the
    /// error alone.
    pub(crate) unsafe fn detach_child_metadata_theap(
        self: Pin<&Self>,
        config: MemoryConfig,
        parent: &'static MainSubprocess,
        child_heap: &mut Heap,
        child_theap: NonNull<Theap>,
    ) -> Result<(), ChildMetadataTheapError> {
        let mut entry = self.enter().map_err(ChildMetadataTheapError::Metadata)?;
        entry
            .ensure_existing_ready(config, parent)
            .map_err(ChildMetadataTheapError::Metadata)?;
        // SAFETY: `allocator()` mutably borrows the existing page session and
        // its single Theap/TLD projection; the engine entry stays live for
        // both source unlink steps.
        unsafe {
            entry
                .allocator()
                .detach_child_metadata_theap(parent, child_heap, child_theap)
        }
        .map_err(ChildMetadataTheapError::TheapList)
    }

    /// Allocates zeroed metadata through the detached source theap.
    pub(crate) fn zalloc(
        self: Pin<&'owner Self>,
        config: MemoryConfig,
        size: usize,
    ) -> Result<MetaAllocation<'owner>, MetaError> {
        self.zalloc_for_main_subprocess(config, self.default_subprocess(), size)
    }

    /// Allocates zeroed metadata for one already selected process-main
    /// identity. `ThreadLocalDataOwner` calls this only after its source
    /// total-thread ticket is issued; an initialization/map failure therefore
    /// cannot roll that sequence back or create a live-count lease.
    pub(crate) fn zalloc_for_main_subprocess(
        self: Pin<&'owner Self>,
        config: MemoryConfig,
        subprocess: &'static MainSubprocess,
        size: usize,
    ) -> Result<MetaAllocation<'owner>, MetaError> {
        self.require_published_detached_metadata_theap(subprocess)?;
        let mut entry = self.enter_for_main_subprocess(subprocess)?;
        entry.ensure_ready(config, subprocess)?;
        #[cfg(test)]
        if size != 0
            && self
                .fail_next_direct_zeroed_size
                .compare_exchange(size, 0, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            return Err(MetaError::AllocationUnavailable);
        }
        let pointer = entry
            .allocator()
            .allocate_zeroed(size)
            .ok_or(MetaError::AllocationUnavailable)?;
        let allocation = MetaAllocation::new(
            self,
            pointer,
            size,
            MetaAllocationOrigin::DirectZeroed,
        );
        #[cfg(any(test, feature = "native-runtime-test-audit"))]
        self.get_ref().test_note_allocation_created();
        Ok(allocation)
    }

    /// Makes one test-only direct-zeroed request of exactly `size` fail after
    /// the detached owner is ready. This isolates a later lifecycle
    /// allocation edge without pretending that the source metadata allocator
    /// has a production per-request fault policy.
    #[cfg(test)]
    #[inline]
    pub(crate) fn test_fail_next_direct_zeroed_size(&self, size: usize) {
        assert_ne!(size, 0);
        self.fail_next_direct_zeroed_size.store(size, Ordering::Release);
    }

    /// Makes one exact `_mi_meta_rezalloc` replacement request fail after its
    /// old capability has entered the source-shaped moving state. The failure
    /// path must restore that old capability before it returns; this is a
    /// narrow test seam, not a production metadata fault policy.
    #[cfg(test)]
    #[inline]
    pub(crate) fn test_fail_next_rezalloc_size(&self, size: usize) {
        assert_ne!(size, 0);
        self.fail_next_rezalloc_size.store(size, Ordering::Release);
    }

    /// Makes one exact aligned-zeroed metadata request fail in an isolated
    /// test. This remains narrower than an allocator policy: it only proves
    /// a caller's pre-publication ownership branch.
    #[cfg(test)]
    #[inline]
    pub(crate) fn test_fail_next_aligned_zeroed_size(&self, size: usize) {
        self.test_fail_aligned_zeroed_size_attempts(size, 1);
    }

    /// Makes the next `attempts` exact aligned-zeroed metadata requests fail.
    ///
    /// The counted plan is needed when the public allocation boundary follows
    /// pinned `mi_malloc_generic_fallback`: it force-collects and retries one
    /// source OOM result before it can report allocation failure. It models no
    /// production retry policy and is consumed only by a matching request.
    #[cfg(test)]
    #[inline]
    pub(crate) fn test_fail_aligned_zeroed_size_attempts(&self, size: usize, attempts: usize) {
        assert_ne!(size, 0);
        assert_ne!(attempts, 0);
        assert_eq!(
            self.fail_aligned_zeroed_size_attempts.load(Ordering::Acquire),
            0,
            "one metadata fixture owns the selected aligned-zeroed fault plan"
        );
        self.fail_next_aligned_zeroed_size.store(size, Ordering::Release);
        self.fail_aligned_zeroed_size_attempts
            .store(attempts, Ordering::Release);
    }

    /// Allocates zeroed metadata with the source alignment contract.
    pub(crate) fn zalloc_aligned(
        self: Pin<&'owner Self>,
        config: MemoryConfig,
        size: usize,
        alignment: usize,
    ) -> Result<MetaAllocation<'owner>, MetaError> {
        self.zalloc_aligned_for_main_subprocess(config, self.default_subprocess(), size, alignment)
    }

    /// Allocates zeroed aligned metadata for the selected process-main
    /// identity. The process-global TLS-key registry uses this exact route so
    /// its bitmap stays allocator metadata owned by the main subprocess even
    /// if future callers acquire keys while attached somewhere else.
    pub(crate) fn zalloc_aligned_for_main_subprocess(
        self: Pin<&'owner Self>,
        config: MemoryConfig,
        subprocess: &'static MainSubprocess,
        size: usize,
        alignment: usize,
    ) -> Result<MetaAllocation<'owner>, MetaError> {
        if !size_class::alignment_is_valid(alignment) {
            return Err(MetaError::InvalidAlignment);
        }
        self.require_published_detached_metadata_theap(subprocess)?;
        let mut entry = self.enter_for_main_subprocess(subprocess)?;
        entry.ensure_ready(config, subprocess)?;
        #[cfg(test)]
        if size != 0 && self.fail_next_aligned_zeroed_size.load(Ordering::Acquire) == size {
            let attempts = self.fail_aligned_zeroed_size_attempts.fetch_update(
                Ordering::AcqRel,
                Ordering::Acquire,
                |remaining| remaining.checked_sub(1),
            );
            if let Ok(remaining) = attempts {
                if remaining == 1 {
                    let _ = self.fail_next_aligned_zeroed_size.compare_exchange(
                        size,
                        0,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    );
                }
                return Err(MetaError::AllocationUnavailable);
            }
        }
        let pointer = entry
            .allocator()
            .allocate_aligned_zeroed(size, alignment)
            .ok_or(MetaError::AllocationUnavailable)?;
        let allocation = MetaAllocation::new(
            self,
            pointer,
            size,
            MetaAllocationOrigin::AlignedZeroed,
        );
        #[cfg(any(test, feature = "native-runtime-test-audit"))]
        self.get_ref().test_note_allocation_created();
        Ok(allocation)
    }

    /// Replaces a metadata allocation with a zeroed one.
    ///
    /// The replacement is allocated while holding the metadata lock. On
    /// allocation failure `old` remains live and is returned unchanged through
    /// its mutable capability. On success this method drops the lock before
    /// copying and before freeing `old`, exactly avoiding the source's
    /// `_mi_meta_rezalloc` recursive-lock hazard.
    pub(crate) fn rezalloc(
        self: Pin<&'owner Self>,
        config: MemoryConfig,
        old: Option<&mut MetaAllocation<'owner>>,
        new_size: usize,
    ) -> Result<MetaAllocation<'owner>, MetaError> {
        self.rezalloc_for_main_subprocess(config, self.default_subprocess(), old, new_size)
    }

    /// Replaces one metadata allocation while retaining the already selected
    /// main-subprocess identity. Current-thread TLS backing uses this rather
    /// than the global convenience route so all of its images remain with the
    /// same TLD/Theap/registry process selection in isolated tests and later
    /// integration.
    pub(crate) fn rezalloc_for_main_subprocess(
        self: Pin<&'owner Self>,
        config: MemoryConfig,
        subprocess: &'static MainSubprocess,
        old: Option<&mut MetaAllocation<'owner>>,
        new_size: usize,
    ) -> Result<MetaAllocation<'owner>, MetaError> {
        let Some(old) = old else {
            return self.zalloc_for_main_subprocess(config, subprocess, new_size);
        };
        if !old.belongs_to(self) {
            return Err(MetaError::ForeignOwner);
        }
        self.require_published_detached_metadata_theap(subprocess)?;

        let (replacement, copy_size) = {
            let mut entry = self.enter_for_main_subprocess(subprocess)?;
            entry.ensure_ready(config, subprocess)?;
            if !old.claim(ALLOCATION_LIVE, ALLOCATION_MOVING)
                || !old.has_consistent_malloc_provenance()
            {
                old.reject();
                return Err(MetaError::ReleasedOrStale);
            }
            let old_usable = match unsafe { entry.allocator().usable_size(old.pointer) } {
                Some(size) => size,
                None => {
                    old.reject();
                    return Err(MetaError::ReleasedOrStale);
                }
            };
            #[cfg(test)]
            if new_size != 0
                && self
                    .fail_next_rezalloc_size
                    .compare_exchange(new_size, 0, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
            {
                old.restore_live();
                return Err(MetaError::AllocationUnavailable);
            }
            let Some(pointer) = entry.allocator().allocate_zeroed(new_size) else {
                old.restore_live();
                return Err(MetaError::AllocationUnavailable);
            };
            let replacement = MetaAllocation::new(
                self,
                pointer,
                new_size,
                MetaAllocationOrigin::Replacement,
            );
            #[cfg(any(test, feature = "native-runtime-test-audit"))]
            self.get_ref().test_note_allocation_created();
            (replacement, new_size.min(old_usable))
        };

        // SAFETY: `old` is in MOVING state under its exclusive mutable
        // capability; no safe metadata operation can free it. `replacement`
        // has not escaped this method. The source copy extent is bounded by
        // the validated old usable size and requested replacement size.
        unsafe {
            core::ptr::copy_nonoverlapping(
                old.pointer.as_ptr(),
                replacement.pointer.as_ptr(),
                copy_size,
            );
        }

        old.state.store(ALLOCATION_RELEASING, Ordering::Release);
        if let Err(error) = self.release_claimed(old) {
            // The old block was fully validated while held exclusively, so a
            // free failure is an internal lifecycle fault. Retire the private
            // replacement before reporting it rather than leaking an
            // unpublishable allocation; both operations remain serialized.
            let mut replacement = replacement;
            replacement.state.store(ALLOCATION_RELEASING, Ordering::Release);
            let cleanup = self.release_claimed(&mut replacement);
            #[cfg(any(test, feature = "native-runtime-test-audit"))]
            if cleanup.is_ok() {
                self.get_ref().test_note_allocation_released();
            }
            #[cfg(not(any(test, feature = "native-runtime-test-audit")))]
            let _ = cleanup;
            old.reject();
            return Err(error);
        }
        old.release();
        #[cfg(any(test, feature = "native-runtime-test-audit"))]
        self.get_ref().test_note_allocation_released();
        Ok(replacement)
    }

    /// Releases one metadata allocation under the detached owner lock.
    ///
    /// Existing direct lifecycle owners treat an admitted exact-owner failure
    /// as terminal, so this general route retains its terminal-on-error
    /// capability contract. A foreign-owner rejection remains non-consuming.
    /// The selected [`MetaRelease::Malloc`] boundary uses
    /// [`Self::release_selected_malloc`] when it must explicitly retain a
    /// pre-entry failure for retry.
    pub(crate) fn free(
        self: Pin<&'owner Self>,
        allocation: &mut MetaAllocation<'owner>,
    ) -> Result<(), MetaError> {
        if !allocation.belongs_to(self) {
            return Err(MetaError::ForeignOwner);
        }
        if !allocation.claim(ALLOCATION_LIVE, ALLOCATION_RELEASING)
            || !allocation.has_consistent_malloc_provenance()
        {
            allocation.reject();
            return Err(MetaError::ReleasedOrStale);
        }
        match self.release_claimed(allocation) {
            Ok(()) => {
                allocation.release();
                #[cfg(any(test, feature = "native-runtime-test-audit"))]
                self.get_ref().test_note_allocation_released();
                Ok(())
            }
            Err(error) => {
                allocation.reject();
                Err(error)
            }
        }
    }

    /// Releases one selected exact-owner Malloc capability for
    /// [`MetaRelease`].
    ///
    /// Unlike [`Self::free`], this narrow boundary can return the owned
    /// capability to its caller. It therefore establishes the Rust backing
    /// entry before changing LIVE to RELEASING, so an eligible entry failure
    /// leaves the exact value retryable. Pinned `_mi_meta_free`'s
    /// `MI_MEM_MALLOC` branch does not take `theap_meta_lock`; Rust serializes
    /// this selected local free with its separate backing lock only.
    fn release_selected_malloc(
        self: Pin<&'static Self>,
        allocation: &mut MetaAllocation<'static>,
    ) -> Result<(), MetaError> {
        if !allocation.belongs_to(self) {
            return Err(MetaError::ForeignOwner);
        }
        if !allocation.is_live() || !allocation.has_consistent_malloc_provenance() {
            allocation.reject();
            return Err(MetaError::ReleasedOrStale);
        }
        let mut entry = self.enter()?;
        if !allocation.claim(ALLOCATION_LIVE, ALLOCATION_RELEASING) {
            allocation.reject();
            return Err(MetaError::ReleasedOrStale);
        }
        let result = Self::release_claimed_under_entry(&mut entry, allocation);
        // Match the general free boundary: release the backing lock and
        // recursion marker before publishing the capability's final state.
        drop(entry);
        match result {
            Ok(()) => {
                allocation.release();
                #[cfg(any(test, feature = "native-runtime-test-audit"))]
                self.get_ref().test_note_allocation_released();
                Ok(())
            }
            Err(error) => {
                allocation.reject();
                Err(error)
            }
        }
    }

    /// Enforces the source `_mi_meta_zalloc` precondition before a metadata
    /// caller can enter its private lock. A cold owner has no published
    /// source-static image, so only `prepare_for_main_subprocess` may bind and
    /// publish it. `MetaEntry::ensure_ready` repeats the exact check before it
    /// can map a first backing page.
    fn require_published_detached_metadata_theap(
        self: Pin<&'owner Self>,
        subprocess: &'static MainSubprocess,
    ) -> Result<(), MetaError> {
        if !subprocess.is_process_main() {
            return Err(MetaError::SubprocessMismatch);
        }
        match self.get_ref().status.load(Ordering::Acquire) {
            CLOSED | CLOSE_RETAINED => Err(MetaError::Closed),
            COLD => Err(MetaError::TheapMetaUnpublished),
            BOUND | READY => {
                if !core::ptr::eq(
                    self.get_ref().subprocess.load(Ordering::Acquire),
                    subprocess.identity_ptr(),
                ) {
                    return Err(MetaError::SubprocessMismatch);
                }
                self.validate_bound_detached_metadata_theap(subprocess)
            }
            FAILED | _ => Err(MetaError::InitializationRetained),
        }
    }

    /// Checks that a BOUND or READY metadata owner is still the exact Theap
    /// identity published through its selected source subprocess.
    ///
    /// The caller observed BOUND or READY with Acquire. Those states
    /// Release-publish this immutable address after the source subprocess
    /// publication. This method only compares stable atomics; it never
    /// reborrows the mutable bootstrap or dereferences the subprocess slot.
    fn validate_bound_detached_metadata_theap(
        self: Pin<&Self>,
        subprocess: &'static MainSubprocess,
    ) -> Result<(), MetaError> {
        let this = self.get_ref();
        let Some(identity) = NonNull::new(
            this.detached_metadata_theap.load(Ordering::Acquire),
        ) else {
            return Err(MetaError::TheapMetaUnpublished);
        };
        if subprocess.matches_published_detached_metadata_theap(identity) {
            Ok(())
        } else {
            Err(MetaError::TheapMetaMismatch)
        }
    }

    fn enter<'borrow>(
        self: Pin<&'borrow Self>,
    ) -> Result<MetaEntry<'borrow, 'owner>, MetaError> {
        let this = self.get_ref();
        if matches!(this.status.load(Ordering::Acquire), CLOSED | CLOSE_RETAINED) {
            return Err(MetaError::Closed);
        }
        let thread = current_entry_thread()?;
        #[cfg(test)]
        this.test_entry_attempt_count.fetch_add(1, Ordering::Relaxed);
        if this.active_entry_thread.load(Ordering::Acquire) == thread {
            return Err(MetaError::RecursiveEntry);
        }
        let guard = this.lock.lock().map_err(MetaError::Lock)?;
        if this.active_entry_thread.load(Ordering::Acquire) == thread {
            drop(guard);
            return Err(MetaError::RecursiveEntry);
        }
        if matches!(this.status.load(Ordering::Acquire), CLOSED | CLOSE_RETAINED) {
            drop(guard);
            return Err(MetaError::Closed);
        }
        this.active_entry_thread.store(thread, Ordering::Release);
        Ok(MetaEntry {
            owner: self,
            entry_thread: thread,
            theap_meta_guard: None,
            guard: Some(guard),
        })
    }

    /// Enters the selected direct metadata-allocation phase after the source
    /// `theap_meta` identity preflight. The Rust backing lock is acquired
    /// first so its existing same-thread marker covers a wait on the source
    /// nonrecursive lock; the source guard then nests inside it and is
    /// released first. Bootstrap and exact-owner free keep using only the
    /// backing lock because neither is a selected source allocation phase.
    fn enter_for_main_subprocess<'borrow>(
        self: Pin<&'borrow Self>,
        subprocess: &'static MainSubprocess,
    ) -> Result<MetaEntry<'borrow, 'owner>, MetaError> {
        let mut entry = self.enter()?;
        let theap_meta_guard = subprocess.lock_metadata_theap().map_err(MetaError::Lock)?;
        entry.theap_meta_guard = Some(theap_meta_guard);
        Ok(entry)
    }

    fn release_claimed(
        self: Pin<&'owner Self>,
        allocation: &mut MetaAllocation<'owner>,
    ) -> Result<(), MetaError> {
        let mut entry = self.enter()?;
        Self::release_claimed_under_entry(&mut entry, allocation)
    }

    /// Runs the selected local free while the caller already owns the backing
    /// metadata entry. The capability has been claimed by that caller; this
    /// helper deliberately neither acquires the source `theap_meta` lock nor
    /// changes the capability state.
    fn release_claimed_under_entry(
        entry: &mut MetaEntry<'_, 'owner>,
        allocation: &mut MetaAllocation<'owner>,
    ) -> Result<(), MetaError> {
        if entry.status() != READY || !allocation.has_consistent_malloc_provenance() {
            return Err(MetaError::ReleasedOrStale);
        }
        // SAFETY: the allocation capability is RELEASING or MOVING and the
        // metadata lock excludes every other allocator/page-map mutation.
        unsafe { entry.allocator().free(allocation.pointer) }.map_err(MetaError::Free)
    }

    #[cfg(any(test, feature = "native-runtime-test-audit"))]
    fn test_note_allocation_created(&self) {
        let live = self
            .test_live_allocation_count
            .fetch_add(1, Ordering::AcqRel)
            .checked_add(1)
            .expect("the test metadata capability count does not overflow");
        let mut high_water = self.test_allocation_high_water.load(Ordering::Acquire);
        while live > high_water {
            match self.test_allocation_high_water.compare_exchange_weak(
                high_water,
                live,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(observed) => high_water = observed,
            }
        }
    }

    #[cfg(any(test, feature = "native-runtime-test-audit"))]
    fn test_note_allocation_released(&self) {
        let previous = self
            .test_live_allocation_count
            .fetch_sub(1, Ordering::AcqRel);
        assert_ne!(
            previous, 0,
            "a successful metadata release must own one live test capability"
        );
    }

    /// Forms the source-static detached metadata Theap image without mapping a
    /// private arena or PageMap.
    ///
    /// The caller holds `lock`, COLD excludes every projection, and the
    /// bootstrap slot has never been initialized. Pinned C performs this
    /// identity setup in `mi_heap_main_init_once`; its first `_mi_meta_zalloc`
    /// later obtains ordinary backing on demand.
    fn bind_empty_detached_identity(
        self: Pin<&'owner Self>,
        config: MemoryConfig,
        subprocess: &'static MainSubprocess,
    ) -> Result<(), MetaError> {
        let this = self.get_ref();
        debug_assert_eq!(this.status.load(Ordering::Acquire), COLD);

        // SAFETY: COLD and the held private lock make this the one write to
        // the process-static, pinned bootstrap slot before any session may
        // borrow its self-referential fields.
        unsafe { (*this.bootstrap.get()).write(ExclusiveTheapBootstrap::new()) };
        let mut bootstrap = unsafe {
            Pin::new_unchecked((&mut *this.bootstrap.get()).assume_init_mut())
        };
        let bound = if let Some(heap) = unsafe { *this.canonical_heap.get() } {
            bootstrap.as_mut().bind_detached_for_main_heap(heap)
        } else {
            bootstrap.as_mut().bind_detached_for_main_subprocess(subprocess)
        };
        if bound.is_err() {
            // Binding a valid static detached image cannot normally fail. If
            // a Rust guard nevertheless rejects it, its final slot may have
            // been touched; retain rather than overwrite that process state.
            this.status.store(FAILED, Ordering::Release);
            return Err(MetaError::InitializationRetained);
        }

        let Some(identity) = bootstrap
            .as_ref()
            .detached_metadata_theap_identity(subprocess)
        else {
            // A successful detached bind must expose this exact image before
            // source `subproc->theap_meta` publication. Retain rather than
            // inventing a later lazy publication from an incomplete image.
            this.status.store(FAILED, Ordering::Release);
            return Err(MetaError::TheapMetaMismatch);
        };
        // SAFETY: `bootstrap` names this allocator's pinned process-lifetime
        // final slot. The identity is never dereferenced through the
        // subprocess, and COLD plus the held private lock ensure that this is
        // its sole one-way source publication attempt.
        if !unsafe { subprocess.publish_detached_metadata_theap(identity) } {
            // Another static detached image already claimed this source
            // subprocess. Do not overwrite it or make this partially bound
            // image retryable under a second process identity.
            this.status.store(FAILED, Ordering::Release);
            return Err(MetaError::TheapMetaMismatch);
        }

        // SAFETY: the immutable tuple is written before BOUND's Release
        // publication and is never replaced on a clean backing retry. The
        // exact Theap identity was already one-way published through the
        // selected source subprocess above, so this independent atomic is a
        // comparison-only mirror for lock-free precondition checks.
        unsafe { (*this.config.get()).write(config) };
        this.subprocess.store(subprocess.identity_ptr(), Ordering::Release);
        this.detached_metadata_theap
            .store(identity.as_ptr(), Ordering::Release);
        this.status.store(BOUND, Ordering::Release);
        Ok(())
    }

    /// Initializes the bounded Rust backing for an already source-bound
    /// detached metadata image on its first real metadata request.
    fn initialize_backing(
        self: Pin<&'owner Self>,
        entry: &mut MetaEntry<'_, 'owner>,
        config: MemoryConfig,
        subprocess: &'static MainSubprocess,
    ) -> Result<(), MetaError> {
        let this = self.get_ref();
        debug_assert_eq!(this.status.load(Ordering::Acquire), BOUND);
        // The source process path takes its first page through the ordinary
        // arena/OS selector, not a private map and a fixed-capacity arena.
        if let Some(backing) = unsafe { *this.process_backing.get() } {
            if unsafe { (*this.canonical_heap.get()).is_some() } {
                // No whole-bootstrap reference is formed after source list
                // publication. The session owns only metadata-local fields.
                let pointer = unsafe { NonNull::new_unchecked(this.bootstrap.get().cast::<ExclusiveTheapBootstrap>()) };
                let session = unsafe { ExclusiveTheapBootstrap::begin_canonical_metadata_session_at(pointer) }
                    .map_err(|_| {
                        this.status.store(FAILED, Ordering::Release);
                        MetaError::InitializationRetained
                    })?;
                let allocator = unsafe { CanonicalProcessMetadataPageAllocator::activate_canonical_process_metadata(
                    session, backing.binding.process(), backing.page_map) };
                unsafe { (*this.allocator.get()).write(MetadataPageAllocator::CanonicalProcess(allocator)); }
                this.status.store(READY, Ordering::Release);
                return Ok(());
            }
            let bootstrap = unsafe { Pin::new_unchecked((&mut *this.bootstrap.get()).assume_init_mut()) };
            let allocator = unsafe { ProcessMetadataPageAllocator::activate_process_metadata(
                bootstrap, backing.binding.process(), backing.page_map) }
                .map_err(|_| {
                    this.status.store(FAILED, Ordering::Release);
                    MetaError::InitializationRetained
                })?;
            unsafe { (*this.allocator.get()).write(MetadataPageAllocator::Process(allocator)) };
            this.status.store(READY, Ordering::Release);
            return Ok(());
        }
        let page_map = match PageMap::initialize(config, MAX_VABITS, false) {
            Ok(page_map) => page_map,
            Err(PageMapInitializationError::Failed { .. }) => {
                return Err(MetaError::InitializationFailed);
            }
            Err(PageMapInitializationError::Retained { mapping, .. }) => {
                // SAFETY: `entry` owns the initialization lock, BOUND exposes
                // no backing projection, and the private PageMap never reached its
                // final PageMap slot. Preserve the still-live mapping in its
                // distinct terminal owner before publishing FAILED.
                unsafe { this.write_retained_page_map_initialization_mapping(mapping) };
                this.has_retained_page_map_initialization_mapping
                    .store(true, Ordering::Release);
                this.status.store(FAILED, Ordering::Release);
                return Err(MetaError::InitializationRetained);
            }
        };
        // SAFETY: `entry` owns the sole initialization lock and BOUND exposes
        // no private PageMap projection.
        unsafe { (*this.page_map.get()).write(page_map) };
        // SAFETY: `entry` holds the metadata owner's private initialization
        // lock, and BOUND means no arena was written or published. This is the
        // unique pre-publication transition for the process-long registry
        // identity; no concurrent insert can observe or race this count-zero
        // state.
        if !unsafe {
            this.registry
                .bind_subprocess_before_publication(subprocess.as_ptr())
        } {
            // A BOUND metadata owner can reach this only after a prior failed
            // initialization bound a different process-main identity. Never
            // construct an arena under a second identity; release the private
            // page map if possible and leave a retained failure otherwise.
            return match unsafe { (&mut *this.page_map.get()).assume_init_mut().destroy() } {
                Ok(()) => Err(MetaError::SubprocessMismatch),
                Err(_) => {
                    this.status.store(FAILED, Ordering::Release);
                    Err(MetaError::InitializationRetained)
                }
            };
        }

        let mapping = match Mapping::map_aligned_for_allocator(
            config,
            ARENA_MIN_SIZE,
            ARENA_ALIGNMENT,
            MapAccess::Committed,
        ) {
            Ok(mapping) => mapping,
            Err(failure) => match failure.into_mapping() {
                None => return self.cleanup_page_map_after_failed_init(),
                Some(mapping) => {
                    // The aligned-map cleanup failed after this metadata
                    // owner had already formed its private PageMap. Both
                    // final slots are now the exact terminal owners; never
                    // destroy the PageMap and then forget the live arena map.
                    // SAFETY: `entry` owns initialization, BOUND exposes no
                    // backing reader, and this mapping slot is still
                    // uninitialized.
                    unsafe { (*this.mapping.get()).write(mapping) };
                    this.status.store(FAILED, Ordering::Release);
                    return Err(MetaError::InitializationRetained);
                }
            },
        };
        // SAFETY: same BOUND/lock proof as the page-map slot above.
        unsafe { (*this.mapping.get()).write(mapping) };
        // SAFETY: the preceding in-place write initialized this unique mapping
        // owner and the metadata lock excludes all other projection.
        let mapping = unsafe { (&mut *this.mapping.get()).assume_init_mut() };
        let base = match mapping.base() {
            Ok(base) => base,
            Err(_) => return self.cleanup_mapping_and_page_map_after_failed_init(),
        };
        let length = match mapping.length() {
            Ok(length) => length,
            Err(_) => return self.cleanup_mapping_and_page_map_after_failed_init(),
        };
        let managed = unsafe {
            manage_external_in_place(
                &this.registry,
                base,
                length,
                config.page_size(),
                mapping.initially_committed(),
                false,
                mapping.initially_zero(),
                -1,
                false,
                None,
            )
        };
        let managed = match managed {
            Ok(managed) => managed,
            Err(_) => return self.cleanup_mapping_and_page_map_after_failed_init(),
        };
        let arena = match unsafe { ArenaView::from_ptr(managed.arena_id().as_ptr()) } {
            Some(arena) if managed.is_complete() => arena,
            _ => {
                this.status.store(FAILED, Ordering::Release);
                return Err(MetaError::InitializationRetained);
            }
        };

        // SAFETY: BOUND initialized this final pinned slot before it
        // Release-published the source detached Theap identity. The private
        // lock excludes a second session while this first backing becomes
        // ready.
        let bootstrap = unsafe { Pin::new_unchecked((&mut *this.bootstrap.get()).assume_init_mut()) };
        let page_map = unsafe { (&mut *this.page_map.get()).assume_init_mut() };
        let allocator = match SingleThreadAllocator::activate_bound_detached(
            bootstrap,
            subprocess,
            arena,
            ArenaId::none(),
            page_map,
            0,
        ) {
            Ok(allocator) => allocator,
            Err(BootstrapError::AlreadyInitialized | BootstrapError::InvalidThreadState) => {
                this.status.store(FAILED, Ordering::Release);
                return Err(MetaError::InitializationRetained);
            }
        };
        // SAFETY: every reference captured by `allocator` names one prior
        // final static slot. No operation can observe it before READY.
        unsafe { (*this.allocator.get()).write(MetadataPageAllocator::LegacySelectedArena(allocator)) };
        this.status.store(READY, Ordering::Release);
        let _ = entry;
        Ok(())
    }

    /// Writes the exact private PageMap bootstrap mapping into the metadata
    /// owner's terminal slot.
    ///
    /// # Safety
    ///
    /// `initialize_backing` still owns the metadata private lock, status is
    /// BOUND, no private PageMap or arena was published, and this final slot
    /// is uninitialized.
    #[inline]
    unsafe fn write_retained_page_map_initialization_mapping(&self, mapping: Mapping) {
        unsafe { (*self.retained_page_map_initialization_mapping.get()).write(mapping) };
    }

    fn cleanup_page_map_after_failed_init(self: Pin<&'owner Self>) -> Result<(), MetaError> {
        let this = self.get_ref();
        // SAFETY: the unshared page map was written while BOUND exposed no
        // backing projection. Successful destroy releases all direct mappings
        // before the same bound image retries its first backing request.
        match unsafe { (&mut *this.page_map.get()).assume_init_mut().destroy() } {
            Ok(()) => Err(MetaError::InitializationFailed),
            Err(_) => {
                this.status.store(FAILED, Ordering::Release);
                Err(MetaError::InitializationRetained)
            }
        }
    }

    fn cleanup_mapping_and_page_map_after_failed_init(
        self: Pin<&'owner Self>,
    ) -> Result<(), MetaError> {
        let this = self.get_ref();
        // SAFETY: failure happened before the arena was registry-published;
        // the mapping is private to this BOUND backing attempt.
        let mapping_result = unsafe { (&mut *this.mapping.get()).assume_init_mut().unmap() };
        let page_map_result = unsafe { (&mut *this.page_map.get()).assume_init_mut().destroy() };
        if mapping_result.is_ok() && page_map_result.is_ok() {
            Err(MetaError::InitializationFailed)
        } else {
            this.status.store(FAILED, Ordering::Release);
            Err(MetaError::InitializationRetained)
        }
    }
}

/// A held metadata private lock and its exclusive initialized-state access.
struct MetaEntry<'borrow, 'owner> {
    owner: Pin<&'borrow MetadataEngine<'owner>>,
    entry_thread: usize,
    /// The bounded source-owned lock for direct allocation phases. It is
    /// nested inside `guard` so the existing recursion marker covers a wait
    /// on this nonrecursive lock; Drop releases it before the backing lock.
    theap_meta_guard: Option<PrivateLockGuard<'borrow>>,
    guard: Option<PrivateLockGuard<'borrow>>,
}

impl<'borrow, 'owner> MetaEntry<'borrow, 'owner> {
    /// Ensures the source-static detached metadata image names this exact
    /// process tuple. BOUND deliberately does not make a backing PageMap,
    /// arena, or allocator projection available.
    fn ensure_bound(
        &mut self,
        config: MemoryConfig,
        subprocess: &'static MainSubprocess,
    ) -> Result<(), MetaError>
    where
        'borrow: 'owner,
    {
        match self.status() {
            COLD => self.owner.bind_empty_detached_identity(config, subprocess),
            BOUND | READY => self.validate_bound_tuple(config, subprocess),
            FAILED => Err(MetaError::InitializationRetained),
            _ => Err(MetaError::InitializationRetained),
        }
    }

    fn ensure_ready(
        &mut self,
        config: MemoryConfig,
        subprocess: &'static MainSubprocess,
    ) -> Result<(), MetaError>
    where
        'borrow: 'owner,
    {
        self.ensure_bound(config, subprocess)?;
        self.owner
            .validate_bound_detached_metadata_theap(subprocess)?;
        match self.status() {
            READY => Ok(()),
            BOUND => self.owner.initialize_backing(self, config, subprocess),
            FAILED => Err(MetaError::InitializationRetained),
            _ => Err(MetaError::InitializationRetained),
        }
    }

    fn validate_bound_tuple(
        &self,
        config: MemoryConfig,
        subprocess: &'static MainSubprocess,
    ) -> Result<(), MetaError> {
        // SAFETY: BOUND Release-publishes this immutable tuple before the
        // current held lock can observe it; READY retains the same tuple.
        let stored = unsafe { self.owner.get_ref().config.get().read().assume_init() };
        if stored != config {
            return Err(MetaError::ConfigurationMismatch);
        }
        if !core::ptr::eq(
            self.owner
                .get_ref()
                .subprocess
                .load(Ordering::Acquire),
            subprocess.identity_ptr(),
        ) {
            Err(MetaError::SubprocessMismatch)
        } else {
            self.owner
                .validate_bound_detached_metadata_theap(subprocess)
        }
    }

    /// Verifies an already-ready parent engine without permitting a short
    /// child lifecycle borrow to initialize its self-referential page session.
    fn ensure_existing_ready(
        &self,
        config: MemoryConfig,
        subprocess: &'static MainSubprocess,
    ) -> Result<(), MetaError> {
        if self.status() != READY {
            return Err(MetaError::InitializationRetained);
        }
        self.validate_bound_tuple(config, subprocess)
    }

    #[inline]
    fn status(&self) -> u8 {
        self.owner.get_ref().status.load(Ordering::Acquire)
    }

    #[inline]
    fn allocator(&mut self) -> &mut MetadataPageAllocator<'owner> {
        // SAFETY: READY plus this held private lock gives exclusive mutation
        // of the final static allocator slot.
        unsafe { (&mut *self.owner.get_ref().allocator.get()).assume_init_mut() }
    }

    #[inline]
    fn allocator_ref(&self) -> &MetadataPageAllocator<'owner> {
        // SAFETY: see `allocator`; this shared projection is used only for
        // source pointer identity while the same metadata lock is held.
        unsafe { (&*self.owner.get_ref().allocator.get()).assume_init_ref() }
    }
}

impl Drop for MetaEntry<'_, '_> {
    fn drop(&mut self) {
        // Unlock the nested selected source lock, then the Rust backing lock,
        // before clearing the recursion marker. The first release preserves
        // source `_mi_meta_rezalloc`'s unlock-before-copy/free order. Clearing
        // first would let same-thread signal reentry miss the marker and wait
        // forever on a still-held nonrecursive lock. A different thread may
        // acquire and replace the marker between these operations, so cleanup
        // uses a compare-exchange and must not erase that successor's owner.
        drop(self.theap_meta_guard.take());
        drop(self.guard.take());
        clear_entry_thread_after_unlock(
            &self.owner.get_ref().active_entry_thread,
            self.entry_thread,
        );
    }
}

#[inline]
fn clear_entry_thread_after_unlock(active: &AtomicUsize, entry_thread: usize) {
    let _ = active.compare_exchange(
        entry_thread,
        0,
        Ordering::Release,
        Ordering::Relaxed,
    );
}

#[inline]
fn current_entry_thread() -> Result<usize, MetaError> {
    let thread = crate::os::thread_pointer_identity();
    LiveThreadId::new(thread)
        .map(LiveThreadId::get)
        .ok_or(MetaError::InvalidEntryThread)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{mpsc, Arc, Barrier};
    use std::thread;
    use std::time::{Duration, Instant};

    use crate::os::{fault, PageSize};
    use crate::types::MemoryKind;

    fn config() -> MemoryConfig {
        let page_size = PageSize::new(4096).unwrap();
        MemoryConfig::from_observations(page_size, 1024 * 1024, false, false)
    }

    /// Test-only process lifetime mirrors the production static singleton:
    /// the detached engine stores `'static` references into its final slots.
    /// This deliberately leaves the source detached-metadata image cold so a
    /// regression can prove direct demand does not publish it.
    fn cold_static_allocator() -> Pin<&'static MetaAllocator> {
        MetaAllocator::test_static_owner()
    }

    /// Returns an isolated fixture after the production-shaped preparation
    /// edge has bound and published its own selected main-subprocess image.
    fn static_allocator() -> Pin<&'static MetaAllocator> {
        let allocator = cold_static_allocator();
        allocator
            .prepare_for_main_subprocess(config(), allocator.test_default_subprocess())
            .expect("the isolated fixture publishes its detached metadata-Theap before demand");
        allocator
    }

    fn wait_for_metadata_theap_lock_contention(subprocess: &MainSubprocess) {
        let deadline = Instant::now() + Duration::from_secs(2);
        while !subprocess.test_metadata_theap_lock_is_contended() {
            assert!(
                Instant::now() < deadline,
                "the selected direct metadata caller must reach the subprocess metadata lock"
            );
            thread::yield_now();
        }
    }

    #[test]
    fn metadata_singleton_outgrows_the_first_arena_without_a_private_capacity_limit() {
        let allocator = static_allocator();
        let process = bind_process_fixture(allocator, false).process();
        let mut first = allocator.zalloc(config(), 64).unwrap();
        assert_eq!(process.subprocess().arena_backing().registry().count(), 1);
        // `src/subproc.c:_mi_meta_zalloc` delegates to normal Theap allocation;
        // `src/arena.c:mi_arenas_page_alloc_fresh` may grow backing or use OS
        // memory. The first arena's extent is not a metadata allocation cap.
        let size = 2 * ARENA_MIN_SIZE;
        let mut allocation = allocator.zalloc(config(), size)
            .expect("ordinary metadata demand may exceed its first arena");
        assert_eq!(process.subprocess().arena_backing().registry().count(), 2,
            "source normal reservation grows beyond the first source-configured arena");
        assert_eq!(allocation.memory_id().kind(), MemoryKind::Malloc);
        // SAFETY: the live exclusive capability owns all requested bytes.
        let bytes = unsafe { core::slice::from_raw_parts(allocation.pointer().as_ptr(), size) };
        assert!(bytes.iter().all(|byte| *byte == 0));
        allocator.free(&mut allocation).expect("the exact metadata owner releases its singleton");
        allocator.free(&mut first).unwrap();
        std::println!("m2.metadata.capacity.bytes={size}");
        std::println!("m2.metadata.capacity.zeroed_malloc_released=1");
    }

    /// The canonical detached metadata Theap owns ordinary OS-backed pages
    /// under the metadata entry lock. Its no-live-thread session identity is
    /// `THREAD_ID_DETACHED`, which public free must distinguish from a
    /// selected main Heap's abandoned OS-list identity.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn canonical_metadata_os_singleton_frees_with_detached_identity() {
        thread::spawn(|| {
            let config = config();
            let allocator = MetaAllocator::test_static_owner();
            let process = crate::process_init::ProcessMainInitializationStorage::test_static_owner();
            let main_static = crate::main_theap::MainStaticAttachmentStorage::test_static_owner();
            let subprocess = allocator.test_default_subprocess();
            let page_map_storage = crate::process_page_map::ProcessPageMapStorage::test_static_owner();
            let mut options = crate::config::VmOptions::uninitialized();
            options.initialize_all(|_| crate::config::VmOptionEnvironment::Absent);
            options.set(crate::config::VmOption::ArenaReserve, 64 * 1024);
            let owner = unsafe {
                process.initialize_with_test_components_and_vm_options(
                    config,
                    options,
                    main_static,
                    subprocess,
                    allocator,
                    page_map_storage,
                )
            }
            .expect("the source process publishes canonical metadata backing");
            let binding = owner
                .ready()
                .expect("the ticket-zero source owner reaches READY")
                .process_backing()
                .expect("READY retains the canonical policy and PageMap binding");
            let mut allocation = allocator
                .zalloc_aligned(config, 7, 128 * 1024)
                .expect("canonical detached metadata allocates one direct OS singleton");
            {
                let mut entry = allocator
                    .enter()
                    .expect("the metadata entry remains available for canonical observation");
                assert!(
                    matches!(entry.allocator(), MetadataPageAllocator::CanonicalProcess(_)),
                    "policy-backed metadata uses its canonical detached session"
                );
            }
            let page_map = unsafe { binding.page_map().page_map_for_owned_ranges() }
                .expect("the canonical process PageMap remains observable");
            let page = unsafe { page_map.checked_lookup(allocation.pointer().as_ptr()) };
            assert!(!page.is_null(), "the canonical OS singleton is PageMap-published");
            let page = unsafe { &*page };
            assert!(page.memid().is_os());
            assert_eq!(
                page.abandoned_test_thread_id(),
                crate::types::THREAD_ID_DETACHED,
                "canonical metadata retains source detached page identity"
            );
            let pointer = allocation.pointer();
            allocator
                .free(&mut allocation)
                .expect("canonical detached metadata frees its direct OS singleton locally");
            assert!(
                unsafe { page_map.checked_lookup(pointer.as_ptr()) }.is_null(),
                "canonical metadata local free unregisters the OS singleton"
            );
            // The process owner and canonical metadata engine intentionally
            // remain process-lived beyond this direct-free regression.
            core::mem::forget(owner);
        })
        .join()
        .expect("the canonical metadata OS singleton regression remains current-thread local");
    }

    #[test]
    fn source_retained_metadata_transfer_preserves_typed_owner_across_thread_handoff() {
        let allocator = static_allocator();
        bind_process_fixture(allocator, false);
        let mut theap = allocator.zalloc(config(), size_of::<Theap>()).unwrap();
        let mut tld = allocator.zalloc(config(), size_of::<ThreadLocalData>()).unwrap();
        assert!(!theap.can_transfer_source_retained_theap());
        assert!(!tld.can_transfer_source_retained_tld());
        assert!(theap.initialize_dynamic_theap_metadata().is_some());
        assert!(tld.initialize_thread_local_data_subprocess_attached_no_theap(
            LiveThreadId::new(current_entry_thread().unwrap()).unwrap(),
            ThreadSequence::from_previous_total_count(9), 0,
            allocator.test_default_subprocess(),
        ));
        assert!(!theap.can_transfer_source_retained_tld());
        assert!(!tld.can_transfer_source_retained_theap());
        let theap_memory = theap.memory_id();
        let tld_memory = tld.memory_id();
        let theap_pointer = match theap.into_source_retained_theap() {
            Ok(pointer) => pointer, Err(_) => panic!("typed Theap transfers"),
        };
        let tld_pointer = match tld.into_source_retained_tld() {
            Ok(pointer) => pointer, Err(_) => panic!("typed TLD transfers"),
        };
        assert_eq!(allocator.test_allocation_audit().live_capability_count, 2);
        let published_theap = AtomicPtr::new(core::ptr::null_mut());
        let published_tld = AtomicPtr::new(core::ptr::null_mut());
        published_theap.store(theap_pointer.as_ptr(), Ordering::Release);
        published_tld.store(tld_pointer.as_ptr(), Ordering::Release);
        let (theap, tld) = thread::scope(|scope| {
            scope.spawn(|| {
                // SAFETY: both images were explicitly transferred above;
                // this sole consumer acquires their publication, and the
                // isolated process has no other source/TLS/list owner. It
                // recovers each once before returning either allocation.
                let mut theap = unsafe { MetaAllocation::recover_source_retained_theap(
                    allocator, NonNull::new(published_theap.load(Ordering::Acquire)).unwrap(),
                ) }.unwrap();
                let mut tld = unsafe { MetaAllocation::recover_source_retained_tld(
                    allocator, NonNull::new(published_tld.load(Ordering::Acquire)).unwrap(),
                ) }.unwrap();
                assert!(theap.dynamic_theap_mut().is_some());
                assert!(tld.thread_local_data_mut().is_some());
                assert_eq!(allocator.test_allocation_audit().live_capability_count, 2);
                (theap, tld)
            }).join().unwrap()
        });
        assert!(theap.matches_memory_id(theap_memory));
        assert!(tld.matches_memory_id(tld_memory));
        assert!(MetaRelease::Malloc(theap).release().is_ok());
        assert!(MetaRelease::Malloc(tld).release().is_ok());
        assert_eq!(allocator.test_allocation_audit().live_capability_count, 0);
    }

    #[test]
    fn rejected_source_metadata_transfer_returns_the_original_live_capability() {
        let allocator = static_allocator();
        let block = allocator.zalloc(config(), size_of::<Theap>()).unwrap();
        let pointer = block.pointer();
        let memory = block.memory_id();
        let mut block = match block.into_source_retained_theap() {
            Err(block) => block, Ok(_) => panic!("uninitialized bytes cannot transfer as a Theap"),
        };
        assert!(block.is_live());
        assert_eq!(block.pointer(), pointer);
        assert!(block.matches_memory_id(memory));
        assert!(block.initialize_dynamic_theap_metadata().is_some());
        let mut block = match block.into_source_retained_tld() {
            Err(block) => block, Ok(_) => panic!("a Theap cannot transfer as a TLD"),
        };
        allocator.free(&mut block).unwrap();
        assert_eq!(allocator.test_allocation_audit().live_capability_count, 0);
    }

    /// Direct source metadata calls use the same detached owner after thread
    /// handoff. The pinned C companion is `m2_metadata_x86_64.c`; this checks
    /// payload/provenance publication and failed replacement retention through
    /// the production process backing, without a request-specific fault seam.
    #[test]
    fn process_metadata_cross_thread_publication_and_replacement_trace() {
        let allocator = static_allocator();
        let binding = bind_process_fixture(allocator, false);
        let subprocess = binding.process().subprocess();
        let map = unsafe { binding.page_map().page_map_for_owned_ranges() }.unwrap();
        let barrier = Barrier::new(4);
        let completed = AtomicUsize::new(0);
        let first_stage: std::vec::Vec<std::sync::Mutex<Option<(MetaAllocation<'static>, usize, usize)>>> =
            (0..48).map(|_| std::sync::Mutex::new(None)).collect();
        thread::scope(|scope| {
            let mut workers = std::vec::Vec::new();
            for worker in 0..4 {
                let barrier = &barrier;
                let completed = &completed;
                let first_stage = &first_stage;
                workers.push(scope.spawn(move || {
                    let mut published = std::vec::Vec::new();
                    for iteration in 0..12 {
                        let size = [0, 1, 63, 1025, 4097, 131073][iteration % 6];
                        let alignment = [8, 64, 4096, 65536][(worker + iteration) % 4];
                        let block = if iteration % 2 == 0 {
                            allocator.zalloc(config(), size).unwrap()
                        } else {
                            allocator.zalloc_aligned(config(), size, alignment).unwrap()
                        };
                        if iteration % 2 != 0 {
                            assert_eq!(block.pointer().as_ptr().addr() % alignment, 0);
                        }
                        assert_eq!(block.memory_id().kind(), MemoryKind::Malloc);
                        assert_eq!(block.memory_id().size(), Some(size));
                        assert!(block.memory_id().initially_zero());
                        let usable = {
                            let mut entry = allocator.enter().unwrap();
                            unsafe { entry.allocator().usable_size(block.pointer()) }.unwrap()
                        };
                        // SAFETY: the exclusive allocation owns its full usable
                        // payload. Padding is initialized too because source
                        // rezalloc copies usable size, not its metadata request.
                        unsafe {
                            assert!(core::slice::from_raw_parts(block.pointer().as_ptr(), size)
                                .iter().all(|byte| *byte == 0));
                            core::ptr::write_bytes(block.pointer().as_ptr(), 0xa5, usable);
                        }
                        *first_stage[worker * 12 + iteration].lock().unwrap() =
                            Some((block, usable, iteration));
                    }
                    barrier.wait();
                    if worker == 0 {
                        // The source detached metadata lock admits allocation
                        // and release from independent callers. Free and
                        // replace peer-published metadata while those peers
                        // continue the second allocation batch below.
                        for other in 1..4 {
                            for iteration in 0..6 {
                                let (mut old, usable, index) = first_stage[other * 12 + iteration]
                                    .lock().unwrap().take().unwrap();
                                let pointer = old.pointer();
                                let memory = old.memory_id();
                                assert!(matches!(allocator.rezalloc(config(), Some(&mut old), usize::MAX),
                                    Err(MetaError::AllocationUnavailable)));
                                assert!(old.is_live());
                                assert_eq!(old.pointer(), pointer);
                                assert!(old.matches_memory_id(memory));
                                let new_size = if index % 2 == 0 { usable + 47 } else { usable / 2 };
                                let replacement = allocator.rezalloc(config(), Some(&mut old), new_size).unwrap();
                                let bytes = unsafe {
                                    core::slice::from_raw_parts(replacement.pointer().as_ptr(), new_size)
                                };
                                assert!(bytes[..usable.min(new_size)].iter().all(|byte| *byte == 0xa5));
                                assert!(bytes[usable.min(new_size)..].iter().all(|byte| *byte == 0));
                                assert!(!old.is_live());
                                assert!(MetaRelease::Malloc(replacement).release().is_ok());
                            }
                        }
                    }
                    for iteration in 12..24 {
                        let size = [0, 1, 63, 1025, 4097, 131073][iteration % 6];
                        let alignment = [8, 64, 4096, 65536][(worker + iteration) % 4];
                        let block = if iteration % 2 == 0 {
                            allocator.zalloc(config(), size).unwrap()
                        } else {
                            allocator.zalloc_aligned(config(), size, alignment).unwrap()
                        };
                        if iteration % 2 != 0 {
                            assert_eq!(block.pointer().as_ptr().addr() % alignment, 0);
                        }
                        assert_eq!(block.memory_id().kind(), MemoryKind::Malloc);
                        assert_eq!(block.memory_id().size(), Some(size));
                        assert!(block.memory_id().initially_zero());
                        let usable = {
                            let mut entry = allocator.enter().unwrap();
                            unsafe { entry.allocator().usable_size(block.pointer()) }.unwrap()
                        };
                        unsafe {
                            assert!(core::slice::from_raw_parts(block.pointer().as_ptr(), size)
                                .iter().all(|byte| *byte == 0));
                            core::ptr::write_bytes(block.pointer().as_ptr(), 0xa5, usable);
                        }
                        published.push((block, usable, iteration));
                    }
                    completed.fetch_add(1, Ordering::Release);
                    published
                }));
            }
            // The mid-run barrier publishes the first batch; the joined
            // second batch transfers the remaining exact capabilities.
            let mut remaining = std::vec::Vec::new();
            for worker in workers {
                remaining.extend(worker.join().unwrap());
            }
            for slot in &first_stage {
                let allocation = slot.lock().unwrap().take();
                if let Some(allocation) = allocation { remaining.push(allocation); }
            }
            for (mut old, usable, iteration) in remaining {
                let pointer = old.pointer();
                let memory = old.memory_id();
                assert!(matches!(allocator.rezalloc(config(), Some(&mut old), usize::MAX),
                    Err(MetaError::AllocationUnavailable)));
                assert!(old.is_live());
                assert_eq!(old.pointer(), pointer);
                assert!(old.matches_memory_id(memory));
                // SAFETY: the transferred live capability keeps this page
                // registered while the lookup and payload reads execute.
                let page = unsafe { map.checked_lookup(pointer.as_ptr()) };
                assert!(subprocess.is_metadata_page(unsafe { page.as_ref() }));
                let new_size = if iteration % 2 == 0 { usable + 47 } else { usable / 2 };
                let replacement = allocator.rezalloc(config(), Some(&mut old), new_size).unwrap();
                let bytes = unsafe { core::slice::from_raw_parts(replacement.pointer().as_ptr(), new_size) };
                assert!(bytes[..usable.min(new_size)].iter().all(|byte| *byte == 0xa5));
                assert!(bytes[usable.min(new_size)..].iter().all(|byte| *byte == 0));
                assert!(!old.is_live());
                assert!(MetaRelease::Malloc(replacement).release().is_ok());
            }
        });
        assert_eq!(completed.load(Ordering::Acquire), 4);
        assert_eq!(allocator.test_allocation_audit().live_capability_count, 0);
        let mut entry = allocator.enter().unwrap();
        let MetadataPageAllocator::Process(engine) = entry.allocator() else { panic!("process engine"); };
        assert!(engine.collect_retired(true));
        std::println!("CRABC_MI_M2_METADATA_LIFECYCLE_TRACE_BEGIN");
        std::println!("m2.metadata.lifecycle.workers=4");
        std::println!("m2.metadata.lifecycle.published=96");
        std::println!("m2.metadata.lifecycle.failed_replacement_preserved=96");
        std::println!("m2.metadata.lifecycle.replaced_released=96");
        std::println!("m2.metadata.lifecycle.midrun_peer_replacements=18");
        std::println!("CRABC_MI_M2_METADATA_LIFECYCLE_TRACE_END");
    }

    fn bind_process_fixture(allocator: Pin<&'static MetaAllocator>, disallow_arena: bool)
        -> crate::process_init::ProcessMainBackingBinding {
        use crate::config::{VmOptions, VmOption, VmOptionEnvironment};
        let mut options = VmOptions::uninitialized();
        options.initialize_all(|_| VmOptionEnvironment::Absent);
        options.set(VmOption::ArenaReserve, 64 * 1024); // source size option in KiB
        // These existing fixture observations deliberately report no
        // overcommit; explicitly select source full-page commitment.
        options.set(VmOption::PageCommitOnDemand, 0);
        options.set(VmOption::DisallowArenaAlloc, i64::from(disallow_arena));
        let binding = process_binding_fixture(allocator.test_default_subprocess(), options);
        allocator.bind_process_backing(binding).unwrap();
        binding
    }

    fn process_binding_fixture(subprocess: &'static MainSubprocess, options: crate::config::VmOptions)
        -> crate::process_init::ProcessMainBackingBinding {
        let storage = crate::process_init::ProcessMainInitializationStorage::test_static_owner();
        let map = crate::process_page_map::ProcessPageMapStorage::test_static_owner();
        // SAFETY: these process-lifetime owners are isolated to this test;
        // this is their sole pre-READY coordinator setup, with no TLS owner.
        unsafe { storage.test_prepare_vm_process_backing_binding(config(), options, subprocess, map) }.unwrap()
    }

    /// The pinned v3.5.0 regular-page policy used by the incremental metadata
    /// probes. `disallow_arena` selects the source OS fallback after the
    /// process policy has already selected on-demand commitment.
    fn incremental_process_options(disallow_arena: bool) -> crate::config::VmOptions {
        let mut options = crate::config::VmOptions::uninitialized();
        options.initialize_all(|_| crate::config::VmOptionEnvironment::Absent);
        options.set(crate::config::VmOption::PageCommitOnDemand, 1);
        options.set(crate::config::VmOption::ArenaEagerCommit, 0);
        options.set(crate::config::VmOption::ArenaReserve, 64 * 1024);
        options.set(crate::config::VmOption::PurgeDelay, -1);
        options.set(
            crate::config::VmOption::DisallowArenaAlloc,
            i64::from(disallow_arena),
        );
        options
    }

    #[test]
    fn process_metadata_uses_os_policy_without_constructing_an_initial_arena() {
        let allocator = static_allocator();
        let binding = bind_process_fixture(allocator, true);
        let process = binding.process();
        let page_map = binding.page_map();
        let before = process.subprocess().vm_statistics().snapshot();
        let mut block = allocator.zalloc(config(), 2 * ARENA_MIN_SIZE).unwrap();
        assert!(allocator.test_private_page_map_address().is_none());
        let map = unsafe { page_map.page_map_for_owned_ranges() }.unwrap();
        let page = unsafe { map.checked_lookup(block.pointer().as_ptr()) };
        assert!(!page.is_null());
        assert_eq!(unsafe { (*page).memid().kind() }, MemoryKind::Os);
        assert_eq!(process.subprocess().arena_backing().registry().count(), 0);
        allocator.bind_process_backing(binding).unwrap();
        let pointer = block.pointer();
        allocator.free(&mut block).unwrap();
        assert!(unsafe { map.checked_lookup(pointer.as_ptr()) }.is_null());
        assert_eq!(process.subprocess().vm_statistics().snapshot().reserved_current, before.reserved_current);
    }

    #[test]
    fn process_metadata_backing_rejects_foreign_map_or_policy_and_legacy_migration() {
        let allocator = static_allocator();
        let binding = bind_process_fixture(allocator, true);
        let mut options = crate::config::VmOptions::uninitialized();
        options.initialize_all(|_| crate::config::VmOptionEnvironment::Absent);
        let foreign = process_binding_fixture(MainSubprocess::test_static_owner(), options);
        assert_eq!(allocator.bind_process_backing(foreign), Err(MetaError::SubprocessMismatch));
        let replacement = process_binding_fixture(
            binding.process().main_subprocess().unwrap(), options,
        );
        assert_ne!(replacement.page_map().root().unwrap(), binding.page_map().root().unwrap());
        assert_eq!(allocator.bind_process_backing(replacement), Err(MetaError::BackingAlreadySelected));
        let legacy = static_allocator();
        let mut live = legacy.zalloc(config(), 64).unwrap();
        let own_binding = process_binding_fixture(legacy.test_default_subprocess(), options);
        assert_eq!(legacy.bind_process_backing(own_binding),
            Err(MetaError::BackingAlreadySelected));
        legacy.free(&mut live).unwrap();
    }

    #[test]
    fn process_metadata_incrementally_commits_and_releases_its_arena_page_prefix() {
        let allocator = static_allocator();
        let binding = process_binding_fixture(
            allocator.test_default_subprocess(),
            incremental_process_options(false),
        );
        let process = binding.process();
        allocator.bind_process_backing(binding).unwrap();
        let mut allocations = std::vec::Vec::new();
        for _ in 0..400 {
            allocations.push(allocator.zalloc(config(), 64)
                .expect("source incremental policy must allocate without committing the whole page"));
        }
        let map = unsafe { binding.page_map().page_map_for_owned_ranges() }.unwrap();
        let pointer = allocations[0].pointer();
        let page = unsafe { map.checked_lookup(pointer.as_ptr()) };
        assert!(!page.is_null());
        let committed = unsafe { (*page).slice_pcommitted() } as usize * 4096;
        assert_eq!(unsafe { (*page).block_size() }, 64);
        assert_eq!(unsafe { (*page).capacity() }, 512);
        assert_eq!(
            unsafe { (*page).start() }.addr() % crate::config::ARENA_SLICE_SIZE,
            64,
            "the C oracle's offset is relative to the aligned page slice, not Page metadata"
        );
        assert_eq!(committed, 48 * 1024);
        assert_eq!(process.subprocess().arena_backing().registry().count(), 1);
        let before_release = process.subprocess().vm_statistics().snapshot();
        for allocation in &mut allocations {
            let bytes = unsafe { core::slice::from_raw_parts(allocation.pointer().as_ptr(), 64) };
            assert!(bytes.iter().all(|byte| *byte == 0));
            allocator.free(allocation).unwrap();
        }
        let mut entry = allocator.enter().unwrap();
        let MetadataPageAllocator::Process(engine) = entry.allocator() else { panic!("process engine"); };
        assert!(engine.collect_retired(true));
        assert!(unsafe { map.checked_lookup(pointer.as_ptr()) }.is_null());
        let after_release = process.subprocess().vm_statistics().snapshot();
        assert_eq!(before_release.committed_current - after_release.committed_current, committed as i64);
    }

    #[test]
    fn process_metadata_os_only_on_demand_commits_before_publishing_capacity() {
        let allocator = static_allocator();
        let binding = process_binding_fixture(
            allocator.test_default_subprocess(),
            incremental_process_options(true),
        );
        let process = binding.process();
        allocator.bind_process_backing(binding).unwrap();
        let mut allocations = std::vec::Vec::new();
        for _ in 0..400 {
            allocations.push(allocator.zalloc(config(), 64).expect(
                "the OS-only source fallback commits its first prefix before writing free-list links",
            ));
        }
        let map = unsafe { binding.page_map().page_map_for_owned_ranges() }.unwrap();
        let pointer = allocations[0].pointer();
        let page = unsafe { map.checked_lookup(pointer.as_ptr()) };
        assert!(!page.is_null());
        for allocation in &allocations {
            assert_eq!(unsafe { map.checked_lookup(allocation.pointer().as_ptr()) }, page);
        }
        assert_eq!(unsafe { (*page).memid().kind() }, MemoryKind::Os);
        assert!(
            !unsafe { (*page).memid().initially_committed() },
            "the reserved OS area must not claim full commitment before its prefix is committed"
        );
        let committed = unsafe { (*page).slice_pcommitted() } as usize * 4096;
        assert_eq!(unsafe { (*page).block_size() }, 64);
        assert_eq!(unsafe { (*page).capacity() }, 512);
        assert_eq!(
            unsafe { (*page).start() }.addr() % crate::config::ARENA_SLICE_SIZE,
            64,
            "the C oracle's offset is relative to the aligned page slice, not Page metadata"
        );
        assert_eq!(committed, 48 * 1024);
        assert_eq!(process.subprocess().arena_backing().registry().count(), 0);
        let before_release = process.subprocess().vm_statistics().snapshot();
        for allocation in &mut allocations {
            let bytes = unsafe { core::slice::from_raw_parts(allocation.pointer().as_ptr(), 64) };
            assert!(bytes.iter().all(|byte| *byte == 0));
            allocator.free(allocation).unwrap();
        }
        let mut entry = allocator.enter().unwrap();
        let MetadataPageAllocator::Process(engine) = entry.allocator() else { panic!("process engine"); };
        assert!(engine.collect_retired(true));
        assert!(unsafe { map.checked_lookup(pointer.as_ptr()) }.is_null());
        let after_release = process.subprocess().vm_statistics().snapshot();
        assert_eq!(before_release.committed_current - after_release.committed_current, committed as i64);
    }

    #[test]
    fn process_metadata_terminal_close_denies_every_bitmap_projection() {
        for poison in [false, true] {
            let allocator = static_allocator();
            let binding = process_binding_fixture(
                allocator.test_default_subprocess(), incremental_process_options(false),
            );
            allocator.bind_process_backing(binding).unwrap();
            let layout = BitmapLayout::for_bit_count(1024).unwrap();
            let mut published = allocator.zalloc_aligned(config(), layout.byte_size(), BCHUNK_SIZE).unwrap();
            published.initialize_zeroed_bitmap(allocator, layout, |_| ()).unwrap();
            let mut copied = allocator.zalloc_aligned(config(), layout.byte_size(), BCHUNK_SIZE).unwrap();
            copied.copy_bitmap_image_from(allocator, layout, &published, layout).unwrap();
            let mut fresh = allocator.zalloc_aligned(config(), layout.byte_size(), BCHUNK_SIZE).unwrap();
            if poison {
                let mut entry = allocator.enter().unwrap();
                let MetadataPageAllocator::Process(engine) = entry.allocator() else { panic!("process"); };
                engine.test_latch_metadata_commit_poison();
            }
            // The isolated source image remains mapped. No earlier typed
            // view survives sealing; every following safe projection must
            // reject before entering a caller callback or copying bytes.
            let result = unsafe { allocator.close_process_engine_quiescent() };
            assert_eq!(result, if poison { Err(MetaCloseError::UnfinishedEngine) } else { Ok(()) });
            assert_eq!(published.with_bitmap_view(allocator, layout, |_| ()),
                Err(MetaBitmapProjectionError::InvalidImage));
            assert_eq!(fresh.initialize_zeroed_bitmap(allocator, layout, |_| ()),
                Err(MetaBitmapProjectionError::InvalidImage));
            assert_eq!(copied.publish_preserved_bitmap(allocator, layout, |_| ()),
                Err(MetaBitmapProjectionError::InvalidImage));
            assert_eq!(fresh.copy_bitmap_image_from(allocator, layout, &published, layout),
                Err(MetaBitmapProjectionError::InvalidImage));
        }
    }

    #[test]
    fn process_metadata_terminal_close_retains_source_direct_os_mapping() {
        let allocator = static_allocator();
        let binding = process_binding_fixture(
            allocator.test_default_subprocess(), incremental_process_options(true),
        );
        allocator.bind_process_backing(binding).unwrap();
        let allocation = allocator.zalloc(config(), 64).unwrap();
        let map = unsafe { binding.page_map().page_map_for_owned_ranges() }.unwrap();
        let page = unsafe { map.checked_lookup(allocation.pointer().as_ptr()) };
        assert!(!page.is_null());
        let malloc_owned = usize::from(allocation.memory_id().kind() == MemoryKind::Malloc);
        let os_backed = usize::from(unsafe { (*page).memid().kind() } == MemoryKind::Os);
        let address = allocation.pointer().as_ptr().map_addr(|value| value & !4095);
        let mut residency = 0_u8;
        let before = usize::from(unsafe { crabc_core::mm::mincore_raw(address, 4096, &mut residency) }.is_ok());
        // SAFETY: isolated permanently quiescent fixture retains the exact
        // capability and pinned source images; no typed page borrow escaped.
        unsafe { allocator.close_process_engine_quiescent() }.unwrap();
        let after = usize::from(unsafe { crabc_core::mm::mincore_raw(address, 4096, &mut residency) }.is_ok());
        let values = [malloc_owned, os_backed, before, after];
        assert_eq!(values, [1, 1, 1, 1]);
        for (index, value) in values.into_iter().enumerate() {
            std::println!("m2.metadata.retirement.{index}={value}");
        }
    }

    #[test]
    fn process_metadata_terminal_close_seals_live_capabilities_and_retains_poison() {
        let allocator = static_allocator();
        let binding = process_binding_fixture(
            allocator.test_default_subprocess(), incremental_process_options(false),
        );
        allocator.bind_process_backing(binding).unwrap();
        let mut allocation = allocator.zalloc(config(),
            DynamicThreadLocalBacking::allocation_size(1).unwrap()).unwrap();
        assert!(allocation.dynamic_thread_local_backing_mut(1).is_some());
        assert!(allocation.is_live());
        let audit = allocator.test_allocation_audit();
        // SAFETY: this isolated fixture has no thread or escaped typed view;
        // its leaked backing and exact capability remain retained below.
        unsafe { allocator.close_process_engine_quiescent() }.unwrap();
        assert_eq!(allocator.status.load(Ordering::Acquire), CLOSED);
        assert!(!allocation.is_live());
        assert!(allocation.dynamic_thread_local_backing_mut(1).is_none());
        assert!(matches!(allocator.zalloc(config(), 64), Err(MetaError::Closed)));
        assert_eq!(allocator.free(&mut allocation), Err(MetaError::Closed));
        assert_eq!(allocator.test_allocation_audit(), audit);
        assert!(unsafe { (*allocator.process_backing.get()).is_none() });
        assert_eq!(unsafe { allocator.close_process_engine_quiescent() },
            Err(MetaCloseError::Entry(MetaError::Closed)));

        let retained = static_allocator();
        let binding = process_binding_fixture(
            retained.test_default_subprocess(), incremental_process_options(false),
        );
        retained.bind_process_backing(binding).unwrap();
        let capability = retained.zalloc(config(), 64).unwrap();
        {
            let mut entry = retained.enter().unwrap();
            let MetadataPageAllocator::Process(engine) = entry.allocator() else { panic!("process"); };
            engine.test_latch_metadata_commit_poison();
        }
        assert_eq!(unsafe { retained.close_process_engine_quiescent() },
            Err(MetaCloseError::UnfinishedEngine));
        assert_eq!(retained.status.load(Ordering::Acquire), CLOSE_RETAINED);
        assert!(!capability.is_live());
        assert!(unsafe { (*retained.process_backing.get()).is_some() });
        // Only this isolated test inspects the terminal owner's retained slot.
        // Production has no safe engine entry after CLOSE_RETAINED.
        let MetadataPageAllocator::Process(engine) = (unsafe {
            (*retained.allocator.get()).assume_init_ref()
        }) else { panic!("exact process engine retained"); };
        assert!(engine.test_metadata_commit_poison());
        assert!(matches!(retained.zalloc(config(), 64), Err(MetaError::Closed)));
    }

    #[test]
    fn process_metadata_failed_extension_keeps_the_old_page_and_selects_fresh() {
        let fault = fault::install(fault::Plan::disabled());
        let allocator = static_allocator();
        let binding = process_binding_fixture(
            allocator.test_default_subprocess(),
            incremental_process_options(false),
        );
        allocator.bind_process_backing(binding).unwrap();
        let mut allocations = std::vec::Vec::new();
        for _ in 0..384 { allocations.push(allocator.zalloc(config(), 64).unwrap()); }
        let map = unsafe { binding.page_map().page_map_for_owned_ranges() }.unwrap();
        let old_page = unsafe { map.checked_lookup(allocations[0].pointer().as_ptr()) };
        assert_eq!(unsafe { (*old_page).capacity() }, 384);
        assert_eq!(unsafe { (*old_page).slice_pcommitted() }, 8);
        let before = binding.process().subprocess().vm_statistics().snapshot();
        fault.set(fault::Plan::at(fault::Point::Commit, 1, crabc_core::Errno::NOMEM));
        let mut next = allocator.zalloc(config(), 64)
            .expect("source candidate extension failure selects a fresh page without poisoning the engine");
        assert_ne!(unsafe { map.checked_lookup(next.pointer().as_ptr()) }, old_page);
        assert_eq!(unsafe { (*old_page).capacity() }, 384);
        assert_eq!(unsafe { (*old_page).slice_pcommitted() }, 8);
        let after = binding.process().subprocess().vm_statistics().snapshot();
        assert_eq!(after.committed_current - before.committed_current, 16 * 1024);
        assert_eq!(after.commit_calls - before.commit_calls, 2);
        for allocation in &mut allocations { allocator.free(allocation).unwrap(); }
        allocator.free(&mut next).unwrap();
        let mut entry = allocator.enter().unwrap();
        let MetadataPageAllocator::Process(engine) = entry.allocator() else { panic!("process engine"); };
        assert_eq!(engine.test_forced_collect_retired_call_count(), 0);
        assert!(engine.collect_retired(true));
    }

    #[test]
    fn process_metadata_os_only_failed_extension_selects_fresh_without_forging_commitment() {
        let fault = fault::install(fault::Plan::disabled());
        let allocator = static_allocator();
        let binding = process_binding_fixture(
            allocator.test_default_subprocess(),
            incremental_process_options(true),
        );
        allocator.bind_process_backing(binding).unwrap();
        let mut allocations = std::vec::Vec::new();
        for _ in 0..384 { allocations.push(allocator.zalloc(config(), 64).unwrap()); }
        let map = unsafe { binding.page_map().page_map_for_owned_ranges() }.unwrap();
        let old_page = unsafe { map.checked_lookup(allocations[0].pointer().as_ptr()) };
        assert_eq!(unsafe { (*old_page).memid().kind() }, MemoryKind::Os);
        assert!(!unsafe { (*old_page).memid().initially_committed() });
        assert_eq!(unsafe { (*old_page).capacity() }, 384);
        assert_eq!(unsafe { (*old_page).slice_pcommitted() }, 8);
        let before = binding.process().subprocess().vm_statistics().snapshot();
        fault.set(fault::Plan::at(fault::Point::Commit, 1, crabc_core::Errno::NOMEM));
        let mut next = allocator.zalloc(config(), 64).expect(
            "a failed published OS-page extension retries through source fresh selection",
        );
        let fresh_page = unsafe { map.checked_lookup(next.pointer().as_ptr()) };
        assert_ne!(fresh_page, old_page);
        assert_eq!(unsafe { (*old_page).capacity() }, 384);
        assert_eq!(unsafe { (*old_page).slice_pcommitted() }, 8);
        assert!(!unsafe { (*fresh_page).memid().initially_committed() });
        let after = binding.process().subprocess().vm_statistics().snapshot();
        assert_eq!(after.committed_current - before.committed_current, 16 * 1024);
        assert_eq!(after.commit_calls - before.commit_calls, 3,
            "failed published extension, then fresh metadata and prefix commitments");
        for allocation in &mut allocations { allocator.free(allocation).unwrap(); }
        allocator.free(&mut next).unwrap();
        let mut entry = allocator.enter().unwrap();
        let MetadataPageAllocator::Process(engine) = entry.allocator() else { panic!("process engine"); };
        assert_eq!(engine.test_forced_collect_retired_call_count(), 0);
        assert!(engine.collect_retired(true));
    }

    #[test]
    fn process_metadata_os_only_failed_initial_prefix_rolls_back_before_source_retry() {
        let fault = fault::install(fault::Plan::disabled());
        let allocator = static_allocator();
        let binding = process_binding_fixture(
            allocator.test_default_subprocess(),
            incremental_process_options(true),
        );
        allocator.bind_process_backing(binding).unwrap();
        // Warm the process PageMap and a distinct small bin so the selected
        // failure is the private OS claim's first page-area prefix, after its
        // metadata commitment but before Page/free-list publication.
        let mut warm = allocator.zalloc(config(), 128).unwrap();
        let before = binding.process().subprocess().vm_statistics().snapshot();
        fault.set(fault::Plan::at(fault::Point::Commit, 2, crabc_core::Errno::NOMEM));
        let mut next = allocator.zalloc(config(), 64).expect(
            "the failed private OS prefix rolls back and source fresh retry commits a new prefix",
        );
        let map = unsafe { binding.page_map().page_map_for_owned_ranges() }.unwrap();
        let page = unsafe { map.checked_lookup(next.pointer().as_ptr()) };
        let pointer = next.pointer();
        assert_eq!(unsafe { (*page).memid().kind() }, MemoryKind::Os);
        assert!(!unsafe { (*page).memid().initially_committed() });
        assert_eq!(unsafe { (*page).capacity() }, 128);
        assert_eq!(unsafe { (*page).slice_pcommitted() }, 4);
        let after = binding.process().subprocess().vm_statistics().snapshot();
        assert_eq!(after.committed_current - before.committed_current, 16 * 1024);
        assert_eq!(after.commit_calls - before.commit_calls, 4,
            "metadata, failed prefix, then metadata and prefix for the source retry");
        allocator.free(&mut next).unwrap();
        {
            let mut entry = allocator.enter().unwrap();
            let MetadataPageAllocator::Process(engine) = entry.allocator() else { panic!("process engine"); };
            assert!(engine.collect_retired(true));
        }
        assert!(unsafe { map.checked_lookup(pointer.as_ptr()) }.is_null());
        let after_release = binding.process().subprocess().vm_statistics().snapshot();
        assert_eq!(after_release.reserved_current, before.reserved_current,
            "the failed unpublished claim retains no reservation");
        assert_eq!(after_release.committed_current, before.committed_current,
            "the failed unpublished claim retains no prefix accounting");
        allocator.free(&mut warm).unwrap();
        let mut entry = allocator.enter().unwrap();
        let MetadataPageAllocator::Process(engine) = entry.allocator() else { panic!("process engine"); };
        assert!(engine.collect_retired(true));
    }

    #[test]
    fn process_metadata_failed_initial_prefix_takes_source_retry_before_forced_collection() {
        let fault = fault::install(fault::Plan::disabled());
        let allocator = static_allocator();
        let binding = process_binding_fixture(
            allocator.test_default_subprocess(),
            incremental_process_options(false),
        );
        allocator.bind_process_backing(binding).unwrap();
        // A different bin warms the arena, aligned page metadata, and shared
        // PageMap so only the requested page's prefix calls are faulted.
        let mut warm = allocator.zalloc(config(), 128).unwrap();
        let before = binding.process().subprocess().vm_statistics().snapshot();
        fault.set(fault::Plan::at(fault::Point::Commit, 1, crabc_core::Errno::NOMEM));
        let mut next = allocator.zalloc(config(), 64).unwrap();
        let after = binding.process().subprocess().vm_statistics().snapshot();
        assert_eq!(after.committed_current - before.committed_current, 16 * 1024);
        assert_eq!(after.commit_calls - before.commit_calls, 2);
        allocator.free(&mut next).unwrap();
        allocator.free(&mut warm).unwrap();
        let mut entry = allocator.enter().unwrap();
        let MetadataPageAllocator::Process(engine) = entry.allocator() else { panic!("process engine"); };
        assert_eq!(engine.test_forced_collect_retired_call_count(), 0,
            "mi_page_queue_find_free_ex retries before the separate forced collection fallback");
        assert!(engine.collect_retired(true));
    }

    #[test]
    fn initial_metadata_binding_rejects_a_foreign_policy_of_existing_process_arenas() {
        use crate::page_backing::{PageBacking, ProcessMetadataPageBacking};
        let allocator = static_allocator();
        let mut options = crate::config::VmOptions::uninitialized();
        options.initialize_all(|_| crate::config::VmOptionEnvironment::Absent);
        options.set(crate::config::VmOption::ArenaReserve, 64 * 1024);
        let first_binding = process_binding_fixture(allocator.test_default_subprocess(), options);
        let first = first_binding.process();
        let claim = ProcessMetadataPageBacking::new(first)
            .claim(config(), ArenaId::none(), 1, true, 0).unwrap();
        let second_binding = process_binding_fixture(first.main_subprocess().unwrap(), options);
        let before = first.subprocess().vm_statistics().snapshot();
        let rejected = allocator.bind_process_backing(second_binding);
        assert!(claim.release());
        assert_eq!(rejected, Err(MetaError::BackingAlreadySelected));
        assert_eq!(first.subprocess().vm_statistics().snapshot(), before);
        allocator.bind_process_backing(first_binding).unwrap();
    }

    #[test]
    fn zero_and_aligned_zero_metadata_has_malloc_provenance() {
        let allocator = static_allocator();
        let mut block = allocator.zalloc(config(), 91).unwrap();
        let aligned = allocator.zalloc_aligned(config(), 47, 4096).unwrap();

        assert_eq!(block.memory_id().kind(), MemoryKind::Malloc);
        assert!(block.memory_id().is_pinned());
        assert!(block.memory_id().initially_committed());
        assert!(block.memory_id().initially_zero());
        assert_eq!(block.memory_id().size(), Some(91));
        assert_eq!(aligned.pointer().as_ptr().addr() & 4095, 0);
        // SAFETY: this fresh metadata capability owns 91 initialized bytes.
        assert!(unsafe { core::slice::from_raw_parts(block.pointer().as_ptr(), 91) }
            .iter()
            .all(|byte| *byte == 0));
        assert!(allocator.free(&mut block).is_ok());
        let mut aligned = aligned;
        assert!(allocator.free(&mut aligned).is_ok());
    }

    #[test]
    fn typed_release_uses_the_metadata_capabilitys_recorded_owner() {
        let allocator = static_allocator();
        let block = allocator.zalloc(config(), 91).unwrap();
        assert!(MetaRelease::Malloc(block).release().is_ok());
    }

    #[test]
    fn typed_malloc_release_retains_a_terminal_capability_for_diagnosis() {
        let allocator = static_allocator();
        let mut block = allocator.zalloc(config(), 91).unwrap();
        allocator.free(&mut block).unwrap();

        let failure = MetaRelease::Malloc(block)
            .release()
            .expect_err("a stale metadata capability must not be released twice");
        let MetaReleaseFailure::MallocTerminal { error, allocation } = failure else {
            panic!("typed Malloc release returned the wrong failure branch");
        };
        assert_eq!(error, MetaError::ReleasedOrStale);
        assert!(
            !allocation.is_live(),
            "a failed exact-owner free is terminal rather than retryable"
        );
    }

    #[test]
    fn typed_malloc_release_retains_a_live_capability_after_recursive_entry_rejection() {
        let allocator = static_allocator();
        let block = allocator.zalloc(config(), 91).unwrap();
        let pointer = block.pointer();
        let memory_id = block.memory_id();
        let live_audit = MetaAllocationAudit {
            live_capability_count: 1,
            high_water_capability_count: 1,
        };
        assert_eq!(allocator.test_allocation_audit(), live_audit);

        let entry = allocator.enter().unwrap();
        let failure = MetaRelease::Malloc(block)
            .release()
            .expect_err("same-thread Malloc release must reject before claiming its capability");
        let MetaReleaseFailure::MallocRetryable { error, allocation } = failure else {
            panic!("same-thread Malloc release returned the wrong failure branch");
        };
        assert_eq!(error, MetaError::RecursiveEntry);
        assert!(
            allocation.is_live(),
            "the pre-claim failure retains the exact Malloc capability for retry"
        );
        assert_eq!(allocation.pointer(), pointer);
        assert!(allocation.matches_memory_id(memory_id));
        assert_eq!(allocator.test_allocation_audit(), live_audit);

        drop(entry);
        assert!(MetaRelease::Malloc(allocation).release().is_ok());
        assert_eq!(
            allocator.test_allocation_audit(),
            MetaAllocationAudit {
                live_capability_count: 0,
                high_water_capability_count: 1,
            }
        );
    }

    #[test]
    fn typed_regular_os_release_returns_the_exact_mapping_for_retry() {
        let mapping = Mapping::map_for_allocator(config(), 4096, MapAccess::Reserved).unwrap();
        let fault = fault::install(fault::Plan::at(
            fault::Point::Unmap,
            1,
            Errno::NOMEM,
        ));

        let failure = MetaRelease::RegularOs(mapping)
            .release()
            .expect_err("a failed unmap must retain the mapping owner");
        let MetaReleaseFailure::RegularOs {
            error,
            mut mapping,
        } = failure
        else {
            panic!("typed regular-OS release returned the wrong failure branch");
        };
        assert_eq!(error, Errno::NOMEM);
        assert_eq!(mapping.length().unwrap(), 4096);

        fault.set(fault::Plan::disabled());
        mapping.unmap().unwrap();
    }

    #[test]
    fn typed_regular_os_release_closes_a_live_mapping() {
        let mapping = Mapping::map_for_allocator(config(), 4096, MapAccess::Reserved).unwrap();
        assert!(MetaRelease::RegularOs(mapping).release().is_ok());
    }

    #[test]
    fn selected_aligned_main_metadata_projects_only_an_exact_transient_bitmap_image() {
        let allocator = cold_static_allocator();
        let subprocess = MainSubprocess::test_static_owner();
        allocator
            .prepare_for_main_subprocess(config(), subprocess)
            .expect("the selected detached metadata image publishes before bitmap demand");
        let layout = BitmapLayout::for_bit_count(1024).unwrap();
        let wrong_layout = BitmapLayout::for_bit_count(512).unwrap();
        let mut image = allocator
            .zalloc_aligned_for_main_subprocess(
                config(),
                subprocess,
                layout.byte_size(),
                BCHUNK_SIZE,
            )
            .expect("the selected-main aligned bitmap allocation succeeds");

        assert_eq!(image.pointer().as_ptr().addr() % BCHUNK_SIZE, 0);
        assert_eq!(image.memory_id().kind(), MemoryKind::Malloc);
        assert!(allocator
            .get_ref()
            .registry
            .is_bound_to_subprocess(subprocess.as_ptr()));
        assert_eq!(
            image.initialize_zeroed_bitmap(allocator, wrong_layout, |_| ()),
            Err(MetaBitmapProjectionError::InvalidImage),
            "a projection cannot name fewer bytes than the retained typed image"
        );
        assert_eq!(
            image
                .initialize_zeroed_bitmap(allocator, layout, |view| unsafe {
                    view.unsafe_set_range_local(0, 1)
                })
                .expect("the exact zeroed image initializes"),
            Some(())
        );
        assert_eq!(
            image
                .with_bitmap_view(allocator, layout, |view| view.try_find_and_claim_lowest())
                .expect("the bitmap view is a transient exact projection"),
            Some(0)
        );
        let foreign = static_allocator();
        assert_eq!(
            image.with_bitmap_view(foreign, layout, |_| ()),
            Err(MetaBitmapProjectionError::ForeignOwner)
        );
        allocator.free(&mut image).unwrap();
    }

    #[test]
    fn tls_projection_cannot_be_reinterpreted_as_dynamic_arena_or_bitmap_image() {
        let allocator = cold_static_allocator();
        let subprocess = MainSubprocess::test_static_owner();
        allocator
            .prepare_for_main_subprocess(config(), subprocess)
            .expect("the selected detached metadata image publishes before TLS-image demand");
        let arena_layout = ArenaPagesLayout::for_slice_count(crate::config::BCHUNK_BITS)
            .expect("the source minimum arena has a dynamic pages layout");
        assert_eq!(arena_layout.byte_size(), 12_416);
        let count = (1..=u16::MAX as usize)
            .find(|count| DynamicThreadLocalBacking::allocation_size(*count) == Some(arena_layout.byte_size()))
            .expect("the source-sized arena pages image coincides with one valid TLS backing");
        let bitmap_layout = BitmapLayout::for_bit_count(crate::config::BCHUNK_BITS * 192)
            .expect("the same aligned image also has one ordinary bitmap layout");
        assert_eq!(bitmap_layout.byte_size(), arena_layout.byte_size());

        let mut image = allocator
            .zalloc_aligned_for_main_subprocess(
                config(),
                subprocess,
                arena_layout.byte_size(),
                BCHUNK_SIZE,
            )
            .expect("the colliding aligned metadata request succeeds");
        let memory = image.memory_id();
        {
            let backing = image
                .dynamic_thread_local_backing_mut(count)
                .expect("the exact flexible TLS image projects once");
            // SAFETY: this exact typed backing projection owns the flexible
            // source request and writes its fixed header before publication.
            unsafe { backing.initialize_owned_header(memory, count) };
            assert_eq!(backing.count(), count);
        }
        assert!(
            image.dynamic_thread_local_backing_mut(count).is_some(),
            "the retained TLS role permits its own later typed projection"
        );
        assert_eq!(
            image.initialize_zeroed_bitmap(allocator, bitmap_layout, |_| ()),
            Err(MetaBitmapProjectionError::InvalidImage),
            "a TLS-projected image cannot become an ordinary bitmap"
        );
        assert!(
            !image.initialize_dynamic_arena_pages(allocator, arena_layout),
            "a TLS-projected image cannot become a dynamic arena-pages header"
        );
        allocator.free(&mut image).unwrap();

        let mut bitmap = allocator
            .zalloc_aligned_for_main_subprocess(
                config(),
                subprocess,
                bitmap_layout.byte_size(),
                BCHUNK_SIZE,
            )
            .expect("the same-sized ordinary bitmap image allocates");
        assert!(bitmap
            .initialize_zeroed_bitmap(allocator, bitmap_layout, |_| ())
            .is_ok());
        assert!(
            bitmap.dynamic_thread_local_backing_mut(count).is_none(),
            "a published ordinary bitmap cannot later take the TLS backing role"
        );
        allocator.free(&mut bitmap).unwrap();
    }

    #[test]
    fn bitmap_image_lifecycle_rejects_out_of_order_or_duplicate_projection() {
        let allocator = cold_static_allocator();
        let subprocess = MainSubprocess::test_static_owner();
        allocator
            .prepare_for_main_subprocess(config(), subprocess)
            .expect("the selected detached metadata image publishes before bitmap lifecycle demand");
        let layout = BitmapLayout::for_bit_count(1024).unwrap();
        let mut source = allocator
            .zalloc_aligned_for_main_subprocess(
                config(),
                subprocess,
                layout.byte_size(),
                BCHUNK_SIZE,
            )
            .expect("the source image allocation succeeds");
        let mut target = allocator
            .zalloc_aligned_for_main_subprocess(
                config(),
                subprocess,
                layout.byte_size(),
                BCHUNK_SIZE,
            )
            .expect("the replacement image allocation succeeds");

        assert_eq!(
            target.with_bitmap_view(allocator, layout, |_| ()),
            Err(MetaBitmapProjectionError::InvalidImage),
            "a fresh typed image is not observable before initialization"
        );
        assert_eq!(
            target.publish_preserved_bitmap(allocator, layout, |_| ()),
            Err(MetaBitmapProjectionError::InvalidImage),
            "a fresh image cannot publish without an exact copied prefix"
        );
        assert_eq!(
            source.initialize_zeroed_bitmap(allocator, layout, |_| ()),
            Ok(())
        );
        assert_eq!(
            source.initialize_zeroed_bitmap(allocator, layout, |_| ()),
            Err(MetaBitmapProjectionError::InvalidImage),
            "a direct zero initializer cannot overwrite a published image"
        );

        assert_eq!(
            target.copy_bitmap_image_from(allocator, layout, &source, layout),
            Ok(())
        );
        assert_eq!(
            target.copy_bitmap_image_from(allocator, layout, &source, layout),
            Err(MetaBitmapProjectionError::InvalidImage),
            "a copied replacement cannot copy a second prefix"
        );
        assert_eq!(
            target.with_bitmap_view(allocator, layout, |_| ()),
            Err(MetaBitmapProjectionError::InvalidImage),
            "a copied prefix is not observable before its Release publication"
        );
        assert_eq!(
            target.publish_preserved_bitmap(allocator, layout, |_| ()),
            Ok(())
        );
        assert_eq!(
            target.publish_preserved_bitmap(allocator, layout, |_| ()),
            Err(MetaBitmapProjectionError::InvalidImage),
            "a published replacement cannot publish twice"
        );

        allocator.free(&mut source).unwrap();
        allocator.free(&mut target).unwrap();
    }

    #[test]
    fn detached_metadata_bootstrap_uses_its_selected_main_subprocess_identity() {
        let allocator = cold_static_allocator();
        let subprocess = MainSubprocess::test_static_owner();
        allocator
            .prepare_for_main_subprocess(config(), subprocess)
            .expect("the selected detached metadata image publishes before demand");
        let mut block = allocator
            .zalloc_for_main_subprocess(config(), subprocess, 8)
            .expect("the detached metadata owner initializes for this main identity");
        assert!(allocator.test_is_bound_for(config(), subprocess));
        assert!(allocator
            .get_ref()
            .registry
            .is_bound_to_subprocess(subprocess.as_ptr()));
        let arena = unsafe { allocator.get_ref().registry.arena_at(0) }
            .expect("the detached metadata arena is published");
        assert!(core::ptr::eq(arena.subprocess, subprocess.as_ptr()));
        assert!(matches!(
            allocator.zalloc(config(), 8),
            Err(MetaError::SubprocessMismatch)
        ), "one bounded metadata owner cannot name two process-main identities");
        allocator.free(&mut block).unwrap();
    }

    #[test]
    fn typed_tld_initialization_rejects_aligned_and_replacement_origins() {
        let allocator = static_allocator();
        let thread = LiveThreadId::new(crate::os::thread_pointer_identity())
            .expect("the native test thread has a live identity");
        let sequence = ThreadSequence::from_previous_total_count(7);
        let tld_size = size_of::<ThreadLocalData>();

        let mut aligned = allocator
            .zalloc_aligned(config(), tld_size, 4096)
            .expect("the aligned metadata request succeeds");
        assert!(!aligned.initialize_thread_local_data_subprocess_attached_no_theap(
            thread,
            sequence,
            0,
            MainSubprocess::global(),
        ));
        assert!(aligned.thread_local_data_mut().is_none());
        allocator.free(&mut aligned).unwrap();

        let mut old = allocator.zalloc(config(), 8).unwrap();
        let mut replacement = allocator
            .rezalloc(config(), Some(&mut old), tld_size)
            .expect("the replacement request succeeds");
        assert!(!replacement.initialize_thread_local_data_subprocess_attached_no_theap(
            thread,
            sequence,
            0,
            MainSubprocess::global(),
        ));
        assert!(replacement.thread_local_data_mut().is_none());
        allocator.free(&mut replacement).unwrap();
    }

    #[test]
    fn released_capability_cannot_project_any_safe_typed_image() {
        let allocator = static_allocator();
        let count = 16;
        let mut backing = allocator
            .zalloc(config(), DynamicThreadLocalBacking::allocation_size(count).unwrap())
            .expect("the exact fresh backing allocation succeeds");

        allocator.free(&mut backing).unwrap();
        assert!(
            backing.dynamic_thread_local_backing_mut(count).is_none(),
            "a released linear capability must not form a safe reference into freed bytes"
        );

        let thread = LiveThreadId::new(crate::os::thread_pointer_identity())
            .expect("the native test thread has a live identity");
        let mut tld = allocator
            .zalloc(config(), size_of::<ThreadLocalData>())
            .expect("the exact fresh TLD allocation succeeds");
        assert!(tld.initialize_thread_local_data_subprocess_attached_no_theap(
            thread,
            ThreadSequence::from_previous_total_count(9),
            0,
            MainSubprocess::global(),
        ));
        allocator.free(&mut tld).unwrap();
        assert!(
            tld.thread_local_data_mut().is_none(),
            "a released capability must not project an already initialized TLD"
        );

        let mut theap = allocator
            .zalloc(config(), size_of::<Theap>())
            .expect("the exact fresh dynamic Theap allocation succeeds");
        assert!(theap.initialize_dynamic_theap_metadata().is_some());
        allocator.free(&mut theap).unwrap();
        assert!(
            theap.dynamic_theap_mut().is_none(),
            "a released capability must not project an already initialized dynamic Theap"
        );
    }

    #[test]
    fn invalid_alignment_does_not_initialize_or_publish_metadata_state() {
        let allocator = cold_static_allocator();
        assert!(matches!(
            allocator.zalloc_aligned(config(), 8, 3),
            Err(MetaError::InvalidAlignment)
        ));
        assert_eq!(allocator.status.load(Ordering::Acquire), COLD);
    }

    #[test]
    fn cold_direct_metadata_demand_requires_prepared_theap_publication() {
        let allocator = cold_static_allocator();
        let subprocess = allocator.test_default_subprocess();
        let fault = fault::install(fault::Plan::at(fault::Point::Map, 1, Errno::NOMEM));

        assert!(!subprocess.test_has_published_metadata_theap());
        assert_eq!(allocator.test_entry_attempt_count(), 0);
        assert_eq!(
            allocator.test_allocation_audit(),
            MetaAllocationAudit {
                live_capability_count: 0,
                high_water_capability_count: 0,
            }
        );
        assert!(matches!(
            allocator.zalloc(config(), 8),
            Err(MetaError::TheapMetaUnpublished)
        ));
        assert!(matches!(
            allocator.zalloc_aligned(config(), 8, 8),
            Err(MetaError::TheapMetaUnpublished)
        ));
        assert!(matches!(
            allocator.rezalloc(config(), None, 8),
            Err(MetaError::TheapMetaUnpublished)
        ));
        assert_eq!(allocator.status.load(Ordering::Acquire), COLD);
        assert!(!subprocess.test_has_published_metadata_theap());
        assert_eq!(fault.observed(), 0, "cold demand cannot reach any mapping edge");
        assert_eq!(
            allocator.test_entry_attempt_count(),
            0,
            "cold demand rejects before the source metadata-lock entry boundary"
        );
        assert_eq!(
            allocator.test_allocation_audit(),
            MetaAllocationAudit {
                live_capability_count: 0,
                high_water_capability_count: 0,
            }
        );

        allocator
            .prepare_for_main_subprocess(config(), subprocess)
            .expect("only preparation may bind and publish the detached metadata Theap");
        assert_eq!(allocator.status.load(Ordering::Acquire), BOUND);
        assert!(subprocess.test_has_published_metadata_theap());
        assert_eq!(fault.observed(), 0, "preparation is identity-only");
        assert_eq!(allocator.test_entry_attempt_count(), 1);

        assert!(matches!(
            allocator.zalloc(config(), 8),
            Err(MetaError::InitializationFailed)
        ));
        assert_eq!(fault.observed(), 1, "prepared demand may consume the pending map fault");
        assert_eq!(allocator.status.load(Ordering::Acquire), BOUND);

        fault.set(fault::Plan::disabled());
        let mut allocation = allocator
            .zalloc(config(), 8)
            .expect("the bound owner retries demand after the map fault");
        allocator.free(&mut allocation).unwrap();
    }

    #[test]
    fn map_and_commit_failure_leave_the_owner_retryable_without_private_backing() {
        let allocator = static_allocator();
        let fault = fault::install(fault::Plan::at(fault::Point::Map, 1, Errno::NOMEM));
        assert!(matches!(
            allocator.zalloc(config(), 8),
            Err(MetaError::InitializationFailed)
        ));
        assert_eq!(allocator.status.load(Ordering::Acquire), BOUND);
        fault.set(fault::Plan::at(fault::Point::Map, 2, Errno::NOMEM));
        assert!(matches!(
            allocator.zalloc(config(), 8),
            Err(MetaError::InitializationFailed)
        ));
        assert_eq!(fault.observed(), 2, "the second map is the metadata arena");
        assert_eq!(allocator.status.load(Ordering::Acquire), BOUND);
        fault.set(fault::Plan::at(fault::Point::Commit, 1, Errno::NOMEM));
        assert!(matches!(
            allocator.zalloc(config(), 8),
            Err(MetaError::InitializationFailed)
        ));
        assert_eq!(allocator.status.load(Ordering::Acquire), BOUND);
        fault.set(fault::Plan::disabled());
        let mut retry = allocator.zalloc(config(), 8).unwrap();
        allocator.free(&mut retry).unwrap();
    }

    #[test]
    fn bound_metadata_rejects_a_foreign_subprocess_before_first_backing() {
        let allocator = cold_static_allocator();
        let selected = MainSubprocess::test_static_owner();
        let foreign = MainSubprocess::test_static_owner();

        let _binding = allocator
            .prepare_for_main_subprocess(config(), selected)
            .expect("the source-static detached image binds without private backing");
        assert!(allocator.test_is_bound_for(config(), selected));
        assert!(
            selected.test_has_published_metadata_theap(),
            "the selected source subprocess receives its detached metadata-Theap identity before first backing",
        );
        assert!(
            !foreign.test_has_published_metadata_theap(),
            "an unrelated subprocess cannot inherit the selected metadata-Theap identity"
        );
        assert!(allocator.test_private_page_map_address().is_none());

        let fault = fault::install(fault::Plan::at(fault::Point::Map, 1, Errno::NOMEM));
        assert!(
            matches!(
                allocator.zalloc_for_main_subprocess(config(), foreign, 8),
                Err(MetaError::SubprocessMismatch)
            ),
            "a foreign identity rejects before the deferred backing path can map"
        );
        assert_eq!(fault.observed(), 0);
        assert!(allocator.test_private_page_map_address().is_none());

        assert!(
            matches!(
                allocator.zalloc_for_main_subprocess(config(), selected, 8),
                Err(MetaError::InitializationFailed)
            ),
            "the selected first request consumes the still-pending backing failure"
        );
        assert_eq!(fault.observed(), 1);
        assert_eq!(allocator.status.load(Ordering::Acquire), BOUND);

        fault.set(fault::Plan::disabled());
        let mut allocation = allocator
            .zalloc_for_main_subprocess(config(), selected, 8)
            .expect("the same bound identity retries its first backing request");
        allocator.free(&mut allocation).unwrap();
    }

    #[test]
    fn detached_metadata_theap_publication_is_one_way_before_first_backing() {
        let first = cold_static_allocator();
        let selected = MainSubprocess::test_static_owner();
        let second = cold_static_allocator();

        let _first_binding = first
            .prepare_for_main_subprocess(config(), selected)
            .expect("the first detached metadata image publishes the selected identity");
        assert!(first.test_is_bound_for(config(), selected));
        assert!(selected.test_has_published_metadata_theap());
        assert!(first.test_private_page_map_address().is_none());
        assert_eq!(
            first.test_allocation_audit(),
            MetaAllocationAudit {
                live_capability_count: 0,
                high_water_capability_count: 0,
            },
            "publication is identity-only and cannot take metadata backing"
        );

        assert!(
            matches!(
                second.prepare_for_main_subprocess(config(), selected),
                Err(MetaError::TheapMetaMismatch)
            ),
            "a second detached image cannot overwrite the source process's one-way metadata-Theap slot",
        );
        assert!(
            first.test_is_bound_for(config(), selected),
            "the first source image remains the exact published identity after the rejected collision",
        );
        assert!(selected.test_has_published_metadata_theap());
        assert!(second.test_private_page_map_address().is_none());
        assert_eq!(
            second.test_allocation_audit(),
            MetaAllocationAudit {
                live_capability_count: 0,
                high_water_capability_count: 0,
            },
            "the rejected collision cannot create a caller-visible metadata capability"
        );
    }

    #[test]
    fn failed_arena_cleanup_retains_the_static_owner_and_rejects_retry() {
        let allocator = static_allocator();
        let fault = fault::install(fault::Plan::at_pair(
            fault::Point::Map,
            2,
            fault::Point::Unmap,
            1,
            Errno::NOMEM,
        ));
        assert!(matches!(
            allocator.zalloc(config(), 8),
            Err(MetaError::InitializationRetained)
        ));
        assert_eq!(allocator.status.load(Ordering::Acquire), FAILED);
        fault.set(fault::Plan::disabled());
        assert!(matches!(
            allocator.zalloc(config(), 8),
            Err(MetaError::InitializationRetained)
        ));
    }

    #[cfg(not(miri))]
    #[test]
    fn aligned_map_prefix_cleanup_failure_retains_metadata_before_private_backing_publication() {
        let allocator = cold_static_allocator();
        let mut selected_config = config();
        selected_config.test_force_full_aligned_map_trim();
        allocator
            .prepare_for_main_subprocess(
                selected_config,
                allocator.test_default_subprocess(),
            )
            .expect("the isolated fixture publishes before its selected backing configuration");
        let fault = fault::install(fault::Plan::at(
            fault::Point::Unmap,
            2,
            Errno::NOMEM,
        ));

        assert!(matches!(
            allocator.zalloc(selected_config, 8),
            Err(MetaError::InitializationRetained)
        ));
        assert_eq!(allocator.status.load(Ordering::Acquire), FAILED);

        fault.set(fault::Plan::at(fault::Point::Map, 1, Errno::NOMEM));
        assert!(matches!(
            allocator.zalloc(selected_config, 8),
            Err(MetaError::InitializationRetained)
        ));
        assert_eq!(
            fault.observed(),
            0,
            "the terminal metadata owner never opens a retry that could overlap its retained map"
        );
    }

    #[test]
    fn paired_page_map_initial_commit_and_cleanup_failure_retains_the_exact_mapping() {
        let allocator = static_allocator();
        let fault = fault::install(fault::Plan::at_pair(
            fault::Point::Commit,
            1,
            fault::Point::Unmap,
            1,
            Errno::NOMEM,
        ));

        assert!(matches!(
            allocator.zalloc(config(), 8),
            Err(MetaError::InitializationRetained)
        ));
        assert_eq!(allocator.status.load(Ordering::Acquire), FAILED);
        assert!(allocator.test_has_retained_page_map_initialization_mapping());

        fault.set(fault::Plan::disabled());
        assert!(matches!(
            allocator.zalloc(config(), 8),
            Err(MetaError::InitializationRetained)
        ));
        allocator
            .test_release_retained_page_map_initialization_mapping()
            .expect("the retained PageMap mapping releases after the injected fault is removed");
        assert!(!allocator.test_has_retained_page_map_initialization_mapping());
    }

    #[test]
    fn rezalloc_failure_preserves_old_and_success_copies_then_releases_it() {
        let allocator = static_allocator();
        let mut old = allocator.zalloc(config(), 32).unwrap();
        // SAFETY: `old` is a current exclusive metadata capability.
        unsafe { core::ptr::write_bytes(old.pointer().as_ptr(), 0x5a, 32) };
        assert!(matches!(
            allocator.rezalloc(config(), Some(&mut old), usize::MAX),
            Err(MetaError::AllocationUnavailable)
        ));
        // SAFETY: the failed replacement retained the old current block.
        assert!(unsafe { core::slice::from_raw_parts(old.pointer().as_ptr(), 32) }
            .iter()
            .all(|byte| *byte == 0x5a));

        let mut replacement = allocator.rezalloc(config(), Some(&mut old), 96).unwrap();
        // SAFETY: replacement owns 96 requested bytes, and the source copy
        // preserves the old 32-byte initialized prefix.
        assert!(unsafe { core::slice::from_raw_parts(replacement.pointer().as_ptr(), 32) }
            .iter()
            .all(|byte| *byte == 0x5a));
        assert_eq!(allocator.free(&mut old), Err(MetaError::ReleasedOrStale));
        allocator.free(&mut replacement).unwrap();
    }

    #[test]
    fn metadata_capability_audit_tracks_live_and_warm_high_water() {
        let allocator = static_allocator();
        assert_eq!(
            allocator.test_allocation_audit(),
            MetaAllocationAudit {
                live_capability_count: 0,
                high_water_capability_count: 0,
            },
            "the test fixture begins with no caller-visible metadata capability"
        );

        let mut first = allocator.zalloc(config(), 32).unwrap();
        assert_eq!(
            allocator.test_allocation_audit(),
            MetaAllocationAudit {
                live_capability_count: 1,
                high_water_capability_count: 1,
            },
            "one direct allocation becomes the first live and high-water capability"
        );
        let mut aligned = allocator.zalloc_aligned(config(), 64, 4096).unwrap();
        assert_eq!(
            allocator.test_allocation_audit(),
            MetaAllocationAudit {
                live_capability_count: 2,
                high_water_capability_count: 2,
            },
            "the aligned route contributes one distinct live capability"
        );

        let mut replacement = allocator.rezalloc(config(), Some(&mut first), 96).unwrap();
        assert_eq!(
            allocator.test_allocation_audit(),
            MetaAllocationAudit {
                live_capability_count: 2,
                high_water_capability_count: 3,
            },
            "rezalloc briefly owns old plus replacement before releasing old"
        );
        allocator.free(&mut aligned).unwrap();
        allocator.free(&mut replacement).unwrap();
        assert_eq!(
            allocator.test_allocation_audit(),
            MetaAllocationAudit {
                live_capability_count: 0,
                high_water_capability_count: 3,
            },
            "releases return the live count to baseline without erasing warm high-water"
        );
    }

    #[test]
    fn released_capability_rejects_double_release() {
        let allocator = static_allocator();
        let mut block = allocator.zalloc(config(), 8).unwrap();
        allocator.free(&mut block).unwrap();
        assert_eq!(allocator.free(&mut block), Err(MetaError::ReleasedOrStale));
    }

    #[test]
    fn bound_subprocess_metadata_page_query_is_exact_without_backing() {
        let selected_allocator = cold_static_allocator();
        let selected = selected_allocator.test_default_subprocess();
        let foreign_allocator = cold_static_allocator();
        let foreign = foreign_allocator.test_default_subprocess();
        selected_allocator
            .prepare_for_main_subprocess(config(), selected)
            .expect("the selected source-static Theap publishes before any private backing");
        foreign_allocator
            .prepare_for_main_subprocess(config(), foreign)
            .expect("the foreign source-static Theap publishes before any private backing");

        for allocator in [selected_allocator, foreign_allocator] {
            assert_eq!(allocator.status.load(Ordering::Acquire), BOUND);
            assert!(
                allocator.test_private_page_map_address().is_none(),
                "the query is valid while the detached Theap is bound but has no private backing"
            );
            assert_eq!(
                allocator.test_allocation_audit(),
                MetaAllocationAudit {
                    live_capability_count: 0,
                    high_water_capability_count: 0,
                },
                "the query starts before any metadata allocation or detached session"
            );
        }

        let selected_identity = NonNull::new(
            selected_allocator
                .get_ref()
                .detached_metadata_theap
                .load(Ordering::Acquire),
        )
        .expect("BOUND Release-publishes the selected detached metadata-Theap identity");
        let foreign_identity = NonNull::new(
            foreign_allocator
                .get_ref()
                .detached_metadata_theap
                .load(Ordering::Acquire),
        )
        .expect("BOUND Release-publishes the foreign detached metadata-Theap identity");
        let mut page = Page::remote_free_test_unassociated();

        let selected_entries_before_lock = selected_allocator.test_entry_attempt_count();
        let foreign_entries = foreign_allocator.test_entry_attempt_count();
        let _selected_entry = selected_allocator
            .enter()
            .expect("the selected metadata owner accepts one held entry");
        let selected_entries = selected_allocator.test_entry_attempt_count();
        assert_eq!(selected_entries, selected_entries_before_lock + 1);

        assert!(
            !selected.is_metadata_page(None),
            "None represents C's null page pointer"
        );
        assert!(
            !selected.is_metadata_page(Some(&page)),
            "a readable page with a null Theap field does not match a bound subprocess"
        );
        page.abandoned_test_set_theap(foreign_identity.as_ptr());
        assert!(
            !selected.is_metadata_page(Some(&page)),
            "the selected subprocess rejects the foreign published identity"
        );
        assert!(
            foreign.is_metadata_page(Some(&page)),
            "the foreign subprocess accepts only its exact published identity"
        );
        page.abandoned_test_set_theap(selected_identity.as_ptr());
        assert!(
            selected.is_metadata_page(Some(&page)),
            "the selected subprocess accepts its exact published identity without READY"
        );
        assert!(
            !foreign.is_metadata_page(Some(&page)),
            "the foreign subprocess rejects the selected published identity"
        );

        assert_eq!(
            selected_allocator.test_entry_attempt_count(),
            selected_entries,
            "the source page query stays outside the selected metadata allocator lock"
        );
        assert_eq!(
            foreign_allocator.test_entry_attempt_count(),
            foreign_entries,
            "the source page query stays outside the foreign metadata allocator lock"
        );
        for allocator in [selected_allocator, foreign_allocator] {
            assert_eq!(allocator.status.load(Ordering::Acquire), BOUND);
            assert!(
                allocator.test_private_page_map_address().is_none(),
                "the read-only comparison does not map metadata backing"
            );
            assert_eq!(
                allocator.test_allocation_audit(),
                MetaAllocationAudit {
                    live_capability_count: 0,
                    high_water_capability_count: 0,
                },
                "the read-only comparison does not lend a detached session"
            );
        }
    }

    #[test]
    fn bound_subprocess_theap_meta_lock_serializes_direct_allocation_phase() {
        let allocator = cold_static_allocator();
        let subprocess = allocator.test_default_subprocess();
        allocator
            .prepare_for_main_subprocess(config(), subprocess)
            .expect("the selected detached metadata image binds before direct demand");
        assert_eq!(allocator.status.load(Ordering::Acquire), BOUND);
        assert!(allocator.test_private_page_map_address().is_none());
        assert_eq!(
            allocator.test_allocation_audit(),
            MetaAllocationAudit {
                live_capability_count: 0,
                high_water_capability_count: 0,
            }
        );

        thread::scope(|scope| {
            let held = subprocess
                .test_hold_metadata_theap_lock()
                .expect("the selected subprocess metadata lock starts unlocked");
            let (started_sender, started_receiver) = mpsc::channel();
            let (completed_sender, completed_receiver) = mpsc::channel();
            let worker = scope.spawn(move || {
                started_sender
                    .send(())
                    .expect("the test receiver remains live");
                let mut allocation = allocator
                    .zalloc_for_main_subprocess(config(), subprocess, 64)
                    .expect("the selected direct allocation resumes after the subprocess lock releases");
                allocator
                    .free(&mut allocation)
                    .expect("the worker returns its selected direct capability");
                completed_sender
                    .send(())
                    .expect("the test receiver remains live");
            });

            started_receiver
                .recv_timeout(Duration::from_secs(2))
                .expect("the direct worker starts while the subprocess lock is held");
            wait_for_metadata_theap_lock_contention(subprocess);
            assert!(
                completed_receiver
                    .recv_timeout(Duration::from_millis(50))
                    .is_err(),
                "direct zalloc must not reach backing or create a capability before the selected subprocess lock releases"
            );
            assert_eq!(allocator.status.load(Ordering::Acquire), BOUND);
            assert!(allocator.test_private_page_map_address().is_none());
            assert_eq!(
                allocator.test_allocation_audit(),
                MetaAllocationAudit {
                    live_capability_count: 0,
                    high_water_capability_count: 0,
                }
            );

            drop(held);
            completed_receiver
                .recv_timeout(Duration::from_secs(2))
                .expect("direct zalloc completes after the selected subprocess lock releases");
            worker.join().expect("the direct worker completes");
        });

        assert_eq!(allocator.status.load(Ordering::Acquire), READY);
        assert_eq!(
            allocator.test_allocation_audit(),
            MetaAllocationAudit {
                live_capability_count: 0,
                high_water_capability_count: 1,
            }
        );

        thread::scope(|scope| {
            let held = subprocess
                .test_hold_metadata_theap_lock()
                .expect("the selected subprocess metadata lock is reusable");
            let (started_sender, started_receiver) = mpsc::channel();
            let (completed_sender, completed_receiver) = mpsc::channel();
            let worker = scope.spawn(move || {
                started_sender
                    .send(())
                    .expect("the test receiver remains live");
                let mut allocation = allocator
                    .zalloc_aligned_for_main_subprocess(config(), subprocess, 64, 64)
                    .expect("the selected aligned direct allocation resumes after the subprocess lock releases");
                allocator
                    .free(&mut allocation)
                    .expect("the worker returns its selected aligned capability");
                completed_sender
                    .send(())
                    .expect("the test receiver remains live");
            });

            started_receiver
                .recv_timeout(Duration::from_secs(2))
                .expect("the aligned direct worker starts while the subprocess lock is held");
            wait_for_metadata_theap_lock_contention(subprocess);
            assert!(
                completed_receiver
                    .recv_timeout(Duration::from_millis(50))
                    .is_err(),
                "direct aligned zalloc must wait for the selected subprocess lock"
            );

            drop(held);
            completed_receiver
                .recv_timeout(Duration::from_secs(2))
                .expect("direct aligned zalloc completes after the selected subprocess lock releases");
            worker.join().expect("the aligned direct worker completes");
        });

        let mut old = allocator
            .zalloc_for_main_subprocess(config(), subprocess, 32)
            .expect("the selected old capability is live before rezalloc");
        // SAFETY: `old` is a current exclusive metadata capability.
        unsafe { core::ptr::write_bytes(old.pointer().as_ptr(), 0xa5, 32) };
        thread::scope(|scope| {
            let held = subprocess
                .test_hold_metadata_theap_lock()
                .expect("the selected subprocess metadata lock is reusable for rezalloc");
            let (started_sender, started_receiver) = mpsc::channel();
            let (completed_sender, completed_receiver) = mpsc::channel();
            let worker = scope.spawn(move || {
                started_sender
                    .send(())
                    .expect("the test receiver remains live");
                let mut replacement = allocator
                    .rezalloc_for_main_subprocess(config(), subprocess, Some(&mut old), 96)
                    .expect("the selected rezalloc resumes after the subprocess lock releases");
                // SAFETY: the successful replacement owns the copied source prefix.
                assert!(unsafe { core::slice::from_raw_parts(replacement.pointer().as_ptr(), 32) }
                    .iter()
                    .all(|byte| *byte == 0xa5));
                allocator
                    .free(&mut replacement)
                    .expect("the worker returns the selected replacement capability");
                completed_sender
                    .send(())
                    .expect("the test receiver remains live");
            });

            started_receiver
                .recv_timeout(Duration::from_secs(2))
                .expect("the rezalloc worker starts while the subprocess lock is held");
            wait_for_metadata_theap_lock_contention(subprocess);
            assert!(
                completed_receiver
                    .recv_timeout(Duration::from_millis(50))
                    .is_err(),
                "rezalloc must wait for the selected subprocess lock before its replacement allocation"
            );

            drop(held);
            completed_receiver
                .recv_timeout(Duration::from_secs(2))
                .expect("rezalloc completes after the selected subprocess lock releases");
            worker.join().expect("the rezalloc worker completes");
        });

        let block = allocator
            .zalloc_for_main_subprocess(config(), subprocess, 64)
            .expect("the selected capability is live before exact-owner free");
        thread::scope(|scope| {
            let held = subprocess
                .test_hold_metadata_theap_lock()
                .expect("the selected subprocess metadata lock is reusable for free");
            let (started_sender, started_receiver) = mpsc::channel();
            let (completed_sender, completed_receiver) = mpsc::channel();
            let worker = scope.spawn(move || {
                started_sender
                    .send(())
                    .expect("the test receiver remains live");
                let mut block = block;
                allocator
                    .free(&mut block)
                    .expect("the exact-owner Malloc free stays outside the source allocation lock");
                completed_sender
                    .send(())
                    .expect("the test receiver remains live");
            });

            started_receiver
                .recv_timeout(Duration::from_secs(2))
                .expect("the exact-owner free worker starts while the subprocess lock is held");
            completed_receiver
                .recv_timeout(Duration::from_secs(2))
                .expect("the exact-owner Malloc free remains outside the source allocation lock");
            worker.join().expect("the exact-owner free worker completes");
            drop(held);
        });

        assert_eq!(
            allocator.test_allocation_audit(),
            MetaAllocationAudit {
                live_capability_count: 0,
                high_water_capability_count: 2,
            }
        );
    }

    #[test]
    fn foreign_owner_rejection_preserves_the_live_metadata_capability() {
        let owner = static_allocator();
        let foreign = static_allocator();
        let mut block = owner.zalloc(config(), 32).unwrap();

        assert_eq!(foreign.free(&mut block), Err(MetaError::ForeignOwner));
        assert!(matches!(
            foreign.rezalloc(config(), Some(&mut block), 64),
            Err(MetaError::ForeignOwner)
        ));
        // The foreign owner did not claim or retire `block`; its actual owner
        // can still replace and then release it.
        let mut replacement = owner.rezalloc(config(), Some(&mut block), 64).unwrap();
        owner.free(&mut replacement).unwrap();
    }

    #[test]
    fn configuration_mismatch_does_not_disturb_ready_metadata_state() {
        let allocator = static_allocator();
        let mut block = allocator.zalloc(config(), 8).unwrap();
        let different = MemoryConfig::from_observations(
            PageSize::new(4 * 1024).unwrap(),
            1024 * 1024 + 1,
            false,
            false,
        );
        assert!(matches!(
            allocator.zalloc(different, 8),
            Err(MetaError::ConfigurationMismatch)
        ));
        allocator.free(&mut block).unwrap();
    }

    #[test]
    fn recursive_metadata_entry_is_rejected_without_waiting() {
        let allocator = static_allocator();
        let entry = allocator.enter().unwrap();
        assert!(matches!(
            allocator.enter(),
            Err(MetaError::RecursiveEntry)
        ));
        drop(entry);
    }

    #[test]
    fn metadata_entry_borrows_a_nonstatic_engine_only_for_the_entry() {
        // The engine's backing-provenance lifetime is independent of this
        // short pin borrow. The empty COLD engine only exercises entry-lock
        // ownership; no allocator capability can be minted from it.
        let engine = MetadataEngine::<'static>::new();
        // SAFETY: pinning a stack local is sufficient here because entry only
        // takes a shared pinned borrow and no self-referential backing exists
        // in the COLD image.
        let pinned = unsafe { Pin::new_unchecked(&engine) };
        let entry = pinned.enter().expect("a fresh engine admits one entry");
        assert!(matches!(pinned.enter(), Err(MetaError::RecursiveEntry)));
        drop(entry);
        drop(engine);
    }

    #[test]
    fn recursive_metadata_entry_rejects_real_routes_before_backing_or_capability_mutation() {
        let allocator = static_allocator();
        let fault = fault::install(fault::Plan::at(fault::Point::Map, 1, Errno::NOMEM));
        let empty_audit = MetaAllocationAudit {
            live_capability_count: 0,
            high_water_capability_count: 0,
        };

        assert_eq!(allocator.status.load(Ordering::Acquire), BOUND);
        assert!(allocator.test_private_page_map_address().is_none());
        assert_eq!(allocator.test_allocation_audit(), empty_audit);
        let attempts_before = allocator.test_entry_attempt_count();

        let entry = allocator.enter().unwrap();
        assert!(matches!(
            allocator.zalloc(config(), 8),
            Err(MetaError::RecursiveEntry)
        ));
        assert!(matches!(
            allocator.zalloc_aligned(config(), 8, 8),
            Err(MetaError::RecursiveEntry)
        ));
        assert!(matches!(
            allocator.rezalloc(config(), None, 8),
            Err(MetaError::RecursiveEntry)
        ));
        assert_eq!(
            allocator.test_entry_attempt_count(),
            attempts_before + 4,
            "the held entry plus every direct demand reaches the same-thread guard"
        );
        assert_eq!(fault.observed(), 0, "recursive demand cannot reach the map fault");
        assert_eq!(allocator.status.load(Ordering::Acquire), BOUND);
        assert!(allocator.test_private_page_map_address().is_none());
        assert_eq!(allocator.test_allocation_audit(), empty_audit);

        fault.set(fault::Plan::disabled());
        drop(entry);

        let mut old = allocator
            .zalloc(config(), 32)
            .expect("dropping the recursive entry restores direct metadata demand");
        // SAFETY: `old` is a current exclusive metadata capability.
        unsafe { core::ptr::write_bytes(old.pointer().as_ptr(), 0xa5, 32) };
        let old_pointer = old.pointer();
        let old_memory_id = old.memory_id();
        assert_eq!(
            allocator.test_allocation_audit(),
            MetaAllocationAudit {
                live_capability_count: 1,
                high_water_capability_count: 1,
            }
        );

        let attempts_before_rezalloc = allocator.test_entry_attempt_count();
        let entry = allocator.enter().unwrap();
        assert!(matches!(
            allocator.rezalloc(config(), Some(&mut old), 64),
            Err(MetaError::RecursiveEntry)
        ));
        assert_eq!(
            allocator.test_entry_attempt_count(),
            attempts_before_rezalloc + 2,
            "rezalloc reaches the guard before it can claim the old capability"
        );
        assert!(old.is_live());
        assert_eq!(old.pointer(), old_pointer);
        assert!(old.matches_memory_id(old_memory_id));
        assert_eq!(
            allocator.test_allocation_audit(),
            MetaAllocationAudit {
                live_capability_count: 1,
                high_water_capability_count: 1,
            }
        );

        drop(entry);
        let mut replacement = allocator
            .rezalloc(config(), Some(&mut old), 64)
            .expect("dropping the recursive entry restores replacement demand");
        // SAFETY: `replacement` owns its copied 32-byte source prefix.
        assert!(unsafe { core::slice::from_raw_parts(replacement.pointer().as_ptr(), 32) }
            .iter()
            .all(|byte| *byte == 0xa5));
        assert_eq!(allocator.free(&mut old), Err(MetaError::ReleasedOrStale));
        allocator.free(&mut replacement).unwrap();
        assert_eq!(
            allocator.test_allocation_audit(),
            MetaAllocationAudit {
                live_capability_count: 0,
                high_water_capability_count: 2,
            }
        );
    }

    #[test]
    fn recursive_metadata_free_keeps_the_general_lifecycle_contract_terminal() {
        let allocator = static_allocator();
        let mut block = allocator
            .zalloc(config(), 32)
            .expect("the general lifecycle capability is live before recursive free");

        let entry = allocator.enter().unwrap();
        assert_eq!(allocator.free(&mut block), Err(MetaError::RecursiveEntry));
        assert!(
            !block.is_live(),
            "the general lifecycle route keeps its existing terminal-on-error contract"
        );

        drop(entry);
        assert_eq!(
            allocator.free(&mut block),
            Err(MetaError::ReleasedOrStale),
            "a generic lifecycle caller must not accidentally gain the selected retry path"
        );
    }

    #[test]
    fn entry_cleanup_does_not_erase_a_successor_marker() {
        let marker = AtomicUsize::new(24);
        clear_entry_thread_after_unlock(&marker, 12);
        assert_eq!(marker.load(Ordering::Acquire), 24);
        clear_entry_thread_after_unlock(&marker, 24);
        assert_eq!(marker.load(Ordering::Acquire), 0);
    }

    #[test]
    fn private_lock_serializes_concurrent_detached_allocations() {
        let allocator = static_allocator();
        let barrier = Arc::new(Barrier::new(5));
        let completed = Arc::new(AtomicUsize::new(0));
        thread::scope(|scope| {
            for _ in 0..4 {
                let barrier = Arc::clone(&barrier);
                let completed = Arc::clone(&completed);
                scope.spawn(move || {
                    barrier.wait();
                    let mut block = allocator.zalloc(config(), 64).unwrap();
                    allocator.free(&mut block).unwrap();
                    completed.fetch_add(1, Ordering::Release);
                });
            }
            barrier.wait();
        });
        assert_eq!(completed.load(Ordering::Acquire), 4);
    }

    #[test]
    fn cross_thread_free_uses_the_private_metadata_lock() {
        let allocator = static_allocator();
        let block = allocator.zalloc(config(), 64).unwrap();
        thread::scope(|scope| {
            let worker = scope.spawn(move || {
                let mut block = block;
                allocator.free(&mut block)
            });
            assert!(worker.join().unwrap().is_ok());
        });
    }

    #[test]
    fn static_global_metadata_allocation_leaves_compiler_tls_roots_unchanged() {
        let dynamic_before = crate::compiler_tls::dynamic_backing_peek();
        let fast_before = crate::compiler_tls::fast_slot_peek();
        let default_before = crate::compiler_tls::default_theap();
        let cached_before = crate::compiler_tls::cached_theap();

        let allocator = MetaAllocator::global();
        allocator
            .prepare_for_main_subprocess(config(), MainSubprocess::global())
            .expect("the process metadata image publishes before global demand");
        let mut block = allocator.zalloc(config(), 8).unwrap();
        allocator.free(&mut block).unwrap();

        assert_eq!(crate::compiler_tls::dynamic_backing_peek(), dynamic_before);
        assert_eq!(crate::compiler_tls::fast_slot_peek(), fast_before);
        assert_eq!(crate::compiler_tls::default_theap(), default_before);
        assert_eq!(crate::compiler_tls::cached_theap(), cached_before);
    }
}
