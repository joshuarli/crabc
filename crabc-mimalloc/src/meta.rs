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
//! its pages never enter abandonment. A source free on a detached metadata
//! page publishes to its remote head, which the metadata owner or a quiescent
//! Heap visitor later collects. The mapping,
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
    ArenaId, ArenaPagesLayout, ArenaRegistry, ArenaView, MetadataGuardHook,
    manage_external_in_place_with_guard,
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
/// The exact static prefix is held while source callbacks run outside the metadata lock.
const BINDING: u8 = 6;
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
    /// The actual winning bootstrap output admission refused or changed.
    #[cfg(target_arch = "x86_64")]
    BootstrapOutput(crate::process_init::BootstrapOutputAdmissionError),
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
    /// A detached metadata page could not accept the source remote free.
    DetachedRemoteFree(crate::remote_free::RemoteFreeError),
    /// The selected process PageMap was unavailable for a detached metadata
    /// block whose source free requires remote publication.
    DetachedRemoteFreeUnavailable,
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
        // has the image's exact size/alignment, and has no prior role. The
        // in-place initializer writes every field before the pinned view.
        unsafe { Image::write_at(self.pointer.cast()); }
        self.child_subprocess_image_initialized = true;
        // SAFETY: the external capability owns this stable address until
        // release and the image is `!Unpin` after this projection.
        Some(unsafe {
            Pin::new_unchecked(&mut *self.pointer.as_ptr().cast::<Image>())
        })
    }

    /// Short shared projection of an initialized child image. Source state
    /// uses its own synchronization; the embedded native control can retain
    /// an independent mutable owner borrow in its interior mutable slot.
    /// The exact allocation capability stays live for the complete borrow.
    #[inline]
    pub(crate) fn child_subprocess_image(
        &self,
    ) -> Option<Pin<&crate::subproc::ChildSubprocessImage>> {
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
        // SAFETY: only the exact initializer sets this marker. The live
        // capability pins the source identity; its control slot remains
        // interior mutable and is never covered by an exclusive image borrow.
        Some(unsafe { Pin::new_unchecked(&*self.pointer.as_ptr().cast::<Image>()) })
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
            || self.requested_size != crate::types::SOURCE_THREAD_LOCAL_DATA_SIZE
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

    /// Returns the original retained initialized TLD pointer without
    /// borrowing its independently locked source list. The exact metadata
    /// role and layout guards remain those of the mutable projection.
    #[inline]
    pub(crate) fn thread_local_data_pointer(&self) -> Option<NonNull<ThreadLocalData>> {
        if !self.is_live()
            || !self.thread_local_data_initialized
            || self.dynamic_theap_initialized
            || self.dynamic_thread_local_backing_projected
            || self.dynamic_arena_pages_initialized
            || self.requested_size != crate::types::SOURCE_THREAD_LOCAL_DATA_SIZE
            || self.pointer.as_ptr().addr() % align_of::<ThreadLocalData>() != 0
        {
            return None;
        }
        Some(self.pointer.cast())
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
            || self.requested_size != crate::types::SOURCE_THREAD_LOCAL_DATA_SIZE
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
        debug_assert_eq!(self.requested_size, crate::types::SOURCE_THREAD_LOCAL_DATA_SIZE);
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
        unsafe { Theap::write_empty_at(self.pointer.cast()) };
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
            || self.requested_size != crate::types::SOURCE_THREAD_LOCAL_DATA_SIZE
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

    /// Recovers the ordinary main-Heap Theap at its exclusive last source
    /// reference. Other live process owners remain unaffected.
    ///
    /// # Safety
    /// `pointer` is the initialized, still-live image returned by exactly one
    /// prior `into_source_retained_theap` belonging to the global metadata
    /// owner. Its memory ID is unchanged and the transfer was never recovered.
    /// The caller owns its last source reference, has detached every Heap/TLD
    /// and retained-list link, and excludes all page sessions, callbacks, TLS
    /// wrappers and other accesses through recovery and terminal release.
    /// SourceOwned is a checked marker, not proof of these lifetime rights.
    /// Rejection retains the source owner and grants no raw release right.
    #[cfg(target_arch = "x86_64")]
    pub(crate) unsafe fn recover_last_reference_main_heap_theap(
        owner: Pin<&'static MetaAllocator>, pointer: NonNull<Theap>,
    ) -> Option<Self> {
        use crate::subproc::main_heaps::MainHeapTheapMetadataOwnership;
        if !core::ptr::eq(owner.get_ref(), MetaAllocator::global().get_ref())
            || pointer.as_ptr().addr() % align_of::<Theap>() != 0 { return None; }
        // SAFETY: the exclusive last-reference contract grants only these
        // bounded initialized field reads, without a whole-Theap reference.
        let lifecycle = unsafe { Theap::main_heap_lifecycle_at(pointer) };
        if unsafe { (*lifecycle).metadata } != MainHeapTheapMetadataOwnership::SourceOwned {
            return None;
        }
        let memory = unsafe { Theap::memory_id_at(pointer) };
        let mut allocation = Self::new(owner, pointer.cast(), size_of::<Theap>(),
            MetaAllocationOrigin::DirectZeroed);
        if !allocation.matches_memory_id(memory) { return None; }
        allocation.dynamic_theap_initialized = true;
        // The successful inverse consumes source custody once. A second
        // recovery rejects this marker before constructing another capability.
        unsafe { (*lifecycle).metadata = MainHeapTheapMetadataOwnership::ReleaseClaimed };
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
        let mut allocation = Self::new(owner, pointer.cast(), crate::types::SOURCE_THREAD_LOCAL_DATA_SIZE,
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

/// The detached metadata Theap that issued a child subprocess's context,
/// metadata Theap, and native record. A nested child's parent must remain
/// live until those allocations have all been released.
#[derive(Clone, Copy)]
pub(crate) enum ChildParentMetadata {
    Process {
        allocator: Pin<&'static MetaAllocator>,
        main: &'static MainSubprocess,
        config: MemoryConfig,
    },
    Child {
        id: crate::subproc::lifecycle::NativeSubprocessId,
        binding: crate::process_init::ProcessMainBackingBinding,
    },
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ChildMetadataRole { Fresh, Context, Theap, Released }

/// A linear metadata block from either the process detached Theap or a
/// retained child detached Theap. The route above owns release authority;
/// this token owns the exact pointer, extent, and typed-image state.
#[must_use = "child metadata must be released through its parent"]
pub(crate) enum ChildMetadataAllocation {
    Process(MetaAllocation<'static>),
    Child { pointer: NonNull<u8>, size: usize, role: ChildMetadataRole },
}

impl ChildMetadataAllocation {
    pub(crate) fn pointer(&self) -> NonNull<u8> {
        assert!(self.is_live(), "released child metadata grants no byte projection");
        match self { Self::Process(block) => block.pointer(), Self::Child { pointer, .. } => *pointer }
    }

    /// A released or rejected capability grants no fresh byte projection.
    /// Child release records logical consumption before a late lifecycle error.
    pub(crate) fn is_live(&self) -> bool {
        match self {
            Self::Process(block) => block.is_live(),
            Self::Child { role, .. } => *role != ChildMetadataRole::Released,
        }
    }

    pub(crate) fn memory_id(&self) -> MemoryId {
        match self {
            Self::Process(block) => block.memory_id(),
            Self::Child { pointer, size, .. } => MemoryId::malloc(pointer.as_ptr(), *size, true),
        }
    }

    fn initialize_child_subprocess_image(&mut self) -> Option<Pin<&mut crate::subproc::ChildSubprocessImage>> {
        match self {
            Self::Process(block) => block.initialize_child_subprocess_image(),
            Self::Child { pointer, size, role } => {
                type Image = crate::subproc::ChildSubprocessImage;
                if *role != ChildMetadataRole::Fresh || *size != size_of::<Image>()
                    || pointer.as_ptr().addr() % align_of::<Image>() != 0 { return None; }
                // SAFETY: this fresh zeroed exact block is uniquely owned,
                // aligned, and retained until the child finishes teardown.
                unsafe { Image::write_at(pointer.cast()) };
                *role = ChildMetadataRole::Context;
                // SAFETY: the linear token retains this exact pinned image.
                Some(unsafe { Pin::new_unchecked(&mut *pointer.as_ptr().cast::<Image>()) })
            }
        }
    }

    fn child_subprocess_image(&self) -> Option<Pin<&crate::subproc::ChildSubprocessImage>> {
        match self {
            Self::Process(block) => block.child_subprocess_image(),
            Self::Child { pointer, role: ChildMetadataRole::Context, .. } => {
                // SAFETY: only the initializer above assigns this role. The
                // exact token retains the image through this shared projection,
                // including independent borrows in its interior mutable control.
                Some(unsafe { Pin::new_unchecked(&*pointer.as_ptr().cast()) })
            }
            Self::Child { .. } => None,
        }
    }

    fn initialize_dynamic_theap_metadata(&mut self) -> Option<&mut Theap> {
        match self {
            Self::Process(block) => block.initialize_dynamic_theap_metadata(),
            Self::Child { pointer, size, role } => {
                if *role != ChildMetadataRole::Fresh || *size != size_of::<Theap>()
                    || pointer.as_ptr().addr() % align_of::<Theap>() != 0 { return None; }
                // SAFETY: the fresh exact block is uniquely retained and
                // receives a complete empty source image before projection.
                unsafe { Theap::write_empty_at(pointer.cast()) };
                let theap = unsafe { &mut *pointer.as_ptr().cast::<Theap>() };
                if !theap.set_dynamic_metadata_memid(MemoryId::malloc(pointer.as_ptr(), *size, true)) {
                    return None;
                }
                *role = ChildMetadataRole::Theap;
                Some(theap)
            }
        }
    }

    fn dynamic_theap_mut(&mut self) -> Option<&mut Theap> {
        match self {
            Self::Process(block) => block.dynamic_theap_mut(),
            Self::Child { pointer, role: ChildMetadataRole::Theap, .. } => {
                // SAFETY: the role records the complete image initialization;
                // the unique token retains the live allocation.
                Some(unsafe { &mut *pointer.as_ptr().cast::<Theap>() })
            }
            Self::Child { .. } => None,
        }
    }

    fn dynamic_theap_pointer(&self) -> Option<NonNull<Theap>> {
        match self {
            Self::Process(block) => block.dynamic_theap_pointer(),
            Self::Child { pointer, role: ChildMetadataRole::Theap, .. } => Some(pointer.cast()),
            Self::Child { .. } => None,
        }
    }

    /// # Safety
    /// The caller excludes every concurrent Theap or intrusive-list user.
    unsafe fn is_unlinked_dynamic_theap(&mut self) -> bool {
        self.dynamic_theap_mut().is_some_and(|theap| unsafe { theap.is_unlinked_dynamic_metadata() })
    }
}

impl ChildParentMetadata {
    pub(crate) fn with_identity<R>(self, operation: impl FnOnce(&crate::subproc::SubprocessIdentity) -> R) -> Result<R, MetaError> {
        match self {
            Self::Process { main, .. } => Ok(operation(main.identity())),
            Self::Child { id, .. } => {
                // SAFETY: a nested child retains its parent through teardown.
                unsafe { id.with_owner(|owner| owner.as_mut().and_then(|child| {
                    child.with_child_image(|image| operation(image.identity()))
                })) }.map_err(|_| MetaError::Closed)?.ok_or(MetaError::Closed)
            }
        }
    }

    pub(crate) fn allocate(self, size: usize) -> Result<ChildMetadataAllocation, MetaError> {
        match self {
            Self::Process { allocator, main, config } => allocator
                .zalloc_for_main_subprocess(config, main, size).map(ChildMetadataAllocation::Process),
            Self::Child { id, binding } => {
                // SAFETY: the parent id stays live while the new child and
                // its exact metadata allocations are being created.
                unsafe { id.with_owner(|owner| {
                    owner.as_mut().ok_or(MetaError::Closed)?
                        .with_metadata_page_engine(binding, |_image, engine| engine.allocate_zeroed(size))
                        .map_err(|_| MetaError::InitializationRetained)?
                        .map(|pointer| ChildMetadataAllocation::Child {
                            pointer, size, role: ChildMetadataRole::Fresh,
                        }).ok_or(MetaError::AllocationUnavailable)
                }) }.map_err(|_| MetaError::Closed)?
            }
        }
    }

    pub(crate) fn free(self, allocation: &mut ChildMetadataAllocation) -> Result<(), MetaError> {
        match (self, allocation) {
            (Self::Process { allocator, .. }, ChildMetadataAllocation::Process(block)) => allocator.free(block),
            (Self::Child { id, binding }, ChildMetadataAllocation::Child { pointer, role, .. })
                if *role != ChildMetadataRole::Released => {
                // SAFETY: this route minted the exact linear block; the
                // caller ended every typed projection and intrusive edge.
                let freed = unsafe { id.with_owner(|owner| {
                    owner.as_mut().ok_or(MetaError::Closed)?
                        .with_metadata_page_engine(binding, |_image, engine| {
                            // This exact local metadata client can be consumed
                            // before a later queue or backing error. Preserve
                            // that disposition so no retry frees reused bytes.
                            match unsafe { engine.free_with_progress(*pointer) } {
                                crate::single_thread::LocalClientFreeProgress::RefusedBeforeConsumption(error) => {
                                    Err(MetaError::Free(error))
                                }
                                crate::single_thread::LocalClientFreeProgress::Consumed(result) => {
                                    *role = ChildMetadataRole::Released;
                                    result.map_err(MetaError::Free)
                                }
                            }
                        })
                        .map_err(|_| MetaError::InitializationRetained)?
                }) }.map_err(|_| MetaError::Closed)?;
                freed?;
                *role = ChildMetadataRole::Released;
                Ok(())
            }
            _ => Err(MetaError::ForeignOwner),
        }
    }

    /// Attaches a new child's detached metadata Theap to its Heap and the
    /// actual parent's detached TLD while the parent metadata route is held.
    ///
    /// # Safety
    /// Both child images are pinned and uniquely owned; the parent remains
    /// live through the child's subsequent detach and release.
    pub(crate) unsafe fn initialize_child_metadata_theap(
        self, child_heap: &mut Heap, child_theap: &mut Theap,
    ) -> Result<(), ChildMetadataTheapError> {
        match self {
            Self::Process { allocator, main, config } => unsafe {
                allocator.initialize_child_metadata_theap(config, main, child_heap, child_theap)
            },
            Self::Child { id, .. } => {
                // SAFETY: the live parent record serializes its detached
                // metadata Theap and TLD for the complete list insertion.
                unsafe { id.with_owner(|owner| {
                    owner.as_mut().ok_or(ChildMetadataTheapError::Metadata(MetaError::Closed))?
                        .with_metadata_theap(|parent_theap| {
                            let tld = parent_theap.deferred_free_tld()
                                .ok_or(ChildMetadataTheapError::Metadata(MetaError::InitializationRetained))?;
                            // SAFETY: the parent metadata Theap retains this
                            // detached TLD while the record lock is held.
                            unsafe { child_theap.initialize_child_metadata(child_heap, &mut *tld.as_ptr()) }
                                .map_err(ChildMetadataTheapError::Theap)
                        })
                        .ok_or(ChildMetadataTheapError::Metadata(MetaError::InitializationRetained))?
                }) }.map_err(|_| ChildMetadataTheapError::Metadata(MetaError::Closed))?
            }
        }
    }

    /// Removes the child's metadata Theap from its parent's detached TLD
    /// before its exact metadata allocation is freed.
    ///
    /// # Safety
    /// The child is quiescent, its Heap and Theap remain pinned, and no typed
    /// projection of `child_theap` is live during the raw list transition.
    pub(crate) unsafe fn detach_child_metadata_theap(
        self, child_heap: &mut Heap, child_theap: NonNull<Theap>,
    ) -> Result<(), ChildMetadataTheapError> {
        match self {
            Self::Process { allocator, main, config } => unsafe {
                allocator.detach_child_metadata_theap(config, main, child_heap, child_theap)
            },
            Self::Child { id, .. } => {
                // SAFETY: the parent record lock excludes every operation on
                // its detached metadata Theap and TLD during the unlink.
                unsafe { id.with_owner(|owner| {
                    owner.as_mut().ok_or(ChildMetadataTheapError::Metadata(MetaError::Closed))?
                        .with_metadata_theap(|parent_theap| {
                            let tld = parent_theap.deferred_free_tld()
                                .ok_or(ChildMetadataTheapError::Metadata(MetaError::InitializationRetained))?;
                            // SAFETY: the caller's quiescence and parent lock
                            // preserve both intrusive lists through unlink.
                            unsafe { (&mut *tld.as_ptr()).detach_one_child_theap_for_heap_destroy(
                                child_heap, child_theap.as_ptr(),
                            ) }.map_err(ChildMetadataTheapError::TheapList)
                        })
                        .ok_or(ChildMetadataTheapError::Metadata(MetaError::InitializationRetained))?
                }) }.map_err(|_| ChildMetadataTheapError::Metadata(MetaError::Closed))?
            }
        }
    }
}

/// Exact parent-issued storage for one reclaimable child source context.
///
/// The process metadata engine is process-lived, while a nested parent and
/// its metadata blocks remain live only through the child's lifetime. The
/// capabilities stay
/// outside the allocated child image, so releasing the context can never
/// invalidate the value that authorizes that release. Child Heap creation
/// and its own metadata engine are later source transitions and are not
/// represented by this owner yet.
/// The process-main route and a retained child-parent route both preserve
/// the exact issuing metadata Theap through the child's release.
#[must_use = "a child context owner must be retained through child teardown"]
pub(crate) struct ChildContextOwner {
    parent_metadata: ChildParentMetadata,
    parent_subprocess: &'static MainSubprocess,
    config: MemoryConfig,
    // The capability's live state and this owner's borrow-gated projections
    // end at explicit release.
    context: ChildMetadataAllocation,
    metadata_theap: Option<ChildMetadataAllocation>,
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
        Self::allocate_with(
            ChildParentMetadata::Process { allocator: parent_metadata, main: parent_subprocess, config },
            parent_subprocess, config,
        )
    }

    pub(crate) fn allocate_with(
        parent_metadata: ChildParentMetadata,
        parent_subprocess: &'static MainSubprocess,
        config: MemoryConfig,
    ) -> Result<Self, ChildContextCreateFailure> {
        let mut context = parent_metadata
            .allocate(size_of::<crate::subproc::ChildSubprocessImage>())
            .map_err(|error| ChildContextCreateFailure::Allocation {
                stage: ChildContextCreateStage::AllocateContext,
                error,
            })?;
        let initialized = context.initialize_child_subprocess_image().is_some();
        let mut owner = Self {
            parent_metadata,
            parent_subprocess,
            config,
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

        let metadata_theap = match parent_metadata.allocate(size_of::<Theap>()) {
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
            .and_then(ChildMetadataAllocation::initialize_dynamic_theap_metadata)
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
    ///
    /// The projection is shared: every child-image transition is atomic or
    /// internally synchronized, so child threads may hold their own shared
    /// projections concurrently.
    pub(crate) fn with_image<R>(
        &mut self,
        operation: impl for<'image> FnOnce(
            Pin<&'image crate::subproc::ChildSubprocessImage>,
        ) -> R,
    ) -> Option<R> {
        if self.terminal || !self.image_initialized { return None; }
        self.with_lease(|mut lease| lease.with_image(operation))
    }

    /// Projects the child image, then locks its metadata entry before forming
    /// a mutable projection of the separately parent-owned metadata Theap.
    /// Both capabilities remain in this owner for the full closure.
    fn with_locked_metadata_entry<R>(
        &mut self,
        operation: impl for<'image, 'theap> FnOnce(
            Pin<&'image crate::subproc::ChildSubprocessImage>,
            &'theap mut Theap,
        ) -> R,
    ) -> Option<R> {
        if self.terminal || !self.image_initialized { return None; }
        let Self { context, metadata_theap, .. } = self;
        let image = context.child_subprocess_image()?;
        let child = image.as_ref();
        let identity = child.get_ref().identity();
        let _metadata_lock = identity.lock_metadata_theap().ok()?;
        let theap = metadata_theap.as_mut()?.dynamic_theap_mut()?;
        let theap_pointer = NonNull::from(&mut *theap);
        if !identity.matches_published_detached_metadata_theap(theap_pointer) {
            return None;
        }
        Some(operation(child, theap))
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
        let valid = self.parent_metadata.with_identity(|parent| {
            self.with_image(|image| {
                let identity = image.identity();
                identity.is_registered_child_of(parent)
                    && identity.main_heap_publication_state()
                        == crate::subproc::MainHeapPublicationState::Absent
                    && !identity.has_published_metadata_theap()
            }).unwrap_or(false)
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
                    .child_subprocess_image()
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

/// The parent user-Heap allocation holding one child main Heap image
/// (`_mi_heap_new_for_subproc`: `mi_heap_zalloc(parent->heap_main)`).
///
/// `Parent` is minted by a later-main owner-local engine and must be freed
/// by that same owner. `Native` is an ordinary allocation through the native
/// runtime entry points, which source `_mi_free_subproc_safe` may free from
/// any thread.
pub(crate) enum ChildHeapStorage<'heap> {
    Parent(crate::main_heap_page::ParentHeapAllocation<'heap>),
    Native(NativeChildHeapImage),
}

impl ChildHeapStorage<'_> {
    /// Original address for identity comparisons only. It does not authorize
    /// reading image bytes after preparation, consumption or rejection.
    #[inline]
    pub(crate) const fn pointer_for_identity(&self) -> NonNull<Heap> {
        match self {
            Self::Parent(allocation) => allocation.pointer_for_identity(),
            Self::Native(image) => image.pointer,
        }
    }

    /// Returns projection authority only while native bytes remain a live
    /// Heap image. Diagnostic identity is separately available after release.
    #[cfg(target_arch = "x86_64")]
    fn pointer_for_live_image(&self) -> Option<NonNull<Heap>> {
        match self {
            Self::Native(image) if image.state != NativeChildHeapImageState::Live => None,
            _ => Some(self.pointer_for_identity()),
        }
    }

    #[inline]
    pub(crate) const fn memory_id(&self) -> MemoryId {
        match self {
            Self::Parent(allocation) => allocation.memory_id(),
            Self::Native(image) => image.memory_id(),
        }
    }

    fn initialize_empty_image(&mut self) -> bool {
        match self {
            Self::Parent(allocation) => allocation.initialize_empty_image(),
            Self::Native(image) => image.initialize_empty_image(),
        }
    }

    pub(crate) fn with_heap<R>(
        &mut self,
        operation: impl for<'image> FnOnce(Pin<&'image mut Heap>) -> R,
    ) -> Option<R> {
        match self {
            Self::Parent(allocation) => allocation.with_heap(operation),
            Self::Native(image) => image.with_heap(operation),
        }
    }
}

/// The free route for [`ChildHeapStorage`] at child destruction.
pub(crate) enum ChildHeapRelease<'a, 'heap> {
    Parent {
        heap_owner: &'a mut crate::main_heap_page::MainHeapThreadOwnerLocalPageEngine<'heap>,
        attachment: &'a mut crate::main_heap_thread::MainHeapThreadAttachment<'heap>,
    },
    Native,
    /// Process destruction (`_mi_subprocs_unsafe_destroy_all`) under
    /// permanent terminal quiescence, when the native entry points are
    /// closed. The `Native` image is not freed block by block: it stays a
    /// live block on its parent's page, which later parent destruction
    /// releases with that parent's pages. Source frees
    /// it with `_mi_free_subproc_safe` just before; in the release statistics
    /// profile that free changes no statistic unless it empties a page that
    /// is not its queue's only page, which is then freed early.
    Terminal,
}

#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativeChildHeapImageState {
    Live,
    // Source free preparation can overwrite the payload and padding. The
    // exact live allocation remains releasable, but is no longer a Heap image.
    Prepared,
    // This token keeps only the original diagnostic identity after consumed
    // failure or padding rejection. The issuing allocator retains unfinished
    // backing; bytes may be reused/unmapped after consumption. No image
    // projection or release retry is permitted.
    Terminal,
}

/// One zeroed Heap image allocated through the native runtime.
/// The token owns the allocation; dropping it frees nothing.
#[must_use = "a child Heap image must be freed after child Heap teardown"]
pub(crate) struct NativeChildHeapImage {
    pointer: NonNull<Heap>,
    initialized: bool,
    #[cfg(target_arch = "x86_64")]
    state: NativeChildHeapImageState,
}

impl NativeChildHeapImage {
    const fn image_request_size() -> usize {
        #[cfg(target_arch = "x86_64")]
        { crate::source_heap_api::SOURCE_HEAP_IMAGE_REQUEST_SIZE }
        #[cfg(not(target_arch = "x86_64"))]
        { size_of::<Heap>() }
    }

    /// `mi_heap_zalloc(parent->heap_main, sizeof(mi_heap_t))` on the calling
    /// thread, through the native runtime's current owner.
    pub(crate) fn allocate() -> Option<Self> {
        #[cfg(target_arch = "x86_64")]
        {
            const _: () = assert!(size_of::<Heap>() <= crate::source_heap_api::SOURCE_HEAP_IMAGE_REQUEST_SIZE);
            let parent = crate::source_heap_api::heap_main();
            if parent.is_null() { return None; }
            // SAFETY: subprocess creation retains the calling thread's live
            // parent main Heap until this unpublished child image is released.
            let pointer = unsafe {
                crate::source_heap_api::heap_zalloc(parent, Self::image_request_size())
            }.value?;
            // SAFETY: this exact ordinary allocation is still exclusively
            // owned and contains no published Heap or client projection.
            let usable = unsafe { crate::runtime_lifecycle::native_usable_size(pointer) };
            if pointer.as_ptr().addr() % core::mem::align_of::<Heap>() != 0
                || usable.is_none_or(|usable| usable < Self::image_request_size()) {
                // SAFETY: no typed image or client was published in the block.
                let _ = unsafe { crate::runtime_lifecycle::native_free(pointer) };
                return None;
            }
            Some(Self { pointer: pointer.cast(), initialized: false, state: NativeChildHeapImageState::Live })
        }
        #[cfg(not(target_arch = "x86_64"))]
        match crate::runtime_lifecycle::native_allocate_aligned(
            size_of::<Heap>(), core::mem::align_of::<Heap>(), true,
        ) {
            crate::runtime_lifecycle::NativePageAllocationResult::Allocated(pointer) => {
                Some(Self { pointer: pointer.cast(), initialized: false })
            }
            _ => None,
        }
    }

    #[inline]
    const fn memory_id(&self) -> MemoryId {
        MemoryId::malloc(self.pointer.as_ptr().cast(), Self::image_request_size(), true)
    }

    fn initialize_empty_image(&mut self) -> bool {
        #[cfg(target_arch = "x86_64")]
        if self.state != NativeChildHeapImageState::Live { return false; }
        if self.initialized || self.pointer.as_ptr().addr() % core::mem::align_of::<Heap>() != 0 {
            return false;
        }
        // SAFETY: the token was minted from one successful sufficiently large zeroed
        // allocation, is uniquely borrowed, and keeps its stable address.
        unsafe { Heap::write_bootstrap_empty_at(self.pointer) };
        self.initialized = true;
        true
    }

    fn with_heap<R>(
        &mut self,
        operation: impl for<'image> FnOnce(Pin<&'image mut Heap>) -> R,
    ) -> Option<R> {
        #[cfg(target_arch = "x86_64")]
        if self.state != NativeChildHeapImageState::Live { return None; }
        if !self.initialized { return None; }
        // SAFETY: the linear token retains this exact allocation, no mutable
        // projection escapes the HRTB closure, and its address is stable.
        Some(operation(unsafe { Pin::new_unchecked(&mut *self.pointer.as_ptr()) }))
    }

    /// Frees the image with the source `_mi_free_subproc_safe` policy.
    /// On x86 a pre-consumption refusal returns its exact live token. A
    /// prepared refusal retains only release authority, without image access.
    /// A consumed error returns terminal diagnostic custody, which permits no
    /// image access or release retry. Padding rejection is also diagnostic
    /// terminal custody without claiming consumption. Other targets keep their historical
    /// unclassified native result and the outer caller's terminal policy.
    ///
    /// # Safety
    /// Child Heap teardown is complete: the Heap is off every list, no Theap
    /// or page names it, and no projection of it remains. A live token owns
    /// the exact current allocation. Terminal custody is admitted only to
    /// refuse before any pointer is passed to the release primitive.
    pub(crate) unsafe fn free(self) -> Result<(), Self> {
        #[cfg(target_arch = "x86_64")]
        {
            let mut image = self;
            if image.state == NativeChildHeapImageState::Terminal { return Err(image); }
            let Some(operation) = crate::runtime_lifecycle::NativeSubprocessOperation::enter() else {
                return Err(image);
            };
            // SAFETY: this exact live token has completed teardown. No
            // image projection spans source warning or padding callbacks.
            if unsafe { image.prepare_for_free(&operation) }.is_err() { return Err(image); }
            // SAFETY: retained admission and the exact prepared capability
            // authorize release. A retry does not repeat padding preparation.
            return unsafe { image.free_with_progress(|pointer| {
                unsafe { crate::subproc::main_heaps::free_prepared_subproc_safe_with_progress(pointer) }
            }) };
        }
        #[cfg(not(target_arch = "x86_64"))]
        // SAFETY: the token owns this exact live native allocation.
        match unsafe { crate::runtime_lifecycle::native_free(self.pointer.cast()) } {
            crate::runtime_lifecycle::NativePageFreeResult::Freed => Ok(()),
            _ => Err(self),
        }
    }

    /// # Safety
    /// The exact live or prepared allocation and its issuing owner remain
    /// retained with `operation`; teardown is complete. No image projection
    /// spans preparation callbacks, which cannot free this in-flight client.
    #[cfg(target_arch = "x86_64")]
    unsafe fn prepare_for_free(
        &mut self,
        operation: &crate::runtime_lifecycle::NativeSubprocessOperation,
    ) -> Result<(), crate::runtime_lifecycle::NativeFreePreparationError> {
        use crate::runtime_lifecycle::NativeFreePreparationError;
        match self.state {
            NativeChildHeapImageState::Terminal => Err(NativeFreePreparationError::Retained),
            NativeChildHeapImageState::Prepared => Ok(()),
            NativeChildHeapImageState::Live => {
                // SAFETY: exact retained custody and admission are forwarded.
                match unsafe { operation.prepare_client_for_free(self.pointer.cast()) } {
                    Ok(()) => {
                        self.state = NativeChildHeapImageState::Prepared;
                        self.initialized = false;
                        Ok(())
                    }
                    Err(NativeFreePreparationError::Retained) => Err(NativeFreePreparationError::Retained),
                    #[cfg(any(feature = "mi-debug-1", feature = "mi-secure-3"))]
                    Err(NativeFreePreparationError::PaddingRejected) => {
                        self.state = NativeChildHeapImageState::Terminal;
                        self.initialized = false;
                        Err(NativeFreePreparationError::PaddingRejected)
                    }
                }
            }
        }
    }

    /// # Safety
    /// Live or prepared custody owns the exact current allocation and its
    /// completed teardown. `release` reports actual consumption and retains backing on
    /// error. Terminal custody cannot invoke `release` or access image bytes.
    #[cfg(target_arch = "x86_64")]
    unsafe fn free_with_progress(
        mut self,
        release: impl FnOnce(NonNull<u8>) -> crate::single_thread::LocalClientFreeProgress,
    ) -> Result<(), Self> {
        use crate::single_thread::LocalClientFreeProgress;
        if self.state == NativeChildHeapImageState::Terminal { return Err(self); }
        match release(self.pointer.cast()) {
            LocalClientFreeProgress::Consumed(Ok(())) => Ok(()),
            LocalClientFreeProgress::RefusedBeforeConsumption(_) => Err(self),
            LocalClientFreeProgress::Consumed(Err(_)) => {
                self.state = NativeChildHeapImageState::Terminal;
                Err(self)
            }
        }
    }

}

/// A child context whose main Heap image is retained by the exact parent
/// user-Heap allocation token. This owner spans registry admission through
/// the represented Heap/Theap list transitions; it does not claim page
/// destruction or child MetadataEngine readiness.
#[must_use = "a parent-allocated child Heap owner must remain through terminal release"]
pub(crate) struct ChildMainHeapContextOwner<'heap> {
    context: ChildContextOwner,
    heap_storage: Option<ChildHeapStorage<'heap>>,
    pending_os_release: Option<crate::os_page::OsAlignedPageOwner>,
    // This owner retains the original issuing images while an unpublished
    // claim remains terminal; the claim's raw identities grant no lifetime.
    pending_fresh_initialization: Option<crate::single_thread::PendingFreshOsPageInitialization>,
    pending_live_page_validity: Option<crate::single_thread::PendingLivePageValidity>,
    page_engine: ChildPageEngineState,
    metadata_pages_may_exist: bool,
    stage: ChildMainHeapStage,
    #[cfg(test)]
    fail_next_metadata_session_setup: bool,
}

/// One exact zeroed block allocated from the child's own metadata Theap.
/// These blocks back the ordinary child TLD and thread Theap; their bytes are
/// separate from the parent-issued context/metadata-Theap capabilities.
struct ChildMetadataImageBlock {
    pointer: NonNull<u8>,
    size: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ChildThreadOwnerState {
    Starting,
    Attached,
    Terminal,
    Complete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ChildThreadTeardownError {
    InvalidTransition,
    PagesRemain,
    PageEngine(ChildMetadataPageEngineError),
    TheapList(crate::types::ThreadLocalTheapListError),
    TheapClear,
    TldLock(crate::types::ThreadLocalDataQuiesceError),
    TheapRelease(FreeError),
    TldRelease(FreeError),
}

/// One ordinary child-thread TLD and regular Theap, with metadata allocations
/// and the live subprocess registration retained outside their images.
///
/// The owner does not borrow its child context, so the context can be shared
/// with other child threads while this thread allocates. Its registration
/// lease keeps the child's live thread count raised until [`Self::teardown`].
/// Ordinary owned destruction refuses a live thread. Native terminal destruction
/// can instead retain an orphan control under permanent worker quiescence;
/// allocation therefore also requires the caller to exclude that destruction.
/// A retained unfinished owner keeps its original TLD/Theap clients and any
/// unpublished page claim alive; terminal destruction must preserve those
/// issuing images until orphan completion rather than infer lifetime from a
/// thread count or a raw address.
///
/// Each thread keeps its own page-engine state (pending raw unmap retry and
/// engine poison), as source keeps page state per Theap.
#[must_use = "retain a child TLD/Theap owner through page and thread teardown"]
pub(crate) struct ChildThreadOwner {
    image: NonNull<crate::subproc::ChildSubprocessImage>,
    heap: NonNull<Heap>,
    parent_subprocess: &'static MainSubprocess,
    config: MemoryConfig,
    tld: Option<ChildMetadataImageBlock>,
    theap: Option<ChildMetadataImageBlock>,
    registration: Option<crate::subproc::ChildThreadRegistrationLease>,
    thread: LiveThreadId,
    sequence: ThreadSequence,
    state: ChildThreadOwnerState,
    pending_os_release: Option<crate::os_page::OsAlignedPageOwner>,
    // This owner retains the original issuing images while an unpublished
    // claim remains terminal; the claim's raw identities grant no lifetime.
    pending_fresh_initialization: Option<crate::single_thread::PendingFreshOsPageInitialization>,
    pending_live_page_validity: Option<crate::single_thread::PendingLivePageValidity>,
    page_engine: ChildPageEngineState,
    /// This thread's regular dynamic thread-local slots
    /// (`mi_thread_locals_t`), allocated from the child's metadata as
    /// `mi_thread_locals_expand` does with `_mi_subproc()`, and installed in
    /// the compiler-TLS dynamic root.
    thread_locals: Option<ChildMetadataImageBlock>,
    // A failed growth retains the copied unpublished allocation alongside
    // any old array whose release refused before consumption. Neither is
    // active compiler-TLS storage after the thread owner becomes terminal.
    #[cfg(target_arch = "x86_64")]
    pending_thread_locals: Option<ChildMetadataImageBlock>,
    /// The one retained raw-unmap retry of this thread's Theaps for non-main
    /// Heaps, with the Theap whose engine it latched `RetryPending` (`None`
    /// once that Theap is freed); see [`ChildHeapTheapImage`].
    heap_theap_pending_os_release: Option<(Option<NonNull<Theap>>, crate::os_page::OsAlignedPageOwner)>,
    heap_theap_pending_fresh_initialization: Option<(NonNull<Theap>, crate::single_thread::PendingFreshOsPageInitialization)>,
    heap_theap_pending_live_page_validity: Option<(NonNull<Theap>, crate::single_thread::PendingLivePageValidity)>,
}

/// One child-thread Theap for a non-main Heap: the source `mi_theap_t` at
/// offset zero, then this Theap's own page-engine state.
///
/// Source `_mi_theap_alloc` takes an ordinary Heap's image from its
/// subprocess metadata and a selected Heap's image from its requested arena.
/// The Theap's `memid` carries the exact release provenance. The image also carries the page
/// engine state that the thread's main-Heap Theap keeps in its
/// [`ChildThreadOwner`], because pinned `mi_arena_pages_alloc`
/// (`arena.c:1661-1672`) allocates a non-main Heap's per-arena page record
/// with `mi_heap_zalloc_aligned(heap_main, ...)` from inside a page
/// allocation for that Heap (`mi_heap_ensure_arena_pages`, `arena.c:804`):
/// the inner allocation runs a second page operation on the thread's
/// main-Heap Theap while the outer one is still in progress on this Theap.
/// Source page queues and their state are per Theap, so each engine owns its
/// Theap's state. Only the engine state fits: the block keeps the source size
/// class (`heap_lifecycle::tests::child_heap_theap_image_keeps_the_theap_size_class`),
/// which a retained raw-unmap retry owner (`OsAlignedPageOwner`) would break,
/// so that owner lives in the thread's [`ChildThreadOwner`] instead (one slot
/// for all of the thread's non-main Theaps; a second concurrent retry is
/// leaked with its Theap's engine poisoned).
#[repr(C)]
pub(crate) struct ChildHeapTheapImage {
    theap: Theap,
    page_engine: ChildPageEngineState,
}

impl ChildThreadOwner {
    #[inline]
    pub(crate) const fn sequence(&self) -> ThreadSequence { self.sequence }

    #[inline]
    pub(crate) const fn thread(&self) -> LiveThreadId { self.thread }

    /// This thread's regular Theap while the owner retains its block. The
    /// address identifies the Theap for the thread's compiler-TLS roots; it
    /// grants no projection of the image.
    #[inline]
    pub(crate) fn theap_pointer(&self) -> Option<NonNull<Theap>> {
        self.theap.as_ref().map(|block| block.pointer.cast())
    }

    /// An original unpublished claim or detached live Page assertion prevents
    /// member/image retirement before registration, lists or caches change.
    pub(crate) fn has_pending_page_assertion(&self) -> bool {
        (self.pending_fresh_initialization.is_some() || self.pending_live_page_validity.is_some())
            || (self.heap_theap_pending_fresh_initialization.is_some() || self.heap_theap_pending_live_page_validity.is_some())
    }

    /// Moves a source assertion from this exact retained current member.
    /// The caller already retains its actual issuer and ends every member
    /// and record projection before delivering diagnostic output.
    #[cfg(all(target_arch = "x86_64", feature = "mi-debug-3"))]
    pub(crate) fn take_thread_done_live_validity(&mut self)
        -> Option<crate::single_thread::PendingLivePageValidity> {
        self.pending_live_page_validity.take().or_else(|| {
            self.heap_theap_pending_live_page_validity.take().map(|(_, task)| task)
        })
    }

    #[cfg(test)]
    pub(crate) fn test_has_main_pending_fresh_initialization(&self) -> bool {
        self.pending_fresh_initialization.is_some()
    }

    #[cfg(test)]
    pub(crate) fn test_has_heap_theap_pending_fresh_initialization(&self, theap: NonNull<Theap>) -> bool {
        self.heap_theap_pending_fresh_initialization.as_ref()
            .is_some_and(|(issuer, _)| *issuer == theap)
    }

    /// Whether `child` is the context owner that admitted this thread.
    pub(crate) fn belongs_to(&self, child: &mut ChildMainHeapContextOwner<'_>) -> bool {
        child.identity_pointer()
            .is_some_and(|identity| identity == self.image.as_ptr().cast())
    }

    /// Projects the child image that this thread's TLD names, for source
    /// subprocess-scoped transitions such as thread statistics. It is
    /// available only while the registration keeps the child alive.
    pub(crate) fn with_child_image<R>(
        &mut self,
        operation: impl for<'image> FnOnce(Pin<&'image crate::subproc::ChildSubprocessImage>) -> R,
    ) -> Option<R> {
        self.registration.as_ref()?;
        // SAFETY: the enclosing lifecycle retains this registered member's
        // child image. Ordinary destruction refuses live members; permanent
        // quiescent destruction retains the image for orphan completion and
        // excludes further allocation. Each projected transition is atomic
        // or internally synchronized; it does not authorize allocation after
        // terminal destruction.
        Some(operation(unsafe { Pin::new_unchecked(self.image.as_ref()) }))
    }

    /// Completes the raw unmap retry retained by one of this thread's Theaps
    /// for a non-main Heap, as [`Self::retry_pending_os_release`] does for
    /// its main-Heap Theap. `Ok(false)` when there is none or it is not ready.
    ///
    /// # Safety
    /// As for [`Self::retry_pending_os_release`]; the Theap is still live.
    pub(crate) unsafe fn retry_heap_theap_pending_os_release(
        &mut self,
    ) -> Result<bool, crate::os_page::OsAlignedPageError> {
        let Some((theap, owner)) = self.heap_theap_pending_os_release.take() else { return Ok(false) };
        if !owner.raw_retry_ready() {
            self.heap_theap_pending_os_release = Some((theap, owner));
            return Ok(false);
        }
        // SAFETY: the sole outstanding release right of that mapping.
        match unsafe { owner.retry_release() } {
            Ok(()) => {
                if let Some(theap) = theap {
                    // SAFETY: a named Theap is still allocated (a free clears it).
                    let state = unsafe { &mut (*theap.cast::<ChildHeapTheapImage>().as_ptr()).page_engine };
                    *state = state.complete_raw_retry().unwrap_or(ChildPageEngineState::Poisoned);
                }
                Ok(true)
            }
            Err(failure) => {
                let error = failure.error();
                self.heap_theap_pending_os_release = Some((theap, failure.into_owner()));
                Err(error)
            }
        }
    }

    /// Completes an already-accounted raw unmap retry retained by this
    /// thread's own page operation.
    ///
    /// # Safety
    /// The caller has stopped all operations using the failed page and keeps
    /// this exact child-thread owner alive through the retry.
    pub(crate) unsafe fn retry_pending_os_release(
        &mut self,
    ) -> Result<bool, crate::os_page::OsAlignedPageError> {
        if self.page_engine != ChildPageEngineState::RetryPending { return Ok(false); }
        let Some(owner) = self.pending_os_release.take() else { return Ok(false); };
        if !owner.raw_retry_ready() {
            self.pending_os_release = Some(owner);
            return Ok(false);
        }
        // SAFETY: this owner is the sole outstanding terminal mapping release
        // right, and its registration keeps the child context alive.
        match unsafe { owner.retry_release() } {
            Ok(()) => {
                let Some(next) = self.page_engine.complete_raw_retry() else {
                    unreachable!("raw retry was admitted only in the retry-pending state");
                };
                self.page_engine = next;
                Ok(true)
            }
            Err(failure) => {
                let error = failure.error();
                self.pending_os_release = Some(failure.into_owner());
                Err(error)
            }
        }
    }

    /// Runs one ordinary child-thread page-engine operation using that
    /// thread's live TLD/Theap and the child's arena identity. Metadata pages
    /// continue to use `ChildMainHeapContextOwner::with_metadata_page_engine`.
    ///
    /// Like the persistent later-main owner, the operation takes no PageMap
    /// lifecycle lease: it registers and unregisters only the page ranges it
    /// owns, which source updates with plain writes, and it does not borrow
    /// the child context, so other child threads run concurrently.
    ///
    /// # Safety
    /// This must run on the child thread represented by the owner, with no
    /// competing mutation of its TLD/Theap. The canonical PageMap and child
    /// arena binding remain retained for the complete operation.
    pub(crate) unsafe fn with_page_engine<R>(
        &mut self,
        binding: crate::process_init::ProcessMainBackingBinding,
        operation: impl for<'session, 'child> FnOnce(
            Pin<&'child crate::subproc::ChildSubprocessImage>,
            &mut crate::single_thread::ChildOrdinaryPageAllocator<'session, 'child, 'static>,
        ) -> R,
    ) -> Result<R, ChildMetadataPageEngineError> {
        if self.state != ChildThreadOwnerState::Attached
            || self.registration.is_none()
            || self.pending_os_release.is_some() || (self.pending_fresh_initialization.is_some() || self.pending_live_page_validity.is_some())
            || self.page_engine != ChildPageEngineState::Active
            || !binding.is_active()
            || !binding.is_allocation_ready()
            || binding.process().main_subprocess().is_none_or(|parent| {
                !core::ptr::eq(parent, self.parent_subprocess)
            })
            || binding.page_map().memory_config().ok() != Some(self.config)
        {
            return Err(ChildMetadataPageEngineError::InvalidTransition);
        }
        let tld = self.tld.as_ref()
            .map(|block| block.pointer.cast::<ThreadLocalData>())
            .ok_or(ChildMetadataPageEngineError::InvalidTransition)?;
        let theap = self.theap.as_ref()
            .map(|block| block.pointer.cast::<Theap>())
            .ok_or(ChildMetadataPageEngineError::InvalidTransition)?;
        let Self { image, heap, thread, sequence, pending_os_release, pending_fresh_initialization, pending_live_page_validity, page_engine, .. } = self;
        // SAFETY: see `with_child_image`; the registration was checked above.
        let child_ref = unsafe { Pin::new_unchecked(image.as_ref()) };
        let child_process = crate::os::ChildVmProcess::new(binding.process(), child_ref)
            .map_err(ChildMetadataPageEngineError::ChildProcess)?;
        let pair = crate::process_arena::ChildProcessPageArenaLease::join(
            binding.page_map(), child_process,
        ).map_err(ChildMetadataPageEngineError::BackingPair)?;
        // SAFETY: this engine registers and unregisters only the exact page
        // ranges this Theap owns, and retains their page metadata until its
        // local access is quiescent and the entries are removed. Other plain
        // map writers may overlap only for disjoint owned ranges.
        let page_map = unsafe { pair.page_map_for_owned_ranges() }
            .map_err(ChildMetadataPageEngineError::BackingPair)?;
        // SAFETY: this owner retains the exact TLD/Theap metadata blocks and
        // its session state; the registration retains the child image and
        // its main Heap.
        let session = unsafe {
            crate::types::metadata_session::ChildOrdinaryTheapPageSession::new(
                child_ref, tld, theap, *heap, *thread, *sequence,
                pending_os_release, page_engine,
            ).and_then(|session| session.with_fresh_initialization_slot(pending_fresh_initialization))
                .and_then(|session| session.with_live_page_validity_slot(pending_live_page_validity))
        }.ok_or(ChildMetadataPageEngineError::SessionNotReady)?;
        let backing = crate::page_backing::ChildMetadataArenaBacking::new(pair);
        // SAFETY: the validated child pair and session are held through the
        // complete operation.
        let mut engine = unsafe {
            crate::single_thread::ChildOrdinaryPageAllocator::activate_child_ordinary(
                session, backing, page_map, *sequence, crate::arena::ArenaId::none(),
            )
        };
        let value = operation(child_ref, &mut engine);
        if let Err(engine) = engine.finish_operation() {
            // Its Drop transfers an accounted OS retry owner and latches any
            // other unfinished page-engine state in this thread owner.
            drop(engine);
            return Err(ChildMetadataPageEngineError::EngineRetained);
        }
        Ok(value)
    }

    /// Drains this thread's now-unused pages, detaches its regular Theap from
    /// the child Heap and TLD, then releases the exact Theap/TLD blocks
    /// through the child's metadata allocator. Clients must free every
    /// ordinary allocation first.
    ///
    /// # Safety
    /// The caller has ended every client use of this thread allocator, has
    /// freed every allocation made through it, and calls on the same OS
    /// thread that initialized this owner. `child` is the context owner that
    /// admitted this thread, with no other operation on it running. Any error
    /// after page drain or list mutation leaves this owner terminal and must
    /// retain it with the child.
    pub(crate) unsafe fn teardown(
        &mut self,
        child: &mut ChildMainHeapContextOwner<'_>,
        binding: crate::process_init::ProcessMainBackingBinding,
    ) -> Result<(), ChildThreadTeardownError> {
        if self.has_pending_page_assertion()
            || self.state != ChildThreadOwnerState::Attached || !self.belongs_to(child) {
            return Err(ChildThreadTeardownError::InvalidTransition);
        }
        // A live allocation leaves its page attached and the owner retryable.
        let drained = unsafe {
            self.with_page_engine(binding, |_child, engine| engine.finish_pages_in_place())
        }.map_err(ChildThreadTeardownError::PageEngine)?;
        if !drained {
            return Err(ChildThreadTeardownError::PagesRemain);
        }

        self.state = ChildThreadOwnerState::Terminal;
        let tld_pointer = self.tld.as_ref()
            .ok_or(ChildThreadTeardownError::InvalidTransition)?
            .pointer.cast::<ThreadLocalData>();
        let theap_pointer = self.theap.as_ref()
            .ok_or(ChildThreadTeardownError::InvalidTransition)?
            .pointer.cast::<Theap>();
        let detached = child.heap_storage.as_mut()
            .and_then(|storage| storage.with_heap(|mut heap| {
                // SAFETY: owner state is terminal; page drain completed; the
                // exact TLD/Theap images remain retained in `self`.
                let tld = unsafe { &mut *tld_pointer.as_ptr() };
                let result = tld.detach_one_theap_from_heap(
                    unsafe { heap.as_mut().get_unchecked_mut() },
                    theap_pointer.as_ptr(),
                );
                if let Err(error) = result { return Err(error); }
                tld.detach_one_theap_from_tld(theap_pointer.as_ptr())
            }));
        match detached {
            Some(Ok(())) => {}
            Some(Err(error)) => return Err(ChildThreadTeardownError::TheapList(error)),
            None => return Err(ChildThreadTeardownError::InvalidTransition),
        }

        // SAFETY: both intrusive list edges were removed above, with the
        // source heap publication cleared by the Heap detach transition.
        if !unsafe { (&mut *theap_pointer.as_ptr()).clear_dynamic_metadata_after_detach() } {
            return Err(ChildThreadTeardownError::TheapClear);
        }
        let registration = self.registration.take()
            .ok_or(ChildThreadTeardownError::InvalidTransition)?;
        // This is `mi_tld_free`'s first source transition: live subprocess
        // count decreases before the TLD identity is invalidated.
        // SAFETY: `child` is the context owner that issued this lease and is
        // uniquely borrowed for this call, so its parent-metadata allocation
        // and pinned child image cannot be released before it returns. Both
        // Theap list edges were removed above, and the TLD identity is valid.
        unsafe { registration.release() };
        let tld = unsafe { &mut *tld_pointer.as_ptr() };
        tld.invalidate_attached_theap_for_teardown();
        tld.quiesce_theap_list_lock_for_teardown()
            .map_err(ChildThreadTeardownError::TldLock)?;

        let mut free_theap = None;
        let mut free_tld = None;
        let mut theap_consumed = false;
        let mut tld_consumed = false;
        let release = child.with_metadata_page_engine(binding, |_child, engine| {
            // Both blocks are exact child metadata allocations. No typed
            // projections remain after list removal and invalidation.
            free_theap = Some(match unsafe { engine.free_with_progress(theap_pointer.cast()) } {
                crate::single_thread::LocalClientFreeProgress::RefusedBeforeConsumption(error) => Err(error),
                crate::single_thread::LocalClientFreeProgress::Consumed(result) => {
                    theap_consumed = true;
                    result
                }
            });
            if matches!(free_theap, Some(Ok(()))) {
                free_tld = Some(match unsafe { engine.free_with_progress(tld_pointer.cast()) } {
                    crate::single_thread::LocalClientFreeProgress::RefusedBeforeConsumption(error) => Err(error),
                    crate::single_thread::LocalClientFreeProgress::Consumed(result) => {
                        tld_consumed = true;
                        result
                    }
                });
            }
        });
        // Returning a client to the local free list ends its allocation
        // custody. Later backing or PageMap cleanup may still fail, but its
        // retained page-engine state never grants a second client release.
        // Settle both slots before propagating even an outer engine error.
        if theap_consumed {
            self.theap = None;
            child.context.with_image(|image| {
                image.get_ref().identity().record_statistics_theap_unlinked();
            });
        }
        if tld_consumed { self.tld = None; }
        release.map_err(ChildThreadTeardownError::PageEngine)?;
        match free_theap {
            Some(Ok(())) => {}
            Some(Err(error)) => return Err(ChildThreadTeardownError::TheapRelease(error)),
            None => return Err(ChildThreadTeardownError::InvalidTransition),
        }
        match free_tld {
            Some(Ok(())) => {}
            Some(Err(error)) => return Err(ChildThreadTeardownError::TldRelease(error)),
            None => return Err(ChildThreadTeardownError::InvalidTransition),
        }
        self.state = ChildThreadOwnerState::Complete;
        Ok(())
    }
}

/// Physical initializedness of one caller-retained owner slot. This does
/// not replace the source thread owner's lifecycle state.
#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ChildThreadInitializationStorageState { Vacant, Owned, Consumed }

/// One original child-thread owner retained in its caller's final storage
/// across source callbacks. The exclusive borrow passed through preparation
/// and completion prevents a caller from consuming it between those phases.
/// Retained bytes deliberately have no implicit resource-releasing drop;
/// the actual child initialization admission must survive a terminal outcome.
#[cfg(target_arch = "x86_64")]
pub(crate) struct ChildThreadInitializationStorage {
    owner: core::mem::MaybeUninit<ChildThreadOwner>,
    state: ChildThreadInitializationStorageState,
}

#[cfg(target_arch = "x86_64")]
impl ChildThreadInitializationStorage {
    pub(crate) const fn vacant() -> Self {
        Self { owner: core::mem::MaybeUninit::uninit(), state: ChildThreadInitializationStorageState::Vacant }
    }

    pub(crate) fn owns_candidate(&self) -> bool { self.state == ChildThreadInitializationStorageState::Owned }

    fn owner_mut(&mut self) -> &mut ChildThreadOwner {
        assert!(self.owns_candidate(), "only an initialized original owner may be projected");
        // SAFETY: allocation records Owned only after writing every field;
        // the exclusive storage borrow ends before any source callback.
        unsafe { self.owner.assume_init_mut() }
    }

    pub(crate) fn retain_refusal(&mut self) -> ChildThreadStartError {
        self.owner_mut().state = ChildThreadOwnerState::Terminal;
        ChildThreadStartError::InvalidTransition
    }

    pub(crate) fn retain(&mut self, error: crate::types::TheapMainStaticInitError) -> ChildThreadStartError {
        self.owner_mut().state = ChildThreadOwnerState::Terminal;
        ChildThreadStartError::TheapInitialization(child_dynamic_init_error(error))
    }

    /// Consumes the original value once at the final keeper or publication
    /// boundary. No image or registration is reconstructed from its address.
    pub(crate) fn take_owner(&mut self) -> ChildThreadOwner {
        assert!(self.owns_candidate(), "the original owner is consumed exactly once");
        self.state = ChildThreadInitializationStorageState::Consumed;
        // SAFETY: Owned proves all fields initialized and not consumed. The
        // MaybeUninit field cannot drop this moved value a second time.
        unsafe { self.owner.as_ptr().read() }
    }

    /// Consumes an attached owner only at its final member publication edge.
    ///
    /// # Safety
    /// This slot holds the same candidate that completed source publication.
    /// The caller already owns its exact issued record-member token, retains
    /// the original child and compiler-TLS roots, and publishes this owner as
    /// that token's member before any callback or competing lifecycle operation.
    pub(crate) unsafe fn take_attached_owner(&mut self) -> ChildThreadOwner {
        assert_eq!(self.owner_mut().state, ChildThreadOwnerState::Attached,
            "member publication consumes an actually attached original owner");
        self.take_owner()
    }

    pub(crate) fn theap_pointer(&mut self) -> Option<NonNull<Theap>> { self.owner_mut().theap_pointer() }

    pub(crate) fn record_thread_attached(&mut self) -> bool {
        self.owner_mut().with_child_image(|image| {
            image.get_ref().identity().record_statistics_thread_attached();
        }).is_some()
    }

    /// Counts and publishes this same candidate after every callback ended.
    ///
    /// # Safety
    /// `ready` derives from this slot's exact preparation. The caller retains
    /// its original child admission across all source phases and excludes
    /// competing lifecycle mutation until this same candidate is published.
    /// Every callback and candidate-image projection has ended.
    pub(crate) unsafe fn complete_source(
        &mut self, ready: crate::types::ReadyTheapInitialization,
    ) -> Result<(), ChildThreadStartError> {
        // SAFETY: the original initialized owner and admission are retained.
        unsafe { complete_child_thread_source(self.owner_mut(), ready) }
    }
}

/// Preparation returns only its source phase or scalar refusal. The original
/// candidate stays in the caller-retained slot on every initialized outcome.
#[cfg(target_arch = "x86_64")]
#[must_use]
pub(crate) enum ChildThreadPreparationOutcome {
    Prepared(crate::types::PreparedTheapInitialization),
    Rejected(ChildThreadStartError),
    Retained(ChildThreadStartError),
}

/// Final source publication shared by direct keepers and caller-retained
/// storage. A refusal terminalizes the original owner without guessed teardown.
#[cfg(target_arch = "x86_64")]
unsafe fn complete_child_thread_source(
    owner: &mut ChildThreadOwner, ready: crate::types::ReadyTheapInitialization,
) -> Result<(), ChildThreadStartError> {
    if owner.with_child_image(|image| image.get_ref().identity().record_statistics_theap_linked()).is_none() {
        owner.state = ChildThreadOwnerState::Terminal;
        return Err(ChildThreadStartError::TheapInitialization(child_dynamic_init_error(
            crate::types::TheapMainStaticInitError::InvalidInput)));
    }
    // SAFETY: this same candidate and original child registration are
    // retained through the source counter and final list publication.
    if let Err(error) = unsafe { ready.publish_heap() } {
        owner.state = ChildThreadOwnerState::Terminal;
        return Err(ChildThreadStartError::TheapInitialization(child_dynamic_init_error(error)));
    }
    owner.state = ChildThreadOwnerState::Attached;
    Ok(())
}

/// The original child-thread blocks and registration awaiting source
/// option and random phases. Dropping this owner never guesses teardown.
#[cfg(target_arch = "x86_64")]
#[must_use]
pub(crate) struct PendingChildThreadInitialization {
    keeper: ChildThreadInitializationOwner,
    phase: crate::types::PreparedTheapInitialization,
}

#[cfg(target_arch = "x86_64")]
impl PendingChildThreadInitialization {
    pub(crate) fn into_phase(self) -> (ChildThreadInitializationOwner, crate::types::PreparedTheapInitialization) {
        (self.keeper, self.phase)
    }
}

/// Actual allocation and registration custody independent of the raw
/// initializer phase. The enclosing admission retains the original child.
#[cfg(target_arch = "x86_64")]
#[must_use]
pub(crate) struct ChildThreadInitializationOwner(ChildThreadOwner);

#[cfg(target_arch = "x86_64")]
impl ChildThreadInitializationOwner {
    pub(crate) fn retain_refusal(mut self) -> ChildThreadStartFailure {
        self.0.state = ChildThreadOwnerState::Terminal;
        ChildThreadStartFailure::Retained { owner: self.0, error: ChildThreadStartError::InvalidTransition }
    }

    pub(crate) fn retain(mut self, error: crate::types::TheapMainStaticInitError) -> ChildThreadStartFailure {
        self.0.state = ChildThreadOwnerState::Terminal;
        ChildThreadStartFailure::Retained { owner: self.0,
            error: ChildThreadStartError::TheapInitialization(child_dynamic_init_error(error)) }
    }

    /// Counts and publishes this original candidate, then admits its thread
    /// owner. Every callback phase has already ended before this transition.
    ///
    /// # Safety
    /// `ready` derives from this keeper's exact preparation. The caller retains
    /// the original child admission and excludes competing image/list mutation.
    pub(crate) unsafe fn complete_source(
        mut self, ready: crate::types::ReadyTheapInitialization,
    ) -> Result<ChildThreadOwner, ChildThreadStartFailure> {
        // SAFETY: this keeper is the original allocated owner and its
        // caller retains the exact child admission through publication.
        match unsafe { complete_child_thread_source(&mut self.0, ready) } {
            Ok(()) => Ok(self.0),
            Err(error) => Err(ChildThreadStartFailure::Retained { owner: self.0, error }),
        }
    }
}

#[cfg(target_arch = "x86_64")]
fn child_dynamic_init_error(error: crate::types::TheapMainStaticInitError) -> crate::types::TheapDynamicInitError {
    use crate::types::{TheapDynamicInitError as Dynamic, TheapMainStaticInitError as Static};
    match error {
        Static::InvalidInput => Dynamic::InvalidInput,
        Static::ThreadList(error) => Dynamic::ThreadList(error),
        Static::HeapList(error) => Dynamic::HeapList(error),
    }
}

/// A checked existing child Theap or the exact new candidate awaiting
/// source getters. Existing cache/slot selection creates no initializer.
#[cfg(target_arch = "x86_64")]
pub(crate) enum ChildHeapTheapSelection {
    Existing(NonNull<Theap>),
    Pending(PendingChildHeapTheapInitialization),
    Retained(ChildHeapTheapInitializationFailure),
}

/// The original child metadata or requested-arena allocation, together with
/// its prepared phase. Neither field borrows a member or child projection.
#[cfg(target_arch = "x86_64")]
#[must_use]
pub(crate) struct PendingChildHeapTheapInitialization {
    keeper: ChildHeapTheapInitializationOwner,
    phase: crate::types::PreparedTheapInitialization,
}

#[cfg(target_arch = "x86_64")]
impl PendingChildHeapTheapInitialization {
    pub(crate) fn into_phase(self) -> (ChildHeapTheapInitializationOwner, crate::types::PreparedTheapInitialization) {
        (self.keeper, self.phase)
    }
}

/// Exact candidate storage and source selection carried through callback
/// windows. The enclosing real admission retains the child, Heap and TLD.
/// Dropping this keeper deliberately leaves its original storage retained.
#[cfg(target_arch = "x86_64")]
#[must_use]
pub(crate) struct ChildHeapTheapInitializationOwner {
    block: ChildMetadataImageBlock,
    heap: NonNull<Heap>,
    tld: NonNull<ThreadLocalData>,
    image: NonNull<crate::subproc::ChildSubprocessImage>,
    key: crate::thread_local::ThreadLocalKey,
}

#[cfg(target_arch = "x86_64")]
impl ChildHeapTheapInitializationOwner {
    pub(crate) fn retain(self, error: crate::types::TheapMainStaticInitError) -> ChildHeapTheapInitializationFailure {
        ChildHeapTheapInitializationFailure { keeper: self,
            error: ChildHeapTheapError::TheapInitialization(child_dynamic_init_error(error)) }
    }

    pub(crate) fn retain_refusal(self) -> ChildHeapTheapInitializationFailure {
        ChildHeapTheapInitializationFailure { keeper: self, error: ChildHeapTheapError::InvalidTransition }
    }
}

/// A refused phase carrying the original allocated candidate. Its caller
/// retains the actual child admission rather than inferring lifetime from
/// this ticket's addresses or forgetting a partially linked source image.
#[cfg(target_arch = "x86_64")]
#[must_use]
pub(crate) struct ChildHeapTheapInitializationFailure {
    pub(crate) keeper: ChildHeapTheapInitializationOwner,
    pub(crate) error: ChildHeapTheapError,
}

/// Why a child thread's Theap for a non-main Heap could not be found,
/// created, or used.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ChildHeapTheapError {
    /// The thread owner, Heap, or Theap is not in a usable state.
    InvalidTransition,
    /// The child metadata page engine could not run.
    PageEngine(ChildMetadataPageEngineError),
    /// The thread-local slot array could not grow (`mi_thread_locals_expand`).
    ThreadLocals,
    /// `_mi_theap_alloc` returned null.
    TheapAllocation,
    /// `_mi_theap_init` failed; an image with a published list edge is retained.
    TheapInitialization(crate::types::TheapDynamicInitError),
    /// A metadata image could not be freed.
    Metadata(FreeError),
}

/// Transfers an initialized requested-parent image to its stored memory ID,
/// or returns its exact slice while no intrusive list can name the image.
///
/// # Safety
/// The claimed span contains an initialized `ChildHeapTheapImage`; a successful
/// initializer stored the claim's exact memory identity in its Theap.
unsafe fn finish_child_requested_theap_claim(
    claim: crate::arena::ArenaSliceClaim<'_>,
    initialized: Result<(), crate::types::TheapDynamicInitError>,
) -> Result<NonNull<Theap>, ChildHeapTheapError> {
    let block = NonNull::new(claim.start()).expect("a claimed arena slice has a start");
    match initialized {
        Ok(()) => {
            // The initialized Theap now owns this exact arena span through
            // its stored source memory identity.
            core::mem::forget(claim);
            Ok(block.cast())
        }
        Err(error @ (crate::types::TheapDynamicInitError::InvalidInput
            | crate::types::TheapDynamicInitError::ThreadList(
                crate::types::ThreadLocalTheapListError::Busy))) => {
            // Neither failure published a list edge. Return the exact claim
            // before its image can escape.
            unsafe { core::ptr::drop_in_place(block.cast::<ChildHeapTheapImage>().as_ptr()) };
            if claim.release() {
                Err(ChildHeapTheapError::TheapInitialization(error))
            } else {
                Err(ChildHeapTheapError::InvalidTransition)
            }
        }
        Err(error) => {
            // A list edge may already name this image; retain its arena span
            // until the child owner is destroyed.
            core::mem::forget(claim);
            Err(ChildHeapTheapError::TheapInitialization(error))
        }
    }
}

/// The regular thread-local key a Heap's Theaps use (`heap->theap`).
fn heap_theap_key(heap: NonNull<Heap>) -> Option<crate::thread_local::ThreadLocalKey> {
    // SAFETY: the caller's live Heap; an immutable field.
    let raw = unsafe { heap.as_ref() }.regular_theap_slot() as u64;
    let index = crate::thread_local::ThreadLocalSlotIndex::new((raw & crate::thread_local::TLS_INDEX_MASK) as usize)?;
    crate::thread_local::ThreadLocalKey::from_parts(index, raw >> crate::thread_local::TLS_INDEX_BITS)
}

/// Reads a child-domain regular slot from the calling thread's installed
/// source backing. Missing storage or a generation mismatch returns null.
///
/// # Safety
/// The calling thread retains the actual installed child slot backing, its
/// complete source flexible allocation and its allocation owner. No slot
/// replacement, mutation or teardown
/// overlaps this short query; no reference survives it. The root alone does
/// not grant backing lifetime or authority to follow a returned Theap.
#[cfg(all(target_arch = "x86_64", feature = "mi-debug-3"))]
pub(crate) unsafe fn source_regular_slot_peek(key: crate::thread_local::ThreadLocalKey) -> *mut () {
    let Some(mut backing) = crate::compiler_tls::dynamic_backing_peek() else {
        return core::ptr::null_mut();
    };
    // The count-zero root is immutable process storage, so reject it by
    // identity before creating any mutable dynamic-image projection.
    if crate::compiler_tls::is_empty_dynamic_backing(backing) {
        return core::ptr::null_mut();
    }
    // SAFETY: the retained calling-thread owner excludes all slot writers;
    // this temporary projection ends before any callback or allocator entry.
    let slots = crate::thread_local::ThreadLocalSlots::new(unsafe { backing.as_mut().slots_mut() });
    slots.get(key)
}

impl ChildThreadOwner {
    #[inline]
    fn tld_pointer(&self) -> Option<NonNull<ThreadLocalData>> {
        self.tld.as_ref().map(|block| block.pointer.cast())
    }

    /// Retained terminal arrays carry release custody, never active slot
    /// projection authority. This check precedes every safe regular-slot read.
    #[cfg(target_arch = "x86_64")]
    fn active_thread_local_backing(
        storage: &Option<ChildMetadataImageBlock>,
        state: ChildThreadOwnerState,
    ) -> Option<&ChildMetadataImageBlock> {
        (state == ChildThreadOwnerState::Attached).then(|| storage.as_ref()).flatten()
    }

    /// `_mi_thread_local_get` for a regular key (`threadlocal.c:169-190`).
    fn thread_local_get(&self, key: crate::thread_local::ThreadLocalKey) -> *mut () {
        #[cfg(target_arch = "x86_64")]
        let block = Self::active_thread_local_backing(&self.thread_locals, self.state);
        #[cfg(not(target_arch = "x86_64"))]
        let block = self.thread_locals.as_ref();
        let Some(block) = block else { return core::ptr::null_mut() };
        // SAFETY: this owner retains the exact slot image it installed, and
        // only this thread uses it.
        let slots = unsafe { (*block.pointer.cast::<DynamicThreadLocalBacking>().as_ptr()).slots_mut() };
        crate::thread_local::ThreadLocalSlots::new(slots).get(key)
    }

    /// A failed slot operation retains allocation custody and withdraws the
    /// regular, fast and cached compiler-TLS roots. Terminal state refuses
    /// engine projection; the TLD's owned cached reference stays retained.
    #[cfg(target_arch = "x86_64")]
    fn poison_thread_local_owner(state: &mut ChildThreadOwnerState) {
        *state = ChildThreadOwnerState::Terminal;
        crate::compiler_tls::clear_dynamic_backing();
        crate::compiler_tls::set_fast_slot(None);
        crate::compiler_tls::set_cached_theap(NonNull::from(crate::bootstrap::empty_default_theap()));
    }

    /// Settle client ownership inside the free closure, before engine finish
    /// can fail. Consumed storage is never an initialized live array again.
    /// Refusal retains its exact allocation only under terminal owner custody.
    #[cfg(target_arch = "x86_64")]
    fn observe_thread_local_release(
        storage: &mut Option<ChildMetadataImageBlock>,
        state: &mut ChildThreadOwnerState,
        progress: crate::single_thread::LocalClientFreeProgress,
        thread_done: bool,
    ) {
        use crate::single_thread::LocalClientFreeProgress as Progress;
        if matches!(progress, Progress::Consumed(_)) {
            *storage = None;
            crate::compiler_tls::clear_dynamic_backing();
            if thread_done { crate::compiler_tls::set_fast_slot(None); }
        }
        if !matches!(progress, Progress::Consumed(Ok(()))) {
            Self::poison_thread_local_owner(state);
        }
    }

    /// Publication waits for successful source release and engine finish.
    /// Failure retains the unpublished copied replacement; the old token is
    /// retained only when its precise release never consumed it.
    #[cfg(target_arch = "x86_64")]
    fn complete_thread_local_growth(
        storage: &mut Option<ChildMetadataImageBlock>,
        pending: &mut Option<ChildMetadataImageBlock>,
        state: &mut ChildThreadOwnerState,
        replacement: Option<ChildMetadataImageBlock>,
        progress: Option<crate::single_thread::LocalClientFreeProgress>,
        finished: Result<(), ChildMetadataPageEngineError>,
    ) -> Result<(), ChildHeapTheapError> {
        use crate::single_thread::LocalClientFreeProgress as Progress;
        if let Some(progress) = progress {
            Self::observe_thread_local_release(storage, state, progress, false);
        }
        let result = match finished {
            Err(error) => Err(ChildHeapTheapError::PageEngine(error)),
            Ok(()) => match progress {
                Some(Progress::RefusedBeforeConsumption(error) | Progress::Consumed(Err(error))) => {
                    Err(ChildHeapTheapError::Metadata(error))
                }
                _ => Ok(()),
            },
        };
        if let Err(error) = result {
            debug_assert!(pending.is_none());
            *pending = replacement;
            Self::poison_thread_local_owner(state);
            return Err(error);
        }
        let Some(block) = replacement else {
            if progress.is_some() { Self::poison_thread_local_owner(state); }
            return Err(ChildHeapTheapError::ThreadLocals);
        };
        crate::compiler_tls::install_dynamic_backing(block.pointer.cast());
        *storage = Some(block);
        Ok(())
    }

    /// Source thread-done removes regular and fast roots when consumption is
    /// observed, even when subsequent local lifecycle or finish reports fail.
    #[cfg(target_arch = "x86_64")]
    fn complete_thread_local_release(
        storage: &mut Option<ChildMetadataImageBlock>,
        state: &mut ChildThreadOwnerState,
        progress: Option<crate::single_thread::LocalClientFreeProgress>,
        finished: Result<(), ChildMetadataPageEngineError>,
    ) -> Result<(), ChildHeapTheapError> {
        use crate::single_thread::LocalClientFreeProgress as Progress;
        if let Some(progress) = progress {
            Self::observe_thread_local_release(storage, state, progress, true);
        }
        let result = match finished {
            Err(error) => Err(ChildHeapTheapError::PageEngine(error)),
            Ok(()) => match progress {
                Some(Progress::Consumed(Ok(()))) => Ok(()),
                Some(Progress::RefusedBeforeConsumption(error) | Progress::Consumed(Err(error))) => {
                    Err(ChildHeapTheapError::Metadata(error))
                }
                None => Err(ChildHeapTheapError::InvalidTransition),
            },
        };
        if result.is_err() { Self::poison_thread_local_owner(state); }
        result
    }

    /// Source regular-slot growth: zero a fresh metadata image, copy the old
    /// slots, free the old array, then publish the new count and backing.
    ///
    /// # Safety
    /// This runs exclusively on this owner's attached thread; `child` is its
    /// context and retains the source detached metadata engine and backing.
    #[cfg(target_arch = "x86_64")]
    unsafe fn thread_local_set(
        &mut self,
        child: &mut ChildMainHeapContextOwner<'_>,
        binding: crate::process_init::ProcessMainBackingBinding,
        key: crate::thread_local::ThreadLocalKey,
        value: *mut (),
    ) -> Result<(), ChildHeapTheapError> {
        if self.state != ChildThreadOwnerState::Attached || self.pending_thread_locals.is_some() {
            return Err(ChildHeapTheapError::InvalidTransition);
        }
        let count = self.thread_locals.as_ref().map_or(0, |block| {
            // SAFETY: this thread retains the initialized slot image.
            unsafe { (*block.pointer.cast::<DynamicThreadLocalBacking>().as_ptr()).count() }
        });
        let index = key.index().get();
        if index >= count {
            if value.is_null() { return Ok(()); }
            let new_count = crate::thread_local::expanded_slot_count(count, index)
                .map_err(|_| ChildHeapTheapError::ThreadLocals)?;
            let size = DynamicThreadLocalBacking::allocation_size(new_count)
                .ok_or(ChildHeapTheapError::ThreadLocals)?;
            let old = self.thread_locals.as_ref().map(|block| block.pointer);
            let mut grown = None;
            let mut progress = None;
            let finished = child.with_metadata_page_engine(binding, |_child, engine| {
                let Some(block) = engine.allocate_zeroed(size) else { return };
                let image = block.cast::<DynamicThreadLocalBacking>().as_ptr();
                // SAFETY: fresh zeroed flexible storage and the exact live
                // old array contain `count` initialized slots until release.
                unsafe {
                    (*image).initialize_owned_header(MemoryId::malloc(block.as_ptr(), size, true), new_count);
                    if let Some(old) = old {
                        core::ptr::copy_nonoverlapping(
                            (*old.cast::<DynamicThreadLocalBacking>().as_ptr()).slots_mut().as_ptr(),
                            (*image).slots_mut().as_mut_ptr(), count,
                        );
                    }
                }
                grown = Some(ChildMetadataImageBlock { pointer: block, size });
                if let Some(old) = old {
                    // SAFETY: the exact old array is no longer projected.
                    let observed = unsafe { engine.free_with_progress(old) };
                    Self::observe_thread_local_release(&mut self.thread_locals, &mut self.state, observed, false);
                    progress = Some(observed);
                }
            });
            Self::complete_thread_local_growth(&mut self.thread_locals, &mut self.pending_thread_locals,
                &mut self.state, grown, progress, finished)?;
        }
        let block = self.thread_locals.as_ref().ok_or(ChildHeapTheapError::ThreadLocals)?;
        // SAFETY: the retained newly sized array is owned by this thread.
        let slots = unsafe { (*block.pointer.cast::<DynamicThreadLocalBacking>().as_ptr()).slots_mut() };
        crate::thread_local::ThreadLocalSlots::new(slots).set(key, value)
            .map_err(|_| ChildHeapTheapError::ThreadLocals)
    }

    /// Frees regular dynamic storage before source thread-done clears the
    /// independent fast slot. Consumption and engine completion are observed
    /// separately so completion cannot revive a consumed array.
    ///
    /// # Safety
    /// This is the attached owner's finishing thread and exact context. No
    /// slot image, value or compiler-TLS projection spans the source free.
    #[cfg(target_arch = "x86_64")]
    unsafe fn free_thread_locals(
        &mut self,
        child: &mut ChildMainHeapContextOwner<'_>,
        binding: crate::process_init::ProcessMainBackingBinding,
    ) -> Result<(), ChildHeapTheapError> {
        if self.state != ChildThreadOwnerState::Attached || self.pending_thread_locals.is_some() {
            return Err(ChildHeapTheapError::InvalidTransition);
        }
        let Some(block) = self.thread_locals.as_ref().map(|block| block.pointer) else {
            crate::compiler_tls::set_fast_slot(None);
            return Ok(());
        };
        let mut progress = None;
        let finished = child.with_metadata_page_engine(binding, |_child, engine| {
            // SAFETY: this exact live array has no remaining slot users.
            let observed = unsafe { engine.free_with_progress(block) };
            Self::observe_thread_local_release(&mut self.thread_locals, &mut self.state, observed, true);
            progress = Some(observed);
        });
        Self::complete_thread_local_release(&mut self.thread_locals, &mut self.state, progress, finished)
    }

    /// Historical non-x86 slot growth with unclassified release errors.
    /// `_mi_thread_local_set` for a regular key (`threadlocal.c:103-166`):
    /// a slot beyond the array grows it (`mi_thread_locals_expand`, 16 slots
    /// first, then doubling) with a fresh zeroed child metadata block, the
    /// old slots copied and the old block freed, as `_mi_meta_rezalloc`.
    ///
    /// # Safety
    /// This runs on this owner's thread; `child` is its context.
    #[cfg(not(target_arch = "x86_64"))]
    unsafe fn thread_local_set(
        &mut self,
        child: &mut ChildMainHeapContextOwner<'_>,
        binding: crate::process_init::ProcessMainBackingBinding,
        key: crate::thread_local::ThreadLocalKey,
        value: *mut (),
    ) -> Result<(), ChildHeapTheapError> {
        let count = self.thread_locals.as_ref().map_or(0, |block| {
            // SAFETY: the retained slot image.
            unsafe { (*block.pointer.cast::<DynamicThreadLocalBacking>().as_ptr()).count() }
        });
        let index = key.index().get();
        if index >= count {
            if value.is_null() {
                return Ok(());
            }
            let new_count = crate::thread_local::expanded_slot_count(count, index)
                .map_err(|_| ChildHeapTheapError::ThreadLocals)?;
            let size = DynamicThreadLocalBacking::allocation_size(new_count)
                .ok_or(ChildHeapTheapError::ThreadLocals)?;
            let old = self.thread_locals.as_ref().map(|block| block.pointer);
            let mut grown = None;
            child
                .with_metadata_page_engine(binding, |_child, engine| {
                    let Some(block) = engine.allocate_zeroed(size) else { return };
                    let image = block.cast::<DynamicThreadLocalBacking>().as_ptr();
                    // SAFETY: a fresh zeroed block of the exact flexible size;
                    // the old image, if any, holds `count` initialized slots.
                    unsafe {
                        (*image).initialize_owned_header(MemoryId::malloc(block.as_ptr(), size, true), new_count);
                        if let Some(old) = old {
                            let from = (*old.cast::<DynamicThreadLocalBacking>().as_ptr()).slots_mut().as_ptr();
                            let to = (*image).slots_mut().as_mut_ptr();
                            core::ptr::copy_nonoverlapping(from, to, count);
                        }
                    }
                    grown = Some(block);
                    if let Some(old) = old {
                        // SAFETY: the exact old slot image, no longer used.
                        if unsafe { engine.free(old) }.is_err() {
                            grown = None;
                        }
                    }
                })
                .map_err(ChildHeapTheapError::PageEngine)?;
            let block = grown.ok_or(ChildHeapTheapError::ThreadLocals)?;
            crate::compiler_tls::install_dynamic_backing(block.cast());
            self.thread_locals = Some(ChildMetadataImageBlock { pointer: block, size });
        }
        let block = self.thread_locals.as_ref().ok_or(ChildHeapTheapError::ThreadLocals)?;
        // SAFETY: the retained slot image, now large enough.
        let slots = unsafe { (*block.pointer.cast::<DynamicThreadLocalBacking>().as_ptr()).slots_mut() };
        crate::thread_local::ThreadLocalSlots::new(slots)
            .set(key, value)
            .map_err(|_| ChildHeapTheapError::ThreadLocals)
    }

    /// Historical non-x86 slot release with unclassified errors.
    /// `_mi_thread_locals_thread_done` (`threadlocal.c:192-202`): free the
    /// slot array and clear the compiler-TLS root.
    ///
    /// # Safety
    /// As for [`Self::thread_local_set`]; no slot is used again.
    #[cfg(not(target_arch = "x86_64"))]
    unsafe fn free_thread_locals(
        &mut self,
        child: &mut ChildMainHeapContextOwner<'_>,
        binding: crate::process_init::ProcessMainBackingBinding,
    ) -> Result<(), ChildHeapTheapError> {
        let Some(block) = self.thread_locals.as_ref().map(|block| block.pointer) else {
            // Source clears the independent fast slot even when the regular
            // slot array never materialized, before any Theap page traversal.
            crate::compiler_tls::set_fast_slot(None);
            return Ok(());
        };
        let mut freed = None;
        child
            .with_metadata_page_engine(binding, |_child, engine| {
                // SAFETY: the exact slot image this owner installed.
                freed = Some(unsafe { engine.free(block) });
            })
            .map_err(ChildHeapTheapError::PageEngine)?;
        match freed {
            Some(Ok(())) => {
                crate::compiler_tls::clear_dynamic_backing();
                self.thread_locals = None;
                crate::compiler_tls::set_fast_slot(None);
                Ok(())
            }
            Some(Err(error)) => Err(ChildHeapTheapError::Metadata(error)),
            None => Err(ChildHeapTheapError::InvalidTransition),
        }
    }

    /// `_mi_theap_cached_set` (`prim-tls.c:211-229`): the cached Theap takes
    /// a reference to `theap` and drops the one it held, freeing a Theap
    /// whose last reference that was.
    ///
    /// # Safety
    /// This runs on this owner's thread; `theap` is a live Theap of this
    /// thread or the empty Theap; `child` is its context.
    pub(crate) unsafe fn cached_set(
        &mut self,
        child: &mut ChildMainHeapContextOwner<'_>,
        binding: crate::process_init::ProcessMainBackingBinding,
        theap: NonNull<Theap>,
    ) -> Result<(), ChildHeapTheapError> {
        let previous = crate::compiler_tls::cached_theap();
        if previous == theap {
            return Ok(());
        }
        crate::compiler_tls::set_cached_theap(theap);
        // SAFETY: forwarded liveness of both Theaps.
        unsafe {
            Theap::incref_at(theap);
            self.theap_decref(child, binding, previous)
        }
    }

    /// `_mi_theap_decref` with `mi_theap_free_mem` (`theap.c:347-370`).
    ///
    /// # Safety
    /// `theap` is a live Theap holding the reference being dropped; a Theap
    /// freed here is on no list and no root names it.
    pub(crate) unsafe fn theap_decref(
        &mut self,
        child: &mut ChildMainHeapContextOwner<'_>,
        binding: crate::process_init::ProcessMainBackingBinding,
        theap: NonNull<Theap>,
    ) -> Result<(), ChildHeapTheapError> {
        // The task slot retains the original issuing allocation, including
        // the reference that this path would otherwise consume. Refuse before
        // decrementing: a scalar task identity cannot replace that custody
        // after the image has reached its final-reference release boundary.
        if self.pending_live_page_validity.as_ref().is_some_and(|task| task.matches_theap(theap))
            || self.heap_theap_pending_live_page_validity.as_ref().is_some_and(|(issuer, _)| *issuer == theap)
            || self.pending_fresh_initialization.as_ref().is_some_and(|task| task.matches_theap(theap))
            || self.heap_theap_pending_fresh_initialization.as_ref()
                .is_some_and(|(issuer, _)| *issuer == theap)
        {
            return Err(ChildHeapTheapError::InvalidTransition);
        }
        // SAFETY: forwarded.
        if !unsafe { Theap::decref_at(theap) } {
            return Ok(());
        }
        if let Some((named @ Some(_), _)) = self.heap_theap_pending_os_release.as_mut() {
            if *named == Some(theap) {
                *named = None;
            }
        }
        // SAFETY: as above; the flag is immutable.
        if !unsafe { Theap::is_detached_at(theap) } {
            child.context.with_image(|image| image.identity().record_statistics_theap_unlinked());
        }
        // SAFETY: the final reference made the initialized Theap exclusive.
        let memory = unsafe { theap.as_ref() }.memory_id();
        if memory.arena_memory().is_some() {
            // SAFETY: all Theap users are gone; destroy its Rust fields before
            // its source `memid` returns the exact arena slice to this child.
            unsafe { core::ptr::drop_in_place(theap.as_ptr()) };
            let released = child.with_child_image(|image| {
                // SAFETY: the selected slice belongs to this child, remains
                // published, and no Theap or page still uses the span.
                unsafe { image.identity().arena_backing().release_slices(memory) }
            });
            return if released == Some(true) { Ok(()) } else { Err(ChildHeapTheapError::InvalidTransition) };
        }
        let mut freed = None;
        child
            .with_metadata_page_engine(binding, |_child, engine| {
                // SAFETY: the exact child metadata image of this Theap.
                freed = Some(unsafe { engine.free(theap.cast()) });
            })
            .map_err(ChildHeapTheapError::PageEngine)?;
        match freed {
            Some(Ok(())) => Ok(()),
            Some(Err(error)) => Err(ChildHeapTheapError::Metadata(error)),
            None => Err(ChildHeapTheapError::InvalidTransition),
        }
    }

    /// Pinned `_mi_heap_theap` (`prim-tls.h:389-397`) for a non-main Heap of
    /// this thread's child: the cached Theap if it belongs to `heap`,
    /// otherwise `_mi_heap_theap_get_or_init` (`heap.c:59-99`): the Theap on
    /// the Heap's thread-local slot, or a fresh one from `_mi_theap_create`
    /// (child metadata, `_mi_theap_init` at the head of this TLD's list and
    /// of the Heap's, counted in `theaps`) stored on that slot; then it
    /// becomes the cached Theap.
    ///
    /// # Safety
    /// This runs on this owner's thread, `heap` is a live non-main Heap of
    /// `child`, and no other operation on `child` runs.
    pub(crate) unsafe fn heap_theap(
        &mut self,
        child: &mut ChildMainHeapContextOwner<'_>,
        binding: crate::process_init::ProcessMainBackingBinding,
        heap: NonNull<Heap>,
    ) -> Result<NonNull<Theap>, ChildHeapTheapError> {
        let cached = crate::compiler_tls::cached_theap();
        // SAFETY: the cached root names a live Theap or the empty Theap.
        if unsafe { Theap::heap_at(cached) } == heap.as_ptr() {
            return Ok(cached);
        }
        let key = heap_theap_key(heap).ok_or(ChildHeapTheapError::InvalidTransition)?;
        let theap = match NonNull::new(self.thread_local_get(key).cast::<Theap>()) {
            Some(theap) => theap,
            None => {
                // SAFETY: forwarded.
                let theap = unsafe { self.create_heap_theap(child, binding, heap) }?;
                // SAFETY: forwarded; `_mi_heap_theap_set`.
                unsafe { self.thread_local_set(child, binding, key, theap.as_ptr().cast()) }?;
                theap
            }
        };
        // SAFETY: forwarded; `theap` is this thread's live Theap for `heap`.
        unsafe { self.cached_set(child, binding, theap) }?;
        Ok(theap)
    }

    /// Ends ordinary allocation after an initializer retains a partial
    /// image on this member's actual TLD. The caller must keep the original
    /// admission and failure keeper; this changes state, not lifetime custody.
    #[cfg(target_arch = "x86_64")]
    pub(crate) fn retain_heap_theap_initialization_failure(
        &mut self, failure: &ChildHeapTheapInitializationFailure,
    ) -> bool {
        if self.image != failure.keeper.image || self.tld_pointer() != Some(failure.keeper.tld) {
            return false;
        }
        self.state = ChildThreadOwnerState::Terminal;
        self.page_engine = ChildPageEngineState::Poisoned;
        true
    }

    /// Selects an existing source member or allocates the exact incoming
    /// Theap without publishing it. Callback stages consume the returned
    /// owned ticket after all child/member/metadata projections have ended.
    ///
    /// # Safety
    /// This is the current thread's actual member, and `heap` belongs to its
    /// retained child. The caller retains both and the TLD across all phases;
    /// each image/list transition excludes overlapping projections, while
    /// callbacks may perform independently admitted source operations.
    #[cfg(target_arch = "x86_64")]
    pub(crate) unsafe fn prepare_heap_theap_selection(
        &mut self, child: &mut ChildMainHeapContextOwner<'_>,
        binding: crate::process_init::ProcessMainBackingBinding, heap: NonNull<Heap>,
    ) -> Result<ChildHeapTheapSelection, ChildHeapTheapError> {
        if self.state != ChildThreadOwnerState::Attached || !self.belongs_to(child) {
            return Err(ChildHeapTheapError::InvalidTransition);
        }
        let cached = crate::compiler_tls::cached_theap();
        // SAFETY: this actual member retains every cached source reference.
        if unsafe { Theap::heap_at(cached) } == heap.as_ptr() {
            return Ok(ChildHeapTheapSelection::Existing(cached));
        }
        let key = heap_theap_key(heap).ok_or(ChildHeapTheapError::InvalidTransition)?;
        if let Some(theap) = NonNull::new(self.thread_local_get(key).cast::<Theap>()) {
            // SAFETY: the checked slot and existing cache are this member's
            // retained live Theaps, and no callback crosses the transition.
            unsafe { self.cached_set(child, binding, theap) }?;
            return Ok(ChildHeapTheapSelection::Existing(theap));
        }
        let tld = self.tld_pointer().ok_or(ChildHeapTheapError::InvalidTransition)?;
        // SAFETY: this member and child retain the incoming block's allocator
        // and requested arena; its source memory identity remains stored.
        let (block, refusal) = unsafe { self.allocate_heap_theap_candidate(child, binding, heap, tld) }?;
        let keeper = ChildHeapTheapInitializationOwner {
            block: ChildMetadataImageBlock { pointer: block.cast(), size: size_of::<ChildHeapTheapImage>() },
            heap, tld, image: self.image, key,
        };
        if let Some(error) = refusal {
            return Ok(ChildHeapTheapSelection::Retained(ChildHeapTheapInitializationFailure { keeper, error }));
        }
        // SAFETY: the actual allocated block remains in this keeper, and the
        // caller retains the original child, Heap and member's TLD admission.
        let phase = unsafe { Theap::prepare_initialization_at(block, heap, tld,
            crate::types::TheapInitializationKind::Dynamic {
                page_mode: crate::types::TheapPageMode::OrdinaryAbandoning,
                tld_may_have_theaps: true,
            }) };
        match phase {
            Ok(phase) => Ok(ChildHeapTheapSelection::Pending(PendingChildHeapTheapInitialization { keeper, phase })),
            Err(error) => Ok(ChildHeapTheapSelection::Retained(keeper.retain(error))),
        }
    }

    /// Publishes this exact candidate and only then installs its source TLS
    /// slot/cache. A failed phase returns the allocated keeper terminally.
    ///
    /// # Safety
    /// `ready` derives from `keeper`'s exact preparation. The caller retains
    /// the original member/child/Heap admission across every callback and
    /// excludes competing lifecycle operations through this final transition.
    #[cfg(target_arch = "x86_64")]
    pub(crate) unsafe fn complete_heap_theap_initialization(
        &mut self, child: &mut ChildMainHeapContextOwner<'_>,
        binding: crate::process_init::ProcessMainBackingBinding,
        keeper: ChildHeapTheapInitializationOwner, ready: crate::types::ReadyTheapInitialization,
    ) -> Result<NonNull<Theap>, ChildHeapTheapInitializationFailure> {
        if self.state != ChildThreadOwnerState::Attached || !self.belongs_to(child)
            || self.image != keeper.image || self.tld_pointer() != Some(keeper.tld)
            || heap_theap_key(keeper.heap) != Some(keeper.key) {
            return Err(keeper.retain_refusal());
        }
        if child.context.with_image(|image| image.identity().record_statistics_theap_linked()).is_none() {
            return Err(keeper.retain_refusal());
        }
        // SAFETY: the original allocated block and actual admission retain
        // these exact lists through source accounting and publication.
        if let Err(error) = unsafe { ready.publish_heap() } { return Err(keeper.retain(error)); }
        let theap = keeper.block.pointer.cast::<Theap>();
        // SAFETY: the exact incoming source image is now initialized; the
        // checked member owns both its slot table and cached references.
        let installed = unsafe { self.thread_local_set(child, binding, keeper.key, theap.as_ptr().cast()) }
            .and_then(|()| unsafe { self.cached_set(child, binding, theap) });
        match installed {
            Ok(()) => Ok(theap),
            Err(error) => Err(ChildHeapTheapInitializationFailure { keeper, error }),
        }
    }

    /// Allocates the child source image and records exact concrete memory
    /// provenance before any list can name it. A partial candidate is retained.
    ///
    /// # Safety
    /// The caller owns this member's allocation operation and retains its
    /// child, Heap, TLD and any requested parent arena through initialization.
    #[cfg(target_arch = "x86_64")]
    unsafe fn allocate_heap_theap_candidate(
        &mut self, child: &mut ChildMainHeapContextOwner<'_>,
        binding: crate::process_init::ProcessMainBackingBinding,
        heap: NonNull<Heap>, tld: NonNull<ThreadLocalData>,
    ) -> Result<(NonNull<Theap>, Option<ChildHeapTheapError>), ChildHeapTheapError> {
        let size = size_of::<ChildHeapTheapImage>();
        // SAFETY: the retained Heap's arena identity is immutable.
        let requested = unsafe { heap.as_ref() }.exclusive_arena_id()
            .ok_or(ChildHeapTheapError::InvalidTransition)?;
        let prefix = |block: NonNull<u8>, memory: MemoryId| {
            let image = block.cast::<ChildHeapTheapImage>().as_ptr();
            // SAFETY: this exact fresh zeroed allocation is exclusively
            // owned. Both Rust fields precede any source list publication.
            unsafe {
                Theap::write_empty_at(NonNull::new_unchecked(core::ptr::addr_of_mut!((*image).theap)));
                core::ptr::addr_of_mut!((*image).page_engine).write(ChildPageEngineState::Active);
                let incoming = &mut (*image).theap;
                if requested.as_ptr().is_null() {
                    incoming.set_dynamic_metadata_memid(memory)
                } else {
                    incoming.set_requested_arena_metadata_memid(memory)
                }
            }
        };
        if requested.as_ptr().is_null() {
            let mut allocated = None;
            let page_result = child.with_metadata_page_engine(binding, |_child, engine| {
                allocated = engine.allocate_zeroed(size);
            });
            let Some(block) = allocated else {
                return Err(page_result.err().map(ChildHeapTheapError::PageEngine)
                    .unwrap_or(ChildHeapTheapError::TheapAllocation));
            };
            let provenance = prefix(block, MemoryId::malloc(block.as_ptr(), size, true));
            // A session can refuse completion after issuing its exact block.
            // Keep that block visible to the terminal keeper on every refusal.
            let refusal = page_result.err().map(ChildHeapTheapError::PageEngine)
                .or_else(|| (!provenance).then_some(ChildHeapTheapError::InvalidTransition));
            Ok((block.cast(), refusal))
        } else {
            let config = binding.page_map().memory_config().map_err(|_| ChildHeapTheapError::InvalidTransition)?;
            child.with_child_image(|image| {
                let process = crate::os::ChildVmProcess::new(binding.process(), image)
                    .map_err(|_| ChildHeapTheapError::InvalidTransition)?;
                let search = crate::arena::ArenaSearch {
                    heap_sequence: 0, heap_count: 1, thread_sequence: self.sequence.get(),
                    numa_node: unsafe { tld.as_ref() }.numa_node(), requested, allow_pinned: true,
                };
                // SAFETY: this real child process and requested arena remain
                // retained while the exact source minimum object is claimed.
                let claim = unsafe { image.identity().arena_backing().try_allocate_requested_arena_object(
                    process.process(), config, search, size.next_multiple_of(crate::config::ARENA_MIN_OBJ_SIZE),
                    crate::config::ARENA_SLICE_SIZE, 0, true,
                ) }.map_err(|_| ChildHeapTheapError::TheapAllocation)?;
                let block = NonNull::new(claim.start()).expect("a claimed arena slice has a start");
                if !prefix(block, claim.memory_id()) {
                    // No source phase or list operation has begun, so this
                    // exact claim can be returned after clearing its Rust image.
                    unsafe { core::ptr::drop_in_place(block.cast::<ChildHeapTheapImage>().as_ptr()); }
                    return if claim.release() { Err(ChildHeapTheapError::InvalidTransition) }
                        else { Err(ChildHeapTheapError::TheapAllocation) };
                }
                // The exact memory ID now owns this claimed span through the
                // pending source image. Refused later phases must retain it.
                core::mem::forget(claim);
                Ok((block.cast(), None))
            }).ok_or(ChildHeapTheapError::InvalidTransition)?
        }
    }

    /// `_mi_theap_create(heap, tld)` (`theap.c:307-341`) as a
    /// [`ChildHeapTheapImage`] from child metadata or the Heap's selected
    /// parent arena.
    ///
    /// # Safety
    /// As for [`Self::heap_theap`].
    unsafe fn create_heap_theap(
        &mut self,
        child: &mut ChildMainHeapContextOwner<'_>,
        binding: crate::process_init::ProcessMainBackingBinding,
        heap: NonNull<Heap>,
    ) -> Result<NonNull<Theap>, ChildHeapTheapError> {
        if self.state != ChildThreadOwnerState::Attached {
            return Err(ChildHeapTheapError::InvalidTransition);
        }
        let tld = self.tld_pointer().ok_or(ChildHeapTheapError::InvalidTransition)?;
        let size = size_of::<ChildHeapTheapImage>();
        // SAFETY: the live Heap fixes its requested parent for its lifetime.
        let requested = unsafe { heap.as_ref() }.exclusive_arena_id()
            .ok_or(ChildHeapTheapError::InvalidTransition)?;
        let initialize = |block: NonNull<u8>, memory: MemoryId| {
            let image = block.cast::<ChildHeapTheapImage>().as_ptr();
            // SAFETY: a fresh, exclusively owned, zeroed image; the Rust state
            // fields are written whole before the Theap is published. The TLD
            // is this thread's and the Heap's lists take their own locks.
            unsafe {
                Theap::write_empty_at(NonNull::new_unchecked(core::ptr::addr_of_mut!((*image).theap)));
                core::ptr::addr_of_mut!((*image).page_engine).write(ChildPageEngineState::Active);
                let theap = &mut (*image).theap;
                let provenance = if requested.as_ptr().is_null() {
                    theap.set_dynamic_metadata_memid(memory)
                } else {
                    theap.set_requested_arena_metadata_memid(memory)
                };
                if !provenance {
                    Err(crate::types::TheapDynamicInitError::InvalidInput)
                } else {
                    theap.initialize_dynamic_metadata_on_tld(
                        &mut *heap.as_ptr(),
                        &mut *tld.as_ptr(),
                        crate::types::TheapPageMode::OrdinaryAbandoning,
                        true,
                    )
                }
            }
        };
        let block = if requested.as_ptr().is_null() {
            let block = child
                .with_metadata_page_engine(binding, |_child, engine| engine.allocate_zeroed(size))
                .map_err(ChildHeapTheapError::PageEngine)?
                .ok_or(ChildHeapTheapError::TheapAllocation)?;
            initialize(block, MemoryId::malloc(block.as_ptr(), size, true))
                .map_err(ChildHeapTheapError::TheapInitialization)?;
            block
        } else {
            let config = binding.page_map().memory_config()
                .map_err(|_| ChildHeapTheapError::InvalidTransition)?;
            // SAFETY: this owner retains the live child image and its arena
            // backing until the Theap's stored source `memid` returns the
            // exact claim before child teardown.
            child.with_child_image(|image| -> Result<NonNull<Theap>, ChildHeapTheapError> {
                let process = crate::os::ChildVmProcess::new(binding.process(), image)
                    .map_err(|_| ChildHeapTheapError::InvalidTransition)?;
                let search = crate::arena::ArenaSearch {
                    heap_sequence: 0,
                    heap_count: 1,
                    thread_sequence: self.sequence.get(),
                    numa_node: unsafe { tld.as_ref() }.numa_node(),
                    requested,
                    allow_pinned: true,
                };
                let claim = unsafe { image.identity().arena_backing().try_allocate_requested_arena_object(
                    process.process(), config, search,
                    size.next_multiple_of(crate::config::ARENA_MIN_OBJ_SIZE),
                    crate::config::ARENA_SLICE_SIZE, 0, true,
                ) }.map_err(|_| ChildHeapTheapError::TheapAllocation)?;
                let block = NonNull::new(claim.start()).expect("a claimed arena slice has a start");
                let result = initialize(block, claim.memory_id());
                // SAFETY: `initialize` wrote the complete image and stored
                // this claim's memory identity before attempting publication.
                unsafe { finish_child_requested_theap_claim(claim, result) }
            }).ok_or(ChildHeapTheapError::InvalidTransition)??.cast()
        };
        // theap.c:290-292: a non-detached Theap counts in its subprocess.
        child.context.with_image(|image| image.identity().record_statistics_theap_linked());
        Ok(block.cast())
    }

    /// Runs one page operation on this thread's Theap `theap` for a non-main
    /// Heap, with that Theap's own page-engine state (see
    /// [`ChildHeapTheapImage`]). When a fresh page first comes from an arena,
    /// the Heap's per-arena page record is allocated from the child main
    /// Heap through this thread's main-Heap Theap, which becomes the cached
    /// Theap, as `mi_heap_zalloc_aligned(heap_main)` does in source.
    ///
    /// # Safety
    /// `this` is the owner of the running thread, `theap` one of its live
    /// Theaps for a non-main Heap of `child`, and `child` its context with
    /// no other operation running. Neither pointer is otherwise borrowed for
    /// the call.
    pub(crate) unsafe fn with_heap_theap_page_engine<R>(
        this: *mut Self,
        child: *mut ChildMainHeapContextOwner<'_>,
        binding: crate::process_init::ProcessMainBackingBinding,
        theap: NonNull<Theap>,
        operation: impl for<'session, 'image> FnOnce(
            &mut crate::single_thread::ChildOrdinaryPageAllocator<'session, 'image, 'static>,
        ) -> R,
    ) -> Result<R, ChildMetadataPageEngineError> {
        // SAFETY: short copies of this owner's immutable identity fields.
        let (image, tld, thread, sequence, state, config, parent) = unsafe {
            let owner = &*this;
            (owner.image, owner.tld_pointer(), owner.thread, owner.sequence, owner.state, owner.config, owner.parent_subprocess)
        };
        let tld = tld.ok_or(ChildMetadataPageEngineError::InvalidTransition)?;
        if unsafe { ((*this).heap_theap_pending_fresh_initialization.is_some() || (*this).heap_theap_pending_live_page_validity.is_some()) }
            || state != ChildThreadOwnerState::Attached
            || !binding.is_active()
            || !binding.is_allocation_ready()
            || binding.process().main_subprocess().is_none_or(|main| !core::ptr::eq(main, parent))
            || binding.page_map().memory_config().ok() != Some(config)
        {
            return Err(ChildMetadataPageEngineError::InvalidTransition);
        }
        // SAFETY: a live Theap of this thread.
        let heap = NonNull::new(unsafe { Theap::heap_at(theap) }).ok_or(ChildMetadataPageEngineError::InvalidTransition)?;
        let theap_image = theap.cast::<ChildHeapTheapImage>().as_ptr();
        // SAFETY: the Theap's own state field, used only by its engine.
        let page_engine = unsafe { &mut (*theap_image).page_engine };
        let mut pending_os_release = None;
        let mut pending_fresh_initialization = None;
        let mut pending_live_page_validity = None;
        // SAFETY: the owner's registration keeps the child image allocated.
        let child_ref = unsafe { Pin::new_unchecked(image.as_ref()) };
        let child_process = crate::os::ChildVmProcess::new(binding.process(), child_ref)
            .map_err(ChildMetadataPageEngineError::ChildProcess)?;
        let pair = crate::process_arena::ChildProcessPageArenaLease::join(binding.page_map(), child_process)
            .map_err(ChildMetadataPageEngineError::BackingPair)?;
        // SAFETY: this engine registers and unregisters only its own pages.
        let page_map = unsafe { pair.page_map_for_owned_ranges() }
            .map_err(ChildMetadataPageEngineError::BackingPair)?;
        let mut allocate_arena_pages = |size: usize, alignment: usize| -> Option<NonNull<u8>> {
            if child.is_null() {
                return None;
            }
            // SAFETY: the outer engine borrows neither the owner nor the
            // child context; this nested operation runs on the thread's
            // main-Heap Theap with that Theap's own engine state.
            unsafe {
                let owner = &mut *this;
                let main = owner.theap_pointer()?;
                owner.cached_set(&mut *child, binding, main).ok()?;
                owner.with_page_engine(binding, |_image, engine| engine.allocate_aligned_zeroed(size, alignment))
                    .ok()
                    .flatten()
            }
        };
        // SAFETY: the owner's images, this Theap's state, and the child stay
        // live for the operation, which runs on this thread only.
        let session = unsafe {
            crate::types::metadata_session::ChildOrdinaryTheapPageSession::new_for_non_main_heap(
                child_ref, tld, theap, heap, thread, sequence,
                &mut pending_os_release, &mut *page_engine, &mut allocate_arena_pages,
            ).and_then(|session| session.with_fresh_initialization_slot(&mut pending_fresh_initialization))
                .and_then(|session| session.with_live_page_validity_slot(&mut pending_live_page_validity))
        }
        .ok_or(ChildMetadataPageEngineError::SessionNotReady)?;
        let backing = crate::page_backing::ChildMetadataArenaBacking::new(pair);
        // SAFETY: the validated child pair and session are held through the
        // complete operation.
        let mut engine = unsafe {
            crate::single_thread::ChildOrdinaryPageAllocator::activate_child_ordinary(
                session, backing, page_map, sequence,
                unsafe { heap.as_ref() }.exclusive_arena_id().ok_or(ChildMetadataPageEngineError::InvalidTransition)?,
            )
        };
        let value = operation(&mut engine);
        // A refused finish's Drop transfers any unfinished OS release into
        // `pending_os_release` and latches the engine state.
        let finished = engine.finish_operation().map_err(drop).is_ok();
        if let Some(task) = pending_fresh_initialization.take() {
            // The engine has ended its projections. This original thread
            // owner retains the auxiliary image and its Heap; terminal state
            // prevents either from being retired while this claim persists.
            let slot = unsafe { &mut (*this).heap_theap_pending_fresh_initialization };
            if slot.is_none() {
                *slot = Some((theap, task));
            } else {
                core::mem::forget(task);
            }
            *page_engine = ChildPageEngineState::Poisoned;
        }

        if let Some(task) = pending_live_page_validity.take() {
            // The engine has ended its projections. This original thread
            // owner retains the auxiliary image and its Heap; terminal state
            // prevents either from being retired while this claim persists.
            let slot = unsafe { &mut (*this).heap_theap_pending_live_page_validity };
            if slot.is_none() {
                *slot = Some((theap, task));
            } else {
                core::mem::forget(task);
            }
            *page_engine = ChildPageEngineState::Poisoned;
        }
        if let Some(owner) = pending_os_release.take() {
            // See `ChildHeapTheapImage`: the thread keeps one retry slot.
            // SAFETY: the engine is gone; the owner is not otherwise borrowed.
            let slot = unsafe { &mut (*this).heap_theap_pending_os_release };
            if slot.is_none() && *page_engine == ChildPageEngineState::RetryPending {
                *slot = Some((Some(theap), owner));
            } else {
                core::mem::forget(owner);
                *page_engine = ChildPageEngineState::Poisoned;
            }
        }
        if !finished {
            return Err(ChildMetadataPageEngineError::EngineRetained);
        }
        Ok(value)
    }

    /// The first half of `_mi_thread_done` (`init.c:452-480`) for this
    /// thread's Theaps of non-main Heaps: `_mi_thread_locals_thread_done`
    /// frees the thread-local slot array, then each such Theap on the TLD
    /// list, in list order, is collected (`_mi_theap_collect_abandon`): its
    /// all-free pages are released and pages with live blocks are abandoned
    /// to that Heap's own records (an OS-backed page to its OS-abandoned
    /// list). A failed page transition returns
    /// [`ChildHeapTheapError::InvalidTransition`].
    ///
    /// # Safety
    /// As for [`Self::with_heap_theap_page_engine`], on the finishing thread.
    pub(crate) unsafe fn drain_heap_theaps_for_thread_done(
        this: *mut Self,
        child: *mut ChildMainHeapContextOwner<'_>,
        binding: crate::process_init::ProcessMainBackingBinding,
    ) -> Result<(), ChildHeapTheapError> {
        unsafe { Self::drain_heap_theaps_for_thread_done_using(this, child, binding,
            |_theap, engine| engine.collect_abandon_for_thread_done()) }
    }

    /// Source-locked auxiliary page traversal with a caller-owned assertion
    /// transport. The collector performs no output and exports no projection;
    /// a failed exact task must retain its issuer before this lock is released.
    ///
    /// # Safety
    /// The current member, original child and all source images remain live.
    /// `collect` may mutate only the selected Theap's owned page fields and
    /// must not invoke callbacks, detach source lists or reenter the TLD lock.
    pub(crate) unsafe fn drain_heap_theaps_for_thread_done_using(
        this: *mut Self,
        child: *mut ChildMainHeapContextOwner<'_>,
        binding: crate::process_init::ProcessMainBackingBinding,
        mut collect: impl for<'session, 'image> FnMut(
            NonNull<Theap>,
            &mut crate::single_thread::ChildOrdinaryPageAllocator<'session, 'image, 'static>,
        ) -> bool,
    ) -> Result<(), ChildHeapTheapError> {
        // Refuse before freeing source locals or unlinking any issuer image.
        if unsafe { (*this).has_pending_page_assertion() } {
            return Err(ChildHeapTheapError::InvalidTransition);
        }
        // SAFETY: forwarded; the owner and child are not otherwise borrowed.
        unsafe { (*this).free_thread_locals(&mut *child, binding) }?;
        // SAFETY: short reads of this owner's identities.
        let (tld, main) = unsafe { ((*this).tld_pointer(), (*this).theap_pointer()) };
        let tld = tld.ok_or(ChildHeapTheapError::InvalidTransition)?;
        let main = main.ok_or(ChildHeapTheapError::InvalidTransition)?;
        // SAFETY: the source TLD lock retains every selected Heap/Theap while
        // its current thread collects only that issuer's local page fields.
        let drained = unsafe { ThreadLocalData::drain_auxiliary_theaps_for_thread_done(
            tld, main, |theap| {
                Self::with_heap_theap_page_engine(this, child, binding, theap,
                    |engine| collect(theap, engine)).unwrap_or(false)
            },
        ) }.map_err(|_| ChildHeapTheapError::InvalidTransition)?;
        if !drained { return Err(ChildHeapTheapError::InvalidTransition); }
        Ok(())
    }

    /// The `mi_thread_theaps_done` tail (`init.c:396-419`) for this thread's
    /// Theaps of non-main Heaps: the cached Theap is reset to the empty Theap
    /// (dropping its reference, which frees a Theap whose Heap was already
    /// freed), then each such Theap leaves its Heap and the TLD
    /// (`_mi_tld_detach_theaps`) and drops the Heap's reference. The
    /// main-Heap Theap is left to [`Self::teardown`].
    ///
    /// # Safety
    /// As for [`Self::drain_heap_theaps_for_thread_done`], after it succeeded
    /// and the default root was reset.
    pub(crate) unsafe fn release_heap_theaps_for_thread_done(
        &mut self,
        child: &mut ChildMainHeapContextOwner<'_>,
        binding: crate::process_init::ProcessMainBackingBinding,
    ) -> Result<(), ChildHeapTheapError> {
        if self.has_pending_page_assertion() {
            return Err(ChildHeapTheapError::InvalidTransition);
        }
        // SAFETY: the immutable source empty Theap is process-static.
        let empty = unsafe { NonNull::new_unchecked(crate::bootstrap::empty_default_theap_ptr()) };
        // SAFETY: forwarded.
        unsafe { self.cached_set(child, binding, empty) }?;
        let tld = self.tld_pointer().ok_or(ChildHeapTheapError::InvalidTransition)?;
        let main = self.theap_pointer();
        let identity = child
            .context
            .with_image(|image| NonNull::from(image.get_ref().identity()))
            .ok_or(ChildHeapTheapError::InvalidTransition)?;
        // SAFETY: as in the drain above.
        let mut current = unsafe { ThreadLocalData::theaps_head_at(tld) };
        while let Some(theap) = NonNull::new(current) {
            // SAFETY: a live member of the list, read before it leaves.
            current = unsafe { Theap::tld_next_at(theap) };
            if Some(theap) == main {
                continue;
            }
            // SAFETY: forwarded; the drained Theap owns no page.
            unsafe { ThreadLocalData::detach_theap_for_thread_done(tld, theap, identity.as_ref()) }
                .map_err(|_| ChildHeapTheapError::InvalidTransition)?;
            // SAFETY: the Heap's reference, dropped once.
            unsafe { self.theap_decref(child, binding, theap) }?;
        }
        Ok(())
    }

    /// The slot count of this thread's thread-local array (0 before the
    /// first regular slot is set).
    #[cfg(test)]
    pub(crate) fn test_thread_local_count(&self) -> usize {
        #[cfg(target_arch = "x86_64")]
        if self.state != ChildThreadOwnerState::Attached { return 0; }
        self.thread_locals.as_ref().map_or(0, |block| {
            // SAFETY: the retained slot image.
            unsafe { (*block.pointer.cast::<DynamicThreadLocalBacking>().as_ptr()).count() }
        })
    }

    /// Whether one of this thread's non-main Theaps retains a raw unmap retry.
    #[cfg(test)]
    pub(crate) fn test_has_heap_theap_pending_os_release(&self) -> bool {
        self.heap_theap_pending_os_release.is_some()
    }

    /// The page-engine state of this thread's Theap `theap` for a non-main Heap.
    ///
    /// # Safety
    /// `theap` is a live such Theap.
    #[cfg(test)]
    pub(crate) unsafe fn test_heap_theap_engine_state(theap: NonNull<Theap>) -> ChildPageEngineState {
        unsafe { (*theap.cast::<ChildHeapTheapImage>().as_ptr()).page_engine }
    }

    /// This thread's value on `heap`'s thread-local slot.
    #[cfg(test)]
    pub(crate) fn test_heap_slot(&self, heap: NonNull<Heap>) -> *mut () {
        heap_theap_key(heap).map_or(core::ptr::null_mut(), |key| self.thread_local_get(key))
    }

    /// `mi_abandoned_page_try_reclaim` (`free.c:423-469`) of a claimed child
    /// page into this thread: `_mi_page_associated_theap_peek` names the
    /// Theap on the page's Heap's thread-local slot (the fast slot for a main
    /// Heap), which must belong to that Heap; its engine then applies the
    /// source reclaim limits and appends the page
    /// (`reclaim_abandoned_page_on_free`). Otherwise the page is declined.
    ///
    /// # Safety
    /// `this` is the running thread's owner; `child` is its locked context or
    /// null (a reclaim never allocates a page record).
    pub(crate) unsafe fn reclaim_on_free(
        this: *mut Self,
        child: *mut ChildMainHeapContextOwner<'_>,
        binding: crate::process_init::ProcessMainBackingBinding,
        candidate: crate::abandoned::ReclaimOnFreeCandidate<'_, crate::single_thread::ChildMappedAbandonedPage<'static>>,
    ) -> crate::abandoned::ReclaimOnFreeOutcome {
        use crate::abandoned::ReclaimOnFreeOutcome::Declined;
        let Some(heap) = NonNull::new(candidate.page_heap()) else { return Declined };
        // SAFETY: the claimed page keeps its Heap alive.
        let theap = if unsafe { heap.as_ref() }.is_subprocess_main() {
            crate::compiler_tls::fast_slot_peek().map(NonNull::cast::<Theap>)
        } else {
            // SAFETY: a short read of this owner's slot array.
            heap_theap_key(heap).and_then(|key| NonNull::new(unsafe { (*this).thread_local_get(key) }.cast::<Theap>()))
        };
        let Some(theap) = theap else { return Declined };
        // SAFETY: a Theap on this thread's slots is live.
        if unsafe { Theap::heap_at(theap) } != heap.as_ptr() {
            return Declined;
        }
        // SAFETY: short read of this owner's main-Heap Theap.
        if Some(theap) == unsafe { (*this).theap_pointer() } {
            // SAFETY: the admitted thread runs its own engine.
            unsafe { (*this).with_page_engine(binding, |_image, engine| engine.reclaim_abandoned_page_on_free(candidate)) }
                .unwrap_or(Declined)
        } else {
            // SAFETY: forwarded; one of this thread's non-main Theaps.
            unsafe {
                Self::with_heap_theap_page_engine(this, child, binding, theap, |engine| {
                    engine.reclaim_abandoned_page_on_free(candidate)
                })
            }
            .unwrap_or(Declined)
        }
    }

    /// Frees one locally owned Heap administration record while preserving
    /// whether the client was consumed before a session-finish failure.
    ///
    /// # Safety
    /// This thread retains `this`, its admitted child, binding, and the exact
    /// live captured allocation. Its source Theap owns the allocation and
    /// belongs to this owner's TLD. No competing local free or page mutation
    /// may race this operation. A consumed client is never accessed or retried.
    #[cfg(target_arch = "x86_64")]
    pub(crate) unsafe fn free_local_heap_metadata_with_progress(
        this: *mut Self,
        child: *mut ChildMainHeapContextOwner<'_>,
        binding: crate::process_init::ProcessMainBackingBinding,
        allocation: crate::process_page_map::LiveAllocationPointer,
    ) -> crate::single_thread::LocalClientFreeProgress {
        use crate::single_thread::{FreeError, LocalClientFreeProgress as Progress};
        if !crate::compiler_tls::current_thread_identity()
            .is_some_and(|thread| allocation.is_associated_with(thread)) {
            return Progress::RefusedBeforeConsumption(FreeError::ForeignPage);
        }
        // SAFETY: the captured current client retains immutable source identity;
        // the admitted thread owns the short TLD/Theap identity projections.
        let selected = NonNull::new(unsafe { crate::types::Page::theap_at(allocation.page()) });
        let (main, tld) = unsafe { ((*this).theap_pointer(), (*this).tld_pointer()) };
        let mut observed = None;
        let finished = if selected == main && main.is_some() {
            // SAFETY: the selected main Theap owns this exact current client.
            unsafe { (*this).with_page_engine(binding, |_image, engine| {
                observed = Some(unsafe { engine.free_captured_live_allocation_with_progress(allocation) });
            }) }.is_ok()
        } else if let Some(selected) = selected.filter(|selected| tld.is_some() && unsafe {
            Theap::tld_at(*selected) == tld.map_or(core::ptr::null_mut(), NonNull::as_ptr)
        }) {
            // SAFETY: the selected auxiliary Theap belongs to this retained TLD.
            unsafe { Self::with_heap_theap_page_engine(this, child, binding, selected, |engine| {
                observed = Some(unsafe { engine.free_captured_live_allocation_with_progress(allocation) });
            }) }.is_ok()
        } else {
            return Progress::RefusedBeforeConsumption(FreeError::ForeignPage);
        };
        match observed {
            Some(Progress::Consumed(Ok(()))) if !finished => Progress::Consumed(Err(FreeError::Lifecycle)),
            Some(progress) => progress,
            None => Progress::RefusedBeforeConsumption(FreeError::Lifecycle),
        }
    }

    /// Frees `block`, a live block observed through `binding`'s PageMap, on
    /// this thread: through the owning engine when one of this thread's
    /// Theaps owns its page, otherwise through the nonlocal route.
    ///
    /// # Safety
    /// As for [`Self::with_heap_theap_page_engine`]; `block` is live and
    /// freed once.
    pub(crate) unsafe fn free_block(
        this: *mut Self,
        child: *mut ChildMainHeapContextOwner<'_>,
        binding: crate::process_init::ProcessMainBackingBinding,
        block: NonNull<u8>,
    ) -> Result<(), ChildHeapTheapError> {
        // SAFETY: forwarded exact-live-block contract.
        let allocation = unsafe { binding.page_map().lookup_live_allocation(block) }
            .ok()
            .flatten()
            .ok_or(ChildHeapTheapError::InvalidTransition)?;
        // SAFETY: the live block keeps its page; a raw field read.
        let owner_theap = unsafe { crate::types::Page::theap_at(allocation.page()) };
        // SAFETY: short read of this owner's Theap and TLD identities.
        let (main, tld) = unsafe { ((*this).theap_pointer(), (*this).tld_pointer()) };
        let owner_theap = NonNull::new(owner_theap);
        let current = crate::compiler_tls::current_thread_identity();
        if current.is_some_and(|current| allocation.is_associated_with(current)) {
            if owner_theap == main {
                drop(allocation);
                // SAFETY: the main-Heap Theap owns the page.
                return unsafe { (*this).with_page_engine(binding, |_image, engine| unsafe { engine.free(block) }) }
                    .map_err(ChildHeapTheapError::PageEngine)?
                    .map_err(ChildHeapTheapError::Metadata);
            }
            if let Some(theap) = owner_theap.filter(|theap| unsafe { Theap::tld_at(*theap) } == tld.map_or(core::ptr::null_mut(), NonNull::as_ptr)) {
                drop(allocation);
                // SAFETY: one of this thread's non-main Theaps owns the page.
                return unsafe {
                    Self::with_heap_theap_page_engine(this, child, binding, theap, |engine| unsafe { engine.free(block) })
                }
                .map_err(ChildHeapTheapError::PageEngine)?
                .map_err(ChildHeapTheapError::Metadata);
            }
        }
        // SAFETY: forwarded; the page belongs to another owner or none.
        let reclaim = |candidate: crate::abandoned::ReclaimOnFreeCandidate<'_, crate::single_thread::ChildMappedAbandonedPage<'static>>| {
            // SAFETY: forwarded; the owner and child are not otherwise borrowed.
            unsafe { Self::reclaim_on_free(this, child, binding, candidate) }
        };
        match unsafe { crate::subproc::lifecycle::free_child_block_nonlocal(binding, allocation, reclaim) } {
            Some(crate::single_thread::ChildNonlocalFreeResult::Freed | crate::single_thread::ChildNonlocalFreeResult::Released) => Ok(()),
            _ => Err(ChildHeapTheapError::InvalidTransition),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ChildThreadStartError {
    InvalidTransition,
    CurrentThread,
    NumaNode,
    PageEngine(ChildMetadataPageEngineError),
    ChildNotReady(crate::subproc::ChildThreadTicketError),
    TldAllocation,
    TheapAllocation,
    TldRelease(FreeError),
    TheapInitialization(crate::types::TheapDynamicInitError),
}

#[must_use = "a failed child thread start may retain initialized TLD/Theap ownership"]
pub(crate) enum ChildThreadStartFailure {
    Rejected(ChildThreadStartError),
    Retained {
        owner: ChildThreadOwner,
        error: ChildThreadStartError,
    },
}

/// Whether caller-retained child-owner storage contains an initialized
/// owner after metadata allocation. Retained keeps the original partial
/// TLD, Theap and registration custody; Rejected owns no source resource.
#[cfg(target_arch = "x86_64")]
#[must_use = "initialized child-owner storage must be consumed or retained"]
enum ChildThreadOwnerInitializationOutcome {
    Ready,
    Rejected(ChildThreadStartError),
    Retained(ChildThreadStartError),
}

#[cfg(target_arch = "x86_64")]
impl ChildThreadOwnerInitializationOutcome {
    fn reject_cold_owner(owner: &mut ChildThreadOwner, error: ChildThreadStartError) -> Self {
        debug_assert!(owner.tld.is_none() && owner.theap.is_none() && owner.registration.is_none()
            && owner.pending_os_release.is_none() && owner.pending_fresh_initialization.is_none()
            && owner.pending_live_page_validity.is_none() && owner.thread_locals.is_none()
            && owner.pending_thread_locals.is_none() && owner.heap_theap_pending_os_release.is_none()
            && owner.heap_theap_pending_fresh_initialization.is_none()
            && owner.heap_theap_pending_live_page_validity.is_none());
        // SAFETY: this completely initialized cold owner acquired no source
        // image or registration. Ending its value returns the destination to
        // vacant storage, which the caller will not read or drop as an owner.
        unsafe { core::ptr::drop_in_place(owner) };
        Self::Rejected(error)
    }
}

enum ChildThreadAllocationOutcome {
    Ready {
        tld: ChildMetadataImageBlock,
        theap: ChildMetadataImageBlock,
        registration: crate::subproc::ChildThreadRegistrationLease,
        sequence: ThreadSequence,
    },
    Rejected(ChildThreadStartError),
    Retained {
        tld: ChildMetadataImageBlock,
        registration: Option<crate::subproc::ChildThreadRegistrationLease>,
        sequence: ThreadSequence,
        error: ChildThreadStartError,
    },
}

/// Source-ordered progress of one child subprocess from creation through
/// `mi_subproc_destroy`. `Terminal` retains an owner whose next source step
/// could not be proven safe; no transition leaves it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ChildMainHeapStage {
    Registered,
    HeapReady,
    RegistryUnlinked,
    TheapDetached,
    MetadataTheapReleased,
    HeapListRemoved,
    /// Source `mi_heap_free` freed the parent-allocated Heap image, and the
    /// child record was merged into the process-main statistics.
    HeapStorageReleased,
    ArenaBackingDestroyed,
    Terminal,
}

/// Child state that pinned C exposes after `mi_subproc_new`.
#[cfg(test)]
pub(crate) struct ChildCreatedFacts {
    pub(crate) sequence: usize,
    pub(crate) parent_is_main: bool,
    pub(crate) heap_count: usize,
    pub(crate) heap_total_count: usize,
    pub(crate) heap_list_is_main_only: bool,
    pub(crate) main_heap_sequence: usize,
    pub(crate) main_heap_names_child: bool,
    pub(crate) metadata_theap_is_heap_only_member: bool,
    pub(crate) metadata_theap_on_parent_detached_tld: bool,
    pub(crate) live_threads: usize,
    pub(crate) total_threads: usize,
    pub(crate) arena_count: usize,
    pub(crate) heaps_current: i64,
    pub(crate) statistics: crate::statistics::FinalStatisticsSnapshot,
}

/// Page-engine failure ownership remains distinct from subprocess teardown.
/// A failed accounted `munmap` can be retried raw while its context remains
/// retained; other unfinished engine state is permanently poisoned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ChildPageEngineState {
    Active,
    RetryPending,
    RetryComplete,
    Poisoned,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ChildMetadataPageEngineError {
    InvalidTransition,
    ChildProcess(crate::os::ChildVmProcessError),
    BackingPair(crate::process_arena::ChildProcessPageArenaLeaseError),
    PageMapLifecycle(crate::process_page_map::ProcessPageMapError),
    Registry(crate::subproc::registry::SourceSubprocessRegistryError),
    SessionNotReady,
    EngineRetained,
    MetadataPagesRemain,
    /// A child thread still holds its TLD registration; destruction would
    /// free its TLD, Theap, and pages under it.
    LiveThreads,
}

impl ChildPageEngineState {
    fn permits_page_projection(self) -> bool { self == Self::Active }
    fn permits_teardown(self) -> bool { matches!(self, Self::Active | Self::RetryComplete) }

    pub(crate) fn with_retained_release(self, retryable: bool) -> Option<Self> {
        (self == Self::Active).then_some(if retryable { Self::RetryPending } else { Self::Poisoned })
    }

    pub(crate) fn latch_unfinished(self) -> Self {
        if self == Self::RetryPending { self } else { Self::Poisoned }
    }

    fn complete_raw_retry(self) -> Option<Self> {
        (self == Self::RetryPending).then_some(Self::RetryComplete)
    }
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
    pub(crate) heap: ChildHeapStorage<'heap>,
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
    /// Native image release failed. The retained owner's stage distinguishes
    /// an exact live refusal from terminal consumed or padding-rejected custody.
    NativeHeapFree,
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
        self,
        heap: crate::main_heap_page::ParentHeapAllocation<'heap>,
    ) -> Result<ChildMainHeapContextOwner<'heap>, ChildMainHeapBindFailure<'heap>> {
        self.bind_heap_storage(ChildHeapStorage::Parent(heap))
    }

    /// [`Self::bind_parent_heap_storage`] for either child Heap storage.
    pub(crate) fn bind_heap_storage<'heap>(
        mut self,
        mut heap: ChildHeapStorage<'heap>,
    ) -> Result<ChildMainHeapContextOwner<'heap>, ChildMainHeapBindFailure<'heap>> {
        let registered = self.parent_metadata.with_identity(|parent| {
            self.with_image(|image| {
                let identity = image.identity();
                identity.is_registered_child_of(parent)
                    && identity.main_heap_publication_state()
                        == crate::subproc::MainHeapPublicationState::Absent
                    && !identity.has_published_metadata_theap()
            }).unwrap_or(false)
        }).unwrap_or(false);
        let error = if self.terminal || !registered {
            Some(ChildMainHeapBindError::ChildNotRegistered)
        } else if !match &heap {
            ChildHeapStorage::Parent(allocation) => {
                allocation.was_allocated_by(self.parent_subprocess.identity())
            }
            // The native runtime allocates on the caller's current Heap;
            // verify the exact page Heap before initializing the image.
            ChildHeapStorage::Native(image) => self.parent_metadata.with_identity(|parent| {
                // SAFETY: the image token retains this live allocation and
                // no operation moves its containing page during binding.
                (unsafe { crate::source_heap_api::heap_of(image.pointer.as_ptr().cast()) })
                    == parent.ready_main_heap_pointer().cast()
            }).unwrap_or(false),
        } {
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
            pending_os_release: None,
            pending_fresh_initialization: None,
            pending_live_page_validity: None,
            page_engine: ChildPageEngineState::Active,
            metadata_pages_may_exist: false,
            stage: ChildMainHeapStage::Registered,
            #[cfg(test)]
            fail_next_metadata_session_setup: false,
        })
    }
}

impl<'heap> ChildMainHeapContextOwner<'heap> {
    /// The source lifecycle step this owner has completed.
    #[inline]
    pub(crate) const fn stage(&self) -> ChildMainHeapStage {
        self.stage
    }

    /// The child main Heap image address while its bytes remain initialized.
    /// Prepared and terminal native custody provide no projection authority. Only
    /// field-level projections that source performs on another Heap's main
    /// Heap (its statistics) may use it.
    #[inline]
    pub(crate) fn main_heap_pointer(&self) -> Option<NonNull<Heap>> {
        #[cfg(target_arch = "x86_64")]
        return self.heap_storage.as_ref().and_then(ChildHeapStorage::pointer_for_live_image);
        #[cfg(not(target_arch = "x86_64"))]
        self.heap_storage.as_ref().map(ChildHeapStorage::pointer_for_identity)
    }

    /// Projects the shared child image for one subprocess-scoped transition,
    /// such as a Heap-list operation under that list's own lock.
    pub(crate) fn with_child_image<R>(
        &mut self,
        operation: impl for<'image> FnOnce(Pin<&'image crate::subproc::ChildSubprocessImage>) -> R,
    ) -> Option<R> {
        self.context.with_image(operation)
    }

    /// The pinned child identity as an address only: list order, and the
    /// subprocess comparison of `mi_subproc_add_current_thread`.
    pub(crate) fn identity_pointer(&mut self) -> Option<*mut crate::subproc::SubprocessIdentity> {
        self.context.with_image(|child| child.identity().as_ptr())
    }

    /// Source `mi_subproc_visit_heaps` over this child (`subproc.c:303-313`)
    /// under its Heap-list lock. `None` when the child image is gone.
    pub(crate) fn visit_heaps(
        &mut self,
        visitor: impl FnMut(NonNull<Heap>) -> bool,
    ) -> Option<Result<bool, crate::types::heap_registry::SourceHeapRegistryError>> {
        self.context.with_image(|child| child.identity().heap_list().visit_heaps(visitor))
    }

    /// Runs source `mi_subproc_visit_heaps` over this child and counts the
    /// visitor calls.
    #[cfg(test)]
    pub(crate) fn test_visit_heaps(
        &mut self,
        mut visitor: impl FnMut(NonNull<Heap>) -> bool,
    ) -> (bool, usize) {
        self.context.with_image(|child| {
            let mut count = 0;
            let ok = child.identity().heap_list().visit_heaps(|heap| {
                count += 1;
                visitor(heap)
            }).expect("the child Heap-list lock is uncontended");
            (ok, count)
        }).expect("a created child projects its image")
    }

    /// Source-visible child facts after `mi_subproc_new`, for the pinned-C
    /// lifecycle differential.
    #[cfg(test)]
    pub(crate) fn test_created_child_facts(
        &mut self,
        parent: &'static MainSubprocess,
    ) -> Option<ChildCreatedFacts> {
        let heap = self.heap_storage.as_ref()?.pointer_for_identity();
        let metadata_theap = self.context.metadata_theap.as_ref()
            .and_then(ChildMetadataAllocation::dynamic_theap_pointer)?;
        let parent_metadata_theap = NonNull::new(parent.identity().test_published_metadata_theap())?;
        self.context.with_image(|child| {
            let identity = child.identity();
            let (heap_count, heap_total_count, _) = identity.heap_list().test_counts();
            let mut members = 0;
            let mut only_child_main = true;
            identity.heap_list().visit_heaps(|member| {
                members += 1;
                only_child_main &= member == heap;
                true
            }).ok()?;
            // SAFETY: the owner retains the child Heap and metadata Theap
            // images, and the parent's detached metadata Theap is
            // process-lifetime; no list operation runs during the read.
            let image = unsafe {
                heap.as_ref().test_child_main_image_facts(metadata_theap, parent_metadata_theap)
            };
            Some(ChildCreatedFacts {
                sequence: identity.test_registry_sequence(),
                parent_is_main: identity.is_registered_child_of(parent.identity()),
                heap_count,
                heap_total_count,
                heap_list_is_main_only: members == 1 && only_child_main,
                main_heap_sequence: image.heap_sequence,
                main_heap_names_child: image.subprocess == identity.as_ptr(),
                metadata_theap_is_heap_only_member: image.metadata_theap_is_only_member,
                metadata_theap_on_parent_detached_tld: image.metadata_theap_on_parent_tld,
                live_threads: identity.live_thread_count(),
                total_threads: identity.total_thread_count(),
                arena_count: identity.arena_backing().registry().count(),
                heaps_current: identity.statistics().final_output_snapshot().heaps.current,
                statistics: identity.statistics().final_output_snapshot(),
            })
        }).flatten()
    }

    #[cfg(test)]
    pub(crate) const fn test_page_engine_state(&self) -> ChildPageEngineState {
        self.page_engine
    }

    #[cfg(test)]
    pub(crate) const fn test_has_pending_os_release(&self) -> bool {
        self.pending_os_release.is_some()
    }

    #[cfg(test)]
    pub(crate) fn test_has_pending_fresh_initialization(&self) -> bool {
        self.pending_fresh_initialization.is_some()
    }

    #[cfg(test)]
    pub(crate) fn test_is_heap_ready(&self) -> bool {
        self.stage == ChildMainHeapStage::HeapReady
    }

    #[cfg(test)]
    pub(crate) fn test_is_registry_unlinked(&self) -> bool {
        self.stage == ChildMainHeapStage::RegistryUnlinked
    }

    #[cfg(test)]
    pub(crate) fn test_theap_heap_detach_state(&mut self) -> (bool, bool, bool) {
        let has_heap_projection = self.heap_storage.as_mut()
            .is_some_and(|heap| heap.with_heap(|_| ()).is_some());
        let Some(theap) = self.context.metadata_theap.as_ref()
            .and_then(ChildMetadataAllocation::dynamic_theap_pointer) else {
            return (has_heap_projection, false, false);
        };
        let published = self.context.with_image(|child| {
            child.identity().matches_published_detached_metadata_theap(theap)
        }).unwrap_or(false);
        let attached = self.context.with_image(|child| {
            child.identity().has_published_metadata_theap()
        }).unwrap_or(false);
        (has_heap_projection, attached, published)
    }

    #[cfg(test)]
    pub(crate) fn test_fail_next_metadata_session_setup(&mut self) {
        self.fail_next_metadata_session_setup = true;
    }

    #[cfg(test)]
    pub(crate) fn test_child_vm_statistics(
        &mut self,
    ) -> Option<crate::statistics::VmStatisticsSnapshot> {
        self.context.with_image(|child| child.identity().vm_statistics().snapshot())
    }

    pub(crate) fn retain_pending_os_release(
        &mut self,
        owner: crate::os_page::OsAlignedPageOwner,
    ) -> Result<(), crate::os_page::OsAlignedPageOwner> {
        if self.pending_os_release.is_some() || (self.pending_fresh_initialization.is_some() || self.pending_live_page_validity.is_some()) || self.stage == ChildMainHeapStage::Terminal {
            return Err(owner);
        }
        let belongs_to_child = self.context.with_image(|child| {
            owner.belongs_to_subprocess(child.as_ref().get_ref().identity())
        }).unwrap_or(false);
        if !belongs_to_child {
            return Err(owner);
        }
        let retryable = owner.raw_retry_ready();
        let Some(next) = self.page_engine.with_retained_release(retryable) else {
            return Err(owner);
        };
        self.pending_os_release = Some(owner);
        self.page_engine = next;
        Ok(())
    }

    pub(crate) fn latch_unfinished_page_engine(&mut self) {
        self.page_engine = self.page_engine.latch_unfinished();
    }

    /// Retries only an owner whose process accounting edge already ran.
    /// The child context remains in `self` throughout the processless raw
    /// continuation; terminal and pre-accounted owners are preserved.
    pub(crate) unsafe fn retry_pending_os_release(
        &mut self,
    ) -> Result<bool, crate::os_page::OsAlignedPageError> {
        if self.page_engine != ChildPageEngineState::RetryPending { return Ok(false); }
        let Some(owner) = self.pending_os_release.take() else { return Ok(false); };
        if !owner.raw_retry_ready() {
            self.pending_os_release = Some(owner);
            return Ok(false);
        }
        // SAFETY: `self` retains the exact pinned child context and this
        // owner is the sole outstanding terminal mapping release right.
        match unsafe { owner.retry_release() } {
            Ok(()) => {
                let Some(next) = self.page_engine.complete_raw_retry() else {
                    unreachable!("raw retry was admitted only in the retry-pending state");
                };
                self.page_engine = next;
                Ok(true)
            }
            Err(failure) => {
                let error = failure.error();
                self.pending_os_release = Some(failure.into_owner());
                Err(error)
            }
        }
    }

    /// Projects the child context and its parent-allocated Heap together for
    /// one source transition. Both references are bounded by the closure.
    pub(crate) fn with_child_heap<R>(
        &mut self,
        operation: impl for<'context, 'heap_view> FnOnce(
            Pin<&'context crate::subproc::ChildSubprocessImage>,
            Pin<&'heap_view mut Heap>,
            MemoryId,
        ) -> R,
    ) -> Option<R> {
        if self.stage != ChildMainHeapStage::HeapReady || self.pending_os_release.is_some() || (self.pending_fresh_initialization.is_some() || self.pending_live_page_validity.is_some())
            || !self.page_engine.permits_page_projection() { return None; }
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
        if self.stage != ChildMainHeapStage::HeapReady || self.pending_os_release.is_some() || (self.pending_fresh_initialization.is_some() || self.pending_live_page_validity.is_some())
            || !self.page_engine.permits_page_projection() { return None; }
        self.context.with_lease(|mut lease| lease.with_metadata_theap(operation))
    }

    /// Holds the child subprocess's own metadata-Theap lock while lending
    /// the pinned child identity, exact child main Heap, and metadata Theap
    /// for one operation. The closure cannot retain any projection after the
    /// lock or owner borrow ends.
    pub(crate) fn with_child_metadata_entry<R>(
        &mut self,
        operation: impl for<'child, 'heap_view, 'theap> FnOnce(
            Pin<&'child crate::subproc::ChildSubprocessImage>,
            Pin<&'heap_view mut Heap>,
            &'theap mut Theap,
            MemoryId,
        ) -> R,
    ) -> Option<R> {
        if self.stage != ChildMainHeapStage::HeapReady || self.pending_os_release.is_some() || (self.pending_fresh_initialization.is_some() || self.pending_live_page_validity.is_some())
            || !self.page_engine.permits_page_projection() { return None; }
        let Self { context, heap_storage, .. } = self;
        let heap_storage = heap_storage.as_mut()?;
        let memory = heap_storage.memory_id();
        let result = context.with_locked_metadata_entry(|child, metadata_theap| {
            heap_storage.with_heap(|heap| operation(child, heap, metadata_theap, memory))
        })?;
        result
    }

    /// Runs one ordinary child metadata page-engine operation against the
    /// child's detached metadata Theap. The process binding supplies the
    /// canonical parent PageMap/policy; arena claims, statistics, and process
    /// VM accounting are routed through the exact registered child identity.
    /// The engine is short-lived, while live pages remain linked to the
    /// retained child Theap between operations.
    pub(crate) fn with_metadata_page_engine<R>(
        &mut self,
        binding: crate::process_init::ProcessMainBackingBinding,
        operation: impl for<'session, 'child> FnOnce(
            Pin<&'child crate::subproc::ChildSubprocessImage>,
            &mut crate::single_thread::ChildMetadataPageAllocator<'session, 'child, 'static>,
        ) -> R,
    ) -> Result<R, ChildMetadataPageEngineError> {
        #[cfg(test)]
        if self.fail_next_metadata_session_setup {
            self.fail_next_metadata_session_setup = false;
            return Err(ChildMetadataPageEngineError::SessionNotReady);
        }
        if self.stage != ChildMainHeapStage::HeapReady
            || self.pending_os_release.is_some() || (self.pending_fresh_initialization.is_some() || self.pending_live_page_validity.is_some())
            || self.page_engine != ChildPageEngineState::Active
            || !binding.is_active()
            || !binding.is_allocation_ready()
            || binding.process().main_subprocess().is_none_or(|parent| {
                !core::ptr::eq(parent, self.context.parent_subprocess)
            })
            || binding.page_map().memory_config().ok() != Some(self.context.config)
        {
            return Err(ChildMetadataPageEngineError::InvalidTransition);
        }

        let Self {
            context,
            heap_storage,
            pending_os_release,
            pending_fresh_initialization,
            pending_live_page_validity,
            page_engine,
            metadata_pages_may_exist,
            ..
        } = self;
        let result = context.with_locked_metadata_entry(|child, theap| {
            let child_process = crate::os::ChildVmProcess::new(binding.process(), child)
                .map_err(ChildMetadataPageEngineError::ChildProcess)?;
            let pair = crate::process_arena::ChildProcessPageArenaLease::join(
                binding.page_map(),
                child_process,
            )
            .map_err(ChildMetadataPageEngineError::BackingPair)?;
            let page_lifecycle = pair
                .begin_page_lifecycle()
                .map_err(ChildMetadataPageEngineError::BackingPair)?;
            // SAFETY: this engine owns child page ranges for the complete
            // operation and the lifecycle capability above excludes every
            // other plain PageMap mutation.
            let page_map = unsafe { pair.page_map_for_owned_ranges() }
                .map_err(ChildMetadataPageEngineError::BackingPair)?;
            // Identity-only raw projection: the linear token below retains
            // this exact allocation, but this path must not form `&mut Heap`
            // because ordinary child Heap projections use the Heap's own
            // synchronization. Page publication records only its address.
            let heap = heap_storage
                .as_ref()
                .map(ChildHeapStorage::pointer_for_identity)
                .ok_or(ChildMetadataPageEngineError::InvalidTransition)?;
            // SAFETY: the locked entry supplies the exact child Theap/image;
            // owner fields retain its Heap allocation and pending-state slots
            // for this bounded engine operation.
            let session = unsafe {
                crate::types::metadata_session::ChildMetadataTheapPageSession::new(
                    child,
                    theap,
                    heap,
                    pending_os_release,
                    page_engine,
                    metadata_pages_may_exist,
                ).and_then(|session| session.with_fresh_initialization_slot(pending_fresh_initialization))
                .and_then(|session| session.with_live_page_validity_slot(pending_live_page_validity))
            }
            .ok_or(ChildMetadataPageEngineError::SessionNotReady)?;
            let backing = crate::page_backing::ChildMetadataArenaBacking::new(pair);
            // SAFETY: exact child/context ownership, detached-Theap lock, and
            // canonical PageMap lifecycle are held through the engine call.
            let mut engine = unsafe {
                crate::single_thread::ChildMetadataPageAllocator::activate_child_metadata(
                    session, backing, page_map,
                )
            };
            let value = operation(child, &mut engine);
            let result = if let Err(engine) = engine.finish_operation() {
                // Its Drop transfers an accounted OS retry owner and latches
                // any other unfinished page-engine state in this child.
                drop(engine);
                Err(ChildMetadataPageEngineError::EngineRetained)
            } else {
                Ok(value)
            };
            if let Err(error) = page_lifecycle.finish() {
                *page_engine = ChildPageEngineState::Poisoned;
                return Err(ChildMetadataPageEngineError::PageMapLifecycle(error));
            }
            result
        })
        .ok_or(ChildMetadataPageEngineError::SessionNotReady)?;
        result
    }

    /// Creates the first ordinary child-thread TLD and regular Theap from
    /// the child's own metadata-Theap, then attaches that Theap to the child
    /// main Heap and TLD. Its registration records the live member; ordinary
    /// destruction refuses it. Permanent quiescent destruction must retain
    /// the image for orphan completion and forbid further allocation.
    ///
    /// # Safety
    /// The caller owns the current thread's TLD lifecycle, and no other
    /// operation on this child runs concurrently. The returned owner remains
    /// the exclusive route for its TLD/Theap until teardown.
    pub(crate) unsafe fn begin_child_thread(
        &mut self,
        binding: crate::process_init::ProcessMainBackingBinding,
    ) -> Result<ChildThreadOwner, ChildThreadStartFailure> {
        // SAFETY: this direct compatibility transition owns the current
        // thread's candidate and excludes concurrent child operations.
        let mut owner = unsafe { self.allocate_child_thread_owner(binding) }?;
        let tld_pointer = owner.tld.as_ref().expect("stored child TLD block").pointer;
        let theap_pointer = owner.theap.as_ref().expect("stored child Theap block").pointer;
        let initialize = self.heap_storage.as_mut().and_then(|storage| storage.with_heap(|mut heap| {
            // SAFETY: the original candidate blocks remain exclusively owned
            // and no image or list projection overlaps this initialization.
            let tld = unsafe { &mut *tld_pointer.as_ptr().cast::<ThreadLocalData>() };
            let theap = unsafe { &mut *theap_pointer.as_ptr().cast::<Theap>() };
            let memory = MemoryId::malloc(theap_pointer.as_ptr(), size_of::<Theap>(), true);
            unsafe {
                if !theap.set_dynamic_metadata_memid(memory) {
                    return Err(crate::types::TheapDynamicInitError::InvalidInput);
                }
                theap.initialize_dynamic_metadata(heap.as_mut().get_unchecked_mut(), tld,
                    crate::types::TheapPageMode::OrdinaryAbandoning)
            }
        }));
        match initialize {
            Some(Ok(())) => {
                owner.state = ChildThreadOwnerState::Attached;
                owner.with_child_image(|image| image.get_ref().identity().record_statistics_theap_linked());
                Ok(owner)
            }
            Some(Err(error)) => {
                owner.state = ChildThreadOwnerState::Terminal;
                Err(ChildThreadStartFailure::Retained { owner,
                    error: ChildThreadStartError::TheapInitialization(error) })
            }
            None => {
                owner.state = ChildThreadOwnerState::Terminal;
                Err(ChildThreadStartFailure::Retained { owner,
                    error: ChildThreadStartError::InvalidTransition })
            }
        }
    }

    /// Allocates and prepares the original child-thread images without
    /// publishing a Heap predicate or retaining an image projection.
    ///
    /// # Safety
    /// The caller retains this child and the actual current-thread operation
    /// across every option and warning callback. No competing child or TLS
    /// lifecycle operation may retire the resulting candidate or registration.
    #[cfg(target_arch = "x86_64")]
    pub(crate) unsafe fn prepare_child_thread_initialization(
        &mut self, binding: crate::process_init::ProcessMainBackingBinding,
    ) -> Result<PendingChildThreadInitialization, ChildThreadStartFailure> {
        let mut destination = ChildThreadInitializationStorage::vacant();
        // SAFETY: the legacy keeper route retains this child's actual
        // admission and consumes the same original candidate exactly once.
        match unsafe { self.prepare_child_thread_initialization_in(binding, &mut destination) } {
            ChildThreadPreparationOutcome::Prepared(phase) => Ok(PendingChildThreadInitialization {
                keeper: ChildThreadInitializationOwner(destination.take_owner()), phase,
            }),
            ChildThreadPreparationOutcome::Rejected(error) => Err(ChildThreadStartFailure::Rejected(error)),
            ChildThreadPreparationOutcome::Retained(error) => Err(ChildThreadStartFailure::Retained {
                owner: destination.take_owner(), error,
            }),
        }
    }

    /// Prepares the original images in caller-retained storage, leaving only
    /// the typed source phase outside that slot during callback windows.
    ///
    /// # Safety
    /// The caller retains the original child and current-thread admission
    /// through callbacks and completion. Destination is vacant and exclusively
    /// borrowed throughout; no competing lifecycle may consume its images.
    #[cfg(target_arch = "x86_64")]
    pub(crate) unsafe fn prepare_child_thread_initialization_in(
        &mut self, binding: crate::process_init::ProcessMainBackingBinding,
        destination: &mut ChildThreadInitializationStorage,
    ) -> ChildThreadPreparationOutcome {
        // SAFETY: the caller owns this vacant slot and exact child operation.
        match unsafe { self.allocate_child_thread_owner_into(binding, destination) } {
            ChildThreadOwnerInitializationOutcome::Ready => {},
            ChildThreadOwnerInitializationOutcome::Rejected(error) => return ChildThreadPreparationOutcome::Rejected(error),
            ChildThreadOwnerInitializationOutcome::Retained(error) => return ChildThreadPreparationOutcome::Retained(error),
        }
        let owner = destination.owner_mut();
        let theap = owner.theap.as_ref().expect("stored child Theap block").pointer.cast::<Theap>();
        let tld = owner.tld.as_ref().expect("stored child TLD block").pointer.cast::<ThreadLocalData>();
        // SAFETY: this owner retains the original allocated blocks and
        // registration; the caller's actual child admission retains its Heap.
        let prepared = unsafe {
            // The metadata allocation supplies zeroed storage. Establish the
            // empty Theap image before the typed initializer validates it.
            Theap::write_empty_at(theap);
            if (*theap.as_ptr()).set_dynamic_metadata_memid(
                MemoryId::malloc(theap.as_ptr().cast(), size_of::<Theap>(), true)) {
                Theap::prepare_initialization_at(theap, owner.heap, tld,
                    crate::types::TheapInitializationKind::Dynamic {
                        page_mode: crate::types::TheapPageMode::OrdinaryAbandoning,
                        tld_may_have_theaps: false,
                    })
            } else {
                Err(crate::types::TheapMainStaticInitError::InvalidInput)
            }
        };
        match prepared {
            Ok(phase) => ChildThreadPreparationOutcome::Prepared(phase),
            Err(error) => ChildThreadPreparationOutcome::Retained(destination.retain(error)),
        }
    }

    /// Allocates and registers the candidate while the real child operation
    /// owns its metadata entry. The returned owner remains unpublished.
    ///
    /// # Safety
    /// The caller owns current-thread TLS admission and excludes competing
    /// child operations until the allocated blocks and registration are retained.
    #[cfg(target_arch = "x86_64")]
    unsafe fn allocate_child_thread_owner(
        &mut self, binding: crate::process_init::ProcessMainBackingBinding,
    ) -> Result<ChildThreadOwner, ChildThreadStartFailure> {
        let mut destination = ChildThreadInitializationStorage::vacant();
        // SAFETY: this local destination is vacant and exclusively retained;
        // each initialized outcome moves its exact owner once into the result.
        match unsafe { self.allocate_child_thread_owner_into(binding, &mut destination) } {
            ChildThreadOwnerInitializationOutcome::Ready => Ok(destination.take_owner()),
            ChildThreadOwnerInitializationOutcome::Rejected(error) => Err(ChildThreadStartFailure::Rejected(error)),
            ChildThreadOwnerInitializationOutcome::Retained(error) => Err(ChildThreadStartFailure::Retained {
                owner: destination.take_owner(), error,
            }),
        }
    }

    /// Constructs one child owner in caller-retained vacant storage.
    ///
    /// # Safety
    /// The caller owns this current-thread child operation and exclusive
    /// aligned writable vacant storage for `ChildThreadOwner` through return.
    /// Ready and Retained leave exactly one initialized owner there; the
    /// caller must consume or retain it. Rejected leaves vacant storage that
    /// must not be read or dropped as an owner. No destination projection may
    /// overlap this call or a metadata callback.
    #[cfg(target_arch = "x86_64")]
    unsafe fn allocate_child_thread_owner_into(
        &mut self,
        binding: crate::process_init::ProcessMainBackingBinding,
        destination: &mut ChildThreadInitializationStorage,
    ) -> ChildThreadOwnerInitializationOutcome {
        assert_eq!(destination.state, ChildThreadInitializationStorageState::Vacant, "child owner destination is vacant");
        if self.stage != ChildMainHeapStage::HeapReady
            || self.page_engine != ChildPageEngineState::Active
            || self.pending_os_release.is_some() || (self.pending_fresh_initialization.is_some() || self.pending_live_page_validity.is_some())
        {
            return ChildThreadOwnerInitializationOutcome::Rejected(ChildThreadStartError::InvalidTransition);
        }
        let thread = match crate::compiler_tls::current_thread_identity() {
            Some(thread) => thread,
            None => return ChildThreadOwnerInitializationOutcome::Rejected(ChildThreadStartError::CurrentThread),
        };
        let numa = match i32::try_from(crate::os::numa_node()) {
            Ok(numa) => numa,
            Err(_) => return ChildThreadOwnerInitializationOutcome::Rejected(ChildThreadStartError::NumaNode),
        };
        let (Some(heap), Some(image)) = (
            self.heap_storage.as_ref().map(ChildHeapStorage::pointer_for_identity),
            self.context.with_image(|child| NonNull::from(child.get_ref())),
        ) else {
            return ChildThreadOwnerInitializationOutcome::Rejected(ChildThreadStartError::InvalidTransition);
        };
        let owner_pointer = destination.owner.as_mut_ptr();
        // SAFETY: all scalar admission checks precede this first write. The
        // caller owns vacant aligned storage; each field is initialized once
        // before any complete-owner projection or metadata allocation.
        unsafe {
            core::ptr::addr_of_mut!((*owner_pointer).image).write(image);
            core::ptr::addr_of_mut!((*owner_pointer).heap).write(heap);
            core::ptr::addr_of_mut!((*owner_pointer).parent_subprocess).write(self.context.parent_subprocess);
            core::ptr::addr_of_mut!((*owner_pointer).config).write(self.context.config);
            core::ptr::addr_of_mut!((*owner_pointer).pending_os_release).write(None);
            core::ptr::addr_of_mut!((*owner_pointer).pending_fresh_initialization).write(None);
            core::ptr::addr_of_mut!((*owner_pointer).pending_live_page_validity).write(None);
            core::ptr::addr_of_mut!((*owner_pointer).page_engine).write(ChildPageEngineState::Active);
            core::ptr::addr_of_mut!((*owner_pointer).thread_locals).write(None);
            core::ptr::addr_of_mut!((*owner_pointer).pending_thread_locals).write(None);
            core::ptr::addr_of_mut!((*owner_pointer).heap_theap_pending_os_release).write(None);
            core::ptr::addr_of_mut!((*owner_pointer).heap_theap_pending_fresh_initialization).write(None);
            core::ptr::addr_of_mut!((*owner_pointer).heap_theap_pending_live_page_validity).write(None);
            core::ptr::addr_of_mut!((*owner_pointer).tld).write(None);
            core::ptr::addr_of_mut!((*owner_pointer).theap).write(None);
            core::ptr::addr_of_mut!((*owner_pointer).registration).write(None);
            core::ptr::addr_of_mut!((*owner_pointer).thread).write(thread);
            core::ptr::addr_of_mut!((*owner_pointer).sequence).write(ThreadSequence::from_previous_total_count(0));
            core::ptr::addr_of_mut!((*owner_pointer).state).write(ChildThreadOwnerState::Starting);
        }

        // Every field is initialized before callbacks may unwind. The
        // enclosing actual admission guard can now retain this exact owner.
        destination.state = ChildThreadInitializationStorageState::Owned;
        let mut allocation_outcome = None;
        let page_result = self.with_metadata_page_engine(binding, |child, engine| {
            let outcome = Self::allocate_child_thread_images(child, engine, thread, numa);
            allocation_outcome = Some(outcome);
        });
        // SAFETY: every owner field is initialized above, and all child
        // metadata projections have ended before this exclusive observation.
        let owner = unsafe { &mut *owner_pointer };
        if let Err(error) = page_result {
            return match allocation_outcome {
                Some(ChildThreadAllocationOutcome::Ready { tld, theap, registration, sequence }) => {
                    owner.tld = Some(tld);
                    owner.theap = Some(theap);
                    owner.registration = Some(registration);
                    owner.sequence = sequence;
                    owner.state = ChildThreadOwnerState::Terminal;
                    ChildThreadOwnerInitializationOutcome::Retained(ChildThreadStartError::PageEngine(error))
                }
                Some(ChildThreadAllocationOutcome::Retained { tld, registration, sequence, error: _ }) => {
                    owner.tld = Some(tld);
                    owner.registration = registration;
                    owner.sequence = sequence;
                    owner.state = ChildThreadOwnerState::Terminal;
                    ChildThreadOwnerInitializationOutcome::Retained(ChildThreadStartError::PageEngine(error))
                }
                Some(ChildThreadAllocationOutcome::Rejected(_)) | None => {
                    let outcome = ChildThreadOwnerInitializationOutcome::reject_cold_owner(owner, ChildThreadStartError::PageEngine(error));
                    destination.state = ChildThreadInitializationStorageState::Vacant;
                    outcome
                }
            };
        }

        match allocation_outcome.expect("successful child page session records its allocation outcome") {
            ChildThreadAllocationOutcome::Rejected(error) => {
                let outcome = ChildThreadOwnerInitializationOutcome::reject_cold_owner(owner, error);
                destination.state = ChildThreadInitializationStorageState::Vacant;
                outcome
            }
            ChildThreadAllocationOutcome::Retained { tld, registration, sequence, error } => {
                owner.tld = Some(tld);
                owner.registration = registration;
                owner.sequence = sequence;
                owner.state = ChildThreadOwnerState::Terminal;
                ChildThreadOwnerInitializationOutcome::Retained(error)
            }
            ChildThreadAllocationOutcome::Ready { tld, theap, registration, sequence } => {
                owner.tld = Some(tld);
                owner.theap = Some(theap);
                owner.registration = Some(registration);
                owner.sequence = sequence;
                ChildThreadOwnerInitializationOutcome::Ready
            }
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
    unsafe fn allocate_child_thread_owner(
        &mut self,
        binding: crate::process_init::ProcessMainBackingBinding,
    ) -> Result<ChildThreadOwner, ChildThreadStartFailure> {
        if self.stage != ChildMainHeapStage::HeapReady
            || self.page_engine != ChildPageEngineState::Active
            || self.pending_os_release.is_some() || (self.pending_fresh_initialization.is_some() || self.pending_live_page_validity.is_some())
        {
            return Err(ChildThreadStartFailure::Rejected(
                ChildThreadStartError::InvalidTransition,
            ));
        }
        let thread = crate::compiler_tls::current_thread_identity().ok_or_else(|| {
            ChildThreadStartFailure::Rejected(ChildThreadStartError::CurrentThread)
        })?;
        let numa = i32::try_from(crate::os::numa_node()).map_err(|_| {
            ChildThreadStartFailure::Rejected(ChildThreadStartError::NumaNode)
        })?;
        let (Some(heap), Some(image)) = (
            self.heap_storage.as_ref().map(ChildHeapStorage::pointer_for_identity),
            self.context.with_image(|child| NonNull::from(child.get_ref())),
        ) else {
            return Err(ChildThreadStartFailure::Rejected(
                ChildThreadStartError::InvalidTransition,
            ));
        };
        let mut owner = ChildThreadOwner {
            image,
            heap,
            parent_subprocess: self.context.parent_subprocess,
            config: self.context.config,
            pending_os_release: None,
            pending_fresh_initialization: None,
            pending_live_page_validity: None,
            page_engine: ChildPageEngineState::Active,
            thread_locals: None,
            #[cfg(target_arch = "x86_64")]
            pending_thread_locals: None,
            heap_theap_pending_os_release: None,
            heap_theap_pending_fresh_initialization: None,
            heap_theap_pending_live_page_validity: None,
            tld: None,
            theap: None,
            registration: None,
            thread,
            sequence: ThreadSequence::from_previous_total_count(0),
            state: ChildThreadOwnerState::Starting,
        };

        let mut allocation_outcome = None;
        let page_result = self.with_metadata_page_engine(binding, |child, engine| {
            let outcome = Self::allocate_child_thread_images(child, engine, thread, numa);
            allocation_outcome = Some(outcome);
        });
        if let Err(error) = page_result {
            return match allocation_outcome {
                Some(ChildThreadAllocationOutcome::Ready { tld, theap, registration, sequence }) => {
                    owner.tld = Some(tld);
                    owner.theap = Some(theap);
                    owner.registration = Some(registration);
                    owner.sequence = sequence;
                    owner.state = ChildThreadOwnerState::Terminal;
                    Err(ChildThreadStartFailure::Retained {
                        owner,
                        error: ChildThreadStartError::PageEngine(error),
                    })
                }
                Some(ChildThreadAllocationOutcome::Retained { tld, registration, sequence, error: _ }) => {
                    owner.tld = Some(tld);
                    owner.registration = registration;
                    owner.sequence = sequence;
                    owner.state = ChildThreadOwnerState::Terminal;
                    Err(ChildThreadStartFailure::Retained {
                        owner,
                        error: ChildThreadStartError::PageEngine(error),
                    })
                }
                Some(ChildThreadAllocationOutcome::Rejected(_)) | None => {
                    Err(ChildThreadStartFailure::Rejected(
                        ChildThreadStartError::PageEngine(error),
                    ))
                }
            };
        }

        match allocation_outcome.expect("successful child page session records its allocation outcome") {
            ChildThreadAllocationOutcome::Rejected(error) => {
                Err(ChildThreadStartFailure::Rejected(error))
            }
            ChildThreadAllocationOutcome::Retained { tld, registration, sequence, error } => {
                owner.tld = Some(tld);
                owner.registration = registration;
                owner.sequence = sequence;
                owner.state = ChildThreadOwnerState::Terminal;
                Err(ChildThreadStartFailure::Retained { owner, error })
            }
            ChildThreadAllocationOutcome::Ready { tld, theap, registration, sequence } => {
                owner.tld = Some(tld);
                owner.theap = Some(theap);
                owner.registration = Some(registration);
                owner.sequence = sequence;
                Ok(owner)
            }
        }
    }

    fn allocate_child_thread_images(
        child: Pin<&crate::subproc::ChildSubprocessImage>,
        engine: &mut crate::single_thread::ChildMetadataPageAllocator<'_, '_, 'static>,
        thread: LiveThreadId,
        numa: i32,
    ) -> ChildThreadAllocationOutcome {
        let ticket = match child.issue_metadata_thread_ticket() {
            Ok(ticket) => ticket,
            Err(error) => return ChildThreadAllocationOutcome::Rejected(
                ChildThreadStartError::ChildNotReady(error),
            ),
        };
        let sequence = ticket.sequence();
        // `mi_tld_create` requests the source `sizeof(mi_tld_t)`.
        let Some(tld_pointer) = engine.allocate_zeroed(crate::types::SOURCE_THREAD_LOCAL_DATA_SIZE) else {
            return ChildThreadAllocationOutcome::Rejected(ChildThreadStartError::TldAllocation);
        };
        let tld_block = ChildMetadataImageBlock {
            pointer: tld_pointer,
            size: crate::types::SOURCE_THREAD_LOCAL_DATA_SIZE,
        };
        let tld_memid = MemoryId::malloc(
            tld_pointer.as_ptr(),
            tld_block.size,
            true,
        );
        // SAFETY: the child metadata page engine returned this exact fresh
        // zeroed, aligned TLD block; no typed projection exists yet.
        unsafe {
            ThreadLocalData::write_subprocess_attached_no_theap_at(
                tld_pointer.as_ptr().cast(),
                thread,
                sequence,
                || numa,
                child.get_ref().identity(),
                tld_memid,
            );
        }
        // SAFETY: the raw writer above completed every TLD field before this
        // short typed read; the allocation token remains locally owned.
        let tld = unsafe { tld_pointer.cast::<ThreadLocalData>().as_ref() };
        // SAFETY: the lease travels only in this outcome and then in the
        // `ChildThreadOwner` holding the issuing context owner's unique
        // borrow, which it keeps until release or terminal retention.
        let registration = match unsafe { ticket.activate_after_initialized_tld(tld, thread) } {
            Ok(registration) => registration,
            Err(error) => {
                return ChildThreadAllocationOutcome::Retained {
                    tld: tld_block,
                    registration: None,
                    sequence,
                    error: ChildThreadStartError::ChildNotReady(error),
                };
            }
        };
        let Some(theap_pointer) = engine.allocate_zeroed(size_of::<Theap>()) else {
            // This mirrors `mi_thread_init_with_heap`: a failed regular
            // Theap allocation tears down the already registered TLD.
            // Preserve ownership if lock teardown or the exact child free
            // fails after that irreversible source transition.
            let tld = unsafe { &mut *tld_pointer.as_ptr().cast::<ThreadLocalData>() };
            // `mi_tld_free` decrements the subprocess live count before
            // invalidating the thread identity and destroying its lock.
            // SAFETY: this runs inside the issuing owner's live `child`
            // image projection, from which the lease was just minted. The TLD
            // never had a Theap attached, and its identity is still valid.
            unsafe { registration.release() };
            tld.invalidate_subprocess_attached_no_theap_for_teardown();
            if tld.quiesce_theap_list_lock_for_teardown().is_err() {
                return ChildThreadAllocationOutcome::Retained {
                    tld: tld_block,
                    registration: None,
                    sequence,
                    error: ChildThreadStartError::InvalidTransition,
                };
            }
            return match unsafe { engine.free(tld_pointer) } {
                Ok(()) => ChildThreadAllocationOutcome::Rejected(ChildThreadStartError::TheapAllocation),
                Err(error) => ChildThreadAllocationOutcome::Retained {
                    tld: tld_block,
                    registration: None,
                    sequence,
                    error: ChildThreadStartError::TldRelease(error),
                },
            };
        };
        let theap_block = ChildMetadataImageBlock {
            pointer: theap_pointer,
            size: size_of::<Theap>(),
        };
        // The source allocation and ticket order is observable: child seq 0
        // is metadata-backed, the TLD becomes live before `_mi_theap_alloc`.
        ChildThreadAllocationOutcome::Ready {
            tld: tld_block,
            theap: theap_block,
            registration,
            sequence,
        }
    }

    /// Ends the child metadata page lifetime after all child-owned metadata
    /// blocks have been freed. A false result means live pages remain; an
    /// ambiguous source transition latches the owner so teardown cannot pass.
    pub(crate) fn finish_metadata_pages(
        &mut self,
        binding: crate::process_init::ProcessMainBackingBinding,
    ) -> Result<bool, ChildMetadataPageEngineError> {
        self.with_metadata_page_engine(binding, |_child, engine| engine.finish_pages_in_place())
    }

    /// Source-ordered child destroy prefix: while registry admission still
    /// exists, either unlink directly when this metadata Theap has no pages
    /// left, or create its page session, unlink the child, and detach every
    /// metadata page, live blocks included, from its queues and the process
    /// PageMap without releasing it. As in source, those pages are released
    /// only with the child arenas, after the statistics merge. This covers
    /// only this metadata-Theap's pages; the caller remains responsible for
    /// every other child Heap/Theap page.
    ///
    /// # Safety
    /// All child threads and users are quiescent, no metadata block of the
    /// child is used again, and `registry` is the
    /// exact source registry that admitted this child. Setup errors before
    /// registry mutation leave this owner registered and retryable. An
    /// ambiguous unlink or post-unlink error retains this owner with the
    /// context and remaining capabilities intact; only an already-accounted
    /// raw unmap failure has an explicit retry transition.
    pub(crate) unsafe fn unlink_registry_and_finish_metadata_pages(
        &mut self,
        registry: &'static crate::subproc::registry::SourceSubprocessRegistry,
        binding: crate::process_init::ProcessMainBackingBinding,
    ) -> Result<(), ChildMetadataPageEngineError> {
        if self.stage != ChildMainHeapStage::HeapReady {
            return Err(ChildMetadataPageEngineError::InvalidTransition);
        }
        // Source destroys a subprocess even while its threads are live; that
        // leaves their TLDs and default Theaps dangling, so refuse instead.
        // Only process destruction takes that route, through
        // `unlink_registry_and_detach_pages_terminal`.
        if self.context.with_image(|child| child.identity().live_thread_count()) != Some(0) {
            return Err(ChildMetadataPageEngineError::LiveThreads);
        }
        // SAFETY: forwarded obligations; no thread belongs to the child.
        unsafe { self.unlink_registry_and_detach_metadata_pages(registry, binding) }
    }

    /// Process-destruction form of
    /// [`Self::unlink_registry_and_finish_metadata_pages`], for a child that
    /// threads may still belong to, as source `_mi_subprocs_unsafe_destroy_all`
    /// destroys it. First every page of each child-thread Theap on the child
    /// main Heap is detached from its queues and the process PageMap, live
    /// blocks included and none released, exactly as the metadata pages are
    /// next; the pages go with the child arenas. Those threads' TLDs,
    /// Theaps, and compiler-TLS roots then name child memory that no longer
    /// exists; process destruction never reopens the native entry points
    /// that could reach them.
    ///
    /// A member page that cannot be detached (an OS-backed page, or an
    /// unprovable span) leaves this owner terminal and the child registered.
    ///
    /// # Safety
    /// Permanent terminal quiescence: no thread, client, or producer reaches
    /// the child again, no child operation or registry user runs, and
    /// `registry` admitted the child.
    pub(crate) unsafe fn unlink_registry_and_detach_pages_terminal(
        &mut self,
        registry: &'static crate::subproc::registry::SourceSubprocessRegistry,
        binding: crate::process_init::ProcessMainBackingBinding,
    ) -> Result<(), ChildMetadataPageEngineError> {
        if self.stage != ChildMainHeapStage::HeapReady {
            return Err(ChildMetadataPageEngineError::InvalidTransition);
        }
        // SAFETY: forwarded terminal quiescence.
        if let Err(error) = unsafe { self.detach_member_pages_terminal(binding) } {
            self.stage = ChildMainHeapStage::Terminal;
            return Err(error);
        }
        // SAFETY: forwarded obligations.
        unsafe { self.unlink_registry_and_detach_metadata_pages(registry, binding) }
    }

    /// Detaches the pages of every child-thread Theap on the child main
    /// Heap; see [`Self::unlink_registry_and_detach_pages_terminal`].
    ///
    /// # Safety
    /// As for [`Self::unlink_registry_and_detach_pages_terminal`].
    unsafe fn detach_member_pages_terminal(
        &mut self,
        binding: crate::process_init::ProcessMainBackingBinding,
    ) -> Result<(), ChildMetadataPageEngineError> {
        if !binding.is_active()
            || !binding.is_allocation_ready()
            || binding.process().main_subprocess().is_none_or(|parent| {
                !core::ptr::eq(parent, self.context.parent_subprocess)
            })
            || binding.page_map().memory_config().ok() != Some(self.context.config)
        {
            return Err(ChildMetadataPageEngineError::InvalidTransition);
        }
        let heap = self.main_heap_pointer().ok_or(ChildMetadataPageEngineError::InvalidTransition)?;
        let metadata_theap = self.context.metadata_theap.as_ref()
            .and_then(ChildMetadataAllocation::dynamic_theap_pointer);
        let mut result = Ok(());
        let visited = self.context.with_image(|child| {
            // SAFETY: terminal quiescence keeps the Theap list unchanged and
            // every listed Theap and TLD allocated for this walk; the visitor
            // below changes page queues only, never either list.
            unsafe {
                (*heap.as_ptr()).visit_theaps_quiescent(|theap, tld| {
                    if Some(theap) == metadata_theap {
                        return true;
                    }
                    // SAFETY: forwarded terminal quiescence.
                    result = unsafe { detach_child_thread_pages_terminal(child, binding, heap, theap, tld) };
                    result.is_ok()
                })
            }
        });
        match visited {
            Some(_) => result,
            None => Err(ChildMetadataPageEngineError::InvalidTransition),
        }
    }

    /// The registry unlink and metadata-page detach shared by the ordinary
    /// and terminal destroy prefixes.
    ///
    /// # Safety
    /// As for [`Self::unlink_registry_and_finish_metadata_pages`], except
    /// that under terminal quiescence threads may still belong to the child.
    unsafe fn unlink_registry_and_detach_metadata_pages(
        &mut self,
        registry: &'static crate::subproc::registry::SourceSubprocessRegistry,
        binding: crate::process_init::ProcessMainBackingBinding,
    ) -> Result<(), ChildMetadataPageEngineError> {
        if self.page_engine == ChildPageEngineState::RetryComplete {
            if self.pending_os_release.is_some() || (self.pending_fresh_initialization.is_some() || self.pending_live_page_validity.is_some()) || self.metadata_pages_may_exist {
                return Err(ChildMetadataPageEngineError::InvalidTransition);
            }
            let result = self.context.with_image(|child| {
                // SAFETY: forwarded exact-registry and child-quiescence
                // obligations; this owner proves there are no metadata pages
                // or pending raw page releases left in the child context.
                unsafe { registry.unlink_child_terminal(child.as_ref().get_ref()) }
            }).unwrap_or(Err(
                crate::subproc::registry::SourceSubprocessRegistryError::InvalidMembership,
            ));
            self.stage = if result.is_ok() {
                ChildMainHeapStage::RegistryUnlinked
            } else {
                ChildMainHeapStage::Terminal
            };
            return result.map_err(ChildMetadataPageEngineError::Registry);
        }
        let mut registry_attempted = false;
        let mut registry_unlinked = false;
        let result = self.with_metadata_page_engine(binding, |child, engine| {
            // SAFETY: forwarded quiescence/exact-registry contract; the child
            // page pair was validated while the registry edge was still live.
            registry_attempted = true;
            let unlink = unsafe { registry.unlink_child_terminal(child.get_ref()) };
            if let Err(error) = unlink {
                return Err(ChildMetadataPageEngineError::Registry(error));
            }
            registry_unlinked = true;
            // SAFETY: the registry edge is gone and the caller guarantees
            // that no thread, client, or producer reaches the child; source
            // releases these pages, and those that finished threads
            // abandoned, only with the child arenas.
            Ok(unsafe {
                engine.detach_pages_for_subprocess_destroy()
                    && engine.unregister_arena_pages_for_subprocess_destroy(
                        child.get_ref().identity().arena_backing().registry(),
                    )
            })
        });
        if registry_unlinked {
            self.stage = ChildMainHeapStage::RegistryUnlinked;
        }
        match result {
            Err(error) => {
                if registry_unlinked && self.page_engine == ChildPageEngineState::Active {
                    self.page_engine = ChildPageEngineState::Poisoned;
                }
                if registry_attempted && !registry_unlinked {
                    self.stage = ChildMainHeapStage::Terminal;
                }
                Err(error)
            }
            Ok(Err(error)) => {
                self.stage = ChildMainHeapStage::Terminal;
                Err(error)
            }
            Ok(Ok(true)) => Ok(()),
            Ok(Ok(false)) => {
                self.page_engine = ChildPageEngineState::Poisoned;
                Err(ChildMetadataPageEngineError::MetadataPagesRemain)
            }
        }
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
        _config: MemoryConfig,
    ) -> Result<(), ChildMetadataTheapError> {
        if self.stage != ChildMainHeapStage::Registered || self.heap_storage.is_none() {
            return Err(ChildMetadataTheapError::Metadata(MetaError::InitializationRetained));
        }
        let parent_metadata = self.context.parent_metadata;
        let Self { context, heap_storage, .. } = self;
        let heap = heap_storage.as_mut().expect("checked child Heap allocation");
        let memory = heap.memory_id();
        let initialized = heap.with_heap(|mut heap_image| {
            context.with_image(|mut child_image| unsafe {
                heap_image.as_mut().initialize_child_main(child_image, memory)
            })
        }).flatten();
        match initialized {
            Some(Ok(())) => {}
            Some(Err(_)) => {
                self.stage = ChildMainHeapStage::Terminal;
                return Err(ChildMetadataTheapError::Metadata(MetaError::InitializationRetained));
            }
            None => {
                return Err(ChildMetadataTheapError::Metadata(MetaError::InitializationRetained));
            },
        }
        let attached = heap.with_heap(|mut heap_image| {
            context.with_lease(|mut lease| {
                lease.with_metadata_theap(|theap| unsafe {
                    parent_metadata.initialize_child_metadata_theap(
                        heap_image.as_mut().get_unchecked_mut(), theap,
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
            .and_then(ChildMetadataAllocation::dynamic_theap_pointer) else {
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
        if self.stage != ChildMainHeapStage::HeapReady || self.metadata_pages_may_exist {
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

    /// Source `_mi_heap_detach_theaps` and `mi_heap_free_theaps`
    /// (`theap.c:381-411`, `heap.c:162-182`) for the child-thread Theaps
    /// still on the child main Heap at process destruction: each leaves the
    /// Heap list and its TLD's list, merges its statistics into the Heap, and
    /// drops the Heap's reference as `_mi_theap_decref` does: it is counted
    /// out of the child's `theaps` statistic only when that was its last
    /// reference (the thread's cached entry may hold another, after the
    /// nested page-record allocation of `mi_arena_pages_alloc` moved the
    /// cache to it). The Theap and TLD blocks are not freed one by one: they are
    /// live child metadata blocks, released with the child arenas. The TLDs
    /// keep their live registration, as source never runs `mi_tld_free` for
    /// them. The metadata Theap is detached next, as before.
    ///
    /// Any list failure leaves this owner terminal.
    ///
    /// # Safety
    /// Registry unlink and the terminal page detach succeeded, and permanent
    /// terminal quiescence excludes every other Heap, TLD, and Theap user.
    pub(crate) unsafe fn detach_child_thread_theaps_terminal(
        &mut self,
    ) -> Result<(), ChildMainHeapReleaseError> {
        if self.stage != ChildMainHeapStage::RegistryUnlinked {
            return Err(ChildMainHeapReleaseError::InvalidTransition);
        }
        let metadata_theap = self.context.metadata_theap.as_ref()
            .and_then(ChildMetadataAllocation::dynamic_theap_pointer);
        loop {
            let Some(storage) = self.heap_storage.as_mut() else {
                self.stage = ChildMainHeapStage::Terminal;
                return Err(ChildMainHeapReleaseError::InvalidTransition);
            };
            let detached = storage.with_heap(|mut heap| {
                // SAFETY: terminal quiescence (caller contract).
                let Some((theap, tld)) = (unsafe { heap.first_theap_other_than_quiescent(metadata_theap) }) else {
                    return Ok(None);
                };
                let Some(tld) = NonNull::new(tld) else { return Err(()) };
                // SAFETY: the listed TLD is allocated and, under quiescence,
                // exclusively ours; no other reference to it exists.
                let tld = unsafe { &mut *tld.as_ptr() };
                // SAFETY: the Heap image is exclusively ours under quiescence.
                let heap = unsafe { heap.as_mut().get_unchecked_mut() };
                tld.detach_one_theap_from_heap(heap, theap.as_ptr()).map_err(|_| ())?;
                tld.detach_one_theap_from_tld(theap.as_ptr()).map_err(|_| ())?;
                // heap.c:173-181, then `_mi_theap_decref` (theap.c:350-370):
                // the Theap is counted out only when that was its last
                // reference; a thread's cached entry can still hold one.
                // SAFETY: the detached Theap stays allocated in child metadata.
                heap.merge_detached_theap_statistics(unsafe { theap.as_ref() });
                // SAFETY: as above; the reference-count field is atomic.
                let last = unsafe { Theap::decref_at(theap) && !Theap::is_detached_at(theap) };
                Ok(Some(last))
            });
            match detached {
                Some(Ok(Some(last))) => {
                    if last {
                        self.context.with_image(|image| {
                            image.get_ref().identity().record_statistics_theap_unlinked();
                        });
                    }
                }
                Some(Ok(None)) => return Ok(()),
                Some(Err(())) | None => {
                    self.stage = ChildMainHeapStage::Terminal;
                    return Err(ChildMainHeapReleaseError::InvalidTransition);
                }
            }
        }
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
        _parent_metadata: Pin<&'static MetaAllocator>,
        _config: MemoryConfig,
    ) -> Result<(), ChildMetadataTheapError> {
        if self.stage != ChildMainHeapStage::RegistryUnlinked
            || self.metadata_pages_may_exist
            || self.pending_os_release.is_some() || (self.pending_fresh_initialization.is_some() || self.pending_live_page_validity.is_some())
            || !self.page_engine.permits_teardown() {
            return Err(ChildMetadataTheapError::Metadata(MetaError::InitializationRetained));
        }
        let parent_metadata = self.context.parent_metadata;
        let Some(heap_storage) = self.heap_storage.as_mut() else {
            return Err(ChildMetadataTheapError::Metadata(MetaError::InitializationRetained));
        };
        let Some(metadata_theap) = self.context.metadata_theap.as_ref()
            .and_then(ChildMetadataAllocation::dynamic_theap_pointer) else {
            return Err(ChildMetadataTheapError::Metadata(MetaError::InitializationRetained));
        };
        let result = heap_storage.with_heap(|mut heap| unsafe {
            parent_metadata.detach_child_metadata_theap(
                heap.as_mut().get_unchecked_mut(), metadata_theap,
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
        if self.stage != ChildMainHeapStage::TheapDetached || self.pending_os_release.is_some() || (self.pending_fresh_initialization.is_some() || self.pending_live_page_validity.is_some())
            || !self.page_engine.permits_teardown() {
            return Err(ChildMainHeapReleaseError::InvalidTransition);
        }
        let Some(heap) = self.heap_storage.as_ref() else {
            return Err(ChildMainHeapReleaseError::InvalidTransition);
        };
        let metadata_pointer = self.context.metadata_theap.as_ref()
            .and_then(ChildMetadataAllocation::dynamic_theap_pointer);
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
        // heap.c:171-172: `mi_heap_free_theaps` merges each detached Theap's
        // statistics into its Heap before `_mi_theap_decref` frees it.
        let merged = match (self.heap_storage.as_mut(), metadata_theap.dynamic_theap_mut()) {
            (Some(heap), Some(theap)) => heap
                .with_heap(|heap| heap.merge_detached_theap_statistics(theap))
                .is_some(),
            _ => false,
        };
        if !merged {
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
        if self.stage != ChildMainHeapStage::MetadataTheapReleased || self.pending_os_release.is_some() || (self.pending_fresh_initialization.is_some() || self.pending_live_page_validity.is_some())
            || !self.page_engine.permits_teardown() {
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

    /// Completes source child destruction after the Heap list removal, in
    /// `mi_subproc_unsafe_destroy` order: free the parent-allocated child main
    /// Heap image (`heap.c:223-226`), clear the metadata-Theap identity
    /// (`subproc.c:231`), merge the child statistics into the process main
    /// subprocess (`subproc.c:233-236`), destroy the child arenas
    /// (`subproc.c:239`), and free the child image last (`subproc.c:252`).
    /// A returned owner resumes at the first step that did not complete.
    ///
    /// # Safety
    /// Every child client and page is gone; registry unlink, TLD-first Theap
    /// detach, metadata-Theap free, and Heap-list removal succeeded; all Heap
    /// projections ended; and the supplied current parent attachment is the
    /// exact allocator owner that minted this token.
    pub(crate) unsafe fn release_after_empty_heap_teardown<'tracking>(
        self,
        tracking: &'tracking mut [usize],
        heap_owner: &mut crate::main_heap_page::MainHeapThreadOwnerLocalPageEngine<'heap>,
        attachment: &mut crate::main_heap_thread::MainHeapThreadAttachment<'heap>,
    ) -> Result<(), ChildMainHeapReleaseFailure<'heap, 'tracking>> {
        // SAFETY: forwarded caller obligations.
        unsafe {
            self.release_after_empty_heap_teardown_with(
                tracking, ChildHeapRelease::Parent { heap_owner, attachment },
            )
        }
    }

    fn retain_native_heap_release_failure(
        heap_storage: &mut Option<ChildHeapStorage<'heap>>,
        stage: &mut ChildMainHeapStage,
        image: NativeChildHeapImage,
    ) {
        debug_assert!(heap_storage.is_none());
        #[cfg(target_arch = "x86_64")]
        if image.state == NativeChildHeapImageState::Terminal {
            // Earlier Heap teardown stays complete, but a consumed or rejected
            // image cannot continue child release or regain live capability.
            *stage = ChildMainHeapStage::Terminal;
        }
        #[cfg(not(target_arch = "x86_64"))]
        let _ = stage;
        *heap_storage = Some(ChildHeapStorage::Native(image));
    }

    /// [`Self::release_after_empty_heap_teardown`] with the free route that
    /// matches this child's Heap storage. An exact live image refusal keeps
    /// only the final storage-release step available; a prepared refusal is
    /// release-only. Consumed failure or padding rejection is terminal.
    /// Neither result restarts completed Heap teardown steps.
    ///
    /// # Safety
    /// As for [`Self::release_after_empty_heap_teardown`]. A `Parent` route
    /// is the owner-local engine that allocated the image; the `Native` route
    /// may run on any thread with the native runtime active.
    pub(crate) unsafe fn release_after_empty_heap_teardown_with<'tracking>(
        self,
        tracking: &'tracking mut [usize],
        release: ChildHeapRelease<'_, 'heap>,
    ) -> Result<(), ChildMainHeapReleaseFailure<'heap, 'tracking>> {
        let mut destination = None;
        // SAFETY: forwarded teardown and exact release-route obligations.
        match unsafe { self.release_after_empty_heap_teardown_with_into(tracking, release, &mut destination) } {
            Err(ChildMainHeapReleaseFailure::Retained { owner, stage: ChildMainHeapReleaseStage::ArenaBacking,
                error: ChildMainHeapReleaseError::ArenaReleaseRetained }) => {
                Err(ChildMainHeapReleaseFailure::ArenaBacking {
                    owner, destroyed: destination.take().expect("retained child arena releases"),
                })
            }
            result => result,
        }
    }

    /// Releases the child while initializing arena failures directly in
    /// caller-retained storage. A failure leaves the exact child owner in the
    /// result and any committed arena releases in `destination`.
    ///
    /// # Safety
    /// The same teardown and exact release-route obligations apply as to
    /// `release_after_empty_heap_teardown_with`. The empty destination and
    /// tracking storage live outside every retiring child arena and remain
    /// allocated alongside this child owner until raw retries complete.
    pub(crate) unsafe fn release_after_empty_heap_teardown_with_into<'tracking>(
        mut self,
        tracking: &'tracking mut [usize],
        release: ChildHeapRelease<'_, 'heap>,
        destination: &mut Option<crate::arena::DestroyedArenas<'tracking>>,
    ) -> Result<(), ChildMainHeapReleaseFailure<'heap, 'tracking>> {
        let retained = |owner, stage, error| {
            Err(ChildMainHeapReleaseFailure::Retained { owner, stage, error })
        };
        if destination.is_some() || self.pending_os_release.is_some() || (self.pending_fresh_initialization.is_some() || self.pending_live_page_validity.is_some())
            || self.metadata_pages_may_exist
            || !self.page_engine.permits_teardown()
            || !matches!(
                self.stage,
                ChildMainHeapStage::HeapListRemoved
                    | ChildMainHeapStage::HeapStorageReleased
                    | ChildMainHeapStage::ArenaBackingDestroyed
            )
        {
            return retained(self, ChildMainHeapReleaseStage::Validate,
                ChildMainHeapReleaseError::InvalidTransition);
        }
        if self.stage == ChildMainHeapStage::HeapListRemoved {
            let heap_pointer = self.heap_storage.as_ref()
                .map(ChildHeapStorage::pointer_for_identity);
            let matches = self.context.with_image(|child| {
                let identity = child.identity();
                identity.has_published_metadata_theap()
                    && heap_pointer.is_some_and(|heap| identity.matches_ready_main_heap(heap))
            }).unwrap_or(false);
            if !matches {
                return retained(self, ChildMainHeapReleaseStage::Validate,
                    ChildMainHeapReleaseError::InvalidTransition);
            }
            let storage = self.heap_storage.take().expect("validated child Heap capability");
            match (storage, release) {
                (ChildHeapStorage::Parent(allocation), ChildHeapRelease::Parent { heap_owner, attachment }) => {
                    match unsafe { heap_owner.release_child_heap_storage_after_teardown(attachment, allocation) } {
                        Ok(()) => {}
                        Err(crate::main_heap_page::ParentHeapAllocationReleaseFailure::Retained { allocation, error }) => {
                            self.heap_storage = Some(ChildHeapStorage::Parent(allocation));
                            return retained(self, ChildMainHeapReleaseStage::ParentHeap,
                                ChildMainHeapReleaseError::ParentHeap(error));
                        }
                        Err(crate::main_heap_page::ParentHeapAllocationReleaseFailure::Terminal(allocation)) => {
                            self.stage = ChildMainHeapStage::Terminal;
                            return Err(ChildMainHeapReleaseFailure::Terminal { owner: self, allocation });
                        }
                    }
                }
                // The main-subprocess destruction that follows releases the
                // block with its page; the token frees nothing on drop.
                (ChildHeapStorage::Native(image), ChildHeapRelease::Terminal) => drop(image),
                // SAFETY: the validated teardown above leaves no observer.
                (ChildHeapStorage::Native(image), ChildHeapRelease::Native) => match unsafe { image.free() } {
                    Ok(()) => {}
                    Err(image) => {
                        Self::retain_native_heap_release_failure(&mut self.heap_storage, &mut self.stage, image);
                        return retained(self, ChildMainHeapReleaseStage::ParentHeap,
                            ChildMainHeapReleaseError::NativeHeapFree);
                    }
                },
                (storage, _) => {
                    self.heap_storage = Some(storage);
                    return retained(self, ChildMainHeapReleaseStage::ParentHeap,
                        ChildMainHeapReleaseError::InvalidTransition);
                }
            }
            // SAFETY: the Heap and its only Theap are gone, so no source
            // observer can classify a metadata page through this child.
            let merged = self.context.with_image(|child| unsafe {
                let identity = child.identity();
                identity.clear_metadata_identity_terminal();
                // Metadata allocation remains parent-owned; destroyed child
                // statistics accumulate in the process-main subprocess.
                MainSubprocess::global().identity().statistics()
                    .merge_child_subprocess_and_reset(identity.statistics());
            }).is_some();
            if !merged {
                self.stage = ChildMainHeapStage::Terminal;
                return retained(self, ChildMainHeapReleaseStage::Context,
                    ChildMainHeapReleaseError::InvalidTransition);
            }
            self.stage = ChildMainHeapStage::HeapStorageReleased;
        }
        if self.stage == ChildMainHeapStage::HeapStorageReleased {
            let destroyed = self.context.with_image(|child| unsafe {
                // This exact context stays retained until every raw retry
                // finishes; the caller's destination grants no lifetime to
                // the reclaimable child identity or its selected VM policy.
                child.identity().arena_backing().destroy_all_retained_child_into(tracking, destination)
            }).unwrap_or(Err(crate::arena::ArenaDestroyError::InvalidOwnership));
            match destroyed {
                Err(error) => {
                    if destination.is_some() {
                        // The registry pass committed but did not finish.
                        // Recorded raw retries cannot account for unvisited
                        // entries, even when the failure array is empty.
                        self.stage = ChildMainHeapStage::Terminal;
                    }
                    return retained(self, ChildMainHeapReleaseStage::ArenaBacking,
                        ChildMainHeapReleaseError::ArenaDestroy(error));
                }
                Ok(()) if !destination.as_ref().expect("committed child arena releases").is_released() => {
                    return retained(self, ChildMainHeapReleaseStage::ArenaBacking,
                        ChildMainHeapReleaseError::ArenaReleaseRetained);
                }
                Ok(()) => {
                    drop(destination.take());
                    self.stage = ChildMainHeapStage::ArenaBackingDestroyed;
                }
            }
        }
        #[cfg(target_arch = "x86_64")]
        let native_record = self.context.with_image(|image| image.native_record()).flatten();
        #[cfg(target_arch = "x86_64")]
        if let Some(record) = native_record {
            // SAFETY: source Heap, Theap, arena, and registry teardown have
            // finished. Native destruction holds this record's lock, and no
            // source image projection survives the completed closure above.
            unsafe { crate::subproc::lifecycle::retain_native_child_control_storage(record, self.context.context); }
            return Ok(());
        }
        if let Err(error) = self.context.parent_metadata.free(&mut self.context.context) {
            self.stage = ChildMainHeapStage::Terminal;
            return retained(self, ChildMainHeapReleaseStage::Context,
                ChildMainHeapReleaseError::Metadata(error));
        }
        Ok(())
    }

    /// Retries arena failures in their retained slot without transporting
    /// the child owner or the failure array through an aggregate result.
    ///
    /// # Safety
    /// The destination is the committed arena failure owner produced by this
    /// exact child. Its tracking allocation and this child's context remain
    /// live and exclusively retained; no child operation can resume.
    pub(crate) unsafe fn retry_arena_backing_into(
        &mut self,
        destination: &mut Option<crate::arena::DestroyedArenas<'_>>,
    ) -> Result<(), ChildMainHeapReleaseError> {
        if self.stage != ChildMainHeapStage::HeapStorageReleased {
            return Err(ChildMainHeapReleaseError::InvalidTransition);
        }
        let destroyed = destination.as_mut().ok_or(ChildMainHeapReleaseError::InvalidTransition)?;
        if destroyed.retry_raw().is_err() || !destroyed.is_released() {
            return Err(ChildMainHeapReleaseError::ArenaReleaseRetained);
        }
        self.stage = ChildMainHeapStage::ArenaBackingDestroyed;
        drop(destination.take());
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

/// Detaches every page of one child-thread Theap for process destruction
/// through an ordinary child page engine over that Theap, built from the
/// listed Theap and TLD instead of the thread's own owner (which lives in
/// that thread's storage). The engine starts with fresh page-engine state:
/// a pending raw unmap retry of the thread is not visible here, and its page
/// would make the detach refuse.
///
/// # Safety
/// Permanent terminal quiescence: the thread neither runs an allocator
/// operation nor ever will, `theap` and `tld` are a listed child-thread
/// Theap of the child main Heap `heap` and its TLD, and no other PageMap or
/// page writer runs.
unsafe fn detach_child_thread_pages_terminal(
    child: Pin<&crate::subproc::ChildSubprocessImage>,
    binding: crate::process_init::ProcessMainBackingBinding,
    heap: NonNull<Heap>,
    theap: NonNull<Theap>,
    tld: *mut ThreadLocalData,
) -> Result<(), ChildMetadataPageEngineError> {
    let tld = NonNull::new(tld).ok_or(ChildMetadataPageEngineError::InvalidTransition)?;
    let (thread, sequence) = {
        // SAFETY: a listed TLD is allocated; this reads two scalars.
        let tld = unsafe { tld.as_ref() };
        (LiveThreadId::new(tld.thread_id()), tld.thread_sequence())
    };
    let thread = thread.ok_or(ChildMetadataPageEngineError::InvalidTransition)?;
    let child_process = crate::os::ChildVmProcess::new(binding.process(), child)
        .map_err(ChildMetadataPageEngineError::ChildProcess)?;
    let pair = crate::process_arena::ChildProcessPageArenaLease::join(binding.page_map(), child_process)
        .map_err(ChildMetadataPageEngineError::BackingPair)?;
    let page_lifecycle = pair.begin_page_lifecycle().map_err(ChildMetadataPageEngineError::BackingPair)?;
    // SAFETY: the lifecycle capability above excludes every other plain
    // PageMap mutation for this operation.
    let page_map = unsafe { pair.page_map_for_owned_ranges() }
        .map_err(ChildMetadataPageEngineError::BackingPair)?;
    let mut pending_os_release = None;
    let mut page_engine = ChildPageEngineState::Active;
    // SAFETY: quiescence makes this the sole user of the Theap and TLD, the
    // child image, Heap, and blocks stay allocated through the operation.
    let session = unsafe {
        crate::types::metadata_session::ChildOrdinaryTheapPageSession::new(
            child, tld, theap, heap, thread, sequence, &mut pending_os_release, &mut page_engine,
        )
    }
    .ok_or(ChildMetadataPageEngineError::SessionNotReady)?;
    let backing = crate::page_backing::ChildMetadataArenaBacking::new(pair);
    // SAFETY: the validated child pair and session are held through the
    // complete operation.
    let mut engine = unsafe {
        crate::single_thread::ChildOrdinaryPageAllocator::activate_child_ordinary(
            session, backing, page_map, sequence, crate::arena::ArenaId::none(),
        )
    };
    // SAFETY: forwarded quiescence; the child arenas are destroyed next.
    let detached = unsafe { engine.detach_pages_for_subprocess_destroy() };
    let finished = engine.finish_operation().map_err(drop);
    let lifecycle = page_lifecycle.finish();
    if !detached {
        return Err(ChildMetadataPageEngineError::MetadataPagesRemain);
    }
    finished.map_err(|()| ChildMetadataPageEngineError::EngineRetained)?;
    lifecycle.map_err(ChildMetadataPageEngineError::PageMapLifecycle)
}

impl ChildContextLease<'_> {
    #[inline]
    pub(crate) fn context_memory_id(&self) -> MemoryId {
        self.owner.context.memory_id()
    }

    #[inline]
    pub(crate) fn with_image<R>(
        &mut self,
        operation: impl for<'image> FnOnce(
            Pin<&'image crate::subproc::ChildSubprocessImage>,
        ) -> R,
    ) -> Option<R> {
        if self.owner.terminal { return None; }
        let image = self
            .owner
            .context
            .child_subprocess_image()?;
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
            .and_then(ChildMetadataAllocation::dynamic_theap_mut)
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
    /// Moves the exact original claim retained by a direct allocation adapter.
    /// The caller keeps its preallocation issuer admission through settlement.
    #[cfg(target_arch = "x86_64")]
    fn take_pending_fresh_initialization(&mut self)
        -> Option<crate::single_thread::PendingFreshOsPageInitialization> {
        match self {
            Self::LegacySelectedArena(engine) => engine.take_pending_fresh_initialization(),
            Self::Process(engine) => engine.take_pending_fresh_initialization(),
            Self::CanonicalProcess(engine) => engine.take_pending_fresh_initialization(),
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn take_pending_live_page_validity(&mut self)
        -> Option<crate::single_thread::PendingLivePageValidity> {
        match self {
            Self::LegacySelectedArena(engine) => engine.take_pending_live_page_validity(),
            Self::Process(engine) => engine.take_pending_live_page_validity(),
            Self::CanonicalProcess(engine) => engine.take_pending_live_page_validity(),
        }
    }

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

/// Refusal to capture the original metadata diagnostic domain before a
/// fresh process-backed candidate is created. Refusal grants no replacement
/// allocation, cleanup or process-readiness authority.
#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SourceInitializationOutputAdmissionError {
    Metadata(MetaError),
    Bootstrap(crate::process_init::BootstrapOutputAdmissionError),
    BackingUnavailable,
    OriginMismatch,
}

/// A borrowed startup diagnostic admission for the actual detached metadata
/// issuer. The scope retains its original completion, output and VM process;
/// the pinned metadata owner and its selected process binding retain the
/// exact Theap, canonical Heap and PageMap. No image projection or allocator
/// lock is retained. This is captured before the original page candidate,
/// and cannot be persisted beside a task that outlives the startup scope.
#[cfg(target_arch = "x86_64")]
pub(crate) struct SourceInitializationOutputWitness<'scope, 'startup, 'owner> {
    scope: &'scope crate::process_init::ScopedBootstrapOutput<'startup>,
    issuer: MetaAllocatorBound<'owner>,
    process: &'scope crate::os::VmProcess<'static>,
    binding: crate::process_init::ProcessMainBackingBinding,
    page_map: &'static PageMap,
    theap: NonNull<Theap>,
    _not_send_or_sync: PhantomData<*mut ()>,
}

#[cfg(target_arch = "x86_64")]
impl SourceInitializationOutputWitness<'_, '_, '_> {
    fn validate(&self) -> Result<(), SourceInitializationOutputAdmissionError> {
        use SourceInitializationOutputAdmissionError as Error;
        if !self.scope.matches_process(self.process)
            || !self.scope.matches_subprocess(self.issuer.subprocess)
            || !self.binding.is_active()
        { return Err(Error::OriginMismatch); }
        let entry = self.issuer.allocator.enter().map_err(Error::Metadata)?;
        if !matches!(entry.status(), BOUND | READY) { return Err(Error::OriginMismatch); }
        entry.validate_bound_tuple(self.issuer.config, self.issuer.subprocess).map_err(Error::Metadata)?;
        // SAFETY: this short entry serializes immutable backing selection.
        // The copied binding retains the actual process map; no projection
        // survives this validation or a later output callback.
        let backing = unsafe { *self.issuer.allocator.get_ref().process_backing.get() }
            .ok_or(Error::BackingUnavailable)?;
        if !core::ptr::eq(backing.page_map, self.page_map)
            || !self.scope.matches_process(&backing.binding.process())
            || self.issuer.allocator.get_ref().detached_metadata_theap.load(Ordering::Acquire) != self.theap.as_ptr()
        { return Err(Error::OriginMismatch); }
        Ok(())
    }

    /// Moves a failed candidate from the same preadmitted persistent issuer.
    /// The returned original task carries no replacement diagnostic admission;
    /// settlement retains this witness and all actual issuing owners. The
    /// metadata entry ends before the caller receives the claim.
    pub(crate) fn take_retained_initialization_task(&self)
        -> Result<Option<crate::single_thread::PendingFreshOsPageInitialization>,
            SourceInitializationOutputAdmissionError> {
        self.validate()?;
        let mut entry = self.issuer.allocator.enter()
            .map_err(SourceInitializationOutputAdmissionError::Metadata)?;
        if entry.status() != READY { return Ok(None); }
        entry.validate_bound_tuple(self.issuer.config, self.issuer.subprocess)
            .map_err(SourceInitializationOutputAdmissionError::Metadata)?;
        Ok(entry.allocator().take_pending_fresh_initialization())
    }

    /// Moves the exact detached live Page task from the original metadata
    /// issuer. Entry validation and all projections end before delivery;
    /// the caller retains this witness and issuer through dispatch or refusal.
    pub(crate) fn take_retained_live_page_validity_task(&self)
        -> Result<Option<crate::single_thread::PendingLivePageValidity>,
            SourceInitializationOutputAdmissionError> {
        self.validate()?;
        let mut entry = self.issuer.allocator.enter()
            .map_err(SourceInitializationOutputAdmissionError::Metadata)?;
        if entry.status() != READY { return Ok(None); }
        entry.validate_bound_tuple(self.issuer.config, self.issuer.subprocess)
            .map_err(SourceInitializationOutputAdmissionError::Metadata)?;
        Ok(entry.allocator().take_pending_live_page_validity())
    }

    /// Revalidates this original domain after all allocator projections end.
    /// The returned output borrow remains bounded by the winning startup scope.
    pub(crate) fn output(&self) -> Result<&crate::diagnostic_output::OutputOwner,
        SourceInitializationOutputAdmissionError> {
        self.validate()?;
        self.scope.output().map_err(SourceInitializationOutputAdmissionError::Bootstrap)
    }

    pub(crate) fn process(&self) -> Result<&crate::os::VmProcess<'static>,
        SourceInitializationOutputAdmissionError> {
        self.validate()?;
        Ok(self.process)
    }

    pub(crate) fn page_map(&self) -> Result<&PageMap, SourceInitializationOutputAdmissionError> {
        self.validate()?;
        Ok(self.page_map)
    }

    /// This comparison refuses a foreign original task; the retained issuer
    /// pin and scope, rather than address equality, carry lifetime authority.
    pub(crate) fn matches_theap(&self, theap: NonNull<Theap>) -> bool {
        self.validate().is_ok() && self.theap == theap
    }
}

impl<'owner> MetaAllocatorBound<'owner> {
    /// Captures the actual startup metadata output domain before allocation.
    /// The process PageMap may be initialized while global process readiness
    /// remains unpublished. Earlier bootstrap prefixes without a selected
    /// process backing refuse this factory and retain failures terminally.
    ///
    /// # Safety
    /// The caller retains this actual pinned metadata owner, canonical Heap,
    /// original scope and selected process binding before creating a fresh
    /// candidate and continuously through any diagnostic dispatch. It excludes
    /// issuer teardown/rebinding and ends every allocator, metadata, Page,
    /// Heap, Theap, TLD and random projection or guard before output delivery.
    /// Callback registrations and arguments remain valid and serialized; no
    /// nested operation may reuse the unpublished original candidate.
    #[cfg(target_arch = "x86_64")]
    pub(crate) unsafe fn capture_startup_source_initialization_output<'scope, 'startup>(
        self,
        scope: &'scope crate::process_init::ScopedBootstrapOutput<'startup>,
    ) -> Result<SourceInitializationOutputWitness<'scope, 'startup, 'owner>,
        SourceInitializationOutputAdmissionError> {
        use SourceInitializationOutputAdmissionError as Error;
        let process = scope.process().map_err(Error::Bootstrap)?;
        if !scope.matches_subprocess(self.subprocess) { return Err(Error::OriginMismatch); }
        let entry = self.allocator.enter().map_err(Error::Metadata)?;
        if !matches!(entry.status(), BOUND | READY) { return Err(Error::OriginMismatch); }
        entry.validate_bound_tuple(self.config, self.subprocess).map_err(Error::Metadata)?;
        // SAFETY: the original metadata entry excludes selection changes;
        // these copies retain the actual already selected process backing.
        let backing = unsafe { *self.allocator.get_ref().process_backing.get() }
            .ok_or(Error::BackingUnavailable)?;
        if !backing.binding.is_active() || !scope.matches_process(&backing.binding.process()) {
            return Err(Error::OriginMismatch);
        }
        let theap = NonNull::new(self.allocator.get_ref().detached_metadata_theap.load(Ordering::Acquire))
            .ok_or(Error::Metadata(MetaError::TheapMetaUnpublished))?;
        // No metadata-entry guard crosses the returned caller boundary.
        drop(entry);
        Ok(SourceInitializationOutputWitness { scope, issuer: self, process,
            binding: backing.binding, page_map: backing.page_map, theap,
            _not_send_or_sync: PhantomData })
    }

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

    /// Pinned `_mi_auto_process_init`'s metadata reseed: while holding
    /// `subproc->theap_meta_lock`, `_mi_random_reinit_if_weak` on the
    /// subprocess metadata Theap (`src/init.c:526-531`). Returns whether the
    /// weak image retried entropy and whether it remains weak. The source
    /// metadata lock is released before these facts reach a diagnostic caller.
    #[cfg(target_arch = "x86_64")]
    pub(crate) fn reinitialize_detached_metadata_random_if_weak(
        self: Pin<&'static Self>, subprocess: &'static MainSubprocess,
    ) -> Result<crate::random::RandomReinitialization, MetaError> {
        self.reinitialize_detached_metadata_random_if_weak_with_warning(subprocess, || {})
    }

    /// Retry the exact bound detached random image. End all metadata entry
    /// projections before delivering a weak-entropy warning, then reacquire
    /// the same source image and apply the already prepared entropy material.
    #[cfg(target_arch = "x86_64")]
    pub(crate) fn reinitialize_detached_metadata_random_if_weak_with_warning(
        self: Pin<&'static Self>, subprocess: &'static MainSubprocess,
        warning: impl FnOnce(),
    ) -> Result<crate::random::RandomReinitialization, MetaError> {
        let entry = self.enter_for_main_subprocess(subprocess)?;
        self.validate_bound_detached_metadata_theap(subprocess)?;
        let pointer = NonNull::new(self.get_ref().detached_metadata_theap.load(Ordering::Acquire))
            .ok_or(MetaError::InitializationRetained)?;
        // SAFETY: the exact metadata entry excludes other random projections.
        let weak = unsafe { Theap::with_os_reservation_random_at(pointer, |random|
            random.map(|random| random.is_weak())) }
            .ok_or(MetaError::InitializationRetained)?;
        if !weak { return Ok(crate::random::RandomReinitialization::default()); }
        let prepared = crate::random::PreparedRandomInitialization::prepare_normal();
        let (material, _entry) = if prepared.requires_warning() {
            drop(entry);
            warning();
            // SAFETY: the warning returned with no source projection live.
            let material = unsafe { prepared.after_warning() };
            let entry = self.enter_for_main_subprocess(subprocess)?;
            self.validate_bound_detached_metadata_theap(subprocess)?;
            if self.get_ref().detached_metadata_theap.load(Ordering::Acquire) != pointer.as_ptr() {
                return Err(MetaError::InitializationRetained);
            }
            (material, entry)
        } else {
            // SAFETY: strong entropy needs no warning or weak observations;
            // the short random projection ended before entropy acquisition.
            (unsafe { prepared.after_warning() }, entry)
        };
        // SAFETY: reacquired entry retains the original validated image and
        // excludes every other projection while applying prepared material.
        let remains_weak = unsafe { Theap::with_os_reservation_random_at(pointer, |random| {
            random.map(|random| {
                random.initialize_prepared(material);
                random.is_weak()
            })
        }) }.ok_or(MetaError::InitializationRetained)?;
        Ok(crate::random::RandomReinitialization { attempted: true, remains_weak })
    }

    /// Test-only weak-random observation of the detached metadata Theap
    /// under the same entry and source lock as its reseed.
    #[cfg(all(test, target_arch = "x86_64"))]
    pub(crate) fn test_detached_metadata_random_is_weak(
        self: Pin<&'static Self>, subprocess: &'static MainSubprocess,
    ) -> Option<bool> {
        let _entry = self.enter_for_main_subprocess(subprocess).ok()?;
        let pointer = NonNull::new(self.get_ref().detached_metadata_theap.load(Ordering::Acquire))?;
        // SAFETY: entry and the source lock exclude overlapping projections.
        unsafe { Theap::test_random_is_weak_at(pointer) }
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

    /// Diagnoses the exact read-only parent metadata binding predicates used
    /// by child Theap detach. This grants no entry or allocator capability.
    #[cfg(test)]
    pub(crate) fn test_child_detach_binding(
        self: Pin<&'static Self>,
        config: MemoryConfig,
        subprocess: &'static MainSubprocess,
    ) -> (u8, bool, bool, Result<(), MetaError>) {
        let this = self.get_ref();
        let status = this.status.load(Ordering::Acquire);
        let config_matches = if matches!(status, BOUND | READY) {
            // SAFETY: BOUND/READY publishes the immutable config tuple.
            unsafe { this.config.get().read().assume_init() == config }
        } else {
            false
        };
        let subprocess_matches = core::ptr::eq(
            this.subprocess.load(Ordering::Acquire),
            subprocess.identity_ptr(),
        );
        let theap = self.validate_bound_detached_metadata_theap(subprocess);
        (status, config_matches, subprocess_matches, theap)
    }

    /// Legacy projection-based binding for explicit-configuration fixtures.
    /// Callback-producing native startup uses the scoped output supplier so
    /// no metadata entry or whole-image projection crosses a lazy getter.
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

    /// Initializes the canonical static metadata image with its actual
    /// winning startup output and storage retained across source callbacks.
    /// The prefix claim is never rolled back to an untouched state.
    ///
    /// # Safety
    /// `output` retains the winning startup transaction, selected output,
    /// actual VM, subprocess and canonical foundation through this call.
    /// No Heap/TLD/Theap, allocator session or metadata entry projection
    /// survives an option getter or entropy-warning delivery.
    #[cfg(target_arch = "x86_64")]
    pub(crate) unsafe fn prepare_for_main_heap_with_bootstrap_output(
        self: Pin<&'owner Self>, config: MemoryConfig, subprocess: &'static MainSubprocess,
        foundation: crate::main_theap::MainStaticHeapFoundation,
        output: &crate::process_init::ScopedBootstrapOutput<'_>,
    ) -> Result<MetaAllocatorBound<'owner>, MetaError> {
        if !core::ptr::eq(foundation.subprocess(), subprocess) {
            return Err(MetaError::SubprocessMismatch);
        }
        if !output.matches_subprocess(subprocess) {
            return Err(MetaError::BootstrapOutput(crate::process_init::BootstrapOutputAdmissionError::Invalid));
        }
        let mut binding = {
            let entry = self.enter()?;
            if entry.status() != COLD { return Err(MetaError::InitializationRetained); }
            let this = self.get_ref();
            let heap = foundation.metadata_heap();
            // The original UnsafeCell owns the pinned slot. No pointer is
            // derived from a whole-bootstrap mutable reference.
            let bootstrap = unsafe { NonNull::new_unchecked(this.bootstrap.get().cast::<ExclusiveTheapBootstrap>()) };
            unsafe {
                ExclusiveTheapBootstrap::write_empty_at(bootstrap);
                *this.canonical_heap.get() = Some(heap);
                (*this.config.get()).write(config);
            }
            this.subprocess.store(subprocess.identity_ptr(), Ordering::Release);
            this.status.store(BINDING, Ordering::Release);
            let binding = SourceMetadataBinding { owner: self, bootstrap, complete: false };
            let phase = unsafe { ExclusiveTheapBootstrap::prepare_source_metadata_at(bootstrap, heap) }
                .map_err(|_| MetaError::InitializationRetained)?;
            // Keep the binding token live before releasing the entry. Failure
            // retains the exact claimed slot; no second initializer may write it.
            entry.end_source_prefix_entry();
            (binding, phase)
        };
        let options = unsafe { crate::types::SourceTheapOptions::capture_from_output(
            output.output().map_err(MetaError::BootstrapOutput)?,
        ) };
        if !output.matches_subprocess(subprocess) {
            return Err(MetaError::BootstrapOutput(crate::process_init::BootstrapOutputAdmissionError::Invalid));
        }
        let linked = match unsafe { binding.0.attach_source_options(binding.1, options) }? {
            crate::types::TheapRandomInitialization::SplitComplete(linked) => linked,
            crate::types::TheapRandomInitialization::FirstHead(first) => {
                let prepared = crate::random::PreparedRandomInitialization::prepare_normal();
                let material = unsafe { output.deliver_prepared_random_warning(prepared) }
                    .map_err(MetaError::BootstrapOutput)?;
                unsafe { first.finish_random_initialization(material) }
            }
        };
        #[cfg(feature = "mi-guarded")]
        let ready = {
            let sample = unsafe { crate::types::GuardedSampleOptions::capture_from_output(
                output.output().map_err(MetaError::BootstrapOutput)?,
            ) };
            if !output.matches_subprocess(subprocess) {
                return Err(MetaError::BootstrapOutput(crate::process_init::BootstrapOutputAdmissionError::Invalid));
            }
            let sampled = unsafe { linked.apply_guarded_sample_options(sample) };
            let bounds = unsafe { crate::types::GuardedSizeOptions::capture_from_output(
                output.output().map_err(MetaError::BootstrapOutput)?,
            ) };
            if !output.matches_subprocess(subprocess) {
                return Err(MetaError::BootstrapOutput(crate::process_init::BootstrapOutputAdmissionError::Invalid));
            }
            unsafe { sampled.apply_guarded_size_options(bounds) }
        };
        #[cfg(not(feature = "mi-guarded"))]
        let ready = linked.finish_without_guarded_options();
        if !output.matches_subprocess(subprocess) {
            return Err(MetaError::BootstrapOutput(crate::process_init::BootstrapOutputAdmissionError::Invalid));
        }
        let identity = unsafe { ready.publish_heap() }.map_err(|_| MetaError::InitializationRetained)?;
        unsafe { ExclusiveTheapBootstrap::complete_source_metadata_at(binding.0.bootstrap, identity) }
            .map_err(|_| MetaError::InitializationRetained)?;
        if !unsafe { subprocess.publish_detached_metadata_theap(identity) } {
            return Err(MetaError::TheapMetaMismatch);
        }
        let this = self.get_ref();
        this.detached_metadata_theap.store(identity.as_ptr(), Ordering::Release);
        this.status.store(BOUND, Ordering::Release);
        binding.0.complete = true;
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
    /// main-subprocess identity. The regular thread-local slot owner uses the
    /// typed sibling below so replaced images take the detached remote-free
    /// path; this general route retains its existing local release contract.
    pub(crate) fn rezalloc_for_main_subprocess(
        self: Pin<&'owner Self>,
        config: MemoryConfig,
        subprocess: &'static MainSubprocess,
        old: Option<&mut MetaAllocation<'owner>>,
        new_size: usize,
    ) -> Result<MetaAllocation<'owner>, MetaError> {
        self.rezalloc_for_main_subprocess_with_release(config, subprocess, old, new_size, false)
    }

    /// Replaces an installed regular thread-local slot image. Source copies
    /// the old flexible image after releasing the metadata allocation lock,
    /// then frees it through the detached page's remote head.
    pub(crate) fn rezalloc_thread_local_backing_for_main_subprocess(
        self: Pin<&'owner Self>,
        config: MemoryConfig,
        subprocess: &'static MainSubprocess,
        old: &mut MetaAllocation<'owner>,
        new_size: usize,
    ) -> Result<MetaAllocation<'owner>, MetaError> {
        if !old.dynamic_thread_local_backing_projected {
            return Err(MetaError::ReleasedOrStale);
        }
        self.rezalloc_for_main_subprocess_with_release(config, subprocess, Some(old), new_size, true)
    }

    fn rezalloc_for_main_subprocess_with_release(
        self: Pin<&'owner Self>,
        config: MemoryConfig,
        subprocess: &'static MainSubprocess,
        old: Option<&mut MetaAllocation<'owner>>,
        new_size: usize,
        remote_old: bool,
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
        let old_release = if remote_old {
            // SAFETY: the old image remains the exact live metadata block
            // through the source copy; its capability is now RELEASING.
            unsafe { self.publish_claimed_detached_metadata(old) }
        } else {
            self.release_claimed(old)
        };
        if let Err(error) = old_release {
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

    /// Releases a non-main Heap Theap image through the detached metadata
    /// page's remote list, as source `mi_free` does for this caller-relative
    /// free. The exact capability ends at publication; its page remains
    /// counted until the detached owner collects the remote head.
    ///
    /// # Safety
    /// The caller has detached the Theap from all Heap and TLD lists and
    /// excludes concurrent process teardown and access to its image.
    pub(crate) unsafe fn free_detached_heap_theap(
        self: Pin<&'owner Self>,
        allocation: &mut MetaAllocation<'owner>,
    ) -> Result<(), MetaError> {
        if !allocation.belongs_to(self) {
            return Err(MetaError::ForeignOwner);
        }
        if self.get_ref().status.load(Ordering::Acquire) != READY
            || !allocation.is_live()
            || !allocation.has_consistent_malloc_provenance()
        {
            return Err(MetaError::ReleasedOrStale);
        }
        if !allocation.claim(ALLOCATION_LIVE, ALLOCATION_RELEASING) {
            return Err(MetaError::ReleasedOrStale);
        }
        // SAFETY: the source Heap release has relinquished all image users;
        // this exact capability retains its page through publication.
        match unsafe { self.publish_claimed_detached_metadata(allocation) } {
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

    /// Publishes an already claimed exact Malloc block to its detached
    /// metadata page and leaves its used count pending for owner collection.
    ///
    /// # Safety
    /// `allocation` is in RELEASING state, its exact block remains live and
    /// registered, and no source owner can access its bytes after success.
    unsafe fn publish_claimed_detached_metadata(
        self: Pin<&'owner Self>,
        allocation: &mut MetaAllocation<'owner>,
    ) -> Result<(), MetaError> {
        let this = self.get_ref();
        // A detached owner must observe its block through the same PageMap
        // that registered it. The isolated explicit-config owner retains a
        // private map; process-backed owners retain their selected binding.
        #[cfg(test)]
        let private_observed = if this.test_default_subprocess.load(Ordering::Acquire).is_null()
            || unsafe { (*this.process_backing.get()).is_some() }
        {
            None
        } else {
            if this.status.load(Ordering::Acquire) != READY {
                return Err(MetaError::DetachedRemoteFreeUnavailable);
            }
            // SAFETY: READY publishes the private map, and the exact live
            // allocation keeps its page registration stable through release.
            let map = unsafe { (*this.page_map.get()).assume_init_ref() };
            let page = NonNull::new(unsafe { map.checked_lookup(allocation.pointer.as_ptr()) })
                .ok_or(MetaError::DetachedRemoteFreeUnavailable)?;
            Some(unsafe { crate::process_page_map::classify_live_allocation_in_page(
                page, allocation.pointer,
            ) }
            .ok_or(MetaError::DetachedRemoteFreeUnavailable)?)
        };
        let observed = {
            #[cfg(test)]
            if let Some(observed) = private_observed {
                observed
            } else {
                unsafe { self.lookup_detached_process_allocation(allocation.pointer) }?
            }
            #[cfg(not(test))]
            unsafe { self.lookup_detached_process_allocation(allocation.pointer) }?
        };
        // SAFETY: the one PageMap observation binds the exact block to the
        // detached metadata page whose owner remains process-live.
        unsafe { crate::remote_free::push_detached_metadata_allocation(observed) }
            .map_err(MetaError::DetachedRemoteFree)
    }

    /// # Safety
    /// `pointer` is an exact live block registered in this owner's selected
    /// process PageMap until its detached remote publication consumes it.
    unsafe fn lookup_detached_process_allocation(
        self: Pin<&'owner Self>,
        pointer: NonNull<u8>,
    ) -> Result<crate::process_page_map::LiveAllocationPointer, MetaError> {
        let binding = if let Some(selected) = unsafe { *self.get_ref().process_backing.get() } {
            selected.binding
        } else {
            crate::process_init::ProcessMainInitializationStorage::global()
                .ready_child_subprocess_inputs()
                .ok_or(MetaError::DetachedRemoteFreeUnavailable)?
                .0
        };
        // SAFETY: the exact live block retains its metadata page and PageMap
        // registration until the consuming remote publication completes.
        unsafe { binding.page_map().lookup_live_allocation(pointer) }
            .map_err(|_| MetaError::DetachedRemoteFreeUnavailable)?
            .ok_or(MetaError::DetachedRemoteFreeUnavailable)
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
        let pointer = unsafe { NonNull::new_unchecked(this.bootstrap.get().cast::<ExclusiveTheapBootstrap>()) };
        unsafe { ExclusiveTheapBootstrap::write_empty_at(pointer) };
        let mut bootstrap = unsafe { Pin::new_unchecked(&mut *pointer.as_ptr()) };
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
            .as_mut()
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
    /// Keep first-backing temporaries out of the already-ready entry frame.
    #[cfg_attr(target_arch = "x86_64", cold)]
    #[cfg_attr(target_arch = "x86_64", inline(never))]
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
                return self.initialize_canonical_process_backing(backing);
            }
            return self.initialize_process_backing(backing);
        }
        self.initialize_legacy_backing(entry, config, subprocess)
    }

    /// Activates the explicit process-backed session without reserving its
    /// allocator temporaries in the canonical session's dispatch frame.
    fn initialize_process_backing(
        self: Pin<&'owner Self>,
        backing: MetadataProcessBacking,
    ) -> Result<(), MetaError> {
        let this = self.get_ref();
        let bootstrap = unsafe { Pin::new_unchecked((&mut *this.bootstrap.get()).assume_init_mut()) };
        let allocator = unsafe { ProcessMetadataPageAllocator::activate_process_metadata(
            bootstrap, backing.binding.process(), backing.page_map) }
            .map_err(|_| {
                this.status.store(FAILED, Ordering::Release);
                MetaError::InitializationRetained
            })?;
        // SAFETY: the metadata entry excludes all other projections; BOUND
        // leaves this final slot uninitialized until the complete allocator
        // is written. READY publishes it only after this write.
        unsafe { this.allocator.get().cast::<MetadataPageAllocator>().write(MetadataPageAllocator::Process(allocator)) };
        this.status.store(READY, Ordering::Release);
        Ok(())
    }

    /// Activates the canonical process metadata session separately from
    /// legacy allocator variants so their unused aggregate temporaries do
    /// not consume the selected worker's stack.
    fn initialize_canonical_process_backing(
        self: Pin<&'owner Self>,
        backing: MetadataProcessBacking,
    ) -> Result<(), MetaError> {
        let this = self.get_ref();
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
        // SAFETY: the metadata entry retains the canonical session and the
        // final uninitialized allocator slot. Write the complete typed value
        // directly, before READY allows any allocator projection.
        unsafe { this.allocator.get().cast::<MetadataPageAllocator>().write(MetadataPageAllocator::CanonicalProcess(allocator)); }
        this.status.store(READY, Ordering::Release);
        Ok(())
    }

    /// Builds the private explicit-config backing only when no process
    /// backing was selected. Keeping its mapping and arena temporaries out
    /// of the process-backed activation frame bounds worker bootstrap stack
    /// use even when debug codegen reserves every branch's local storage.
    fn initialize_legacy_backing(
        self: Pin<&'owner Self>,
        entry: &mut MetaEntry<'_, 'owner>,
        config: MemoryConfig,
        subprocess: &'static MainSubprocess,
    ) -> Result<(), MetaError> {
        let this = self.get_ref();
        let page_map = match PageMap::initialize(config, MAX_VABITS, false) {
            Ok(page_map) => page_map,
            Err(PageMapInitializationError::Failed { .. }) => {
                return Err(MetaError::InitializationFailed);
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
            // Aligned trim failures leak (source `mi_os_prim_free`), so a
            // failed map owns nothing.
            Err(_) => return self.cleanup_page_map_after_failed_init(),
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
            manage_external_in_place_with_guard(
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
                Some(MetadataGuardHook::new(decommit_metadata_backing_guard, mapping)),
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
        unsafe { this.allocator.get().cast::<MetadataPageAllocator>().write(MetadataPageAllocator::LegacySelectedArena(allocator)) };
        this.status.store(READY, Ordering::Release);
        let _ = entry;
        Ok(())
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

/// Performs the arena metadata guard transition through its retained map.
/// The synchronous callback ends before arena headers or bitmaps are exposed.
unsafe fn decommit_metadata_backing_guard(
    start: *mut u8, size: usize, argument: *const core::ffi::c_void,
) {
    // SAFETY: the hook borrows the exact final-slot mapping through arena
    // initialization, before any typed view of the metadata guard exists.
    let mapping = unsafe { &*argument.cast::<Mapping>() };
    let base = mapping.base().expect("metadata backing retains its mapping");
    let length = mapping.length().expect("metadata backing retains its extent");
    let offset = start.addr().checked_sub(base.addr()).expect("metadata guard belongs to its mapping");
    assert!(offset.checked_add(size).is_some_and(|end| end <= length),
        "metadata guard stays inside its retained mapping");
    // Source arena initialization proceeds after a guard transition failure;
    // the original mapping owner still retains the complete backing.
    let _ = mapping.decommit(offset, size);
}

/// Exclusive custody of one original static metadata slot while callback
/// windows run without a metadata entry. An incomplete slot is retained;
/// dropping this token never frees or restores an untouched bootstrap image.
#[cfg(target_arch = "x86_64")]
struct SourceMetadataBinding<'owner> {
    owner: Pin<&'owner MetadataEngine<'owner>>,
    bootstrap: NonNull<ExclusiveTheapBootstrap>,
    complete: bool,
}

#[cfg(target_arch = "x86_64")]
impl SourceMetadataBinding<'_> {
    /// # Safety
    /// The phase was prepared from this exact claimed bootstrap allocation.
    /// This owner and canonical foundation retain all images; no projection,
    /// list mutator, or existing-head random mutation overlaps attachment.
    unsafe fn attach_source_options(
        &mut self,
        phase: crate::types::PreparedTheapInitialization,
        options: crate::types::SourceTheapOptions,
    ) -> Result<crate::types::TheapRandomInitialization, MetaError> {
        match unsafe { phase.apply_source_options_and_attach_with_failure_owner(options) } {
            Ok(random) => Ok(random),
            Err(failure) => {
                if let Ok(unattached) = failure.into_unattached() {
                    // The linear prelink witness permits resetting only this
                    // owned Theap. The original TLD mutex may still be held;
                    // keep the claimed bootstrap terminal rather than replace
                    // its lock image or infer permission to release storage.
                    unsafe { unattached.reset_unattached() };
                }
                Err(MetaError::InitializationRetained)
            }
        }
    }
}

#[cfg(target_arch = "x86_64")]
impl Drop for SourceMetadataBinding<'_> {
    fn drop(&mut self) {
        if !self.complete {
            let _ = self.owner.get_ref().status.compare_exchange(
                BINDING, FAILED, Ordering::Release, Ordering::Relaxed,
            );
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
    /// Ends the prefix entry before callback-producing source operations.
    /// An unknown unlock result cannot admit user code or release the retained
    /// prefix custody through ordinary Rust destruction.
    #[cfg(target_arch = "x86_64")]
    fn end_source_prefix_entry(mut self) {
        if let Some(guard) = self.theap_meta_guard.take() {
            if guard.unlock().is_err() { crabc_core::process::exit_immediately(134); }
        }
        if let Some(guard) = self.guard.take() {
            if guard.unlock().is_err() { crabc_core::process::exit_immediately(134); }
        }
        let thread = self.entry_thread;
        self.entry_thread = 0;
        clear_entry_thread_after_unlock(&self.owner.get_ref().active_entry_thread, thread);
    }

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

    // Keep the shared readiness checks separate from first-backing initialization.
    #[cfg_attr(target_arch = "x86_64", inline(never))]
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

    #[cfg(target_arch = "x86_64")]
    fn child_tls_array_fixture(
        allocator: Pin<&'static MetaAllocator>,
        count: usize,
    ) -> (ChildMetadataImageBlock, MetaAllocation<'static>) {
        let size = DynamicThreadLocalBacking::allocation_size(count).unwrap();
        let mut allocation = allocator.zalloc(config(), size).unwrap();
        let pointer = allocation.pointer();
        let memory = allocation.memory_id();
        // SAFETY: the exact direct-zeroed metadata capability validates the
        // complete flexible request and retains it through its final release.
        unsafe { allocation.dynamic_thread_local_backing_mut(count).unwrap()
            .initialize_owned_header(memory, count) };
        (ChildMetadataImageBlock { pointer, size }, allocation)
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn child_thread_local_consumption_survives_release_and_completion_errors() {
        use crate::single_thread::{FreeError, LocalClientFreeProgress as Progress};
        crate::test_process::run_in_fresh_process(
            "meta::tests::child_thread_local_consumption_survives_release_and_completion_errors", || {
                for growth in [false, true] {
                    for completion_error in [false, true] {
                        let allocator = static_allocator();
                        let (old, old_allocation) = child_tls_array_fixture(allocator, 16);
                        let old_pointer = old.pointer;
                        let replacement_pair = growth.then(|| child_tls_array_fixture(allocator, 32));
                        let (replacement, mut replacement_allocation) = match replacement_pair {
                            Some((block, allocation)) => (Some(block), Some(allocation)),
                            None => (None, None),
                        };
                        let replacement_pointer = replacement.as_ref().map(|block| block.pointer);
                        let mut storage = Some(old);
                        let mut pending = None;
                        let mut state = ChildThreadOwnerState::Attached;
                        crate::compiler_tls::install_dynamic_backing(old_pointer.cast());
                        let mut fast = 17usize;
                        crate::compiler_tls::set_fast_slot(Some(NonNull::from(&mut fast).cast()));
                        let mut mapping = crate::os::Mapping::map_for_allocator(config(), 4096, crate::os::MapAccess::Committed).unwrap();
                        let injection = fault::install(fault::Plan::disabled());
                        // SAFETY: the installed array is exclusively owned,
                        // no slot projection survives, and this consumes it once.
                        assert!(MetaRelease::Malloc(old_allocation).release().is_ok());
                        assert_eq!(allocator.test_allocation_audit().live_capability_count, usize::from(growth));
                        injection.set(fault::Plan::at(fault::Point::Unmap, 1, crabc_core::Errno::NOMEM));
                        assert_eq!(mapping.unmap(), Err(crabc_core::Errno::NOMEM));
                        let (progress, finished) = if completion_error {
                            (Progress::Consumed(Ok(())), Err(ChildMetadataPageEngineError::EngineRetained))
                        } else {
                            (Progress::Consumed(Err(FreeError::Lifecycle)), Ok(()))
                        };
                        let result = if growth {
                            ChildThreadOwner::complete_thread_local_growth(&mut storage, &mut pending,
                                &mut state, replacement, Some(progress), finished)
                        } else {
                            ChildThreadOwner::complete_thread_local_release(&mut storage, &mut state,
                                Some(progress), finished)
                        };
                        assert!(result.is_err());
                        assert!(storage.is_none(), "consumption never retains the old array as live");
                        assert!(crate::compiler_tls::dynamic_backing_peek().is_none());
                        assert!(crate::compiler_tls::fast_slot_peek().is_none());
                        assert_eq!(state, ChildThreadOwnerState::Terminal);
                        assert!(ChildThreadOwner::active_thread_local_backing(&storage, state).is_none());
                        assert_eq!(pending.as_ref().map(|block| block.pointer), replacement_pointer);
                        injection.set(fault::Plan::disabled());
                        mapping.unmap().unwrap();
                        if let Some(block) = pending.take() {
                            // SAFETY: terminal custody retained this unpublished
                            // replacement live; the consumed old array is absent.
                            assert_eq!(replacement_allocation.as_ref().unwrap().pointer(), block.pointer);
                            assert!(MetaRelease::Malloc(replacement_allocation.take().unwrap()).release().is_ok());
                        }
                        assert_eq!(allocator.test_allocation_audit().live_capability_count, 0);
                    }
                }
            });
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn child_thread_local_refusal_retains_exact_arrays_in_terminal_custody() {
        use crate::single_thread::{FreeError, LocalClientFreeProgress as Progress};
        crate::test_process::run_in_fresh_process(
            "meta::tests::child_thread_local_refusal_retains_exact_arrays_in_terminal_custody", || {
                for growth in [false, true] {
                    let allocator = static_allocator();
                    let (old, old_allocation) = child_tls_array_fixture(allocator, 16);
                    let original = old.pointer;
                    let replacement_pair = growth.then(|| child_tls_array_fixture(allocator, 32));
                        let (replacement, mut replacement_allocation) = match replacement_pair {
                            Some((block, allocation)) => (Some(block), Some(allocation)),
                            None => (None, None),
                        };
                    let replacement_pointer = replacement.as_ref().map(|block| block.pointer);
                    let mut storage = Some(old);
                    let mut pending = None;
                    let mut state = ChildThreadOwnerState::Attached;
                    crate::compiler_tls::install_dynamic_backing(original.cast());
                    let mut fast = 19usize;
                    crate::compiler_tls::set_fast_slot(Some(NonNull::from(&mut fast).cast()));
                    let mut mapping = crate::os::Mapping::map_for_allocator(config(), 4096, crate::os::MapAccess::Committed).unwrap();
                    let injection = fault::install(fault::Plan::at(fault::Point::Unmap, 1, crabc_core::Errno::NOMEM));
                    assert_eq!(mapping.unmap(), Err(crabc_core::Errno::NOMEM));
                    let entry = allocator.enter().unwrap();
                    let failure = MetaRelease::Malloc(old_allocation).release().unwrap_err();
                    let MetaReleaseFailure::MallocRetryable { error, allocation } = failure else {
                        panic!("recursive owner entry must refuse before array consumption");
                    };
                    assert_eq!(error, MetaError::RecursiveEntry);
                    drop(entry);
                    let old_allocation = allocation;
                    let progress = Progress::RefusedBeforeConsumption(FreeError::Lifecycle);
                    let result = if growth {
                        ChildThreadOwner::complete_thread_local_growth(&mut storage, &mut pending,
                            &mut state, replacement, Some(progress), Ok(()))
                    } else {
                        ChildThreadOwner::complete_thread_local_release(&mut storage, &mut state,
                            Some(progress), Ok(()))
                    };
                    assert!(result.is_err());
                    assert_eq!(storage.as_ref().map(|block| block.pointer), Some(original));
                    assert_eq!(pending.as_ref().map(|block| block.pointer), replacement_pointer);
                    assert_eq!(allocator.test_allocation_audit().live_capability_count, 1 + usize::from(growth));
                    assert_eq!(state, ChildThreadOwnerState::Terminal);
                    assert!(ChildThreadOwner::active_thread_local_backing(&storage, state).is_none());
                    assert!(crate::compiler_tls::dynamic_backing_peek().is_none());
                    assert!(crate::compiler_tls::fast_slot_peek().is_none());
                    injection.set(fault::Plan::disabled());
                    mapping.unmap().unwrap();
                    assert_eq!(storage.take().unwrap().pointer, old_allocation.pointer());
                    assert!(MetaRelease::Malloc(old_allocation).release().is_ok());
                    if let Some(block) = pending.take() {
                        assert_eq!(block.pointer, replacement_allocation.as_ref().unwrap().pointer());
                        assert!(MetaRelease::Malloc(replacement_allocation.take().unwrap()).release().is_ok());
                    }
                    assert_eq!(allocator.test_allocation_audit().live_capability_count, 0);
                }
            });
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn child_thread_local_growth_preserves_copied_slots_and_independent_fast_slot() {
        use crate::single_thread::LocalClientFreeProgress as Progress;
        crate::test_process::run_in_fresh_process(
            "meta::tests::child_thread_local_growth_preserves_copied_slots_and_independent_fast_slot", || {
                let allocator = static_allocator();
                let (old, old_allocation) = child_tls_array_fixture(allocator, 16);
                let (replacement, replacement_allocation) = child_tls_array_fixture(allocator, 32);
                let key = crate::thread_local::ThreadLocalKey::from_parts(
                    crate::thread_local::ThreadLocalSlotIndex::new(7).unwrap(), 11,
                ).unwrap();
                let mut value = 31usize;
                let value = core::ptr::from_mut(&mut value).cast();
                // SAFETY: both exact flexible arrays are live and exclusive.
                unsafe {
                    let old_slots = (*old.pointer.cast::<DynamicThreadLocalBacking>().as_ptr()).slots_mut();
                    crate::thread_local::ThreadLocalSlots::new(old_slots).set(key, value).unwrap();
                    core::ptr::copy_nonoverlapping(old_slots.as_ptr(),
                        (*replacement.pointer.cast::<DynamicThreadLocalBacking>().as_ptr()).slots_mut().as_mut_ptr(), 16);
                }
                crate::compiler_tls::install_dynamic_backing(old.pointer.cast());
                let mut fast = 23usize;
                let fast = NonNull::from(&mut fast).cast();
                crate::compiler_tls::set_fast_slot(Some(fast));
                let mut storage = Some(old);
                let mut pending = None;
                let mut state = ChildThreadOwnerState::Attached;
                // SAFETY: no slot projection spans the old array's sole free.
                assert!(MetaRelease::Malloc(old_allocation).release().is_ok());
                ChildThreadOwner::complete_thread_local_growth(&mut storage, &mut pending, &mut state,
                    Some(replacement), Some(Progress::Consumed(Ok(()))), Ok(())).unwrap();
                let block = storage.as_ref().unwrap();
                assert_eq!(crate::compiler_tls::dynamic_backing_peek(), Some(block.pointer.cast()));
                assert_eq!(crate::compiler_tls::fast_slot_peek(), Some(fast));
                assert_eq!(state, ChildThreadOwnerState::Attached);
                assert_eq!(ChildThreadOwner::active_thread_local_backing(&storage, state).map(|block| block.pointer), Some(block.pointer));
                assert!(pending.is_none());
                // SAFETY: successful publication retains the initialized new
                // array; only this fixture reads its copied source slots.
                let backing = unsafe { &mut *block.pointer.cast::<DynamicThreadLocalBacking>().as_ptr() };
                assert_eq!(backing.count(), 32);
                assert_eq!(crate::thread_local::ThreadLocalSlots::new(unsafe { backing.slots_mut() }).get(key), value);
                // SAFETY: the published replacement is freed exactly once.
                assert!(MetaRelease::Malloc(replacement_allocation).release().is_ok());
                ChildThreadOwner::complete_thread_local_release(&mut storage, &mut state,
                    Some(Progress::Consumed(Ok(()))), Ok(())).unwrap();
                assert!(storage.is_none());
                assert!(crate::compiler_tls::dynamic_backing_peek().is_none());
                assert!(crate::compiler_tls::fast_slot_peek().is_none());
                assert_eq!(allocator.test_allocation_audit().live_capability_count, 0);
            });
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn refused_native_child_heap_image_retains_exact_live_custody_for_release() {
        use crate::single_thread::{FreeError, LocalClientFreeProgress as Progress};
        unsafe extern "C" fn silent(_: *const core::ffi::c_char) {}
        crate::test_process::run_in_fresh_process(
            "meta::tests::refused_native_child_heap_image_retains_exact_live_custody_for_release", || {
                assert!(crate::runtime_lifecycle::test_initialize_process_from_host_environment(4096,
                    unsafe { crate::__crabc_runtime::RuntimeStderrOutput::new(silent) }));
                let mut image = NativeChildHeapImage::allocate().unwrap();
                assert!(image.initialize_empty_image());
                let original = image.pointer;
                let mut pending = crate::os::Mapping::map_for_allocator(config(), 4096, crate::os::MapAccess::Committed).unwrap();
                let injection = fault::install(fault::Plan::at(fault::Point::Unmap, 1, crabc_core::Errno::NOMEM));
                // SAFETY: the unpublished image is still live and exclusive.
                // This actual cleanup refusal happens before image consumption.
                let retained = match unsafe { image.free_with_progress(|_| {
                    assert_eq!(pending.unmap(), Err(crabc_core::Errno::NOMEM));
                    Progress::RefusedBeforeConsumption(FreeError::Lifecycle)
                }) } {
                    Err(image) => image,
                    Ok(()) => panic!("a refusal retains the exact live image"),
                };
                assert_eq!(retained.state, NativeChildHeapImageState::Live);
                assert_eq!(retained.pointer, original);
                let mut storage = None;
                let mut stage = ChildMainHeapStage::HeapListRemoved;
                ChildMainHeapContextOwner::retain_native_heap_release_failure(&mut storage, &mut stage, retained);
                assert_eq!(storage.as_ref().and_then(ChildHeapStorage::pointer_for_live_image), Some(original));
                assert_eq!(stage, ChildMainHeapStage::HeapListRemoved,
                    "a live refusal keeps only the remaining image release step available");
                let Some(ChildHeapStorage::Native(mut retained)) = storage.take() else {
                    panic!("live refusal retains the exact native image owner");
                };
                assert_eq!(retained.with_heap(|heap| core::ptr::from_ref(heap.as_ref().get_ref()).addr()), Some(original.as_ptr().addr()));
                injection.set(fault::Plan::disabled());
                pending.unmap().unwrap();
                // SAFETY: this generic pre-consumption retry has no earlier
                // Heap-list or page mutation; source image teardown is complete.
                assert!(unsafe { retained.free() }.is_ok());
            });
    }

    #[cfg(all(target_arch = "x86_64", feature = "mi-guarded"))]
    #[test]
    fn native_child_heap_image_guard_warning_reentry_retains_exact_tls_release_custody() {
        struct Callback {
            allocator: Pin<&'static MetaAllocator>,
            allocation: Option<MetaAllocation<'static>>,
            warnings: usize,
            refused: bool,
            nested: bool,
        }
        unsafe extern "C" fn silent(_: *const core::ffi::c_char) {}
        unsafe extern "C" fn output(message: *const core::ffi::c_char, argument: *mut core::ffi::c_void) {
            if message.is_null() || argument.is_null() { return; }
            // SAFETY: source output lends a terminated fragment, and the test
            // retains this exclusive callback state through synchronous free.
            let message = unsafe { core::ffi::CStr::from_ptr(message) }.to_bytes();
            if !message.starts_with(b"cannot unprotect OS memory") { return; }
            let callback = unsafe { &mut *argument.cast::<Callback>() };
            callback.warnings += 1;
            if callback.warnings != 1 { return; }
            let Some(allocation) = callback.allocation.take() else { return };
            let original = allocation.pointer();
            let result = callback.allocator.test_with_held_backing_entry(|| {
                MetaRelease::Malloc(allocation).release()
            });
            if let Ok(Err(MetaReleaseFailure::MallocRetryable { error, allocation })) = result {
                callback.refused = error == MetaError::RecursiveEntry && allocation.pointer() == original;
                callback.allocation = Some(allocation);
            }
            if let crate::runtime_lifecycle::NativePageAllocationResult::Allocated(nested) =
                crate::runtime_lifecycle::native_allocate(96, false)
            {
                // SAFETY: this independent callback client is exclusively
                // owned and consumed once, without touching the in-flight Heap.
                unsafe { nested.as_ptr().write_bytes(0x47, 96); }
                callback.nested = unsafe { crate::runtime_lifecycle::native_free(nested) }
                    == crate::runtime_lifecycle::NativePageFreeResult::Freed;
            }
        }
        crate::test_process::run_in_fresh_process(
            "meta::tests::native_child_heap_image_guard_warning_reentry_retains_exact_tls_release_custody", || {
                std::env::set_var("mimalloc_guarded_sample_rate", "1");
                let image_size = std::format!("{}", NativeChildHeapImage::image_request_size());
                std::env::set_var("mimalloc_guarded_min", &image_size);
                std::env::set_var("mimalloc_guarded_max", &image_size);
                std::env::set_var("mimalloc_show_errors", "1");
                assert!(crate::runtime_lifecycle::test_initialize_process_from_host_environment(4096,
                    unsafe { crate::__crabc_runtime::RuntimeStderrOutput::new(silent) }));
                let allocator = static_allocator();
                let (backing, mut allocation) = child_tls_array_fixture(allocator, 16);
                let key = crate::thread_local::ThreadLocalKey::from_parts(
                    crate::thread_local::ThreadLocalSlotIndex::new(7).unwrap(), 11,
                ).unwrap();
                let mut value = 41usize;
                let value = core::ptr::from_mut(&mut value).cast();
                // SAFETY: this exact flexible array is exclusively live; its
                // slot value remains borrowed from the enclosing fixture.
                unsafe { crate::thread_local::ThreadLocalSlots::new(
                    allocation.dynamic_thread_local_backing_mut(16).unwrap().slots_mut(),
                ).set(key, value).unwrap(); }
                let mut image = NativeChildHeapImage::allocate().unwrap();
                assert!(image.initialize_empty_image());
                let binding = crate::process_init::ProcessMainInitializationStorage::global()
                    .ready_child_subprocess_inputs().unwrap().0;
                // SAFETY: this exclusively owned unpublished image retains
                // the PageMap registration through the short observation.
                let observed = unsafe { binding.page_map().lookup_live_allocation(image.pointer.cast()) }
                    .unwrap().unwrap();
                assert!(observed.is_guarded());
                assert_eq!(unsafe { crate::types::Page::theap_at(observed.page()) },
                    crate::compiler_tls::default_theap().as_ptr(),
                    "the exact image belongs to the original process-main issuer");
                drop(observed);
                let mut callback = Callback { allocator, allocation: Some(allocation),
                    warnings: 0, refused: false, nested: false };
                let output_owner = crate::process_init::process_output_owner().unwrap();
                // SAFETY: registration and delivery are confined to this
                // isolated thread; the callback state outlives the sole free.
                unsafe { output_owner.register_output(Some(output), core::ptr::from_mut(&mut callback).cast()); }
                let fault = fault::install(fault::Plan::at(fault::Point::Unprotect, 1, crabc_core::Errno::NOMEM));
                // SAFETY: this unpublished Heap has no list, Theap, page or
                // image projection. The callback owns only distinct clients.
                assert!(unsafe { image.free() }.is_ok());
                // Source unprotect failure warns but does not cancel free.
                // The consumed image is never observed or retried afterwards.
                assert_eq!(fault.observed(), 1);
                assert_eq!(callback.warnings, 1);
                assert!(callback.refused && callback.nested);
                // SAFETY: synchronous free ended before unregistering output.
                unsafe { output_owner.register_output(None, core::ptr::null_mut()); }
                fault.set(fault::Plan::disabled());
                assert_eq!(allocator.test_allocation_audit().live_capability_count, 1);
                let mut allocation = callback.allocation.take().unwrap();
                assert_eq!(allocation.pointer(), backing.pointer);
                // SAFETY: recursive entry refused before consumption, so this
                // retained exact array and copied source slot remain live.
                assert_eq!(unsafe { crate::thread_local::ThreadLocalSlots::new(
                    allocation.dynamic_thread_local_backing_mut(16).unwrap().slots_mut(),
                ).get(key) }, value);
                assert!(MetaRelease::Malloc(allocation).release().is_ok());
                assert_eq!(allocator.test_allocation_audit().live_capability_count, 0);
            });
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn native_child_heap_image_release_after_issuing_worker_finish_uses_retained_source_page() {
        struct Transfer(NativeChildHeapImage);
        // SAFETY: the worker transfers this unique unpublished image only
        // after ending every projection. Source subprocess-safe free may
        // publish it remotely while its original Page/backing remain retained.
        unsafe impl Send for Transfer {}
        unsafe extern "C" fn silent(_: *const core::ffi::c_char) {}
        crate::test_process::run_in_fresh_process(
            "meta::tests::native_child_heap_image_release_after_issuing_worker_finish_uses_retained_source_page", || {
                assert!(crate::runtime_lifecycle::test_initialize_process_from_host_environment(4096,
                    unsafe { crate::__crabc_runtime::RuntimeStderrOutput::new(silent) }));
                assert!(crate::runtime_lifecycle::prepare_native_later_thread_arena());
                let transferred = std::thread::spawn(|| {
                    let descriptor = crate::runtime_lifecycle::current_native_allocator_thread_descriptor();
                    // SAFETY: the joined host worker retains its TLS mapping
                    // through registration, source owner finish and transfer.
                    // No fork or terminal registry scan visits this test worker.
                    assert!(unsafe { crate::runtime_lifecycle::register_current_native_allocator_worker_descriptor(descriptor) });
                    assert_eq!(crate::runtime_lifecycle::attach_current_thread(),
                        crate::runtime_lifecycle::ThreadAttachResult::Attached);
                    let mut image = NativeChildHeapImage::allocate().unwrap();
                    assert!(image.initialize_empty_image());
                    let issuer = crate::compiler_tls::default_theap();
                    assert_eq!(crate::runtime_lifecycle::finish_current_thread_native_after_user_destructors(),
                        crate::runtime_lifecycle::ThreadFinishResult::Finished);
                    (Transfer(image), issuer.as_ptr().addr())
                }).join().unwrap();
                let (Transfer(mut image), issuer) = transferred;
                assert_ne!(crate::compiler_tls::default_theap().as_ptr().addr(), issuer);
                let binding = crate::process_init::ProcessMainInitializationStorage::global()
                    .ready_child_subprocess_inputs().unwrap().0;
                // SAFETY: transfer retains this exact still-live image and
                // its original abandoned Page; only short identity reads occur.
                let observed = unsafe { binding.page_map().lookup_live_allocation(image.pointer.cast()) }
                    .unwrap().unwrap();
                assert!(!observed.is_associated_with(crate::compiler_tls::current_thread_identity().unwrap()),
                    "the retired worker's Page is not this releasing thread's local page");
                drop(observed);
                assert!(image.with_heap(|_| ()).is_some());
                // SAFETY: the joined issuer ended all image projections and
                // this exact remote capability is published once, without reclaim.
                assert!(unsafe { image.free() }.is_ok());
                let mut recovery = NativeChildHeapImage::allocate().unwrap();
                assert!(recovery.initialize_empty_image());
                // SAFETY: this newly issued image owns independent current
                // custody; no consumed pointer is accessed or retried.
                assert!(unsafe { recovery.free() }.is_ok());
            });
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn prepared_native_child_heap_image_refusal_retains_only_release_authority() {
        use crate::single_thread::{FreeError, LocalClientFreeProgress as Progress};
        unsafe extern "C" fn silent(_: *const core::ffi::c_char) {}
        crate::test_process::run_in_fresh_process(
            "meta::tests::prepared_native_child_heap_image_refusal_retains_only_release_authority", || {
                assert!(crate::runtime_lifecycle::test_initialize_process_from_host_environment(4096,
                    unsafe { crate::__crabc_runtime::RuntimeStderrOutput::new(silent) }));
                let mut image = NativeChildHeapImage::allocate().unwrap();
                assert!(image.initialize_empty_image());
                let original = image.pointer;
                let operation = crate::runtime_lifecycle::NativeSubprocessOperation::enter().unwrap();
                // SAFETY: the unique unpublished image has no list, Theap or
                // page users; source preparation runs with actual admission.
                unsafe { image.prepare_for_free(&operation) }.unwrap();
                let mut pending = crate::os::Mapping::map_for_allocator(config(), 4096, crate::os::MapAccess::Committed).unwrap();
                let injection = fault::install(fault::Plan::at(fault::Point::Unmap, 1, crabc_core::Errno::NOMEM));
                // SAFETY: this real cleanup refusal precedes consumption of
                // the prepared image. Its allocation remains exactly live.
                let retained = match unsafe { image.free_with_progress(|_| {
                    assert_eq!(pending.unmap(), Err(crabc_core::Errno::NOMEM));
                    Progress::RefusedBeforeConsumption(FreeError::Lifecycle)
                }) } {
                    Err(image) => image,
                    Ok(()) => panic!("the prepared refusal retains release authority"),
                };
                assert_eq!(retained.state, NativeChildHeapImageState::Prepared);
                assert_eq!(retained.pointer, original);
                let mut storage = None;
                let mut stage = ChildMainHeapStage::HeapListRemoved;
                ChildMainHeapContextOwner::retain_native_heap_release_failure(&mut storage, &mut stage, retained);
                assert_eq!(stage, ChildMainHeapStage::HeapListRemoved);
                assert_eq!(storage.as_ref().and_then(ChildHeapStorage::pointer_for_live_image), None);
                let Some(ChildHeapStorage::Native(mut retained)) = storage.take() else {
                    panic!("prepared refusal retains the exact release-only token");
                };
                assert!(!retained.initialize_empty_image());
                assert_eq!(retained.with_heap(|_| panic!("prepared bytes cannot be a Heap image")), None::<()>);
                injection.set(fault::Plan::disabled());
                pending.unmap().unwrap();
                drop(operation);
                // SAFETY: exact prepared custody authorizes only the final
                // source free. A retry must not repeat padding marking/fill.
                assert!(unsafe { retained.free() }.is_ok());
            });
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn consumed_native_child_heap_image_keeps_only_terminal_diagnostic_custody() {
        use crate::single_thread::{FreeError, LocalClientFreeProgress as Progress};
        unsafe extern "C" fn silent(_: *const core::ffi::c_char) {}
        crate::test_process::run_in_fresh_process(
            "meta::tests::consumed_native_child_heap_image_keeps_only_terminal_diagnostic_custody", || {
                assert!(crate::runtime_lifecycle::test_initialize_process_from_host_environment(4096,
                    unsafe { crate::__crabc_runtime::RuntimeStderrOutput::new(silent) }));
                let mut image = NativeChildHeapImage::allocate().expect("the source parent allocates an unpublished image");
                assert!(image.initialize_empty_image());
                let original = image.pointer;
                let mut pending = crate::os::Mapping::map_for_allocator(config(), 4096, crate::os::MapAccess::Committed).unwrap();
                let injection = fault::install(fault::Plan::disabled());
                // SAFETY: this unique unpublished image has no list, Theap or
                // page users. Its actual free consumes it before mapping cleanup.
                let retained = match unsafe { image.free_with_progress(|pointer| {
                    assert_eq!(crate::runtime_lifecycle::native_free(pointer), crate::runtime_lifecycle::NativePageFreeResult::Freed);
                    injection.set(fault::Plan::at(fault::Point::Unmap, 1, crabc_core::Errno::NOMEM));
                    assert_eq!(pending.unmap(), Err(crabc_core::Errno::NOMEM));
                    Progress::Consumed(Err(FreeError::Lifecycle))
                }) } {
                    Err(image) => image,
                    Ok(()) => panic!("a completion failure retains diagnostic custody"),
                };
                assert_eq!(retained.pointer, original);
                assert_eq!(retained.state, NativeChildHeapImageState::Terminal,
                    "a consumed image token cannot offer live projection or release retry");
                let mut storage = None;
                let mut stage = ChildMainHeapStage::HeapListRemoved;
                ChildMainHeapContextOwner::retain_native_heap_release_failure(&mut storage, &mut stage, retained);
                assert_eq!(storage.as_ref().and_then(ChildHeapStorage::pointer_for_live_image), None);
                assert_eq!(stage, ChildMainHeapStage::Terminal,
                    "full child release cannot offer continuation after image consumption");
                let Some(ChildHeapStorage::Native(mut retained)) = storage.take() else {
                    panic!("terminal settlement retains the exact native diagnostic token");
                };
                assert!(!retained.initialize_empty_image());
                assert_eq!(retained.with_heap(|_| panic!("a consumed image cannot be projected")), None::<()>);
                // SAFETY: terminal custody must refuse before passing any
                // address to a release primitive; no second source free runs.
                assert!(unsafe { retained.free_with_progress(|_| panic!("terminal image reached a release primitive")) }.is_err());
                injection.set(fault::Plan::disabled());
                pending.unmap().expect("the exact failed mapping owner remains retained");
            });
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn child_owner_destination_stays_vacant_until_heap_is_ready() {
        crate::main_heap_page::tests::with_owner_local_fixture(true, |attachment, mut heap_owner, pair| {
            let (parent, registry, binding) =
                crate::subproc::lifecycle::tests::child_fixture_inputs(attachment, pair);
            let config = attachment.memory_config().unwrap();
            let mut context = ChildContextOwner::allocate(
                attachment.parent_metadata_allocator(), parent, config,
            ).ok().expect("ordinary child context allocation");
            let memory = context.with_lease(|lease| lease.context_memory_id());
            context.with_image(|image| {
                // SAFETY: the isolated registry holds this parent and the
                // exclusively owned child has not yet been published.
                unsafe { registry.initialize_child(image.get_ref(), parent.identity(), memory) }
                    .expect("ordinary source child registration");
            }).unwrap();
            let storage = heap_owner.allocate_child_heap_storage(attachment).unwrap().unwrap();
            let mut child = context.bind_heap_storage(ChildHeapStorage::Parent(storage))
                .ok().expect("ordinary parent-issued Heap storage");
            assert_eq!(child.stage(), ChildMainHeapStage::Registered);
            let mut destination = ChildThreadInitializationStorage::vacant();
            // SAFETY: arbitrary initialized bytes are valid for MaybeUninit;
            // no owner projection exists and its alignment/extent are exact.
            unsafe { destination.owner.as_mut_ptr().cast::<u8>().write_bytes(0xa5, size_of::<ChildThreadOwner>()) };
            // SAFETY: this source initializer owns the child and the entire
            // vacant destination. The registered child has no ready Heap yet.
            let outcome = unsafe { child.allocate_child_thread_owner_into(binding, &mut destination) };
            assert!(matches!(outcome, ChildThreadOwnerInitializationOutcome::Rejected(ChildThreadStartError::InvalidTransition)));
            assert!(!destination.owns_candidate());
            // SAFETY: the scalar admission refusal precedes every destination
            // write; all bytes still carry the initialized sentinel above.
            let bytes = unsafe { core::slice::from_raw_parts(destination.owner.as_ptr().cast::<u8>(), size_of::<ChildThreadOwner>()) };
            assert!(bytes.iter().all(|byte| *byte == 0xa5));
            // SAFETY: the sole child initializer now completes the ordinary
            // source Heap and metadata-Theap publication in their original order.
            unsafe { child.initialize_heap_and_metadata_theap(config) }.unwrap();
            assert_eq!(child.stage(), ChildMainHeapStage::HeapReady);
            // SAFETY: this child has no threads, user pages or escaped views.
            unsafe { crate::subproc::lifecycle::destroy_child(
                child, registry, binding, &mut [], attachment, &mut heap_owner,
            ) }.ok().expect("ordinary empty child destruction");
            heap_owner.finish(attachment).ok().expect("parent engine retirement");
            attachment.finish_after_user_destructors().ok().expect("parent attachment retirement");
        });
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn child_image_projection_preserves_embedded_control_borrow() {
        let mut storage = std::boxed::Box::new(core::mem::MaybeUninit::<crate::subproc::ChildSubprocessImage>::uninit());
        let pointer = NonNull::from(storage.as_mut()).cast::<u8>();
        let mut allocation = ChildMetadataAllocation::Child {
            pointer, size: size_of::<crate::subproc::ChildSubprocessImage>(), role: ChildMetadataRole::Fresh,
        };
        let control = allocation.initialize_child_subprocess_image().unwrap()
            .native_control_pointer().cast::<core::mem::MaybeUninit<crate::subproc::lifecycle::NativeChildSubprocess>>();
        let control_size = size_of::<crate::subproc::lifecycle::NativeChildSubprocess>();
        // SAFETY: the initialized source image owns this aligned interior
        // mutable slot. Its MaybeUninit representation permits arbitrary
        // bytes, and no initialized record projection exists.
        unsafe { control.as_ptr().cast::<u8>().write_bytes(0, control_size); }
        // SAFETY: every byte in the exclusive slot was initialized above;
        // the source allocation stays live through this short projection.
        let control = unsafe { core::slice::from_raw_parts_mut(control.as_ptr().cast::<u8>(), control_size) };
        fn child_is_registered<P: core::ops::Deref<Target = crate::subproc::ChildSubprocessImage>>(
            image: Pin<P>,
        ) -> bool { image.identity().is_registered() }
        fn project_with_control_borrow(control: &mut [u8], allocation: &mut ChildMetadataAllocation) {
            let image = allocation.child_subprocess_image().unwrap();
            assert!(!child_is_registered(image));
            // The real native owner lives in this same interior mutable slot.
            // A source identity projection must preserve its independent borrow.
            control[0] = 1;
        }
        project_with_control_borrow(control, &mut allocation);
        drop(allocation);
        drop(storage);
    }

    #[cfg(all(target_arch = "x86_64", not(miri), feature = "mi-debug-3"))]
    #[test]
    fn child_metadata_engine_drop_retains_original_live_page_assertion() {
        unsafe extern "C" fn silent(_: *const core::ffi::c_char) {}
        unsafe fn observe(snapshot: &crate::types::PageValiditySnapshot, argument: *mut core::ffi::c_void) -> Option<usize> {
            let area = unsafe { &*argument.cast::<usize>() };
            if snapshot.area.as_ptr().addr() == *area {
                assert_eq!((snapshot.capacity, snapshot.used), (1, 1));
                return Some(usize::from(snapshot.capacity) + 1);
            }
            None
        }
        crate::test_process::run_in_fresh_process(
            "meta::tests::child_metadata_engine_drop_retains_original_live_page_assertion", || {
                assert!(crate::runtime_lifecycle::test_initialize_process_from_host_environment(4096,
                    unsafe { crate::__crabc_runtime::RuntimeStderrOutput::new(silent) }));
                assert!(crate::runtime_lifecycle::prepare_native_later_thread_arena());
                let id = crate::subproc::lifecycle::native_subproc_new().unwrap();
                let (binding, _) = crate::process_init::ProcessMainInitializationStorage::global()
                    .ready_child_subprocess_inputs().unwrap();
                unsafe { id.with_owner(|owner| {
                    let owner = owner.as_mut().unwrap();
                    let (client, page, theap, area) = owner.with_metadata_page_engine(binding, |_, engine| {
                        let client = engine.allocate_zeroed(12280).unwrap();
                        client.as_ptr().write(0x5a);
                        let page = NonNull::new(engine.page_for_block(client)).unwrap();
                        let snapshot = crate::types::Page::validity_snapshot_at(page);
                        assert_eq!((snapshot.capacity, snapshot.used), (1, 1));
                        (client, page, engine.allocation_theap(), snapshot.area.as_ptr().addr())
                    }).unwrap();
                    // This observer overrides only a copied scalar. The actual
                    // client, registered Page and live lists remain unchanged.
                    let result = crate::page_validity::with_live_page_validity_observer_for_test(
                        observe, core::ptr::from_ref(&area).cast_mut().cast(), || {
                            owner.with_metadata_page_engine(binding, |_, engine| {
                                assert!(engine.allocate_zeroed(12280).is_none());
                            })
                        });
                    assert!(matches!(result, Err(ChildMetadataPageEngineError::EngineRetained)));
                    let task = owner.pending_live_page_validity.as_ref().expect("the exact detached Page task survives Engine Drop");
                    assert!(task.matches_theap(theap));
                    assert!(task.has_retirement_refusal_marker());
                    assert_eq!(owner.page_engine, ChildPageEngineState::Poisoned);
                    assert_eq!(owner.stage(), ChildMainHeapStage::HeapReady);
                    assert_eq!(binding.page_map().lookup_registered_page(client.as_ptr()).unwrap(), Some(page));
                    assert_eq!(client.as_ptr().read(), 0x5a);
                    assert!(owner.with_metadata_page_engine(binding, |_, _| ()).is_err(),
                        "the retained issuing engine cannot reopen or retire its live Page");
                }) }.unwrap();
                // The actual context retains the task's Page and backing until
                // process exit; diagnostic witness refusal grants no cleanup.
            });
    }

    #[cfg(all(target_arch = "x86_64", not(miri), feature = "mi-debug-3"))]
    #[test]
    fn child_metadata_engine_drop_retains_original_fresh_os_claim() {
        use crate::subproc::lifecycle::*;
        unsafe extern "C" fn silent(_: *const core::ffi::c_char) {}
        struct Probe {
            map: crate::process_page_map::ProcessPageMapRoot,
            observations: core::cell::Cell<usize>,
            theap: core::cell::Cell<Option<NonNull<Theap>>>,
            baseline: core::cell::Cell<Option<crate::statistics::FinalStatCount>>,
        }
        unsafe fn observe(state: &crate::types::PageValiditySnapshot,
            page: NonNull<crate::types::Page>, argument: *mut core::ffi::c_void) {
            // SAFETY: the scoped observer owns its stack probe, and the engine
            // retains this exact initialized committed region before lists or
            // clients are published. Only one owned backing byte changes.
            let probe = unsafe { &*argument.cast::<Probe>() };
            probe.observations.set(probe.observations.get() + 1);
            let theap = probe.theap.get().expect("original metadata issuer");
            let baseline = probe.baseline.get().unwrap();
            let registered = unsafe { probe.map.lookup_registered_page(state.area.as_ptr()) }.unwrap();
            let pages = unsafe { Theap::final_statistics_at(theap) }.unwrap().1.pages;
            assert_eq!((registered, pages.total, pages.current),
                (Some(page), baseline.total + 1, baseline.current + 1),
                "original PageMap and statistics are registered before the genuine source refusal");
            assert_eq!(state.used, 0);
            assert_eq!(state.capacity, 0);
            assert!(state.free.is_null());
            unsafe { state.area.as_ptr().write(0x5a) };
        }
        crate::test_process::run_in_fresh_process(
            "meta::tests::child_metadata_engine_drop_retains_original_fresh_os_claim", || {
                assert!(crate::runtime_lifecycle::test_initialize_process_from_host_environment(4096,
                    unsafe { crate::__crabc_runtime::RuntimeStderrOutput::new(silent) }));
                assert!(crate::runtime_lifecycle::prepare_native_later_thread_arena());
                crate::source_options_api::option_set(crate::config::SourceOption::ArenaReserve as i32, 0);
                crate::source_options_api::option_set(crate::config::SourceOption::DisallowArenaAlloc as i32, 1);
                let id = native_subproc_new().expect("actual child issuer");
                let (binding, _) = crate::process_init::ProcessMainInitializationStorage::global()
                    .ready_child_subprocess_inputs().unwrap();
                let probe = Probe { map: binding.page_map(), observations: core::cell::Cell::new(0),
                    theap: core::cell::Cell::new(None), baseline: core::cell::Cell::new(None) };
                let result = unsafe { id.with_owner(|owner| {
                    let owner = owner.as_mut().unwrap();
                    // SAFETY: the probe and actual child issuer remain live
                    // throughout this synchronous engine operation. The
                    // callback neither allocates nor reenters the allocator.
                    let result = crate::page_validity::with_fresh_page_initialization_observer_for_test(
                        observe, core::ptr::from_ref(&probe).cast_mut().cast(), || {
                            owner.with_metadata_page_engine(binding, |child, engine| {
                                let original_theap = engine.allocation_theap();
                                probe.theap.set(Some(original_theap));
                                probe.baseline.set(Some(Theap::final_statistics_at(original_theap).unwrap().1.pages));
                                // Detached metadata has no ordinary caller-stack
                                // frequency phase. Its actual allocation entry
                                // retains the failed candidate in this engine.
                                assert!(engine.allocate_aligned(7, 128 * 1024).is_none());
                                let task = engine.take_pending_fresh_initialization()
                                    .expect("actual failed source initialization retains its original claim");
                                assert!(task.matches_theap(original_theap));
                                assert!(task.belongs_to_subprocess(child.identity()));
                                assert_eq!(task.failure(), crate::single_thread::FreshOsPageInitializationFailure::SourceObservation(
                                    crate::page_validity::SourcePageInvariant::InitiallyZero));
                                assert!(!task.has_retirement_refusal_marker());
                                assert!(engine.retain_fresh_os_initialization(task).is_ok());
                            })
                        });
                    assert!(owner.pending_fresh_initialization.is_some(),
                        "engine Drop transfers the original claim to its retained issuer");
                    let retained = owner.pending_fresh_initialization.as_ref().unwrap();
                    assert!(retained.matches_theap(probe.theap.get().unwrap()));
                    assert!(retained.has_retirement_refusal_marker());
                    assert!(owner.context.with_image(|child|
                        retained.belongs_to_subprocess(child.identity())).unwrap());
                    assert_eq!(owner.page_engine, ChildPageEngineState::Poisoned);
                    assert!(matches!(owner.with_metadata_page_engine(binding, |_, _| ()),
                        Err(ChildMetadataPageEngineError::InvalidTransition)));
                    result
                }) }.expect("actual child lock");
                assert_eq!(probe.observations.get(), 1);
                assert!(matches!(result, Err(ChildMetadataPageEngineError::EngineRetained)));
                // The actual child control, Heap, metadata Theap and PageMap
                // remain retained with the terminal task; no fabricated retry
                // or diagnostic admission is created from their addresses.
            });
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn source_metadata_prelink_refusal_resets_only_theap_and_retains_claimed_slot() {
        struct ScopedTldMutex(NonNull<ThreadLocalData>);
        // SAFETY: the scoped worker projects only the synchronized list mutex;
        // the actual fixture retains the original writable TLD allocation.
        unsafe impl Send for ScopedTldMutex {}
        impl ScopedTldMutex {
            fn hold(self, ready: &Barrier, release: &Barrier) -> bool {
                // SAFETY: the owner retains the TLD through the joined worker;
                // the bounded body neither allocates nor enters the allocator.
                unsafe { ThreadLocalData::with_locked_theap_list_for_test_at(self.0, || {
                    ready.wait();
                    release.wait();
                }) }.is_some()
            }
        }
        let owner = MetaAllocator::test_static_owner();
        let subprocess = owner.test_default_subprocess();
        let storage = crate::main_theap::MainStaticAttachmentStorage::test_static_owner();
        let mut selection = subprocess.reserve_static_bootstrap().unwrap();
        let foundation = crate::main_theap::MainStaticHeapFoundation::initialize(
            storage, subprocess, &mut selection,
        ).unwrap();
        // SAFETY: the fixture owns the previously untouched pinned slot; no
        // whole-bootstrap projection is formed after its field pointers exist.
        let bootstrap = unsafe { NonNull::new_unchecked(owner.bootstrap.get().cast::<ExclusiveTheapBootstrap>()) };
        unsafe { bootstrap.as_ptr().write(ExclusiveTheapBootstrap::new()) };
        let phase = unsafe { ExclusiveTheapBootstrap::prepare_source_metadata_at(
            bootstrap, foundation.metadata_heap(),
        ) }.unwrap();
        let (theap, tld) = unsafe { ExclusiveTheapBootstrap::test_source_metadata_pointers_at(bootstrap) };
        owner.status.store(BINDING, Ordering::Release);
        let mut binding = SourceMetadataBinding { owner, bootstrap, complete: false };
        let ready = Barrier::new(2);
        let release = Barrier::new(2);
        let (refused, image, original_lock_busy, retry_refused) = std::thread::scope(|scope| {
            let lock_owner = ScopedTldMutex(tld);
            let observer = scope.spawn(|| lock_owner.hold(&ready, &release));
            ready.wait();
            // SAFETY: this original binding retains all three images; only
            // the foreign mutex guard overlaps, so attachment must refuse.
            let refused = matches!(unsafe { binding.attach_source_options(phase,
                crate::types::SourceTheapOptions::release_defaults_for_test()) },
                Err(MetaError::InitializationRetained));
            let image = unsafe { theap.as_ref().test_main_static_fields() };
            let original_lock_busy = unsafe {
                ThreadLocalData::with_locked_theap_list_for_test_at(tld, || ()).is_none()
            };
            drop(binding);
            let retry_refused = matches!(owner.prepare_for_main_subprocess(config(), subprocess),
                Err(MetaError::InitializationRetained));
            // Release and join the foreign guard before any assertion can
            // unwind the owning fixture or strand the observer.
            release.wait();
            assert!(observer.join().unwrap());
            (refused, image, original_lock_busy, retry_refused)
        });
        assert!(refused && original_lock_busy && retry_refused);
        assert!(!image.initialized && !image.random_initialized);
        assert!(image.detached, "an unattached failure restores the empty Theap prefix");
        assert!(!image.allows_page_reclaim && image.allows_page_abandon);
        assert_eq!(image.page_full_retain, 0);
        assert_eq!(image.memid.kind(), MemoryKind::Static);
        assert_eq!(owner.status.load(Ordering::Acquire), FAILED);
        assert!(unsafe { tld.as_ref().test_theaps_lock_starts_and_restores_unlocked() });
        selection.retain();
    }

    #[cfg(all(target_arch = "x86_64", not(miri)))]
    #[test]
    fn child_attached_deferred_callback_allocates_on_fixed_and_auxiliary_heaps() {
        use crate::subproc::lifecycle::*;
        use crate::runtime_lifecycle::{self, NativePageFreeResult};
        use core::ffi::c_void;
        use core::sync::atomic::AtomicBool;
        unsafe fn environment() -> *const *const core::ffi::c_char { core::ptr::null() }
        unsafe extern "C" fn stderr(_: *const core::ffi::c_char) {}
        struct Context { heap: NonNull<Heap>, fixed: bool, calls: AtomicUsize, nested: AtomicBool }
        unsafe extern "C" fn callback(_: bool, _: u64, argument: *mut c_void) {
            // The synchronous invocation retains the selected Heap/member and
            // the stack argument. Its recursion guard excludes redispatch,
            // while an ordinary allocation on that owner remains valid.
            let context = unsafe { &*argument.cast::<Context>() };
            context.calls.fetch_add(1, Ordering::AcqRel);
            let block = if context.fixed {
                match native_child_thread_allocate(33, None, false) {
                    Some(runtime_lifecycle::NativePageAllocationResult::Allocated(block)) => Some(block),
                    _ => None,
                }
            } else { unsafe { native_child_heap_allocate(context.heap, 33) }.flatten() };
            if let Some(block) = block {
                context.nested.store(unsafe { runtime_lifecycle::native_free(block) }
                    == NativePageFreeResult::Freed, Ordering::Release);
            }
        }
        crate::test_process::run_in_fresh_process(
            "meta::tests::child_attached_deferred_callback_allocates_on_fixed_and_auxiliary_heaps",
            || {
                let facts = unsafe { runtime_lifecycle::NativeProcessStartupFacts::new(
                    4096, environment, crate::__crabc_runtime::RuntimeStderrOutput::new(stderr),
                ) }.unwrap();
                assert!(runtime_lifecycle::publish_native_process_startup_facts(facts));
                assert!(runtime_lifecycle::initialize_process());
                assert!(runtime_lifecycle::prepare_native_later_thread_arena());
                let child = native_subproc_new().unwrap();
                let observations = std::thread::spawn(move || {
                    let descriptor = crate::__crabc_runtime::current_native_allocator_thread_descriptor();
                    assert!(unsafe { crate::__crabc_runtime::register_current_native_allocator_worker_descriptor(descriptor) });
                    assert!(unsafe { native_subproc_add_current_thread(child) }.is_ok());
                    let fixed = crate::compiler_tls::default_theap();
                    let fixed_heap = NonNull::new(unsafe { Theap::heap_at(fixed) }).unwrap();
                    let auxiliary = native_child_heap_new().unwrap().unwrap().unwrap();
                    let client = unsafe { native_child_heap_allocate(auxiliary, 80) }.flatten().unwrap();
                    let auxiliary_theap = unsafe { native_child_heap_theap(auxiliary) }.unwrap();
                    let mut observations = std::vec::Vec::new();
                    for (heap, theap) in [(fixed_heap, fixed), (auxiliary, auxiliary_theap)] {
                        let mut context = Context { heap, fixed: heap == fixed_heap,
                            calls: AtomicUsize::new(0), nested: AtomicBool::new(false) };
                        unsafe { crate::deferred_free::register_process_callback(Some(callback),
                            core::ptr::from_mut(&mut context).cast()) };
                        let tld = NonNull::new(unsafe { Theap::tld_at(theap) }).unwrap();
                        let _operation = runtime_lifecycle::NativeSubprocessOperation::enter().unwrap();
                        // The production source primitive owns the real TLD
                        // recursion guard for this entire callback window.
                        let invocation = unsafe { crate::deferred_free::begin_process(theap, tld, false) }.unwrap();
                        assert!(unsafe { crate::__crabc_runtime::with_native_allocator_callback_boundary(|| {
                            invocation.invoke()
                        }) }.is_ok());
                        unsafe { crate::deferred_free::register_process_callback(None, core::ptr::null_mut()) };
                        observations.push((context.calls.load(Ordering::Acquire), context.nested.load(Ordering::Acquire)));
                    }
                    assert_eq!(unsafe { runtime_lifecycle::native_free(client) }, NativePageFreeResult::Freed);
                    assert!(unsafe { native_child_heap_release(auxiliary, false) }.unwrap().unwrap().is_ok());
                    assert_eq!(runtime_lifecycle::finish_current_thread_native_after_user_destructors(),
                        runtime_lifecycle::ThreadFinishResult::Finished);
                    observations
                }).join().unwrap();
                assert_eq!(unsafe { native_subproc_destroy(child) }, Ok(()));
                assert_eq!(observations, [(1, true), (1, true)]);
            },
        );
    }


    #[test]
    fn requested_child_theap_prepublication_errors_return_exact_arena_slice() {
        let layout = std::alloc::Layout::from_size_align(ARENA_MIN_SIZE, ARENA_ALIGNMENT).unwrap();
        // SAFETY: the layout is nonzero and page-aligned; the region stays
        // live until its arena view and registry have gone out of scope.
        let region = unsafe { std::alloc::alloc_zeroed(layout) };
        assert!(!region.is_null());
        {
            let subprocess = MainSubprocess::test_static_owner();
            let registry = ArenaRegistry::new(subprocess.as_ptr());
            // SAFETY: this exclusive zeroed region has the required alignment
            // and remains live for the registry and every claim below.
            let managed = unsafe { crate::arena::manage_external_in_place(
                &registry, region, ARENA_MIN_SIZE, PageSize::new(4096).unwrap(),
                true, false, true, -1, true, None,
            ) }.unwrap();
            // SAFETY: the registry retains the initialized arena and region.
            let view = unsafe { crate::arena::ArenaView::from_ptr(managed.arena_id().as_ptr()) }.unwrap();
            let errors = [
                crate::types::TheapDynamicInitError::InvalidInput,
                crate::types::TheapDynamicInitError::ThreadList(
                    crate::types::ThreadLocalTheapListError::Busy),
            ];
            let mut first_slice = None;
            for error in errors {
                let claim = view.try_claim_suitable_slices(
                    managed.arena_id(), crate::config::ARENA_MIN_OBJ_SLICES, true, 0,
                ).expect("the requested parent has a Theap slice");
                let slice = claim.slice_index();
                if let Some(first) = first_slice {
                    assert_eq!(slice, first, "the preceding failure returned its exact slice");
                } else {
                    first_slice = Some(slice);
                }
                // SAFETY: the live committed claim is large enough for this
                // image; the rollback helper consumes it before reuse.
                unsafe { claim.start().cast::<ChildHeapTheapImage>().write(
                    ChildHeapTheapImage {
                        theap: Theap::empty(),
                        page_engine: ChildPageEngineState::Active,
                    },
                ) };
                // SAFETY: the complete image was written into this claim.
                assert_eq!(
                    unsafe { finish_child_requested_theap_claim(claim, Err(error)) },
                    Err(ChildHeapTheapError::TheapInitialization(error)),
                );
                // SAFETY: no claim or other mutable bitmap view remains.
                let free = unsafe { view.slices_free() }.unwrap();
                assert_eq!(free.is_set_range(slice, crate::config::ARENA_MIN_OBJ_SLICES), Some(true));
            }
        }
        // SAFETY: the arena registry and every view and claim have ended.
        unsafe { std::alloc::dealloc(region, layout) };
    }

    #[test]
    fn child_page_engine_retry_and_poison_states_keep_teardown_distinct() {
        let active = ChildPageEngineState::Active;
        assert!(active.permits_page_projection());
        assert!(active.permits_teardown());

        let retry_pending = active.with_retained_release(true).unwrap();
        assert_eq!(retry_pending, ChildPageEngineState::RetryPending);
        assert!(!retry_pending.permits_page_projection());
        assert!(!retry_pending.permits_teardown());
        assert_eq!(retry_pending.latch_unfinished(), retry_pending,
            "an accounted unmap remains recoverable when the engine drops");
        let retry_complete = retry_pending.complete_raw_retry().unwrap();
        assert_eq!(retry_complete, ChildPageEngineState::RetryComplete);
        assert!(!retry_complete.permits_page_projection());
        assert!(retry_complete.permits_teardown());

        let publication_failure = active.with_retained_release(false).unwrap();
        assert_eq!(publication_failure, ChildPageEngineState::Poisoned);
        assert_eq!(publication_failure.latch_unfinished(), publication_failure);
        assert!(!publication_failure.permits_page_projection());
        assert!(!publication_failure.permits_teardown());
        assert!(publication_failure.complete_raw_retry().is_none());
    }

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

    /// A detached metadata request reaching a fresh page while one OS
    /// primitive stays unavailable. Each case has one fresh process owner.
    /// A failed request publishes no capability, rolls its private mapping
    /// back, and leaves the live metadata owner, its PageMap entry, and the
    /// engine usable: the same request succeeds once the primitive recovers.
    /// The recovery trace records each lazy PageMap submap separately because
    /// the kernel may place fresh mappings on opposite sides of a submap
    /// boundary in otherwise equivalent processes.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn emit_metadata_publication_fault_receiver_trace() {
        const WARM_SIZE: usize = 64;
        const REQUEST_SIZE: usize = 1024;
        const CASES: [(&str, bool, fault::Point); 3] = [
            ("os-map-failure", true, fault::Point::Map),
            ("os-commit-failure", true, fault::Point::Commit),
            ("arena-commit-failure", false, fault::Point::Commit),
        ];
        let mut deltas = [0i64; 3];
        let mut recovery = [[0i64; 5]; 3];
        std::println!("CRABC_MI_M2_METADATA_PUBLICATION_TRACE_BEGIN");
        for (selected, (name, disallow_arena, point)) in CASES.into_iter().enumerate() {
            let facts = thread::spawn(move || {
                let config = config();
                let allocator = MetaAllocator::test_static_owner();
                let process = crate::process_init::ProcessMainInitializationStorage::test_static_owner();
                let main_static = crate::main_theap::MainStaticAttachmentStorage::test_static_owner();
                let subprocess = allocator.test_default_subprocess();
                let page_map_storage = crate::process_page_map::ProcessPageMapStorage::test_static_owner();
                let mut options = crate::config::VmOptions::uninitialized();
                options.initialize_all(|_| crate::config::VmOptionEnvironment::Absent);
                options.set(crate::config::VmOption::ArenaReserve, 64 * 1024);
                options.set(crate::config::VmOption::ArenaEagerCommit, 0);
                options.set(crate::config::VmOption::PageCommitOnDemand, 0);
                options.set(crate::config::VmOption::AllowLargeOsPages, 0);
                options.set(crate::config::VmOption::DisallowArenaAlloc, i64::from(disallow_arena));
                let owner = unsafe {
                    process.initialize_with_test_components_and_vm_options(
                        config, options, main_static, subprocess, allocator, page_map_storage,
                    )
                }
                .expect("the source process publishes canonical metadata backing");
                let binding = owner.ready().expect("READY").process_backing().expect("process backing");
                let map = unsafe { binding.page_map().page_map_for_owned_ranges() }.unwrap();
                let statistics = || binding.process().subprocess().vm_statistics().snapshot();

                let mut warm = allocator.zalloc(config, WARM_SIZE).expect("warm metadata");
                let warm_pointer = warm.pointer();
                unsafe { warm_pointer.as_ptr().write_bytes(0xa5, WARM_SIZE) };
                let warm_page = unsafe { map.checked_lookup(warm_pointer.as_ptr()) };
                assert!(!warm_page.is_null());

                let fault = fault::install(fault::Plan::disabled());
                let before = statistics();
                let lazy_before = map.test_published_submap_count().unwrap();
                fault.set(fault::Plan::every(point, crabc_core::Errno::NOMEM));
                let failed = allocator.zalloc(config, REQUEST_SIZE);
                let reached = fault.observed() != 0;
                fault.set(fault::Plan::disabled());
                let after = statistics();
                let mut facts = [false; 8];
                facts[0] = failed.is_err();
                facts[1] = matches!(failed, Err(MetaError::AllocationUnavailable));
                facts[2] = reached;
                facts[3] = unsafe { core::slice::from_raw_parts(warm_pointer.as_ptr(), WARM_SIZE) }
                    .iter().all(|byte| *byte == 0xa5)
                    && unsafe { map.checked_lookup(warm_pointer.as_ptr()) } == warm_page;
                facts[4] = after.reserved_current == before.reserved_current;
                // A failed OS-page commit rolls back through the source
                // still-committed release accounting; the exact delta is
                // compared with pinned C rather than asserted here.
                let committed_delta = after.committed_current - before.committed_current;
                facts[5] = true;
                let retry = allocator.zalloc(config, REQUEST_SIZE);
                facts[6] = retry.as_ref().is_ok_and(|block| {
                    block.memory_id().kind() == MemoryKind::Malloc
                        && unsafe { core::slice::from_raw_parts(block.pointer().as_ptr(), REQUEST_SIZE) }
                            .iter().all(|byte| *byte == 0)
                });
                facts[7] = retry.as_ref().is_ok_and(|block| {
                    let page = unsafe { map.checked_lookup(block.pointer().as_ptr()) };
                    !page.is_null() && page != warm_page
                });
                let after_retry = statistics();
                let recovery = [
                    after_retry.reserved_current - before.reserved_current,
                    after_retry.committed_current - before.committed_current,
                    after_retry.reserved_total - before.reserved_total,
                    after_retry.committed_total - before.committed_total,
                    (map.test_published_submap_count().unwrap() - lazy_before) as i64,
                ];
                drop(fault);
                if let Ok(mut retry) = retry { allocator.free(&mut retry).unwrap(); }
                allocator.free(&mut warm).unwrap();
                // The process and canonical metadata owners stay process-lived.
                core::mem::forget(owner);
                (facts, committed_delta, recovery)
            })
            .join()
            .expect("metadata publication fault case");
            let (facts, committed_delta, recovered) = facts;
            deltas[selected] = committed_delta;
            recovery[selected] = recovered;
            let case = selected + 1;
            assert!(facts.iter().all(|fact| *fact), "metadata publication case {case} ({name}): {facts:?}");
            for (field, value) in ["request_failed", "no_capability", "fault_reached", "live_owner_intact",
                "reserved_restored", "committed_recorded", "retry_zeroed_malloc", "retry_page_published"]
                .into_iter().zip(facts) {
                std::println!("metadata_publication.{case}.{field}={}", u8::from(value));
            }
        }
        std::println!("CRABC_MI_M2_METADATA_PUBLICATION_TRACE_END");
        std::println!("CRABC_MI_M2_METADATA_PUBLICATION_DELTAS_BEGIN");
        for (index, delta) in deltas.into_iter().enumerate() {
            std::println!("metadata_publication.{}.committed_delta={delta}", index + 1);
        }
        std::println!("CRABC_MI_M2_METADATA_PUBLICATION_DELTAS_END");
        std::println!("CRABC_MI_M2_METADATA_PUBLICATION_RECOVERY_BEGIN");
        for (index, values) in recovery.into_iter().enumerate() {
            for (field, value) in ["reserved_current_delta", "committed_current_delta",
                "reserved_total_delta", "committed_total_delta", "lazy_submaps"]
                .into_iter().zip(values) {
                std::println!("metadata_recovery.{}.{field}={value}", index + 1);
            }
        }
        std::println!("CRABC_MI_M2_METADATA_PUBLICATION_RECOVERY_END");
        let normalized = recovery.map(|row| {
            let charge = row[4] * crate::page_map::PAGE_MAP_SUB_SIZE as i64;
            [row[0] - charge, row[1] - charge, row[2] - charge, row[3] - charge]
        });
        assert_eq!(normalized, [
            [131072, 65536, 131072, 65536],
            [131072, -720896, 917504, 65536],
            [0, -720896, 403439616, 65536],
        ], "each published lazy PageMap submap must carry its full VM charge");
        assert!(recovery.iter().any(|row| row[4] != 0),
            "the recovery sequence must exercise lazy PageMap publication");
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn main_heap_last_reference_recovers_exact_transferred_metadata_once() {
        use crate::subproc::main_heaps::MainHeapTheapMetadataOwnership;
        let allocator = MetaAllocator::global();
        allocator.prepare_for_main_subprocess(config(), MainSubprocess::global()).unwrap();
        let mut block = allocator.zalloc(config(), size_of::<Theap>()).unwrap();
        let memory = block.memory_id();
        let theap = block.initialize_dynamic_theap_metadata().unwrap();
        // This test owns the exact capability and its initialized empty image;
        // no Heap/TLD link, callback, page session or TLS wrapper was published.
        let pointer = NonNull::from(theap);
        unsafe {
            (*Theap::main_heap_lifecycle_at(pointer)).metadata = MainHeapTheapMetadataOwnership::SourceOwned;
        }
        let pointer = match block.into_source_retained_theap() {
            Ok(pointer) => pointer, Err(_) => panic!("initialized exact Theap transfers"),
        };
        // SAFETY: the prior transfer above is the sole source reference;
        // no image user or source list was published, and its global owner lives.
        let mut recovered = unsafe { MetaAllocation::recover_last_reference_main_heap_theap(allocator, pointer) }.unwrap();
        assert!(recovered.matches_memory_id(memory));
        assert!(recovered.matches_memory_id(unsafe { Theap::memory_id_at(pointer) }));
        assert!(unsafe { (*Theap::main_heap_lifecycle_at(pointer)).metadata }
            == MainHeapTheapMetadataOwnership::ReleaseClaimed);
        assert!(recovered.dynamic_theap().is_some());
        // No Heap was ever published: this recovered capability returns the
        // ordinary metadata allocation through its exact original owner.
        allocator.free(&mut recovered).unwrap();
    }

    #[test]
    fn source_retained_metadata_transfer_preserves_typed_owner_across_thread_handoff() {
        let allocator = static_allocator();
        bind_process_fixture(allocator, false);
        let mut theap = allocator.zalloc(config(), size_of::<Theap>()).unwrap();
        let mut tld = allocator.zalloc(config(), crate::types::SOURCE_THREAD_LOCAL_DATA_SIZE).unwrap();
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

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn process_metadata_map_refusal_covers_source_reservation_and_page_retries() {
        crate::test_process::run_in_fresh_process(
            "meta::tests::process_metadata_map_refusal_covers_source_reservation_and_page_retries", || {
                for unavailable in [false, true] {
                    let allocator = static_allocator();
                    let mut options = crate::config::VmOptions::uninitialized();
                    options.initialize_all(|_| crate::config::VmOptionEnvironment::Absent);
                    let binding = process_binding_fixture(allocator.test_default_subprocess(), options);
                    allocator.bind_process_backing(binding).unwrap();
                    assert_eq!(allocator.status.load(Ordering::Acquire), BOUND);
                    let plan = if unavailable {
                        fault::Plan::every(fault::Point::Map, crabc_core::Errno::NOMEM)
                    } else {
                        fault::Plan::at(fault::Point::Map, 1, crabc_core::Errno::NOMEM)
                    };
                    let fault = fault::install(plan);
                    let allocation = allocator.zalloc(config(), crate::types::SOURCE_THREAD_LOCAL_DATA_SIZE);
                    assert!(fault.observed() > 1, "source reservation or page selection retries a refused map");
                    assert_eq!(allocator.status.load(Ordering::Acquire), READY,
                        "process session activation precedes demand for ordinary page backing");
                    assert!(allocator.test_private_page_map_address().is_none());
                    let allocation = if unavailable {
                        assert!(matches!(allocation, Err(MetaError::AllocationUnavailable)));
                        assert_eq!(allocator.test_allocation_audit(), MetaAllocationAudit {
                            live_capability_count: 0, high_water_capability_count: 0,
                        }, "a wholly refused request never publishes a metadata capability");
                        fault.set(fault::Plan::disabled());
                        allocator.zalloc(config(), crate::types::SOURCE_THREAD_LOCAL_DATA_SIZE)
                            .expect("the same detached owner remains ready after complete map refusal")
                    } else {
                        allocation.expect("a one-shot map refusal permits the source fallback")
                    };
                    assert_eq!(allocator.test_allocation_audit().live_capability_count, 1);
                    assert!(MetaRelease::Malloc(allocation).release().is_ok());
                    assert_eq!(allocator.test_allocation_audit().live_capability_count, 0);
                }
            });
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
        let map = unsafe { page_map.page_map_for_owned_ranges() }.unwrap();
        let submaps_before = map.test_lazy_submap_allocation_count();
        let before = process.subprocess().vm_statistics().snapshot();
        let mut block = allocator.zalloc(config(), 2 * ARENA_MIN_SIZE).unwrap();
        assert!(allocator.test_private_page_map_address().is_none());
        let page = unsafe { map.checked_lookup(block.pointer().as_ptr()) };
        assert!(!page.is_null());
        assert_eq!(unsafe { (*page).memid().kind() }, MemoryKind::Os);
        assert_eq!(process.subprocess().arena_backing().registry().count(), 0);
        allocator.bind_process_backing(binding).unwrap();
        let pointer = block.pointer();
        allocator.free(&mut block).unwrap();
        assert!(unsafe { map.checked_lookup(pointer.as_ptr()) }.is_null());
        // Only the process PageMap's lazily published submaps, which
        // `page-map.c` charges to the main subprocess, remain reserved.
        let submaps = (map.test_lazy_submap_allocation_count() - submaps_before) as i64;
        assert_eq!(process.subprocess().vm_statistics().snapshot().reserved_current - before.reserved_current,
            submaps * crate::page_map::PAGE_MAP_SUB_SIZE as i64);
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
        let submaps_before = map.test_lazy_submap_allocation_count();
        let before = binding.process().subprocess().vm_statistics().snapshot();
        fault.set(fault::Plan::at(fault::Point::Commit, 1, crabc_core::Errno::NOMEM));
        let mut next = allocator.zalloc(config(), 64).expect(
            "a failed published OS-page extension retries through source fresh selection",
        );
        let submaps = map.test_lazy_submap_allocation_count() - submaps_before;
        let fresh_page = unsafe { map.checked_lookup(next.pointer().as_ptr()) };
        assert_ne!(fresh_page, old_page);
        assert_eq!(unsafe { (*old_page).capacity() }, 384);
        assert_eq!(unsafe { (*old_page).slice_pcommitted() }, 8);
        assert!(!unsafe { (*fresh_page).memid().initially_committed() });
        let after = binding.process().subprocess().vm_statistics().snapshot();
        // A fresh OS page may need a new process PageMap submap, which
        // `page-map.c` charges to the main subprocess as a committed map.
        assert_eq!(after.committed_current - before.committed_current,
            (16 * 1024 + submaps * crate::page_map::PAGE_MAP_SUB_SIZE) as i64);
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
        let map = unsafe { binding.page_map().page_map_for_owned_ranges() }.unwrap();
        let submaps_before = map.test_lazy_submap_allocation_count();
        let before = binding.process().subprocess().vm_statistics().snapshot();
        fault.set(fault::Plan::at(fault::Point::Commit, 2, crabc_core::Errno::NOMEM));
        let mut next = allocator.zalloc(config(), 64).expect(
            "the failed private OS prefix rolls back and source fresh retry commits a new prefix",
        );
        let submaps = map.test_lazy_submap_allocation_count() - submaps_before;
        let page = unsafe { map.checked_lookup(next.pointer().as_ptr()) };
        let pointer = next.pointer();
        assert_eq!(unsafe { (*page).memid().kind() }, MemoryKind::Os);
        assert!(!unsafe { (*page).memid().initially_committed() });
        assert_eq!(unsafe { (*page).capacity() }, 128);
        assert_eq!(unsafe { (*page).slice_pcommitted() }, 4);
        let after = binding.process().subprocess().vm_statistics().snapshot();
        assert_eq!(after.committed_current - before.committed_current,
            (16 * 1024 + submaps * crate::page_map::PAGE_MAP_SUB_SIZE) as i64);
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
        // Only the lazily published PageMap submaps stay charged.
        let submap_bytes = (submaps * crate::page_map::PAGE_MAP_SUB_SIZE) as i64;
        assert_eq!(after_release.reserved_current - before.reserved_current, submap_bytes,
            "the failed unpublished claim retains no reservation");
        assert_eq!(after_release.committed_current - before.committed_current, submap_bytes,
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
        let tld_size = crate::types::SOURCE_THREAD_LOCAL_DATA_SIZE;

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
            .zalloc(config(), crate::types::SOURCE_THREAD_LOCAL_DATA_SIZE)
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

    #[cfg(all(not(miri), any(feature = "mi-secure-1", feature = "mi-secure-2", feature = "mi-secure-3", feature = "mi-secure-4", feature = "mi-secure-5")))]
    #[test]
    fn mapped_metadata_backing_supplies_its_secure_guard_owner() {
        for fail_guard in [false, true] {
            let allocator = static_allocator();
            let plan = if fail_guard {
                fault::Plan::at(fault::Point::Decommit, 1, Errno::NOMEM)
            } else { fault::Plan::disabled() };
            let fault = fault::install(plan);
            let mut block = allocator.zalloc(config(), 64)
                .expect("the retained private mapping supplies its metadata guard");
            if fail_guard {
                assert_eq!(fault.observed(), 1, "source initialization attempts the owned guard");
            }
            fault.set(fault::Plan::disabled());
            // SAFETY: this exact live metadata capability owns all 64 bytes.
            unsafe { core::ptr::write_bytes(block.pointer().as_ptr(), 0x63, 64); }
            allocator.free(&mut block).expect("the ordinary metadata client frees");
            assert_eq!(allocator.test_allocation_audit().live_capability_count, 0);
            assert_eq!(allocator.status.load(Ordering::Acquire), READY,
                "a guard failure retains the original usable backing");
        }
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

    /// The metadata backing receiver of source `mi_os_prim_alloc_aligned`:
    /// a failed prefix release of its aligned arena map is leaked and the
    /// metadata backing still forms, so the allocation succeeds.
    #[cfg(not(miri))]
    #[test]
    fn aligned_map_prefix_cleanup_failure_leaks_and_metadata_backing_forms() {
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
        let mut block = allocator
            .zalloc(selected_config, 8)
            .expect("a failed aligned-map trim does not fail metadata backing");
        assert!(fault.observed() >= 2, "the selected trim release ran");
        fault.set(fault::Plan::disabled());
        allocator.free(&mut block).expect("the metadata block frees");
    }

    /// The legacy private PageMap receiver of source `mi_page_map_init_once`:
    /// a failed initial commit whose cleanup unmap also fails leaks the
    /// mapping and fails initialization without retaining an owner.
    #[test]
    fn paired_page_map_initial_commit_and_cleanup_failure_leaks_the_mapping() {
        let allocator = static_allocator();
        let fault = fault::install(fault::Plan::at_pair(
            fault::Point::Commit,
            1,
            fault::Point::Unmap,
            1,
            Errno::NOMEM,
        ));
        let capture = fault.capture_unmap_ranges();
        assert!(matches!(
            allocator.zalloc(config(), 8),
            Err(MetaError::InitializationFailed)
        ));
        let (ranges, count) = capture.all().expect("bounded releases");
        drop(capture);
        assert_eq!(fault.secondary_observed(), 1, "the cleanup release failed");
        fault.set(fault::Plan::disabled());
        let (leaked, leaked_length) = ranges[count - 1];
        // SAFETY: the leaked mapping is represented by no owner.
        unsafe { crabc_core::mm::munmap_raw(leaked as *mut u8, leaked_length) }
            .expect("fixture teardown of the leaked PageMap mapping");
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

/// Rust half of `compat/allocator/m2_metadata_ownership_x86_64.c`: the
/// `_mi_meta_free` no-free predicate, non-main subprocess metadata ownership,
/// one deterministic allocation/release overlap, and `_mi_meta_free`'s Arena
/// branch. Both sides print the
/// same ordered `m2.metadata.ownership.N=V` fields.
#[cfg(test)]
mod ownership_tests {
    extern crate std;

    use super::*;
    use crate::config::{ARENA_MIN_SIZE, KIB, VmOption, VmOptionEnvironment, VmOptions};
    use crate::os::PageSize;
    use crate::types::MemoryKind;
    use std::vec::Vec;

    struct Trace { values: Vec<i64> }

    impl Trace {
        fn emit(&mut self, value: i64) { self.values.push(value); }
        fn emit_bool(&mut self, value: bool) { self.emit(i64::from(value)); }
        fn marker(&mut self, scenario: i64) { self.emit(-1000 - scenario); }
    }

    fn config() -> MemoryConfig {
        MemoryConfig::from_observations(PageSize::new(4096).unwrap(), 1024 * 1024, false, false)
    }

    fn all_bytes(pointer: *const u8, size: usize, value: u8) -> bool {
        // SAFETY: each caller passes a live block of at least `size` bytes.
        unsafe { core::slice::from_raw_parts(pointer, size) }.iter().all(|byte| *byte == value)
    }

    /// 1. Pinned `_mi_meta_free` returns without freeing for exactly these
    /// kinds; every other kind selects a typed release owner in Rust.
    fn no_free_predicate(trace: &mut Trace) {
        trace.marker(1);
        for kind in [MemoryKind::None, MemoryKind::External, MemoryKind::Static, MemoryKind::Os,
            MemoryKind::OsHuge, MemoryKind::OsRemap, MemoryKind::Arena, MemoryKind::Malloc]
        {
            trace.emit_bool(kind.needs_no_free());
        }
    }

    /// 2. A non-main subprocess: its image and metadata Theap are parent
    /// metadata; its own metadata blocks live on its own metadata pages in its
    /// own arenas without growing the parent's arenas.
    fn child_ownership() -> Vec<i64> {
        let (sender, receiver) = std::sync::mpsc::channel();
        crate::main_heap_page::tests::with_owner_local_fixture(true, move |attachment, mut heap_owner, pair| {
            let (parent, registry, binding) =
                crate::subproc::lifecycle::tests::child_fixture_inputs(attachment, pair);
            let mut trace = Trace { values: Vec::new() };
            trace.marker(2);
            let metadata = attachment.parent_metadata_allocator();
            // SAFETY: the registry holds main and this is the attached
            // fixture thread; no other child operation exists.
            let mut child = unsafe { crate::subproc::lifecycle::new_child(registry, attachment, &mut heap_owner) }
                .ok()
                .expect("the child is created");
            // Parent arenas are counted after the parent issued the child image.
            let main_arenas_before = parent.arena_backing().registry().count();
            let identity = child.identity_pointer().expect("a created child projects its identity");
            // SAFETY: the created child image stays live until destruction.
            let child_identity = unsafe { &*identity };
            // The parent's metadata engine resolves its own pages; the child
            // image and metadata Theap are live blocks on those pages.
            let parent_page_is = |pointer: *mut u8, owner: &crate::subproc::SubprocessIdentity| {
                let mut entry = metadata.enter().unwrap();
                let pointer = NonNull::new(pointer).unwrap();
                // SAFETY: the live block's page stays registered while the
                // metadata entry excludes every page transition.
                let page = unsafe { match entry.allocator() {
                    MetadataPageAllocator::LegacySelectedArena(engine) => engine.page_for_block(pointer),
                    MetadataPageAllocator::Process(engine) => engine.page_for_block(pointer),
                    MetadataPageAllocator::CanonicalProcess(engine) => engine.page_for_block(pointer),
                }.as_ref() };
                owner.is_metadata_page(page)
            };
            trace.emit_bool(parent_page_is(identity.cast(), parent));
            trace.emit_bool(parent_page_is(identity.cast(), child_identity));
            trace.emit_bool(parent_page_is(child_identity.test_published_metadata_theap().cast(), parent));
            trace.emit(child_identity.arena_backing().registry().count() as i64);
            let sizes = [1usize, 64, 1025, 131073];
            child
                .with_metadata_page_engine(binding, |_child, engine| {
                    let mut blocks = Vec::new();
                    for size in sizes {
                        let block = engine.allocate(size, true).expect("child metadata allocates");
                        // SAFETY: the exact live block allocated just above.
                        let page = unsafe { &*engine.page_for_block(block) };
                        trace.emit_bool(all_bytes(block.as_ptr(), size, 0));
                        trace.emit_bool(child_identity.is_metadata_page(Some(page)));
                        trace.emit_bool(parent.is_metadata_page(Some(page)));
                        let arena = page.memid().arena_memory().map(|memory| memory.arena);
                        trace.emit_bool(arena.is_some_and(|arena| {
                            // SAFETY: a live page's arena outlives the page.
                            core::ptr::eq(unsafe { (*arena).subprocess }, identity)
                        }));
                        trace.emit(child_identity.arena_backing().registry().count() as i64);
                        trace.emit(parent.arena_backing().registry().count() as i64
                            - main_arenas_before as i64);
                        // SAFETY: the block owns `size` writable bytes.
                        unsafe { core::ptr::write_bytes(block.as_ptr(), 0x5a, size) };
                        blocks.push((block, size));
                    }
                    for (block, size) in blocks {
                        trace.emit_bool(all_bytes(block.as_ptr(), size, 0x5a));
                        // SAFETY: the exact live block allocated above.
                        unsafe { engine.free(block) }.expect("child metadata frees");
                    }
                })
                .expect("the child metadata engine is available");
            trace.emit(child_identity.arena_backing().registry().count() as i64);
            trace.emit(parent.arena_backing().registry().count() as i64 - main_arenas_before as i64);
            // SAFETY: the child has no users, blocks, or threads left.
            unsafe {
                crate::subproc::lifecycle::destroy_child(child, registry, binding, &mut [], attachment, &mut heap_owner)
            }
            .ok()
            .expect("the child is destroyed");
            heap_owner.finish(attachment).ok().expect("the parent engine is quiescent");
            attachment
                .finish_after_user_destructors()
                .ok()
                .expect("the parent attachment completes after its child");
            sender.send(trace.values).unwrap();
        });
        receiver.recv().expect("the child ownership fixture reports its trace")
    }

    /// 3. A deterministic allocation/release overlap on the main subprocess.
    /// The fixture holds `theap_meta_lock` until an arena-growing allocation
    /// waits on it, then a third thread releases a published block. Source
    /// `_mi_meta_free` of a Malloc block is a lock-free `mi_free`, while the
    /// Rust release reaches its backing lock inside the same window;
    /// only facts common to both are emitted.
    fn allocation_release_overlap(trace: &mut Trace) {
        trace.marker(3);
        let allocator = MetaAllocator::test_static_owner();
        let subprocess = allocator.test_default_subprocess();
        allocator.prepare_for_main_subprocess(config(), subprocess).unwrap();
        let mut options = VmOptions::uninitialized();
        options.initialize_all(|_| VmOptionEnvironment::Absent);
        options.set(VmOption::ArenaReserve, (ARENA_MIN_SIZE / KIB) as i64);
        options.set(VmOption::ArenaEagerCommit, 0);
        options.set(VmOption::PageCommitOnDemand, 0);
        options.set(VmOption::PurgeDelay, -1);
        let storage = crate::process_init::ProcessMainInitializationStorage::test_static_owner();
        let page_map = crate::process_page_map::ProcessPageMapStorage::test_static_owner();
        // SAFETY: these process-lifetime owners are isolated to this test.
        let binding = unsafe {
            storage.test_prepare_vm_process_backing_binding(config(), options, subprocess, page_map)
        }
        .unwrap();
        allocator.bind_process_backing(binding).unwrap();
        let map = unsafe { binding.page_map().page_map_for_owned_ranges() }.unwrap();
        let arenas = || subprocess.arena_backing().registry().count() as i64;

        let published = std::thread::spawn(move || {
            let block = allocator.zalloc(config(), 64).unwrap();
            assert!(all_bytes(block.pointer().as_ptr(), 64, 0));
            // SAFETY: the exclusive allocation owns 64 writable bytes.
            unsafe { core::ptr::write_bytes(block.pointer().as_ptr(), 0xa5, 64) };
            block
        })
        .join()
        .unwrap();
        let published_pointer = published.pointer().as_ptr() as usize;
        let arenas_before = arenas();
        let size = 2 * ARENA_MIN_SIZE;

        std::thread::scope(|scope| {
            let held = subprocess.test_hold_metadata_theap_lock().unwrap();
            let allocation = scope.spawn(move || allocator.zalloc(config(), size).unwrap());
            while !subprocess.test_metadata_theap_lock_is_contended() { std::thread::yield_now(); }
            trace.emit(1); // the allocation is waiting on theap_meta_lock
            trace.emit(arenas() - arenas_before);
            let release = scope.spawn(move || {
                let intact = all_bytes(published_pointer as *const u8, 64, 0xa5);
                assert!(MetaRelease::Malloc(published).release().is_ok());
                intact
            });
            // Rust synchronization point: the release waits on the backing
            // lock held by the in-flight allocation.
            while !allocator.get_ref().lock.test_is_contended() { std::thread::yield_now(); }
            trace.emit_bool(!allocation.is_finished()); // still inside the held lock
            drop(held);
            let block = allocation.join().unwrap();
            let intact = release.join().unwrap();
            trace.emit_bool(intact);
            trace.emit_bool(block.memory_id().kind() == MemoryKind::Malloc);
            trace.emit_bool(all_bytes(block.pointer().as_ptr(), size, 0));
            // SAFETY: the live allocation keeps its page registered.
            let page = unsafe { map.checked_lookup(block.pointer().as_ptr()).as_ref() };
            trace.emit_bool(subprocess.is_metadata_page(page));
            trace.emit_bool(block.pointer().as_ptr() as usize != published_pointer);
            trace.emit(arenas() - arenas_before);
            assert!(MetaRelease::Malloc(block).release().is_ok());
        });

        // 4. `_mi_meta_free`'s Arena branch. Rust has no memory-ID
        // dispatcher: the typed exclusive-arena Theap reservation is the
        // only owner that can return this slice.
        trace.marker(4);
        let process = binding.process();
        let backing = subprocess.arena_backing();
        // SAFETY: the isolated process backing and its fixed binding live for
        // the test; no teardown overlaps these calls.
        let exclusive = unsafe { backing.reserve_os_memory_for_process(process, config(),
            ARENA_MIN_SIZE, crate::os::MapAccess::Reserved, false, true, None) }.unwrap();
        let statistics = || process.subprocess().vm_statistics().snapshot();
        let before = statistics();
        let reservation = unsafe { backing.try_reserve_exclusive_theap(process, config(), subprocess,
            exclusive, crate::types::ThreadSequence::from_previous_total_count(0), -1) }.unwrap();
        let memory = reservation.memory_id();
        let arena_memory = memory.arena_memory().unwrap();
        let view = unsafe { crate::arena::ArenaView::from_ptr(arena_memory.arena) }.unwrap();
        let index = arena_memory.slice_index as usize;
        let count = arena_memory.slice_count as usize;
        trace.emit_bool(memory.kind() == MemoryKind::Arena && arena_memory.arena == exclusive.as_ptr());
        trace.emit_bool(memory.needs_no_free());
        trace.emit(count as i64);
        trace.emit_bool(unsafe { view.slices_free() }.unwrap().is_clear_range(index, count) == Some(true));
        trace.emit(statistics().committed_current - before.committed_current);
        assert!(matches!(reservation.release(), Ok(true)));
        trace.emit_bool(unsafe { view.slices_free() }.unwrap().is_set_range(index, count) == Some(true));
        trace.emit_bool(unsafe { view.slices_purge() }.unwrap().is_set_range(index, count) == Some(true));
        trace.emit(statistics().committed_current - before.committed_current);
        trace.emit(statistics().reserved_current - before.reserved_current);
    }

    #[test]
    fn emit_native_metadata_ownership_trace() {
        let mut trace = Trace { values: Vec::new() };
        no_free_predicate(&mut trace);
        trace.values.extend(child_ownership());
        allocation_release_overlap(&mut trace);
        trace.marker(5);
        for (index, value) in trace.values.iter().enumerate() {
            std::println!("m2.metadata.ownership.{index}={value}");
        }
    }
}
