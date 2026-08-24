// Copyright (c) 2018-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `include/mimalloc/types.h:288-456`
// (`MemoryKind`, memory-ID layout, `Block`, page flags, and `Page`),
// `include/mimalloc/types.h:499-598` (the default-theap prefix, including
// `mi_page_queue_t`, `mi_random_ctx_t`, and `mi_theap_t` through `memid`),
// `include/mimalloc/types.h:618-701` (the heap and TLD prefixes used by the
// bootstrap-only ownership model), `include/mimalloc/types.h:608-758`
// (arena-page and arena metadata layouts), `src/init.c:15-145` (the
// empty-page, direct-page table, all 75 default queues, detached TLD, and
// empty-theap initializers), `src/arena.c:1023-1095` (fresh-page metadata
// publication), `src/page.c:708-757` (fresh-page local-state invariants),
// and `src/arena.c:199-219` (arena memory-ID construction and projection).
// The intrusive membership operations from `src/page-queue.c:40-55,126-423`
// are isolated in the `page_queue` child module below.
// `Heap`, `ThreadLocalData`, and `Theap` below are exact source-layout
// *prefixes* only. The included fields are the complete state used by the
// allocation-free, exclusive single-thread bootstrap. The remaining heap,
// TLD, subprocess, lock, and statistics lifecycle is deliberately absent;
// no code may treat a prefix size as `sizeof(mi_heap_t)`, `sizeof(mi_tld_t)`,
// or `sizeof(mi_theap_t)`.

use core::ffi::c_void;
use core::mem::{align_of, size_of};
use core::num::NonZeroUsize;
use core::ptr::{NonNull, null_mut};
use core::sync::atomic::{AtomicI64, AtomicPtr, AtomicUsize};

use crate::config::{
    BIN_COUNT, BIN_FULL, LARGE_MAX_OBJ_WSIZE, PAGES_DIRECT, WORD_SIZE,
};

pub(crate) type ThreadId = usize;
pub(crate) type ThreadFree = usize;
pub(crate) type PageFlags = usize;

pub(crate) const PAGE_IN_FULL_QUEUE: PageFlags = 0x01;
pub(crate) const PAGE_HAS_INTERIOR_POINTERS: PageFlags = 0x02;
pub(crate) const PAGE_FLAG_MASK: PageFlags = 0x03;
pub(crate) const PAGE_FLAG_BITS: usize = 2;
pub(crate) const THREAD_ID_ABANDONED: ThreadId = 0;
pub(crate) const THREAD_ID_ABANDONED_MAPPED: ThreadId = 1 << PAGE_FLAG_BITS;
pub(crate) const THREAD_ID_DETACHED: ThreadId = 2 << PAGE_FLAG_BITS;

/// One valid non-detached `mi_threadid_t` for the exclusive bootstrap slice.
///
/// `src/prim/prim-tls.c:_mi_thread_id` reserves the low two bits for page
/// flags. The source's detached and abandoned encodings occupy the other
/// values below `3 << MI_PAGE_FLAG_BITS`; an attached default theap must not
/// use any of them. This is an input contract supplied by the integrating
/// runtime, not a thread-ID syscall or TLS mechanism.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LiveThreadId(NonZeroUsize);

impl LiveThreadId {
    #[inline]
    pub(crate) const fn new(raw: ThreadId) -> Option<Self> {
        if raw == THREAD_ID_ABANDONED
            || raw == THREAD_ID_ABANDONED_MAPPED
            || raw == THREAD_ID_DETACHED
            || raw & PAGE_FLAG_MASK != 0
        {
            return None;
        }

        match NonZeroUsize::new(raw) {
            Some(raw) => Some(Self(raw)),
            None => None,
        }
    }

    #[inline]
    pub(crate) const fn get(self) -> ThreadId {
        self.0.get()
    }
}

/// Opaque because the subprocess lifecycle is outside the bootstrap slice.
pub(crate) enum Subprocess {}

/// Prefix of `mi_heap_t` through its `subproc` member.
///
/// The exclusive bootstrap does not create, enumerate, or destroy heaps. It
/// owns one caller-pinned image solely so pages and the default theap can hold
/// the source-shaped heap pointer. Its null subprocess pointer records that
/// subprocess lifecycle is not part of this slice.
#[repr(C)]
pub(crate) struct Heap {
    subprocess: *mut Subprocess,
}

impl Heap {
    #[inline]
    pub(crate) const fn bootstrap_empty() -> Self {
        Self {
            subprocess: null_mut(),
        }
    }
}

/// Prefix of `mi_tld_t` through its thread identity.
///
/// Queue locks, theap lists, NUMA selection, and the rest of `mi_tld_t` need
/// the omitted thread lifecycle. This prefix exists only to retain the exact
/// pointer and identity relationship used by `mi_theap_t` during bootstrap.
#[repr(C)]
pub(crate) struct ThreadLocalData {
    thread_id: ThreadId,
}

impl ThreadLocalData {
    #[inline]
    pub(crate) const fn detached() -> Self {
        Self {
            thread_id: THREAD_ID_DETACHED,
        }
    }

    #[inline]
    pub(crate) const fn thread_id(&self) -> ThreadId {
        self.thread_id
    }

    #[inline]
    pub(crate) fn attach_exclusive(&mut self, thread_id: LiveThreadId) {
        self.thread_id = thread_id.get();
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MemoryKind {
    None,
    External,
    Static,
    Os,
    OsHuge,
    OsRemap,
    Arena,
    Malloc,
}

impl MemoryKind {
    #[inline]
    pub(crate) const fn is_os(self) -> bool {
        matches!(self, Self::Os | Self::OsHuge | Self::OsRemap)
    }

    #[inline]
    pub(crate) const fn needs_no_free(self) -> bool {
        matches!(self, Self::None | Self::External | Self::Static)
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct OsMemory {
    pub(crate) base: *mut u8,
    pub(crate) size: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct ArenaMemory {
    pub(crate) arena: *mut Arena,
    pub(crate) slice_index: u32,
    pub(crate) slice_count: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct MallocMemory {
    pub(crate) base: *mut u8,
    pub(crate) size: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) union MemoryInfo {
    pub(crate) os: OsMemory,
    pub(crate) arena: ArenaMemory,
    pub(crate) malloc: MallocMemory,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct MemoryId {
    pub(crate) info: MemoryInfo,
    pub(crate) kind: MemoryKind,
    pub(crate) is_pinned: bool,
    pub(crate) initially_committed: bool,
    pub(crate) initially_zero: bool,
}

impl MemoryId {
    #[inline]
    const fn empty_with_kind(kind: MemoryKind) -> Self {
        Self {
            info: MemoryInfo {
                os: OsMemory {
                    base: null_mut(),
                    size: 0,
                },
            },
            kind,
            is_pinned: false,
            initially_committed: false,
            initially_zero: false,
        }
    }

    #[inline]
    pub(crate) const fn none() -> Self {
        Self::empty_with_kind(MemoryKind::None)
    }

    /// Relinquishes ownership while preserving the source memory attributes.
    ///
    /// `mi_manage_os_memory_ex2` changes only `memkind` after publishing the
    /// parent arena. Sub-arenas must therefore retain the original committed,
    /// pinned, and zero-state observations even though they do not own the
    /// external allocation.
    #[inline]
    pub(crate) fn relinquish_ownership(&mut self) {
        self.kind = MemoryKind::None;
    }

    #[inline]
    pub(crate) const fn external(
        base: *mut u8,
        size: usize,
        initially_committed: bool,
        is_pinned: bool,
        initially_zero: bool,
    ) -> Self {
        Self {
            info: MemoryInfo {
                os: OsMemory { base, size },
            },
            kind: MemoryKind::External,
            is_pinned,
            initially_committed,
            initially_zero,
        }
    }

    #[inline]
    /// Constructs arena provenance after checking the source's slice bounds.
    ///
    /// # Safety
    ///
    /// `arena` must point to a live initialized arena for the duration of this
    /// check and every later operation that projects the stored pointer.
    pub(crate) unsafe fn from_arena(
        arena: *mut Arena,
        slice_index: usize,
        slice_count: usize,
    ) -> Option<Self> {
        if arena.is_null()
            || slice_count == 0
            || slice_index >= u32::MAX as usize
            || slice_count >= u32::MAX as usize
        {
            return None;
        }
        if slice_index >= unsafe { (*arena).slice_count } {
            return None;
        }
        Some(Self {
            info: MemoryInfo {
                arena: ArenaMemory {
                    arena,
                    slice_index: slice_index as u32,
                    slice_count: slice_count as u32,
                },
            },
            kind: MemoryKind::Arena,
            is_pinned: false,
            initially_committed: false,
            initially_zero: false,
        })
    }

    #[inline]
    pub(crate) const fn static_empty() -> Self {
        Self {
            info: MemoryInfo {
                os: OsMemory {
                    base: null_mut(),
                    size: 0,
                },
            },
            kind: MemoryKind::Static,
            is_pinned: true,
            initially_committed: true,
            initially_zero: false,
        }
    }

    #[inline]
    pub(crate) const fn kind(&self) -> MemoryKind {
        self.kind
    }

    #[inline]
    pub(crate) const fn is_os(&self) -> bool {
        self.kind.is_os()
    }

    #[inline]
    pub(crate) const fn needs_no_free(&self) -> bool {
        self.kind.needs_no_free()
    }

    #[inline]
    pub(crate) const fn is_pinned(&self) -> bool {
        self.is_pinned
    }

    #[inline]
    pub(crate) const fn initially_committed(&self) -> bool {
        self.initially_committed
    }

    #[inline]
    pub(crate) const fn initially_zero(&self) -> bool {
        self.initially_zero
    }

    #[inline]
    pub(crate) fn os_memory(&self) -> Option<OsMemory> {
        if matches!(
            self.kind,
            MemoryKind::External
                | MemoryKind::Os
                | MemoryKind::OsHuge
                | MemoryKind::OsRemap
        ) {
            Some(unsafe { self.info.os })
        } else {
            None
        }
    }

    #[inline]
    pub(crate) fn arena_memory(&self) -> Option<ArenaMemory> {
        if self.kind == MemoryKind::Arena {
            Some(unsafe { self.info.arena })
        } else {
            None
        }
    }
}

#[repr(transparent)]
#[derive(Clone, Copy)]
pub(crate) struct Encoded(pub(crate) usize);

#[repr(C)]
pub(crate) struct Block {
    next: Encoded,
}

/// Narrow mutable projection for the exclusive local free-list algorithms.
///
/// It deliberately omits ownership, queue links, thread-free state, and heap
/// pointers. `free_list.rs` may update only the fields that the source local
/// free-list routines own; queue and direct-cache transitions stay with the
/// default-theap lifecycle.
pub(super) struct PageFreeListState<'a> {
    pub(super) area: NonNull<u8>,
    pub(super) area_bytes: usize,
    pub(super) block_size: usize,
    pub(super) capacity: &'a mut u16,
    pub(super) reserved: u16,
    pub(super) free: &'a mut *mut Block,
    pub(super) local_free: &'a mut *mut Block,
    pub(super) used: &'a mut usize,
    pub(super) free_is_zero: &'a mut bool,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PageKind {
    Small,
    Medium,
    Large,
    Singleton,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct PageQueue {
    first: *mut Page,
    last: *mut Page,
    count: usize,
    block_size: usize,
}

impl PageQueue {
    pub(crate) const fn empty(block_size: usize) -> Self {
        Self {
            first: null_mut(),
            last: null_mut(),
            count: 0,
            block_size,
        }
    }

    #[inline]
    pub(crate) const fn block_size(&self) -> usize {
        self.block_size
    }

    #[inline]
    pub(crate) const fn count(&self) -> usize {
        self.count
    }

    #[inline]
    pub(crate) const fn is_empty(&self) -> bool {
        self.first.is_null() && self.last.is_null() && self.count == 0
    }

    #[inline]
    pub(crate) const fn first(&self) -> *mut Page {
        self.first
    }

    #[inline]
    pub(crate) const fn last(&self) -> *mut Page {
        self.last
    }
}

// `src/init.c:MI_PAGE_QUEUES_EMPTY`; all source values are machine-word
// counts, so multiplying by `WORD_SIZE` is the direct language adaptation.
pub(crate) const BIN_BLOCK_SIZES: [usize; BIN_COUNT] = [
    1 * WORD_SIZE,
    1 * WORD_SIZE, 2 * WORD_SIZE, 3 * WORD_SIZE, 4 * WORD_SIZE,
    5 * WORD_SIZE, 6 * WORD_SIZE, 7 * WORD_SIZE, 8 * WORD_SIZE,
    10 * WORD_SIZE, 12 * WORD_SIZE, 14 * WORD_SIZE, 16 * WORD_SIZE,
    20 * WORD_SIZE, 24 * WORD_SIZE, 28 * WORD_SIZE, 32 * WORD_SIZE,
    40 * WORD_SIZE, 48 * WORD_SIZE, 56 * WORD_SIZE, 64 * WORD_SIZE,
    80 * WORD_SIZE, 96 * WORD_SIZE, 112 * WORD_SIZE, 128 * WORD_SIZE,
    160 * WORD_SIZE, 192 * WORD_SIZE, 224 * WORD_SIZE, 256 * WORD_SIZE,
    320 * WORD_SIZE, 384 * WORD_SIZE, 448 * WORD_SIZE, 512 * WORD_SIZE,
    640 * WORD_SIZE, 768 * WORD_SIZE, 896 * WORD_SIZE, 1024 * WORD_SIZE,
    1280 * WORD_SIZE, 1536 * WORD_SIZE, 1792 * WORD_SIZE, 2048 * WORD_SIZE,
    2560 * WORD_SIZE, 3072 * WORD_SIZE, 3584 * WORD_SIZE, 4096 * WORD_SIZE,
    5120 * WORD_SIZE, 6144 * WORD_SIZE, 7168 * WORD_SIZE, 8192 * WORD_SIZE,
    10_240 * WORD_SIZE, 12_288 * WORD_SIZE, 14_336 * WORD_SIZE, 16_384 * WORD_SIZE,
    20_480 * WORD_SIZE, 24_576 * WORD_SIZE, 28_672 * WORD_SIZE, 32_768 * WORD_SIZE,
    40_960 * WORD_SIZE, 49_152 * WORD_SIZE, 57_344 * WORD_SIZE, 65_536 * WORD_SIZE,
    81_920 * WORD_SIZE, 98_304 * WORD_SIZE, 114_688 * WORD_SIZE, 131_072 * WORD_SIZE,
    163_840 * WORD_SIZE, 196_608 * WORD_SIZE, 229_376 * WORD_SIZE, 262_144 * WORD_SIZE,
    327_680 * WORD_SIZE, 393_216 * WORD_SIZE, 458_752 * WORD_SIZE, 524_288 * WORD_SIZE,
    (LARGE_MAX_OBJ_WSIZE + 1) * WORD_SIZE,
    (LARGE_MAX_OBJ_WSIZE + 2) * WORD_SIZE,
];

const fn empty_page_queues() -> [PageQueue; BIN_COUNT] {
    let mut queues = [PageQueue::empty(0); BIN_COUNT];
    let mut index = 0;
    while index < BIN_COUNT {
        queues[index] = PageQueue::empty(BIN_BLOCK_SIZES[index]);
        index += 1;
    }
    queues
}

pub(crate) const EMPTY_PAGE_QUEUES: [PageQueue; BIN_COUNT] = empty_page_queues();

// `keys` is absent exactly as in the default C layout: both `MI_PADDING` and
// `MI_ENCODE_FREELIST` resolve to zero for this profile.
#[repr(C)]
pub(crate) struct Page {
    self_: AtomicPtr<Page>,
    xthread_id: AtomicUsize,
    free: *mut Block,
    used: usize,
    local_free: *mut Block,
    block_size: usize,
    page_offset: usize,
    capacity: u16,
    reserved: u16,
    slice_pcommitted: u16,
    retire_expire: u8,
    free_is_zero: bool,
    xthread_free: AtomicUsize,
    theap: *mut Theap,
    heap: *mut Heap,
    next: *mut Page,
    prev: *mut Page,
    memid: MemoryId,
}

/// Public-source custom commit/decommit hook retained by externally managed
/// arenas. The function pointer is nullable in [`Arena`].
pub(crate) type CommitFunction = unsafe extern "C" fn(
    commit: bool,
    start: *mut u8,
    size: usize,
    is_zero: *mut bool,
    user_argument: *mut c_void,
) -> bool;

/// C-shaped `mi_arena_pages_t` header. Its variable-size ordinary bitmaps live
/// in caller-owned storage immediately after this fixed pointer table.
#[repr(C)]
pub(crate) struct ArenaPages {
    pub(crate) pages: *mut u8,
    pub(crate) pages_abandoned: [*mut u8; crate::config::ARENA_BIN_COUNT],
}

/// The fixed `mi_arena_t` metadata image for the frozen default profile.
///
/// Bitmap pointers name atomically accessed caller-owned images in the arena's
/// reserved prefix. All non-atomic fields are initialized before registry
/// publication and remain immutable in the current substrate, except for the
/// source-defined partial-split adjustment of a parent `total_size`.
#[repr(C)]
pub(crate) struct Arena {
    pub(crate) memid: MemoryId,
    pub(crate) subprocess: *mut Subprocess,
    pub(crate) arena_index: usize,
    pub(crate) start: *mut u8,
    pub(crate) slice_count: usize,
    pub(crate) info_slices: usize,
    pub(crate) numa_node: i32,
    pub(crate) is_exclusive: bool,
    pub(crate) purge_expire: AtomicI64,
    pub(crate) commit_function: Option<CommitFunction>,
    pub(crate) commit_function_argument: *mut c_void,
    pub(crate) total_size: usize,
    pub(crate) parent: *mut Arena,
    pub(crate) slices_free: *mut u8,
    pub(crate) slices_committed: *mut u8,
    pub(crate) slices_dirty: *mut u8,
    pub(crate) slices_purge: *mut u8,
    pub(crate) pages_meta: *mut Page,
    pub(crate) pages_main: ArenaPages,
}

// SAFETY: registry publication gives shared access only after every ordinary
// field and bitmap pointer is initialized. Concurrent bitmap state is atomic;
// later lifecycle slices must preserve this publication/quiescence contract.
unsafe impl Send for Arena {}
unsafe impl Sync for Arena {}

impl Page {
    const fn empty() -> Self {
        Self {
            self_: AtomicPtr::new(null_mut()),
            xthread_id: AtomicUsize::new(THREAD_ID_ABANDONED),
            free: null_mut(),
            used: 0,
            local_free: null_mut(),
            block_size: 0,
            page_offset: 0,
            capacity: 0,
            reserved: 0,
            slice_pcommitted: 0,
            retire_expire: 0,
            free_is_zero: false,
            xthread_free: AtomicUsize::new(0),
            theap: null_mut(),
            heap: null_mut(),
            next: null_mut(),
            prev: null_mut(),
            memid: MemoryId::static_empty(),
        }
    }

    /// Associates a newly initialized page with the caller's exclusive
    /// default theap.
    ///
    /// This is the single-thread subset of
    /// `internal.h:mi_page_set_theap`: the page has no remote-free producer,
    /// so no flags need to survive a compare/exchange loop. `theap` and
    /// `heap` must remain address-stable while the page can be observed; the
    /// bootstrap owner enforces that by requiring pinning before it exposes
    /// either address. The page metadata itself must likewise remain live and
    /// exclusively mutable for the complete association.
    pub(crate) fn associate_exclusive(
        &mut self,
        theap: &mut Theap,
        heap: &mut Heap,
        thread_id: LiveThreadId,
    ) {
        debug_assert!(theap.matches_thread(thread_id));
        self.theap = core::ptr::from_mut(theap);
        self.heap = core::ptr::from_mut(heap);
        self.xthread_id.store(thread_id.get(), core::sync::atomic::Ordering::Release);
        // The source's owner bit permits access to the non-atomic page fields.
        // This exclusive slice has no remote-free transitions but begins with
        // the same owned empty-list state.
        self.xthread_free.store(1, core::sync::atomic::Ordering::Release);
    }

    /// Publishes a freshly acquired page into the exclusive local lifecycle.
    ///
    /// This is the source-defined partial initialization from
    /// `arena.c:mi_arenas_page_alloc_fresh` followed by the reset invariants
    /// checked in `page.c:_mi_page_init`; extending the local free list is a
    /// separate operation. The pointed theap and heap must be the stable
    /// fields of a pinned [`crate::bootstrap::DefaultSingleThreadBootstrap`].
    /// `reserved` is the complete source-reserved block count and must be
    /// nonzero. `page_offset` identifies the already-provisioned live block
    /// area; this routine deliberately does not allocate, map, or validate it.
    pub(crate) fn publish_fresh_exclusive(
        &mut self,
        theap: &mut Theap,
        heap: &mut Heap,
        thread_id: LiveThreadId,
        block_size: usize,
        page_offset: usize,
        reserved: u16,
        slice_pcommitted: u16,
        free_is_zero: bool,
        memid: MemoryId,
    ) -> bool {
        if !Self::fresh_parameters_are_valid(block_size, page_offset, reserved) {
            return false;
        }

        self.free = null_mut();
        self.used = 0;
        self.local_free = null_mut();
        self.block_size = block_size;
        self.page_offset = page_offset;
        self.capacity = 0;
        self.reserved = reserved;
        self.slice_pcommitted = slice_pcommitted;
        self.retire_expire = 0;
        self.free_is_zero = free_is_zero;
        self.next = null_mut();
        self.prev = null_mut();
        self.memid = memid;
        self.associate_exclusive(theap, heap, thread_id);
        // `MI_PAGE_META_IS_ALIGNED` is enabled in the frozen profile. As in
        // `arena.c`, publish the self map only after every ordinary page field
        // and exclusive owner record is ready.
        let self_pointer = core::ptr::from_mut(self);
        self.self_
            .store(self_pointer, core::sync::atomic::Ordering::Release);
        true
    }

    #[inline]
    const fn fresh_parameters_are_valid(block_size: usize, page_offset: usize, reserved: u16) -> bool {
        block_size != 0 && page_offset != 0 && reserved != 0
    }

    /// Initializes potentially nonzero raw metadata and publishes a fresh
    /// page into the exclusive local lifecycle.
    ///
    /// This is the only fresh-page entry point for newly committed arena
    /// metadata. It writes [`Self::empty`] before creating a Rust reference,
    /// matching `arena.c`'s explicit metadata zeroing rather than assuming the
    /// OS mapping happened to contain a valid `Page` value.
    ///
    /// # Safety
    ///
    /// `metadata` must be aligned writable storage for exactly one `Page` and
    /// must not currently hold a live Rust `Page`; no alias or page-map entry
    /// may observe it while this method initializes it. The storage, the
    /// supplied pinned theap/heap, and the complete page block area described
    /// by `page_offset` and `reserved * block_size` must remain live and
    /// exclusively owned through the local page lifecycle. All source page
    /// geometry/provenance inputs must describe that existing memory. This
    /// method maps no memory and does not validate a virtual-memory range.
    pub(crate) unsafe fn publish_fresh_exclusive_at(
        mut metadata: NonNull<Self>,
        theap: &mut Theap,
        heap: &mut Heap,
        thread_id: LiveThreadId,
        block_size: usize,
        page_offset: usize,
        reserved: u16,
        slice_pcommitted: u16,
        free_is_zero: bool,
        memid: MemoryId,
    ) -> Option<NonNull<Self>> {
        if !Self::fresh_parameters_are_valid(block_size, page_offset, reserved) {
            return None;
        }
        // SAFETY: the caller proves that this aligned writable metadata does
        // not contain a live `Page`, so initialization by raw write is valid.
        unsafe { metadata.as_ptr().write(Self::empty()) };
        // SAFETY: the preceding raw write initialized a valid Page value at
        // `metadata`; exclusive caller ownership permits this mutable borrow.
        let page = unsafe { metadata.as_mut() };
        debug_assert!(page.publish_fresh_exclusive(
            theap,
            heap,
            thread_id,
            block_size,
            page_offset,
            reserved,
            slice_pcommitted,
            free_is_zero,
            memid,
        ));
        Some(metadata)
    }

    /// Removes an exclusive-theap association before the page metadata is
    /// reused. No remote free may be in flight.
    pub(crate) fn disassociate_exclusive(&mut self) {
        self.theap = null_mut();
        self.xthread_id
            .store(THREAD_ID_ABANDONED, core::sync::atomic::Ordering::Release);
        self.xthread_free.store(0, core::sync::atomic::Ordering::Release);
    }

    /// Retires a fully free, queue-detached page before its mapping/provenance
    /// is released, returning the source memory ID needed for that release.
    ///
    /// The caller must already have removed the page from its queue and direct
    /// cache, decremented the owning theap page count, and established that no
    /// remote free or observer exists. The caller must use the returned
    /// provenance to unregister the raw page address before it releases the
    /// backing mapping. This is the exclusive single-thread subset of
    /// `page.c:_mi_page_free` plus the metadata reset performed by its arena
    /// release path; it is not abandonment or cross-thread reclamation.
    #[inline]
    pub(crate) fn retire_exclusive(&mut self) -> Option<MemoryId> {
        if self.used != 0 || !self.next.is_null() || !self.prev.is_null() {
            return None;
        }

        let memid = self.memid;
        self.self_
            .store(null_mut(), core::sync::atomic::Ordering::Release);
        self.xthread_id
            .store(THREAD_ID_ABANDONED, core::sync::atomic::Ordering::Release);
        self.xthread_free.store(0, core::sync::atomic::Ordering::Release);
        self.free = null_mut();
        self.local_free = null_mut();
        self.block_size = 0;
        self.page_offset = 0;
        self.capacity = 0;
        self.reserved = 0;
        self.slice_pcommitted = 0;
        self.retire_expire = 0;
        self.free_is_zero = false;
        self.theap = null_mut();
        self.heap = null_mut();
        self.next = null_mut();
        self.prev = null_mut();
        self.memid = MemoryId::none();
        Some(memid)
    }

    #[inline]
    pub(crate) const fn free_list_head(&self) -> *mut Block {
        self.free
    }

    /// Replaces the ordinary free-list head while this page is exclusively
    /// owned by its associated single-thread theap.
    ///
    /// `head` must be null or the first valid block of this page's unencoded
    /// free list. Encoded and remote free-list protocols remain out of scope.
    #[inline]
    pub(crate) fn set_exclusive_free_list_head(&mut self, head: *mut Block) {
        self.free = head;
    }

    #[inline]
    pub(crate) const fn used(&self) -> usize {
        self.used
    }

    /// Changes `used` only for the exclusive local lifecycle. The caller must
    /// preserve the source page equation relative to the free list and
    /// capacity; remote-free collection is not implemented in this slice.
    #[inline]
    pub(crate) fn set_exclusive_used(&mut self, used: usize) {
        self.used = used;
    }

    #[inline]
    pub(crate) const fn reserved(&self) -> u16 {
        self.reserved
    }

    #[inline]
    pub(crate) const fn capacity(&self) -> u16 {
        self.capacity
    }

    /// Sets the local page capacity record before the page is published into
    /// an exclusive theap queue. `capacity` must not exceed `reserved`.
    #[inline]
    pub(crate) fn set_capacity_reserved(&mut self, capacity: u16, reserved: u16) -> bool {
        if capacity > reserved {
            return false;
        }
        self.capacity = capacity;
        self.reserved = reserved;
        true
    }

    #[inline]
    pub(crate) const fn block_size(&self) -> usize {
        self.block_size
    }

    #[inline]
    pub(crate) fn set_block_size(&mut self, block_size: usize) {
        self.block_size = block_size;
    }

    /// Returns the source `mi_page_start` address.
    ///
    /// # Safety
    ///
    /// The metadata must describe a live page whose block area starts exactly
    /// `page_offset` bytes after this `Page`; the resulting pointer range must
    /// remain in the same allocated object. The return value carries no access
    /// permission by itself.
    #[inline]
    pub(crate) unsafe fn start(&self) -> *mut u8 {
        // SAFETY: the caller proves the source page-area layout and bounds.
        unsafe { (self as *const Self).cast_mut().cast::<u8>().add(self.page_offset) }
    }

    #[inline]
    pub(crate) const fn page_offset(&self) -> usize {
        self.page_offset
    }

    #[inline]
    pub(crate) const fn memid(&self) -> MemoryId {
        self.memid
    }

    #[inline]
    pub(crate) const fn retire_expire(&self) -> u8 {
        self.retire_expire
    }

    #[inline]
    pub(crate) const fn free_is_zero(&self) -> bool {
        self.free_is_zero
    }

    /// Sets the source retirement countdown while the caller exclusively owns
    /// this page and its queue membership.
    #[inline]
    pub(crate) fn set_retire_expire(&mut self, retire_expire: u8) {
        self.retire_expire = retire_expire;
    }

    /// Projects exactly the local free-list fields used by the single-thread
    /// source path.
    ///
    /// # Safety
    ///
    /// The caller must exclusively own this live page and its entire block
    /// area: `page_offset` bytes from this metadata address must begin a
    /// writable allocation of exactly `reserved * block_size` bytes, with
    /// nonzero `block_size` and `reserved`. The multiplication and resulting
    /// pointer range must not overflow. The page must be associated with the
    /// caller's live exclusive theap, and no remote-free, page-map,
    /// queue-retirement, or other access may observe or mutate the projected
    /// fields for the lifetime of the returned projection. Each free-list
    /// pointer written through it must be null or an aligned block inside this
    /// area. These are the source `mi_page_t` local-list invariants; this
    /// bootstrap slice intentionally does not supply their concurrent form.
    #[inline]
    pub(super) unsafe fn local_free_list_state(&mut self) -> PageFreeListState<'_> {
        debug_assert!(self.block_size != 0);
        debug_assert!(self.reserved != 0);
        // SAFETY: the caller's live-area contract proves that advancing from
        // this page metadata address by `page_offset` remains in bounds and
        // produces the beginning of its writable block area.
        let area = unsafe { (self as *mut Self).cast::<u8>().add(self.page_offset) };
        // SAFETY: the live-area contract also proves the returned area pointer
        // is non-null and valid for the derived byte count.
        let area = unsafe { NonNull::new_unchecked(area) };
        // SAFETY: the same caller contract proves this source field product
        // does not overflow and identifies the complete page block area.
        let area_bytes = unsafe { usize::from(self.reserved).unchecked_mul(self.block_size) };

        PageFreeListState {
            area,
            area_bytes,
            block_size: self.block_size,
            capacity: &mut self.capacity,
            reserved: self.reserved,
            free: &mut self.free,
            local_free: &mut self.local_free,
            used: &mut self.used,
            free_is_zero: &mut self.free_is_zero,
        }
    }

    #[inline]
    pub(crate) const fn theap(&self) -> *mut Theap {
        self.theap
    }

    #[inline]
    pub(crate) const fn heap(&self) -> *mut Heap {
        self.heap
    }

    /// Returns the next raw queue link for exclusive retired-page traversal.
    ///
    /// Queue mutation remains confined to `page_queue`; callers may only
    /// follow this pointer while the owning single-thread session guarantees
    /// that the page stays queue-linked and live.
    #[inline]
    pub(crate) const fn next(&self) -> *mut Page {
        self.next
    }
}

// This is the immutable `src/init.c:mi_page_empty` prototype. `Page` contains
// raw pointers and is therefore not auto-`Sync`; the wrapper exposes only a
// shared reference and never permits mutation of this static prototype.
#[repr(transparent)]
pub(crate) struct BootstrapPage(Page);

// SAFETY: `BootstrapPage` only exposes `&Page`; its non-atomic fields are an
// immutable zero-state prototype and no safe API exposes mutable access.
unsafe impl Sync for BootstrapPage {}

impl BootstrapPage {
    #[inline]
    pub(crate) const fn as_ref(&self) -> &Page {
        &self.0
    }

    /// Returns the source-shaped direct-cache sentinel pointer.
    ///
    /// The pointed page is immutable bootstrap metadata. A direct-cache slot
    /// may compare against it, but it must never mutate it or enqueue it.
    #[inline]
    pub(crate) const fn as_ptr(&self) -> *mut Page {
        core::ptr::addr_of!(self.0).cast_mut()
    }
}

pub(crate) static EMPTY_PAGE: BootstrapPage = BootstrapPage(Page::empty());

// `src/init.c:mi_tld_detached`. It is immutable: the live default-theap
// bootstrap owns a separate TLD prefix after pinning. Keeping this source
// static separate is what lets the initial empty theap avoid any TLS access.
pub(crate) static DETACHED_THREAD_LOCAL: ThreadLocalData = ThreadLocalData::detached();

/// Exact ABI image of `mi_random_ctx_t` used only by the static theap prefix.
///
/// The active random lifecycle is owned by `random::RandomContext`, whose
/// RustCrypto-backed representation intentionally is not this C layout. The
/// bootstrap only needs the source's all-zero input/output state with `weak`
/// set, so an inert layout image keeps those roles separate.
#[repr(C)]
struct TheapRandomImage {
    input: [u32; 16],
    output: [u32; 16],
    output_available: i32,
    weak: bool,
}

impl TheapRandomImage {
    const fn empty_weak() -> Self {
        Self {
            input: [0; 16],
            output: [0; 16],
            output_available: 0,
            weak: true,
        }
    }
}

/// Source-layout prefix of `mi_theap_t` through `memid`.
///
/// This prefix contains every field required by the default direct-page
/// cache, page queues, and exclusive local page accounting. `mi_stats_t`
/// follows `memid` in C but is not represented: statistics require their own
/// lifecycle and merge contract. Consequently this Rust type intentionally
/// has no complete-`mi_theap_t` size claim.
#[repr(C)]
pub(crate) struct Theap {
    // Keep first for `internal.h:_mi_theap_get_free_small_page`.
    pages_free_direct: [*mut Page; PAGES_DIRECT],
    tld: *mut ThreadLocalData,
    heap: AtomicPtr<Heap>,
    subproc: AtomicPtr<Subprocess>,
    refcount: AtomicUsize,
    heartbeat: u64,
    cookie: usize,
    random: TheapRandomImage,
    page_count: usize,
    page_retired_min: usize,
    page_retired_max: usize,
    pages_full_size: usize,
    generic_count: isize,
    generic_collect_count: isize,
    tnext: *mut Theap,
    tprev: *mut Theap,
    hnext: *mut Theap,
    hprev: *mut Theap,
    page_full_retain: isize,
    allow_page_reclaim: bool,
    allow_page_abandon: bool,
    is_detached: bool,
    pages: [PageQueue; BIN_COUNT],
    memid: MemoryId,
}

impl Theap {
    /// `src/init.c:_mi_theap_empty` through its `memid` prefix.
    ///
    /// No heap is published, so `is_initialized` remains false exactly as in
    /// `internal.h:mi_theap_is_initialized`. The direct table is deliberately
    /// populated with the immutable empty-page sentinel rather than null.
    pub(crate) const fn empty() -> Self {
        Self {
            pages_free_direct: [EMPTY_PAGE.as_ptr(); PAGES_DIRECT],
            tld: core::ptr::addr_of!(DETACHED_THREAD_LOCAL).cast_mut(),
            heap: AtomicPtr::new(null_mut()),
            subproc: AtomicPtr::new(null_mut()),
            refcount: AtomicUsize::new(1),
            heartbeat: 0,
            cookie: 0,
            random: TheapRandomImage::empty_weak(),
            page_count: 0,
            page_retired_min: BIN_FULL,
            page_retired_max: 0,
            pages_full_size: 0,
            generic_count: 0,
            generic_collect_count: 0,
            tnext: null_mut(),
            tprev: null_mut(),
            hnext: null_mut(),
            hprev: null_mut(),
            page_full_retain: 0,
            allow_page_reclaim: false,
            allow_page_abandon: true,
            is_detached: true,
            pages: EMPTY_PAGE_QUEUES,
            memid: MemoryId::static_empty(),
        }
    }

    /// Binds the empty source image to the one pinned default heap/TLD pair.
    ///
    /// The caller must first attach `tld` to a valid [`LiveThreadId`] and must
    /// ensure both input addresses remain stable for every associated page.
    /// `DefaultSingleThreadBootstrap` is the only owner in this slice and
    /// makes that condition explicit with `Pin`. Publishing `heap` last is
    /// source order from `src/theap.c:_mi_theap_init`: it is the initialized
    /// predicate and must not become non-null before the preceding fields are
    /// ready.
    pub(crate) fn bind_exclusive_single_thread(
        &mut self,
        heap: &mut Heap,
        tld: &mut ThreadLocalData,
    ) -> bool {
        let Some(thread_id) = LiveThreadId::new(tld.thread_id()) else {
            return false;
        };
        if self.is_initialized() {
            return false;
        }

        self.tld = core::ptr::from_mut(tld);
        self.refcount.store(1, core::sync::atomic::Ordering::Release);
        self.subproc
            .store(heap.subprocess, core::sync::atomic::Ordering::Release);
        self.is_detached = false;
        // The normal source default permits abandonment. This bounded state
        // intentionally uses the source's non-abandoning/destroyable-theap
        // mode because it does not implement remote-free or adoption.
        self.allow_page_abandon = false;
        debug_assert!(self.matches_thread(thread_id));
        self.heap.store(
            core::ptr::from_mut(heap),
            core::sync::atomic::Ordering::Release,
        );
        true
    }

    #[inline]
    pub(crate) fn is_initialized(&self) -> bool {
        !self.heap.load(core::sync::atomic::Ordering::Relaxed).is_null()
    }

    #[inline]
    pub(crate) fn matches_thread(&self, thread_id: LiveThreadId) -> bool {
        // The only constructors use `DETACHED_THREAD_LOCAL` or a pinned
        // `DefaultSingleThreadBootstrap` field, both live for this reference.
        let tld = unsafe { self.tld.as_ref() };
        matches!(tld, Some(tld) if tld.thread_id() == thread_id.get())
    }

    #[inline]
    pub(crate) const fn is_detached(&self) -> bool {
        self.is_detached
    }

    #[inline]
    pub(crate) fn refcount(&self) -> usize {
        self.refcount.load(core::sync::atomic::Ordering::Relaxed)
    }

    #[inline]
    pub(crate) fn heap(&self) -> *mut Heap {
        self.heap.load(core::sync::atomic::Ordering::Relaxed)
    }

    #[inline]
    pub(crate) const fn page_count(&self) -> usize {
        self.page_count
    }

    #[inline]
    pub(crate) const fn allows_page_abandon(&self) -> bool {
        self.allow_page_abandon
    }

    #[inline]
    pub(crate) const fn retired_bounds(&self) -> (usize, usize) {
        (self.page_retired_min, self.page_retired_max)
    }

    /// Includes one source regular-bin retirement in the bounded collection
    /// range. Full and huge queues are never retired through this mechanism.
    #[inline]
    pub(crate) fn note_retired_bin(&mut self, bin: usize) -> bool {
        if bin >= BIN_FULL {
            return false;
        }
        if bin < self.page_retired_min {
            self.page_retired_min = bin;
        }
        if bin > self.page_retired_max {
            self.page_retired_max = bin;
        }
        true
    }

    /// Restores the empty `src/init.c:_mi_theap_empty` retirement range after
    /// a collection pass has found no remaining retired regular-bin page.
    #[inline]
    pub(crate) fn reset_retired_bounds(&mut self) {
        self.page_retired_min = BIN_FULL;
        self.page_retired_max = 0;
    }

    #[inline]
    pub(crate) fn queue(&self, bin: usize) -> Option<&PageQueue> {
        self.pages.get(bin)
    }

    /// Grants the single-thread lifecycle code mutable access to one exact
    /// source queue. It must maintain `page_count` through
    /// [`Self::note_page_added`] and [`Self::note_page_removed`] alongside the
    /// intrusive `page_queue` transitions.
    #[inline]
    pub(crate) fn queue_mut(&mut self, bin: usize) -> Option<&mut PageQueue> {
        self.pages.get_mut(bin)
    }

    #[inline]
    pub(crate) fn direct_page(&self, index: usize) -> Option<*mut Page> {
        match self.pages_free_direct.get(index) {
            Some(page) => Some(*page),
            None => None,
        }
    }

    /// Replaces one direct-cache entry under the exclusive local lifecycle.
    ///
    /// `page` must be [`EMPTY_PAGE`] or a live page owned by this exact theap;
    /// callers must clear the slot before retiring or reusing that live page.
    #[inline]
    pub(crate) fn set_direct_page(&mut self, index: usize, page: *mut Page) -> bool {
        let Some(slot) = self.pages_free_direct.get_mut(index) else {
            return false;
        };
        *slot = page;
        true
    }

    #[inline]
    pub(crate) fn clear_direct_page(&mut self, index: usize) -> bool {
        self.set_direct_page(index, EMPTY_PAGE.as_ptr())
    }

    /// Mirrors the owning-theap count update performed around the source's
    /// queue insertion helpers. The caller must have exclusively inserted one
    /// page into a queue first.
    #[inline]
    pub(crate) fn note_page_added(&mut self) {
        self.page_count += 1;
    }

    /// Mirrors the owning-theap count update performed around the source's
    /// queue removal helpers. Returns `false` rather than underflowing when a
    /// caller violates the queue/page-count pairing contract.
    #[inline]
    pub(crate) fn note_page_removed(&mut self) -> bool {
        let Some(next) = self.page_count.checked_sub(1) else {
            return false;
        };
        self.page_count = next;
        true
    }
}

const _: [(); 4] = [(); size_of::<MemoryKind>()];
const _: [(); 16] = [(); size_of::<MemoryInfo>()];
const _: [(); 8] = [(); align_of::<MemoryInfo>()];
const _: [(); 24] = [(); size_of::<MemoryId>()];
const _: [(); 8] = [(); align_of::<MemoryId>()];
const _: [(); 496] = [(); size_of::<ArenaPages>()];
const _: [(); 8] = [(); align_of::<ArenaPages>()];
const _: [(); 648] = [(); size_of::<Arena>()];
const _: [(); 8] = [(); align_of::<Arena>()];
const _: [(); 8] = [(); size_of::<Block>()];
const _: [(); 32] = [(); size_of::<PageQueue>()];
const _: [(); 128] = [(); size_of::<Page>()];
const _: [(); 8] = [(); align_of::<Page>()];
const _: [(); 8] = [(); size_of::<Heap>()];
const _: [(); 8] = [(); align_of::<Heap>()];
const _: [(); 136] = [(); size_of::<TheapRandomImage>()];
const _: [(); 4] = [(); align_of::<TheapRandomImage>()];
const _: [(); 3736] = [(); size_of::<Theap>()];
const _: [(); 8] = [(); align_of::<Theap>()];
const _: [(); 129] = [(); PAGES_DIRECT];
const _: [(); 74] = [(); BIN_FULL];

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::mem::{align_of, offset_of, size_of};

    #[test]
    fn oracle_layout_probe_emits_machine_record() {
        macro_rules! record {
            ($name:literal, $value:expr) => {
                std::println!("{}={}", $name, $value);
            };
        }

        std::println!("CRABC_MI_LAYOUT_BEGIN");
        record!("pointer.size", size_of::<*const ()>());
        record!("sizeof.mi_memkind_t", size_of::<MemoryKind>());
        record!("alignof.mi_memkind_t", align_of::<MemoryKind>());
        record!("value.MI_MEM_NONE", MemoryKind::None as usize);
        record!("value.MI_MEM_EXTERNAL", MemoryKind::External as usize);
        record!("value.MI_MEM_STATIC", MemoryKind::Static as usize);
        record!("value.MI_MEM_OS", MemoryKind::Os as usize);
        record!("value.MI_MEM_OS_HUGE", MemoryKind::OsHuge as usize);
        record!("value.MI_MEM_OS_REMAP", MemoryKind::OsRemap as usize);
        record!("value.MI_MEM_ARENA", MemoryKind::Arena as usize);
        record!("value.MI_MEM_MALLOC", MemoryKind::Malloc as usize);
        record!("sizeof.mi_memid_t", size_of::<MemoryId>());
        record!("alignof.mi_memid_t", align_of::<MemoryId>());
        record!("offsetof.mi_memid_t.mem", offset_of!(MemoryId, info));
        record!("offsetof.mi_memid_t.memkind", offset_of!(MemoryId, kind));
        record!("offsetof.mi_memid_t.is_pinned", offset_of!(MemoryId, is_pinned));
        record!(
            "offsetof.mi_memid_t.initially_committed",
            offset_of!(MemoryId, initially_committed)
        );
        record!(
            "offsetof.mi_memid_t.initially_zero",
            offset_of!(MemoryId, initially_zero)
        );
        record!("sizeof.mi_page_t", size_of::<Page>());
        record!("alignof.mi_page_t", align_of::<Page>());
        record!("offsetof.mi_page_t.xthread_free", offset_of!(Page, xthread_free));
        record!("offsetof.mi_page_t.theap", offset_of!(Page, theap));
        record!("offsetof.mi_page_t.memid", offset_of!(Page, memid));
        record!("sizeof.mi_page_kind_t", size_of::<PageKind>());
        record!("alignof.mi_page_kind_t", align_of::<PageKind>());
        record!("value.MI_PAGE_SMALL", PageKind::Small as usize);
        record!("value.MI_PAGE_MEDIUM", PageKind::Medium as usize);
        record!("value.MI_PAGE_LARGE", PageKind::Large as usize);
        record!("value.MI_PAGE_SINGLETON", PageKind::Singleton as usize);
        record!("sizeof.mi_page_queue_t", size_of::<PageQueue>());
        record!("alignof.mi_page_queue_t", align_of::<PageQueue>());
        record!("offsetof.mi_page_queue_t.first", offset_of!(PageQueue, first));
        record!("offsetof.mi_page_queue_t.last", offset_of!(PageQueue, last));
        record!("offsetof.mi_page_queue_t.count", offset_of!(PageQueue, count));
        record!(
            "offsetof.mi_page_queue_t.block_size",
            offset_of!(PageQueue, block_size)
        );
        record!("alignof.mi_theap_t", align_of::<Theap>());
        record!(
            "offsetof.mi_theap_t.pages_free_direct",
            offset_of!(Theap, pages_free_direct)
        );
        record!("offsetof.mi_theap_t.page_count", offset_of!(Theap, page_count));
        record!("offsetof.mi_theap_t.pages", offset_of!(Theap, pages));
        record!("offsetof.mi_theap_t.memid", offset_of!(Theap, memid));
        // This exact prefix ends where the intentionally absent C `stats`
        // field begins; it is not a complete `sizeof(mi_theap_t)` claim.
        record!("offsetof.mi_theap_t.stats", size_of::<Theap>());
        record!("sizeof.mi_arena_t", size_of::<Arena>());
        record!("alignof.mi_arena_t", align_of::<Arena>());
        record!("offsetof.mi_arena_t.memid", offset_of!(Arena, memid));
        record!("offsetof.mi_arena_t.subproc", offset_of!(Arena, subprocess));
        record!("offsetof.mi_arena_t.arena_idx", offset_of!(Arena, arena_index));
        record!("offsetof.mi_arena_t.start", offset_of!(Arena, start));
        record!("offsetof.mi_arena_t.slice_count", offset_of!(Arena, slice_count));
        record!("offsetof.mi_arena_t.info_slices", offset_of!(Arena, info_slices));
        record!("offsetof.mi_arena_t.numa_node", offset_of!(Arena, numa_node));
        record!("offsetof.mi_arena_t.is_exclusive", offset_of!(Arena, is_exclusive));
        record!("offsetof.mi_arena_t.purge_expire", offset_of!(Arena, purge_expire));
        record!("offsetof.mi_arena_t.commit_fun", offset_of!(Arena, commit_function));
        record!(
            "offsetof.mi_arena_t.commit_fun_arg",
            offset_of!(Arena, commit_function_argument)
        );
        record!("offsetof.mi_arena_t.total_size", offset_of!(Arena, total_size));
        record!("offsetof.mi_arena_t.parent", offset_of!(Arena, parent));
        record!("offsetof.mi_arena_t.slices_free", offset_of!(Arena, slices_free));
        record!(
            "offsetof.mi_arena_t.slices_committed",
            offset_of!(Arena, slices_committed)
        );
        record!("offsetof.mi_arena_t.slices_dirty", offset_of!(Arena, slices_dirty));
        record!("offsetof.mi_arena_t.slices_purge", offset_of!(Arena, slices_purge));
        record!("offsetof.mi_arena_t.pages_meta", offset_of!(Arena, pages_meta));
        record!("offsetof.mi_arena_t.pages_main", offset_of!(Arena, pages_main));
        record!("sizeof.mi_arena_pages_t", size_of::<ArenaPages>());
        record!("alignof.mi_arena_pages_t", align_of::<ArenaPages>());
        record!("offsetof.mi_arena_pages_t.pages", offset_of!(ArenaPages, pages));
        record!(
            "offsetof.mi_arena_pages_t.pages_abandoned",
            offset_of!(ArenaPages, pages_abandoned)
        );
        record!("MI_DEBUG", crate::config::DEBUG_LEVEL);
        record!("MI_SECURE", crate::config::SECURE_LEVEL);
        record!("MI_STAT", crate::config::STAT_LEVEL);
        record!("MI_GUARDED", crate::config::GUARDED as usize);
        record!("MI_PADDING", (crate::config::PADDING_SIZE != 0) as usize);
        record!("MI_ENCODE_FREELIST", crate::config::ENCODE_FREELIST as usize);
        record!("MI_FREE_IS_CHECKED", crate::config::FREE_IS_CHECKED as usize);
        record!("MI_BIN_COUNT", crate::config::BIN_COUNT);
        record!("MI_BIN_HUGE", crate::config::BIN_HUGE);
        record!("MI_ARENA_SLICE_SIZE", crate::config::ARENA_SLICE_SIZE);
        record!("MI_ARENA_CHUNK_SIZE", crate::config::ARENA_CHUNK_SIZE);
        record!("MI_SMALL_PAGE_SIZE", crate::config::SMALL_PAGE_SIZE);
        record!("MI_MEDIUM_PAGE_SIZE", crate::config::MEDIUM_PAGE_SIZE);
        record!("MI_LARGE_PAGE_SIZE", crate::config::LARGE_PAGE_SIZE);
        record!("MI_SMALL_MAX_OBJ_SIZE", crate::config::SMALL_MAX_OBJ_SIZE);
        record!("MI_MEDIUM_MAX_OBJ_SIZE", crate::config::MEDIUM_MAX_OBJ_SIZE);
        record!("MI_LARGE_MAX_OBJ_SIZE", crate::config::LARGE_MAX_OBJ_SIZE);
        record!("MI_MAX_ARENAS", crate::config::MAX_ARENAS);

        // Keep one machine record for every source-derived production
        // constant in `config.rs`; the runner compares these values directly
        // with the pinned v3.5.0 C expressions in `LAYOUT_PROBE`.
        record!("config.WORD_SIZE", crate::config::WORD_SIZE);
        record!("config.MAX_ALIGN_SIZE", crate::config::MAX_ALIGN_SIZE);
        record!("config.SECURE_LEVEL", crate::config::SECURE_LEVEL);
        record!("config.DEBUG_LEVEL", crate::config::DEBUG_LEVEL);
        record!("config.STAT_LEVEL", crate::config::STAT_LEVEL);
        record!(
            "config.FREE_IS_CHECKED",
            crate::config::FREE_IS_CHECKED as usize
        );
        record!(
            "config.FREE_USE_PAGEMAP",
            crate::config::FREE_USE_PAGEMAP as usize
        );
        record!(
            "config.OPT_FREE_SMALL",
            crate::config::OPT_FREE_SMALL as usize
        );
        record!(
            "config.ENABLE_LARGE_PAGES",
            crate::config::ENABLE_LARGE_PAGES as usize
        );
        record!(
            "config.ENCODE_FREELIST",
            crate::config::ENCODE_FREELIST as usize
        );
        record!("config.GUARDED", crate::config::GUARDED as usize);
        record!("config.OPT_SIMD", crate::config::OPT_SIMD as usize);
        record!("config.PADDING_SIZE", crate::config::PADDING_SIZE);
        record!("config.PADDING_WSIZE", crate::config::PADDING_WSIZE);
        record!("config.PAGE_KEY_COUNT", crate::config::PAGE_KEY_COUNT);
        record!("config.ARENA_SLICE_SHIFT", crate::config::ARENA_SLICE_SHIFT);
        record!("config.BCHUNK_BITS_SHIFT", crate::config::BCHUNK_BITS_SHIFT);
        record!("config.BCHUNK_BITS", crate::config::BCHUNK_BITS);
        record!("config.ARENA_SLICE_SIZE", crate::config::ARENA_SLICE_SIZE);
        record!("config.ARENA_SLICE_ALIGN", crate::config::ARENA_SLICE_ALIGN);
        record!("config.ARENA_CHUNK_SIZE", crate::config::ARENA_CHUNK_SIZE);
        record!(
            "config.ARENA_MIN_OBJ_SLICES",
            crate::config::ARENA_MIN_OBJ_SLICES
        );
        record!(
            "config.ARENA_MAX_CHUNK_OBJ_SLICES",
            crate::config::ARENA_MAX_CHUNK_OBJ_SLICES
        );
        record!("config.ARENA_MIN_OBJ_SIZE", crate::config::ARENA_MIN_OBJ_SIZE);
        record!(
            "config.ARENA_MAX_CHUNK_OBJ_SIZE",
            crate::config::ARENA_MAX_CHUNK_OBJ_SIZE
        );
        record!("config.SMALL_PAGE_SIZE", crate::config::SMALL_PAGE_SIZE);
        record!("config.MEDIUM_PAGE_SIZE", crate::config::MEDIUM_PAGE_SIZE);
        record!("config.LARGE_PAGE_SIZE", crate::config::LARGE_PAGE_SIZE);
        record!("config.BIN_HUGE", crate::config::BIN_HUGE);
        record!("config.BIN_FULL", crate::config::BIN_FULL);
        record!("config.BIN_COUNT", crate::config::BIN_COUNT);
        record!("config.MAX_ALLOC_SIZE", crate::config::MAX_ALLOC_SIZE);
        record!(
            "config.PAGE_MIN_COMMIT_SIZE",
            crate::config::PAGE_MIN_COMMIT_SIZE
        );
        record!(
            "config.PAGE_META_IS_SEPARATED",
            crate::config::PAGE_META_IS_SEPARATED as usize
        );
        record!(
            "config.PAGE_META_IS_ALIGNED",
            crate::config::PAGE_META_IS_ALIGNED as usize
        );
        record!(
            "config.PAGE_META_ALIGNED_CHUNKS",
            crate::config::PAGE_META_ALIGNED_CHUNKS
        );
        record!(
            "config.PAGE_META_ALIGNED_COUNT",
            crate::config::PAGE_META_ALIGNED_COUNT
        );
        record!(
            "config.PAGE_META_ALIGNMENT",
            crate::config::PAGE_META_ALIGNMENT
        );
        record!("config.ARENA_ALIGNMENT", crate::config::ARENA_ALIGNMENT);
        record!("config.PAGE_ALIGN", crate::config::PAGE_ALIGN);
        record!(
            "config.PAGE_MIN_START_BLOCK_ALIGN",
            crate::config::PAGE_MIN_START_BLOCK_ALIGN
        );
        record!(
            "config.PAGE_MAX_START_BLOCK_ALIGN2",
            crate::config::PAGE_MAX_START_BLOCK_ALIGN2
        );
        record!(
            "config.PAGE_OSPAGE_BLOCK_ALIGN2",
            crate::config::PAGE_OSPAGE_BLOCK_ALIGN2
        );
        record!(
            "config.PAGE_MAX_OVERALLOC_ALIGN",
            crate::config::PAGE_MAX_OVERALLOC_ALIGN
        );
        record!("config.SMALL_WSIZE_MAX", crate::config::SMALL_WSIZE_MAX);
        record!("config.SMALL_SIZE_MAX", crate::config::SMALL_SIZE_MAX);
        record!(
            "config.SMALL_MAX_OBJ_SIZE",
            crate::config::SMALL_MAX_OBJ_SIZE
        );
        record!(
            "config.MEDIUM_MAX_OBJ_SIZE",
            crate::config::MEDIUM_MAX_OBJ_SIZE
        );
        record!(
            "config.LARGE_MAX_OBJ_SIZE",
            crate::config::LARGE_MAX_OBJ_SIZE
        );
        record!(
            "config.LARGE_MAX_OBJ_WSIZE",
            crate::config::LARGE_MAX_OBJ_WSIZE
        );
        record!(
            "config.MAX_SINGLETON_BIN",
            crate::config::MAX_SINGLETON_BIN
        );
        record!("config.PAGES_DIRECT", crate::config::PAGES_DIRECT);
        record!("config.MAX_ARENAS", crate::config::MAX_ARENAS);
        record!("config.ARENA_BIN_COUNT", crate::config::ARENA_BIN_COUNT);
        record!(
            "config.BITMAP_MAX_BIT_COUNT",
            crate::config::BITMAP_MAX_BIT_COUNT
        );
        record!("config.ARENA_MIN_SIZE", crate::config::ARENA_MIN_SIZE);
        record!("config.ARENA_MAX_SIZE", crate::config::ARENA_MAX_SIZE);
        record!("config.MAX_VABITS", crate::config::MAX_VABITS);
        record!("config.MIN_VABITS", crate::config::MIN_VABITS);
        record!("config.PAGE_MAP_FLAT", crate::config::PAGE_MAP_FLAT as usize);
        record!(
            "config.PAGE_MAP_SUB_SHIFT",
            crate::config::PAGE_MAP_SUB_SHIFT
        );
        record!(
            "config.PAGE_MAP_SUB_COUNT",
            crate::config::PAGE_MAP_SUB_COUNT
        );
        record!("config.PAGE_MAP_SHIFT", crate::config::PAGE_MAP_SHIFT);
        for (bin_index, block_size) in BIN_BLOCK_SIZES.iter().copied().enumerate() {
            std::println!("bin.block_size.{bin_index}={block_size}");
            for (label, size) in [
                ("minus", block_size - 1),
                ("at", block_size),
                ("plus", block_size + 1),
            ] {
                let selected = crate::size_class::bin(size)
                    .expect("every queue boundary is below the size-overflow limit");
                std::println!("bin.index.{bin_index}.{label}={selected}");
            }
        }
        std::println!("CRABC_MI_LAYOUT_END");
    }

    #[test]
    fn metadata_layout_matches_the_default_release_c_contract() {
        assert_eq!(size_of::<MemoryKind>(), 4);
        assert_eq!(size_of::<MemoryInfo>(), 16);
        assert_eq!(align_of::<MemoryInfo>(), 8);
        assert_eq!(size_of::<MemoryId>(), 24);
        assert_eq!(align_of::<MemoryId>(), 8);
        assert_eq!(offset_of!(MemoryId, info), 0);
        assert_eq!(offset_of!(MemoryId, kind), 16);
        assert_eq!(offset_of!(MemoryId, is_pinned), 20);
        assert_eq!(offset_of!(MemoryId, initially_committed), 21);
        assert_eq!(offset_of!(MemoryId, initially_zero), 22);

        assert_eq!(size_of::<Block>(), 8);
        assert_eq!(size_of::<PageQueue>(), 32);
        assert_eq!(align_of::<PageQueue>(), 8);
        assert_eq!(size_of::<Page>(), 128);
        assert_eq!(align_of::<Page>(), 8);
        assert_eq!(offset_of!(Page, self_), 0);
        assert_eq!(offset_of!(Page, xthread_id), 8);
        assert_eq!(offset_of!(Page, xthread_free), 64);
        assert_eq!(offset_of!(Page, memid), 104);
    }

    #[test]
    fn represented_theap_prefix_keeps_the_pinned_field_offsets() {
        // These are offsets in the actual C `mi_theap_t`; this Rust prefix
        // stops at the same `memid` end boundary before absent `mi_stats_t`.
        assert_eq!(size_of::<Heap>(), 8);
        assert_eq!(align_of::<Heap>(), 8);
        assert_eq!(size_of::<TheapRandomImage>(), 136);
        assert_eq!(offset_of!(Theap, pages_free_direct), 0);
        assert_eq!(offset_of!(Theap, tld), PAGES_DIRECT * size_of::<*mut Page>());
        assert_eq!(offset_of!(Theap, heap), 1_040);
        assert_eq!(offset_of!(Theap, random), 1_080);
        assert_eq!(offset_of!(Theap, pages), 1_312);
        assert_eq!(offset_of!(Theap, memid), 3_712);
        assert_eq!(size_of::<Theap>(), 3_736);
        assert_eq!(align_of::<Theap>(), 8);
    }

    #[test]
    fn fresh_page_publication_resets_every_local_lifecycle_field() {
        let thread_id = LiveThreadId::new(12).expect("valid source thread identity");
        let mut heap = Heap::bootstrap_empty();
        let mut tld = ThreadLocalData::detached();
        tld.attach_exclusive(thread_id);
        let mut theap = Theap::empty();
        assert!(theap.bind_exclusive_single_thread(&mut heap, &mut tld));

        let mut page = Page::empty();
        page.used = 7;
        page.local_free = core::ptr::without_provenance_mut::<Block>(0x1000);
        page.capacity = 7;
        page.retire_expire = 3;
        page.free_is_zero = true;
        page.next = core::ptr::without_provenance_mut::<Page>(0x1000);
        page.prev = core::ptr::without_provenance_mut::<Page>(0x2000);

        let memid = MemoryId::none();
        assert!(page.publish_fresh_exclusive(
            &mut theap,
            &mut heap,
            thread_id,
            16,
            128,
            32,
            0,
            false,
            memid,
        ));

        assert_eq!(page.self_.load(core::sync::atomic::Ordering::Acquire), core::ptr::from_mut(&mut page));
        assert_eq!(page.theap(), core::ptr::from_mut(&mut theap));
        assert_eq!(page.heap(), core::ptr::from_mut(&mut heap));
        assert_eq!(page.xthread_id.load(core::sync::atomic::Ordering::Acquire), thread_id.get());
        assert_eq!(page.xthread_free.load(core::sync::atomic::Ordering::Acquire), 1);
        assert!(page.free.is_null());
        assert!(page.local_free.is_null());
        assert_eq!(page.used(), 0);
        assert_eq!(page.capacity(), 0);
        assert_eq!(page.reserved(), 32);
        assert_eq!(page.block_size(), 16);
        assert_eq!(page.page_offset(), 128);
        assert_eq!(page.slice_pcommitted, 0);
        assert!(!page.free_is_zero);
        assert_eq!(page.retire_expire(), 0);
        assert!(page.next.is_null());
        assert!(page.prev.is_null());
        assert_eq!(page.memid().kind(), MemoryKind::None);
    }

    #[test]
    fn free_detached_page_retirement_clears_owner_and_returns_provenance() {
        let thread_id = LiveThreadId::new(12).expect("valid source thread identity");
        let mut heap = Heap::bootstrap_empty();
        let mut tld = ThreadLocalData::detached();
        tld.attach_exclusive(thread_id);
        let mut theap = Theap::empty();
        assert!(theap.bind_exclusive_single_thread(&mut heap, &mut tld));

        let source_memid = MemoryId::external(
            core::ptr::without_provenance_mut::<u8>(0x1000),
            4096,
            true,
            false,
            true,
        );
        let mut page = Page::empty();
        assert!(page.publish_fresh_exclusive(
            &mut theap,
            &mut heap,
            thread_id,
            16,
            128,
            32,
            1,
            true,
            source_memid,
        ));

        let released = page
            .retire_exclusive()
            .expect("fresh page is free and queue-detached");
        assert_eq!(released.kind(), MemoryKind::External);
        assert!(page.self_.load(core::sync::atomic::Ordering::Acquire).is_null());
        assert_eq!(
            page.xthread_id.load(core::sync::atomic::Ordering::Acquire),
            THREAD_ID_ABANDONED
        );
        assert_eq!(page.xthread_free.load(core::sync::atomic::Ordering::Acquire), 0);
        assert!(page.free.is_null());
        assert!(page.local_free.is_null());
        assert_eq!(page.used(), 0);
        assert_eq!(page.block_size(), 0);
        assert_eq!(page.page_offset(), 0);
        assert_eq!(page.capacity(), 0);
        assert_eq!(page.reserved(), 0);
        assert_eq!(page.slice_pcommitted, 0);
        assert_eq!(page.retire_expire(), 0);
        assert!(!page.free_is_zero());
        assert!(page.theap().is_null());
        assert!(page.heap().is_null());
        assert!(page.next().is_null());
        assert!(page.prev.is_null());
        assert_eq!(page.memid().kind(), MemoryKind::None);
    }

    #[test]
    fn empty_page_is_static_and_has_no_allocator_owned_state() {
        let page = EMPTY_PAGE.as_ref();
        assert_eq!(page.xthread_id.load(core::sync::atomic::Ordering::Relaxed), 0);
        assert_eq!(page.xthread_free.load(core::sync::atomic::Ordering::Relaxed), 0);
        assert!(page.memid.needs_no_free());
        assert_eq!(page.memid.kind(), MemoryKind::Static);
        assert_eq!(page.block_size, 0);
        assert_eq!(page.capacity, 0);
        assert_eq!(page.reserved, 0);
    }

    #[test]
    fn relinquishing_parent_memory_ownership_preserves_subarena_observations() {
        let base = core::ptr::without_provenance_mut::<u8>(0x1_0000);
        let mut memory = MemoryId::external(base, 32 * 1024 * 1024, true, true, true);

        memory.relinquish_ownership();

        assert_eq!(memory.kind(), MemoryKind::None);
        assert!(memory.is_pinned());
        assert!(memory.initially_committed());
        assert!(memory.initially_zero());
        assert!(memory.os_memory().is_none(), "a subarena does not own the parent mapping");
    }

    #[test]
    fn page_queue_initializers_match_all_pinned_bin_sizes() {
        assert_eq!(BIN_BLOCK_SIZES.len(), crate::config::BIN_COUNT);
        assert_eq!(BIN_BLOCK_SIZES[0], 8);
        assert_eq!(BIN_BLOCK_SIZES[1], 8);
        assert_eq!(BIN_BLOCK_SIZES[8], 64);
        assert_eq!(BIN_BLOCK_SIZES[9], 80);
        assert_eq!(BIN_BLOCK_SIZES[72], 4 * 1024 * 1024);
        assert_eq!(BIN_BLOCK_SIZES[73], 524_296);
        assert_eq!(BIN_BLOCK_SIZES[74], 524_304);
        for (queue, size) in EMPTY_PAGE_QUEUES.iter().zip(BIN_BLOCK_SIZES) {
            assert!(queue.first.is_null());
            assert!(queue.last.is_null());
            assert_eq!(queue.count, 0);
            assert_eq!(queue.block_size, size);
        }
    }
}

#[path = "page_queue.rs"]
pub(crate) mod page_queue;
