// Copyright (c) 2018-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `include/mimalloc/internal.h:1245-1291`
// (`mi_block_nextx`, `mi_block_set_nextx`, `mi_block_next`, and
// `mi_block_set_next`), `src/page.c:204-242,537-559,574-644`
// (`mi_page_free_quick_collect`, the local-only portion of
// `_mi_page_free_collect`, `mi_page_free_list_extend`, and
// `mi_page_extend_free`), `src/alloc.c:35-103` (the scalar free-list pop and
// zeroing branch of `mi_page_malloc_zero`), and `src/free.c:28-50`
// (`mi_free_block_local`).
//
// This is the frozen normal-release path only: `MI_ENCODE_FREELIST == 0` and
// `MI_PADDING == 0`. This module neither detaches `xthread_free` nor performs
// queue/theap/allocation policy. Its bounded raw collection transfer supports
// both source force modes after `remote_free` has detached the current live
// producer-list snapshot. A concurrent producer may publish a later atomic
// head while the owner operates on only disjoint ordinary fields. Ordinary
// lifecycle callers use only the false-force form; the bounded later-main
// all-free exit drain uses the force append before it decides whether a
// departing owner's page can release.
// That raw operation is not by itself a general owner-exit traversal. The
// explicit detached metadata branch has no remote producer path and uses the
// false-force transfer directly. The existing borrowed core
// remains exclusive-local. Pinned v3.5.0 has no
// separate delayed-free state; its `_mi_deferred_free` user callback is outside
// this local-list core.

use core::mem::{align_of, size_of};
use core::ptr::{self, NonNull};

use crate::types::{Block, Page, PageFreeListState, PageLocalCollectState};

const MAX_EXTEND_SIZE: usize = 8 * 1024;
const MIN_EXTEND: usize = 1;
const LINK_SIZE: usize = size_of::<*mut u8>();
const LINK_ALIGN: usize = align_of::<*mut u8>();

/// An invalid state at the scalar, single-threaded free-list boundary.
///
/// These errors make source assertions and the Rust raw-memory boundary
/// explicit. They do not turn allocator misuse into a supported recovery
/// path: callers still must not double free or retain a popped block after it
/// has been returned to this list.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FreeListError {
    /// The caller did not supply a valid scalar page geometry.
    InvalidPage,
    /// The caller-owned storage does not cover the reserved block range.
    InsufficientStorage,
    /// The source extension precondition requires no deferred local frees.
    LocalFreeListNotEmpty,
    /// A pointer is outside the currently initialized block range.
    InvalidBlock,
    /// The scalar page's used count would leave its valid range.
    InvalidUsedCount,
    /// A stored next link is misaligned, outside the page, or cyclic.
    CorruptFreeList,
}

/// Scalar free-list operations borrowed from one caller-owned page area.
///
/// This object retains only the non-atomic state used by the source's local
/// free-list routines. The live constructor borrows the corresponding narrow
/// projection from `types::Page`; the raw constructor makes the same core
/// available to aligned caller-owned test buffers. It is neither `Send` nor a
/// remote-free adapter by contract; callers use it only while exclusively
/// owning the ordinary local-list fields and the source-selected block nodes
/// they actually access. A source remote-free producer may write its own
/// distinct current block and retain only its disjoint atomic projection.
pub(crate) struct LocalFreeList {
    base: NonNull<u8>,
    bytes: usize,
    block_size: usize,
    capacity: NonNull<u16>,
    reserved: u16,
    free: NonNull<*mut Block>,
    local_free: NonNull<*mut Block>,
    used: NonNull<usize>,
    free_is_zero: NonNull<bool>,
}

impl LocalFreeList {
    /// Binds scalar free-list operations to caller-owned page state.
    ///
    /// A fresh page supplies zero initialized capacity and no free-list links,
    /// matching the relevant `mi_page_t` state before `mi_page_extend_free`.
    /// A live page may instead supply its current scalar local-list state.
    ///
    /// # Safety
    ///
    /// `base..base + bytes` must name one live, writable allocation uniquely
    /// owned by this local page operation for the lifetime of the returned
    /// object. It must contain at least `reserved * block_size` bytes and no
    /// Rust reference may be retained into any block while this object writes
    /// a link there. The metadata references must refer to the same exclusive
    /// source page state, with `free_is_zero` truthful for its current free
    /// blocks. The caller must use every returned block as an allocation and
    /// return it at most once through [`Self::push_local`].
    pub(crate) unsafe fn from_raw_parts(
        base: NonNull<u8>,
        bytes: usize,
        block_size: usize,
        capacity: &mut u16,
        reserved: u16,
        free: &mut *mut Block,
        local_free: &mut *mut Block,
        used: &mut usize,
        free_is_zero: &mut bool,
    ) -> Result<Self, FreeListError> {
        if reserved == 0
            || block_size < LINK_SIZE
            || block_size % LINK_ALIGN != 0
            || base.addr().get() % LINK_ALIGN != 0
        {
            return Err(FreeListError::InvalidPage);
        }
        let required = (reserved as usize)
            .checked_mul(block_size)
            .ok_or(FreeListError::InvalidPage)?;
        if bytes < required {
            return Err(FreeListError::InsufficientStorage);
        }
        if *capacity > reserved || *used > *capacity as usize {
            return Err(FreeListError::InvalidPage);
        }

        Ok(Self {
            base,
            bytes: required,
            block_size,
            capacity: NonNull::from(capacity),
            reserved,
            free: NonNull::from(free),
            local_free: NonNull::from(local_free),
            used: NonNull::from(used),
            free_is_zero: NonNull::from(free_is_zero),
        })
    }

    /// Borrows the exact local free-list fields projected from `types::Page`.
    ///
    /// # Safety
    ///
    /// The caller must uphold the live-area, owner-field, block-partition, and
    /// local-list invariants documented by
    /// `Page::local_free_list_state_at`. In particular, no queue, page-map,
    /// lifecycle, or other owner operation may observe the projected ordinary
    /// fields while this raw view is used. A live client may concurrently
    /// access only its distinct current block and disjoint atomic producer
    /// projection.
    pub(crate) unsafe fn from_page_state(
        state: PageFreeListState,
    ) -> Result<Self, FreeListError> {
        let PageFreeListState {
            area,
            area_bytes,
            block_size,
            capacity,
            reserved,
            free,
            local_free,
            used,
            free_is_zero,
        } = state;
        // SAFETY: the caller upholds the projection's concrete backing-area
        // and exclusive metadata contracts; direct reads name only its
        // disjoint ordinary subobjects.
        if reserved == 0
            || block_size < LINK_SIZE
            || block_size % LINK_ALIGN != 0
            || area.addr().get() % LINK_ALIGN != 0
        {
            return Err(FreeListError::InvalidPage);
        }
        let required = (reserved as usize)
            .checked_mul(block_size)
            .ok_or(FreeListError::InvalidPage)?;
        if area_bytes < required {
            return Err(FreeListError::InsufficientStorage);
        }
        // SAFETY: state construction proves initialized owner-only fields.
        if unsafe { ptr::read(capacity.as_ptr()) } > reserved
            || unsafe { ptr::read(used.as_ptr()) }
                > unsafe { ptr::read(capacity.as_ptr()) } as usize
        {
            return Err(FreeListError::InvalidPage);
        }
        Ok(Self {
            base: area,
            bytes: required,
            block_size,
            capacity,
            reserved,
            free,
            local_free,
            used,
            free_is_zero,
        })
    }

    /// Projects the scalar local-list state of one live `types::Page`.
    ///
    /// # Safety
    ///
    /// The caller must own the projected ordinary fields and associated live
    /// theap while this value is used. The complete block area must stay live,
    /// but access is partitioned by source allocation state: the owner may
    /// touch only its list nodes, extension range, selected pop block, or exact
    /// local-free input; a producer may touch its own distinct current block.
    /// The page's `page_offset`, block geometry, and local list pointers must
    /// meet the concrete requirements documented by
    /// `Page::local_free_list_state_at`; no page-map, queue, lifecycle, or
    /// other owner operation may observe the projected ordinary fields while
    /// this value is used. A valid live client may retain only the disjoint
    /// remote-free producer atomics.
    #[inline]
    pub(crate) unsafe fn from_page_at(page: NonNull<Page>) -> Result<Self, FreeListError> {
        // SAFETY: the caller upholds the ordinary-field, block-partition, and
        // stable live-page contracts needed by the raw narrow projection.
        let state = unsafe { Page::local_free_list_state_at(page) };
        // SAFETY: `state` retains exactly the same caller-proven page area and
        // local metadata projection for this scalar view.
        unsafe { Self::from_page_state(state) }
    }

    #[inline]
    fn capacity_value(&self) -> u16 {
        // SAFETY: construction proves this initialized owner-only field.
        unsafe { ptr::read(self.capacity.as_ptr()) }
    }

    #[inline]
    fn free(&self) -> *mut u8 {
        // SAFETY: construction proves this initialized owner-only field.
        unsafe { ptr::read(self.free.as_ptr()) }.cast()
    }

    #[inline]
    fn set_free(&mut self, free: *mut u8) {
        // SAFETY: this owner has exclusive access to the ordinary field.
        unsafe { ptr::write(self.free.as_ptr(), free.cast()) };
    }

    #[inline]
    fn local_free(&self) -> *mut u8 {
        // SAFETY: construction proves this initialized owner-only field.
        unsafe { ptr::read(self.local_free.as_ptr()) }.cast()
    }

    #[inline]
    fn set_local_free(&mut self, local_free: *mut u8) {
        // SAFETY: this owner has exclusive access to the ordinary field.
        unsafe { ptr::write(self.local_free.as_ptr(), local_free.cast()) };
    }

    #[inline]
    fn used_value(&self) -> usize {
        // SAFETY: construction proves this initialized owner-only field.
        unsafe { ptr::read(self.used.as_ptr()) }
    }

    #[inline]
    fn free_is_zero_value(&self) -> bool {
        // SAFETY: construction proves this initialized owner-only field.
        unsafe { ptr::read(self.free_is_zero.as_ptr()) }
    }

    /// Returns the source-defined next extension count before any link write.
    ///
    /// This is the default `MI_SECURE < 2` arithmetic from
    /// `mi_page_extend_free`; on-demand commitment belongs to the OS/page
    /// lifecycle slice and cannot change this frozen profile's scalar count.
    #[inline]
    pub(crate) const fn page_extend_count(
        capacity: u16,
        reserved: u16,
        block_size: usize,
    ) -> Option<u16> {
        if reserved == 0 || capacity > reserved || block_size == 0 {
            return None;
        }
        let available = (reserved - capacity) as usize;
        if available == 0 {
            return Some(0);
        }

        let mut max_extend = if block_size >= MAX_EXTEND_SIZE {
            MIN_EXTEND
        } else {
            MAX_EXTEND_SIZE / block_size
        };
        if max_extend < MIN_EXTEND {
            max_extend = MIN_EXTEND;
        }
        let extend = if available < max_extend {
            available
        } else {
            max_extend
        };
        if extend == 0 || extend > u16::MAX as usize {
            None
        } else {
            Some(extend as u16)
        }
    }

    /// Initializes the next sequential source span and prepends it to `free`.
    ///
    /// This is `mi_page_extend_free` plus `mi_page_free_list_extend` after the
    /// page owner has made the required bytes accessible. A non-empty `free`
    /// list is an already-successful extension and returns zero as the C path
    /// does; a non-empty `local_free` list is a caller-ordering error.
    #[inline]
    pub(crate) fn extend(&mut self) -> Result<u16, FreeListError> {
        if !self.local_free().is_null() {
            return Err(FreeListError::LocalFreeListNotEmpty);
        }
        if !self.free().is_null() {
            return Ok(0);
        }

        let capacity = self.capacity_value();
        let extend = Self::page_extend_count(capacity, self.reserved, self.block_size)
            .ok_or(FreeListError::InvalidPage)?;
        if extend == 0 {
            return Ok(0);
        }

        self.extend_count(extend)
    }

    /// Initializes exactly `extend` next sequential blocks and prepends them
    /// to `free`.
    ///
    /// `mi_page_extend_free` computes the scalar count before it commits an
    /// on-demand page area. The owner uses this narrow form only after that
    /// commitment succeeds, so the list/capacity write cannot precede the
    /// corresponding source accessibility transition. A live immediate list
    /// still reports the source's no-op result; every nonzero requested count
    /// must fit the remaining reserved capacity exactly.
    #[inline]
    pub(crate) fn extend_count(&mut self, extend: u16) -> Result<u16, FreeListError> {
        if !self.local_free().is_null() {
            return Err(FreeListError::LocalFreeListNotEmpty);
        }
        if !self.free().is_null() {
            return Ok(0);
        }

        let capacity = self.capacity_value();
        if extend == 0 || capacity.checked_add(extend).is_none_or(|next| next > self.reserved) {
            return Err(FreeListError::InvalidPage);
        }

        let first_index = capacity as usize;
        let last_index = first_index
            .checked_add(extend as usize - 1)
            .ok_or(FreeListError::InvalidPage)?;
        let first = self.block_at(first_index)?;
        let last = self.block_at(last_index)?;

        let mut index = first_index;
        while index < last_index {
            let block = self.block_at(index)?;
            let next = self.block_at(index + 1)?;
            // SAFETY: `block` and `next` are distinct aligned block starts
            // within the uniquely owned backing allocation. This writes the
            // default-profile direct pointer link without an integer roundtrip.
            unsafe { Self::write_next(block, next.as_ptr()) };
            index += 1;
        }
        // SAFETY: `last` is the final initialized block. `free` is null by
        // the checked extension precondition, exactly as the scalar source
        // path's final `mi_block_set_next` write.
        unsafe { Self::write_next(last, self.free()) };
        self.set_free(first.as_ptr());
        let next_capacity = capacity
            .checked_add(extend)
            .ok_or(FreeListError::InvalidPage)?;
        // SAFETY: this owner has exclusive access to the ordinary field.
        unsafe { ptr::write(self.capacity.as_ptr(), next_capacity) };
        Ok(extend)
    }

    /// Pops one available block as `mi_page_malloc_zero` does on its fast path.
    ///
    /// `zero` selects the source's full-block zeroing branch. The returned raw
    /// pointer remains valid only while this page backing area remains live;
    /// its allocation, aliasing, and eventual exactly-once local-free duties
    /// remain the caller's responsibility.
    #[inline]
    pub(crate) fn pop(&mut self, zero: bool) -> Result<Option<NonNull<u8>>, FreeListError> {
        let Some(block) = NonNull::new(self.free()) else {
            return Ok(None);
        };
        let used = self.used_value();
        if used >= self.capacity_value() as usize {
            return Err(FreeListError::InvalidUsedCount);
        }
        let next = self.checked_next(block)?;

        // SAFETY: `block` was checked as the current owner-list head and this
        // operation owns its link word. Clearing that link is the source's
        // `block->next = 0` non-leak transition before client use.
        unsafe { Self::write_next(block, ptr::null_mut()) };
        self.set_free(next);
        // SAFETY: this owner has exclusive access to the ordinary field.
        unsafe { ptr::write(self.used.as_ptr(), used + 1) };

        if zero && !self.free_is_zero_value() {
            // SAFETY: `block` names exactly `block_size` writable bytes in the
            // caller-owned page. No typed reference is created while the raw
            // allocation is being returned to the caller.
            unsafe { ptr::write_bytes(block.as_ptr(), 0, self.block_size) };
        }
        Ok(Some(block))
    }

    /// Pushes one currently allocated block onto the source `local_free` list.
    ///
    /// This local-only operation intentionally performs no remote-free atomic
    /// protocol, padding validation, page-queue transition, retirement, or the
    /// unrelated `_mi_deferred_free` user callback.
    ///
    /// # Safety
    ///
    /// The caller must exclusively own the projected ordinary local-list
    /// fields and this exact current `block`; other clients may own distinct
    /// current blocks. `block` must be aligned in the live backing allocation.
    /// On an `Ok` result it must be one block previously returned by
    /// [`Self::pop`] that has not already been freed; violating that
    /// exactly-once rule can create a cyclic list that the source fast path
    /// does not detect. A pointer outside the initialized range, or a free
    /// attempted after the checked `used == 0` state, instead returns an error
    /// without writing a link.
    #[inline]
    pub(crate) unsafe fn push_local(
        &mut self,
        block: NonNull<u8>,
    ) -> Result<(), FreeListError> {
        self.validate_initialized_block(block)?;
        let used = self.used_value();
        if used == 0 {
            return Err(FreeListError::InvalidUsedCount);
        }
        if let Some(head) = NonNull::new(self.local_free()) {
            self.validate_initialized_block(head)?;
        }

        // SAFETY: `block` is a validated initialized block that the caller
        // owns uniquely as an allocation; `local_free` is null or a validated
        // link target in the same backing allocation.
        unsafe { Self::write_next(block, self.local_free()) };
        // SAFETY: this owner has exclusive access to the ordinary field.
        unsafe { ptr::write(self.used.as_ptr(), used - 1) };
        self.set_local_free(block.as_ptr());
        Ok(())
    }

    /// Validates non-mutating local-free preflight geometry and the lower
    /// source `used` bound.
    ///
    /// This is intentionally narrower than [`Self::push_local`]: it checks
    /// only initialized geometry and the source `used > 0` lower bound, then
    /// leaves the block link and every page field untouched. The caller still
    /// supplies the same exactly-once live-allocation proof as `push_local`;
    /// the normal-release representation cannot detect a duplicate raw
    /// pointer without mutating the local list.
    #[inline]
    pub(crate) fn validate_local_free_preflight(
        &self,
        block: NonNull<u8>,
    ) -> Result<(), FreeListError> {
        self.validate_initialized_block(block)?;
        if self.used_value() == 0 {
            return Err(FreeListError::InvalidUsedCount);
        }
        Ok(())
    }

    /// Moves `local_free` to `free` only when the immediate list is exhausted.
    ///
    /// This is `mi_page_free_quick_collect`. It deliberately leaves a
    /// non-empty immediate list untouched, preserving the source's monotonic
    /// local-free behavior.
    #[inline]
    pub(crate) fn quick_collect(&mut self) -> Result<bool, FreeListError> {
        if !self.free().is_null() {
            return Ok(true);
        }
        let Some(local_free) = NonNull::new(self.local_free()) else {
            return Ok(false);
        };
        self.validate_initialized_block(local_free)?;
        self.set_free(local_free.as_ptr());
        self.set_local_free(ptr::null_mut());
        // SAFETY: this owner has exclusive access to the ordinary field.
        unsafe { ptr::write(self.free_is_zero.as_ptr(), false) };
        Ok(true)
    }

    /// Collects deferred local frees into the immediate list.
    ///
    /// This is the local-list part of `_mi_page_free_collect`; `force == true`
    /// performs the source's linear append when `free` is already non-empty.
    /// Remote `thread_free` collection is intentionally absent.
    #[inline]
    pub(crate) fn collect_local(&mut self, force: bool) -> Result<bool, FreeListError> {
        let Some(local_free) = NonNull::new(self.local_free()) else {
            return Ok(false);
        };
        self.validate_initialized_block(local_free)?;
        if self.free().is_null() {
            self.set_free(local_free.as_ptr());
            self.set_local_free(ptr::null_mut());
            // SAFETY: this owner has exclusive access to the ordinary field.
            unsafe { ptr::write(self.free_is_zero.as_ptr(), false) };
            return Ok(true);
        }
        if !force {
            return Ok(false);
        }

        let tail = self.list_tail(local_free)?;
        let free = NonNull::new(self.free()).ok_or(FreeListError::CorruptFreeList)?;
        self.validate_initialized_block(free)?;
        // SAFETY: `tail` is the terminal node of the validated local list and
        // `free` is the validated immediate head. The source force path links
        // precisely these two owned list fragments.
        unsafe { Self::write_next(tail, free.as_ptr()) };
        self.set_free(local_free.as_ptr());
        self.set_local_free(ptr::null_mut());
        // SAFETY: this owner has exclusive access to the ordinary field.
        unsafe { ptr::write(self.free_is_zero.as_ptr(), false) };
        Ok(true)
    }

    #[inline]
    pub(crate) fn capacity(&self) -> u16 {
        self.capacity_value()
    }

    #[inline]
    pub(crate) const fn reserved(&self) -> u16 {
        self.reserved
    }

    #[inline]
    pub(crate) fn used(&self) -> usize {
        self.used_value()
    }

    #[inline]
    pub(crate) fn free_is_zero(&self) -> bool {
        self.free_is_zero_value()
    }

    #[inline]
    fn block_at(&self, index: usize) -> Result<NonNull<u8>, FreeListError> {
        if index >= self.reserved as usize {
            return Err(FreeListError::InvalidBlock);
        }
        let offset = index
            .checked_mul(self.block_size)
            .ok_or(FreeListError::InvalidBlock)?;
        if offset >= self.bytes {
            return Err(FreeListError::InvalidBlock);
        }
        // SAFETY: `index < reserved` and `bytes` was checked against the full
        // reserved span in `from_raw_parts`, so this derives an in-allocation block start
        // from the original provenance-bearing page pointer.
        Ok(unsafe { NonNull::new_unchecked(self.base.as_ptr().add(offset)) })
    }

    #[inline]
    fn validate_initialized_block(&self, block: NonNull<u8>) -> Result<(), FreeListError> {
        let start = self.base.addr().get();
        let end = start
            .checked_add(self.bytes)
            .ok_or(FreeListError::InvalidPage)?;
        let address = block.addr().get();
        if address < start || address >= end {
            return Err(FreeListError::InvalidBlock);
        }
        let offset = address - start;
        if offset % self.block_size != 0
            || offset / self.block_size >= self.capacity_value() as usize
        {
            return Err(FreeListError::InvalidBlock);
        }
        Ok(())
    }

    #[inline]
    fn checked_next(&self, block: NonNull<u8>) -> Result<*mut u8, FreeListError> {
        self.validate_initialized_block(block)?;
        // SAFETY: `block` is an initialized free-list node. Every link is
        // written by `write_next` before it is read, and no typed reference is
        // formed over caller-owned allocation memory.
        let next = unsafe { Self::read_next(block) };
        if let Some(next) = NonNull::new(next) {
            self.validate_initialized_block(next)
                .map_err(|_| FreeListError::CorruptFreeList)?;
        }
        Ok(next)
    }

    #[inline]
    fn list_tail(&self, mut block: NonNull<u8>) -> Result<NonNull<u8>, FreeListError> {
        let mut count = 0usize;
        loop {
            if count >= self.capacity_value() as usize {
                return Err(FreeListError::CorruptFreeList);
            }
            count += 1;
            let next = self.checked_next(block)?;
            let Some(next) = NonNull::new(next) else {
                return Ok(block);
            };
            block = next;
        }
    }

    #[inline]
    unsafe fn read_next(block: NonNull<u8>) -> *mut u8 {
        // SAFETY: the caller proves `block` points at one initialized link
        // word in a live, aligned, caller-owned block allocation.
        unsafe { ptr::read(block.as_ptr().cast::<*mut u8>()) }
    }

    #[inline]
    unsafe fn write_next(block: NonNull<u8>, next: *mut u8) {
        // SAFETY: the caller proves `block` points at one writable, aligned
        // link word in a live, uniquely owned page block. Direct pointer
        // storage is the exact `MI_ENCODE_FREELIST == 0` representation.
        unsafe { ptr::write(block.as_ptr().cast::<*mut u8>(), next) };
    }
}

/// Performs the raw local half of `_mi_page_free_collect`.
///
/// Pinned `page.c:214-243` first detaches a remote list, then moves
/// `local_free` to `free` when `free` is null. When `force` is true and both
/// lists are non-empty, it validates the source local list, appends the old
/// immediate head to its tail, and installs that local head as `free`. This
/// raw state is distinct from [`LocalFreeList`]: it avoids a whole-page
/// mutable borrow. The enclosing lifecycle's queue transitions likewise use
/// raw disjoint link fields, so a valid client may retain or use only its
/// atomic producer projection throughout. The detached metadata branch instead
/// has an explicit no-remote-producer contract.
///
/// # Safety
///
/// The caller must have completed the remote detach first and exclusively own
/// the projected ordinary fields. `state` must come from one live associated
/// page whose area remains writable for this operation. It must preserve that
/// page's no-retirement/no-release lifetime while the raw collection runs.
pub(crate) unsafe fn collect_local(
    state: PageLocalCollectState,
    force: bool,
) -> Result<bool, FreeListError> {
    validate_raw_collect_state(&state)?;
    // SAFETY: caller supplies exclusive ordinary-field ownership. The raw
    // state construction established these exact initialized field pointers.
    let local_free = unsafe { *state.local_free.as_ptr() };
    let Some(local_free) = NonNull::new(local_free) else {
        return Ok(false);
    };
    validate_raw_initialized_block(&state, local_free)?;
    // SAFETY: see the `local_free` read above; source collection observes
    // `free` only to decide whether it transfers or appends the local head.
    let free = unsafe { *state.free.as_ptr() };
    let Some(free) = NonNull::new(free) else {
        // SAFETY: the local head is a validated initialized block and caller
        // exclusivity covers these three ordinary fields. This is the source
        // transfer common to both force modes; it neither appends nor creates
        // a delayed/deferred list state.
        unsafe {
            *state.free.as_ptr() = local_free.as_ptr();
            *state.local_free.as_ptr() = ptr::null_mut();
            *state.free_is_zero.as_ptr() = false;
        }
        return Ok(true);
    };
    if !force {
        return Ok(false);
    }
    validate_raw_initialized_block(&state, free)?;
    let tail = raw_list_tail(&state, local_free)?;
    // SAFETY: the local head is a validated initialized block, `free` is
    // validated, and `tail` is the terminal node of the validated local list.
    // Caller exclusivity covers these ordinary fields. This is exactly the
    // source force append before the local head replaces `free`.
    unsafe {
        ptr::write(tail.as_ptr().cast::<*mut u8>(), free.as_ptr().cast());
        *state.free.as_ptr() = local_free.as_ptr();
        *state.local_free.as_ptr() = ptr::null_mut();
        *state.free_is_zero.as_ptr() = false;
    }
    Ok(true)
}

/// Performs the false-force local half of `_mi_page_free_collect`.
///
/// Existing regular/full collection callers deliberately retain this wrapper:
/// their source branches never request the linear local-list append reserved
/// for forced owner-exit collection.
#[inline]
pub(crate) unsafe fn collect_local_false(
    state: PageLocalCollectState,
) -> Result<bool, FreeListError> {
    // SAFETY: this wrapper preserves the caller's raw collection obligations
    // while selecting the source `force == false` branch.
    unsafe { collect_local(state, false) }
}

fn validate_raw_collect_state(state: &PageLocalCollectState) -> Result<(), FreeListError> {
    if state.reserved == 0
        || state.block_size < LINK_SIZE
        || state.block_size % LINK_ALIGN != 0
        || state.area.addr().get() % LINK_ALIGN != 0
        || state.capacity > state.reserved
    {
        return Err(FreeListError::InvalidPage);
    }
    // SAFETY: the caller's ordinary-field proof covers this raw field read;
    // only the source owner updates `used`.
    if unsafe { *state.used.as_ptr() } > state.capacity as usize {
        return Err(FreeListError::InvalidPage);
    }
    let required = usize::from(state.reserved)
        .checked_mul(state.block_size)
        .ok_or(FreeListError::InvalidPage)?;
    if state.area_bytes < required {
        return Err(FreeListError::InsufficientStorage);
    }
    Ok(())
}

fn validate_raw_initialized_block(
    state: &PageLocalCollectState,
    block: NonNull<Block>,
) -> Result<(), FreeListError> {
    let initialized_bytes = usize::from(state.capacity)
        .checked_mul(state.block_size)
        .ok_or(FreeListError::InvalidBlock)?;
    let base = state.area.addr().get();
    let end = base
        .checked_add(initialized_bytes)
        .ok_or(FreeListError::InvalidBlock)?;
    let address = block.as_ptr().addr();
    if address < base
        || address >= end
        || (address - base) % state.block_size != 0
        || address % LINK_ALIGN != 0
    {
        return Err(FreeListError::InvalidBlock);
    }
    Ok(())
}

/// Returns the terminal node of one validated raw local-free list.
///
/// A valid source local list contains at most `capacity` initialized blocks.
/// Bounding the walk preserves that invariant at the Rust raw-memory boundary
/// and prevents a malformed cyclic list from being linked into `free`.
fn raw_list_tail(
    state: &PageLocalCollectState,
    mut block: NonNull<Block>,
) -> Result<NonNull<Block>, FreeListError> {
    let mut count = 0usize;
    loop {
        if count >= state.capacity as usize {
            return Err(FreeListError::CorruptFreeList);
        }
        count += 1;
        validate_raw_initialized_block(state, block)?;
        // SAFETY: `block` has just been validated as an initialized list node
        // in the caller-proved writable page area. The source normal profile
        // stores its unencoded next pointer in this first word.
        let next = unsafe { ptr::read(block.as_ptr().cast::<*mut u8>()) };
        let Some(next) = NonNull::new(next.cast::<Block>()) else {
            return Ok(block);
        };
        validate_raw_initialized_block(state, next)
            .map_err(|_| FreeListError::CorruptFreeList)?;
        block = next;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(align(16))]
    struct Page<const N: usize>([u8; N]);

    struct TestPageState {
        capacity: u16,
        free: *mut Block,
        local_free: *mut Block,
        used: usize,
        free_is_zero: bool,
    }

    impl TestPageState {
        const fn fresh(free_is_zero: bool) -> Self {
            Self {
                capacity: 0,
                free: ptr::null_mut(),
                local_free: ptr::null_mut(),
                used: 0,
                free_is_zero,
            }
        }
    }

    fn list_for<const N: usize>(
        state: &mut TestPageState,
        storage: &mut Page<N>,
        block_size: usize,
        reserved: u16,
    ) -> LocalFreeList {
        let base = NonNull::new(storage.0.as_mut_ptr()).unwrap();
        // SAFETY: `storage` remains alive and uniquely borrowed for the test,
        // its explicit alignment satisfies every tested block boundary, and
        // the requested range lies within the fixed array. `state` is the
        // exclusive local page metadata for that same backing allocation.
        let state = PageFreeListState {
            area: base,
            area_bytes: N,
            block_size,
            capacity: NonNull::from(&mut state.capacity),
            reserved,
            free: NonNull::from(&mut state.free),
            local_free: NonNull::from(&mut state.local_free),
            used: NonNull::from(&mut state.used),
            free_is_zero: NonNull::from(&mut state.free_is_zero),
        };
        // SAFETY: the test state and backing buffer meet the mirrored live
        // `PageFreeListState` contract above.
        unsafe { LocalFreeList::from_page_state(state) }
            .expect("valid aligned caller-owned test page")
    }

    fn raw_collect_state<const N: usize>(
        state: &mut TestPageState,
        storage: &mut Page<N>,
        block_size: usize,
        reserved: u16,
    ) -> PageLocalCollectState {
        PageLocalCollectState {
            area: NonNull::new(storage.0.as_mut_ptr()).expect("test storage is non-null"),
            area_bytes: N,
            block_size,
            capacity: state.capacity,
            reserved,
            free: NonNull::from(&mut state.free),
            local_free: NonNull::from(&mut state.local_free),
            used: NonNull::from(&mut state.used),
            free_is_zero: NonNull::from(&mut state.free_is_zero),
        }
    }

    #[test]
    fn a_fresh_scalar_page_accepts_an_aligned_caller_owned_buffer() {
        let mut storage = Page([0; 64]);
        let mut state = TestPageState::fresh(true);
        let list = list_for(&mut state, &mut storage, 16, 4);
        assert_eq!(list.capacity(), 0);
        assert_eq!(list.reserved(), 4);
        assert_eq!(list.used(), 0);
        assert!(list.free_is_zero());
    }

    #[test]
    fn construction_makes_geometry_and_storage_preconditions_explicit() {
        let mut storage = Page::<64>([0; 64]);
        let base = NonNull::new(storage.0.as_mut_ptr()).unwrap();
        let mut state = TestPageState::fresh(true);
        // SAFETY: all calls still point inside the one live local buffer; each
        // case intentionally violates a checked scalar precondition.
        unsafe {
            assert!(matches!(
                LocalFreeList::from_raw_parts(
                    base,
                    64,
                    16,
                    &mut state.capacity,
                    0,
                    &mut state.free,
                    &mut state.local_free,
                    &mut state.used,
                    &mut state.free_is_zero,
                ),
                Err(FreeListError::InvalidPage)
            ));
            assert!(matches!(
                LocalFreeList::from_raw_parts(
                    base,
                    64,
                    LINK_SIZE - 1,
                    &mut state.capacity,
                    4,
                    &mut state.free,
                    &mut state.local_free,
                    &mut state.used,
                    &mut state.free_is_zero,
                ),
                Err(FreeListError::InvalidPage)
            ));
            assert!(matches!(
                LocalFreeList::from_raw_parts(
                    base,
                    63,
                    16,
                    &mut state.capacity,
                    4,
                    &mut state.free,
                    &mut state.local_free,
                    &mut state.used,
                    &mut state.free_is_zero,
                ),
                Err(FreeListError::InsufficientStorage)
            ));
            let unaligned = NonNull::new(base.as_ptr().add(1)).unwrap();
            assert!(matches!(
                LocalFreeList::from_raw_parts(
                    unaligned,
                    63,
                    16,
                    &mut state.capacity,
                    3,
                    &mut state.free,
                    &mut state.local_free,
                    &mut state.used,
                    &mut state.free_is_zero,
                ),
                Err(FreeListError::InvalidPage)
            ));
        }
    }

    #[test]
    fn page_extend_count_covers_each_default_scalar_boundary() {
        assert_eq!(LocalFreeList::page_extend_count(0, 0, 8), None);
        assert_eq!(LocalFreeList::page_extend_count(9, 8, 8), None);
        assert_eq!(LocalFreeList::page_extend_count(0, 8, 0), None);
        assert_eq!(LocalFreeList::page_extend_count(8, 8, 8), Some(0));

        assert_eq!(LocalFreeList::page_extend_count(0, 1023, 8), Some(1023));
        assert_eq!(LocalFreeList::page_extend_count(0, 1024, 8), Some(1024));
        assert_eq!(LocalFreeList::page_extend_count(0, 1025, 8), Some(1024));
        assert_eq!(LocalFreeList::page_extend_count(0, 3, 4096), Some(2));
        assert_eq!(LocalFreeList::page_extend_count(0, 3, 4097), Some(1));
        assert_eq!(LocalFreeList::page_extend_count(0, 2, 8191), Some(1));
        assert_eq!(LocalFreeList::page_extend_count(0, 2, 8192), Some(1));
        assert_eq!(LocalFreeList::page_extend_count(0, 2, 8193), Some(1));
    }

    #[test]
    fn extension_threads_blocks_in_source_order_then_exhausts() {
        let mut storage = Page([0; 128]);
        let mut state = TestPageState::fresh(true);
        let mut list = list_for(&mut state, &mut storage, 16, 8);
        assert_eq!(list.extend(), Ok(8));
        assert_eq!(list.capacity(), 8);
        assert_eq!(list.extend(), Ok(0), "a live immediate list prevents extension");

        for index in 0..8 {
            let block = list.pop(false).unwrap().expect("one sequential free block");
            let expected = unsafe { storage.0.as_mut_ptr().add(index * 16) };
            assert_eq!(block.as_ptr(), expected);
        }
        assert_eq!(list.pop(false), Ok(None));
        assert_eq!(list.used(), 8);
        assert_eq!(list.extend(), Ok(0), "capacity equals reservation after exhaustion");
        drop(list);

        // The borrowed projection updates the page-owned metadata in place;
        // there is no parallel free-list state after this view is dropped.
        assert_eq!(state.capacity, 8);
        assert!(state.free.is_null());
        assert!(state.local_free.is_null());
        assert_eq!(state.used, 8);
        assert!(state.free_is_zero);
    }

    #[test]
    fn extension_stops_at_eight_kib_then_resumes_in_sequential_order() {
        let mut storage = Page([0; 8216]);
        let mut state = TestPageState::fresh(true);
        let mut list = list_for(&mut state, &mut storage, 8, 1027);
        assert_eq!(list.extend(), Ok(1024));
        for _ in 0..1024 {
            list.pop(false).unwrap().expect("first source extension block");
        }
        assert_eq!(list.pop(false), Ok(None));
        assert_eq!(list.extend(), Ok(3));
        for index in 1024..1027 {
            let block = list.pop(false).unwrap().expect("second source extension block");
            let expected = unsafe { storage.0.as_mut_ptr().add(index * 8) };
            assert_eq!(block.as_ptr(), expected);
        }
    }

    #[test]
    fn local_frees_stay_deferred_until_the_matching_collection_transition() {
        let mut storage = Page([0; 64]);
        let mut state = TestPageState::fresh(true);
        let mut list = list_for(&mut state, &mut storage, 16, 4);
        assert_eq!(list.extend(), Ok(4));
        let first = list.pop(false).unwrap().unwrap();
        let second = list.pop(false).unwrap().unwrap();
        assert_eq!(list.used(), 2);
        let third = NonNull::new(unsafe { storage.0.as_mut_ptr().add(32) }).unwrap();

        // SAFETY: both blocks were popped once from this exclusively owned
        // local list and have not yet been returned.
        unsafe {
            list.push_local(first).unwrap();
            list.push_local(second).unwrap();
        }
        assert_eq!(list.used(), 0);
        assert!(list.quick_collect().unwrap(), "the third block remains immediately free");
        assert!(!list.collect_local(false).unwrap());
        assert!(list.collect_local(true).unwrap());
        assert!(!list.free_is_zero());

        assert_eq!(list.pop(false).unwrap(), Some(second));
        assert_eq!(list.pop(false).unwrap(), Some(first));
        assert_eq!(list.pop(false).unwrap(), Some(third));
    }

    #[test]
    fn raw_force_collection_appends_local_frees_before_the_existing_immediate_head() {
        let mut storage = Page([0; 64]);
        let mut state = TestPageState::fresh(true);
        let (first, second) = {
            let mut list = list_for(&mut state, &mut storage, 16, 4);
            assert_eq!(list.extend(), Ok(4));
            let first = list.pop(false).unwrap().unwrap();
            let second = list.pop(false).unwrap().unwrap();
            // SAFETY: both blocks were popped once from this exclusive list
            // and the remaining immediate list begins at the third block.
            unsafe {
                list.push_local(first).unwrap();
                list.push_local(second).unwrap();
            }
            (first, second)
        };
        let third = NonNull::new(unsafe { storage.0.as_mut_ptr().add(32) }).unwrap();
        let fourth = NonNull::new(unsafe { storage.0.as_mut_ptr().add(48) }).unwrap();
        let raw = raw_collect_state(&mut state, &mut storage, 16, 4);

        // Source `_mi_page_free_collect(page, true)` appends the local list
        // only during forced owner collection: its LIFO local head remains
        // first, and the pre-existing immediate list follows its local tail.
        assert_eq!(unsafe { collect_local(raw, true) }, Ok(true));
        assert!(state.local_free.is_null());
        assert!(!state.free_is_zero);

        let mut list = list_for(&mut state, &mut storage, 16, 4);
        assert_eq!(list.pop(false).unwrap(), Some(second));
        assert_eq!(list.pop(false).unwrap(), Some(first));
        assert_eq!(list.pop(false).unwrap(), Some(third));
        assert_eq!(list.pop(false).unwrap(), Some(fourth));
        assert_eq!(list.pop(false).unwrap(), None);
    }

    #[test]
    fn raw_false_collection_preserves_both_lists_when_immediate_blocks_exist() {
        let mut storage = Page([0; 64]);
        let mut state = TestPageState::fresh(true);
        {
            let mut list = list_for(&mut state, &mut storage, 16, 4);
            assert_eq!(list.extend(), Ok(4));
            let first = list.pop(false).unwrap().unwrap();
            let second = list.pop(false).unwrap().unwrap();
            // SAFETY: both blocks were popped once and become the deferred
            // local list while two immediate source blocks remain available.
            unsafe {
                list.push_local(first).unwrap();
                list.push_local(second).unwrap();
            }
        }
        let free_before = state.free;
        let local_before = state.local_free;
        let raw = raw_collect_state(&mut state, &mut storage, 16, 4);

        assert_eq!(unsafe { collect_local(raw, false) }, Ok(false));
        assert_eq!(state.free, free_before);
        assert_eq!(state.local_free, local_before);
        assert!(state.free_is_zero);
    }

    #[test]
    fn raw_force_collection_rejects_a_cyclic_local_list_before_linking_it_to_free() {
        let mut storage = Page([0; 64]);
        let mut state = TestPageState::fresh(true);
        let (first, second) = {
            let mut list = list_for(&mut state, &mut storage, 16, 4);
            assert_eq!(list.extend(), Ok(4));
            let first = list.pop(false).unwrap().unwrap();
            let second = list.pop(false).unwrap().unwrap();
            // SAFETY: both blocks were popped once before this fixture makes
            // the intentionally invalid cycle below.
            unsafe {
                list.push_local(first).unwrap();
                list.push_local(second).unwrap();
            }
            (first, second)
        };
        // SAFETY: this intentionally breaks the source local-list invariant
        // inside the still-live test storage: second -> first -> second.
        unsafe { ptr::write(first.as_ptr().cast::<*mut u8>(), second.as_ptr()) };
        let free_before = state.free;
        let local_before = state.local_free;
        let raw = raw_collect_state(&mut state, &mut storage, 16, 4);

        assert_eq!(
            unsafe { collect_local(raw, true) },
            Err(FreeListError::CorruptFreeList)
        );
        assert_eq!(state.free, free_before);
        assert_eq!(state.local_free, local_before);
    }

    #[test]
    fn exhausted_immediate_list_quick_collects_local_reuse() {
        let mut storage = Page([0; 32]);
        let mut state = TestPageState::fresh(true);
        let mut list = list_for(&mut state, &mut storage, 16, 2);
        list.extend().unwrap();
        let first = list.pop(false).unwrap().unwrap();
        let second = list.pop(false).unwrap().unwrap();
        assert_eq!(list.pop(false), Ok(None));

        // SAFETY: `first` was popped once from this exclusive page.
        unsafe { list.push_local(first).unwrap() };
        assert!(list.quick_collect().unwrap());
        assert_eq!(list.pop(false).unwrap(), Some(first));
        // SAFETY: `second` was popped once from this exclusive page.
        unsafe { list.push_local(second).unwrap() };
        assert!(list.collect_local(false).unwrap());
        assert_eq!(list.pop(false).unwrap(), Some(second));
    }

    #[test]
    fn zeroing_observes_initial_zero_and_clears_reused_local_blocks() {
        let mut storage = Page([0; 32]);
        let mut state = TestPageState::fresh(true);
        let mut list = list_for(&mut state, &mut storage, 16, 2);
        list.extend().unwrap();
        let first = list.pop(true).unwrap().unwrap();
        // SAFETY: `first` was just popped and is uniquely allocated to this
        // test; its full block belongs to the caller-owned page buffer.
        unsafe {
            for index in 0..16 {
                assert_eq!(*first.as_ptr().add(index), 0);
            }
        }

        let second = list.pop(false).unwrap().unwrap();
        // SAFETY: `second` is uniquely allocated and may receive test data
        // before it is returned through the local-free transition.
        unsafe { ptr::write_bytes(second.as_ptr(), 0xa5, 16) };
        // SAFETY: `second` was popped once from this exclusive page and is no
        // longer observed through the temporary raw writes above.
        unsafe { list.push_local(second).unwrap() };
        assert!(list.quick_collect().unwrap());
        let zeroed = list.pop(true).unwrap().unwrap();
        assert_eq!(zeroed, second);
        // SAFETY: `zeroed` was just returned uniquely by the zeroing pop.
        unsafe {
            for index in 0..16 {
                assert_eq!(*zeroed.as_ptr().add(index), 0);
            }
        }
    }

    #[test]
    fn checked_state_rejects_uninitialized_and_underflowing_local_frees() {
        let mut storage = Page([0; 64]);
        let mut state = TestPageState::fresh(true);
        let mut list = list_for(&mut state, &mut storage, 16, 4);
        let base = NonNull::new(storage.0.as_mut_ptr()).unwrap();
        // SAFETY: `base` is inside the live backing allocation. The checked
        // uninitialized-capacity state rejects it before any link write.
        assert_eq!(unsafe { list.push_local(base) }, Err(FreeListError::InvalidBlock));
        list.extend().unwrap();
        let block = list.pop(false).unwrap().unwrap();
        // SAFETY: `block` was popped once from this exclusive page.
        unsafe { list.push_local(block).unwrap() };
        // SAFETY: the pointer remains inside the live page. This deliberately
        // exercises the checked `used == 0` rejection before it can relink.
        assert_eq!(
            unsafe { list.push_local(block) },
            Err(FreeListError::InvalidUsedCount)
        );
    }
}
