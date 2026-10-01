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
// The default path uses direct links; selected encoded profiles use the source page
// key pair to encode them. This module neither detaches `xthread_free` nor performs
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

const LINK_SIZE: usize = size_of::<*mut u8>();
const LINK_ALIGN: usize = align_of::<*mut u8>();

#[cfg(any(feature = "mi-debug-1", all(target_arch = "x86_64", feature = "mi-secure-3")))]
#[inline]
pub(super) fn encode_page_link(page_address: usize, keys: [usize; 2], next_address: usize) -> usize {
    let address = if next_address == 0 { page_address } else { next_address };
    (address ^ keys[1]).rotate_left(keys[0] as u32).wrapping_add(keys[0])
}

#[cfg(any(feature = "mi-debug-1", all(target_arch = "x86_64", feature = "mi-secure-3")))]
#[inline]
pub(super) fn decode_page_link(page_address: usize, keys: [usize; 2], encoded: usize) -> usize {
    let address = encoded.wrapping_sub(keys[0]).rotate_right(keys[0] as u32) ^ keys[1];
    if address == page_address { 0 } else { address }
}

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
    /// The owning thread supplied no initialized, nonzero source random word.
    RandomSourceUnavailable,
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
    #[cfg(any(feature = "mi-debug-1", all(target_arch = "x86_64", feature = "mi-secure-3")))]
    page_address: usize,
    #[cfg(any(feature = "mi-debug-1", all(target_arch = "x86_64", feature = "mi-secure-3")))]
    page_key: usize,
    #[cfg(any(feature = "mi-debug-1", all(target_arch = "x86_64", feature = "mi-secure-3")))]
    page_key2: usize,
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
            #[cfg(any(feature = "mi-debug-1", all(target_arch = "x86_64", feature = "mi-secure-3")))]
            page_address: base.as_ptr().addr(),
            #[cfg(any(feature = "mi-debug-1", all(target_arch = "x86_64", feature = "mi-secure-3")))]
            page_key: 0,
            #[cfg(any(feature = "mi-debug-1", all(target_arch = "x86_64", feature = "mi-secure-3")))]
            page_key2: 0,
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
    #[inline(always)]
    pub(crate) unsafe fn from_page_state(
        state: PageFreeListState,
    ) -> Result<Self, FreeListError> {
        let PageFreeListState {
            area,
            area_bytes,
            block_size,
            #[cfg(any(feature = "mi-debug-1", all(target_arch = "x86_64", feature = "mi-secure-3")))]
            page_address,
            #[cfg(any(feature = "mi-debug-1", all(target_arch = "x86_64", feature = "mi-secure-3")))]
            page_key,
            #[cfg(any(feature = "mi-debug-1", all(target_arch = "x86_64", feature = "mi-secure-3")))]
            page_key2,
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
            #[cfg(any(feature = "mi-debug-1", all(target_arch = "x86_64", feature = "mi-secure-3")))]
            page_address,
            #[cfg(any(feature = "mi-debug-1", all(target_arch = "x86_64", feature = "mi-secure-3")))]
            page_key,
            #[cfg(any(feature = "mi-debug-1", all(target_arch = "x86_64", feature = "mi-secure-3")))]
            page_key2,
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
    #[inline(always)]
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
    /// This uses the selected `mi_page_extend_free` minimum; on-demand
    /// commitment belongs to the OS/page lifecycle and is already complete
    /// for this local-list entrypoint.
    #[inline]
    pub(crate) const fn page_extend_count(
        capacity: u16,
        reserved: u16,
        block_size: usize,
    ) -> Option<u16> {
        crate::page::page_extend_count(capacity, reserved, block_size, 0)
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
            // selected profile's source free-list link.
            unsafe { self.write_next(block, next.as_ptr()) };
            index += 1;
        }
        // SAFETY: `last` is the final initialized block. `free` is null by
        // the checked extension precondition, exactly as the scalar source
        // path's final `mi_block_set_next` write.
        unsafe { self.write_next(last, self.free()) };
        self.set_free(first.as_ptr());
        let next_capacity = capacity
            .checked_add(extend)
            .ok_or(FreeListError::InvalidPage)?;
        // SAFETY: this owner has exclusive access to the ordinary field.
        unsafe { ptr::write(self.capacity.as_ptr(), next_capacity) };
        Ok(extend)
    }

    /// Initializes the source secure slice permutation after backing commitment.
    /// The random projection must not allocate or mutate this page. Existing
    /// immediate and deferred heads remain owned; only the new suffix is linked.
    #[cfg(target_arch = "x86_64")]
    pub(crate) fn extend_count_randomized(
        &mut self,
        extend: u16,
        random_word: impl FnOnce() -> Option<usize>,
    ) -> Result<u16, FreeListError> {
        let capacity = self.capacity_value();
        let next_capacity = capacity.checked_add(extend)
            .filter(|next| extend != 0 && *next <= self.reserved)
            .ok_or(FreeListError::InvalidPage)?;
        // Validate the entire writable suffix before consuming thread randomness
        // or changing a link. Construction guarantees uniform block geometry.
        let first = self.block_at(capacity as usize)?;
        let last = self.block_at(next_capacity as usize - 1)?;
        if extend == 1 {
            // SAFETY: this is the sole new block in the accessible owner suffix.
            unsafe { self.write_next(last, self.free()) };
            self.set_free(first.as_ptr());
        } else {
            let random = random_word().filter(|word| *word != 0)
                .ok_or(FreeListError::RandomSourceUnavailable)?;
            let mut slice_count = 1usize;
            while slice_count < 64 && slice_count * 2 <= extend as usize {
                slice_count *= 2;
            }
            let slice_extend = extend as usize / slice_count;
            let mut blocks = [0usize; 64];
            let mut counts = [0usize; 64];
            for index in 0..slice_count {
                blocks[index] = capacity as usize + index * slice_extend;
                counts[index] = slice_extend;
            }
            counts[slice_count - 1] += extend as usize % slice_count;
            let mut current = random % slice_count;
            counts[current] -= 1;
            let start = self.block_at(blocks[current])?;
            let mut shuffled = crate::random::shuffle(random | 1);
            for index in 1..extend as usize {
                let round = index % size_of::<usize>();
                if round == 0 {
                    shuffled = crate::random::shuffle(shuffled);
                }
                let mut next = (shuffled >> (8 * round)) & (slice_count - 1);
                while counts[next] == 0 {
                    next = (next + 1) & (slice_count - 1);
                }
                counts[next] -= 1;
                let block = self.block_at(blocks[current])?;
                blocks[current] += 1;
                // Advance first: the source may choose the same slice again.
                let successor = self.block_at(blocks[next])?;
                // SAFETY: both nodes belong to the validated new suffix, and
                // the slice counts ensure each node receives exactly one link.
                unsafe { self.write_next(block, successor.as_ptr()) };
                current = next;
            }
            let tail = self.block_at(blocks[current])?;
            // SAFETY: the final new node retains the previous immediate head.
            unsafe { self.write_next(tail, self.free()) };
            self.set_free(start.as_ptr());
        }
        // SAFETY: publication follows all initialized suffix links under the
        // caller's exclusive owner-field authority.
        unsafe { ptr::write(self.capacity.as_ptr(), next_capacity) };
        Ok(extend)
    }

    /// Selects the configured source extension without drawing in default mode.
    #[cfg(target_arch = "x86_64")]
    pub(crate) fn extend_count_with_random(
        &mut self,
        extend: u16,
        random_word: impl FnOnce() -> Option<usize>,
    ) -> Result<u16, FreeListError> {
        if crate::config::SECURE_LEVEL >= 2 {
            self.extend_count_randomized(extend, random_word)
        } else {
            self.extend_count(extend)
        }
    }

    /// Computes the selected source bound before drawing thread randomness.
    #[cfg(target_arch = "x86_64")]
    pub(crate) fn extend_with_random(
        &mut self,
        random_word: impl FnOnce() -> Option<usize>,
    ) -> Result<u16, FreeListError> {
        if crate::config::SECURE_LEVEL < 2 {
            return self.extend();
        }
        let count = crate::page::page_extend_count(
            self.capacity_value(), self.reserved, self.block_size, 0,
        ).ok_or(FreeListError::InvalidPage)?;
        if count == 0 { return Ok(0); }
        self.extend_count_randomized(count, random_word)
    }

    /// Pops one available block as `mi_page_malloc_zero` does on its fast path.
    ///
    /// `zero` selects the source's full-block zeroing branch. The returned raw
    /// pointer remains valid only while this page backing area remains live;
    /// its allocation, aliasing, and eventual exactly-once local-free duties
    /// remain the caller's responsibility.
    #[inline(always)]
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
        unsafe { ptr::write(block.as_ptr().cast::<usize>(), 0) };
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
    #[inline(always)]
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
        unsafe { self.write_next(block, self.local_free()) };
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
    #[inline(always)]
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
        unsafe { self.write_next(tail, free.as_ptr()) };
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

    /// Checks that `block` is a link-aligned word inside the initialized
    /// `capacity * block_size` prefix of this page area.
    ///
    /// This bounds every allocator-owned link read or write to initialized
    /// page memory. It deliberately does not test block-start divisibility:
    /// pinned normal-release `mi_block_next`, `mi_page_malloc_zero`, and
    /// `mi_free_block_local` validate nothing here, and even the
    /// `MI_ENCODE_FREELIST` form checks only page containment. A division
    /// per list node was the dominant arithmetic cost of the local path. A
    /// link-aligned in-range interior word is still a writable link slot:
    /// `block_size` is a nonzero multiple of `LINK_ALIGN`, so the aligned
    /// offset leaves at least `LINK_SIZE` initialized bytes before the end.
    #[inline(always)]
    fn validate_initialized_block(&self, block: NonNull<u8>) -> Result<(), FreeListError> {
        // Construction proved `reserved * block_size <= bytes`, and
        // `capacity <= reserved`, so this product cannot overflow.
        let initialized = self.capacity_value() as usize * self.block_size;
        let address = block.addr().get();
        if address.wrapping_sub(self.base.addr().get()) >= initialized
            || address % LINK_ALIGN != 0
        {
            return Err(FreeListError::InvalidBlock);
        }
        Ok(())
    }

    #[inline(always)]
    fn checked_next(&self, block: NonNull<u8>) -> Result<*mut u8, FreeListError> {
        self.validate_initialized_block(block)?;
        // SAFETY: `block` is an initialized free-list node. Every link is
        // written by `write_next` before it is read, and no typed reference is
        // formed over caller-owned allocation memory.
        let next = unsafe { self.read_next(block) };
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
    unsafe fn read_next(&self, block: NonNull<u8>) -> *mut u8 {
        // SAFETY: the caller proves `block` points at one initialized link
        // word in a live, aligned, caller-owned block allocation.
        #[cfg(not(any(feature = "mi-debug-1", all(target_arch = "x86_64", feature = "mi-secure-3"))))]
        return unsafe { ptr::read(block.as_ptr().cast::<*mut u8>()) };
        #[cfg(any(feature = "mi-debug-1", all(target_arch = "x86_64", feature = "mi-secure-3")))]
        {
            // SAFETY: the node's first word is the source encoded link.
            let encoded = unsafe { ptr::read(block.as_ptr().cast::<usize>()) };
            let address = decode_page_link(self.page_address, [self.page_key, self.page_key2], encoded);
            if address == 0 {
                ptr::null_mut()
            } else {
                block.as_ptr().map_addr(|_| address)
            }
        }
    }

    #[inline]
    unsafe fn write_next(&self, block: NonNull<u8>, next: *mut u8) {
        // SAFETY: the caller proves `block` points at one writable, aligned
        // link word in a live, uniquely owned page block.
        #[cfg(not(any(feature = "mi-debug-1", all(target_arch = "x86_64", feature = "mi-secure-3"))))]
        unsafe { ptr::write(block.as_ptr().cast::<*mut u8>(), next) };
        #[cfg(any(feature = "mi-debug-1", all(target_arch = "x86_64", feature = "mi-secure-3")))]
        {
            let encoded = encode_page_link(self.page_address, [self.page_key, self.page_key2], next.addr());
            // SAFETY: source `mi_block_set_next` stores this encoded scalar in
            // the same first word that the direct profile uses for a pointer.
            unsafe { ptr::write(block.as_ptr().cast::<usize>(), encoded) };
        }
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
        #[cfg(not(any(feature = "mi-debug-1", all(target_arch = "x86_64", feature = "mi-secure-3"))))]
        ptr::write(tail.as_ptr().cast::<*mut u8>(), free.as_ptr().cast());
        #[cfg(any(feature = "mi-debug-1", all(target_arch = "x86_64", feature = "mi-secure-3")))]
        ptr::write(tail.as_ptr().cast::<usize>(),
            encode_page_link(state.page_address, [state.page_key, state.page_key2], free.as_ptr().addr()));
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
    // Same containment-only contract as `LocalFreeList::validate_initialized_block`.
    if address < base
        || address >= end
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
        #[cfg(not(any(feature = "mi-debug-1", all(target_arch = "x86_64", feature = "mi-secure-3"))))]
        let next = unsafe { ptr::read(block.as_ptr().cast::<*mut u8>()) };
        #[cfg(any(feature = "mi-debug-1", all(target_arch = "x86_64", feature = "mi-secure-3")))]
        let next: *mut u8 = {
            // SAFETY: the validated node's first word holds the source link.
            let encoded = unsafe { ptr::read(block.as_ptr().cast::<usize>()) };
            let address = decode_page_link(state.page_address, [state.page_key, state.page_key2], encoded);
            if address == 0 { ptr::null_mut() } else { block.as_ptr().map_addr(|_| address).cast() }
        };
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
            #[cfg(any(feature = "mi-debug-1", all(target_arch = "x86_64", feature = "mi-secure-3")))]
            page_address: core::ptr::from_ref(&*state).addr(),
            #[cfg(any(feature = "mi-debug-1", all(target_arch = "x86_64", feature = "mi-secure-3")))]
            page_key: 0,
            #[cfg(any(feature = "mi-debug-1", all(target_arch = "x86_64", feature = "mi-secure-3")))]
            page_key2: 0,
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
            #[cfg(any(feature = "mi-debug-1", all(target_arch = "x86_64", feature = "mi-secure-3")))]
            page_address: core::ptr::from_ref(&*state).addr(),
            #[cfg(any(feature = "mi-debug-1", all(target_arch = "x86_64", feature = "mi-secure-3")))]
            page_key: 0,
            #[cfg(any(feature = "mi-debug-1", all(target_arch = "x86_64", feature = "mi-secure-3")))]
            page_key2: 0,
            capacity: state.capacity,
            reserved,
            free: NonNull::from(&mut state.free),
            local_free: NonNull::from(&mut state.local_free),
            used: NonNull::from(&mut state.used),
            free_is_zero: NonNull::from(&mut state.free_is_zero),
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn secure_slice_extension_preserves_immediate_and_deferred_heads() {
        let mut storage = Page([0; 4096]);
        let mut state = TestPageState::fresh(true);
        let mut list = list_for(&mut state, &mut storage, size_of::<usize>(), 512);
        assert_eq!(list.extend_count(3).unwrap(), 3);
        let clients = [list.pop(false).unwrap().unwrap(), list.pop(false).unwrap().unwrap(),
            list.pop(false).unwrap().unwrap()];
        // SAFETY: these three distinct popped blocks return exactly once;
        // the first two become immediately available and the third stays deferred.
        unsafe {
            list.push_local(clients[1]).unwrap();
            list.push_local(clients[0]).unwrap();
        }
        assert!(list.collect_local(false).unwrap());
        unsafe { list.push_local(clients[2]).unwrap(); }
        let deferred = list.local_free();
        let used = list.used_value();
        assert_eq!(list.extend_count_randomized(65, || Some(0x1122334455667788)).unwrap(), 65);
        assert_eq!(list.local_free(), deferred);
        assert_eq!(list.used_value(), used);
        assert_eq!(list.capacity(), 68);
        // Pinned source slice threading for the staged full random word
        // 0x1122334455667788, including the 65th block in the final slice.
        let expected = [11, 36, 64, 29, 13, 55, 40, 18, 24, 12, 23, 25, 15, 26,
            45, 14, 53, 60, 4, 42, 16, 9, 38, 46, 5, 58, 17, 56, 19, 63,
            34, 20, 33, 65, 57, 22, 21, 43, 27, 10, 54, 44, 28, 30, 31, 41,
            32, 66, 59, 67, 35, 3, 62, 6, 37, 7, 39, 47, 48, 49, 50, 51,
            8, 52, 61, 0, 1];
        for index in expected {
            let block = list.pop(false).unwrap().unwrap();
            assert_eq!((block.as_ptr().addr() - list.base.as_ptr().addr()) / size_of::<usize>(), index);
        }
        assert!(list.pop(false).unwrap().is_none());
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn secure_extension_refuses_missing_random_before_any_page_write() {
        let mut storage = Page([0xa5; 64]);
        let mut state = TestPageState::fresh(false);
        let mut list = list_for(&mut state, &mut storage, 16, 4);
        for random in [None, Some(0)] {
            assert_eq!(list.extend_count_randomized(3, || random),
                Err(FreeListError::RandomSourceUnavailable));
            assert_eq!(list.capacity(), 0);
            assert!(list.free().is_null());
            assert!(list.local_free().is_null());
            // SAFETY: the owner buffer remains fully live; rejected extension
            // creates no initialized links or client allocations.
            assert!(unsafe { core::slice::from_raw_parts(list.base.as_ptr(), list.bytes) }
                .iter().all(|byte| *byte == 0xa5));
        }
        assert_eq!(list.extend_count_randomized(5, || panic!("invalid geometry drew")),
            Err(FreeListError::InvalidPage));
        assert_eq!(list.extend_count_randomized(1, || panic!("single block drew")), Ok(1));
        assert!(list.pop(false).unwrap().is_some());
        assert!(list.pop(false).unwrap().is_none());
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn default_extension_does_not_consume_thread_randomness() {
        let mut storage = Page([0; 64]);
        let mut state = TestPageState::fresh(true);
        let mut list = list_for(&mut state, &mut storage, 16, 4);
        assert_eq!(list.extend_count_with_random(2, || panic!("default mode drew")), Ok(2));
        assert_eq!(list.extend_with_random(|| panic!("available list drew")), Ok(0));
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
    fn source_bin_free_list_matrix_preserves_order_and_zeroing() {
        fn names(list: &LocalFreeList, head: *mut u8) -> std::string::String {
            let mut result = std::string::String::new();
            let mut current = head;
            let mut count = 0;
            while let Some(block) = NonNull::new(current) {
                assert!(count < usize::from(list.capacity()));
                let offset = block.addr().get() - list.base.addr().get();
                assert_eq!(offset % list.block_size, 0);
                if count > 0 { result.push(','); }
                result.push_str(&std::format!("{}", offset / list.block_size));
                current = list.checked_next(block).unwrap();
                count += 1;
            }
            if count == 0 { result.push('-'); }
            result
        }

        fn show(stage: &str, list: &LocalFreeList) {
            let free = names(list, list.free());
            let local = names(list, list.local_free());
            if !cfg!(miri) {
                std::println!(
                    "M3F size={} stage={stage} capacity={} reserved={} used={} zero={} free={free} local={local}",
                    list.block_size, list.capacity(), list.reserved(), list.used(),
                    u8::from(list.free_is_zero()),
                );
            }
        }

        fn pop_checked(list: &mut LocalFreeList, zeroes: &[u8]) -> NonNull<u8> {
            let block = list.pop(true).unwrap().unwrap();
            // SAFETY: this pop uniquely returns one full initialized block;
            // the byte observation ends before any local-free link write.
            let bytes = unsafe { core::slice::from_raw_parts(block.as_ptr(), list.block_size) };
            assert_eq!(bytes, zeroes);
            block
        }

        for bin in 1..crate::config::BIN_HUGE {
            let block_size = crate::size_class::bin_size(bin).unwrap();
            if crate::size_class::bin(block_size) != Some(bin) { continue; }
            let first_extend = LocalFreeList::page_extend_count(0, u16::MAX, block_size).unwrap();
            let reserved = first_extend + 3;
            let bytes = usize::from(reserved) * block_size;
            let zeroes = std::vec![0_u8; block_size];
            let mut storage = std::vec![0_usize; bytes / LINK_SIZE];
            let base = NonNull::new(storage.as_mut_ptr().cast::<u8>()).unwrap();
            let mut state = TestPageState::fresh(true);
            // SAFETY: the aligned word buffer owns exactly the reserved
            // byte span, remains live throughout the receiver, and has no
            // references into its blocks while list operations write links.
            let source_state = PageFreeListState {
                area: base,
                area_bytes: bytes,
                block_size,
                // The source null sentinel belongs to metadata, never the
                // first client block in the separately owned block area.
                #[cfg(any(feature = "mi-debug-1", all(target_arch = "x86_64", feature = "mi-secure-3")))]
                page_address: core::ptr::from_ref(&state).addr(),
                #[cfg(any(feature = "mi-debug-1", all(target_arch = "x86_64", feature = "mi-secure-3")))]
                page_key: 0,
                #[cfg(any(feature = "mi-debug-1", all(target_arch = "x86_64", feature = "mi-secure-3")))]
                page_key2: 0,
                capacity: NonNull::from(&mut state.capacity),
                reserved,
                free: NonNull::from(&mut state.free),
                local_free: NonNull::from(&mut state.local_free),
                used: NonNull::from(&mut state.used),
                free_is_zero: NonNull::from(&mut state.free_is_zero),
            };
            let mut list = unsafe { LocalFreeList::from_page_state(source_state) }.unwrap();
            let mut allocated = std::vec::Vec::new();
            show("fresh", &list);
            while allocated.len() < usize::from(reserved) {
                if list.free().is_null() {
                    assert!(list.extend().unwrap() > 0);
                    show("extend", &list);
                }
                allocated.push(pop_checked(&mut list, &zeroes));
            }
            show("allocated", &list);
            for &block in &allocated[..2] {
                // SAFETY: each exact allocation is dirtied before its one
                // local free; at least two other clients remain allocated.
                unsafe {
                    ptr::write_bytes(block.as_ptr(), 0xa5, block_size);
                    list.push_local(block).unwrap();
                }
            }
            show("local-two", &list);
            assert!(list.collect_local(false).unwrap());
            show("transfer", &list);
            assert_eq!(pop_checked(&mut list, &zeroes), allocated[1]);
            // SAFETY: the exact block just returned by pop is no longer
            // observed after this write and its next local free.
            unsafe {
                ptr::write_bytes(allocated[1].as_ptr(), 0xa5, block_size);
                list.push_local(allocated[1]).unwrap();
            }
            show("both-lists", &list);
            assert!(!list.collect_local(false).unwrap());
            show("false-force", &list);
            assert!(list.quick_collect().unwrap());
            show("quick-preserve", &list);
            assert!(list.collect_local(true).unwrap());
            show("force-append", &list);
            assert_eq!(pop_checked(&mut list, &zeroes), allocated[1]);
            assert_eq!(pop_checked(&mut list, &zeroes), allocated[0]);
            show("reallocated", &list);
            for &block in &allocated[..allocated.len() - 1] {
                // SAFETY: every selected allocation is current and returned
                // exactly once; the final client keeps `used` positive.
                unsafe {
                    ptr::write_bytes(block.as_ptr(), 0xa5, block_size);
                    list.push_local(block).unwrap();
                }
            }
            show("local-many", &list);
            assert!(list.quick_collect().unwrap());
            show("quick-transfer", &list);
            for &block in allocated[..allocated.len() - 1].iter().rev() {
                assert_eq!(pop_checked(&mut list, &zeroes), block);
            }
            assert_eq!(list.extend().unwrap(), 0);
            assert!(!list.collect_local(true).unwrap());
            assert!(!list.quick_collect().unwrap());
            show("exhausted", &list);
        }
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
        let list = list_for(&mut state, &mut storage, 16, 4);
        unsafe { list.write_next(first, second.as_ptr()) };
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
