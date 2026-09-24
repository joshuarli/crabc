// SPDX-License-Identifier: MIT
//
// Test-audit-only Theap trace image for the M3 persistent-owner local-path
// differential (`compat/allocator/m3-local-engine-x86_64-v3.5.0.json`,
// component `persistent-owner-local-path`).
//
// `crabc-mimalloc/tests/native_persistent_owner_local_trace.rs` drives the
// production `native_allocate_aligned`/`native_free` boundary and, after each
// operation, asks the current persistent owner for this image of its default
// Theap. It then normalizes the facts exactly as
// `compat/allocator/m3_local_trace_x86_64.c` does for the pinned C default
// Theap. The image copies scalar source fields only: pages are named by their
// arena slice index and free-list heads by block index. No allocator
// capability leaves this module; the only addresses are the opaque arena
// identity, which proves every traced page shares one arena, and each page's
// block-area start, which names a returned block by its page and index.
//
// The whole module is compiled only with `native-runtime-test-audit`, which
// production allocator and libc builds never enable.

use crate::config::{BIN_COUNT, PAGES_DIRECT};
use crate::types::page_queue::page_is_in_full;
use crate::types::{Block, EMPTY_PAGE, Page, Theap};

/// One free-list head, as its block index and byte remainder from the page's
/// block area (the source trace spells it `<index>` or `<index>r<rem>`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[doc(hidden)]
pub struct NativeTheapTraceBlock {
    pub index: usize,
    pub remainder: usize,
}

/// Copied source `mi_page_t` facts for one queue member.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[doc(hidden)]
pub struct NativeTheapTracePage {
    /// Opaque identity of the page's source arena (`memid.mem.arena.arena`).
    pub arena: usize,
    /// `memid.mem.arena.slice_index`: the page's arena slice.
    pub slice: usize,
    /// Address of the page's block area (`mi_page_start`).
    pub start: usize,
    pub block_size: usize,
    pub capacity: usize,
    pub reserved: usize,
    pub used: usize,
    pub free: Option<NativeTheapTraceBlock>,
    pub local_free: Option<NativeTheapTraceBlock>,
    pub retire_expire: u8,
    pub in_full: bool,
    pub free_is_zero: bool,
}

/// One direct-page cache entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[doc(hidden)]
pub enum NativeTheapTraceDirect {
    /// The source `_mi_page_empty` sentinel.
    Empty,
    /// A page in an arena, named as in [`NativeTheapTracePage`].
    Page { arena: usize, slice: usize },
    /// A non-arena page, which the trace reports as unknown.
    Other,
}

/// One fact of the source-order Theap walk. The sequence is: `Options`, then
/// for each bin `0..BIN_COUNT` its `Page` members in queue order followed by
/// its `Queue` summary, then every `Direct` entry in index order, then
/// `Counters`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[doc(hidden)]
pub enum NativeTheapTraceFact {
    Options { page_full_retain: isize, allow_page_abandon: bool, allow_page_reclaim: bool },
    Page { bin: usize, page: NativeTheapTracePage },
    /// A queue member with non-arena memory; the trace cannot name it.
    NonArenaPage { bin: usize },
    Queue { bin: usize, block_size: usize, count: usize },
    Direct { index: usize, page: NativeTheapTraceDirect },
    Counters {
        page_count: usize,
        retired_min: usize,
        retired_max: usize,
        pages_full_size: usize,
        generic_count: isize,
        generic_collect_count: isize,
        heartbeat: u64,
    },
}

fn block_index(page: &Page, block: *mut Block) -> Option<NativeTheapTraceBlock> {
    if block.is_null() {
        return None;
    }
    // SAFETY: `page` is a live queue member of the exclusively borrowed
    // owner; `start` only forms its block-area address.
    let start = unsafe { page.start() }.addr();
    let offset = block.addr().wrapping_sub(start);
    let size = page.block_size();
    Some(NativeTheapTraceBlock { index: offset / size, remainder: offset % size })
}

/// Walks one live, exclusively borrowed default Theap in source order.
///
/// Queue walks are bounded by `max_members`; a queue that does not terminate
/// within it stops the walk and returns `false`.
pub(crate) fn visit_theap(
    theap: &Theap,
    max_members: usize,
    visit: &mut dyn FnMut(NativeTheapTraceFact),
) -> bool {
    visit(NativeTheapTraceFact::Options {
        page_full_retain: theap.page_full_retain(),
        allow_page_abandon: theap.allows_page_abandon(),
        allow_page_reclaim: theap.allows_page_reclaim(),
    });
    for bin in 0..BIN_COUNT {
        let Some(queue) = theap.queue(bin) else { return false };
        let mut page = queue.first();
        let mut walked = 0usize;
        while !page.is_null() {
            walked += 1;
            if walked > max_members {
                return false;
            }
            // SAFETY: queue members are live page metadata owned by the
            // caller's exclusively borrowed Theap; no remote producer exists
            // in the traced owner-local workload.
            let page_ref = unsafe { &*page };
            match page_ref.memid().arena_memory() {
                Some(memory) => visit(NativeTheapTraceFact::Page {
                    bin,
                    page: NativeTheapTracePage {
                        arena: memory.arena.addr(),
                        slice: memory.slice_index as usize,
                        // SAFETY: as for `block_index`, this only forms the
                        // live page's block-area address.
                        start: unsafe { page_ref.start() }.addr(),
                        block_size: page_ref.block_size(),
                        capacity: usize::from(page_ref.capacity()),
                        reserved: usize::from(page_ref.reserved()),
                        used: page_ref.used(),
                        free: block_index(page_ref, page_ref.free_list_head()),
                        local_free: block_index(page_ref, page_ref.remote_free_test_local_free()),
                        retire_expire: page_ref.retire_expire(),
                        in_full: page_is_in_full(page_ref),
                        free_is_zero: page_ref.free_is_zero(),
                    },
                }),
                None => visit(NativeTheapTraceFact::NonArenaPage { bin }),
            }
            page = page_ref.next();
        }
        visit(NativeTheapTraceFact::Queue { bin, block_size: queue.block_size(), count: queue.count() });
    }
    for index in 0..PAGES_DIRECT {
        let Some(page) = theap.direct_page(index) else { return false };
        let entry = if core::ptr::eq(page, EMPTY_PAGE.as_ptr()) {
            NativeTheapTraceDirect::Empty
        } else {
            // SAFETY: a non-sentinel direct entry is a live page of this
            // exclusively borrowed Theap.
            match unsafe { &*page }.memid().arena_memory() {
                Some(memory) => NativeTheapTraceDirect::Page {
                    arena: memory.arena.addr(),
                    slice: memory.slice_index as usize,
                },
                None => NativeTheapTraceDirect::Other,
            }
        };
        visit(NativeTheapTraceFact::Direct { index, page: entry });
    }
    let (retired_min, retired_max) = theap.retired_bounds();
    let (heartbeat, generic_count, generic_collect_count) = theap.test_generic_administration_image();
    visit(NativeTheapTraceFact::Counters {
        page_count: theap.page_count(),
        retired_min,
        retired_max,
        pages_full_size: theap.pages_full_size(),
        generic_count,
        generic_collect_count,
        heartbeat,
    });
    true
}
