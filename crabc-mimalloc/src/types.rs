// Copyright (c) 2018-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `include/mimalloc/types.h:288-456`
// (`MemoryKind`, memory-ID layout, `Block`, page flags, and `Page`),
// `include/mimalloc/types.h:499-557` (`PageKind` and `PageQueue`), and
// `src/init.c:15-80` (the empty-page and all 75 default queue initializers).
// The intrusive membership operations from `src/page-queue.c:40-55,126-423`
// are isolated in the `page_queue` child module below.
// This module deliberately stops before heap, theap, TLD, lock, and statistics
// state: those fields require their complete lifecycle and atomic contracts,
// and are therefore absent rather than stubbed.

use core::mem::{align_of, size_of};
use core::ptr::null_mut;
use core::sync::atomic::{AtomicPtr, AtomicUsize};

use crate::config::{
    BIN_COUNT, BIN_FULL, LARGE_MAX_OBJ_WSIZE, PAGES_DIRECT, WORD_SIZE,
};

pub(crate) enum Arena {}
pub(crate) enum Heap {}
pub(crate) enum Theap {}

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
}

#[repr(transparent)]
#[derive(Clone, Copy)]
pub(crate) struct Encoded(pub(crate) usize);

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

#[repr(C)]
pub(crate) struct Block {
    next: Encoded,
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
    const fn empty(block_size: usize) -> Self {
        Self {
            first: null_mut(),
            last: null_mut(),
            count: 0,
            block_size,
        }
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
}

pub(crate) static EMPTY_PAGE: BootstrapPage = BootstrapPage(Page::empty());

const _: [(); 4] = [(); size_of::<MemoryKind>()];
const _: [(); 16] = [(); size_of::<MemoryInfo>()];
const _: [(); 8] = [(); align_of::<MemoryInfo>()];
const _: [(); 24] = [(); size_of::<MemoryId>()];
const _: [(); 8] = [(); align_of::<MemoryId>()];
const _: [(); 8] = [(); size_of::<Block>()];
const _: [(); 32] = [(); size_of::<PageQueue>()];
const _: [(); 128] = [(); size_of::<Page>()];
const _: [(); 8] = [(); align_of::<Page>()];
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
