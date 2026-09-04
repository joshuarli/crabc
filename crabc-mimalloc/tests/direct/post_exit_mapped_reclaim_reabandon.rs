use super::*;

const BLOCK_SIZE: usize = (crate::config::MEDIUM_MAX_OBJ_SIZE + crate::config::MAX_ALIGN_SIZE)
    & !(crate::config::MAX_ALIGN_SIZE - 1);
const RESERVED: usize = 4;
const PAGE_OFFSET: usize = core::mem::size_of::<Page>();
const STORAGE_WORDS: usize =
    (PAGE_OFFSET + RESERVED * BLOCK_SIZE) / core::mem::size_of::<usize>();

#[repr(align(16))]
struct SourceLargePageStorage {
    words: [core::mem::MaybeUninit<usize>; STORAGE_WORDS],
}

impl SourceLargePageStorage {
    const fn uninit() -> Self {
        Self {
            words: [const { core::mem::MaybeUninit::uninit() }; STORAGE_WORDS],
        }
    }

    fn page_and_block(&mut self) -> (NonNull<Page>, NonNull<u8>) {
        let page = NonNull::new(self.words.as_mut_ptr().cast::<Page>())
            .expect("the source-shaped large page metadata is non-null");
        // SAFETY: this backing reserves the complete source page area after
        // its metadata, and `PAGE_OFFSET` is the matching page alignment.
        let block = unsafe { NonNull::new_unchecked(page.as_ptr().cast::<u8>().add(PAGE_OFFSET)) };
        (page, block)
    }
}

/// Pinned mimalloc v3.5.0 `src/free.c:479-515` tries reclaim once after
/// collection. A rejected already-mapped reclaim falls through the mapped
/// no-op reabandon check and calls `mi_abandoned_page_unown_from_free`; a
/// later bitmap claim may then reassociate only its current live Theap.
#[test]
fn post_exit_rejected_mapped_reclaim_unowns_once_before_live_adoption() {
    assert!(BLOCK_SIZE > crate::config::MEDIUM_MAX_OBJ_SIZE);
    let bin = size_class::bin(BLOCK_SIZE).expect("the selected large size has an arena bin");
    assert!(bin < ARENA_BIN_COUNT);

    let mut storage = BitmapStorage::uninit();
    let mut arena = map_fixture_for_bin(&mut storage, bin);
    let view = unsafe { ArenaView::from_ptr(&mut arena).unwrap() };
    let map = view.abandoned_pages(bin).unwrap();

    let source_thread = LiveThreadId::new(16).unwrap();
    let target_thread = LiveThreadId::new(24).unwrap();
    let mut source_heap = Heap::bootstrap_empty();
    let mut source_tld = ThreadLocalData::detached();
    let mut departed_theap = Theap::empty();
    let mut target_heap = Heap::bootstrap_empty();
    let mut target_tld = ThreadLocalData::detached();
    let mut target_theap = Theap::empty();
    let target = bind_adopting_theap(
        &mut target_heap,
        &mut target_tld,
        &mut target_theap,
        target_thread,
    );

    let departed = bind_adopting_theap(
        &mut source_heap,
        &mut source_tld,
        &mut departed_theap,
        source_thread,
    );
    let mut storage = SourceLargePageStorage::uninit();
    let (mut page, block) = storage.page_and_block();
    page = unsafe {
        Page::publish_fresh_exclusive_at(
            page,
            &mut departed_theap,
            &source_heap,
            source_thread,
            BLOCK_SIZE,
            PAGE_OFFSET,
            RESERVED as u16,
            0,
            false,
            MemoryId::none(),
        )
    }
    .expect("the source-shaped large page initializes");
    assert!(unsafe { page.as_mut() }.set_capacity_reserved(RESERVED as u16, RESERVED as u16));
    unsafe { page.as_mut() }.set_exclusive_used(3);
    assert!(unsafe { page.as_mut().abandoned_test_set_arena_memory(&mut arena, 17, 1) });
    assert_eq!(unsafe { abandon(page, Some(&map)) }, Ok(AbandonResult::UnownedMapped));
    assert!(map.is_published(17));

    assert_eq!(
        unsafe { free_mapped_and_reclaim(page, block, &map, departed, source_thread) },
        Ok(MappedAbandonedFreeResult::UnownedMapped),
        "a rejected large mapped reclaim must finish the source unown tail"
    );
    assert!(map.is_published(17), "the already-mapped source publication stays available");
    assert_eq!(
        unsafe { page.as_ref() }.abandoned_test_thread_id(),
        THREAD_ID_ABANDONED_MAPPED,
        "the rejected free preserves mapped abandonment rather than reopening the exited owner"
    );
    assert_eq!(
        unsafe { page.as_ref() }.remote_free_test_head() & THREAD_FREE_OWNED,
        0,
        "the rejected reclaim releases its one low-bit owner exactly once"
    );
    assert_eq!(
        unsafe { page.as_ref() }.remote_free_test_used(),
        2,
        "the rejected reclaim collects the one exact allocation before unowning"
    );
    assert_eq!(
        unsafe { page.as_ref() }.theap(),
        departed.as_ptr(),
        "the rejected source tail does not reassociate the departed Theap"
    );

    let adopted = unsafe {
        try_adopt_retained(&map, 0, target, target_thread, |slice_index| {
            (slice_index == 17).then_some(page)
        })
    }
    .expect("the mapped source claim does not retain terminal provenance")
    .expect("the released mapped owner admits one later live claim");
    assert_eq!(adopted.page(), page);
    assert_eq!(adopted.collected_remote_blocks(), 0);
    assert!(!map.is_published(17), "the permitted claim consumes the same publication once");
    assert_eq!(
        unsafe { page.as_ref() }.theap(),
        target.as_ptr(),
        "only the later permitted claim installs its current live Theap"
    );
    assert_eq!(
        unsafe { page.as_ref() }.abandoned_test_thread_id(),
        target_thread.get(),
        "adoption restores the current live identity without reviving the departed one"
    );
}
