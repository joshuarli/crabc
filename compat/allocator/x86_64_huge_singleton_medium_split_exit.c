/* A huge arena singleton and a regular medium page survive one worker's exit.
   Separate attached threads free them after exit while the other page remains
   live, then the medium owner completes its retired-page collection. */
#include "mimalloc/internal.h"
#include "mimalloc/prim-tls.h"
#include "bitmap.h"
#include <pthread.h>
#include <semaphore.h>
#include <stdio.h>

#if !defined(__linux__) || !defined(__x86_64__)
#error this private source fixture requires native Linux/x86-64
#endif
#if MI_BUILD_RELEASE != 1 || MI_DEBUG != 0 || MI_STAT != 0 || MI_SECURE != 0 || MI_GUARDED != 0
#error this fixture requires the pinned release configuration
#endif

#define HUGE_REQUEST (5 * 1024 * 1024)
#define MEDIUM_REQUEST (64 * 1024)
#define TRACE(name, value) printf(#name "=%lld\n", (long long)(value))

static sem_t owner_ready, owner_exit;
static sem_t medium_ready, medium_first_go, medium_first_done, medium_final_go, medium_final_done;
static sem_t huge_ready, huge_go, huge_done;
static mi_heap_t* shared_heap;
static void* huge_client;
static void* medium_client[2];
static mi_page_t* huge_page;
static mi_page_t* medium_page;
static mi_arena_t* arena;
static mi_arena_pages_t* arena_pages;
static size_t huge_slice_index, huge_slice_count, huge_map_count;
static size_t medium_slice_index, medium_slice_count, medium_map_count;
static size_t huge_block_size, medium_block_size, medium_reserved;
static uintptr_t huge_map_start, medium_map_start;
static int setup_valid, medium_reclaimed, medium_retained_before_collect, medium_final_release;
static unsigned medium_retire_expire;
static int huge_final_release;

static size_t source_map_prefix(mi_page_t* page, uintptr_t* start) {
  size_t area_size = 0;
  uint8_t* area = mi_page_area(page, &area_size);
  uint8_t* slice = mi_page_slice_start(page);
  if (area == NULL || slice == NULL || area < slice) return 0;
  if (area_size > MI_LARGE_PAGE_SIZE) area_size = MI_LARGE_PAGE_SIZE - MI_ARENA_SLICE_SIZE;
  *start = (uintptr_t)slice;
  return mi_slice_count_of_size(area_size) + (size_t)(area - slice) / MI_ARENA_SLICE_SIZE;
}

static int map_is(mi_page_t* page, uintptr_t start, size_t count) {
  if (count == 0) return 0;
  for (size_t i = 0; i < count; i++) {
    if (_mi_safe_ptr_page((void*)(start + i * MI_ARENA_SLICE_SIZE)) != page) return 0;
  }
  return 1;
}

static int map_clear(uintptr_t start, size_t count) {
  if (count == 0) return 0;
  for (size_t i = 0; i < count; i++) {
    if (_mi_safe_ptr_page((void*)(start + i * MI_ARENA_SLICE_SIZE)) != NULL) return 0;
  }
  return 1;
}

static size_t count_bitmap(mi_bitmap_t* bitmap, size_t first, size_t count) {
  size_t result = 0;
  for (size_t i = 0; i < count; i++) result += mi_bitmap_is_setN(bitmap, first + i, 1);
  return result;
}

static size_t count_bbitmap(mi_bbitmap_t* bitmap, size_t first, size_t count) {
  size_t result = 0;
  for (size_t i = 0; i < count; i++) result += mi_bbitmap_is_setN(bitmap, first + i, 1);
  return result;
}

static void* source_owner(void* ignored) {
  (void)ignored;
  mi_thread_init();
  huge_client = mi_heap_malloc_aligned(shared_heap, HUGE_REQUEST, 16);
  medium_client[0] = mi_heap_malloc_aligned(shared_heap, MEDIUM_REQUEST, 16);
  medium_client[1] = mi_heap_malloc_aligned(shared_heap, MEDIUM_REQUEST, 16);
  if (huge_client != NULL) huge_page = _mi_ptr_page(huge_client);
  if (medium_client[0] != NULL) medium_page = _mi_ptr_page(medium_client[0]);
  if (huge_page != NULL && medium_page != NULL) {
    huge_block_size = huge_page->block_size;
    medium_block_size = medium_page->block_size;
    medium_reserved = medium_page->reserved;
    arena = mi_memid_arena(huge_page->memid);
    if (arena != NULL) {
      arena_pages = mi_atomic_load_ptr_acquire(mi_arena_pages_t,
          &shared_heap->arena_pages[arena->arena_idx]);
    }
    huge_slice_index = huge_page->memid.mem.arena.slice_index;
    huge_slice_count = huge_page->memid.mem.arena.slice_count;
    medium_slice_index = medium_page->memid.mem.arena.slice_index;
    medium_slice_count = medium_page->memid.mem.arena.slice_count;
    huge_map_count = source_map_prefix(huge_page, &huge_map_start);
    medium_map_count = source_map_prefix(medium_page, &medium_map_start);
    mi_page_queue_t* medium_queue = mi_page_queue(medium_page->theap, medium_page->block_size);
    setup_valid = huge_page != medium_page && arena != NULL && arena_pages != NULL
        && huge_page->memid.memkind == MI_MEM_ARENA
        && medium_page->memid.memkind == MI_MEM_ARENA
        && mi_memid_arena(medium_page->memid) == arena
        && mi_page_is_singleton(huge_page) && mi_page_is_in_full(huge_page)
        && huge_page->used == 1 && huge_page->reserved == 1
        && huge_block_size >= HUGE_REQUEST && huge_map_count < huge_slice_count
        && _mi_ptr_page(medium_client[1]) == medium_page
        && medium_page->used == 2 && medium_reserved > 2
        && medium_block_size > MI_SMALL_MAX_OBJ_SIZE
        && medium_block_size <= MI_MEDIUM_MAX_OBJ_SIZE
        && medium_queue->first == medium_page && medium_queue->count == 1
        && medium_slice_count == 8 && medium_map_count == 8
        && mi_bitmap_is_setN(arena_pages->pages, huge_slice_index, 1)
        && mi_bitmap_is_setN(arena_pages->pages, medium_slice_index, 1)
        && map_is(huge_page, huge_map_start, huge_map_count)
        && map_is(medium_page, medium_map_start, medium_map_count);
  }
  sem_post(&owner_ready);
  sem_wait(&owner_exit);
  mi_thread_done();
  return NULL;
}

static void* medium_survivor(void* ignored) {
  (void)ignored;
  mi_thread_init();
  sem_post(&medium_ready);
  sem_wait(&medium_first_go);
  mi_free(medium_client[0]);
  mi_page_queue_t* queue = mi_page_queue(_mi_theap_default(), medium_block_size);
  medium_reclaimed = medium_page->used == 1
      && medium_page->theap == _mi_theap_default()
      && mi_page_is_owned(medium_page) && !mi_page_is_abandoned(medium_page)
      && queue->first == medium_page && queue->count == 1;
  sem_post(&medium_first_done);
  sem_wait(&medium_final_go);
  mi_free(medium_client[1]);
  medium_retire_expire = medium_page->retire_expire;
  medium_retained_before_collect = medium_page->used == 0
      && map_is(medium_page, medium_map_start, medium_map_count);
  mi_collect(true);
  medium_final_release = map_clear(medium_map_start, medium_map_count);
  sem_post(&medium_final_done);
  mi_thread_done();
  return NULL;
}

static void* huge_survivor(void* ignored) {
  (void)ignored;
  mi_thread_init();
  sem_post(&huge_ready);
  sem_wait(&huge_go);
  mi_free(huge_client);
  huge_final_release = map_clear(huge_map_start, huge_map_count);
  sem_post(&huge_done);
  mi_thread_done();
  return NULL;
}

int main(void) {
  _mi_auto_process_init();
  mi_option_set(mi_option_purge_delay, 1000000);
  mi_option_set(mi_option_purge_decommits, 1);
  mi_option_set(mi_option_page_full_retain, -1);
  mi_option_set(mi_option_page_reclaim_on_free, 1);
  mi_thread_init();
  void* warmup = mi_malloc(48);
  if (warmup == NULL) return 2;
  mi_free(warmup);
  shared_heap = _mi_theap_heap(_mi_theap_default());
  if (shared_heap == NULL) return 2;
  sem_t* semaphores[] = { &owner_ready, &owner_exit, &medium_ready, &medium_first_go,
      &medium_first_done, &medium_final_go, &medium_final_done, &huge_ready, &huge_go, &huge_done };
  for (size_t i = 0; i < sizeof(semaphores)/sizeof(semaphores[0]); i++) {
    if (sem_init(semaphores[i], 0, 0) != 0) return 2;
  }
  pthread_t owner_thread, medium_thread, huge_thread;
  if (pthread_create(&owner_thread, NULL, source_owner, NULL) != 0) return 2;
  if (sem_wait(&owner_ready) != 0 || !setup_valid) {
    fprintf(stderr, "setup: valid=%d huge_block=%zu huge_claim=%zu huge_map=%zu medium_block=%zu\n",
        setup_valid, huge_block_size, huge_slice_count, huge_map_count, medium_block_size);
    return 3;
  }
  if (pthread_create(&medium_thread, NULL, medium_survivor, NULL) != 0
      || pthread_create(&huge_thread, NULL, huge_survivor, NULL) != 0) return 2;
  if (sem_wait(&medium_ready) != 0 || sem_wait(&huge_ready) != 0) return 2;
  sem_post(&owner_exit);
  if (pthread_join(owner_thread, NULL) != 0) return 2;
  int huge_unmapped_after_exit = mi_page_is_abandoned(huge_page)
      && !mi_page_is_abandoned_mapped(huge_page) && !mi_page_is_owned(huge_page);
  int medium_mapped_after_exit = mi_page_is_abandoned_mapped(medium_page)
      && !mi_page_is_owned(medium_page);
  int both_registered_after_exit = map_is(huge_page, huge_map_start, huge_map_count)
      && map_is(medium_page, medium_map_start, medium_map_count);
  int both_arena_claimed_after_exit = mi_bitmap_is_setN(arena_pages->pages, huge_slice_index, 1)
      && mi_bitmap_is_setN(arena_pages->pages, medium_slice_index, 1);
  int os_list_empty_after_exit = shared_heap->os_abandoned_pages == NULL;
  if (!huge_unmapped_after_exit || !medium_mapped_after_exit
      || !both_registered_after_exit || !both_arena_claimed_after_exit
      || !os_list_empty_after_exit) return 4;

  sem_post(&medium_first_go);
  if (sem_wait(&medium_first_done) != 0 || !medium_reclaimed) return 5;
  int huge_still_registered = map_is(huge_page, huge_map_start, huge_map_count);
  int medium_still_registered = map_is(medium_page, medium_map_start, medium_map_count);
  if (!huge_still_registered || !medium_still_registered) return 5;

  mi_subproc_t* subproc = _mi_subproc_main();
  int64_t reserved_before_huge = subproc->stats.reserved.current;
  int64_t committed_before_huge = subproc->stats.committed.current;
  sem_post(&huge_go);
  if (sem_wait(&huge_done) != 0 || !huge_final_release) return 6;
  int huge_claim_clear = mi_bitmap_is_clearN(arena_pages->pages, huge_slice_index, 1);
  int huge_slices_free = mi_bbitmap_is_setN(arena->slices_free, huge_slice_index, huge_slice_count);
  int medium_retained_after_huge = map_is(medium_page, medium_map_start, medium_map_count)
      && mi_bitmap_is_setN(arena_pages->pages, medium_slice_index, 1);
  size_t huge_free_after_release = count_bbitmap(arena->slices_free, huge_slice_index, huge_slice_count);
  size_t huge_committed_after_release = count_bitmap(arena->slices_committed, huge_slice_index, huge_slice_count);
  size_t huge_purge_after_release = count_bitmap(arena->slices_purge, huge_slice_index, huge_slice_count);
  int64_t reserved_after_huge = subproc->stats.reserved.current;
  int64_t committed_after_huge = subproc->stats.committed.current;
  if (!huge_claim_clear || !huge_slices_free || !medium_retained_after_huge) return 6;

  sem_post(&medium_final_go);
  if (sem_wait(&medium_final_done) != 0 || !medium_retained_before_collect
      || medium_retire_expire != 4 || !medium_final_release) return 7;
  int medium_claim_clear = mi_bitmap_is_clearN(arena_pages->pages, medium_slice_index, 1);
  int huge_still_clear = map_clear(huge_map_start, huge_map_count);
  int os_list_empty_after_final = shared_heap->os_abandoned_pages == NULL;
  int64_t reserved_after_medium = subproc->stats.reserved.current;
  int64_t committed_after_medium = subproc->stats.committed.current;
  if (!medium_claim_clear || !huge_still_clear || !os_list_empty_after_final) return 7;
  if (pthread_join(medium_thread, NULL) != 0 || pthread_join(huge_thread, NULL) != 0) return 2;

  printf("CRABC_MI_HUGE_SINGLETON_MEDIUM_SPLIT_EXIT_BEGIN\n");
  TRACE(huge_request, HUGE_REQUEST); TRACE(medium_request, MEDIUM_REQUEST);
  TRACE(huge_block_size, huge_block_size); TRACE(medium_block_size, medium_block_size);
  TRACE(medium_reserved, medium_reserved);
  TRACE(huge_slice_count, huge_slice_count); TRACE(huge_map_count, huge_map_count);
  TRACE(medium_slice_count, medium_slice_count); TRACE(medium_map_count, medium_map_count);
  TRACE(setup_valid, setup_valid); TRACE(two_survivors_ready, 1);
  TRACE(huge_unmapped_after_exit, huge_unmapped_after_exit);
  TRACE(medium_mapped_after_exit, medium_mapped_after_exit);
  TRACE(both_registered_after_exit, both_registered_after_exit);
  TRACE(both_arena_claimed_after_exit, both_arena_claimed_after_exit);
  TRACE(os_list_empty_after_exit, os_list_empty_after_exit);
  TRACE(medium_reclaimed, medium_reclaimed);
  TRACE(huge_still_registered, huge_still_registered);
  TRACE(medium_still_registered, medium_still_registered);
  TRACE(huge_final_release, huge_final_release);
  TRACE(huge_claim_clear, huge_claim_clear);
  TRACE(huge_slices_free, huge_slices_free);
  TRACE(medium_retained_after_huge, medium_retained_after_huge);
  TRACE(huge_free_after_release, huge_free_after_release);
  TRACE(huge_committed_after_release, huge_committed_after_release);
  TRACE(huge_purge_after_release, huge_purge_after_release);
  TRACE(huge_reserved_drop, reserved_before_huge - reserved_after_huge);
  TRACE(huge_committed_drop, committed_before_huge - committed_after_huge);
  TRACE(medium_retained_before_collect, medium_retained_before_collect);
  TRACE(medium_final_release, medium_final_release);
  TRACE(medium_claim_clear, medium_claim_clear);
  TRACE(huge_still_clear, huge_still_clear);
  TRACE(os_list_empty_after_final, os_list_empty_after_final);
  TRACE(medium_reserved_drop, reserved_after_huge - reserved_after_medium);
  TRACE(medium_committed_drop, committed_after_huge - committed_after_medium);
  TRACE(warning_enabled, mi_option_is_enabled(mi_option_show_errors));
  printf("CRABC_MI_HUGE_SINGLETON_MEDIUM_SPLIT_EXIT_END\n");
  printf("CRABC_MI_C_HUGE_SOURCE_STATE medium_retire_expire=%u\n", medium_retire_expire);
  return huge_free_after_release == huge_slice_count
      && huge_committed_after_release == huge_slice_count
      && huge_purge_after_release == huge_slice_count
      && reserved_before_huge == reserved_after_huge
      && committed_before_huge == committed_after_huge
      && reserved_after_huge == reserved_after_medium
      && committed_after_huge == committed_after_medium ? 0 : 8;
}
