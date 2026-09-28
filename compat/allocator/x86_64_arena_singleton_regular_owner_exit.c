/* A later owner exits with one arena singleton and one live regular page.
   The active survivor reclaims the regular page while independently releasing
   the singleton; the page map and arena claims are observed at each boundary. */
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

#define SINGLETON_REQUEST (MI_LARGE_MAX_OBJ_SIZE + 1)
#define REGULAR_REQUEST (64 * 1024)

static sem_t ready;
static sem_t exit_go;
static mi_heap_t* shared_heap;
static void* singleton;
static void* regular[2];
static mi_page_t* singleton_page;
static mi_page_t* regular_page;
static mi_arena_t* arena;
static mi_arena_pages_t* arena_pages;
static size_t singleton_slice_index;
static size_t regular_slice_index;
static size_t singleton_slice_count;
static size_t regular_slice_count;
static size_t regular_reserved;
static uintptr_t singleton_start;
static uintptr_t regular_start;
static size_t singleton_map_count;
static size_t regular_map_count;
static int setup_valid;

static size_t map_prefix(mi_page_t* page, uintptr_t* start) {
  size_t area_size = 0;
  uint8_t* area = mi_page_area(page, &area_size);
  uint8_t* slice = mi_page_slice_start(page);
  if (area == NULL || slice == NULL || area < slice || area_size > MI_LARGE_PAGE_SIZE) return 0;
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

static void* owner(void* ignored) {
  (void)ignored;
  mi_thread_init();
  mi_heap_t* heap = shared_heap;
  if (heap != NULL) {
    singleton = mi_heap_malloc_aligned(heap, SINGLETON_REQUEST, 16);
    regular[0] = mi_heap_malloc_aligned(heap, REGULAR_REQUEST, 16);
    regular[1] = mi_heap_malloc_aligned(heap, REGULAR_REQUEST, 16);
  }
  if (singleton != NULL && regular[0] != NULL && regular[1] != NULL) {
    singleton_page = _mi_ptr_page(singleton);
    regular_page = _mi_ptr_page(regular[0]);
  }
  if (singleton_page != NULL && regular_page != NULL) {
    arena = mi_memid_arena(singleton_page->memid);
    arena_pages = arena == NULL ? NULL : mi_atomic_load_ptr_acquire(mi_arena_pages_t, &heap->arena_pages[arena->arena_idx]);
    singleton_slice_index = singleton_page->memid.mem.arena.slice_index;
    regular_slice_index = regular_page->memid.mem.arena.slice_index;
    singleton_slice_count = singleton_page->memid.mem.arena.slice_count;
    regular_slice_count = regular_page->memid.mem.arena.slice_count;
    regular_reserved = regular_page->reserved;
    singleton_map_count = map_prefix(singleton_page, &singleton_start);
    regular_map_count = map_prefix(regular_page, &regular_start);
    mi_page_queue_t* regular_queue = mi_page_queue(regular_page->theap, regular_page->block_size);
    setup_valid = singleton_page != regular_page
        && singleton_page->memid.memkind == MI_MEM_ARENA
        && regular_page->memid.memkind == MI_MEM_ARENA
        && mi_memid_arena(regular_page->memid) == arena
        && singleton_page->block_size == 589824
        && singleton_page->used == 1 && singleton_page->reserved == 1
        && mi_page_is_singleton(singleton_page)
        && mi_page_is_in_full(singleton_page)
        && regular_page->used == 2 && regular_page->reserved > 2
        && _mi_ptr_page(regular[1]) == regular_page
        && regular_queue->first == regular_page && regular_queue->count == 1
        && singleton_slice_count == 9 && regular_slice_count == 8
        && singleton_map_count == 9 && regular_map_count == 8
        && arena_pages != NULL
        && mi_bitmap_is_setN(arena_pages->pages, singleton_slice_index, 1)
        && mi_bitmap_is_setN(arena_pages->pages, regular_slice_index, 1)
        && map_is(singleton_page, singleton_start, singleton_map_count)
        && map_is(regular_page, regular_start, regular_map_count);
  }
  sem_post(&ready);
  sem_wait(&exit_go);
  mi_thread_done();
  return NULL;
}

int main(void) {
  mi_option_set(mi_option_page_full_retain, -1);
  mi_option_set(mi_option_page_reclaim_on_free, 1);
  mi_thread_init();
  void* warmup = mi_malloc(48);
  if (warmup == NULL) return 2;
  mi_free(warmup);
  shared_heap = _mi_theap_heap(_mi_theap_default());
  if (shared_heap == NULL) return 2;
  if (sem_init(&ready, 0, 0) != 0 || sem_init(&exit_go, 0, 0) != 0) return 2;
  pthread_t worker;
  if (pthread_create(&worker, NULL, owner, NULL) != 0) return 2;
  if (sem_wait(&ready) != 0) return 2;
  if (!setup_valid) return 3;
  sem_post(&exit_go);
  if (pthread_join(worker, NULL) != 0) return 2;

  int singleton_unmapped = mi_page_is_abandoned(singleton_page)
      && !mi_page_is_abandoned_mapped(singleton_page) && !mi_page_is_owned(singleton_page);
  int regular_mapped = mi_page_is_abandoned_mapped(regular_page)
      && !mi_page_is_owned(regular_page);
  int both_map_registered = map_is(singleton_page, singleton_start, singleton_map_count)
      && map_is(regular_page, regular_start, regular_map_count);
  int both_arena_claimed = mi_bitmap_is_setN(arena_pages->pages, singleton_slice_index, 1)
      && mi_bitmap_is_setN(arena_pages->pages, regular_slice_index, 1);
  if (!singleton_unmapped || !regular_mapped || !both_map_registered || !both_arena_claimed) return 4;

  mi_free(regular[0]);
  mi_page_queue_t* regular_queue = mi_page_queue(_mi_theap_default(), regular_page->block_size);
  int regular_reclaimed = regular_page->used == 1
      && regular_page->theap == _mi_theap_default()
      && mi_page_is_owned(regular_page) && !mi_page_is_abandoned(regular_page)
      && regular_queue->first == regular_page && regular_queue->count == 1;
  int singleton_retained = map_is(singleton_page, singleton_start, singleton_map_count)
      && mi_bitmap_is_setN(arena_pages->pages, singleton_slice_index, 1);
  if (!regular_reclaimed || !singleton_retained) return 5;

  mi_free(singleton);
  int singleton_map_clear = map_clear(singleton_start, singleton_map_count);
  int singleton_arena_clear = mi_bitmap_is_clearN(arena_pages->pages, singleton_slice_index, 1);
  int singleton_slices_free = mi_bbitmap_is_setN(arena->slices_free, singleton_slice_index, singleton_slice_count);
  int regular_still_registered = map_is(regular_page, regular_start, regular_map_count)
      && mi_bitmap_is_setN(arena_pages->pages, regular_slice_index, 1);
  if (!singleton_map_clear || !singleton_arena_clear || !singleton_slices_free || !regular_still_registered) return 6;

  mi_free(regular[1]);
  int regular_retired = regular_page->used == 0 && regular_page->retire_expire == 4
      && map_is(regular_page, regular_start, regular_map_count);
  if (!regular_retired) return 7;
  mi_collect(true);
  int regular_map_clear = map_clear(regular_start, regular_map_count);
  int regular_arena_clear = mi_bitmap_is_clearN(arena_pages->pages, regular_slice_index, 1);
  int regular_slices_free = mi_bbitmap_is_setN(arena->slices_free, regular_slice_index, regular_slice_count);
  void* survivor = mi_malloc(64);
  int survivor_usable = survivor != NULL;
  mi_free(survivor);

  printf("CRABC_MI_ARENA_SINGLETON_REGULAR_EXIT_BEGIN\n");
  printf("singleton_request=%zu\nregular_request=%zu\n", (size_t)SINGLETON_REQUEST, (size_t)REGULAR_REQUEST);
  printf("singleton_block_size=589824\nregular_reserved=%zu\n", regular_reserved);
  printf("singleton_slice_count=%zu\nregular_slice_count=%zu\n", singleton_slice_count, regular_slice_count);
  printf("singleton_map_count=%zu\nregular_map_count=%zu\n", singleton_map_count, regular_map_count);
  printf("owner_setup_valid=%d\nboth_arena_backed=1\nboth_map_registered=%d\n", setup_valid, both_map_registered);
  printf("regular_reclaimed=%d\nsingleton_retained=%d\n", regular_reclaimed, singleton_retained);
  printf("singleton_map_clear=%d\n", singleton_map_clear);
  printf("regular_still_registered=%d\nregular_retired=%d\n", regular_still_registered, regular_retired);
  printf("regular_map_clear=%d\nsurvivor_usable=%d\n", regular_map_clear, survivor_usable);
  printf("CRABC_MI_ARENA_SINGLETON_REGULAR_EXIT_END\n");
  printf("CRABC_MI_C_ARENA_TRANSITIONS singleton_unmapped=%d regular_mapped=%d claimed_after_exit=%d singleton_arena_clear=%d singleton_slices_free=%d regular_arena_clear=%d regular_slices_free=%d\n",
      singleton_unmapped, regular_mapped, both_arena_claimed, singleton_arena_clear,
      singleton_slices_free, regular_arena_clear, regular_slices_free);
  return regular_map_clear && regular_arena_clear && regular_slices_free && survivor_usable ? 0 : 8;
}
