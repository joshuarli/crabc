/* Two survivor threads free distinct live arena singletons only after their
   common owner has completed source thread exit. Each release must clear its
   own PageMap and arena claim while preserving the other's live claim. */
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

#define REQUEST (MI_LARGE_MAX_OBJ_SIZE + 1)

static sem_t owner_ready;
static sem_t owner_exit_go;
static sem_t releaser_ready[2];
static sem_t releaser_go[2];
static mi_heap_t* shared_heap;
static void* clients[2];
static mi_page_t* pages[2];
static mi_arena_t* arena;
static mi_arena_pages_t* arena_pages;
static size_t slice_index[2];
static size_t slice_count[2];
static size_t map_count[2];
static uintptr_t map_start[2];
static int setup_valid;
static int releaser_freed[2];

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
  for (size_t i = 0; i < 2; i++) {
    clients[i] = mi_heap_malloc_aligned(shared_heap, REQUEST, 16);
    if (clients[i] != NULL) pages[i] = _mi_ptr_page(clients[i]);
  }
  if (pages[0] != NULL && pages[1] != NULL) {
    arena = mi_memid_arena(pages[0]->memid);
    arena_pages = arena == NULL ? NULL : mi_atomic_load_ptr_acquire(mi_arena_pages_t, &shared_heap->arena_pages[arena->arena_idx]);
    for (size_t i = 0; i < 2; i++) {
      slice_index[i] = pages[i]->memid.mem.arena.slice_index;
      slice_count[i] = pages[i]->memid.mem.arena.slice_count;
      map_count[i] = map_prefix(pages[i], &map_start[i]);
    }
    setup_valid = pages[0] != pages[1] && arena != NULL && arena_pages != NULL;
    for (size_t i = 0; i < 2; i++) {
      setup_valid = setup_valid
          && pages[i]->memid.memkind == MI_MEM_ARENA
          && mi_memid_arena(pages[i]->memid) == arena
          && mi_page_is_singleton(pages[i]) && mi_page_is_in_full(pages[i])
          && pages[i]->block_size == 589824 && pages[i]->used == 1
          && pages[i]->reserved == 1 && slice_count[i] == 9 && map_count[i] == 9
          && mi_bitmap_is_setN(arena_pages->pages, slice_index[i], 1)
          && map_is(pages[i], map_start[i], map_count[i]);
    }
  }
  sem_post(&owner_ready);
  sem_wait(&owner_exit_go);
  mi_thread_done();
  return NULL;
}

static void* releaser(void* argument) {
  const size_t index = *(const size_t*)argument;
  mi_thread_init();
  sem_post(&releaser_ready[index]);
  sem_wait(&releaser_go[index]);
  if (clients[index] != NULL) {
    mi_free(clients[index]);
    releaser_freed[index] = 1;
  }
  mi_thread_done();
  return NULL;
}

int main(void) {
  mi_option_set(mi_option_page_full_retain, -1);
  mi_thread_init();
  void* warmup = mi_malloc(48);
  if (warmup == NULL) return 2;
  mi_free(warmup);
  shared_heap = _mi_theap_heap(_mi_theap_default());
  if (shared_heap == NULL) return 2;
  if (sem_init(&owner_ready, 0, 0) != 0 || sem_init(&owner_exit_go, 0, 0) != 0) return 2;
  for (size_t i = 0; i < 2; i++) {
    if (sem_init(&releaser_ready[i], 0, 0) != 0 || sem_init(&releaser_go[i], 0, 0) != 0) return 2;
  }
  pthread_t source_owner;
  pthread_t survivors[2];
  size_t survivor_index[2] = { 0, 1 };
  if (pthread_create(&source_owner, NULL, owner, NULL) != 0) return 2;
  if (sem_wait(&owner_ready) != 0 || !setup_valid) return 3;
  for (size_t i = 0; i < 2; i++) {
    if (pthread_create(&survivors[i], NULL, releaser, &survivor_index[i]) != 0) return 2;
    if (sem_wait(&releaser_ready[i]) != 0) return 2;
  }
  sem_post(&owner_exit_go);
  if (pthread_join(source_owner, NULL) != 0) return 2;

  int both_unmapped = 1;
  int both_map_registered = 1;
  int both_arena_claimed = 1;
  for (size_t i = 0; i < 2; i++) {
    both_unmapped = both_unmapped && mi_page_is_abandoned(pages[i])
        && !mi_page_is_abandoned_mapped(pages[i]) && !mi_page_is_owned(pages[i]);
    both_map_registered = both_map_registered && map_is(pages[i], map_start[i], map_count[i]);
    both_arena_claimed = both_arena_claimed
        && mi_bitmap_is_setN(arena_pages->pages, slice_index[i], 1);
  }
  if (!both_unmapped || !both_map_registered || !both_arena_claimed) return 4;

  sem_post(&releaser_go[0]);
  if (pthread_join(survivors[0], NULL) != 0) return 2;
  int first_map_clear = map_clear(map_start[0], map_count[0]);
  int first_arena_clear = mi_bitmap_is_clearN(arena_pages->pages, slice_index[0], 1);
  int first_slices_free = mi_bbitmap_is_setN(arena->slices_free, slice_index[0], slice_count[0]);
  int second_retained = map_is(pages[1], map_start[1], map_count[1])
      && mi_bitmap_is_setN(arena_pages->pages, slice_index[1], 1);
  if (!releaser_freed[0] || !first_map_clear || !first_arena_clear
      || !first_slices_free || !second_retained) return 5;

  sem_post(&releaser_go[1]);
  if (pthread_join(survivors[1], NULL) != 0) return 2;
  int second_map_clear = map_clear(map_start[1], map_count[1]);
  int second_arena_clear = mi_bitmap_is_clearN(arena_pages->pages, slice_index[1], 1);
  int second_slices_free = mi_bbitmap_is_setN(arena->slices_free, slice_index[1], slice_count[1]);
  int first_still_clear = map_clear(map_start[0], map_count[0]);
  if (!releaser_freed[1] || !second_map_clear || !second_arena_clear
      || !second_slices_free || !first_still_clear) return 6;

  printf("CRABC_MI_ARENA_SINGLETON_SPLIT_EXIT_BEGIN\n");
  printf("request=%zu\nblock_size=589824\n", (size_t)REQUEST);
  printf("first_slice_count=%zu\nsecond_slice_count=%zu\n", slice_count[0], slice_count[1]);
  printf("first_map_count=%zu\nsecond_map_count=%zu\n", map_count[0], map_count[1]);
  printf("owner_setup_valid=%d\ntwo_releasers_ready=1\nowner_joined_before_free=1\n", setup_valid);
  printf("both_arena_backed=1\nboth_map_registered=%d\n", both_map_registered);
  printf("first_free_completed=%d\nfirst_map_clear=%d\nsecond_retained=%d\n", releaser_freed[0], first_map_clear, second_retained);
  printf("second_free_completed=%d\nsecond_map_clear=%d\nfirst_still_clear=%d\n", releaser_freed[1], second_map_clear, first_still_clear);
  printf("CRABC_MI_ARENA_SINGLETON_SPLIT_EXIT_END\n");
  printf("CRABC_MI_C_SPLIT_ARENA_TRANSITIONS both_unmapped=%d claimed_after_exit=%d first_arena_clear=%d first_slices_free=%d second_arena_clear=%d second_slices_free=%d\n",
      both_unmapped, both_arena_claimed, first_arena_clear, first_slices_free,
      second_arena_clear, second_slices_free);
  return 0;
}
