/* One exiting worker owns an arena medium page and an OS medium page.
   A surviving thread publishes frees to both before separate workers reclaim
   and reuse them; their final frees exercise both terminal release routes. */
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

#define REQUEST (48 * 1024)
#define CLIENTS 9
#define TRACE(name, value) printf(#name "=%lld\n", (long long)(value))

static sem_t owner_ready, owner_go, remote_ready, remote_go, remote_done;
static sem_t arena_ready, arena_go, arena_done, arena_exit;
static sem_t os_ready, os_go, os_done, os_exit;
static sem_t final_go, final_arena_done, final_os_go, final_os_done, remote_exit;
static mi_heap_t* shared_heap;
static void* arena_clients[CLIENTS];
static void* os_clients[CLIENTS];
static void* arena_reuse;
static void* os_reuse;
static void* remote_warm;
static mi_page_t* arena_page;
static mi_page_t* os_page;
static mi_arena_t* arena;
static mi_arena_pages_t* arena_pages;
static size_t arena_slice_index, arena_slice_count, arena_bin;
static uintptr_t arena_map_start, os_map_start;
static size_t arena_map_count, os_map_count;
static size_t os_mapping_size;
static size_t arena_block_size;
static int setup_valid, remote_queue_ready, arena_reclaimed, os_reclaimed;
static int arena_reused, os_reused, remote_first_done, final_arena_freed, final_os_freed;

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

static void* owner(void* unused) {
  (void)unused;
  mi_thread_init();
  for (size_t i = 0; i < CLIENTS; i++) arena_clients[i] = mi_heap_malloc_aligned(shared_heap, REQUEST, 16);
  arena_page = arena_clients[0] == NULL ? NULL : _mi_ptr_page(arena_clients[0]);
  if (arena_page != NULL) {
    arena_block_size = arena_page->block_size;
    arena_map_count = map_prefix(arena_page, &arena_map_start);
    arena = mi_memid_arena(arena_page->memid);
    if (arena != NULL) {
      arena_slice_index = arena_page->memid.mem.arena.slice_index;
      arena_slice_count = arena_page->memid.mem.arena.slice_count;
      arena_pages = mi_atomic_load_ptr_acquire(mi_arena_pages_t,
          &shared_heap->arena_pages[arena->arena_idx]);
      arena_bin = _mi_bin(arena_page->block_size);
    }
  }
  mi_option_set(mi_option_disallow_arena_alloc, 1);
  for (size_t i = 0; i < CLIENTS; i++) os_clients[i] = mi_heap_malloc_aligned(shared_heap, REQUEST, 16);
  os_page = os_clients[0] == NULL ? NULL : _mi_ptr_page(os_clients[0]);
  if (os_page != NULL) {
    os_map_count = map_prefix(os_page, &os_map_start);
    if (os_page->memid.memkind == MI_MEM_OS) os_mapping_size = os_page->memid.mem.os.size;
  }
  setup_valid = arena_page != NULL && os_page != NULL && arena_page != os_page
      && arena != NULL && arena_pages != NULL
      && arena_page->memid.memkind == MI_MEM_ARENA
      && os_page->memid.memkind == MI_MEM_OS
      && arena_page->block_size == 57344 && os_page->block_size == 57344
      && arena_page->reserved == 9 && os_page->reserved == 9
      && arena_page->used == 9 && os_page->used == 9
      && arena_slice_count == 8 && arena_map_count == 8 && os_map_count == 8
      && _mi_ptr_page(arena_clients[8]) == arena_page
      && _mi_ptr_page(os_clients[8]) == os_page
      && mi_page_is_in_full(arena_page) && mi_page_is_in_full(os_page)
      && map_is(arena_page, arena_map_start, arena_map_count)
      && map_is(os_page, os_map_start, os_map_count);
  sem_post(&owner_ready);
  sem_wait(&owner_go);
  mi_thread_done();
  return NULL;
}

static void* remote_survivor(void* unused) {
  (void)unused;
  mi_thread_init();
  remote_warm = mi_heap_malloc_aligned(shared_heap, REQUEST, 16);
  remote_queue_ready = remote_warm != NULL
      && _mi_ptr_page(remote_warm) != arena_page
      && _mi_ptr_page(remote_warm) != os_page
      && mi_page_queue(_mi_theap_default(), 57344)->count == 1;
  sem_post(&remote_ready);
  sem_wait(&remote_go);
  mi_free(arena_clients[0]);
  mi_free(os_clients[0]);
  remote_first_done = 1;
  sem_post(&remote_done);
  sem_wait(&final_go);
  for (size_t i = 2; i < CLIENTS; i++) mi_free(arena_clients[i]);
  mi_free(arena_reuse);
  final_arena_freed = 1;
  sem_post(&final_arena_done);
  sem_wait(&final_os_go);
  for (size_t i = 2; i < CLIENTS; i++) mi_free(os_clients[i]);
  mi_free(os_reuse);
  final_os_freed = 1;
  sem_post(&final_os_done);
  sem_wait(&remote_exit);
  mi_free(remote_warm);
  mi_thread_done();
  return NULL;
}

static void* arena_reclaimer(void* unused) {
  (void)unused;
  mi_thread_init();
  sem_post(&arena_ready);
  sem_wait(&arena_go);
  mi_free(arena_clients[1]);
  arena_reclaimed = arena_page->theap == _mi_theap_default()
      && !mi_page_is_abandoned(arena_page) && arena_page->used == 7;
  arena_reuse = mi_heap_malloc_aligned(shared_heap, REQUEST, 16);
  arena_reused = arena_reuse != NULL && _mi_ptr_page(arena_reuse) == arena_page
      && arena_page->used == 8;
  sem_post(&arena_done);
  sem_wait(&arena_exit);
  mi_thread_done();
  return NULL;
}

static void* os_reclaimer(void* unused) {
  (void)unused;
  mi_thread_init();
  sem_post(&os_ready);
  sem_wait(&os_go);
  mi_free(os_clients[1]);
  os_reclaimed = os_page->theap == _mi_theap_default()
      && !mi_page_is_abandoned(os_page) && os_page->used == 7;
  os_reuse = mi_heap_malloc_aligned(shared_heap, REQUEST, 16);
  os_reused = os_reuse != NULL && _mi_ptr_page(os_reuse) == os_page
      && os_page->used == 8;
  sem_post(&os_done);
  sem_wait(&os_exit);
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
  sem_t* semaphores[] = { &owner_ready, &owner_go, &remote_ready, &remote_go, &remote_done,
      &arena_ready, &arena_go, &arena_done, &arena_exit, &os_ready, &os_go, &os_done,
      &os_exit, &final_go, &final_arena_done, &final_os_go, &final_os_done, &remote_exit };
  for (size_t i = 0; i < sizeof(semaphores)/sizeof(semaphores[0]); i++) {
    if (sem_init(semaphores[i], 0, 0) != 0) return 2;
  }
  pthread_t owner_thread, remote_thread, arena_thread, os_thread;
  if (pthread_create(&owner_thread, NULL, owner, NULL) != 0) return 2;
  if (sem_wait(&owner_ready) != 0 || !setup_valid) {
    fprintf(stderr, "setup: valid=%d arena=%d os=%d arena_used=%zu os_used=%zu\n",
        setup_valid, arena_page == NULL ? -1 : arena_page->memid.memkind,
        os_page == NULL ? -1 : os_page->memid.memkind,
        arena_page == NULL ? 0 : (size_t)arena_page->used,
        os_page == NULL ? 0 : (size_t)os_page->used);
    return 3;
  }
  if (pthread_create(&remote_thread, NULL, remote_survivor, NULL) != 0
      || pthread_create(&arena_thread, NULL, arena_reclaimer, NULL) != 0
      || pthread_create(&os_thread, NULL, os_reclaimer, NULL) != 0) return 2;
  if (sem_wait(&remote_ready) != 0 || sem_wait(&arena_ready) != 0
      || sem_wait(&os_ready) != 0 || !remote_queue_ready) return 3;
  sem_post(&owner_go);
  if (pthread_join(owner_thread, NULL) != 0) return 2;
  int exit_arena_abandoned = mi_page_is_abandoned(arena_page)
      && !mi_page_is_abandoned_mapped(arena_page) && !mi_page_is_owned(arena_page);
  int exit_os_abandoned = mi_page_is_abandoned(os_page)
      && !mi_page_is_abandoned_mapped(os_page) && !mi_page_is_owned(os_page);
  int exit_os_list = shared_heap->os_abandoned_pages == os_page;
  int exit_arena_bitmap = mi_bitmap_is_setN(arena_pages->pages_abandoned[arena_bin], arena_slice_index, 1);
  if (!exit_arena_abandoned || !exit_os_abandoned || !exit_os_list || exit_arena_bitmap) return 4;

  sem_post(&remote_go);
  if (sem_wait(&remote_done) != 0) return 2;
  int first_remote_class = remote_first_done && arena_page->used == 8 && os_page->used == 8
      && mi_page_thread_free(arena_page) == NULL && mi_page_thread_free(os_page) == NULL
      && mi_page_is_abandoned(arena_page) && mi_page_is_abandoned(os_page)
      && shared_heap->os_abandoned_pages == os_page;
  if (!first_remote_class) return 5;

  sem_post(&arena_go);
  if (sem_wait(&arena_done) != 0) return 2;
  int arena_map_after_reclaim = map_is(arena_page, arena_map_start, arena_map_count);
  int os_list_while_arena_reclaimed = shared_heap->os_abandoned_pages == os_page;
  if (!arena_reclaimed || !arena_reused || !arena_map_after_reclaim
      || !os_list_while_arena_reclaimed) return 6;
  sem_post(&os_go);
  if (sem_wait(&os_done) != 0) return 2;
  int os_map_after_reclaim = map_is(os_page, os_map_start, os_map_count);
  int os_list_after_reclaim_empty = shared_heap->os_abandoned_pages == NULL;
  if (!os_reclaimed || !os_reused || !os_map_after_reclaim || !os_list_after_reclaim_empty) return 7;

  sem_post(&arena_exit);
  sem_post(&os_exit);
  if (pthread_join(arena_thread, NULL) != 0 || pthread_join(os_thread, NULL) != 0) return 2;
  int reexit_arena_bitmap = mi_bitmap_is_setN(arena_pages->pages_abandoned[arena_bin], arena_slice_index, 1);
  int reexit_os_list = shared_heap->os_abandoned_pages == os_page;
  int reexit_both_mapped = mi_page_is_abandoned_mapped(arena_page)
      && !mi_page_is_abandoned_mapped(os_page)
      && map_is(arena_page, arena_map_start, arena_map_count)
      && map_is(os_page, os_map_start, os_map_count);
  if (!reexit_arena_bitmap || !reexit_os_list || !reexit_both_mapped) return 8;

  mi_subproc_t* subproc = _mi_subproc_main();
  int64_t reserved_before_final = subproc->stats.reserved.current;
  int64_t committed_before_final = subproc->stats.committed.current;
  sem_post(&final_go);
  if (sem_wait(&final_arena_done) != 0) return 2;
  int arena_map_clear = map_clear(arena_map_start, arena_map_count);
  int os_map_retained = map_is(os_page, os_map_start, os_map_count);
  int arena_bitmap_final_clear = mi_bitmap_is_clearN(arena_pages->pages_abandoned[arena_bin], arena_slice_index, 1);
  size_t arena_free_after_final = count_bbitmap(arena->slices_free, arena_slice_index, arena_slice_count);
  size_t arena_committed_after_final = count_bitmap(arena->slices_committed, arena_slice_index, arena_slice_count);
  size_t arena_purge_after_final = count_bitmap(arena->slices_purge, arena_slice_index, arena_slice_count);
  int64_t reserved_after_arena_final = subproc->stats.reserved.current;
  int64_t committed_after_arena_final = subproc->stats.committed.current;
  if (!arena_map_clear || !os_map_retained || !arena_bitmap_final_clear) return 9;

  sem_post(&final_os_go);
  if (sem_wait(&final_os_done) != 0) return 2;
  int os_map_clear = map_clear(os_map_start, os_map_count);
  int os_list_final_empty = shared_heap->os_abandoned_pages == NULL;
  int64_t reserved_after_os_final = subproc->stats.reserved.current;
  int64_t committed_after_os_final = subproc->stats.committed.current;
  if (!os_map_clear || !os_list_final_empty) return 10;
  sem_post(&remote_exit);
  if (pthread_join(remote_thread, NULL) != 0) return 2;
  mi_collect(true);
  size_t arena_purge_after_collect = count_bitmap(arena->slices_purge, arena_slice_index, arena_slice_count);

  printf("CRABC_MI_MIXED_MEDIUM_PRE_RECLAIM_BEGIN\n");
  TRACE(request, REQUEST); TRACE(block_size, arena_block_size);
  TRACE(arena_map_count, arena_map_count); TRACE(os_map_count, os_map_count);
  TRACE(arena_slice_count, arena_slice_count); TRACE(os_mapping_size, os_mapping_size);
  TRACE(setup_valid, setup_valid); TRACE(remote_queue_ready, remote_queue_ready);
  TRACE(exit_arena_abandoned, exit_arena_abandoned); TRACE(exit_os_abandoned, exit_os_abandoned);
  TRACE(exit_os_list, exit_os_list); TRACE(exit_arena_bitmap, exit_arena_bitmap);
  TRACE(first_remote_class, first_remote_class);
  TRACE(arena_reclaimed, arena_reclaimed); TRACE(arena_reused, arena_reused);
  TRACE(arena_map_after_reclaim, arena_map_after_reclaim);
  TRACE(os_list_while_arena_reclaimed, os_list_while_arena_reclaimed);
  TRACE(os_reclaimed, os_reclaimed); TRACE(os_reused, os_reused);
  TRACE(os_map_after_reclaim, os_map_after_reclaim);
  TRACE(os_list_after_reclaim_empty, os_list_after_reclaim_empty);
  TRACE(reexit_arena_bitmap, reexit_arena_bitmap); TRACE(reexit_os_list, reexit_os_list);
  TRACE(reexit_both_mapped, reexit_both_mapped);
  TRACE(final_arena_freed, final_arena_freed); TRACE(arena_map_clear, arena_map_clear);
  TRACE(os_map_retained, os_map_retained); TRACE(arena_bitmap_final_clear, arena_bitmap_final_clear);
  TRACE(arena_free_after_final, arena_free_after_final);
  TRACE(arena_committed_after_final, arena_committed_after_final);
  TRACE(arena_purge_after_final, arena_purge_after_final);
  TRACE(arena_reserved_drop, reserved_before_final - reserved_after_arena_final);
  TRACE(arena_committed_drop, committed_before_final - committed_after_arena_final);
  TRACE(final_os_freed, final_os_freed); TRACE(os_map_clear, os_map_clear);
  TRACE(os_list_final_empty, os_list_final_empty);
  TRACE(os_reserved_drop, reserved_after_arena_final - reserved_after_os_final);
  TRACE(os_committed_drop, committed_after_arena_final - committed_after_os_final);
  TRACE(arena_purge_after_collect, arena_purge_after_collect);
  TRACE(warning_enabled, mi_option_is_enabled(mi_option_show_errors));
  printf("CRABC_MI_MIXED_MEDIUM_PRE_RECLAIM_END\n");
  return arena_free_after_final == arena_slice_count
      && arena_committed_after_final == arena_slice_count
      && arena_purge_after_final == arena_slice_count
      && reserved_before_final == reserved_after_arena_final
      && committed_before_final == committed_after_arena_final
      && reserved_after_arena_final - reserved_after_os_final == (int64_t)os_mapping_size
      && committed_after_arena_final - committed_after_os_final == (int64_t)(os_map_count * MI_ARENA_SLICE_SIZE)
      && arena_purge_after_collect == 0 ? 0 : 11;
}
