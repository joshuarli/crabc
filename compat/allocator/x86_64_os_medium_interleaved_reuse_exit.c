/* A worker reclaims an OS-backed medium page after its first owner exits.
   A second survivor frees remotely while that new owner is active; the new
   owner collects and reuses the page before exiting, then the second survivor
   releases every remaining client. */
#include "mimalloc/internal.h"
#include "mimalloc/prim-tls.h"
#include <pthread.h>
#include <semaphore.h>
#include <stdio.h>

#if !defined(__linux__) || !defined(__x86_64__)
#error this private source fixture requires native Linux/x86-64
#endif
#if MI_BUILD_RELEASE != 1 || MI_DEBUG != 0 || MI_STAT != 0 || MI_SECURE != 0 || MI_GUARDED != 0
#error this fixture requires the pinned release configuration
#endif

#define REQUEST (64 * 1024)
#define CLIENTS 3

static sem_t owner_ready, owner_go;
static sem_t first_ready, first_go, first_phase_done, first_resume;
static sem_t second_ready, second_remote_go, second_remote_done, second_final_go;
static mi_heap_t* shared_heap;
static void* clients[CLIENTS];
static void* reused[2];
static mi_page_t* page;
static uintptr_t map_start;
static size_t map_count, reserved, block_size;
static int setup_valid;
static int first_reclaimed, first_reuse_same_page;
static int remote_pending, used_before_collect, used_after_collect;
static int second_reuse_same_page, remote_head_cleared;
static int second_free_completed[4];

static size_t map_prefix(mi_page_t* selected, uintptr_t* start) {
  size_t area_size = 0;
  uint8_t* area = mi_page_area(selected, &area_size);
  uint8_t* slice = mi_page_slice_start(selected);
  if (area == NULL || slice == NULL || area < slice || area_size > MI_LARGE_PAGE_SIZE) return 0;
  *start = (uintptr_t)slice;
  return mi_slice_count_of_size(area_size) + (size_t)(area - slice) / MI_ARENA_SLICE_SIZE;
}

static int map_is(mi_page_t* selected, uintptr_t start, size_t count) {
  if (count == 0) return 0;
  for (size_t i = 0; i < count; i++) {
    if (_mi_safe_ptr_page((void*)(start + i * MI_ARENA_SLICE_SIZE)) != selected) return 0;
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

static void* owner(void* unused) {
  (void)unused;
  mi_thread_init();
  for (size_t i = 0; i < CLIENTS; i++) clients[i] = mi_heap_malloc_aligned(shared_heap, REQUEST, 16);
  if (clients[0] != NULL) page = _mi_ptr_page(clients[0]);
  if (page != NULL) {
    map_count = map_prefix(page, &map_start);
    reserved = page->reserved;
    block_size = page->block_size;
    mi_page_queue_t* queue = mi_page_queue(page->theap, page->block_size);
    setup_valid = mi_option_get(mi_option_disallow_arena_alloc) == 1
        && page->memid.memkind == MI_MEM_OS
        && _mi_ptr_page(clients[1]) == page && _mi_ptr_page(clients[2]) == page
        && page->used == 3 && page->reserved == 6
        && !mi_page_is_singleton(page) && !mi_page_is_in_full(page)
        && page->block_size == 81920 && map_count == 8
        && queue->first == page && queue->count == 1
        && map_is(page, map_start, map_count);
  }
  sem_post(&owner_ready);
  sem_wait(&owner_go);
  mi_thread_done();
  return NULL;
}

static void* first_survivor(void* unused) {
  (void)unused;
  mi_thread_init();
  sem_post(&first_ready);
  sem_wait(&first_go);
  mi_free(clients[0]);
  first_reclaimed = !mi_page_is_abandoned(page) && mi_page_is_owned(page)
      && page->used == 2;
  reused[0] = mi_heap_malloc_aligned(shared_heap, REQUEST, 16);
  first_reuse_same_page = reused[0] != NULL && _mi_ptr_page(reused[0]) == page;
  sem_post(&first_phase_done);
  sem_wait(&first_resume);
  used_before_collect = page->used;
  mi_collect(false);
  used_after_collect = page->used;
  reused[1] = mi_heap_malloc_aligned(shared_heap, REQUEST, 16);
  second_reuse_same_page = reused[1] != NULL && _mi_ptr_page(reused[1]) == page;
  remote_head_cleared = mi_page_thread_free(page) == NULL;
  mi_thread_done();
  return NULL;
}

static void* second_survivor(void* unused) {
  (void)unused;
  mi_thread_init();
  sem_post(&second_ready);
  sem_wait(&second_remote_go);
  mi_free(clients[1]);
  second_free_completed[0] = 1;
  sem_post(&second_remote_done);
  sem_wait(&second_final_go);
  mi_free(clients[2]);
  second_free_completed[1] = 1;
  mi_free(reused[0]);
  second_free_completed[2] = 1;
  mi_free(reused[1]);
  second_free_completed[3] = 1;
  mi_thread_done();
  return NULL;
}

int main(void) {
  mi_option_set(mi_option_disallow_arena_alloc, 1);
  mi_option_set(mi_option_page_full_retain, -1);
  mi_thread_init();
  void* warmup = mi_malloc(48);
  if (warmup == NULL) return 2;
  mi_free(warmup);
  shared_heap = _mi_theap_heap(_mi_theap_default());
  if (shared_heap == NULL) return 2;
  sem_t* semaphores[] = { &owner_ready, &owner_go, &first_ready, &first_go,
      &first_phase_done, &first_resume, &second_ready, &second_remote_go,
      &second_remote_done, &second_final_go };
  for (size_t i = 0; i < sizeof(semaphores)/sizeof(semaphores[0]); i++) {
    if (sem_init(semaphores[i], 0, 0) != 0) return 2;
  }
  pthread_t initial, first, second;
  if (pthread_create(&initial, NULL, owner, NULL) != 0) return 2;
  if (sem_wait(&owner_ready) != 0 || !setup_valid) return 3;
  if (pthread_create(&first, NULL, first_survivor, NULL) != 0) return 2;
  if (pthread_create(&second, NULL, second_survivor, NULL) != 0) return 2;
  if (sem_wait(&first_ready) != 0 || sem_wait(&second_ready) != 0) return 2;
  sem_post(&owner_go);
  if (pthread_join(initial, NULL) != 0) return 2;
  int abandoned_after_exit = mi_page_is_abandoned(page) && !mi_page_is_abandoned_mapped(page)
      && !mi_page_is_owned(page) && page->used == 3;
  int registered_after_exit = map_is(page, map_start, map_count);
  int os_list_after_exit = shared_heap->os_abandoned_pages == page;
  if (!abandoned_after_exit || !registered_after_exit || !os_list_after_exit) return 4;

  sem_post(&first_go);
  if (sem_wait(&first_phase_done) != 0) return 2;
  int registered_after_first_reuse = map_is(page, map_start, map_count);
  int first_used_three = page->used == 3;
  int os_list_empty_after_reclaim = shared_heap->os_abandoned_pages == NULL;
  if (!first_reclaimed || !first_reuse_same_page || !first_used_three
      || !os_list_empty_after_reclaim) return 5;

  sem_post(&second_remote_go);
  if (sem_wait(&second_remote_done) != 0) return 2;
  remote_pending = mi_page_thread_free(page) != NULL && page->used == 3;
  if (!remote_pending) return 6;

  sem_post(&first_resume);
  if (pthread_join(first, NULL) != 0) return 2;
  int abandoned_after_reuser_exit = mi_page_is_abandoned(page)
      && !mi_page_is_abandoned_mapped(page) && !mi_page_is_owned(page);
  int registered_after_reuser_exit = map_is(page, map_start, map_count);
  int live_after_reuser_exit = page->used == 3;
  int os_list_after_reuser_exit = shared_heap->os_abandoned_pages == page;
  if (!abandoned_after_reuser_exit || !registered_after_reuser_exit
      || !live_after_reuser_exit || !second_reuse_same_page
      || !os_list_after_reuser_exit) return 7;

  sem_post(&second_final_go);
  if (pthread_join(second, NULL) != 0) return 2;
  int terminal_map_clear = map_clear(map_start, map_count);
  int terminal_region_clear = !mi_is_in_heap_region(clients[2]);
  int os_list_empty_after_final = shared_heap->os_abandoned_pages == NULL;

  printf("CRABC_MI_OS_MEDIUM_INTERLEAVED_REUSE_BEGIN\n");
  printf("request=%zu\nblock_size=%zu\nreserved=%zu\nmap_count=%zu\n",
      (size_t)REQUEST, block_size, reserved, map_count);
  printf("owner_setup_valid=%d\ntwo_survivors_ready=1\nabandoned_after_exit=%d\nregistered_after_exit=%d\n",
      setup_valid, abandoned_after_exit, registered_after_exit);
  printf("first_reclaimed=%d\nfirst_reuse_same_page=%d\nregistered_after_first_reuse=%d\nfirst_used_three=%d\n",
      first_reclaimed, first_reuse_same_page, registered_after_first_reuse,
      first_used_three);
  printf("remote_pending=%d\nused_before_collect=%d\nused_after_collect=%d\nsecond_reuse_same_page=%d\nremote_head_cleared=%d\n",
      remote_pending, used_before_collect, used_after_collect,
      second_reuse_same_page, remote_head_cleared);
  printf("abandoned_after_reuser_exit=%d\nregistered_after_reuser_exit=%d\nlive_after_reuser_exit=%d\n",
      abandoned_after_reuser_exit, registered_after_reuser_exit,
      live_after_reuser_exit);
  printf("remote_and_final_frees=%d\nterminal_map_clear=%d\nterminal_region_clear=%d\n",
      second_free_completed[0] && second_free_completed[1] && second_free_completed[2]
          && second_free_completed[3], terminal_map_clear,
      terminal_region_clear);
  printf("CRABC_MI_OS_MEDIUM_INTERLEAVED_REUSE_END\n");
  printf("CRABC_MI_C_OS_MEDIUM_STATE os_list_after_exit=%d os_list_empty_after_reclaim=%d os_list_after_reuser_exit=%d os_list_empty_after_final=%d\n",
      os_list_after_exit, os_list_empty_after_reclaim,
      os_list_after_reuser_exit, os_list_empty_after_final);
  return terminal_map_clear && terminal_region_clear && os_list_empty_after_final ? 0 : 8;
}
