/* A remote free reaches an abandoned OS medium page before any new Theap
   reclaims it. Another survivor then reuses that page and exits before the
   first survivor releases its final clients. */
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

#define REQUEST (48 * 1024)
#define CLIENTS 9

static sem_t owner_ready, owner_go;
static sem_t reclaimer_ready, reclaimer_go, reclaimer_phase_done, reclaimer_resume;
static sem_t remote_ready, remote_first_go, remote_first_done, remote_late_go, remote_late_done, remote_final_go;
static mi_heap_t* shared_heap;
static void* clients[CLIENTS];
static void* reused[2];
static void* remote_warm;
static mi_page_t* page;
static uintptr_t map_start;
static size_t map_count, reserved, block_size;
static int setup_valid;
static int second_reclaimed_on_free, first_reuse_same_page;
static int late_remote_pending, used_before_collect, used_after_collect;
static int second_reuse_same_page, late_remote_head_cleared;
static mi_theap_t* reclaimer_theap;
static int first_remote_completed, late_remote_completed, final_frees_completed;
static int remote_queue_blocks_first_reclaim;

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
        && _mi_ptr_page(clients[1]) == page && _mi_ptr_page(clients[8]) == page
        && page->used == 9 && page->reserved == 9
        && !mi_page_is_singleton(page) && mi_page_is_in_full(page)
        && page->block_size == 57344 && map_count == 8
        && queue->count == 0
        && map_is(page, map_start, map_count);
  }
  sem_post(&owner_ready);
  sem_wait(&owner_go);
  mi_thread_done();
  return NULL;
}

static void* reclaimer(void* unused) {
  (void)unused;
  mi_thread_init();
  reclaimer_theap = _mi_theap_default();
  sem_post(&reclaimer_ready);
  sem_wait(&reclaimer_go);
  mi_free(clients[1]);
  second_reclaimed_on_free = !mi_page_is_abandoned(page)
      && page->theap == reclaimer_theap && page->used == 7;
  reused[0] = mi_heap_malloc_aligned(shared_heap, REQUEST, 16);
  first_reuse_same_page = reused[0] != NULL && _mi_ptr_page(reused[0]) == page;
  sem_post(&reclaimer_phase_done);
  sem_wait(&reclaimer_resume);
  used_before_collect = page->used;
  mi_collect(false);
  used_after_collect = page->used;
  reused[1] = mi_heap_malloc_aligned(shared_heap, REQUEST, 16);
  second_reuse_same_page = reused[1] != NULL && _mi_ptr_page(reused[1]) == page;
  late_remote_head_cleared = mi_page_thread_free(page) == NULL;
  mi_thread_done();
  return NULL;
}

static void* remote_survivor(void* unused) {
  (void)unused;
  mi_thread_init();
  remote_warm = mi_heap_malloc_aligned(shared_heap, REQUEST, 16);
  remote_queue_blocks_first_reclaim = remote_warm != NULL
      && _mi_ptr_page(remote_warm) != page
      && mi_page_queue(_mi_theap_default(), block_size)->count == 1;
  sem_post(&remote_ready);
  sem_wait(&remote_first_go);
  mi_free(clients[0]);
  first_remote_completed = 1;
  sem_post(&remote_first_done);
  sem_wait(&remote_late_go);
  mi_free(clients[2]);
  late_remote_completed = 1;
  sem_post(&remote_late_done);
  sem_wait(&remote_final_go);
  for (size_t i = 3; i < CLIENTS; i++) mi_free(clients[i]);
  mi_free(reused[0]);
  mi_free(reused[1]);
  mi_free(remote_warm);
  final_frees_completed = 1;
  mi_thread_done();
  return NULL;
}

int main(void) {
  mi_option_set(mi_option_disallow_arena_alloc, 1);
  mi_option_set(mi_option_page_full_retain, -1);
  mi_option_set(mi_option_page_reclaim_on_free, 1);
  mi_thread_init();
  void* warmup = mi_malloc(48);
  if (warmup == NULL) return 2;
  mi_free(warmup);
  shared_heap = _mi_theap_heap(_mi_theap_default());
  if (shared_heap == NULL) return 2;
  sem_t* semaphores[] = { &owner_ready, &owner_go, &reclaimer_ready, &reclaimer_go,
      &reclaimer_phase_done, &reclaimer_resume, &remote_ready, &remote_first_go,
      &remote_first_done, &remote_late_go, &remote_late_done, &remote_final_go };
  for (size_t i = 0; i < sizeof(semaphores)/sizeof(semaphores[0]); i++) {
    if (sem_init(semaphores[i], 0, 0) != 0) return 2;
  }
  pthread_t initial, reclaiming, remote;
  if (pthread_create(&initial, NULL, owner, NULL) != 0) return 2;
  if (sem_wait(&owner_ready) != 0 || !setup_valid) {
    fprintf(stderr, "setup: valid=%d block=%zu reserved=%zu used=%zu full=%d map=%zu\n",
        setup_valid, block_size, reserved, page == NULL ? 0 : (size_t)page->used,
        page == NULL ? -1 : mi_page_is_in_full(page), map_count);
    return 3;
  }
  if (pthread_create(&reclaiming, NULL, reclaimer, NULL) != 0) return 2;
  if (pthread_create(&remote, NULL, remote_survivor, NULL) != 0) return 2;
  if (sem_wait(&reclaimer_ready) != 0 || sem_wait(&remote_ready) != 0
      || !remote_queue_blocks_first_reclaim) return 2;
  sem_post(&owner_go);
  if (pthread_join(initial, NULL) != 0) return 2;
  int abandoned_after_exit = mi_page_is_abandoned(page) && !mi_page_is_abandoned_mapped(page)
      && !mi_page_is_owned(page) && page->used == 9;
  int registered_after_exit = map_is(page, map_start, map_count);
  int os_list_after_exit = shared_heap->os_abandoned_pages == page;
  if (!abandoned_after_exit || !registered_after_exit || !os_list_after_exit) return 4;

  sem_post(&remote_first_go);
  if (sem_wait(&remote_first_done) != 0) return 2;
  int abandoned_after_first_remote = mi_page_is_abandoned(page)
      && !mi_page_is_abandoned_mapped(page) && !mi_page_is_owned(page);
  int registered_after_first_remote = map_is(page, map_start, map_count);
  int used_after_first_remote = page->used;
  int mostly_used_after_first_remote = mi_page_is_mostly_used(page);
  int first_remote_head_cleared = mi_page_thread_free(page) == NULL;
  int os_list_after_first_remote = shared_heap->os_abandoned_pages == page;
  if (!first_remote_completed || !abandoned_after_first_remote
      || !registered_after_first_remote || used_after_first_remote != 8
      || !first_remote_head_cleared || !mostly_used_after_first_remote
      || !os_list_after_first_remote) {
    fprintf(stderr, "first remote: completed=%d abandoned=%d registered=%d used=%d head_clear=%d os_list=%d owned=%d\n",
        first_remote_completed, abandoned_after_first_remote,
        registered_after_first_remote, used_after_first_remote,
        first_remote_head_cleared, os_list_after_first_remote,
        mi_page_is_owned(page));
    return 5;
  }

  sem_post(&reclaimer_go);
  if (sem_wait(&reclaimer_phase_done) != 0) return 2;
  int registered_after_first_reuse = map_is(page, map_start, map_count);
  int first_used_eight = page->used == 8;
  int os_list_empty_after_reclaim = shared_heap->os_abandoned_pages == NULL;
  if (!second_reclaimed_on_free || !first_reuse_same_page || !first_used_eight
      || !registered_after_first_reuse || !os_list_empty_after_reclaim) {
    fprintf(stderr, "reclaim: selected=%d owner=%d abandoned=%d used=%zu list_empty=%d map=%d\n",
        first_reuse_same_page, page->theap == reclaimer_theap,
        mi_page_is_abandoned(page), (size_t)page->used,
        os_list_empty_after_reclaim, registered_after_first_reuse);
    return 6;
  }

  sem_post(&remote_late_go);
  if (sem_wait(&remote_late_done) != 0) return 2;
  late_remote_pending = mi_page_thread_free(page) != NULL && page->used == 8;
  if (!late_remote_pending) return 7;

  sem_post(&reclaimer_resume);
  if (pthread_join(reclaiming, NULL) != 0) return 2;
  int abandoned_after_reclaimer_exit = mi_page_is_abandoned(page)
      && !mi_page_is_abandoned_mapped(page) && !mi_page_is_owned(page);
  int registered_after_reclaimer_exit = map_is(page, map_start, map_count);
  int live_after_reclaimer_exit = page->used == 8;
  int os_list_after_reclaimer_exit = shared_heap->os_abandoned_pages == page;
  if (!abandoned_after_reclaimer_exit || !registered_after_reclaimer_exit
      || !live_after_reclaimer_exit || !second_reuse_same_page
      || !os_list_after_reclaimer_exit) return 8;

  sem_post(&remote_final_go);
  if (pthread_join(remote, NULL) != 0) return 2;
  int terminal_map_clear = map_clear(map_start, map_count);
  int terminal_region_clear = !mi_is_in_heap_region(clients[8]);
  int os_list_empty_after_final = shared_heap->os_abandoned_pages == NULL;

  printf("CRABC_MI_OS_MEDIUM_PRE_RECLAIM_REMOTE_BEGIN\n");
  printf("request=%zu\nblock_size=%zu\nreserved=%zu\nmap_count=%zu\n",
      (size_t)REQUEST, block_size, reserved, map_count);
  printf("owner_setup_valid=%d\ntwo_survivors_ready=1\nabandoned_after_exit=%d\nregistered_after_exit=%d\n",
      setup_valid, abandoned_after_exit, registered_after_exit);
  printf("remote_queue_blocks_first_reclaim=%d\nfirst_remote_completed=%d\nabandoned_after_first_remote=%d\nregistered_after_first_remote=%d\nused_after_first_remote=%d\nfirst_remote_head_cleared=%d\n",
      remote_queue_blocks_first_reclaim, first_remote_completed,
      abandoned_after_first_remote, registered_after_first_remote,
      used_after_first_remote, first_remote_head_cleared);
  printf("second_reclaimed_on_free=%d\nfirst_reuse_same_page=%d\nregistered_after_first_reuse=%d\nfirst_used_eight=%d\n",
      second_reclaimed_on_free, first_reuse_same_page,
      registered_after_first_reuse, first_used_eight);
  printf("late_remote_pending=%d\nused_before_collect=%d\nused_after_collect=%d\nsecond_reuse_same_page=%d\nlate_remote_head_cleared=%d\n",
      late_remote_pending, used_before_collect, used_after_collect,
      second_reuse_same_page, late_remote_head_cleared);
  printf("abandoned_after_reclaimer_exit=%d\nregistered_after_reclaimer_exit=%d\nlive_after_reclaimer_exit=%d\n",
      abandoned_after_reclaimer_exit, registered_after_reclaimer_exit,
      live_after_reclaimer_exit);
  printf("remote_and_final_frees=%d\nterminal_map_clear=%d\nterminal_region_clear=%d\n",
      first_remote_completed && late_remote_completed && final_frees_completed,
      terminal_map_clear,
      terminal_region_clear);
  printf("CRABC_MI_OS_MEDIUM_PRE_RECLAIM_REMOTE_END\n");
  printf("CRABC_MI_C_OS_MEDIUM_STATE os_list_after_exit=%d os_list_after_first_remote=%d mostly_used_after_first_remote=%d os_list_empty_after_reclaim=%d os_list_after_reclaimer_exit=%d os_list_empty_after_final=%d\n",
      os_list_after_exit, os_list_after_first_remote, mostly_used_after_first_remote,
      os_list_empty_after_reclaim,
      os_list_after_reclaimer_exit, os_list_empty_after_final);
  return terminal_map_clear && terminal_region_clear && os_list_empty_after_final ? 0 : 9;
}
