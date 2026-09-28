/* A later owner abandons two nonfull regular pages. A surviving thread's
   large free reabandons its mapped page while its medium free reclaims the
   regular queue; their final releases remain independent. */
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

#define LARGE_REQUEST (MI_MEDIUM_MAX_OBJ_SIZE + 64 * 1024)
#define MEDIUM_REQUEST (64 * 1024)

static sem_t ready;
static sem_t exit_go;
static void* large_client[2];
static void* medium_client[2];
static mi_page_t* large_page;
static mi_page_t* medium_page;
static size_t large_reserved;
static size_t medium_reserved;
static size_t large_slice_count;
static size_t medium_slice_count;
static size_t large_registered_slice_count;
static size_t medium_registered_slice_count;
static int owner_queues_valid;

static size_t source_registered_slices(mi_page_t* page) {
  size_t area_size = 0;
  uint8_t* area = mi_page_area(page, &area_size);
  uint8_t* slice_start = mi_page_slice_start(page);
  if (area == NULL || slice_start == NULL || area < slice_start) return 0;
  if (area_size > MI_LARGE_PAGE_SIZE) area_size = MI_LARGE_PAGE_SIZE - MI_ARENA_SLICE_SIZE;
  return mi_slice_count_of_size(area_size)
      + (size_t)(area - slice_start) / MI_ARENA_SLICE_SIZE;
}

static void* owner(void* ignored) {
  (void)ignored;
  mi_thread_init();
  for (size_t i = 0; i < 2; i++) {
    large_client[i] = mi_malloc_aligned(LARGE_REQUEST, 16);
    medium_client[i] = mi_malloc_aligned(MEDIUM_REQUEST, 16);
  }
  if (large_client[0] != NULL && medium_client[0] != NULL) {
    large_page = _mi_ptr_page(large_client[0]);
    medium_page = _mi_ptr_page(medium_client[0]);
  }
  if (large_page != NULL && medium_page != NULL) {
    large_reserved = large_page->reserved;
    medium_reserved = medium_page->reserved;
    large_slice_count = large_page->memid.mem.arena.slice_count;
    medium_slice_count = medium_page->memid.mem.arena.slice_count;
    large_registered_slice_count = source_registered_slices(large_page);
    medium_registered_slice_count = source_registered_slices(medium_page);
    mi_page_queue_t* large_queue = mi_page_queue(large_page->theap, large_page->block_size);
    mi_page_queue_t* medium_queue = mi_page_queue(medium_page->theap, medium_page->block_size);
    owner_queues_valid = _mi_ptr_page(large_client[1]) == large_page
        && _mi_ptr_page(medium_client[1]) == medium_page
        && large_page != medium_page
        && large_page->block_size > MI_MEDIUM_MAX_OBJ_SIZE
        && large_page->block_size <= MI_LARGE_MAX_OBJ_SIZE
        && medium_page->block_size > MI_SMALL_MAX_OBJ_SIZE
        && medium_page->block_size <= MI_MEDIUM_MAX_OBJ_SIZE
        && large_page->memid.memkind == MI_MEM_ARENA
        && medium_page->memid.memkind == MI_MEM_ARENA
        && large_page->used == 2 && medium_page->used == 2
        && large_reserved > 2 && medium_reserved > 2
        && large_registered_slice_count > 0 && large_registered_slice_count <= large_slice_count
        && medium_registered_slice_count > 0 && medium_registered_slice_count <= medium_slice_count
        && !mi_page_is_in_full(large_page) && !mi_page_is_in_full(medium_page)
        && large_queue->first == large_page && large_queue->count == 1
        && medium_queue->first == medium_page && medium_queue->count == 1;
  }
  sem_post(&ready);
  sem_wait(&exit_go);
  mi_thread_done();
  return NULL;
}

int main(void) {
  mi_option_set(mi_option_page_full_retain, -1);
  mi_thread_init();
  void* warmup = mi_malloc(48);
  if (warmup == NULL) return 2;
  mi_free(warmup);
  if (sem_init(&ready, 0, 0) != 0 || sem_init(&exit_go, 0, 0) != 0) return 2;
  pthread_t worker;
  if (pthread_create(&worker, NULL, owner, NULL) != 0) return 2;
  if (sem_wait(&ready) != 0) return 2;
  if (!owner_queues_valid) return 3;
  sem_post(&exit_go);
  if (pthread_join(worker, NULL) != 0) return 2;
  int large_mapped_after_exit = mi_page_is_abandoned_mapped(large_page);
  int medium_mapped_after_exit = mi_page_is_abandoned_mapped(medium_page);
  int large_unowned_after_exit = !mi_page_is_owned(large_page);
  int medium_unowned_after_exit = !mi_page_is_owned(medium_page);
  int large_registered_after_exit = _mi_safe_ptr_page(large_client[1]) == large_page;
  int medium_registered_after_exit = _mi_safe_ptr_page(medium_client[1]) == medium_page;
  printf("CRABC_MI_C_SOURCE_MAPPED_STATE large_mapped=%d medium_mapped=%d large_unowned=%d medium_unowned=%d\n",
      large_mapped_after_exit, medium_mapped_after_exit,
      large_unowned_after_exit, medium_unowned_after_exit);
  if (!large_mapped_after_exit || !medium_mapped_after_exit
      || !large_unowned_after_exit || !medium_unowned_after_exit) return 4;

  mi_free(large_client[0]);
  int large_reabandoned = _mi_safe_ptr_page(large_client[1]) == large_page
      && large_page->used == 1 && mi_page_is_abandoned_mapped(large_page)
      && !mi_page_is_owned(large_page);
  printf("CRABC_MI_C_SOURCE_LARGE_FIRST_FREE mapped=%d unowned=%d used=%zu\n",
      mi_page_is_abandoned_mapped(large_page), !mi_page_is_owned(large_page), large_page->used);
  if (!large_reabandoned) return 6;
  mi_free(medium_client[0]);
  mi_page_queue_t* medium_queue = mi_page_queue(_mi_theap_default(), medium_page->block_size);
  int medium_requeued = _mi_safe_ptr_page(medium_client[1]) == medium_page
      && medium_page->used == 1 && medium_page->theap == _mi_theap_default()
      && !mi_page_is_abandoned(medium_page) && mi_page_is_owned(medium_page)
      && medium_queue->first == medium_page && medium_queue->count == 1;

  mi_free(large_client[1]);
  int large_released_on_final = !mi_is_in_heap_region(large_client[1]);
  int medium_registered_after_large_final = _mi_safe_ptr_page(medium_client[1]) == medium_page;
  mi_free(medium_client[1]);
  mi_page_t* large_after_final = _mi_safe_ptr_page(large_client[1]);
  mi_page_t* medium_after_final = _mi_safe_ptr_page(medium_client[1]);
  int large_registered_before_collect = large_after_final == large_page;
  int medium_registered_before_collect = medium_after_final == medium_page;
  size_t large_used_before_collect = large_registered_before_collect ? large_page->used : (size_t)-1;
  size_t medium_used_before_collect = medium_registered_before_collect ? medium_page->used : (size_t)-1;
  unsigned large_expire_before_collect = large_registered_before_collect ? large_page->retire_expire : 0;
  unsigned medium_expire_before_collect = medium_registered_before_collect ? medium_page->retire_expire : 0;
  int medium_retired = medium_registered_before_collect
      && medium_used_before_collect == 0 && medium_expire_before_collect == 4;
  printf("CRABC_MI_C_SOURCE_FINAL_STATE large_registered=%d large_used=%zu large_expire=%u medium_registered=%d medium_used=%zu medium_expire=%u\n",
      large_registered_before_collect, large_used_before_collect, large_expire_before_collect,
      medium_registered_before_collect, medium_used_before_collect, medium_expire_before_collect);
  if (large_registered_before_collect || !medium_retired) return 5;
  mi_collect(true);
  int large_released = !mi_is_in_heap_region(large_client[1]);
  int medium_released = !mi_is_in_heap_region(medium_client[1]);
  void* survivor = mi_malloc(64);
  int survivor_usable = survivor != NULL;
  mi_free(survivor);
  printf("CRABC_MI_MAPPED_LARGE_OWNER_EXIT_BEGIN\n");
  printf("full_retain=%ld\n", mi_option_get(mi_option_page_full_retain));
  printf("large_request=%zu\nmedium_request=%zu\n", (size_t)LARGE_REQUEST, (size_t)MEDIUM_REQUEST);
  printf("large_reserved=%zu\nmedium_reserved=%zu\n", large_reserved, medium_reserved);
  printf("large_slice_count=%zu\nmedium_slice_count=%zu\n", large_slice_count, medium_slice_count);
  printf("large_registered_slice_count=%zu\nmedium_registered_slice_count=%zu\n",
      large_registered_slice_count, medium_registered_slice_count);
  printf("owner_queues_valid=%d\n", owner_queues_valid);
  printf("large_registered_after_exit=%d\nmedium_registered_after_exit=%d\n",
      large_registered_after_exit, medium_registered_after_exit);
  printf("large_stays_registered_nonlocal=%d\nmedium_requeued=%d\n", large_reabandoned, medium_requeued);
  printf("large_released_on_final=%d\nmedium_registered_after_large_final=%d\n",
      large_released_on_final, medium_registered_after_large_final);
  printf("medium_registered_before_collect=%d\n", medium_retired);
  printf("large_released=%d\nmedium_released=%d\n", large_released, medium_released);
  printf("survivor_usable=%d\n", survivor_usable);
  printf("CRABC_MI_MAPPED_LARGE_OWNER_EXIT_END\n");
  return 0;
}
