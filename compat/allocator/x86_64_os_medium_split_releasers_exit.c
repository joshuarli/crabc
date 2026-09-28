/* A non-arena medium page survives its owner's exit with two live clients.
   Two other attached threads free those clients in order, preserving the
   PageMap through the first free and releasing it after the last client. */
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

static sem_t owner_ready;
static sem_t owner_exit_go;
static sem_t releaser_ready[2];
static sem_t releaser_go[2];
static mi_heap_t* shared_heap;
static void* clients[2];
static mi_page_t* page;
static uintptr_t map_start;
static size_t map_count;
static size_t reserved;
static size_t block_size;
static int setup_valid;
static int releaser_freed[2];
static int first_reclaimed_before_exit;

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

static void* owner(void* ignored) {
  (void)ignored;
  mi_thread_init();
  for (size_t i = 0; i < 2; i++) {
    clients[i] = mi_heap_malloc_aligned(shared_heap, REQUEST, 16);
  }
  if (clients[0] != NULL && clients[1] != NULL) {
    page = _mi_ptr_page(clients[0]);
  }
  if (page != NULL) {
    map_count = map_prefix(page, &map_start);
    reserved = page->reserved;
    block_size = page->block_size;
    mi_page_queue_t* queue = mi_page_queue(page->theap, page->block_size);
    setup_valid = mi_option_get(mi_option_disallow_arena_alloc) == 1
        && page->memid.memkind == MI_MEM_OS
        && _mi_ptr_page(clients[1]) == page
        && page->used == 2 && page->reserved > 2
        && !mi_page_is_singleton(page) && !mi_page_is_in_full(page)
        && page->block_size == 81920 && map_count == 8
        && queue->first == page && queue->count == 1
        && map_is(page, map_start, map_count);
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
    if (index == 0) {
      first_reclaimed_before_exit = !mi_page_is_abandoned(page)
          && mi_page_is_owned(page) && page->used == 1;
    }
  }
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

  int os_list_abandoned = mi_page_is_abandoned(page)
      && !mi_page_is_abandoned_mapped(page) && !mi_page_is_owned(page);
  int registered_after_exit = map_is(page, map_start, map_count);
  int used_after_exit = page->used == 2;
  if (!os_list_abandoned || !registered_after_exit || !used_after_exit) return 4;

  sem_post(&releaser_go[0]);
  if (pthread_join(survivors[0], NULL) != 0) return 2;
  int first_registered = map_is(page, map_start, map_count);
  int first_used_one = first_registered && page->used == 1;
  int second_client_live = _mi_safe_ptr_page(clients[1]) == page;
  if (!releaser_freed[0] || !first_registered || !first_used_one || !second_client_live) return 5;

  sem_post(&releaser_go[1]);
  if (pthread_join(survivors[1], NULL) != 0) return 2;
  int terminal_map_clear = map_clear(map_start, map_count);
  int terminal_region_clear = !mi_is_in_heap_region(clients[1]);
  if (!releaser_freed[1] || !terminal_map_clear || !terminal_region_clear) return 6;

  printf("CRABC_MI_OS_MEDIUM_SPLIT_EXIT_BEGIN\n");
  printf("request=%zu\nblock_size=%zu\nreserved=%zu\nmap_count=%zu\n",
      (size_t)REQUEST, block_size, reserved, map_count);
  printf("owner_setup_valid=%d\ntwo_releasers_ready=1\nowner_joined_before_free=1\n", setup_valid);
  printf("os_backed=1\nregistered_after_exit=%d\nmedium_used_after_exit=%d\n",
      registered_after_exit, used_after_exit);
  printf("first_free_completed=%d\nfirst_reclaimed_before_exit=%d\nfirst_registered=%d\nsecond_client_live=%d\n",
      releaser_freed[0], first_reclaimed_before_exit, first_registered, second_client_live);
  printf("second_free_completed=%d\nterminal_map_clear=%d\n",
      releaser_freed[1], terminal_map_clear);
  printf("CRABC_MI_OS_MEDIUM_SPLIT_EXIT_END\n");
  printf("CRABC_MI_C_OS_MEDIUM_STATE os_list_abandoned=%d first_used_one=%d terminal_region_clear=%d\n",
      os_list_abandoned, first_used_one, terminal_region_clear);
  return 0;
}
