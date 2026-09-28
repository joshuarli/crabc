/* A regular OS medium page survives owner exit and its first remote free.
   The second survivor's final free fails only the exact terminal munmap. */
#define _DEFAULT_SOURCE
#include "mimalloc/internal.h"
#include "mimalloc/prim-tls.h"
#include <errno.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

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
static int fail_final_unmap;
static size_t attempted_unmaps;
static void* attempted_base;
static size_t attempted_size;
static void* os_base;
static size_t os_size;
static int64_t reserved_before_final;
static int64_t committed_before_final;
static unsigned warning_fragments;
static int warning_prefix;
static int warning_body;
static char warning_text[4][256];

static void capture_warning(const char* message, void* argument) {
  (void)argument;
  if (warning_fragments < 4) {
    strncpy(warning_text[warning_fragments], message, 255);
    warning_text[warning_fragments][255] = '\0';
  }
  if (warning_fragments == 0) {
    warning_prefix = strncmp(message, "mimalloc: warning: thread 0x",
        sizeof("mimalloc: warning: thread 0x") - 1) == 0;
  }
  else if (warning_fragments == 1) {
    warning_body = strncmp(message, "unable to free OS memory (error: 12 (0x0C)",
        sizeof("unable to free OS memory (error: 12 (0x0C)") - 1) == 0;
  }
  warning_fragments++;
}

int __real_munmap(void* address, size_t length);
int __wrap_munmap(void* address, size_t length) {
  if (fail_final_unmap) {
    fail_final_unmap = 0;
    attempted_unmaps++;
    attempted_base = address;
    attempted_size = length;
    errno = ENOMEM;
    return -1;
  }
  return __real_munmap(address, length);
}

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
  mi_option_set_enabled(mi_option_show_errors, true);
  mi_register_output(capture_warning, NULL);
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

  mi_memid_t memory = page->memid;
  if (memory.memkind != MI_MEM_OS || memory.mem.os.base == NULL) return 5;
  os_base = memory.mem.os.base;
  os_size = memory.mem.os.size;
  mi_subproc_t* subproc = _mi_subproc_main();
  reserved_before_final = subproc->stats.reserved.current;
  committed_before_final = subproc->stats.committed.current;
  warning_fragments = 0;
  warning_prefix = 0;
  warning_body = 0;
  fail_final_unmap = 1;

  sem_post(&releaser_go[1]);
  if (pthread_join(survivors[1], NULL) != 0) return 2;
  int terminal_map_clear = map_clear(map_start, map_count);
  unsigned char residency = 0;
  int mapping_retained = mincore(os_base, _mi_os_page_size(), &residency) == 0;
  int exact_failed_range = attempted_unmaps == 1 && attempted_base == os_base
      && attempted_size == os_size;
  int counters_released = reserved_before_final - subproc->stats.reserved.current == (int64_t)os_size
      && committed_before_final - subproc->stats.committed.current
          == (int64_t)(map_count * MI_ARENA_SLICE_SIZE);
  printf("CRABC_MI_OS_MEDIUM_FAILED_UNMAP_BEGIN\n");
  printf("request=%zu\nblock_size=%zu\nreserved=%zu\nmap_count=%zu\n",
      (size_t)REQUEST, block_size, reserved, map_count);
  printf("owner_setup_valid=%d\ntwo_releasers_ready=1\nowner_joined_before_free=1\n", setup_valid);
  printf("os_backed=1\nregistered_after_exit=%d\nmedium_used_after_exit=%d\n",
      registered_after_exit, used_after_exit);
  printf("first_free_completed=%d\nfirst_reclaimed_before_exit=%d\nfirst_registered=%d\nsecond_client_live=%d\n",
      releaser_freed[0], first_reclaimed_before_exit, first_registered, second_client_live);
  printf("second_free_completed=%d\nterminal_map_clear=%d\n",
      releaser_freed[1], terminal_map_clear);
  printf("failed_unmap_attempts=%zu\nfailed_range_exact=%d\nmapping_retained=%d\ncounters_released=%d\n",
      attempted_unmaps, exact_failed_range, mapping_retained, counters_released);
  printf("os_size=%zu\n", os_size);
  printf("reserved_drop=%lld\ncommitted_drop=%lld\n",
      (long long)(reserved_before_final - subproc->stats.reserved.current),
      (long long)(committed_before_final - subproc->stats.committed.current));
  for (unsigned i = 0; i < warning_fragments && i < 4; i++) fprintf(stderr, "warning[%u]=%s\n", i, warning_text[i]);
  printf("CRABC_MI_OS_MEDIUM_FAILED_UNMAP_END\n");
  printf("CRABC_MI_OS_MEDIUM_FAILED_RANGE base=%p length=%zu\n", attempted_base, attempted_size);
  printf("CRABC_MI_C_OS_MEDIUM_STATE os_list_abandoned=%d first_used_one=%d warning_enabled=%d warning_fragments=%u warning_prefix=%d warning_body=%d\n",
      os_list_abandoned, first_used_one, mi_option_is_enabled(mi_option_show_errors),
      warning_fragments, warning_prefix, warning_body);
  if (!releaser_freed[1] || !terminal_map_clear || !mapping_retained
      || !exact_failed_range || !counters_released) return 6;
  if (__real_munmap(os_base, os_size) != 0) return 7;
  return 0;
}
