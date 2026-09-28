/* An OS-backed huge singleton outlives its worker. Its final remote free
   attempts one whole-mapping unmap; a separate medium page still releases. */
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

#define HUGE_REQUEST (5 * 1024 * 1024)
#define MEDIUM_REQUEST (64 * 1024)
#define TRACE(name, value) printf(#name "=%lld\n", (long long)(value))

static sem_t owner_ready, owner_exit, huge_ready, huge_go, huge_done;
static sem_t medium_ready, medium_go, medium_done;
static mi_heap_t* shared_heap;
static void* huge_client;
static void* medium_client[2];
static mi_page_t* huge_page;
static mi_page_t* medium_page;
static uintptr_t huge_map_start, medium_map_start;
static size_t huge_map_count, medium_map_count;
static void* huge_base;
static size_t huge_size;
static size_t medium_size;
static size_t huge_block_size, medium_block_size;
static int setup_valid, huge_free_done, medium_free_done;
static int fail_huge_unmap;
static size_t failed_unmap_calls, all_unmap_calls;
static void* failed_base;
static size_t failed_length;
static unsigned warning_fragments;
static char warning_text[4][256];

static void capture_warning(const char* message, void* argument) {
  (void)argument;
  if (warning_fragments < 4) {
    strncpy(warning_text[warning_fragments], message, 255);
    warning_text[warning_fragments][255] = '\0';
  }
  warning_fragments++;
}

int __real_munmap(void* address, size_t length);
int __wrap_munmap(void* address, size_t length) {
  all_unmap_calls++;
  if (fail_huge_unmap && address == huge_base && length == huge_size) {
    fail_huge_unmap = 0;
    failed_unmap_calls++;
    failed_base = address;
    failed_length = length;
    errno = ENOMEM;
    return -1;
  }
  return __real_munmap(address, length);
}

static size_t map_prefix(mi_page_t* selected, uintptr_t* start) {
  size_t area_size = 0;
  uint8_t* area = mi_page_area(selected, &area_size);
  uint8_t* slice = mi_page_slice_start(selected);
  if (area == NULL || slice == NULL || area < slice) return 0;
  if (area_size > MI_LARGE_PAGE_SIZE) area_size = MI_LARGE_PAGE_SIZE - MI_ARENA_SLICE_SIZE;
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

static int abandoned_list_is(mi_page_t* first, mi_page_t* second) {
  return shared_heap->os_abandoned_pages == first && first->next == second
      && second->next == NULL;
}

static void* owner_thread(void* ignored) {
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
    huge_map_count = map_prefix(huge_page, &huge_map_start);
    medium_map_count = map_prefix(medium_page, &medium_map_start);
    huge_base = huge_page->memid.mem.os.base;
    huge_size = huge_page->memid.mem.os.size;
    medium_size = medium_page->memid.mem.os.size;
    setup_valid = huge_page != medium_page
        && huge_page->memid.memkind == MI_MEM_OS
        && medium_page->memid.memkind == MI_MEM_OS
        && mi_page_is_singleton(huge_page) && huge_page->reserved == 1 && huge_page->used == 1
        && _mi_ptr_page(medium_client[1]) == medium_page
        && medium_page->used == 2 && medium_page->reserved == 6
        && huge_block_size >= HUGE_REQUEST && medium_block_size == 81920
        && huge_map_count == 63 && medium_map_count == 8
        && map_is(huge_page, huge_map_start, huge_map_count)
        && map_is(medium_page, medium_map_start, medium_map_count);
  }
  sem_post(&owner_ready);
  sem_wait(&owner_exit);
  mi_thread_done();
  return NULL;
}

static void* huge_survivor(void* ignored) {
  (void)ignored;
  mi_thread_init();
  sem_post(&huge_ready);
  sem_wait(&huge_go);
  mi_free(huge_client);
  huge_free_done = 1;
  sem_post(&huge_done);
  mi_thread_done();
  return NULL;
}

static void* medium_survivor(void* ignored) {
  (void)ignored;
  mi_thread_init();
  sem_post(&medium_ready);
  sem_wait(&medium_go);
  mi_free(medium_client[0]);
  mi_free(medium_client[1]);
  mi_collect(true);
  medium_free_done = 1;
  sem_post(&medium_done);
  mi_thread_done();
  return NULL;
}

int main(void) {
  _mi_auto_process_init();
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
  sem_t* semaphores[] = { &owner_ready, &owner_exit, &huge_ready, &huge_go,
      &huge_done, &medium_ready, &medium_go, &medium_done };
  for (size_t i = 0; i < sizeof(semaphores)/sizeof(semaphores[0]); i++) {
    if (sem_init(semaphores[i], 0, 0) != 0) return 2;
  }
  pthread_t owner, huge, medium;
  if (pthread_create(&owner, NULL, owner_thread, NULL) != 0) return 2;
  if (sem_wait(&owner_ready) != 0 || !setup_valid) {
    fprintf(stderr, "setup: valid=%d huge_block=%zu huge_map=%zu huge_size=%zu medium_block=%zu\n",
        setup_valid, huge_block_size, huge_map_count, huge_size, medium_block_size);
    return 3;
  }
  if (pthread_create(&huge, NULL, huge_survivor, NULL) != 0
      || pthread_create(&medium, NULL, medium_survivor, NULL) != 0) return 2;
  if (sem_wait(&huge_ready) != 0 || sem_wait(&medium_ready) != 0) return 2;
  sem_post(&owner_exit);
  if (pthread_join(owner, NULL) != 0) return 2;
  int abandoned_after_exit = mi_page_is_abandoned(huge_page)
      && mi_page_is_abandoned(medium_page)
      && abandoned_list_is(huge_page, medium_page);
  int both_registered_after_exit = map_is(huge_page, huge_map_start, huge_map_count)
      && map_is(medium_page, medium_map_start, medium_map_count);
  if (!abandoned_after_exit || !both_registered_after_exit) {
    fprintf(stderr, "exit: huge_abandoned=%d medium_abandoned=%d list_head=%p medium=%p huge=%p medium_next=%p huge_next=%p registered=%d\n",
        mi_page_is_abandoned(huge_page), mi_page_is_abandoned(medium_page),
        (void*)shared_heap->os_abandoned_pages, (void*)medium_page, (void*)huge_page,
        (void*)medium_page->next, (void*)huge_page->next, both_registered_after_exit);
    return 4;
  }
  mi_subproc_t* subproc = _mi_subproc_main();
  int64_t reserved_before = subproc->stats.reserved.current;
  int64_t committed_before = subproc->stats.committed.current;
  size_t arena_count_before = mi_atomic_load_relaxed(&subproc->arena_count);
  warning_fragments = 0;
  fail_huge_unmap = 1;
  sem_post(&huge_go);
  if (sem_wait(&huge_done) != 0 || !huge_free_done) return 5;
  int huge_map_clear = map_clear(huge_map_start, huge_map_count);
  int medium_still_registered = map_is(medium_page, medium_map_start, medium_map_count);
  int medium_still_listed = shared_heap->os_abandoned_pages == medium_page
      && medium_page->next == NULL;
  unsigned char residency = 0;
  int huge_mapping_retained = mincore(huge_base, _mi_os_page_size(), &residency) == 0;
  int64_t reserved_after_huge = subproc->stats.reserved.current;
  int64_t committed_after_huge = subproc->stats.committed.current;
  if (!huge_map_clear || !medium_still_registered || !medium_still_listed
      || !huge_mapping_retained || failed_unmap_calls != 1) return 5;

  sem_post(&medium_go);
  if (sem_wait(&medium_done) != 0 || !medium_free_done) return 6;
  int medium_map_clear = map_clear(medium_map_start, medium_map_count);
  int medium_mapping_gone = mincore((void*)medium_map_start, _mi_os_page_size(), &residency) != 0;
  int os_list_empty = shared_heap->os_abandoned_pages == NULL;
  int64_t reserved_after_medium = subproc->stats.reserved.current;
  int64_t committed_after_medium = subproc->stats.committed.current;
  int arena_count_stable = mi_atomic_load_relaxed(&subproc->arena_count) == arena_count_before;
  if (!medium_map_clear || !medium_mapping_gone || !os_list_empty || !arena_count_stable) return 6;
  if (pthread_join(huge, NULL) != 0 || pthread_join(medium, NULL) != 0) return 2;

  int warning_order = warning_fragments == 2
      && strncmp(warning_text[0], "mimalloc: warning: thread 0x", 28) == 0
      && strncmp(warning_text[1], "unable to free OS memory (error: 12 (0x0C)", 41) == 0;
  int exact_failed_range = failed_base == huge_base && failed_length == huge_size;
  size_t unmaps_before_retry = all_unmap_calls;
  int raw_retry = __real_munmap(huge_base, huge_size) == 0;
  int terminal_unmapped = mincore(huge_base, _mi_os_page_size(), &residency) != 0;
  int raw_only_retry = all_unmap_calls == unmaps_before_retry
      && reserved_after_medium == subproc->stats.reserved.current
      && committed_after_medium == subproc->stats.committed.current
      && warning_fragments == 2;
  printf("CRABC_MI_HUGE_OS_FAILED_UNMAP_BEGIN\n");
  TRACE(huge_request, HUGE_REQUEST); TRACE(medium_request, MEDIUM_REQUEST);
  TRACE(huge_block_size, huge_block_size); TRACE(medium_block_size, medium_block_size);
  TRACE(huge_map_count, huge_map_count); TRACE(medium_map_count, medium_map_count);
  TRACE(huge_os_size, huge_size); TRACE(medium_os_size, medium_size);
  TRACE(setup_valid, setup_valid); TRACE(two_survivors_ready, 1);
  TRACE(abandoned_after_exit, abandoned_after_exit);
  TRACE(both_registered_after_exit, both_registered_after_exit);
  TRACE(failed_unmap_calls, failed_unmap_calls); TRACE(exact_failed_range, exact_failed_range);
  TRACE(huge_map_clear, huge_map_clear); TRACE(huge_mapping_retained, huge_mapping_retained);
  TRACE(medium_still_registered, medium_still_registered);
  TRACE(medium_still_listed, medium_still_listed);
  TRACE(medium_map_clear, medium_map_clear); TRACE(medium_mapping_gone, medium_mapping_gone);
  TRACE(os_list_empty, os_list_empty); TRACE(arena_count_stable, arena_count_stable);
  TRACE(huge_reserved_drop, reserved_before - reserved_after_huge);
  TRACE(huge_committed_drop, committed_before - committed_after_huge);
  TRACE(medium_reserved_drop, reserved_after_huge - reserved_after_medium);
  TRACE(medium_committed_drop, committed_after_huge - committed_after_medium);
  TRACE(warning_order, warning_order); TRACE(raw_retry, raw_retry);
  TRACE(raw_only_retry, raw_only_retry); TRACE(terminal_unmapped, terminal_unmapped);
  printf("CRABC_MI_HUGE_OS_FAILED_UNMAP_END\n");
  printf("CRABC_MI_HUGE_OS_FAILED_RANGE base=%p length=%zu\n", failed_base, failed_length);
  printf("CRABC_MI_C_HUGE_OS_SOURCE_STATE memkind=%d huge_reserved=%zu medium_reserved=%zu failed_primitive_os_unmaps=%zu warnings=%u\n",
      (int)MI_MEM_OS, (size_t)1, (size_t)6, failed_unmap_calls, warning_fragments);
  for (unsigned i = 0; i < warning_fragments && i < 4; i++) {
    fprintf(stderr, "warning[%u]=%s\n", i, warning_text[i]);
  }
  return warning_order && exact_failed_range && raw_retry && raw_only_retry && terminal_unmapped
      && reserved_before - reserved_after_huge == (int64_t)huge_size
      && committed_before - committed_after_huge == (int64_t)(huge_size - MI_ARENA_SLICE_SIZE)
      && reserved_after_huge - reserved_after_medium == (int64_t)medium_size
      && committed_after_huge - committed_after_medium == (int64_t)(medium_map_count * MI_ARENA_SLICE_SIZE)
      ? 0 : 7;
}
