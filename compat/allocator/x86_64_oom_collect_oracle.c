/* Fixed mimalloc v3.5.0 (18b08671c9302247bfb682286e6bf3cc1773f801)
 * page.c:mi_malloc_generic_fallback -> theap.c:mi_theap_collect_ex(MI_FORCE).
 * Include the unchanged source so real arena claims can supply bounded
 * resource pressure without replacing an allocator transition. */
#define _GNU_SOURCE
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include "static.c"

static void* remote_free(void* block) {
  mi_free(block);
  return NULL;
}

int main(void) {
  mi_arena_id_t arena_id;
  assert(mi_reserve_os_memory_ex(32 * 1024 * 1024, true, false, true, &arena_id) == 0);
  mi_heap_t* heap = mi_heap_new_in_arena(arena_id);
  assert(heap != NULL);
  void* block = mi_heap_malloc(heap, 32);
  assert(block != NULL);
  mi_page_t* page = _mi_ptr_page(block);
  mi_arena_t* arena = page->memid.mem.arena.arena;
  const size_t bin = _mi_bin(32);
  assert(page->retire_expire == 0 && page->used == 1);

  mi_memid_t claims[1024];
  size_t count = 0;
  while (count < 1024 && mi_arena_try_alloc_at(arena, 1, true, 0, &claims[count]) != NULL) {
    count++;
  }
  assert(count > 0 && count < 1024);
  pthread_t thread;
  assert(pthread_create(&thread, NULL, remote_free, block) == 0);
  assert(pthread_join(thread, NULL) == 0);
  assert(page->used == 1);

  void* replacement = mi_heap_malloc(heap, 64);
  assert(replacement != NULL);
  mi_theap_t* theap = mi_heap_theap(heap);
  assert(theap->pages[bin].count == 0);
  puts("oom_retry_released_remote_empty_other_bin=1");
  mi_free(replacement);
  mi_heap_delete(heap);
  for (size_t i = 0; i < count; i++) {
    assert(mi_bbitmap_setN(arena->slices_free, claims[i].mem.arena.slice_index, 1));
  }
  return 0;
}
