#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "mimalloc.h"
#ifdef CRABC_M6_SOURCE_INTERNAL
#include "mimalloc/internal.h"
#include "bitmap.h"
#endif

typedef struct {
  pthread_mutex_t lock;
  pthread_cond_t changed;
  unsigned stage;
  mi_subproc_id_t child;
  mi_arena_id_t arena;
  void* area;
  size_t area_size;
  mi_heap_t* heap;
  mi_theap_t* first;
  mi_theap_t* second;
  bool first_done;
  bool second_done;
#ifdef CRABC_M6_SOURCE_INTERNAL
  int64_t baseline_current;
  int64_t baseline_total;
  mi_memid_t first_memid;
  mi_memid_t second_memid;
#endif
} fixture_t;

static void advance(fixture_t* fixture, unsigned stage) {
  pthread_mutex_lock(&fixture->lock);
  fixture->stage = stage;
  pthread_cond_broadcast(&fixture->changed);
  pthread_mutex_unlock(&fixture->lock);
}

static void await(fixture_t* fixture, unsigned stage) {
  pthread_mutex_lock(&fixture->lock);
  while (fixture->stage < stage) pthread_cond_wait(&fixture->changed, &fixture->lock);
  pthread_mutex_unlock(&fixture->lock);
}

static bool in_area(const fixture_t* fixture, const void* pointer) {
  uintptr_t p = (uintptr_t)pointer;
  uintptr_t base = (uintptr_t)fixture->area;
  return pointer != NULL && fixture->area != NULL && p >= base && p - base < fixture->area_size;
}

#ifdef CRABC_M6_SOURCE_INTERNAL
static mi_subproc_t* source_child(const fixture_t* fixture) {
  return (mi_subproc_t*)fixture->child._mi_subproc_id;
}

static bool source_slice_claimed(mi_memid_t memory) {
  return memory.memkind == MI_MEM_ARENA &&
         mi_bbitmap_is_clearN(memory.mem.arena.arena->slices_free,
                              memory.mem.arena.slice_index,
                              memory.mem.arena.slice_count);
}

static bool source_slice_free(mi_memid_t memory) {
  return memory.memkind == MI_MEM_ARENA &&
         mi_bbitmap_is_setN(memory.mem.arena.arena->slices_free,
                            memory.mem.arena.slice_index,
                            memory.mem.arena.slice_count);
}
#endif

static void* second_worker(void* argument) {
  fixture_t* fixture = (fixture_t*)argument;
  mi_subproc_add_current_thread(fixture->child);
  mi_heap_t* main_heap = mi_heap_main();
  mi_theap_t* base = mi_heap_theap(main_heap);
  advance(fixture, 2);
  await(fixture, 3);
  fixture->second = mi_heap_theap(fixture->heap);
  if (fixture->second == NULL) return NULL;
#ifdef CRABC_M6_SOURCE_INTERNAL
  fixture->second_memid = fixture->second->memid;
#endif
  void* block = mi_heap_malloc(fixture->heap, 96);
  printf("two.second_page=%d,%d\n", in_area(fixture, block),
         mi_heap_of(block) == fixture->heap);
  if (block != NULL) mi_free(block);
  fixture->second = mi_heap_theap(fixture->heap);
  advance(fixture, 4);
  await(fixture, 6);
  printf("two.second_held=%d,%d\n", fixture->second != base,
         mi_theap_get_default() == base);
  printf("two.second_released=%d\n", mi_heap_theap(main_heap) == base);
  advance(fixture, 7);
  await(fixture, 8);
  fixture->second_done = true;
  return NULL;
}

static void* first_worker(void* argument) {
  fixture_t* fixture = (fixture_t*)argument;
  mi_subproc_add_current_thread(fixture->child);
  mi_heap_t* main_heap = mi_heap_main();
  mi_theap_t* base = mi_heap_theap(main_heap);
  errno = 0;
  int reserve = mi_reserve_os_memory_ex(128 * 1024 * 1024, true, false, true, &fixture->arena);
  fixture->area = mi_arena_area(fixture->arena, &fixture->area_size);
  fixture->heap = mi_heap_new_in_arena(fixture->arena);
  printf("two.reserved=%d,%d,%d,%d\n", reserve == 0, fixture->arena != NULL,
         fixture->area != NULL, fixture->heap != NULL);
  if (reserve != 0 || fixture->arena == NULL || fixture->heap == NULL) return NULL;
  advance(fixture, 1);
  await(fixture, 2);
#ifdef CRABC_M6_SOURCE_INTERNAL
  fixture->baseline_current = source_child(fixture)->stats.theaps.current;
  fixture->baseline_total = source_child(fixture)->stats.theaps.total;
#endif
  fixture->first = mi_heap_theap(fixture->heap);
  if (fixture->first == NULL) return NULL;
#ifdef CRABC_M6_SOURCE_INTERNAL
  fixture->first_memid = fixture->first->memid;
#endif
  void* block = mi_heap_malloc(fixture->heap, 64);
  printf("two.first_page=%d,%d\n", in_area(fixture, block),
         mi_heap_of(block) == fixture->heap);
  if (block != NULL) mi_free(block);
  fixture->first = mi_heap_theap(fixture->heap);
  advance(fixture, 3);
  await(fixture, 4);
  printf("two.theaps=%d,%d,%d\n", fixture->first != fixture->second,
         in_area(fixture, fixture->first), in_area(fixture, fixture->second));
#ifdef CRABC_M6_SOURCE_INTERNAL
  mi_subproc_t* child = source_child(fixture);
  mi_theap_t* first = fixture->first;
  mi_theap_t* second = fixture->second;
  fprintf(stderr, "source.two_before=%d,%d,%d,%d,%d,%d\n",
          fixture->heap->theaps == second && second->hnext == first && first->hnext == NULL,
          first->tld != second->tld && first->tld->theaps == first && second->tld->theaps == second,
          first->memid.memkind == MI_MEM_ARENA && second->memid.memkind == MI_MEM_ARENA &&
              first->memid.mem.arena.arena == (mi_arena_t*)fixture->arena &&
              second->memid.mem.arena.arena == (mi_arena_t*)fixture->arena &&
              first->memid.mem.arena.slice_index != second->memid.mem.arena.slice_index,
          source_slice_claimed(first->memid) && source_slice_claimed(second->memid),
          mi_atomic_load_relaxed(&first->refcount) == 2 && mi_atomic_load_relaxed(&second->refcount) == 2,
          child->stats.theaps.current - fixture->baseline_current == 2 &&
              child->stats.theaps.total - fixture->baseline_total == 2);
  fprintf(stderr, "source.two_refs=%zu,%zu\n",
          (size_t)mi_atomic_load_relaxed(&first->refcount),
          (size_t)mi_atomic_load_relaxed(&second->refcount));
#endif
  mi_heap_delete(fixture->heap);
  printf("two.deleted=%d\n", mi_subproc_current()._mi_subproc_id == fixture->child._mi_subproc_id);
#ifdef CRABC_M6_SOURCE_INTERNAL
  fprintf(stderr, "source.two_detached=%d,%d,%d,%d\n",
          second->tld == NULL && second->hnext == NULL && second->hprev == NULL,
          mi_atomic_load_relaxed(&second->refcount) == 1,
          source_slice_free(fixture->first_memid) && source_slice_claimed(fixture->second_memid),
          child->stats.theaps.current - fixture->baseline_current == 1);
#endif
  printf("two.first_released=%d\n", mi_heap_theap(main_heap) == base);
#ifdef CRABC_M6_SOURCE_INTERNAL
  fprintf(stderr, "source.two_first_released=%d,%d,%d\n",
          source_slice_free(fixture->first_memid),
          source_slice_claimed(fixture->second_memid),
          child->stats.theaps.current - fixture->baseline_current == 1);
#endif
  mi_heap_t* probe = mi_heap_new_in_arena(fixture->arena);
  mi_theap_t* probe_theap = mi_heap_theap(probe);
  printf("two.no_early_reuse=%d,%d\n", in_area(fixture, probe_theap),
         probe_theap != fixture->second);
  mi_heap_destroy(probe);
  (void)mi_heap_theap(main_heap);
#ifdef CRABC_M6_SOURCE_INTERNAL
  fprintf(stderr, "source.two_held=%d,%d\n", source_slice_claimed(fixture->second_memid),
          child->stats.theaps.current - fixture->baseline_current == 1);
#endif
  advance(fixture, 6);
  await(fixture, 7);
#ifdef CRABC_M6_SOURCE_INTERNAL
  fprintf(stderr, "source.two_released=%d,%d\n", source_slice_free(fixture->second_memid),
          child->stats.theaps.current - fixture->baseline_current == 0);
#endif
  mi_heap_t* final = mi_heap_new_in_arena(fixture->arena);
  mi_theap_t* final_theap = mi_heap_theap(final);
  printf("two.final=%d,%d\n", final != NULL, in_area(fixture, final_theap));
  mi_heap_destroy(final);
  (void)mi_heap_theap(main_heap);
  advance(fixture, 8);
  fixture->first_done = true;
  return NULL;
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  puts("CRABC_MI_M6_TWO_WORKER_ARENA_BEGIN");
  fixture_t fixture = {
      .lock = PTHREAD_MUTEX_INITIALIZER,
      .changed = PTHREAD_COND_INITIALIZER,
      .child = mi_subproc_new(),
  };
  if (fixture.child._mi_subproc_id == NULL) return 2;
  pthread_t first;
  pthread_t second;
  if (pthread_create(&first, NULL, first_worker, &fixture) != 0) return 3;
  await(&fixture, 1);
  if (pthread_create(&second, NULL, second_worker, &fixture) != 0) return 4;
  if (pthread_join(second, NULL) != 0 || pthread_join(first, NULL) != 0) return 5;
  printf("two.joined=%d,%d\n", fixture.first_done, fixture.second_done);
  mi_subproc_destroy(fixture.child);
  printf("two.teardown=%d\n", mi_subproc_current()._mi_subproc_id == mi_subproc_main()._mi_subproc_id);
  puts("CRABC_MI_M6_TWO_WORKER_ARENA_END");
  return fixture.first_done && fixture.second_done ? 0 : 6;
}
