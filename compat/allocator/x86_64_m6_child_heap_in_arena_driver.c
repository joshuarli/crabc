#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <pthread.h>

#include "mimalloc.h"
#ifdef CRABC_M6_SOURCE_INTERNAL
#include "mimalloc/internal.h"
#endif

typedef struct {
  mi_subproc_id_t child;
  bool complete;
} child_state_t;

static bool in_area(const void* pointer, const void* area, size_t size) {
  uintptr_t p = (uintptr_t)pointer;
  uintptr_t base = (uintptr_t)area;
  return pointer != NULL && area != NULL && p >= base && p - base < size;
}

static void* child_worker(void* argument) {
  child_state_t* state = (child_state_t*)argument;
  mi_subproc_add_current_thread(state->child);
  mi_heap_t* main_heap = mi_heap_main();
  printf("child.attached=%d,%d\n", mi_subproc_current()._mi_subproc_id == state->child._mi_subproc_id,
         main_heap != NULL);
  if (main_heap == NULL) return NULL;

  mi_arena_id_t id = NULL;
  errno = 0;
  int reserve = mi_reserve_os_memory_ex(64 * 1024 * 1024, true, false, true, &id);
  size_t area_size = 0;
  void* area = mi_arena_area(id, &area_size);
  printf("child.reserved=%d,%d,%d,%d,%d\n", reserve == 0, id != NULL,
         area != NULL, area_size >= 64 * 1024 * 1024, errno == 0);
  if (reserve != 0 || id == NULL || area == NULL) return NULL;

  errno = 0;
  mi_heap_t* selected = mi_heap_new_in_arena(id);
  if (selected == NULL) return NULL;
  mi_theap_t* theap = mi_heap_theap(selected);
  printf("child.selected=%d,%d,%d,%d\n", selected != main_heap, theap != NULL,
         in_area(theap, area, area_size), errno == 0);
#ifdef CRABC_M6_SOURCE_INTERNAL
  mi_subproc_t* child = (mi_subproc_t*)state->child._mi_subproc_id;
  fprintf(stderr, "source.child_binding=%d,%d\n",
          selected->exclusive_arena == (mi_arena_t*)id,
          ((mi_arena_t*)id)->subproc == child);
#endif
  if (theap == NULL) return NULL;
  void* block = mi_heap_malloc(selected, 64);
  if (block == NULL) return NULL;
  printf("child.allocated=%d,%d,%d\n", in_area(block, area, area_size),
         mi_heap_of(block) == selected, mi_heap_contains(selected, block));
  errno = 0;
  void* oversized = mi_heap_malloc(selected, 128 * 1024 * 1024);
  printf("child.no_os_fallback=%d,%d,%d\n", oversized == NULL, errno == ENOMEM,
         mi_heap_of(block) == selected);
  if (oversized != NULL) mi_free(oversized);
  mi_heap_delete(selected);
  printf("child.deleted=%d,%d\n", mi_heap_of(block) == main_heap,
         in_area(block, area, area_size));
  mi_free(block);

  mi_heap_t* second = mi_heap_new_in_arena(id);
  if (second == NULL) return NULL;
  mi_theap_t* second_theap = mi_heap_theap(second);
  void* second_block = mi_heap_malloc(second, 128);
  if (second_theap == NULL || second_block == NULL) return NULL;
  printf("child.recreated=%d,%d,%d\n", in_area(second_theap, area, area_size),
         in_area(second_block, area, area_size), mi_heap_of(second_block) == second);
  mi_free(second_block);
  mi_heap_destroy(second);
  printf("child.destroyed=%d\n", mi_subproc_current()._mi_subproc_id == state->child._mi_subproc_id);

  mi_arena_id_t failed_id = id;
  errno = 0;
  int failed_reserve = mi_reserve_os_memory_ex(SIZE_MAX, true, false, true, &failed_id);
  printf("child.failed_reserve=%d,%d,%d\n", failed_reserve == ENOMEM,
         failed_id == NULL, errno == ENOMEM);
  errno = 0;
  mi_heap_t* ordinary = mi_heap_new_in_arena(failed_id);
  if (ordinary == NULL) return NULL;
  void* ordinary_block = mi_heap_malloc(ordinary, 64);
  if (ordinary_block == NULL) return NULL;
  printf("child.no_selection=%d,%d,%d\n", !in_area(ordinary_block, area, area_size),
         mi_heap_of(ordinary_block) == ordinary, errno == 0);
#ifdef CRABC_M6_SOURCE_INTERNAL
  fprintf(stderr, "source.child_no_selection=%d\n", ordinary->exclusive_arena == NULL);
#endif
  mi_free(ordinary_block);
  mi_heap_destroy(ordinary);
  state->complete = true;
  return NULL;
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  puts("CRABC_MI_M6_CHILD_HEAP_IN_ARENA_BEGIN");
  child_state_t state = {mi_subproc_new(), false};
  if (state.child._mi_subproc_id == NULL) return 2;
  pthread_t worker;
  if (pthread_create(&worker, NULL, child_worker, &state) != 0) return 3;
  if (pthread_join(worker, NULL) != 0) return 4;
  printf("child.joined=%d\n", state.complete);
  mi_subproc_destroy(state.child);
  printf("child.teardown=%d\n", mi_subproc_current()._mi_subproc_id == mi_subproc_main()._mi_subproc_id);
  puts("CRABC_MI_M6_CHILD_HEAP_IN_ARENA_END");
  return state.complete ? 0 : 5;
}
