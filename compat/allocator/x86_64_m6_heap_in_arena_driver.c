#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "mimalloc.h"
#ifdef CRABC_M6_SOURCE_INTERNAL
#include "mimalloc/internal.h"
#endif

static size_t heap_count;

static bool count_heap(mi_heap_t* heap, void* argument) {
  (void)heap;
  (void)argument;
  heap_count++;
  return true;
}

static size_t current_heap_count(void) {
  heap_count = 0;
  mi_subproc_visit_heaps(mi_subproc_main(), count_heap, NULL);
  return heap_count;
}

static bool in_area(const void* pointer, const void* area, size_t size) {
  uintptr_t p = (uintptr_t)pointer;
  uintptr_t base = (uintptr_t)area;
  return pointer != NULL && area != NULL && p >= base && p - base < size;
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  puts("CRABC_MI_M6_HEAP_IN_ARENA_BEGIN");
  mi_heap_t* main_heap = mi_heap_main();
  printf("heap.initial=%d,%d\n", main_heap != NULL, current_heap_count() == 1);
  if (main_heap == NULL) return 2;

  mi_arena_id_t id = NULL;
  errno = 0;
  int reserve = mi_reserve_os_memory_ex(64 * 1024 * 1024, true, false, true, &id);
  size_t area_size = 0;
  void* area = mi_arena_area(id, &area_size);
  printf("arena.reserved=%d,%d,%d,%d,%d\n", reserve == 0, id != NULL,
         area != NULL, area_size >= 64 * 1024 * 1024, errno == 0);
  if (reserve != 0 || id == NULL || area == NULL) return 3;
  size_t empty_size = 123;
  void* empty_area = mi_arena_area(NULL, &empty_size);
  printf("arena.none=%d,%d\n", empty_area == NULL, empty_size == 0);

  errno = 0;
  mi_heap_t* selected = mi_heap_new_in_arena(id);
  if (selected == NULL) return 4;
  mi_theap_t* theap = mi_heap_theap(selected);
  printf("heap.selected=%d,%d,%d,%d,%d\n", selected != main_heap,
         current_heap_count() == 2, theap != NULL, in_area(theap, area, area_size), errno == 0);
#ifdef CRABC_M6_SOURCE_INTERNAL
  fprintf(stderr, "source.selected_binding=%d\n", selected->exclusive_arena == (mi_arena_t*)id);
#endif
  void* block = mi_heap_malloc(selected, 64);
  if (block == NULL) return 5;
  printf("heap.allocated=%d,%d,%d\n", in_area(block, area, area_size),
         mi_heap_of(block) == selected, mi_heap_contains(selected, block));
  errno = 0;
  void* oversized = mi_heap_malloc(selected, 128 * 1024 * 1024);
  printf("heap.no_os_fallback=%d,%d,%d\n", oversized == NULL,
         errno == ENOMEM, mi_heap_of(block) == selected);
  if (oversized != NULL) mi_free(oversized);
  mi_heap_delete(selected);
  printf("heap.deleted=%d,%d,%d\n", current_heap_count() == 1,
         mi_heap_of(block) == main_heap, in_area(block, area, area_size));
  mi_free(block);

  mi_heap_t* second = mi_heap_new_in_arena(id);
  if (second == NULL) return 6;
  mi_theap_t* second_theap = mi_heap_theap(second);
  void* second_block = mi_heap_malloc(second, 128);
  if (second_theap == NULL || second_block == NULL) return 7;
  printf("heap.recreated=%d,%d,%d,%d\n", current_heap_count() == 2,
         in_area(second_theap, area, area_size), in_area(second_block, area, area_size),
         mi_heap_of(second_block) == second);
  mi_free(second_block);
  mi_heap_destroy(second);
  printf("heap.destroyed=%d\n", current_heap_count() == 1);

  mi_arena_id_t failed_id = id;
  errno = 0;
  int failed_reserve = mi_reserve_os_memory_ex(SIZE_MAX, true, false, true, &failed_id);
  printf("arena.failed_reserve=%d,%d,%d\n", failed_reserve == ENOMEM,
         failed_id == NULL, errno == ENOMEM);
  errno = 0;
  mi_heap_t* ordinary = mi_heap_new_in_arena(failed_id);
  if (ordinary == NULL) return 8;
  void* ordinary_block = mi_heap_malloc(ordinary, 64);
  if (ordinary_block == NULL) return 9;
  printf("heap.no_selection=%d,%d,%d,%d\n", current_heap_count() == 2,
         !in_area(ordinary_block, area, area_size), mi_heap_of(ordinary_block) == ordinary,
         errno == 0);
#ifdef CRABC_M6_SOURCE_INTERNAL
  fprintf(stderr, "source.no_selection_binding=%d\n", ordinary->exclusive_arena == NULL);
#endif
  mi_free(ordinary_block);
  mi_heap_destroy(ordinary);
  printf("heap.no_selection_destroyed=%d\n", current_heap_count() == 1);
  puts("CRABC_MI_M6_HEAP_IN_ARENA_END");
  return 0;
}
