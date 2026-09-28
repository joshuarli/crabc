#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "mimalloc.h"
#ifdef CRABC_M6_SOURCE_INTERNAL
#include "mimalloc/internal.h"
#include "bitmap.h"
#endif

typedef struct fixture_s {
  uintptr_t blocks[3];
  uintptr_t keeper;
  bool ready;
} fixture_t;

typedef struct visit_s {
  const fixture_t* fixture;
  unsigned areas;
  unsigned target_areas;
  unsigned target_blocks;
  unsigned freed_blocks;
  unsigned other_blocks;
  unsigned target_used;
  unsigned stop;
  char order[64];
  unsigned length;
} visit_t;

static bool in_area(uintptr_t pointer, const mi_heap_area_t* area) {
  uintptr_t start = (uintptr_t)area->blocks;
  return pointer >= start && pointer - start < area->committed;
}

static void append(visit_t* visit, char event) {
  if (visit->length + 1 >= sizeof(visit->order)) abort();
  visit->order[visit->length++] = event;
  visit->order[visit->length] = '\0';
}

static bool observe(const mi_heap_t* heap, const mi_heap_area_t* area,
                    void* block, size_t block_size, void* argument) {
  visit_t* visit = (visit_t*)argument;
  if (heap != mi_heap_main() || block_size != area->block_size) abort();
  if (block == NULL) {
    visit->areas++;
    if (visit->fixture->blocks[0] != 0 && in_area(visit->fixture->blocks[0], area)) {
      visit->target_areas++;
      visit->target_used += (unsigned)area->used;
      append(visit, 'R');
      return visit->stop != 1;
    }
    append(visit, in_area(visit->fixture->keeper, area) ? 'N' : 'X');
    return true;
  }
  uintptr_t address = (uintptr_t)block;
  if (address == visit->fixture->blocks[0]) {
    visit->target_blocks++;
    append(visit, '1');
    return visit->stop != 2;
  }
  if (address == visit->fixture->blocks[1]) {
    visit->freed_blocks++;
    append(visit, 'F');
    return true;
  }
  if (address == visit->fixture->blocks[2]) {
    visit->target_blocks++;
    append(visit, '3');
    return visit->stop != 2;
  }
  visit->other_blocks++;
  append(visit, address == visit->fixture->keeper ? 'K' : 'x');
  return true;
}

static void print_visit(const char* name, const fixture_t* fixture,
                        bool visit_blocks, unsigned stop, bool null_heap) {
  visit_t visit = { 0 };
  visit.fixture = fixture;
  visit.stop = stop;
  mi_heap_t* heap = null_heap ? NULL : mi_heap_main();
  bool complete = mi_heap_visit_abandoned_blocks(heap, visit_blocks, observe, &visit);
  printf("main.%s=%d,%u,%u,%u,%u,%u,%u,%s\n", name, complete,
         visit.areas, visit.target_areas, visit.target_blocks,
         visit.freed_blocks, visit.other_blocks, visit.target_used, visit.order);
}

static void* worker(void* argument) {
  fixture_t* fixture = (fixture_t*)argument;
  mi_heap_t* heap = mi_heap_main();
  for (unsigned index = 0; index < 3; index++) {
    void* block = mi_heap_malloc(heap, 128);
    if (block == NULL) return NULL;
    fixture->blocks[index] = (uintptr_t)block;
  }
  mi_free((void*)fixture->blocks[1]);
  fixture->ready = true;
  return NULL;
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  puts("CRABC_MI_M6_MAIN_ABANDONED_VISITOR_TRACE_BEGIN");
  fixture_t fixture = { 0 };
  fixture.keeper = (uintptr_t)mi_heap_malloc(mi_heap_main(), 128);
  if (fixture.keeper == 0) return 4;
  print_visit("before", &fixture, false, 0, false);
  pthread_t thread;
  if (pthread_create(&thread, NULL, worker, &fixture) != 0) return 2;
  if (pthread_join(thread, NULL) != 0 || !fixture.ready) return 3;
#ifdef CRABC_M6_SOURCE_INTERNAL
  mi_page_t* page = _mi_ptr_page((void*)fixture.blocks[0]);
  mi_page_t* keeper = _mi_ptr_page((void*)fixture.keeper);
  mi_heap_t* heap = mi_heap_main();
  mi_arena_t* arena = page->memid.mem.arena.arena;
  size_t slice = page->memid.mem.arena.slice_index;
  size_t bin = _mi_bin(mi_page_block_size(page));
  mi_arena_pages_t* selected = mi_atomic_load_ptr_acquire(mi_arena_pages_t,
                                                          &heap->arena_pages[arena->arena_idx]);
  fprintf(stderr, "source.selected=%d,%d,%d,%d,%d\n",
          mi_page_heap(page) == heap, mi_page_is_abandoned_mapped(page),
          (size_t)mi_atomic_load_relaxed(&heap->abandoned_count[bin]) == 1,
          selected == &arena->pages_main,
          mi_bitmap_is_setN(arena->pages_main.pages_abandoned[bin], slice, 1));
  fprintf(stderr, "source.keeper=%d,%d,%d\n", keeper != page,
          mi_page_heap(keeper) == heap, !mi_page_is_abandoned_mapped(keeper));
#endif
  print_visit("areas", &fixture, false, 0, false);
  print_visit("blocks", &fixture, true, 0, false);
  print_visit("stop_area", &fixture, true, 1, false);
  print_visit("stop_block", &fixture, true, 2, false);
  print_visit("null_heap", &fixture, true, 0, true);
  puts("CRABC_MI_M6_MAIN_ABANDONED_VISITOR_TRACE_END");
  return 0;
}
