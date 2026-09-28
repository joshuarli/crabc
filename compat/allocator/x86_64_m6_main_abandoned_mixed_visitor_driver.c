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
  uintptr_t regular[2][3];
  uintptr_t regular_keeper[2];
  uintptr_t os_live;
  uintptr_t os_freed;
  uintptr_t os_keeper;
  bool ready;
} fixture_t;

typedef struct visit_s {
  const fixture_t* fixture;
  unsigned areas[4];
  unsigned blocks[4];
  unsigned freed_blocks;
  unsigned regular_keeper_events;
  unsigned used;
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
    visit->used += (unsigned)area->used;
    for (unsigned bin = 0; bin < 2; bin++) {
      if (in_area(visit->fixture->regular[bin][0], area)) {
        visit->areas[bin]++;
        append(visit, bin == 0 ? 'L' : 'H');
        return visit->stop != (bin == 0 ? 1u : 3u);
      }
    }
    if (in_area(visit->fixture->os_live, area)) {
      visit->areas[2]++;
      append(visit, 'O');
      return visit->stop != 5;
    }
    if (in_area(visit->fixture->os_keeper, area)) {
      visit->areas[3]++;
      append(visit, 'K');
      return true;
    }
    for (unsigned bin = 0; bin < 2; bin++) {
      if (in_area(visit->fixture->regular_keeper[bin], area)) {
        visit->regular_keeper_events++;
        append(visit, 'N');
        return true;
      }
    }
    if (in_area(visit->fixture->os_freed, area)) {
      append(visit, 'F');
      return true;
    }
    abort();
  }
  uintptr_t pointer = (uintptr_t)block;
  for (unsigned bin = 0; bin < 2; bin++) {
    if (pointer == visit->fixture->regular[bin][0]) {
      visit->blocks[bin]++;
      append(visit, bin == 0 ? '1' : '4');
      return visit->stop != (bin == 0 ? 2u : 4u);
    }
    if (pointer == visit->fixture->regular[bin][1]) {
      visit->freed_blocks++;
      append(visit, 'F');
      return true;
    }
    if (pointer == visit->fixture->regular[bin][2]) {
      visit->blocks[bin]++;
      append(visit, bin == 0 ? '3' : '6');
      return true;
    }
    if (pointer == visit->fixture->regular_keeper[bin]) {
      visit->regular_keeper_events++;
      append(visit, 'n');
      return true;
    }
  }
  if (pointer == visit->fixture->os_live) {
    visit->blocks[2]++;
    append(visit, 'S');
    return visit->stop != 6;
  }
  if (pointer == visit->fixture->os_keeper) {
    visit->blocks[3]++;
    append(visit, 'T');
    return true;
  }
  if (pointer == visit->fixture->os_freed) {
    visit->freed_blocks++;
    append(visit, 'F');
    return true;
  }
  abort();
}

static void print_visit(const char* name, const fixture_t* fixture,
                        bool visit_blocks, unsigned stop, bool null_heap) {
  visit_t visit = { 0 };
  visit.fixture = fixture;
  visit.stop = stop;
  mi_heap_t* heap = null_heap ? NULL : mi_heap_main();
  bool complete = mi_heap_visit_abandoned_blocks(heap, visit_blocks, observe, &visit);
  printf("mixed.%s=%d,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%s\n", name, complete,
         visit.areas[0], visit.areas[1], visit.areas[2], visit.areas[3],
         visit.blocks[0], visit.blocks[1], visit.blocks[2], visit.blocks[3],
         visit.freed_blocks, visit.regular_keeper_events, visit.used, visit.order);
}

static void* worker(void* argument) {
  fixture_t* fixture = (fixture_t*)argument;
  mi_heap_t* heap = mi_heap_main();
  fixture->os_live = (uintptr_t)mi_heap_malloc_aligned(heap, 10 * 1024 + 1, 128 * 1024);
  fixture->os_freed = (uintptr_t)mi_heap_malloc_aligned(heap, 10 * 1024 + 1, 128 * 1024);
  if (fixture->os_live == 0 || fixture->os_freed == 0) return NULL;
  for (unsigned bin = 2; bin > 0; bin--) {
    for (unsigned block = 0; block < 3; block++) {
      fixture->regular[bin - 1][block] =
          (uintptr_t)mi_heap_malloc(heap, bin == 1 ? 128 : 4096);
      if (fixture->regular[bin - 1][block] == 0) return NULL;
    }
  }
#ifdef CRABC_M6_SOURCE_INTERNAL
  mi_page_t* freed_page = _mi_ptr_page((void*)fixture->os_freed);
  bool was_list_head = heap->os_abandoned_pages == freed_page;
#endif
  mi_free((void*)fixture->regular[0][1]);
  mi_free((void*)fixture->regular[1][1]);
  mi_free((void*)fixture->os_freed);
#ifdef CRABC_M6_SOURCE_INTERNAL
  fprintf(stderr, "source.freed_os=%d,%d\n", was_list_head,
          heap->os_abandoned_pages != freed_page);
#endif
  fixture->ready = true;
  return NULL;
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  puts("CRABC_MI_M6_MAIN_ABANDONED_MIXED_VISITOR_TRACE_BEGIN");
  fixture_t fixture = { 0 };
  fixture.regular_keeper[0] = (uintptr_t)mi_heap_malloc(mi_heap_main(), 128);
  fixture.regular_keeper[1] = (uintptr_t)mi_heap_malloc(mi_heap_main(), 4096);
  fixture.os_keeper = (uintptr_t)mi_heap_malloc_aligned(mi_heap_main(), 10 * 1024 + 1, 128 * 1024);
  if (fixture.regular_keeper[0] == 0 || fixture.regular_keeper[1] == 0 || fixture.os_keeper == 0) return 4;
  print_visit("before", &fixture, true, 0, false);
  pthread_t thread;
  if (pthread_create(&thread, NULL, worker, &fixture) != 0) return 2;
  if (pthread_join(thread, NULL) != 0 || !fixture.ready) return 3;
#ifdef CRABC_M6_SOURCE_INTERNAL
  mi_heap_t* heap = mi_heap_main();
  mi_page_t* low = _mi_ptr_page((void*)fixture.regular[0][0]);
  mi_page_t* high = _mi_ptr_page((void*)fixture.regular[1][0]);
  mi_page_t* low_keeper = _mi_ptr_page((void*)fixture.regular_keeper[0]);
  mi_page_t* high_keeper = _mi_ptr_page((void*)fixture.regular_keeper[1]);
  mi_page_t* os = _mi_ptr_page((void*)fixture.os_live);
  mi_page_t* os_keeper = _mi_ptr_page((void*)fixture.os_keeper);
  size_t low_bin = _mi_bin(mi_page_block_size(low));
  size_t high_bin = _mi_bin(mi_page_block_size(high));
  mi_arena_t* low_arena = low->memid.mem.arena.arena;
  mi_arena_t* high_arena = high->memid.mem.arena.arena;
  fprintf(stderr, "source.regular=%d,%d,%d,%d,%d,%d,%d,%d,%d,%d\n",
          low->memid.memkind == MI_MEM_ARENA,
          high->memid.memkind == MI_MEM_ARENA,
          mi_page_is_abandoned_mapped(low), mi_page_is_abandoned_mapped(high),
          mi_page_heap(low) == heap && mi_page_heap(high) == heap,
          low_bin < high_bin,
          (size_t)mi_atomic_load_relaxed(&heap->abandoned_count[low_bin]) == 1 &&
          (size_t)mi_atomic_load_relaxed(&heap->abandoned_count[high_bin]) == 1,
          mi_bitmap_is_setN(low_arena->pages_main.pages_abandoned[low_bin],
                            low->memid.mem.arena.slice_index, 1),
          mi_bitmap_is_setN(high_arena->pages_main.pages_abandoned[high_bin],
                            high->memid.mem.arena.slice_index, 1),
          low_keeper != low && high_keeper != high &&
          !mi_page_is_abandoned(low_keeper) && !mi_page_is_abandoned(high_keeper));
  fprintf(stderr, "source.os=%d,%d,%d,%d,%d\n",
          mi_memid_is_os(os->memid), mi_page_heap(os) == heap,
          heap->os_abandoned_pages == os, os->next == os_keeper,
          mi_memid_is_os(os_keeper->memid) && mi_page_is_abandoned(os_keeper));
#endif
  print_visit("areas", &fixture, false, 0, false);
  print_visit("blocks", &fixture, true, 0, false);
  print_visit("stop_low_area", &fixture, true, 1, false);
  print_visit("stop_low_block", &fixture, true, 2, false);
  print_visit("stop_high_area", &fixture, true, 3, false);
  print_visit("stop_high_block", &fixture, true, 4, false);
  print_visit("stop_os_area", &fixture, true, 5, false);
  print_visit("stop_os_block", &fixture, true, 6, false);
  print_visit("null_heap", &fixture, true, 0, true);
  puts("CRABC_MI_M6_MAIN_ABANDONED_MIXED_VISITOR_TRACE_END");
  return 0;
}
