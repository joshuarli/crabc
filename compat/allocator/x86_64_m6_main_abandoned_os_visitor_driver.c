#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "mimalloc.h"
#ifdef CRABC_M6_SOURCE_INTERNAL
#include "mimalloc/internal.h"
#endif

typedef struct fixture_s {
  uintptr_t live;
  uintptr_t freed;
  uintptr_t keeper;
  bool ready;
} fixture_t;

typedef struct visit_s {
  const fixture_t* fixture;
  unsigned areas;
  unsigned live_areas;
  unsigned freed_areas;
  unsigned keeper_areas;
  unsigned live_blocks;
  unsigned freed_blocks;
  unsigned keeper_blocks;
  unsigned used;
  unsigned stop;
  char order[32];
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
    visit->used += (unsigned)area->used;
    if (in_area(visit->fixture->live, area)) {
      visit->live_areas++;
      append(visit, 'O');
      return visit->stop != 1;
    }
    if (in_area(visit->fixture->freed, area)) {
      visit->freed_areas++;
      append(visit, 'F');
    } else if (in_area(visit->fixture->keeper, area)) {
      visit->keeper_areas++;
      append(visit, 'K');
    } else {
      append(visit, 'X');
    }
    return true;
  }
  uintptr_t pointer = (uintptr_t)block;
  if (pointer == visit->fixture->live) {
    visit->live_blocks++;
    append(visit, '1');
    return visit->stop != 2;
  }
  if (pointer == visit->fixture->freed) {
    visit->freed_blocks++;
    append(visit, 'F');
  } else if (pointer == visit->fixture->keeper) {
    visit->keeper_blocks++;
    append(visit, 'K');
  } else {
    append(visit, 'x');
  }
  return true;
}

static void print_visit(const char* name, const fixture_t* fixture,
                        bool visit_blocks, unsigned stop, bool null_heap) {
  visit_t visit = { 0 };
  visit.fixture = fixture;
  visit.stop = stop;
  mi_heap_t* heap = null_heap ? NULL : mi_heap_main();
  bool complete = mi_heap_visit_abandoned_blocks(heap, visit_blocks, observe, &visit);
  printf("main_os.%s=%d,%u,%u,%u,%u,%u,%u,%u,%u,%s\n", name, complete,
         visit.areas, visit.live_areas, visit.freed_areas, visit.keeper_areas,
         visit.live_blocks, visit.freed_blocks, visit.keeper_blocks, visit.used,
         visit.order);
}

static void* worker(void* argument) {
  fixture_t* fixture = (fixture_t*)argument;
  mi_heap_t* heap = mi_heap_main();
  void* live = mi_heap_malloc_aligned(heap, 10 * 1024 + 1, 128 * 1024);
  void* freed = mi_heap_malloc_aligned(heap, 10 * 1024 + 1, 128 * 1024);
  if (live == NULL || freed == NULL) return NULL;
  fixture->live = (uintptr_t)live;
  fixture->freed = (uintptr_t)freed;
#ifdef CRABC_M6_SOURCE_INTERNAL
  fprintf(stderr, "source.worker_os=%d,%d\n",
          mi_memid_is_os(_mi_ptr_page(live)->memid),
          mi_memid_is_os(_mi_ptr_page(freed)->memid));
  mi_page_t* freed_page = _mi_ptr_page(freed);
  bool was_list_head = heap->os_abandoned_pages == freed_page;
#endif
  mi_free(freed);
#ifdef CRABC_M6_SOURCE_INTERNAL
  fprintf(stderr, "source.freed_removed=%d,%d\n", was_list_head,
          heap->os_abandoned_pages != freed_page);
#endif
  fixture->ready = true;
  return NULL;
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  puts("CRABC_MI_M6_MAIN_ABANDONED_OS_VISITOR_TRACE_BEGIN");
  fixture_t fixture = { 0 };
  fixture.keeper = (uintptr_t)mi_heap_malloc_aligned(mi_heap_main(), 10 * 1024 + 1, 128 * 1024);
  if (fixture.keeper == 0) return 4;
#ifdef CRABC_M6_SOURCE_INTERNAL
  mi_page_t* initial_keeper = _mi_ptr_page((void*)fixture.keeper);
  fprintf(stderr, "source.keeper=%d,%d,%d,%d\n",
          mi_memid_is_os(initial_keeper->memid),
          mi_page_heap(initial_keeper) == mi_heap_main(),
          mi_page_is_abandoned(initial_keeper),
          mi_heap_main()->os_abandoned_pages == initial_keeper);
#endif
  print_visit("before", &fixture, false, 0, false);
  pthread_t thread;
  if (pthread_create(&thread, NULL, worker, &fixture) != 0) return 2;
  if (pthread_join(thread, NULL) != 0 || !fixture.ready) return 3;
#ifdef CRABC_M6_SOURCE_INTERNAL
  mi_heap_t* heap = mi_heap_main();
  mi_page_t* page = _mi_ptr_page((void*)fixture.live);
  mi_page_t* keeper = _mi_ptr_page((void*)fixture.keeper);
  fprintf(stderr, "source.selected=%d,%d,%d,%d,%d,%d,%d\n",
          mi_memid_is_os(page->memid), mi_page_is_abandoned(page),
          mi_page_heap(page) == heap, heap->os_abandoned_pages == page,
          page->next == keeper, keeper != page,
          mi_memid_is_os(keeper->memid) && mi_page_is_abandoned(keeper));
#endif
  print_visit("areas", &fixture, false, 0, false);
  print_visit("blocks", &fixture, true, 0, false);
  print_visit("stop_area", &fixture, true, 1, false);
  print_visit("stop_block", &fixture, true, 2, false);
  print_visit("null_heap", &fixture, true, 0, true);
  puts("CRABC_MI_M6_MAIN_ABANDONED_OS_VISITOR_TRACE_END");
  return 0;
}
