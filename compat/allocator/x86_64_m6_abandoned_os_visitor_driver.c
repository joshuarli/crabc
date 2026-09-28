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
  mi_heap_t* heap;
  uintptr_t live;
  uintptr_t freed;
  bool ready;
} fixture_t;

typedef struct visit_s {
  const fixture_t* fixture;
  unsigned areas;
  unsigned blocks;
  unsigned used;
  unsigned live_area;
  unsigned live_block;
  unsigned freed_area;
  unsigned freed_block;
  unsigned order;
  unsigned stop;
} visit_t;

static bool in_area(uintptr_t pointer, const mi_heap_area_t* area) {
  uintptr_t start = (uintptr_t)area->blocks;
  return pointer >= start && pointer - start < area->committed;
}

static bool observe(const mi_heap_t* heap, const mi_heap_area_t* area,
                    void* block, size_t block_size, void* argument) {
  visit_t* visit = (visit_t*)argument;
  if (heap != visit->fixture->heap || block_size != area->block_size) abort();
  if (block == NULL) {
    visit->areas++;
    visit->used += (unsigned)area->used;
    visit->live_area += in_area(visit->fixture->live, area);
    visit->freed_area += in_area(visit->fixture->freed, area);
    visit->order = visit->order * 10 + 1;
    return visit->stop != 1;
  }
  visit->blocks++;
  visit->live_block += (uintptr_t)block == visit->fixture->live;
  visit->freed_block += (uintptr_t)block == visit->fixture->freed;
  visit->order = visit->order * 10 + 2;
  return visit->stop != 2;
}

static void print_visit(const char* name, const fixture_t* fixture,
                        bool abandoned, bool visit_blocks, unsigned stop) {
  visit_t visit = { 0 };
  visit.fixture = fixture;
  visit.stop = stop;
  bool complete = abandoned
    ? mi_heap_visit_abandoned_blocks(fixture->heap, visit_blocks, observe, &visit)
    : mi_heap_visit_blocks(fixture->heap, visit_blocks, observe, &visit);
  printf("os.%s=%d,%u,%u,%u,%u,%u,%u,%u,%u\n", name, complete,
         visit.areas, visit.blocks, visit.used, visit.live_area,
         visit.live_block, visit.freed_area, visit.freed_block, visit.order);
}

static void* worker(void* argument) {
  fixture_t* fixture = (fixture_t*)argument;
  fixture->heap = mi_heap_new();
  if (fixture->heap == NULL) return NULL;
  void* live = mi_heap_malloc_aligned(fixture->heap, 10 * 1024 + 1, 128 * 1024);
  void* freed = mi_heap_malloc_aligned(fixture->heap, 10 * 1024 + 1, 128 * 1024);
  if (live == NULL || freed == NULL) return NULL;
  fixture->live = (uintptr_t)live;
  fixture->freed = (uintptr_t)freed;
#ifdef CRABC_M6_SOURCE_INTERNAL
  fprintf(stderr, "source.os=%d,%d\n",
          mi_memid_is_os(_mi_ptr_page(live)->memid),
          mi_memid_is_os(_mi_ptr_page(freed)->memid));
#endif
  mi_free(freed);
  fixture->ready = true;
  return NULL;
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  puts("CRABC_MI_M6_ABANDONED_OS_VISITOR_TRACE_BEGIN");
  fixture_t fixture = { 0 };
  pthread_t thread;
  if (pthread_create(&thread, NULL, worker, &fixture) != 0) return 2;
  if (pthread_join(thread, NULL) != 0 || !fixture.ready) return 3;
#ifdef CRABC_M6_SOURCE_INTERNAL
  mi_page_t* page = _mi_ptr_page((void*)fixture.live);
  fprintf(stderr, "source.transfer=%d,%d,%d\n",
          mi_page_is_abandoned(page), mi_page_heap(page) == fixture.heap,
          fixture.heap->os_abandoned_pages == page);
#endif
  print_visit("areas", &fixture, true, false, 0);
  print_visit("blocks", &fixture, true, true, 0);
  print_visit("stop_area", &fixture, true, true, 1);
  print_visit("stop_block", &fixture, true, true, 2);
  print_visit("ordinary", &fixture, false, true, 0);
  puts("CRABC_MI_M6_ABANDONED_OS_VISITOR_TRACE_END");
  return 0;
}
