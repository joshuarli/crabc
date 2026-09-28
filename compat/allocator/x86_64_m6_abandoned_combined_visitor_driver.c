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
  uintptr_t regular[3];
  uintptr_t os;
  bool ready;
} fixture_t;

typedef struct visit_s {
  const fixture_t* fixture;
  unsigned regular_areas;
  unsigned os_areas;
  unsigned regular_blocks;
  unsigned os_blocks;
  unsigned freed_blocks;
  unsigned regular_used;
  unsigned os_used;
  unsigned stop;
  char order[8];
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
  if (heap != visit->fixture->heap || block_size != area->block_size) abort();
  if (block == NULL) {
    if (in_area(visit->fixture->regular[0], area)) {
      visit->regular_areas++;
      visit->regular_used += (unsigned)area->used;
      append(visit, 'R');
      return visit->stop != 1;
    }
    if (in_area(visit->fixture->os, area)) {
      visit->os_areas++;
      visit->os_used += (unsigned)area->used;
      append(visit, 'O');
      return true;
    }
    abort();
  }
  uintptr_t address = (uintptr_t)block;
  if (address == visit->fixture->regular[0]) {
    visit->regular_blocks++;
    append(visit, '1');
    return visit->stop != 2;
  }
  if (address == visit->fixture->regular[1]) {
    visit->freed_blocks++;
    append(visit, 'F');
    return true;
  }
  if (address == visit->fixture->regular[2]) {
    visit->regular_blocks++;
    append(visit, '3');
    return visit->stop != 2;
  }
  if (address == visit->fixture->os) {
    visit->os_blocks++;
    append(visit, 'S');
    return true;
  }
  abort();
}

static void print_visit(const char* name, const fixture_t* fixture,
                        bool abandoned, bool visit_blocks, unsigned stop) {
  visit_t visit = { 0 };
  visit.fixture = fixture;
  visit.stop = stop;
  bool complete = abandoned
    ? mi_heap_visit_abandoned_blocks(fixture->heap, visit_blocks, observe, &visit)
    : mi_heap_visit_blocks(fixture->heap, visit_blocks, observe, &visit);
  printf("combined.%s=%d,%u,%u,%u,%u,%u,%u,%u,%s\n", name, complete,
         visit.regular_areas, visit.os_areas, visit.regular_blocks,
         visit.os_blocks, visit.freed_blocks, visit.regular_used,
         visit.os_used, visit.order);
}

static void* worker(void* argument) {
  fixture_t* fixture = (fixture_t*)argument;
  fixture->heap = mi_heap_new();
  if (fixture->heap == NULL) return NULL;
  void* os = mi_heap_malloc_aligned(fixture->heap, 10 * 1024 + 1, 128 * 1024);
  if (os == NULL) return NULL;
  fixture->os = (uintptr_t)os;
  for (unsigned index = 0; index < 3; index++) {
    void* block = mi_heap_malloc(fixture->heap, 128);
    if (block == NULL) return NULL;
    fixture->regular[index] = (uintptr_t)block;
  }
  mi_free((void*)fixture->regular[1]);
  fixture->ready = true;
  return NULL;
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  puts("CRABC_MI_M6_ABANDONED_COMBINED_VISITOR_TRACE_BEGIN");
  fixture_t fixture = { 0 };
  pthread_t thread;
  if (pthread_create(&thread, NULL, worker, &fixture) != 0) return 2;
  if (pthread_join(thread, NULL) != 0 || !fixture.ready) return 3;
#ifdef CRABC_M6_SOURCE_INTERNAL
  mi_page_t* regular = _mi_ptr_page((void*)fixture.regular[0]);
  mi_page_t* os = _mi_ptr_page((void*)fixture.os);
  size_t bin = _mi_bin(mi_page_block_size(regular));
  fprintf(stderr, "source.transfer=%d,%d,%d,%d,%d\n",
          mi_page_is_abandoned_mapped(regular),
          mi_page_is_abandoned(os) && !mi_page_is_abandoned_mapped(os),
          fixture.heap->os_abandoned_pages == os,
          (size_t)mi_atomic_load_relaxed(&fixture.heap->abandoned_count[bin]) == 1,
          mi_memid_is_os(os->memid));
#endif
  print_visit("areas", &fixture, true, false, 0);
  print_visit("blocks", &fixture, true, true, 0);
  print_visit("stop_regular_area", &fixture, true, true, 1);
  print_visit("stop_regular_block", &fixture, true, true, 2);
  print_visit("ordinary", &fixture, false, true, 0);
  puts("CRABC_MI_M6_ABANDONED_COMBINED_VISITOR_TRACE_END");
  return 0;
}
