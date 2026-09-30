#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mimalloc.h"
#ifdef CRABC_M6_SOURCE_INTERNAL
#include "mimalloc/internal.h"
#endif

typedef struct fixture_s {
  mi_subproc_id_t child;
  mi_heap_t* heap;
  uintptr_t regular[3];
  uintptr_t os;
  size_t usable[4];
  bool ready;
} fixture_t;

typedef struct visit_s {
  const fixture_t* fixture;
  const char* stage;
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

// Callbacks read retained clients only; the owner has joined before remote
// observation, and no callback allocates, frees, or changes Heap membership.
static void geometry(const visit_t* visit, const mi_heap_area_t* area,
                     const void* block, size_t block_size, char kind) {
  size_t usable = 0;
  if (block != NULL && kind != 'F') {
    unsigned index = kind == '1' ? 0 : kind == '3' ? 2 : 3;
    size_t requested = index == 3 ? 10 * 1024 + 1 : 128;
    unsigned char expected = index == 3 ? 0x71 : (unsigned char)(0x61 + index);
    const unsigned char* bytes = (const unsigned char*)block;
    for (size_t offset = 0; offset < requested; offset++) {
      if (bytes[offset] != expected) abort();
    }
    usable = visit->fixture->usable[index];
    if (usable < requested) abort();
  }
  fprintf(stderr, "geometry.%s=%c,%zu,%zu,%zu,%zu,%zu,%zu,%zu\n",
          visit->stage, kind, area->reserved, area->committed, area->used,
          area->block_size, area->full_block_size, block_size, usable);
}

static bool observe(const mi_heap_t* heap, const mi_heap_area_t* area,
                    void* block, size_t block_size, void* argument) {
  visit_t* visit = (visit_t*)argument;
  if (heap != visit->fixture->heap || block_size != area->block_size) abort();
  if (block == NULL) {
    if (in_area(visit->fixture->regular[0], area)) {
      visit->regular_areas++;
      visit->regular_used += (unsigned)area->used;
      geometry(visit, area, block, block_size, 'R');
      append(visit, 'R');
      return visit->stop != 1;
    }
    if (in_area(visit->fixture->os, area)) {
      visit->os_areas++;
      visit->os_used += (unsigned)area->used;
      geometry(visit, area, block, block_size, 'O');
      append(visit, 'O');
      return true;
    }
    abort();
  }
  uintptr_t address = (uintptr_t)block;
  if (address == visit->fixture->regular[0]) {
    visit->regular_blocks++;
    geometry(visit, area, block, block_size, '1');
    append(visit, '1');
    return visit->stop != 2;
  }
  if (address == visit->fixture->regular[1]) {
    visit->freed_blocks++;
    geometry(visit, area, block, block_size, 'F');
    append(visit, 'F');
    return true;
  }
  if (address == visit->fixture->regular[2]) {
    visit->regular_blocks++;
    geometry(visit, area, block, block_size, '3');
    append(visit, '3');
    return visit->stop != 2;
  }
  if (address == visit->fixture->os) {
    visit->os_blocks++;
    geometry(visit, area, block, block_size, 'S');
    append(visit, 'S');
    return true;
  }
  abort();
}

static void print_visit(const char* name, const fixture_t* fixture,
                        bool abandoned, bool visit_blocks, unsigned stop) {
  visit_t visit = { 0 };
  visit.fixture = fixture;
  visit.stage = name;
  visit.stop = stop;
  bool complete = abandoned
    ? mi_heap_visit_abandoned_blocks(fixture->heap, visit_blocks, observe, &visit)
    : mi_heap_visit_blocks(fixture->heap, visit_blocks, observe, &visit);
  printf("child.%s=%d,%u,%u,%u,%u,%u,%u,%u,%s\n", name, complete,
         visit.regular_areas, visit.os_areas, visit.regular_blocks,
         visit.os_blocks, visit.freed_blocks, visit.regular_used,
         visit.os_used, visit.order);
}

static void* worker(void* argument) {
  fixture_t* fixture = (fixture_t*)argument;
  mi_subproc_add_current_thread(fixture->child);
  if (mi_subproc_current()._mi_subproc_id != fixture->child._mi_subproc_id) return NULL;
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
  for (unsigned index = 0; index < 3; index++) {
    memset((void*)fixture->regular[index], 0x61 + index, 128);
    fixture->usable[index] = mi_usable_size((void*)fixture->regular[index]);
  }
  memset((void*)fixture->os, 0x71, 10 * 1024 + 1);
  fixture->usable[3] = mi_usable_size((void*)fixture->os);
  mi_free((void*)fixture->regular[1]);
  fixture->ready = true;
  return NULL;
}

static void* visitor_worker(void* argument) {
  fixture_t* fixture = (fixture_t*)argument;
  mi_subproc_add_current_thread(fixture->child);
  if (mi_subproc_current()._mi_subproc_id != fixture->child._mi_subproc_id) return NULL;
  print_visit("areas", fixture, true, false, 0);
  print_visit("blocks", fixture, true, true, 0);
  print_visit("stop_regular_area", fixture, true, true, 1);
  print_visit("stop_regular_block", fixture, true, true, 2);
  print_visit("ordinary", fixture, false, true, 0);
  return NULL;
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  puts("CRABC_MI_M6_CHILD_ABANDONED_VISITOR_TRACE_BEGIN");
  fixture_t fixture = { .child = mi_subproc_new() };
  if (fixture.child._mi_subproc_id == NULL) return 2;
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
  if (pthread_create(&thread, NULL, visitor_worker, &fixture) != 0) return 4;
  if (pthread_join(thread, NULL) != 0) return 5;
  mi_subproc_destroy(fixture.child);
  puts("CRABC_MI_M6_CHILD_ABANDONED_VISITOR_TRACE_END");
  return 0;
}
