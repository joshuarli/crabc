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
  mi_heap_t* main_heap;
  uintptr_t regular[3];
  uintptr_t os;
  size_t usable[4];
  bool ready;
} fixture_t;

typedef struct visit_s {
  const fixture_t* fixture;
  const char* stage;
  unsigned areas;
  unsigned blocks;
  unsigned used;
  unsigned stop;
  char order[16];
  unsigned length;
} visit_t;

static void append(visit_t* visit, char event) {
  if (visit->length + 1 >= sizeof(visit->order)) abort();
  visit->order[visit->length++] = event;
  visit->order[visit->length] = '\0';
}

static bool in_area(uintptr_t pointer, const mi_heap_area_t* area) {
  uintptr_t start = (uintptr_t)area->blocks;
  return pointer >= start && pointer - start < area->committed;
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
  if (heap != visit->fixture->main_heap || block_size != area->block_size) {
    fprintf(stderr, "visitor.identity=%d,%zu,%zu\n", heap == visit->fixture->main_heap,
            block_size, area->block_size);
    abort();
  }
  if (block == NULL) {
    if (in_area(visit->fixture->regular[0], area)) {
      visit->areas++;
      visit->used += (unsigned)area->used;
      geometry(visit, area, block, block_size, 'R');
      append(visit, 'R');
      return visit->stop != 1;
    }
    if (in_area(visit->fixture->os, area)) {
      visit->areas++;
      visit->used += (unsigned)area->used;
      geometry(visit, area, block, block_size, 'O');
      append(visit, 'O');
      return true;
    }
    // The child main Heap also owns subprocess metadata pages.
    return true;
  }
  uintptr_t pointer = (uintptr_t)block;
  if (pointer == visit->fixture->regular[0]) {
    visit->blocks++;
    geometry(visit, area, block, block_size, '1');
    append(visit, '1');
    return visit->stop != 2;
  }
  if (pointer == visit->fixture->regular[1]) {
    geometry(visit, area, block, block_size, 'F');
    append(visit, 'F');
    return true;
  }
  if (pointer == visit->fixture->regular[2]) {
    visit->blocks++;
    geometry(visit, area, block, block_size, '3');
    append(visit, '3');
    return true;
  }
  if (pointer == visit->fixture->os) {
    visit->blocks++;
    geometry(visit, area, block, block_size, 'S');
    append(visit, 'S');
    return true;
  }
  // Subprocess metadata blocks are outside the selected client allocations.
  return true;
}

static void print_visit(const char* stage, const fixture_t* fixture,
                        bool abandoned, bool visit_blocks, unsigned stop,
                        bool null_heap) {
  visit_t visit = { .fixture = fixture, .stage = stage, .stop = stop };
  mi_heap_t* heap = null_heap ? NULL : fixture->main_heap;
  bool complete = abandoned
      ? mi_heap_visit_abandoned_blocks(heap, visit_blocks, observe, &visit)
      : mi_heap_visit_blocks(heap, visit_blocks, observe, &visit);
  printf("child_main.%s=%d,%u,%u,%u,%s\n", stage, complete,
         visit.areas, visit.blocks, visit.used, visit.order);
}

static void* owner(void* argument) {
  fixture_t* fixture = (fixture_t*)argument;
  mi_subproc_add_current_thread(fixture->child);
  if (mi_subproc_current()._mi_subproc_id != fixture->child._mi_subproc_id) {
    fputs("owner.admission_failed\n", stderr);
    return NULL;
  }
  fixture->main_heap = mi_heap_main();
  if (fixture->main_heap == NULL) {
    fputs("owner.main_heap_missing\n", stderr);
    return NULL;
  }
  fixture->os = (uintptr_t)mi_heap_malloc_aligned(fixture->main_heap, 10 * 1024 + 1, 128 * 1024);
  for (unsigned index = 0; index < 3; index++) {
    fixture->regular[index] = (uintptr_t)mi_heap_malloc(fixture->main_heap, 128);
  }
  if (!fixture->os || !fixture->regular[0] || !fixture->regular[1] || !fixture->regular[2]) {
    fprintf(stderr, "owner.allocation_failed=%d,%d,%d,%d\n", !!fixture->os,
            !!fixture->regular[0], !!fixture->regular[1], !!fixture->regular[2]);
    return NULL;
  }
  for (unsigned index = 0; index < 3; index++) {
    memset((void*)fixture->regular[index], 0x61 + index, 128);
    fixture->usable[index] = mi_usable_size((void*)fixture->regular[index]);
  }
  memset((void*)fixture->os, 0x71, 10 * 1024 + 1);
  fixture->usable[3] = mi_usable_size((void*)fixture->os);
  mi_free((void*)fixture->regular[1]);
  print_visit("owner_ordinary", fixture, false, true, 0, false);
  print_visit("owner_abandoned", fixture, true, true, 0, false);
  fixture->ready = true;
  return NULL;
}

static void* observer(void* argument) {
  fixture_t* fixture = (fixture_t*)argument;
  mi_subproc_add_current_thread(fixture->child);
  if (mi_subproc_current()._mi_subproc_id != fixture->child._mi_subproc_id ||
      mi_heap_main() != fixture->main_heap) return NULL;
  print_visit("areas", fixture, true, false, 0, false);
  print_visit("blocks", fixture, true, true, 0, false);
  print_visit("stop_area", fixture, true, true, 1, false);
  print_visit("stop_block", fixture, true, true, 2, false);
  print_visit("null_heap", fixture, true, true, 0, true);
  print_visit("ordinary", fixture, false, true, 0, false);
  mi_free((void*)fixture->regular[0]);
  mi_free((void*)fixture->regular[2]);
  mi_free((void*)fixture->os);
  print_visit("after_free", fixture, true, true, 0, false);
  return (void*)1;
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  puts("CRABC_MI_M6_CHILD_MAIN_HEAP_VISITOR_TRACE_BEGIN");
  fixture_t fixture = { .child = mi_subproc_new() };
  if (fixture.child._mi_subproc_id == NULL) return 2;
  pthread_t thread;
  if (pthread_create(&thread, NULL, owner, &fixture) != 0) return 3;
  if (pthread_join(thread, NULL) != 0 || !fixture.ready) return 4;
#ifdef CRABC_M6_SOURCE_INTERNAL
  mi_page_t* regular = _mi_ptr_page((void*)fixture.regular[0]);
  mi_page_t* os = _mi_ptr_page((void*)fixture.os);
  size_t bin = _mi_bin(mi_page_block_size(regular));
  fprintf(stderr, "source.child_main=%d,%d,%d,%d\n",
          mi_page_is_abandoned_mapped(regular),
          (size_t)mi_atomic_load_relaxed(&fixture.main_heap->abandoned_count[bin]) == 1,
          mi_page_is_abandoned(os),
          fixture.main_heap->os_abandoned_pages == os);
#endif
  void* result = NULL;
  if (pthread_create(&thread, NULL, observer, &fixture) != 0) return 5;
  if (pthread_join(thread, &result) != 0 || result != (void*)1) return 6;
  mi_subproc_destroy(fixture.child);
  puts("CRABC_MI_M6_CHILD_MAIN_HEAP_VISITOR_TRACE_END");
  return 0;
}
