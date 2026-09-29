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
  mi_subproc_id_t child;
  mi_heap_t* main_heap;
  mi_theap_t* first_theap;
  uintptr_t block[4];
  bool ready;
} fixture_t;

typedef struct visit_s {
  const fixture_t* fixture;
  unsigned areas;
  unsigned blocks;
  unsigned used;
  char order[32];
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

static bool observe(const mi_heap_t* heap, const mi_heap_area_t* area,
                    void* block, size_t block_size, void* argument) {
  visit_t* visit = (visit_t*)argument;
  if (heap != visit->fixture->main_heap || block_size != area->block_size) abort();
  if (block == NULL) {
    for (unsigned index = 0; index < 4; index++) {
      if (visit->fixture->block[index] != 0 && in_area(visit->fixture->block[index], area)) {
        visit->areas++;
        visit->used += (unsigned)area->used;
        append(visit, "ABOP"[index]);
        return true;
      }
    }
    return true;
  }
  for (unsigned index = 0; index < 4; index++) {
    if ((uintptr_t)block == visit->fixture->block[index]) {
      visit->blocks++;
      append(visit, "1234"[index]);
      return true;
    }
  }
  return true;
}

static void visit(const char* stage, const fixture_t* fixture, bool abandoned) {
  visit_t state = { .fixture = fixture };
  bool complete = abandoned
      ? mi_heap_visit_abandoned_blocks(fixture->main_heap, true, observe, &state)
      : mi_heap_visit_blocks(fixture->main_heap, true, observe, &state);
  printf("reuse.%s=%d,%u,%u,%u,%s\n", stage, complete, state.areas,
         state.blocks, state.used, state.order);
}

static void* first_worker(void* argument) {
  fixture_t* fixture = (fixture_t*)argument;
  mi_subproc_add_current_thread(fixture->child);
  fixture->main_heap = mi_heap_main();
  fixture->first_theap = mi_heap_theap(fixture->main_heap);
  fixture->block[0] = (uintptr_t)mi_heap_malloc(fixture->main_heap, 128);
  fixture->block[2] = (uintptr_t)mi_heap_malloc_aligned(fixture->main_heap, 10 * 1024 + 1, 128 * 1024);
  fixture->ready = fixture->main_heap != NULL && fixture->first_theap != NULL &&
      fixture->block[0] != 0 && fixture->block[2] != 0;
  if (fixture->ready) {
    printf("reuse.first_owner=%d,%d,%d\n",
           mi_subproc_current()._mi_subproc_id == fixture->child._mi_subproc_id,
           mi_heap_of((void*)fixture->block[0]) == fixture->main_heap,
           mi_heap_of((void*)fixture->block[2]) == fixture->main_heap);
    visit("first_live", fixture, false);
  }
  return NULL;
}

static void* second_worker(void* argument) {
  fixture_t* fixture = (fixture_t*)argument;
  mi_subproc_add_current_thread(fixture->child);
  mi_heap_t* main_heap = mi_heap_main();
  mi_theap_t* second_theap = mi_heap_theap(main_heap);
  printf("reuse.reattached=%d,%d,%d,%d\n",
         mi_subproc_current()._mi_subproc_id == fixture->child._mi_subproc_id,
         main_heap == fixture->main_heap,
         second_theap != NULL && second_theap == fixture->first_theap,
         mi_theap_get_default() == second_theap);
  visit("first_exited", fixture, true);
  fixture->block[1] = (uintptr_t)mi_heap_malloc(main_heap, 128);
  fixture->block[3] = (uintptr_t)mi_heap_malloc_aligned(main_heap, 10 * 1024 + 1, 128 * 1024);
  if (!fixture->block[1] || !fixture->block[3]) return NULL;
  printf("reuse.second_owner=%d,%d,%d,%d\n",
         mi_heap_of((void*)fixture->block[0]) == main_heap,
         mi_heap_of((void*)fixture->block[1]) == main_heap,
         mi_heap_of((void*)fixture->block[2]) == main_heap,
         mi_heap_of((void*)fixture->block[3]) == main_heap);
  visit("second_live", fixture, false);
  visit("second_abandoned", fixture, true);
  return (void*)1;
}

static void* final_worker(void* argument) {
  fixture_t* fixture = (fixture_t*)argument;
  mi_subproc_add_current_thread(fixture->child);
  printf("reuse.final_reattached=%d,%d\n", mi_heap_main() == fixture->main_heap,
         mi_heap_theap(fixture->main_heap) == fixture->first_theap);
  visit("second_exited", fixture, true);
  for (unsigned index = 0; index < 4; index++) {
    mi_free((void*)fixture->block[index]);
  }
  visit("freed", fixture, true);
  return (void*)1;
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  puts("CRABC_MI_M6_CHILD_MAIN_HEAP_REUSE_BEGIN");
  fixture_t fixture = { .child = mi_subproc_new() };
  if (fixture.child._mi_subproc_id == NULL) return 2;
  pthread_t thread;
  void* result;
  if (pthread_create(&thread, NULL, first_worker, &fixture) != 0) return 3;
  if (pthread_join(thread, NULL) != 0 || !fixture.ready) return 4;
  if (pthread_create(&thread, NULL, second_worker, &fixture) != 0) return 5;
  if (pthread_join(thread, &result) != 0 || result != (void*)1) return 6;
#ifdef CRABC_M6_SOURCE_INTERNAL
  mi_subproc_t* child = (mi_subproc_t*)fixture.child._mi_subproc_id;
  mi_page_t* first = _mi_ptr_page((void*)fixture.block[0]);
  mi_page_t* second = _mi_ptr_page((void*)fixture.block[1]);
  mi_page_t* first_os = _mi_ptr_page((void*)fixture.block[2]);
  mi_page_t* second_os = _mi_ptr_page((void*)fixture.block[3]);
  size_t bin = _mi_bin(mi_page_block_size(first));
  fprintf(stderr, "source.reuse=%d,%d,%d,%d,%d,%d,%d,%d,%d,%zu\n",
          child->heap_main == fixture.main_heap,
          (size_t)mi_atomic_load_relaxed(&child->heap_count) == 1,
          child->heaps == fixture.main_heap && fixture.main_heap->next == NULL,
          first == second,
          mi_page_is_abandoned_mapped(first),
          mi_page_is_abandoned_mapped(second),
          mi_page_is_abandoned(first_os),
          mi_page_is_abandoned(second_os),
          fixture.main_heap->os_abandoned_pages == second_os && second_os->next == first_os,
          (size_t)mi_atomic_load_relaxed(&fixture.main_heap->abandoned_count[bin]));
#endif
  if (pthread_create(&thread, NULL, final_worker, &fixture) != 0) return 7;
  if (pthread_join(thread, &result) != 0 || result != (void*)1) return 8;
  mi_subproc_destroy(fixture.child);
  puts("CRABC_MI_M6_CHILD_MAIN_HEAP_REUSE_END");
  return 0;
}
