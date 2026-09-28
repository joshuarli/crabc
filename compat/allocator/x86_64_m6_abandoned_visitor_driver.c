#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "mimalloc.h"

typedef struct fixture_s {
  mi_heap_t* heap;
  unsigned char* blocks[3];
  bool ready;
} fixture_t;

typedef struct visit_s {
  unsigned areas;
  unsigned blocks;
  unsigned used;
  size_t block_size;
  unsigned tags;
  unsigned stop;
} visit_t;

static bool observe(const mi_heap_t* heap, const mi_heap_area_t* area,
                    void* block, size_t block_size, void* argument) {
  (void)heap;
  visit_t* visit = (visit_t*)argument;
  if (block == NULL) {
    visit->areas++;
    visit->used += (unsigned)area->used;
    visit->block_size = area->block_size;
    return visit->stop != 1;
  }
  visit->blocks++;
  visit->tags = visit->tags * 10 + *(unsigned char*)block;
  if (block_size != area->block_size) abort();
  return visit->stop != 2;
}

static void print_visit(const char* name, mi_heap_t* heap, bool abandoned,
                        bool visit_blocks, unsigned stop) {
  visit_t visit = { 0 };
  visit.stop = stop;
  bool complete = abandoned
    ? mi_heap_visit_abandoned_blocks(heap, visit_blocks, observe, &visit)
    : mi_heap_visit_blocks(heap, visit_blocks, observe, &visit);
  printf("abandoned.%s=%d,%u,%u,%u,%zu,%u\n", name, complete,
         visit.areas, visit.blocks, visit.used, visit.block_size, visit.tags);
}

static void* worker(void* argument) {
  fixture_t* fixture = (fixture_t*)argument;
  for (unsigned index = 0; index < 3; index++) {
    fixture->blocks[index] = (unsigned char*)mi_heap_malloc(fixture->heap, 128);
    if (fixture->blocks[index] == NULL) return NULL;
    fixture->blocks[index][0] = (unsigned char)(index + 1);
  }
  mi_free(fixture->blocks[1]);
  fixture->ready = true;
  return NULL;
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  puts("CRABC_MI_M6_ABANDONED_VISITOR_TRACE_BEGIN");
  fixture_t fixture = { 0 };
  fixture.heap = mi_heap_new();
  if (fixture.heap == NULL) return 2;
  print_visit("before", fixture.heap, true, true, 0);
  pthread_t thread;
  if (pthread_create(&thread, NULL, worker, &fixture) != 0) return 3;
  if (pthread_join(thread, NULL) != 0 || !fixture.ready) return 4;
  print_visit("areas", fixture.heap, true, false, 0);
  print_visit("blocks", fixture.heap, true, true, 0);
  print_visit("stop_area", fixture.heap, true, true, 1);
  print_visit("stop_block", fixture.heap, true, true, 2);
  print_visit("ordinary", fixture.heap, false, true, 0);
  mi_heap_destroy(fixture.heap);
  puts("CRABC_MI_M6_ABANDONED_VISITOR_TRACE_END");
  return 0;
}
