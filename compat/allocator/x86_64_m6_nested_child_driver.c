#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "mimalloc.h"
#ifdef CRABC_M6_SOURCE_INTERNAL
#include "mimalloc/internal.h"
#endif

typedef struct {
  mi_subproc_id_t outer;
  mi_subproc_id_t inner;
  mi_heap_t* outer_main;
  mi_heap_t* inner_main;
  void* outer_block;
  void* inner_block;
  bool ready;
} fixture_t;

typedef struct {
  mi_heap_t* expected;
  unsigned count;
  bool matched;
} visit_t;

static bool visit_heap(mi_heap_t* heap, void* argument) {
  visit_t* visit = (visit_t*)argument;
  visit->count++;
  if (heap == visit->expected) visit->matched = true;
  return true;
}

static void* outer_owner(void* argument) {
  fixture_t* fixture = (fixture_t*)argument;
  mi_subproc_add_current_thread(fixture->outer);
  fixture->outer_main = mi_heap_main();
  fixture->outer_block = mi_heap_malloc(fixture->outer_main, 80);
  fixture->inner = mi_subproc_new();
  if (fixture->outer_main == NULL || fixture->outer_block == NULL ||
      fixture->inner._mi_subproc_id == NULL) return NULL;
  printf("nested.create=%d,%d,%d,%d\n",
         mi_subproc_current()._mi_subproc_id == fixture->outer._mi_subproc_id,
         mi_heap_of(fixture->outer_block) == fixture->outer_main,
         fixture->inner._mi_subproc_id != fixture->outer._mi_subproc_id,
         mi_heap_of(fixture->inner._mi_subproc_id) == fixture->outer_main);
#ifdef CRABC_M6_SOURCE_INTERNAL
  mi_subproc_t* inner = (mi_subproc_t*)fixture->inner._mi_subproc_id;
  mi_subproc_t* outer = (mi_subproc_t*)fixture->outer._mi_subproc_id;
  fprintf(stderr, "source.nested_parent=%d,%d\n",
          inner->parent == outer,
          mi_heap_of(inner->heap_main) == outer->heap_main);
#endif
  fixture->ready = true;
  return NULL;
}

static void* inner_owner(void* argument) {
  fixture_t* fixture = (fixture_t*)argument;
  mi_subproc_add_current_thread(fixture->inner);
  fixture->inner_main = mi_heap_main();
  fixture->inner_block = mi_heap_malloc(fixture->inner_main, 128);
  if (fixture->inner_main == NULL || fixture->inner_block == NULL) return NULL;
  visit_t visit = { .expected = fixture->inner_main };
  bool completed = mi_subproc_visit_heaps(fixture->inner, visit_heap, &visit);
  printf("nested.owner=%d,%d,%d,%u,%d\n",
         mi_subproc_current()._mi_subproc_id == fixture->inner._mi_subproc_id,
         mi_heap_of(fixture->inner_block) == fixture->inner_main,
         completed, visit.count, visit.matched);
  return (void*)1;
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  puts("CRABC_MI_M6_NESTED_CHILD_BEGIN");
  fixture_t fixture = { .outer = mi_subproc_new() };
  if (fixture.outer._mi_subproc_id == NULL) return 2;
  pthread_t worker;
  void* result;
  if (pthread_create(&worker, NULL, outer_owner, &fixture) != 0) return 3;
  if (pthread_join(worker, NULL) != 0 || !fixture.ready) return 4;
  if (pthread_create(&worker, NULL, inner_owner, &fixture) != 0) return 5;
  if (pthread_join(worker, &result) != 0 || result != (void*)1) return 6;
  printf("nested.after_exit=%d,%d\n",
         mi_heap_of(fixture.outer_block) == fixture.outer_main,
         mi_heap_of(fixture.inner_block) == fixture.inner_main);
  mi_free(fixture.inner_block);
  mi_subproc_destroy(fixture.inner);
  mi_free(fixture.outer_block);
  mi_subproc_destroy(fixture.outer);
  printf("nested.destroyed=%d\n",
         mi_subproc_current()._mi_subproc_id == mi_subproc_main()._mi_subproc_id);
  puts("CRABC_MI_M6_NESTED_CHILD_END");
  return 0;
}
