#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "mimalloc.h"
#ifdef CRABC_M6_SOURCE_INTERNAL
#include "mimalloc/internal.h"
#include "mimalloc/prim-tls.h"
#endif

typedef struct worker_state_s {
  mi_subproc_id_t child;
  bool complete;
} worker_state_t;

typedef struct visit_state_s {
  mi_heap_t* expected[3];
  size_t count;
  bool ordered;
} visit_state_t;

static bool visit_heap(mi_heap_t* heap, void* argument) {
  visit_state_t* state = (visit_state_t*)argument;
  if (state->count >= 3 || heap != state->expected[state->count]) state->ordered = false;
  state->count++;
  return true;
}

static bool visit_is(mi_subproc_id_t child, mi_heap_t* first, mi_heap_t* second,
                     mi_heap_t* third, size_t count) {
  visit_state_t state = {{first, second, third}, 0, true};
  return mi_subproc_visit_heaps(child, visit_heap, &state) && state.ordered && state.count == count;
}

#ifdef CRABC_M6_SOURCE_INTERNAL
static void source_heap_image(mi_subproc_id_t id, mi_heap_t* main, mi_heap_t* first,
                              mi_heap_t* second, mi_theap_t* base,
                              mi_theap_t* first_theap, mi_theap_t* second_theap) {
  mi_subproc_t* child = (mi_subproc_t*)id._mi_subproc_id;
  const size_t index_bits = sizeof(size_t) * 8 / 4;
  const size_t index_mask = ((size_t)1 << index_bits) - 1;
  fprintf(stderr, "source.initial=%d,%zu,%zu,%zu\n",
          child->heap_main == main && main->subproc == child,
          main->heap_seq, first->heap_seq, second->heap_seq);
  fprintf(stderr, "source.list=%d,%d,%d,%zu\n",
          child->heaps == second && second->prev == NULL && second->next == first,
          first->prev == second && first->next == main,
          main->prev == first && main->next == NULL,
          (size_t)mi_atomic_load_relaxed(&child->heap_count));
  fprintf(stderr, "source.keys=%zu,%zu,%zu,%zu\n",
          first->theap & index_mask, first->theap >> index_bits,
          second->theap & index_mask, second->theap >> index_bits);
  fprintf(stderr, "source.theaps=%d,%d,%d,%zu\n",
          first->theaps == first_theap && second->theaps == second_theap,
          first_theap != NULL && second_theap != NULL &&
              first_theap->tld == base->tld && second_theap->tld == base->tld,
          base->tld->theaps == second_theap && second_theap->tnext == first_theap &&
              first_theap->tnext == base,
          base->tld->thread_seq);
}

static void source_reuse(mi_subproc_id_t id, mi_heap_t* third, size_t prior_key) {
  mi_subproc_t* child = (mi_subproc_t*)id._mi_subproc_id;
  const size_t index_bits = sizeof(size_t) * 8 / 4;
  const size_t index_mask = ((size_t)1 << index_bits) - 1;
  fprintf(stderr, "source.reuse=%d,%zu,%zu,%zu\n",
          child->heaps == third && third->next == child->heap_main &&
              child->heap_main->prev == third,
          third->theap & index_mask, third->theap >> index_bits,
          prior_key & index_mask);
}
#endif

static void* child_worker(void* argument) {
  worker_state_t* state = (worker_state_t*)argument;
  mi_subproc_add_current_thread(state->child);
  mi_heap_t* main = mi_heap_main();
  mi_theap_t* base = mi_theap_get_default();
  printf("child.preflight=%d,%d\n", main != NULL, base != NULL);
  if (main == NULL || base == NULL) return NULL;
  printf("child.initial=%d,%d\n", mi_subproc_current()._mi_subproc_id == state->child._mi_subproc_id,
         mi_heap_theap(main) == base);

  mi_heap_t* first = mi_heap_new();
  mi_heap_t* second = mi_heap_new();
  if (first == NULL || second == NULL) return NULL;
  printf("child.created=%d,%d,%d\n", first != main, second != main && second != first,
         visit_is(state->child, second, first, main, 3));

  mi_theap_t* first_theap = mi_heap_theap(first);
  mi_theap_t* second_theap = mi_heap_theap(second);
  printf("child.theaps=%d,%d,%d,%d\n", first_theap != NULL, second_theap != NULL,
         first_theap != base && second_theap != base && first_theap != second_theap,
         mi_theap_get_default() == base);
#ifdef CRABC_M6_SOURCE_INTERNAL
  if (first_theap == NULL || second_theap == NULL) return NULL;
  source_heap_image(state->child, main, first, second, base, first_theap, second_theap);
  const size_t first_key = first->theap;
#endif
  mi_theap_t* main_reselected = mi_heap_theap(main);
  printf("child.main_reselected=%d,%d\n", main_reselected == base,
         mi_theap_get_default() == base);
#ifdef CRABC_M6_SOURCE_INTERNAL
  fprintf(stderr, "source.main_cached=%d\n", _mi_theap_cached() == base);
#endif
  void* block = mi_heap_malloc(first, 64);
  if (block == NULL) return NULL;
  printf("child.owned=%d,%d\n", mi_heap_of(block) == first, mi_heap_contains(first, block));

  mi_heap_delete(first);
  printf("child.deleted=%d,%d\n", visit_is(state->child, second, main, NULL, 2),
         mi_heap_of(block) == main);
  mi_free(block);
  mi_heap_destroy(second);
  printf("child.destroyed=%d\n", visit_is(state->child, main, NULL, NULL, 1));

  mi_heap_t* third = mi_heap_new();
  if (third == NULL) return NULL;
  printf("child.recreated=%d\n", visit_is(state->child, third, main, NULL, 2));
#ifdef CRABC_M6_SOURCE_INTERNAL
  source_reuse(state->child, third, first_key);
#endif
  mi_heap_delete(third);
  printf("child.restored=%d\n", visit_is(state->child, main, NULL, NULL, 1));
  state->complete = true;
  return NULL;
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  puts("CRABC_MI_M6_PUBLIC_CHILD_HEAP_BEGIN");
  worker_state_t state = {mi_subproc_new(), false};
  if (state.child._mi_subproc_id == NULL) return 2;
  pthread_t worker;
  if (pthread_create(&worker, NULL, child_worker, &state) != 0) return 3;
  if (pthread_join(worker, NULL) != 0 || !state.complete) return 4;
  printf("child.joined=%d\n", state.complete);
  mi_subproc_destroy(state.child);
  printf("child.teardown=%d\n", mi_subproc_current()._mi_subproc_id == mi_subproc_main()._mi_subproc_id);
  puts("CRABC_MI_M6_PUBLIC_CHILD_HEAP_END");
  return 0;
}
