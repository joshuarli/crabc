#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <mimalloc.h>
#include <mimalloc-stats.h>

struct callback_state {
  mi_heap_t* heap;
  bool entered;
  bool completed;
};

static void allocate_and_free(const char* message, void* argument) {
  struct callback_state* state = argument;
  assert(message != NULL && state != NULL);
  if (state->entered) return;
  state->entered = true;
  puts("callback-entered");
  fflush(stdout);
  unsigned char* block = mi_heap_malloc(state->heap, 37);
  assert(block != NULL && mi_usable_size(block) >= 37);
  assert(mi_heap_of(block) == state->heap);
  memset(block, 0xa7, 37);
  assert(block[36] == 0xa7);
  mi_free(block);
  state->completed = true;
}

int main(void) {
  mi_heap_t* heap = mi_heap_new();
  assert(heap != NULL);
  void* live = mi_heap_malloc(heap, 43);
  assert(live != NULL);
  struct callback_state state = {.heap = heap};
  mi_subproc_heap_stats_print_out(mi_subproc_main(), allocate_and_free, &state);
  assert(state.entered && state.completed);
  mi_free(live);
  mi_heap_delete(heap);
  puts("non-main-heap-callback=ok");
  return 0;
}
