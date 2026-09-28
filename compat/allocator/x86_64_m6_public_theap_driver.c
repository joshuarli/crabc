#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#include "mimalloc.h"
#ifdef CRABC_M6_SOURCE_INTERNAL
#include "mimalloc/internal.h"
#endif

typedef struct worker_input_s {
  mi_theap_t* parent_default;
  bool complete;
} worker_input_t;

static bool all_zero(const unsigned char* block, size_t size) {
  for (size_t index = 0; index < size; index++) {
    if (block[index] != 0) return false;
  }
  return true;
}

static bool run_case(const char* name, mi_theap_t* parent_default) {
  mi_heap_t* main_heap = mi_heap_main();
  mi_theap_t* base = mi_theap_get_default();
  if (main_heap == NULL || base == NULL) return false;
  printf("%s.base=%d,%d,%d\n", name, mi_heap_theap(main_heap) == base,
         parent_default == NULL || base != parent_default,
         parent_default != NULL && base == parent_default);

  mi_heap_t* heap = mi_heap_new();
  if (heap == NULL) return false;
  mi_theap_t* other = mi_heap_theap(heap);
  if (other == NULL) return false;
#ifdef CRABC_M6_SOURCE_INTERNAL
  fprintf(stderr, "source.%s=%d,%d,%d\n", name,
          _mi_theap_heap(base) == main_heap,
          _mi_theap_heap(other) == heap,
          base->tld == other->tld);
#endif
  printf("%s.other=%d,%d,%d\n", name, other != base,
         mi_theap_get_default() == base, mi_heap_theap(heap) == other);

  mi_theap_t* rejected = mi_theap_set_default(NULL);
  printf("%s.reject=%d,%d\n", name, rejected == base,
         mi_theap_get_default() == base);

  void* direct_before = mi_theap_malloc(other, 64);
  if (direct_before == NULL) return false;
  printf("%s.direct_before=%d,%d\n", name,
         mi_heap_of(direct_before) == heap, mi_theap_get_default() == base);

  mi_theap_t* previous = mi_theap_set_default(other);
  printf("%s.switch=%d,%d,%d\n", name, previous == base,
         mi_theap_get_default() == other, mi_heap_theap(main_heap) == base);

  void* switched = mi_malloc(80);
  void* explicit_main = mi_theap_malloc(base, 96);
  void* zero = mi_theap_zalloc(other, 32);
  if (switched == NULL || explicit_main == NULL || zero == NULL) return false;
  printf("%s.allocate=%d,%d,%d,%d\n", name,
         mi_heap_of(switched) == heap, mi_heap_of(explicit_main) == main_heap,
         mi_heap_of(zero) == heap, all_zero((const unsigned char*)zero, 32));
  printf("%s.still_switched=%d,%d\n", name,
         mi_theap_get_default() == other, mi_heap_theap(heap) == other);

  mi_free(direct_before);
  mi_free(switched);
  mi_free(explicit_main);
  mi_free(zero);
  previous = mi_theap_set_default(base);
  printf("%s.restore=%d,%d\n", name, previous == other,
         mi_theap_get_default() == base);
  void* after = mi_malloc(48);
  if (after == NULL) return false;
  printf("%s.after=%d,%d\n", name, mi_heap_of(after) == main_heap,
         mi_theap_get_default() == base);
  mi_free(after);
  mi_heap_delete(heap);
  printf("%s.done=%d\n", name, mi_theap_get_default() == base);
  return true;
}

static void* worker(void* argument) {
  worker_input_t* input = (worker_input_t*)argument;
  input->complete = run_case("worker", input->parent_default);
  return NULL;
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  puts("CRABC_MI_M6_PUBLIC_THEAP_TRACE_BEGIN");
  if (!run_case("main", NULL)) return 4;
  mi_theap_t* main_default = mi_theap_get_default();
  worker_input_t input = { main_default, false };
  pthread_t thread;
  if (pthread_create(&thread, NULL, worker, &input) != 0) return 2;
  if (pthread_join(thread, NULL) != 0 || !input.complete) return 3;
  printf("main.after_worker=%d\n", mi_theap_get_default() == main_default);
  pid_t child = fork();
  if (child == 0) {
    bool complete = run_case("fork", main_default);
    _exit(complete ? 0 : 5);
  }
  int status = -1;
  bool joined = child > 0 && waitpid(child, &status, 0) == child;
  printf("main.after_fork=%d,%d\n", joined && WIFEXITED(status) && WEXITSTATUS(status) == 0,
         mi_theap_get_default() == main_default);
  puts("CRABC_MI_M6_PUBLIC_THEAP_TRACE_END");
  return 0;
}
