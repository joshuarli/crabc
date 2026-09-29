#define _GNU_SOURCE 1
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include "mimalloc.h"
#include "mimalloc-stats.h"

typedef struct {
  mi_heap_t* heap;
  unsigned char* regular;
  unsigned char* singleton;
} owner_result_t;

static void* owner(void* argument) {
  owner_result_t* result = (owner_result_t*)argument;
  result->heap = mi_heap_new();
  result->regular = result->heap == NULL ? NULL :
      (unsigned char*)mi_heap_malloc(result->heap, 80);
  result->singleton = result->heap == NULL ? NULL :
      (unsigned char*)mi_heap_zalloc_aligned_at(result->heap, 81, 128, 11);
  if (result->regular != NULL) result->regular[0] = 0x5a;
  return NULL;
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  mi_option_set(mi_option_arena_reserve, 0);
  puts("CRABC_MI_M6_HEAP_DELETE_AFTER_OWNER_EXIT_BEGIN");
  owner_result_t result = {0};
  pthread_t thread;
  if (pthread_create(&thread, NULL, owner, &result) != 0) _exit(2);
  if (pthread_join(thread, NULL) != 0) _exit(3);
  bool created = result.heap != NULL && result.regular != NULL &&
      result.singleton != NULL;
  printf("exit.created=%d\n", created);
  if (!created) _exit(4);
  printf("exit.live=%d,%d,%d,%d\n",
      mi_heap_of(result.regular) == result.heap,
      mi_heap_of(result.singleton) == result.heap,
      result.regular[0] == 0x5a,
      result.singleton[0] == 0 && result.singleton[80] == 0);
  // Save address bits before delete/free; later PageMap probes never
  // dereference the former Heap or blocks.
  uintptr_t heap_address = (uintptr_t)result.heap;
  uintptr_t regular_address = (uintptr_t)result.regular;
  uintptr_t singleton_address = (uintptr_t)result.singleton;
  errno = 37;
  mi_heap_delete(result.heap);
  printf("exit.deleted=%d,%d,%d,%d\n",
      (uintptr_t)mi_heap_of((const void*)regular_address) == heap_address,
      (uintptr_t)mi_heap_of((const void*)singleton_address) == heap_address,
      mi_is_in_heap_region((const void*)regular_address),
      mi_is_in_heap_region((const void*)singleton_address));
  mi_free(result.regular);
  mi_free(result.singleton);
  printf("exit.freed=%d,%d,%d\n", errno,
      mi_is_in_heap_region((const void*)regular_address),
      mi_is_in_heap_region((const void*)singleton_address));
  mi_collect(true);
  printf("exit.collected=%d,%d\n",
      mi_is_in_heap_region((const void*)regular_address),
      mi_is_in_heap_region((const void*)singleton_address));
  puts("CRABC_MI_M6_HEAP_DELETE_AFTER_OWNER_EXIT_END");
  _exit(0);
}
