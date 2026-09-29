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
  unsigned char* first;
  unsigned char* second;
  unsigned char* aligned;
  bool first_ready;
  bool second_ready;
} worker_result_t;

static void* first_worker(void* argument) {
  worker_result_t* result = (worker_result_t*)argument;
  result->heap = mi_heap_new();
  result->first = result->heap == NULL ? NULL :
      (unsigned char*)mi_heap_malloc(result->heap, 80);
  if (result->first != NULL) result->first[0] = 0x51;
  result->first_ready = result->heap != NULL && result->first != NULL &&
      mi_heap_of(result->first) == result->heap;
  return NULL;
}

static void* second_worker(void* argument) {
  worker_result_t* result = (worker_result_t*)argument;
  result->second = (unsigned char*)mi_heap_malloc(result->heap, 144);
  result->aligned = (unsigned char*)mi_heap_zalloc_aligned_at(result->heap, 81, 128, 11);
  if (result->second != NULL) result->second[0] = 0x62;
  result->second_ready = result->second != NULL && result->aligned != NULL &&
      mi_heap_of(result->second) == result->heap &&
      mi_heap_of(result->aligned) == result->heap &&
      (((uintptr_t)result->aligned + 11) % 128) == 0 &&
      result->aligned[0] == 0 && result->aligned[80] == 0;
  return NULL;
}

static mi_stats_t stats_now(void) {
  mi_stats_t_decl(stats);
  mi_stats_get(&stats);
  return stats;
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  mi_option_set(mi_option_arena_reserve, 0);
  puts("CRABC_MI_M6_HEAP_DESTROY_AFTER_WORKERS_BEGIN");
  worker_result_t result = {0};
  pthread_t first;
  pthread_t second;
  if (pthread_create(&first, NULL, first_worker, &result) != 0) _exit(2);
  if (pthread_join(first, NULL) != 0) _exit(3);
  if (!result.first_ready) _exit(4);
  printf("workers.first=%d,%d\n", result.first_ready,
         mi_is_in_heap_region(result.first));
  if (pthread_create(&second, NULL, second_worker, &result) != 0) _exit(5);
  if (pthread_join(second, NULL) != 0) _exit(6);
  if (!result.second_ready) _exit(7);
  printf("workers.second=%d,%d,%d,%d\n", result.second_ready,
         mi_is_in_heap_region(result.second),
         mi_is_in_heap_region(result.aligned),
         result.first[0] == 0x51 && result.second[0] == 0x62);

  uintptr_t first_address = (uintptr_t)result.first;
  uintptr_t second_address = (uintptr_t)result.second;
  uintptr_t aligned_address = (uintptr_t)result.aligned;
  mi_stats_t before = stats_now();
  errno = 37;
  mi_heap_destroy(result.heap);
  mi_stats_t after = stats_now();
  printf("workers.destroy=%d,%d,%d,%d\n", errno,
         mi_is_in_heap_region((const void*)first_address),
         mi_is_in_heap_region((const void*)second_address),
         mi_is_in_heap_region((const void*)aligned_address));
  printf("workers.stats=%lld,%lld\n",
         (long long)(after.pages.current - before.pages.current),
         (long long)(after.theaps.current - before.theaps.current));
  mi_collect(true);
  printf("workers.collect=%d,%d,%d\n",
         mi_is_in_heap_region((const void*)first_address),
         mi_is_in_heap_region((const void*)second_address),
         mi_is_in_heap_region((const void*)aligned_address));
  puts("CRABC_MI_M6_HEAP_DESTROY_AFTER_WORKERS_END");
  _exit(0);
}
