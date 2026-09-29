#define _GNU_SOURCE 1
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include "mimalloc.h"
#include "mimalloc-stats.h"

enum { ROUNDS = 64 };

typedef struct {
  pthread_barrier_t race;
  mi_heap_t* heap;
  unsigned char* creator_block;
  bool creator_ready;
  bool worker_ready;
} fixture_t;

static void* creator(void* argument) {
  fixture_t* fixture = (fixture_t*)argument;
  fixture->heap = mi_heap_new();
  fixture->creator_block = fixture->heap == NULL ? NULL :
      (unsigned char*)mi_heap_malloc(fixture->heap, 80);
  fixture->creator_ready = fixture->heap != NULL && fixture->creator_block != NULL &&
      mi_heap_of(fixture->creator_block) == fixture->heap;
  return NULL;
}

static void* worker(void* argument) {
  fixture_t* fixture = (fixture_t*)argument;
  unsigned char* block = (unsigned char*)mi_heap_malloc(fixture->heap, 144);
  fixture->worker_ready = block != NULL && mi_heap_of(block) == fixture->heap;
  if (block != NULL) mi_free(block);
  int waited = pthread_barrier_wait(&fixture->race);
  if (waited != 0 && waited != PTHREAD_BARRIER_SERIAL_THREAD) _exit(5);
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
  puts("CRABC_MI_M6_HEAP_DESTROY_RACING_DETACH_BEGIN");
  mi_stats_t before = stats_now();
  int completed = 0;
  for (int round = 0; round < ROUNDS; round++) {
    fixture_t fixture = {0};
    if (pthread_barrier_init(&fixture.race, NULL, 2) != 0) _exit(2);
    pthread_t first;
    pthread_t second;
    if (pthread_create(&first, NULL, creator, &fixture) != 0) _exit(3);
    if (pthread_join(first, NULL) != 0 || !fixture.creator_ready) _exit(4);
    if (pthread_create(&second, NULL, worker, &fixture) != 0) _exit(6);
    int waited = pthread_barrier_wait(&fixture.race);
    if (waited != 0 && waited != PTHREAD_BARRIER_SERIAL_THREAD) _exit(7);
    if (!fixture.worker_ready) _exit(8);
    uintptr_t creator_address = (uintptr_t)fixture.creator_block;
    mi_heap_destroy(fixture.heap);
    if (pthread_join(second, NULL) != 0) _exit(9);
    if (pthread_barrier_destroy(&fixture.race) != 0) _exit(10);
    if (mi_is_in_heap_region((void*)creator_address)) _exit(11);
    completed++;
  }
  mi_stats_t after = stats_now();
  printf("race.completed=%d\n", completed);
  printf("race.owners=%lld,%lld\n",
         (long long)(after.heaps.current - before.heaps.current),
         (long long)(after.theaps.current - before.theaps.current));
  puts("CRABC_MI_M6_HEAP_DESTROY_RACING_DETACH_END");
  _exit(0);
}
