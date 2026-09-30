#define _GNU_SOURCE 1
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdio.h>
#include <unistd.h>

#include "mimalloc.h"
#include "mimalloc-stats.h"

enum { ROUNDS = 64 };
#ifdef CRABC_NATIVE_THREAD_DONE_AUDIT
extern size_t crabc_test_thread_done_observation(size_t kind, size_t code);
#endif

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

#ifdef CRABC_NATIVE_THREAD_DONE_INTERLEAVE
extern size_t crabc_test_thread_done_drain_gate_control(size_t action);
static atomic_bool destroy_started;
static atomic_bool destroy_completed;
static bool destroyed_before_drain;
static void* release_drain(void* unused) {
  (void)unused;
  while (crabc_test_thread_done_drain_gate_control(0) != 2) usleep(100);
  while (!atomic_load_explicit(&destroy_started, memory_order_acquire)) usleep(100);
  for (int attempt = 0; attempt < 32; attempt++) {
    if (atomic_load_explicit(&destroy_completed, memory_order_acquire)) break;
    usleep(1000);
  }
  destroyed_before_drain = atomic_load_explicit(&destroy_completed, memory_order_acquire);
  crabc_test_thread_done_drain_gate_control(3);
  return NULL;
}
#endif

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
#ifdef CRABC_NATIVE_THREAD_DONE_INTERLEAVE
    pthread_t releaser;
    if (round == 0) {
      crabc_test_thread_done_drain_gate_control(1);
      if (pthread_create(&releaser, NULL, release_drain, NULL) != 0) _exit(12);
    }
#endif
    if (pthread_create(&second, NULL, worker, &fixture) != 0) _exit(6);
    int waited = pthread_barrier_wait(&fixture.race);
    if (waited != 0 && waited != PTHREAD_BARRIER_SERIAL_THREAD) _exit(7);
    if (!fixture.worker_ready) _exit(8);
    uintptr_t creator_address = (uintptr_t)fixture.creator_block;
#ifdef CRABC_NATIVE_THREAD_DONE_INTERLEAVE
    if (round == 0) {
      while (crabc_test_thread_done_drain_gate_control(0) != 2) usleep(100);
      atomic_store_explicit(&destroy_started, true, memory_order_release);
    }
#endif
    mi_heap_destroy(fixture.heap);
#ifdef CRABC_NATIVE_THREAD_DONE_INTERLEAVE
    if (round == 0) {
      atomic_store_explicit(&destroy_completed, true, memory_order_release);
      if (pthread_join(releaser, NULL) != 0) _exit(13);
    }
#endif
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
#ifdef CRABC_NATIVE_THREAD_DONE_INTERLEAVE
  printf("race.destroy_before_drain=%d\n", destroyed_before_drain);
#endif
#ifdef CRABC_NATIVE_THREAD_DONE_AUDIT
  printf("race.finish=%zu,%zu,%zu,%zu,%zu\n",
         crabc_test_thread_done_observation(0,0), crabc_test_thread_done_observation(0,1),
         crabc_test_thread_done_observation(0,2), crabc_test_thread_done_observation(0,3),
         crabc_test_thread_done_observation(0,4));
  printf("race.refusal=%zu,%zu,%zu,%zu\n",
         crabc_test_thread_done_observation(1,0), crabc_test_thread_done_observation(1,1),
         crabc_test_thread_done_observation(1,2), crabc_test_thread_done_observation(1,3));
#endif
  puts("CRABC_MI_M6_HEAP_DESTROY_RACING_DETACH_END");
  _exit(0);
}
