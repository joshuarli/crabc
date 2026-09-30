#define _GNU_SOURCE 1
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdio.h>
#include <time.h>
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
  unsigned char* worker_block;
  bool creator_ready;
  bool worker_ready;
  bool park_exit;
} fixture_t;

#ifdef CRABC_C_THREAD_DONE_INTERLEAVE
static atomic_uint source_drain_gate;
static _Thread_local bool park_current_exit;
static void source_deferred_free(bool force, unsigned long long heartbeat, void* unused) {
  (void)heartbeat;
  (void)unused;
  unsigned int armed = 1;
  if (force && park_current_exit &&
      atomic_compare_exchange_strong_explicit(&source_drain_gate, &armed, 2,
                                              memory_order_acq_rel, memory_order_acquire)) {
    while (atomic_load_explicit(&source_drain_gate, memory_order_acquire) == 2) {}
  }
}
#endif

static void* creator(void* argument) {
  fixture_t* fixture = (fixture_t*)argument;
  fixture->heap = mi_heap_new();
  fixture->creator_block = fixture->heap == NULL ? NULL :
      (unsigned char*)mi_heap_malloc(fixture->heap, 80);
  if (fixture->creator_block != NULL) fixture->creator_block[0] = 0x31;
  fixture->creator_ready = fixture->heap != NULL && fixture->creator_block != NULL &&
      mi_heap_of(fixture->creator_block) == fixture->heap;
  return NULL;
}

static void* worker(void* argument) {
  fixture_t* fixture = (fixture_t*)argument;
  unsigned char* block = (unsigned char*)mi_heap_malloc(fixture->heap, 144);
  fixture->worker_block = block;
  if (block != NULL) block[0] = 0x52;
  fixture->worker_ready = block != NULL && mi_heap_of(block) == fixture->heap;
  if (block != NULL && !fixture->park_exit) mi_free(block);
  int waited = pthread_barrier_wait(&fixture->race);
  if (waited != 0 && waited != PTHREAD_BARRIER_SERIAL_THREAD) _exit(5);
#ifdef CRABC_C_THREAD_DONE_INTERLEAVE
  park_current_exit = fixture->park_exit;
#endif
  return NULL;
}

#if defined(CRABC_NATIVE_THREAD_DONE_INTERLEAVE) || defined(CRABC_C_THREAD_DONE_INTERLEAVE)
#ifdef CRABC_NATIVE_THREAD_DONE_INTERLEAVE
extern size_t crabc_test_thread_done_drain_gate_control(size_t action);
#endif
static size_t drain_control(size_t action) {
#ifdef CRABC_NATIVE_THREAD_DONE_INTERLEAVE
  return crabc_test_thread_done_drain_gate_control(action);
#else
  if (action == 1 || action == 3)
    atomic_store_explicit(&source_drain_gate, (unsigned int)action, memory_order_release);
  return atomic_load_explicit(&source_drain_gate, memory_order_acquire);
#endif
}
static double monotonic_now(void) {
  struct timespec value;
  if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) _exit(14);
  return (double)value.tv_sec + (double)value.tv_nsec / 1000000000.0;
}
static atomic_bool releaser_ready;
static atomic_bool destroy_started;
static atomic_bool destroy_completed;
static bool destroyed_before_drain;
static bool preserved_before_retry;
static int64_t wait_baseline;
static int64_t observed_waits;
static mi_subproc_id_t main_subprocess;
static int64_t heap_waits(void) {
  mi_stats_t_decl(stats);
  if (!mi_subproc_stats_get_exclusive(main_subprocess, &stats)) _exit(15);
  return stats.heaps_delete_wait.total;
}
static void* release_drain(void* argument) {
  fixture_t* fixture = (fixture_t*)argument;
  if (mi_theap_get_default() == NULL) _exit(21);
  atomic_store_explicit(&releaser_ready, true, memory_order_release);
  double deadline = monotonic_now() + 15.0;
  while (drain_control(0) != 2 ||
         !atomic_load_explicit(&destroy_started, memory_order_acquire)) {
    if (monotonic_now() >= deadline) _exit(16);
    usleep(100);
  }
  // Only a failed detach try-lock advances this source counter. Keep the
  // worker's drain parked until the destroyer has actually failed that lock.
  while ((observed_waits = heap_waits() - wait_baseline) <= 0) {
    if (monotonic_now() >= deadline) _exit(17);
    usleep(100);
  }
  destroyed_before_drain = atomic_load_explicit(&destroy_completed, memory_order_acquire);
  // The parked Theap prevents Heap detachment and page retirement. Inspect
  // these live clients before releasing the lock that permits the retry.
  preserved_before_retry = drain_control(0) == 2 && !destroyed_before_drain &&
      mi_is_in_heap_region(fixture->creator_block) &&
      mi_is_in_heap_region(fixture->worker_block) &&
      fixture->creator_block[0] == 0x31 && fixture->worker_block[0] == 0x52;
  drain_control(3);
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
#ifdef CRABC_C_THREAD_DONE_INTERLEAVE
  mi_register_deferred_free(source_deferred_free, NULL);
#endif
#if defined(CRABC_NATIVE_THREAD_DONE_INTERLEAVE) || defined(CRABC_C_THREAD_DONE_INTERLEAVE)
  main_subprocess = mi_subproc_main();
#endif
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
#if defined(CRABC_NATIVE_THREAD_DONE_INTERLEAVE) || defined(CRABC_C_THREAD_DONE_INTERLEAVE)
    pthread_t releaser;
    if (round == 0) {
      fixture.park_exit = true;
      drain_control(1);
      if (pthread_create(&releaser, NULL, release_drain, &fixture) != 0) _exit(12);
      double deadline = monotonic_now() + 15.0;
      while (!atomic_load_explicit(&releaser_ready, memory_order_acquire)) {
        if (monotonic_now() >= deadline) _exit(18);
        usleep(100);
      }
      wait_baseline = heap_waits();
    }
#endif
    if (pthread_create(&second, NULL, worker, &fixture) != 0) _exit(6);
    int waited = pthread_barrier_wait(&fixture.race);
    if (waited != 0 && waited != PTHREAD_BARRIER_SERIAL_THREAD) _exit(7);
    if (!fixture.worker_ready) _exit(8);
    uintptr_t creator_address = (uintptr_t)fixture.creator_block;
#if defined(CRABC_NATIVE_THREAD_DONE_INTERLEAVE) || defined(CRABC_C_THREAD_DONE_INTERLEAVE)
    if (round == 0) {
      double deadline = monotonic_now() + 15.0;
      while (drain_control(0) != 2) {
        if (monotonic_now() >= deadline) _exit(19);
        usleep(100);
      }
      atomic_store_explicit(&destroy_started, true, memory_order_release);
    }
#endif
    mi_heap_destroy(fixture.heap);
#if defined(CRABC_NATIVE_THREAD_DONE_INTERLEAVE) || defined(CRABC_C_THREAD_DONE_INTERLEAVE)
    if (round == 0) {
      atomic_store_explicit(&destroy_completed, true, memory_order_release);
      if (pthread_join(releaser, NULL) != 0) _exit(13);
    }
#endif
    if (pthread_join(second, NULL) != 0) _exit(9);
    if (pthread_barrier_destroy(&fixture.race) != 0) _exit(10);
    if (mi_is_in_heap_region((void*)creator_address)) _exit(11);
    if (fixture.park_exit && mi_is_in_heap_region(fixture.worker_block)) _exit(20);
    completed++;
  }
  mi_stats_t after = stats_now();
  printf("race.completed=%d\n", completed);
  printf("race.owners=%lld,%lld\n",
         (long long)(after.heaps.current - before.heaps.current),
         (long long)(after.theaps.current - before.theaps.current));
#if defined(CRABC_NATIVE_THREAD_DONE_INTERLEAVE) || defined(CRABC_C_THREAD_DONE_INTERLEAVE)
  printf("race.destroy_before_drain=%d\n", destroyed_before_drain);
  printf("race.contention_waits=%lld\n", (long long)observed_waits);
  printf("race.preserved_before_retry=%d\n", preserved_before_retry);
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
