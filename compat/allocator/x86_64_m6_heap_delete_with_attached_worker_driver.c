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
  pthread_mutex_t lock;
  pthread_cond_t condition;
  int stage;
  mi_heap_t* heap;
  unsigned char* owner_block;
  unsigned char* worker_block;
  unsigned char* worker_aligned;
  bool owner_ready;
  bool worker_ready;
} fixture_t;

static void* creator(void* argument) {
  fixture_t* fixture = (fixture_t*)argument;
  fixture->heap = mi_heap_new();
  fixture->owner_block = fixture->heap == NULL ? NULL :
      (unsigned char*)mi_heap_malloc(fixture->heap, 80);
  if (fixture->owner_block != NULL) fixture->owner_block[0] = 0x31;
  fixture->owner_ready = fixture->heap != NULL && fixture->owner_block != NULL &&
      mi_heap_of(fixture->owner_block) == fixture->heap;
  return NULL;
}

static void* attached_worker(void* argument) {
  fixture_t* fixture = (fixture_t*)argument;
  fixture->worker_block = (unsigned char*)mi_heap_malloc(fixture->heap, 144);
  fixture->worker_aligned = (unsigned char*)mi_heap_zalloc_aligned_at(fixture->heap, 81, 128, 11);
  if (fixture->worker_block != NULL) fixture->worker_block[0] = 0x52;
  fixture->worker_ready = fixture->worker_block != NULL && fixture->worker_aligned != NULL &&
      mi_heap_of(fixture->worker_block) == fixture->heap &&
      mi_heap_of(fixture->worker_aligned) == fixture->heap &&
      (((uintptr_t)fixture->worker_aligned + 11) % 128) == 0 &&
      fixture->worker_aligned[0] == 0 && fixture->worker_aligned[80] == 0;
  if (pthread_mutex_lock(&fixture->lock) != 0) _exit(5);
  fixture->stage = 1;
  pthread_cond_signal(&fixture->condition);
  while (fixture->stage != 2) pthread_cond_wait(&fixture->condition, &fixture->lock);
  pthread_mutex_unlock(&fixture->lock);
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
  puts("CRABC_MI_M6_HEAP_DELETE_WITH_ATTACHED_WORKER_BEGIN");
  fixture_t fixture = { .lock = PTHREAD_MUTEX_INITIALIZER,
                        .condition = PTHREAD_COND_INITIALIZER };
  pthread_t owner;
  pthread_t worker;
  if (pthread_create(&owner, NULL, creator, &fixture) != 0) _exit(2);
  if (pthread_join(owner, NULL) != 0) _exit(3);
  if (!fixture.owner_ready) _exit(4);
  printf("attached.owner=%d,%d\n", fixture.owner_ready,
         mi_is_in_heap_region(fixture.owner_block));
  if (pthread_create(&worker, NULL, attached_worker, &fixture) != 0) _exit(6);
  if (pthread_mutex_lock(&fixture.lock) != 0) _exit(7);
  while (fixture.stage != 1) pthread_cond_wait(&fixture.condition, &fixture.lock);
  pthread_mutex_unlock(&fixture.lock);
  if (!fixture.worker_ready) _exit(8);
  printf("attached.live=%d,%d,%d,%d\n", fixture.worker_ready,
         mi_is_in_heap_region(fixture.worker_block),
         mi_is_in_heap_region(fixture.worker_aligned),
         fixture.owner_block[0] == 0x31 && fixture.worker_block[0] == 0x52);
  uintptr_t owner_address = (uintptr_t)fixture.owner_block;
  uintptr_t worker_address = (uintptr_t)fixture.worker_block;
  uintptr_t aligned_address = (uintptr_t)fixture.worker_aligned;
  mi_stats_t before = stats_now();
  errno = 37;
  mi_heap_delete(fixture.heap);
  mi_stats_t after = stats_now();
  printf("attached.delete=%d,%d,%d,%d\n", errno,
         mi_is_in_heap_region((void*)owner_address),
         mi_is_in_heap_region((void*)worker_address),
         mi_is_in_heap_region((void*)aligned_address));
  printf("attached.stats=%lld,%lld\n",
         (long long)(after.pages.current - before.pages.current),
         (long long)(after.theaps.current - before.theaps.current));
  if (pthread_mutex_lock(&fixture.lock) != 0) _exit(9);
  fixture.stage = 2;
  pthread_cond_signal(&fixture.condition);
  pthread_mutex_unlock(&fixture.lock);
  if (pthread_join(worker, NULL) != 0) _exit(10);
  mi_free(fixture.owner_block);
  mi_free(fixture.worker_block);
  mi_free(fixture.worker_aligned);
  mi_collect(true);
  printf("attached.joined=%d,%d,%d\n",
         mi_is_in_heap_region((void*)owner_address),
         mi_is_in_heap_region((void*)worker_address),
         mi_is_in_heap_region((void*)aligned_address));
  puts("CRABC_MI_M6_HEAP_DELETE_WITH_ATTACHED_WORKER_END");
  _exit(0);
}
