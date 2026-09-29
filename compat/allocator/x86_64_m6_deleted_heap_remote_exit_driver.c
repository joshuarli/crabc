#define _GNU_SOURCE 1
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "mimalloc.h"
#include "mimalloc-stats.h"

typedef struct remote_exit_state_s {
  pthread_mutex_t lock;
  pthread_cond_t changed;
  int stage;
  bool exit_before_free;
  mi_heap_t* deleted_heap;
  unsigned char* block;
  bool ready;
  bool deleted_identity;
  bool deleted_region;
  bool remote_identity;
  bool remote_region;
  bool remote_owned;
  int remote_errno;
} remote_exit_state_t;

static void advance(remote_exit_state_t* state, int stage) {
  pthread_mutex_lock(&state->lock);
  state->stage = stage;
  pthread_cond_broadcast(&state->changed);
  pthread_mutex_unlock(&state->lock);
}

static void await_stage(remote_exit_state_t* state, int stage) {
  pthread_mutex_lock(&state->lock);
  while (state->stage < stage) pthread_cond_wait(&state->changed, &state->lock);
  pthread_mutex_unlock(&state->lock);
}

static void* owning_worker(void* argument) {
  remote_exit_state_t* state = (remote_exit_state_t*)argument;
  mi_heap_t* heap = mi_heap_new();
  unsigned char* block = heap == NULL ? NULL :
      (unsigned char*)mi_heap_zalloc_aligned_at(heap, 81, 128, 11);
  state->deleted_heap = heap;
  state->block = block;
  state->ready = heap != NULL && block != NULL &&
      (((uintptr_t)block + 11) % 128) == 0 && block[0] == 0 && block[80] == 0 &&
      mi_heap_of(block) == heap;
  puts("remote.event_alloc=1");
  if (heap != NULL) mi_heap_delete(heap);
  puts("remote.event_deleted=1");
  state->deleted_identity = block != NULL && mi_heap_of(block) == heap;
  state->deleted_region = block != NULL && mi_is_in_heap_region(block);
  advance(state, 1);
  await_stage(state, state->exit_before_free ? 2 : 4);
  puts("remote.event_owner_return=1");
  return NULL;
}

static void* freeing_worker(void* argument) {
  remote_exit_state_t* state = (remote_exit_state_t*)argument;
  await_stage(state, state->exit_before_free ? 3 : 2);
  unsigned char* block = state->block;
  state->remote_identity = block != NULL && mi_heap_of(block) == state->deleted_heap;
  puts("remote.event_free_start=1");
  errno = 37;
  if (block != NULL) mi_free(block);
  puts("remote.event_free_done=1");
  state->remote_errno = errno;
  state->remote_region = block != NULL && mi_is_in_heap_region(block);
  state->remote_owned = block != NULL && mi_check_owned(block);
  advance(state, state->exit_before_free ? 4 : 3);
  return NULL;
}

static mi_stats_t stats_now(void) {
  mi_stats_t_decl(stats);
  mi_stats_get(&stats);
  return stats;
}

int main(int argc, char** argv) {
  setvbuf(stdout, NULL, _IONBF, 0);
  mi_option_set(mi_option_arena_reserve, 0);
  remote_exit_state_t state = {
      .lock = PTHREAD_MUTEX_INITIALIZER,
      .changed = PTHREAD_COND_INITIALIZER,
      .exit_before_free = argc > 1 && strcmp(argv[1], "after") == 0,
  };
  puts("CRABC_MI_M6_DELETED_HEAP_REMOTE_EXIT_BEGIN");
  pthread_t owner;
  pthread_t remote;
  if (pthread_create(&owner, NULL, owning_worker, &state) != 0) _exit(2);
  if (pthread_create(&remote, NULL, freeing_worker, &state) != 0) _exit(3);
  await_stage(&state, 1);
  mi_stats_t after_delete = stats_now();
  mi_stats_t after_first;
  mi_stats_t after_second;
  bool first_region;
  if (state.exit_before_free) {
    advance(&state, 2);
    pthread_join(owner, NULL);
    puts("remote.event_owner_exit=1");
    after_first = stats_now();
    first_region = state.block != NULL && mi_is_in_heap_region(state.block);
    advance(&state, 3);
    await_stage(&state, 4);
    pthread_join(remote, NULL);
    after_second = stats_now();
  } else {
    advance(&state, 2);
    await_stage(&state, 3);
    pthread_join(remote, NULL);
    after_first = stats_now();
    first_region = state.block != NULL && mi_is_in_heap_region(state.block);
    advance(&state, 4);
    pthread_join(owner, NULL);
    puts("remote.event_owner_exit=1");
    after_second = stats_now();
  }
  bool exit_region = state.block != NULL && mi_is_in_heap_region(state.block);
  bool exit_owned = state.block != NULL && mi_check_owned(state.block);
  mi_collect(true);
  mi_stats_t after_collect = stats_now();
  bool collect_region = state.block != NULL && mi_is_in_heap_region(state.block);
  bool collect_owned = state.block != NULL && mi_check_owned(state.block);
  printf("remote.mode=%d,%d\n", state.exit_before_free, first_region);
  printf("remote.ready=%d,%d,%d\n", state.ready, state.deleted_identity, state.deleted_region);
  printf("remote.published=%d,%d,%d,%d\n", state.remote_identity,
         state.remote_region, state.remote_owned, state.remote_errno);
  printf("remote.exit=%d,%d\n", exit_region, exit_owned);
  printf("remote.collect=%d,%d\n", collect_region, collect_owned);
  printf("remote.stats=%lld,%lld,%lld,%lld,%lld,%lld\n",
         (long long)(after_first.pages.current - after_delete.pages.current),
         (long long)(after_second.pages.current - after_first.pages.current),
         (long long)(after_collect.pages.current - after_second.pages.current),
         (long long)(after_first.theaps.current - after_delete.theaps.current),
         (long long)(after_second.theaps.current - after_first.theaps.current),
         (long long)(after_collect.theaps.current - after_second.theaps.current));
  puts("CRABC_MI_M6_DELETED_HEAP_REMOTE_EXIT_END");
  _exit(state.ready ? 0 : 4);
}
