#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "mimalloc.h"

static bool all_zero(const unsigned char* bytes, size_t size) {
  if (bytes == NULL) return false;
  for (size_t i = 0; i < size; i++) {
    if (bytes[i] != 0) return false;
  }
  return true;
}

typedef struct {
  mi_heap_t* heap;
  mi_theap_t* main_theap;
  bool complete;
} worker_state_t;

static void* worker_allocate(void* argument) {
  worker_state_t* state = (worker_state_t*)argument;
  errno = 0;
  unsigned char* block = (unsigned char*)mi_heap_zalloc_aligned_at(
      state->heap, 1000, 256, 31);
  mi_theap_t* theap = mi_heap_theap(state->heap);
  printf("alignment.worker=%d,%d,%d,%d,%d,%d\n",
      block != NULL, block != NULL && (((uintptr_t)block + 31) % 256) == 0,
      all_zero(block, 1000), block != NULL && mi_heap_of(block) == state->heap,
      theap != NULL && theap != state->main_theap, errno == 0);
  state->complete = block != NULL && theap != NULL && theap != state->main_theap;
  if (block != NULL) mi_free(block);
  return NULL;
}

static bool success_case(mi_heap_t* heap, size_t size, size_t alignment,
                         size_t offset, size_t index) {
  errno = 0;
  unsigned char* block = (unsigned char*)mi_heap_zalloc_aligned_at(
      heap, size, alignment, offset);
  bool present = block != NULL;
  bool aligned = present && (((uintptr_t)block + offset) % alignment) == 0;
  bool zero = all_zero(block, size);
  bool owner = present && mi_heap_of(block) == heap && mi_heap_contains(heap, block);
  bool usable = present && mi_usable_size(block) >= size;
  bool unchanged = errno == 0;
  printf("alignment.case%zu=%d,%d,%d,%d,%d,%d\n", index,
         present, aligned, zero, owner, usable, unchanged);
  if (present) {
    memset(block, 0xa5, size);
    mi_free(block);
  }
  return present && aligned && zero && owner && usable && unchanged;
}

static void failure_case(mi_heap_t* heap, size_t size, size_t alignment,
                         size_t offset, size_t index) {
  errno = 0;
  void* block = mi_heap_zalloc_aligned_at(heap, size, alignment, offset);
  printf("alignment.failure%zu=%d,%d\n", index, block == NULL, errno);
  if (block != NULL) mi_free(block);
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  mi_option_set_enabled(mi_option_show_errors, true);
  mi_option_set(mi_option_arena_reserve, 0);
  puts("CRABC_MI_M6_PUBLIC_HEAP_ALIGNMENT_BEGIN");
  mi_heap_t* heap = mi_heap_new();
  mi_theap_t* main_theap = heap == NULL ? NULL : mi_heap_theap(heap);
  printf("alignment.heap=%d,%d\n", heap != NULL, main_theap != NULL);
  if (heap == NULL || main_theap == NULL) return 2;
  unsigned char* dirty = (unsigned char*)mi_heap_malloc(heap, 73);
  if (dirty == NULL) return 3;
  memset(dirty, 0xa5, 73);
  mi_free(dirty);
  bool cases = true;
  cases &= success_case(heap, 24, 8, 0, 0);
  cases &= success_case(heap, 73, 128, 7, 1);
  cases &= success_case(heap, 7, 64, 19, 2);
  cases &= success_case(heap, 1024, 4096, 1, 3);
  cases &= success_case(heap, 8192, 65536, 13, 4);
  cases &= success_case(heap, 4096, 1024 * 1024, 0, 5);
  failure_case(heap, 64, 24, 0, 0);
  failure_case(heap, 64, 0, 0, 1);
  failure_case(heap, SIZE_MAX, 64, 0, 2);
  failure_case(heap, 64, 1024 * 1024, 1, 3);
  worker_state_t worker_state = {heap, main_theap, false};
  pthread_t worker;
  if (pthread_create(&worker, NULL, worker_allocate, &worker_state) != 0) return 4;
  if (pthread_join(worker, NULL) != 0) return 5;
  unsigned char* live = (unsigned char*)mi_heap_zalloc_aligned_at(heap, 73, 128, 7);
  bool live_owned = live != NULL && mi_heap_of(live) == heap && all_zero(live, 73);
  printf("alignment.before_delete=%d,%d\n", live_owned, worker_state.complete);
  mi_heap_delete(heap);
  bool retained_owner = live != NULL && mi_heap_of(live) == heap;
  bool main_owner = live != NULL && mi_heap_of(live) == mi_heap_main();
  bool remained = live != NULL && live[0] == 0 && live[72] == 0;
  printf("alignment.after_delete=%d,%d,%d\n", retained_owner,
         main_owner, remained);
  if (live != NULL) mi_free(live);
  puts("alignment.freed_after_delete=1");
  mi_heap_t* destroyed = mi_heap_new();
  printf("alignment.second_heap=%d\n", destroyed != NULL);
  unsigned char* terminal = destroyed == NULL ? NULL :
      (unsigned char*)mi_heap_zalloc_aligned_at(destroyed, 81, 128, 11);
  bool terminal_owned = terminal != NULL && mi_heap_of(terminal) == destroyed &&
      all_zero(terminal, 81);
  printf("alignment.second_block=%d\n", terminal_owned);
  if (destroyed != NULL) mi_heap_destroy(destroyed);
  puts("alignment.second_destroyed=1");
  void* after = mi_malloc(64);
  printf("alignment.destroy=%d,%d\n", terminal_owned, after != NULL);
  if (after != NULL) mi_free(after);
  puts("CRABC_MI_M6_PUBLIC_HEAP_ALIGNMENT_END");
  _exit(cases && worker_state.complete && live_owned && remained &&
        terminal_owned && after != NULL ? 0 : 6);
}
