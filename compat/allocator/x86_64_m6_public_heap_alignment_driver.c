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


typedef void (*new_handler_t)(void);
static size_t new_calls;
static void count_new_handler(void) { new_calls++; }
/* Supply the C++ new-handler input through the pinned weak C boundary. */
new_handler_t _ZSt15get_new_handlerv(void) { return count_new_handler; }

/* Keep every exported Heap entry in one content/ownership transaction.
   Small-entry requests remain within their documented size precondition. */
static bool allocation_contract(void) {
  mi_heap_t* growth_heap = mi_heap_new();
  if (growth_heap == NULL) return false;
  bool growth = true;
  for (size_t i = 0; i < 28; i++) {
    unsigned char* block = mi_heap_malloc(growth_heap, 8192);
    growth &= block != NULL;
    if (block != NULL) memset(block, 0x5a, 8192);
  }
  mi_heap_destroy(growth_heap);
  printf("contract.growth=%d\n", growth);
  if (!growth) return false;
  mi_heap_t* heap = mi_heap_new();
  if (heap == NULL) return false;
  unsigned char* live[28];
  size_t sizes[28];
  live[0] = mi_heap_malloc(heap, 73);
  live[1] = mi_heap_zalloc(heap, 73);
  live[2] = mi_heap_calloc(heap, 1, 73);
  live[3] = mi_heap_mallocn(heap, 1, 73);
  live[4] = mi_heap_malloc_small(heap, 73);
  live[5] = mi_heap_zalloc_small(heap, 73);
  live[6] = mi_heap_malloc_aligned(heap, 73, 128);
  live[7] = mi_heap_malloc_aligned_at(heap, 73, 128, 7);
  live[8] = mi_heap_zalloc_aligned(heap, 73, 128);
  live[9] = mi_heap_zalloc_aligned_at(heap, 73, 128, 7);
  live[10] = mi_heap_calloc_aligned(heap, 1, 73, 128);
  live[11] = mi_heap_calloc_aligned_at(heap, 1, 73, 128, 7);
  live[12] = mi_heap_alloc_new(heap, 73);
  live[13] = mi_heap_alloc_new_n(heap, 1, 73);
  bool allocations = true;
  for (size_t i = 0; i < 14; i++) {
    sizes[i] = 73;
    bool zero = i == 1 || i == 2 || i == 5 || (i >= 8 && i <= 11);
    allocations &= live[i] != NULL && mi_heap_of(live[i]) == heap;
    if (zero) allocations &= all_zero(live[i], 73);
    if (i >= 6 && i <= 11) {
      allocations &= live[i] != NULL &&
          (((uintptr_t)live[i] + ((i & 1) ? 7 : 0)) % 128) == 0;
    }
    if (live[i] != NULL) memset(live[i], 0xa5, 73);
  }
  printf("contract.allocations=%d\n", allocations);

  bool strings = true;
  char* text = mi_heap_strdup(heap, "heap-content");
  char* limited = mi_heap_strndup(heap, "heap-content", 4);
  char* path = mi_heap_realpath(heap, "/", NULL);
  strings &= text != NULL && strcmp(text, "heap-content") == 0 && mi_heap_of(text) == heap;
  strings &= limited != NULL && strcmp(limited, "heap") == 0 && mi_heap_of(limited) == heap;
  strings &= path != NULL && strcmp(path, "/") == 0 && mi_heap_of(path) == heap;
  strings &= mi_heap_strdup(heap, NULL) == NULL;
  strings &= mi_heap_strndup(heap, NULL, 4) == NULL;
  strings &= mi_heap_realpath(heap, "/crabc-heap-contract-absent/path", NULL) == NULL;
  live[14] = (unsigned char*)text; sizes[14] = 13;
  live[15] = (unsigned char*)limited; sizes[15] = 5;
  live[16] = (unsigned char*)path; sizes[16] = 2;
  for (size_t i = 14; i < 17; i++) {
    if (live[i] != NULL) memset(live[i], 0xa5, sizes[i]);
  }
  printf("contract.strings=%d\n", strings);

  bool failures = true;
  errno = 0; failures &= mi_heap_malloc(heap, SIZE_MAX) == NULL && errno == ENOMEM;
  errno = 0; failures &= mi_heap_zalloc(heap, SIZE_MAX) == NULL && errno == ENOMEM;
  /* Release count overflow returns before the diagnostic/default errno path. */
  errno = 0; failures &= mi_heap_mallocn(heap, SIZE_MAX, 2) == NULL && errno == 0;
  errno = 0; failures &= mi_heap_calloc(heap, SIZE_MAX, 2) == NULL && errno == 0;
  errno = 0; failures &= mi_heap_calloc_aligned(heap, SIZE_MAX, 2, 128) == NULL && errno == 0;
  errno = 0; failures &= mi_heap_calloc_aligned_at(heap, SIZE_MAX, 2, 128, 7) == NULL && errno == 0;
  errno = 0; failures &= mi_heap_malloc_aligned(heap, 73, 24) == NULL && errno == EINVAL;
  errno = 0; failures &= mi_heap_malloc_aligned_at(heap, 73, 24, 7) == NULL && errno == EINVAL;
  errno = 0; failures &= mi_heap_zalloc_aligned(heap, 73, 24) == NULL && errno == EINVAL;
  errno = 0; failures &= mi_heap_zalloc_aligned_at(heap, 73, 24, 7) == NULL && errno == EINVAL;
  size_t before_new = new_calls;
  errno = 0; failures &= mi_heap_alloc_new(heap, SIZE_MAX) == NULL && errno == ENOMEM;
  errno = 0; failures &= mi_heap_alloc_new_n(heap, SIZE_MAX, 2) == NULL && errno == 0;
  failures &= new_calls == before_new + 2;
  printf("contract.failures=%d\n", failures);

  bool replacements = true;
  for (size_t kind = 0; kind < 10; kind++) {
    unsigned char* old = mi_heap_zalloc(heap, 73);
    if (old == NULL) return false;
    memset(old, 0x6b, 73);
    unsigned char* result = NULL;
    bool zero = kind == 2 || kind == 3 || kind >= 6;
    for (size_t stage = 0; stage < 2; stage++) {
      size_t size = stage == 0 ? SIZE_MAX : 4096;
      errno = 0;
      switch (kind) {
        case 0: result = mi_heap_realloc(heap, old, size); break;
        case 1: result = mi_heap_reallocn(heap, old, 1, size); break;
        case 2: result = mi_heap_rezalloc(heap, old, size); break;
        case 3: result = mi_heap_recalloc(heap, old, 1, size); break;
        case 4: result = mi_heap_realloc_aligned(heap, old, size, 128); break;
        case 5: result = mi_heap_realloc_aligned_at(heap, old, size, 128, 7); break;
        case 6: result = mi_heap_rezalloc_aligned(heap, old, size, 128); break;
        case 7: result = mi_heap_rezalloc_aligned_at(heap, old, size, 128, 7); break;
        case 8: result = mi_heap_recalloc_aligned(heap, old, 1, size, 128); break;
        case 9: result = mi_heap_recalloc_aligned_at(heap, old, 1, size, 128, 7); break;
      }
      if (stage == 0) {
        replacements &= result == NULL && errno != 0;
        for (size_t j = 0; j < 73; j++) replacements &= old[j] == 0x6b;
      } else {
        replacements &= result != NULL && mi_heap_of(result) == heap;
        if (result != NULL) {
          for (size_t j = 0; j < 73; j++) replacements &= result[j] == 0x6b;
          if (zero) replacements &= all_zero(result + 73, size - 73);
          if (kind >= 4) replacements &=
              (((uintptr_t)result + ((kind & 1) ? 7 : 0)) % 128) == 0;
        }
        live[17 + kind] = result; sizes[17 + kind] = 4096;
        if (result != NULL) memset(result, 0xa5, 4096);
      }
    }
  }
  unsigned char* consumed = mi_heap_malloc(heap, 73);
  if (consumed == NULL) return false;
  errno = 0;
  replacements &= mi_heap_reallocf(heap, consumed, SIZE_MAX) == NULL && errno == ENOMEM;
  unsigned char* reallocf_source = mi_heap_malloc(heap, 73);
  if (reallocf_source == NULL) return false;
  memset(reallocf_source, 0xa5, 73);
  live[27] = mi_heap_reallocf(heap, reallocf_source, 4096); sizes[27] = 4096;
  replacements &= live[27] != NULL && mi_heap_of(live[27]) == heap;
  if (live[27] != NULL) {
    for (size_t j = 0; j < 73; j++) replacements &= live[27][j] == 0xa5;
    memset(live[27], 0xa5, 4096);
  }
  /* reallocf consumed its argument; it is never accessed again. */
  printf("contract.replacements=%d\n", replacements);

  mi_heap_delete(heap);
  mi_heap_t* destination = mi_heap_new();
  if (destination == NULL) return false;
  bool lifetime = true;
  for (size_t i = 0; i < 28; i++) {
    if (live[i] == NULL) { lifetime = false; continue; }
    bool before = true;
    for (size_t j = 0; j < sizes[i]; j++) before &= live[i][j] == 0xa5;
    unsigned char* replacement = mi_heap_realloc(destination, live[i], 8192);
    bool owner = replacement != NULL && mi_heap_of(replacement) == destination;
    bool copied = replacement != NULL;
    if (replacement != NULL) {
      for (size_t j = 0; j < sizes[i]; j++) copied &= replacement[j] == 0xa5;
      /* The destination owns every replacement until its destroy below. */
    } else {
      mi_free(live[i]);
    }
    lifetime &= before && owner && copied;
    if (!before || !owner || !copied) {
      fprintf(stderr, "heap contract lifetime item %zu: before=%d owner=%d copied=%d\n",
              i, before, owner, copied);
    }
  }
  unsigned char* terminal = mi_heap_zalloc(destination, 4096);
  lifetime &= all_zero(terminal, 4096);
  mi_heap_destroy(destination);
  /* Destroy consumes the remaining block; no stale client is observed. */
  void* after = mi_malloc(73);
  lifetime &= after != NULL;
  mi_free(after);
  printf("contract.lifetime=%d\n", lifetime);
  return growth && allocations && strings && failures && replacements && lifetime;
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
  bool contract = allocation_contract();
  puts("CRABC_MI_M6_PUBLIC_HEAP_ALIGNMENT_END");
  _exit(cases && worker_state.complete && live_owned && remained &&
        terminal_owned && after != NULL && contract ? 0 : 6);
}
