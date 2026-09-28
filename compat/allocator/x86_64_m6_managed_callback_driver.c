#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

#include "mimalloc.h"
#ifdef CRABC_M6_SOURCE_INTERNAL
#include "mimalloc/internal.h"
#endif

typedef struct {
  bool commit;
  size_t offset;
  size_t size;
  bool zero_output;
} callback_event_t;

typedef struct {
  void* area;
  size_t size;
  callback_event_t events[32];
  size_t count;
  bool valid;
} callback_state_t;

static void* aligned_reservation(size_t size, size_t alignment) {
  void* raw = mmap(NULL, size + alignment, PROT_NONE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (raw == MAP_FAILED) return NULL;
  uintptr_t base = (uintptr_t)raw;
  uintptr_t aligned = (base + alignment - 1) & ~(uintptr_t)(alignment - 1);
  size_t prefix = aligned - base;
  size_t suffix = alignment - prefix;
  if (prefix != 0 && munmap(raw, prefix) != 0) return NULL;
  if (suffix != 0 && munmap((void*)(aligned + size), suffix) != 0) return NULL;
  return (void*)aligned;
}

static bool managed_transition(bool commit, void* start, size_t size,
                               bool* is_zero, void* argument) {
  callback_state_t* state = (callback_state_t*)argument;
  uintptr_t base = (uintptr_t)state->area;
  uintptr_t address = (uintptr_t)start;
  if (address < base || size > state->size || address - base > state->size - size ||
      state->count >= 32 || (address % 4096) != 0 || (size % 4096) != 0) {
    state->valid = false;
    return false;
  }
  state->events[state->count++] = (callback_event_t){
      commit, address - base, size, is_zero != NULL};
  if (commit) {
    if (mprotect(start, size, PROT_READ | PROT_WRITE) != 0) {
      state->valid = false;
      return false;
    }
    if (is_zero != NULL) *is_zero = false;
    return true;
  }
  if (is_zero != NULL || mprotect(start, size, PROT_NONE) != 0) {
    state->valid = false;
    return false;
  }
  return true;
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  mi_option_set_enabled(mi_option_show_errors, true);
  mi_option_set(mi_option_arena_reserve, 0);
  mi_option_set(mi_option_purge_delay, 0);
  puts("CRABC_MI_M6_MANAGED_CALLBACK_BEGIN");
  size_t minimum = mi_arena_min_size();
  size_t alignment = mi_arena_min_alignment();
  if (minimum == 0 || alignment == 0) return 2;
  void* area = aligned_reservation(minimum, alignment);
  if (area == NULL) return 3;
  callback_state_t state = {area, minimum, {{0}}, 0, true};
  mi_arena_id_t rejected = area;
  errno = 0;
  bool short_region = mi_manage_memory(area, minimum - 1, false, false, true,
                                        -1, true, managed_transition, &state, &rejected);
  printf("callback.reject=%d,%d,%d,%d\n", !short_region, rejected == NULL,
         errno == 0, state.count == 0);
  mi_arena_id_t arena = NULL;
  bool managed = mi_manage_memory(area, minimum, false, false, true,
                                  -1, true, managed_transition, &state, &arena);
  printf("callback.manage=%d,%d,%d,%d\n", managed, arena != NULL,
         state.valid, state.count == 1);
#ifdef CRABC_M6_SOURCE_INTERNAL
  fprintf(stderr, "\nsource.callback=%d,%d\n", arena != NULL &&
          ((mi_arena_t*)arena)->commit_fun == managed_transition,
          arena != NULL && ((mi_arena_t*)arena)->commit_fun_arg == &state);
#endif
  if (!managed || arena == NULL) return 4;
  mi_heap_t* heap = mi_heap_new_in_arena(arena);
  void* block = heap == NULL ? NULL : mi_heap_malloc(heap, 64);
  bool in_area = block != NULL && (uintptr_t)block >= (uintptr_t)area &&
                 (uintptr_t)block < (uintptr_t)area + minimum;
  printf("callback.allocation=%d,%d\n", heap != NULL, in_area);
  if (block != NULL) mi_free(block);
  if (heap != NULL) mi_heap_destroy(heap);
  printf("callback.release=%d,%zu\n", state.valid, state.count);
  for (size_t index = 0; index < state.count; index++) {
    callback_event_t event = state.events[index];
    printf("callback.event%zu=%d,%zu,%zu,%d\n", index,
           event.commit, event.offset, event.size, event.zero_output);
  }
  unsigned char resident = 0;
  bool mapped_before_release = mincore(area, 4096, &resident) == 0;
  bool caller_released = munmap(area, minimum) == 0;
  errno = 0;
  bool unmapped = mincore(area, 4096, &resident) != 0 && errno == ENOMEM;
  printf("callback.terminal=%d,%d,%d\n", mapped_before_release,
         caller_released, unmapped);
  puts("CRABC_MI_M6_MANAGED_CALLBACK_END");
  _exit(state.valid && in_area && caller_released && unmapped ? 0 : 5);
}
