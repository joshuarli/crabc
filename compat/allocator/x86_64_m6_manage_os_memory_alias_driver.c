#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>

#include "mimalloc.h"
#ifdef CRABC_M6_SOURCE_INTERNAL
#include "mimalloc/internal.h"
#endif

typedef struct {
  mi_subproc_id_t child;
  void* area;
  size_t size;
  bool done;
} child_alias_t;

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

#ifdef CRABC_M6_SOURCE_INTERNAL
static mi_arena_t* source_arena_at(mi_subproc_t* subproc, void* area) {
  for (size_t index = 0; index < subproc->arena_count; index++) {
    mi_arena_t* arena = mi_atomic_load_ptr_acquire(mi_arena_t, &subproc->arenas[index]);
    if (arena != NULL && arena->start == area) return arena;
  }
  return NULL;
}

static void source_alias_row(const char* name, mi_subproc_t* subproc, void* area) {
  mi_arena_t* arena = source_arena_at(subproc, area);
  fprintf(stderr, "\nsource.%s=%d,%d,%d,%d\n", name, arena != NULL,
          arena != NULL && arena->subproc == subproc,
          arena != NULL && arena->memid.memkind == MI_MEM_EXTERNAL && !arena->is_exclusive,
          arena != NULL && arena->commit_fun == NULL);
}
#endif

static void* child_worker(void* argument) {
  child_alias_t* state = (child_alias_t*)argument;
  mi_subproc_add_current_thread(state->child);
  bool member = mi_subproc_current()._mi_subproc_id == state->child._mi_subproc_id;
  errno = 0;
  bool managed = mi_manage_os_memory(state->area, state->size,
                                      false, false, true, -1);
  bool ordinary_errno = errno == 0;
  errno = 0;
  bool short_region = mi_manage_os_memory(state->area, state->size - 1,
                                           false, false, true, -1);
  unsigned char resident = 0;
  printf("alias.child=%d,%d,%d,%d,%d\n", member, managed, ordinary_errno,
         !short_region && errno == 0,
         mincore(state->area, 4096, &resident) == 0);
#ifdef CRABC_M6_SOURCE_INTERNAL
  source_alias_row("child_alias", (mi_subproc_t*)state->child._mi_subproc_id, state->area);
#endif
  state->done = member && managed && !short_region;
  return NULL;
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  mi_option_set_enabled(mi_option_show_errors, true);
  puts("CRABC_MI_M6_MANAGE_OS_MEMORY_ALIAS_BEGIN");
  size_t minimum = mi_arena_min_size();
  size_t alignment = mi_arena_min_alignment();
  if (minimum == 0 || alignment == 0) return 2;
  void* main_area = aligned_reservation(minimum, alignment);
  void* child_area = aligned_reservation(minimum, alignment);
  if (main_area == NULL || child_area == NULL) return 3;
  errno = 0;
  bool main_managed = mi_manage_os_memory(main_area, minimum,
                                           false, false, true, -1);
  bool ordinary_errno = errno == 0;
  errno = 0;
  bool short_region = mi_manage_os_memory(main_area, minimum - 1,
                                           false, false, true, -1);
  unsigned char resident = 0;
  printf("alias.main=%d,%d,%d,%d\n", main_managed, ordinary_errno,
         !short_region && errno == 0,
         mincore(main_area, 4096, &resident) == 0);
#ifdef CRABC_M6_SOURCE_INTERNAL
  source_alias_row("main_alias", (mi_subproc_t*)mi_subproc_main()._mi_subproc_id, main_area);
#endif
  if (!main_managed || short_region) return 4;
  child_alias_t state = {mi_subproc_new(), child_area, minimum, false};
  if (state.child._mi_subproc_id == NULL) return 5;
  pthread_t worker;
  if (pthread_create(&worker, NULL, child_worker, &state) != 0) return 6;
  if (pthread_join(worker, NULL) != 0 || !state.done) return 7;
  mi_subproc_destroy(state.child);
  bool mapped_after_destroy = mincore(child_area, 4096, &resident) == 0;
  bool caller_released = munmap(child_area, minimum) == 0;
  printf("alias.child_terminal=%d,%d\n", mapped_after_destroy, caller_released);
  puts("CRABC_MI_M6_MANAGE_OS_MEMORY_ALIAS_END");
  return 0;
}
