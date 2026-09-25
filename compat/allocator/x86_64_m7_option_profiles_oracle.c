/* Pinned-C half of the allocator M7 option-profile differential.

   Some descriptors decide at process start or only on a page-allocation
   route (`disallow_arena_alloc` and `disallow_os_alloc` in
   `_mi_arenas_page_alloc` and `mi_arenas_try_alloc`, src/arena.c:540-560,
   576-590,790-830). This probe runs under one `mimalloc_*` environment
   image per profile, allocates a fixed set of sizes, and prints for each
   whether it failed and the `mi_memkind_t` of the page that backs it. The
   Rust half is the `native_option_profiles` integration test, run under the
   same image. Driven by `compat/allocator/x86_64_m7_gate.py
   --option-profiles-differential`. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <stdint.h>
#include <stdio.h>
#include "static.c"

static void report(const char* name, size_t size) {
  void* p = mi_malloc(size);
  printf("profile.%s.null=%d\n", name, p == NULL ? 1 : 0);
  printf("profile.%s.memkind=%d\n", name, p == NULL ? -1 : (int)_mi_ptr_page(p)->memid.memkind);
  mi_free(p);
}

/* The arena backing a first small allocation: its size and whether it was
   committed eagerly (the startup `reserve_os_memory` arena, or the first
   `mi_arena_reserve` with `arena_reserve` and `arena_eager_commit`). */
static void report_first_arena(void) {
  void* p = mi_malloc(64);
  mi_page_t* page = (p == NULL ? NULL : _mi_ptr_page(p));
  if (page == NULL || page->memid.memkind != MI_MEM_ARENA) {
    printf("profile.first_arena=none\n");
  } else {
    mi_arena_t* arena = page->memid.mem.arena.arena;
    printf("profile.first_arena=%zu,%d\n", mi_arena_size(arena), arena->memid.initially_committed ? 1 : 0);
  }
  mi_free(p);
}

int main(void) {
  printf("CRABC_MI_M7_OPTION_PROFILES_TRACE_BEGIN\n");
  report_first_arena();
  report("small", 64);
  report("medium", 200 * 1024);
  report("large", 3 * 1024 * 1024);
  report("huge", 48 * 1024 * 1024);
  printf("CRABC_MI_M7_OPTION_PROFILES_TRACE_END\n");
  return 0;
}
