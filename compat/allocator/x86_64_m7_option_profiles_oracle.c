/* Pinned-C half of the allocator M7 option-profile differential.

   Some descriptors decide at process start or only on a page-allocation
   route (`disallow_arena_alloc` and `disallow_os_alloc` in
   `_mi_arenas_page_alloc` and `mi_arenas_try_alloc`, src/arena.c:540-560,
   576-590,790-830). This probe runs under one `mimalloc_*` environment
   image per profile. It prints the process decisions (the page map's
   reserved size and whether its entries are fully committed for `max_vabits` and
   `pagemap_commit`, src/page-map.c:271-356; the arenas startup reserved for
   `reserve_os_memory` and `reserve_huge_os_pages(_at)`, src/init.c:566-580;
   and the kernel's per-process THP state after `allow_thp`,
   src/prim/unix/prim.c:264-275), then allocates a fixed set of sizes and
   prints for each whether it failed, the `mi_memkind_t` of its page, and
   the page's `slice_pcommitted` (`page_commit_on_demand`,
   src/arena.c:1139-1142), and the first arena's size, eager commitment, and
   NUMA node (`arena_is_numa_local`, src/arena.c:1735-1740). The
   Rust half is the `native_option_profiles` integration test, run under the
   same image. Driven by `compat/allocator/x86_64_m7_gate.py
   --option-profiles-differential`. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "static.c"

static void report(const char* name, size_t size) {
  void* p = mi_malloc(size);
  printf("profile.%s.null=%d\n", name, p == NULL ? 1 : 0);
  printf("profile.%s.memkind=%d\n", name, p == NULL ? -1 : (int)_mi_ptr_page(p)->memid.memkind);
  printf("profile.%s.slice_pcommitted=%d\n", name, p == NULL ? -1 : (int)_mi_ptr_page(p)->slice_pcommitted);
  mi_free(p);
}

static void report_process(void) {
  const mi_page_map_t* pmap = _mi_page_map();
  const size_t committed = mi_atomic_load_relaxed(&((mi_page_map_t*)pmap)->committed_count);
  printf("profile.page_map=%zu,%d\n", pmap->reserved_size,
         committed == mi_page_map_count_of_size(pmap->reserved_size) ? 1 : 0);
  printf("profile.arena_count=%zu\n", mi_arenas_get_count(_mi_subproc()));
  char line[256];
  const char* thp = "absent";
  static char value[64];
  FILE* status = fopen("/proc/self/status", "r");
  while (status != NULL && fgets(line, sizeof(line), status) != NULL) {
    if (strncmp(line, "THP_enabled:", 12) == 0) {
      const char* v = line + 12;
      while (*v == ' ' || *v == '\t') v++;
      snprintf(value, sizeof(value), "%s", v);
      value[strcspn(value, "\n")] = 0;
      thp = value;
    }
  }
  if (status != NULL) fclose(status);
  printf("profile.thp_enabled=%s\n", thp);
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
    printf("profile.first_arena=%zu,%d,%d\n", mi_arena_size(arena), arena->memid.initially_committed ? 1 : 0,
           arena->numa_node);
  }
  mi_free(p);
}

int main(void) {
  printf("CRABC_MI_M7_OPTION_PROFILES_TRACE_BEGIN\n");
  report_first_arena();
  report_process();
  report("small", 64);
  report("medium", 200 * 1024);
  report("large", 3 * 1024 * 1024);
  report("huge", 48 * 1024 * 1024);
  printf("CRABC_MI_M7_OPTION_PROFILES_TRACE_END\n");
  return 0;
}
