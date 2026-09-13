/* Native x86-64 source-start regular-arena oracle.
 *
 * This child-mode probe directly includes pinned mimalloc v3.5.0 `src/init.c`
 * to retain the source-static ticket-zero TLD and the normal
 * `mi_process_init()` body. Each remaining release source object is linked
 * once. It observes the ordinary first `mi_malloc(79)` route after the
 * optional `mimalloc_reserve_os_memory` startup operation, including the
 * source's ignored too-small reservation failure and direct-OS fallback when
 * arena allocation is disabled. It does not qualify huge pages or host NUMA
 * placement.
 */
#define _GNU_SOURCE

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <mimalloc.h>
#include <mimalloc/internal.h>
#include <mimalloc/prim.h>

/* `src/init.c` owns the private static TLD and source process-init body for
 * this translation unit. `src/arena.c` remains linked normally below. */
#include "init.c"

extern size_t mi_arenas_get_count(mi_subproc_t* subproc);
extern mi_arena_t* mi_arena_from_index(mi_subproc_t* subproc, size_t idx);

#define TRACE_BEGIN "CRABC_MI_STARTUP_REGULAR_ARENA_TRACE_BEGIN"
#define TRACE_END "CRABC_MI_STARTUP_REGULAR_ARENA_TRACE_END"

static void trace_unsigned(const char* name, size_t value) {
  printf("%s=%zu\n", name, value);
}

static bool set_source_environment(const char* scenario) {
  if (clearenv() != 0
      || setenv("mimalloc_arena_reserve", "128M", 1) != 0
      || setenv("mimalloc_arena_eager_commit", "1", 1) != 0
      || setenv("mimalloc_allow_large_os_pages", "0", 1) != 0
      || setenv("mimalloc_allow_thp", "0", 1) != 0
      || setenv("mimalloc_use_numa_nodes", "1", 1) != 0) return false;
  if (strcmp(scenario, "reuse") == 0 || strcmp(scenario, "ineligible") == 0) {
    if (setenv("mimalloc_reserve_os_memory", "64M", 1) != 0) return false;
  } else if (strcmp(scenario, "failed") == 0) {
    /* `arena.c:1817-1821` rejects this one-slice managed region below the
     * source minimum. `init.c:576-579` deliberately ignores the failure. */
    if (setenv("mimalloc_reserve_os_memory", "1K", 1) != 0) return false;
  } else if (strcmp(scenario, "absent") != 0) {
    return false;
  }
  return strcmp(scenario, "ineligible") != 0
      || setenv("mimalloc_disallow_arena_alloc", "1", 1) == 0;
}

int main(int argc, char** argv) {
  if (argc != 2 || !set_source_environment(argv[1])) return 1;

  mi_process_init();
  mi_subproc_t* const subproc = _mi_subproc_main();
  const size_t registry_after_init = mi_arenas_get_count(subproc);
  mi_arena_t* const startup = registry_after_init == 1
      ? mi_arena_from_index(subproc, 0) : NULL;

  void* const allocation = mi_malloc(79);
  mi_page_t* const page = allocation == NULL ? NULL : _mi_ptr_page(allocation);
  const bool client_is_arena_backed = page != NULL && page->memid.memkind == MI_MEM_ARENA;
  const bool client_uses_startup = client_is_arena_backed && startup != NULL
      && page->memid.mem.arena.arena == startup;
  const size_t client_startup_identity = client_uses_startup ? 1 : 2;
  const size_t registry_after_allocation = mi_arenas_get_count(subproc);
  mi_arena_t* const first_arena = registry_after_allocation == 1
      ? mi_arena_from_index(subproc, 0) : NULL;
  const size_t arena_size = first_arena == NULL ? 0 : first_arena->memid.mem.os.size;
  const size_t arena_initially_committed = first_arena != NULL
      && first_arena->memid.initially_committed;

  mi_free(allocation);
  const size_t registry_after_free = mi_arenas_get_count(subproc);

  puts(TRACE_BEGIN);
  trace_unsigned("registry_after_init", registry_after_init);
  trace_unsigned("client_is_arena_backed", client_is_arena_backed);
  trace_unsigned("client_startup_identity", client_startup_identity);
  trace_unsigned("registry_after_allocation", registry_after_allocation);
  trace_unsigned("arena_size_after_allocation", arena_size);
  trace_unsigned("arena_initially_committed", arena_initially_committed);
  trace_unsigned("registry_after_free", registry_after_free);
  puts(TRACE_END);

  const bool source_parent = strcmp(argv[1], "reuse") == 0
      || strcmp(argv[1], "ineligible") == 0;
  const bool direct_os = strcmp(argv[1], "ineligible") == 0;
  const size_t expected_size = source_parent ? 64 * 1024 * 1024 : 128 * 1024 * 1024;
  return allocation != NULL
      && registry_after_init == (source_parent ? 1 : 0)
      && client_is_arena_backed == !direct_os
      && client_startup_identity == (strcmp(argv[1], "reuse") == 0 ? 1 : 2)
      && registry_after_allocation == 1
      && arena_size == expected_size
      && arena_initially_committed
      && registry_after_free == 1
      ? 0 : 2;
}
