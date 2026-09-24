/* Pinned-C half of the allocator M7 option-effects differential.

   This probe includes the pinned mimalloc v3.5.0 `src/static.c` as one
   translation unit so it can call the source read points that consume an
   allocator-effect descriptor. Each scenario performs `mi_option_set` on the
   live `mi_options[]` table after process initialization and before the
   read point runs, records the source decision as `key=value` lines, then
   restores the startup table image. The Rust half is
   `diagnostic_output::tests::source_option_effects_trace_for_pinned_c_comparison`,
   which performs the same `mi_option_set` on the process descriptor table
   read by the x86 process `VmPolicy`. Both halves print the host facts the
   decisions depend on, so a detection drift fails instead of skewing a value.
   Driven by `compat/allocator/x86_64_m7_gate.py --option-effects-differential`. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "static.c"

static mi_option_desc_t startup_options[_mi_option_last];

static void restore_options(void) {
  for (int i = 0; i < _mi_option_last; i++) {
    mi_options[i].value = startup_options[i].value;
    mi_options[i].init = startup_options[i].init;
  }
}

/* `src/arena.c:115-127`. */
static void arena_max_object_size(long kib) {
  mi_option_set(mi_option_arena_max_object_size, kib);
  printf("arena_max_object_size.%ld=%zu\n", kib, mi_arena_max_object_size());
  restore_options();
}

/* `src/arena.c:2243-2252`, the delay every arena purge schedules with. */
static void arena_purge_delay(long delay, long mult) {
  mi_option_set(mi_option_purge_delay, delay);
  mi_option_set(mi_option_arena_purge_mult, mult);
  printf("arena_purge_delay.%ld.%ld=%ld\n", delay, mult, mi_arena_purge_delay());
  restore_options();
}

/* `src/os.c:55-66`. */
static void minimal_purge_size(long kib, long allow_thp) {
  mi_option_set(mi_option_minimal_purge_size, kib);
  mi_option_set(mi_option_allow_thp, allow_thp);
  printf("minimal_purge_size.%ld.%ld=%zu\n", kib, allow_thp, _mi_os_minimal_purge_size());
  restore_options();
}

/* `src/os.c:861-878`: the first read after the cache is empty decides. */
static void numa_node_count(long nodes) {
  mi_atomic_store_release(&mi_numa_node_count, (size_t)0);
  mi_option_set(mi_option_use_numa_nodes, nodes);
  printf("numa_node_count.%ld=%d\n", nodes, _mi_os_numa_node_count());
  mi_atomic_store_release(&mi_numa_node_count, (size_t)0);
  restore_options();
}

/* The `src/page.c:1030` read point of `_mi_malloc_generic`. */
static void generic_collect(long value) {
  mi_option_set(mi_option_generic_collect, value);
  printf("generic_collect.%ld=%ld\n", value, mi_option_get_clamp(mi_option_generic_collect, 1, 1000000L));
  restore_options();
}

/* `src/arena.c:341-407`: reserve one fresh arena and report the reserved size
   and whether it was committed eagerly, or `none` when the source declines.
   `arena_count` is the count the reservation observed, so the Rust half can
   apply the same count-scaled reserve. */
static void arena_reserve(long reserve_kib, long eager, long allow_large, size_t request) {
  mi_subproc_t* subproc = _mi_subproc();
  const size_t arena_count = mi_arenas_get_count(subproc);
  mi_option_set(mi_option_arena_reserve, reserve_kib);
  mi_option_set(mi_option_arena_eager_commit, eager);
  mi_option_set(mi_option_allow_large_os_pages, allow_large);
  mi_arena_id_t id = _mi_arena_id_none();
  /* `allow_large == false`: the caller bit never asks for large OS pages, so
     only the descriptor decides eager commit and no huge mapping is tried. */
  const bool reserved = mi_arena_reserve(subproc, request, false, &id);
  printf("arena_reserve.%ld.%ld.%ld.%zu=%zu,", reserve_kib, eager, allow_large, request, arena_count);
  if (reserved) {
    mi_arena_t* arena = _mi_arena_from_id(id);
    printf("%zu,%d\n", mi_arena_size(arena), arena->memid.initially_committed ? 1 : 0);
  }
  else {
    printf("none\n");
  }
  restore_options();
}

int main(void) {
  memcpy(startup_options, mi_options, sizeof(startup_options));
  printf("CRABC_MI_M7_OPTION_EFFECTS_TRACE_BEGIN\n");
  printf("host.page_size=%zu\n", _mi_os_page_size());
  printf("host.large_page_size=%zu\n", _mi_os_large_page_size());
  printf("host.overcommit=%d\n", _mi_os_has_overcommit() ? 1 : 0);
  printf("host.transparent_huge_pages=%d\n", mi_os_mem_config.has_transparent_huge_pages ? 1 : 0);

  static const long max_object_kib[] = { -1, 0, 1, 64, 65, 4096, 1048576, 1L << 40 };
  for (size_t i = 0; i < sizeof(max_object_kib) / sizeof(max_object_kib[0]); i++) {
    arena_max_object_size(max_object_kib[i]);
  }
  static const long purge[][2] = {
    { 1000, 4 }, { -1, 4 }, { 10, -1 }, { 0, 4 }, { 10, 0 }, { LONG_MAX, 2 }, { 7, 3 },
  };
  for (size_t i = 0; i < sizeof(purge) / sizeof(purge[0]); i++) {
    arena_purge_delay(purge[i][0], purge[i][1]);
  }
  static const long purge_kib[] = { 0, 1, 5, 100, -3 };
  for (size_t i = 0; i < sizeof(purge_kib) / sizeof(purge_kib[0]); i++) {
    for (long thp = 0; thp <= 2; thp++) minimal_purge_size(purge_kib[i], thp);
  }
  static const long nodes[] = { 0, 1, 3, -1, INT_MAX, (long)INT_MAX - 1 };
  for (size_t i = 0; i < sizeof(nodes) / sizeof(nodes[0]); i++) numa_node_count(nodes[i]);
  static const long collect[] = { -5, 0, 1, 10000, 2000000 };
  for (size_t i = 0; i < sizeof(collect) / sizeof(collect[0]); i++) generic_collect(collect[i]);
  /* Fewer than eight reservations keep the source count multiplier at one. */
  arena_reserve(1048576, 2, 0, 1);
  arena_reserve(0, 2, 0, 1);
  arena_reserve(1, 0, 0, 1);
  arena_reserve(33000, 1, 0, 1);
  arena_reserve(65536, 2, 1, 40u << 20);
  arena_reserve(65536, 0, 1, 1);
  arena_reserve(1L << 40, 0, 0, 1);
  printf("CRABC_MI_M7_OPTION_EFFECTS_TRACE_END\n");
  return 0;
}
