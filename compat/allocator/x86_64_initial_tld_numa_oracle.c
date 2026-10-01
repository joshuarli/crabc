/* Native x86-64 initial-TLD NUMA source oracle.
 *
 * This child-only probe directly includes pinned mimalloc v3.5.0 `src/init.c`
 * so it can inspect the source-static `mi_process_tld_main` after the normal
 * `mi_process_init()` path. The ordinary source closure deliberately omits
 * only `src/init.c`; every other release source unit is linked once. That
 * keeps the actual `mi_tld_init` body, its `_mi_os_numa_node()` write, and
 * the source-static ticket-zero TLD singular rather than reproducing them in
 * a fixture. It then makes one ordinary `mi_malloc(79)` request through the
 * linked release source so `mi_arena_initialize` stores the first regular
 * arena's policy-normalized node after its normal metadata preparation. It
 * proves configured NUMA-region policy selection, not host multi-node
 * placement or huge-page success.
 */
#define _GNU_SOURCE

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include <mimalloc.h>
#include <mimalloc/internal.h>
#include <mimalloc/prim.h>

/* Resolved through `-I <pinned-source>/src`. `src/init.c` owns the private
 * static TLD and normal process-init body for this one translation unit. */
#include "init.c"

#ifdef CRABC_MI_STATIC_THEAP_ACCOUNTING
/* The linker routes the ordinary source counter call through this observer.
 * Delegating to the original counter preserves its update and memory order;
 * neither the initializer nor its publication stores are replaced. */
void __real___mi_stat_increase_mt(mi_stat_count_t* stat, size_t amount);
static size_t initial_theap_count_calls;
static bool count_before_heap_publication;
static bool count_after_tld_link;
static bool count_before_heap_link;
static bool count_update_before_heap_publication;
static mi_stat_count_t initial_theap_count;

void __wrap___mi_stat_increase_mt(mi_stat_count_t* stat, size_t amount) {
  const bool selected = stat == &_mi_subproc_main()->stats.theaps;
  if (selected) {
    initial_theap_count_calls++;
    count_before_heap_publication = amount == 1
        && !mi_theap_is_initialized(&mi_process_theap_main)
        && _mi_theap_heap_peek(&mi_process_theap_main) == NULL;
    count_after_tld_link = mi_process_tld_main.theaps == &mi_process_theap_main
        && mi_process_theap_main.tld == &mi_process_tld_main;
    count_before_heap_link = mi_process_heap_main.theaps == &mi_process_theap_meta
        && mi_process_theap_meta.hnext == NULL
        && mi_process_theap_main.hprev == NULL
        && mi_process_theap_main.hnext == NULL;
  }
  __real___mi_stat_increase_mt(stat, amount);
  if (selected) {
    initial_theap_count = *stat;
    count_update_before_heap_publication =
        _mi_theap_heap_peek(&mi_process_theap_main) == NULL
        && stat->current == 1 && stat->total == 1 && stat->peak == 1;
  }
}
#endif

/* `src/arena.c` owns these non-public source definitions. The fixture links
 * that ordinary translation unit exactly once and observes only the first
 * regular arena it actually registered after `mi_malloc(79)`. */
extern size_t mi_arenas_get_count(mi_subproc_t* subproc);
extern mi_arena_t* mi_arena_from_index(mi_subproc_t* subproc, size_t idx);

#define TRACE_BEGIN "CRABC_MI_INITIAL_TLD_NUMA_TRACE_BEGIN"
#define TRACE_END "CRABC_MI_INITIAL_TLD_NUMA_TRACE_END"

static void trace_unsigned(const char* name, size_t value) {
  printf("%s=%zu\n", name, value);
}

int main(void) {
  if (clearenv() != 0
      || setenv("mimalloc_arena_reserve", "128M", 1) != 0
      || setenv("mimalloc_arena_eager_commit", "2", 1) != 0
      || setenv("mimalloc_allow_large_os_pages", "0", 1) != 0
      || setenv("mimalloc_allow_thp", "0", 1) != 0
      || setenv("mimalloc_use_numa_nodes", "3", 1) != 0
      || setenv("mimalloc_arena_is_numa_local", "1", 1) != 0) return 1;

  /* This is the unchanged source initialization body. With
   * MI_PRIM_HAS_PROCESS_ATTACH, the linked Unix primitive does not construct
   * a competing pre-main process image before this explicit option setup. */
  mi_process_init();

  mi_tld_t* const tld = &mi_process_tld_main;
  mi_theap_t* const default_theap = _mi_theap_default();
  const int numa_count = _mi_os_numa_node_count();
  const long configured_count = mi_option_get(mi_option_use_numa_nodes);
  const long configured_arena_is_numa_local =
      mi_option_get(mi_option_arena_is_numa_local);
  const bool source_option_applied = configured_count == 3;
  const bool arena_is_numa_local_option_applied = configured_arena_is_numa_local == 1;
  const bool count_uses_configured_policy = numa_count == 3;
  const bool ticket_zero_tld = tld->thread_seq == 0
      && tld->thread_id != MI_THREADID_DETACHED
      && tld->subproc == _mi_subproc_main();
  const bool default_theap_uses_ticket_zero_tld =
      default_theap != NULL && default_theap->tld == tld;
  const bool ticket_zero_tld_numa_in_range =
      tld->numa_node >= 0 && tld->numa_node < numa_count;

  /* The source allocation, not a copied arena initializer, reaches the
   * regular `mi_reserve_os_memory_ex2(..., -1, ...)` route. Disable the
   * large/THP options above so this witness stays in the ordinary OS mapping
   * branch; it is not a host huge-page result. */
  void* const allocation = mi_malloc(79);
  mi_subproc_t* const subproc = _mi_subproc_main();
  const size_t arena_count_before_free = mi_arenas_get_count(subproc);
  mi_arena_t* const regular_first_arena =
      (allocation != NULL && arena_count_before_free == 1)
          ? mi_arena_from_index(subproc, 0)
          : NULL;
  const bool regular_first_arena_is_os = regular_first_arena != NULL
      && regular_first_arena->memid.memkind == MI_MEM_OS;
  const int regular_first_arena_numa_node =
      regular_first_arena == NULL ? -1 : regular_first_arena->numa_node;
  const bool regular_first_arena_numa_in_range = regular_first_arena_is_os
      && regular_first_arena_numa_node >= 0
      && regular_first_arena_numa_node < numa_count;
  mi_free(allocation);
  const bool regular_first_arena_retained_after_free = regular_first_arena_is_os
      && mi_arenas_get_count(subproc) == 1
      && mi_arena_from_index(subproc, 0) == regular_first_arena;

  puts(TRACE_BEGIN);
  trace_unsigned("source_option_applied", source_option_applied);
  trace_unsigned("arena_is_numa_local_option_applied", arena_is_numa_local_option_applied);
  trace_unsigned("configured_numa_node_count", (size_t)configured_count);
  trace_unsigned("resolved_numa_node_count", (size_t)numa_count);
  trace_unsigned("ticket_zero_tld", ticket_zero_tld);
  trace_unsigned("default_theap_uses_ticket_zero_tld", default_theap_uses_ticket_zero_tld);
  trace_unsigned("ticket_zero_tld_numa_node", (size_t)tld->numa_node);
  trace_unsigned("ticket_zero_tld_numa_in_range", ticket_zero_tld_numa_in_range);
  trace_unsigned("regular_first_arena_is_os", regular_first_arena_is_os);
  trace_unsigned("regular_first_arena_numa_node",
      regular_first_arena_numa_node >= 0 ? (size_t)regular_first_arena_numa_node : 0);
  trace_unsigned("regular_first_arena_numa_in_range", regular_first_arena_numa_in_range);
  trace_unsigned("regular_first_arena_retained_after_free",
      regular_first_arena_retained_after_free);
  puts(TRACE_END);

#ifdef CRABC_MI_STATIC_THEAP_ACCOUNTING
  const bool static_main_counted = initial_theap_count_calls == 1
      && initial_theap_count.current == 1 && initial_theap_count.total == 1
      && initial_theap_count.peak == 1
      && mi_process_theap_main.memid.memkind == MI_MEM_STATIC;
  const bool detached_metadata_excluded = mi_process_theap_meta.is_detached
      && mi_process_theap_meta.memid.memkind == MI_MEM_STATIC
      && mi_tld_detached.theaps == &mi_process_theap_meta;
  const bool final_heap_link = mi_process_heap_main.theaps == &mi_process_theap_main
      && mi_process_theap_main.hnext == &mi_process_theap_meta
      && mi_process_theap_meta.hprev == &mi_process_theap_main;
  mi_process_init();
  const bool repeated_init_count_unchanged = initial_theap_count_calls == 1
      && subproc->stats.theaps.current == 1
      && subproc->stats.theaps.total == 1 && subproc->stats.theaps.peak == 1;
  mi_thread_done();
  const bool static_teardown_count_retained = subproc->stats.theaps.current == 1
      && subproc->stats.theaps.total == 1 && subproc->stats.theaps.peak == 1
      && mi_process_tld_main.theaps == NULL
      && mi_process_theap_main.tld == NULL
      && _mi_theap_heap_peek(&mi_process_theap_main) == NULL
      && mi_process_heap_main.theaps == &mi_process_theap_meta;
  puts("CRABC_MI_STATIC_THEAP_ACCOUNTING_TRACE_BEGIN");
  trace_unsigned("static_main_counted", static_main_counted);
  trace_unsigned("detached_metadata_excluded", detached_metadata_excluded);
  trace_unsigned("count_before_heap_publication", count_before_heap_publication);
  trace_unsigned("count_after_tld_link", count_after_tld_link);
  trace_unsigned("count_before_heap_link", count_before_heap_link);
  trace_unsigned("count_update_before_heap_publication", count_update_before_heap_publication);
  trace_unsigned("final_heap_link", final_heap_link);
  trace_unsigned("repeated_init_count_unchanged", repeated_init_count_unchanged);
  trace_unsigned("static_teardown_count_retained", static_teardown_count_retained);
  puts("CRABC_MI_STATIC_THEAP_ACCOUNTING_TRACE_END");
  if (!(static_main_counted && detached_metadata_excluded
        && count_before_heap_publication && count_after_tld_link
        && count_before_heap_link && count_update_before_heap_publication
        && final_heap_link && repeated_init_count_unchanged
        && static_teardown_count_retained)) return 3;
#endif

  return (source_option_applied && arena_is_numa_local_option_applied
          && count_uses_configured_policy && ticket_zero_tld
          && default_theap_uses_ticket_zero_tld && ticket_zero_tld_numa_in_range
          && regular_first_arena_numa_in_range && regular_first_arena_retained_after_free)
      ? 0
      : 2;
}
