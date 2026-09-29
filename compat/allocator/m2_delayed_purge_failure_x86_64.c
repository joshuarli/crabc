/* A delayed arena purge consumes a failed decommit without losing a live neighbor. */
#define _GNU_SOURCE 1
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "static.c"

typedef struct owner_s { mi_subproc_t subproc; mi_heap_t heap; } owner_t;
static owner_t owner;
static void* failed_start;
static size_t advice_calls;
static size_t exact_advice;
static size_t warnings;
static size_t warning_after_stats;
static bool fail_once;
static int64_t before_calls;
static int64_t before_bytes;
static int64_t before_visits;

int __real_madvise(void* address, size_t length, int advice);
int __wrap_madvise(void* address, size_t length, int advice) {
  if (failed_start != NULL) {
    advice_calls++;
    exact_advice += address == failed_start && length == MI_ARENA_SLICE_SIZE
        && advice == MADV_DONTNEED;
    if (fail_once) {
      fail_once = false;
      errno = EIO;
      return -1;
    }
  }
  return __real_madvise(address, length, advice);
}

static void warning(const char* message, void* argument) {
  MI_UNUSED(argument);
  if (strstr(message, "cannot decommit OS memory") != NULL) {
    warnings++;
    warning_after_stats += owner.subproc.stats.purge_calls.total == before_calls + 1
        && owner.subproc.stats.purged.total == before_bytes + MI_ARENA_SLICE_SIZE
        && owner.subproc.stats.arena_purges.total == before_visits + 1
        && strstr(message, "error: 5 (0x05)") != NULL
        && strstr(message, "size: 0x10000 bytes") != NULL;
  }
}

static void emit(const char* name, long long value) {
  printf("m2.delayed_purge_failure.%s=%lld\n", name, value);
}
static bool live(void* address) {
  unsigned char residency = 0;
  return mincore(address, (size_t)sysconf(_SC_PAGESIZE), &residency) == 0;
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  mi_process_init();
  os_preloading = false;
  memset(&owner, 0, sizeof(owner));
  mi_lock_init(&owner.subproc.arena_reserve_lock);
  mi_atomic_store_relaxed(&owner.subproc.heap_count, 1);
  owner.heap.subproc = &owner.subproc;
  mi_os_mem_config.has_overcommit = true;
  mi_os_mem_config.has_transparent_huge_pages = false;
  mi_option_set(mi_option_arena_reserve, MI_ARENA_MIN_SIZE / MI_KiB);
  mi_option_set(mi_option_arena_eager_commit, 0);
  mi_option_set(mi_option_allow_large_os_pages, 0);
  mi_option_set(mi_option_allow_thp, 0);
  mi_option_set(mi_option_arena_is_numa_local, 0);
  mi_option_set(mi_option_purge_delay, 100000);
  mi_option_set(mi_option_arena_purge_mult, 1);
  mi_option_set(mi_option_purge_decommits, 1);
  mi_option_set(mi_option_show_errors, 1);
  mi_option_set(mi_option_max_warnings, 100);
  mi_register_output(warning, NULL);

  mi_memid_t released_id = _mi_memid_none();
  mi_memid_t survivor_id = _mi_memid_none();
  void* released = mi_arenas_try_alloc(&owner.heap, 1, MI_ARENA_SLICE_ALIGN,
                                      true, true, NULL, 0, -1, &released_id);
  if (released == NULL || released_id.memkind != MI_MEM_ARENA) return 2;
  mi_arena_t* arena = released_id.mem.arena.arena;
  void* survivor = mi_arenas_try_alloc(&owner.heap, 1, MI_ARENA_SLICE_ALIGN,
                                      true, true, arena, 0, -1, &survivor_id);
  if (survivor == NULL || survivor_id.mem.arena.arena != arena) return 3;
  size_t index = released_id.mem.arena.slice_index;
  size_t survivor_index = survivor_id.mem.arena.slice_index;
  const bool setup = mi_arenas_get_count(&owner.subproc) == 1
      && arena->memid.memkind == MI_MEM_OS
      && index == 9 && survivor_index == 10
      && live(arena->start) && live(released) && live(survivor);
  const int64_t reserved = owner.subproc.stats.reserved.current;
  const int64_t committed = owner.subproc.stats.committed.current;
  before_calls = owner.subproc.stats.purge_calls.total;
  before_bytes = owner.subproc.stats.purged.total;
  before_visits = owner.subproc.stats.arena_purges.total;
  _mi_arenas_free(&owner.subproc, released, MI_ARENA_SLICE_SIZE, released_id);
  const bool pending_purge = mi_bitmap_is_setN(arena->slices_purge, index, 1);
  const bool pending_committed = mi_bitmap_is_setN(arena->slices_committed, index, 1);
  const bool pending_free = mi_bbitmap_is_setN(arena->slices_free, index, 1);
  const bool pending_survivor = mi_bbitmap_is_clearN(arena->slices_free, survivor_index, 1);
  const bool pending_expiry = mi_atomic_loadi64_relaxed(&arena->purge_expire) > 0;
  const bool pending = pending_purge && pending_committed && pending_free
      && pending_survivor && pending_expiry;
  const bool pending_no_advice = advice_calls == 0 && warnings == 0
      && owner.subproc.stats.purge_calls.total == before_calls;
  failed_start = released;
  fail_once = true;
  mi_arenas_try_purge(true, true, &owner.subproc, 0);
  const bool consumed = mi_bitmap_is_clearN(arena->slices_purge, index, 1)
      && mi_bitmap_is_setN(arena->slices_committed, index, 1)
      && mi_bbitmap_is_setN(arena->slices_free, index, 1)
      && mi_bbitmap_is_clearN(arena->slices_free, survivor_index, 1)
      && mi_atomic_loadi64_relaxed(&arena->purge_expire) == 0;
  const long long first_calls = advice_calls;
  const long long first_warnings = warnings;
  const long long first_purges = owner.subproc.stats.purge_calls.total - before_calls;
  const long long first_bytes = owner.subproc.stats.purged.total - before_bytes;
  const long long first_visits = owner.subproc.stats.arena_purges.total - before_visits;
  const long long first_committed = owner.subproc.stats.committed.current - committed;
  mi_arenas_try_purge(true, true, &owner.subproc, 0);
  const bool no_retry = advice_calls == (size_t)first_calls && warnings == (size_t)first_warnings
      && owner.subproc.stats.purge_calls.total - before_calls == first_purges
      && owner.subproc.stats.arena_purges.total - before_visits == first_visits;

  mi_memid_t later_id = _mi_memid_none();
  void* later = mi_arenas_try_alloc(&owner.heap, 2, MI_ARENA_SLICE_ALIGN,
                                   true, true, arena, 0, -1, &later_id);
  if (later == NULL || later_id.mem.arena.arena != arena) return 4;
  const size_t later_index = later_id.mem.arena.slice_index;
  const bool later_disjoint = later_index > survivor_index && later != released
      && mi_bbitmap_is_clearN(arena->slices_free, later_index, 2);
  _mi_arenas_free(&owner.subproc, later, 2 * MI_ARENA_SLICE_SIZE, later_id);
  const bool later_pending = mi_bitmap_is_setN(arena->slices_purge, later_index, 2)
      && mi_bbitmap_is_clearN(arena->slices_free, survivor_index, 1);
  const bool owner_live = live(arena->start) && live(survivor)
      && mi_arenas_get_count(&owner.subproc) == 1
      && owner.subproc.stats.reserved.current == reserved;
  _mi_arenas_free(&owner.subproc, survivor, MI_ARENA_SLICE_SIZE, survivor_id);
  const bool terminal = live(arena->start) && mi_arenas_get_count(&owner.subproc) == 1
      && mi_bbitmap_is_setN(arena->slices_free, survivor_index, 1);
  emit("setup", setup); emit("pending", pending);
  emit("pending_purge", pending_purge); emit("pending_committed", pending_committed);
  emit("pending_free", pending_free); emit("pending_survivor", pending_survivor);
  emit("pending_expiry", pending_expiry);
  emit("pending_no_advice", pending_no_advice); emit("consumed", consumed);
  emit("first_calls", first_calls); emit("first_exact", exact_advice);
  emit("first_warnings", first_warnings); emit("warning_after_stats", warning_after_stats);
  emit("first_purges", first_purges); emit("first_bytes", first_bytes);
  emit("first_visits", first_visits); emit("first_committed", first_committed);
  emit("no_retry", no_retry); emit("later_disjoint", later_disjoint);
  emit("later_pending", later_pending); emit("owner_live", owner_live);
  emit("terminal", terminal); emit("released_slice", index);
  emit("survivor_slice", survivor_index); emit("later_slice", later_index);
  emit("registry", mi_arenas_get_count(&owner.subproc));
  emit("reserved", owner.subproc.stats.reserved.current - reserved);
  emit("purge_calls", owner.subproc.stats.purge_calls.total - before_calls);
  emit("purged_bytes", owner.subproc.stats.purged.total - before_bytes);
  emit("arena_purges", owner.subproc.stats.arena_purges.total - before_visits);
  emit("advice_calls", advice_calls); emit("warnings", warnings);
  return setup && pending && pending_no_advice && consumed && no_retry
      && later_disjoint && later_pending && owner_live && terminal ? 0 : 1;
}
