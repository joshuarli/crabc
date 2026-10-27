#define _GNU_SOURCE 1
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "static.c"

typedef struct owner_s { mi_subproc_t subproc; mi_heap_t heap; } owner_t;
static owner_t owner;
static bool fail_monotonic;
static size_t preferred_calls;
static size_t fallback_calls;

int __real_clock_gettime(clockid_t clock_id, struct timespec* value);
int __wrap_clock_gettime(clockid_t clock_id, struct timespec* value) {
  if (fail_monotonic && clock_id == CLOCK_MONOTONIC) {
    preferred_calls++;
    errno = EIO;
    return -1;
  }
  return __real_clock_gettime(clock_id, value);
}

clock_t __real_clock(void);
clock_t __wrap_clock(void) {
  if (fail_monotonic) fallback_calls++;
  return __real_clock();
}

int main(void) {
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

  mi_memid_t id = _mi_memid_none();
  void* block = mi_arenas_try_alloc(&owner.heap, 1, MI_ARENA_SLICE_ALIGN,
                                    true, true, NULL, 0, -1, &id);
  if (block == NULL || id.memkind != MI_MEM_ARENA) return 2;
  mi_arena_t* arena = id.mem.arena.arena;
  const size_t slice = id.mem.arena.slice_index;
  fail_monotonic = true;
  _mi_arenas_free(&owner.subproc, block, MI_ARENA_SLICE_SIZE, id);
  const size_t schedule_clock = preferred_calls;
  const size_t schedule_fallback = fallback_calls;
  const bool scheduled = mi_bitmap_is_setN(arena->slices_purge, slice, 1)
      && mi_atomic_loadi64_relaxed(&arena->purge_expire) > 0
      && mi_atomic_loadi64_relaxed(&owner.subproc.purge_expire) > 0;
  mi_atomic_storei64_release(&arena->purge_expire, -1);
  mi_atomic_storei64_release(&owner.subproc.purge_expire, -1);
  const int64_t before = owner.subproc.stats.arena_purges.total;
  preferred_calls = 0;
  fallback_calls = 0;
  mi_arenas_try_purge(false, true, &owner.subproc, 0);
  const bool cleared = mi_bitmap_is_clearN(arena->slices_purge, slice, 1)
      && mi_bbitmap_is_setN(arena->slices_free, slice, 1);
  printf("m2.arena_clock.schedule_clock=%zu\n", schedule_clock);
  printf("m2.arena_clock.scheduled=%d\n", (int)scheduled);
  printf("m2.arena_clock.purge_clock=%zu\n", preferred_calls);
  printf("m2.arena_clock.cleared=%d\n", (int)cleared);
  printf("m2.arena_clock.purges=%lld\n", (long long)(owner.subproc.stats.arena_purges.total - before));
  return schedule_fallback == 1 && fallback_calls == 1 ? 0 : 3;
}
