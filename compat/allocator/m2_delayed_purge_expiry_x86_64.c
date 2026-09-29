/* Observe the same delayed arena schedule immediately before and at expiry. */
#define _GNU_SOURCE 1
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/mman.h>
#include <unistd.h>

#include "static.c"

typedef struct owner_s { mi_subproc_t subproc; mi_heap_t heap; } owner_t;
static owner_t owner;
static int64_t synthetic_now = -1;
static void* expected_advice;
static size_t advice_count;
static size_t exact_advice;
static size_t warnings;

int __real_clock_gettime(clockid_t clock_id, struct timespec* value);
int __wrap_clock_gettime(clockid_t clock_id, struct timespec* value) {
  if (synthetic_now >= 0 && clock_id == CLOCK_MONOTONIC) {
    value->tv_sec = synthetic_now / 1000;
    value->tv_nsec = (synthetic_now % 1000) * 1000000;
    return 0;
  }
  return __real_clock_gettime(clock_id, value);
}
int __real_madvise(void* address, size_t length, int advice);
int __wrap_madvise(void* address, size_t length, int advice) {
  if (expected_advice != NULL) {
    advice_count++;
    exact_advice += address == expected_advice
        && length == MI_ARENA_SLICE_SIZE && advice == MADV_DONTNEED;
  }
  return __real_madvise(address, length, advice);
}
static void warning(const char* message, void* argument) {
  MI_UNUSED(argument);
  if (strstr(message, "cannot decommit OS memory") != NULL) warnings++;
}
static void emit(const char* name, long long value) {
  printf("m2.delayed_purge_expiry.%s=%lld\n", name, value);
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
  mi_memid_t neighbor_id = _mi_memid_none();
  void* released = mi_arenas_try_alloc(&owner.heap, 1, MI_ARENA_SLICE_ALIGN,
                                      true, true, NULL, 0, -1, &released_id);
  if (released == NULL || released_id.memkind != MI_MEM_ARENA) return 2;
  mi_arena_t* arena = released_id.mem.arena.arena;
  void* neighbor = mi_arenas_try_alloc(&owner.heap, 1, MI_ARENA_SLICE_ALIGN,
                                      true, true, arena, 0, -1, &neighbor_id);
  if (neighbor == NULL || neighbor_id.mem.arena.arena != arena) return 3;
  const size_t released_slice = released_id.mem.arena.slice_index;
  const size_t neighbor_slice = neighbor_id.mem.arena.slice_index;
  const bool setup = mi_arenas_get_count(&owner.subproc) == 1
      && arena->memid.memkind == MI_MEM_OS
      && released_slice == 9 && neighbor_slice == 10
      && live(arena->start) && live(released) && live(neighbor);
  *(volatile unsigned char*)neighbor = 0x7b;
  const int64_t reserved = owner.subproc.stats.reserved.current;
  const int64_t committed = owner.subproc.stats.committed.current;
  const int64_t calls = owner.subproc.stats.purge_calls.total;
  const int64_t bytes = owner.subproc.stats.purged.total;
  const int64_t visits = owner.subproc.stats.arena_purges.total;
  _mi_arenas_free(&owner.subproc, released, MI_ARENA_SLICE_SIZE, released_id);
  const bool scheduled = mi_bitmap_is_setN(arena->slices_purge, released_slice, 1)
      && mi_bitmap_is_setN(arena->slices_committed, released_slice, 1)
      && mi_bbitmap_is_setN(arena->slices_free, released_slice, 1)
      && mi_bbitmap_is_clearN(arena->slices_free, neighbor_slice, 1)
      && mi_atomic_loadi64_relaxed(&arena->purge_expire) > 0
      && mi_atomic_loadi64_relaxed(&owner.subproc.purge_expire) > 0;
  // The isolated fixture retains the only arena visitor, so replacing both
  // scheduled clock values keeps the source ownership and bitmap transition.
  mi_atomic_storei64_release(&arena->purge_expire, 10000);
  mi_atomic_storei64_release(&owner.subproc.purge_expire, 10000);
  expected_advice = released;
  synthetic_now = 9999;
  mi_arenas_try_purge(false, true, &owner.subproc, 0);
  const bool before_quiet = advice_count == 0 && warnings == 0
      && owner.subproc.stats.purge_calls.total == calls
      && owner.subproc.stats.purged.total == bytes
      && owner.subproc.stats.arena_purges.total == visits;
  const bool before_pending = mi_bitmap_is_setN(arena->slices_purge, released_slice, 1)
      && mi_bitmap_is_setN(arena->slices_committed, released_slice, 1)
      && mi_atomic_loadi64_relaxed(&arena->purge_expire) == 10000;
  const int64_t before_global = mi_atomic_loadi64_relaxed(&owner.subproc.purge_expire);
  synthetic_now = 10000;
  mi_arenas_try_purge(false, true, &owner.subproc, 0);
  const bool due_bits = mi_bitmap_is_clearN(arena->slices_purge, released_slice, 1)
      && mi_bitmap_is_setN(arena->slices_committed, released_slice, 1)
      && mi_bbitmap_is_setN(arena->slices_free, released_slice, 1)
      && mi_bbitmap_is_clearN(arena->slices_free, neighbor_slice, 1);
  const int64_t due_expiry = mi_atomic_loadi64_relaxed(&arena->purge_expire);
  const int64_t due_global = mi_atomic_loadi64_relaxed(&owner.subproc.purge_expire);
  const int64_t due_calls = owner.subproc.stats.purge_calls.total - calls;
  const int64_t due_bytes = owner.subproc.stats.purged.total - bytes;
  const int64_t due_visits = owner.subproc.stats.arena_purges.total - visits;
  const int64_t due_committed = owner.subproc.stats.committed.current - committed;
  synthetic_now = 10001;
  mi_arenas_try_purge(false, true, &owner.subproc, 0);
  const bool after_no_retry = advice_count == 1 && warnings == 0
      && owner.subproc.stats.purge_calls.total - calls == due_calls
      && owner.subproc.stats.arena_purges.total - visits == due_visits;
  const int64_t after_global = mi_atomic_loadi64_relaxed(&owner.subproc.purge_expire);
  synthetic_now = -1;
  mi_memid_t later_id = _mi_memid_none();
  void* later = mi_arenas_try_alloc(&owner.heap, 1, MI_ARENA_SLICE_ALIGN,
                                   true, true, arena, 0, -1, &later_id);
  if (later == NULL || later_id.mem.arena.arena != arena) return 4;
  const bool later_same = later == released && later_id.mem.arena.slice_index == released_slice;
  _mi_arenas_free(&owner.subproc, later, MI_ARENA_SLICE_SIZE, later_id);
  const bool later_pending = mi_bitmap_is_setN(arena->slices_purge, released_slice, 1);
  const bool survivor = live(arena->start) && live(neighbor)
      && *(volatile unsigned char*)neighbor == 0x7b
      && mi_bbitmap_is_clearN(arena->slices_free, neighbor_slice, 1);
  _mi_arenas_free(&owner.subproc, neighbor, MI_ARENA_SLICE_SIZE, neighbor_id);
  const bool terminal = live(arena->start) && mi_arenas_get_count(&owner.subproc) == 1
      && mi_bbitmap_is_setN(arena->slices_free, neighbor_slice, 1)
      && owner.subproc.stats.reserved.current == reserved;
  emit("setup", setup); emit("scheduled", scheduled);
  emit("before_quiet", before_quiet); emit("before_pending", before_pending);
  emit("before_global", before_global); emit("due_advice", advice_count);
  emit("due_exact", exact_advice); emit("due_bits", due_bits);
  emit("due_expiry", due_expiry); emit("due_global", due_global);
  emit("due_calls", due_calls); emit("due_bytes", due_bytes);
  emit("due_visits", due_visits); emit("due_committed", due_committed);
  emit("after_no_retry", after_no_retry); emit("after_global", after_global);
  emit("later_same", later_same); emit("later_pending", later_pending);
  emit("survivor", survivor); emit("terminal", terminal);
  emit("released_slice", released_slice); emit("neighbor_slice", neighbor_slice);
  emit("registry", mi_arenas_get_count(&owner.subproc));
  emit("reserved_delta", owner.subproc.stats.reserved.current - reserved);
  emit("purge_calls", owner.subproc.stats.purge_calls.total - calls);
  emit("purged_bytes", owner.subproc.stats.purged.total - bytes);
  emit("arena_purges", owner.subproc.stats.arena_purges.total - visits);
  emit("warnings", warnings);
  return setup && scheduled && before_quiet && before_pending && due_bits
      && after_no_retry && later_same && later_pending && survivor && terminal ? 0 : 1;
}
