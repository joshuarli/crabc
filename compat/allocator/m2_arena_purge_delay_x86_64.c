/* Copyright (c) 2026 crabc contributors. SPDX-License-Identifier: MIT */
/* Pinned `mi_arena_purge_delay` (src/arena.c:2242-2252): the product of
   `purge_delay` and `arena_purge_mult`, its disabled (either negative) and
   immediate (either zero) results, and its fallback to the bare delay when
   the unsigned product overflows or exceeds LONG_MAX. The environment row
   reads both options through `mi_option_init` (src/options.c:623-690); the
   other rows set them with `mi_option_set`. For a selected subset, one freed
   committed slice in a fresh arena is scheduled with that delay
   (src/arena.c:1433-1495, 2286-2311), and a forced visit-all
   `mi_arenas_try_purge` purges it and rebases the subprocess expiration by
   `delay/10` (src/arena.c:2389-2435). No selected row makes
   `_mi_clock_now() + delay` overflow. */
#define _GNU_SOURCE 1
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "static.c"

#define require(condition) \
  do { if (!(condition)) { fprintf(stderr, "m2_arena_purge_delay_x86_64.c:%d: %s\n", __LINE__, #condition); abort(); } } while (0)

static mi_subproc_t* owner;

static void emit(const char* name, const char* field, long long value) {
  printf("m2.arena_purge_delay.%s.%s=%lld\n", name, field, value);
}

static void schedule(const char* name) {
  mi_arena_id_t arena_id = _mi_arena_id_none();
  require(mi_reserve_os_memory_ex2(owner, MI_ARENA_MIN_SIZE, false, false, false, &arena_id) == 0);
  mi_arena_t* const arena = _mi_arena_from_id(arena_id);
  mi_memid_t memid;
  void* const block = mi_arena_try_alloc_at(arena, 1, true, 0, &memid);
  require(block != NULL);
  const size_t slice = memid.mem.arena.slice_index;
  mi_atomic_storei64_release(&owner->purge_expire, 0);
  const long delay = mi_arena_purge_delay();
  const int64_t calls = owner->stats.purge_calls.total;
  const mi_msecs_t before = _mi_clock_now();
  _mi_arenas_free(owner, block, MI_ARENA_SLICE_SIZE, memid);
  const mi_msecs_t after = _mi_clock_now();
  const mi_msecs_t expire = mi_atomic_loadi64_acquire(&arena->purge_expire);
  const mi_msecs_t global = mi_atomic_loadi64_acquire(&owner->purge_expire);
  emit(name, "pending", mi_bitmap_is_setN(arena->slices_purge, slice, 1));
  emit(name, "expire", delay > 0 ? (expire >= before + delay && expire <= after + delay) : expire == 0);
  emit(name, "global", delay > 0 ? global == expire : global == 0);
  emit(name, "committed", mi_bitmap_is_setN(arena->slices_committed, slice, 1));
  emit(name, "free", mi_bbitmap_is_setN(arena->slices_free, slice, 1));
  emit(name, "purge_calls", owner->stats.purge_calls.total - calls);
  if (delay <= 0) return;
  const mi_msecs_t rebase_before = _mi_clock_now();
  mi_arenas_try_purge(true, true, owner, 0);
  const mi_msecs_t rebase_after = _mi_clock_now();
  const mi_msecs_t rebased = mi_atomic_loadi64_acquire(&owner->purge_expire);
  emit(name, "rebased", rebased >= rebase_before + delay / 10 && rebased <= rebase_after + delay / 10);
  emit(name, "purged_pending", mi_bitmap_is_setN(arena->slices_purge, slice, 1));
  emit(name, "purged_expire", mi_atomic_loadi64_acquire(&arena->purge_expire));
  emit(name, "purged_committed", mi_bitmap_is_setN(arena->slices_committed, slice, 1));
  emit(name, "purged_calls", owner->stats.purge_calls.total - calls);
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  mi_process_init();
  os_preloading = false;
  owner = _mi_subproc_main();
  emit("environment", "delay", mi_arena_purge_delay());
  static const struct { const char* name; long delay; long mult; bool schedule; } rows[] = {
    { "defaults", 1000, 4, false },
    { "product", 7, 3, true },
    { "disabled_delay", -1, 4, true },
    { "disabled_mult", 10, -1, false },
    { "immediate_delay", 0, 4, true },
    { "immediate_mult", 10, 0, false },
    { "exact_power", 1L << 31, 1L << 31, false },
    { "long_max", LONG_MAX, 1, false },
    { "above_long_max", 1L << 62, 2, true },
    { "size_overflow", 1L << 62, 4, false },
    { "both_max", LONG_MAX, LONG_MAX, false },
  };
  for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
    mi_option_set(mi_option_purge_delay, rows[i].delay);
    mi_option_set(mi_option_arena_purge_mult, rows[i].mult);
    emit(rows[i].name, "delay", mi_arena_purge_delay());
    if (rows[i].schedule) schedule(rows[i].name);
  }
  return 0;
}
