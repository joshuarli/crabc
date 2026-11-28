/* Copyright (c) 2026 crabc contributors. SPDX-License-Identifier: MIT */
/* Pinned `mi_arenas_try_purge` (src/arena.c:2389-2435) over eight regular
   arenas, each with one freed committed slice scheduled for purge and arena 1
   marked pinned afterwards. A preloading call returns before any visit; four
   forced bounded calls then spend the `max_arena/4 + 1` budget from their
   thread-sequence start, skip the pinned arena (src/arena.c:2362-2365), drain
   the rest and finally clear the subprocess expiration. */
#define _GNU_SOURCE 1
#include <stdint.h>
#include <stdio.h>

#include "static.c"

#define ARENAS 8
#define PINNED 1

static mi_subproc_t* owner;
static mi_arena_t* arenas[ARENAS];
static size_t slices[ARENAS];

static void emit(const char* name, long long value) {
  printf("m2.arena_purge_rotation.%s=%lld\n", name, value);
}

static long long pending_mask(void) {
  long long mask = 0;
  for (size_t i = 0; i < ARENAS; i++) {
    if (mi_bitmap_is_setN(arenas[i]->slices_purge, slices[i], 1)) mask |= 1LL << i;
  }
  return mask;
}

static long long expiry_mask(void) {
  long long mask = 0;
  for (size_t i = 0; i < ARENAS; i++) {
    if (mi_atomic_loadi64_relaxed(&arenas[i]->purge_expire) == 0) mask |= 1LL << i;
  }
  return mask;
}

static long long global_state(void) {
  const mi_msecs_t value = mi_atomic_loadi64_relaxed(&owner->purge_expire);
  return value == INT64_MAX ? 1 : value == 0 ? 0 : 2;
}

static void emit_stage(const char* stage, int64_t visits, int64_t calls) {
  char name[64];
  snprintf(name, sizeof(name), "%s_pending", stage);
  emit(name, pending_mask());
  snprintf(name, sizeof(name), "%s_expiry", stage);
  emit(name, expiry_mask());
  snprintf(name, sizeof(name), "%s_global", stage);
  emit(name, global_state());
  snprintf(name, sizeof(name), "%s_visits", stage);
  emit(name, owner->stats.arena_purges.total - visits);
  snprintf(name, sizeof(name), "%s_calls", stage);
  emit(name, owner->stats.purge_calls.total - calls);
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  mi_process_init();
  os_preloading = false;
  owner = _mi_subproc_main();
  mi_option_set(mi_option_purge_delay, 100000);
  mi_option_set(mi_option_arena_purge_mult, 1);
  mi_option_set(mi_option_purge_decommits, 1);
  for (size_t i = 0; i < ARENAS; i++) {
    mi_arena_id_t arena_id = _mi_arena_id_none();
    if (mi_reserve_os_memory_ex2(owner, MI_ARENA_MIN_SIZE, false, false, false, &arena_id) != 0) return 2;
    arenas[i] = _mi_arena_from_id(arena_id);
    mi_memid_t memid;
    void* address = mi_arena_try_alloc_at(arenas[i], 1, true, 0, &memid);
    if (address == NULL) return 3;
    slices[i] = memid.mem.arena.slice_index;
    _mi_arenas_free(owner, address, MI_ARENA_SLICE_SIZE, memid);
    mi_atomic_storei64_release(&arenas[i]->purge_expire, INT64_MAX);
  }
  mi_atomic_storei64_release(&owner->purge_expire, INT64_MAX);
  arenas[PINNED]->memid.is_pinned = true;
  const int64_t visits = owner->stats.arena_purges.total;
  const int64_t calls = owner->stats.purge_calls.total;
  const int64_t bytes = owner->stats.purged.total;
  emit("setup", mi_arenas_get_count(owner) == ARENAS);
  emit("initial_pending", pending_mask());
  os_preloading = true;
  mi_arenas_try_purge(true, true, owner, 0);
  os_preloading = false;
  emit_stage("preloading", visits, calls);
  mi_arenas_try_purge(true, false, owner, 0);
  emit_stage("first", visits, calls);
  mi_arenas_try_purge(true, false, owner, 5);
  emit_stage("second", visits, calls);
  mi_arenas_try_purge(true, false, owner, 0);
  emit_stage("third", visits, calls);
  mi_arenas_try_purge(true, false, owner, 0);
  emit_stage("fourth", visits, calls);
  emit("bytes", owner->stats.purged.total - bytes);
  emit("pinned_committed", mi_bitmap_is_setN(arenas[PINNED]->slices_committed, slices[PINNED], 1));
  emit("registry", mi_arenas_get_count(owner));
  arenas[PINNED]->memid.is_pinned = false;
  return 0;
}
