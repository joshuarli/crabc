/* A failed purge still spends one process-wide arena visit. */
#define _GNU_SOURCE 1
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

#include "static.c"

static mi_subproc_t* owner;
static void* selected_address;
static size_t advice_calls;
static size_t exact_first;
static bool fail_first;

int __real_madvise(void* address, size_t length, int advice);
int __wrap_madvise(void* address, size_t length, int advice) {
  if (selected_address != NULL) {
    advice_calls++;
    if (advice_calls == 1) {
      exact_first = address == selected_address && length == MI_ARENA_SLICE_SIZE
          && advice == MADV_DONTNEED;
    }
    if (fail_first) {
      fail_first = false;
      errno = EIO;
      return -1;
    }
  }
  return __real_madvise(address, length, advice);
}

static void emit(const char* name, long long value) {
  printf("m2.arena_purge_budget_failure.%s=%lld\n", name, value);
}

static int64_t pending_mask(mi_arena_t* arenas[3], size_t slices[3]) {
  int64_t mask = 0;
  for (size_t i = 0; i < 3; i++) {
    if (mi_bitmap_is_setN(arenas[i]->slices_purge, slices[i], 1)) mask |= 1 << i;
  }
  return mask;
}

static int64_t expiry_mask(mi_arena_t* arenas[3]) {
  int64_t mask = 0;
  for (size_t i = 0; i < 3; i++) {
    if (mi_atomic_loadi64_relaxed(&arenas[i]->purge_expire) == 0) mask |= 1 << i;
  }
  return mask;
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  mi_process_init();
  os_preloading = false;
  owner = _mi_subproc_main();
  mi_option_set(mi_option_purge_delay, 100000);
  mi_option_set(mi_option_arena_purge_mult, 1);
  mi_option_set(mi_option_purge_decommits, 1);
  mi_option_set(mi_option_show_errors, 0);
  mi_arena_t* arenas[3];
  mi_memid_t ids[3];
  size_t slices[3];
  void* addresses[3];
  for (size_t i = 0; i < 3; i++) {
    mi_arena_id_t arena_id = _mi_arena_id_none();
    if (mi_reserve_os_memory_ex2(owner, MI_ARENA_MIN_SIZE, false, false, false, &arena_id) != 0) return 2;
    arenas[i] = _mi_arena_from_id(arena_id);
    addresses[i] = mi_arena_try_alloc_at(arenas[i], 1, true, 0, &ids[i]);
    if (addresses[i] == NULL) return 3;
    slices[i] = ids[i].mem.arena.slice_index;
    _mi_arenas_free(owner, addresses[i], MI_ARENA_SLICE_SIZE, ids[i]);
    mi_atomic_storei64_release(&arenas[i]->purge_expire, INT64_MAX);
  }
  mi_atomic_storei64_release(&owner->purge_expire, INT64_MAX);
  const int64_t calls = owner->stats.purge_calls.total;
  const int64_t bytes = owner->stats.purged.total;
  const int64_t visits = owner->stats.arena_purges.total;
  emit("setup", mi_arenas_get_count(owner) == 3 && pending_mask(arenas, slices) == 7);
  emit("initial_pending", pending_mask(arenas, slices));
  selected_address = addresses[1];
  fail_first = true;
  mi_arenas_try_purge(true, false, owner, 1);
  emit("first_pending", pending_mask(arenas, slices));
  emit("first_expiry", expiry_mask(arenas));
  emit("first_advice", advice_calls);
  emit("first_exact", exact_first);
  emit("first_visits", owner->stats.arena_purges.total - visits);
  emit("first_calls", owner->stats.purge_calls.total - calls);
  emit("first_bytes", owner->stats.purged.total - bytes);
  emit("first_committed", mi_bitmap_is_setN(arenas[1]->slices_committed, slices[1], 1));
  mi_arenas_try_purge(true, false, owner, 2);
  emit("second_pending", pending_mask(arenas, slices));
  emit("second_expiry", expiry_mask(arenas));
  emit("second_advice", advice_calls);
  emit("second_visits", owner->stats.arena_purges.total - visits);
  mi_arenas_try_purge(true, false, owner, 0);
  emit("third_pending", pending_mask(arenas, slices));
  emit("third_expiry", expiry_mask(arenas));
  emit("third_advice", advice_calls);
  emit("third_visits", owner->stats.arena_purges.total - visits);
  mi_arenas_try_purge(true, false, owner, 0);
  emit("global_cleared", mi_atomic_loadi64_relaxed(&owner->purge_expire) == 0);
  emit("calls", owner->stats.purge_calls.total - calls);
  emit("bytes", owner->stats.purged.total - bytes);
  emit("registry", mi_arenas_get_count(owner));
  return 0;
}
