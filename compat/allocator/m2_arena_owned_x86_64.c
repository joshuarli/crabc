/* Copyright (c) 2026 crabc contributors. SPDX-License-Identifier: MIT */
/* Direct pinned v3.5.0 arena algorithms and real OS backing, no substitutes. */
#include "static.c"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static size_t field;
static mi_subproc_t* subprocess;

static void require(bool condition) { if (!condition) abort(); }

static mi_arena_t* arena(bool committed) {
  mi_arena_id_t id = _mi_arena_id_none();
  if (committed) {
    mi_subproc_stat_adjust_decrease(subprocess, committed, MI_ARENA_MIN_SIZE);
  }
  require(mi_reserve_os_memory_ex2(subprocess, MI_ARENA_MIN_SIZE, committed, false, false, &id) == 0);
  return _mi_arena_from_id(id);
}

static void emit(int64_t value) {
  printf("m2.arena.owned.%zu=%lld\n", field++, (long long)value);
}

static void trace_claim(mi_arena_t* owner, bool commit) {
  const int64_t current = subprocess->stats.committed.current;
  const int64_t total = subprocess->stats.committed.total;
  const int64_t calls = subprocess->stats.commit_calls.total;
  mi_memid_t memory;
  void* p = mi_arena_try_alloc_at(owner, 2, commit, 0, &memory);
  require(p != NULL);
  emit(subprocess->stats.committed.current - current);
  emit(subprocess->stats.committed.total - total);
  emit(subprocess->stats.commit_calls.total - calls);
  emit(memory.initially_zero);
  emit(memory.initially_committed);
  _mi_arenas_free(subprocess, p, 2 * MI_ARENA_SLICE_SIZE, memory);
}

static size_t purge_field;
static void emit_purge(int64_t value) {
  printf("m2.arena.purge.%zu=%lld\n", purge_field++, (long long)value);
}

/*
  `_mi_arenas_collect` reaches the static `mi_arenas_try_purge` process-wide
  traversal. Record that relation before the earlier local traces add their
  own arenas, then append the observations after their established 32 fields.
  The forced future expiration avoids a clock/sleep race; emitted fields are
  source-state relations rather than timestamps.
*/
static int64_t process_collect_trace[48];
static size_t process_collect_field;

static void record_process_collect(int64_t value) {
  require(process_collect_field < 48);
  process_collect_trace[process_collect_field++] = value;
}

static int64_t process_collect_expiry_zero_mask(mi_arena_t* owners[3]) {
  int64_t mask = 0;
  for (size_t index = 0; index < 3; index++) {
    if (mi_atomic_loadi64_relaxed(&owners[index]->purge_expire) == 0) {
      mask |= ((int64_t)1 << index);
    }
  }
  return mask;
}

static int64_t process_collect_bitmap_mask(mi_arena_t* owners[3], size_t starts[3], int kind) {
  int64_t mask = 0;
  for (size_t index = 0; index < 3; index++) {
    bool set;
    if (kind == 0) {
      set = mi_bbitmap_is_setN(owners[index]->slices_free, starts[index], 1);
    }
    else if (kind == 1) {
      set = mi_bitmap_is_setN(owners[index]->slices_committed, starts[index], 1);
    }
    else {
      set = mi_bitmap_is_setN(owners[index]->slices_purge, starts[index], 1);
    }
    if (set) mask |= ((int64_t)1 << index);
  }
  return mask;
}

/* 1=future, 2=finite positive rebased/scheduled, 0=cleared. */
static int64_t process_collect_global_state(mi_msecs_t future) {
  const mi_msecs_t value = mi_atomic_loadi64_relaxed(&subprocess->purge_expire);
  if (value == future) return 1;
  if (value == 0) return 0;
  require(value > 0 && value < future);
  return 2;
}

static void record_process_collect_stage(
    mi_arena_t* owners[3], size_t starts[3], mi_msecs_t future,
    int64_t before_arena_purges, int64_t before_purge_calls, int64_t before_purged) {
  record_process_collect(subprocess->stats.arena_purges.total - before_arena_purges);
  record_process_collect(subprocess->stats.purge_calls.total - before_purge_calls);
  record_process_collect(subprocess->stats.purged.total - before_purged);
  record_process_collect((int64_t)mi_arenas_get_count(subprocess));
  record_process_collect(process_collect_global_state(future));
  record_process_collect(process_collect_expiry_zero_mask(owners));
  record_process_collect(process_collect_bitmap_mask(owners, starts, 2));
  record_process_collect(process_collect_bitmap_mask(owners, starts, 0));
  record_process_collect(process_collect_bitmap_mask(owners, starts, 1));
}

static void trace_process_arena_collect(void) {
  mi_arena_t* owners[3];
  mi_memid_t memories[3];
  size_t starts[3];
  const mi_msecs_t future = (mi_msecs_t)INT64_MAX;
  // `src/init.c` keeps the first main-thread TLD in file-static storage;
  // main invokes `_mi_auto_process_init` before calling this trace.
  mi_tld_t* const main_tld = &mi_process_tld_main;
  const size_t saved_thread_seq = main_tld->thread_seq;

  mi_option_set(mi_option_purge_delay, 100000);
  mi_option_set(mi_option_purge_decommits, true);
  for (size_t index = 0; index < 3; index++) {
    owners[index] = arena(false);
    void* p = mi_arena_try_alloc_at(owners[index], 1, true, 0, &memories[index]);
    require(p != NULL);
    starts[index] = memories[index].mem.arena.slice_index;
    _mi_arenas_free(subprocess, p, MI_ARENA_SLICE_SIZE, memories[index]);
    mi_atomic_storei64_release(&owners[index]->purge_expire, future);
  }
  mi_atomic_storei64_release(&subprocess->purge_expire, future);
  require(mi_arenas_get_count(subprocess) == 3);
  require(process_collect_global_state(future) == 1);
  require(process_collect_expiry_zero_mask(owners) == 0);
  require(process_collect_bitmap_mask(owners, starts, 2) == 7);
  require(process_collect_bitmap_mask(owners, starts, 0) == 7);
  require(process_collect_bitmap_mask(owners, starts, 1) == 7);
  record_process_collect((int64_t)mi_arenas_get_count(subprocess));
  record_process_collect(process_collect_bitmap_mask(owners, starts, 0));
  record_process_collect(process_collect_bitmap_mask(owners, starts, 1));

  int64_t before_arena_purges = subprocess->stats.arena_purges.total;
  int64_t before_purge_calls = subprocess->stats.purge_calls.total;
  int64_t before_purged = subprocess->stats.purged.total;
  _mi_arenas_collect(false, false, main_tld);
  require(subprocess->stats.arena_purges.total == before_arena_purges);
  require(subprocess->stats.purge_calls.total == before_purge_calls);
  require(subprocess->stats.purged.total == before_purged);
  require(process_collect_global_state(future) == 1);
  require(process_collect_expiry_zero_mask(owners) == 0);
  require(process_collect_bitmap_mask(owners, starts, 2) == 7);
  require(process_collect_bitmap_mask(owners, starts, 0) == 7);
  require(process_collect_bitmap_mask(owners, starts, 1) == 7);
  record_process_collect_stage(owners, starts, future, before_arena_purges, before_purge_calls, before_purged);

  before_arena_purges = subprocess->stats.arena_purges.total;
  before_purge_calls = subprocess->stats.purge_calls.total;
  before_purged = subprocess->stats.purged.total;
  _mi_arenas_collect(false, true, main_tld);
  require(subprocess->stats.arena_purges.total == before_arena_purges);
  require(subprocess->stats.purge_calls.total == before_purge_calls);
  require(subprocess->stats.purged.total == before_purged);
  require(process_collect_global_state(future) == 2);
  require(process_collect_expiry_zero_mask(owners) == 0);
  require(process_collect_bitmap_mask(owners, starts, 2) == 7);
  require(process_collect_bitmap_mask(owners, starts, 0) == 7);
  require(process_collect_bitmap_mask(owners, starts, 1) == 7);
  record_process_collect_stage(owners, starts, future, before_arena_purges, before_purge_calls, before_purged);

  main_tld->thread_seq = 1;
  before_arena_purges = subprocess->stats.arena_purges.total;
  before_purge_calls = subprocess->stats.purge_calls.total;
  before_purged = subprocess->stats.purged.total;
  _mi_arenas_collect(true, false, main_tld);
  require(subprocess->stats.arena_purges.total == before_arena_purges + 1);
  require(subprocess->stats.purge_calls.total > before_purge_calls);
  require(subprocess->stats.purged.total > before_purged);
  require(process_collect_global_state(future) == 2);
  require(process_collect_expiry_zero_mask(owners) == 2);
  require(process_collect_bitmap_mask(owners, starts, 2) == 5);
  require(process_collect_bitmap_mask(owners, starts, 0) == 7);
  // Pinned Linux release MADV_DONTNEED keeps needs_recommit false here.
  require(process_collect_bitmap_mask(owners, starts, 1) == 7);
  record_process_collect_stage(owners, starts, future, before_arena_purges, before_purge_calls, before_purged);

  main_tld->thread_seq = 2;
  before_arena_purges = subprocess->stats.arena_purges.total;
  before_purge_calls = subprocess->stats.purge_calls.total;
  before_purged = subprocess->stats.purged.total;
  _mi_arenas_collect(true, true, main_tld);
  require(subprocess->stats.arena_purges.total == before_arena_purges + 2);
  require(subprocess->stats.purge_calls.total > before_purge_calls);
  require(subprocess->stats.purged.total > before_purged);
  require(process_collect_global_state(future) == 2);
  require(process_collect_expiry_zero_mask(owners) == 7);
  require(process_collect_bitmap_mask(owners, starts, 2) == 0);
  require(process_collect_bitmap_mask(owners, starts, 0) == 7);
  require(process_collect_bitmap_mask(owners, starts, 1) == 7);
  record_process_collect_stage(owners, starts, future, before_arena_purges, before_purge_calls, before_purged);

  before_arena_purges = subprocess->stats.arena_purges.total;
  before_purge_calls = subprocess->stats.purge_calls.total;
  before_purged = subprocess->stats.purged.total;
  _mi_arenas_collect(true, true, main_tld);
  require(subprocess->stats.arena_purges.total == before_arena_purges);
  require(subprocess->stats.purge_calls.total == before_purge_calls);
  require(subprocess->stats.purged.total == before_purged);
  require(process_collect_global_state(future) == 0);
  require(process_collect_expiry_zero_mask(owners) == 7);
  require(process_collect_bitmap_mask(owners, starts, 2) == 0);
  require(process_collect_bitmap_mask(owners, starts, 0) == 7);
  require(process_collect_bitmap_mask(owners, starts, 1) == 7);
  record_process_collect_stage(owners, starts, future, before_arena_purges, before_purge_calls, before_purged);

  require(process_collect_field == 48);
  main_tld->thread_seq = saved_thread_seq;
}

/*
  A delayed two-slice release can be partly reclaimed before collection. The
  source collector must fail its whole-range `slices_free` claim, try each
  slice, and purge only the free sibling. This is a sequential observation of
  the source atomic ownership relation, not a scheduler race fixture.
*/
static int64_t reallocation_mask(mi_arena_t* owner, size_t start, int kind) {
  int64_t mask = 0;
  for (size_t offset = 0; offset < 2; offset++) {
    bool set;
    if (kind == 0) {
      set = mi_bbitmap_is_setN(owner->slices_free, start + offset, 1);
    }
    else if (kind == 1) {
      set = mi_bitmap_is_setN(owner->slices_purge, start + offset, 1);
    }
    else {
      set = mi_bitmap_is_setN(owner->slices_committed, start + offset, 1);
    }
    if (set) mask |= ((int64_t)1 << offset);
  }
  return mask;
}

static void trace_reallocated_slice_purge_fallback(void) {
  mi_tld_t* const main_tld = &mi_process_tld_main;
  // The preceding 80 fields intentionally retain their original order. Drain
  // their independent delayed-purge work before this measured relation, then
  // choose the same explicit positive delay as the Rust isolated process.
  mi_option_set(mi_option_purge_delay, 100000);
  mi_option_set(mi_option_purge_decommits, true);
  _mi_arenas_collect(true, true, main_tld);
  _mi_arenas_collect(true, true, main_tld);
  require(mi_atomic_loadi64_relaxed(&subprocess->purge_expire) == 0);

  mi_arena_t* owner = arena(false);
  mi_memid_t released;
  void* const original = mi_arena_try_alloc_at(owner, 2, true, 0, &released);
  require(original != NULL);
  const size_t start = released.mem.arena.slice_index;
  _mi_arenas_free(subprocess, original, 2 * MI_ARENA_SLICE_SIZE, released);

  mi_memid_t reallocated;
  void* const live = mi_arena_try_alloc_at(owner, 1, true, 0, &reallocated);
  require(live != NULL);
  require(reallocated.mem.arena.slice_index == start);
  require(live == original);
  *(volatile uint8_t*)live = 0x7b;
  const int64_t before_free_mask = reallocation_mask(owner, start, 0);
  const int64_t before_purge_mask = reallocation_mask(owner, start, 1);
  const int64_t before_committed_mask = reallocation_mask(owner, start, 2);
  require(before_free_mask == 2);
  require(before_purge_mask == 3);
  require(before_committed_mask == 3);

  const int64_t purge_calls = subprocess->stats.purge_calls.total;
  const int64_t purged = subprocess->stats.purged.total;
  const int64_t reset_calls = subprocess->stats.reset_calls.total;
  const int64_t reset = subprocess->stats.reset.total;
  const int64_t committed = subprocess->stats.committed.current;
  const int64_t arena_purges = subprocess->stats.arena_purges.total;
  _mi_arenas_collect(true, true, main_tld);
  require(subprocess->stats.purge_calls.total == purge_calls + 1);
  require(subprocess->stats.purged.total == purged + (int64_t)MI_ARENA_SLICE_SIZE);
  require(subprocess->stats.reset_calls.total == reset_calls);
  require(subprocess->stats.reset.total == reset);
  require(subprocess->stats.committed.current == committed);
  require(subprocess->stats.arena_purges.total == arena_purges + 1);
  require(mi_atomic_loadi64_relaxed(&owner->purge_expire) == 0);
  const int64_t after_free_mask = reallocation_mask(owner, start, 0);
  const int64_t after_purge_mask = reallocation_mask(owner, start, 1);
  const int64_t after_committed_mask = reallocation_mask(owner, start, 2);
  require(after_free_mask == 2);
  require(after_purge_mask == 0);
  // Pinned Linux release MADV_DONTNEED reports no recommit requirement.
  require(after_committed_mask == 3);
  require(*(volatile uint8_t*)live == 0x7b);

  emit_purge((int64_t)(reallocated.mem.arena.slice_index == start));
  emit_purge((int64_t)(live == original));
  emit_purge(before_free_mask);
  emit_purge(before_purge_mask);
  emit_purge(before_committed_mask);
  emit_purge(subprocess->stats.purge_calls.total - purge_calls);
  emit_purge(subprocess->stats.purged.total - purged);
  emit_purge(subprocess->stats.reset_calls.total - reset_calls);
  emit_purge(subprocess->stats.reset.total - reset);
  emit_purge(subprocess->stats.committed.current - committed);
  emit_purge(subprocess->stats.arena_purges.total - arena_purges);
  emit_purge((int64_t)(mi_atomic_loadi64_relaxed(&owner->purge_expire) == 0));
  emit_purge(after_free_mask);
  emit_purge(after_purge_mask);
  emit_purge(after_committed_mask);
  emit_purge(*(volatile uint8_t*)live);

  _mi_arenas_free(subprocess, live, MI_ARENA_SLICE_SIZE, reallocated);
  require(reallocation_mask(owner, start, 0) == 3);
  require(reallocation_mask(owner, start, 1) == 1);
  require(mi_atomic_loadi64_relaxed(&owner->purge_expire) > 0);
  emit_purge(reallocation_mask(owner, start, 0));
  emit_purge(reallocation_mask(owner, start, 1));
  emit_purge((int64_t)(mi_atomic_loadi64_relaxed(&owner->purge_expire) > 0));
}

static void trace_purge(long delay, bool decommit, bool mixed) {
  mi_option_set(mi_option_purge_delay, delay);
  mi_option_set(mi_option_purge_decommits, decommit);
  const int64_t arena_count = subprocess->stats.arena_count.total;
  mi_arena_t* owner = arena(false);
  mi_memid_t memory;
  void* p = mi_arena_try_alloc_at(owner, 2, !mixed, 0, &memory);
  require(p != NULL);
  const size_t start = memory.mem.arena.slice_index;
  if (mixed) {
    require(_mi_os_commit(subprocess, p, MI_ARENA_SLICE_SIZE, NULL));
    mi_bitmap_setN(owner->slices_committed, start, 1, NULL);
  }
  const int64_t calls = subprocess->stats.purge_calls.total;
  const int64_t purged = subprocess->stats.purged.total;
  const int64_t reset_calls = subprocess->stats.reset_calls.total;
  const int64_t reset = subprocess->stats.reset.total;
  const int64_t committed = subprocess->stats.committed.current;
  const int64_t arena_purges = subprocess->stats.arena_purges.total;
  _mi_arenas_free(subprocess, p, 2 * MI_ARENA_SLICE_SIZE, memory);
  if (delay > 0) mi_arena_try_purge(owner, _mi_clock_now(), true);
  emit_purge(subprocess->stats.purge_calls.total - calls);
  emit_purge(subprocess->stats.purged.total - purged);
  emit_purge(subprocess->stats.reset_calls.total - reset_calls);
  emit_purge(subprocess->stats.reset.total - reset);
  emit_purge(subprocess->stats.committed.current - committed);
  emit_purge(mi_bitmap_popcountN(owner->slices_committed, start, 2));
  emit_purge(subprocess->stats.arena_purges.total - arena_purges);
  emit_purge(subprocess->stats.arena_count.total - arena_count);
}

int main(void) {
  // `src/init.c`'s process-loader entry clears the source preloading state
  // before its normal process initialization. This direct fixture needs that
  // exact state for delayed purge scheduling; it does not claim CRT integration.
  _mi_auto_process_init();
  subprocess = _mi_subproc_main();
  require(_mi_os_has_overcommit());
  trace_process_arena_collect();
  mi_arena_t* eager = arena(true);
  trace_claim(eager, true);
  trace_claim(eager, true);
  mi_arena_t* reserved = arena(false);
  trace_claim(reserved, true);
  mi_arena_t* mixed = arena(false);
  mi_memid_t memory;
  void* p = mi_arena_try_alloc_at(mixed, 2, false, 0, &memory);
  require(p != NULL);
  require(_mi_os_commit(subprocess, p, MI_ARENA_SLICE_SIZE, NULL));
  mi_bitmap_setN(mixed->slices_committed, memory.mem.arena.slice_index, 1, NULL);
  _mi_arenas_free(subprocess, p, 2 * MI_ARENA_SLICE_SIZE, memory);
  trace_claim(mixed, false);
  require(field == 20);
  trace_purge(0, true, false);
  trace_purge(0, false, false);
  trace_purge(0, false, true);
  trace_purge(1000, true, false);
  require(purge_field == 32);
  for (size_t index = 0; index < process_collect_field; index++) {
    emit_purge(process_collect_trace[index]);
  }
  require(purge_field == 80);
  trace_reallocated_slice_purge_fallback();
  require(purge_field == 99);
  return 0;
}
