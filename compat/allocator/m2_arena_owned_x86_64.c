/* Copyright (c) 2026 crabc contributors. SPDX-License-Identifier: MIT */
/* Direct pinned v3.5.0 arena algorithms and real OS backing, no substitutes. */
#include "static.c"
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

int main(void) {
  mi_process_init();
  subprocess = _mi_subproc_main();
  require(_mi_os_has_overcommit());
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
  return 0;
}
