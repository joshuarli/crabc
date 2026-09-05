/* Copyright (c) 2026 crabc contributors. SPDX-License-Identifier: MIT */
/* Registry semantics only: anonymous memory simulates successful huge
 * primitives. No kernel huge-page availability or reservation claim. */
#include "static.c"
#include <stdio.h>
#include <stdlib.h>
static void require(bool value) { if (!value) abort(); }
int main(void) {
  mi_subproc_t* subproc = _mi_subproc();
  const size_t initial_count = mi_atomic_load_relaxed(&subproc->arena_count);
  mi_arena_id_t regular;
  require(mi_reserve_os_memory_ex2(subproc, MI_ARENA_MIN_SIZE, true, false, false, &regular) == 0);
  mi_memid_t memory;
  const size_t size = 17 * MI_GiB;
  void* p = _mi_os_alloc_aligned(subproc, size, MI_GiB, true, false, &memory);
  require(p != NULL);
  memory.memkind = MI_MEM_OS_HUGE;
  memory.is_pinned = true;
  mi_arena_id_t id;
  require(mi_manage_os_memory_ex2(subproc, p, size, -1, false, memory, NULL, NULL, &id));
  mi_arena_t* parent = _mi_arena_from_id(id);
  mi_arena_t* child = mi_atomic_load_ptr_acquire(mi_arena_t, &subproc->arenas[initial_count + 2]);
  require(child != NULL);
  const int64_t commits = subproc->stats.commit_calls.total;
  const int64_t committed = subproc->stats.committed.current;
  mi_memid_t claim_memory;
  void* claim = mi_arena_try_alloc_at(parent, 1, true, 0, &claim_memory);
  require(claim != NULL && claim_memory.is_pinned);
  _mi_arenas_free(subproc, claim, MI_ARENA_SLICE_SIZE, claim_memory);
  const size_t values[] = {
    mi_atomic_load_relaxed(&subproc->arena_count) - initial_count,
    parent->total_size / MI_GiB, parent->memid.memkind == MI_MEM_OS_HUGE,
    child->parent == parent, child->memid.memkind == MI_MEM_NONE, child->memid.is_pinned,
    subproc->stats.commit_calls.total - commits,
    subproc->stats.committed.current - committed,
  };
  for (size_t i = 0; i < sizeof(values)/sizeof(values[0]); i++)
    printf("m2.huge.registry.%zu=%zu\n", i, values[i]);
  return 0;
}
