/* Copyright (c) 2026 crabc contributors. SPDX-License-Identifier: MIT */
/* Pinned mi_subproc_new / mi_subproc_destroy / mi_subproc_visit_heaps
   lifecycle for root children of the main subprocess, printed in the field
   order of subproc_lifecycle::tests::source_ordered_child_subprocess_lifecycle_trace. */
#include "static.c"
#include <stdio.h>
#include <stdlib.h>

static void require(bool condition) { if (!condition) abort(); }

static size_t member_count(void) {
  size_t count = 0;
  for (mi_subproc_t* subproc = mi_subprocs; subproc != NULL; subproc = subproc->next) count++;
  return count;
}

static mi_subproc_t* member_at(size_t index) {
  mi_subproc_t* subproc = mi_subprocs;
  while (subproc != NULL && index-- > 0) subproc = subproc->next;
  return subproc;
}

typedef struct visit_state_s { size_t count; bool result; } visit_state_t;

static bool visit_count(mi_heap_t* heap, void* arg) {
  (void)heap;
  visit_state_t* state = (visit_state_t*)arg;
  state->count++;
  return state->result;
}

static int64_t values[64];
static size_t value_count;
static void push(int64_t value) { require(value_count < 64); values[value_count++] = value; }

int main(void) {
  mi_process_init();
  /* Match the Rust fixture's arena policy: one minimum-size reservation
     without eager commit. */
  mi_option_set(mi_option_arena_reserve, (long)(MI_ARENA_MIN_SIZE / MI_KiB));
  mi_option_set(mi_option_arena_eager_commit, 0);
  mi_subproc_t* const main_subproc = _mi_subproc_main();
  push((int64_t)member_count());

  mi_subproc_t* const first = _mi_subproc_from_id(mi_subproc_new());
  require(first != NULL);
  push((int64_t)member_count());
  push(member_at(0) == first);
  push((int64_t)first->subproc_seq);
  push(first->parent == main_subproc);
  push((int64_t)mi_atomic_load_relaxed(&first->heap_count));
  push((int64_t)mi_atomic_load_relaxed(&first->heap_total_count));
  push(first->heaps == first->heap_main && first->heap_main->next == NULL);
  push((int64_t)first->heap_main->heap_seq);
  push(first->heap_main->subproc == first);
  mi_theap_t* const meta = first->theap_meta;
  push(meta != NULL && first->heap_main->theaps == meta && meta->hnext == NULL
       && meta->hprev == NULL && mi_atomic_load_ptr_relaxed(mi_heap_t, &meta->heap) == first->heap_main);
  push(meta->is_detached && meta->tld != NULL && meta->tld == main_subproc->theap_meta->tld);
  push((int64_t)mi_atomic_load_relaxed(&first->thread_count));
  push((int64_t)mi_atomic_load_relaxed(&first->thread_total_count));
  push((int64_t)mi_arenas_get_count(first));
  push(first->stats.heaps.current);

  mi_subproc_t* const second = _mi_subproc_from_id(mi_subproc_new());
  require(second != NULL);
  push((int64_t)member_count());
  push(member_at(0) == second && member_at(1) == first);
  push((int64_t)second->subproc_seq);

  visit_state_t state = { 0, true };
  push(mi_subproc_visit_heaps(_mi_subproc_to_id(first), &visit_count, &state));
  push((int64_t)state.count);
  state.count = 0; state.result = false;
  push(mi_subproc_visit_heaps(_mi_subproc_to_id(first), &visit_count, &state));
  push((int64_t)state.count);

  /* The first child metadata block reserves the child's first arena. */
  const size_t main_arenas_before = mi_arenas_get_count(main_subproc);
  mi_memid_t memid;
  void* block = _mi_meta_zalloc(first, 64, &memid);
  require(block != NULL);
  push((int64_t)mi_arenas_get_count(first));
  push((int64_t)mi_arenas_get_count(main_subproc) - (int64_t)main_arenas_before);
  _mi_meta_free(first, block, memid);
  const int64_t first_reserved = first->stats.reserved.current;
  push(first_reserved > 0);

  const int64_t heaps_before = main_subproc->stats.heaps.total;
  const int64_t reserved_before = main_subproc->stats.reserved.current;
  const int64_t arenas_before = main_subproc->stats.arena_count.total;
  const int64_t pages_before = main_subproc->stats.pages.total;
  mi_subproc_destroy(_mi_subproc_to_id(first));
  push((int64_t)member_count());
  push(member_at(0) == second && member_at(1) == main_subproc);
  push(main_subproc->stats.heaps.total - heaps_before);
  push(main_subproc->stats.reserved.current - reserved_before == first_reserved);
  push(main_subproc->stats.arena_count.total - arenas_before);
  push(main_subproc->stats.pages.total > pages_before);

  /* Destroying the main subprocess or a null identifier is a no-op. The Rust
     child owner cannot name either, so these are asserted but not traced. */
  mi_subproc_destroy(mi_subproc_main());
  mi_subproc_id_t none = { NULL };
  mi_subproc_destroy(none);
  require(member_count() == 2);

  mi_subproc_destroy(_mi_subproc_to_id(second));
  push((int64_t)member_count());

  mi_subproc_t* const third = _mi_subproc_from_id(mi_subproc_new());
  require(third != NULL);
  push((int64_t)third->subproc_seq);
  mi_subproc_destroy(_mi_subproc_to_id(third));
  push((int64_t)member_count());
  push(_mi_subproc_from_id(mi_subproc_current()) == main_subproc
       && _mi_subproc_from_id(mi_subproc_main()) == main_subproc);

  for (size_t i = 0; i < value_count; i++) {
    printf("m6.subproc.lifecycle.%zu=%lld\n", i, (long long)values[i]);
  }
  return 0;
}
