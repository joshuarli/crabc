/* Copyright (c) 2026 crabc contributors. SPDX-License-Identifier: MIT */
/* Pinned mi_subproc_new / mi_subproc_add_current_thread /
   mi_subproc_visit_heaps / mi_subproc_destroy lifecycle for root children of
   the main subprocess, printed in the field
   order of subproc_lifecycle::tests::source_ordered_child_subprocess_lifecycle_trace. */
#include "static.c"
#include <pthread.h>
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

static int64_t values[128];
static size_t value_count;
static void push(int64_t value) { require(value_count < 128); values[value_count++] = value; }

/* A fresh thread joins `subproc`, allocates and frees one block, and runs
   `mi_thread_done`. Its fields follow the main-thread fields in order. */
typedef struct worker_s { mi_subproc_t* subproc; int64_t values[16]; size_t count; } worker_t;
static void wpush(worker_t* worker, int64_t value) {
  require(worker->count < 16);
  worker->values[worker->count++] = value;
}

static void* worker_main(void* arg) {
  worker_t* const worker = (worker_t*)arg;
  mi_subproc_t* const subproc = worker->subproc;
  require(!mi_theap_is_initialized(_mi_theap_default()));
  mi_subproc_add_current_thread(_mi_subproc_to_id(subproc));
  mi_theap_t* const theap = _mi_theap_default();
  wpush(worker, (int64_t)mi_atomic_load_relaxed(&subproc->thread_count));
  wpush(worker, (int64_t)mi_atomic_load_relaxed(&subproc->thread_total_count));
  wpush(worker, subproc->stats.threads.current);
  wpush(worker, subproc->stats.theaps.current);
  wpush(worker, mi_theap_is_initialized(theap) && _mi_theap_heap(theap) == subproc->heap_main
                && !theap->is_detached);
  wpush(worker, theap->tld->subproc == subproc);
  wpush(worker, (int64_t)theap->tld->thread_seq);
  /* Re-adding a thread of the same subprocess changes nothing. */
  mi_subproc_add_current_thread(_mi_subproc_to_id(subproc));
  require(_mi_theap_default() == theap && mi_atomic_load_relaxed(&subproc->thread_count) == 1);
  void* const block = mi_malloc(64);
  require(block != NULL);
  const mi_page_t* const page = _mi_ptr_page(block);
  wpush(worker, mi_page_heap(page) == subproc->heap_main);
  wpush(worker, mi_page_thread_id(page) == _mi_thread_id());
  mi_free(block);
  mi_thread_done();
  wpush(worker, !mi_theap_is_initialized(_mi_theap_default()));
  wpush(worker, (int64_t)mi_atomic_load_relaxed(&subproc->thread_count));
  wpush(worker, (int64_t)mi_atomic_load_relaxed(&subproc->thread_total_count));
  wpush(worker, subproc->stats.threads.current);
  wpush(worker, subproc->stats.theaps.current);
  return NULL;
}

/* A fresh thread joins `subproc`, allocates three 64-byte blocks on one
   page and one 3000-byte block on another, frees the middle 64-byte block,
   and finishes with the other three live: `_mi_thread_done` hands both pages
   to the child main Heap as abandoned pages. */
typedef struct handoff_s { mi_subproc_t* subproc; void* small[2]; void* medium; } handoff_t;

static void* handoff_main(void* arg) {
  handoff_t* const handoff = (handoff_t*)arg;
  mi_subproc_add_current_thread(_mi_subproc_to_id(handoff->subproc));
  handoff->small[0] = mi_malloc(64);
  void* const freed = mi_malloc(64);
  handoff->small[1] = mi_malloc(64);
  handoff->medium = mi_malloc(3000);
  require(handoff->small[0] != NULL && freed != NULL && handoff->small[1] != NULL && handoff->medium != NULL);
  mi_free(freed);
  mi_thread_done();
  return NULL;
}

/* The abandoned-page facts of one page of `heap`. */
static void push_abandoned(mi_heap_t* heap, mi_page_t* page) {
  push(mi_page_is_abandoned(page));
  push(mi_page_is_abandoned_mapped(page));
  push((int64_t)mi_atomic_load_relaxed(&heap->abandoned_count[_mi_bin(mi_page_block_size(page))]));
  push((int64_t)page->used);
}

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

  /* `mi_subproc_add_current_thread` on a thread already in the main
     subprocess only warns. */
  mi_subproc_add_current_thread(_mi_subproc_to_id(first));
  push(_mi_theap_default()->tld->subproc == main_subproc);
  push((int64_t)mi_atomic_load_relaxed(&first->thread_count));
  push((int64_t)mi_atomic_load_relaxed(&first->thread_total_count));
  worker_t worker = { first, {0}, 0 };
  pthread_t thread;
  require(pthread_create(&thread, NULL, &worker_main, &worker) == 0);
  require(pthread_join(thread, NULL) == 0);
  for (size_t i = 0; i < worker.count; i++) push(worker.values[i]);
  push(first->stats.threads.total);

  const int64_t heaps_before = main_subproc->stats.heaps.total;
  const int64_t reserved_before = main_subproc->stats.reserved.current;
  const int64_t arenas_before = main_subproc->stats.arena_count.total;
  const int64_t pages_before = main_subproc->stats.pages.total;
  const int64_t threads_before = main_subproc->stats.threads.total;
  const int64_t pages_current_before = main_subproc->stats.pages.current;
  mi_subproc_destroy(_mi_subproc_to_id(first));
  push((int64_t)member_count());
  push(member_at(0) == second && member_at(1) == main_subproc);
  push(main_subproc->stats.heaps.total - heaps_before);
  push(main_subproc->stats.reserved.current - reserved_before == first_reserved);
  push(main_subproc->stats.arena_count.total - arenas_before);
  push(main_subproc->stats.pages.total > pages_before);
  push(main_subproc->stats.threads.total - threads_before);
  /* Destroy releases the child's pages only with its arenas, after the
     statistics merge, so its retired metadata page stays counted. */
  push(main_subproc->stats.pages.current - pages_current_before);

  /* Destroying the main subprocess or a null identifier is a no-op. The Rust
     child owner cannot name either, so these are asserted but not traced. */
  mi_subproc_destroy(mi_subproc_main());
  mi_subproc_id_t none = { NULL };
  mi_subproc_destroy(none);
  require(member_count() == 2);

  /* A child destroyed with a live metadata block: its page is released
     with the child arenas. */
  mi_memid_t live_memid;
  void* const live = _mi_meta_zalloc(second, 64, &live_memid);
  require(live != NULL);
  const int64_t second_reserved = second->stats.reserved.current;
  const int64_t second_pages = second->stats.pages.current;
  push(second_pages);
  const int64_t reserved_before_second = main_subproc->stats.reserved.current;
  const int64_t pages_before_second = main_subproc->stats.pages.current;
  mi_subproc_destroy(_mi_subproc_to_id(second));
  push((int64_t)member_count());
  push(main_subproc->stats.pages.current - pages_before_second);
  push(main_subproc->stats.reserved.current - reserved_before_second == second_reserved);

  mi_subproc_t* const third = _mi_subproc_from_id(mi_subproc_new());
  require(third != NULL);
  push((int64_t)third->subproc_seq);
  mi_subproc_destroy(_mi_subproc_to_id(third));
  push((int64_t)member_count());
  push(_mi_subproc_from_id(mi_subproc_current()) == main_subproc
       && _mi_subproc_from_id(mi_subproc_main()) == main_subproc);

  /* Page handoff at thread finish (init.c:377-421, theap.c:95-156,
     page.c:291-304, arena.c:1304-1356), then frees from a thread outside
     the child, which never reclaims (free.c:372-493). */
  mi_subproc_t* const fourth = _mi_subproc_from_id(mi_subproc_new());
  require(fourth != NULL);
  handoff_t handoff = { fourth, { NULL, NULL }, NULL };
  require(pthread_create(&thread, NULL, &handoff_main, &handoff) == 0);
  require(pthread_join(thread, NULL) == 0);
  mi_heap_t* const handoff_heap = fourth->heap_main;
  mi_page_t* const small_page = _mi_ptr_page(handoff.small[0]);
  mi_page_t* const medium_page = _mi_ptr_page(handoff.medium);
  push((int64_t)mi_atomic_load_relaxed(&fourth->thread_count));
  push(small_page != medium_page && _mi_ptr_page(handoff.small[1]) == small_page);
  push(mi_page_heap(small_page) == handoff_heap && mi_page_heap(medium_page) == handoff_heap);
  push_abandoned(handoff_heap, small_page);
  push_abandoned(handoff_heap, medium_page);
  /* A free that leaves a live block keeps the page abandoned and mapped. */
  mi_free(handoff.small[0]);
  push_abandoned(handoff_heap, small_page);
  /* The last block of a page unabandons and frees it. */
  const size_t medium_bin = _mi_bin(mi_page_block_size(medium_page));
  mi_free(handoff.medium);
  push((int64_t)mi_atomic_load_relaxed(&handoff_heap->abandoned_count[medium_bin]));
  /* The child is destroyed with one live block on an abandoned page. */
  mi_subproc_destroy(_mi_subproc_to_id(fourth));
  push((int64_t)member_count());

  for (size_t i = 0; i < value_count; i++) {
    printf("m6.subproc.lifecycle.%zu=%lld\n", i, (long long)values[i]);
  }
  return 0;
}
