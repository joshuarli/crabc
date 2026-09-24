/* Copyright (c) 2026 crabc contributors. SPDX-License-Identifier: MIT */
/* Pinned mi_heap_new / mi_heap_delete / mi_heap_destroy on a thread of a
   child subprocess, for Heaps that never allocate: Heap list order and
   membership, sequence numbers, counts and statistics, dynamic thread-local
   keys, and main-Heap refusal. Printed in the field order of
   types::heap_registry::lifecycle::tests::source_ordered_empty_heap_lifecycle_trace. */
#include "static.c"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

static void require(bool condition) { if (!condition) abort(); }

static int64_t values[128];
static size_t value_count;
static void push(int64_t value) { require(value_count < 128); values[value_count++] = value; }

static size_t list_length(mi_subproc_t* subproc) {
  size_t count = 0;
  for (mi_heap_t* heap = subproc->heaps; heap != NULL; heap = heap->next) count++;
  return count;
}

/* The list in order, with each member's prev link checked. */
static bool list_is(mi_subproc_t* subproc, mi_heap_t* const* expected, size_t count) {
  mi_heap_t* prev = NULL;
  mi_heap_t* heap = subproc->heaps;
  for (size_t i = 0; i < count; i++) {
    if (heap != expected[i] || heap->prev != prev) return false;
    prev = heap;
    heap = heap->next;
  }
  return heap == NULL;
}

static void push_counts(mi_subproc_t* subproc) {
  push((int64_t)mi_atomic_load_relaxed(&subproc->heap_count));
  push((int64_t)mi_atomic_load_relaxed(&subproc->heap_total_count));
  push(subproc->stats.heaps.current);
  push(subproc->stats.heaps.total);
}

/* A non-main Heap image as source initializes it. */
static void push_heap(mi_subproc_t* subproc, mi_heap_t* heap) {
  push((int64_t)heap->heap_seq);
  push(heap->subproc == subproc);
  push(heap->exclusive_arena == NULL);
  push(heap->numa_node);
  push(heap->theaps == NULL);
  push((int64_t)(heap->theap & MI_TLS_IDX_MASK));
  push((int64_t)(heap->theap >> MI_TLS_IDX_BITS));
}

static bool visit_count(mi_heap_t* heap, void* arg) {
  (void)heap;
  (*(size_t*)arg)++;
  return true;
}

static void* worker_main(void* arg) {
  mi_subproc_t* const subproc = (mi_subproc_t*)arg;
  mi_subproc_add_current_thread(_mi_subproc_to_id(subproc));
  mi_heap_t* const main_heap = subproc->heap_main;
  push_counts(subproc);

  mi_heap_t* const first = mi_heap_new();
  require(first != NULL);
  push_heap(subproc, first);
  mi_heap_t* const second = mi_heap_new();
  require(second != NULL);
  push_heap(subproc, second);
  push_counts(subproc);
  { mi_heap_t* const order[] = { second, first, main_heap }; push(list_is(subproc, order, 3)); }
  size_t visited = 0;
  push(mi_subproc_visit_heaps(_mi_subproc_to_id(subproc), &visit_count, &visited));
  push((int64_t)visited);

  /* The main Heap is neither deleted nor destroyed. */
  mi_heap_delete(main_heap);
  mi_heap_destroy(main_heap);
  push((int64_t)list_length(subproc));

  /* Delete the middle member, then destroy the head. */
  mi_heap_delete(first);
  push_counts(subproc);
  { mi_heap_t* const order[] = { second, main_heap }; push(list_is(subproc, order, 2)); }
  mi_heap_destroy(second);
  push_counts(subproc);
  { mi_heap_t* const order[] = { main_heap }; push(list_is(subproc, order, 1)); }

  /* A later Heap reuses the lowest freed key index with the next version. */
  mi_heap_t* const third = mi_heap_new();
  require(third != NULL);
  push_heap(subproc, third);
  push_counts(subproc);
  mi_heap_delete(third);
  push_counts(subproc);

  /* The first allocation from a Heap creates this thread's Theap for it
     (heap.c:59-99, theap.c:236-341): at the head of the thread's TLD list,
     on the Heap's dynamic thread-local slot, and as the cached Theap. */
  mi_theap_t* const main_theap = _mi_theap_default();
  mi_heap_t* const fourth = mi_heap_new();
  require(fourth != NULL);
  push(fourth->theaps == NULL);
  push((int64_t)mi_thread_locals_peek()->count);
  void* const a = mi_heap_malloc(fourth, 64);
  require(a != NULL);
  mi_theap_t* const theap = fourth->theaps;
  push(theap != NULL && theap->hnext == NULL && theap->hprev == NULL && _mi_theap_heap(theap) == fourth);
  push(theap->tld == main_theap->tld && main_theap->tld->theaps == theap
       && theap->tnext == main_theap && main_theap->tprev == theap);
  push((int64_t)mi_atomic_load_relaxed(&theap->refcount));
  push(_mi_theap_cached() == theap);
  push((int64_t)mi_thread_locals_peek()->count);
  push(_mi_thread_local_get(fourth->theap) == theap);
  push(subproc->stats.theaps.current);
  push(subproc->stats.theaps.total);
  push((int64_t)theap->page_count);
  push(mi_heap_of(a) == fourth && mi_heap_contains(fourth, a) && !mi_heap_contains(main_heap, a));
  size_t arena_page_images = 0;
  for (size_t i = 0; i < MI_MAX_ARENAS; i++) {
    if (mi_atomic_load_ptr_relaxed(mi_arena_pages_t, &fourth->arena_pages[i]) != NULL) arena_page_images++;
  }
  push((int64_t)arena_page_images);
  void* const b = mi_heap_malloc(fourth, 1000);
  void* const c = mi_heap_malloc(fourth, 64);
  require(b != NULL && c != NULL);
  push((int64_t)theap->page_count);
  push(_mi_ptr_page(a) == _mi_ptr_page(c) && _mi_ptr_page(a) != _mi_ptr_page(b));
  mi_free(c);
  push((int64_t)_mi_ptr_page(a)->used);

  /* mi_heap_destroy with two live blocks (heap.c:162-259, arena.c:2531-2644):
     its Theaps leave their TLDs, its pages are freed, and the Theap stays
     allocated while it is the cached Theap. */
  mi_heap_destroy(fourth);
  push(subproc->stats.theaps.current);
  push(main_theap->tld->theaps == main_theap && main_theap->tprev == NULL);
  push(_mi_theap_cached() == theap && theap->tld == NULL);
  push((int64_t)mi_atomic_load_relaxed(&theap->refcount));
  push_counts(subproc);
  { mi_heap_t* const order[] = { main_heap }; push(list_is(subproc, order, 1)); }
  mi_thread_done();
  return NULL;
}

int main(void) {
  mi_process_init();
  /* Match the Rust fixture's arena policy: one minimum-size reservation
     without eager commit. */
  mi_option_set(mi_option_arena_reserve, (long)(MI_ARENA_MIN_SIZE / MI_KiB));
  mi_option_set(mi_option_arena_eager_commit, 0);
  mi_subproc_t* const child = _mi_subproc_from_id(mi_subproc_new());
  require(child != NULL);
  pthread_t thread;
  require(pthread_create(&thread, NULL, &worker_main, child) == 0);
  require(pthread_join(thread, NULL) == 0);
  push((int64_t)list_length(child));
  /* `_mi_thread_done` released the cached Theap. */
  push(child->stats.theaps.current);
  push(child->stats.theaps.total);
  mi_subproc_destroy(_mi_subproc_to_id(child));
  for (size_t i = 0; i < value_count; i++) {
    printf("m6.heap.lifecycle.%zu=%lld\n", i, (long long)values[i]);
  }
  return 0;
}
