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
#include <string.h>

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

/* The Heap and block that outlive the worker thread. */
static mi_heap_t* sixth;
static void* sixth_block;
static mi_heap_t* seventh;
static void* seventh_block;

/* A second thread allocates two main-Heap blocks and finishes, abandoning
   their page. */
static void* handoff[2];
static void* abandon_main(void* arg) {
  mi_subproc_add_current_thread(_mi_subproc_to_id((mi_subproc_t*)arg));
  handoff[0] = mi_malloc(64);
  handoff[1] = mi_malloc(64);
  require(handoff[0] != NULL && handoff[1] != NULL);
  mi_thread_done();
  return NULL;
}

/* A third thread reclaims abandoned pages: on a free into the main Heap's
   page while its own queue for the bin is empty (free.c:423-469), and on an
   allocation from the non-main Heap whose page the first thread abandoned
   (arena.c:725-776, page.c:307-340). */
static void* reclaim_main(void* arg) {
  mi_subproc_t* const subproc = (mi_subproc_t*)arg;
  mi_subproc_add_current_thread(_mi_subproc_to_id(subproc));
  mi_theap_t* const theap = _mi_theap_default();
  mi_page_t* const page = _mi_ptr_page(handoff[1]);
  const size_t bin = _mi_bin(mi_page_block_size(page));
  push((int64_t)mi_atomic_load_relaxed(&subproc->heap_main->abandoned_count[bin]));
  mi_free(handoff[0]);
  push(!mi_page_is_abandoned(page) && page->theap == theap && mi_page_thread_id(page) == _mi_thread_id());
  push((int64_t)page->used);
  push((int64_t)mi_atomic_load_relaxed(&subproc->heap_main->abandoned_count[bin]));
  push((int64_t)theap->page_count);
  mi_page_t* const sixth_page = _mi_ptr_page(sixth_block);
  const size_t sixth_bin = _mi_bin(mi_page_block_size(sixth_page));
  void* const reused = mi_heap_malloc(sixth, 64);
  require(reused != NULL);
  push(_mi_ptr_page(reused) == sixth_page && !mi_page_is_abandoned(sixth_page));
  push(sixth_page->theap == sixth->theaps && sixth->theaps != NULL && sixth->theaps->tld == theap->tld);
  push((int64_t)sixth_page->used);
  push((int64_t)mi_atomic_load_relaxed(&sixth->abandoned_count[sixth_bin]));
  mi_thread_done();
  return NULL;
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

  /* The next Heap image is allocated from the main Heap through
     `_mi_heap_theap(heap_main)`, which moves the cached Theap to the main
     Heap's Theap and so frees the destroyed Heap's Theap. */
  mi_heap_t* const fifth = mi_heap_new();
  require(fifth != NULL);
  push(_mi_theap_cached() == main_theap);
  push(subproc->stats.theaps.current);

  /* mi_heap_delete with live pages (heap.c:228-238, arena.c:2531-2638):
     the pages move to the main Heap as abandoned pages. */
  void* const d = mi_heap_malloc(fifth, 64);
  void* const e = mi_heap_malloc(fifth, 1000);
  require(d != NULL && e != NULL);
  mi_page_t* const d_page = _mi_ptr_page(d);
  mi_page_t* const e_page = _mi_ptr_page(e);
  mi_heap_delete(fifth);
  push(mi_page_heap(d_page) == main_heap && mi_page_heap(e_page) == main_heap);
  push(mi_page_is_abandoned(d_page));
  push(mi_page_is_abandoned_mapped(d_page));
  push((int64_t)mi_atomic_load_relaxed(&main_heap->abandoned_count[_mi_bin(mi_page_block_size(d_page))]));
  push((int64_t)mi_atomic_load_relaxed(&main_heap->abandoned_count[_mi_bin(mi_page_block_size(e_page))]));
  push((int64_t)d_page->used);
  push(subproc->stats.theaps.current);
  push_counts(subproc);
  /* The last block of a moved page frees it (free.c:372-379). */
  const size_t d_bin = _mi_bin(mi_page_block_size(d_page));
  mi_free(d);
  push((int64_t)mi_atomic_load_relaxed(&main_heap->abandoned_count[d_bin]));

  /* A thread that finishes with a live block on a non-main Heap's page
     abandons that page to the Heap (theap.c:95-156, arena.c:1304-1356). */
  sixth = mi_heap_new();
  require(sixth != NULL);
  sixth_block = mi_heap_malloc(sixth, 64);
  require(sixth_block != NULL);
  /* An OS-backed block (alignment beyond MI_PAGE_MAX_OVERALLOC_ALIGN) on
     another Heap: its page joins that Heap's OS-abandoned list
     (arena.c:1340-1356). */
  seventh = mi_heap_new();
  require(seventh != NULL);
  seventh_block = mi_heap_malloc_aligned(seventh, 10 * MI_KiB + 1, 128 * MI_KiB);
  require(seventh_block != NULL && mi_memid_is_os(_mi_ptr_page(seventh_block)->memid));
  mi_thread_done();
  return NULL;
}

/* Heaps of the process main subprocess on the main thread (the `main`
   argument, in its own process), printed as `m6.heap.main.*` in the field
   order of
   types::heap_registry::lifecycle::main::tests::source_ordered_main_subprocess_heap_trace:
   test-api.c's heap-os1, heap-os2, and heap-many shapes. */
static int64_t main_values[64];
static size_t main_count;
static void mpush(int64_t value) { require(main_count < 64); main_values[main_count++] = value; }

static void main_subprocess_heaps(void) {
  mi_subproc_t* const subproc = _mi_subproc_main();
  mi_heap_t* const main_heap = subproc->heap_main;
  mi_theap_t* const theap = _mi_theap_default();
  const int64_t theaps0 = subproc->stats.theaps.current;
  const int64_t theaps_total0 = subproc->stats.theaps.total;
  const int64_t heaps0 = (int64_t)mi_atomic_load_relaxed(&subproc->heap_count);

  /* heap-os1: a Heap deleted with a live OS-backed block, then freed. */
  mi_heap_t* const h = mi_heap_new();
  require(h != NULL);
  mpush(h->subproc == subproc && h->theaps == NULL && subproc->heaps == h);
  mpush((int64_t)mi_atomic_load_relaxed(&subproc->heap_count) - heaps0);
  void* const p = mi_heap_malloc_aligned(h, 1 << 20, 2 << 20);
  require(p != NULL);
  mi_page_t* const page = _mi_ptr_page(p);
  mpush(mi_page_heap(page) == h && mi_memid_is_os(page->memid) && page->theap == h->theaps);
  mpush(h->theaps != NULL && h->theaps->tld == theap->tld && theap->tld->theaps == h->theaps
        && h->theaps->tnext == theap);
  mpush(_mi_theap_cached() == h->theaps);
  mpush(subproc->stats.theaps.current - theaps0);
  mi_heap_delete(h);
  mpush(mi_page_heap(page) == main_heap && main_heap->os_abandoned_pages == page
        && mi_page_is_abandoned(page));
  mpush(theap->tld->theaps == theap && theap->tprev == NULL);
  mpush((int64_t)mi_atomic_load_relaxed(&subproc->heap_count) - heaps0);
  mi_free(p);
  mpush(main_heap->os_abandoned_pages == NULL);

  /* heap-os2: a Heap destroyed with ten live OS-backed blocks. */
  mi_heap_t* const h2 = mi_heap_new();
  require(h2 != NULL);
  mpush(_mi_theap_cached() == theap);
  mpush(subproc->stats.theaps.current - theaps0);
  long failed = 0;
  for (int i = 0; i < 10; i++) {
    int* const q = (int*)mi_heap_malloc_aligned(h2, 1 << 20, 2 << 20);
    if (q == NULL) failed++; else q[0] = 42;
  }
  mpush(failed);
  mpush((int64_t)h2->theaps->page_count);
  mi_heap_destroy(h2);
  mpush(main_heap->os_abandoned_pages == NULL);
  mpush((int64_t)mi_atomic_load_relaxed(&subproc->heap_count) - heaps0);

  /* heap-many: 1000 Heaps, each with a Theap and a block, then destroyed. */
  enum { NHEAPS = 1000 };
  static mi_heap_t* heaps[NHEAPS];
  bool allocated = true;
  for (size_t i = 0; i < NHEAPS; i++) {
    heaps[i] = mi_heap_new();
    if (heaps[i] == NULL || mi_heap_malloc(heaps[i], 32) == NULL) { allocated = false; break; }
  }
  mpush(allocated);
  mpush((int64_t)mi_atomic_load_relaxed(&subproc->heap_count) - heaps0);
  mpush((int64_t)mi_thread_locals_peek()->count);
  mpush(subproc->stats.theaps.current - theaps0);
  size_t theaps_on_tld = 0;
  for (mi_theap_t* t = theap->tld->theaps; t != NULL; t = t->tnext) theaps_on_tld++;
  mpush((int64_t)theaps_on_tld);
  for (size_t i = 0; i < NHEAPS; i++) mi_heap_destroy(heaps[i]);
  mpush((int64_t)mi_atomic_load_relaxed(&subproc->heap_count) - heaps0);
  mpush(subproc->heaps == main_heap && main_heap->next == NULL);
  mpush(theap->tld->theaps == theap);
  mpush(subproc->stats.theaps.current - theaps0);
  mpush(subproc->stats.theaps.total - theaps_total0);
  mpush((int64_t)mi_thread_locals_peek()->count);

  /* A Heap created after those were destroyed reuses a freed key whose slot
     on this thread still holds the destroyed Heap's stale Theap value. */
  mi_heap_t* reused = mi_heap_new();
  void* block = mi_heap_malloc(reused, 64);
  mpush(block != NULL);
  mpush(subproc->stats.theaps.current - theaps0);
  mpush((int64_t)mi_thread_locals_peek()->count);
  mi_free(block);
  mi_heap_destroy(reused);
  mpush((int64_t)mi_atomic_load_relaxed(&subproc->heap_count) - heaps0);
  mpush(subproc->stats.theaps.current - theaps0);
}

/* A non-main Heap of the process main subprocess attached by a later
   thread (the `later` argument, in its own process), printed as
   `m6.heap.later.*` in the field order of
   subproc::main_heaps::tests::source_ordered_main_subprocess_later_thread_heap_trace:
   the first allocation creates the thread's Theap for the Heap
   (`_mi_heap_theap_get_or_init`, heap.c:59-99; `_mi_theap_create`,
   theap.c:307-341) at the TLD-list head, on the thread's regular
   thread-local slot, as the cached Theap; a second Heap moves the cached
   root and back; thread done releases the Theap (theap.c:95-156). The
   worker initializes its thread first, as crabc's pthread attach does. */
static int64_t later_values[32];
static size_t later_count;
static void lpush(int64_t value) { require(later_count < 32); later_values[later_count++] = value; }
static mi_heap_t* later_heap;
static int64_t later_theaps0;

static void* later_main(void* argument) {
  (void)argument;
  mi_thread_init();
  mi_subproc_t* const subproc = _mi_subproc_main();
  mi_heap_t* const h = later_heap;
  mi_theap_t* const def = _mi_theap_default();
  require(mi_theap_is_initialized(def));
  lpush(subproc->stats.theaps.current - later_theaps0);
  void* const p1 = mi_heap_malloc(h, 64);
  require(p1 != NULL);
  mi_theap_t* const ht = h->theaps;
  lpush(ht != NULL && ht->tld == def->tld && def->tld->theaps == ht && ht->tnext == def
        && ht->heap == h);
  lpush(_mi_theap_cached() == ht);
  lpush((int64_t)mi_atomic_load_relaxed(&ht->refcount));
  lpush(subproc->stats.theaps.current - later_theaps0);
  lpush((int64_t)mi_thread_locals_peek()->count);
  mi_heap_t* const h2 = mi_heap_new();
  require(h2 != NULL);
  lpush(_mi_theap_cached() == def);
  lpush((int64_t)mi_atomic_load_relaxed(&ht->refcount));
  void* const p2 = mi_heap_malloc(h, 64);
  require(p2 != NULL);
  lpush(h->theaps == ht && _mi_theap_cached() == ht && _mi_ptr_page(p2)->theap == ht);
  lpush((int64_t)mi_atomic_load_relaxed(&ht->refcount));
  lpush(subproc->stats.theaps.current - later_theaps0);
  void* const p3 = mi_heap_malloc(h2, 64);
  require(p3 != NULL);
  mi_theap_t* const h2t = h2->theaps;
  lpush(h2t != NULL && def->tld->theaps == h2t && h2t->tnext == ht);
  lpush(subproc->stats.theaps.current - later_theaps0);
  mi_free(p1);
  mi_free(p2);
  mi_free(p3);
  mi_heap_delete(h2);
  lpush(def->tld->theaps == ht && ht->tprev == NULL);
  lpush(subproc->stats.theaps.current - later_theaps0);
  /* This build's thread done is not attached to pthread exit
     (MI_PRIM_HAS_PROCESS_ATTACH), so the worker runs it explicitly, as the
     child-subprocess worker above does and crabc's pthread exit does. */
  mi_thread_done();
  return NULL;
}

static void main_subprocess_later_thread_heaps(void) {
  mi_subproc_t* const subproc = _mi_subproc_main();
  const int64_t heaps0 = (int64_t)mi_atomic_load_relaxed(&subproc->heap_count);
  later_heap = mi_heap_new();
  require(later_heap != NULL);
  lpush(later_heap->theaps == NULL);
  later_theaps0 = subproc->stats.theaps.current;
  const int64_t theaps_total0 = subproc->stats.theaps.total;
  pthread_t thread;
  require(pthread_create(&thread, NULL, &later_main, NULL) == 0);
  require(pthread_join(thread, NULL) == 0);
  lpush(later_heap->theaps == NULL);
  lpush(subproc->stats.theaps.current - later_theaps0);
  lpush(subproc->stats.theaps.total - theaps_total0);
  lpush((int64_t)mi_atomic_load_relaxed(&subproc->heap_count) - heaps0);
  mi_heap_delete(later_heap);
  lpush((int64_t)mi_atomic_load_relaxed(&subproc->heap_count) - heaps0);
}

int main(int argc, char** argv) {
  mi_process_init();
  if (argc > 1 && strcmp(argv[1], "main") == 0) {
    /* A separate process: the process-global thread-local key registry
       and the initial thread's roots start as in test-api.c. */
    main_subprocess_heaps();
    for (size_t i = 0; i < main_count; i++) {
      printf("m6.heap.main.%zu=%lld\n", i, (long long)main_values[i]);
    }
    return 0;
  }
  if (argc > 1 && strcmp(argv[1], "later") == 0) {
    main_subprocess_later_thread_heaps();
    for (size_t i = 0; i < later_count; i++) {
      printf("m6.heap.later.%zu=%lld\n", i, (long long)later_values[i]);
    }
    return 0;
  }
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
  mi_page_t* const sixth_page = _mi_ptr_page(sixth_block);
  push(mi_page_heap(sixth_page) == sixth && sixth->theaps == NULL);
  push(mi_page_is_abandoned_mapped(sixth_page));
  push((int64_t)mi_atomic_load_relaxed(&sixth->abandoned_count[_mi_bin(mi_page_block_size(sixth_page))]));
  mi_page_t* const seventh_page = _mi_ptr_page(seventh_block);
  push(seventh->os_abandoned_pages == seventh_page && seventh_page->next == NULL && seventh_page->prev == NULL);
  push(mi_page_is_abandoned(seventh_page) && !mi_page_is_abandoned_mapped(seventh_page));
  /* Its only block's free unabandons and frees it (free.c:372-379). */
  mi_free(seventh_block);
  push(seventh->os_abandoned_pages == NULL);
  require(pthread_create(&thread, NULL, &abandon_main, child) == 0);
  require(pthread_join(thread, NULL) == 0);
  require(pthread_create(&thread, NULL, &reclaim_main, child) == 0);
  require(pthread_join(thread, NULL) == 0);
  /* mi_subproc_destroy force-destroys the non-main Heap with its abandoned
     page and live block (subproc.c:215-221). */
  mi_subproc_destroy(_mi_subproc_to_id(child));
  for (size_t i = 0; i < value_count; i++) {
    printf("m6.heap.lifecycle.%zu=%lld\n", i, (long long)values[i]);
  }
  return 0;
}
