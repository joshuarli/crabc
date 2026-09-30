/* Copyright (c) 2026 crabc contributors. SPDX-License-Identifier: MIT */
/* Pinned mi_heap_new / mi_heap_delete / mi_heap_destroy on a thread of a
   child subprocess, for Heaps that never allocate: Heap list order and
   membership, sequence numbers, counts and statistics, dynamic thread-local
   keys, and main-Heap refusal. Printed in the field order of
   types::heap_registry::lifecycle::tests::source_ordered_empty_heap_lifecycle_trace. */
#ifdef CRABC_HEAP_KEY_FAULT
#include "mimalloc.h"
#include "mimalloc/internal.h"
#include "mimalloc/prim.h"
#include "bitmap.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool key_bitmap_refuse;
static size_t key_bitmap_refusals;
static size_t key_bitmap_expected_size;

static void* key_bitmap_allocate(mi_subproc_t* subproc, size_t size,
                                 size_t alignment, mi_memid_t* memid) {
  if (key_bitmap_refuse) {
    if (subproc != _mi_subproc_main() ||
        size != key_bitmap_expected_size || alignment != MI_BCHUNK_SIZE) abort();
    key_bitmap_refusals++;
    return NULL;
  }
  return _mi_meta_zalloc_aligned(subproc, size, alignment, memid);
}

/* Only the private key-bitmap allocation call is intercepted; Heap creation,
   metadata ownership, bitmap publication, and key release use pinned bodies. */
#define _mi_meta_zalloc_aligned(subproc, size, alignment, memid) \
  key_bitmap_allocate(subproc, size, alignment, memid)
#include "threadlocal.c"
#undef _mi_meta_zalloc_aligned

static void key_observe(size_t index, bool value) {
  if (!value) abort();
  printf("m6.heap.key_fault.%zu=%d\n", index, value);
}

static bool key_count_client(const mi_heap_t* heap, const mi_heap_area_t* area,
                             void* block, size_t size, void* argument) {
  (void)heap; (void)area; (void)size;
  if (block != NULL) (*(size_t*)argument)++;
  return true;
}

static size_t key_main_clients(mi_heap_t* main) {
  size_t count = 0;
  if (!mi_heap_visit_blocks(main, true, key_count_client, &count)) abort();
  return count;
}

static bool key_intact(const unsigned char* caller) {
  for (size_t i = 0; i < 64; i++) if (caller[i] != 0x59) return false;
  return true;
}

int main(void) {
  mi_process_init();
  unsigned char* caller = mi_malloc(64);
  if (caller == NULL) abort();
  memset(caller, 0x59, 64);
  mi_subproc_t* subproc = _mi_subproc_main();
  mi_heap_t* main = mi_heap_main();
  mi_theap_t* base = mi_theap_get_default();
  mi_theap_t* head = main->theaps;
  size_t live = mi_atomic_load_relaxed(&subproc->heap_count);
  size_t total = mi_atomic_load_relaxed(&subproc->heap_total_count);
  size_t clients = key_main_clients(main);
  key_observe(0, mi_thread_locals_free == NULL && mi_thread_locals_version == 0);
  key_bitmap_expected_size = mi_bitmap_size(1024, NULL);
  for (size_t attempt = 0; attempt < 2; attempt++) {
    key_bitmap_refuse = true;
    mi_heap_t* failed = mi_heap_new();
    key_bitmap_refuse = false;
    if (key_bitmap_refusals != attempt + 1) abort();
    size_t first = 1 + attempt * 6;
    key_observe(first, failed == NULL);
    key_observe(first + 1, mi_atomic_load_relaxed(&subproc->heap_count) == live &&
                 mi_atomic_load_relaxed(&subproc->heap_total_count) == total);
    key_observe(first + 2, mi_thread_locals_free == NULL && mi_thread_locals_version == 0);
    key_observe(first + 3, key_main_clients(main) == clients);
    key_observe(first + 4, mi_theap_get_default() == base && main->theaps == head);
    key_observe(first + 5, key_intact(caller));
  }
  mi_heap_t* retry = mi_heap_new();
  if (retry == NULL) abort();
  key_observe(13, mi_atomic_load_relaxed(&subproc->heap_count) == live + 1 &&
              mi_atomic_load_relaxed(&subproc->heap_total_count) == total + 1 && retry->theaps == NULL);
  key_observe(14, mi_key_index(retry->theap) == 0 && mi_key_version(retry->theap) == 1);
  key_observe(15, key_intact(caller));
  mi_heap_destroy(retry);
  key_observe(16, mi_atomic_load_relaxed(&subproc->heap_count) == live &&
              mi_atomic_load_relaxed(&subproc->heap_total_count) == total + 1);
  mi_bitmap_t* bitmap = mi_thread_locals_free;
  mi_heap_t* reused = mi_heap_new();
  if (reused == NULL) abort();
  key_observe(17, mi_key_index(reused->theap) == 0 && mi_key_version(reused->theap) == 2 && reused->theaps == NULL);
  mi_heap_destroy(reused);
  key_observe(18, mi_atomic_load_relaxed(&subproc->heap_count) == live &&
              mi_atomic_load_relaxed(&subproc->heap_total_count) == total + 2 &&
              mi_thread_locals_free == bitmap);
  key_observe(19, mi_theap_get_default() == base && main->theaps == head && key_intact(caller));
  size_t capacity = mi_bitmap_max_bits(mi_thread_locals_free);
  mi_heap_t** owned = calloc(capacity, sizeof(*owned));
  if (owned == NULL || capacity != 1024) abort();
  for (size_t i = 0; i < capacity; i++) {
    owned[i] = mi_heap_new();
    if (owned[i] == NULL || mi_key_index(owned[i]->theap) != i) abort();
  }
  unsigned char* owned_client = mi_heap_malloc(owned[0], 64);
  if (owned_client == NULL) abort();
  memset(owned_client, 0x59, 64);
  mi_theap_t* owned_theap = mi_heap_theap(owned[0]);
  size_t expansion_live = mi_atomic_load_relaxed(&subproc->heap_count);
  size_t expansion_total = mi_atomic_load_relaxed(&subproc->heap_total_count);
  size_t expansion_version = mi_thread_locals_version;
  bitmap = mi_thread_locals_free;
  clients = key_main_clients(main);
  key_observe(20, expansion_live == live + capacity && expansion_total == total + 2 + capacity);
  key_bitmap_expected_size = mi_bitmap_size(capacity + 1024, NULL);
  key_bitmap_refuse = true;
  mi_heap_t* failed = mi_heap_new();
  key_bitmap_refuse = false;
  if (key_bitmap_refusals != 3) abort();
  key_observe(21, failed == NULL);
  key_observe(22, mi_atomic_load_relaxed(&subproc->heap_count) == expansion_live &&
              mi_atomic_load_relaxed(&subproc->heap_total_count) == expansion_total);
  key_observe(23, mi_thread_locals_free == bitmap && mi_thread_locals_version == expansion_version);
  key_observe(24, key_main_clients(main) == clients && key_intact(caller));
  key_observe(25, mi_heap_of(owned_client) == owned[0] && key_intact(owned_client) &&
              mi_heap_theap(owned[0]) == owned_theap);
  mi_heap_t* expanded = mi_heap_new();
  if (expanded == NULL) abort();
  key_observe(26, mi_key_index(expanded->theap) == capacity &&
              mi_key_version(expanded->theap) == expansion_version + 1 &&
              mi_atomic_load_relaxed(&subproc->heap_count) == expansion_live + 1);
  bool retained_keys = true;
  for (size_t i = 0; i < capacity; i++) {
    if (mi_key_index(owned[i]->theap) != i || mi_key_version(owned[i]->theap) != 3 + i) retained_keys = false;
  }
  key_observe(27, retained_keys && mi_thread_locals_free != bitmap);
  key_observe(28, key_intact(caller) && key_intact(owned_client) && mi_heap_theap(owned[0]) == owned_theap);
  mi_heap_destroy(expanded);
  key_observe(29, mi_atomic_load_relaxed(&subproc->heap_count) == expansion_live);
  mi_free(owned_client);
  for (size_t i = 0; i < capacity; i++) mi_heap_destroy(owned[i]);
  mi_heap_theap(main);
  key_observe(30, mi_atomic_load_relaxed(&subproc->heap_count) == live &&
              mi_atomic_load_relaxed(&subproc->heap_total_count) == expansion_total + 1);
  key_observe(31, mi_theap_get_default() == base && main->theaps == head && key_intact(caller));
  free(owned);
  mi_free(caller);
  return 0;
}
#else
#include "static.c"
#include <pthread.h>
#include <stdatomic.h>
#include <time.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static void require(bool condition);
static size_t list_length(mi_subproc_t* subproc);

typedef struct {
  void* area;
  size_t size;
  size_t refused;
  bool refuse;
} heap_fault_state_t;

static bool heap_fault_commit(bool commit, void* start, size_t size,
                              bool* zero, void* argument) {
  heap_fault_state_t* state = argument;
  require((uintptr_t)start >= (uintptr_t)state->area &&
          size <= state->size &&
          (uintptr_t)start - (uintptr_t)state->area <= state->size - size);
  if (!commit) return false;
  if (state->refuse) { state->refused++; return false; }
  require(mprotect(start, size, PROT_READ | PROT_WRITE) == 0);
  if (zero != NULL) *zero = false;
  return true;
}

static void require(bool condition) { if (!condition) abort(); }

static bool heap_fault_count_page(const mi_heap_t* heap, const mi_heap_area_t* area,
                                 void* block, size_t size, void* argument) {
  (void)heap; (void)area; (void)block; (void)size;
  (*(size_t*)argument)++;
  return true;
}

static void heap_faults(bool image_failure) {
  mi_option_set(mi_option_arena_reserve, 0);
  mi_option_set(mi_option_purge_delay, 0);
  const size_t size = mi_arena_min_size();
  const size_t alignment = mi_arena_min_alignment();
  void* raw = mmap(NULL, size + alignment, PROT_NONE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  require(raw != MAP_FAILED);
  const uintptr_t start = ((uintptr_t)raw + alignment - 1) & ~(alignment - 1);
  const size_t prefix = start - (uintptr_t)raw;
  if (prefix != 0) require(munmap(raw, prefix) == 0);
  require(munmap((void*)(start + size), alignment - prefix) == 0);
  heap_fault_state_t state = {(void*)start, size, 0, false};
  mi_arena_id_t arena = NULL;
  require(mi_manage_memory(state.area, size, false, false, true,
                           -1, !image_failure, heap_fault_commit, &state, &arena));
  if (image_failure) {
    mi_option_set(mi_option_limit_os_alloc, 1);
    mi_theap_t* base = mi_theap_get_default();
    void* caller = mi_malloc(64);
    require(caller != NULL);
    memset(caller, 0x59, 64);
    const size_t count = list_length(_mi_subproc());
    state.refuse = true;
    for (size_t attempt = 0; attempt < 2; attempt++) {
      size_t before = state.refused;
      mi_heap_t* failed = mi_heap_new();
      printf("m6.heap.image_fault.%zu=%d\n", attempt * 3, failed == NULL);
      printf("m6.heap.image_fault.%zu=%d\n", attempt * 3 + 1, state.refused > before);
      printf("m6.heap.image_fault.%zu=%d\n", attempt * 3 + 2, list_length(_mi_subproc()) == count);
    }
    state.refuse = false;
    mi_heap_t* retry = mi_heap_new();
    require(retry != NULL);
    printf("m6.heap.image_fault.6=%d\n", list_length(_mi_subproc()) == count + 1);
    printf("m6.heap.image_fault.7=%d\n", mi_theap_get_default() == base);
    printf("m6.heap.image_fault.8=%d\n", ((unsigned char*)caller)[0] == 0x59 && mi_heap_of(caller) == mi_heap_main());
    mi_heap_destroy(retry);
    printf("m6.heap.image_fault.9=%d\n", list_length(_mi_subproc()) == count);
    printf("m6.heap.image_fault.10=%d\n", ((unsigned char*)caller)[0] == 0x59);
    unsigned char resident;
    printf("m6.heap.image_fault.11=%d\n", mincore(state.area, 4096, &resident) == 0);
    mi_free(caller);
    fflush(stdout);
    _exit(0);
  }
  mi_heap_t* heap = mi_heap_new_in_arena(arena);
  require(heap != NULL);
  mi_theap_t* base = mi_theap_get_default();
  void* caller = mi_malloc(64);
  require(caller != NULL);
  memset(caller, 0x59, 64);
  state.refuse = true;
  for (size_t attempt = 0; attempt < 2; attempt++) {
    size_t before = state.refused;
    void* failed = mi_heap_malloc(heap, 64);
    printf("m6.heap.fault.%zu=%d\n", attempt * 3, failed == NULL);
    printf("m6.heap.fault.%zu=%d\n", attempt * 3 + 1, state.refused > before);
    require(heap->theaps == NULL && _mi_thread_local_get(heap->theap) == NULL);
    size_t pages = 0;
    require(mi_heap_visit_blocks(heap, false, heap_fault_count_page, &pages));
    printf("m6.heap.fault.%zu=%d\n", attempt * 3 + 2, pages == 0);
  }
  require(mi_theap_get_default() == base && ((unsigned char*)caller)[0] == 0x59);
  state.refuse = false;
  void* first = mi_heap_malloc(heap, 64);
  require(first != NULL);
  memset(first, 0x6b, 64);
  mi_theap_t* selected = mi_heap_theap(heap);
  printf("m6.heap.fault.6=%d\n", mi_heap_of(first) == heap);
  printf("m6.heap.fault.7=%d\n", (uintptr_t)first >= start && (uintptr_t)first < start + size);
  require(selected == heap->theaps && selected->hnext == NULL);
  printf("m6.heap.fault.8=%d\n", selected != base && selected == mi_heap_theap(heap));
  state.refuse = true;
  size_t before = state.refused;
  void* failed = mi_heap_malloc(heap, 589824);
  size_t retained_pages = 0;
  require(mi_heap_visit_blocks(heap, false, heap_fault_count_page, &retained_pages));
  require(retained_pages == 1);
  printf("m6.heap.fault.9=%d\n", failed == NULL && state.refused > before);
  require(heap->theaps == selected && selected->hnext == NULL);
  printf("m6.heap.fault.10=%d\n", mi_heap_theap(heap) == selected);
  printf("m6.heap.fault.11=%d\n", ((unsigned char*)first)[0] == 0x6b && mi_heap_of(first) == heap);
  state.refuse = false;
  void* retry = mi_heap_malloc(heap, 589824);
  retained_pages = 0;
  require(mi_heap_visit_blocks(heap, false, heap_fault_count_page, &retained_pages));
  require(retained_pages == 2);
  printf("m6.heap.fault.12=%d\n", retry != NULL && mi_heap_of(retry) == heap);
  printf("m6.heap.fault.13=%d\n", mi_heap_theap(heap) == selected && mi_theap_get_default() == base);
  mi_free(first);
  mi_free(retry);
  mi_heap_destroy(heap);
  printf("m6.heap.fault.14=%d\n", ((unsigned char*)caller)[0] == 0x59 && mi_heap_of(caller) == mi_heap_main());
  unsigned char resident;
  printf("m6.heap.fault.15=%d\n", mincore(state.area, 4096, &resident) == 0);
  mi_free(caller);
  /* The registered arena retains the callback and its caller-owned mapping
     until process exit; no allocator operation has the caller's unmap right. */
  fflush(stdout);
  _exit(0);
}

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

typedef struct {
  mi_subproc_t* subproc;
  mi_heap_t* heap;
  unsigned char* client;
  bool destroy;
  pthread_barrier_t ready;
  pthread_barrier_t owner_go;
  pthread_barrier_t owner_done;
  pthread_barrier_t release_go;
  _Atomic(bool) complete;
  size_t before_total;
  size_t observed[5];
  size_t visited;
} heap_lock_state_t;

static void heap_lock_barrier(pthread_barrier_t* barrier) {
  int result = pthread_barrier_wait(barrier);
  require(result == 0 || result == PTHREAD_BARRIER_SERIAL_THREAD);
}

static void* heap_lock_owner(void* argument) {
  heap_lock_state_t* state = argument;
  mi_subproc_add_current_thread(_mi_subproc_to_id(state->subproc));
  state->heap = mi_heap_new();
  require(state->heap != NULL);
  state->client = mi_heap_malloc(state->heap, 64);
  require(state->client != NULL);
  memset(state->client, 0x6b, 64);
  heap_lock_barrier(&state->ready);
  heap_lock_barrier(&state->owner_go);
  mi_thread_done();
  heap_lock_barrier(&state->owner_done);
  return NULL;
}

static void* heap_lock_release(void* argument) {
  heap_lock_state_t* state = argument;
  mi_subproc_add_current_thread(_mi_subproc_to_id(state->subproc));
  heap_lock_barrier(&state->release_go);
  if (state->destroy) mi_heap_destroy(state->heap);
  else mi_heap_delete(state->heap);
  atomic_store_explicit(&state->complete, true, memory_order_release);
  mi_thread_done();
  return NULL;
}

static bool heap_lock_visitor(mi_heap_t* heap, void* argument) {
  heap_lock_state_t* state = argument;
  state->visited++;
  if (heap == state->heap) {
    heap_lock_barrier(&state->owner_go);
    heap_lock_barrier(&state->owner_done);
    state->observed[0] = 1;
    state->observed[1] = mi_atomic_load_relaxed(&state->subproc->heap_count);
    heap_lock_barrier(&state->release_go);
    /* The source count decrement precedes the locked unlink. Waiting for it
       establishes real release progress while this visitor retains the list. */
    struct timespec start, now;
    require(clock_gettime(CLOCK_MONOTONIC, &start) == 0);
    while (mi_atomic_load_relaxed(&state->subproc->heap_count) != 1) {
      require(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
      require(now.tv_sec - start.tv_sec < 10);
      sched_yield();
    }
    state->observed[2] = mi_atomic_load_relaxed(&state->subproc->heap_count);
    state->observed[3] = mi_atomic_load_relaxed(&state->subproc->heap_total_count) - state->before_total;
    state->observed[4] = atomic_load_explicit(&state->complete, memory_order_acquire);
  }
  return true;
}

static void heap_lock_controls(void) {
  unsigned char* caller = mi_malloc(64);
  require(caller != NULL);
  memset(caller, 0x59, 64);
  for (size_t case_index = 0; case_index < 4; case_index++) {
    bool child = case_index >= 2;
    mi_subproc_t* subproc = child ? _mi_subproc_from_id(mi_subproc_new()) : _mi_subproc_main();
    require(subproc != NULL);
    size_t baseline_total = mi_atomic_load_relaxed(&subproc->heap_total_count);
    heap_lock_state_t state = {.subproc = subproc, .destroy = (case_index % 2 != 0)};
    require(pthread_barrier_init(&state.ready, NULL, 2) == 0);
    require(pthread_barrier_init(&state.owner_go, NULL, 2) == 0);
    require(pthread_barrier_init(&state.owner_done, NULL, 2) == 0);
    require(pthread_barrier_init(&state.release_go, NULL, 2) == 0);
    pthread_t owner, releaser;
    require(pthread_create(&owner, NULL, heap_lock_owner, &state) == 0);
    heap_lock_barrier(&state.ready);
    state.before_total = mi_atomic_load_relaxed(&subproc->heap_total_count);
    size_t values[16] = {child, state.destroy,
      mi_atomic_load_relaxed(&subproc->heap_count), state.before_total - baseline_total};
    require(values[2] == 2 && values[3] == 1);
    require(pthread_create(&releaser, NULL, heap_lock_release, &state) == 0);
    bool visited = mi_subproc_visit_heaps(_mi_subproc_to_id(subproc), heap_lock_visitor, &state);
    for (size_t i = 0; i < 5; i++) values[4 + i] = state.observed[i];
    values[9] = state.visited;
    values[10] = visited;
    require(pthread_join(owner, NULL) == 0);
    require(pthread_join(releaser, NULL) == 0);
    require(atomic_load_explicit(&state.complete, memory_order_acquire));
    values[11] = mi_atomic_load_relaxed(&subproc->heap_count);
    values[12] = list_length(subproc);
    mi_heap_t* expected[] = {subproc->heap_main};
    values[13] = list_is(subproc, expected, 1);
    require(values[11] == 1 && values[12] == 1 && values[13]);
    require(mi_atomic_load_relaxed(&subproc->heap_total_count) == state.before_total);
    if (!state.destroy) {
      values[14] = mi_heap_of(state.client) == subproc->heap_main;
      for (size_t i = 0; i < 64; i++) values[14] &= state.client[i] == 0x6b;
      require(values[14]);
      mi_free(state.client);
    }
    values[15] = 1;
    for (size_t i = 0; i < 64; i++) values[15] &= caller[i] == 0x59;
    require(values[15]);
    for (size_t i = 0; i < 16; i++) printf("m6.heap.lock.%zu=%zu\n", case_index * 16 + i, values[i]);
    require(pthread_barrier_destroy(&state.ready) == 0);
    require(pthread_barrier_destroy(&state.owner_go) == 0);
    require(pthread_barrier_destroy(&state.owner_done) == 0);
    require(pthread_barrier_destroy(&state.release_go) == 0);
    if (child) mi_subproc_destroy(_mi_subproc_to_id(subproc));
  }
  mi_free(caller);
}

typedef struct {
  mi_subproc_t* subproc;
  mi_heap_t* heap;
  unsigned char* client;
  pthread_barrier_t attached;
  pthread_barrier_t birth_go;
  pthread_barrier_t born;
  pthread_barrier_t finish_go;
  pthread_barrier_t finished;
  _Atomic(bool) returned;
  size_t baseline_total;
  size_t counters[3];
  size_t visited;
} heap_birth_state_t;

static void* heap_birth_worker(void* argument) {
  heap_birth_state_t* state = argument;
  mi_subproc_add_current_thread(_mi_subproc_to_id(state->subproc));
  heap_lock_barrier(&state->attached);
  heap_lock_barrier(&state->birth_go);
  state->heap = mi_heap_new();
  require(state->heap != NULL);
  atomic_store_explicit(&state->returned, true, memory_order_release);
  state->client = mi_heap_malloc(state->heap, 64);
  require(state->client != NULL);
  memset(state->client, 0x6b, 64);
  heap_lock_barrier(&state->born);
  heap_lock_barrier(&state->finish_go);
  mi_thread_done();
  heap_lock_barrier(&state->finished);
  return NULL;
}

static bool heap_birth_visitor(mi_heap_t* heap, void* argument) {
  heap_birth_state_t* state = argument;
  require(heap == state->subproc->heap_main);
  state->visited++;
  heap_lock_barrier(&state->birth_go);
  /* Sequence reservation precedes the locked list push. Observing it proves
     factory progress without inspecting the unpublished Heap image. */
  struct timespec start, now;
  require(clock_gettime(CLOCK_MONOTONIC, &start) == 0);
  while (mi_atomic_load_relaxed(&state->subproc->heap_total_count) != state->baseline_total + 1) {
    require(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
    require(now.tv_sec - start.tv_sec < 10);
    sched_yield();
  }
  state->counters[0] = mi_atomic_load_relaxed(&state->subproc->heap_total_count) - state->baseline_total;
  state->counters[1] = mi_atomic_load_relaxed(&state->subproc->heap_count);
  state->counters[2] = atomic_load_explicit(&state->returned, memory_order_acquire);
  return true;
}

static void heap_birth_controls(void) {
  unsigned char* caller = mi_malloc(64);
  require(caller != NULL);
  memset(caller, 0x59, 64);
  for (size_t case_index = 0; case_index < 2; case_index++) {
    bool child = case_index != 0;
    mi_subproc_t* subproc = child ? _mi_subproc_from_id(mi_subproc_new()) : _mi_subproc_main();
    require(subproc != NULL);
    heap_birth_state_t state = {.subproc = subproc,
      .baseline_total = mi_atomic_load_relaxed(&subproc->heap_total_count)};
    require(pthread_barrier_init(&state.attached, NULL, 2) == 0);
    require(pthread_barrier_init(&state.birth_go, NULL, 2) == 0);
    require(pthread_barrier_init(&state.born, NULL, 2) == 0);
    require(pthread_barrier_init(&state.finish_go, NULL, 2) == 0);
    require(pthread_barrier_init(&state.finished, NULL, 2) == 0);
    size_t values[20] = {child, mi_atomic_load_relaxed(&subproc->heap_count)};
    require(values[1] == 1);
    pthread_t worker;
    require(pthread_create(&worker, NULL, heap_birth_worker, &state) == 0);
    heap_lock_barrier(&state.attached);
    bool visit_ok = mi_subproc_visit_heaps(_mi_subproc_to_id(subproc), heap_birth_visitor, &state);
    for (size_t i = 0; i < 3; i++) values[2 + i] = state.counters[i];
    values[5] = state.visited;
    values[6] = visit_ok;
    require(values[2] == 1 && values[3] == 1 && values[4] == 0 && values[5] == 1 && visit_ok);
    heap_lock_barrier(&state.born);
    values[7] = atomic_load_explicit(&state.returned, memory_order_acquire);
    values[8] = mi_atomic_load_relaxed(&subproc->heap_count);
    values[9] = mi_atomic_load_relaxed(&subproc->heap_total_count) - state.baseline_total;
    values[10] = list_length(subproc);
    mi_heap_t* expected[] = {state.heap, subproc->heap_main};
    values[11] = list_is(subproc, expected, 2);
    values[12] = state.heap->heap_seq - state.baseline_total;
    values[13] = mi_heap_of(state.client) == state.heap;
    require(values[7] == 1 && values[8] == 2 && values[9] == 1 && values[10] == 2 &&
            values[11] && values[12] == 0 && values[13]);
    heap_lock_barrier(&state.finish_go);
    heap_lock_barrier(&state.finished);
    require(pthread_join(worker, NULL) == 0);
    values[14] = 1;
    values[15] = mi_heap_of(state.client) == state.heap;
    for (size_t i = 0; i < 64; i++) values[15] &= state.client[i] == 0x6b;
    require(values[15]);
    mi_heap_destroy(state.heap);
    values[16] = mi_atomic_load_relaxed(&subproc->heap_count);
    values[17] = mi_atomic_load_relaxed(&subproc->heap_total_count) - state.baseline_total;
    values[18] = list_length(subproc);
    mi_heap_t* final[] = {subproc->heap_main};
    require(values[16] == 1 && values[17] == 1 && values[18] == 1 && list_is(subproc, final, 1));
    values[19] = 1;
    for (size_t i = 0; i < 64; i++) values[19] &= caller[i] == 0x59;
    require(values[19]);
    for (size_t i = 0; i < 20; i++) printf("m6.heap.birth.%zu=%zu\n", case_index * 20 + i, values[i]);
    require(pthread_barrier_destroy(&state.attached) == 0);
    require(pthread_barrier_destroy(&state.birth_go) == 0);
    require(pthread_barrier_destroy(&state.born) == 0);
    require(pthread_barrier_destroy(&state.finish_go) == 0);
    require(pthread_barrier_destroy(&state.finished) == 0);
    if (child) mi_subproc_destroy(_mi_subproc_to_id(subproc));
  }
  mi_free(caller);
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
  if (argc > 1 && strcmp(argv[1], "birth") == 0) { heap_birth_controls(); return 0; }
  if (argc > 1 && strcmp(argv[1], "locks") == 0) { heap_lock_controls(); return 0; }
  if (argc > 1 && strcmp(argv[1], "faults") == 0) { heap_faults(false); }
  if (argc > 1 && strcmp(argv[1], "image-faults") == 0) { heap_faults(true); }
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
#endif
