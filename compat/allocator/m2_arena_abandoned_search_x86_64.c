/* Copyright (c) 2026 crabc contributors. SPDX-License-Identifier: MIT */
/* Pinned `mi_arenas_page_try_find_abandoned` (src/arena.c:725-779) across
   three reserved arenas and two non-main heaps. An owner thread fills one
   heap's medium pages across all three arenas, frees every sixteenth block
   and exits, so each partly used page is abandoned to that heap's own
   `arena_pages` record (src/arena.c:1316-1337). A second owner abandons one
   page of the other heap. The main heap then allocates without reclaiming:
   its `abandoned_count` is zero (src/arena.c:739-742). Allocations from the
   owning heap on fresh threads
   reclaim in `mi_forall_suitable_arenas` order (src/arena.c:454-490), whose
   start `mi_arena_start_idx` takes from the heap sequence and the live heap
   count (src/arena.c:429-452): five sibling heaps move it from the middle
   arena to the first, and releasing them moves it back. A last thread
   drains every abandoned page in that order until a fresh page is needed,
   leaving the other heap's page in its own record for that heap to reclaim.
   `crabc-mimalloc/tests/native_arena_abandoned_search.rs` prints the same
   fields. */
#include "static.c"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

#define ARENA_SIZE (64 * 1024 * 1024)
#define REQUEST (32 * 1024)
#define CLIENTS 4096
#define STRIDE 16
#define FREED (CLIENTS / STRIDE)
#define SIBLINGS 5
#define PAGE_BLOCKS 16

#define require(condition) \
  do { if (!(condition)) { fprintf(stderr, "m2_arena_abandoned_search_x86_64.c:%d: %s\n", __LINE__, #condition); abort(); } } while (0)

static mi_arena_id_t arenas[3];
static mi_heap_t* heap;
static mi_heap_t* other;
static void* clients[CLIENTS];
static void* freed[FREED];
static void* drained[FREED];
static void* other_clients[PAGE_BLOCKS];

static void emit(const char* name, long long value) {
  printf("m2.arena_abandoned_search.%s=%lld\n", name, value);
}

static long long arena_of(const void* block) {
  for (int i = 0; i < 3; i++) {
    if (mi_arena_contains(arenas[i], block)) return i;
  }
  return -1;
}

static long long take_freed(const void* block) {
  for (size_t i = 0; i < FREED; i++) {
    if (freed[i] != NULL && freed[i] == block) {
      freed[i] = NULL;
      return 1;
    }
  }
  return 0;
}

static void* owner(void* unused) {
  (void)unused;
  mi_thread_init();
  for (size_t i = 0; i < CLIENTS; i++) {
    clients[i] = mi_heap_malloc(heap, REQUEST);
    require(clients[i] != NULL);
  }
  for (size_t i = 0; i < CLIENTS; i += STRIDE) {
    freed[i / STRIDE] = clients[i];
    mi_free(clients[i]);
    clients[i] = NULL;
  }
  mi_thread_done();
  return NULL;
}

static void* other_owner(void* unused) {
  (void)unused;
  mi_thread_init();
  for (size_t i = 0; i < PAGE_BLOCKS; i++) {
    other_clients[i] = mi_heap_malloc(other, REQUEST);
    require(other_clients[i] != NULL);
  }
  mi_free(other_clients[0]);
  mi_thread_done();
  return NULL;
}

typedef struct probe_s { mi_heap_t* heap; void* block; } probe_t;

static void* allocate_once(void* argument) {
  probe_t* const probe = argument;
  mi_thread_init();
  probe->block = probe->heap == NULL ? mi_malloc(REQUEST) : mi_heap_malloc(probe->heap, REQUEST);
  require(probe->block != NULL);
  mi_thread_done();
  return NULL;
}

static void* run_probe(mi_heap_t* target) {
  probe_t probe = { target, NULL };
  pthread_t thread;
  require(pthread_create(&thread, NULL, allocate_once, &probe) == 0);
  require(pthread_join(thread, NULL) == 0);
  return probe.block;
}

static void* step(const char* name) {
  void* const block = run_probe(heap);
  char field[64];
  snprintf(field, sizeof(field), "%s.reclaimed", name);
  emit(field, take_freed(block));
  snprintf(field, sizeof(field), "%s.arena", name);
  emit(field, arena_of(block));
  return block;
}

typedef struct drain_s { size_t count; void* fresh; long long arenas[FREED]; } drain_t;

static void* drain(void* argument) {
  drain_t* const state = argument;
  mi_thread_init();
  for (;;) {
    void* const block = mi_heap_malloc(heap, REQUEST);
    require(block != NULL);
    if (!take_freed(block)) {
      state->fresh = block;
      break;
    }
    require(state->count < FREED);
    state->arenas[state->count] = arena_of(block);
    drained[state->count++] = block;
  }
  mi_thread_done();
  return NULL;
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  /* The suppressed process constructor's entry ends the preloading interval
     before `mi_process_init` (src/init.c:493-512), as in a loaded program. */
  _mi_auto_process_init();
  for (int i = 0; i < 3; i++) {
    require(mi_reserve_os_memory_ex(ARENA_SIZE, true, false, false, &arenas[i]) == 0);
  }
  other = mi_heap_new();
  heap = mi_heap_new();
  require(other != NULL && heap != NULL);

  pthread_t thread;
  require(pthread_create(&thread, NULL, owner, NULL) == 0);
  require(pthread_join(thread, NULL) == 0);
  long long placement[3] = { 0, 0, 0 };
  for (size_t i = 0; i < FREED; i++) {
    const long long arena = arena_of(freed[i]);
    require(arena >= 0);
    placement[arena]++;
  }
  emit("registry", (long long)mi_arenas_get_count(_mi_subproc_main()));
  emit("placement.0", placement[0]);
  emit("placement.1", placement[1]);
  emit("placement.2", placement[2]);

  require(pthread_create(&thread, NULL, other_owner, NULL) == 0);
  require(pthread_join(thread, NULL) == 0);
  void* const other_freed = other_clients[0];
  other_clients[0] = NULL;
  emit("other.placement", arena_of(other_freed));
  void* const main_block = run_probe(NULL);
  emit("main.reclaimed", take_freed(main_block));

  void* steps[3];
  steps[0] = step("first");
  mi_heap_t* siblings[SIBLINGS];
  for (int i = 0; i < SIBLINGS; i++) {
    siblings[i] = mi_heap_new();
    require(siblings[i] != NULL);
  }
  steps[1] = step("siblings");
  for (int i = 0; i < SIBLINGS; i++) mi_heap_delete(siblings[i]);
  steps[2] = step("released");

  drain_t state = { 0 };
  require(pthread_create(&thread, NULL, drain, &state) == 0);
  require(pthread_join(thread, NULL) == 0);
  size_t segments = 0;
  for (size_t i = 0; i < state.count; i++) {
    if (i == 0 || state.arenas[i] != state.arenas[i - 1]) {
      char field[64];
      snprintf(field, sizeof(field), "drain.%zu.arena", segments);
      emit(field, state.arenas[i]);
      size_t run = 0;
      while (i + run < state.count && state.arenas[i + run] == state.arenas[i]) run++;
      snprintf(field, sizeof(field), "drain.%zu.count", segments);
      emit(field, (long long)run);
      segments++;
    }
  }
  emit("drain.segments", (long long)segments);
  emit("drain.fresh", state.fresh != NULL);
  size_t remaining = 0;
  for (size_t i = 0; i < FREED; i++) remaining += freed[i] != NULL;
  emit("drain.remaining", (long long)remaining);
  void* const foreign = run_probe(other);
  emit("other.reclaimed", foreign == other_freed);
  emit("other.arena", arena_of(foreign));

  mi_free(state.fresh);
  for (size_t i = 0; i < state.count; i++) mi_free(drained[i]);
  for (size_t i = 0; i < CLIENTS; i++) mi_free(clients[i]);
  for (size_t i = 0; i < PAGE_BLOCKS; i++) mi_free(other_clients[i]);
  for (int i = 0; i < 3; i++) mi_free(steps[i]);
  mi_free(foreign);
  mi_free(main_block);
  mi_heap_delete(heap);
  mi_heap_delete(other);
  return 0;
}
