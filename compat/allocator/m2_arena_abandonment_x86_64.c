/* Copyright (c) 2026 crabc contributors. SPDX-License-Identifier: MIT */
/* Pinned v3.5.0 arena page abandonment through the ordinary owner exit and
   foreign frees. A freeing worker keeps one live block in the medium bin, so
   `mi_abandoned_page_try_reclaim` never reclaims (src/free.c:440-475), and
   then runs an owner worker to its `mi_thread_done`.

   mapped: the owner leaves two of 42 blocks live; `_mi_arenas_page_abandon`
   maps the page (src/arena.c:1316-1337). The first foreign free unowns it
   again; the last one reaches `mi_abandoned_page_try_free`, which unabandons
   and frees the page (src/arena.c:1384-1409, 1216-1302).

   full: the owner's 42nd allocation fills the page, which the generic
   allocation path abandons at once (src/page.c:1076-1079, 374-389); the full
   page stays unmapped (src/arena.c:1339-1354). Five foreign frees keep it
   mostly used; the sixth
   reabandons it to the mapped bitmap (src/arena.c:1359-1382), and the last
   free unabandons and frees it.

   os: the owner leaves one 32-MiB-aligned singleton, which the OS backs
   (src/arena.c:796-866); its abandonment enters `heap->os_abandoned_pages`
   (src/arena.c:1343-1352) and the foreign free unlinks and frees it
   (src/arena.c:1410-1421).

   `crabc-mimalloc/tests/native_arena_abandonment.rs` prints the same fields. */
#include "static.c"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

#define REQUEST 10248
#define BLOCKS 42
#define OS_REQUEST 7
#define OS_ALIGNMENT (32 * 1024 * 1024)

#define require(condition) \
  do { if (!(condition)) { fprintf(stderr, "m2_arena_abandonment_x86_64.c:%d: %s\n", __LINE__, #condition); abort(); } } while (0)

typedef struct span_s {
  mi_arena_t* arena;
  mi_arena_pages_t* pages;
  size_t slice;
  size_t count;
  size_t bin;
} span_t;

static span_t span_of(void* block) {
  mi_page_t* const page = _mi_ptr_page(block);
  require(page != NULL && page->memid.memkind == MI_MEM_ARENA);
  span_t span;
  span.arena = page->memid.mem.arena.arena;
  span.slice = page->memid.mem.arena.slice_index;
  span.count = page->memid.mem.arena.slice_count;
  span.bin = _mi_bin(mi_page_block_size(page));
  span.pages = mi_atomic_load_ptr_acquire(mi_arena_pages_t,
      &mi_page_heap(page)->arena_pages[span.arena->arena_idx]);
  require(span.pages != NULL);
  return span;
}

static void emit(const char* name, const char* field, long long value) {
  printf("m2.arena_abandon.%s.%s=%lld\n", name, field, value);
}

static void emit_span(const char* name, const span_t* span) {
  size_t free_slices = 0, committed = 0, purge = 0;
  for (size_t i = span->slice; i < span->slice + span->count; i++) {
    free_slices += mi_bbitmap_is_setN(span->arena->slices_free, i, 1);
    committed += mi_bitmap_is_setN(span->arena->slices_committed, i, 1);
    purge += mi_bitmap_is_setN(span->arena->slices_purge, i, 1);
  }
  emit(name, "page", mi_bitmap_is_setN(span->pages->pages, span->slice, 1));
  emit(name, "abandoned", mi_bitmap_is_setN(span->pages->pages_abandoned[span->bin], span->slice, 1));
  emit(name, "free", (long long)free_slices);
  emit(name, "committed", (long long)committed);
  emit(name, "purge", (long long)purge);
}

static void emit_live(const char* name, const span_t* span, void* live) {
  emit_span(name, span);
  emit(name, "reclaimed", mi_page_thread_id(_mi_ptr_page(live)) == _mi_thread_id());
}

typedef struct owner_s { size_t count; size_t alignment; void* blocks[BLOCKS]; size_t reserved; size_t block_size; } owner_t;

static void* owner(void* argument) {
  owner_t* const state = argument;
  mi_thread_init();
  for (size_t i = 0; i < state->count; i++) {
    state->blocks[i] = state->alignment == 0 ? mi_malloc(REQUEST) : mi_malloc_aligned(OS_REQUEST, state->alignment);
    require(state->blocks[i] != NULL && _mi_ptr_page(state->blocks[i]) == _mi_ptr_page(state->blocks[0]));
  }
  mi_page_t* const page = _mi_ptr_page(state->blocks[0]);
  state->reserved = page->reserved;
  state->block_size = mi_page_block_size(page);
  mi_thread_done();
  return NULL;
}

static void run_owner(owner_t* state) {
  pthread_t thread;
  require(pthread_create(&thread, NULL, owner, state) == 0);
  require(pthread_join(thread, NULL) == 0);
}

static void* freer(void* unused) {
  (void)unused;
  mi_thread_init();
  void* const own = mi_malloc(REQUEST);
  require(own != NULL);

  owner_t mapped = { .count = 2 };
  run_owner(&mapped);
  span_t span = span_of(mapped.blocks[0]);
  emit("mapped", "reserved", (long long)mapped.reserved);
  emit("mapped", "block_size", (long long)mapped.block_size);
  emit("mapped", "slices", (long long)span.count);
  emit_live("mapped.exit", &span, mapped.blocks[0]);
  mi_free(mapped.blocks[1]);
  emit_live("mapped.first", &span, mapped.blocks[0]);
  mi_free(mapped.blocks[0]);
  emit_span("mapped.last", &span);

  owner_t full = { .count = BLOCKS };
  run_owner(&full);
  require(full.reserved == BLOCKS);
  span = span_of(full.blocks[0]);
  emit_live("full.exit", &span, full.blocks[0]);
  static const char* const steps[] = { "full.free1", "full.free2", "full.free3", "full.free4", "full.free5", "full.free6", "full.free7" };
  for (size_t i = 0; i < 7; i++) {
    mi_free(full.blocks[BLOCKS - 1 - i]);
    emit_live(steps[i], &span, full.blocks[0]);
  }
  for (size_t i = 7; i < BLOCKS - 1; i++) mi_free(full.blocks[BLOCKS - 1 - i]);
  emit_live("full.penultimate", &span, full.blocks[0]);
  mi_free(full.blocks[0]);
  emit_span("full.last", &span);

  owner_t os = { .count = 1, .alignment = OS_ALIGNMENT };
  run_owner(&os);
  mi_page_t* const os_page = _mi_ptr_page(os.blocks[0]);
  mi_heap_t* const heap = mi_page_heap(os_page);
  emit("os", "arena", os_page->memid.memkind == MI_MEM_ARENA);
  emit("os.exit", "listed", heap->os_abandoned_pages != NULL);
  emit("os.exit", "reclaimed", mi_page_thread_id(os_page) == _mi_thread_id());
  mi_free(os.blocks[0]);
  emit("os.last", "listed", heap->os_abandoned_pages != NULL);

  mi_free(own);
  mi_thread_done();
  return NULL;
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  /* The suppressed process constructor's entry ends the preloading interval
     before `mi_process_init` (src/init.c:493-512), as in a loaded program. */
  _mi_auto_process_init();
  pthread_t thread;
  require(pthread_create(&thread, NULL, freer, NULL) == 0);
  require(pthread_join(thread, NULL) == 0);
  return 0;
}
