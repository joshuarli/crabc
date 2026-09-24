/* Copyright (c) 2026 crabc contributors. SPDX-License-Identifier: MIT */
/* Pinned `mi_abandoned_page_try_reclaim` decisions on worker threads, with
   the default `page_reclaim_on_free = 0`. Each case uses its own size class
   and frees every block, so no abandoned page survives into the next case.
   `crabc-mimalloc/tests/native_reclaim_on_free.rs` prints the same fields. */
#include "static.c"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

#define MAX_BLOCKS 16384

#define require(condition) \
  do { if (!(condition)) { fprintf(stderr, "reclaim_on_free.c:%d: %s\n", __LINE__, #condition); abort(); } } while (0)

/* The freeing thread's view of the page of one of its still-live blocks. */
static void emit_page(const char* name, void* live) {
  mi_page_t* page = _mi_ptr_page(live);
  const bool reclaimed = mi_page_thread_id(page) == _mi_thread_id();
  size_t used = 0, queue_count = 0;
  if (reclaimed) {
    used = page->used;
    queue_count = _mi_theap_default()->pages[_mi_bin(mi_page_block_size(page))].count;
  }
  printf("reclaim.%s.reclaimed=%d\nreclaim.%s.used=%zu\nreclaim.%s.queue_count=%zu\n",
    name, reclaimed ? 1 : 0, name, used, name, queue_count);
}

/* own-full: the worker allocates until a search moves its first page to
   full (after `page_full_retain` newer full pages), which abandons it; the
   worker's own free then meets that page's originating Theap. */
static void* own_full(void* unused) {
  (void)unused;
  mi_thread_init();
  static void* blocks[MAX_BLOCKS];
  size_t count = 0;
  blocks[count++] = mi_malloc(64);
  mi_page_t* page = _mi_ptr_page(blocks[0]);
  while (!mi_page_is_abandoned(page)) {
    require(count < MAX_BLOCKS);
    blocks[count++] = mi_malloc(64);
  }
  require(_mi_ptr_page(blocks[1]) == page);
  mi_free(blocks[1]);
  emit_page("own_full", blocks[0]);
  while (count > 2) mi_free(blocks[--count]);
  mi_free(blocks[0]);
  mi_thread_done();
  return NULL;
}

/* A foreign owner allocates `count` blocks of `size` and exits. */
struct foreign { size_t size; size_t count; void* blocks[4]; };

static void* foreign_owner(void* argument) {
  struct foreign* foreign = argument;
  mi_thread_init();
  for (size_t i = 0; i < foreign->count; i++) foreign->blocks[i] = mi_malloc(foreign->size);
  mi_thread_done();
  return NULL;
}

struct freer { const char* name; size_t size; bool own_block_first; };

/* The freeing worker optionally owns one block of the same size class, runs
   the foreign owner to its exit, and then frees one of its three blocks. */
static void* foreign_freer(void* argument) {
  const struct freer* freer = argument;
  mi_thread_init();
  void* own = freer->own_block_first ? mi_malloc(freer->size) : NULL;
  struct foreign foreign = { freer->size, 3, { NULL } };
  pthread_t thread;
  require(pthread_create(&thread, NULL, foreign_owner, &foreign) == 0);
  require(pthread_join(thread, NULL) == 0);
  require(mi_page_is_abandoned(_mi_ptr_page(foreign.blocks[0])));
  mi_free(foreign.blocks[2]);
  emit_page(freer->name, foreign.blocks[0]);
  mi_free(foreign.blocks[1]);
  mi_free(foreign.blocks[0]);
  mi_free(own);
  mi_thread_done();
  return NULL;
}

/* crabc's libc attaches every pthread to the allocator before user code, as
   `mi_thread_init` does, so each worker below initializes its Theap first. */
static void run(void* (*worker)(void*), void* argument) {
  pthread_t thread;
  require(pthread_create(&thread, NULL, worker, argument) == 0);
  require(pthread_join(thread, NULL) == 0);
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  mi_process_init();
  run(own_full, NULL);
  struct freer empty = { "foreign_empty_queue", 80, false };
  run(foreign_freer, &empty);
  struct freer nonempty = { "foreign_nonempty_queue", 96, true };
  run(foreign_freer, &nonempty);
  struct freer large = { "foreign_large", 86699, false };
  run(foreign_freer, &large);
  return 0;
}
