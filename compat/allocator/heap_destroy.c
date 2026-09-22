/* Copyright (c) 2026 crabc contributors. SPDX-License-Identifier: MIT */
/* Pinned main-Heap Theap-list destruction after real process_done disabled
   the Unix automatic thread destructor. No arena/PageMap destruction claim. */
#include "static.c"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

static mi_tld_t* retained_tlds[3];
static void require(bool condition) { if (!condition) abort(); }

static void* retain_worker(void* argument) {
  const size_t index = (size_t)argument;
  mi_thread_init();
  mi_theap_t* theap = _mi_theap_default();
  require(mi_theap_is_initialized(theap));
  retained_tlds[index] = theap->tld;
  return NULL;
}

int main(void) {
  mi_process_init();
  mi_heap_t* heap = mi_process_subproc_main.heap_main;
  mi_process_done();
  for (size_t i = 0; i < 3; i++) {
    pthread_t thread;
    require(pthread_create(&thread, NULL, retain_worker, (void*)i) == 0);
    require(pthread_join(thread, NULL) == 0);
  }
  const size_t before_live = mi_atomic_load_relaxed(&mi_process_subproc_main.thread_count);
  size_t dynamic_members = 0;
  size_t total_members = 0;
  for (mi_theap_t* theap = heap->theaps; theap != NULL; theap = theap->hnext) {
    total_members++;
    if (theap->memid.memkind == MI_MEM_MALLOC) dynamic_members++;
  }
  size_t attached_tlds = 0;
  for (size_t i = 0; i < 3; i++) {
    if (retained_tlds[i]->theaps != NULL) attached_tlds++;
  }
  /* Source force-destroy's exact first phase, including every static and
     dynamic member. Main-Heap page destruction is a later no-op in source;
     statistics/Heap bookkeeping and subprocess destruction are not compared. */
  mi_heap_free_theaps(heap);
  size_t detached_tlds = 0;
  for (size_t i = 0; i < 3; i++) {
    if (retained_tlds[i]->theaps == NULL) detached_tlds++;
  }
  const size_t values[] = { before_live, dynamic_members, attached_tlds,
    heap->theaps == NULL, detached_tlds,
    mi_atomic_load_relaxed(&mi_process_subproc_main.thread_count), total_members };
  for (size_t i = 0; i < sizeof(values)/sizeof(values[0]); i++) {
    printf("m2.heap.destroy.%zu=%zu\n", i, values[i]);
  }
  return 0;
}
