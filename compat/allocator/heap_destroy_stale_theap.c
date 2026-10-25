/* Copyright (c) 2026 crabc contributors. SPDX-License-Identifier: MIT */
#include "mimalloc.h"
#include "mimalloc/internal.h"
#include "mimalloc/prim.h"
#include "static.c"
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t condition = PTHREAD_COND_INITIALIZER;
static mi_heap_t* old_heap;
static mi_heap_t* reused_heap;
static mi_theap_t* old_theap;
static bool ready;
static bool resume_worker;
static bool stop_worker;
static bool cache_changed;
static bool contains;

static void require(bool condition) {
  if (!condition) abort();
}

static void* worker(void* argument) {
  (void)argument;
  mi_thread_init();
  for (size_t i = 0; i < 2; i++) {
    void* block = mi_heap_malloc(old_heap, 64);
    require(block != NULL);
    mi_free(block);
  }
  old_theap = _mi_theap_cached();
  require(old_theap != NULL && old_theap->heap == old_heap);
  require(pthread_mutex_lock(&mutex) == 0);
  ready = true;
  require(pthread_cond_signal(&condition) == 0);
  while (!resume_worker) require(pthread_cond_wait(&condition, &mutex) == 0);
  bool stop = stop_worker;
  mi_heap_t* target = reused_heap;
  require(pthread_mutex_unlock(&mutex) == 0);
  if (!stop) {
    bool cached_old = (_mi_theap_cached() == old_theap);
    printf("m6.heap.stale.cached_old=%d\n", cached_old);
    void* block = mi_heap_malloc(target, 64);
    require(block != NULL);
    cache_changed = (_mi_theap_cached() != old_theap);
    printf("m6.heap.stale.cache_changed=%d\n", cache_changed);
    contains = mi_heap_contains(target, block);
    printf("m6.heap.stale.contains=%d\n", contains);
    if (!contains) return NULL;
    mi_free(block);
  }
  mi_thread_done();
  return NULL;
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  mi_process_init();
  old_heap = mi_heap_new();
  require(old_heap != NULL);
  uintptr_t old_address = (uintptr_t)old_heap;
  pthread_t thread;
  require(pthread_create(&thread, NULL, worker, NULL) == 0);
  require(pthread_mutex_lock(&mutex) == 0);
  while (!ready) require(pthread_cond_wait(&condition, &mutex) == 0);
  require(pthread_mutex_unlock(&mutex) == 0);
  mi_heap_destroy(old_heap);
  for (size_t attempt = 0; attempt < 64; attempt++) {
    mi_heap_t* candidate = mi_heap_new();
    require(candidate != NULL);
    if ((uintptr_t)candidate == old_address) {
      reused_heap = candidate;
      break;
    }
    mi_heap_destroy(candidate);
  }
  require(pthread_mutex_lock(&mutex) == 0);
  stop_worker = (reused_heap == NULL);
  bool reused = (reused_heap != NULL);
  printf("m6.heap.stale.reused=%d\n", reused);
  resume_worker = true;
  require(pthread_cond_signal(&condition) == 0);
  require(pthread_mutex_unlock(&mutex) == 0);
  require(pthread_join(thread, NULL) == 0);
  if (!reused) return 77;
  if (!contains) return 1;
  mi_heap_destroy(reused_heap);
  return contains && cache_changed ? 0 : 1;
}
