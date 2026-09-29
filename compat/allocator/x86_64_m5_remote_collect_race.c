/* Pinned-C live-owner publication/collection race on one small page. */
#define _POSIX_C_SOURCE 200809L
#include "mimalloc/internal.h"
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>

#if !defined(__linux__) || !defined(__x86_64__)
#error this private fixture requires native Linux/x86-64
#endif
#if MI_BUILD_RELEASE != 1 || MI_DEBUG != 0 || MI_STAT != 0 || MI_SECURE != 0 || MI_GUARDED != 0
#error this private fixture requires the pinned release profile
#endif

enum { PRODUCERS = 3 };
static pthread_barrier_t start;
static _Atomic unsigned completed;
static void* clients[PRODUCERS];

static void* producer(void* argument) {
  const size_t index = (size_t)argument;
  mi_thread_init();
  const int barrier = pthread_barrier_wait(&start);
  if (barrier != 0 && barrier != PTHREAD_BARRIER_SERIAL_THREAD) return (void*)1;
  mi_free(clients[index]);
  atomic_fetch_add_explicit(&completed, 1, memory_order_release);
  mi_thread_done();
  return NULL;
}

static int mark_clients_in_chain(mi_page_t* page, mi_block_t* head, unsigned seen[PRODUCERS]) {
  size_t visited = 0;
  while (head != NULL) {
    if (++visited > page->reserved) return 0;
    for (size_t i = 0; i < PRODUCERS; i++) {
      if (head == (mi_block_t*)clients[i]) seen[i]++;
    }
    head = mi_block_next(page, head);
  }
  return 1;
}

int main(void) {
  mi_thread_init();
  for (size_t i = 0; i < PRODUCERS; i++) {
    clients[i] = mi_malloc(64);
    if (clients[i] == NULL) return 2;
  }
  mi_page_t* page = _mi_ptr_page(clients[0]);
  if (page == NULL || page->used != PRODUCERS || page->block_size > MI_SMALL_SIZE_MAX) return 3;
  for (size_t i = 1; i < PRODUCERS; i++) {
    if (_mi_ptr_page(clients[i]) != page) return 3;
  }
  if (pthread_barrier_init(&start, NULL, PRODUCERS + 1) != 0) return 2;
  pthread_t threads[PRODUCERS];
  for (size_t i = 0; i < PRODUCERS; i++) {
    if (pthread_create(&threads[i], NULL, producer, (void*)i) != 0) return 2;
  }
  const int barrier = pthread_barrier_wait(&start);
  if (barrier != 0 && barrier != PTHREAD_BARRIER_SERIAL_THREAD) return 2;
  while (atomic_load_explicit(&completed, memory_order_acquire) < PRODUCERS) {
    _mi_page_free_collect(page, false);
    sched_yield();
  }
  for (size_t i = 0; i < PRODUCERS; i++) {
    void* result = NULL;
    if (pthread_join(threads[i], &result) != 0 || result != NULL) return 2;
  }
  _mi_page_free_collect(page, false);
  unsigned seen[PRODUCERS] = {0};
  const int valid_chains = mark_clients_in_chain(page, page->free, seen)
      && mark_clients_in_chain(page, page->local_free, seen);
  size_t collected = 0;
  for (size_t i = 0; i < PRODUCERS; i++) {
    if (seen[i] == 1) collected++;
  }
  const mi_thread_free_t head = mi_atomic_load_relaxed(&page->xthread_free);
  printf("CRABC_MI_M5_REMOTE_COLLECT_RACE_BEGIN\n");
  printf("producer_count=%d\nused_before=%d\nused_after=%zu\n", PRODUCERS, PRODUCERS, page->used);
  printf("head_owned_empty=%d\ncollected_count=%zu\n",
      mi_tf_is_owned(head) && mi_tf_block(head) == NULL, collected);
  printf("CRABC_MI_M5_REMOTE_COLLECT_RACE_END\n");
  return valid_chains && page->used == 0 && collected == PRODUCERS && mi_tf_is_owned(head)
      && mi_tf_block(head) == NULL ? 0 : 4;
}
