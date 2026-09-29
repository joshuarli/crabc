/* Three bounded foreign publishers, one live owner drain, and final release. */
#define _POSIX_C_SOURCE 200809L
#include "mimalloc/internal.h"
#include <pthread.h>
#include <stdio.h>

#if !defined(__linux__) || !defined(__x86_64__)
#error this fixture requires native Linux/x86-64
#endif
#if MI_BUILD_RELEASE != 1 || MI_DEBUG != 0 || MI_STAT != 0 || MI_SECURE != 0 || MI_GUARDED != 0
#error this fixture requires the pinned release profile
#endif

enum { PRODUCERS = 3, CLIENTS = 4, REQUEST = 64 * 1024 };
static pthread_barrier_t start;
static void* clients[CLIENTS];

static void* producer(void* argument) {
  size_t index = (size_t)argument;
  mi_thread_init();
  int barrier = pthread_barrier_wait(&start);
  if (barrier != 0 && barrier != PTHREAD_BARRIER_SERIAL_THREAD) return (void*)1;
  mi_free(clients[index]);
  mi_thread_done();
  return NULL;
}

static int mark_chain(mi_page_t* page, mi_block_t* head, unsigned seen[PRODUCERS]) {
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
  mi_option_set(mi_option_page_full_retain, -1);
  mi_thread_init();
  for (size_t i = 0; i < CLIENTS; i++) {
    clients[i] = mi_malloc_aligned(REQUEST, 16);
    if (clients[i] == NULL) return 2;
  }
  mi_page_t* page = _mi_ptr_page(clients[0]);
  if (page == NULL || page->used != CLIENTS || page->reserved < CLIENTS) return 3;
  for (size_t i = 1; i < CLIENTS; i++) {
    if (_mi_ptr_page(clients[i]) != page) return 3;
  }
  if (pthread_barrier_init(&start, NULL, PRODUCERS + 1) != 0) return 2;
  pthread_t threads[PRODUCERS];
  for (size_t i = 0; i < PRODUCERS; i++) {
    if (pthread_create(&threads[i], NULL, producer, (void*)i) != 0) return 2;
  }
  int barrier = pthread_barrier_wait(&start);
  if (barrier != 0 && barrier != PTHREAD_BARRIER_SERIAL_THREAD) return 2;
  for (size_t i = 0; i < PRODUCERS; i++) {
    void* result = NULL;
    if (pthread_join(threads[i], &result) != 0 || result != NULL) return 2;
  }
  mi_thread_free_t pending = mi_atomic_load_relaxed(&page->xthread_free);
  unsigned seen[PRODUCERS] = {0};
  int pending_chain_valid = mark_chain(page, mi_tf_block(pending), seen);
  int pending_count = 0;
  for (size_t i = 0; i < PRODUCERS; i++) pending_count += seen[i] == 1;
  int owned_before = mi_tf_is_owned(pending);
  size_t used_before = page->used;
  int mapped_before = mi_is_in_heap_region(clients[3]);
  mi_collect(false);
  mi_thread_free_t drained = mi_atomic_load_relaxed(&page->xthread_free);
  unsigned collected[PRODUCERS] = {0};
  int collected_chain_valid = mark_chain(page, page->free, collected)
      && mark_chain(page, page->local_free, collected);
  int collected_count = 0;
  for (size_t i = 0; i < PRODUCERS; i++) collected_count += collected[i] == 1;
  size_t used_after = page->used;
  int owned_empty_after = mi_tf_is_owned(drained) && mi_tf_block(drained) == NULL;
  int mapped_after = mi_is_in_heap_region(clients[3]);
  mi_free(clients[3]);
  mi_collect(true);
  int released = !mi_is_in_heap_region(clients[3]);
  mi_collect(true);
  int still_released = !mi_is_in_heap_region(clients[3]);
  printf("CRABC_MI_M5_REMOTE_OWNER_COLLECT_BEGIN\n");
  printf("producer_count=%d\nrequest=%d\nused_before=%zu\n", PRODUCERS, REQUEST, used_before);
  printf("owned_before=%d\npending_count=%d\npending_chain_valid=%d\n", owned_before, pending_count, pending_chain_valid);
  printf("mapped_before=%d\nused_after=%zu\nowned_empty_after=%d\n", mapped_before, used_after, owned_empty_after);
  printf("collected_count=%d\ncollected_chain_valid=%d\nmapped_after=%d\n", collected_count, collected_chain_valid, mapped_after);
  printf("released=%d\nstill_released=%d\n", released, still_released);
  printf("CRABC_MI_M5_REMOTE_OWNER_COLLECT_END\n");
  return used_before == CLIENTS && owned_before && pending_count == PRODUCERS
      && pending_chain_valid && mapped_before && used_after == 1 && owned_empty_after
      && collected_count == PRODUCERS && collected_chain_valid && mapped_after
      && released && still_released ? 0 : 4;
}
