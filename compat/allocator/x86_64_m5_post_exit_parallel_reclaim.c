/* Two remote frees start together after their page's owner has exited. */
#define _POSIX_C_SOURCE 200809L
#include "mimalloc/internal.h"
#include <pthread.h>
#include <semaphore.h>
#include <stdio.h>

#if !defined(__linux__) || !defined(__x86_64__)
#error this private source fixture requires native Linux/x86-64
#endif
#if MI_BUILD_RELEASE != 1 || MI_DEBUG != 0 || MI_STAT != 0 || MI_SECURE != 0 || MI_GUARDED != 0
#error this fixture requires the pinned release configuration
#endif

#define REQUEST (64 * 1024)

static sem_t ready;
static void* clients[3];
static mi_page_t* page;
static size_t capacity;
static int setup_valid;
static pthread_barrier_t publish_start;
static size_t usable[2];

static void* owner(void* ignored) {
  (void)ignored;
  mi_thread_init();
  for (size_t i = 0; i < 3; i++) {
    clients[i] = mi_malloc_aligned(REQUEST, 16);
    if (clients[i] == NULL) goto publish;
  }
  page = _mi_ptr_page(clients[0]);
  if (page == NULL) goto publish;
  capacity = page->reserved;
  setup_valid = capacity > 3 && _mi_ptr_page(clients[1]) == page
      && _mi_ptr_page(clients[2]) == page && page->used == 3;
publish:
  sem_post(&ready);
  mi_thread_done();
  return NULL;
}

static void* publisher(void* argument) {
  const size_t index = (size_t)argument;
  mi_thread_init();
  const int start = pthread_barrier_wait(&publish_start);
  if (start != 0 && start != PTHREAD_BARRIER_SERIAL_THREAD) return (void*)1;
  usable[index] = mi_usable_size(clients[index]);
  mi_free(clients[index]);
  mi_thread_done();
  return NULL;
}

int main(void) {
  mi_option_set(mi_option_page_full_retain, -1);
  mi_option_set(mi_option_page_reclaim_on_free, 1);
  mi_thread_init();
  void* warmup = mi_malloc(48);
  if (warmup == NULL) return 2;
  mi_free(warmup);
  if (sem_init(&ready, 0, 0) != 0 || pthread_barrier_init(&publish_start, NULL, 3) != 0) return 2;
  pthread_t a;
  if (pthread_create(&a, NULL, owner, NULL) != 0) return 2;
  sem_wait(&ready);
  if (!setup_valid || pthread_join(a, NULL) != 0) return 3;
  const int registered_after_exit = _mi_safe_ptr_page(clients[2]) == page;
  const size_t used_after_exit = page->used;
  const int abandoned_after_exit = mi_page_is_abandoned(page) && !mi_page_is_owned(page);
  pthread_t b[2];
  for (size_t i = 0; i < 2; i++) {
    if (pthread_create(&b[i], NULL, publisher, (void*)i) != 0) return 2;
  }
  const int start = pthread_barrier_wait(&publish_start);
  if (start != 0 && start != PTHREAD_BARRIER_SERIAL_THREAD) return 2;
  for (size_t i = 0; i < 2; i++) {
    void* result = NULL;
    if (pthread_join(b[i], &result) != 0 || result != NULL) return 2;
  }
  const int registered_after_publications = _mi_safe_ptr_page(clients[2]) == page;
  const size_t used_after_publications = page->used;
  const int abandoned_after_publications = mi_page_is_abandoned(page) && !mi_page_is_owned(page);
  const size_t final_usable = mi_usable_size(clients[2]);
  mi_free(clients[2]);
  mi_collect(true);
  const int released_after_collect = !mi_is_in_heap_region(clients[2]);
  mi_collect(true);
  const int still_released = !mi_is_in_heap_region(clients[2]);
  printf("CRABC_MI_M5_POST_EXIT_PARALLEL_RECLAIM_BEGIN\n");
  printf("request=%d\ncapacity=%zu\nsetup_valid=%d\n", REQUEST, capacity, setup_valid);
  printf("registered_after_exit=%d\nused_after_exit=%zu\nabandoned_after_exit=%d\n",
      registered_after_exit, used_after_exit, abandoned_after_exit);
  printf("publisher_usable_equal=%d\nregistered_after_publications=%d\n",
      usable[0] == usable[1] && usable[0] != 0, registered_after_publications);
  printf("used_after_publications=%zu\nabandoned_after_publications=%d\nfinal_usable=%zu\n",
      used_after_publications, abandoned_after_publications, final_usable);
  printf("released_after_collect=%d\nstill_released=%d\n",
      released_after_collect, still_released);
  printf("CRABC_MI_M5_POST_EXIT_PARALLEL_RECLAIM_END\n");
  return 0;
}
