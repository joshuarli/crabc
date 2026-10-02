/* Observe reset through a live child main Heap and its exclusive image. */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include "mimalloc.h"
#include "mimalloc-stats.h"

static mi_subproc_id_t child;

static long long exclusive_pages(void) {
  mi_stats_t_decl(image);
  if (!mi_subproc_stats_get_exclusive(child, &image)) abort();
  return (long long)image.pages.current;
}

static void* worker(void* argument) {
  (void)argument;
  mi_subproc_add_current_thread(child);
  void* client = mi_malloc(80);
  if (client == NULL) abort();
  const long long before = exclusive_pages();
  mi_stats_reset();
  const long long after = exclusive_pages();
  printf("reset.child.pages.delta=%lld\n", after - before);
  if (after - before != 1) abort();
  mi_stats_reset();
  if (exclusive_pages() != after) abort();
  mi_theap_t* main_theap = mi_heap_theap(mi_heap_main());
  mi_heap_t* auxiliary = mi_heap_new();
  if (auxiliary == NULL) abort();
  mi_theap_t* auxiliary_theap = mi_heap_theap(auxiliary);
  mi_theap_t* previous = mi_theap_set_default(auxiliary_theap);
  void* auxiliary_client = mi_malloc(192);
  if (auxiliary_client == NULL) abort();
  mi_stats_t_decl(auxiliary_image);
  if (!mi_theap_stats_get(auxiliary_theap, &auxiliary_image)) abort();
  const long long auxiliary_before = auxiliary_image.pages.current;
  if (auxiliary_before != 1) abort();
  mi_stats_reset();
  mi_stats_t_decl(main_image);
  if (!mi_theap_stats_get(main_theap, &main_image) || main_image.pages.current != 0) abort();
  if (!mi_theap_stats_get(auxiliary_theap, &auxiliary_image) || auxiliary_image.pages.current != auxiliary_before) abort();
  printf("reset.auxiliary.pages.retained=%lld\n", auxiliary_before);
  mi_free(auxiliary_client);
  mi_theap_set_default(previous);
  mi_heap_destroy(auxiliary);
  mi_thread_done();
  return client;
}

int main(void) {
  child = mi_subproc_new();
  if (child._mi_subproc_id == NULL) abort();
  pthread_t thread;
  void* client;
  if (pthread_create(&thread, NULL, worker, NULL) != 0) abort();
  if (pthread_join(thread, &client) != 0) abort();
  mi_free(client);
  mi_subproc_destroy(child);
  return 0;
}
