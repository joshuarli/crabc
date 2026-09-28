/* Observe automatic process destruction after setting its option before any client allocation. */
#include "static.c"
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

static atomic_bool worker_ready;
static atomic_bool worker_stop;

static void require(bool condition) {
  if (!condition) abort();
}

static void* live_worker(void* unused) {
  (void)unused;
  void* client = mi_malloc(96);
  require(client != NULL);
  memset(client, 0x63, 96);
  atomic_store_explicit(&worker_ready, true, memory_order_release);
  while (!atomic_load_explicit(&worker_stop, memory_order_acquire)) sched_yield();
  return NULL;
}

int main(int argc, char** argv) {
  require(argc == 2);
  const int os_only = atoi(argv[1]);
  require(os_only == 0 || os_only == 1);
  mi_process_init();
  mi_option_set(mi_option_destroy_on_exit, 1);
  mi_option_set(mi_option_disallow_arena_alloc, os_only);
  mi_option_set(mi_option_arena_reserve, 65536);
  require(mi_option_get(mi_option_destroy_on_exit) == 1);
  void* client = mi_malloc(80);
  require(client != NULL);
  memset(client, 0x35, 80);
  unsigned char residency = 0;
  void* page = (void*)((uintptr_t)client & ~(uintptr_t)4095);
  const size_t before = (mincore(page, 4096, &residency) == 0);
  pthread_t worker;
  require(pthread_create(&worker, NULL, live_worker, NULL) == 0);
  while (!atomic_load_explicit(&worker_ready, memory_order_acquire)) sched_yield();
  const size_t threads = mi_atomic_load_relaxed(&mi_process_subproc_main.thread_count);
  _mi_auto_process_done();
  const size_t values[] = {
    threads, before, mincore(page, 4096, &residency) == 0,
    mi_atomic_load_relaxed(&mi_process_subproc_main.arena_count),
    mi_process_subproc_main.theap_meta == NULL,
    mi_atomic_load_relaxed(&mi_process_subproc_main.heap_count),
    _mi_page_map() == &mi_page_map_empty,
  };
  for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++)
    printf("destroy_on_exit.%zu=%zu\n", i, values[i]);
  atomic_store_explicit(&worker_stop, true, memory_order_release);
  require(pthread_join(worker, NULL) == 0);
  return 0;
}
