/* Compare one arena huge singleton through owner merge and remote release. */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mimalloc.h"
#include "mimalloc-stats.h"

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t changed = PTHREAD_COND_INITIALIZER;
static int ready;
static int release_worker;
static void* remote_block;
static int worker_mapped;

static void discard(const char* message, void* argument) {
  (void)message;
  (void)argument;
}

static void read_stats(mi_stats_t* stats) {
  if (!mi_stats_get(stats)) abort();
}

static void show_count(const char* name, const char* field,
                       const mi_stat_count_t* after, const mi_stat_count_t* before) {
  printf("%s.%s=%lld,%lld,%lld\n", name, field,
         (long long)(after->total - before->total),
         (long long)(after->peak - before->peak),
         (long long)(after->current - before->current));
}

static void show_stage(const char* name, const mi_stats_t* after,
                       const mi_stats_t* before) {
  show_count(name, "huge", &after->malloc_huge, &before->malloc_huge);
  show_count(name, "requested", &after->malloc_requested, &before->malloc_requested);
  show_count(name, "normal", &after->malloc_normal, &before->malloc_normal);
  show_count(name, "huge_bin", &after->malloc_bins[MI_BIN_HUGE],
             &before->malloc_bins[MI_BIN_HUGE]);
  show_count(name, "huge_page_bin", &after->page_bins[MI_BIN_HUGE],
             &before->page_bins[MI_BIN_HUGE]);
  show_count(name, "pages", &after->pages, &before->pages);
  printf("%s.huge_count=%lld\n", name,
         (long long)(after->malloc_huge_count.total - before->malloc_huge_count.total));
  printf("%s.normal_count=%lld\n", name,
         (long long)(after->malloc_normal_count.total - before->malloc_normal_count.total));
}

static void show_arena(const char* name, const mi_stats_t* stats) {
  printf("%s.arena=%lld,%lld,%lld\n", name,
         (long long)stats->reserved.total,
         (long long)stats->mmap_calls.total,
         (long long)stats->arena_count.total);
}

static void* worker(void* argument) {
  (void)argument;
  void* warm = mi_malloc(8);
  if (warm == NULL) abort();
  mi_free(warm);
  if (pthread_mutex_lock(&lock) != 0) abort();
  ready = 1;
  if (pthread_cond_broadcast(&changed) != 0) abort();
  while (!release_worker) {
    if (pthread_cond_wait(&changed, &lock) != 0) abort();
  }
  void* block = remote_block;
  if (pthread_mutex_unlock(&lock) != 0) abort();
  worker_mapped = mi_is_in_heap_region(block);
  mi_free(block);
  mi_thread_stats_print_out(&discard, NULL);
  return NULL;
}

int main(void) {
  const size_t request = 512 * 1024 + 1;
  void* arena_seed = mi_malloc(64);
  if (arena_seed == NULL) return 2;
  mi_option_set(mi_option_disallow_os_alloc, 1);

  pthread_t thread;
  if (pthread_create(&thread, NULL, &worker, NULL) != 0) abort();
  if (pthread_mutex_lock(&lock) != 0) abort();
  while (!ready) {
    if (pthread_cond_wait(&changed, &lock) != 0) abort();
  }
  if (pthread_mutex_unlock(&lock) != 0) abort();

  mi_stats_t_decl(before);
  mi_stats_t_decl(allocated);
  mi_stats_t_decl(merged);
  mi_stats_t_decl(freed);
  mi_stats_t_decl(terminal);
  read_stats(&before);
  void* block = mi_malloc(request);
  if (block == NULL) abort();
  memset(block, 0x5a, 64);
  const size_t usable = mi_usable_size(block);
  const int allocated_mapped = mi_is_in_heap_region(block);
  read_stats(&allocated);
  mi_thread_stats_print_out(&discard, NULL);
  read_stats(&merged);

  if (pthread_mutex_lock(&lock) != 0) abort();
  remote_block = block;
  release_worker = 1;
  if (pthread_cond_broadcast(&changed) != 0) abort();
  if (pthread_mutex_unlock(&lock) != 0) abort();
  if (pthread_join(thread, NULL) != 0) abort();
  read_stats(&freed);
  mi_collect(true);
  read_stats(&terminal);

  printf("CRABC_MI_M7_STATISTICS_HUGE_PAGE_BIN_TRACE_BEGIN\n");
  printf("profile.level=2\n");
  printf("request=%zu\n", request);
  printf("usable=%zu\n", usable);
  printf("disallow_os_alloc=%ld\n", mi_option_get(mi_option_disallow_os_alloc));
  printf("disallow_arena_alloc=%ld\n", mi_option_get(mi_option_disallow_arena_alloc));
  printf("allocated.mapped=%d\n", allocated_mapped);
  printf("worker.mapped=%d\n", worker_mapped);
  show_arena("before", &before);
  show_arena("allocated", &allocated);
  show_arena("terminal", &terminal);
  show_stage("allocated", &allocated, &before);
  show_stage("merged", &merged, &before);
  show_stage("freed", &freed, &before);
  show_stage("terminal", &terminal, &before);
  printf("CRABC_MI_M7_STATISTICS_HUGE_PAGE_BIN_TRACE_END\n");
  mi_free(arena_seed);
  return 0;
}
