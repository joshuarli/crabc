/* A live worker allocation is reset, survives owner exit, and is freed by
   another attached worker. Observe each owner merge through public stats. */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include "mimalloc.h"
#include "mimalloc-stats.h"

enum { BEFORE, FIRST_ALLOC, FIRST_RESET, FIRST_EXIT,
       SECOND_ATTACH, REMOTE_FREE, SECOND_RESET, LOCAL_FREE, SECOND_EXIT, STAGE_COUNT };
static const char* names[STAGE_COUNT] = {
  "before", "first_alloc", "first_reset", "first_exit",
  "second_attach", "remote_free", "second_reset", "local_free", "second_exit"
};
static mi_stats_t observed[STAGE_COUNT];
static void* transferred;
static size_t first_bin, second_bin;

static void capture(unsigned stage) {
  mi_stats_init(&observed[stage]);
  if (!mi_stats_get(&observed[stage])) abort();
}

static size_t bin_for(size_t size) {
  for (size_t index = 0; index < MI_BIN_HUGE; index++) {
    if (mi_stats_get_bin_size(index) == size) return index;
  }
  abort();
}

static void* first_worker(void* ignored) {
  (void)ignored;
  transferred = mi_malloc(64);
  if (transferred == NULL) abort();
  first_bin = bin_for(mi_usable_size(transferred));
  capture(FIRST_ALLOC);
  mi_stats_reset();
  capture(FIRST_RESET);
  return NULL;
}

static void* second_worker(void* ignored) {
  (void)ignored;
  void* local = mi_malloc(16);
  if (local == NULL) abort();
  second_bin = bin_for(mi_usable_size(local));
  capture(SECOND_ATTACH);
  mi_free(transferred);
  capture(REMOTE_FREE);
  mi_stats_reset();
  capture(SECOND_RESET);
  mi_free(local);
  capture(LOCAL_FREE);
  return NULL;
}

static void count(const char* stage, const char* field,
                  const mi_stat_count_t* now, const mi_stat_count_t* baseline) {
  printf("%s.%s=%lld,%lld,%lld\n", stage, field,
         (long long)(now->total - baseline->total),
         (long long)(now->peak - baseline->peak),
         (long long)(now->current - baseline->current));
}

static void show(unsigned stage) {
  const mi_stats_t* now = &observed[stage];
  const mi_stats_t* baseline = &observed[BEFORE];
  count(names[stage], "normal", &now->malloc_normal, &baseline->malloc_normal);
  count(names[stage], "requested", &now->malloc_requested, &baseline->malloc_requested);
  count(names[stage], "first_bin", &now->malloc_bins[first_bin], &baseline->malloc_bins[first_bin]);
  count(names[stage], "second_bin", &now->malloc_bins[second_bin], &baseline->malloc_bins[second_bin]);
  count(names[stage], "pages", &now->pages, &baseline->pages);
  count(names[stage], "first_page_bin", &now->page_bins[first_bin], &baseline->page_bins[first_bin]);
  count(names[stage], "second_page_bin", &now->page_bins[second_bin], &baseline->page_bins[second_bin]);
  count(names[stage], "threads", &now->threads, &baseline->threads);
  count(names[stage], "theaps", &now->theaps, &baseline->theaps);
  printf("%s.normal_count=%lld\n", names[stage],
         (long long)(now->malloc_normal_count.total - baseline->malloc_normal_count.total));
}

int main(void) {
  pthread_t worker;
  capture(BEFORE);
  if (pthread_create(&worker, NULL, first_worker, NULL) != 0) abort();
  if (pthread_join(worker, NULL) != 0) abort();
  capture(FIRST_EXIT);
  if (pthread_create(&worker, NULL, second_worker, NULL) != 0) abort();
  if (pthread_join(worker, NULL) != 0) abort();
  capture(SECOND_EXIT);
  printf("CRABC_MI_M7_STATISTICS_WORKER_TRANSFER_TRACE_BEGIN\n");
  printf("profile.level=2\n");
  printf("first.bin=%zu\n", first_bin);
  printf("second.bin=%zu\n", second_bin);
  for (unsigned stage = 0; stage < STAGE_COUNT; stage++) show(stage);
  printf("CRABC_MI_M7_STATISTICS_WORKER_TRANSFER_TRACE_END\n");
  return 0;
}
