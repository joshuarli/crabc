/* Compare an ordinary remote free after the freeing worker has its own Theap. */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mimalloc.h"
#include "mimalloc-stats.h"

#ifndef CRABC_MI_FRESH_WORKER
#define CRABC_MI_FRESH_WORKER 0
#endif
#ifndef CRABC_MI_STAT_LEVEL
#define CRABC_MI_STAT_LEVEL 1
#endif
#ifndef CRABC_MI_TARGET_REQUEST
#define CRABC_MI_TARGET_REQUEST 64
#endif
#ifndef CRABC_MI_FRESH_WORKER_UFREE
#define CRABC_MI_FRESH_WORKER_UFREE 0
#endif
#ifndef CRABC_MI_FRESH_WORKER_CFREE
#define CRABC_MI_FRESH_WORKER_CFREE 0
#endif

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t changed = PTHREAD_COND_INITIALIZER;
static int ready;
static int release_worker;
static void* remote_block;
static size_t warm_usable;
static size_t worker_free_usable;
static int worker_cfree_owned;
static char worker_output[16384];
static size_t worker_output_length;

static void capture_worker(const char* message, void* argument) {
  (void)argument;
  const size_t length = strlen(message);
  if (length >= sizeof(worker_output) - worker_output_length) abort();
  memcpy(worker_output + worker_output_length, message, length + 1);
  worker_output_length += length;
}

static void read_stats(mi_stats_t* stats) {
  if (!mi_stats_get(stats)) abort();
}

static void show_normal(const char* name, const mi_stats_t* stats, const mi_stats_t* before) {
  printf("%s.normal=%lld,%lld,%lld\n", name,
         (long long)(stats->malloc_normal.total - before->malloc_normal.total),
         (long long)(stats->malloc_normal.peak - before->malloc_normal.peak),
         (long long)(stats->malloc_normal.current - before->malloc_normal.current));
}

#if CRABC_MI_FRESH_WORKER
static size_t bin_for_size(size_t size) {
  for (size_t bin = 1; bin < MI_BIN_HUGE; bin++) {
    if (mi_stats_get_bin_size(bin) == size) return bin;
  }
  abort();
}

static void show_count(const char* name, const char* field,
                       const mi_stat_count_t* after, const mi_stat_count_t* before) {
  printf("%s.%s=%lld,%lld,%lld\n", name, field,
         (long long)(after->total - before->total),
         (long long)(after->peak - before->peak),
         (long long)(after->current - before->current));
}

static void show_fresh_stage(const char* name, const mi_stats_t* after,
                             const mi_stats_t* before, size_t bin) {
  show_count(name, "bin", &after->malloc_bins[bin], &before->malloc_bins[bin]);
  show_count(name, "page_bin", &after->page_bins[bin], &before->page_bins[bin]);
  show_count(name, "pages", &after->pages, &before->pages);
  show_count(name, "requested", &after->malloc_requested, &before->malloc_requested);
  printf("%s.normal_count=%lld\n", name,
         (long long)(after->malloc_normal_count.total - before->malloc_normal_count.total));
}
#endif

static void show_worker_binned(void) {
  const char* row = strstr(worker_output, "  binned");
#if CRABC_MI_FRESH_WORKER
  if (row == NULL) {
    printf("worker.binned.hex=\n");
    return;
  }
#else
  if (row == NULL) abort();
#endif
  const char* end = strchr(row, '\n');
  if (end == NULL) abort();
  printf("worker.binned.hex=");
  for (const char* p = row; p < end; p++) printf("%02x", (unsigned char)*p);
  printf("\n");
}

static void* worker(void* argument) {
  (void)argument;
#if !CRABC_MI_FRESH_WORKER
  void* warm = mi_malloc(1);
  if (warm == NULL) abort();
  warm_usable = mi_usable_size(warm);
  mi_free(warm);
#endif

  if (pthread_mutex_lock(&lock) != 0) abort();
  ready = 1;
  if (pthread_cond_broadcast(&changed) != 0) abort();
  while (!release_worker) {
    if (pthread_cond_wait(&changed, &lock) != 0) abort();
  }
  void* block = remote_block;
  if (pthread_mutex_unlock(&lock) != 0) abort();

#if CRABC_MI_FRESH_WORKER_UFREE
  mi_ufree(block, &worker_free_usable);
#elif CRABC_MI_FRESH_WORKER_CFREE
  worker_cfree_owned = mi_cfree(block);
#else
  mi_free(block);
#endif
  mi_thread_stats_print_out(&capture_worker, NULL);
  return NULL;
}

int main(void) {
  pthread_t thread;
  if (pthread_create(&thread, NULL, &worker, NULL) != 0) return 2;
  if (pthread_mutex_lock(&lock) != 0) abort();
  while (!ready) {
    if (pthread_cond_wait(&changed, &lock) != 0) abort();
  }
  if (pthread_mutex_unlock(&lock) != 0) abort();

  mi_stats_t_decl(before);
  mi_stats_t_decl(allocated);
  mi_stats_t_decl(freed);
  read_stats(&before);
  void* block = mi_malloc(CRABC_MI_TARGET_REQUEST);
  if (block == NULL) return 3;
  memset(block, 0x5a, CRABC_MI_TARGET_REQUEST < 64 ? CRABC_MI_TARGET_REQUEST : 64);
  const size_t target_usable = mi_usable_size(block);
  read_stats(&allocated);

  if (pthread_mutex_lock(&lock) != 0) abort();
  remote_block = block;
  release_worker = 1;
  if (pthread_cond_broadcast(&changed) != 0) abort();
  if (pthread_mutex_unlock(&lock) != 0) abort();
  if (pthread_join(thread, NULL) != 0) abort();
  read_stats(&freed);

  printf("CRABC_MI_M7_STATISTICS_REMOTE_NORMAL_TRACE_BEGIN\n");
  printf("profile.level=%d\n", CRABC_MI_STAT_LEVEL);
  printf("worker.fresh=%d\n", CRABC_MI_FRESH_WORKER);
#if CRABC_MI_FRESH_WORKER
  printf("target.request=%d\n", CRABC_MI_TARGET_REQUEST);
  printf("worker.free_usable=%zu\n", worker_free_usable);
  printf("worker.cfree_owned=%d\n", worker_cfree_owned);
#endif
  printf("warm.usable=%zu\n", warm_usable);
  printf("target.usable=%zu\n", target_usable);
  show_normal("allocated", &allocated, &before);
  show_normal("freed", &freed, &before);
#if CRABC_MI_FRESH_WORKER
  const size_t bin = bin_for_size(target_usable);
  show_fresh_stage("allocated", &allocated, &before, bin);
  show_fresh_stage("freed", &freed, &before, bin);
#endif
  show_worker_binned();
  printf("CRABC_MI_M7_STATISTICS_REMOTE_NORMAL_TRACE_END\n");
  return 0;
}
