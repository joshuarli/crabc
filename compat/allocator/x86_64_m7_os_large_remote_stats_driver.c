/* Compare source statistics for an OS-backed ordinary large remote free. */
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mimalloc.h"
#include "mimalloc-stats.h"

#ifndef CRABC_MI_WARM_OS_MAP
#define CRABC_MI_WARM_OS_MAP 0
#endif
#ifndef CRABC_MI_TRACE_PLACEMENT
#define CRABC_MI_TRACE_PLACEMENT 0
#endif

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t changed = PTHREAD_COND_INITIALIZER;
static int ready;
static int release_worker;
static void* remote_block;
static size_t target_bin;
static uintptr_t worker_warm_address;
static char worker_output[32768];
static size_t worker_output_length;

static void discard(const char* message, void* argument) {
  (void)message;
  (void)argument;
}

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

static void show_stage(const char* name, const mi_stats_t* after,
                       const mi_stats_t* before, size_t bin) {
  show_count(name, "bin", &after->malloc_bins[bin], &before->malloc_bins[bin]);
  show_count(name, "page_bin", &after->page_bins[bin], &before->page_bins[bin]);
  show_count(name, "pages", &after->pages, &before->pages);
  show_count(name, "requested", &after->malloc_requested, &before->malloc_requested);
  show_count(name, "normal", &after->malloc_normal, &before->malloc_normal);
  show_count(name, "reserved", &after->reserved, &before->reserved);
  show_count(name, "committed", &after->committed, &before->committed);
  printf("%s.normal_count=%lld\n", name,
         (long long)(after->malloc_normal_count.total - before->malloc_normal_count.total));
  printf("%s.mmap_calls=%lld\n", name,
         (long long)(after->mmap_calls.total - before->mmap_calls.total));
  printf("%s.arena_count=%lld\n", name,
         (long long)(after->arena_count.total - before->arena_count.total));
}

static void show_worker_bin(void) {
  char label[32];
  snprintf(label, sizeof(label), "  bin%2s  %3zu:", "L", target_bin);
  const char* start = strstr(worker_output, label);
  if (start == NULL) abort();
  const char* end = strchr(start, '\n');
  if (end == NULL) abort();
  printf("worker.bin.hex=");
  for (const char* p = start; p < end; p++) printf("%02x", (unsigned char)*p);
  printf("\n");
}

static void* worker(void* argument) {
  (void)argument;
  void* warm = mi_malloc(86706);
  if (warm == NULL) abort();
  worker_warm_address = (uintptr_t)warm;
  mi_free(warm);
  if (pthread_mutex_lock(&lock) != 0) abort();
  ready = 1;
  if (pthread_cond_broadcast(&changed) != 0) abort();
  while (!release_worker) {
    if (pthread_cond_wait(&changed, &lock) != 0) abort();
  }
  void* block = remote_block;
  if (pthread_mutex_unlock(&lock) != 0) abort();
  mi_free(block);
  mi_thread_stats_print_out(&capture_worker, NULL);
  return NULL;
}

int main(void) {
  const size_t request = 86706;
  mi_option_set(mi_option_disallow_arena_alloc, 1);
  pthread_t thread;
  if (pthread_create(&thread, NULL, &worker, NULL) != 0) return 2;
  if (pthread_mutex_lock(&lock) != 0) abort();
  while (!ready) {
    if (pthread_cond_wait(&changed, &lock) != 0) abort();
  }
  if (pthread_mutex_unlock(&lock) != 0) abort();

  mi_stats_t_decl(before);
  mi_stats_t_decl(before_warm);
  mi_stats_t_decl(after_warm);
  mi_stats_t_decl(allocated);
  mi_stats_t_decl(owner_merged);
  mi_stats_t_decl(worker_merged);
  mi_stats_t_decl(released);
  void* warm_map = NULL;
  read_stats(&before_warm);
#if CRABC_MI_WARM_OS_MAP
  warm_map = mi_malloc(100000);
  if (warm_map == NULL) return 4;
  memset(warm_map, 0x6b, 64);
  read_stats(&after_warm);
#endif
  read_stats(&before);
  void* block = mi_malloc(request);
  if (block == NULL) return 5;
  memset(block, 0x5a, 64);
  const size_t usable = mi_usable_size(block);
  const int heap_region = mi_is_in_heap_region(block);
  target_bin = bin_for_size(usable);
  read_stats(&allocated);
  mi_thread_stats_print_out(&discard, NULL);
  read_stats(&owner_merged);

  if (pthread_mutex_lock(&lock) != 0) abort();
  remote_block = block;
  release_worker = 1;
  if (pthread_cond_broadcast(&changed) != 0) abort();
  if (pthread_mutex_unlock(&lock) != 0) abort();
  if (pthread_join(thread, NULL) != 0) abort();
  read_stats(&worker_merged);
  mi_collect(true);
  read_stats(&released);

  printf("CRABC_MI_M7_OS_LARGE_REMOTE_STATS_BEGIN\n");
  printf("request=%zu\n", request);
  printf("control.warm_os_map=%d\n", CRABC_MI_WARM_OS_MAP);
#if CRABC_MI_WARM_OS_MAP
  show_count("warm", "reserved", &after_warm.reserved, &before_warm.reserved);
  show_count("warm", "committed", &after_warm.committed, &before_warm.committed);
  printf("warm.mmap_calls=%lld\n",
         (long long)(after_warm.mmap_calls.total - before_warm.mmap_calls.total));
#endif
  printf("usable=%zu\n", usable);
  printf("bin=%zu\n", target_bin);
  printf("heap_region=%d\n", heap_region);
  printf("disallow_arena_alloc=%ld\n", mi_option_get(mi_option_disallow_arena_alloc));
#if CRABC_MI_TRACE_PLACEMENT
  // Both source page maps index 64-KiB slices in 8,192-entry submaps.
  printf("placement.worker_index=%zu\n", (size_t)(worker_warm_address >> 29));
#if CRABC_MI_WARM_OS_MAP
  printf("placement.warm_index=%zu\n", (size_t)((uintptr_t)warm_map >> 29));
#endif
  printf("placement.target_index=%zu\n", (size_t)((uintptr_t)block >> 29));
#endif
  show_stage("allocated", &allocated, &before, target_bin);
  show_stage("owner_merged", &owner_merged, &before, target_bin);
  show_stage("worker_merged", &worker_merged, &before, target_bin);
  show_stage("released", &released, &before, target_bin);
  show_worker_bin();
  printf("CRABC_MI_M7_OS_LARGE_REMOTE_STATS_END\n");
#if CRABC_MI_WARM_OS_MAP
  mi_free(warm_map);
#endif
  return 0;
}
