/* Observe a worker's statistics before and after its owner merges. */
#ifndef CRABC_WORKER_STAT_LEVEL
#define CRABC_WORKER_STAT_LEVEL 1
#endif
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mimalloc.h"
#include "mimalloc-stats.h"

static mi_stats_t before, allocated, reset, freed, exited;
static size_t usable, second_usable;
#if CRABC_WORKER_STAT_LEVEL > 1
static size_t first_bin, second_bin;
#endif
static char output[4][32768];
static size_t output_length;
static char* output_target;

static void capture(const char* message, void* argument) {
  (void)argument;
  const size_t size = strlen(message);
  if (output_length + size >= 32768) abort();
  memcpy(output_target + output_length, message, size + 1);
  output_length += size;
}

static void read_stats(mi_stats_t* stats) {
  mi_stats_init(stats);
  if (!mi_stats_get(stats)) abort();
}

#if CRABC_WORKER_STAT_LEVEL > 1
static size_t bin_for_size(size_t size) {
  for (size_t bin = 1; bin < MI_BIN_HUGE; bin++) {
    if (mi_stats_get_bin_size(bin) == size) return bin;
  }
  abort();
}
#endif

static void print_worker(unsigned index) {
  output_target = output[index];
  output_length = 0;
  output_target[0] = 0;
  mi_thread_stats_print_out(&capture, NULL);
}

static void print_process(void) {
  output_target = output[3];
  output_length = 0;
  output_target[0] = 0;
  mi_stats_print_out(&capture, NULL);
}

static void* worker(void* argument) {
  (void)argument;
  void* block = mi_malloc(64);
  if (block == NULL) abort();
  usable = mi_usable_size(block);
#if CRABC_WORKER_STAT_LEVEL > 1
  first_bin = bin_for_size(usable);
#endif
  print_worker(0);
  read_stats(&allocated);
  /* Printing merged the first block into the Heap. The second block leaves
     a fresh Theap record whose reset merge is visible in the next print. */
  void* second = mi_malloc(CRABC_WORKER_STAT_LEVEL > 1 ? 32768 : 64);
  if (second == NULL) abort();
  second_usable = mi_usable_size(second);
#if CRABC_WORKER_STAT_LEVEL > 1
  second_bin = bin_for_size(second_usable);
#endif
  mi_stats_reset();
  print_worker(1);
  read_stats(&reset);
  mi_free(second);
  mi_free(block);
  print_worker(2);
  read_stats(&freed);
  return NULL;
}

static void count(const char* stage, const char* field,
                  const mi_stat_count_t* now, const mi_stat_count_t* baseline) {
  printf("%s.%s=%lld,%lld,%lld\n", stage, field,
         (long long)(now->current - baseline->current),
         (long long)(now->total - baseline->total),
         (long long)(now->peak - baseline->peak));
}

static void stage(const char* name, const mi_stats_t* stats) {
  count(name, "normal", &stats->malloc_normal, &before.malloc_normal);
  count(name, "threads", &stats->threads, &before.threads);
  count(name, "heaps", &stats->heaps, &before.heaps);
  count(name, "theaps", &stats->theaps, &before.theaps);
  printf("%s.normal_count=%lld\n", name,
         (long long)(stats->malloc_normal_count.total - before.malloc_normal_count.total));
#if CRABC_WORKER_STAT_LEVEL > 1
  count(name, "requested", &stats->malloc_requested, &before.malloc_requested);
  count(name, "first_bin", &stats->malloc_bins[first_bin], &before.malloc_bins[first_bin]);
  count(name, "second_bin", &stats->malloc_bins[second_bin], &before.malloc_bins[second_bin]);
  count(name, "first_page_bin", &stats->page_bins[first_bin], &before.page_bins[first_bin]);
  count(name, "second_page_bin", &stats->page_bins[second_bin], &before.page_bins[second_bin]);
#endif
}

static void output_row(unsigned index, const char* key, const char* label) {
  char prefix[32];
  snprintf(prefix, sizeof(prefix), "  %-10s:", label);
  const char* start = strstr(output[index], prefix);
  if (start == NULL) { printf("%s=absent\n", key); return; }
  const char* end = strchr(start, '\n');
  if (end == NULL) abort();
  printf("%s=", key);
  for (const char* p = start; p < end; p++) printf("%02x", (unsigned char)*p);
  printf("\n");
}

static void output_owner(unsigned index, const char* key) {
  const char* end = strchr(output[index], '\n');
  if (end == NULL) abort();
  printf("%s=", key);
  for (const char* p = output[index]; p < end; p++) printf("%02x", (unsigned char)*p);
  printf("\n");
}

#if CRABC_WORKER_STAT_LEVEL > 1
static void output_full(unsigned index, const char* key) {
  printf("%s=", key);
  for (const char* p = output[index]; *p != 0; p++) printf("%02x", (unsigned char)*p);
  printf("\n");
}
#endif

int main(void) {
  pthread_t thread;
  read_stats(&before);
  if (pthread_create(&thread, NULL, &worker, NULL) != 0) abort();
  if (pthread_join(thread, NULL) != 0) abort();
  read_stats(&exited);
  print_process();
  printf("CRABC_MI_M7_STATISTICS_WORKER_RESET_TRACE_BEGIN\n");
  printf("profile.level=%d\n", CRABC_WORKER_STAT_LEVEL);
  printf("allocation.usable=%zu\n", usable);
  printf("allocation.second_usable=%zu\n", second_usable);
#if CRABC_WORKER_STAT_LEVEL > 1
  printf("allocation.first_bin=%zu\n", first_bin);
  printf("allocation.second_bin=%zu\n", second_bin);
#endif
  stage("allocated", &allocated);
  stage("reset", &reset);
  stage("freed", &freed);
  stage("exited", &exited);
  output_owner(0, "worker.live_owner");
  output_owner(1, "worker.reset_owner");
  output_owner(2, "worker.freed_owner");
  output_owner(3, "process.exited_owner");
  output_row(0, "worker.live_binned", "binned");
  output_row(0, "worker.live_total", "total");
  output_row(1, "worker.reset_binned", "binned");
  output_row(1, "worker.reset_total", "total");
  output_row(2, "worker.freed_binned", "binned");
  output_row(2, "worker.freed_total", "total");
  output_row(3, "process.exited_binned", "binned");
  output_row(3, "process.exited_total", "total");
#if CRABC_WORKER_STAT_LEVEL > 1
  char first_label[32], second_label[32];
  snprintf(first_label, sizeof(first_label), "bin%2s  %3zu", "S", first_bin);
  snprintf(second_label, sizeof(second_label), "bin%2s  %3zu", "M", second_bin);
  output_row(0, "worker.live_first_bin", first_label);
  output_row(0, "worker.live_requested", "malloc req");
  output_row(1, "worker.reset_second_bin", second_label);
  output_row(3, "process.exited_first_bin", first_label);
  output_row(3, "process.exited_second_bin", second_label);
  output_row(3, "process.exited_requested", "malloc req");
  output_full(0, "worker.live_full");
  output_full(1, "worker.reset_full");
  output_full(2, "worker.freed_full");
  output_full(3, "process.exited_full");
#endif
  printf("CRABC_MI_M7_STATISTICS_WORKER_RESET_TRACE_END\n");
  return 0;
}
