/* Compare the freeing Theap's size-bin record before its process merge. */
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
static size_t worker_request = 64;
static size_t warm_usable;
static char worker_output[32768];
static size_t worker_output_length;

static void capture_worker(const char* message, void* argument) {
  (void)argument;
  const size_t length = strlen(message);
  if (length >= sizeof(worker_output) - worker_output_length) abort();
  memcpy(worker_output + worker_output_length, message, length + 1);
  worker_output_length += length;
}

static void discard(const char* message, void* argument) {
  (void)message;
  (void)argument;
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
  show_count(name, "requested", &after->malloc_requested, &before->malloc_requested);
  show_count(name, "normal", &after->malloc_normal, &before->malloc_normal);
  printf("%s.normal_count=%lld\n", name,
         (long long)(after->malloc_normal_count.total - before->malloc_normal_count.total));
}

static void show_page_bin(const char* name, const mi_stats_t* after,
                          const mi_stats_t* before, size_t bin) {
  show_count(name, "page_bin", &after->page_bins[bin], &before->page_bins[bin]);
}

static void show_arena(const char* name, const mi_stats_t* stats) {
  printf("medium.%s.arena=%lld,%lld,%lld\n", name,
         (long long)stats->reserved.total, (long long)stats->mmap_calls.total,
         (long long)stats->arena_count.total);
}

static void show_worker_row(const char* name, const char* label) {
  const char* start = strstr(worker_output, label);
  if (start == NULL) abort();
  const char* end = strchr(start, '\n');
  if (end == NULL) abort();
  printf("worker.%s.hex=", name);
  for (const char* p = start; p < end; p++) printf("%02x", (unsigned char)*p);
  printf("\n");
}

static void* worker(void* argument) {
  (void)argument;
  void* warm = mi_malloc(worker_request);
  if (warm == NULL) abort();
  warm_usable = mi_usable_size(warm);
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
  pthread_t thread;
  if (pthread_create(&thread, NULL, &worker, NULL) != 0) return 2;
  if (pthread_mutex_lock(&lock) != 0) abort();
  while (!ready) {
    if (pthread_cond_wait(&changed, &lock) != 0) abort();
  }
  if (pthread_mutex_unlock(&lock) != 0) abort();

  mi_stats_t_decl(before);
  mi_stats_t_decl(allocated);
  mi_stats_t_decl(main_merged);
  mi_stats_t_decl(freed);
  read_stats(&before);
  void* block = mi_malloc(64);
  if (block == NULL) return 3;
  memset(block, 0x5a, 64);
  const size_t target_usable = mi_usable_size(block);
  const size_t bin = bin_for_size(target_usable);
  read_stats(&allocated);
  mi_thread_stats_print_out(&discard, NULL);
  read_stats(&main_merged);

  if (pthread_mutex_lock(&lock) != 0) abort();
  remote_block = block;
  release_worker = 1;
  if (pthread_cond_broadcast(&changed) != 0) abort();
  if (pthread_mutex_unlock(&lock) != 0) abort();
  if (pthread_join(thread, NULL) != 0) abort();
  read_stats(&freed);

  char bin_label[32];
  snprintf(bin_label, sizeof(bin_label), "  bin%2s  %3zu:", "S", bin);
  printf("CRABC_MI_M7_STATISTICS_REMOTE_BIN_TRACE_BEGIN\n");
  printf("profile.level=2\n");
  printf("warm.usable=%zu\n", warm_usable);
  printf("target.usable=%zu\n", target_usable);
  printf("target.bin=%zu\n", bin);
  show_stage("allocated", &allocated, &before, bin);
  show_stage("main_merged", &main_merged, &before, bin);
  show_stage("freed", &freed, &before, bin);
  show_worker_row("bin", bin_label);
  show_worker_row("requested", "  malloc req:");

  mi_option_set(mi_option_disallow_os_alloc, 1);
  worker_request = 32768;
  ready = 0;
  release_worker = 0;
  remote_block = NULL;
  worker_output_length = 0;
  worker_output[0] = '\0';
  if (pthread_create(&thread, NULL, &worker, NULL) != 0) abort();
  if (pthread_mutex_lock(&lock) != 0) abort();
  while (!ready) {
    if (pthread_cond_wait(&changed, &lock) != 0) abort();
  }
  if (pthread_mutex_unlock(&lock) != 0) abort();

  mi_stats_t_decl(medium_before);
  mi_stats_t_decl(medium_allocated);
  mi_stats_t_decl(medium_merged);
  mi_stats_t_decl(medium_freed);
  mi_stats_t_decl(medium_collected);
  mi_stats_t_decl(medium_terminal);
  read_stats(&medium_before);
  void* survivor = mi_malloc(32768);
  void* medium_target = mi_malloc(32768);
  if (survivor == NULL || medium_target == NULL) abort();
  memset(survivor, 0x6b, 32768);
  memset(medium_target, 0x5a, 32768);
  const size_t medium_usable = mi_usable_size(medium_target);
  const size_t medium_bin = bin_for_size(medium_usable);
  const int medium_target_mapped = mi_is_in_heap_region(medium_target);
  read_stats(&medium_allocated);
  mi_thread_stats_print_out(&discard, NULL);
  read_stats(&medium_merged);

  if (pthread_mutex_lock(&lock) != 0) abort();
  remote_block = medium_target;
  release_worker = 1;
  if (pthread_cond_broadcast(&changed) != 0) abort();
  if (pthread_mutex_unlock(&lock) != 0) abort();
  if (pthread_join(thread, NULL) != 0) abort();
  read_stats(&medium_freed);
  const int medium_survivor_mapped = mi_is_in_heap_region(survivor);
  int medium_survivor_data = 1;
  for (size_t index = 0; index < 32768; index++) {
    if (((const unsigned char*)survivor)[index] != 0x6b) medium_survivor_data = 0;
  }
  mi_collect(true);
  read_stats(&medium_collected);
  mi_free(survivor);
  mi_collect(true);
  read_stats(&medium_terminal);

  snprintf(bin_label, sizeof(bin_label), "  bin%2s  %3zu:", "M", medium_bin);
  printf("medium.warm.usable=%zu\n", warm_usable);
  printf("medium.target.usable=%zu\n", medium_usable);
  printf("medium.target.bin=%zu\n", medium_bin);
  printf("medium.disallow_os_alloc=%ld\n", mi_option_get(mi_option_disallow_os_alloc));
  printf("medium.disallow_arena_alloc=%ld\n", mi_option_get(mi_option_disallow_arena_alloc));
  printf("medium.target.mapped=%d\n", medium_target_mapped);
  printf("medium.survivor.mapped=%d\n", medium_survivor_mapped);
  printf("medium.survivor.data=%d\n", medium_survivor_data);
  show_arena("before", &medium_before);
  show_arena("allocated", &medium_allocated);
  show_arena("terminal", &medium_terminal);
  show_stage("medium.allocated", &medium_allocated, &medium_before, medium_bin);
  show_page_bin("medium.allocated", &medium_allocated, &medium_before, medium_bin);
  show_stage("medium.merged", &medium_merged, &medium_before, medium_bin);
  show_page_bin("medium.merged", &medium_merged, &medium_before, medium_bin);
  show_stage("medium.freed", &medium_freed, &medium_before, medium_bin);
  show_page_bin("medium.freed", &medium_freed, &medium_before, medium_bin);
  show_stage("medium.collected", &medium_collected, &medium_before, medium_bin);
  show_page_bin("medium.collected", &medium_collected, &medium_before, medium_bin);
  show_stage("medium.terminal", &medium_terminal, &medium_before, medium_bin);
  show_page_bin("medium.terminal", &medium_terminal, &medium_before, medium_bin);
  show_worker_row("medium.bin", bin_label);
  show_worker_row("medium.requested", "  malloc req:");
  printf("CRABC_MI_M7_STATISTICS_REMOTE_BIN_TRACE_END\n");
  return 0;
}
