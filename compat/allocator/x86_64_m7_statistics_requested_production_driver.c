/* Compare requested-size and bin producers on ordinary and OS-aligned pages. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mimalloc.h"
#include "mimalloc-stats.h"

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

static void show_count(const char* stage, const char* field,
                       const mi_stat_count_t* value, const mi_stat_count_t* before) {
  printf("%s.%s=%lld,%lld,%lld\n", stage, field,
         (long long)(value->total - before->total),
         (long long)(value->peak - before->peak),
         (long long)(value->current - before->current));
}

static void show_stage(const char* name, const mi_stats_t* stats,
                       const mi_stats_t* before, size_t ordinary_bin, size_t aligned_bin) {
  show_count(name, "requested", &stats->malloc_requested, &before->malloc_requested);
  show_count(name, "ordinary_bin", &stats->malloc_bins[ordinary_bin], &before->malloc_bins[ordinary_bin]);
  show_count(name, "aligned_bin", &stats->malloc_bins[aligned_bin], &before->malloc_bins[aligned_bin]);
  printf("%s.normal_count=%lld\n", name,
         (long long)(stats->malloc_normal_count.total - before->malloc_normal_count.total));
  printf("%s.huge_count=%lld\n", name,
         (long long)(stats->malloc_huge_count.total - before->malloc_huge_count.total));
}

int main(void) {
  const size_t ordinary_request = 63;
  const size_t aligned_request = 100;
  const size_t alignment = 1u << 20;
  mi_stats_t_decl(before);
  mi_stats_t_decl(ordinary);
  mi_stats_t_decl(ordinary_merged);
  mi_stats_t_decl(aligned);
  mi_stats_t_decl(aligned_merged);
  mi_stats_t_decl(ordinary_freed);
  mi_stats_t_decl(aligned_freed);
  mi_stats_t_decl(final_merged);
  mi_stats_reset();
  read_stats(&before);

  void* first = mi_malloc(ordinary_request);
  if (first == NULL) return 2;
  memset(first, 0x5a, ordinary_request);
  const size_t ordinary_usable = mi_usable_size(first);
  read_stats(&ordinary);
  mi_thread_stats_print_out(&discard, NULL);
  read_stats(&ordinary_merged);

  void* second = mi_malloc_aligned(aligned_request, alignment);
  if (second == NULL) return 3;
  memset(second, 0xa5, aligned_request);
  const size_t aligned_usable = mi_usable_size(second);
  const int aligned_pointer = (((uintptr_t)second & (alignment - 1)) == 0);
  read_stats(&aligned);
  mi_thread_stats_print_out(&discard, NULL);
  read_stats(&aligned_merged);

  mi_free(first);
  read_stats(&ordinary_freed);
  mi_free(second);
  read_stats(&aligned_freed);
  mi_thread_stats_print_out(&discard, NULL);
  read_stats(&final_merged);

  const size_t ordinary_bin = bin_for_size(ordinary_usable);
  const size_t aligned_bin = bin_for_size(aligned_usable);
  printf("CRABC_MI_M7_STATISTICS_REQUESTED_PRODUCTION_TRACE_BEGIN\n");
  printf("profile.level=2\n");
  printf("ordinary.request=%zu\n", ordinary_request);
  printf("ordinary.usable=%zu\n", ordinary_usable);
  printf("ordinary.bin=%zu\n", ordinary_bin);
  printf("aligned.request=%zu\n", aligned_request);
  printf("aligned.usable=%zu\n", aligned_usable);
  printf("aligned.bin=%zu\n", aligned_bin);
  printf("aligned.pointer=%d\n", aligned_pointer);
  show_stage("ordinary", &ordinary, &before, ordinary_bin, aligned_bin);
  show_stage("ordinary_merged", &ordinary_merged, &before, ordinary_bin, aligned_bin);
  show_stage("aligned", &aligned, &before, ordinary_bin, aligned_bin);
  show_stage("aligned_merged", &aligned_merged, &before, ordinary_bin, aligned_bin);
  show_stage("ordinary_freed", &ordinary_freed, &before, ordinary_bin, aligned_bin);
  show_stage("aligned_freed", &aligned_freed, &before, ordinary_bin, aligned_bin);
  show_stage("final_merged", &final_merged, &before, ordinary_bin, aligned_bin);
  printf("CRABC_MI_M7_STATISTICS_REQUESTED_PRODUCTION_TRACE_END\n");
  return 0;
}
