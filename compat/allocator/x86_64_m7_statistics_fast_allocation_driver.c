/* Compare local normal allocation producers across size-bin boundaries. */
#ifndef CRABC_STAT_LEVEL
#define CRABC_STAT_LEVEL 2
#endif
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

static void show_count(const char* name, const char* field,
                       const mi_stat_count_t* after, const mi_stat_count_t* before) {
  printf("%s.%s=%lld,%lld,%lld\n", name, field,
         (long long)(after->total - before->total),
         (long long)(after->peak - before->peak),
         (long long)(after->current - before->current));
}

static void show_stage(const char* name, const mi_stats_t* after,
                       const mi_stats_t* before, size_t bin) {
  show_count(name, "normal", &after->malloc_normal, &before->malloc_normal);
  show_count(name, "huge", &after->malloc_huge, &before->malloc_huge);
  show_count(name, "requested", &after->malloc_requested, &before->malloc_requested);
  show_count(name, "bin", &after->malloc_bins[bin], &before->malloc_bins[bin]);
  printf("%s.normal_count=%lld\n", name,
         (long long)(after->malloc_normal_count.total - before->malloc_normal_count.total));
  printf("%s.page_bin_current=%lld\n", name,
         (long long)(after->page_bins[bin].current - before->page_bins[bin].current));
  printf("%s.searches=%lld\n", name,
         (long long)(after->page_searches_count.total - before->page_searches_count.total));
  printf("%s.extensions=%lld\n", name,
         (long long)(after->pages_extended.total - before->pages_extended.total));
}

static void run_case(const char* name, size_t request) {
  mi_stats_t_decl(initial);
  mi_stats_t_decl(before);
  mi_stats_t_decl(allocated);
  mi_stats_t_decl(merged);
  mi_stats_t_decl(reset);
  mi_stats_t_decl(freed);
  mi_stats_t_decl(terminal);
  mi_stats_t_decl(final_merged);
  read_stats(&initial);
  void* warm = mi_malloc(request);
  if (warm == NULL) abort();
  memset(warm, 0x37, request);
  const size_t usable = mi_usable_size(warm);
  const size_t bin = bin_for_size(usable);
  void* seed = mi_malloc(request);
  if (seed == NULL) abort();
  memset(seed, 0x6b, usable);
  mi_free(seed);
  mi_thread_stats_print_out(&discard, NULL);
  read_stats(&before);

  void* zeroed = mi_calloc(1, request);
  if (zeroed == NULL) abort();
  int zero_all = 1;
  for (size_t index = 0; index < usable; index++) {
    if (((const unsigned char*)zeroed)[index] != 0) zero_all = 0;
  }
  const int distinct = zeroed != warm;
  read_stats(&allocated);
  mi_thread_stats_print_out(&discard, NULL);
  read_stats(&merged);
  mi_stats_reset();
  read_stats(&reset);
  mi_free(zeroed);
  read_stats(&freed);
  mi_thread_stats_print_out(&discard, NULL);
  read_stats(&final_merged);
  mi_free(warm);
  read_stats(&terminal);

  printf("%s.request=%zu\n", name, request);
  printf("%s.usable=%zu\n", name, usable);
  printf("%s.bin_index=%zu\n", name, bin);
  printf("%s.zero_all=%d\n", name, zero_all);
  printf("%s.distinct=%d\n", name, distinct);
  char stage[80];
  snprintf(stage, sizeof(stage), "%s.prepared", name);
  show_stage(stage, &before, &initial, bin);
  snprintf(stage, sizeof(stage), "%s.allocated", name);
  show_stage(stage, &allocated, &before, bin);
  snprintf(stage, sizeof(stage), "%s.merged", name);
  show_stage(stage, &merged, &before, bin);
  snprintf(stage, sizeof(stage), "%s.reset", name);
  show_stage(stage, &reset, &before, bin);
  snprintf(stage, sizeof(stage), "%s.freed", name);
  show_stage(stage, &freed, &before, bin);
  snprintf(stage, sizeof(stage), "%s.final_merged", name);
  show_stage(stage, &final_merged, &before, bin);
  snprintf(stage, sizeof(stage), "%s.terminal", name);
  show_stage(stage, &terminal, &before, bin);
}

int main(void) {
  mi_stats_reset();
  printf("CRABC_MI_M7_STATISTICS_FAST_ALLOCATION_TRACE_BEGIN\n");
  printf("profile.level=%d\n", CRABC_STAT_LEVEL);
  for (size_t request = 0; request < sizeof(void*); request++) {
    char name[80];
    snprintf(name, sizeof(name), "subword%zu", request);
    run_case(name, request);
  }
  size_t previous = 0;
  for (size_t bin = 1; bin < MI_BIN_HUGE; bin++) {
    const size_t size = mi_stats_get_bin_size(bin);
    if (size > 512u * 1024u) break;
    printf("geometry.bin%zu=%zu\n", bin, size);
    char name[80];
    snprintf(name, sizeof(name), "bin%zu.lower", bin);
    run_case(name, previous + 1);
    snprintf(name, sizeof(name), "bin%zu.middle", bin);
    run_case(name, previous + (size - previous) / 2 + 1);
    snprintf(name, sizeof(name), "bin%zu.upper", bin);
    run_case(name, size);
    previous = size;
  }
  printf("CRABC_MI_M7_STATISTICS_FAST_ALLOCATION_TRACE_END\n");
  return 0;
}
