/* Exercise the first optional statistics profile through the public C API. */
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mimalloc.h"
#include "mimalloc-stats.h"

static char printed[16384];
static size_t printed_length;

static void capture(const char* message, void* argument) {
  (void)argument;
  const size_t length = strlen(message);
  if (length >= sizeof(printed) - printed_length) abort();
  memcpy(printed + printed_length, message, length + 1);
  printed_length += length;
}

static void read_stats(mi_stats_t* stats) {
  if (!mi_stats_get(stats)) abort();
}

static bool printed_line_has(const char* label, const char* fragment) {
  const char* line = strstr(printed, label);
  if (line == NULL) return false;
  const char* end = strchr(line, '\n');
  if (end == NULL) return false;
  const char* content = strstr(line, fragment);
  return content != NULL && content < end;
}

static void normal_delta(const char* name, const mi_stats_t* stats, const mi_stats_t* before) {
  printf("%s=%lld,%lld,%lld\n", name,
         (long long)(stats->malloc_normal.total - before->malloc_normal.total),
         (long long)(stats->malloc_normal.peak - before->malloc_normal.peak),
         (long long)(stats->malloc_normal.current - before->malloc_normal.current));
}

int main(void) {
  mi_stats_t_decl(before);
  mi_stats_t_decl(allocated);
  mi_stats_t_decl(merged);
  mi_stats_t_decl(freed);
  read_stats(&before);

  void* block = mi_malloc(64);
  if (block == NULL) return 2;
  memset(block, 0x5a, 64);
  const size_t usable = mi_usable_size(block);
  read_stats(&allocated);
  mi_stats_reset();
  read_stats(&merged);
  mi_stats_print_out(&capture, NULL);
  const bool live_binned = printed_line_has("binned", "not all freed");
  const bool live_total = printed_line_has("total", ":");
  printed_length = 0;
  printed[0] = 0;
  mi_free(block);
  read_stats(&freed);
  mi_stats_print_out(&capture, NULL);
  const bool freed_binned = printed_line_has("binned", "ok");
  const bool freed_total = printed_line_has("total", "ok");

  printf("CRABC_MI_M7_STATISTICS_LEVEL_ONE_TRACE_BEGIN\n");
  printf("profile.level=1\n");
  printf("allocation.usable=%zu\n", usable);
  normal_delta("allocated.normal", &allocated, &before);
  normal_delta("merged.normal", &merged, &before);
  normal_delta("freed.normal", &freed, &before);
  printf("print.live_binned=%d\n", live_binned);
  printf("print.live_total=%d\n", live_total);
  printf("print.freed_binned=%d\n", freed_binned);
  printf("print.freed_total=%d\n", freed_total);
  printf("CRABC_MI_M7_STATISTICS_LEVEL_ONE_TRACE_END\n");
  return 0;
}
