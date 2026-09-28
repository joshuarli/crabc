/* Exercise the source's requested-size final row after separate owner merges.
   Synthetic counts isolate merge and rendering from unfinished allocation
   producers while preserving the pinned MI_STAT=2 record and print paths. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "static.c"

static char printed[16384];
static size_t printed_length;

static void capture(const char* message, void* argument) {
  (void)argument;
  const size_t length = strlen(message);
  if (length >= sizeof(printed) - printed_length) abort();
  memcpy(printed + printed_length, message, length + 1);
  printed_length += length;
}

static void show_count(const char* name, const mi_stat_count_t* count) {
  printf("%s=%lld,%lld,%lld\n", name, (long long)count->peak,
         (long long)count->total, (long long)count->current);
}

static void show_row(const char* scenario, const char* label) {
  const char* key = (strcmp(label, "malloc req") == 0 ? "malloc_req" : label);
  char prefix[32];
  snprintf(prefix, sizeof(prefix), "  %-10s:", label);
  const char* start = strstr(printed, prefix);
  if (start == NULL) {
    printf("%s.%s=absent\n", scenario, key);
    return;
  }
  const char* end = strchr(start, '\n');
  if (end == NULL) abort();
  printf("%s.%s=%.*s\n", scenario, key, (int)(end - start), start);
}

static void show_output(const char* scenario, const mi_stats_t* stats) {
  printed_length = 0;
  printed[0] = 0;
  _mi_stats_print("subproc", 7, stats, &capture, NULL);
  const char* header = strstr(printed, " blocks     ");
  printf("%s.blocks=%d\n", scenario, header != NULL);
  show_row(scenario, "binned");
  show_row(scenario, "huge");
  show_row(scenario, "total");
  show_row(scenario, "malloc req");
}

static void set_count(mi_stat_count_t* count, long long peak, long long total, long long current) {
  count->peak = peak;
  count->total = total;
  count->current = current;
}

int main(void) {
  mi_stats_t_decl(process);
  mi_stats_t_decl(normal_owner);
  mi_stats_t_decl(huge_owner);
  mi_stats_t_decl(freed_owner);

  printf("CRABC_MI_M7_STATISTICS_LEVEL_TWO_REQUESTED_TRACE_BEGIN\n");
  printf("profile.level=2\n");
  show_output("empty", &process);

  set_count(&normal_owner.malloc_normal, 160, 320, 96);
  set_count(&normal_owner.malloc_requested, 140, 280, 70);
  normal_owner.malloc_normal_count.total = 2;
  _mi_stats_merge_into(&process, &normal_owner);
  show_count("normal.source_requested_reset", &normal_owner.malloc_requested);
  show_count("normal.process_requested", &process.malloc_requested);
  printf("normal.process_count=%lld\n", (long long)process.malloc_normal_count.total);
  show_output("normal", &process);

  set_count(&huge_owner.malloc_huge, 3072, 4096, 2048);
  set_count(&huge_owner.malloc_requested, 3000, 4000, 2000);
  huge_owner.malloc_huge_count.total = 1;
  _mi_stats_merge_into(&process, &huge_owner);
  show_count("live.source_requested_reset", &huge_owner.malloc_requested);
  show_count("live.process_requested", &process.malloc_requested);
  printf("live.process_count=%lld,%lld\n", (long long)process.malloc_normal_count.total,
         (long long)process.malloc_huge_count.total);
  show_output("live", &process);

  set_count(&freed_owner.malloc_normal, 0, 0, -96);
  set_count(&freed_owner.malloc_huge, 0, 0, -2048);
  set_count(&freed_owner.malloc_requested, 0, 0, -2070);
  _mi_stats_merge_into(&process, &freed_owner);
  show_count("freed.source_requested_reset", &freed_owner.malloc_requested);
  show_count("freed.process_requested", &process.malloc_requested);
  show_output("freed", &process);
  printf("CRABC_MI_M7_STATISTICS_LEVEL_TWO_REQUESTED_TRACE_END\n");
  return 0;
}
