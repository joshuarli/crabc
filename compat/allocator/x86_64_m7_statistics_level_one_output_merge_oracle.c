/* Compare the source's level-one count merge and final malloc rows on
   synthetic owner records. Synthetic huge counts exercise display composition
   without claiming that a production huge allocation producer is present. */
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
  char prefix[32];
  snprintf(prefix, sizeof(prefix), "  %-10s:", label);
  const char* start = strstr(printed, prefix);
  if (start == NULL) {
    printf("%s.%s=absent\n", scenario, label);
    return;
  }
  const char* end = strchr(start, '\n');
  if (end == NULL) abort();
  printf("%s.%s=%.*s\n", scenario, label, (int)(end - start), start);
}

static void show_output(const char* scenario, const mi_stats_t* stats) {
  printed_length = 0;
  printed[0] = 0;
  _mi_stats_print("subproc", 7, stats, &capture, NULL);
  show_row(scenario, "binned");
  show_row(scenario, "huge");
  show_row(scenario, "total");
}

static void set_count(mi_stat_count_t* count, long long peak, long long total, long long current) {
  count->peak = peak;
  count->total = total;
  count->current = current;
}

int main(void) {
  mi_stats_t_decl(process);
  mi_stats_t_decl(normal_first);
  mi_stats_t_decl(huge_second);
  mi_stats_t_decl(mixed_third);
  mi_stats_t_decl(freed_fourth);

  printf("CRABC_MI_M7_STATISTICS_LEVEL_ONE_OUTPUT_MERGE_TRACE_BEGIN\n");
  printf("profile.level=1\n");
  show_output("empty", &process);

  set_count(&normal_first.malloc_normal, 160, 320, 96);
  _mi_stats_merge_into(&process, &normal_first);
  show_count("normal.source_reset", &normal_first.malloc_normal);
  show_count("normal.process", &process.malloc_normal);
  show_output("normal", &process);

  set_count(&huge_second.malloc_huge, 3072, 4096, 2048);
  _mi_stats_merge_into(&process, &huge_second);
  show_count("huge.source_reset", &huge_second.malloc_huge);
  show_count("huge.process", &process.malloc_huge);
  show_output("huge", &process);

  set_count(&mixed_third.malloc_normal, 224, 256, 128);
  set_count(&mixed_third.malloc_huge, 1024, 2048, 512);
  _mi_stats_merge_into(&process, &mixed_third);
  show_count("mixed.source_normal_reset", &mixed_third.malloc_normal);
  show_count("mixed.source_huge_reset", &mixed_third.malloc_huge);
  show_count("mixed.process_normal", &process.malloc_normal);
  show_count("mixed.process_huge", &process.malloc_huge);
  show_output("mixed", &process);

  set_count(&freed_fourth.malloc_normal, 0, 0, -224);
  set_count(&freed_fourth.malloc_huge, 0, 0, -2560);
  _mi_stats_merge_into(&process, &freed_fourth);
  show_count("freed.source_normal_reset", &freed_fourth.malloc_normal);
  show_count("freed.source_huge_reset", &freed_fourth.malloc_huge);
  show_count("freed.process_normal", &process.malloc_normal);
  show_count("freed.process_huge", &process.malloc_huge);
  show_output("freed", &process);
  printf("CRABC_MI_M7_STATISTICS_LEVEL_ONE_OUTPUT_MERGE_TRACE_END\n");
  return 0;
}
