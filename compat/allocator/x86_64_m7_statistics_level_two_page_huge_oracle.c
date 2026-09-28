/* Compare independent huge and page section guards after owner merges.
   Synthetic records isolate statistics merge and output from producers. */
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
  size_t length = strlen(message);
  if (length >= sizeof(printed) - printed_length) abort();
  memcpy(printed + printed_length, message, length + 1);
  printed_length += length;
}

static void show_count(const char* name, const mi_stat_count_t* count) {
  printf("%s=%lld,%lld,%lld\n", name, (long long)count->peak,
         (long long)count->total, (long long)count->current);
}

static void set_count(mi_stat_count_t* count, long long peak, long long total, long long current) {
  count->peak = peak;
  count->total = total;
  count->current = current;
}

static const char* row(const char* label) {
  char prefix[32];
  snprintf(prefix, sizeof(prefix), "  %-10s:", label);
  return strstr(printed, prefix);
}

static void show_row(const char* scenario, const char* label) {
  const char* start = row(label);
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
  const char* blocks = strstr(printed, " blocks    ");
  const char* page_header = strstr(printed, " pages     ");
  printf("%s.order=%s\n", scenario, blocks == NULL && page_header == NULL ? "none" :
         blocks != NULL && page_header == NULL ? "blocks" :
         blocks == NULL && page_header != NULL ? "pages" :
         blocks < page_header ? "blocks,pages" : "pages,blocks");
  show_row(scenario, "huge");
  show_row(scenario, "touched");
  show_row(scenario, "pages");
  show_row(scenario, "abandoned");
}

int main(void) {
  mi_stats_t_decl(process);
  mi_stats_t_decl(huge_owner);
  mi_stats_t_decl(page_owner);
  mi_stats_t_decl(freed_owner);

  printf("CRABC_MI_M7_STATISTICS_LEVEL_TWO_PAGE_HUGE_TRACE_BEGIN\n");
  printf("profile.level=2\n");
  show_output("empty", &process);

  set_count(&huge_owner.malloc_huge, 4096, 8192, 4096);
  huge_owner.malloc_huge_count.total = 2;
  _mi_stats_merge_into(&process, &huge_owner);
  show_count("huge.source_reset", &huge_owner.malloc_huge);
  show_count("huge.process", &process.malloc_huge);
  show_output("huge", &process);

  set_count(&page_owner.malloc_huge, 6144, 12288, 2048);
  set_count(&page_owner.pages, 4, 6, 3);
  set_count(&page_owner.page_committed, 16384, 24576, 12288);
  set_count(&page_owner.pages_abandoned, 2, 3, 1);
  page_owner.malloc_huge_count.total = 1;
  _mi_stats_merge_into(&process, &page_owner);
  show_count("live.source_huge_reset", &page_owner.malloc_huge);
  show_count("live.source_pages_reset", &page_owner.pages);
  show_count("live.process_huge", &process.malloc_huge);
  show_count("live.process_pages", &process.pages);
  show_count("live.process_touched", &process.page_committed);
  show_count("live.process_abandoned", &process.pages_abandoned);
  show_output("live", &process);

  set_count(&freed_owner.malloc_huge, 0, 0, -6144);
  set_count(&freed_owner.pages, 0, 0, -3);
  set_count(&freed_owner.page_committed, 0, 0, -12288);
  set_count(&freed_owner.pages_abandoned, 0, 0, -1);
  _mi_stats_merge_into(&process, &freed_owner);
  show_count("freed.source_huge_reset", &freed_owner.malloc_huge);
  show_count("freed.source_pages_reset", &freed_owner.pages);
  show_count("freed.process_huge", &process.malloc_huge);
  show_count("freed.process_pages", &process.pages);
  show_count("freed.process_touched", &process.page_committed);
  show_count("freed.process_abandoned", &process.pages_abandoned);
  show_output("freed", &process);
  printf("CRABC_MI_M7_STATISTICS_LEVEL_TWO_PAGE_HUGE_TRACE_END\n");
  return 0;
}
