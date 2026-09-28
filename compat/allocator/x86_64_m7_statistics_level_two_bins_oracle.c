/* Exercise nonzero per-bin output after separate source owner merges. The
   synthetic records isolate merge and final rendering from allocation hooks. */
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

static const char* bin_row(unsigned index) {
  char label[32];
  const size_t unit = _mi_bin_size((uint8_t)index);
  const char* kind = (unit <= MI_SMALL_MAX_OBJ_SIZE ? "S" :
                      (unit <= MI_MEDIUM_MAX_OBJ_SIZE ? "M" :
                       (unit <= MI_LARGE_MAX_OBJ_SIZE ? "L" : "H")));
  snprintf(label, sizeof(label), "  bin%2s  %3u:", kind, index);
  return strstr(printed, label);
}

static void show_row(const char* scenario, unsigned index) {
  const char* start = bin_row(index);
  if (start == NULL) {
    printf("%s.bin%u=absent\n", scenario, index);
    return;
  }
  const char* end = strchr(start, '\n');
  if (end == NULL) abort();
  printf("%s.bin%u=%.*s\n", scenario, index, (int)(end - start), start);
}

static void show_output(const char* scenario, const mi_stats_t* stats) {
  printed_length = 0;
  printed[0] = 0;
  _mi_stats_print("subproc", 7, stats, &capture, NULL);
  const char* first = bin_row(8);
  const char* second = bin_row(40);
  printf("%s.order=%s\n", scenario,
         first == NULL && second == NULL ? "none" :
         first != NULL && second == NULL ? "8" :
         first == NULL && second != NULL ? "40" :
         first < second ? "8,40" : "40,8");
  show_row(scenario, 8);
  show_row(scenario, 9);
  show_row(scenario, 40);
}

static void set_count(mi_stat_count_t* count, long long peak, long long total, long long current) {
  count->peak = peak;
  count->total = total;
  count->current = current;
}

int main(void) {
  mi_stats_t_decl(process);
  mi_stats_t_decl(first_owner);
  mi_stats_t_decl(second_owner);
  mi_stats_t_decl(freed_owner);

  printf("CRABC_MI_M7_STATISTICS_LEVEL_TWO_BINS_TRACE_BEGIN\n");
  printf("profile.level=2\n");
  show_output("empty", &process);

  set_count(&first_owner.malloc_normal, 64, 64, 64);
  set_count(&first_owner.malloc_bins[8], 2, 3, 1);
  _mi_stats_merge_into(&process, &first_owner);
  show_count("first.source_bin8_reset", &first_owner.malloc_bins[8]);
  show_count("first.process_bin8", &process.malloc_bins[8]);
  show_output("first", &process);

  set_count(&second_owner.malloc_bins[8], 4, 5, 2);
  set_count(&second_owner.malloc_bins[40], 2, 3, 1);
  _mi_stats_merge_into(&process, &second_owner);
  show_count("merged.source_bin8_reset", &second_owner.malloc_bins[8]);
  show_count("merged.source_bin40_reset", &second_owner.malloc_bins[40]);
  show_count("merged.process_bin8", &process.malloc_bins[8]);
  show_count("merged.process_bin40", &process.malloc_bins[40]);
  show_output("merged", &process);

  set_count(&freed_owner.malloc_normal, 0, 0, -64);
  set_count(&freed_owner.malloc_bins[8], 0, 0, -3);
  set_count(&freed_owner.malloc_bins[40], 0, 0, -1);
  _mi_stats_merge_into(&process, &freed_owner);
  show_count("freed.source_bin8_reset", &freed_owner.malloc_bins[8]);
  show_count("freed.source_bin40_reset", &freed_owner.malloc_bins[40]);
  show_count("freed.process_bin8", &process.malloc_bins[8]);
  show_count("freed.process_bin40", &process.malloc_bins[40]);
  show_output("freed", &process);
  printf("CRABC_MI_M7_STATISTICS_LEVEL_TWO_BINS_TRACE_END\n");
  return 0;
}
