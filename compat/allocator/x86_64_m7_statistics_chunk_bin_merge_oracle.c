/* Exercise the complete chunk-bin tail through two source owner merges.
   Source bitmap events normally write the subprocess, but the statistics
   merge itself must also preserve every record in an owner image. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <stdio.h>
#include "static.c"

static void show(const char* stage, const mi_stats_t* stats) {
  for (size_t index = 0; index < MI_CBIN_COUNT; index++) {
    const mi_stat_count_t* count = &stats->chunk_bins[index];
    printf("%s.bin%zu=%lld,%lld,%lld\n", stage, index,
           (long long)count->peak, (long long)count->total,
           (long long)count->current);
  }
}

int main(void) {
  mi_stats_t_decl(process);
  mi_stats_t_decl(first);
  mi_stats_t_decl(second);

  first.chunk_bins[0].peak = 3;
  first.chunk_bins[0].total = 3;
  first.chunk_bins[0].current = 3;
  first.chunk_bins[4].peak = 2;
  first.chunk_bins[4].total = 2;
  first.chunk_bins[4].current = 2;
  first.chunk_bins[5].peak = 7;
  first.chunk_bins[5].total = 7;
  first.chunk_bins[5].current = 7;

  second.chunk_bins[0].peak = 5;
  second.chunk_bins[0].total = 5;
  second.chunk_bins[0].current = 3;
  second.chunk_bins[4].current = -1;
  second.chunk_bins[5].current = -2;

  printf("CRABC_MI_M7_STATISTICS_CHUNK_BIN_MERGE_TRACE_BEGIN\n");
  show("empty", &process);
  _mi_stats_merge_into(&process, &first);
  show("first.process", &process);
  show("first.source_reset", &first);
  _mi_stats_merge_into(&process, &second);
  show("second.process", &process);
  show("second.source_reset", &second);
  printf("CRABC_MI_M7_STATISTICS_CHUNK_BIN_MERGE_TRACE_END\n");
  return 0;
}
