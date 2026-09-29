/* Exercise repeated 8 KiB regular-page extensions through public statistics. */
#include <stdio.h>
#include <stdlib.h>
#include "mimalloc.h"
#include "mimalloc-stats.h"

#define BLOCK_COUNT 48

static void* blocks[BLOCK_COUNT];
static mi_stats_t before;

static void show_count(const char* stage, const char* field,
                       const mi_stat_count_t* after, const mi_stat_count_t* old) {
  printf("%s.%s=%lld,%lld,%lld\n", stage, field,
         (long long)(after->total - old->total),
         (long long)(after->peak - old->peak),
         (long long)(after->current - old->current));
}

static void show_stage(const char* stage, size_t bin) {
  mi_stats_t_decl(now);
  if (!mi_stats_get(&now)) abort();
  printf("%s.extensions=%lld\n", stage,
         (long long)(now.pages_extended.total - before.pages_extended.total));
  show_count(stage, "page_committed", &now.page_committed, &before.page_committed);
  show_count(stage, "pages", &now.pages, &before.pages);
  show_count(stage, "page_bin", &now.page_bins[bin], &before.page_bins[bin]);
  show_count(stage, "normal", &now.malloc_normal, &before.malloc_normal);
  show_count(stage, "bin", &now.malloc_bins[bin], &before.malloc_bins[bin]);
  show_count(stage, "requested", &now.malloc_requested, &before.malloc_requested);
}

int main(void) {
  mi_stats_init(&before);
  if (!mi_stats_get(&before)) abort();
  printf("CRABC_MI_M7_SMALL_PAGE_EXTENSION_BEGIN\n");
  printf("request=8192\n");
  size_t bin = 0;
  for (size_t i = 0; i < BLOCK_COUNT; i++) {
    blocks[i] = mi_malloc(8192);
    if (blocks[i] == NULL || mi_usable_size(blocks[i]) != 8192) abort();
    if (i == 0) {
      for (size_t candidate = 1; candidate < MI_BIN_HUGE; candidate++) {
        if (mi_stats_get_bin_size(candidate) == 8192) bin = candidate;
      }
      if (bin == 0) abort();
      printf("bin.index=%zu\n", bin);
      show_stage("one", bin);
    }
    if (i == 7) show_stage("eight", bin);
    if (i == 15) show_stage("sixteen", bin);
    if (i == 31) show_stage("thirty_two", bin);
    if (i == 47) show_stage("forty_eight", bin);
  }
  for (size_t i = 0; i < BLOCK_COUNT; i++) mi_free(blocks[i]);
  show_stage("freed", bin);
  printf("CRABC_MI_M7_SMALL_PAGE_EXTENSION_END\n");
  return 0;
}
