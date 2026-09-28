/* Exercise the first page extension through the public statistics image.
   The before/after delta excludes startup reservations and Theap setup. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mimalloc.h"
#include "mimalloc-stats.h"

static void read_stats(mi_stats_t* stats) {
  if (!mi_stats_get(stats)) abort();
}

static void show_count(const char* name, const mi_stat_count_t* after, const mi_stat_count_t* before) {
  printf("%s=%lld,%lld,%lld\n", name,
         (long long)(after->total - before->total),
         (long long)(after->peak - before->peak),
         (long long)(after->current - before->current));
}

int main(void) {
  mi_stats_t_decl(before);
  mi_stats_t_decl(allocated);
  mi_stats_t_decl(freed);
  read_stats(&before);

  void* block = mi_malloc(64);
  if (block == NULL) return 2;
  memset(block, 0x5a, 64);
  const size_t usable = mi_usable_size(block);
  read_stats(&allocated);
  mi_free(block);
  read_stats(&freed);

  printf("CRABC_MI_M7_STATISTICS_PAGE_EXTEND_TRACE_BEGIN\n");
  printf("profile.level=1\n");
  printf("allocation.usable=%zu\n", usable);
  printf("allocated.pages_extended=%lld\n",
         (long long)(allocated.pages_extended.total - before.pages_extended.total));
  show_count("allocated.page_committed", &allocated.page_committed, &before.page_committed);
  show_count("allocated.pages", &allocated.pages, &before.pages);
  printf("freed.pages_extended=%lld\n",
         (long long)(freed.pages_extended.total - before.pages_extended.total));
  show_count("freed.page_committed", &freed.page_committed, &before.page_committed);
  printf("CRABC_MI_M7_STATISTICS_PAGE_EXTEND_TRACE_END\n");
  return 0;
}
