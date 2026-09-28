/* Exercise one true huge page through the public process statistics image. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mimalloc.h"
#include "mimalloc-stats.h"

static void read_stats(mi_stats_t* stats) {
  if (!mi_stats_get(stats)) abort();
}

static void show_huge(const char* name, const mi_stats_t* after, const mi_stats_t* before) {
  printf("%s.huge=%lld,%lld,%lld\n", name,
         (long long)(after->malloc_huge.total - before->malloc_huge.total),
         (long long)(after->malloc_huge.peak - before->malloc_huge.peak),
         (long long)(after->malloc_huge.current - before->malloc_huge.current));
  printf("%s.huge_count=%lld\n", name,
         (long long)(after->malloc_huge_count.total - before->malloc_huge_count.total));
}

int main(void) {
  mi_stats_t_decl(before);
  mi_stats_t_decl(allocated);
  mi_stats_t_decl(freed);
  read_stats(&before);
  void* block = mi_malloc(512 * 1024 + 1);
  if (block == NULL) return 2;
  memset(block, 0x5a, 64);
  const size_t usable = mi_usable_size(block);
  read_stats(&allocated);
  mi_free(block);
  read_stats(&freed);

  printf("CRABC_MI_M7_STATISTICS_HUGE_TRACE_BEGIN\n");
  printf("profile.level=1\n");
  printf("allocation.usable=%zu\n", usable);
  show_huge("allocated", &allocated, &before);
  show_huge("freed", &freed, &before);
  printf("allocated.normal=%lld\n",
         (long long)(allocated.malloc_normal.total - before.malloc_normal.total));
  printf("CRABC_MI_M7_STATISTICS_HUGE_TRACE_END\n");
  return 0;
}
