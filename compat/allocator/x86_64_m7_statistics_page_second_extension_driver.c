/* Follow one regular page through repeated free-list extension and final frees. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "mimalloc.h"
#include "mimalloc-stats.h"

#define BLOCK_COUNT 260
/* A regular page occupies one aligned 64 KiB arena slice. */
#define PAGE_SLICE_SHIFT 16

static void* blocks[BLOCK_COUNT];
static mi_stats_t before;

static void show_stage(const char* name) {
  mi_stats_t_decl(now);
  if (!mi_stats_get(&now)) abort();
  printf("%s.pages_extended=%lld\n", name,
         (long long)(now.pages_extended.total - before.pages_extended.total));
  printf("%s.page_committed=%lld,%lld,%lld\n", name,
         (long long)(now.page_committed.total - before.page_committed.total),
         (long long)(now.page_committed.peak - before.page_committed.peak),
         (long long)(now.page_committed.current - before.page_committed.current));
  printf("%s.pages=%lld,%lld,%lld\n", name,
         (long long)(now.pages.total - before.pages.total),
         (long long)(now.pages.peak - before.pages.peak),
         (long long)(now.pages.current - before.pages.current));
}

int main(void) {
  mi_stats_init(&before);
  if (!mi_stats_get(&before)) abort();
  printf("CRABC_MI_M7_STATISTICS_PAGE_SECOND_EXTENSION_TRACE_BEGIN\n");
  printf("profile.level=1\n");
  int same_slice = 1;
  for (size_t i = 0; i < BLOCK_COUNT; i++) {
    blocks[i] = mi_malloc(64);
    if (blocks[i] == NULL || mi_usable_size(blocks[i]) != 64) abort();
    if (i != 0 && ((uintptr_t)blocks[i] >> PAGE_SLICE_SHIFT) !=
                  ((uintptr_t)blocks[0] >> PAGE_SLICE_SHIFT)) same_slice = 0;
    if (i == 0) show_stage("one");
    if (i == 127) show_stage("one_twenty_eight");
    if (i == 128) show_stage("one_twenty_nine");
    if (i == 259) show_stage("two_sixty");
  }
  printf("page.same_slice=%d\n", same_slice);
  for (size_t i = 0; i < BLOCK_COUNT; i++) mi_free(blocks[i]);
  show_stage("freed");
  printf("CRABC_MI_M7_STATISTICS_PAGE_SECOND_EXTENSION_TRACE_END\n");
  return 0;
}
