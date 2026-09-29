#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "mimalloc.h"
#include "mimalloc-stats.h"

static int fail_next_unmap;
static int failed_unmaps;
static int release_warnings;
static uintptr_t target_block;
static mi_stats_t before;

/* Reject one allocator release after the page has been allocated. Other
   unmaps, including startup and alignment cleanup, reach the kernel. */
int crabc_fault_munmap(void* address, size_t size) {
  uintptr_t base = (uintptr_t)address;
  if (fail_next_unmap && target_block >= base && target_block - base < size) {
    fail_next_unmap = 0;
    failed_unmaps++;
    errno = ENOMEM;
    return -1;
  }
  return (int)syscall(SYS_munmap, address, size);
}

static void output(const char* message, void* argument) {
  (void)argument;
  if (strstr(message, "unable to free OS memory") != NULL) release_warnings++;
}

static void show(const char* stage) {
  mi_stats_t_decl(now);
  if (!mi_stats_get(&now)) abort();
  printf("%s.pages=%lld,%lld,%lld\n", stage,
         (long long)(now.pages.total - before.pages.total),
         (long long)(now.pages.peak - before.pages.peak),
         (long long)(now.pages.current - before.pages.current));
  printf("%s.reserved=%lld,%lld,%lld\n", stage,
         (long long)(now.reserved.total - before.reserved.total),
         (long long)(now.reserved.peak - before.reserved.peak),
         (long long)(now.reserved.current - before.reserved.current));
  printf("%s.committed=%lld,%lld,%lld\n", stage,
         (long long)(now.committed.total - before.committed.total),
         (long long)(now.committed.peak - before.committed.peak),
         (long long)(now.committed.current - before.committed.current));
  printf("%s.normal=%lld,%lld,%lld\n", stage,
         (long long)(now.malloc_normal.total - before.malloc_normal.total),
         (long long)(now.malloc_normal.peak - before.malloc_normal.peak),
         (long long)(now.malloc_normal.current - before.malloc_normal.current));
  for (size_t i = 0; i <= MI_BIN_HUGE; i++) {
    if (now.page_bins[i].total > before.page_bins[i].total) {
      printf("%s.page_bin=%zu:%lld,%lld\n", stage, i,
             (long long)(now.page_bins[i].total - before.page_bins[i].total),
             (long long)(now.page_bins[i].current - before.page_bins[i].current));
    }
  }
  printf("%s.warnings=%d\n", stage, release_warnings);
  printf("%s.failures=%d\n", stage, failed_unmaps);
}

int main(void) {
  mi_option_set(mi_option_disallow_arena_alloc, 1);
  mi_option_set(mi_option_show_errors, 1);
  mi_register_output(output, NULL);
  void* warm = mi_malloc(100000);
  if (warm == NULL) abort();
  mi_free(warm);
  mi_collect(true);
  mi_stats_init(&before);
  if (!mi_stats_get(&before)) abort();
  void* block = mi_malloc(100000);
  if (block == NULL) abort();
  target_block = (uintptr_t)block;
  printf("CRABC_MI_M7_PAGE_FAILURE_STATS_TRACE_BEGIN\n");
  printf("profile.level=2\n");
  printf("profile.disallow_arena=%ld\n", mi_option_get(mi_option_disallow_arena_alloc));
  show("allocated");
  mi_free(block);
  show("freed");
  fail_next_unmap = 1;
  mi_collect(true);
  show("failed_release");
  printf("CRABC_MI_M7_PAGE_FAILURE_STATS_TRACE_END\n");
  return 0;
}
