#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "mimalloc.h"
#include "mimalloc-stats.h"

static int fail_next_commit;
static int failed_commits;
static int commit_warnings;
static void* blocks[130];
static mi_stats_t before;

/* The allocator's primitive reaches this renamed mprotect symbol. The hook
   rejects exactly the first write-enable after it is armed, leaving later
   commits to the real kernel syscall. */
int crabc_fault_mprotect(void* address, size_t size, int protection) {
  if (fail_next_commit && protection == (PROT_READ | PROT_WRITE)) {
    fail_next_commit = 0;
    failed_commits++;
    errno = ENOMEM;
    return -1;
  }
  return (int)syscall(SYS_mprotect, address, size, protection);
}

static void output(const char* message, void* argument) {
  (void)argument;
  if (strstr(message, "cannot commit OS memory") != NULL) commit_warnings++;
}

static void show(const char* stage) {
  mi_stats_t_decl(now);
  if (!mi_stats_get(&now)) abort();
  printf("%s.pages_extended=%lld\n", stage, (long long)(now.pages_extended.total - before.pages_extended.total));
  printf("%s.page_committed=%lld,%lld,%lld\n", stage,
         (long long)(now.page_committed.total - before.page_committed.total),
         (long long)(now.page_committed.peak - before.page_committed.peak),
         (long long)(now.page_committed.current - before.page_committed.current));
  printf("%s.pages=%lld,%lld,%lld\n", stage,
         (long long)(now.pages.total - before.pages.total),
         (long long)(now.pages.peak - before.pages.peak),
         (long long)(now.pages.current - before.pages.current));
  printf("%s.requested=%lld,%lld,%lld\n", stage,
         (long long)(now.malloc_requested.total - before.malloc_requested.total),
         (long long)(now.malloc_requested.peak - before.malloc_requested.peak),
         (long long)(now.malloc_requested.current - before.malloc_requested.current));
  printf("%s.normal=%lld,%lld,%lld\n", stage,
         (long long)(now.malloc_normal.total - before.malloc_normal.total),
         (long long)(now.malloc_normal.peak - before.malloc_normal.peak),
         (long long)(now.malloc_normal.current - before.malloc_normal.current));
  for (size_t i = 0; i <= MI_BIN_HUGE; i++) {
    if (now.malloc_bins[i].total > before.malloc_bins[i].total) {
      printf("%s.bin=%zu:%lld,%lld,%lld\n", stage, i,
             (long long)(now.malloc_bins[i].total - before.malloc_bins[i].total),
             (long long)(now.malloc_bins[i].peak - before.malloc_bins[i].peak),
             (long long)(now.malloc_bins[i].current - before.malloc_bins[i].current));
    }
    if (now.page_bins[i].total > before.page_bins[i].total) {
      printf("%s.page_bin=%zu:%lld,%lld\n", stage, i,
             (long long)(now.page_bins[i].total - before.page_bins[i].total),
             (long long)(now.page_bins[i].current - before.page_bins[i].current));
    }
  }
  printf("%s.commit_calls=%lld\n", stage, (long long)(now.commit_calls.total - before.commit_calls.total));
  printf("%s.warnings=%d\n", stage, commit_warnings);
  printf("%s.failures=%d\n", stage, failed_commits);
}

int main(void) {
  mi_option_set(mi_option_page_commit_on_demand, 1);
  mi_option_set(mi_option_arena_eager_commit, 0);
  mi_option_set(mi_option_show_errors, 1);
  mi_register_output(output, NULL);
  mi_stats_init(&before);
  if (!mi_stats_get(&before)) abort();
  for (size_t i = 0; i < 128; i++) {
    blocks[i] = mi_malloc(64);
    if (blocks[i] == NULL) abort();
  }
  printf("CRABC_MI_M7_STATISTICS_PAGE_EXTENSION_FAULT_TRACE_BEGIN\n");
  printf("profile.level=2\n");
  printf("profile.on_demand=%ld\n", mi_option_get(mi_option_page_commit_on_demand));
  printf("profile.eager_arena=%ld\n", mi_option_get(mi_option_arena_eager_commit));
  printf("profile.show_errors=%ld\n", mi_option_get(mi_option_show_errors));
  show("filled");
  fail_next_commit = 1;
  blocks[128] = mi_malloc(64);
  printf("failed_allocation.same_page=%d\n", blocks[128] != NULL && ((uintptr_t)blocks[128] >> 16) == ((uintptr_t)blocks[0] >> 16));
  printf("failed_allocation.nonnull=%d\n", blocks[128] != NULL);
  show("failed_allocation");
  mi_free(blocks[128]);
  blocks[128] = NULL;
  mi_collect(true);
  blocks[129] = mi_malloc(64);
  printf("retry.same_page=%d\n", blocks[129] != NULL && ((uintptr_t)blocks[129] >> 16) == ((uintptr_t)blocks[0] >> 16));
  printf("retry.nonnull=%d\n", blocks[129] != NULL);
  show("retry");
  for (size_t i = 0; i < 130; i++) mi_free(blocks[i]);
  show("freed");
  printf("CRABC_MI_M7_STATISTICS_PAGE_EXTENSION_FAULT_TRACE_END\n");
  return 0;
}
