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
static size_t selected_commit_size;
static mi_stats_t before;

/* Reject the first page write-enable after a warmed arena has its metadata. */
int crabc_fault_mprotect(void* address, size_t size, int protection) {
  if (fail_next_commit && protection == (PROT_READ | PROT_WRITE)) {
    fail_next_commit = 0;
    failed_commits++;
    selected_commit_size = size;
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
#define ROW(name, field) printf("%s." name "=%lld,%lld,%lld\n", stage, \
    (long long)(now.field.total - before.field.total), \
    (long long)(now.field.peak - before.field.peak), \
    (long long)(now.field.current - before.field.current))
  ROW("pages", pages);
  ROW("page_committed", page_committed);
  ROW("reserved", reserved);
  ROW("committed", committed);
  ROW("requested", malloc_requested);
  ROW("normal", malloc_normal);
#undef ROW
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
  void* warm = mi_malloc(64);
  if (warm == NULL) abort();
  mi_free(warm);
  mi_stats_init(&before);
  if (!mi_stats_get(&before)) abort();
  printf("CRABC_MI_M7_INITIAL_PAGE_COMMIT_FAULT_TRACE_BEGIN\n");
  printf("profile.level=2\n");
  printf("profile.on_demand=%ld\n", mi_option_get(mi_option_page_commit_on_demand));
  printf("profile.eager_arena=%ld\n", mi_option_get(mi_option_arena_eager_commit));
  printf("profile.show_errors=%ld\n", mi_option_get(mi_option_show_errors));
  show("before");
  fail_next_commit = 1;
  void* block = mi_malloc(100000);
  printf("fault.nonnull=%d\n", block != NULL);
  printf("fault.commit_size=%zu\n", selected_commit_size);
  show("fault");
  void* recovered = mi_malloc(100000);
  printf("recovery.nonnull=%d\n", recovered != NULL);
  show("recovery");
  mi_free(block);
  mi_free(recovered);
  show("freed");
  printf("CRABC_MI_M7_INITIAL_PAGE_COMMIT_FAULT_TRACE_END\n");
  return 0;
}
