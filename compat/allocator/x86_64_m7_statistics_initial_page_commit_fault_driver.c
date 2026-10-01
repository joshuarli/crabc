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
#ifdef CRABC_STATISTICS_MATRIX
#include "mimalloc/internal.h"
#endif

static int fail_next_commit;
static int failed_commits;
static int commit_warnings;
static size_t selected_commit_size;
static mi_stats_t before;

/* Reject the first page write-enable after a warmed arena has its metadata. */
int crabc_fault_mprotect(void* address, size_t size, int protection) {
#ifdef CRABC_STATISTICS_MATRIX
  if (selected_commit_size == 0 && protection == (PROT_READ | PROT_WRITE)) selected_commit_size = size;
#endif
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

#ifdef CRABC_STATISTICS_MATRIX
static int client_bytes(const void* block, unsigned char pattern) {
  if (block == NULL || mi_usable_size(block) < 100000) return 0;
  const unsigned char* bytes = block;
  for (size_t i = 0; i < 100000; i++) if (bytes[i] != pattern) return 0;
  return 1;
}
#endif

int main(void) {
  mi_option_set(mi_option_page_commit_on_demand, 1);
  mi_option_set(mi_option_arena_eager_commit, 0);
  mi_option_set(mi_option_show_errors, 1);
  mi_register_output(output, NULL);
#ifdef CRABC_STATISTICS_MATRIX
  const int faulted = getenv("CRABC_MI_STATISTICS_FAULT_CONTROL") == NULL ||
      strcmp(getenv("CRABC_MI_STATISTICS_FAULT_CONTROL"), "success") != 0;
  mi_option_set(mi_option_guarded_sample_rate, 0);
  mi_theap_guarded_set_sample_rate(mi_theap_get_default(), 0, 0);
#endif
  void* warm = mi_malloc(64);
  if (warm == NULL) abort();
  mi_free(warm);
  mi_stats_init(&before);
  if (!mi_stats_get(&before)) abort();
  printf("CRABC_MI_M7_INITIAL_PAGE_COMMIT_FAULT_TRACE_BEGIN\n");
#ifdef CRABC_STATISTICS_MATRIX
  printf("profile.level=%d\n", MI_STAT);
  printf("profile.debug=%d\n", MI_DEBUG);
  printf("profile.guarded=%d\n", MI_GUARDED);
  printf("profile.faulted=%d\n", faulted);
  printf("profile.sample_rate=%ld\n", mi_option_get(mi_option_guarded_sample_rate));
  printf("profile.theap_sample_rate=%zu\n", mi_theap_get_default()->guarded_sample_rate);
#else
  printf("profile.level=2\n");
#endif
  printf("profile.on_demand=%ld\n", mi_option_get(mi_option_page_commit_on_demand));
  printf("profile.eager_arena=%ld\n", mi_option_get(mi_option_arena_eager_commit));
  printf("profile.show_errors=%ld\n", mi_option_get(mi_option_show_errors));
  show("before");
#ifdef CRABC_STATISTICS_MATRIX
  selected_commit_size = 0;
  fail_next_commit = faulted;
#else
  fail_next_commit = 1;
#endif
  void* block = mi_malloc(100000);
  printf("fault.nonnull=%d\n", block != NULL);
  printf("fault.commit_size=%zu\n", selected_commit_size);
#ifdef CRABC_STATISTICS_MATRIX
  if (block == NULL || mi_usable_size(block) < 100000) abort();
  memset(block, 0x35, 100000);
#endif
  show("fault");
  void* recovered = mi_malloc(100000);
  printf("recovery.nonnull=%d\n", recovered != NULL);
#ifdef CRABC_STATISTICS_MATRIX
  if (recovered == NULL || mi_usable_size(recovered) < 100000) abort();
  memset(recovered, 0xb7, 100000);
  const uintptr_t first = (uintptr_t)block, second = (uintptr_t)recovered;
  printf("recovery.client_bytes=%d\n", client_bytes(block, 0x35) && client_bytes(recovered, 0xb7));
  printf("recovery.clients_distinct=%d\n", first < second ? second - first >= 100000 : first - second >= 100000);
  printf("recovery.clients_owned=%d\n", mi_check_owned(block) && mi_check_owned(recovered) &&
      mi_heap_contains(mi_heap_main(), block) && mi_heap_contains(mi_heap_main(), recovered));
#endif
  show("recovery");
  mi_free(block);
  mi_free(recovered);
  show("freed");
  printf("CRABC_MI_M7_INITIAL_PAGE_COMMIT_FAULT_TRACE_END\n");
  return 0;
}
