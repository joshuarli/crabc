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
/* The source page extension bounds are private to page.c. */
#define CRABC_PAGE_MAX_EXTEND_SIZE (8 * 1024)
#define CRABC_PAGE_MIN_EXTEND (MI_SECURE >= 2 ? 8 * MI_SECURE : 1)
#endif
#ifndef CRABC_STAT_LEVEL
#define CRABC_STAT_LEVEL 2
#endif
#ifndef CRABC_FAULTED
#define CRABC_FAULTED 1
#endif

static int fail_next_commit;
static int failed_commits;
static int commit_warnings;
static void* blocks[256];
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
  blocks[0] = mi_malloc(64);
  if (blocks[0] == NULL) abort();
#ifdef CRABC_STATISTICS_MATRIX
  mi_page_t* page = _mi_ptr_page(blocks[0]);
  const size_t initial_capacity = page->capacity;
  size_t filled_capacity = initial_capacity;
  size_t filled_extensions = 1;
  size_t allocated = 1;
  for (;;) {
    if (filled_capacity == 0 || filled_capacity + 2 > 256) abort();
    for (; allocated < filled_capacity; allocated++) {
      blocks[allocated] = mi_malloc(64);
      if (blocks[allocated] == NULL || _mi_ptr_page(blocks[allocated]) != page) abort();
      for (size_t j = 0; j < allocated; j++) if (blocks[j] == blocks[allocated]) abort();
    }
    if (page->used != page->capacity || page->free != NULL || page->local_free != NULL) abort();
    /* Exhaust each initialized prefix until the next source extension needs
       an actual OS commit. Debug padding can leave a second extension inside
       the initial commitment even when the immediate free list is empty. */
    const size_t bsize = mi_page_block_size(page);
    size_t extend = page->reserved - page->capacity;
    size_t maximum = (bsize >= CRABC_PAGE_MAX_EXTEND_SIZE ? CRABC_PAGE_MIN_EXTEND : CRABC_PAGE_MAX_EXTEND_SIZE / bsize);
    if (maximum < CRABC_PAGE_MIN_EXTEND) maximum = CRABC_PAGE_MIN_EXTEND;
    if (extend > maximum) extend = maximum;
    if (extend * bsize > MI_ARENA_SLICE_SIZE) extend = _mi_divide_up(MI_ARENA_SLICE_SIZE, bsize);
    const size_t needed = _mi_align_up(mi_page_slice_offset_of(page, (page->capacity + extend) * bsize), mi_page_min_commit_size());
    if (page->slice_pcommitted == 0 || extend == 0) abort();
    if (needed > mi_page_slice_committed(page)) break;
    blocks[allocated] = mi_malloc(64);
    if (blocks[allocated] == NULL || _mi_ptr_page(blocks[allocated]) != page) abort();
    for (size_t j = 0; j < allocated; j++) if (blocks[j] == blocks[allocated]) abort();
    allocated++;
    filled_capacity = page->capacity;
    filled_extensions++;
  }
#else
  const size_t initial_capacity = 128;
  const size_t filled_capacity = initial_capacity;
  for (size_t i = 1; i < filled_capacity; i++) {
    blocks[i] = mi_malloc(64);
    if (blocks[i] == NULL) abort();
  }
#endif
  printf("CRABC_MI_M7_STATISTICS_PAGE_EXTENSION_FAULT_TRACE_BEGIN\n");
  printf("profile.level=%d\n", CRABC_STAT_LEVEL);
#ifdef CRABC_STATISTICS_MATRIX
  printf("profile.debug=%d\n", MI_DEBUG);
  printf("profile.faulted=%d\n", CRABC_FAULTED);
  printf("geometry.initial_capacity=%zu\n", initial_capacity);
  printf("geometry.filled_capacity=%zu\n", filled_capacity);
  printf("geometry.filled_extensions=%zu\n", filled_extensions);
  printf("geometry.block_size=%zu\n", mi_page_block_size(page));
  printf("geometry.slice_pcommitted=%u\n", page->slice_pcommitted);
  printf("geometry.slice_offset=%zu\n", mi_page_slice_offset_of(page, 0));
  printf("geometry.used=%zu\n", page->used);
  printf("geometry.reserved=%u\n", page->reserved);
  printf("geometry.free_empty=%d\n", page->free == NULL && page->local_free == NULL);
#endif
  printf("profile.on_demand=%ld\n", mi_option_get(mi_option_page_commit_on_demand));
  printf("profile.eager_arena=%ld\n", mi_option_get(mi_option_arena_eager_commit));
  printf("profile.show_errors=%ld\n", mi_option_get(mi_option_show_errors));
  show("filled");
  fail_next_commit = CRABC_FAULTED;
  blocks[filled_capacity] = mi_malloc(64);
  printf("failed_allocation.same_page=%d\n", blocks[filled_capacity] != NULL && ((uintptr_t)blocks[filled_capacity] >> 16) == ((uintptr_t)blocks[0] >> 16));
  printf("failed_allocation.nonnull=%d\n", blocks[filled_capacity] != NULL);
  show("failed_allocation");
  mi_free(blocks[filled_capacity]);
  blocks[filled_capacity] = NULL;
  mi_collect(true);
  blocks[filled_capacity + 1] = mi_malloc(64);
  printf("retry.same_page=%d\n", blocks[filled_capacity + 1] != NULL && ((uintptr_t)blocks[filled_capacity + 1] >> 16) == ((uintptr_t)blocks[0] >> 16));
  printf("retry.nonnull=%d\n", blocks[filled_capacity + 1] != NULL);
  show("retry");
  for (size_t i = 0; i < filled_capacity + 2; i++) mi_free(blocks[i]);
  show("freed");
  printf("CRABC_MI_M7_STATISTICS_PAGE_EXTENSION_FAULT_TRACE_END\n");
  return 0;
}
