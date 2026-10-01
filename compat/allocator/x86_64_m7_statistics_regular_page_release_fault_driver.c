#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <unistd.h>
#include "mimalloc.h"
#include "mimalloc-stats.h"
#ifdef CRABC_STATISTICS_MATRIX
#include "mimalloc/internal.h"
#endif
#ifndef CRABC_STAT_LEVEL
#define CRABC_STAT_LEVEL 2
#endif
#ifndef CRABC_FAULTED
#define CRABC_FAULTED 1
#endif

static int fail_next_unmap;
static int failed_unmaps;
static int release_warnings;
static uintptr_t target_block;
static uintptr_t released_base;
static size_t released_size;
static int target_unmaps;
static mi_stats_t before;

/* Reject one regular-page allocator release after the page has been allocated. Other
   unmaps, including startup and alignment cleanup, reach the kernel. */
int crabc_fault_munmap(void* address, size_t size) {
  uintptr_t base = (uintptr_t)address;
  if (target_block >= base && target_block - base < size) {
    released_base = base;
    released_size = size;
    target_unmaps++;
  }
  if (fail_next_unmap && target_block >= base && target_block - base < size) {
    fail_next_unmap = 0;
    failed_unmaps++;
    errno = ENOMEM;
    return -1;
  }
  return (int)syscall(SYS_munmap, address, size);
}

#if defined(CRABC_STATISTICS_MATRIX) && MI_GUARDED
static int mapping_present(int expected) {
  if (released_base == 0 || released_size == 0 || released_base % 4096 || released_size % 4096) abort();
  for (size_t offset = 0; offset < released_size; offset += 4096) {
    unsigned char residency = 0;
    int result = mincore((void*)(released_base + offset), 4096, &residency);
    if (result != 0 && errno != ENOMEM) abort();
    if ((result == 0) != expected) abort();
  }
  return expected;
}

static int client_bytes(void* block, size_t size, unsigned char value) {
  for (size_t i = 0; i < size; i++) if (((unsigned char*)block)[i] != value) return 0;
  return 1;
}
#endif

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
  void* warm = mi_malloc(64);
  if (warm == NULL) abort();
  mi_free(warm);
  mi_collect(true);
#if defined(CRABC_STATISTICS_MATRIX) && MI_GUARDED
  void* survivor = mi_malloc(128);
  if (survivor == NULL) abort();
  memset(survivor, 0x5a, 128);
#endif
  mi_stats_init(&before);
  if (!mi_stats_get(&before)) abort();
  void* block = mi_malloc(64);
  if (block == NULL) abort();
#if defined(CRABC_STATISTICS_MATRIX) && MI_GUARDED
  if (_mi_ptr_page(block)->memid.memkind != MI_MEM_OS) abort();
  memset(block, 0xa5, 64);
#endif
  target_block = (uintptr_t)block;
  printf("CRABC_MI_M7_PAGE_FAILURE_STATS_TRACE_BEGIN\n");
  printf("profile.level=%d\n", CRABC_STAT_LEVEL);
#ifdef CRABC_STATISTICS_MATRIX
  printf("profile.debug=%d\n", MI_DEBUG);
  printf("profile.faulted=%d\n", CRABC_FAULTED);
  printf("allocation.usable=%zu\n", mi_usable_size(block));
  printf("geometry.block_size=%zu\n", mi_page_block_size(_mi_ptr_page(block)));
#if MI_GUARDED
  printf("profile.guarded=%d\n", MI_GUARDED);
  printf("profile.guarded_sample_rate=%ld\n", mi_option_get(mi_option_guarded_sample_rate));
  printf("profile.theap_guarded_sample_rate=%zu\n", mi_theap_get_default()->guarded_sample_rate);
  printf("allocation.os_backed=%d\n", _mi_ptr_page(block)->memid.memkind == MI_MEM_OS);
  printf("allocated.client_bytes=%d\n", client_bytes(block, 64, 0xa5));
#endif
#endif
  printf("profile.disallow_arena=%ld\n", mi_option_get(mi_option_disallow_arena_alloc));
  show("allocated");
  mi_free(block);
  show("freed");
  fail_next_unmap = CRABC_FAULTED;
  mi_collect(true);
  show("failed_release");
#if defined(CRABC_STATISTICS_MATRIX) && MI_GUARDED
  printf("failed_release.mapping_present=%d\n", mapping_present(CRABC_FAULTED));
  printf("failed_release.survivor_bytes=%d\n", client_bytes(survivor, 128, 0x5a));
  if (target_unmaps != 1) abort();
  mi_stats_t_decl(released);
  mi_stats_t_decl(recollected);
  if (!mi_stats_get(&released)) abort();
  mi_collect(true);
  if (!mi_stats_get(&recollected)) abort();
  printf("recollect.no_unmap=%d\n", target_unmaps == 1);
  printf("recollect.mapping_present=%d\n", mapping_present(CRABC_FAULTED));
  printf("recollect.survivor_bytes=%d\n", client_bytes(survivor, 128, 0x5a));
  printf("recollect.counters_unchanged=%d\n",
    released.pages.total == recollected.pages.total && released.pages.peak == recollected.pages.peak && released.pages.current == recollected.pages.current &&
    released.reserved.total == recollected.reserved.total && released.reserved.peak == recollected.reserved.peak && released.reserved.current == recollected.reserved.current &&
    released.committed.total == recollected.committed.total && released.committed.peak == recollected.committed.peak && released.committed.current == recollected.committed.current);
  void* recovery = mi_malloc(64);
  if (recovery == NULL) abort();
  memset(recovery, 0x3c, 64);
  printf("recovery.nonnull=1\n");
  printf("recovery.distinct_from_survivor=%d\n", recovery != survivor);
  printf("recovery.client_bytes=%d\n", client_bytes(recovery, 64, 0x3c));
  printf("recovery.survivor_bytes=%d\n", client_bytes(survivor, 128, 0x5a));
#endif
  printf("CRABC_MI_M7_PAGE_FAILURE_STATS_TRACE_END\n");
#if defined(CRABC_STATISTICS_MATRIX) && MI_GUARDED
  if (CRABC_FAULTED && syscall(SYS_munmap, (void*)released_base, released_size) != 0) abort();
  mi_free(recovery);
  mi_free(survivor);
  mi_collect(true);
#endif
  return 0;
}
