/* Observe aligned blocks through allocation refusal, owner exit, and remote
   release. The freeing worker optionally attaches before touching either block. */
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mimalloc.h"
#include "mimalloc-stats.h"

#ifndef CRABC_STAT_LEVEL
#define CRABC_STAT_LEVEL 2
#endif
#ifndef CRABC_FRESH_FREE
#define CRABC_FRESH_FREE 0
#endif

enum { BEFORE, ALLOCATED, REFUSED, OWNER_EXIT, REMOTE_FREE, REMOTE_EXIT,
       COLLECTED, STAGE_COUNT };
static const char* stages[] = {
  "before", "allocated", "refused", "owner_exit", "remote_free", "remote_exit", "collected"
};
static mi_stats_t snapshots[STAGE_COUNT];
static void* small_block;
static void* huge_block;
static size_t small_usable, huge_usable;
static int allocation_refused;
static char owner_output[32768], freeing_output[32768], final_output[32768];
static size_t output_length;

static void capture_output(const char* message, void* context) {
  char* output = (char*)context;
  size_t length = strlen(message);
  if (length >= 32768 - output_length) abort();
  memcpy(output + output_length, message, length + 1);
  output_length += length;
}

static void print_thread(char* output) {
  output_length = 0;
  output[0] = 0;
  mi_thread_stats_print_out(capture_output, output);
}

static void capture(unsigned stage) {
  mi_stats_init(&snapshots[stage]);
  if (!mi_stats_get(&snapshots[stage])) abort();
}

static void* owner(void* ignored) {
  (void)ignored;
  small_block = mi_malloc_aligned(33, 256);
  huge_block = mi_malloc_aligned(512 * 1024 + 1, 256);
  if (small_block == NULL || huge_block == NULL) abort();
  if (((uintptr_t)small_block & 255) || ((uintptr_t)huge_block & 255)) abort();
  memset(small_block, 0x5a, 33);
  memset(huge_block, 0xa5, 512 * 1024 + 1);
  small_usable = mi_usable_size(small_block);
  huge_usable = mi_usable_size(huge_block);
  print_thread(owner_output);
  capture(ALLOCATED);

  const long arena = mi_option_get(mi_option_disallow_arena_alloc);
  const long os = mi_option_get(mi_option_disallow_os_alloc);
  mi_option_set(mi_option_disallow_arena_alloc, 1);
  mi_option_set(mi_option_disallow_os_alloc, 1);
  void* refused = mi_malloc_aligned(8 * 1024 * 1024, 256);
  allocation_refused = refused == NULL;
  if (!allocation_refused) abort();
  mi_option_set(mi_option_disallow_arena_alloc, arena);
  mi_option_set(mi_option_disallow_os_alloc, os);
  capture(REFUSED);
  return NULL;
}

static void* freeing_worker(void* ignored) {
  (void)ignored;
#if !CRABC_FRESH_FREE
  void* warm = mi_malloc(8);
  if (warm == NULL) abort();
  mi_free(warm);
#endif
  const unsigned char* small = (const unsigned char*)small_block;
  const unsigned char* huge = (const unsigned char*)huge_block;
  for (size_t i = 0; i < 33; i++) if (small[i] != 0x5a) abort();
  for (size_t i = 0; i < 512 * 1024 + 1; i++) if (huge[i] != 0xa5) abort();
  mi_free(small_block);
  mi_free(huge_block);
  print_thread(freeing_output);
  capture(REMOTE_FREE);
  return NULL;
}

static void show_count(const char* stage, const char* field,
                       const mi_stat_count_t* now, const mi_stat_count_t* before) {
  printf("%s.%s=%lld,%lld,%lld\n", stage, field,
         (long long)(now->total - before->total),
         (long long)(now->peak - before->peak),
         (long long)(now->current - before->current));
}

static void show_bins(const char* stage, const char* field,
                      const mi_stat_count_t* now, const mi_stat_count_t* before) {
  printf("%s.%s=", stage, field);
  for (size_t i = 0; i <= MI_BIN_HUGE; i++) {
    const long long total = now[i].total - before[i].total;
    const long long peak = now[i].peak - before[i].peak;
    const long long current = now[i].current - before[i].current;
    if (total || peak || current) printf("%zu:%lld:%lld:%lld;", i, total, peak, current);
  }
  printf("\n");
}

static void show(unsigned stage) {
  const mi_stats_t* now = &snapshots[stage];
  const mi_stats_t* before = &snapshots[BEFORE];
#define COUNT(field, member) show_count(stages[stage], field, &now->member, &before->member)
  COUNT("normal", malloc_normal);
  COUNT("huge", malloc_huge);
  COUNT("requested", malloc_requested);
  COUNT("pages", pages);
  COUNT("threads", threads);
  COUNT("theaps", theaps);
  COUNT("reserved", reserved);
  COUNT("committed", committed);
#undef COUNT
  show_bins(stages[stage], "malloc_bins", now->malloc_bins, before->malloc_bins);
  show_bins(stages[stage], "page_bins", now->page_bins, before->page_bins);
  printf("%s.normal_count=%lld\n", stages[stage],
         (long long)(now->malloc_normal_count.total - before->malloc_normal_count.total));
  printf("%s.huge_count=%lld\n", stages[stage],
         (long long)(now->malloc_huge_count.total - before->malloc_huge_count.total));
}

static void show_rows(const char* stage, const char* output) {
  const char* fields[] = { "binned", "huge", "requested" };
  const char* labels[] = { "  binned", "  huge      :", "  malloc req" };
  for (size_t i = 0; i < 3; i++) {
    const char* row = strstr(output, labels[i]);
    printf("%s.%s.hex=", stage, fields[i]);
    if (row != NULL) {
      const char* end = strchr(row, '\n');
      if (end == NULL) abort();
      for (const char* at = row; at < end; at++) printf("%02x", (unsigned char)*at);
    }
    printf("\n");
  }
}

int main(void) {
  mi_option_set(mi_option_show_errors, 0);
  if (mi_reserve_os_memory(128 * 1024 * 1024, true, false) != 0) abort();
  void* warm = mi_malloc(64);
  if (warm == NULL) abort();
  mi_free(warm);
  mi_collect(true);
  capture(BEFORE);
  pthread_t thread;
  if (pthread_create(&thread, NULL, owner, NULL) != 0) abort();
  if (pthread_join(thread, NULL) != 0) abort();
  capture(OWNER_EXIT);
  if (pthread_create(&thread, NULL, freeing_worker, NULL) != 0) abort();
  if (pthread_join(thread, NULL) != 0) abort();
  capture(REMOTE_EXIT);
  mi_collect(true);
  capture(COLLECTED);
  output_length = 0;
  final_output[0] = 0;
  mi_stats_print_out(capture_output, final_output);

  printf("CRABC_MI_M7_STATISTICS_ALIGNED_TRANSFER_TRACE_BEGIN\n");
  printf("profile.level=%d\n", CRABC_STAT_LEVEL);
  printf("profile.fresh_free=%d\n", CRABC_FRESH_FREE);
  printf("allocation.small_usable=%zu\n", small_usable);
  printf("allocation.huge_usable=%zu\n", huge_usable);
  printf("allocation.refused=%d\n", allocation_refused);
  for (unsigned stage = 0; stage < STAGE_COUNT; stage++) show(stage);
  show_rows("owner_output", owner_output);
  show_rows("freeing_output", freeing_output);
  show_rows("final_output", final_output);
  printf("CRABC_MI_M7_STATISTICS_ALIGNED_TRANSFER_TRACE_END\n");
  return 0;
}
