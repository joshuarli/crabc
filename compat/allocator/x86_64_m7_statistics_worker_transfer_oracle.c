/* A live worker allocation is reset, survives owner exit, and is freed by
   another attached worker. Observe each owner merge through public stats. */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include "mimalloc.h"
#include "mimalloc-stats.h"

#ifndef CRABC_INITIAL_ATTACHMENT
enum { BEFORE, FIRST_ALLOC, FIRST_RESET, FIRST_EXIT,
       SECOND_ATTACH, REMOTE_FREE, SECOND_RESET, LOCAL_FREE, SECOND_EXIT, STAGE_COUNT };
static const char* names[STAGE_COUNT] = {
  "before", "first_alloc", "first_reset", "first_exit",
  "second_attach", "remote_free", "second_reset", "local_free", "second_exit"
};
static mi_stats_t observed[STAGE_COUNT];
static void* transferred;
static size_t first_bin, second_bin;

static void capture(unsigned stage) {
  mi_stats_init(&observed[stage]);
  if (!mi_stats_get(&observed[stage])) abort();
}

static size_t bin_for(size_t size) {
  for (size_t index = 0; index < MI_BIN_HUGE; index++) {
    if (mi_stats_get_bin_size(index) == size) return index;
  }
  abort();
}

static void* first_worker(void* ignored) {
  (void)ignored;
  transferred = mi_malloc(64);
  if (transferred == NULL) abort();
  first_bin = bin_for(mi_usable_size(transferred));
  capture(FIRST_ALLOC);
  mi_stats_reset();
  capture(FIRST_RESET);
  return NULL;
}

static void* second_worker(void* ignored) {
  (void)ignored;
  void* local = mi_malloc(16);
  if (local == NULL) abort();
  second_bin = bin_for(mi_usable_size(local));
  capture(SECOND_ATTACH);
  mi_free(transferred);
  capture(REMOTE_FREE);
  mi_stats_reset();
  capture(SECOND_RESET);
  mi_free(local);
  capture(LOCAL_FREE);
  return NULL;
}

static void count(const char* stage, const char* field,
                  const mi_stat_count_t* now, const mi_stat_count_t* baseline) {
  printf("%s.%s=%lld,%lld,%lld\n", stage, field,
         (long long)(now->total - baseline->total),
         (long long)(now->peak - baseline->peak),
         (long long)(now->current - baseline->current));
}

static void show(unsigned stage) {
  const mi_stats_t* now = &observed[stage];
  const mi_stats_t* baseline = &observed[BEFORE];
  count(names[stage], "normal", &now->malloc_normal, &baseline->malloc_normal);
  count(names[stage], "requested", &now->malloc_requested, &baseline->malloc_requested);
  count(names[stage], "first_bin", &now->malloc_bins[first_bin], &baseline->malloc_bins[first_bin]);
  count(names[stage], "second_bin", &now->malloc_bins[second_bin], &baseline->malloc_bins[second_bin]);
  count(names[stage], "pages", &now->pages, &baseline->pages);
  count(names[stage], "first_page_bin", &now->page_bins[first_bin], &baseline->page_bins[first_bin]);
  count(names[stage], "second_page_bin", &now->page_bins[second_bin], &baseline->page_bins[second_bin]);
  count(names[stage], "threads", &now->threads, &baseline->threads);
  count(names[stage], "theaps", &now->theaps, &baseline->theaps);
  printf("%s.normal_count=%lld\n", names[stage],
         (long long)(now->malloc_normal_count.total - baseline->malloc_normal_count.total));
}

int main(void) {
  pthread_t worker;
  capture(BEFORE);
  if (pthread_create(&worker, NULL, first_worker, NULL) != 0) abort();
  if (pthread_join(worker, NULL) != 0) abort();
  capture(FIRST_EXIT);
  if (pthread_create(&worker, NULL, second_worker, NULL) != 0) abort();
  if (pthread_join(worker, NULL) != 0) abort();
  capture(SECOND_EXIT);
  printf("CRABC_MI_M7_STATISTICS_WORKER_TRANSFER_TRACE_BEGIN\n");
  printf("profile.level=2\n");
  printf("first.bin=%zu\n", first_bin);
  printf("second.bin=%zu\n", second_bin);
  for (unsigned stage = 0; stage < STAGE_COUNT; stage++) show(stage);
  printf("CRABC_MI_M7_STATISTICS_WORKER_TRANSFER_TRACE_END\n");
  return 0;
}

#else

/* A statistics query on an untouched worker precedes its first allocation.
   Keep the block live across exit so attachment and ownership merges remain
   independently visible before the main thread releases it. */
#include <stdint.h>
#include <string.h>
#ifndef CRABC_STAT_LEVEL
#define CRABC_STAT_LEVEL 2
#endif
#ifndef CRABC_INITIAL_PLACEMENT_DIAGNOSTIC
#define CRABC_INITIAL_PLACEMENT_DIAGNOSTIC 0
#endif
#ifndef CRABC_INITIAL_REQUEST
#define CRABC_INITIAL_REQUEST 64
#endif
#ifndef CRABC_INITIAL_ALIGNMENT
#define CRABC_INITIAL_ALIGNMENT 0
#endif
enum { BEFORE, UNTOUCHED, ALLOCATED, OWNER_EXIT, FREED, COLLECTED, STAGE_COUNT };
static const char* stages[] = { "before", "untouched", "allocated", "owner_exit", "freed", "collected" };
static mi_stats_t snapshots[STAGE_COUNT];
static void* block;
static size_t usable;
#if CRABC_INITIAL_PLACEMENT_DIAGNOSTIC
static uintptr_t warm_address, client_address;
#endif
static char owner_output[32768], final_output[32768];
static size_t output_length;
static void capture_output(const char* message, void* context) {
  char* output = (char*)context;
  size_t length = strlen(message);
  if (length >= 32768 - output_length) abort();
  memcpy(output + output_length, message, length + 1);
  output_length += length;
}
static void capture(unsigned stage) {
  mi_stats_init(&snapshots[stage]);
  if (!mi_stats_get(&snapshots[stage])) abort();
}
static void* owner(void* ignored) {
  (void)ignored;
  capture(UNTOUCHED);
#if CRABC_INITIAL_ALIGNMENT
  block = mi_malloc_aligned(CRABC_INITIAL_REQUEST, CRABC_INITIAL_ALIGNMENT);
#else
  block = mi_malloc(CRABC_INITIAL_REQUEST);
#endif
  if (block == NULL) abort();
#if CRABC_INITIAL_ALIGNMENT
  if ((uintptr_t)block % CRABC_INITIAL_ALIGNMENT) abort();
#endif
  memset(block, 0x5a, CRABC_INITIAL_REQUEST);
  usable = mi_usable_size(block);
#if CRABC_INITIAL_PLACEMENT_DIAGNOSTIC
  client_address = (uintptr_t)block;
#endif
  output_length = 0;
  mi_thread_stats_print_out(capture_output, owner_output);
  capture(ALLOCATED);
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
#if CRABC_INITIAL_PLACEMENT_DIAGNOSTIC
  warm_address = (uintptr_t)warm;
#endif
  mi_free(warm);
  mi_collect(true);
  capture(BEFORE);
  pthread_t thread;
  if (pthread_create(&thread, NULL, owner, NULL) != 0) abort();
  if (pthread_join(thread, NULL) != 0) abort();
  capture(OWNER_EXIT);
  for (size_t i = 0; i < CRABC_INITIAL_REQUEST; i++) if (((unsigned char*)block)[i] != 0x5a) abort();
  mi_free(block);
  capture(FREED);
  mi_collect(true);
  capture(COLLECTED);
  output_length = 0;
  mi_stats_print_out(capture_output, final_output);
  printf("CRABC_MI_M7_STATISTICS_INITIAL_TRANSFER_TRACE_BEGIN\n");
  printf("profile.level=%d\n", CRABC_STAT_LEVEL);
  printf("allocation.request=%d\n", CRABC_INITIAL_REQUEST);
  printf("allocation.alignment=%d\n", CRABC_INITIAL_ALIGNMENT);
  printf("allocation.usable=%zu\n", usable);
  for (unsigned stage = 0; stage < STAGE_COUNT; stage++) show(stage);
  show_rows("owner_output", owner_output);
  show_rows("final_output", final_output);
  printf("CRABC_MI_M7_STATISTICS_INITIAL_TRANSFER_TRACE_END\n");
#if CRABC_INITIAL_PLACEMENT_DIAGNOSTIC
  /* These are integers copied from live client pointers, not metadata
     identities. The OS-aligned singleton starts its data at the client;
     PageMap registers one data slice plus its one-slice page offset, from
     that data start. Earlier alignment overmapping is not registered there.
     These diagnostics leave every statistics counter unchanged. */
  const int os_small = CRABC_INITIAL_ALIGNMENT == 1048576 && CRABC_INITIAL_REQUEST == 17;
  if (os_small && (usable > 65536 || (client_address & (1048576 - 1)) != 0)) abort();
  const size_t span = os_small ? 2 * 65536 : CRABC_INITIAL_ALIGNMENT + usable + 65536;
  if (client_address > UINTPTR_MAX - span) abort();
  fprintf(stderr, "placement.warm_index=%zu\n", (size_t)(warm_address >> 29));
  fprintf(stderr, "placement.client_index=%zu\n", (size_t)(client_address >> 29));
  fprintf(stderr, "placement.client_lower_bound_index=%zu\n", (size_t)(client_address >> 29));
  fprintf(stderr, "placement.client_bound_index=%zu\n", (size_t)((client_address + span - 1) >> 29));
  for (unsigned stage = 0; stage < STAGE_COUNT; stage++) {
    fprintf(stderr, "placement.%s.mmap_calls=%lld\n", stages[stage],
        (long long)(snapshots[stage].mmap_calls.total - snapshots[BEFORE].mmap_calls.total));
  }
#endif
  return 0;
}

#endif
