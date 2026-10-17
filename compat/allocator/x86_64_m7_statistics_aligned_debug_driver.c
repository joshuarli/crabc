#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mimalloc.h"
#include "mimalloc/internal.h"
#include "mimalloc-stats.h"

enum { ALLOCATED, FREED, COLLECTED, STAGE_COUNT };
static const char* stages[] = { "allocated", "freed", "collected" };
static mi_stats_t snapshots[STAGE_COUNT];
static mi_stats_t baseline;

typedef struct output_buffer_s {
  char bytes[32768];
  size_t length;
} output_buffer_t;

static void capture_output(const char* message, void* context) {
  output_buffer_t* output = (output_buffer_t*)context;
  const size_t length = strlen(message);
  if (length >= sizeof(output->bytes) - output->length) abort();
  memcpy(output->bytes + output->length, message, length + 1);
  output->length += length;
}

static void capture(unsigned stage) {
  mi_stats_init(&snapshots[stage]);
  if (!mi_stats_get(&snapshots[stage])) abort();
}

static size_t bin_for_usable_size(size_t size) {
  for (size_t bin = 1; bin < MI_BIN_HUGE; bin++) {
    const size_t block_size = mi_stats_get_bin_size(bin);
    if (block_size >= MI_PADDING_SIZE && block_size - MI_PADDING_SIZE == size) return bin;
  }
  abort();
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
  for (size_t bin = 0; bin <= MI_BIN_HUGE; bin++) {
    const long long total = now[bin].total - before[bin].total;
    const long long peak = now[bin].peak - before[bin].peak;
    const long long current = now[bin].current - before[bin].current;
    if (total || peak || current) printf("%zu:%lld:%lld:%lld;", bin, total, peak, current);
  }
  printf("\n");
}

static void show(unsigned stage) {
  const mi_stats_t* now = &snapshots[stage];
  const mi_stats_t* before = &baseline;
#define COUNT(field, member) show_count(stages[stage], field, &now->member, &before->member)
  COUNT("normal", malloc_normal);
  COUNT("huge", malloc_huge);
  COUNT("requested", malloc_requested);
  COUNT("page_committed", page_committed);
  COUNT("pages", pages);
  COUNT("committed", committed);
#undef COUNT
  show_bins(stages[stage], "malloc_bins", now->malloc_bins, before->malloc_bins);
  show_bins(stages[stage], "page_bins", now->page_bins, before->page_bins);
  printf("%s.normal_count=%lld\n", stages[stage],
         (long long)(now->malloc_normal_count.total - before->malloc_normal_count.total));
  printf("%s.huge_count=%lld\n", stages[stage],
         (long long)(now->malloc_huge_count.total - before->malloc_huge_count.total));
  printf("%s.pages_extended=%lld\n", stages[stage],
         (long long)(now->pages_extended.total - before->pages_extended.total));
  printf("%s.pages_retire=%lld\n", stages[stage],
         (long long)(now->pages_retire.total - before->pages_retire.total));
}

static void show_rows(const char* stage, const output_buffer_t* output) {
  const char* fields[] = { "binned", "huge", "requested" };
  const char* labels[] = { "  binned", "  huge      :", "  malloc req" };
  for (size_t index = 0; index < 3; index++) {
    const char* row = strstr(output->bytes, labels[index]);
    printf("%s.%s.hex=", stage, fields[index]);
    if (row != NULL) {
      const char* end = strchr(row, '\n');
      if (end == NULL) abort();
      for (const char* at = row; at < end; at++) printf("%02x", (unsigned char)*at);
    }
    printf("\n");
  }
}

int main(int argc, char** argv) {
  size_t request = 8193;
  size_t alignment = 4096;
  if (argc == 3) {
    char* request_end = NULL;
    char* alignment_end = NULL;
    request = strtoull(argv[1], &request_end, 10);
    alignment = strtoull(argv[2], &alignment_end, 10);
    if (*request_end != 0 || *alignment_end != 0) abort();
  }
  else if (argc != 1) abort();
  if (!((request == 8193 && alignment == 4096)
      || (request == 65537 && alignment == 4096)
      || (request == 262145 && alignment == 65536))) abort();
  mi_stats_init(&baseline);
  if (!mi_stats_get(&baseline)) abort();

  void* block = mi_malloc_aligned(request, alignment);
  if (block == NULL) return 2;
  const size_t oversize_request = request + alignment - 1;
  const size_t page_block_size = mi_good_size(oversize_request);
  if (page_block_size < MI_PADDING_SIZE) abort();
  const size_t normal_bin = bin_for_usable_size(page_block_size - MI_PADDING_SIZE);
  if (mi_stats_get_bin_size(normal_bin) != page_block_size) abort();
  const int aligned = (((uintptr_t)block & (alignment - 1)) == 0);
  const int mapped = mi_is_in_heap_region(block);
  const size_t usable = mi_usable_size(block);
  memset(block, 0x5a, request);
  int payload_intact = 1;
  for (size_t index = 0; index < request; index++) {
    if (((const unsigned char*)block)[index] != 0x5a) payload_intact = 0;
  }
  capture(ALLOCATED);

  output_buffer_t live_output = { .bytes = { 0 }, .length = 0 };
  mi_stats_print_out(&capture_output, &live_output);
  mi_free(block);
  capture(FREED);
  mi_collect(true);
  capture(COLLECTED);
  output_buffer_t final_output = { .bytes = { 0 }, .length = 0 };
  mi_stats_print_out(&capture_output, &final_output);

  printf("CRABC_MI_M7_STATISTICS_ALIGNED_DEBUG_TRACE_BEGIN\n");
  printf("profile.level=%d\n", MI_STAT);
  printf("profile.debug=%d\n", MI_DEBUG);
  printf("allocation.request=%zu\n", request);
  printf("allocation.alignment=%zu\n", alignment);
  printf("allocation.oversize_request=%zu\n", oversize_request);
  printf("allocation.page_block_size=%zu\n", page_block_size);
  printf("allocation.padding_size=%zu\n", (size_t)MI_PADDING_SIZE);
  printf("allocation.normal_bin=%zu\n", normal_bin);
  printf("allocation.usable=%zu\n", usable);
  printf("allocation.aligned=%d\n", aligned);
  printf("allocation.mapped=%d\n", mapped);
  printf("allocation.payload_intact=%d\n", payload_intact);
  for (unsigned stage = 0; stage < STAGE_COUNT; stage++) show(stage);
  show_rows("live_output", &live_output);
  show_rows("final_output", &final_output);
  printf("CRABC_MI_M7_STATISTICS_ALIGNED_DEBUG_TRACE_END\n");
  return 0;
}
