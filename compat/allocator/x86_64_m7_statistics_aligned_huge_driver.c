/* Compare one OS-aligned huge page's public statistics and output. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mimalloc.h"
#include "mimalloc-stats.h"

static char output[32768];
static size_t output_length;

static void capture(const char* message, void* argument) {
  (void)argument;
  const size_t length = strlen(message);
  if (length >= sizeof(output) - output_length) abort();
  memcpy(output + output_length, message, length + 1);
  output_length += length;
}

static void read_stats(mi_stats_t* stats) {
  if (!mi_stats_get(stats)) abort();
}

static void show_huge(const char* name, const mi_stats_t* after, const mi_stats_t* before) {
  printf("%s.huge=%lld,%lld,%lld\n", name,
         (long long)(after->malloc_huge.total - before->malloc_huge.total),
         (long long)(after->malloc_huge.peak - before->malloc_huge.peak),
         (long long)(after->malloc_huge.current - before->malloc_huge.current));
  printf("%s.huge_count=%lld\n", name,
         (long long)(after->malloc_huge_count.total - before->malloc_huge_count.total));
}

static int warning_count(void) {
  int count = 0;
  const char* at = output;
  while ((at = strstr(at, "warning:")) != NULL) {
    count++;
    at += strlen("warning:");
  }
  return count;
}

static void show_live_huge_row(void) {
  const char* row = strstr(output, "  huge      :");
  if (row == NULL) abort();
  const char* end = strchr(row, '\n');
  if (end == NULL) abort();
  printf("thread.live_huge.hex=");
  for (const char* p = row; p < end; p++) printf("%02x", (unsigned char)*p);
  printf("\n");
}

int main(void) {
  const size_t alignment = 1u << 20;
  mi_register_output(&capture, NULL);
  mi_stats_t_decl(before);
  mi_stats_t_decl(allocated);
  mi_stats_t_decl(merged);
  mi_stats_t_decl(freed);
  read_stats(&before);
  output_length = 0;
  output[0] = 0;

  void* block = mi_malloc_aligned(512 * 1024 + 1, alignment);
  if (block == NULL) return 2;
  memset(block, 0x5a, 64);
  const size_t usable = mi_usable_size(block);
  const int aligned = ((uintptr_t)block & (alignment - 1)) == 0;
  mi_thread_stats_print_out(&capture, NULL);
  const int live_huge = strstr(output, "  huge      :") != NULL;
  read_stats(&allocated);
  read_stats(&merged);
  mi_free(block);
  read_stats(&freed);
  const int warnings = warning_count();

  printf("CRABC_MI_M7_STATISTICS_ALIGNED_HUGE_TRACE_BEGIN\n");
  printf("profile.level=1\n");
  printf("allocation.aligned=%d\n", aligned);
  printf("allocation.usable=%zu\n", usable);
  show_huge("allocated", &allocated, &before);
  show_huge("merged", &merged, &before);
  show_huge("freed", &freed, &before);
  printf("thread.live_huge=%d\n", live_huge);
  show_live_huge_row();
  printf("warning.count=%d\n", warnings);
  printf("CRABC_MI_M7_STATISTICS_ALIGNED_HUGE_TRACE_END\n");
  return 0;
}
