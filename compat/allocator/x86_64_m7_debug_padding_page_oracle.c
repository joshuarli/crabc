/* Observe one regular page in fresh debug-padding processes. */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mimalloc.h"
#include "mimalloc-stats.h"

static char diagnostic[1024];
static size_t diagnostic_length;
static unsigned errors;
static int last_error;
static mi_stats_t baseline;
static size_t bin;

static void capture_output(const char *message, void *argument) {
  (void)argument;
  if (message == NULL) return;
  size_t length = strlen(message);
  if (length >= sizeof(diagnostic) - diagnostic_length) abort();
  memcpy(diagnostic + diagnostic_length, message, length + 1);
  diagnostic_length += length;
}

static void capture_error(int code, void *argument) {
  (void)argument;
  errors++;
  last_error = code;
}

static void read_stats(mi_stats_t *stats) {
  mi_stats_init(stats);
  if (!mi_stats_get(stats)) abort();
}

static void count(const char *stage, const char *field,
                  const mi_stat_count_t *now, const mi_stat_count_t *before) {
  printf("%s.%s=%lld,%lld,%lld\n", stage, field,
         (long long)(now->current - before->current),
         (long long)(now->total - before->total),
         (long long)(now->peak - before->peak));
}

static void stage(const char *name) {
  mi_stats_t stats;
  read_stats(&stats);
  count(name, "normal", &stats.malloc_normal, &baseline.malloc_normal);
  count(name, "requested", &stats.malloc_requested, &baseline.malloc_requested);
  count(name, "pages", &stats.pages, &baseline.pages);
  count(name, "page_bin", &stats.page_bins[bin], &baseline.page_bins[bin]);
  count(name, "malloc_bin", &stats.malloc_bins[bin], &baseline.malloc_bins[bin]);
  printf("%s.pages_retire=%lld\n", name,
         (long long)(stats.pages_retire.total - baseline.pages_retire.total));
}

int main(int argc, char **argv) {
  if (argc != 2 || (strcmp(argv[1], "clean") && strcmp(argv[1], "corrupt"))) return 2;
  const int corrupt = strcmp(argv[1], "corrupt") == 0;
  mi_register_output(&capture_output, NULL);
  mi_register_error(&capture_error, NULL);
  read_stats(&baseline);
  unsigned char *first = (unsigned char *)mi_malloc(17);
  unsigned char *second = (unsigned char *)mi_malloc(17);
  if (first == NULL || second == NULL) abort();
  const size_t usable = mi_usable_size(first);
  const size_t good = mi_good_size(17);
  bin = 0;
  for (size_t index = 1; index < MI_BIN_HUGE; index++) {
    if (mi_stats_get_bin_size(index) == 32) { bin = index; break; }
  }
  if (bin == 0) abort();
  unsigned fill_bytes = 0;
  for (size_t index = 0; index < 17; index++) {
    if (first[index] == 0xD0) fill_bytes++;
  }
  printf("CRABC_MI_M7_DEBUG_PADDING_PAGE_TRACE_BEGIN\n");
  printf("case=%s\n", argv[1]);
  printf("usable=%zu\n", usable);
  printf("good_size=%zu\n", good);
  printf("debug_uninit_fill_bytes=%u\n", fill_bytes);
  printf("same_page=%u\n", ((uintptr_t)first >> 16) == ((uintptr_t)second >> 16));
  printf("owned.live=%u\n", mi_check_owned(first));
  stage("live");
  volatile size_t corrupt_offset = 17;
  if (corrupt) first[corrupt_offset] = 0;
  mi_free(first);
  printf("errors.after_first_free=%u\n", errors);
  printf("error_code.after_first_free=%d\n", last_error);
  printf("diagnostic.overflow=%u\n", strstr(diagnostic, "buffer overflow in heap block") != NULL);
  printf("diagnostic.offset_17=%u\n", strstr(diagnostic, "write after 17 bytes") != NULL);
  printf("owned.after_first_free=%u\n", mi_check_owned(second));
  stage("after_first_free");
  mi_free(second);
  mi_collect(true);
  stage("terminal");
  printf("CRABC_MI_M7_DEBUG_PADDING_PAGE_TRACE_END\n");
  return 0;
}
