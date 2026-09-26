/* Shared C driver for the allocator statistics differential.

   Linked once against the pinned mimalloc v3.5.0 release sources and once
   against the native Rust adapter, each run as its own process, it drives
   the process-wide `mimalloc-stats.h` and `mimalloc.h` statistics entries:
   `mi_stats_print_out`, `mi_stats_print` (with a registered output, a
   `stdout` argument, and a callback), `mi_thread_stats_print_out` on the
   initial thread and a worker, `mi_stats_reset`, `mi_stats_get_bin_size`,
   `mi_stats_get_json` and `mi_stats_as_json` into grown, exact, and short
   buffers, and the `mi_process_info` family.

   Printed statistics carry counts, sizes, and times that depend on the
   process, so each captured line is recorded with every token containing a
   digit replaced by `N` (and a unit token directly after it dropped). The
   callback delivery count, bin sizes, allocation and worker counter deltas,
   and selected absolute arena snapshots are compared exactly. The line
   structure, labels, sections, and `ok`/`not all freed` states are also exact. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "mimalloc.h"
#include "mimalloc-stats.h"

static char captured[65536];
static size_t captured_length;
static int deliveries;

static void capture(const char* message, void* argument) {
  (void)argument;
  deliveries++;
  size_t length = strlen(message);
  if (captured_length + length < sizeof(captured)) {
    memcpy(captured + captured_length, message, length);
    captured_length += length;
    captured[captured_length] = 0;
  }
}

static bool has_digit(const char* token, size_t length) {
  for (size_t i = 0; i < length; i++) if (token[i] >= '0' && token[i] <= '9') return true;
  return false;
}

static bool is_unit(const char* token, size_t length) {
  static const char* units[] = { "B", "KiB", "MiB", "GiB", "K", "M", "G", "s", "avg" };
  for (size_t i = 0; i < sizeof(units) / sizeof(units[0]); i++) {
    if (strlen(units[i]) == length && strncmp(units[i], token, length) == 0) return true;
  }
  return false;
}

/* Prints `text` as hex after normalizing each line's tokens. */
static void print_normalized(const char* key, const char* text) {
  printf("%s=", key);
  const char* p = text;
  while (*p != 0) {
    const char* end = strchr(p, '\n');
    if (end == NULL) end = p + strlen(p);
    bool first = true;
    bool previous_number = false;
    for (const char* q = p; q < end; ) {
      while (q < end && *q == ' ') q++;
      const char* t = q;
      while (q < end && *q != ' ') q++;
      size_t length = (size_t)(q - t);
      if (length == 0) break;
      if (previous_number && is_unit(t, length)) { previous_number = false; continue; }
      if (!first) printf("20");
      first = false;
      if (has_digit(t, length)) {
        printf("4e");
        previous_number = true;
      } else {
        for (size_t i = 0; i < length; i++) printf("%02x", (unsigned char)t[i]);
        previous_number = false;
      }
    }
    printf("0a");
    p = (*end == '\n') ? end + 1 : end;
  }
  printf("\n");
}

static void reset_capture(void) {
  captured_length = 0;
  captured[0] = 0;
  deliveries = 0;
}

static void record_capture(const char* key) {
  char name[128];
  snprintf(name, sizeof(name), "%s.text", key);
  print_normalized(name, captured);
  printf("%s.deliveries=%d\n", key, deliveries);
  reset_capture();
}

static void* worker(void* argument) {
  (void)argument;
  void* p = mi_malloc(100);
  mi_thread_stats_print_out(&capture, NULL);
  record_capture("worker.thread_stats");
  mi_free(p);
  return NULL;
}

int main(void) {
  mi_register_output(&capture, NULL);
  reset_capture();
  printf("CRABC_MI_M7_STATISTICS_TRACE_BEGIN\n");

  mi_stats_t_decl(allocation_before);
  if (!mi_stats_get(&allocation_before)) return 4;

  void* blocks[4] = { mi_malloc(64), mi_malloc(100000), mi_malloc(3u << 20), mi_malloc(40u << 20) };
  void* live = mi_malloc(200);
  mi_stats_t_decl(allocation_after);
  if (!mi_stats_get(&allocation_after)) return 5;
  printf("arena.before=%lld,%lld,%lld\n", (long long)allocation_before.reserved.total,
    (long long)allocation_before.mmap_calls.total, (long long)allocation_before.arena_count.total);
  printf("arena.after=%lld,%lld,%lld\n", (long long)allocation_after.reserved.total,
    (long long)allocation_after.mmap_calls.total, (long long)allocation_after.arena_count.total);
#define COUNT_DELTA(name) printf("allocation." #name "=%lld,%lld,%lld\n", \
    (long long)(allocation_after.name.total - allocation_before.name.total), \
    (long long)(allocation_after.name.peak - allocation_before.name.peak), \
    (long long)(allocation_after.name.current - allocation_before.name.current))
#define COUNTER_DELTA(name) printf("allocation." #name "=%lld\n", \
    (long long)(allocation_after.name.total - allocation_before.name.total))
  COUNT_DELTA(pages);
  COUNT_DELTA(page_committed);
  COUNT_DELTA(committed);
  COUNT_DELTA(threads);
  COUNT_DELTA(heaps);
  COUNT_DELTA(theaps);
  COUNTER_DELTA(commit_calls);
  COUNTER_DELTA(pages_extended);
  COUNTER_DELTA(page_searches);
  COUNTER_DELTA(page_searches_count);
  for (size_t bin = 0; bin <= MI_BIN_HUGE; bin++) {
    const mi_stat_count_t* before_bin = &allocation_before.page_bins[bin];
    const mi_stat_count_t* after_bin = &allocation_after.page_bins[bin];
    printf("allocation.page_bin.%zu=%lld,%lld,%lld\n", bin,
      (long long)(after_bin->total - before_bin->total),
      (long long)(after_bin->peak - before_bin->peak),
      (long long)(after_bin->current - before_bin->current));
  }
#undef COUNT_DELTA
#undef COUNTER_DELTA

  mi_stats_print_out(&capture, NULL);
  record_capture("print_out.callback");
  mi_stats_print_out(NULL, NULL);
  record_capture("print_out.default");
  mi_stats_print(stdout);
  record_capture("print.stdout");
  mi_stats_print(NULL);
  record_capture("print.null");
  mi_thread_stats_print_out(&capture, NULL);
  record_capture("initial.thread_stats");
  mi_stats_t_decl(worker_before);
  if (!mi_stats_get(&worker_before)) return 6;
  pthread_t thread;
  if (pthread_create(&thread, NULL, worker, NULL) != 0 || pthread_join(thread, NULL) != 0) return 3;
  mi_stats_t_decl(worker_after);
  if (!mi_stats_get(&worker_after)) return 7;
#define WORKER_COUNT_DELTA(name) printf("worker." #name "=%lld,%lld,%lld\n", \
    (long long)(worker_after.name.total - worker_before.name.total), \
    (long long)(worker_after.name.peak - worker_before.name.peak), \
    (long long)(worker_after.name.current - worker_before.name.current))
  WORKER_COUNT_DELTA(threads);
  WORKER_COUNT_DELTA(pages);
  WORKER_COUNT_DELTA(heaps);
  WORKER_COUNT_DELTA(theaps);
#undef WORKER_COUNT_DELTA

  mi_stats_t_decl(before);
  mi_stats_get(&before);
  mi_stats_reset();
  mi_stats_t_decl(after);
  mi_stats_get(&after);
  printf("reset.pages=%lld,%lld\n", (long long)(after.pages.current - before.pages.current),
         (long long)(after.pages.total - before.pages.total));
  printf("reset.threads=%lld\n", (long long)(after.threads.current - before.threads.current));

  printf("bin_size=");
  for (size_t bin = 0; bin <= 76; bin++) printf("%s%zu", bin == 0 ? "" : ",", mi_stats_get_bin_size(bin));
  printf("\n");

  char* json = mi_stats_get_json(0, NULL);
  printf("json.grown=%d\n", json != NULL ? 1 : 0);
  if (json != NULL) { print_normalized("json.grown.text", json); mi_free(json); }
  char small[80];
  memset(small, 'x', sizeof(small));
  char* result = mi_stats_get_json(sizeof(small), small);
  printf("json.short=%d\n", result == NULL ? 0 : (result == small ? 1 : 2));
  printf("json.short.buffer=");
  for (size_t i = 0; i < sizeof(small); i++) printf("%02x", (unsigned char)small[i]);
  printf("\n");
  static char large[65536];
  result = mi_stats_get_json(sizeof(large), large);
  printf("json.large=%d\n", result == NULL ? 0 : (result == large ? 1 : 2));
  if (result != NULL) print_normalized("json.large.text", large);
  mi_stats_t_decl(image);
  mi_stats_get(&image);
  json = mi_stats_as_json(&image, 0, NULL);
  printf("json.as=%d\n", json != NULL ? 1 : 0);
  if (json != NULL) { print_normalized("json.as.text", json); mi_free(json); }
  mi_stats_t bad;
  memset(&bad, 0, sizeof(bad));
  printf("json.bad=%d\n", mi_stats_as_json(&bad, 0, NULL) == NULL ? 0 : 1);
  printf("json.null=%d\n", mi_stats_as_json(NULL, 0, NULL) == NULL ? 0 : 1);

  size_t elapsed = 0, user = 0, system = 0, current_rss = 0, peak_rss = 0, current_commit = 0, peak_commit = 0,
         faults = 0;
  mi_process_info(&elapsed, &user, &system, &current_rss, &peak_rss, &current_commit, &peak_commit, &faults);
  printf("process_info.rss_is_commit=%d\n", current_rss == current_commit ? 1 : 0);
  printf("process_info.commit_nonzero=%d,%d\n", current_commit != 0, peak_commit >= current_commit);
  printf("process_info.peak_rss_nonzero=%d\n", peak_rss != 0);
  mi_process_info(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
  mi_process_info_print_out(&capture, NULL);
  record_capture("process_info.callback");
  mi_process_info_print();
  record_capture("process_info.default");

  for (int i = 0; i < 4; i++) mi_free(blocks[i]);
  mi_free(live);
  printf("CRABC_MI_M7_STATISTICS_TRACE_END\n");
  return 0;
}
