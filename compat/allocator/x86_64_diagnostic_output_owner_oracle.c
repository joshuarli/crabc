/*
 * Pinned mimalloc v3.5.0 `src/options.c` diagnostic-output source fixture.
 *
 * This is a private future C half for `x86_64_diagnostic_output_owner_evidence.py`.
 * It does not select a public mi_* API, a libc backend, a VM receiver, or a
 * runtime integration path.
 */

#include "mimalloc.h"
#include "mimalloc/internal.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

/* `stats.c` keeps this exact formatter private; the source fixture calls it
 * directly so the comparison cannot accidentally substitute a public
 * statistics API or a subprocess-state query. */
void _mi_stats_print(const char* name, size_t id, const mi_stats_t* stats,
                     mi_output_fun* out, void* arg) mi_attr_noexcept;

#define MAX_MESSAGES 40
#define MAX_MESSAGE_BYTES 256

typedef struct capture_s {
  size_t count;
  size_t lengths[MAX_MESSAGES];
  char messages[MAX_MESSAGES][MAX_MESSAGE_BYTES];
} capture_t;

static void capture_reset(capture_t* capture) {
  memset(capture, 0, sizeof(*capture));
}

static void capture_output(const char* message, void* argument) {
  capture_t* const capture = (capture_t*)argument;
  if (message == NULL || capture == NULL || capture->count >= MAX_MESSAGES) return;
  const size_t length = _mi_strnlen(message, MAX_MESSAGE_BYTES - 1);
  const size_t index = capture->count++;
  memcpy(capture->messages[index], message, length);
  capture->messages[index][length] = 0;
  capture->lengths[index] = length;
}

static void print_capture(const char* scenario, const capture_t* capture, uintptr_t thread_identity) {
  printf("%s=", scenario);
  for (size_t index = 0; index < capture->count; index++) {
    if (index != 0) printf(":");
    for (size_t byte = 0; byte < capture->lengths[index]; byte++) {
      printf("%02x", (unsigned char)capture->messages[index][byte]);
    }
  }
  printf("\n");
  /* Observe the same run's `_mi_thread_id()` independently of its prefix. */
  printf("thread_identity=%" PRIxPTR "\n", thread_identity);
}

static void initialize_diagnostic_options(long show_errors, long show_stats, long verbose, long max_warnings) {
  mi_option_set(mi_option_show_errors, show_errors);
  mi_option_set(mi_option_show_stats, show_stats);
  mi_option_set(mi_option_verbose, verbose);
  mi_option_set(mi_option_max_warnings, max_warnings);
  _mi_options_init();
}

static int run_release(void) {
  capture_t capture;
  initialize_diagnostic_options(0, 0, 0, 32);
  capture_reset(&capture);
  mi_register_output(&capture_output, &capture);
  capture_reset(&capture);  /* source registration flushed its empty buffer */
  const uintptr_t thread_identity = (uintptr_t)_mi_thread_id();
  _mi_warning_message("%s", "selected mbind failure\n");
  print_capture("release", &capture, thread_identity);
  return 0;
}

static int run_enabled(void) {
  capture_t capture;
  initialize_diagnostic_options(1, 0, 0, 1);
  capture_reset(&capture);
  mi_register_output(&capture_output, &capture);
  capture_reset(&capture);
  const uintptr_t thread_identity = (uintptr_t)_mi_thread_id();
  _mi_warning_message("%s", "selected mbind failure\n");
  print_capture("enabled", &capture, thread_identity);
  return 0;
}

static int run_cap(void) {
  capture_t capture;
  initialize_diagnostic_options(1, 0, 0, 1);
  capture_reset(&capture);
  mi_register_output(&capture_output, &capture);
  capture_reset(&capture);
  const uintptr_t thread_identity = (uintptr_t)_mi_thread_id();
  _mi_warning_message("%s", "first\n");
  _mi_warning_message("%s", "second\n");
  print_capture("cap", &capture, thread_identity);
  return 0;
}

static int run_verbose(void) {
  capture_t capture;
  initialize_diagnostic_options(0, 0, 1, 0);
  capture_reset(&capture);
  mi_register_output(&capture_output, &capture);
  capture_reset(&capture);
  const uintptr_t thread_identity = (uintptr_t)_mi_thread_id();
  _mi_warning_message("%s", "first\n");
  _mi_warning_message("%s", "second\n");
  print_capture("verbose", &capture, thread_identity);
  return 0;
}

static int run_delayed(void) {
  capture_t capture;
  capture_reset(&capture);
  const uintptr_t thread_identity = (uintptr_t)_mi_thread_id();
  _mi_raw_message("early\n");
  mi_register_output(&capture_output, &capture);
  _mi_raw_message("later\n");
  print_capture("delayed", &capture, thread_identity);
  return 0;
}

static int run_null(void) {
  capture_t capture;
  capture_reset(&capture);
  const uintptr_t thread_identity = (uintptr_t)_mi_thread_id();
  _mi_raw_message("early\n");
  mi_register_output(NULL, NULL);
  _mi_raw_message("stderr\n");
  mi_register_output(&capture_output, &capture);
  print_capture("null", &capture, thread_identity);
  return 0;
}

static int run_post_init(void) {
  capture_t capture;
  initialize_diagnostic_options(0, 0, 0, 32);
  capture_reset(&capture);
  const uintptr_t thread_identity = (uintptr_t)_mi_thread_id();
  _mi_raw_message("early\n");
  _mi_options_post_init();
  _mi_raw_message("later\n");
  mi_register_output(&capture_output, &capture);
  print_capture("post_init", &capture, thread_identity);
  return 0;
}

/* Write one fixed release-profile `mi_stat_count_t` image. The three fields
 * are deliberately named in C's storage order, unlike the display's
 * peak/total/current column order. */
static void set_stat_count(mi_stat_count_t* stat, int64_t total, int64_t peak, int64_t current) {
  stat->total = total;
  stat->peak = peak;
  stat->current = current;
}

static void set_stat_counter(mi_stat_counter_t* stat, int64_t total) {
  stat->total = total;
}

/*
 * The source half of the final-output comparison. It calls the retained
 * `stats.c:356-430` formatter with a scalar image that has already crossed
 * the source merge boundary. The fixture does not model process teardown:
 * `stats.c` itself supplies the line buffering and process-info formatting,
 * while the explicit source condition below retains `init.c:636-640` and
 * `subproc.c:241-245`'s signed show_stats-or-verbose gate. The verbose tail
 * is dispatched separately, as `init.c:649` requires after later teardown.
 */
static int run_final_stats(void) {
  capture_t capture;
  mi_stats_t stats;
  initialize_diagnostic_options(0, -7, -1, 32);
  capture_reset(&capture);
  mi_register_output(&capture_output, &capture);
  capture_reset(&capture);
  mi_stats_init(&stats);

  set_stat_count(&stats.pages, 7, 5, 2);
  set_stat_count(&stats.page_committed, 5120, 6144, 4096);
  set_stat_count(&stats.pages_abandoned, 2, 1, 0);
  set_stat_count(&stats.threads, 2, 2, 1);
  set_stat_count(&stats.reserved, 3072, 2048, 1024);
  set_stat_count(&stats.committed, 3072, 2048, 1024);
  set_stat_count(&stats.theaps, 2, 2, 1);
  set_stat_count(&stats.heaps, 3, 3, 1);
  set_stat_counter(&stats.reset, 1024);
  set_stat_counter(&stats.purged, 2048);
  set_stat_counter(&stats.mmap_calls, 3);
  set_stat_counter(&stats.commit_calls, 4);
  set_stat_counter(&stats.reset_calls, 5);
  set_stat_counter(&stats.purge_calls, 6);
  set_stat_counter(&stats.arena_count, 1);
  set_stat_counter(&stats.malloc_guarded_count, 7);
  set_stat_counter(&stats.arena_rollback_count, 2);
  set_stat_counter(&stats.pages_reclaim_on_alloc, 3);
  set_stat_counter(&stats.pages_reclaim_on_free, 4);
  set_stat_counter(&stats.pages_reabandon_full, 5);
  set_stat_counter(&stats.pages_unabandon_busy_wait, 6);
  set_stat_counter(&stats.pages_extended, 7);
  set_stat_counter(&stats.pages_retire, 8);
  set_stat_counter(&stats.page_searches, 9);
  set_stat_counter(&stats.page_searches_count, 2);
  set_stat_counter(&stats.heaps_delete_wait, 8);

  if (mi_option_is_enabled(mi_option_show_stats) || mi_option_is_enabled(mi_option_verbose)) {
    _mi_stats_print("subproc", 7, &stats, &capture_output, &capture);
  }
  _mi_verbose_message("process done %zu\n", (size_t)97);
  print_capture("final_stats", &capture, (uintptr_t)_mi_thread_id());
  return 0;
}

int main(int argc, char** argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: %s SCENARIO\n", argv[0]);
    return 64;
  }
  if (strcmp(argv[1], "release") == 0) return run_release();
  if (strcmp(argv[1], "enabled") == 0) return run_enabled();
  if (strcmp(argv[1], "cap") == 0) return run_cap();
  if (strcmp(argv[1], "verbose") == 0) return run_verbose();
  if (strcmp(argv[1], "delayed") == 0) return run_delayed();
  if (strcmp(argv[1], "null") == 0) return run_null();
  if (strcmp(argv[1], "post_init") == 0) return run_post_init();
  if (strcmp(argv[1], "final_stats") == 0) return run_final_stats();
  fprintf(stderr, "unknown scenario: %s\n", argv[1]);
  return 64;
}
