/* Pinned-C half of the allocator M7 options/environment differential.

   This probe includes the pinned mimalloc v3.5.0 `src/static.c` as one
   translation unit so it can reset the private `mi_options[]` table between
   environment scenarios. Each scenario replays the option prefix of
   `mi_process_init_once` (src/init.c:540-544) against a fixed `environ`
   image and prints the descriptor table, the TID-normalized warning
   fragments, and the option API results as `key=value` lines. The Rust half is
   `diagnostic_output::tests::source_options_trace_for_pinned_c_comparison`;
   both halves print the environment entries they install, so a drift in
   either scenario list fails the comparison instead of passing vacuously.
   Driven by `compat/allocator/x86_64_m7_gate.py --options-differential`. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "static.c"

extern char** environ;

#define MAX_MESSAGES 80
#define MAX_MESSAGE_BYTES 256
#define MAX_ENTRIES 32

typedef struct capture_s {
  size_t count;
  size_t lengths[MAX_MESSAGES];
  char messages[MAX_MESSAGES][MAX_MESSAGE_BYTES];
} capture_t;

static long initial_values[_mi_option_last];
static char thread_text[40];

static void capture_output(const char* message, void* argument) {
  capture_t* capture = (capture_t*)argument;
  if (message == NULL || capture == NULL) return;
  const size_t index = capture->count++;
  const size_t length = strlen(message);
  if (index >= MAX_MESSAGES || length > MAX_MESSAGE_BYTES) return;
  memcpy(capture->messages[index], message, length);
  capture->lengths[index] = length;
}

static void print_hex(const char* bytes, size_t length) {
  for (size_t i = 0; i < length; i++) printf("%02x", (unsigned char)bytes[i]);
}

/* Replace the live `0x<thread>` spelling with `0xTID` before hex encoding. */
static void print_capture(const capture_t* capture) {
  if (capture->count > MAX_MESSAGES) { fprintf(stderr, "capture overflow\n"); exit(3); }
  const size_t thread_length = strlen(thread_text);
  for (size_t index = 0; index < capture->count; index++) {
    if (index != 0) printf(":");
    const char* message = capture->messages[index];
    const size_t length = capture->lengths[index];
    for (size_t i = 0; i < length; ) {
      if (i + thread_length <= length && memcmp(message + i, thread_text, thread_length) == 0) {
        print_hex("0xTID", 5);
        i += thread_length;
      } else {
        print_hex(message + i, 1);
        i++;
      }
    }
  }
  printf("\n");
}

static void reset_options(void) {
  for (int i = 0; i < _mi_option_last; i++) {
    mi_options[i].value = initial_values[i];
    mi_options[i].init = MI_OPTION_UNINIT;
  }
  mi_atomic_store_release(&warning_count, (size_t)0);
  mi_atomic_store_release(&error_count, (size_t)0);
  mi_max_warning_count = 16;
  mi_max_error_count = 16;
}

/* The option prefix of `mi_process_init_once` (src/init.c:540-544). */
static void initialize_options(void) {
  _mi_verbose_message("process init: 0x%zx\n", _mi_thread_id());
  _mi_options_init();
}

static char* scenario_vector[MAX_ENTRIES + 1];

static void install_environment(const char* scenario, const char* const* entries, size_t count) {
  printf("scenario.%s.environment=", scenario);
  for (size_t i = 0; i < count; i++) {
    if (i != 0) printf(":");
    print_hex(entries[i], strlen(entries[i]));
    scenario_vector[i] = (char*)entries[i];
  }
  printf("\n");
  scenario_vector[count] = NULL;
  environ = scenario_vector;
}

static void run_scenario(const char* scenario, const char* const* entries, size_t count) {
  static capture_t capture;
  install_environment(scenario, entries, count);
  reset_options();
  memset(&capture, 0, sizeof(capture));
  mi_register_output(&capture_output, &capture);
  capture.count = 0;
  initialize_options();
  printf("scenario.%s.messages=", scenario);
  print_capture(&capture);
  for (int i = 0; i < _mi_option_last; i++) {
    const long value = mi_options[i].value;
    const int init = (int)mi_options[i].init;
    const size_t size = mi_option_get_size((mi_option_t)i);
    printf("scenario.%s.option.%s=%ld,%d,%zu\n", scenario, mi_options[i].name, value, init, size);
  }
  printf("scenario.%s.lazy_messages=", scenario);
  print_capture(&capture);
}

#define RUN(name, ...) do { \
  static const char* const entries[] = { __VA_ARGS__ }; \
  run_scenario(name, entries, sizeof(entries) / sizeof(entries[0])); \
} while (0)

static void record(const char* step, long value) { printf("api.%s=%ld\n", step, value); }

static void image(const char* step, mi_option_t option) {
  printf("api.%s=%ld,%d\n", step, mi_options[option].value, (int)mi_options[option].init);
}

/* `_mi_error_message` (src/options.c:596-608): two default-policy reports,
   one through a registered handler, and one after clearing it. Each result
   is the handler's code (0 when uncalled), whether it saw the registered
   argument, and errno after a report that started with errno 0. */
static int handler_code;
static void* handler_argument;
static char handler_sentinel;

static void record_error(int code, void* argument) {
  handler_code = code;
  handler_argument = argument;
}

static void run_error_scenario(const char* scenario, const char* const* entries, size_t count) {
  static capture_t capture;
  static const struct { int code; const char* message; bool handled; } steps[] = {
    { ENOMEM, "first report\n", false },
    { EINVAL, "second report\n", false },
    { EOVERFLOW, "third report\n", false },
    { EFAULT, "handled report\n", true },
    { EAGAIN, "cleared report\n", false },
  };
  printf("error.%s.environment=", scenario);
  for (size_t i = 0; i < count; i++) {
    if (i != 0) printf(":");
    print_hex(entries[i], strlen(entries[i]));
    scenario_vector[i] = (char*)entries[i];
  }
  printf("\n");
  scenario_vector[count] = NULL;
  environ = scenario_vector;
  reset_options();
  memset(&capture, 0, sizeof(capture));
  mi_register_output(&capture_output, &capture);
  initialize_options();
  capture.count = 0;
  printf("error.%s.results=", scenario);
  for (size_t i = 0; i < sizeof(steps) / sizeof(steps[0]); i++) {
    handler_code = 0;
    handler_argument = NULL;
    mi_register_error(steps[i].handled ? &record_error : NULL, &handler_sentinel);
    errno = 0;
    _mi_error_message(steps[i].code, "%s", steps[i].message);
    printf("%s%d/%d/%d", i == 0 ? "" : ",", handler_code,
           handler_argument == &handler_sentinel ? 1 : 0, errno);
  }
  printf("\n");
  mi_register_error(NULL, NULL);
  printf("error.%s.messages=", scenario);
  print_capture(&capture);
}

#define ERROR_RUN(name, ...) do { \
  static const char* const entries[] = { __VA_ARGS__ }; \
  const size_t count = sizeof(entries) / sizeof(entries[0]); \
  run_error_scenario(name, entries, (count == 1 && entries[0] == NULL) ? 0 : count); \
} while (0)

/* Recursive diagnostic output. The registered callback reads `verbose`
   through `mi_option_get` on every delivery and, on its first delivery,
   re-enters `_mi_warning_message`. Pinned C restores a temporarily enabled
   invalid `verbose` only after that warning's delivery returns, and has no
   recursion guard on Linux, so both the observed values and the nested
   fragments are source behavior. */
static capture_t recursion_capture;
static long recursion_verbose[MAX_MESSAGES];
static int recursion_reentries;
static bool recursion_active;

static void recursive_output(const char* message, void* argument) {
  /* The registration flush only captures: reading `verbose` there would
     initialize it inside `mi_register_output`. */
  if (!recursion_active) { capture_output(message, argument); return; }
  const size_t index = recursion_capture.count;
  const long verbose = mi_option_get(mi_option_verbose);
  if (index < MAX_MESSAGES) recursion_verbose[index] = verbose;
  capture_output(message, argument);
  if (recursion_reentries == 0) {
    recursion_reentries++;
    _mi_warning_message("reentered warning\n");
  }
}

static void print_recursion(const char* scenario, const char* step) {
  printf("recursion.%s.%s.messages=", scenario, step);
  print_capture(&recursion_capture);
  printf("recursion.%s.%s.verbose=", scenario, step);
  for (size_t i = 0; i < recursion_capture.count && i < MAX_MESSAGES; i++) {
    printf("%s%ld", i == 0 ? "" : ",", recursion_verbose[i]);
  }
  printf("\n");
}

static void run_recursion_scenario(const char* scenario, const char* const* entries, size_t count) {
  printf("recursion.%s.environment=", scenario);
  for (size_t i = 0; i < count; i++) {
    if (i != 0) printf(":");
    print_hex(entries[i], strlen(entries[i]));
    scenario_vector[i] = (char*)entries[i];
  }
  printf("\n");
  scenario_vector[count] = NULL;
  environ = scenario_vector;
  reset_options();
  memset(&recursion_capture, 0, sizeof(recursion_capture));
  recursion_active = false;
  mi_register_output(&recursive_output, &recursion_capture);
  recursion_capture.count = 0;
  recursion_reentries = 0;
  recursion_active = true;
  initialize_options();
  print_recursion(scenario, "init");
  printf("recursion.%s.final_verbose=%ld,%d\n", scenario,
         mi_options[mi_option_verbose].value, (int)mi_options[mi_option_verbose].init);
  recursion_capture.count = 0;
  recursion_reentries = 0;
  _mi_warning_message("direct warning\n");
  print_recursion(scenario, "direct");
}

#define RECURSION_RUN(name, ...) do { \
  static const char* const entries[] = { __VA_ARGS__ }; \
  run_recursion_scenario(name, entries, sizeof(entries) / sizeof(entries[0])); \
} while (0)

/* `mi_vfprintf_thread`'s `"%sthread 0x%tx: "` prefix for fixed identities. */
static void print_thread_prefix(const char* name, uintptr_t identity) {
  char prefix[64];
  _mi_snprintf(prefix, sizeof(prefix), "%sthread 0x%tx: ", "mimalloc: warning: ", identity);
  printf("format.thread_prefix.%s=", name);
  print_hex(prefix, strlen(prefix));
  printf("\n");
}

int main(void) {
  for (int i = 0; i < _mi_option_last; i++) initial_values[i] = mi_options[i].value;
  snprintf(thread_text, sizeof(thread_text), "0x%02lX", (unsigned long)_mi_thread_id());

  printf("CRABC_MI_M7_OPTIONS_TRACE_BEGIN\n");
  printf("options.count=%d\n", (int)_mi_option_last);
  for (int i = 0; i < _mi_option_last; i++) {
    printf("options.descriptor.%d=%s,%s,%d\n", i, mi_options[i].name,
           mi_options[i].legacy_name == NULL ? "-" : mi_options[i].legacy_name,
           mi_option_has_size_in_kib((mi_option_t)i) ? 1 : 0);
  }

  {
    static char* empty_vector[1] = { NULL };
    printf("scenario.empty.environment=\n");
    environ = empty_vector;
    static capture_t capture;
    reset_options();
    memset(&capture, 0, sizeof(capture));
    mi_register_output(&capture_output, &capture);
    capture.count = 0;
    initialize_options();
    printf("scenario.empty.messages=");
    print_capture(&capture);
    for (int i = 0; i < _mi_option_last; i++) {
      const long value = mi_options[i].value;
      const int init = (int)mi_options[i].init;
      const size_t size = mi_option_get_size((mi_option_t)i);
      printf("scenario.empty.option.%s=%ld,%d,%zu\n", mi_options[i].name, value, init, size);
    }
    printf("scenario.empty.lazy_messages=");
    print_capture(&capture);
  }
  RUN("canonical",
      "MIMALLOC_PURGE_DELAY=250",
      "mimalloc_arena_reserve=2MiB",
      "mimalloc_reserve_os_memory=3g",
      "mimalloc_minimal_purge_size=1500",
      "mimalloc_arena_max_object_size=-5",
      "Mimalloc_Allow_Thp=off",
      "mimalloc_page_full_retain=",
      "mimalloc_os_tag=yes",
      "mimalloc_generic_collect=+42",
      "mimalloc_page_max_reclaim= -3",
      "mimalloc_guarded_min=4096",
      "mimalloc_guarded_max=100",
      "mimalloc_max_vabits=39",
      "mimalloc_deprecated_eager_commit=0",
      "mimalloc_retry_on_oom=TRUE",
      "mimalloc_use_numa_nodes=9223372036854775807",
      "mimalloc_reserve_huge_os_pages_at=-9223372036854775808",
      "mimalloc_arena_purge_mult=1tb",
      "mimalloc_verbose",
      "mimalloc_show_stats_extra=1",
      "unrelated=1");
  RUN("legacy",
      "mimalloc_show_errors=1",
      "mimalloc_reset_delay=5",
      "MIMALLOC_LARGE_OS_PAGES=1",
      "mimalloc_decommit_extend_delay=bogus",
      "mimalloc_abandoned_reclaim_on_free=1",
      "mimalloc_purge_decommits=0",
      "mimalloc_reset_decommits=1",
      "mimalloc_eager_region_commit=1",
      "mimalloc_limit_os_alloc=0");
  RUN("invalid",
      "mimalloc_show_errors=1",
      "mimalloc_arena_reserve=12Q",
      "mimalloc_max_warnings=2",
      "mimalloc_purge_delay=9223372036854775808",
      "mimalloc_reserve_os_memory=99999999999999999999T",
      "mimalloc_arena_max_object_size=9223372036854775807T",
      "mimalloc_minimal_purge_size=4kib",
      "mimalloc_verbose=bogus");
  RUN("verbose",
      "mimalloc_verbose=1",
      "mimalloc_arena_reserve=zz",
      "mimalloc_reset_delay=7");
  RUN("guarded_boolean",
      "mimalloc_guarded_min=TRUE",
      "mimalloc_guarded_max=0");
  RUN("guarded_numeric",
      "mimalloc_guarded_min=2000",
      "mimalloc_guarded_max=off",
      "mimalloc_guarded_sample_rate=7");
  RUN("size_without_digits",
      "mimalloc_show_errors=1",
      "mimalloc_arena_reserve=K",
      "mimalloc_reserve_os_memory=MiB",
      "mimalloc_minimal_purge_size=b",
      "mimalloc_arena_max_object_size=-K",
      "mimalloc_purge_delay=K");
  RUN("cap",
      "mimalloc_show_errors=1",
      "mimalloc_max_warnings=0",
      "mimalloc_deprecated_eager_commit=x",
      "mimalloc_arena_eager_commit=x",
      "mimalloc_purge_decommits=x",
      "mimalloc_allow_large_os_pages=x",
      "mimalloc_reserve_huge_os_pages=x",
      "mimalloc_reserve_huge_os_pages_at=x",
      "mimalloc_reserve_os_memory=x",
      "mimalloc_deprecated_segment_cache=x",
      "mimalloc_deprecated_page_reset=x",
      "mimalloc_deprecated_abandoned_page_purge=x",
      "mimalloc_deprecated_segment_reset=x",
      "mimalloc_deprecated_eager_commit_delay=x",
      "mimalloc_purge_delay=x",
      "mimalloc_use_numa_nodes=x",
      "mimalloc_disallow_os_alloc=x",
      "mimalloc_os_tag=x",
      "mimalloc_max_errors=x",
      "mimalloc_deprecated_max_segment_reclaim=x",
      "mimalloc_destroy_on_exit=x",
      "mimalloc_arena_reserve=x");
  RUN("overlong",
      "mimalloc_show_errors=1",
      "mimalloc_purge_delay=11111111111111111111111111111111111111111111111111111111111111111",
      "mimalloc_reset_delay=3",
      "mimalloc_arena_reserve=0000000000000000000000000000000000000000000000000000000000000007");

  {
    static char* empty_vector[1] = { NULL };
    static capture_t capture;
    static capture_t print;
    environ = empty_vector;
    reset_options();
    memset(&capture, 0, sizeof(capture));
    mi_register_output(&capture_output, &capture);
    capture.count = 0;
    initialize_options();
    record("clamp.arena_purge_mult", mi_option_get_clamp(mi_option_arena_purge_mult, 5, 10));
    record("clamp.purge_delay_low", mi_option_get_clamp(mi_option_purge_delay, -1, 100));
    record("clamp.purge_delay_inverted", mi_option_get_clamp(mi_option_purge_delay, 2000, 10));
    record("clamp.reserve_at", mi_option_get_clamp(mi_option_reserve_huge_os_pages_at, 0, 5));
    mi_option_set(mi_option_arena_reserve, LONG_MAX);
    record("size.arena_reserve_max", (long)mi_option_get_size(mi_option_arena_reserve));
    mi_option_set(mi_option_arena_reserve, -5);
    record("size.arena_reserve_negative", (long)mi_option_get_size(mi_option_arena_reserve));
    mi_option_set(mi_option_arena_reserve, 3);
    record("size.arena_reserve_three", (long)mi_option_get_size(mi_option_arena_reserve));
    mi_option_set(mi_option_purge_delay, -5);
    record("size.purge_delay_negative", (long)mi_option_get_size(mi_option_purge_delay));
    mi_option_set(mi_option_purge_delay, 7);
    record("size.purge_delay_seven", (long)mi_option_get_size(mi_option_purge_delay));
    mi_option_set(mi_option_guarded_min, 1L << 31);
    image("guarded.raise_min.min", mi_option_guarded_min);
    image("guarded.raise_min.max", mi_option_guarded_max);
    mi_option_set(mi_option_guarded_max, 10);
    image("guarded.lower_max.min", mi_option_guarded_min);
    image("guarded.lower_max.max", mi_option_guarded_max);
    mi_option_set(mi_option_guarded_max, 20);
    image("guarded.raise_max.min", mi_option_guarded_min);
    image("guarded.raise_max.max", mi_option_guarded_max);
    mi_option_set_default(mi_option_show_stats, 7);
    image("set_default.defaulted", mi_option_show_stats);
    mi_option_set(mi_option_show_stats, 0);
    mi_option_set_default(mi_option_show_stats, 9);
    image("set_default.initialized", mi_option_show_stats);
    mi_option_set_enabled(mi_option_allow_thp, false);
    mi_option_set_enabled_default(mi_option_allow_thp, true);
    image("enabled.allow_thp", mi_option_allow_thp);
    mi_option_set_enabled_default(mi_option_os_tag, true);
    image("enabled.os_tag_default", mi_option_os_tag);
    mi_option_enable(mi_option_disallow_os_alloc);
    image("enabled.enable", mi_option_disallow_os_alloc);
    mi_option_disable(mi_option_disallow_os_alloc);
    image("enabled.disable", mi_option_disallow_os_alloc);
    record("enabled.arena_eager_commit", mi_option_is_enabled(mi_option_arena_eager_commit) ? 1 : 0);
    record("invalid.get_negative", mi_option_get((mi_option_t)-1));
    record("invalid.get_last", mi_option_get((mi_option_t)_mi_option_last));
    record("invalid.get_large", mi_option_get((mi_option_t)1000));
    record("invalid.clamp", mi_option_get_clamp((mi_option_t)-1, 5, 10));
    record("invalid.enabled", mi_option_is_enabled((mi_option_t)_mi_option_last) ? 1 : 0);
    /* Out-of-range mutation is ignored by the source; the traces below and
       the full print prove it left every descriptor unchanged. */
    mi_option_set((mi_option_t)_mi_option_last, 3);
    mi_option_set_default((mi_option_t)-1, 3);
    memset(&print, 0, sizeof(print));
    mi_options_print_out(&capture_output, &print);
    printf("api.print=");
    print_capture(&print);
    printf("api.messages=");
    print_capture(&capture);
  }
  ERROR_RUN("hidden", NULL);
  ERROR_RUN("capped", "mimalloc_show_errors=1", "mimalloc_max_errors=1");
  ERROR_RUN("verbose", "mimalloc_verbose=1", "mimalloc_max_errors=0");
  RECURSION_RUN("invalid_verbose", "mimalloc_verbose=bogus");
  RECURSION_RUN("show_errors", "mimalloc_show_errors=1", "mimalloc_arena_reserve=bogus");
  RECURSION_RUN("capped", "mimalloc_show_errors=1", "mimalloc_max_warnings=0",
                "mimalloc_arena_reserve=bogus", "mimalloc_purge_delay=bogus");
  print_thread_prefix("zero", 0);
  print_thread_prefix("small", 0xA);
  print_thread_prefix("wide", 0xABC0D);
  printf("CRABC_MI_M7_OPTIONS_TRACE_END\n");
  return 0;
}
