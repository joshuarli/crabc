/* Shared C driver for the allocator M7 adapter differential.

   The same unmodified source is linked once against the pinned mimalloc
   v3.5.0 release sources (`src/static.c`) and once against the native Rust
   adapter (`native-mi-adapter/`), and each binary runs as its own process
   with an empty environment. It calls only the public `mimalloc.h` and
   `mimalloc-stats.h` M7 entries (options, callbacks, statistics) and prints
   address-free `key=value` facts, so the two traces must be identical.
   Output fragments have the calling thread's `0x<tid>` replaced by `0xTID`.
   Driven by `compat/allocator/x86_64_m7_gate.py --adapter-differential`. */
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Walloc-size-larger-than="
#endif
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>

#include "mimalloc.h"
#include "mimalloc-stats.h"

#define MAX_MESSAGES 128
#define MAX_MESSAGE_BYTES 256

static size_t message_count;
static char messages[MAX_MESSAGES][MAX_MESSAGE_BYTES];
static char thread_text[40];

static void capture(const char* message, void* argument) {
  (void)argument;
  if (message == NULL || message[0] == 0) return;
  if (message_count < MAX_MESSAGES) snprintf(messages[message_count], MAX_MESSAGE_BYTES, "%s", message);
  message_count++;
}

static void print_hex(const char* bytes, size_t length) {
  for (size_t i = 0; i < length; i++) printf("%02x", (unsigned char)bytes[i]);
}

static void print_messages(const char* key) {
  printf("%s=", key);
  const size_t thread_length = strlen(thread_text);
  for (size_t index = 0; index < message_count && index < MAX_MESSAGES; index++) {
    if (index != 0) printf(":");
    const char* message = messages[index];
    const size_t length = strlen(message);
    for (size_t i = 0; i < length; ) {
      if (thread_length > 0 && i + thread_length <= length && memcmp(message + i, thread_text, thread_length) == 0) {
        print_hex("0xTID", 5);
        i += thread_length;
      } else {
        print_hex(message + i, 1);
        i++;
      }
    }
  }
  printf("\n");
  message_count = 0;
}

static int error_codes[16];
static size_t error_count;
static char error_argument;
static bool error_argument_seen;

static void record_error(int code, void* argument) {
  if (error_count < 16) error_codes[error_count] = code;
  error_count++;
  error_argument_seen = (argument == &error_argument);
}

static char deferred[64];
static size_t deferred_count;

static void record_deferred(bool force, unsigned long long heartbeat, void* argument) {
  (void)heartbeat; (void)argument;
  if (deferred_count < sizeof(deferred) - 1) deferred[deferred_count++] = force ? '1' : '0';
}

static void options_section(void) {
  printf("version=%d\n", mi_version());
  printf("option.get.verbose=%ld\n", mi_option_get(mi_option_verbose));
  printf("option.get.arena_reserve=%ld\n", mi_option_get(mi_option_arena_reserve));
  printf("option.size.arena_reserve=%zu\n", mi_option_get_size(mi_option_arena_reserve));
  printf("option.clamp.purge_delay=%ld\n", mi_option_get_clamp(mi_option_purge_delay, 5, 10));
  mi_option_set(mi_option_purge_delay, 42);
  printf("option.set.purge_delay=%ld\n", mi_option_get(mi_option_purge_delay));
  mi_option_set_default(mi_option_purge_delay, 7);
  printf("option.set_default.initialized=%ld\n", mi_option_get(mi_option_purge_delay));
  mi_option_enable(mi_option_disallow_os_alloc);
  printf("option.enable=%d\n", mi_option_is_enabled(mi_option_disallow_os_alloc) ? 1 : 0);
  mi_option_disable(mi_option_disallow_os_alloc);
  printf("option.disable=%d\n", mi_option_is_enabled(mi_option_disallow_os_alloc) ? 1 : 0);
  mi_option_set_enabled(mi_option_guarded_precise, true);
  printf("option.set_enabled=%ld\n", mi_option_get(mi_option_guarded_precise));
  mi_option_set_enabled_default(mi_option_guarded_precise, false);
  printf("option.set_enabled_default=%ld\n", mi_option_get(mi_option_guarded_precise));
  mi_option_set(mi_option_guarded_min, 1L << 20);
  printf("option.guarded_coupling=%ld,%ld\n", mi_option_get(mi_option_guarded_min), mi_option_get(mi_option_guarded_max));
  printf("option.invalid.get=%ld\n", mi_option_get((mi_option_t)-1));
  printf("option.invalid.size=%zu\n", mi_option_get_size((mi_option_t)_mi_option_last));
  printf("option.invalid.enabled=%d\n", mi_option_is_enabled((mi_option_t)1000) ? 1 : 0);
  mi_option_set((mi_option_t)_mi_option_last, 3);
  mi_options_print_out(&capture, NULL);
  print_messages("print_out");
}

static void callbacks_section(void) {
  /* Registration flushes the delayed buffer; discard it. */
  mi_register_output(&capture, NULL);
  message_count = 0;
  mi_options_print();
  print_messages("print.registered");
  mi_option_enable(mi_option_show_errors);
  mi_register_error(&record_error, &error_argument);
  errno = 0;
  volatile size_t too_large = (size_t)PTRDIFF_MAX + 1;
  void* p = mi_malloc(too_large);
  printf("error.handled.null=%d\n", p == NULL ? 1 : 0);
  printf("error.handled.errno=%d\n", errno);
  printf("error.handled.codes=");
  for (size_t i = 0; i < error_count && i < 16; i++) printf("%s%d", i == 0 ? "" : ",", error_codes[i]);
  printf("\nerror.handled.argument=%d\n", error_argument_seen ? 1 : 0);
  print_messages("error.handled.messages");
  mi_register_error(NULL, NULL);
  errno = 0;
  p = mi_malloc_aligned(100, 24);
  printf("error.default.errno=%d\n", errno);
  print_messages("error.default.messages");
  mi_option_disable(mi_option_show_errors);
  mi_register_deferred_free(&record_deferred, NULL);
  mi_collect(true);
  mi_collect(false);
  deferred[deferred_count] = 0;
  printf("deferred.collect=%s\n", deferred);
  mi_register_deferred_free(NULL, NULL);
}

static void stats_section(void) {
  mi_stats_t bad;
  memset(&bad, 0, sizeof(bad));
  printf("stats.bad_header=%d\n", mi_stats_get(&bad) ? 1 : 0);
  printf("stats.null=%d\n", mi_stats_get(NULL) ? 1 : 0);
  mi_collect(true);
  mi_stats_t_decl(before);
  printf("stats.ok=%d\n", mi_stats_get(&before) ? 1 : 0);
  printf("stats.header=%zu,%zu\n", before.size, before.version);
  void* blocks[4];
  for (int i = 0; i < 4; i++) blocks[i] = mi_malloc(1 << 20);
  mi_stats_t_decl(during);
  mi_stats_get(&during);
  for (int i = 0; i < 4; i++) mi_free(blocks[i]);
  mi_collect(true);
  mi_stats_t_decl(after);
  mi_stats_get(&after);
  printf("stats.pages.during=%lld\n", (long long)(during.pages.current - before.pages.current));
  printf("stats.pages.after=%lld\n", (long long)(after.pages.current - before.pages.current));
  printf("stats.threads.current=%lld\n", (long long)before.threads.current);
}

static void* worker(void* argument) {
  (void)argument;
  mi_stats_t_decl(stats);
  printf("worker.stats.ok=%d\n", mi_stats_get(&stats) ? 1 : 0);
  printf("worker.stats.threads.current=%lld\n", (long long)stats.threads.current);
  return NULL;
}

int main(void) {
  snprintf(thread_text, sizeof(thread_text), "0x%02lX", (unsigned long)(uintptr_t)pthread_self());
  printf("CRABC_MI_M7_ADAPTER_TRACE_BEGIN\n");
  options_section();
  callbacks_section();
  stats_section();
  pthread_t thread;
  if (pthread_create(&thread, NULL, worker, NULL) != 0 || pthread_join(thread, NULL) != 0) return 3;
  printf("CRABC_MI_M7_ADAPTER_TRACE_END\n");
  return 0;
}
