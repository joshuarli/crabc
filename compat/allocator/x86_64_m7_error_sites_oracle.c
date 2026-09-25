/* Pinned-C half of the allocator M7 error-reporting-site differential.

   This probe includes the pinned mimalloc v3.5.0 `src/static.c` and runs with
   `mimalloc_show_errors=1`, so every release-live allocation `_mi_error_message`
   site it reaches is shown. For each request it prints the TID-normalized
   output fragments, whether the call returned NULL, and the errno the
   source's default error policy left after starting from zero. The Rust half
   is the `native_error_sites` integration test, which drives the matching
   native entries (`native_allocate` for `mi_malloc`, `native_allocate_aligned`
   and `native_allocate_aligned_at` for the aligned forms) and prints the same
   keys. Driven by `compat/allocator/x86_64_m7_gate.py --error-sites-differential`. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "static.c"

#define MAX_MESSAGES 16
#define MAX_MESSAGE_BYTES 256

static size_t message_count;
static char messages[MAX_MESSAGES][MAX_MESSAGE_BYTES];
static char thread_text[40];

static void capture_output(const char* message, void* argument) {
  (void)argument;
  if (message == NULL || message[0] == 0) return;
  if (message_count < MAX_MESSAGES) {
    snprintf(messages[message_count], MAX_MESSAGE_BYTES, "%s", message);
  }
  message_count++;
}

static void print_hex(const char* bytes, size_t length) {
  for (size_t i = 0; i < length; i++) printf("%02x", (unsigned char)bytes[i]);
}

static void print_messages(const char* name) {
  printf("error_site.%s.messages=", name);
  const size_t thread_length = strlen(thread_text);
  for (size_t index = 0; index < message_count && index < MAX_MESSAGES; index++) {
    if (index != 0) printf(":");
    const char* message = messages[index];
    const size_t length = strlen(message);
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

/* The force flag of every deferred-free invocation during one request: the
   forced collection before the `mi_find_page` retry calls it with `true`. */
static char deferred[64];
static size_t deferred_count;

static void record_deferred(bool force, unsigned long long heartbeat, void* argument) {
  (void)heartbeat; (void)argument;
  if (deferred_count < sizeof(deferred) - 1) deferred[deferred_count++] = force ? '1' : '0';
}

static void report(const char* name, void* p) {
  const int error = errno;
  print_messages(name);
  deferred[deferred_count] = 0;
  printf("error_site.%s.deferred=%s\n", name, deferred);
  printf("error_site.%s.null=%d\nerror_site.%s.errno=%d\n", name, p == NULL ? 1 : 0, name, error);
  if (p != NULL) mi_free(p);
}

#define CASE(name, call) do { \
  message_count = 0; \
  deferred_count = 0; \
  errno = 0; \
  void* p = (call); \
  report(name, p); \
} while (0)

static volatile size_t too_large;

/* The same requests on one thread; `prefix` distinguishes the main thread
   from a worker whose Theap is initialized by its first request. */
static void run_cases(const char* prefix) {
  char name[96];
#define NAMED(suffix) (snprintf(name, sizeof(name), "%s%s", prefix, suffix), name)
  snprintf(thread_text, sizeof(thread_text), "0x%02lX", (unsigned long)_mi_thread_id());
  /* `src/page.c:951-954` on each `mi_find_page` attempt, then `src/page.c:1061-1064`. */
  CASE(NAMED("malloc_too_large"), mi_malloc(too_large));
  /* `src/alloc-aligned.c:191-193`. */
  CASE(NAMED("aligned_bad_alignment"), mi_malloc_aligned(100, 24));
  /* `src/alloc-aligned.c:163-166`. */
  CASE(NAMED("aligned_too_large"), mi_malloc_aligned(too_large, 16));
  /* `src/alloc-aligned.c:81-84`: an alignment above `MI_PAGE_MAX_OVERALLOC_ALIGN`. */
  CASE(NAMED("aligned_large_alignment_offset"), mi_malloc_aligned_at(100, (size_t)1 << 20, 8));
  /* A nonzero offset skips the natural path; the over-allocation then
     exceeds `MI_MAX_ALLOC_SIZE`, so `mi_find_page` refuses it. */
  CASE(NAMED("aligned_overallocation_too_large"), mi_malloc_aligned_at((size_t)PTRDIFF_MAX - 16, 4096, 8));
  /* An ordinary valid request reports nothing. */
  CASE(NAMED("malloc_ordinary"), mi_malloc(100));
#undef NAMED
}

static void* worker(void* argument) {
  (void)argument;
  run_cases("worker_");
  return NULL;
}

int main(void) {
  mi_register_output(&capture_output, NULL);
  mi_register_deferred_free(&record_deferred, NULL);
  /* volatile: keep the compiler from diagnosing the constant request. */
  too_large = (size_t)PTRDIFF_MAX + 1;
  printf("CRABC_MI_M7_ERROR_SITES_TRACE_BEGIN\n");
  /* Process startup (`src/init.c:575-579`) reserved `mimalloc_reserve_os_memory`
     KiB; a size beyond `MI_MAX_ALLOC_SIZE` reported `src/arena.c:1891-1894`
     into the delayed buffer, which `_mi_options_post_init` flushed to stderr
     before `main`. The driver reads that stderr as the startup record. The
     registration above flushed the buffer again; discard that copy. */
  message_count = 0;
  run_cases("");
  pthread_t thread;
  if (pthread_create(&thread, NULL, worker, NULL) != 0 || pthread_join(thread, NULL) != 0) return 3;
  printf("CRABC_MI_M7_ERROR_SITES_TRACE_END\n");
  return 0;
}
