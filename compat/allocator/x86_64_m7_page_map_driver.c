/* Shared C driver for the allocator M7 startup page-map failure
   differential (`src/page-map.c:302-305`).

   Linked once against the pinned mimalloc v3.5.0 release sources and once
   against the native Rust adapter, each run as its own process. A priority
   101 constructor runs before either allocator's load-time process start and
   lowers the soft address-space limit to 1 MiB above the current mapping
   total, so the 2116 KiB page-map reservation fails while the rest of
   process start fits. `main` restores the limit, so every later OS request
   can succeed and only the page map is missing.

   The trace records the startup error, and for each later allocation shape
   on the initial thread and on a worker, whether it failed, its errno, and
   the error messages it reported. Warnings are counted outside the trace:
   pinned C retries the on-demand page-map commit and warns on each attempt,
   and the Rust runtime has no page map to retry (see
   `known-differences.md`, CRABC-MI-STARTUP-PAGE-MAP-FAILURE). Driven by
   `compat/allocator/x86_64_m7_gate.py --page-map-differential`. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

#include "mimalloc.h"

static struct rlimit saved_limit;
static int limit_status = -1;

__attribute__((constructor(101))) static void limit_address_space(void) {
  /* The environment image is read by each allocator's process start. */
  setenv("MIMALLOC_SHOW_ERRORS", "1", 1);
  FILE* statm = fopen("/proc/self/statm", "r");
  unsigned long pages = 0;
  if (statm == NULL) return;
  if (fscanf(statm, "%lu", &pages) != 1) pages = 0;
  fclose(statm);
  if (pages == 0 || getrlimit(RLIMIT_AS, &saved_limit) != 0) return;
  struct rlimit lowered = saved_limit;
  lowered.rlim_cur = pages * (unsigned long)sysconf(_SC_PAGESIZE) + (1ul << 20);
  limit_status = setrlimit(RLIMIT_AS, &lowered);
}

static char errors[8192];
static size_t errors_length;
static int warnings;
static enum { FRAGMENT_BODY, FRAGMENT_ERROR, FRAGMENT_WARNING } next_fragment;

static void append_error(const char* body, size_t length) {
  if (errors_length + length < sizeof(errors)) {
    memcpy(errors + errors_length, body, length);
    errors_length += length;
    errors[errors_length] = 0;
  }
}

/* Registration flushes the delayed buffer as one fragment of whole lines,
   each with its prefix and `thread 0x<id>: ` part. */
static void capture_delayed(const char* message) {
  for (const char* line = message; *line != 0; ) {
    const char* end = strchr(line, '\n');
    end = end == NULL ? line + strlen(line) : end + 1;
    if (strncmp(line, "mimalloc: error: ", 17) == 0) {
      const char* body = strstr(line, ": thread 0x");
      body = body != NULL && body < end ? strstr(body + 2, ": ") : NULL;
      if (body != NULL && body < end) append_error(body + 2, (size_t)(end - body - 2));
    } else if (strncmp(line, "mimalloc: warning: ", 19) == 0) {
      warnings++;
    }
    line = end;
  }
}

static void capture(const char* message, void* argument) {
  (void)argument;
  /* Otherwise each prefix, with its `thread 0x<id>: ` part, is its own
     fragment before the body. */
  const char* newline = strchr(message, '\n');
  if (newline != NULL && newline[1] != 0) { capture_delayed(message); next_fragment = FRAGMENT_BODY; return; }
  if (strncmp(message, "mimalloc: error: ", 17) == 0) {
    if (newline != NULL) { capture_delayed(message); return; }
    next_fragment = FRAGMENT_ERROR;
    return;
  }
  if (strncmp(message, "mimalloc: warning: ", 19) == 0) {
    if (newline != NULL) { capture_delayed(message); return; }
    next_fragment = FRAGMENT_WARNING;
    warnings++;
    return;
  }
  if (next_fragment == FRAGMENT_ERROR) append_error(message, strlen(message));
  next_fragment = FRAGMENT_BODY;
}

static void print_errors(const char* key) {
  printf("%s.errors=", key);
  for (size_t i = 0; i < errors_length; i++) printf("%02x", (unsigned char)errors[i]);
  printf("\n");
  errors_length = 0;
  errors[0] = 0;
}

static void record(const char* key, void* p, int error) {
  printf("%s.result=%s\n%s.errno=%d\n", key, p == NULL ? "null" : "block", key, error);
  print_errors(key);
  mi_free(p);
}

#define RECORD(key, expression) do { errno = 0; void* p_ = (expression); record((key), p_, errno); } while (0)

static void allocate_shapes(const char* thread) {
  char key[64];
  snprintf(key, sizeof(key), "%s.small", thread);
  RECORD(key, mi_malloc(64));
  snprintf(key, sizeof(key), "%s.zalloc", thread);
  RECORD(key, mi_zalloc(1000));
  snprintf(key, sizeof(key), "%s.calloc", thread);
  RECORD(key, mi_calloc(10, 100));
  snprintf(key, sizeof(key), "%s.medium", thread);
  RECORD(key, mi_malloc(100000));
  snprintf(key, sizeof(key), "%s.large", thread);
  RECORD(key, mi_malloc(1u << 20));
  snprintf(key, sizeof(key), "%s.huge", thread);
  RECORD(key, mi_malloc(64u << 20));
  snprintf(key, sizeof(key), "%s.aligned", thread);
  RECORD(key, mi_malloc_aligned(64, 4096));
  snprintf(key, sizeof(key), "%s.realloc_null", thread);
  RECORD(key, mi_realloc(NULL, 64));
}

static void* worker(void* argument) {
  (void)argument;
  allocate_shapes("worker");
  return NULL;
}

int main(void) {
  if (limit_status != 0) return 2;
  if (setrlimit(RLIMIT_AS, &saved_limit) != 0) return 2;
  /* Registration flushes the delayed startup output. */
  mi_register_output(&capture, NULL);
  printf("CRABC_MI_M7_PAGE_MAP_TRACE_BEGIN\n");
  print_errors("startup");
  allocate_shapes("initial");
  pthread_t thread;
  if (pthread_create(&thread, NULL, worker, NULL) != 0 || pthread_join(thread, NULL) != 0) return 3;
  printf("CRABC_MI_M7_PAGE_MAP_TRACE_END\n");
  fprintf(stderr, "warnings=%d\n", warnings);
  return 0;
}
