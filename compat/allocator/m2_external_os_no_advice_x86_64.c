/* Source policy skips advice without taking ownership of a caller's map. */
#define _GNU_SOURCE

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <mimalloc.h>
#include <mimalloc/internal.h>
#include <mimalloc/prim.h>

#include "os.c"
#include "init.c"

enum profile {
  negative_delay,
  reset_forbidden,
  decommit_empty,
  reset_empty,
  contained_control,
};

static bool capture_advice;
static unsigned advice_calls;
static void* advice_address;
static size_t advice_length;
static int advice_kind;
static unsigned warning_calls;
static bool capture_unmap;
static unsigned unmap_calls;
static void* unmapped_address;
static size_t unmapped_length;

int __real_madvise(void* address, size_t length, int advice);
int __real_munmap(void* address, size_t length);

int __wrap_madvise(void* address, size_t length, int advice) {
  if (capture_advice) {
    advice_calls++;
    advice_address = address;
    advice_length = length;
    advice_kind = advice;
  }
  return __real_madvise(address, length, advice);
}

int __wrap_munmap(void* address, size_t length) {
  if (capture_unmap) {
    unmap_calls++;
    unmapped_address = address;
    unmapped_length = length;
  }
  return __real_munmap(address, length);
}

static void capture_warning(const char* message, void* argument) {
  (void)argument;
  if (strstr(message, "cannot decommit OS memory") != NULL
      || strstr(message, "cannot reset OS memory") != NULL) warning_calls++;
}

int main(int argc, char** argv) {
  if (argc != 2) return 1;
  enum profile selected;
  if (strcmp(argv[1], "negative-delay") == 0) selected = negative_delay;
  else if (strcmp(argv[1], "reset-forbidden") == 0) selected = reset_forbidden;
  else if (strcmp(argv[1], "decommit-empty") == 0) selected = decommit_empty;
  else if (strcmp(argv[1], "reset-empty") == 0) selected = reset_empty;
  else if (strcmp(argv[1], "contained-control") == 0) selected = contained_control;
  else return 2;

  const bool decommits = selected == negative_delay || selected == decommit_empty
      || selected == contained_control;
  if (clearenv() != 0
      || setenv("mimalloc_purge_delay", selected == negative_delay ? "-1" : "0", 1) != 0
      || setenv("mimalloc_purge_decommits", decommits ? "1" : "0", 1) != 0
      || setenv("mimalloc_show_errors", "1", 1) != 0) return 3;
  _mi_auto_process_init();
  mi_option_set(mi_option_max_warnings, 100);
  mi_register_output(capture_warning, NULL);
  mi_subproc_t* const subproc = _mi_subproc_main();
  if (subproc == NULL) return 4;
  const size_t page = (size_t)sysconf(_SC_PAGESIZE);
  const size_t mapping_length = 3 * page;
  unsigned char* const mapping = mmap(NULL, mapping_length, PROT_READ | PROT_WRITE,
                                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (mapping == MAP_FAILED) return 5;
  memset(mapping, 0x5a, mapping_length);
  const bool empty = selected == decommit_empty || selected == reset_empty;
  const size_t raw_length = empty ? page - 2 : mapping_length - 2;
  const bool allow_reset = selected != reset_forbidden;
  const int64_t purge_calls_before = subproc->stats.purge_calls.total;
  const int64_t purged_before = subproc->stats.purged.total;
  const int64_t reset_calls_before = subproc->stats.reset_calls.total;
  const int64_t reset_before = subproc->stats.reset.total;
  const int64_t reserved_before = subproc->stats.reserved.current;
  const int64_t committed_before = subproc->stats.committed.current;
  capture_advice = true;
  const bool needs_recommit = _mi_os_purge_ex(subproc, mapping + 1,
      raw_length, allow_reset, page, NULL, NULL);
  capture_advice = false;
  const unsigned middle_byte = mapping[page];
  const bool neighbors_retained = mapping[0] == 0x5a && mapping[mapping_length - 1] == 0x5a;
  mapping[page] = 0x3c;
  const bool mapping_writable = mapping[page] == 0x3c;
  const bool mapping_live = mincore(mapping, page, (unsigned char[1]){0}) == 0;
  const int64_t purge_calls_delta = subproc->stats.purge_calls.total - purge_calls_before;
  const int64_t purged_delta = subproc->stats.purged.total - purged_before;
  const int64_t reset_calls_delta = subproc->stats.reset_calls.total - reset_calls_before;
  const int64_t reset_delta = subproc->stats.reset.total - reset_before;
  const int64_t reserved_delta = subproc->stats.reserved.current - reserved_before;
  const int64_t committed_delta = subproc->stats.committed.current - committed_before;
  capture_unmap = true;
  const int released = munmap(mapping, mapping_length);
  capture_unmap = false;

  puts("CRABC_M2_EXTERNAL_OS_NO_ADVICE_C_TRACE_BEGIN");
  printf("profile=%u\n", (unsigned)selected);
  printf("purge_delay_raw=%ld\n", mi_option_get(mi_option_purge_delay));
  printf("purge_decommits_raw=%ld\n", mi_option_get(mi_option_purge_decommits));
  printf("allow_reset=%u\n", (unsigned)allow_reset);
  printf("mapping_length=%zu\n", mapping_length);
  printf("raw_purge_length=%zu\n", raw_length);
  printf("advice_calls=%u\n", advice_calls);
  printf("advice_exact=%u\n", (unsigned)(advice_address == mapping + page
      && advice_length == page && advice_kind == MADV_DONTNEED));
  printf("advice_kind=%d\n", advice_kind);
  printf("needs_recommit=%u\n", (unsigned)needs_recommit);
  printf("purge_calls_delta=%lld\n", (long long)purge_calls_delta);
  printf("purged_delta=%lld\n", (long long)purged_delta);
  printf("reset_calls_delta=%lld\n", (long long)reset_calls_delta);
  printf("reset_delta=%lld\n", (long long)reset_delta);
  printf("reserved_delta=%lld\n", (long long)reserved_delta);
  printf("committed_delta=%lld\n", (long long)committed_delta);
  printf("warning_calls=%u\n", warning_calls);
  printf("middle_byte=%u\n", middle_byte);
  printf("neighbors_retained=%u\n", (unsigned)neighbors_retained);
  printf("mapping_writable=%u\n", (unsigned)mapping_writable);
  printf("mapping_live=%u\n", (unsigned)mapping_live);
  printf("terminal_unmap_calls=%u\n", unmap_calls);
  printf("terminal_unmap_exact=%u\n", (unsigned)(unmapped_address == mapping && unmapped_length == mapping_length));
  printf("caller_released=%u\n", (unsigned)(released == 0));
  puts("CRABC_M2_EXTERNAL_OS_NO_ADVICE_C_TRACE_END");
  return 0;
}
