/* A caller retains terminal ownership while the source purges its external map. */
#define _GNU_SOURCE

#include <errno.h>
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

static bool capture_advice;
static bool fail_advice;
static unsigned advice_calls;
static void* advice_address;
static size_t advice_length;
static int advice_kind;
static int advice_result;
static unsigned warning_calls;
static unsigned warning_after_purge;
static unsigned warning_exact;
static mi_subproc_t* selected_subprocess;
static int64_t purge_calls_before;
static int64_t purged_before;
static size_t raw_length;
static bool capture_unmap;
static unsigned unmap_calls;
static void* unmapped_address;
static size_t unmapped_length;
static int unmap_result;

int __real_madvise(void* address, size_t length, int advice);
int __real_munmap(void* address, size_t length);

int __wrap_madvise(void* address, size_t length, int advice) {
  if (!capture_advice) return __real_madvise(address, length, advice);
  advice_calls++;
  advice_address = address;
  advice_length = length;
  advice_kind = advice;
  if (fail_advice) {
    advice_result = -1;
    errno = EIO;
    return -1;
  }
  advice_result = __real_madvise(address, length, advice);
  return advice_result;
}

int __wrap_munmap(void* address, size_t length) {
  const int result = __real_munmap(address, length);
  if (capture_unmap) {
    unmap_calls++;
    unmapped_address = address;
    unmapped_length = length;
    unmap_result = result;
  }
  return result;
}

static void capture_warning(const char* message, void* argument) {
  (void)argument;
  if (strstr(message, "cannot decommit OS memory") == NULL) return;
  warning_calls++;
  warning_after_purge += selected_subprocess != NULL
      && selected_subprocess->stats.purge_calls.total == purge_calls_before + 1
      && selected_subprocess->stats.purged.total == purged_before + (int64_t)raw_length;
  warning_exact += strstr(message, "error: 5 (0x05)") != NULL
      && strstr(message, "size: 0x1000 bytes") != NULL;
}

int main(int argc, char** argv) {
  if (argc != 2 || (strcmp(argv[1], "success") != 0 && strcmp(argv[1], "failure") != 0)) return 1;
  fail_advice = strcmp(argv[1], "failure") == 0;
  if (clearenv() != 0 || setenv("mimalloc_purge_delay", "0", 1) != 0
      || setenv("mimalloc_purge_decommits", "1", 1) != 0
      || setenv("mimalloc_show_errors", "1", 1) != 0) return 2;
  _mi_auto_process_init();
  mi_option_set(mi_option_max_warnings, 100);
  selected_subprocess = _mi_subproc_main();
  if (selected_subprocess == NULL) return 3;
  mi_register_output(capture_warning, NULL);
  const size_t page = (size_t)sysconf(_SC_PAGESIZE);
  const size_t mapping_length = 3 * page;
  unsigned char* const mapping = mmap(NULL, mapping_length, PROT_READ | PROT_WRITE,
                                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (mapping == MAP_FAILED) return 4;
  memset(mapping, 0x5a, mapping_length);
  void* const raw_address = mapping + 1;
  raw_length = mapping_length - 2;
  purge_calls_before = selected_subprocess->stats.purge_calls.total;
  purged_before = selected_subprocess->stats.purged.total;
  const int64_t reserved_before = selected_subprocess->stats.reserved.current;
  const int64_t committed_before = selected_subprocess->stats.committed.current;
  const int64_t reset_calls_before = selected_subprocess->stats.reset_calls.total;
  capture_advice = true;
  const bool needs_recommit = _mi_os_purge_ex(selected_subprocess, raw_address,
      raw_length, true, page, NULL, NULL);
  capture_advice = false;
  const bool neighbors_retained = mapping[0] == 0x5a && mapping[mapping_length - 1] == 0x5a;
  const unsigned middle_byte = mapping[page];
  mapping[page] = 0x3c;
  const bool mapping_writable = mapping[page] == 0x3c;
  const bool mapping_live = mincore(mapping, page, (unsigned char[1]){0}) == 0;
  const int64_t purge_calls_delta = selected_subprocess->stats.purge_calls.total - purge_calls_before;
  const int64_t purged_delta = selected_subprocess->stats.purged.total - purged_before;
  const int64_t reserved_delta = selected_subprocess->stats.reserved.current - reserved_before;
  const int64_t committed_delta = selected_subprocess->stats.committed.current - committed_before;
  const int64_t reset_calls_delta = selected_subprocess->stats.reset_calls.total - reset_calls_before;
  capture_unmap = true;
  const int released = munmap(mapping, mapping_length);
  capture_unmap = false;

  puts("CRABC_M2_EXTERNAL_OS_PURGE_C_TRACE_BEGIN");
  printf("case_failure=%u\n", (unsigned)fail_advice);
  printf("purge_delay_raw=%ld\n", mi_option_get(mi_option_purge_delay));
  printf("purge_decommits_raw=%ld\n", mi_option_get(mi_option_purge_decommits));
  printf("external_mapping_length=%zu\n", mapping_length);
  printf("raw_purge_length=%zu\n", raw_length);
  printf("advice_calls=%u\n", advice_calls);
  printf("advice_exact=%u\n", (unsigned)(advice_address == mapping + page
      && advice_length == page && advice_kind == MADV_DONTNEED));
  printf("advice_result=%d\n", advice_result);
  printf("needs_recommit=%u\n", (unsigned)needs_recommit);
  printf("purge_calls_delta=%lld\n", (long long)purge_calls_delta);
  printf("purged_delta=%lld\n", (long long)purged_delta);
  printf("reset_calls_delta=%lld\n", (long long)reset_calls_delta);
  printf("reserved_delta=%lld\n", (long long)reserved_delta);
  printf("committed_delta=%lld\n", (long long)committed_delta);
  printf("warning_calls=%u\n", warning_calls);
  printf("warning_after_purge=%u\n", warning_after_purge);
  printf("warning_exact=%u\n", warning_exact);
  printf("middle_byte=%u\n", middle_byte);
  printf("neighbors_retained=%u\n", (unsigned)neighbors_retained);
  printf("mapping_writable=%u\n", (unsigned)mapping_writable);
  printf("mapping_live=%u\n", (unsigned)mapping_live);
  printf("terminal_unmap_calls=%u\n", unmap_calls);
  printf("terminal_unmap_exact=%u\n", (unsigned)(unmapped_address == mapping
      && unmapped_length == mapping_length));
  printf("terminal_unmap_result=%d\n", unmap_result);
  printf("caller_released=%u\n", (unsigned)(released == 0));
  puts("CRABC_M2_EXTERNAL_OS_PURGE_C_TRACE_END");
  return 0;
}
