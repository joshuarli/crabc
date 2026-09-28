/* A failed mixed external commit leaves its caller-owned map available for retry. */
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

static bool capture_commit;
static unsigned commit_attempts;
static void* commit_addresses[2];
static size_t commit_lengths[2];
static int commit_protections[2];
static int commit_results[2];
static unsigned warning_calls;
static unsigned warning_after_call;
static unsigned warning_before_charge;
static unsigned warning_exact;
static mi_subproc_t* selected_subproc;
static int64_t calls_before;
static int64_t committed_before;
static bool capture_unmap;
static unsigned unmap_calls;
static void* unmapped_address;
static size_t unmapped_length;

int __real_mprotect(void* address, size_t length, int protection);
int __real_munmap(void* address, size_t length);

int __wrap_mprotect(void* address, size_t length, int protection) {
  if (!capture_commit) return __real_mprotect(address, length, protection);
  const unsigned index = commit_attempts++;
  if (index >= 2) return -1;
  commit_addresses[index] = address;
  commit_lengths[index] = length;
  commit_protections[index] = protection;
  if (index == 0) {
    errno = EIO;
    commit_results[index] = -1;
    return -1;
  }
  commit_results[index] = __real_mprotect(address, length, protection);
  return commit_results[index];
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
  if (strstr(message, "cannot commit OS memory") == NULL) return;
  warning_calls++;
  warning_after_call += selected_subproc->stats.commit_calls.total == calls_before + 1;
  warning_before_charge += selected_subproc->stats.committed.current == committed_before;
  warning_exact += strstr(message, "error: 5 (0x05)") != NULL
      && strstr(message, "size: 0x2000 bytes") != NULL;
}

int main(void) {
  if (clearenv() != 0 || setenv("mimalloc_show_errors", "1", 1) != 0) return 1;
  _mi_auto_process_init();
  mi_option_set(mi_option_max_warnings, 100);
  selected_subproc = _mi_subproc_main();
  if (selected_subproc == NULL) return 2;
  mi_register_output(capture_warning, NULL);
  const size_t page = (size_t)sysconf(_SC_PAGESIZE);
  const size_t length = 2 * page;
  unsigned char* const mapping = mmap(NULL, length, PROT_NONE,
                                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (mapping == MAP_FAILED || mprotect(mapping, page, PROT_READ | PROT_WRITE) != 0) return 3;
  mapping[0] = 0x5a;
  calls_before = selected_subproc->stats.commit_calls.total;
  committed_before = selected_subproc->stats.committed.current;
  const int64_t committed_total_before = selected_subproc->stats.committed.total;
  const int64_t reserved_before = selected_subproc->stats.reserved.current;

  capture_commit = true;
  const bool first_committed = _mi_os_commit_ex(selected_subproc, mapping, length, NULL, page);
  const int64_t calls_after_failure = selected_subproc->stats.commit_calls.total - calls_before;
  const int64_t current_after_failure = selected_subproc->stats.committed.current - committed_before;
  const int64_t total_after_failure = selected_subproc->stats.committed.total - committed_total_before;
  const bool first_retained = mapping[0] == 0x5a;
  const bool mapping_live_after_failure = mincore(mapping, page, (unsigned char[1]){0}) == 0;
  const bool retry_committed = _mi_os_commit_ex(selected_subproc, mapping, length, NULL, page);
  capture_commit = false;
  mapping[page] = 0x3c;
  const bool second_writable = mapping[page] == 0x3c;
  const int64_t calls_after_retry = selected_subproc->stats.commit_calls.total - calls_before;
  const int64_t current_after_retry = selected_subproc->stats.committed.current - committed_before;
  const int64_t total_after_retry = selected_subproc->stats.committed.total - committed_total_before;
  const int64_t reserved_delta = selected_subproc->stats.reserved.current - reserved_before;
  capture_unmap = true;
  const int released = munmap(mapping, length);
  capture_unmap = false;

  puts("CRABC_M2_EXTERNAL_OS_COMMIT_FAILURE_C_TRACE_BEGIN");
  printf("mapping_length=%zu\n", length);
  printf("already_committed=%zu\n", page);
  printf("attempts=%u\n", commit_attempts);
  printf("first_exact=%u\n", (unsigned)(commit_addresses[0] == mapping
      && commit_lengths[0] == length && commit_protections[0] == (PROT_READ | PROT_WRITE)));
  printf("retry_exact=%u\n", (unsigned)(commit_addresses[1] == mapping
      && commit_lengths[1] == length && commit_protections[1] == (PROT_READ | PROT_WRITE)));
  printf("first_primitive_result=%d\n", commit_results[0]);
  printf("retry_primitive_result=%d\n", commit_results[1]);
  printf("first_source_committed=%u\n", (unsigned)first_committed);
  printf("retry_source_committed=%u\n", (unsigned)retry_committed);
  printf("calls_after_failure=%lld\n", (long long)calls_after_failure);
  printf("current_after_failure=%lld\n", (long long)current_after_failure);
  printf("total_after_failure=%lld\n", (long long)total_after_failure);
  printf("warning_calls=%u\n", warning_calls);
  printf("warning_after_call=%u\n", warning_after_call);
  printf("warning_before_charge=%u\n", warning_before_charge);
  printf("warning_exact=%u\n", warning_exact);
  printf("first_retained=%u\n", (unsigned)first_retained);
  printf("mapping_live_after_failure=%u\n", (unsigned)mapping_live_after_failure);
  printf("calls_after_retry=%lld\n", (long long)calls_after_retry);
  printf("current_after_retry=%lld\n", (long long)current_after_retry);
  printf("total_after_retry=%lld\n", (long long)total_after_retry);
  printf("reserved_delta=%lld\n", (long long)reserved_delta);
  printf("second_writable=%u\n", (unsigned)second_writable);
  printf("terminal_unmap_calls=%u\n", unmap_calls);
  printf("terminal_unmap_exact=%u\n", (unsigned)(unmapped_address == mapping && unmapped_length == length));
  printf("caller_released=%u\n", (unsigned)(released == 0));
  puts("CRABC_M2_EXTERNAL_OS_COMMIT_FAILURE_C_TRACE_END");
  return 0;
}
