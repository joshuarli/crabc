/* A caller-owned partly committed map retains its release owner. */
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

static bool capture_commit;
static unsigned commit_attempts;
static void* commit_address;
static size_t commit_length;
static int commit_protection;
static int commit_result;
static bool capture_unmap;
static unsigned unmap_calls;
static void* unmap_address;
static size_t unmap_length;

int __real_mprotect(void* address, size_t length, int protection);
int __real_munmap(void* address, size_t length);

int __wrap_mprotect(void* address, size_t length, int protection) {
  if (capture_commit) {
    commit_attempts++;
    commit_address = address;
    commit_length = length;
    commit_protection = protection;
  }
  const int result = __real_mprotect(address, length, protection);
  if (capture_commit) commit_result = result;
  return result;
}

int __wrap_munmap(void* address, size_t length) {
  if (capture_unmap) {
    unmap_calls++;
    unmap_address = address;
    unmap_length = length;
  }
  return __real_munmap(address, length);
}

int main(void) {
  if (clearenv() != 0) return 1;
  _mi_auto_process_init();
  mi_subproc_t* const subproc = _mi_subproc_main();
  if (subproc == NULL) return 2;
  const size_t page = (size_t)sysconf(_SC_PAGESIZE);
  const size_t length = 2 * page;
  unsigned char* const mapping = mmap(NULL, length, PROT_NONE,
                                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (mapping == MAP_FAILED || mprotect(mapping, page, PROT_READ | PROT_WRITE) != 0) return 3;
  mapping[0] = 0x5a;

  const int64_t calls_before = subproc->stats.commit_calls.total;
  const int64_t committed_before = subproc->stats.committed.current;
  const int64_t committed_total_before = subproc->stats.committed.total;
  const int64_t reserved_before = subproc->stats.reserved.current;
  capture_commit = true;
  const bool committed = _mi_os_commit_ex(subproc, mapping, length, NULL, page);
  capture_commit = false;
  const bool first_retained = mapping[0] == 0x5a;
  mapping[page] = 0x3c;
  const bool second_writable = mapping[page] == 0x3c;
  const bool map_live = mincore(mapping, page, (unsigned char[1]){0}) == 0;
  const int64_t calls_delta = subproc->stats.commit_calls.total - calls_before;
  const int64_t current_delta = subproc->stats.committed.current - committed_before;
  const int64_t total_delta = subproc->stats.committed.total - committed_total_before;
  const int64_t reserved_delta = subproc->stats.reserved.current - reserved_before;
  capture_unmap = true;
  const int released = munmap(mapping, length);
  capture_unmap = false;

  puts("CRABC_M2_EXTERNAL_OS_COMMIT_C_TRACE_BEGIN");
  printf("mapping_length=%zu\n", length);
  printf("already_committed=%zu\n", page);
  printf("commit_attempts=%u\n", commit_attempts);
  printf("commit_exact=%u\n", (unsigned)(commit_address == mapping
      && commit_length == length && commit_protection == (PROT_READ | PROT_WRITE)));
  printf("commit_result=%d\n", commit_result);
  printf("source_committed=%u\n", (unsigned)committed);
  printf("commit_calls_delta=%lld\n", (long long)calls_delta);
  printf("committed_current_delta=%lld\n", (long long)current_delta);
  printf("committed_total_delta=%lld\n", (long long)total_delta);
  printf("reserved_delta=%lld\n", (long long)reserved_delta);
  printf("first_retained=%u\n", (unsigned)first_retained);
  printf("second_writable=%u\n", (unsigned)second_writable);
  printf("mapping_live=%u\n", (unsigned)map_live);
  printf("terminal_unmap_calls=%u\n", unmap_calls);
  printf("terminal_unmap_exact=%u\n", (unsigned)(unmap_address == mapping && unmap_length == length));
  printf("caller_released=%u\n", (unsigned)(released == 0));
  puts("CRABC_M2_EXTERNAL_OS_COMMIT_C_TRACE_END");
  return 0;
}
