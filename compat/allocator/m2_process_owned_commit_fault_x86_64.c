/* A failed commit retains a regular process-owned reservation for exact retry. */
#define _GNU_SOURCE 1
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include "static.c"

static bool capture_commit;
static unsigned protection_calls;
static void* protection_address[2];
static size_t protection_length[2];
static int protection_flags[2];
static unsigned selected_warning_count;
static bool warning_exact;
static size_t warning_offset;
static size_t warning_size;
static unsigned warning_after_attempt;
static int64_t warning_reserved;
static int64_t warning_committed;
static int64_t warning_commit_calls;
static int64_t warning_mmap_calls;
static unsigned char* owned_base;
static mi_subproc_t* observed_subproc;

int __real_mprotect(void*, size_t, int);
int __wrap_mprotect(void* address, size_t length, int protection) {
  if (capture_commit && protection == (PROT_READ | PROT_WRITE)) {
    if (protection_calls < 2) {
      protection_address[protection_calls] = address;
      protection_length[protection_calls] = length;
      protection_flags[protection_calls] = protection;
    }
    protection_calls++;
    if (protection_calls == 1) {
      errno = EIO;
      return -1;
    }
  }
  return __real_mprotect(address, length, protection);
}

static void capture_warning(const char* message, void* ignored) {
  MI_UNUSED(ignored);
  if (message == NULL || strstr(message, "cannot commit OS memory") == NULL) return;
  selected_warning_count++;
  warning_after_attempt = protection_calls;
  char expected[256];
  _mi_snprintf(expected, sizeof(expected),
      "cannot commit OS memory (error: %d (0x%02x), address: %p, size: 0x%zx bytes)\n",
      EIO, EIO, protection_address[0], protection_length[0]);
  warning_exact = strcmp(message, expected) == 0;
  warning_offset = (uintptr_t)protection_address[0] - (uintptr_t)owned_base;
  warning_size = protection_length[0];
  warning_reserved = observed_subproc->stats.reserved.current;
  warning_committed = observed_subproc->stats.committed.current;
  warning_commit_calls = observed_subproc->stats.commit_calls.total;
  warning_mmap_calls = observed_subproc->stats.mmap_calls.total;
}

#define EMIT(name, value) printf(name "=%lld\n", (long long)(value))
int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  mi_process_init();
  os_preloading = false;
  mi_option_set(mi_option_allow_large_os_pages, 0);
  mi_option_set(mi_option_allow_thp, 0);
  mi_option_set(mi_option_show_errors, 1);
  mi_option_set(mi_option_max_warnings, 100);
  mi_subproc_t* const subproc = _mi_subproc_main();
  observed_subproc = subproc;
  mi_register_output(capture_warning, NULL);
  const int64_t reserved_before = subproc->stats.reserved.current;
  const int64_t committed_before = subproc->stats.committed.current;
  const int64_t commits_before = subproc->stats.commit_calls.total;
  const int64_t mmaps_before = subproc->stats.mmap_calls.total;
  const size_t page = _mi_os_page_size();
  const size_t mapping_size = 3 * page;
  mi_memid_t memid = _mi_memid_none();
  unsigned char* const base = _mi_os_alloc_aligned(subproc, mapping_size, page,
      false /* commit */, false /* allow_large */, &memid);
  if (base == NULL || memid.memkind != MI_MEM_OS) return 2;
  owned_base = base;
  const int64_t reserved_at_map = subproc->stats.reserved.current;
  const int64_t committed_at_map = subproc->stats.committed.current;
  const int64_t commits_at_map = subproc->stats.commit_calls.total;
  const int64_t mmaps_at_map = subproc->stats.mmap_calls.total;
  const size_t request_offset = 19;
  const size_t request_size = page + 5;
  bool first_is_zero = true;
  bool retry_is_zero = true;
  capture_commit = true;
  const bool first = _mi_os_commit_ex(subproc, base + request_offset, request_size,
      &first_is_zero, 0);
  unsigned char residence = 0;
  const bool mapped_after_failure = mincore(base, page, &residence) == 0;
  const int64_t reserved_after_failure = subproc->stats.reserved.current;
  const int64_t committed_after_failure = subproc->stats.committed.current;
  const int64_t commits_after_failure = subproc->stats.commit_calls.total;
  const int64_t mmaps_after_failure = subproc->stats.mmap_calls.total;
  const bool retry = _mi_os_commit_ex(subproc, base + request_offset, request_size,
      &retry_is_zero, 0);
  capture_commit = false;
  base[0] = 0x51;
  base[page] = 0x52;
  const bool writable_after_retry = base[0] == 0x51 && base[page] == 0x52;
  const bool third_page_mapped = mincore(base + 2 * page, page, &residence) == 0;
  const int64_t reserved_after_retry = subproc->stats.reserved.current;
  const int64_t committed_after_retry = subproc->stats.committed.current;
  const int64_t commits_after_retry = subproc->stats.commit_calls.total;
  const int64_t mmaps_after_retry = subproc->stats.mmap_calls.total;
  const bool full_owner = memid.mem.os.base == base && memid.mem.os.size == mapping_size
      && !memid.initially_committed;
  _mi_os_free(subproc, base, mapping_size, memid);
  const bool terminal_unmapped = mincore(base, page, &residence) == -1 && errno == ENOMEM;
  puts("CRABC_M2_PROCESS_OWNED_COMMIT_FAULT_C_TRACE_BEGIN");
  EMIT("allocated", 1);
  EMIT("full_owner", full_owner);
  EMIT("page_size", page);
  EMIT("mapping_size", mapping_size);
  EMIT("request_offset", request_offset);
  EMIT("request_size", request_size);
  EMIT("first_failed", !first);
  EMIT("first_is_zero", first_is_zero);
  EMIT("mapped_after_failure", mapped_after_failure);
  EMIT("retry_succeeded", retry);
  EMIT("retry_is_zero", retry_is_zero);
  EMIT("writable_after_retry", writable_after_retry);
  EMIT("third_page_mapped", third_page_mapped);
  EMIT("protection_calls", protection_calls);
  EMIT("first_offset", (uintptr_t)protection_address[0] - (uintptr_t)base);
  EMIT("first_length", protection_length[0]);
  EMIT("first_flags", protection_flags[0]);
  EMIT("retry_offset", (uintptr_t)protection_address[1] - (uintptr_t)base);
  EMIT("retry_length", protection_length[1]);
  EMIT("retry_flags", protection_flags[1]);
  EMIT("warning_count", selected_warning_count);
  EMIT("warning_exact", warning_exact);
  EMIT("warning_offset", warning_offset);
  EMIT("warning_size", warning_size);
  EMIT("warning_after_attempt", warning_after_attempt);
  EMIT("reserved_at_map", reserved_at_map - reserved_before);
  EMIT("committed_at_map", committed_at_map - committed_before);
  EMIT("commits_at_map", commits_at_map - commits_before);
  EMIT("mmaps_at_map", mmaps_at_map - mmaps_before);
  EMIT("warning_reserved", warning_reserved - reserved_before);
  EMIT("warning_committed", warning_committed - committed_before);
  EMIT("warning_commit_calls", warning_commit_calls - commits_before);
  EMIT("warning_mmap_calls", warning_mmap_calls - mmaps_before);
  EMIT("reserved_after_failure", reserved_after_failure - reserved_before);
  EMIT("committed_after_failure", committed_after_failure - committed_before);
  EMIT("commits_after_failure", commits_after_failure - commits_before);
  EMIT("mmaps_after_failure", mmaps_after_failure - mmaps_before);
  EMIT("reserved_after_retry", reserved_after_retry - reserved_before);
  EMIT("committed_after_retry", committed_after_retry - committed_before);
  EMIT("commits_after_retry", commits_after_retry - commits_before);
  EMIT("mmaps_after_retry", mmaps_after_retry - mmaps_before);
  EMIT("terminal_reserved", subproc->stats.reserved.current - reserved_before);
  EMIT("terminal_committed", subproc->stats.committed.current - committed_before);
  EMIT("terminal_unmapped", terminal_unmapped);
  puts("CRABC_M2_PROCESS_OWNED_COMMIT_FAULT_C_TRACE_END");
  return 0;
}
