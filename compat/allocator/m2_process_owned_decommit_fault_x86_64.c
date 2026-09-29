/* A failed decommit advisory leaves the process-owned map and its accounting live. */
#define _GNU_SOURCE 1
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include "static.c"

static bool capture_advice;
static bool fail_first_advice;
static unsigned advice_calls;
static void* advice_address[2];
static size_t advice_length[2];
static int advice_kind[2];
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

int __real_madvise(void*, size_t, int);
int __wrap_madvise(void* address, size_t length, int advice) {
  if (capture_advice) {
    if (advice_calls < 2) {
      advice_address[advice_calls] = address;
      advice_length[advice_calls] = length;
      advice_kind[advice_calls] = advice;
    }
    advice_calls++;
    if (fail_first_advice) {
      fail_first_advice = false;
      errno = EIO;
      return -1;
    }
  }
  return __real_madvise(address, length, advice);
}

static void capture_warning(const char* message, void* ignored) {
  MI_UNUSED(ignored);
  if (message == NULL || strstr(message, "cannot decommit OS memory") == NULL) return;
  selected_warning_count++;
  warning_after_attempt = advice_calls;
  char expected[256];
  _mi_snprintf(expected, sizeof(expected),
      "cannot decommit OS memory (error: %d (0x%x), address: %p, size: 0x%zx bytes)\n",
      EIO, EIO, advice_address[0], advice_length[0]);
  warning_exact = strcmp(message, expected) == 0;
  warning_offset = (uintptr_t)advice_address[0] - (uintptr_t)owned_base;
  warning_size = advice_length[0];
  warning_reserved = observed_subproc->stats.reserved.current;
  warning_committed = observed_subproc->stats.committed.current;
  warning_commit_calls = observed_subproc->stats.commit_calls.total;
  warning_mmap_calls = observed_subproc->stats.mmap_calls.total;
}

#if MI_DEBUG >= 1
static bool is_debug_protected(const unsigned char* address) {
  FILE* maps = fopen("/proc/self/maps", "r");
  if (maps == NULL) return false;
  char line[256];
  bool protected = false;
  while (fgets(line, sizeof(line), maps) != NULL) {
    unsigned long start, end;
    char permissions[5];
    if (sscanf(line, "%lx-%lx %4s", &start, &end, permissions) == 3
        && start <= (uintptr_t)address && (uintptr_t)address < end) {
      protected = strcmp(permissions, "---p") == 0;
      break;
    }
  }
  fclose(maps);
  return protected;
}
#endif

#define EMIT(name, value) printf(name "=%lld\n", (long long)(value))
int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  mi_process_init();
  os_preloading = false;
  mi_option_set(mi_option_allow_large_os_pages, 0);
  mi_option_set(mi_option_allow_thp, 0);
  mi_option_set(mi_option_purge_delay, -1);
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
  const size_t request_size = 3 * page;
  mi_memid_t memid = _mi_memid_none();
  unsigned char* const base = _mi_os_alloc(subproc, request_size, &memid);
  if (base == NULL || memid.memkind != MI_MEM_OS) return 2;
  owned_base = base;
  const int64_t reserved_at_map = subproc->stats.reserved.current;
  const int64_t committed_at_map = subproc->stats.committed.current;
  const int64_t commits_at_map = subproc->stats.commit_calls.total;
  const int64_t mmaps_at_map = subproc->stats.mmap_calls.total;
  const size_t request_offset = 19;
  const size_t decommit_size = 2 * page + 5;
  base[page] = 0x51;
  fail_first_advice = true;
  capture_advice = true;
  const bool first = _mi_os_decommit(subproc, base + request_offset, decommit_size);
#if MI_DEBUG >= 1
  if (!is_debug_protected(base + page)) return 20;
  bool first_zero = false;
  if (!_mi_os_commit_ex(subproc, base + page, page, &first_zero, page)) return 21;
#endif
  const bool retained_after_failure = base[page] == 0x51;
  const bool retry = _mi_os_decommit(subproc, base + request_offset, decommit_size);
#if MI_DEBUG >= 1
  if (!is_debug_protected(base + page)) return 22;
  bool retry_zero = false;
  if (!_mi_os_commit_ex(subproc, base + request_offset, decommit_size, &retry_zero, 0)) return 23;
#endif
  capture_advice = false;
  unsigned char residence = 0;
  const bool mapped_after_retry = mincore(base + page, page, &residence) == 0;
  base[page] = 0x52;
  const bool writable_after_retry = base[page] == 0x52;
  const int64_t reserved_after_retry = subproc->stats.reserved.current;
  const int64_t committed_after_retry = subproc->stats.committed.current;
  const int64_t commits_after_retry = subproc->stats.commit_calls.total;
  const int64_t mmaps_after_retry = subproc->stats.mmap_calls.total;
  const bool full_owner = memid.mem.os.base == base && memid.mem.os.size == request_size;
  _mi_os_free(subproc, base, request_size, memid);
  const bool terminal_unmapped = mincore(base, page, &residence) == -1 && errno == ENOMEM;
  puts("CRABC_M2_PROCESS_OWNED_DECOMMIT_FAULT_C_TRACE_BEGIN");
  EMIT("allocated", 1);
  EMIT("full_owner", full_owner);
  EMIT("page_size", page);
  EMIT("mapping_size", memid.mem.os.size);
  EMIT("request_offset", request_offset);
  EMIT("request_size", decommit_size);
  EMIT("first_failed", !first);
  EMIT("retained_after_failure", retained_after_failure);
  EMIT("retry_succeeded", retry);
  EMIT("mapped_after_retry", mapped_after_retry);
  EMIT("writable_after_retry", writable_after_retry);
  EMIT("advice_calls", advice_calls);
  EMIT("first_offset", (uintptr_t)advice_address[0] - (uintptr_t)base);
  EMIT("first_length", advice_length[0]);
  EMIT("first_kind", advice_kind[0]);
  EMIT("retry_offset", (uintptr_t)advice_address[1] - (uintptr_t)base);
  EMIT("retry_length", advice_length[1]);
  EMIT("retry_kind", advice_kind[1]);
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
  EMIT("reserved_after_retry", reserved_after_retry - reserved_before);
  EMIT("committed_after_retry", committed_after_retry - committed_before);
  EMIT("commits_after_retry", commits_after_retry - commits_before);
  EMIT("mmaps_after_retry", mmaps_after_retry - mmaps_before);
  EMIT("terminal_reserved", subproc->stats.reserved.current - reserved_before);
  EMIT("terminal_committed", subproc->stats.committed.current - committed_before);
  EMIT("terminal_unmapped", terminal_unmapped);
  puts("CRABC_M2_PROCESS_OWNED_DECOMMIT_FAULT_C_TRACE_END");
  return 0;
}
