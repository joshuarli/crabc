/* A failed metadata-sized regular OS map leaves no owner; a retry owns one exact map. */
#define _GNU_SOURCE 1
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include "static.c"

static bool capture_map;
static unsigned map_calls;
static void* map_address[2];
static size_t map_length[2];
static int map_protection[2];
static int map_flags[2];
static unsigned captured_warning_count;
static bool warning_errno;
static bool warning_size;
static unsigned warning_after_attempt;
static int64_t warning_reserved;
static int64_t warning_committed;
static int64_t warning_mmap_calls;
static int64_t warning_commit_calls;
static mi_subproc_t* observed_subproc;

void* __real_mmap(void*, size_t, int, int, int, off_t);
void* __wrap_mmap(void* address, size_t length, int protection, int flags, int descriptor, off_t offset) {
  if (capture_map) {
    if (map_calls < 2) {
      map_address[map_calls] = address;
      map_length[map_calls] = length;
      map_protection[map_calls] = protection;
      map_flags[map_calls] = flags;
    }
    map_calls++;
    if (map_calls == 1) {
      errno = ENOMEM;
      return MAP_FAILED;
    }
  }
  return __real_mmap(address, length, protection, flags, descriptor, offset);
}

static void capture_warning(const char* message, void* ignored) {
  MI_UNUSED(ignored);
  if (message == NULL || strstr(message, "unable to allocate OS memory") == NULL) return;
  captured_warning_count++;
  warning_errno = strstr(message, "error: 12 (0x0C)") != NULL;
  char size_text[64];
  _mi_snprintf(size_text, sizeof(size_text), "size: 0x%zx bytes", map_length[0]);
  warning_size = strstr(message, size_text) != NULL;
  warning_after_attempt = map_calls;
  warning_reserved = observed_subproc->stats.reserved.current;
  warning_committed = observed_subproc->stats.committed.current;
  warning_mmap_calls = observed_subproc->stats.mmap_calls.total;
  warning_commit_calls = observed_subproc->stats.commit_calls.total;
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
  const int64_t mmaps_before = subproc->stats.mmap_calls.total;
  const int64_t commits_before = subproc->stats.commit_calls.total;
  const size_t page = _mi_os_page_size();
  const size_t request_size = 2 * page;
  mi_memid_t first_id = _mi_memid_none();
  mi_memid_t retry_id = _mi_memid_none();
  capture_map = true;
  void* const first = _mi_os_alloc(subproc, request_size, &first_id);
  const int64_t failed_reserved = subproc->stats.reserved.current - reserved_before;
  const int64_t failed_committed = subproc->stats.committed.current - committed_before;
  const int64_t failed_mmaps = subproc->stats.mmap_calls.total - mmaps_before;
  const int64_t failed_commits = subproc->stats.commit_calls.total - commits_before;
  unsigned char* const retry = _mi_os_alloc(subproc, request_size, &retry_id);
  capture_map = false;
  if (retry == NULL) return 2;
  retry[0] = 0x51;
  retry[page] = 0x52;
  const bool writable = retry[0] == 0x51 && retry[page] == 0x52;
  const bool full_owner = retry_id.memkind == MI_MEM_OS
      && retry_id.mem.os.base == retry && retry_id.mem.os.size == request_size
      && retry_id.initially_committed;
  const int64_t retry_reserved = subproc->stats.reserved.current - reserved_before;
  const int64_t retry_committed = subproc->stats.committed.current - committed_before;
  const int64_t retry_mmaps = subproc->stats.mmap_calls.total - mmaps_before;
  const int64_t retry_commits = subproc->stats.commit_calls.total - commits_before;
  _mi_os_free(subproc, retry, request_size, retry_id);
  unsigned char residence = 0;
  const bool terminal_unmapped = mincore(retry, page, &residence) == -1 && errno == ENOMEM;
  puts("CRABC_M2_PROCESS_OWNED_MAP_FAULT_C_TRACE_BEGIN");
  EMIT("page_size", page);
  EMIT("request_size", request_size);
  EMIT("first_failed", first == NULL);
  EMIT("first_no_owner", first_id.memkind == MI_MEM_NONE);
  EMIT("map_calls", map_calls);
  EMIT("first_null_hint", map_address[0] == NULL);
  EMIT("first_length", map_length[0]);
  EMIT("first_protection", map_protection[0]);
  EMIT("first_anonymous_private", (map_flags[0] & (MAP_ANONYMOUS | MAP_PRIVATE)) == (MAP_ANONYMOUS | MAP_PRIVATE));
  EMIT("retry_null_hint", map_address[1] == NULL);
  EMIT("retry_length", map_length[1]);
  EMIT("retry_protection", map_protection[1]);
  EMIT("retry_anonymous_private", (map_flags[1] & (MAP_ANONYMOUS | MAP_PRIVATE)) == (MAP_ANONYMOUS | MAP_PRIVATE));
  EMIT("warning_count", captured_warning_count);
  EMIT("warning_errno", warning_errno);
  EMIT("warning_size", warning_size);
  EMIT("warning_after_attempt", warning_after_attempt);
  EMIT("warning_reserved", warning_reserved - reserved_before);
  EMIT("warning_committed", warning_committed - committed_before);
  EMIT("warning_mmap_calls", warning_mmap_calls - mmaps_before);
  EMIT("warning_commit_calls", warning_commit_calls - commits_before);
  EMIT("failed_reserved", failed_reserved);
  EMIT("failed_committed", failed_committed);
  EMIT("failed_mmaps", failed_mmaps);
  EMIT("failed_commits", failed_commits);
  EMIT("retry_succeeded", retry != NULL);
  EMIT("full_owner", full_owner);
  EMIT("writable", writable);
  EMIT("retry_reserved", retry_reserved);
  EMIT("retry_committed", retry_committed);
  EMIT("retry_mmaps", retry_mmaps);
  EMIT("retry_commits", retry_commits);
  EMIT("terminal_reserved", subproc->stats.reserved.current - reserved_before);
  EMIT("terminal_committed", subproc->stats.committed.current - committed_before);
  EMIT("terminal_unmapped", terminal_unmapped);
  puts("CRABC_M2_PROCESS_OWNED_MAP_FAULT_C_TRACE_END");
  return 0;
}
