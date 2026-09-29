/* One failed published OS-page release does not consume a later OS-page owner. */
#define _GNU_SOURCE 1
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "static.c"

static bool fail_first_unmap;
static unsigned unmap_calls;
static void* failed_address;
static size_t failed_length;
static void* selected_second_address;
static size_t selected_second_length;
static bool second_range_exact;
static bool warning_active;
static unsigned warning_calls;
static bool warning_exact;
static bool warning_before_stats;
static mi_subproc_t* subproc;
static int64_t warning_reserved_before;
static int64_t warning_committed_before;

int __real_munmap(void*, size_t);
int __wrap_munmap(void* address, size_t length) {
  if (fail_first_unmap) {
    fail_first_unmap = false;
    unmap_calls++;
    failed_address = address;
    failed_length = length;
    errno = EIO;
    return -1;
  }
  if (address == selected_second_address && length == selected_second_length) {
    unmap_calls++;
    second_range_exact = true;
  }
  return __real_munmap(address, length);
}

static void capture_warning(const char* message, void* ignored) {
  MI_UNUSED(ignored);
  if (!warning_active || message == NULL ||
      strstr(message, "unable to free OS memory") == NULL) return;
  warning_calls++;
  char expected[256];
  _mi_snprintf(expected, sizeof(expected),
      "unable to free OS memory (error: %d (0x%x), size: 0x%zx bytes, address: %p)\n",
      EIO, EIO, failed_length, failed_address);
  warning_exact = strcmp(message, expected) == 0;
  warning_before_stats = subproc->stats.reserved.current == warning_reserved_before
      && subproc->stats.committed.current == warning_committed_before
      && unmap_calls == 1;
}

static bool live_page(void* address) {
  unsigned char residence = 0;
  return mincore(address, (size_t)sysconf(_SC_PAGESIZE), &residence) == 0;
}

#define EMIT(name, value) printf(name "=%lld\n", (long long)(value))

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  mi_process_init();
  subproc = _mi_subproc_main();
  mi_option_set(mi_option_disallow_arena_alloc, 1);
  mi_option_set(mi_option_page_commit_on_demand, 0);
  mi_option_set(mi_option_allow_large_os_pages, 0);
  mi_option_set(mi_option_allow_thp, 0);
  mi_option_set(mi_option_purge_delay, -1);
  mi_option_set(mi_option_show_errors, 1);
  mi_option_set(mi_option_max_warnings, 100);
  mi_register_output(capture_warning, NULL);
  mi_theap_t* const theap = subproc->theap_meta;
  mi_page_t* const first = _mi_arenas_page_alloc(theap, 16 * MI_KiB, 1);
  if (first == NULL || first->memid.memkind != MI_MEM_OS) return 2;
  const mi_memid_t first_id = first->memid;
  const void* first_start = mi_page_start(first);
  void* const first_base = first_id.mem.os.base;
  const size_t first_size = first_id.mem.os.size;
  const bool first_published = first_id.initially_committed
      && first->slice_pcommitted == 0
      && _mi_checked_ptr_page(mi_page_start(first)) == first;
  warning_reserved_before = subproc->stats.reserved.current;
  warning_committed_before = subproc->stats.committed.current;
  const int64_t commit_calls_before = subproc->stats.commit_calls.total;
  const int64_t mmap_calls_before = subproc->stats.mmap_calls.total;
  warning_active = true;
  fail_first_unmap = true;
  _mi_arenas_page_free(first, theap);
  warning_active = false;
  const bool first_page_map_clear = _mi_checked_ptr_page(first_start) == NULL;
  const bool first_escaped = live_page(first_base);
  const bool failed_range_exact = unmap_calls == 1
      && failed_address == first_base && failed_length == first_size;
  const int64_t first_reserved_delta = subproc->stats.reserved.current - warning_reserved_before;
  const int64_t first_committed_delta = subproc->stats.committed.current - warning_committed_before;
  const int64_t first_commit_calls_delta = subproc->stats.commit_calls.total - commit_calls_before;
  const int64_t first_mmap_calls_delta = subproc->stats.mmap_calls.total - mmap_calls_before;
  const int64_t second_reserved_before = subproc->stats.reserved.current;
  const int64_t second_committed_before = subproc->stats.committed.current;
  mi_page_t* const second = _mi_arenas_page_alloc(theap, 16 * MI_KiB, 1);
  if (second == NULL || second->memid.memkind != MI_MEM_OS) return 3;
  const mi_memid_t second_id = second->memid;
  void* const second_base = second_id.mem.os.base;
  const size_t second_size = second_id.mem.os.size;
  selected_second_address = second_base;
  selected_second_length = second_size;
  const int64_t second_live_reserved = subproc->stats.reserved.current - second_reserved_before;
  const int64_t second_live_committed = subproc->stats.committed.current - second_committed_before;
  const bool second_published = second_id.initially_committed
      && second->slice_pcommitted == 0
      && _mi_checked_ptr_page(mi_page_start(second)) == second
      && second_base != first_base && live_page(first_base);
  _mi_arenas_page_free(second, theap);
  const bool second_unmapped = !live_page(second_base);
  const bool first_still_escaped = live_page(first_base);
  const int64_t second_reserved_delta = subproc->stats.reserved.current - second_reserved_before;
  const int64_t second_committed_delta = subproc->stats.committed.current - second_committed_before;
  const bool raw_cleanup = __real_munmap(first_base, first_size) == 0;
  const bool terminal_unmapped = !live_page(first_base) && !live_page(second_base);
  const int64_t raw_reserved_delta = subproc->stats.reserved.current - second_reserved_before;
  const int64_t raw_committed_delta = subproc->stats.committed.current - second_committed_before;
  EMIT("first_published", first_published);
  EMIT("first_size", first_size); EMIT("first_page_map_clear", first_page_map_clear);
  EMIT("unmap_calls", unmap_calls); EMIT("failed_range_exact", failed_range_exact);
  EMIT("warning_calls", warning_calls); EMIT("warning_exact", warning_exact);
  EMIT("warning_before_stats", warning_before_stats);
  EMIT("first_escaped", first_escaped);
  EMIT("first_reserved_delta", first_reserved_delta);
  EMIT("first_committed_delta", first_committed_delta);
  EMIT("first_commit_calls_delta", first_commit_calls_delta);
  EMIT("first_mmap_calls_delta", first_mmap_calls_delta);
  EMIT("second_published", second_published); EMIT("second_size", second_size);
  EMIT("second_live_reserved", second_live_reserved);
  EMIT("second_live_committed", second_live_committed);
  EMIT("second_range_exact", second_range_exact);
  EMIT("second_unmapped", second_unmapped);
  EMIT("first_still_escaped", first_still_escaped);
  EMIT("second_reserved_delta", second_reserved_delta);
  EMIT("second_committed_delta", second_committed_delta);
  EMIT("raw_cleanup", raw_cleanup); EMIT("terminal_unmapped", terminal_unmapped);
  EMIT("raw_reserved_delta", raw_reserved_delta);
  EMIT("raw_committed_delta", raw_committed_delta);
  return 0;
}
