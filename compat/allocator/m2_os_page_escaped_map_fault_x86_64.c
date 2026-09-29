/* A failed second metadata commit does not consume an escaped earlier OS page. */
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
static bool fail_second_metadata;
static unsigned unmap_calls;
static unsigned commit_calls;
static void* first_base;
static size_t first_size;
static void* second_base;
static size_t second_commit_size;
static bool second_rollback_exact;
static void* third_base;
static size_t third_size;
static bool third_release_exact;
static unsigned warning_calls;
static unsigned warning_fragments;
static bool first_warning_exact;
static bool second_warning_exact;
static bool warning_order = true;
static int64_t first_warning_reserved;
static int64_t first_warning_committed;
static int64_t second_warning_reserved;
static int64_t second_warning_committed;
static mi_subproc_t* subproc;

int __real_mprotect(void*, size_t, int);
int __real_munmap(void*, size_t);
int __wrap_mprotect(void* address, size_t length, int protection) {
  if (fail_second_metadata && protection == (PROT_READ | PROT_WRITE)) {
    fail_second_metadata = false;
    commit_calls++;
    second_base = address;
    second_commit_size = length;
    errno = EIO;
    return -1;
  }
  return __real_mprotect(address, length, protection);
}

int __wrap_munmap(void* address, size_t length) {
  if (fail_first_unmap) {
    fail_first_unmap = false;
    unmap_calls++;
    first_base = address;
    first_size = length;
    errno = EIO;
    return -1;
  }
  if (second_base != NULL && address == second_base && length == first_size) {
    second_rollback_exact = true;
    unmap_calls++;
  }
  if (third_base != NULL && address == third_base && length == third_size) {
    third_release_exact = true;
    unmap_calls++;
  }
  return __real_munmap(address, length);
}

static void capture_warning(const char* message, void* ignored) {
  MI_UNUSED(ignored);
  if (message == NULL || message[0] == '\0') return;
  if (strncmp(message, "mimalloc: warning: thread 0x", 27) == 0) {
    warning_order &= warning_fragments == 0 || warning_fragments == 2;
    warning_fragments++;
    return;
  }
  char expected[256];
  if (strstr(message, "unable to free OS memory") != NULL) {
    warning_order &= warning_fragments == 1 && warning_calls == 0;
    warning_calls++;
    warning_fragments++;
    _mi_snprintf(expected, sizeof(expected),
        "unable to free OS memory (error: %d (0x%x), size: 0x%zx bytes, address: %p)\n",
        EIO, EIO, first_size, first_base);
    first_warning_exact = strcmp(message, expected) == 0;
    first_warning_reserved = subproc->stats.reserved.current;
    first_warning_committed = subproc->stats.committed.current;
  }
  else if (strstr(message, "cannot commit OS memory") != NULL) {
    warning_order &= warning_fragments == 3 && warning_calls == 1;
    warning_calls++;
    warning_fragments++;
    _mi_snprintf(expected, sizeof(expected),
        "cannot commit OS memory (error: %d (0x%x), address: %p, size: 0x%zx bytes)\n",
        EIO, EIO, second_base, second_commit_size);
    second_warning_exact = strcmp(message, expected) == 0;
    second_warning_reserved = subproc->stats.reserved.current;
    second_warning_committed = subproc->stats.committed.current;
  }
  else {
    warning_order = false;
  }
}

static bool live(void* address) {
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
  void* const first_start = mi_page_start(first);
  const mi_memid_t first_id = first->memid;
  const int64_t first_reserved_before = subproc->stats.reserved.current;
  const int64_t first_committed_before = subproc->stats.committed.current;
  fail_first_unmap = true;
  _mi_arenas_page_free(first, theap);
  const bool first_cleared = _mi_checked_ptr_page(first_start) == NULL;
  const bool first_escaped = live(first_id.mem.os.base);
  const int64_t first_reserved_after = subproc->stats.reserved.current;
  const int64_t first_committed_after = subproc->stats.committed.current;

  const int64_t second_reserved_before = subproc->stats.reserved.current;
  const int64_t second_committed_before = subproc->stats.committed.current;
  const int64_t second_commit_calls_before = subproc->stats.commit_calls.total;
  const int64_t second_mmap_calls_before = subproc->stats.mmap_calls.total;
  fail_second_metadata = true;
  mi_page_t* const failed = _mi_arenas_page_alloc(theap, 16 * MI_KiB, 1);
  const bool second_failed = failed == NULL && !fail_second_metadata;
  const bool second_unmapped = !live(second_base);
  const bool first_survives = live(first_base);
  const int64_t second_reserved_after = subproc->stats.reserved.current;
  const int64_t second_committed_after = subproc->stats.committed.current;
  const int64_t second_commit_calls_after = subproc->stats.commit_calls.total;
  const int64_t second_mmap_calls_after = subproc->stats.mmap_calls.total;

  mi_page_t* const third = _mi_arenas_page_alloc(theap, 16 * MI_KiB, 1);
  if (third == NULL || third->memid.memkind != MI_MEM_OS) return 3;
  third_base = third->memid.mem.os.base;
  third_size = third->memid.mem.os.size;
  const bool third_published = third->memid.initially_committed
      && _mi_checked_ptr_page(mi_page_start(third)) == third
      && third_base != first_base && live(first_base);
  _mi_arenas_page_free(third, theap);
  const bool third_unmapped = !live(third_base);
  const bool first_after_third = live(first_base);
  const int64_t before_raw_reserved = subproc->stats.reserved.current;
  const int64_t before_raw_committed = subproc->stats.committed.current;
  const bool raw_cleanup = __real_munmap(first_base, first_size) == 0;
  const bool raw_no_stats = subproc->stats.reserved.current == before_raw_reserved
      && subproc->stats.committed.current == before_raw_committed;
  const bool terminal_unmapped = !live(first_base) && !live(third_base);

  EMIT("first_size", first_size);
  EMIT("first_cleared", first_cleared);
  EMIT("first_escaped", first_escaped);
  EMIT("first_reserved_delta", first_reserved_after - first_reserved_before);
  EMIT("first_committed_delta", first_committed_after - first_committed_before);
  EMIT("first_warning_before_stats", first_warning_reserved == first_reserved_before
      && first_warning_committed == first_committed_before);
  EMIT("second_failed", second_failed);
  EMIT("second_commit_calls", commit_calls);
  EMIT("second_commit_size", second_commit_size);
  EMIT("second_rollback_exact", second_rollback_exact);
  EMIT("second_unmapped", second_unmapped);
  EMIT("first_survives", first_survives);
  EMIT("second_reserved_delta", second_reserved_after - second_reserved_before);
  EMIT("second_committed_delta", second_committed_after - second_committed_before);
  EMIT("second_commit_stat_delta", second_commit_calls_after - second_commit_calls_before);
  EMIT("second_mmap_stat_delta", second_mmap_calls_after - second_mmap_calls_before);
  EMIT("second_warning_reserved_delta", second_warning_reserved - second_reserved_before);
  EMIT("second_warning_committed_delta", second_warning_committed - second_committed_before);
  EMIT("warning_calls", warning_calls);
  EMIT("warning_fragments", warning_fragments);
  EMIT("warning_order", warning_order);
  EMIT("first_warning_exact", first_warning_exact);
  EMIT("second_warning_exact", second_warning_exact);
  EMIT("third_published", third_published);
  EMIT("third_size", third_size);
  EMIT("third_release_exact", third_release_exact);
  EMIT("third_unmapped", third_unmapped);
  EMIT("first_after_third", first_after_third);
  EMIT("unmap_calls", unmap_calls);
  EMIT("raw_cleanup", raw_cleanup);
  EMIT("raw_no_stats", raw_no_stats);
  EMIT("terminal_unmapped", terminal_unmapped);
  return 0;
}
