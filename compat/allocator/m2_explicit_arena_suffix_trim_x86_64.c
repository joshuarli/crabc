/* Explicit regular arena reservation through the pinned aligned OS mapping path. */
#define _GNU_SOURCE 1
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "static.c"

#ifndef MAP_FIXED_NOREPLACE
#error "the selected aligned trim requires Linux MAP_FIXED_NOREPLACE"
#endif

typedef struct trim_probe_s {
  bool active;
  size_t size;
  size_t alignment;
  size_t phase;
  size_t unmaps;
  void* direct;
  void* over;
  void* unmap_address[4];
  size_t unmap_size[4];
  int unmap_result[4];
} trim_probe_t;

static trim_probe_t probe;
static bool capture_warnings;
static unsigned warning_order;
static unsigned captured_warning_count;
static int64_t warning_reserved[3];
static int64_t warning_committed[3];
static mi_subproc_t* warning_subproc;

int __real_munmap(void*, size_t);
void* __real_mmap(void*, size_t, int, int, int, off_t);

void* __wrap_mmap(void* address, size_t size, int protection, int flags,
                  int descriptor, off_t offset) {
  if (probe.active && probe.phase == 0 && size == probe.size) {
    probe.phase = 1;
    return __real_mmap(probe.direct, size, protection,
                       flags | MAP_FIXED_NOREPLACE, descriptor, offset);
  }
  if (probe.active && probe.phase == 1 && size == probe.size + probe.alignment) {
    probe.phase = 2;
    return __real_mmap(probe.over, size, protection,
                       flags | MAP_FIXED_NOREPLACE, descriptor, offset);
  }
  return __real_mmap(address, size, protection, flags, descriptor, offset);
}

int __wrap_munmap(void* address, size_t size) {
  if (!probe.active) return __real_munmap(address, size);
  const size_t index = probe.unmaps++;
  if (index >= 4) { errno = EIO; return -1; }
  probe.unmap_address[index] = address;
  probe.unmap_size[index] = size;
  if (index == 2) {
    errno = ENOMEM;
    probe.unmap_result[index] = -1;
    return -1;
  }
  probe.unmap_result[index] = __real_munmap(address, size);
  return probe.unmap_result[index];
}

static void capture_warning(const char* message, void* argument) {
  (void)argument;
  if (!capture_warnings || message == NULL) return;
  unsigned category = 0;
  if (strncmp(message, "unable to allocate aligned OS memory directly", 45) == 0) {
    category = 1;
  } else if (strncmp(message, "unable to free OS memory", 24) == 0) {
    category = 2;
  }
  if (category != 0) {
    warning_order = warning_order * 10 + category;
    captured_warning_count++;
    warning_reserved[category] = warning_subproc->stats.reserved.current;
    warning_committed[category] = warning_subproc->stats.committed.current;
  }
}

static bool prepare_targets(size_t size, size_t alignment) {
  const size_t page = (size_t)sysconf(_SC_PAGESIZE);
  const size_t span = size + 7 * alignment + 2 * page;
  void* reservation = __real_mmap(NULL, span, PROT_NONE,
                                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (reservation == MAP_FAILED) return false;
  const uintptr_t aligned = ((uintptr_t)reservation + alignment - 1) & ~(uintptr_t)(alignment - 1);
  const uintptr_t direct = aligned + alignment + page;
  const uintptr_t over = aligned + 3 * alignment + alignment / 2;
  const bool fits = over + size + alignment <= (uintptr_t)reservation + span;
  if (__real_munmap(reservation, span) != 0 || !fits) return false;
  probe.direct = (void*)direct;
  probe.over = (void*)over;
  return true;
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  mi_process_init();
  os_preloading = false;
  mi_option_set(mi_option_allow_large_os_pages, 0);
  mi_option_set(mi_option_allow_thp, 0);
  mi_option_set(mi_option_arena_is_numa_local, 0);
  mi_option_set(mi_option_show_errors, 1);
  mi_option_set(mi_option_max_warnings, 100);
  mi_register_output(capture_warning, NULL);
  mi_subproc_t* const subproc = _mi_subproc_main();
  const size_t size = MI_ARENA_MIN_SIZE;
  const size_t alignment = MI_ARENA_ALIGNMENT;
  const size_t page = (size_t)sysconf(_SC_PAGESIZE);
  probe.size = size;
  probe.alignment = alignment;
  if (!prepare_targets(size, alignment)) return 1;
  const uintptr_t over = (uintptr_t)probe.over;
  const uintptr_t middle = (over + alignment - 1) & ~(uintptr_t)(alignment - 1);
  const size_t prefix = middle - over;
  const size_t suffix = alignment - prefix;
  if (prefix == 0 || suffix == 0) return 2;
  warning_subproc = subproc;
  const int64_t reserved_before = subproc->stats.reserved.current;
  const int64_t committed_before = subproc->stats.committed.current;
  const int64_t mmap_before = subproc->stats.mmap_calls.total;
  const int64_t arena_before = subproc->stats.arena_count.total;
  probe.active = true;
  capture_warnings = true;
  mi_arena_id_t id = _mi_arena_id_none();
  const int rc = mi_reserve_os_memory_ex2(subproc, size, false, false, false, &id);
  mi_arena_t* arena = _mi_arena_from_id(id);
  const bool memory_exact = rc == 0 && arena != NULL
      && arena->start == (uint8_t*)middle && arena->memid.memkind == MI_MEM_OS
      && arena->memid.mem.os.base == (void*)middle
      && arena->memid.mem.os.size == size
      && !arena->memid.initially_committed && arena->memid.initially_zero;
  const int64_t claimed_reserved = subproc->stats.reserved.current - reserved_before;
  const int64_t claimed_committed = subproc->stats.committed.current - committed_before;
  const int64_t claimed_mmap_calls = subproc->stats.mmap_calls.total - mmap_before;
  const int64_t claimed_arena_delta = subproc->stats.arena_count.total - arena_before;
  const size_t registry_claimed = mi_arenas_get_count(subproc);
  unsigned char residence = 0;
  const bool escaped_live = mincore((void*)(middle + size), page, &residence) == 0;
  const bool middle_live = mincore((void*)middle, page, &residence) == 0;
  const bool geometry = probe.phase == 2 && probe.unmaps == 3
      && probe.unmap_address[0] == probe.direct && probe.unmap_size[0] == size
      && probe.unmap_address[1] == probe.over && probe.unmap_size[1] == prefix
      && probe.unmap_address[2] == (void*)(middle + size)
      && probe.unmap_size[2] == suffix
      && probe.unmap_result[0] == 0 && probe.unmap_result[1] == 0
      && probe.unmap_result[2] == -1;
  const bool warning_timing = warning_reserved[1] == reserved_before + (int64_t)size
      && warning_reserved[2] == reserved_before + (int64_t)(size + suffix)
      && warning_committed[1] == committed_before
      && warning_committed[2] == committed_before;
  _mi_arenas_unsafe_destroy_all(subproc);
  probe.active = false;
  capture_warnings = false;
  const bool terminal_exact = probe.unmaps == 4
      && probe.unmap_address[3] == (void*)middle && probe.unmap_size[3] == size
      && probe.unmap_result[3] == 0;
  const bool middle_gone = mincore((void*)middle, page, &residence) != 0;
  const bool escaped_still_live = mincore((void*)(middle + size), page, &residence) == 0;
  const size_t registry_terminal = mi_arenas_get_count(subproc);
  const int64_t terminal_reserved = subproc->stats.reserved.current - reserved_before;
  const int64_t terminal_committed = subproc->stats.committed.current - committed_before;
  const int64_t terminal_arena_delta = subproc->stats.arena_count.total - arena_before;
  const bool raw_cleanup = escaped_still_live && __real_munmap((void*)(middle + size), suffix) == 0;
  const bool escaped_gone = mincore((void*)(middle + size), page, &residence) != 0;
  const int64_t raw_reserved = subproc->stats.reserved.current - reserved_before;

  puts("CRABC_M2_EXPLICIT_ARENA_SUFFIX_TRIM_C_TRACE_BEGIN");
  printf("size=%zu\n", size);
  printf("alignment=%zu\n", alignment);
  printf("prefix=%zu\n", prefix);
  printf("suffix=%zu\n", suffix);
  printf("reserve_success=%u\n", (unsigned)(rc == 0));
  printf("memory_exact=%u\n", (unsigned)memory_exact);
  printf("geometry=%u\n", (unsigned)geometry);
  printf("warning_order=%u\n", warning_order);
  printf("warning_count=%u\n", captured_warning_count);
  printf("warning_timing=%u\n", (unsigned)warning_timing);
  printf("warning_fallback_reserved=%lld\n", (long long)(warning_reserved[1] - reserved_before));
  printf("warning_free_reserved=%lld\n", (long long)(warning_reserved[2] - reserved_before));
  printf("warning_fallback_committed=%lld\n", (long long)(warning_committed[1] - committed_before));
  printf("warning_free_committed=%lld\n", (long long)(warning_committed[2] - committed_before));
  printf("registry_claimed=%zu\n", registry_claimed);
  printf("claimed_reserved=%lld\n", (long long)claimed_reserved);
  printf("claimed_committed=%lld\n", (long long)claimed_committed);
  printf("claimed_mmap_calls=%lld\n", (long long)claimed_mmap_calls);
  printf("claimed_arena_delta=%lld\n", (long long)claimed_arena_delta);
  printf("escaped_live=%u\n", (unsigned)escaped_live);
  printf("middle_live=%u\n", (unsigned)middle_live);
  printf("terminal_exact=%u\n", (unsigned)terminal_exact);
  printf("middle_gone=%u\n", (unsigned)middle_gone);
  printf("escaped_still_live=%u\n", (unsigned)escaped_still_live);
  printf("registry_terminal=%zu\n", registry_terminal);
  printf("terminal_reserved=%lld\n", (long long)terminal_reserved);
  printf("terminal_committed=%lld\n", (long long)terminal_committed);
  printf("terminal_arena_delta=%lld\n", (long long)terminal_arena_delta);
  printf("raw_cleanup=%u\n", (unsigned)raw_cleanup);
  printf("escaped_gone=%u\n", (unsigned)escaped_gone);
  printf("raw_reserved=%lld\n", (long long)raw_reserved);
  puts("CRABC_M2_EXPLICIT_ARENA_SUFFIX_TRIM_C_TRACE_END");
  return 0;
}
