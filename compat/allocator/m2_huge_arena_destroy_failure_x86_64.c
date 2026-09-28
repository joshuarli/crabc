/* Pinned source huge-arena destroy with one failed primitive release. */
#define _GNU_SOURCE 1
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "static.c"

static mi_subproc_t subproc;
static bool destroying;
static void* first_base;
static void* second_base;
static size_t unmap_calls;
static size_t exact_ranges;
static size_t warning_calls;
static size_t warning_before_accounting;
static int64_t reserved_before;
static int64_t committed_before;

int __real_munmap(void*, size_t);
int __wrap_munmap(void* address, size_t size) {
  if (destroying) {
    unmap_calls++;
    if (unmap_calls == 1) {
      exact_ranges += address == first_base && size == MI_GiB;
      errno = EIO;
      return -1;
    }
    if (unmap_calls == 2) exact_ranges += address == second_base && size == MI_GiB;
  }
  return __real_munmap(address, size);
}

static void warning(const char* message, void* argument) {
  MI_UNUSED(argument);
  if (!destroying || strstr(message, "unable to free OS memory") == NULL) return;
  warning_calls++;
  warning_before_accounting += subproc.stats.reserved.current == reserved_before
      && subproc.stats.committed.current == committed_before
      && strstr(message, "error: 5") != NULL
      && strstr(message, "size: 0x40000000 bytes") != NULL;
}

static bool live_page(void* base) {
  unsigned char residence = 0;
  return mincore(base, (size_t)sysconf(_SC_PAGESIZE), &residence) == 0;
}

static void emit(const char* field, long long value) {
  printf("m2.huge_destroy_failure.%s=%lld\n", field, value);
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  mi_process_init();
  os_preloading = false;
  mi_option_set(mi_option_show_errors, 1);
  mi_option_set(mi_option_max_warnings, 100);
  mi_register_output(warning, NULL);

  mi_arena_id_t ids[2];
  void** bases[2] = { &first_base, &second_base };
  for (size_t index = 0; index < 2; index++) {
    mi_memid_t huge;
    *bases[index] = _mi_os_alloc_aligned(&subproc, MI_GiB, MI_GiB, true, false, &huge);
    if (*bases[index] == NULL) return 2;
    huge.memkind = MI_MEM_OS_HUGE;
    huge.is_pinned = true;
    if (!mi_manage_os_memory_ex2(&subproc, *bases[index], MI_GiB, -1, false,
        huge, NULL, NULL, &ids[index])) return 3;
  }
  const bool setup = mi_arenas_get_count(&subproc) == 2
      && _mi_arena_from_id(ids[0])->memid.memkind == MI_MEM_OS_HUGE
      && _mi_arena_from_id(ids[1])->memid.memkind == MI_MEM_OS_HUGE;
  const bool before_mapped = live_page(first_base) && live_page(second_base);
  reserved_before = subproc.stats.reserved.current;
  committed_before = subproc.stats.committed.current;
  const int64_t arena_count_before = subproc.stats.arena_count.total;
  const int64_t purge_before = subproc.stats.purge_calls.total;
  destroying = true;
  _mi_arenas_unsafe_destroy_all(&subproc);
  destroying = false;
  const size_t registry_after = mi_arenas_get_count(&subproc);
  const bool failed_live = live_page(first_base);
  const bool other_huge_gone = !live_page(second_base);
  const int64_t reserved_delta = subproc.stats.reserved.current - reserved_before;
  const int64_t committed_delta = subproc.stats.committed.current - committed_before;
  const int64_t arena_count_delta = subproc.stats.arena_count.total - arena_count_before;
  const int64_t purge_calls = subproc.stats.purge_calls.total - purge_before;
  const bool raw_retry = __real_munmap(first_base, MI_GiB) == 0;
  const bool terminal_unmapped = !live_page(first_base) && !live_page(second_base);
  const bool terminal_registry = mi_arenas_get_count(&subproc) == 0;
  emit("setup", setup); emit("before_mapped", before_mapped);
  emit("unmap_calls", unmap_calls); emit("exact_ranges", exact_ranges);
  emit("warning_calls", warning_calls);
  emit("warning_before_accounting", warning_before_accounting);
  emit("registry_after", registry_after); emit("failed_live", failed_live);
  emit("other_huge_gone", other_huge_gone);
  emit("reserved_delta", reserved_delta); emit("committed_delta", committed_delta);
  emit("arena_count_delta", arena_count_delta); emit("purge_calls", purge_calls);
  emit("raw_retry", raw_retry); emit("terminal_unmapped", terminal_unmapped);
  emit("terminal_registry", terminal_registry);
  return 0;
}
