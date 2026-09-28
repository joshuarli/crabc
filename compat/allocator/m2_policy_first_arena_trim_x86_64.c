/* Pinned mimalloc v3.5.0 policy-first arena reservation after a failed
 * aligned-overmap prefix or suffix release. The mmap wrapper chooses a
 * deterministic unaligned address; the source still performs every arena,
 * mapping, warning, and statistics transition. */
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
#error "the trim differential requires Linux MAP_FIXED_NOREPLACE"
#endif

typedef struct trim_probe_s {
  bool active;
  size_t size;
  size_t alignment;
  size_t fail_ordinal;
  size_t phase;
  size_t frees;
  void* direct;
  void* over;
  void* freed_address[3];
  size_t freed_size[3];
} trim_probe_t;

static trim_probe_t probe;
static bool capture_warnings;
static unsigned warning_order;
static unsigned observed_warnings;
static mi_subproc_t* warning_subproc;
static int64_t warning_reserved[3];

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
  if (probe.active && probe.frees < 3) {
    const size_t ordinal = ++probe.frees;
    probe.freed_address[ordinal - 1] = address;
    probe.freed_size[ordinal - 1] = size;
    if (ordinal == probe.fail_ordinal) {
      errno = ENOMEM;
      return -1;
    }
  }
  return __real_munmap(address, size);
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
    observed_warnings++;
    warning_reserved[category] = warning_subproc->stats.reserved.current;
  }
}

static bool prepare_targets(size_t size, size_t alignment, trim_probe_t* selected) {
  const size_t page = (size_t)sysconf(_SC_PAGESIZE);
  const size_t span = size + 5 * alignment + 2 * page;
  void* reservation = __real_mmap(NULL, span, PROT_NONE,
                                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (reservation == MAP_FAILED) return false;
  uintptr_t aligned = ((uintptr_t)reservation + alignment - 1) & ~(uintptr_t)(alignment - 1);
  const uintptr_t direct = aligned + page;
  const uintptr_t over = aligned + 2 * alignment + page;
  const bool fits = over + size + alignment <= (uintptr_t)reservation + span;
  if (__real_munmap(reservation, span) != 0 || !fits) return false;
  selected->direct = (void*)direct;
  selected->over = (void*)over;
  return true;
}

static void emit(const char* name, const char* field, long long value) {
  printf("m2.policy_trim.%s.%s=%lld\n", name, field, value);
}

static bool run_case(const char* name, size_t fail_ordinal) {
  mi_subproc_t* subproc = _mi_subproc_main();
  const size_t size = 4 * MI_ARENA_MIN_SIZE;
  const size_t alignment = MI_ARENA_ALIGNMENT;
  const size_t page = (size_t)sysconf(_SC_PAGESIZE);
  trim_probe_t selected = {.size = size, .alignment = alignment,
                           .fail_ordinal = fail_ordinal};
  if (!prepare_targets(size, alignment, &selected)) return false;
  const uintptr_t over = (uintptr_t)selected.over;
  const uintptr_t middle = (over + alignment - 1) & ~(uintptr_t)(alignment - 1);
  const size_t prefix = middle - over;
  const size_t suffix = size + alignment - prefix - size;
  if (prefix == 0 || suffix == 0) return false;
  const int64_t reserved_before = subproc->stats.reserved.current;
  const int64_t maps_before = subproc->stats.mmap_calls.total;
  warning_order = observed_warnings = 0;
  warning_subproc = subproc;
  warning_reserved[1] = warning_reserved[2] = 0;
  probe = selected;
  probe.active = true;
  capture_warnings = true;
  mi_arena_id_t id = _mi_arena_id_none();
  const bool reserved = mi_arena_reserve(subproc, MI_ARENA_SLICE_SIZE,
                                         false, &id);
  capture_warnings = false;
  probe.active = false;
  const trim_probe_t result = probe;
  mi_arena_t* arena = _mi_arena_from_id(id);
  const uintptr_t escaped = fail_ordinal == 2 ? over : middle + size;
  const size_t escaped_size = fail_ordinal == 2 ? prefix : suffix;
  unsigned char residency = 0;
  const bool escaped_live = mincore((void*)escaped, page, &residency) == 0;
  const bool geometry = result.phase == 2 && result.frees == 3
      && result.freed_address[0] == selected.direct && result.freed_size[0] == size
      && result.freed_address[1] == selected.over && result.freed_size[1] == prefix
      && result.freed_address[2] == (void*)(middle + size)
      && result.freed_size[2] == suffix;
  const bool owner = reserved && arena != NULL && arena->start == (uint8_t*)middle
      && arena->memid.memkind == MI_MEM_OS
      && arena->memid.mem.os.base == (void*)middle
      && arena->memid.mem.os.size == size;
  const bool stats = subproc->stats.reserved.current - reserved_before == (int64_t)size
      && subproc->stats.mmap_calls.total - maps_before == 2;
  const bool warning_statistics_order =
      warning_reserved[1] == reserved_before + (int64_t)size
      && warning_reserved[2] == reserved_before + (int64_t)(size + alignment)
          - (fail_ordinal == 3 ? (int64_t)prefix : 0);
  mi_arena_id_t second_id = _mi_arena_id_none();
  const bool second = mi_arena_reserve(subproc, MI_ARENA_SLICE_SIZE,
                                       false, &second_id)
      && _mi_arena_from_id(second_id) != NULL;
  emit(name, "owner", owner);
  emit(name, "geometry", geometry);
  emit(name, "escaped_live", escaped_live);
  emit(name, "warning_order", warning_order);
  emit(name, "warning_count", observed_warnings);
  emit(name, "warning_statistics_order", warning_statistics_order);
  emit(name, "statistics", stats);
  emit(name, "later_valid", second);
  if (escaped_live) __real_munmap((void*)escaped, escaped_size);
  return owner && geometry && escaped_live && warning_order == 12
      && observed_warnings == 2 && warning_statistics_order && stats && second;
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  mi_process_init();
  mi_option_set(mi_option_arena_reserve, 4 * MI_ARENA_MIN_SIZE / MI_KiB);
  mi_option_set(mi_option_arena_eager_commit, 0);
  mi_option_set(mi_option_allow_large_os_pages, 0);
  mi_option_set(mi_option_allow_thp, 0);
  mi_option_set(mi_option_show_errors, 1);
  mi_register_output(capture_warning, NULL);
  const bool prefix = run_case("prefix", 2);
  const bool suffix = run_case("suffix", 3);
  return prefix && suffix ? 0 : 1;
}
