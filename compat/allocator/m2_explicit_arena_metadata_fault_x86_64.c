/* Pinned explicit arena metadata-commit failure after aligned overmapping. */
#define _GNU_SOURCE 1
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "static.c"

#ifndef MAP_FIXED_NOREPLACE
#error "fixed non-replacing mmap is required for the selected overmap"
#endif

static bool capture;
static bool fail_cleanup;
static size_t arena_size;
static size_t arena_alignment;
static void* direct_target;
static void* over_target;
static void* recovery_target;
static unsigned map_phase;
static unsigned unmap_calls;
static void* unmap_addresses[5];
static size_t unmap_lengths[5];
static int unmap_results[5];
static unsigned protect_calls;
static void* protected_address;
static size_t protected_length;
static int protected_flags;
static unsigned warning_order;
static unsigned captured_warning_count;
static int64_t warning_reserved[5];
static int64_t warning_committed[5];
static int64_t warning_commit_calls[5];
static mi_subproc_t* selected_subproc;

void* __real_mmap(void*, size_t, int, int, int, off_t);
int __real_munmap(void*, size_t);
int __real_mprotect(void*, size_t, int);

void* __wrap_mmap(void* address, size_t length, int protection, int flags,
                  int descriptor, off_t offset) {
  if (capture && map_phase == 0 && length == arena_size) {
    map_phase = 1;
    return __real_mmap(direct_target, length, protection,
                       flags | MAP_FIXED_NOREPLACE, descriptor, offset);
  }
  if (capture && map_phase == 1 && length == arena_size + arena_alignment) {
    map_phase = 2;
    return __real_mmap(over_target, length, protection,
                       flags | MAP_FIXED_NOREPLACE, descriptor, offset);
  }
  if (capture && map_phase == 2 && length == arena_size) {
    map_phase = 3;
    return __real_mmap(recovery_target, length, protection,
                       flags | MAP_FIXED_NOREPLACE, descriptor, offset);
  }
  return __real_mmap(address, length, protection, flags, descriptor, offset);
}

int __wrap_mprotect(void* address, size_t length, int protection) {
  if (!capture || map_phase == 3) return __real_mprotect(address, length, protection);
  protect_calls++;
  protected_address = address;
  protected_length = length;
  protected_flags = protection;
  errno = ENOMEM;
  return -1;
}

int __wrap_munmap(void* address, size_t length) {
  if (!capture) return __real_munmap(address, length);
  const unsigned index = unmap_calls++;
  if (index >= 5) { errno = EIO; return -1; }
  unmap_addresses[index] = address;
  unmap_lengths[index] = length;
  if (fail_cleanup && index == 3) {
    errno = ENOMEM;
    unmap_results[index] = -1;
    return -1;
  }
  unmap_results[index] = __real_munmap(address, length);
  return unmap_results[index];
}

static void warning(const char* message, void* argument) {
  (void)argument;
  if (!capture || message == NULL) return;
  unsigned category = 0;
  if (strncmp(message, "unable to allocate aligned OS memory directly", 45) == 0) category = 1;
  else if (strncmp(message, "cannot commit OS memory", 23) == 0) category = 2;
  else if (strncmp(message, "unable to commit meta-data for OS memory", 40) == 0) category = 3;
  else if (strncmp(message, "unable to free OS memory", 24) == 0) category = 4;
  if (category == 0) return;
  warning_order = warning_order * 10 + category;
  captured_warning_count++;
  warning_reserved[category] = selected_subproc->stats.reserved.current;
  warning_committed[category] = selected_subproc->stats.committed.current;
  warning_commit_calls[category] = selected_subproc->stats.commit_calls.total;
}

static bool targets(void) {
  const size_t page = (size_t)sysconf(_SC_PAGESIZE);
  const size_t span = arena_size + 5 * arena_alignment + 2 * page;
  void* reservation = __real_mmap(NULL, span, PROT_NONE,
                                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (reservation == MAP_FAILED) return false;
  const uintptr_t aligned = ((uintptr_t)reservation + arena_alignment - 1)
      & ~(uintptr_t)(arena_alignment - 1);
  const uintptr_t direct = aligned + page;
  const uintptr_t over = aligned + 2 * arena_alignment + page;
  const bool fits = over + arena_size + arena_alignment <= (uintptr_t)reservation + span
      && aligned + 4 * arena_alignment + arena_size <= (uintptr_t)reservation + span;
  if (__real_munmap(reservation, span) != 0 || !fits) return false;
  direct_target = (void*)direct;
  over_target = (void*)over;
  recovery_target = (void*)(aligned + 4 * arena_alignment);
  return true;
}

int main(int argc, char** argv) {
  if (argc != 2 || (strcmp(argv[1], "clean") != 0 && strcmp(argv[1], "leaked") != 0)) return 1;
  fail_cleanup = strcmp(argv[1], "leaked") == 0;
  setvbuf(stdout, NULL, _IONBF, 0);
  mi_process_init();
  os_preloading = false;
  mi_option_set(mi_option_allow_large_os_pages, 0);
  mi_option_set(mi_option_allow_thp, 0);
  mi_option_set(mi_option_arena_is_numa_local, 0);
  mi_option_set(mi_option_show_errors, 1);
  mi_option_set(mi_option_max_warnings, 100);
  mi_register_output(warning, NULL);
  selected_subproc = _mi_subproc_main();
  arena_size = MI_ARENA_MIN_SIZE;
  arena_alignment = MI_ARENA_ALIGNMENT;
  if (!targets()) return 2;
  const uintptr_t over = (uintptr_t)over_target;
  const uintptr_t middle = (over + arena_alignment - 1)
      & ~(uintptr_t)(arena_alignment - 1);
  const size_t prefix = middle - over;
  const size_t suffix = arena_alignment - prefix;
  if (prefix == 0 || suffix == 0) return 3;
  const int64_t before_reserved = selected_subproc->stats.reserved.current;
  const int64_t before_committed = selected_subproc->stats.committed.current;
  const int64_t before_mmap_calls = selected_subproc->stats.mmap_calls.total;
  const int64_t before_commit_calls = selected_subproc->stats.commit_calls.total;
  const int64_t before_arena_count = selected_subproc->stats.arena_count.total;
  capture = true;
  mi_arena_id_t id = _mi_arena_id_none();
  const int rc = mi_reserve_os_memory_ex2(selected_subproc, arena_size, false, false, false, &id);
  capture = false;
  const bool geometry = map_phase == 2 && unmap_calls == 4
      && unmap_addresses[0] == direct_target && unmap_lengths[0] == arena_size
      && unmap_addresses[1] == over_target && unmap_lengths[1] == prefix
      && unmap_addresses[2] == (void*)(middle + arena_size)
      && unmap_lengths[2] == suffix
      && unmap_addresses[3] == (void*)middle && unmap_lengths[3] == arena_size
      && unmap_results[0] == 0 && unmap_results[1] == 0
      && unmap_results[2] == 0
      && unmap_results[3] == (fail_cleanup ? -1 : 0);
  const bool protection_exact = protect_calls == 1
      && protected_address == (void*)middle
      && protected_length > 0 && protected_length <= arena_size
      && protected_flags == (PROT_READ | PROT_WRITE);
  const bool warning_timing = warning_reserved[1] == before_reserved + (int64_t)arena_size
      && warning_reserved[2] == before_reserved + (int64_t)arena_size
      && warning_reserved[3] == before_reserved + (int64_t)arena_size
      && (!fail_cleanup || warning_reserved[4] == before_reserved + (int64_t)arena_size)
      && warning_committed[1] == before_committed
      && warning_committed[2] == before_committed
      && warning_committed[3] == before_committed
      && (!fail_cleanup || warning_committed[4] == before_committed)
      && warning_commit_calls[2] == before_commit_calls + 1
      && warning_commit_calls[3] == before_commit_calls + 1;
  const bool no_memory_id = rc == ENOMEM && (id == _mi_arena_id_none());
  const size_t registry = mi_arenas_get_count(selected_subproc);
  const int64_t reserved_delta = selected_subproc->stats.reserved.current - before_reserved;
  const int64_t committed_delta = selected_subproc->stats.committed.current - before_committed;
  const int64_t mmap_calls_delta = selected_subproc->stats.mmap_calls.total - before_mmap_calls;
  const int64_t commit_calls_delta = selected_subproc->stats.commit_calls.total - before_commit_calls;
  const int64_t arena_count_delta = selected_subproc->stats.arena_count.total - before_arena_count;
  unsigned char residence = 0;
  const bool middle_live = mincore((void*)middle, (size_t)sysconf(_SC_PAGESIZE), &residence) == 0;

  // The rejected arena owns no registry slot. A later reservation must still
  // publish its own mapping while the failed cleanup's range remains live.
  capture = true;
  const unsigned warnings_before_recovery = captured_warning_count;
  mi_arena_id_t recovery_id = _mi_arena_id_none();
  const int recovery_rc = mi_reserve_os_memory_ex2(selected_subproc, arena_size,
                                                   false, false, false, &recovery_id);
  mi_arena_t* recovery_arena = _mi_arena_from_id(recovery_id);
  const bool recovery_memory_exact = recovery_rc == 0 && recovery_arena != NULL
      && recovery_arena->start == recovery_target
      && recovery_arena->memid.memkind == MI_MEM_OS
      && recovery_arena->memid.mem.os.base == recovery_target
      && recovery_arena->memid.mem.os.size == arena_size
      && !recovery_arena->memid.initially_committed;
  const size_t recovery_registry = mi_arenas_get_count(selected_subproc);
  const bool prior_live_during_recovery = mincore((void*)middle,
      (size_t)sysconf(_SC_PAGESIZE), &residence) == (fail_cleanup ? 0 : -1);
  const bool recovery_live = mincore(recovery_target,
      (size_t)sysconf(_SC_PAGESIZE), &residence) == 0;
  const int64_t recovery_reserved_delta = selected_subproc->stats.reserved.current - before_reserved;
  const int64_t recovery_committed_delta = selected_subproc->stats.committed.current - before_committed;
  const int64_t recovery_mmap_calls_delta = selected_subproc->stats.mmap_calls.total - before_mmap_calls;
  const int64_t recovery_commit_calls_delta = selected_subproc->stats.commit_calls.total - before_commit_calls;
  const int64_t recovery_arena_count_delta = selected_subproc->stats.arena_count.total - before_arena_count;
  const unsigned recovery_warning_count = captured_warning_count - warnings_before_recovery;
  _mi_arenas_unsafe_destroy_all(selected_subproc);
  capture = false;
  const bool recovery_release_exact = unmap_calls == 5
      && unmap_addresses[4] == recovery_target
      && unmap_lengths[4] == arena_size && unmap_results[4] == 0;
  const bool recovery_gone = mincore(recovery_target,
      (size_t)sysconf(_SC_PAGESIZE), &residence) != 0;
  const size_t recovery_terminal_registry = mi_arenas_get_count(selected_subproc);
  const bool prior_live_after_release = mincore((void*)middle,
      (size_t)sysconf(_SC_PAGESIZE), &residence) == (fail_cleanup ? 0 : -1);
  const int64_t recovery_terminal_reserved_delta = selected_subproc->stats.reserved.current - before_reserved;
  const int64_t recovery_terminal_committed_delta = selected_subproc->stats.committed.current - before_committed;
  const bool raw_cleanup = !middle_live || __real_munmap((void*)middle, arena_size) == 0;
  const bool middle_gone = mincore((void*)middle, (size_t)sysconf(_SC_PAGESIZE), &residence) != 0;
  const int64_t raw_reserved_delta = selected_subproc->stats.reserved.current - before_reserved;

  puts("CRABC_M2_EXPLICIT_ARENA_METADATA_FAULT_C_TRACE_BEGIN");
  printf("profile=%u\n", (unsigned)fail_cleanup);
  printf("size=%zu\n", arena_size);
  printf("alignment=%zu\n", arena_alignment);
  printf("prefix=%zu\n", prefix);
  printf("suffix=%zu\n", suffix);
  printf("refused=%u\n", (unsigned)(rc == ENOMEM));
  printf("no_memory_id=%u\n", (unsigned)no_memory_id);
  printf("geometry=%u\n", (unsigned)geometry);
  printf("protection_exact=%u\n", (unsigned)protection_exact);
  printf("protection_length=%zu\n", protected_length);
  printf("warning_order=%u\n", warning_order);
  printf("warning_count=%u\n", captured_warning_count);
  printf("warning_timing=%u\n", (unsigned)warning_timing);
  printf("registry=%zu\n", registry);
  printf("reserved_delta=%lld\n", (long long)reserved_delta);
  printf("committed_delta=%lld\n", (long long)committed_delta);
  printf("mmap_calls_delta=%lld\n", (long long)mmap_calls_delta);
  printf("commit_calls_delta=%lld\n", (long long)commit_calls_delta);
  printf("arena_count_delta=%lld\n", (long long)arena_count_delta);
  printf("middle_live=%u\n", (unsigned)middle_live);
  printf("raw_cleanup=%u\n", (unsigned)raw_cleanup);
  printf("middle_gone=%u\n", (unsigned)middle_gone);
  printf("raw_reserved_delta=%lld\n", (long long)raw_reserved_delta);
  printf("recovery_success=%u\n", (unsigned)(recovery_rc == 0));
  printf("recovery_memory_exact=%u\n", (unsigned)recovery_memory_exact);
  printf("recovery_registry=%zu\n", recovery_registry);
  printf("prior_live_during_recovery=%u\n", (unsigned)prior_live_during_recovery);
  printf("recovery_live=%u\n", (unsigned)recovery_live);
  printf("recovery_reserved_delta=%lld\n", (long long)recovery_reserved_delta);
  printf("recovery_committed_delta=%lld\n", (long long)recovery_committed_delta);
  printf("recovery_mmap_calls_delta=%lld\n", (long long)recovery_mmap_calls_delta);
  printf("recovery_commit_calls_delta=%lld\n", (long long)recovery_commit_calls_delta);
  printf("recovery_arena_count_delta=%lld\n", (long long)recovery_arena_count_delta);
  printf("recovery_warning_count=%u\n", recovery_warning_count);
  printf("recovery_warning_order=%u\n", warning_order);
  printf("recovery_release_exact=%u\n", (unsigned)recovery_release_exact);
  printf("recovery_gone=%u\n", (unsigned)recovery_gone);
  printf("recovery_terminal_registry=%zu\n", recovery_terminal_registry);
  printf("prior_live_after_release=%u\n", (unsigned)prior_live_after_release);
  printf("recovery_terminal_reserved_delta=%lld\n", (long long)recovery_terminal_reserved_delta);
  printf("recovery_terminal_committed_delta=%lld\n", (long long)recovery_terminal_committed_delta);
  puts("CRABC_M2_EXPLICIT_ARENA_METADATA_FAULT_C_TRACE_END");
  return 0;
}
