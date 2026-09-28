/* Pinned explicit second-arena metadata failure with a live first arena. */
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
#error "fixed non-replacing mmap is required for selected arena targets"
#endif

static size_t arena_size;
static size_t arena_alignment;
static void* first_target;
static void* second_target;
static unsigned stage;
static unsigned map_calls;
static unsigned protection_calls;
static void* failed_protection_address;
static size_t failed_protection_length;
static unsigned unmap_calls;
static void* unmap_address[2];
static size_t unmap_length[2];
static unsigned warning_order;
static unsigned captured_warning_count;
static int64_t warning_reserved[4];
static int64_t warning_committed[4];
static int64_t warning_commit_calls[4];
static mi_subproc_t* subprocess;

void* __real_mmap(void*, size_t, int, int, int, off_t);
int __real_mprotect(void*, size_t, int);
int __real_munmap(void*, size_t);

void* __wrap_mmap(void* address, size_t length, int protection, int flags,
                  int descriptor, off_t offset) {
  if (stage < 2 && length == arena_size) {
    void* target = stage == 0 ? first_target : second_target;
    stage++;
    map_calls++;
    return __real_mmap(target, length, protection,
                       flags | MAP_FIXED_NOREPLACE, descriptor, offset);
  }
  return __real_mmap(address, length, protection, flags, descriptor, offset);
}

int __wrap_mprotect(void* address, size_t length, int protection) {
  if (stage == 1 || stage == 2) protection_calls++;
  if (stage == 2) {
    failed_protection_address = address;
    failed_protection_length = length;
    errno = ENOMEM;
    return -1;
  }
  return __real_mprotect(address, length, protection);
}

int __wrap_munmap(void* address, size_t length) {
  if (stage >= 2) {
    const unsigned index = unmap_calls++;
    if (index < 2) {
      unmap_address[index] = address;
      unmap_length[index] = length;
    }
  }
  return __real_munmap(address, length);
}

static void warning(const char* message, void* argument) {
  (void)argument;
  if (message == NULL) return;
  unsigned category = 0;
  if (strncmp(message, "cannot commit OS memory", 23) == 0) category = 2;
  else if (strncmp(message, "unable to commit meta-data for OS memory", 40) == 0) category = 3;
  if (category == 0) return;
  warning_order = warning_order * 10 + category;
  captured_warning_count++;
  warning_reserved[category] = subprocess->stats.reserved.current;
  warning_committed[category] = subprocess->stats.committed.current;
  warning_commit_calls[category] = subprocess->stats.commit_calls.total;
}

static bool targets(void) {
  const size_t span = 3 * arena_alignment + arena_size;
  void* reservation = __real_mmap(NULL, span, PROT_NONE,
                                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (reservation == MAP_FAILED) return false;
  const uintptr_t aligned = ((uintptr_t)reservation + arena_alignment - 1)
      & ~(uintptr_t)(arena_alignment - 1);
  const bool fits = aligned + arena_alignment + arena_size <=
                    (uintptr_t)reservation + span;
  const bool released = __real_munmap(reservation, span) == 0;
  if (!fits || !released) return false;
  first_target = (void*)aligned;
  second_target = (void*)(aligned + arena_alignment);
  return true;
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  mi_process_init();
  os_preloading = false;
  mi_option_set(mi_option_allow_large_os_pages, 0);
  mi_option_set(mi_option_allow_thp, 0);
  mi_option_set(mi_option_arena_is_numa_local, 0);
  mi_option_set(mi_option_purge_delay, -1);
  mi_option_set(mi_option_show_errors, 1);
  mi_option_set(mi_option_max_warnings, 100);
  subprocess = _mi_subproc_main();
  arena_size = MI_ARENA_MIN_SIZE;
  arena_alignment = MI_ARENA_ALIGNMENT;
  if (!targets()) return 2;
  mi_register_output(warning, NULL);
  const int64_t reserved_before = subprocess->stats.reserved.current;
  const int64_t committed_before = subprocess->stats.committed.current;
  const int64_t mmap_before = subprocess->stats.mmap_calls.total;
  const int64_t commit_before = subprocess->stats.commit_calls.total;
  const int64_t arena_before = subprocess->stats.arena_count.total;
  mi_arena_id_t first_id = _mi_arena_id_none();
  const int first_rc = mi_reserve_os_memory_ex2(subprocess, arena_size,
                                                false, false, false, &first_id);
  mi_arena_t* first = _mi_arena_from_id(first_id);
  const bool first_exact = first_rc == 0 && first != NULL && first->start == first_target
      && first->memid.memkind == MI_MEM_OS && first->memid.mem.os.base == first_target
      && first->memid.mem.os.size == arena_size && !first->memid.initially_committed;
  const size_t first_registry = mi_arenas_get_count(subprocess);
  const int64_t first_reserved = subprocess->stats.reserved.current - reserved_before;
  const int64_t first_committed = subprocess->stats.committed.current - committed_before;
  const int64_t first_mmap = subprocess->stats.mmap_calls.total - mmap_before;
  const int64_t first_commit = subprocess->stats.commit_calls.total - commit_before;
  mi_arena_id_t refused_id = _mi_arena_id_none();
  const int refused_rc = mi_reserve_os_memory_ex2(subprocess, arena_size,
                                                  false, false, false, &refused_id);
  stage = 3;
  unsigned char residence = 0;
  const bool first_survives = mincore(first_target, (size_t)sysconf(_SC_PAGESIZE), &residence) == 0;
  const bool second_gone = mincore(second_target, (size_t)sysconf(_SC_PAGESIZE), &residence) != 0;
  const bool first_id_retained = _mi_arena_from_id(first_id) == first;
  const bool second_refused = refused_rc == ENOMEM && refused_id == _mi_arena_id_none();
  const size_t after_failure_registry = mi_arenas_get_count(subprocess);
  const int64_t failed_reserved = subprocess->stats.reserved.current - reserved_before;
  const int64_t failed_committed = subprocess->stats.committed.current - committed_before;
  const int64_t failed_mmap = subprocess->stats.mmap_calls.total - mmap_before;
  const int64_t failed_commit = subprocess->stats.commit_calls.total - commit_before;
  const int64_t failed_arena = subprocess->stats.arena_count.total - arena_before;
  const bool warning_timing = warning_reserved[2] == reserved_before + 2 * (int64_t)arena_size
      && warning_reserved[3] == reserved_before + 2 * (int64_t)arena_size
      && warning_committed[2] == committed_before + first_committed
      && warning_committed[3] == committed_before + first_committed
      && warning_commit_calls[2] == commit_before + 2
      && warning_commit_calls[3] == commit_before + 2;
  const bool fault_geometry = map_calls == 2 && protection_calls == 2
      && failed_protection_address == second_target
      && failed_protection_length == (size_t)first_committed
      && unmap_calls == 1 && unmap_address[0] == second_target
      && unmap_length[0] == arena_size;

  mi_memid_t claim_id;
  void* claim = first == NULL ? NULL : mi_arena_try_alloc_at(first, 1, true, 0, &claim_id);
  const bool survivor_claim = claim != NULL && (uintptr_t)claim >= (uintptr_t)first_target
      && (uintptr_t)claim + MI_ARENA_SLICE_SIZE <= (uintptr_t)first_target + arena_size
      && claim_id.memkind == MI_MEM_ARENA && claim_id.mem.arena.arena == first;
  bool survivor_rw = false;
  if (survivor_claim) {
    *(volatile uint8_t*)claim = 0x5a;
    survivor_rw = *(volatile uint8_t*)claim == 0x5a;
    _mi_arenas_free(subprocess, claim, MI_ARENA_SLICE_SIZE, claim_id);
  }
  const bool first_after_claim = mincore(first_target, (size_t)sysconf(_SC_PAGESIZE), &residence) == 0;
  const size_t claim_registry = mi_arenas_get_count(subprocess);
  const int64_t claim_committed = subprocess->stats.committed.current - committed_before;
  const int64_t claim_commit = subprocess->stats.commit_calls.total - commit_before;
  _mi_arenas_unsafe_destroy_all(subprocess);
  const bool terminal_exact = unmap_calls == 2 && unmap_address[1] == first_target
      && unmap_length[1] == arena_size;
  const bool first_gone = mincore(first_target, (size_t)sysconf(_SC_PAGESIZE), &residence) != 0;
  const size_t terminal_registry = mi_arenas_get_count(subprocess);
  const int64_t terminal_reserved = subprocess->stats.reserved.current - reserved_before;
  const int64_t terminal_committed = subprocess->stats.committed.current - committed_before;
  const int64_t terminal_arena = subprocess->stats.arena_count.total - arena_before;

  puts("CRABC_M2_REGISTERED_ARENA_METADATA_FAULT_C_TRACE_BEGIN");
#define FIELD(name, value) printf(#name "=%lld\n", (long long)(value))
  FIELD(size, arena_size); FIELD(alignment, arena_alignment);
  FIELD(first_exact, first_exact); FIELD(first_registry, first_registry);
  FIELD(first_reserved, first_reserved); FIELD(first_committed, first_committed);
  FIELD(first_mmap, first_mmap); FIELD(first_commit, first_commit);
  FIELD(second_refused, second_refused); FIELD(first_id_retained, first_id_retained);
  FIELD(first_survives, first_survives); FIELD(second_gone, second_gone);
  FIELD(after_failure_registry, after_failure_registry);
  FIELD(failed_reserved, failed_reserved); FIELD(failed_committed, failed_committed);
  FIELD(failed_mmap, failed_mmap); FIELD(failed_commit, failed_commit);
  FIELD(failed_arena, failed_arena); FIELD(warning_order, warning_order);
  FIELD(warning_count, captured_warning_count); FIELD(warning_timing, warning_timing);
  FIELD(fault_geometry, fault_geometry);
  FIELD(survivor_claim, survivor_claim); FIELD(survivor_rw, survivor_rw);
  FIELD(first_after_claim, first_after_claim); FIELD(claim_registry, claim_registry);
  FIELD(claim_committed, claim_committed); FIELD(claim_commit, claim_commit);
  FIELD(terminal_exact, terminal_exact); FIELD(first_gone, first_gone);
  FIELD(terminal_registry, terminal_registry);
  FIELD(terminal_reserved, terminal_reserved); FIELD(terminal_committed, terminal_committed);
  FIELD(terminal_arena, terminal_arena);
#undef FIELD
  puts("CRABC_M2_REGISTERED_ARENA_METADATA_FAULT_C_TRACE_END");
  return 0;
}
