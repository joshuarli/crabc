/* Two failed lazy first-page PageMap commits with two live explicit arenas. */
#define _GNU_SOURCE 1
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "mimalloc.h"
#include "mimalloc/internal.h"

static bool m2_partial_page_map_init(void);
#include "alloc.c"
#include "alloc-aligned.c"
#include "alloc-posix.c"
#include "arena.c"
#include "bitmap.c"
#include "heap.c"
#define _mi_page_map_init m2_partial_page_map_init
#include "init.c"
#undef _mi_page_map_init
#include "libc.c"
#include "options.c"
#include "os.c"
#include "page.c"
#include "page-map.c"
#include "random.c"
#include "stats.c"
#include "subproc.c"
#include "theap.c"
#include "threadlocal.c"
#include "prim/prim.c"
#include "prim/prim-tls.c"

/* Preserve process initialization while selecting the source's genuine lazy
 * top-entry policy after the OS observations have been initialized. */
static bool m2_partial_page_map_init(void) {
  mi_os_mem_config.has_overcommit = false;
  return _mi_page_map_init();
}

static unsigned arena_map_count;
static unsigned page_map_commit_failures_remaining;
static bool capture_protection;
static unsigned page_map_commit_faults;
static unsigned armed_protection_calls;
static void* protection_addresses[5];
static size_t protection_lengths[5];
static int protection_flags[5];
static unsigned warning_order;
static unsigned m2_warning_count;
static int64_t warning_commits[3];
static int64_t warning_committed[3];
static int64_t warning_event_commits[4];
static int64_t warning_event_committed[4];
static size_t warning_event_top[4];
static size_t warning_event_registry[4];
static mi_subproc_t* observed_subprocess;
void* __real_mmap(void*, size_t, int, int, int, off_t);
int __real_mprotect(void*, size_t, int);

void* __wrap_mmap(void* address, size_t length, int protection, int flags,
                  int descriptor, off_t offset) {
  if (length == MI_ARENA_MIN_SIZE && arena_map_count < 2) {
    const uintptr_t target = (arena_map_count++ == 0 ? UINT64_C(1) << 40 : UINT64_C(16) << 40);
    return __real_mmap((void*)target, length, protection,
                       flags | MAP_FIXED_NOREPLACE, descriptor, offset);
  }
  return __real_mmap(address, length, protection, flags, descriptor, offset);
}

int __wrap_mprotect(void* address, size_t length, int protection) {
  if (capture_protection) {
    if (armed_protection_calls < 5) {
      protection_addresses[armed_protection_calls] = address;
      protection_lengths[armed_protection_calls] = length;
      protection_flags[armed_protection_calls] = protection;
    }
    armed_protection_calls++;
  }
  if (page_map_commit_failures_remaining > 0 && address == _mi_page_map()) {
    page_map_commit_failures_remaining--;
    page_map_commit_faults++;
    errno = ENOMEM;
    return -1;
  }
  return __real_mprotect(address, length, protection);
}

static void capture_warning(const char* message, void* ignored) {
  (void)ignored;
  if (message == NULL || observed_subprocess == NULL) return;
  unsigned category = 0;
  if (strstr(message, "cannot commit OS memory") != NULL) category = 1;
  if (strstr(message, "unable to commit the allocation page-map on-demand") != NULL) category = 2;
  if (category == 0) return;
  warning_order = warning_order * 10 + category;
  const unsigned event = m2_warning_count++;
  warning_commits[category] = observed_subprocess->stats.commit_calls.total;
  warning_committed[category] = observed_subprocess->stats.committed.current;
  if (event < 4) {
    warning_event_commits[event] = observed_subprocess->stats.commit_calls.total;
    warning_event_committed[event] = observed_subprocess->stats.committed.current;
    warning_event_top[event] = mi_atomic_load_relaxed(&_mi_page_map()->committed_count);
    warning_event_registry[event] = mi_arenas_get_count(observed_subprocess);
  }
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  setenv("mimalloc_max_vabits", "47", 1);
  setenv("mimalloc_pagemap_commit", "0", 1);
  mi_process_init();
  os_preloading = false;
  mi_option_set(mi_option_allow_large_os_pages, 0);
  mi_option_set(mi_option_allow_thp, 0);
  mi_option_set(mi_option_arena_is_numa_local, 0);
  mi_option_set(mi_option_purge_delay, -1);
  mi_option_set(mi_option_show_errors, 1);
  mi_option_set(mi_option_max_warnings, 100);
  mi_page_map_t* const pmap = _mi_page_map();
  mi_subproc_t* const subprocess = _mi_subproc_main();
  observed_subprocess = subprocess;
  mi_register_output(capture_warning, NULL);
  const int64_t reserved_before = subprocess->stats.reserved.current;
  const int64_t committed_before = subprocess->stats.committed.current;
  const int64_t commits_before = subprocess->stats.commit_calls.total;
  const int64_t mmaps_before = subprocess->stats.mmap_calls.total;
  mi_arena_id_t first_id = _mi_arena_id_none();
  mi_arena_id_t second_id = _mi_arena_id_none();
  const int first_rc = mi_reserve_os_memory_ex2(subprocess, MI_ARENA_MIN_SIZE,
                                                false, false, true, &first_id);
  const int second_rc = mi_reserve_os_memory_ex2(subprocess, MI_ARENA_MIN_SIZE,
                                                 false, false, false, &second_id);
  mi_arena_t* const first = _mi_arena_from_id(first_id);
  mi_arena_t* const second = _mi_arena_from_id(second_id);
  const size_t initial_top_committed = mi_atomic_load_relaxed(&pmap->committed_count);
  if (first == NULL || second == NULL) return 2;
  mi_memid_t first_claim = _mi_memid_none();
  void* const first_slice = mi_arena_try_alloc_at(first, 1, false, 0, &first_claim);
  mi_theap_t* const theap = _mi_theap_default();
  if (first_slice == NULL || theap == NULL) return 3;
  const size_t registry_before_fault = mi_arenas_get_count(subprocess);
  const int64_t reserved_at_fault = subprocess->stats.reserved.current;
  const int64_t committed_at_fault = subprocess->stats.committed.current;
  const int64_t commits_at_fault = subprocess->stats.commit_calls.total;
  const int64_t mmaps_at_fault = subprocess->stats.mmap_calls.total;
  page_map_commit_failures_remaining = 2;
  capture_protection = true;
  void* const failed = mi_heap_malloc(_mi_theap_heap(theap), MI_SMALL_MAX_OBJ_SIZE + 1);
  capture_protection = false;
  const size_t top_after_failure = mi_atomic_load_relaxed(&pmap->committed_count);
  const int64_t reserved_after_failure = subprocess->stats.reserved.current;
  const int64_t committed_after_failure = subprocess->stats.committed.current;
  const int64_t commits_after_failure = subprocess->stats.commit_calls.total;
  const int64_t mmaps_after_failure = subprocess->stats.mmap_calls.total;
  const size_t registry_after_failure = mi_arenas_get_count(subprocess);
  unsigned char residence = 0;
  const bool first_mapped = mincore(first->start, 4096, &residence) == 0;
  const bool second_mapped = mincore(second->start, 4096, &residence) == 0;
  mi_page_t* const first_page = failed == NULL ? NULL : _mi_safe_ptr_page(failed);
  const bool first_in_second = first_page != NULL && first_page->memid.memkind == MI_MEM_ARENA
      && first_page->memid.mem.arena.arena == second;
  if (failed != NULL) mi_free(failed);
  void* const retry = mi_heap_malloc(_mi_theap_heap(theap), MI_SMALL_MAX_OBJ_SIZE + 1);
  mi_page_t* const retry_page = retry == NULL ? NULL : _mi_safe_ptr_page(retry);
  const bool retry_in_second = retry_page != NULL && retry_page->memid.memkind == MI_MEM_ARENA
      && retry_page->memid.mem.arena.arena == second;
  const size_t top_after_retry = mi_atomic_load_relaxed(&pmap->committed_count);
  const bool retry_published = retry_page != NULL;
  if (retry != NULL) mi_free(retry);
  mi_collect(true);
  const bool retry_cleared = retry != NULL && _mi_safe_ptr_page(retry) == NULL;
  const size_t registry_after_retry = mi_arenas_get_count(subprocess);
  const bool first_claim_held = !mi_bbitmap_is_setN(first->slices_free,
      first_claim.mem.arena.slice_index, 1);
  const bool first_at_target = first->start == (void*)(UINT64_C(1) << 40);
  const bool second_at_target = second->start == (void*)(UINT64_C(16) << 40);
  const bool partial_top = initial_top_committed < mi_page_map_count_of_size(pmap->reserved_size);
  const uintptr_t first_protection_offset = (uintptr_t)protection_addresses[0] - (uintptr_t)second->start;
  const uintptr_t second_protection_offset = (uintptr_t)protection_addresses[1] - (uintptr_t)second->start;
  const bool third_protects_top = protection_addresses[2] == (void*)pmap;
  const bool fourth_replays_top = protection_addresses[3] == (void*)pmap
      && protection_lengths[3] == protection_lengths[2];
  _mi_arenas_free(subprocess, first_slice, MI_ARENA_SLICE_SIZE, first_claim);
  _mi_arenas_unsafe_destroy_all(subprocess);
  const bool first_gone = mincore((void*)(UINT64_C(1) << 40), 4096, &residence) == -1 && errno == ENOMEM;
  const bool second_gone = mincore((void*)(UINT64_C(16) << 40), 4096, &residence) == -1 && errno == ENOMEM;
  printf("CRABC_M2_REGISTERED_ARENA_PAGE_MAP_DOUBLE_FAULT_C_TRACE_BEGIN\n");
#define EMIT(name, value) printf(name "=%lld\n", (long long)(value))
  EMIT("first_reserved", first_rc == 0 && first_at_target);
  EMIT("second_reserved", second_rc == 0 && second_at_target);
  EMIT("first_claim_held", first_claim_held);
  EMIT("partial_top", partial_top);
  EMIT("registry_before_fault", registry_before_fault);
  EMIT("reserved_before_fault", reserved_at_fault - reserved_before);
  EMIT("committed_before_fault", committed_at_fault - committed_before);
  EMIT("commits_before_fault", commits_at_fault - commits_before);
  EMIT("mmaps_before_fault", mmaps_at_fault - mmaps_before);
  EMIT("first_returned", failed != NULL);
  EMIT("first_in_second", first_in_second);
  EMIT("faults", page_map_commit_faults);
  EMIT("protection_calls", armed_protection_calls);
  EMIT("first_protection_offset", first_protection_offset);
  EMIT("first_protection_length", protection_lengths[0]);
  EMIT("second_protection_offset", second_protection_offset);
  EMIT("second_protection_length", protection_lengths[1]);
  EMIT("third_protects_top", third_protects_top);
  EMIT("third_protection_length", protection_lengths[2]);
  EMIT("third_protection_flags", protection_flags[2]);
  EMIT("fourth_replays_top", fourth_replays_top);
  EMIT("fourth_protection_flags", protection_flags[3]);
  EMIT("fifth_replays_top", protection_addresses[4] == (void*)pmap
      && protection_lengths[4] == protection_lengths[2]);
  EMIT("fifth_protection_length", protection_lengths[4]);
  EMIT("fifth_protection_flags", protection_flags[4]);
  EMIT("top_advanced_after_fault", top_after_failure > initial_top_committed);
  EMIT("registry_after_failure", registry_after_failure);
  EMIT("reserved_after_failure", reserved_after_failure - reserved_before);
  EMIT("committed_after_failure", committed_after_failure - committed_before);
  EMIT("commits_after_failure", commits_after_failure - commits_before);
  EMIT("mmaps_after_failure", mmaps_after_failure - mmaps_before);
  EMIT("first_mapped", first_mapped);
  EMIT("second_mapped", second_mapped);
  EMIT("warning_order", warning_order);
  EMIT("warning_count", m2_warning_count);
  EMIT("warning_first_commits", warning_commits[1] - commits_before);
  EMIT("warning_second_commits", warning_commits[2] - commits_before);
  EMIT("warning_first_committed", warning_committed[1] - committed_before);
  EMIT("warning_second_committed", warning_committed[2] - committed_before);
  EMIT("warning1_commits", warning_event_commits[0] - commits_before);
  EMIT("warning2_commits", warning_event_commits[1] - commits_before);
  EMIT("warning3_commits", warning_event_commits[2] - commits_before);
  EMIT("warning4_commits", warning_event_commits[3] - commits_before);
  EMIT("warning1_committed", warning_event_committed[0] - committed_before);
  EMIT("warning2_committed", warning_event_committed[1] - committed_before);
  EMIT("warning3_committed", warning_event_committed[2] - committed_before);
  EMIT("warning4_committed", warning_event_committed[3] - committed_before);
  EMIT("initial_top_count", initial_top_committed);
  EMIT("warning1_top_count", warning_event_top[0]);
  EMIT("warning2_top_count", warning_event_top[1]);
  EMIT("warning3_top_count", warning_event_top[2]);
  EMIT("warning4_top_count", warning_event_top[3]);
  EMIT("warning1_registry", warning_event_registry[0]);
  EMIT("warning2_registry", warning_event_registry[1]);
  EMIT("warning3_registry", warning_event_registry[2]);
  EMIT("warning4_registry", warning_event_registry[3]);
  EMIT("retry_in_second", retry_in_second);
  EMIT("retry_published", retry_published);
  EMIT("retry_cleared", retry_cleared);
  EMIT("top_advanced", top_after_retry > initial_top_committed);
  EMIT("registry_after_retry", registry_after_retry);
  EMIT("terminal_registry", mi_arenas_get_count(subprocess));
  EMIT("terminal_reserved", subprocess->stats.reserved.current - reserved_before);
  EMIT("terminal_committed", subprocess->stats.committed.current - committed_before);
  EMIT("terminal_first_gone", first_gone);
  EMIT("terminal_second_gone", second_gone);
#undef EMIT
  printf("CRABC_M2_REGISTERED_ARENA_PAGE_MAP_DOUBLE_FAULT_C_TRACE_END\n");
  return 0;
}
