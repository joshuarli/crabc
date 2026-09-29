/* A failed terminal unmap of an explicitly reserved arena retains its raw map. */
#define _GNU_SOURCE 1
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "static.c"

typedef struct owner_s { mi_subproc_t subproc; mi_heap_t heap; } owner_t;
static owner_t owner;
static bool fault_active;
static size_t unmap_calls;
static void* first_base;
static void* second_base;
static size_t arena_size;
static bool first_range_exact;
static bool second_range_exact;
static size_t warning_calls;
static bool warning_exact;
static bool warning_before_accounting;
static int64_t reserved_before;
static int64_t committed_before;

int __real_munmap(void*, size_t);
int __wrap_munmap(void* address, size_t size) {
  if (fault_active) {
    unmap_calls++;
    if (unmap_calls == 1) {
      first_range_exact = address == first_base && size == arena_size;
      errno = EIO;
      return -1;
    }
    second_range_exact = address == second_base && size == arena_size;
  }
  return __real_munmap(address, size);
}

static void warning(const char* message, void* ignored) {
  MI_UNUSED(ignored);
  if (!fault_active || strstr(message, "unable to free OS memory") == NULL) return;
  warning_calls++;
  char expected[256];
  _mi_snprintf(expected, sizeof(expected),
      "unable to free OS memory (error: %d (0x%x), size: 0x%zx bytes, address: %p)\n",
      EIO, EIO, arena_size, first_base);
  warning_exact = strcmp(message, expected) == 0;
  warning_before_accounting = owner.subproc.stats.reserved.current == reserved_before
      && owner.subproc.stats.committed.current == committed_before
      && unmap_calls == 1;
}

static bool live_page(void* base) {
  unsigned char residence = 0;
  return mincore(base, (size_t)sysconf(_SC_PAGESIZE), &residence) == 0;
}

#define EMIT(name, value) printf(name "=%lld\n", (long long)(value))

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  mi_process_init();
  os_preloading = false;
  memset(&owner, 0, sizeof(owner));
  mi_lock_init(&owner.subproc.arena_reserve_lock);
  mi_atomic_store_relaxed(&owner.subproc.heap_count, 1);
  owner.heap.subproc = &owner.subproc;
  mi_os_mem_config.has_overcommit = true;
  mi_os_mem_config.has_transparent_huge_pages = false;
  mi_option_set(mi_option_allow_large_os_pages, 0);
  mi_option_set(mi_option_allow_thp, 0);
  mi_option_set(mi_option_arena_is_numa_local, 0);
  mi_option_set(mi_option_purge_delay, 100000);
  mi_option_set(mi_option_show_errors, 1);
  mi_option_set(mi_option_max_warnings, 100);
  mi_register_output(warning, NULL);
  mi_arena_id_t first_id = _mi_arena_id_none();
  mi_arena_id_t second_id = _mi_arena_id_none();
  if (mi_reserve_os_memory_ex2(&owner.subproc, MI_ARENA_MIN_SIZE,
        false, false, false, &first_id) != 0) return 2;
  if (mi_reserve_os_memory_ex2(&owner.subproc, MI_ARENA_MIN_SIZE,
        true, false, false, &second_id) != 0) return 3;
  mi_arena_t* first = _mi_arena_from_id(first_id);
  mi_arena_t* second = _mi_arena_from_id(second_id);
  if (first == NULL || second == NULL) return 4;
  first_base = first->start;
  second_base = second->start;
  arena_size = first->memid.mem.os.size;
  const bool setup = mi_arenas_get_count(&owner.subproc) == 2
      && first != second && arena_size == MI_ARENA_MIN_SIZE
      && second->memid.mem.os.size == arena_size
      && !first->memid.initially_committed && second->memid.initially_committed;
  const bool page_map_ready = _mi_page_map() != NULL
      && _mi_page_map() != &mi_page_map_empty
      && _mi_ptr_page(NULL) == NULL;
  mi_memid_t claim_id = _mi_memid_none();
  void* const claim = mi_arenas_try_alloc(&owner.heap, 1, MI_ARENA_SLICE_ALIGN,
      true, false, first, 0, -1, &claim_id);
  const bool claim_first = claim != NULL && claim_id.memkind == MI_MEM_ARENA
      && claim_id.mem.arena.arena == first;
  if (claim != NULL) _mi_arenas_free(&owner.subproc, claim, MI_ARENA_SLICE_SIZE, claim_id);
  const bool before_mapped = live_page(first_base) && live_page(second_base);
  reserved_before = owner.subproc.stats.reserved.current;
  committed_before = owner.subproc.stats.committed.current;
  const int64_t commit_calls_before = owner.subproc.stats.commit_calls.total;
  fault_active = true;
  _mi_arenas_unsafe_destroy_all(&owner.subproc);
  fault_active = false;
  const bool failed_live = live_page(first_base);
  const bool other_gone = !live_page(second_base);
  const bool page_map_still_ready = _mi_page_map() != NULL
      && _mi_page_map() != &mi_page_map_empty
      && _mi_ptr_page(NULL) == NULL;
  const size_t registry_after = mi_arenas_get_count(&owner.subproc);
  const int64_t reserved_delta = owner.subproc.stats.reserved.current - reserved_before;
  const int64_t committed_delta = owner.subproc.stats.committed.current - committed_before;
  const int64_t commit_calls_delta = owner.subproc.stats.commit_calls.total - commit_calls_before;
  const bool raw_cleanup = __real_munmap(first_base, arena_size) == 0;
  const bool terminal_unmapped = !live_page(first_base) && !live_page(second_base);
  EMIT("setup", setup); EMIT("page_map_ready", page_map_ready);
  EMIT("claim_first", claim_first); EMIT("before_mapped", before_mapped);
  EMIT("unmap_calls", unmap_calls); EMIT("first_range_exact", first_range_exact);
  EMIT("second_range_exact", second_range_exact);
  EMIT("warning_calls", warning_calls); EMIT("warning_exact", warning_exact);
  EMIT("warning_before_accounting", warning_before_accounting);
  EMIT("failed_live", failed_live); EMIT("other_gone", other_gone);
  EMIT("page_map_still_ready", page_map_still_ready);
  EMIT("registry_after", registry_after); EMIT("reserved_delta", reserved_delta);
  EMIT("committed_delta", committed_delta); EMIT("commit_calls_delta", commit_calls_delta);
  EMIT("raw_cleanup", raw_cleanup); EMIT("terminal_unmapped", terminal_unmapped);
  return 0;
}
