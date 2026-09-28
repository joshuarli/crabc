/* Pinned source second-arena mapping refusal and later successful reservation. */
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
static bool fail_reserve;
static size_t failed_maps;
static size_t failed_direct;
static size_t failed_overmap;
static size_t failed_unmaps;
static size_t os_warnings;
static size_t aligned_warnings;
static size_t warning_order;
static size_t warning_counter_order;
static int64_t mmap_before;
static int64_t reserved_before;

void* __real_mmap(void*, size_t, int, int, int, off_t);
int __real_munmap(void*, size_t);

void* __wrap_mmap(void* address, size_t size, int protection, int flags,
                  int descriptor, off_t offset) {
  if (fail_reserve) {
    failed_maps++;
    failed_direct += size == 2 * MI_ARENA_MIN_SIZE;
    failed_overmap += size == 2 * MI_ARENA_MIN_SIZE + MI_ARENA_ALIGNMENT;
    errno = ENOMEM;
    return MAP_FAILED;
  }
  return __real_mmap(address, size, protection, flags, descriptor, offset);
}

int __wrap_munmap(void* address, size_t size) {
  if (fail_reserve) failed_unmaps++;
  return __real_munmap(address, size);
}

static void warning(const char* message, void* argument) {
  MI_UNUSED(argument);
  if (!fail_reserve) return;
  if (strstr(message, "unable to allocate OS memory") != NULL) {
    os_warnings++;
    warning_order = warning_order * 10 + 1;
    warning_counter_order = warning_counter_order * 10
        + (owner.subproc.stats.mmap_calls.total - mmap_before);
  } else if (strstr(message, "unable to allocate aligned OS memory directly") != NULL) {
    aligned_warnings++;
    warning_order = warning_order * 10 + 2;
    warning_counter_order = warning_counter_order * 10
        + (owner.subproc.stats.mmap_calls.total - mmap_before);
  }
}

static void emit(const char* field, long long value) {
  printf("m2.second_reserve_retry.%s=%lld\n", field, value);
}

static bool live_page(void* base) {
  unsigned char residence = 0;
  return mincore(base, (size_t)sysconf(_SC_PAGESIZE), &residence) == 0;
}

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
  mi_option_set(mi_option_arena_reserve, MI_ARENA_MIN_SIZE / MI_KiB);
  mi_option_set(mi_option_arena_eager_commit, 0);
  mi_option_set(mi_option_allow_large_os_pages, 0);
  mi_option_set(mi_option_allow_thp, 0);
  mi_option_set(mi_option_arena_is_numa_local, 0);
  mi_option_set(mi_option_purge_delay, 100000);
  mi_option_set(mi_option_show_errors, 1);
  mi_option_set(mi_option_max_warnings, 100);
  mi_register_output(warning, NULL);

  mi_memid_t ids[4];
  void* claims[4];
  for (size_t i = 0; i < 3; i++) {
    ids[i] = _mi_memid_none();
    claims[i] = mi_arenas_try_alloc(&owner.heap, 256, MI_ARENA_SLICE_ALIGN,
                                    false, true, NULL, 0, -1, &ids[i]);
    if (claims[i] == NULL || ids[i].memkind != MI_MEM_ARENA) return 2;
  }
  mi_arena_t* first = ids[0].mem.arena.arena;
  size_t first_free_slices = 0;
  for (size_t index = 0; index < first->slice_count; index++) {
    first_free_slices += mi_bbitmap_is_setN(first->slices_free, index, 1);
  }
  const bool first_full = first != NULL && mi_arenas_get_count(&owner.subproc) == 1
      && first_free_slices < 256
      && ids[1].mem.arena.arena == first && ids[2].mem.arena.arena == first
      && mi_bbitmap_is_clearN(first->slices_free, ids[0].mem.arena.slice_index, 256)
      && mi_bbitmap_is_clearN(first->slices_free, ids[1].mem.arena.slice_index, 256)
      && mi_bbitmap_is_clearN(first->slices_free, ids[2].mem.arena.slice_index, 256);
  const int64_t arena_count_before = owner.subproc.stats.arena_count.total;
  const int64_t commit_before = owner.subproc.stats.commit_calls.total;
  const int64_t committed_before = owner.subproc.stats.committed.current;
  const int64_t purge_before = owner.subproc.stats.purge_calls.total;
  mmap_before = owner.subproc.stats.mmap_calls.total;
  reserved_before = owner.subproc.stats.reserved.current;
  fail_reserve = true;
  mi_memid_t failed_id = _mi_memid_none();
  void* failed = mi_arenas_try_alloc(&owner.heap, 256, MI_ARENA_SLICE_ALIGN,
                                    false, true, NULL, 0, -1, &failed_id);
  fail_reserve = false;
  const bool failed_null = failed == NULL;
  const size_t failed_registry = mi_arenas_get_count(&owner.subproc);
  const bool first_claims_live = mi_bbitmap_is_clearN(first->slices_free,
      ids[0].mem.arena.slice_index, 256)
      && mi_bbitmap_is_clearN(first->slices_free, ids[1].mem.arena.slice_index, 256)
      && mi_bbitmap_is_clearN(first->slices_free, ids[2].mem.arena.slice_index, 256);
  const bool failed_map_absent = failed_maps == 4 && failed_unmaps == 0
      && owner.subproc.stats.reserved.current == reserved_before
      && live_page(first->start);
  const int64_t failed_mmap_calls = owner.subproc.stats.mmap_calls.total - mmap_before;
  const int64_t failed_commit_calls = owner.subproc.stats.commit_calls.total - commit_before;
  const int64_t failed_committed_delta = owner.subproc.stats.committed.current - committed_before;
  const int64_t failed_arena_delta = owner.subproc.stats.arena_count.total - arena_count_before;
  const size_t failed_warning_order = warning_order;
  const size_t failed_warning_counter_order = warning_counter_order;

  ids[3] = _mi_memid_none();
  claims[3] = mi_arenas_try_alloc(&owner.heap, 256, MI_ARENA_SLICE_ALIGN,
                                  false, true, NULL, 0, -1, &ids[3]);
  if (claims[3] == NULL || ids[3].memkind != MI_MEM_ARENA) return 3;
  mi_arena_t* second = ids[3].mem.arena.arena;
  const bool retry_second = second != first && second != NULL
      && ids[3].mem.arena.slice_index == 9
      && mi_arenas_get_count(&owner.subproc) == 2;
  const bool registry_order = mi_arena_from_index(&owner.subproc, 0) == first
      && mi_arena_from_index(&owner.subproc, 1) == second;
  const bool mapped_both = live_page(first->start) && live_page(second->start);
  void* const first_base = first->start;
  void* const second_base = second->start;
  const int64_t reserved_delta = owner.subproc.stats.reserved.current - reserved_before;
  const int64_t arena_delta = owner.subproc.stats.arena_count.total - arena_count_before;
  const int64_t purge_calls = owner.subproc.stats.purge_calls.total - purge_before;
  for (size_t i = 0; i < 4; i++) {
    _mi_arenas_free(&owner.subproc, claims[i], 256 * MI_ARENA_SLICE_SIZE, ids[i]);
  }
  const bool released = mi_bbitmap_is_setN(first->slices_free, ids[0].mem.arena.slice_index, 256)
      && mi_bbitmap_is_setN(first->slices_free, ids[1].mem.arena.slice_index, 256)
      && mi_bbitmap_is_setN(first->slices_free, ids[2].mem.arena.slice_index, 256)
      && mi_bbitmap_is_setN(second->slices_free, ids[3].mem.arena.slice_index, 256);
  const bool mappings_retained = live_page(first->start) && live_page(second->start)
      && mi_arenas_get_count(&owner.subproc) == 2;
  _mi_arenas_unsafe_destroy_all(&owner.subproc);
  const bool terminal_unmapped = !live_page(first_base) && !live_page(second_base);
  const size_t terminal_registry = mi_arenas_get_count(&owner.subproc);
  const int64_t terminal_reserved_delta = owner.subproc.stats.reserved.current - reserved_before;
  const int64_t terminal_committed_delta = owner.subproc.stats.committed.current - committed_before;

  emit("first_full", first_full); emit("failed_null", failed_null);
  emit("failed_registry", failed_registry); emit("first_claims_live", first_claims_live);
  emit("failed_map_absent", failed_map_absent); emit("failed_maps", failed_maps);
  emit("failed_direct", failed_direct); emit("failed_overmap", failed_overmap);
  emit("failed_unmaps", failed_unmaps); emit("failed_mmap_calls", failed_mmap_calls);
  emit("failed_commit_calls", failed_commit_calls);
  emit("failed_committed_delta", failed_committed_delta);
  emit("failed_arena_delta", failed_arena_delta);
  emit("os_warnings", os_warnings); emit("aligned_warnings", aligned_warnings);
  emit("failed_warning_order", failed_warning_order);
  emit("failed_warning_counter_order", failed_warning_counter_order);
  emit("retry_second", retry_second); emit("registry_order", registry_order);
  emit("mapped_both", mapped_both); emit("reserved_delta", reserved_delta);
  emit("arena_delta", arena_delta); emit("purge_calls", purge_calls);
  emit("released", released); emit("mappings_retained", mappings_retained);
  emit("terminal_unmapped", terminal_unmapped);
  emit("terminal_registry", terminal_registry);
  emit("terminal_reserved_delta", terminal_reserved_delta);
  emit("terminal_committed_delta", terminal_committed_delta);
  return 0;
}
