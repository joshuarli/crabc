/* Pinned source terminal arena release with one failed regular unmap. */
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
static bool fail_first_unmap;
static bool capture_warning;
static size_t unmap_calls;
static size_t failed_range_exact;
static size_t other_range_exact;
static void* first_base;
static void* second_base;
static size_t arena_size;
static size_t warning_calls;
static size_t warning_before_accounting;
static int64_t reserved_before;
static int64_t committed_before;

int __real_munmap(void*, size_t);
int __wrap_munmap(void* address, size_t size) {
  if (fail_first_unmap) {
    unmap_calls++;
    if (unmap_calls == 1) {
      failed_range_exact += address == first_base && size == arena_size;
      errno = EIO;
      return -1;
    }
    other_range_exact += address == second_base && size == arena_size;
  }
  return __real_munmap(address, size);
}

static void warning(const char* message, void* argument) {
  MI_UNUSED(argument);
  if (!capture_warning || strstr(message, "unable to free OS memory") == NULL) return;
  warning_calls++;
  warning_before_accounting += owner.subproc.stats.reserved.current == reserved_before
      && owner.subproc.stats.committed.current == committed_before
      && strstr(message, "error: 5") != NULL
      && strstr(message, "size: 0x4000000 bytes") != NULL;
}

static void emit(const char* field, long long value) {
  printf("m2.second_destroy_failure.%s=%lld\n", field, value);
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
  for (size_t i = 0; i < 4; i++) {
    ids[i] = _mi_memid_none();
    claims[i] = mi_arenas_try_alloc(&owner.heap, 256, MI_ARENA_SLICE_ALIGN,
                                    false, true, NULL, 0, -1, &ids[i]);
    if (claims[i] == NULL || ids[i].memkind != MI_MEM_ARENA) return 2;
  }
  mi_arena_t* first = mi_arena_from_index(&owner.subproc, 0);
  mi_arena_t* second = mi_arena_from_index(&owner.subproc, 1);
  const bool setup = mi_arenas_get_count(&owner.subproc) == 2
      && first != NULL && second != NULL && first != second
      && ids[0].mem.arena.arena == first && ids[3].mem.arena.arena == second;
  for (size_t i = 0; i < 4; i++) {
    _mi_arenas_free(&owner.subproc, claims[i], 256 * MI_ARENA_SLICE_SIZE, ids[i]);
  }
  first_base = first->start;
  second_base = second->start;
  arena_size = first->memid.mem.os.size;
  const bool before_mapped = live_page(first_base) && live_page(second_base)
      && arena_size == second->memid.mem.os.size && arena_size == 2 * MI_ARENA_MIN_SIZE;
  reserved_before = owner.subproc.stats.reserved.current;
  committed_before = owner.subproc.stats.committed.current;
  const int64_t arena_count_before = owner.subproc.stats.arena_count.total;
  const int64_t purge_before = owner.subproc.stats.purge_calls.total;
  fail_first_unmap = true;
  capture_warning = true;
  _mi_arenas_unsafe_destroy_all(&owner.subproc);
  capture_warning = false;
  fail_first_unmap = false;
  const size_t registry_after = mi_arenas_get_count(&owner.subproc);
  const bool failed_map_live = live_page(first_base);
  const bool other_map_gone = !live_page(second_base);
  const int64_t reserved_delta = owner.subproc.stats.reserved.current - reserved_before;
  const int64_t committed_delta = owner.subproc.stats.committed.current - committed_before;
  const int64_t arena_count_delta = owner.subproc.stats.arena_count.total - arena_count_before;
  const int64_t purge_calls = owner.subproc.stats.purge_calls.total - purge_before;

  mi_memid_t next_id = _mi_memid_none();
  void* next = mi_arenas_try_alloc(&owner.heap, 1, MI_ARENA_SLICE_ALIGN,
                                   false, true, NULL, 0, -1, &next_id);
  const bool next_reserved = next != NULL && next_id.memkind == MI_MEM_ARENA
      && mi_arenas_get_count(&owner.subproc) == 1
      && next_id.mem.arena.arena != first && live_page(first_base);
  void* const next_base = next_reserved ? next_id.mem.arena.arena->start : NULL;
  const bool leak_survives_next = live_page(first_base) && other_map_gone;
  if (next != NULL) {
    _mi_arenas_free(&owner.subproc, next, MI_ARENA_SLICE_SIZE, next_id);
  }
  _mi_arenas_unsafe_destroy_all(&owner.subproc);
  const bool next_cleaned = mi_arenas_get_count(&owner.subproc) == 0
      && next_base != NULL && !live_page(next_base);
  const int64_t after_next_reserved_delta = owner.subproc.stats.reserved.current - reserved_before;
  const int64_t after_next_committed_delta = owner.subproc.stats.committed.current - committed_before;
  const bool raw_cleanup = __real_munmap(first_base, arena_size) == 0;
  const bool post_cleanup_unmapped = !live_page(first_base) && !live_page(second_base);

  emit("setup", setup); emit("before_mapped", before_mapped);
  emit("unmap_calls", unmap_calls); emit("failed_range_exact", failed_range_exact);
  emit("other_range_exact", other_range_exact);
  emit("warning_calls", warning_calls);
  emit("warning_before_accounting", warning_before_accounting);
  emit("registry_after", registry_after);
  emit("failed_map_live", failed_map_live); emit("other_map_gone", other_map_gone);
  emit("reserved_delta", reserved_delta); emit("committed_delta", committed_delta);
  emit("arena_count_delta", arena_count_delta); emit("purge_calls", purge_calls);
  emit("next_reserved", next_reserved); emit("leak_survives_next", leak_survives_next);
  emit("next_cleaned", next_cleaned);
  emit("after_next_reserved_delta", after_next_reserved_delta);
  emit("after_next_committed_delta", after_next_committed_delta);
  emit("raw_cleanup", raw_cleanup);
  emit("post_cleanup_unmapped", post_cleanup_unmapped);
  return 0;
}
