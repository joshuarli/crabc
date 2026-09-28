/* Direct pinned mimalloc v3.5.0 second regular arena after the first fills. */
#define _GNU_SOURCE 1
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "static.c"

typedef struct owner_s {
  mi_subproc_t subproc;
  mi_heap_t heap;
} owner_t;

static owner_t owner;
static void emit(const char* field, long long value) {
  printf("m2.arena_scale.%s=%lld\n", field, value);
}
static void emit_claim(size_t ordinal, const char* field, long long value) {
  printf("m2.arena_scale.claim%zu_%s=%lld\n", ordinal, field, value);
}
static bool live_page(void* base) {
  unsigned char residence = 0;
  return mincore(base, (size_t)sysconf(_SC_PAGESIZE), &residence) == 0;
}
static size_t free_slices(mi_arena_t* arena) {
  size_t count = 0;
  for (size_t index = 0; index < arena->slice_count; index++) {
    if (mi_bbitmap_is_setN(arena->slices_free, index, 1)) count++;
  }
  return count;
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
  mi_option_set(mi_option_purge_delay, 0);
  mi_option_set(mi_option_purge_decommits, 1);
  const int64_t reserved_before = owner.subproc.stats.reserved.current;
  const int64_t purge_calls_before = owner.subproc.stats.purge_calls.total;
  const int64_t purged_before = owner.subproc.stats.purged.total;
  mi_memid_t ids[4];
  void* claims[4];
  bool valid = true;
  for (size_t i = 0; i < 4; i++) {
    ids[i] = _mi_memid_none();
    claims[i] = mi_arenas_try_alloc(&owner.heap, 256, MI_ARENA_SLICE_ALIGN,
                                   false, true, NULL, 0, -1, &ids[i]);
    if (claims[i] == NULL || ids[i].memkind != MI_MEM_ARENA) return 2;
    mi_arena_t* arena = ids[i].mem.arena.arena;
    const size_t index = ids[i].mem.arena.slice_index;
    const bool occupied = mi_bbitmap_is_clearN(arena->slices_free, index, 256);
    emit_claim(i, "registry", (long long)mi_arenas_get_count(&owner.subproc));
    emit_claim(i, "arena", (long long)arena->arena_idx);
    emit_claim(i, "slice", (long long)index);
    emit_claim(i, "count", (long long)ids[i].mem.arena.slice_count);
    emit_claim(i, "occupied", occupied);
    valid = valid && occupied && ids[i].mem.arena.slice_count == 256;
  }
  const size_t count = mi_arenas_get_count(&owner.subproc);
  if (count != 2) return 3;
  mi_arena_t* first = mi_arena_from_index(&owner.subproc, 0);
  mi_arena_t* second = mi_arena_from_index(&owner.subproc, 1);
  const bool distinct = first != second && first == ids[0].mem.arena.arena
      && first == ids[1].mem.arena.arena && first == ids[2].mem.arena.arena
      && second == ids[3].mem.arena.arena;
  const bool owners = first->memid.memkind == MI_MEM_OS
      && second->memid.memkind == MI_MEM_OS
      && first->memid.mem.os.base == first->start
      && second->memid.mem.os.base == second->start
      && first->memid.mem.os.size == second->memid.mem.os.size
      && first->memid.mem.os.size == 2 * MI_ARENA_MIN_SIZE;
  const bool full_first = free_slices(first) < 256
      && mi_bbitmap_is_clearN(first->slices_free, 0, first->info_slices);
  emit("registry_final", (long long)count);
  emit("distinct", distinct);
  emit("owners", owners);
  emit("first_exhausted_for_256", full_first);
  emit("arena_size", (long long)first->memid.mem.os.size);
  emit("reserved_bytes", (long long)(owner.subproc.stats.reserved.current - reserved_before));
  emit("arena_count", (long long)owner.subproc.stats.arena_count.total);

  for (size_t i = 0; i < 4; i++) {
    _mi_arenas_free(&owner.subproc, claims[i], 256 * MI_ARENA_SLICE_SIZE, ids[i]);
  }
  bool restored = true;
  for (size_t i = 0; i < 4; i++) {
    mi_arena_t* arena = ids[i].mem.arena.arena;
    restored = restored && mi_bbitmap_is_setN(
        arena->slices_free, ids[i].mem.arena.slice_index, 256);
  }
  const bool maps_live = live_page(first->start) && live_page(second->start);
  emit("restored", restored);
  emit("purge_calls", (long long)(owner.subproc.stats.purge_calls.total - purge_calls_before));
  emit("purged_bytes", (long long)(owner.subproc.stats.purged.total - purged_before));
  emit("mapped_both", maps_live);
  emit("reserved_still", owner.subproc.stats.reserved.current - reserved_before
      == 2 * (int64_t)first->memid.mem.os.size);
  emit("registry_still", mi_arenas_get_count(&owner.subproc) == 2);
  return valid && distinct && owners && full_first && restored && maps_live ? 0 : 1;
}
