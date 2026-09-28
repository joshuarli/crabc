/* Pinned v3.5.0 delayed purge of one released span beside a live claim. */
#define _GNU_SOURCE 1
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "static.c"

typedef struct owner_s { mi_subproc_t subproc; mi_heap_t heap; } owner_t;
static owner_t owner;

static void emit(const char* field, long long value) {
  printf("m2.second_purge.%s=%lld\n", field, value);
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
  mi_option_set(mi_option_arena_purge_mult, 1);
  mi_option_set(mi_option_purge_decommits, 1);

  mi_memid_t ids[4];
  void* claims[4];
  for (size_t i = 0; i < 4; i++) {
    ids[i] = _mi_memid_none();
    claims[i] = mi_arenas_try_alloc(&owner.heap, 256, MI_ARENA_SLICE_ALIGN,
                                   false, true, NULL, 0, -1, &ids[i]);
    if (claims[i] == NULL || ids[i].memkind != MI_MEM_ARENA) return 2;
  }
  mi_arena_t* first = ids[0].mem.arena.arena;
  mi_arena_t* second = ids[3].mem.arena.arena;
  if (mi_arenas_get_count(&owner.subproc) != 2 || first == second) return 3;
  mi_memid_t survivor_id = _mi_memid_none();
  void* survivor = mi_arenas_try_alloc(&owner.heap, 1, MI_ARENA_SLICE_ALIGN,
                                       false, true, second, 0, -1, &survivor_id);
  if (survivor == NULL || survivor_id.mem.arena.arena != second) return 4;
  const size_t released_index = ids[3].mem.arena.slice_index;
  const size_t survivor_index = survivor_id.mem.arena.slice_index;
  const bool setup = released_index == 9 && survivor_index == 265
      && second->memid.memkind == MI_MEM_OS
      && second->memid.mem.os.base == second->start
      && second->memid.mem.os.size == 2 * MI_ARENA_MIN_SIZE
      && mi_bbitmap_is_clearN(second->slices_free, released_index, 256)
      && mi_bbitmap_is_clearN(second->slices_free, survivor_index, 1);
  const int64_t purge_before = owner.subproc.stats.purge_calls.total;
  const int64_t bytes_before = owner.subproc.stats.purged.total;
  const int64_t visits_before = owner.subproc.stats.arena_purges.total;
  const int64_t reserved_before = owner.subproc.stats.reserved.current;
  _mi_arenas_free(&owner.subproc, claims[3], 256 * MI_ARENA_SLICE_SIZE, ids[3]);
  const bool pending = mi_bbitmap_is_setN(second->slices_free, released_index, 256)
      && mi_bbitmap_is_clearN(second->slices_free, survivor_index, 1)
      && mi_bitmap_is_setN(second->slices_purge, released_index, 256)
      && mi_bitmap_is_clearN(second->slices_purge, survivor_index, 1)
      && mi_atomic_loadi64_relaxed(&second->purge_expire) > 0
      && owner.subproc.stats.purge_calls.total == purge_before
      && owner.subproc.stats.purged.total == bytes_before
      && owner.subproc.stats.arena_purges.total == visits_before;

  mi_arenas_try_purge(true, true, &owner.subproc, 0);
  const int64_t first_calls = owner.subproc.stats.purge_calls.total - purge_before;
  const int64_t first_bytes = owner.subproc.stats.purged.total - bytes_before;
  const int64_t first_visits = owner.subproc.stats.arena_purges.total - visits_before;
  const bool partial = mi_bbitmap_is_setN(second->slices_free, released_index, 256)
      && mi_bbitmap_is_clearN(second->slices_free, survivor_index, 1)
      && mi_bitmap_is_clearN(second->slices_purge, released_index, 256)
      && mi_bitmap_is_clearN(second->slices_purge, survivor_index, 1)
      && first_calls == 5
      && first_bytes == 256 * MI_ARENA_SLICE_SIZE
      && first_visits == 1;

  _mi_arenas_free(&owner.subproc, survivor, MI_ARENA_SLICE_SIZE, survivor_id);
  const bool later_pending = mi_bbitmap_is_setN(second->slices_free, survivor_index, 1)
      && mi_bitmap_is_setN(second->slices_purge, survivor_index, 1)
      && owner.subproc.stats.purge_calls.total == purge_before + 5;
  mi_arenas_try_purge(true, true, &owner.subproc, 0);
  const bool later_purged = mi_bbitmap_is_setN(second->slices_free, released_index, 256)
      && mi_bbitmap_is_setN(second->slices_free, survivor_index, 1)
      && mi_bitmap_is_clearN(second->slices_purge, released_index, 256)
      && mi_bitmap_is_clearN(second->slices_purge, survivor_index, 1)
      && owner.subproc.stats.purge_calls.total == purge_before + 6
      && owner.subproc.stats.purged.total == bytes_before + 257 * MI_ARENA_SLICE_SIZE
      && owner.subproc.stats.arena_purges.total == visits_before + 2;
  const bool first_survives = mi_bbitmap_is_clearN(first->slices_free,
      ids[0].mem.arena.slice_index, 256)
      && mi_bbitmap_is_clearN(first->slices_free, ids[1].mem.arena.slice_index, 256)
      && mi_bbitmap_is_clearN(first->slices_free, ids[2].mem.arena.slice_index, 256);
  const bool maps_live = live_page(first->start) && live_page(second->start)
      && owner.subproc.stats.reserved.current == reserved_before
      && mi_arenas_get_count(&owner.subproc) == 2;
  emit("setup", setup);
  emit("pending", pending);
  emit("partial", partial);
  emit("later_pending", later_pending);
  emit("later_purged", later_purged);
  emit("first_survives", first_survives);
  emit("maps_live", maps_live);
  emit("first_purge_calls", first_calls);
  emit("first_purged_bytes", first_bytes);
  emit("first_arena_purges", first_visits);
  emit("released_slice", (long long)released_index);
  emit("survivor_slice", (long long)survivor_index);
  emit("purge_calls", owner.subproc.stats.purge_calls.total - purge_before);
  emit("purged_bytes", owner.subproc.stats.purged.total - bytes_before);
  emit("arena_purges", owner.subproc.stats.arena_purges.total - visits_before);
  return setup && pending && partial && later_pending && later_purged
      && first_survives && maps_live ? 0 : 1;
}
