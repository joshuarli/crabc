/* Pinned v3.5.0 arena selection, sibling purge, and exact span reuse. */
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
static owner_t exclusive_owner;

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
                                       true, true, second, 0, -1, &survivor_id);
  if (survivor == NULL || survivor_id.mem.arena.arena != second) return 4;
  ((unsigned char*)survivor)[0] = 0x3e;
  mi_memid_t first_marker_id = _mi_memid_none();
  void* first_marker = mi_arenas_try_find_free(&owner.heap, 1, MI_ARENA_SLICE_ALIGN,
      true, true, first, 0, -1, &first_marker_id);
  if (first_marker == NULL) return 5;
  ((unsigned char*)first_marker)[0] = 0xa7;
  mi_memid_t refused_id = _mi_memid_none();
  const bool occupied_fallback = ids[1].mem.arena.arena == first
      && ids[2].mem.arena.arena == first
      && mi_arenas_try_find_free(&owner.heap, 256, MI_ARENA_SLICE_ALIGN,
          false, true, first, 0, -1, &refused_id) == NULL;
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

  const bool survivor_contents = ((unsigned char*)survivor)[0] == 0x3e;
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
  const int64_t original_purge_calls = owner.subproc.stats.purge_calls.total - purge_before;
  const int64_t original_purged_bytes = owner.subproc.stats.purged.total - bytes_before;
  const int64_t original_arena_purges = owner.subproc.stats.arena_purges.total - visits_before;
  const bool first_survives = mi_bbitmap_is_clearN(first->slices_free,
      ids[0].mem.arena.slice_index, 256)
      && mi_bbitmap_is_clearN(first->slices_free, ids[1].mem.arena.slice_index, 256)
      && mi_bbitmap_is_clearN(first->slices_free, ids[2].mem.arena.slice_index, 256);
  const bool maps_live = live_page(first->start) && live_page(second->start)
      && owner.subproc.stats.reserved.current == reserved_before
      && mi_arenas_get_count(&owner.subproc) == 2;
  const int64_t commit_before = owner.subproc.stats.commit_calls.total;
  mi_memid_t second_reuse_id = _mi_memid_none();
  void* second_reuse = mi_arenas_try_find_free(&owner.heap, 256, MI_ARENA_SLICE_ALIGN,
      true, true, NULL, 0, -1, &second_reuse_id);
  if (second_reuse == NULL) return 6;
  const bool second_reuse_exact = second_reuse == claims[3]
      && second_reuse_id.mem.arena.arena == second
      && second_reuse_id.mem.arena.slice_index == released_index;
  const bool second_recommit = second_reuse_id.initially_committed
      && mi_bitmap_is_setN(second->slices_committed, released_index, 256)
      && owner.subproc.stats.commit_calls.total == commit_before + 1;
  const bool second_zero = ((unsigned char*)second_reuse)[0] == 0
      && ((unsigned char*)second_reuse)[256 * MI_ARENA_SLICE_SIZE - 1] == 0;
  ((unsigned char*)second_reuse)[0] = 0xc7;
  ((unsigned char*)second_reuse)[256 * MI_ARENA_SLICE_SIZE - 1] = 0x71;
  _mi_arenas_free(&owner.subproc, claims[2], 256 * MI_ARENA_SLICE_SIZE, ids[2]);
  mi_arenas_try_purge(true, true, &owner.subproc, 0);
  mi_memid_t first_reuse_id = _mi_memid_none();
  void* first_reuse = mi_arenas_try_find_free(&owner.heap, 256, MI_ARENA_SLICE_ALIGN,
      true, true, NULL, 0, -1, &first_reuse_id);
  if (first_reuse == NULL) return 7;
  const bool first_reuse_exact = first_reuse == claims[2]
      && first_reuse_id.mem.arena.arena == first;
  const bool owners_preserved = ((unsigned char*)first_marker)[0] == 0xa7
      && ((unsigned char*)second_reuse)[0] == 0xc7
      && ((unsigned char*)second_reuse)[256 * MI_ARENA_SLICE_SIZE - 1] == 0x71;
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
  emit("purge_calls", original_purge_calls);
  emit("purged_bytes", original_purged_bytes);
  emit("arena_purges", original_arena_purges);
  emit("occupied_fallback", occupied_fallback);
  emit("survivor_contents", survivor_contents);
  emit("second_reuse_exact", second_reuse_exact);
  emit("second_recommit", second_recommit);
  emit("second_zero", second_zero);
  emit("first_reuse_exact", first_reuse_exact);
  emit("owners_preserved", owners_preserved);
  _mi_arenas_free(&owner.subproc, first_reuse, 256 * MI_ARENA_SLICE_SIZE, first_reuse_id);
  _mi_arenas_free(&owner.subproc, second_reuse, 256 * MI_ARENA_SLICE_SIZE, second_reuse_id);
  _mi_arenas_free(&owner.subproc, first_marker, MI_ARENA_SLICE_SIZE, first_marker_id);
  for (size_t i = 0; i < 2; i++)
    _mi_arenas_free(&owner.subproc, claims[i], 256 * MI_ARENA_SLICE_SIZE, ids[i]);
  const bool released_all = mi_bbitmap_is_setN(first->slices_free, ids[0].mem.arena.slice_index, 256)
      && mi_bbitmap_is_setN(first->slices_free, ids[1].mem.arena.slice_index, 256)
      && mi_bbitmap_is_setN(first->slices_free, ids[2].mem.arena.slice_index, 256)
      && mi_bbitmap_is_setN(first->slices_free, first_marker_id.mem.arena.slice_index, 1)
      && mi_bbitmap_is_setN(second->slices_free, released_index, 256);
  emit("released_all", released_all);

  memset(&exclusive_owner, 0, sizeof(exclusive_owner));
  mi_lock_init(&exclusive_owner.subproc.arena_reserve_lock);
  mi_atomic_store_relaxed(&exclusive_owner.subproc.heap_count, 1);
  exclusive_owner.heap.subproc = &exclusive_owner.subproc;
  mi_arena_id_t exclusive = _mi_arena_id_none(), ordinary = _mi_arena_id_none();
  if (mi_reserve_os_memory_ex2(&exclusive_owner.subproc, MI_ARENA_MIN_SIZE,
      false, false, true, &exclusive) != 0
      || mi_reserve_os_memory_ex2(&exclusive_owner.subproc, MI_ARENA_MIN_SIZE,
      false, false, false, &ordinary) != 0) return 8;
  mi_arena_t* exclusive_arena = (mi_arena_t*)exclusive;
  mi_arena_t* ordinary_arena = (mi_arena_t*)ordinary;
  mi_memid_t ordinary_id = _mi_memid_none(), exclusive_id = _mi_memid_none();
  void* ordinary_block = mi_arenas_try_find_free(&exclusive_owner.heap, 1,
      MI_ARENA_SLICE_ALIGN, true, true, NULL, 0, -1, &ordinary_id);
  void* exclusive_block = mi_arenas_try_find_free(&exclusive_owner.heap, 1,
      MI_ARENA_SLICE_ALIGN, true, true, exclusive, 0, -1, &exclusive_id);
  if (ordinary_block == NULL || exclusive_block == NULL) return 9;
  const bool exclusive_skipped = ordinary_id.mem.arena.arena == ordinary
      && exclusive_arena->is_exclusive && mi_arenas_get_count(&exclusive_owner.subproc) == 2;
  const bool exclusive_requested = exclusive_id.mem.arena.arena == exclusive;
  ((unsigned char*)ordinary_block)[0] = 0x5f;
  ((unsigned char*)exclusive_block)[0] = 0x9b;
  _mi_arenas_free(&exclusive_owner.subproc, exclusive_block, MI_ARENA_SLICE_SIZE, exclusive_id);
  mi_arenas_try_purge(true, true, &exclusive_owner.subproc, 0);
  mi_memid_t exclusive_reuse_id = _mi_memid_none();
  void* exclusive_reuse = mi_arenas_try_find_free(&exclusive_owner.heap, 1,
      MI_ARENA_SLICE_ALIGN, true, true, exclusive, 0, -1, &exclusive_reuse_id);
  const bool exclusive_reused = exclusive_reuse == exclusive_block
      && exclusive_reuse_id.mem.arena.arena == exclusive
      && exclusive_reuse_id.initially_committed
      && ((unsigned char*)exclusive_reuse)[0] == 0;
  const bool exclusive_sibling_preserved = ((unsigned char*)ordinary_block)[0] == 0x5f;
  if (exclusive_reuse == NULL) return 10;
  _mi_arenas_free(&exclusive_owner.subproc, exclusive_reuse, MI_ARENA_SLICE_SIZE, exclusive_reuse_id);
  _mi_arenas_free(&exclusive_owner.subproc, ordinary_block, MI_ARENA_SLICE_SIZE, ordinary_id);
  const bool exclusive_released = mi_bbitmap_is_setN(exclusive_arena->slices_free,
      exclusive_reuse_id.mem.arena.slice_index, 1)
      && mi_bbitmap_is_setN(ordinary_arena->slices_free, ordinary_id.mem.arena.slice_index, 1);
  emit("exclusive_skipped", exclusive_skipped);
  emit("exclusive_requested", exclusive_requested);
  emit("exclusive_reused", exclusive_reused);
  emit("exclusive_sibling_preserved", exclusive_sibling_preserved);
  emit("exclusive_released", exclusive_released);
  return setup && pending && partial && later_pending && later_purged
      && first_survives && maps_live && occupied_fallback && survivor_contents
      && second_reuse_exact && second_recommit && second_zero && first_reuse_exact
      && owners_preserved && released_all && exclusive_skipped && exclusive_requested
      && exclusive_reused && exclusive_sibling_preserved && exclusive_released ? 0 : 1;
}
