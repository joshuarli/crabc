/* Pinned source reset of one committed free slice beside a live arena claim. */
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
static mi_arena_t* selected_arena;
static size_t selected_slice;
static size_t advice_calls;
static size_t advice_exact;
static int advice_kind;

int __real_madvise(void* address, size_t length, int advice);
int __wrap_madvise(void* address, size_t length, int advice) {
  if (selected_arena != NULL) {
    advice_calls++;
    advice_exact += address == mi_arena_slice_start(selected_arena, selected_slice)
        && length == MI_ARENA_SLICE_SIZE;
    advice_kind = advice;
  }
  return __real_madvise(address, length, advice);
}

static void emit(const char* field, long long value) {
  printf("m2.second_reset.%s=%lld\n", field, value);
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
  mi_option_set(mi_option_purge_decommits, 0);

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
  mi_memid_t released_id = _mi_memid_none();
  mi_memid_t survivor_id = _mi_memid_none();
  void* released = mi_arenas_try_alloc(&owner.heap, 1, MI_ARENA_SLICE_ALIGN,
                                      true, true, second, 0, -1, &released_id);
  void* survivor = mi_arenas_try_alloc(&owner.heap, 1, MI_ARENA_SLICE_ALIGN,
                                      false, true, second, 0, -1, &survivor_id);
  if (released == NULL || survivor == NULL || released_id.mem.arena.arena != second
      || survivor_id.mem.arena.arena != second) return 4;
  const size_t index = released_id.mem.arena.slice_index;
  const size_t survivor_index = survivor_id.mem.arena.slice_index;
  const int64_t purge_before = owner.subproc.stats.purge_calls.total;
  const int64_t bytes_before = owner.subproc.stats.purged.total;
  const int64_t visits_before = owner.subproc.stats.arena_purges.total;
  const int64_t reset_before = owner.subproc.stats.reset.total;
  const int64_t reset_calls_before = owner.subproc.stats.reset_calls.total;
  const int64_t committed_before = owner.subproc.stats.committed.current;
  const int64_t reserved_before = owner.subproc.stats.reserved.current;
  const bool setup = index == 265 && survivor_index == 266
      && mi_bitmap_is_setN(second->slices_committed, index, 1);
  _mi_arenas_free(&owner.subproc, released, MI_ARENA_SLICE_SIZE, released_id);
  const bool pending = mi_bitmap_is_setN(second->slices_purge, index, 1)
      && mi_bitmap_is_setN(second->slices_committed, index, 1)
      && mi_bbitmap_is_setN(second->slices_free, index, 1)
      && mi_bbitmap_is_clearN(second->slices_free, survivor_index, 1)
      && owner.subproc.stats.reset_calls.total == reset_calls_before;
  selected_arena = second;
  selected_slice = index;
  mi_arenas_try_purge(true, true, &owner.subproc, 0);
  const bool reset_state = mi_bitmap_is_clearN(second->slices_purge, index, 1)
      && mi_bitmap_is_setN(second->slices_committed, index, 1)
      && mi_bbitmap_is_setN(second->slices_free, index, 1)
      && mi_bbitmap_is_clearN(second->slices_free, survivor_index, 1)
      && mi_atomic_loadi64_relaxed(&second->purge_expire) == 0;
  const bool maps_live = live_page(first->start) && live_page(second->start)
      && owner.subproc.stats.reserved.current == reserved_before
      && mi_arenas_get_count(&owner.subproc) == 2;
  emit("setup", setup); emit("pending", pending);
  emit("reset_state", reset_state); emit("advice_calls", advice_calls);
  emit("advice_exact", advice_exact); emit("advice_kind", advice_kind);
  emit("reset_calls", owner.subproc.stats.reset_calls.total - reset_calls_before);
  emit("reset_bytes", owner.subproc.stats.reset.total - reset_before);
  emit("purge_calls", owner.subproc.stats.purge_calls.total - purge_before);
  emit("purged_bytes", owner.subproc.stats.purged.total - bytes_before);
  emit("arena_purges", owner.subproc.stats.arena_purges.total - visits_before);
  emit("committed_delta", owner.subproc.stats.committed.current - committed_before);
  emit("maps_live", maps_live); emit("released_slice", index);
  emit("survivor_slice", survivor_index);
  return setup && pending && reset_state && advice_calls == 1 && advice_exact == 1
      && advice_kind == MADV_FREE && maps_live ? 0 : 1;
}
