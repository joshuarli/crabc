/* Direct pinned mimalloc v3.5.0 external-arena callback lifecycle. */
#define _GNU_SOURCE 1
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

#include "static.c"

typedef struct callback_trace_s {
  unsigned order;
  unsigned calls;
  bool refuse_first;
  bool null_metadata_zero;
  bool claim_zero_output;
  bool null_purge_zero;
  void* last_start;
  size_t last_size;
} callback_trace_t;

static bool external_callback(bool commit, void* start, size_t size,
                              bool* is_zero, void* argument) {
  callback_trace_t* trace = (callback_trace_t*)argument;
  trace->order = trace->order * 10 + (commit ? 1u : 2u);
  trace->calls++;
  trace->last_start = start;
  trace->last_size = size;
  if (!commit) {
    trace->null_purge_zero = (is_zero == NULL);
    return true; /* the purged slices need recommit */
  }
  if (trace->calls <= 2) trace->null_metadata_zero = (is_zero == NULL);
  else trace->claim_zero_output = (is_zero != NULL);
  if (is_zero != NULL) *is_zero = true;
  if (trace->refuse_first) {
    trace->refuse_first = false;
    return false;
  }
  return true;
}

static void emit(const char* field, long long value) {
  printf("m2.external_refusal.%s=%lld\n", field, value);
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  mi_process_init();
  mi_subproc_t* subproc = _mi_subproc_main();
  const size_t size = MI_ARENA_MIN_SIZE;
  const size_t raw_size = size + MI_ARENA_ALIGNMENT;
  void* raw = mmap(NULL, raw_size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (raw == MAP_FAILED) return 2;
  void* base = (void*)(((uintptr_t)raw + MI_ARENA_ALIGNMENT - 1)
                        & ~(uintptr_t)(MI_ARENA_ALIGNMENT - 1));
  callback_trace_t trace = {.refuse_first = true};
  const int64_t maps_before = subproc->stats.mmap_calls.total;
  const int64_t reserved_before = subproc->stats.reserved.current;
  const int64_t purge_calls_before = subproc->stats.purge_calls.total;
  const int64_t purged_before = subproc->stats.purged.total;
  mi_arena_id_t first_id = _mi_arena_id_none();
  const bool first = mi_manage_memory(base, size, false, false, false,
      -1, false, external_callback, &trace, &first_id);
  unsigned char residency = 0;
  const bool refused = !first && first_id == _mi_arena_id_none()
      && mi_arenas_get_count(subproc) == 0 && trace.order == 1
      && trace.null_metadata_zero && _mi_ptr_page(base) == NULL
      && mincore(base, (size_t)sysconf(_SC_PAGESIZE), &residency) == 0
      && subproc->stats.mmap_calls.total == maps_before
      && subproc->stats.reserved.current == reserved_before;

  mi_arena_id_t id = _mi_arena_id_none();
  const bool managed = mi_manage_memory(base, size, false, false, false,
      -1, false, external_callback, &trace, &id);
  mi_arena_t* arena = _mi_arena_from_id(id);
  const bool owner = managed && arena != NULL && arena->start == base
      && arena->memid.memkind == MI_MEM_EXTERNAL
      && arena->memid.mem.os.base == base && arena->memid.mem.os.size == size
      && mi_arenas_get_count(subproc) == 1 && trace.order == 11;
  if (!owner) return 3;
  const size_t info = arena->info_slices;
  const bool initial_bitmap = mi_bbitmap_is_clearN(arena->slices_free, 0, info)
      && mi_bbitmap_is_setN(arena->slices_free, info, arena->slice_count - info)
      && mi_bitmap_is_clearN(arena->slices_committed, 0, arena->slice_count)
      && mi_bitmap_is_setN(arena->slices_dirty, 0, arena->slice_count);

  mi_memid_t claim_id = _mi_memid_none();
  void* claim = mi_arena_try_alloc_at(arena, 2, true, 0, &claim_id);
  const size_t index = claim_id.mem.arena.slice_index;
  const bool claimed = claim != NULL && claim_id.memkind == MI_MEM_ARENA
      && claim_id.mem.arena.arena == arena && trace.order == 111
      && trace.claim_zero_output && trace.last_start == claim
      && trace.last_size == 2 * MI_ARENA_SLICE_SIZE
      && mi_bbitmap_is_clearN(arena->slices_free, index, 2)
      && mi_bitmap_is_setN(arena->slices_committed, index, 2);
  if (!claimed) return 4;

  const bool purged = mi_arena_purge(arena, index, 2);
  const bool purge_state = purged && trace.order == 1112
      && trace.null_purge_zero && trace.last_start == claim
      && trace.last_size == 2 * MI_ARENA_SLICE_SIZE
      && mi_bitmap_is_clearN(arena->slices_committed, index, 2)
      && subproc->stats.purge_calls.total == purge_calls_before + 1
      && subproc->stats.purged.total == purged_before + 2 * MI_ARENA_SLICE_SIZE;
  mi_bbitmap_setN(arena->slices_free, index, 2);
  residency = 0;
  const bool released = mi_bbitmap_is_setN(arena->slices_free, index, 2)
      && _mi_ptr_page(claim) == NULL
      && mincore(base, (size_t)sysconf(_SC_PAGESIZE), &residency) == 0
      && subproc->stats.mmap_calls.total == maps_before
      && subproc->stats.reserved.current == reserved_before;

  emit("refused", refused);
  emit("owner", owner);
  emit("initial_bitmap", initial_bitmap);
  emit("claimed", claimed);
  emit("purge_state", purge_state);
  emit("released_external_live", released);
  emit("callback_order", trace.order);
  emit("callback_count", trace.calls);
  return refused && owner && initial_bitmap && claimed && purge_state
      && released && trace.order == 1112 && trace.calls == 4 ? 0 : 1;
}
