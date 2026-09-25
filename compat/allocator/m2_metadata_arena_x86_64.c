/* Copyright (c) 2026 crabc contributors. SPDX-License-Identifier: MIT
 * Pinned v3.5.0 exclusive-arena Theap slice: `mi_heap_new_in_arena` makes
 * `_mi_theap_alloc` (src/theap.c:308-334) claim the Theap from the Heap's
 * exclusive arena, pages come from that arena, and heap destruction returns
 * the Theap slice through `_mi_meta_free` (src/theap.c:347-355). An
 * exhausted or arena-disallowed exclusive arena yields no Theap and no
 * fallback. Printed with the same keys as
 * dynamic_theap::tests::requested_arena_dynamic_owner_collects_live_pages_before_typed_metadata_release
 * and dynamic_theap::tests::exhausted_requested_arena_rejects_theap_without_fallback_or_published_roots.
 * No allocation/free implementation is replaced by this probe.
 */
#include "static.c"
#include <stdio.h>
#include <string.h>

static size_t free_slices(mi_arena_t* arena) {
  size_t count = 0;
  for (size_t i = 0; i < arena->slice_count; i++) {
    if (mi_bbitmap_is_setN(arena->slices_free, i, 1)) count++;
  }
  return count;
}

int main(void) {
  mi_process_init();
  mi_option_set(mi_option_page_full_retain, -1);
  mi_option_set(mi_option_page_commit_on_demand, 0);
  mi_option_set(mi_option_purge_delay, -1);
  mi_subproc_t* const subproc = _mi_subproc_main();
  mi_arena_id_t arena_id = 0;
  if (mi_reserve_os_memory_ex(MI_ARENA_MIN_SIZE, true, false, true, &arena_id) != 0) return 1;
  mi_arena_t* const arena = _mi_arena_from_id(arena_id);
  const size_t free_before = free_slices(arena);
  mi_heap_t* heap = mi_heap_new_in_arena(arena_id);
  if (heap == NULL) return 2;
  void* blocks[192];
  size_t sizes[] = {37, 1025, 8193, 131073};
  size_t in_exclusive = 0;
  for (size_t i = 0; i < 192; i++) {
    blocks[i] = mi_heap_zalloc(heap, sizes[i % 4]);
    if (blocks[i] == NULL) return 3;
    mi_page_t* page = _mi_ptr_page(blocks[i]);
    if (page->memid.memkind == MI_MEM_ARENA && page->memid.mem.arena.arena == arena) in_exclusive++;
    memset(blocks[i], 0xa5, sizes[i % 4]);
  }
  mi_theap_t* const theap = heap->theaps;
  if (theap == NULL) return 5;
  mi_memid_t const theap_memory = theap->memid;
  size_t slice_index = 0, slice_count = 0;
  const bool theap_in_exclusive = theap_memory.memkind == MI_MEM_ARENA
      && mi_arena_from_memid(theap_memory, &slice_index, &slice_count) == arena;
  const bool theap_claimed = mi_bbitmap_is_clearN(arena->slices_free, slice_index, slice_count);
  const size_t free_after_alloc = free_slices(arena);
  mi_heap_collect(heap, true);
  bool preserved = true;
  for (size_t i = 0; i < 192; i++) {
    unsigned char* bytes = blocks[i];
    for (size_t j = 0; j < sizes[i % 4]; j++) preserved = preserved && bytes[j] == 0xa5;
    mi_free(blocks[i]);
  }
  mi_heap_collect(heap, true);
  const size_t free_after_pages = free_slices(arena);
  _mi_theap_cached_set((mi_theap_t*)&_mi_theap_empty);
  mi_heap_destroy(heap);
  const bool theap_released = mi_bbitmap_is_setN(arena->slices_free, slice_index, slice_count);
  const size_t free_after_theap = free_slices(arena);

  printf("m2.metadata.arena.theap_in_exclusive=%d\n", theap_in_exclusive);
  printf("m2.metadata.arena.theap_slice_offset=%zu\n", slice_index - arena->info_slices);
  printf("m2.metadata.arena.theap_slice_count=%zu\n", slice_count);
  printf("m2.metadata.arena.theap_slice_claimed=%d\n", theap_claimed);
  printf("m2.metadata.arena.clients_in_exclusive=%zu\n", in_exclusive);
  printf("m2.metadata.arena.free_before=%zu\n", free_before);
  printf("m2.metadata.arena.free_after_alloc=%zu\n", free_after_alloc);
  printf("m2.metadata.arena.preserved_through_collect=%d\n", preserved);
  printf("m2.metadata.arena.free_after_pages=%zu\n", free_after_pages);
  printf("m2.metadata.arena.theap_slice_released=%d\n", theap_released);
  printf("m2.metadata.arena.free_after_theap=%zu\n", free_after_theap);

  /* Exhaust the requested parent through real source claims. The metadata
   * producer must return NULL even though the process can allocate elsewhere. */
  heap = mi_heap_new_in_arena(arena_id);
  if (heap == NULL) return 9;
  mi_memid_t claims[MI_ARENA_MIN_SIZE / MI_ARENA_SLICE_SIZE];
  void* pointers[MI_ARENA_MIN_SIZE / MI_ARENA_SLICE_SIZE];
  size_t count = 0;
  for (; count < MI_ARENA_MIN_SIZE / MI_ARENA_SLICE_SIZE; count++) {
    pointers[count] = mi_arena_try_alloc_at(arena, 1, true, 0, &claims[count]);
    if (pointers[count] == NULL) break;
  }
  const bool exhausted_refused = count != 0
      && _mi_theap_alloc(heap, mi_theap_get_default()->tld) == NULL && heap->theaps == NULL;
  for (size_t i = 0; i < count; i++) {
    _mi_arenas_free(subproc, pointers[i], MI_ARENA_SLICE_SIZE, claims[i]);
  }
  mi_option_set(mi_option_disallow_arena_alloc, 1);
  const bool disallowed_refused = _mi_theap_alloc(heap, mi_theap_get_default()->tld) == NULL
      && heap->theaps == NULL;
  mi_option_set(mi_option_disallow_arena_alloc, 0);
  mi_heap_destroy(heap);
  printf("m2.metadata.arena.exhausted_claims=%zu\n", count);
  printf("m2.metadata.arena.exhausted_no_fallback=%d\n", exhausted_refused);
  printf("m2.metadata.arena.disallowed_no_fallback=%d\n", disallowed_refused);
  return 0;
}
