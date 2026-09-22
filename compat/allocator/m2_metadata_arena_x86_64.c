/* Copyright (c) 2026 crabc contributors. SPDX-License-Identifier: MIT
 * Direct fixed-v3.5.0 exclusive-arena Theap producer and metadata release.
 * No allocation/free implementation is replaced by this probe.
 */
#include "static.c"
#include <stdio.h>
#include <string.h>

int main(void) {
  mi_process_init();
  mi_option_set(mi_option_page_full_retain, -1);
  mi_option_set(mi_option_page_commit_on_demand, 0);
  mi_option_set(mi_option_purge_delay, -1);
  mi_subproc_t* const subproc = _mi_subproc_main();
  mi_arena_id_t arena_id = 0;
  if (mi_reserve_os_memory_ex(MI_ARENA_MIN_SIZE, true, false, true, &arena_id) != 0) return 1;
  mi_arena_t* const arena = _mi_arena_from_id(arena_id);
  mi_heap_t* heap = mi_heap_new_in_arena(arena_id);
  if (heap == NULL) return 2;
  void* blocks[192];
  size_t sizes[] = {37, 1025, 8193, 131073};
  for (size_t i = 0; i < 192; i++) {
    blocks[i] = mi_heap_zalloc(heap, sizes[i % 4]);
    if (blocks[i] == NULL) return 3;
    mi_page_t* page = _mi_ptr_page(blocks[i]);
    if (page->memid.memkind != MI_MEM_ARENA || page->memid.mem.arena.arena != arena) return 4;
    memset(blocks[i], 0xa5, sizes[i % 4]);
  }
  mi_theap_t* const theap = heap->theaps;
  if (theap == NULL || theap->memid.memkind != MI_MEM_ARENA) return 5;
  mi_memid_t const theap_memory = theap->memid;
  size_t slice_index, slice_count;
  if (mi_arena_from_memid(theap_memory, &slice_index, &slice_count) != arena) return 6;
  mi_heap_collect(heap, true);
  for (size_t i = 0; i < 192; i++) {
    unsigned char* bytes = blocks[i];
    for (size_t j = 0; j < sizes[i % 4]; j++) if (bytes[j] != 0xa5) return 7;
    mi_free(blocks[i]);
  }
  mi_heap_collect(heap, true);
  _mi_theap_cached_set((mi_theap_t*)&_mi_theap_empty);
  mi_heap_destroy(heap);
  if (!mi_bbitmap_is_setN(arena->slices_free, slice_index, slice_count)) return 8;
  puts("m2.metadata.arena.live_clients=192");
  puts("m2.metadata.arena.preserved_through_collect=1");
  puts("m2.metadata.arena.typed_release_reusable=1");

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
  if (count == 0 || _mi_theap_alloc(heap, mi_theap_get_default()->tld) != NULL
      || heap->theaps != NULL) return 10;
  for (size_t i = 0; i < count; i++) {
    _mi_arenas_free(subproc, pointers[i], MI_ARENA_SLICE_SIZE, claims[i]);
  }
  mi_option_set(mi_option_disallow_arena_alloc, 1);
  if (_mi_theap_alloc(heap, mi_theap_get_default()->tld) != NULL
      || heap->theaps != NULL) return 11;
  mi_option_set(mi_option_disallow_arena_alloc, 0);
  mi_heap_destroy(heap);
  puts("m2.metadata.arena.disallowed_no_fallback=1");
  puts("m2.metadata.arena.exhausted_no_fallback=1");
  return 0;
}
