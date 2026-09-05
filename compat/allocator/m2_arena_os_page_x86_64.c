/* Copyright (c) 2026 crabc contributors. SPDX-License-Identifier: MIT
 * Real fixed-source ordinary/aligned OS page allocation and retirement.
 */
#include "static.c"
#include <stdio.h>

int main(void) {
  mi_process_init();
  mi_option_set(mi_option_disallow_arena_alloc, 1);
  const size_t alignments[] = {1, 128 * 1024};
  const size_t blocks[] = {16,4096,16384,128*1024,1024*1024,8*1024*1024,64*1024*1024};
  mi_theap_t* const theap = _mi_subproc_main()->theap_meta;
  size_t ordinal = 0;
  size_t ownership_ordinal = 0;
  for (size_t a = 0; a < 2; a++) {
    for (size_t b = 0; b < 7; b++) {
      mi_subproc_t* const subprocess = _mi_subproc_main();
      mi_page_t* page = _mi_arenas_page_alloc(theap, blocks[b], alignments[a]);
      if (page == NULL || page->memid.memkind != MI_MEM_OS) return 1;
      size_t subindex, map_slices;
      (void)mi_page_map_get_idx(page, &subindex, &map_slices);
      const size_t values[] = {page->block_size, page->reserved, page->memid.mem.os.size,
        (size_t)(mi_page_slice_start(page) - (uint8_t*)page->memid.mem.os.base),
        (size_t)((uint8_t*)page - (uint8_t*)page->memid.mem.os.base),
        page->page_offset, map_slices * MI_ARENA_SLICE_SIZE};
      for (size_t i = 0; i < 7; i++) printf("m2.arena.os_page.%zu=%zu\n", ordinal++, values[i]);
      const bool singleton = mi_page_is_singleton(page);
      /* Same span selection as `_mi_arenas_page_alloc`; page_full_size also
       * includes source page_offset and is not this fresh-area input. */
      const size_t span = singleton ? blocks[b] :
        (blocks[b] <= MI_SMALL_MAX_OBJ_SIZE ? MI_SMALL_PAGE_SIZE :
         blocks[b] <= MI_MEDIUM_MAX_OBJ_SIZE ? MI_MEDIUM_PAGE_SIZE : MI_LARGE_PAGE_SIZE);
      const size_t slices = mi_slice_count_of_size(span);
      _mi_arenas_page_free(page, theap);

      /* Measure the actual fresh-area owner separately from PageMap's lazy
       * node allocations, which are a different subprocess allocation. */
      const int64_t reserved_before = subprocess->stats.reserved.current;
      const int64_t committed_before = subprocess->stats.committed.current;
      const int64_t calls_before = subprocess->stats.commit_calls.total;
      mi_memid_t memory = _mi_memid_none();
      mi_arena_pages_t* arena_pages = NULL;
      uint8_t* start = mi_arenas_page_alloc_fresh_area(theap, slices,
        singleton && slices > 2 ? 2 : slices, alignments[a],
        alignments[a] > MI_PAGE_MAX_OVERALLOC_ALIGN, true, &memory, &arena_pages);
      if (start == NULL || memory.memkind != MI_MEM_OS) return 3;
      printf("m2.arena.os_owner.%zu=%lld\n", ownership_ordinal++, (long long)(subprocess->stats.reserved.current - reserved_before));
      printf("m2.arena.os_owner.%zu=%lld\n", ownership_ordinal++, (long long)(subprocess->stats.committed.current - committed_before));
      printf("m2.arena.os_owner.%zu=%lld\n", ownership_ordinal++, (long long)(subprocess->stats.commit_calls.total - calls_before));
      _mi_arenas_free(subprocess, start, mi_size_of_slices(slices), memory);
      printf("m2.arena.os_owner.%zu=%lld\n", ownership_ordinal++, (long long)(subprocess->stats.reserved.current - reserved_before));
      printf("m2.arena.os_owner.%zu=%lld\n", ownership_ordinal++, (long long)(subprocess->stats.committed.current - committed_before));
    }
  }
  return ordinal == 98 && ownership_ordinal == 70 ? 0 : 2;
}
