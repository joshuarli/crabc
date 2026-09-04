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
  for (size_t a = 0; a < 2; a++) {
    for (size_t b = 0; b < 7; b++) {
      mi_page_t* page = _mi_arenas_page_alloc(theap, blocks[b], alignments[a]);
      if (page == NULL || page->memid.memkind != MI_MEM_OS) return 1;
      size_t subindex, map_slices;
      (void)mi_page_map_get_idx(page, &subindex, &map_slices);
      const size_t values[] = {page->block_size, page->reserved, page->memid.mem.os.size,
        (size_t)(mi_page_slice_start(page) - (uint8_t*)page->memid.mem.os.base),
        (size_t)((uint8_t*)page - (uint8_t*)page->memid.mem.os.base),
        page->page_offset, map_slices * MI_ARENA_SLICE_SIZE};
      for (size_t i = 0; i < 7; i++) printf("m2.arena.os_page.%zu=%zu\n", ordinal++, values[i]);
      _mi_arenas_page_free(page, theap);
    }
  }
  return ordinal == 98 ? 0 : 2;
}
