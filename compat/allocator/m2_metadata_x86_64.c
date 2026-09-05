/* Copyright (c) 2026 crabc contributors. SPDX-License-Identifier: MIT
 * Direct pinned-v3.5.0 metadata callers; static.c supplies the real detached
 * Theap, arena/OS policy, PageMap, and release implementation, without stubs.
 */
#include "static.c"
#include <stdio.h>

int main(void) {
  mi_process_init();
  mi_subproc_t* const subproc = _mi_subproc_main();
  mi_option_set(mi_option_arena_reserve, 64 * 1024); /* source KiB option */
  mi_option_set(mi_option_page_commit_on_demand, 0);
  mi_memid_t first_memory = _mi_memid_none();
  void* const first = _mi_meta_zalloc(subproc, 64, &first_memory);
  if (first == NULL || mi_atomic_load_relaxed(&subproc->arena_count) != 1) return 5;
  const size_t size = 2 * MI_ARENA_MIN_SIZE;
  mi_memid_t memory = _mi_memid_none();
  unsigned char* const p = _mi_meta_zalloc(subproc, size, &memory);
  if (p == NULL) return 1;
  if (mi_atomic_load_relaxed(&subproc->arena_count) != 2) return 6;
  if (memory.memkind != MI_MEM_MALLOC) return 2;
  for (size_t i = 0; i < size; i++) {
    if (p[i] != 0) return 3;
  }
  if (!_mi_meta_is_meta_page(subproc, _mi_ptr_page(p))) return 4;
  _mi_meta_free(subproc, p, memory);
  _mi_meta_free(subproc, first, first_memory);
  printf("m2.metadata.capacity.bytes=%zu\n", size);
  printf("m2.metadata.capacity.zeroed_malloc_released=1\n");
  return 0;
}
