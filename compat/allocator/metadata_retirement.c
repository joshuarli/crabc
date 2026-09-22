/* Copyright (c) 2026 crabc contributors. SPDX-License-Identifier: MIT */
/* Source destroy_on_exit leaves direct OS metadata pages mapped. */
#include "static.c"
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>

static void require(bool condition) { if (!condition) abort(); }
int main(void) {
  mi_process_init();
  mi_option_set(mi_option_disallow_arena_alloc, 1);
  mi_memid_t memory;
  void* allocation = _mi_meta_zalloc(&mi_process_subproc_main, 64, &memory);
  require(allocation != NULL);
  mi_page_t* page = _mi_ptr_page(allocation);
  require(page != NULL);
  const size_t malloc_owned = (memory.memkind == MI_MEM_MALLOC);
  const size_t os_backed = (page->memid.memkind == MI_MEM_OS);
  void* address = (void*)((uintptr_t)allocation & ~(uintptr_t)4095);
  unsigned char residency = 0;
  const size_t before = (mincore(address, 4096, &residency) == 0);
  mi_option_set(mi_option_destroy_on_exit, 1);
  mi_process_done();
  /* No allocator image dereference after teardown; only kernel mapping query. */
  const size_t after = (mincore(address, 4096, &residency) == 0);
  const size_t values[] = {malloc_owned, os_backed, before, after};
  for (size_t i = 0; i < 4; i++) printf("m2.metadata.retirement.%zu=%zu\n", i, values[i]);
  return 0;
}
