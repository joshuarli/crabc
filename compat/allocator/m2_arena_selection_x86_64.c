/* Copyright (c) 2026 crabc contributors. SPDX-License-Identifier: MIT
 * The exact source helper is visible through static.c; no copied algorithm.
 */
#include "static.c"
#include <stdio.h>

int main(void) {
  const size_t counts[] = {0,1,2,3,8,17,129,2305};
  const size_t heap_counts[] = {0,1,2,3,8,1024,1000000};
  const size_t heap_sequences[] = {0,1,7,SIZE_MAX};
  const size_t thread_sequences[] = {0,1,5,SIZE_MAX};
  mi_subproc_t subproc = {0};
  mi_heap_t heap = {0};
  heap.subproc = &subproc;
  size_t ordinal = 0;
  for (size_t c = 0; c < 8; c++) {
    const size_t cycle = (counts[c] == 0 ? 0 : counts[c] - 1);
    for (size_t hc = 0; hc < 7; hc++) {
      mi_atomic_store_relaxed(&subproc.heap_count, heap_counts[hc]);
      for (size_t hs = 0; hs < 4; hs++) {
        heap.heap_seq = heap_sequences[hs];
        for (size_t ts = 0; ts < 4; ts++) {
          printf("m2.arena.selection.%zu=%zu\n", ordinal++,
                 mi_arena_start_idx(&heap, thread_sequences[ts], cycle));
        }
      }
    }
  }
  return ordinal == 896 ? 0 : 1;
}
