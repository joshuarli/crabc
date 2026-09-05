/* Copyright (c) 2026 crabc contributors. SPDX-License-Identifier: MIT */
/* Exact extracted pinned policy functions, with explicit primitive recorders.
 * This proves policy ordering, not hardware huge-page support. */
#define _GNU_SOURCE
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <sys/mman.h>
#define mi_attr_noexcept
#define MI_HUGE_OS_PAGE_SIZE ((size_t)1 << 30)
typedef struct { int unused; } mi_subproc_t;
static size_t field, calls, fail_at, detected;
static uint8_t* free_base;
static size_t free_calls;
static int _mi_os_numa_node_count(void) { return (int)detected; }
static int mi_reserve_huge_os_pages_at(size_t pages, int node, size_t timeout) {
  calls++;
  printf("m2.huge.interleave.%zu=%zu\n", field++, pages);
  printf("m2.huge.interleave.%zu=%d\n", field++, node);
  printf("m2.huge.interleave.%zu=%zu\n", field++, timeout);
  return (fail_at != 0 && calls == fail_at ? ENOMEM : 0);
}
static bool mi_os_prim_free(mi_subproc_t* subproc, void* p, size_t size, size_t committed, bool adjust) {
  (void)subproc;
  if (size != MI_HUGE_OS_PAGE_SIZE || committed != size || adjust) abort();
  const size_t page = ((uint8_t*)p - free_base) / MI_HUGE_OS_PAGE_SIZE;
  printf("m2.huge.free.%zu=%zu\n", free_calls++, page);
  return page != 0 && page != 2; /* failed first and last source frees */
}
/* INTERLEAVE_SOURCE */
/* HUGE_FREE_SOURCE */
int main(void) {
  const size_t cases[][5] = {
    {0, 0, 3, 0, 0}, {1, 0, 3, 0, 0}, {5, 3, 9, 100, 0},
    {5, 3, 9, 100, 2}, {17, SIZE_MAX, 4, 1, 0}, {5, 2, 1, SIZE_MAX, 0},
    {1, 1, 1, SIZE_MAX, 0}, {2, INT_MAX, 3, 0, 0}, {2, 0, 0, 100, 0},
  };
  for (size_t i = 0; i < sizeof(cases)/sizeof(cases[0]); i++) {
    calls = 0; detected = cases[i][2]; fail_at = cases[i][4];
    const int result = mi_reserve_huge_os_pages_interleave(cases[i][0], cases[i][1], cases[i][3]);
    printf("m2.huge.interleave.%zu=%zu\n", field++, calls);
    printf("m2.huge.interleave.%zu=%d\n", field++, result != 0);
  }
  free_base = mmap(NULL, 3 * MI_HUGE_OS_PAGE_SIZE, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (free_base == MAP_FAILED) return 2;
  mi_subproc_t subproc = {0};
  mi_os_free_huge_os_pages(&subproc, free_base, 3 * MI_HUGE_OS_PAGE_SIZE);
  if (free_calls != 3) return 3;
  return munmap(free_base, 3 * MI_HUGE_OS_PAGE_SIZE) == 0 ? 0 : 4;
}
