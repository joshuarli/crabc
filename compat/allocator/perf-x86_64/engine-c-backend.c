/*
 * SPDX-License-Identifier: MIT
 *
 * Pinned mimalloc v3.5.0 implementation of the private engine performance
 * boundary (`engine-api.h`).  Each entry is a public operation of the pinned
 * source.  `malloc` and `calloc` request the C ABI's 16-byte fundamental
 * alignment (`mi_malloc_aligned(size, 16)`, `mi_calloc_aligned`), the entry
 * crabc-libc's native adapter uses for them because the pinned small bins
 * (24, 40, 56 ... bytes) do not all guarantee it; `realloc` is `mi_realloc`,
 * as the adapter's `native_reallocate` is.  The runner compiles this unit
 * and the pinned sources separately from the fixture, never with LTO.
 */
#include "engine-api.h"

#include <mimalloc.h>

int crabc_allocator_engine_process_init(void)
{
  mi_process_init();
  return 0;
}

int crabc_allocator_engine_thread_init(void)
{
  mi_thread_init();
  return 0;
}

int crabc_allocator_engine_thread_done(void)
{
  mi_thread_done();
  return 0;
}

void *crabc_allocator_engine_malloc(size_t size)
{
  return mi_malloc_aligned(size, 16);
}

void crabc_allocator_engine_free(void *block)
{
  mi_free(block);
}

void *crabc_allocator_engine_calloc(size_t count, size_t size)
{
  return mi_calloc_aligned(count, size, 16);
}

void *crabc_allocator_engine_realloc(void *block, size_t size)
{
  return mi_realloc(block, size);
}

void *crabc_allocator_engine_aligned(size_t alignment, size_t size)
{
  return mi_malloc_aligned(size, alignment);
}

size_t crabc_allocator_engine_usable_size(const void *block)
{
  return mi_usable_size(block);
}

crabc_allocator_engine_heap *crabc_allocator_engine_heap_new(void)
{
  return (crabc_allocator_engine_heap *)mi_heap_new();
}

void *crabc_allocator_engine_heap_malloc(crabc_allocator_engine_heap *heap, size_t size)
{
  return mi_heap_malloc((mi_heap_t *)heap, size);
}

void crabc_allocator_engine_heap_destroy(crabc_allocator_engine_heap *heap)
{
  mi_heap_destroy((mi_heap_t *)heap);
}

crabc_allocator_engine_subproc *crabc_allocator_engine_subproc_new(void)
{
  return (crabc_allocator_engine_subproc *)mi_subproc_new()._mi_subproc_id;
}

int crabc_allocator_engine_subproc_add_current_thread(crabc_allocator_engine_subproc *subproc)
{
  mi_subproc_id_t id = {subproc};
  mi_subproc_add_current_thread(id);
  return 0;
}

void crabc_allocator_engine_subproc_destroy(crabc_allocator_engine_subproc *subproc)
{
  mi_subproc_id_t id = {subproc};
  mi_subproc_destroy(id);
}
