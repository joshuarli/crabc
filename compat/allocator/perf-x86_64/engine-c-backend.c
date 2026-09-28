/*
 * SPDX-License-Identifier: MIT
 *
 * Pinned mimalloc v3.5.0 implementation of the private engine performance
 * boundary (`engine-api.h`).  Each entry is a public operation of the pinned
 * source.  The 8-byte bin needs an explicitly aligned entry to meet the C
 * ABI's 16-byte fundamental alignment. Every ordinary bin for requests
 * from 9 bytes upward has an even word stride and a 16-byte aligned page
 * start, so those calls use the ordinary source entry. `realloc` is
 * `mi_realloc`, as the adapter's `native_reallocate` is. The runner compiles
 * this unit and the pinned sources separately from the fixture, never with LTO.
 */
#include "engine-api.h"

#include <mimalloc.h>
#include <stdint.h>

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
  return (size <= 8 ? mi_malloc_aligned(size, 16) : mi_malloc(size));
}

void crabc_allocator_engine_free(void *block)
{
  mi_free(block);
}

void *crabc_allocator_engine_calloc(size_t count, size_t size)
{
  if (size != 0 && count > SIZE_MAX / size) return NULL;
  const size_t total = count * size;
  return (total <= 8 ? mi_calloc_aligned(count, size, 16) : mi_calloc(count, size));
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
