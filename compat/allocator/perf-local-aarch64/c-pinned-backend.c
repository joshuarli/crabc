/* SPDX-License-Identifier: MIT */
/* Pinned-C lane of the opaque local AArch64 performance boundary. */
#include "perf-api.h"

#include <mimalloc.h>

int crabc_local_allocator_perf_init(void)
{
  mi_process_init();
  mi_thread_init();
  return 0;
}

int crabc_local_allocator_perf_shutdown(void)
{
  mi_collect(true);
  mi_thread_done();
  mi_process_done();
  return 0;
}

void *crabc_local_allocator_perf_malloc(size_t size)
{
  return mi_malloc(size);
}

void crabc_local_allocator_perf_free(void *block)
{
  mi_free(block);
}

const char *crabc_local_allocator_perf_backend_identity(void)
{
  return "pinned-c-mimalloc-v3.5.0";
}

const char *crabc_local_allocator_perf_free_route(void)
{
  return "mi_free";
}
