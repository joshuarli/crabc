/*
 * SPDX-License-Identifier: MIT
 *
 * Pinned-C implementation of the private x86-64 benchmark boundary.  The
 * fixture calls these names only so its workload source remains identical to
 * the Rust-adapter lane.  This file is built with the checked pinned v3.5.0
 * source units; it is not an installed adapter or a public ABI.
 */
#include "perf-api.h"

#include <mimalloc.h>

int crabc_allocator_perf_init(void)
{
  mi_process_init();
  mi_thread_init();
  return 0;
}

int crabc_allocator_perf_shutdown(void)
{
  mi_collect(true);
  mi_thread_done();
  mi_process_done();
  return 0;
}

void *crabc_allocator_perf_malloc(size_t size)
{
  return mi_malloc(size);
}

void crabc_allocator_perf_free(void *block)
{
  mi_free(block);
}
