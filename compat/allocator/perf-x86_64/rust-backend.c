/*
 * SPDX-License-Identifier: MIT
 *
 * Rust-adapter implementation of the private x86-64 benchmark boundary.  It
 * forwards only to the already-audited `crabc_test_*` test ABI.  Those names
 * are deliberately prefixed and remain outside all installed/public headers.
 */
#include "perf-api.h"

#include "crabc-mimalloc-test-adapter.h"

int crabc_allocator_perf_init(void)
{
  return crabc_test_init();
}

int crabc_allocator_perf_shutdown(void)
{
  return crabc_test_shutdown();
}

void *crabc_allocator_perf_malloc(size_t size)
{
  return crabc_test_malloc(size);
}

void crabc_allocator_perf_free(void *block)
{
  crabc_test_free(block);
}
