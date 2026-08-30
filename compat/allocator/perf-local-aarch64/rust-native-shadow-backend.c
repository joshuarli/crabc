/* SPDX-License-Identifier: MIT */
/*
 * Rust-native shadow lane of the opaque local AArch64 performance boundary.
 * `crabc_test_*` is the existing prefixed test-only ABI: it is deliberately
 * not a public mi_* API or crabc-libc allocator selection mechanism.
 */
#include "perf-api.h"

#include "crabc-mimalloc-test-adapter.h"

int crabc_local_allocator_perf_init(void)
{
  return crabc_test_init();
}

int crabc_local_allocator_perf_shutdown(void)
{
  return crabc_test_shutdown();
}

void *crabc_local_allocator_perf_malloc(size_t size)
{
  return crabc_test_malloc(size);
}

void crabc_local_allocator_perf_free(void *block)
{
  crabc_test_free(block);
}
