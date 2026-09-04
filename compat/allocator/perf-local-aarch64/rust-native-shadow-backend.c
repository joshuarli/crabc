/* SPDX-License-Identifier: MIT */
/*
 * Selected native-shadow lane of the opaque local AArch64 performance
 * boundary. The fixture reaches the compile-time-selected crabc-libc C ABI
 * through normal malloc/free spellings; run.py proves the exact linked
 * libc.so has native-mimalloc-shadow enabled and rejects a default C-backed
 * libc link before this shim can be timed.
 */
#include "perf-api.h"

#include <stdlib.h>

int crabc_local_allocator_perf_init(void)
{
  return 0;
}

int crabc_local_allocator_perf_shutdown(void)
{
  return 0;
}

void *crabc_local_allocator_perf_malloc(size_t size)
{
  return malloc(size);
}

void crabc_local_allocator_perf_free(void *block)
{
  free(block);
}

const char *crabc_local_allocator_perf_backend_identity(void)
{
  return "rust-native-shadow-selected-c-abi-v1";
}

const char *crabc_local_allocator_perf_free_route(void)
{
  return "free";
}
