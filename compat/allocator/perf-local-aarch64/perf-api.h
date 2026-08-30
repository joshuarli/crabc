/* SPDX-License-Identifier: MIT */
/*
 * Opaque, fixture-private allocation boundary for the local AArch64 smoke.
 * Neither lane exports this as an installed crabc or mimalloc interface.
 */
#ifndef CRABC_LOCAL_AARCH64_ALLOCATOR_PERF_API_H
#define CRABC_LOCAL_AARCH64_ALLOCATOR_PERF_API_H

#include <stddef.h>

int crabc_local_allocator_perf_init(void);
int crabc_local_allocator_perf_shutdown(void);
void *crabc_local_allocator_perf_malloc(size_t size);
void crabc_local_allocator_perf_free(void *block);

#endif
