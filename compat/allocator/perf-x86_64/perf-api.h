/*
 * SPDX-License-Identifier: MIT
 *
 * Private backend-neutral boundary for the native x86-64 allocator evidence
 * fixture.  It is compiled only into disposable benchmark executables.  It
 * is neither a public mimalloc header nor a crabc libc ABI.
 */
#ifndef CRABC_ALLOCATOR_PERF_X86_64_API_H
#define CRABC_ALLOCATOR_PERF_X86_64_API_H

#include <stddef.h>

int crabc_allocator_perf_init(void);
int crabc_allocator_perf_shutdown(void);
void *crabc_allocator_perf_malloc(size_t size);
void crabc_allocator_perf_free(void *block);

#endif
