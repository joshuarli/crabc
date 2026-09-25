/*
 * SPDX-License-Identifier: MIT
 *
 * The engine fixture's opaque backend over the installed product's public
 * C allocator: every operation is the libc entry point an ordinary program
 * calls.  Which allocator answers (the accepted C backend or the native
 * Rust shadow) is decided only by the installed product the program links.
 */
#define _GNU_SOURCE

#include "engine-api.h"

#include <malloc.h>
#include <stdlib.h>

int crabc_allocator_engine_process_init(void) { return 0; }
int crabc_allocator_engine_thread_init(void) { return 0; }
int crabc_allocator_engine_thread_done(void) { return 0; }
void *crabc_allocator_engine_malloc(size_t size) { return malloc(size); }
void crabc_allocator_engine_free(void *block) { free(block); }
void *crabc_allocator_engine_calloc(size_t count, size_t size) { return calloc(count, size); }
void *crabc_allocator_engine_realloc(void *block, size_t size) { return realloc(block, size); }
void *crabc_allocator_engine_aligned(size_t alignment, size_t size) { return aligned_alloc(alignment, size); }
size_t crabc_allocator_engine_usable_size(const void *block) { return malloc_usable_size((void *)block); }
