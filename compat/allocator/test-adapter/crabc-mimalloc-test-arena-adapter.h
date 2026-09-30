/*
 * SPDX-License-Identifier: MIT
 *
 * Test-only arena diagnostics for a selected private allocator context.
 * Allocation fixtures include the allocation adapter header directly; arena
 * fixtures explicitly opt into these callback and traversal obligations.
 */
#ifndef CRABC_MIMALLOC_TEST_ARENA_ADAPTER_H
#define CRABC_MIMALLOC_TEST_ARENA_ADAPTER_H

#include "crabc-mimalloc-test-adapter.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Creating-thread, serialized output pair. The callback and argument remain
 * live until replacement or completed shutdown; message fragments may not be
 * retained after delivery. Callbacks may allocate/free, but must not replace
 * the pair, shut down the context, or unwind during a diagnostic traversal.
 * Inactive and foreign-thread diagnostic calls produce no output. */
void crabc_test_register_output(void (*output)(const char *, void *), void *argument);
void crabc_test_debug_show_arenas(void);
void crabc_test_arenas_print(void);

#ifdef __cplusplus
}
#endif

#endif
