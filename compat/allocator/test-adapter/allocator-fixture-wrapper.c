/*
 * SPDX-License-Identifier: MIT
 *
 * Checked-in lifecycle wrapper for `tests/fixtures/allocator_test.c` against
 * the Rust mimalloc evidence adapter. The runner compiles this file directly;
 * it must not generate an equivalent C wrapper at runtime.
 *
 * The header's source-only remap is deliberately enabled only here. It sends
 * the fixture's standard allocation calls to prefixed `crabc_test_*` symbols
 * without adding normal malloc/free or mi_* definitions to the linked image.
 */
#define CRABC_TEST_ADAPTER_REMAP_STDLIB 1
#include "crabc-mimalloc-test-adapter.h"

/*
 * This wrapper is compiled as C11 against the pinned native musl profile.
 * Its `size_t` declarations cross directly into Rust `usize` parameters,
 * while its stdlib remap promises `max_align_t` alignment. Fail at compile
 * time if a foreign C ABI would make either adapter assumption false.
 */
_Static_assert(sizeof(size_t) == 8,
               "crabc mimalloc test adapter requires a 64-bit size_t C ABI");
_Static_assert(sizeof(void *) == sizeof(size_t),
               "crabc mimalloc test adapter requires matching C pointer and size_t widths");
_Static_assert(_Alignof(max_align_t) == CRABC_TEST_LIBC_MALLOC_ALIGNMENT,
               "pinned Linux musl max_align_t must match the adapter fixture alignment");

/* Keep the fixture's normal main body intact while giving this wrapper the
 * process entry point that brackets every allocator operation with lifecycle.
 */
#define main crabc_test_allocator_fixture_main
#include "../../../tests/fixtures/allocator_test.c"
#undef main

int main(void)
{
    int fixture_status;
    int shutdown_status;

    if (crabc_test_init() != 0)
        return 1;

    fixture_status = crabc_test_allocator_fixture_main();
    shutdown_status = crabc_test_shutdown();

    /* A fixture failure remains a failure, and teardown failure is never
     * discarded after an otherwise successful body. */
    return (fixture_status == 0 && shutdown_status == 0) ? 0 : 1;
}
