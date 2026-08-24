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
