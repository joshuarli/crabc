/* Source-local observer for the frozen startup-linked DSO graph fixture. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>

#include "x86_64_memory_observer_protocol.h"

#define main crabc_perf_memory_original_graph_main
#include "fixtures/startup_graph.c"
#undef main

int
main(int argc, char **argv)
{
    int begun = crabc_perf_memory_begin_startup();
    int status;

    (void)argc;
    (void)argv;
    if (begun == -1)
        return 2;
    if (begun == -2)
        return 1;
    status = crabc_perf_memory_original_graph_main();
    return crabc_perf_memory_finish(status);
}
