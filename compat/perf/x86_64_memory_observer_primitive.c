/* Separate memory-only artifact for the supplemental primitive fixture. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "x86_64_workload_protocol.h"
#include "x86_64_supplemental_memory_observer.h"

#define main crabc_perf_supplemental_original_primitive_main
#define crabc_perf_observer_reach crabc_perf_supplemental_memory_reach
#include "x86_64_primitive_boundary_workload.c"
#undef crabc_perf_observer_reach
#undef main

int
main(int argc, char **argv)
{
    int begun = crabc_perf_supplemental_memory_begin();

    if (begun == -1)
        return 2;
    if (begun == -2)
        return 1;
    return crabc_perf_supplemental_memory_finish(
        crabc_perf_supplemental_original_primitive_main(argc, argv));
}
