#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "x86_64_workload_protocol.h"

#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static unsigned char
allocation_byte(unsigned long generation, size_t slot, size_t offset)
{
    return (unsigned char)((generation * 29UL + (unsigned long)slot * 17UL +
        (unsigned long)offset * 13UL) & 0xffUL);
}

static void
fill_allocation(unsigned char *allocation, size_t bytes, unsigned long generation,
    size_t slot)
{
    volatile unsigned char *volatile bytes_view = allocation;
    size_t offset;

    for (offset = 0; offset < bytes; offset++)
        bytes_view[offset] = allocation_byte(generation, slot, offset);
}

static int
verify_allocation(const unsigned char *allocation, size_t bytes,
    unsigned long generation, size_t slot)
{
    const volatile unsigned char *volatile bytes_view = allocation;
    size_t offset;

    for (offset = 0; offset < bytes; offset++) {
        if (bytes_view[offset] != allocation_byte(generation, slot, offset))
            return 0;
    }
    return 1;
}

static void
free_allocations(unsigned char **allocations, size_t count)
{
    size_t slot;

    if (!allocations)
        return;
    for (slot = 0; slot < count; slot++)
        free(allocations[slot]);
    free(allocations);
}

static int
clock_id_is_supplemental(unsigned long clock_id)
{
    switch (clock_id) {
    case 0:
    case 2:
    case 3:
    case 4:
    case 5:
    case 6:
    case 7:
    case 8:
    case 9:
    case 11:
        return 1;
    default:
        return 0;
    }
}

static int
run_clock(unsigned long iterations, unsigned long raw_clock_id,
    const struct crabc_perf_observer *observer)
{
    unsigned long index;
    struct timespec value;

    if (!clock_id_is_supplemental(raw_clock_id))
        return 0;
    for (index = 0; index < iterations; index++) {
        if (clock_gettime((clockid_t)raw_clock_id, &value) != 0 ||
            value.tv_nsec < 0 || value.tv_nsec >= 1000000000L)
            return 0;
        crabc_perf_consume_uintptr((uintptr_t)value.tv_sec ^
            ((uintptr_t)value.tv_nsec << 1));
    }
    return crabc_perf_observer_reach(observer);
}

static int
run_live(unsigned long epochs, size_t allocation_count, size_t allocation_bytes,
    const struct crabc_perf_observer *observer)
{
    unsigned long epoch;

    if (allocation_count > SIZE_MAX / sizeof(unsigned char *))
        return 0;
    for (epoch = 0; epoch < epochs; epoch++) {
        unsigned char **allocations;
        size_t slot;
        int valid = 1;

        allocations = calloc(allocation_count, sizeof *allocations);
        if (!allocations)
            return 0;
        for (slot = 0; slot < allocation_count; slot++) {
            allocations[slot] = malloc(allocation_bytes);
            if (!allocations[slot]) {
                valid = 0;
                break;
            }
            fill_allocation(allocations[slot], allocation_bytes, epoch, slot);
        }
        for (slot = 0; valid && slot < allocation_count; slot++) {
            if (!verify_allocation(allocations[slot], allocation_bytes, epoch, slot))
                valid = 0;
        }
        /*
         * The final verified live set is the declared observer plateau. Earlier
         * epochs keep their ordinary allocate/verify/free lifecycle.
         */
        if (valid && epoch + 1 == epochs &&
            !crabc_perf_observer_reach(observer))
            valid = 0;
        free_allocations(allocations, allocation_count);
        if (!valid)
            return 0;
    }
    return 1;
}

static int
run_refill(unsigned long rounds, size_t allocation_count, size_t allocation_bytes,
    size_t refill_count, const struct crabc_perf_observer *observer)
{
    unsigned char **allocations = NULL;
    size_t slot;
    unsigned long round;
    int valid = 1;

    if (allocation_count == 0 || allocation_count > SIZE_MAX / sizeof *allocations ||
        refill_count == 0 || refill_count > SIZE_MAX / 2 ||
        allocation_count != refill_count * 2)
        return 0;
    allocations = calloc(allocation_count, sizeof *allocations);
    if (!allocations)
        return 0;
    for (slot = 0; slot < allocation_count; slot++) {
        allocations[slot] = malloc(allocation_bytes);
        if (!allocations[slot]) {
            valid = 0;
            goto done;
        }
        fill_allocation(allocations[slot], allocation_bytes, 0, slot);
    }

    for (round = 0; valid && round < rounds; round++) {
        for (slot = 0; slot < allocation_count; slot += 2) {
            free(allocations[slot]);
            allocations[slot] = malloc(allocation_bytes);
            if (!allocations[slot]) {
                valid = 0;
                break;
            }
            fill_allocation(allocations[slot], allocation_bytes, round + 1, slot);
        }
        for (slot = 1; valid && slot < allocation_count; slot += 2) {
            if (!verify_allocation(allocations[slot], allocation_bytes, 0, slot))
                valid = 0;
        }
    }
    for (slot = 0; valid && slot < allocation_count; slot++) {
        unsigned long generation = (slot & 1) ? 0 : rounds;

        if (!verify_allocation(allocations[slot], allocation_bytes, generation, slot))
            valid = 0;
    }
    if (valid && !crabc_perf_observer_reach(observer))
        valid = 0;

done:
    free_allocations(allocations, allocation_count);
    return valid;
}

struct worker_job {
    unsigned long epochs;
    size_t lifetimes;
    size_t allocation_bytes;
    size_t worker_index;
    int completed;
};

static void *
run_worker_lifetimes(void *argument)
{
    struct worker_job *job = argument;
    unsigned long epoch;

    for (epoch = 0; epoch < job->epochs; epoch++) {
        size_t lifetime;

        for (lifetime = 0; lifetime < job->lifetimes; lifetime++) {
            unsigned char *allocation = malloc(job->allocation_bytes);
            size_t slot = job->worker_index * job->lifetimes + lifetime;
            unsigned long generation = epoch + job->worker_index * 37UL;

            if (!allocation)
                return NULL;
            fill_allocation(allocation, job->allocation_bytes, generation, slot);
            if (!verify_allocation(allocation, job->allocation_bytes, generation, slot)) {
                free(allocation);
                return NULL;
            }
            free(allocation);
        }
    }
    job->completed = 1;
    return NULL;
}

static int
run_worker(unsigned long epochs, size_t workers, size_t lifetimes,
    size_t allocation_bytes, const struct crabc_perf_observer *observer)
{
    pthread_t *threads = NULL;
    struct worker_job *jobs = NULL;
    size_t worker;
    size_t created = 0;
    int valid = 1;

    if (workers == 0 || workers > SIZE_MAX / sizeof *threads ||
        workers > SIZE_MAX / sizeof *jobs)
        return 0;
    threads = calloc(workers, sizeof *threads);
    jobs = calloc(workers, sizeof *jobs);
    if (!threads || !jobs) {
        valid = 0;
        goto done;
    }
    for (worker = 0; worker < workers; worker++) {
        jobs[worker].epochs = epochs;
        jobs[worker].lifetimes = lifetimes;
        jobs[worker].allocation_bytes = allocation_bytes;
        jobs[worker].worker_index = worker;
        if (pthread_create(&threads[worker], NULL, run_worker_lifetimes,
                &jobs[worker]) != 0) {
            valid = 0;
            break;
        }
        created++;
    }
    for (worker = 0; worker < created; worker++) {
        if (pthread_join(threads[worker], NULL) != 0)
            valid = 0;
    }
    if (created != workers)
        valid = 0;
    for (worker = 0; valid && worker < workers; worker++) {
        if (!jobs[worker].completed)
            valid = 0;
    }
    if (valid && !crabc_perf_observer_reach(observer))
        valid = 0;

done:
    free(jobs);
    free(threads);
    return valid;
}

static int
parse_size(const char *text, size_t *result)
{
    unsigned long parsed;

    if (!crabc_perf_parse_positive(text, &parsed) || parsed > SIZE_MAX)
        return 0;
    *result = (size_t)parsed;
    return 1;
}

int
main(int argc, char **argv)
{
    const char *mode;
    unsigned long iterations;
    struct crabc_perf_observer observer;
    int passed = 0;

    if (!crabc_perf_observer_from_environment(&observer))
        return 2;
    if (argc < 3 || !crabc_perf_parse_positive(argv[2], &iterations))
        return 2;
    mode = argv[1];
    if (strcmp(mode, "clock_gettime") == 0) {
        unsigned long clock_id;

        if (argc != 4 || !crabc_perf_parse_unsigned(argv[3], &clock_id))
            return 2;
        passed = run_clock(iterations, clock_id, &observer);
    } else if (strcmp(mode, "live") == 0) {
        size_t allocation_count;
        size_t allocation_bytes;

        if (argc != 5 || !parse_size(argv[3], &allocation_count) ||
            !parse_size(argv[4], &allocation_bytes))
            return 2;
        passed = run_live(iterations, allocation_count, allocation_bytes, &observer);
    } else if (strcmp(mode, "refill") == 0) {
        size_t allocation_count;
        size_t allocation_bytes;
        size_t refill_count;

        if (argc != 6 || !parse_size(argv[3], &allocation_count) ||
            !parse_size(argv[4], &allocation_bytes) ||
            !parse_size(argv[5], &refill_count))
            return 2;
        passed = run_refill(iterations, allocation_count, allocation_bytes,
            refill_count, &observer);
    } else if (strcmp(mode, "worker") == 0) {
        size_t workers;
        size_t lifetimes;
        size_t allocation_bytes;

        if (argc != 6 || !parse_size(argv[3], &workers) ||
            !parse_size(argv[4], &lifetimes) ||
            !parse_size(argv[5], &allocation_bytes))
            return 2;
        passed = run_worker(iterations, workers, lifetimes, allocation_bytes,
            &observer);
    } else {
        return 2;
    }
    if (!passed)
        return 1;
    puts("ok");
    return 0;
}
