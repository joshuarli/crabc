/* SPDX-License-Identifier: MIT */
/*
 * Shared local allocation/free workload for both AArch64 performance lanes.
 * Each process starts 1, 2, 4, or 8 ordinary pthread workers. A worker owns
 * every allocation it makes, and no allocation address crosses a worker or
 * enters a fixture-owned route table. Three barriers establish each batch's
 * common ready/start/finish interval; the only timestamp pair surrounds that
 * interval, never an individual allocation. Every worker returns normally
 * and main joins it before the opaque backend shuts down.
 */
#define _POSIX_C_SOURCE 200809L

#include "perf-api.h"

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct local_worker_context {
  pthread_barrier_t *ready;
  pthread_barrier_t *start;
  pthread_barrier_t *finish;
  size_t request;
  size_t batches;
  size_t iterations;
  unsigned int worker_index;
  int failure;
  volatile uint64_t sink;
};

static volatile uint64_t crabc_local_allocator_perf_sink;

static void fail(const char *message)
{
  fputs(message, stderr);
  fputc('\n', stderr);
}

static int parse_positive_size(const char *text, size_t *out)
{
  char *end = NULL;
  unsigned long long value;

  if (text == NULL || text[0] == '\0') return -1;
  errno = 0;
  value = strtoull(text, &end, 10);
  if (errno != 0 || end == text || *end != '\0' || value == 0 || value > SIZE_MAX) return -1;
  *out = (size_t)value;
  return 0;
}

static uint64_t elapsed_ns(const struct timespec *before, const struct timespec *after)
{
  const uint64_t seconds = (uint64_t)(after->tv_sec - before->tv_sec);
  const int64_t nanoseconds = (int64_t)after->tv_nsec - before->tv_nsec;
  if (nanoseconds >= 0) return seconds * UINT64_C(1000000000) + (uint64_t)nanoseconds;
  return (seconds - 1) * UINT64_C(1000000000) + (uint64_t)(nanoseconds + 1000000000);
}

static int wait_at_batch_barrier(pthread_barrier_t *barrier)
{
  int result = pthread_barrier_wait(barrier);
  return result == 0 || result == PTHREAD_BARRIER_SERIAL_THREAD ? 0 : result;
}

static void touch_block(void *block, size_t size, unsigned char value,
    volatile uint64_t *sink)
{
  volatile unsigned char *bytes = (volatile unsigned char *)block;
  bytes[0] = value;
  bytes[size - 1] = (unsigned char)(value ^ 0x5aU);
  *sink += (uint64_t)bytes[0] + (uint64_t)bytes[size - 1];
}

static int run_local_batch(struct local_worker_context *context, size_t batch)
{
  size_t iteration;

  for (iteration = 0; iteration < context->iterations; iteration++) {
    void *block = crabc_local_allocator_perf_malloc(context->request);
    if (block == NULL)
      return 1;
    touch_block(block, context->request,
        (unsigned char)(context->worker_index + batch + iteration),
        &context->sink);
    crabc_local_allocator_perf_free(block);
  }
  return 0;
}

static void *local_worker(void *opaque)
{
  struct local_worker_context *context = opaque;
  size_t batch;

  for (batch = 0; batch < context->batches; batch++) {
    if (wait_at_batch_barrier(context->ready) != 0)
      return (void *)(uintptr_t)1;
    if (wait_at_batch_barrier(context->start) != 0)
      return (void *)(uintptr_t)2;
    if (context->failure == 0) {
      int failure = run_local_batch(context, batch);
      if (failure != 0)
        context->failure = failure;
    }
    if (wait_at_batch_barrier(context->finish) != 0)
      return (void *)(uintptr_t)3;
  }
  return NULL;
}

static int run_attestation(const char *expected_identity, const char *expected_free_route)
{
  const char *identity = crabc_local_allocator_perf_backend_identity();
  const char *free_route = crabc_local_allocator_perf_free_route();

  if (strcmp(identity, expected_identity) != 0 || strcmp(free_route, expected_free_route) != 0) {
    fail("opaque allocator fixture selected an unexpected backend or free route");
    return 2;
  }
  printf("backend_identity=%s\n", identity);
  printf("free_route=%s\n", free_route);
  puts("ok");
  return fflush(stdout) == 0 ? 0 : 3;
}

int main(int argc, char **argv)
{
  size_t request;
  size_t worker_count;
  size_t batches;
  size_t iterations;
  struct local_worker_context contexts[8];
  pthread_t workers[8];
  pthread_barrier_t ready;
  pthread_barrier_t start;
  pthread_barrier_t finish;
  size_t worker;
  size_t batch;
  int failed = 0;

  if (argc == 4 && strcmp(argv[1], "attest") == 0)
    return run_attestation(argv[2], argv[3]);
  if (argc != 5 || parse_positive_size(argv[1], &request) != 0
      || parse_positive_size(argv[2], &worker_count) != 0
      || parse_positive_size(argv[3], &batches) != 0
      || parse_positive_size(argv[4], &iterations) != 0
      || worker_count > sizeof(workers) / sizeof(workers[0])) {
    fail("usage: fixture attest <backend-identity> <free-route>|<request-bytes> <workers> <batches> <iterations>");
    return 64;
  }
  if (crabc_local_allocator_perf_init() != 0) {
    fail("opaque allocator benchmark init failed");
    return 2;
  }
  if (pthread_barrier_init(&ready, NULL, (unsigned int)(worker_count + 1)) != 0
      || pthread_barrier_init(&start, NULL, (unsigned int)(worker_count + 1)) != 0
      || pthread_barrier_init(&finish, NULL, (unsigned int)(worker_count + 1)) != 0) {
    fail("local worker batch barrier initialization failed");
    return 3;
  }
  for (worker = 0; worker < worker_count; worker++) {
    contexts[worker] = (struct local_worker_context){
      .ready = &ready,
      .start = &start,
      .finish = &finish,
      .request = request,
      .batches = batches,
      .iterations = iterations,
      .worker_index = (unsigned int)worker,
      .failure = 0,
      .sink = 0,
    };
    if (pthread_create(&workers[worker], NULL, local_worker, &contexts[worker]) != 0) {
      fail("local worker creation failed");
      return 4;
    }
  }
  for (batch = 0; batch < batches; batch++) {
    struct timespec before;
    struct timespec after;

    if (wait_at_batch_barrier(&ready) != 0
        || clock_gettime(CLOCK_MONOTONIC, &before) != 0
        || wait_at_batch_barrier(&start) != 0
        || wait_at_batch_barrier(&finish) != 0
        || clock_gettime(CLOCK_MONOTONIC, &after) != 0) {
      failed = 5;
      break;
    }
    printf("batch_ns=%" PRIu64 "\n", elapsed_ns(&before, &after));
  }
  for (worker = 0; worker < worker_count; worker++) {
    void *result = (void *)(uintptr_t)1;

    if (pthread_join(workers[worker], &result) != 0 || result != NULL)
      failed = 6;
    if (contexts[worker].failure != 0)
      failed = 7;
    crabc_local_allocator_perf_sink += contexts[worker].sink;
  }
  if (pthread_barrier_destroy(&finish) != 0
      || pthread_barrier_destroy(&start) != 0
      || pthread_barrier_destroy(&ready) != 0)
    failed = 8;
  if (crabc_local_allocator_perf_shutdown() != 0)
    failed = 9;
  if (failed != 0) {
    fail("local worker allocation/free batch failed");
    return failed;
  }
  puts("ok");
  return fflush(stdout) == 0 ? 0 : 10;
}
