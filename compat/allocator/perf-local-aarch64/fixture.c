/* SPDX-License-Identifier: MIT */
/*
 * Shared one-thread allocation/free workload for both local AArch64 lanes.
 * One monotonic timestamp pair surrounds each batch.  The fixture never
 * prints pointers, so the report compares timing at an opaque equivalent
 * boundary rather than allocator-specific representation details.
 */
#define _POSIX_C_SOURCE 200809L

#include "perf-api.h"

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

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

static void touch_block(void *block, size_t size, unsigned char value)
{
  volatile unsigned char *bytes = (volatile unsigned char *)block;
  bytes[0] = value;
  bytes[size - 1] = (unsigned char)(value ^ 0x5aU);
  crabc_local_allocator_perf_sink += (uint64_t)bytes[0] + (uint64_t)bytes[size - 1];
}

int main(int argc, char **argv)
{
  size_t request;
  size_t batches;
  size_t iterations;
  size_t batch;

  if (argc != 4 || parse_positive_size(argv[1], &request) != 0
      || parse_positive_size(argv[2], &batches) != 0
      || parse_positive_size(argv[3], &iterations) != 0) {
    fail("usage: fixture <request-bytes> <batches> <iterations>");
    return 64;
  }
  if (crabc_local_allocator_perf_init() != 0) {
    fail("opaque allocator benchmark init failed");
    return 2;
  }
  for (batch = 0; batch < batches; batch++) {
    struct timespec before;
    struct timespec after;
    size_t iteration;

    if (clock_gettime(CLOCK_MONOTONIC, &before) != 0) {
      fail("clock_gettime before batch failed");
      return 3;
    }
    for (iteration = 0; iteration < iterations; iteration++) {
      void *block = crabc_local_allocator_perf_malloc(request);
      if (block == NULL) {
        fail("opaque allocator benchmark allocation failed");
        return 4;
      }
      touch_block(block, request, (unsigned char)(batch + iteration));
      crabc_local_allocator_perf_free(block);
    }
    if (clock_gettime(CLOCK_MONOTONIC, &after) != 0) {
      fail("clock_gettime after batch failed");
      return 5;
    }
    printf("batch_ns=%" PRIu64 "\n", elapsed_ns(&before, &after));
  }
  if (crabc_local_allocator_perf_shutdown() != 0) {
    fail("opaque allocator benchmark shutdown failed");
    return 6;
  }
  puts("ok");
  return fflush(stdout) == 0 ? 0 : 7;
}
