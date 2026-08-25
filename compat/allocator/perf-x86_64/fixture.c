/*
 * SPDX-License-Identifier: MIT
 *
 * One source-shared workload for the native x86-64 private-adapter C/Rust
 * performance evidence lane.  Timer reads surround whole batches, never an
 * individual allocation.  The memory mode has two explicit parent-controlled
 * barriers: after context initialization and while a fixed live set remains
 * touched.  That lets the runner report a post-init memory delta instead of
 * presenting the Rust test context's eager external arena as allocator parity.
 */
#define _POSIX_C_SOURCE 200809L

#include "perf-api.h"

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

enum { CRABC_ALLOCATOR_PERF_MAX_LIVE_BLOCKS = 4096 };

static volatile uint64_t crabc_allocator_perf_sink;

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

static int parse_fd(const char *text, int *out)
{
  size_t value;
  if (parse_positive_size(text, &value) != 0 || value > INT_MAX) return -1;
  *out = (int)value;
  return 0;
}

static uint64_t elapsed_ns(const struct timespec *before, const struct timespec *after)
{
  const uint64_t seconds = (uint64_t)(after->tv_sec - before->tv_sec);
  const int64_t nanoseconds = (int64_t)after->tv_nsec - (int64_t)before->tv_nsec;
  if (nanoseconds >= 0) return seconds * UINT64_C(1000000000) + (uint64_t)nanoseconds;
  return (seconds - 1) * UINT64_C(1000000000) + (uint64_t)(nanoseconds + 1000000000);
}

static void touch_block(void *block, size_t size, unsigned char value)
{
  volatile unsigned char *bytes = (volatile unsigned char *)block;
  bytes[0] = value;
  bytes[size - 1] = (unsigned char)(value ^ 0x5aU);
  crabc_allocator_perf_sink += (uint64_t)bytes[0] + (uint64_t)bytes[size - 1];
}

static int write_exact(int descriptor, const char *text)
{
  size_t remaining = strlen(text);
  const char *cursor = text;
  while (remaining != 0) {
    const ssize_t wrote = write(descriptor, cursor, remaining);
    if (wrote < 0 && errno == EINTR) continue;
    if (wrote <= 0) return -1;
    cursor += wrote;
    remaining -= (size_t)wrote;
  }
  return 0;
}

static int wait_for_parent(int descriptor)
{
  unsigned char byte;
  for (;;) {
    const ssize_t read_count = read(descriptor, &byte, 1);
    if (read_count < 0 && errno == EINTR) continue;
    return read_count == 1 ? 0 : -1;
  }
}

static int run_batch(size_t request, size_t batches, size_t iterations)
{
  size_t batch;

  if (crabc_allocator_perf_init() != 0) {
    fail("private allocator benchmark init failed");
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
      void *block = crabc_allocator_perf_malloc(request);
      if (block == NULL) {
        fail("private allocator benchmark allocation failed");
        return 4;
      }
      touch_block(block, request, (unsigned char)(batch + iteration));
      crabc_allocator_perf_free(block);
    }
    if (clock_gettime(CLOCK_MONOTONIC, &after) != 0) {
      fail("clock_gettime after batch failed");
      return 5;
    }
    printf("batch_ns=%" PRIu64 "\n", elapsed_ns(&before, &after));
  }
  if (crabc_allocator_perf_shutdown() != 0) {
    fail("private allocator benchmark shutdown failed");
    return 6;
  }
  puts("ok");
  return fflush(stdout) == 0 ? 0 : 7;
}

static int run_memory(size_t live_bytes, size_t block_size, int ready_fd, int control_fd)
{
  void *blocks[CRABC_ALLOCATOR_PERF_MAX_LIVE_BLOCKS];
  size_t block_count;
  size_t index;

  if (live_bytes % block_size != 0) {
    fail("live memory bytes must divide by block size");
    return 2;
  }
  block_count = live_bytes / block_size;
  if (block_count == 0 || block_count > CRABC_ALLOCATOR_PERF_MAX_LIVE_BLOCKS) {
    fail("live memory block count is outside fixture contract");
    return 3;
  }
  if (crabc_allocator_perf_init() != 0) {
    fail("private allocator memory init failed");
    return 4;
  }
  if (write_exact(ready_fd, "READY_INIT\n") != 0 || wait_for_parent(control_fd) != 0) {
    fail("memory fixture initialization barrier failed");
    return 5;
  }
  for (index = 0; index < block_count; index++) {
    blocks[index] = crabc_allocator_perf_malloc(block_size);
    if (blocks[index] == NULL) {
      fail("private allocator memory allocation failed");
      return 6;
    }
    memset(blocks[index], (int)(index & 0xffU), block_size);
    touch_block(blocks[index], block_size, (unsigned char)index);
  }
  if (write_exact(ready_fd, "READY_LIVE\n") != 0 || wait_for_parent(control_fd) != 0) {
    fail("memory fixture live barrier failed");
    return 7;
  }
  while (block_count != 0) {
    block_count--;
    crabc_allocator_perf_free(blocks[block_count]);
  }
  if (crabc_allocator_perf_shutdown() != 0) {
    fail("private allocator memory shutdown failed");
    return 8;
  }
  puts("ok");
  return fflush(stdout) == 0 ? 0 : 9;
}

int main(int argc, char **argv)
{
  if (argc >= 2 && strcmp(argv[1], "batch") == 0) {
    size_t request;
    size_t batches;
    size_t iterations;
    if (argc != 5 || parse_positive_size(argv[2], &request) != 0
        || parse_positive_size(argv[3], &batches) != 0
        || parse_positive_size(argv[4], &iterations) != 0) {
      fail("usage: fixture batch <request-bytes> <batches> <iterations>");
      return 64;
    }
    return run_batch(request, batches, iterations);
  }
  if (argc >= 2 && strcmp(argv[1], "memory") == 0) {
    size_t live_bytes;
    size_t block_size;
    int ready_fd;
    int control_fd;
    if (argc != 6 || parse_positive_size(argv[2], &live_bytes) != 0
        || parse_positive_size(argv[3], &block_size) != 0
        || parse_fd(argv[4], &ready_fd) != 0 || parse_fd(argv[5], &control_fd) != 0) {
      fail("usage: fixture memory <live-bytes> <block-bytes> <ready-fd> <control-fd>");
      return 64;
    }
    return run_memory(live_bytes, block_size, ready_fd, control_fd);
  }
  fail("usage: fixture batch|memory ...");
  return 64;
}
