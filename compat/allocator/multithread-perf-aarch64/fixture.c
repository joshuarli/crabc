/*
 * SPDX-License-Identifier: MIT
 *
 * Local allocation/free scaling fixture for the pinned mimalloc C oracle.
 *
 * The runner supplies a distinct allowed CPU to every worker. Each worker
 * times only its own steady-state mi_malloc(64)/touch/mi_free loop after a
 * two-stage start barrier. The reported elapsed time is the slowest worker,
 * so aggregate throughput is the total completed operations divided by the
 * concurrent work interval rather than the sum of worker CPU time.
 */

#define _GNU_SOURCE 1

#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <mimalloc.h>

enum { ALLOCATION_BYTES = 64, MAX_WORKERS = 8 };

struct worker {
  pthread_barrier_t *barrier;
  int cpu;
  unsigned long long iterations;
  unsigned long long elapsed_ns;
  unsigned long long checksum;
  int failure;
};

static int parse_positive(const char *text, unsigned long long *result)
{
  char *end = NULL;
  unsigned long long value;

  if (text == NULL || *text == '\0') return -1;
  errno = 0;
  value = strtoull(text, &end, 10);
  if (errno != 0 || end == text || *end != '\0' || value == 0) return -1;
  *result = value;
  return 0;
}

static int parse_cpus(const char *text, int *cpus, unsigned long long workers)
{
  const char *cursor = text;
  unsigned long long index = 0;

  while (cursor != NULL && *cursor != '\0' && index < workers) {
    char *end = NULL;
    long value;

    errno = 0;
    value = strtol(cursor, &end, 10);
    if (errno != 0 || end == cursor || value < 0 || value > INT_MAX) return -1;
    cpus[index++] = (int)value;
    if (*end == '\0') {
      cursor = end;
      break;
    }
    if (*end != ',') return -1;
    cursor = end + 1;
  }
  return index == workers && cursor != NULL && *cursor == '\0' ? 0 : -1;
}

static unsigned long long monotonic_ns(void)
{
  struct timespec value;

  if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) return 0;
  return (unsigned long long)value.tv_sec * 1000000000ULL + (unsigned long long)value.tv_nsec;
}

static void *run_worker(void *opaque)
{
  struct worker *worker = opaque;
  cpu_set_t set;
  unsigned long long start;
  unsigned long long finish;
  unsigned long long iteration;
  unsigned long long checksum = 0;

  CPU_ZERO(&set);
  CPU_SET(worker->cpu, &set);
  if (pthread_setaffinity_np(pthread_self(), sizeof(set), &set) != 0) worker->failure = 1;

  (void)pthread_barrier_wait(worker->barrier);
  (void)pthread_barrier_wait(worker->barrier);
  if (worker->failure != 0) return NULL;

  start = monotonic_ns();
  if (start == 0) {
    worker->failure = 2;
    return NULL;
  }
  for (iteration = 0; iteration < worker->iterations; ++iteration) {
    unsigned char *block = mi_malloc(ALLOCATION_BYTES);
    if (block == NULL) {
      worker->failure = 3;
      return NULL;
    }
    block[0] = (unsigned char)iteration;
    block[ALLOCATION_BYTES - 1] = (unsigned char)(iteration >> 8);
    checksum += block[0];
    checksum += block[ALLOCATION_BYTES - 1];
    mi_free(block);
  }
  finish = monotonic_ns();
  if (finish <= start) {
    worker->failure = 4;
    return NULL;
  }
  worker->checksum = checksum;
  worker->elapsed_ns = finish - start;
  return NULL;
}

int main(int argc, char **argv)
{
  unsigned long long workers;
  unsigned long long iterations;
  int cpus[MAX_WORKERS];
  struct worker state[MAX_WORKERS];
  pthread_t threads[MAX_WORKERS];
  pthread_barrier_t barrier;
  unsigned long long maximum_ns = 0;
  unsigned long long sum_ns = 0;
  unsigned long long checksum = 0;
  unsigned long long index;

  if (argc != 7 || strcmp(argv[1], "--workers") != 0 || strcmp(argv[3], "--iterations") != 0 ||
      strcmp(argv[5], "--cpus") != 0 || parse_positive(argv[2], &workers) != 0 ||
      parse_positive(argv[4], &iterations) != 0 || workers > MAX_WORKERS ||
      parse_cpus(argv[6], cpus, workers) != 0) {
    return 64;
  }
  if (pthread_barrier_init(&barrier, NULL, (unsigned int)(workers + 1)) != 0) return 65;

  for (index = 0; index < workers; ++index) {
    state[index] = (struct worker){
        .barrier = &barrier,
        .cpu = cpus[index],
        .iterations = iterations,
        .elapsed_ns = 0,
        .checksum = 0,
        .failure = 0,
    };
    if (pthread_create(&threads[index], NULL, run_worker, &state[index]) != 0) return 66;
  }

  (void)pthread_barrier_wait(&barrier);
  (void)pthread_barrier_wait(&barrier);
  for (index = 0; index < workers; ++index) {
    if (pthread_join(threads[index], NULL) != 0 || state[index].failure != 0) return 67;
    if (state[index].elapsed_ns > maximum_ns) maximum_ns = state[index].elapsed_ns;
    sum_ns += state[index].elapsed_ns;
    checksum += state[index].checksum;
  }
  if (maximum_ns == 0) return 68;

  printf("workers=%llu\n", workers);
  printf("iterations=%llu\n", iterations);
  printf("operations=%llu\n", workers * iterations);
  printf("max_worker_ns=%llu\n", maximum_ns);
  printf("sum_worker_ns=%llu\n", sum_ns);
  printf("checksum=%llu\n", checksum);
  printf("affinity=%s\n", argv[6]);
  puts("ok");
  return 0;
}
