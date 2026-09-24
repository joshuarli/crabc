/*
 * SPDX-License-Identifier: MIT
 *
 * Source-shared workload fixture for the native x86-64 allocator engine
 * performance matrix.  The same source is compiled once per lane and links
 * one opaque backend (`engine-api.h`); only that backend differs.
 *
 * Invocation:  engine-fixture <workload> key=value...
 *
 * Timed workloads print one record per batch, then `ok`:
 *
 *   batch ns=<wall ns> cpu_ns=<participant thread CPU ns> ops=<allocator calls>
 *
 * One CLOCK_MONOTONIC pair surrounds each batch, never one operation.  Each
 * participating thread also brackets its own batch work with
 * CLOCK_THREAD_CPUTIME_ID; `cpu_ns` sums those intervals.  On a contended
 * host the CPU cost per call stays meaningful where wall time does not: it
 * excludes preemption but still includes shared-cache-line and lock costs.
 *
 * Memory workloads (`memory_*`) instead write READY_INIT / READY_LIVE /
 * READY_FREED to `ready_fd` and wait for one byte on `control_fd` after each,
 * so the parent can snapshot /proc while the process is quiescent.
 *
 * Multi-threaded workloads pin each worker to one listed CPU; the initial
 * thread only coordinates barriers and never allocates during timing.  A
 * multi-threaded batch spans the first participant's own start timestamp to
 * the last participant's own finish timestamp.
 * Workers call the backend's thread_init before, and thread_done after, all
 * of their allocator operations.  No allocation address is ever printed.
 */
#define _GNU_SOURCE

#include "engine-api.h"

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

enum {
  MAX_WORKERS = 64,
  MAX_LIVE_SLOTS = 1 << 16,
  MAX_BATCH_BLOCKS = 1 << 16,
  REMOTE_RING = 1024,
};

static volatile uint64_t sink;

struct params {
  const char *workload;
  size_t batches;
  size_t iterations;
  size_t size;
  size_t max_size;
  size_t alignment;
  size_t count;
  size_t workers;
  size_t live;
  size_t total;
  uint64_t seed;
  int ready_fd;
  int control_fd;
  int cpus[MAX_WORKERS];
  size_t cpu_count;
};

static void fail(const char *message)
{
  fputs(message, stderr);
  fputc('\n', stderr);
}

static _Noreturn void die(const char *message)
{
  fail(message);
  _exit(70);
}

static int parse_u64(const char *text, uint64_t *out)
{
  char *end = NULL;
  unsigned long long value;
  if (text == NULL || text[0] == '\0') return -1;
  errno = 0;
  value = strtoull(text, &end, 0);
  if (errno != 0 || end == text || *end != '\0') return -1;
  *out = (uint64_t)value;
  return 0;
}

static int parse_size(const char *text, size_t *out)
{
  uint64_t value;
  if (parse_u64(text, &value) != 0 || value > SIZE_MAX) return -1;
  *out = (size_t)value;
  return 0;
}

static int parse_cpus(const char *text, struct params *params)
{
  const char *cursor = text;
  params->cpu_count = 0;
  while (*cursor != '\0') {
    char *end = NULL;
    long value;
    errno = 0;
    value = strtol(cursor, &end, 10);
    if (errno != 0 || end == cursor || value < 0 || value >= CPU_SETSIZE) return -1;
    if (params->cpu_count == MAX_WORKERS) return -1;
    params->cpus[params->cpu_count++] = (int)value;
    if (*end == ',') end++;
    else if (*end != '\0') return -1;
    cursor = end;
  }
  return params->cpu_count == 0 ? -1 : 0;
}

static int parse_params(int argc, char **argv, struct params *params)
{
  int index;
  memset(params, 0, sizeof *params);
  params->batches = 1;
  params->iterations = 1;
  params->workers = 1;
  params->alignment = 16;
  params->seed = UINT64_C(0x9e3779b97f4a7c15);
  params->ready_fd = -1;
  params->control_fd = -1;
  if (argc < 2) return -1;
  params->workload = argv[1];
  for (index = 2; index < argc; index++) {
    const char *argument = argv[index];
    const char *value = strchr(argument, '=');
    size_t key_length;
    size_t parsed = 0;
    if (value == NULL) return -1;
    key_length = (size_t)(value - argument);
    value++;
#define KEY(name) (key_length == sizeof(name) - 1 && strncmp(argument, name, key_length) == 0)
    if (KEY("cpus")) {
      if (parse_cpus(value, params) != 0) return -1;
      continue;
    }
    if (KEY("seed")) {
      if (parse_u64(value, &params->seed) != 0) return -1;
      continue;
    }
    if (parse_size(value, &parsed) != 0) return -1;
    if (KEY("batches")) params->batches = parsed;
    else if (KEY("iterations")) params->iterations = parsed;
    else if (KEY("size")) params->size = parsed;
    else if (KEY("max_size")) params->max_size = parsed;
    else if (KEY("alignment")) params->alignment = parsed;
    else if (KEY("count")) params->count = parsed;
    else if (KEY("workers")) params->workers = parsed;
    else if (KEY("live")) params->live = parsed;
    else if (KEY("total")) params->total = parsed;
    else if (KEY("ready_fd") && parsed <= INT_MAX) params->ready_fd = (int)parsed;
    else if (KEY("control_fd") && parsed <= INT_MAX) params->control_fd = (int)parsed;
    else return -1;
#undef KEY
  }
  if (params->batches == 0 || params->iterations == 0 || params->workers == 0
      || params->workers > MAX_WORKERS) {
    return -1;
  }
  return 0;
}

/* ---- timing ------------------------------------------------------------ */

static uint64_t now_ns(void)
{
  struct timespec value;
  if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) die("clock_gettime failed");
  return (uint64_t)value.tv_sec * UINT64_C(1000000000) + (uint64_t)value.tv_nsec;
}

static uint64_t thread_cpu_ns(void)
{
  struct timespec value;
  if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &value) != 0) die("thread CPU clock failed");
  return (uint64_t)value.tv_sec * UINT64_C(1000000000) + (uint64_t)value.tv_nsec;
}

static void print_batch(uint64_t nanoseconds, uint64_t cpu_nanoseconds, uint64_t operations)
{
  printf("batch ns=%" PRIu64 " cpu_ns=%" PRIu64 " ops=%" PRIu64 "\n", nanoseconds, cpu_nanoseconds, operations);
}

/* ---- deterministic inputs ----------------------------------------------- */

static uint64_t next_random(uint64_t *state)
{
  /* xorshift64*: deterministic, allocation-free workload selection. */
  uint64_t value = *state;
  value ^= value >> 12;
  value ^= value << 25;
  value ^= value >> 27;
  *state = value;
  return value * UINT64_C(2685821657736338717);
}

/* Log-uniform request in [8, max_size]: many small, some medium/large. */
static size_t random_request(uint64_t *state, size_t max_size)
{
  unsigned max_shift = 3;
  unsigned shift;
  size_t base;
  while (max_shift < 62 && ((size_t)1 << (max_shift + 1)) <= max_size) max_shift++;
  shift = 3 + (unsigned)(next_random(state) % (uint64_t)(max_shift - 2));
  base = (size_t)1 << shift;
  base += (size_t)(next_random(state) % (uint64_t)base);
  return base > max_size ? max_size : base;
}

static void touch(void *block, size_t size, unsigned value)
{
  volatile unsigned char *bytes = (volatile unsigned char *)block;
  bytes[0] = (unsigned char)value;
  bytes[size - 1] = (unsigned char)(value ^ 0x5aU);
  sink += (uint64_t)bytes[0] + (uint64_t)bytes[size - 1];
}

static void *checked(void *block)
{
  if (block == NULL) die("allocator backend returned null");
  return block;
}

/* ---- per-thread workload bodies ----------------------------------------- */

struct worker;
typedef uint64_t (*batch_body)(struct worker *worker, size_t batch);

struct worker {
  const struct params *params;
  size_t index;
  uint64_t random;
  void **slots;
  size_t *slot_sizes;
};

static uint64_t body_alloc_free(struct worker *worker, size_t batch)
{
  const size_t size = worker->params->size;
  size_t iteration;
  for (iteration = 0; iteration < worker->params->iterations; iteration++) {
    void *block = checked(crabc_allocator_engine_malloc(size));
    touch(block, size, (unsigned)(batch + iteration));
    crabc_allocator_engine_free(block);
  }
  return 2 * (uint64_t)worker->params->iterations;
}

static uint64_t body_alloc_batch(struct worker *worker, size_t batch)
{
  const size_t size = worker->params->size;
  const size_t count = worker->params->count;
  size_t iteration;
  for (iteration = 0; iteration < worker->params->iterations; iteration++) {
    size_t index;
    for (index = 0; index < count; index++) {
      worker->slots[index] = checked(crabc_allocator_engine_malloc(size));
      touch(worker->slots[index], size, (unsigned)(index + batch));
    }
    if (((iteration + batch) & 1U) == 0) {
      while (index != 0) crabc_allocator_engine_free(worker->slots[--index]);
    } else {
      for (index = 0; index < count; index++) crabc_allocator_engine_free(worker->slots[index]);
    }
  }
  return 2 * (uint64_t)count * worker->params->iterations;
}

static uint64_t body_calloc_free(struct worker *worker, size_t batch)
{
  const size_t size = worker->params->size;
  size_t iteration;
  for (iteration = 0; iteration < worker->params->iterations; iteration++) {
    unsigned char *block = checked(crabc_allocator_engine_calloc(1, size));
    if (block[0] != 0 || block[size / 2] != 0 || block[size - 1] != 0) die("calloc returned nonzero memory");
    touch(block, size, (unsigned)(batch + iteration));
    crabc_allocator_engine_free(block);
  }
  return 2 * (uint64_t)worker->params->iterations;
}

static uint64_t body_aligned_free(struct worker *worker, size_t batch)
{
  const size_t size = worker->params->size;
  const size_t alignment = worker->params->alignment;
  size_t iteration;
  for (iteration = 0; iteration < worker->params->iterations; iteration++) {
    void *block = checked(crabc_allocator_engine_aligned(alignment, size));
    if (((uintptr_t)block & (alignment - 1)) != 0) die("aligned allocation is misaligned");
    touch(block, size, (unsigned)(batch + iteration));
    crabc_allocator_engine_free(block);
  }
  return 2 * (uint64_t)worker->params->iterations;
}

static uint64_t body_realloc_grow(struct worker *worker, size_t batch)
{
  const size_t start = worker->params->size;
  const size_t limit = worker->params->max_size;
  uint64_t operations = 0;
  size_t iteration;
  for (iteration = 0; iteration < worker->params->iterations; iteration++) {
    size_t size = start;
    unsigned char *block = checked(crabc_allocator_engine_malloc(size));
    block[0] = (unsigned char)(batch + iteration);
    operations++;
    while (size < limit) {
      size = size * 2 > limit ? limit : size * 2;
      block = checked(crabc_allocator_engine_realloc(block, size));
      if (block[0] != (unsigned char)(batch + iteration)) die("realloc lost its prefix");
      block[size - 1] = (unsigned char)size;
      operations++;
    }
    crabc_allocator_engine_free(block);
    operations++;
  }
  return operations;
}

/* Alternating shrink/grow within the original usable size: source in-place reuse. */
static uint64_t body_realloc_inplace(struct worker *worker, size_t batch)
{
  const size_t size = worker->params->size;
  size_t iteration;
  unsigned char *block = checked(crabc_allocator_engine_malloc(size));
  block[0] = (unsigned char)batch;
  for (iteration = 0; iteration < worker->params->iterations; iteration++) {
    const size_t next = (iteration & 1U) != 0 ? size : size - size / 4;
    block = checked(crabc_allocator_engine_realloc(block, next));
    if (block[0] != (unsigned char)batch) die("in-place realloc lost its prefix");
  }
  crabc_allocator_engine_free(block);
  return (uint64_t)worker->params->iterations + 2;
}

static uint64_t body_usable_size(struct worker *worker, size_t batch)
{
  const size_t count = worker->params->count;
  size_t iteration;
  (void)batch;
  for (iteration = 0; iteration < worker->params->iterations; iteration++) {
    size_t index;
    for (index = 0; index < count; index++) {
      const size_t usable = crabc_allocator_engine_usable_size(worker->slots[index]);
      if (usable < worker->slot_sizes[index]) die("usable size is below the request");
      sink += usable;
    }
  }
  return (uint64_t)count * worker->params->iterations;
}

static uint64_t body_churn(struct worker *worker, size_t batch)
{
  const size_t live = worker->params->live;
  size_t iteration;
  for (iteration = 0; iteration < worker->params->iterations; iteration++) {
    const size_t slot = (size_t)(next_random(&worker->random) % (uint64_t)live);
    const size_t size = random_request(&worker->random, worker->params->max_size);
    crabc_allocator_engine_free(worker->slots[slot]);
    worker->slots[slot] = checked(crabc_allocator_engine_malloc(size));
    worker->slot_sizes[slot] = size;
    touch(worker->slots[slot], size, (unsigned)(batch + iteration));
  }
  return 2 * (uint64_t)worker->params->iterations;
}

static int slots_create(struct worker *worker, size_t count)
{
  worker->slots = calloc(count, sizeof *worker->slots);
  worker->slot_sizes = calloc(count, sizeof *worker->slot_sizes);
  return worker->slots != NULL && worker->slot_sizes != NULL ? 0 : -1;
}

static void slots_release(struct worker *worker, size_t count)
{
  size_t index;
  for (index = 0; index < count; index++) crabc_allocator_engine_free(worker->slots[index]);
  free(worker->slots);
  free(worker->slot_sizes);
  worker->slots = NULL;
  worker->slot_sizes = NULL;
}

/* Fixture-owned bookkeeping uses musl malloc, never the measured backend. */
static int prepare_worker(struct worker *worker, batch_body *body)
{
  const struct params *params = worker->params;
  const char *name = params->workload;
  size_t index;
  worker->random = params->seed ^ (UINT64_C(0x2545f4914f6cdd1d) * (worker->index + 1));
  if (worker->random == 0) worker->random = 1;
  if (strcmp(name, "alloc_free") == 0 || strcmp(name, "local_scaling") == 0) {
    if (params->size == 0) return -1;
    *body = body_alloc_free;
    return 0;
  }
  if (strcmp(name, "alloc_batch") == 0) {
    if (params->size == 0 || params->count == 0 || params->count > MAX_BATCH_BLOCKS) return -1;
    *body = body_alloc_batch;
    return slots_create(worker, params->count);
  }
  if (strcmp(name, "calloc_free") == 0) {
    if (params->size == 0) return -1;
    *body = body_calloc_free;
    return 0;
  }
  if (strcmp(name, "aligned_free") == 0) {
    if (params->size == 0 || params->alignment == 0 || (params->alignment & (params->alignment - 1)) != 0) return -1;
    *body = body_aligned_free;
    return 0;
  }
  if (strcmp(name, "realloc_grow") == 0) {
    if (params->size == 0 || params->max_size <= params->size) return -1;
    *body = body_realloc_grow;
    return 0;
  }
  if (strcmp(name, "realloc_inplace") == 0) {
    if (params->size < 16) return -1;
    *body = body_realloc_inplace;
    return 0;
  }
  if (strcmp(name, "usable_size") == 0) {
    if (params->size == 0 || params->count == 0 || params->count > MAX_BATCH_BLOCKS) return -1;
    if (slots_create(worker, params->count) != 0) return -1;
    for (index = 0; index < params->count; index++) {
      worker->slot_sizes[index] = params->size + (index % 8) * 8;
      worker->slots[index] = checked(crabc_allocator_engine_malloc(worker->slot_sizes[index]));
    }
    *body = body_usable_size;
    return 0;
  }
  if (strcmp(name, "churn") == 0 || strcmp(name, "churn_scaling") == 0
      || strcmp(name, "memory_churn") == 0) {
    if (params->live == 0 || params->live > MAX_LIVE_SLOTS || params->max_size < 8) return -1;
    if (slots_create(worker, params->live) != 0) return -1;
    for (index = 0; index < params->live; index++) {
      worker->slot_sizes[index] = random_request(&worker->random, params->max_size);
      worker->slots[index] = checked(crabc_allocator_engine_malloc(worker->slot_sizes[index]));
    }
    *body = body_churn;
    return 0;
  }
  return -1;
}

static void finish_worker(struct worker *worker)
{
  const char *name = worker->params->workload;
  if (strcmp(name, "alloc_batch") == 0) {
    free(worker->slots);
    free(worker->slot_sizes);
  } else if (strcmp(name, "usable_size") == 0) {
    slots_release(worker, worker->params->count);
  } else if (strcmp(name, "churn") == 0 || strcmp(name, "churn_scaling") == 0) {
    slots_release(worker, worker->params->live);
  }
}

/* ---- single-thread driver (initial thread) ------------------------------ */

static int run_initial_thread(const struct params *params)
{
  struct worker worker;
  batch_body body = NULL;
  size_t batch;
  memset(&worker, 0, sizeof worker);
  worker.params = params;
  if (prepare_worker(&worker, &body) != 0) {
    fail("unsupported initial-thread workload parameters");
    return 64;
  }
  for (batch = 0; batch < params->batches; batch++) {
    const uint64_t before_cpu = thread_cpu_ns();
    const uint64_t before = now_ns();
    const uint64_t operations = body(&worker, batch);
    const uint64_t after = now_ns();
    print_batch(after - before, thread_cpu_ns() - before_cpu, operations);
  }
  finish_worker(&worker);
  return 0;
}

/* ---- multi-thread drivers ----------------------------------------------- */

struct shared {
  const struct params *params;
  pthread_barrier_t start;
  pthread_barrier_t finish;
  _Atomic uint64_t operations[MAX_WORKERS];
  _Atomic uint64_t cpu_ns[MAX_WORKERS];
  /* Each participant's own work interval: a descheduled coordinator cannot
   * shorten or stretch the recorded batch. */
  _Atomic uint64_t started_ns[MAX_WORKERS];
  _Atomic uint64_t finished_ns[MAX_WORKERS];
};

/* Wall interval from the first participant's start to the last one's finish. */
static uint64_t batch_interval(struct shared *shared, size_t participants)
{
  uint64_t first = UINT64_MAX;
  uint64_t last = 0;
  size_t index;
  for (index = 0; index < participants; index++) {
    const uint64_t started = atomic_load(&shared->started_ns[index]);
    const uint64_t finished = atomic_load(&shared->finished_ns[index]);
    if (started < first) first = started;
    if (finished > last) last = finished;
  }
  if (last <= first) die("batch interval is not positive");
  return last - first;
}

struct worker_argument {
  struct shared *shared;
  size_t index;
};

static void pin_current_thread(const struct params *params, size_t index)
{
  cpu_set_t set;
  if (params->cpu_count == 0) return;
  CPU_ZERO(&set);
  CPU_SET(params->cpus[index % params->cpu_count], &set);
  if (pthread_setaffinity_np(pthread_self(), sizeof set, &set) != 0) die("worker CPU pinning failed");
}

static void barrier_wait(pthread_barrier_t *barrier)
{
  const int result = pthread_barrier_wait(barrier);
  if (result != 0 && result != PTHREAD_BARRIER_SERIAL_THREAD) die("barrier wait failed");
}

static void *independent_worker(void *raw)
{
  struct worker_argument *argument = raw;
  struct shared *shared = argument->shared;
  const struct params *params = shared->params;
  struct worker worker;
  batch_body body = NULL;
  size_t batch;
  pin_current_thread(params, argument->index);
  if (crabc_allocator_engine_thread_init() != 0) die("backend thread_init failed");
  memset(&worker, 0, sizeof worker);
  worker.params = params;
  worker.index = argument->index;
  if (prepare_worker(&worker, &body) != 0) die("unsupported worker workload parameters");
  for (batch = 0; batch < params->batches; batch++) {
    uint64_t operations;
    uint64_t before_cpu;
    barrier_wait(&shared->start);
    before_cpu = thread_cpu_ns();
    atomic_store(&shared->started_ns[argument->index], now_ns());
    operations = body(&worker, batch);
    atomic_store(&shared->finished_ns[argument->index], now_ns());
    atomic_store(&shared->cpu_ns[argument->index], thread_cpu_ns() - before_cpu);
    atomic_store(&shared->operations[argument->index], operations);
    barrier_wait(&shared->finish);
  }
  finish_worker(&worker);
  if (crabc_allocator_engine_thread_done() != 0) die("backend thread_done failed");
  return NULL;
}

static int run_independent_workers(const struct params *params)
{
  struct shared shared;
  struct worker_argument arguments[MAX_WORKERS];
  pthread_t threads[MAX_WORKERS];
  size_t index;
  size_t batch;
  memset(&shared, 0, sizeof shared);
  shared.params = params;
  if (params->cpu_count != 0 && params->cpu_count < params->workers) {
    fail("each independent worker needs a distinct listed CPU");
    return 64;
  }
  if (pthread_barrier_init(&shared.start, NULL, (unsigned)params->workers + 1) != 0
      || pthread_barrier_init(&shared.finish, NULL, (unsigned)params->workers + 1) != 0) {
    fail("barrier init failed");
    return 65;
  }
  for (index = 0; index < params->workers; index++) {
    arguments[index].shared = &shared;
    arguments[index].index = index;
    if (pthread_create(&threads[index], NULL, independent_worker, &arguments[index]) != 0) {
      fail("pthread_create failed");
      return 66;
    }
  }
  for (batch = 0; batch < params->batches; batch++) {
    uint64_t operations = 0;
    uint64_t cpu = 0;
    barrier_wait(&shared.start);
    barrier_wait(&shared.finish);
    for (index = 0; index < params->workers; index++) {
      operations += atomic_load(&shared.operations[index]);
      cpu += atomic_load(&shared.cpu_ns[index]);
    }
    print_batch(batch_interval(&shared, params->workers), cpu, operations);
  }
  for (index = 0; index < params->workers; index++) {
    if (pthread_join(threads[index], NULL) != 0) {
      fail("pthread_join failed");
      return 67;
    }
  }
  return 0;
}

/*
 * Remote free: `workers` producer/consumer pairs.  Each producer allocates,
 * touches, and publishes blocks through its own bounded SPSC ring; its
 * consumer frees every block, so each free takes the backend's cross-thread
 * (remote publication) path and the producer's later allocations collect it.
 */
struct ring {
  _Alignas(64) _Atomic size_t head;
  _Alignas(64) _Atomic size_t tail;
  _Alignas(64) void *blocks[REMOTE_RING];
};

struct remote_pair {
  struct shared *shared;
  struct ring ring;
  size_t index;
};

static void *remote_producer(void *raw)
{
  struct remote_pair *pair = raw;
  struct shared *shared = pair->shared;
  const struct params *params = shared->params;
  size_t batch;
  pin_current_thread(params, 2 * pair->index);
  if (crabc_allocator_engine_thread_init() != 0) die("backend producer thread_init failed");
  for (batch = 0; batch < params->batches; batch++) {
    size_t iteration;
    uint64_t before_cpu;
    barrier_wait(&shared->start);
    before_cpu = thread_cpu_ns();
    atomic_store(&shared->started_ns[2 * pair->index], now_ns());
    for (iteration = 0; iteration < params->iterations; iteration++) {
      void *block = checked(crabc_allocator_engine_malloc(params->size));
      const size_t head = atomic_load_explicit(&pair->ring.head, memory_order_relaxed);
      touch(block, params->size, (unsigned)(batch + iteration));
      while (head - atomic_load_explicit(&pair->ring.tail, memory_order_acquire) == REMOTE_RING) sched_yield();
      pair->ring.blocks[head % REMOTE_RING] = block;
      atomic_store_explicit(&pair->ring.head, head + 1, memory_order_release);
    }
    atomic_store(&shared->finished_ns[2 * pair->index], now_ns());
    atomic_store(&shared->cpu_ns[2 * pair->index], thread_cpu_ns() - before_cpu);
    atomic_store(&shared->operations[2 * pair->index], params->iterations);
    barrier_wait(&shared->finish);
  }
  if (crabc_allocator_engine_thread_done() != 0) die("backend producer thread_done failed");
  return NULL;
}

static void *remote_consumer(void *raw)
{
  struct remote_pair *pair = raw;
  struct shared *shared = pair->shared;
  const struct params *params = shared->params;
  size_t batch;
  pin_current_thread(params, 2 * pair->index + 1);
  if (crabc_allocator_engine_thread_init() != 0) die("backend consumer thread_init failed");
  for (batch = 0; batch < params->batches; batch++) {
    size_t iteration;
    uint64_t before_cpu;
    barrier_wait(&shared->start);
    before_cpu = thread_cpu_ns();
    atomic_store(&shared->started_ns[2 * pair->index + 1], now_ns());
    for (iteration = 0; iteration < params->iterations; iteration++) {
      const size_t tail = atomic_load_explicit(&pair->ring.tail, memory_order_relaxed);
      void *block;
      while (atomic_load_explicit(&pair->ring.head, memory_order_acquire) == tail) sched_yield();
      block = pair->ring.blocks[tail % REMOTE_RING];
      atomic_store_explicit(&pair->ring.tail, tail + 1, memory_order_release);
      crabc_allocator_engine_free(block);
    }
    atomic_store(&shared->finished_ns[2 * pair->index + 1], now_ns());
    atomic_store(&shared->cpu_ns[2 * pair->index + 1], thread_cpu_ns() - before_cpu);
    atomic_store(&shared->operations[2 * pair->index + 1], params->iterations);
    barrier_wait(&shared->finish);
  }
  if (crabc_allocator_engine_thread_done() != 0) die("backend consumer thread_done failed");
  return NULL;
}

static int run_remote_free(const struct params *params)
{
  struct shared shared;
  struct remote_pair *pairs;
  pthread_t threads[MAX_WORKERS];
  const size_t thread_count = 2 * params->workers;
  size_t index;
  size_t batch;
  if (params->size == 0 || thread_count > MAX_WORKERS) {
    fail("unsupported remote-free parameters");
    return 64;
  }
  if (params->cpu_count != 0 && params->cpu_count < thread_count) {
    fail("each remote-free thread needs a distinct listed CPU");
    return 64;
  }
  memset(&shared, 0, sizeof shared);
  shared.params = params;
  pairs = aligned_alloc(64, sizeof *pairs * params->workers);
  if (pairs == NULL) return 65;
  memset(pairs, 0, sizeof *pairs * params->workers);
  if (pthread_barrier_init(&shared.start, NULL, (unsigned)thread_count + 1) != 0
      || pthread_barrier_init(&shared.finish, NULL, (unsigned)thread_count + 1) != 0) {
    return 65;
  }
  for (index = 0; index < params->workers; index++) {
    pairs[index].shared = &shared;
    pairs[index].index = index;
    if (pthread_create(&threads[2 * index], NULL, remote_producer, &pairs[index]) != 0
        || pthread_create(&threads[2 * index + 1], NULL, remote_consumer, &pairs[index]) != 0) {
      fail("pthread_create failed");
      return 66;
    }
  }
  for (batch = 0; batch < params->batches; batch++) {
    uint64_t operations = 0;
    uint64_t cpu = 0;
    barrier_wait(&shared.start);
    barrier_wait(&shared.finish);
    for (index = 0; index < thread_count; index++) {
      operations += atomic_load(&shared.operations[index]);
      cpu += atomic_load(&shared.cpu_ns[index]);
    }
    print_batch(batch_interval(&shared, thread_count), cpu, operations);
  }
  for (index = 0; index < thread_count; index++) {
    if (pthread_join(threads[index], NULL) != 0) return 67;
  }
  free(pairs);
  return 0;
}

/*
 * Thread churn: each batch creates `workers` short-lived threads.  Each one
 * attaches, allocates `count` blocks, frees half locally, hands the other
 * half to the initial thread, finishes its owner, and exits.  The initial
 * thread joins them and then frees every survivor after its owner's exit
 * (source abandonment/reclaim path).  The batch includes creation and join.
 */
struct churn_thread {
  const struct params *params;
  void **survivors;
  size_t index;
  /* The short-lived thread's whole CPU time, read just before it returns. */
  uint64_t cpu_ns;
};

static void *churn_thread_main(void *raw)
{
  struct churn_thread *thread = raw;
  const struct params *params = thread->params;
  size_t index;
  if (crabc_allocator_engine_thread_init() != 0) die("backend churn thread_init failed");
  for (index = 0; index < params->count; index++) {
    thread->survivors[index] = checked(crabc_allocator_engine_malloc(params->size));
    touch(thread->survivors[index], params->size, (unsigned)index);
  }
  for (index = 0; index < params->count; index += 2) {
    crabc_allocator_engine_free(thread->survivors[index]);
    thread->survivors[index] = NULL;
  }
  if (crabc_allocator_engine_thread_done() != 0) die("backend churn thread_done failed");
  thread->cpu_ns = thread_cpu_ns();
  return NULL;
}

static int run_thread_churn(const struct params *params)
{
  struct churn_thread threads[MAX_WORKERS];
  pthread_t handles[MAX_WORKERS];
  void **survivors;
  size_t batch;
  if (params->size == 0 || params->count == 0 || params->count > MAX_BATCH_BLOCKS) {
    fail("unsupported thread-churn parameters");
    return 64;
  }
  survivors = calloc(params->workers * params->count, sizeof *survivors);
  if (survivors == NULL) return 65;
  for (batch = 0; batch < params->batches; batch++) {
    const uint64_t before_cpu = thread_cpu_ns();
    const uint64_t before = now_ns();
    uint64_t after;
    uint64_t cpu;
    size_t index;
    for (index = 0; index < params->workers; index++) {
      threads[index].params = params;
      threads[index].survivors = survivors + index * params->count;
      threads[index].index = index;
      if (pthread_create(&handles[index], NULL, churn_thread_main, &threads[index]) != 0) die("pthread_create failed");
    }
    for (index = 0; index < params->workers; index++) {
      if (pthread_join(handles[index], NULL) != 0) die("pthread_join failed");
    }
    for (index = 0; index < params->workers * params->count; index++) {
      if (survivors[index] != NULL) {
        crabc_allocator_engine_free(survivors[index]);
        survivors[index] = NULL;
      }
    }
    after = now_ns();
    /* The coordinator's create/join/post-exit free plus every thread's own. */
    cpu = thread_cpu_ns() - before_cpu;
    for (index = 0; index < params->workers; index++) cpu += threads[index].cpu_ns;
    print_batch(after - before, cpu, 2 * (uint64_t)params->workers * params->count);
  }
  free(survivors);
  return 0;
}

/* ---- memory workloads --------------------------------------------------- */

static int write_line(int descriptor, const char *text)
{
  size_t remaining = strlen(text);
  while (remaining != 0) {
    const ssize_t wrote = write(descriptor, text, remaining);
    if (wrote < 0 && errno == EINTR) continue;
    if (wrote <= 0) return -1;
    text += wrote;
    remaining -= (size_t)wrote;
  }
  return 0;
}

static int wait_parent(int descriptor)
{
  unsigned char byte;
  for (;;) {
    const ssize_t count = read(descriptor, &byte, 1);
    if (count < 0 && errno == EINTR) continue;
    return count == 1 ? 0 : -1;
  }
}

static int barrier_parent(const struct params *params, const char *line)
{
  return write_line(params->ready_fd, line) == 0 && wait_parent(params->control_fd) == 0 ? 0 : -1;
}

/*
 * `memory_live` threads its live set through the blocks themselves, so the
 * fixture adds no per-block bookkeeping to either lane's resident memory.
 * `memory_churn` keeps one slot array (allocated before READY_INIT) because
 * it replaces random live slots.
 */
static int run_memory(const struct params *params)
{
  const int churn = strcmp(params->workload, "memory_churn") == 0;
  struct worker worker;
  batch_body body = NULL;
  void *list = NULL;
  size_t index;
  if (params->ready_fd < 0 || params->control_fd < 0) {
    fail("memory workloads require ready_fd and control_fd");
    return 64;
  }
  memset(&worker, 0, sizeof worker);
  worker.params = params;
  if (churn) {
    if (prepare_worker(&worker, &body) != 0) {
      fail("unsupported memory_churn parameters");
      return 64;
    }
  } else if (params->size < sizeof(void *) || params->total < params->size) {
    fail("unsupported memory_live parameters");
    return 64;
  }
  if (barrier_parent(params, "READY_INIT\n") != 0) return 65;
  if (churn) {
    size_t batch;
    for (batch = 0; batch < params->batches; batch++) (void)body(&worker, batch);
  } else {
    const size_t count = params->total / params->size;
    for (index = 0; index < count; index++) {
      void **block = checked(crabc_allocator_engine_malloc(params->size));
      memset(block, (int)(index & 0xffU), params->size);
      *block = list;
      list = block;
    }
  }
  if (barrier_parent(params, "READY_LIVE\n") != 0) return 65;
  if (churn) {
    slots_release(&worker, params->live);
  } else {
    while (list != NULL) {
      void *next = *(void **)list;
      crabc_allocator_engine_free(list);
      list = next;
    }
  }
  if (barrier_parent(params, "READY_FREED\n") != 0) return 65;
  return 0;
}

/* ---- single-step trace scenarios (codegen audit only) -------------------
 *
 * `trace_*` workloads run only under compat/allocator/codegen_audit_x86_64.py,
 * which ptrace-single-steps the thread between consecutive `int3` markers.
 * Each scenario first warms the exact operation so the traced call takes its
 * steady-state path; the markers then bracket one allocator call per region.
 * Run untraced, the first marker terminates the process with SIGTRAP.
 */
#define TRACE_MARK() __asm__ volatile("int3" ::: "memory")

enum { TRACE_WARM = 4096 };

static void trace_warm(size_t size)
{
  size_t index;
  for (index = 0; index < TRACE_WARM; index++) {
    void *block = checked(crabc_allocator_engine_malloc(size));
    touch(block, size, (unsigned)index);
    crabc_allocator_engine_free(block);
  }
}

static void trace_local_pair(size_t size)
{
  void *block;
  trace_warm(size);
  TRACE_MARK();
  block = crabc_allocator_engine_malloc(size);
  TRACE_MARK();
  touch(checked(block), size, 1);
  TRACE_MARK();
  crabc_allocator_engine_free(block);
  TRACE_MARK();
}

static void *trace_worker_main(void *raw)
{
  const struct params *params = raw;
  if (crabc_allocator_engine_thread_init() != 0) die("backend trace thread_init failed");
  trace_local_pair(params->size);
  if (crabc_allocator_engine_thread_done() != 0) die("backend trace thread_done failed");
  return NULL;
}

static void *trace_lifecycle_main(void *raw)
{
  const struct params *params = raw;
  int result;
  TRACE_MARK();
  result = crabc_allocator_engine_thread_init();
  TRACE_MARK();
  if (result != 0) die("backend trace thread_init failed");
  trace_warm(params->size);
  TRACE_MARK();
  result = crabc_allocator_engine_thread_done();
  TRACE_MARK();
  if (result != 0) die("backend trace thread_done failed");
  return NULL;
}

struct trace_remote {
  const struct params *params;
  void **blocks;
  atomic_int phase;
};

static void trace_wait_phase(struct trace_remote *remote, int phase)
{
  while (atomic_load_explicit(&remote->phase, memory_order_acquire) != phase) sched_yield();
}

/*
 * The owner keeps its page live while the initial thread frees its blocks
 * (source remote publication), then traces its own next `count` allocations,
 * which collect those published frees.
 */
static void *trace_remote_owner(void *raw)
{
  struct trace_remote *remote = raw;
  const struct params *params = remote->params;
  size_t index;
  if (crabc_allocator_engine_thread_init() != 0) die("backend trace owner thread_init failed");
  trace_warm(params->size);
  for (index = 0; index < params->count; index++) {
    remote->blocks[index] = checked(crabc_allocator_engine_malloc(params->size));
    touch(remote->blocks[index], params->size, (unsigned)index);
  }
  atomic_store_explicit(&remote->phase, 1, memory_order_release);
  trace_wait_phase(remote, 2);
  TRACE_MARK();
  for (index = 0; index < params->count; index++) remote->blocks[index] = crabc_allocator_engine_malloc(params->size);
  TRACE_MARK();
  for (index = 0; index < params->count; index++) crabc_allocator_engine_free(checked(remote->blocks[index]));
  if (crabc_allocator_engine_thread_done() != 0) die("backend trace owner thread_done failed");
  return NULL;
}

static int run_trace(const struct params *params)
{
  const char *scenario = params->workload + strlen("trace_");
  const size_t size = params->size;
  pthread_t thread;
  void *block;
  size_t index;
  if (size < 16) {
    fail("trace scenarios need size >= 16");
    return 64;
  }
  if (strcmp(scenario, "local") == 0) {
    trace_local_pair(size);
  } else if (strcmp(scenario, "worker") == 0 || strcmp(scenario, "thread_lifecycle") == 0) {
    void *(*entry)(void *) = strcmp(scenario, "worker") == 0 ? trace_worker_main : trace_lifecycle_main;
    if (pthread_create(&thread, NULL, entry, (void *)params) != 0 || pthread_join(thread, NULL) != 0) die("trace thread failed");
  } else if (strcmp(scenario, "calloc") == 0) {
    for (index = 0; index < TRACE_WARM; index++) crabc_allocator_engine_free(checked(crabc_allocator_engine_calloc(1, size)));
    TRACE_MARK();
    block = crabc_allocator_engine_calloc(1, size);
    TRACE_MARK();
    crabc_allocator_engine_free(checked(block));
  } else if (strcmp(scenario, "aligned") == 0) {
    if (params->alignment == 0 || (params->alignment & (params->alignment - 1)) != 0) return 64;
    for (index = 0; index < TRACE_WARM; index++) {
      crabc_allocator_engine_free(checked(crabc_allocator_engine_aligned(params->alignment, size)));
    }
    TRACE_MARK();
    block = crabc_allocator_engine_aligned(params->alignment, size);
    TRACE_MARK();
    checked(block);
    TRACE_MARK();
    crabc_allocator_engine_free(block);
    TRACE_MARK();
  } else if (strcmp(scenario, "realloc_move") == 0) {
    for (index = 0; index < TRACE_WARM; index++) {
      block = checked(crabc_allocator_engine_malloc(size));
      crabc_allocator_engine_free(checked(crabc_allocator_engine_realloc(block, 4 * size)));
    }
    block = checked(crabc_allocator_engine_malloc(size));
    memset(block, 0x5a, size);
    TRACE_MARK();
    block = crabc_allocator_engine_realloc(block, 4 * size);
    TRACE_MARK();
    crabc_allocator_engine_free(checked(block));
  } else if (strcmp(scenario, "realloc_inplace") == 0) {
    trace_warm(size);
    block = checked(crabc_allocator_engine_malloc(size));
    for (index = 0; index < TRACE_WARM; index++) {
      block = checked(crabc_allocator_engine_realloc(block, (index & 1U) != 0 ? size : size - size / 4));
    }
    TRACE_MARK();
    block = crabc_allocator_engine_realloc(block, size - size / 4);
    TRACE_MARK();
    crabc_allocator_engine_free(checked(block));
  } else if (strcmp(scenario, "usable_size") == 0) {
    block = checked(crabc_allocator_engine_malloc(size));
    for (index = 0; index < TRACE_WARM; index++) sink += crabc_allocator_engine_usable_size(block);
    TRACE_MARK();
    sink += crabc_allocator_engine_usable_size(block);
    TRACE_MARK();
    crabc_allocator_engine_free(block);
  } else if (strcmp(scenario, "remote_free") == 0) {
    struct trace_remote remote;
    if (params->count < 2 || params->count > MAX_BATCH_BLOCKS) return 64;
    memset(&remote, 0, sizeof remote);
    remote.params = params;
    remote.blocks = calloc(params->count, sizeof *remote.blocks);
    if (remote.blocks == NULL) return 65;
    if (pthread_create(&thread, NULL, trace_remote_owner, &remote) != 0) die("trace owner failed");
    trace_wait_phase(&remote, 1);
    for (index = 0; index + 1 < params->count; index++) crabc_allocator_engine_free(remote.blocks[index]);
    TRACE_MARK();
    crabc_allocator_engine_free(remote.blocks[params->count - 1]);
    TRACE_MARK();
    atomic_store_explicit(&remote.phase, 2, memory_order_release);
    if (pthread_join(thread, NULL) != 0) die("trace owner join failed");
    free(remote.blocks);
  } else {
    fail("unknown trace scenario");
    return 64;
  }
  return 0;
}

int main(int argc, char **argv)
{
  struct params params;
  int status;
  if (parse_params(argc, argv, &params) != 0) {
    fail("usage: engine-fixture <workload> key=value...");
    return 64;
  }
  if (crabc_allocator_engine_process_init() != 0) {
    fail("backend process_init failed");
    return 71;
  }
  if (strncmp(params.workload, "memory_", 7) == 0) status = run_memory(&params);
  else if (strncmp(params.workload, "trace_", 6) == 0) status = run_trace(&params);
  else if (strcmp(params.workload, "local_scaling") == 0 || strcmp(params.workload, "churn_scaling") == 0)
    status = run_independent_workers(&params);
  else if (strcmp(params.workload, "remote_free") == 0) status = run_remote_free(&params);
  else if (strcmp(params.workload, "thread_churn") == 0) status = run_thread_churn(&params);
  else status = run_initial_thread(&params);
  if (status != 0) return status;
  printf("ok\n");
  return fflush(stdout) == 0 ? 0 : 72;
}
