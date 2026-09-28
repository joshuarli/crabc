/* Compare an ordinary remote free after the freeing worker has its own Theap. */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mimalloc.h"
#include "mimalloc-stats.h"

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t changed = PTHREAD_COND_INITIALIZER;
static int ready;
static int release_worker;
static void* remote_block;
static size_t warm_usable;
static char worker_output[16384];
static size_t worker_output_length;

static void capture_worker(const char* message, void* argument) {
  (void)argument;
  const size_t length = strlen(message);
  if (length >= sizeof(worker_output) - worker_output_length) abort();
  memcpy(worker_output + worker_output_length, message, length + 1);
  worker_output_length += length;
}

static void read_stats(mi_stats_t* stats) {
  if (!mi_stats_get(stats)) abort();
}

static void show_normal(const char* name, const mi_stats_t* stats, const mi_stats_t* before) {
  printf("%s.normal=%lld,%lld,%lld\n", name,
         (long long)(stats->malloc_normal.total - before->malloc_normal.total),
         (long long)(stats->malloc_normal.peak - before->malloc_normal.peak),
         (long long)(stats->malloc_normal.current - before->malloc_normal.current));
}

static void show_worker_binned(void) {
  const char* row = strstr(worker_output, "  binned");
  if (row == NULL) abort();
  const char* end = strchr(row, '\n');
  if (end == NULL) abort();
  printf("worker.binned.hex=");
  for (const char* p = row; p < end; p++) printf("%02x", (unsigned char)*p);
  printf("\n");
}

static void* worker(void* argument) {
  (void)argument;
  void* warm = mi_malloc(1);
  if (warm == NULL) abort();
  warm_usable = mi_usable_size(warm);
  mi_free(warm);

  if (pthread_mutex_lock(&lock) != 0) abort();
  ready = 1;
  if (pthread_cond_broadcast(&changed) != 0) abort();
  while (!release_worker) {
    if (pthread_cond_wait(&changed, &lock) != 0) abort();
  }
  void* block = remote_block;
  if (pthread_mutex_unlock(&lock) != 0) abort();

  mi_free(block);
  mi_thread_stats_print_out(&capture_worker, NULL);
  return NULL;
}

int main(void) {
  pthread_t thread;
  if (pthread_create(&thread, NULL, &worker, NULL) != 0) return 2;
  if (pthread_mutex_lock(&lock) != 0) abort();
  while (!ready) {
    if (pthread_cond_wait(&changed, &lock) != 0) abort();
  }
  if (pthread_mutex_unlock(&lock) != 0) abort();

  mi_stats_t_decl(before);
  mi_stats_t_decl(allocated);
  mi_stats_t_decl(freed);
  read_stats(&before);
  void* block = mi_malloc(64);
  if (block == NULL) return 3;
  memset(block, 0x5a, 64);
  const size_t target_usable = mi_usable_size(block);
  read_stats(&allocated);

  if (pthread_mutex_lock(&lock) != 0) abort();
  remote_block = block;
  release_worker = 1;
  if (pthread_cond_broadcast(&changed) != 0) abort();
  if (pthread_mutex_unlock(&lock) != 0) abort();
  if (pthread_join(thread, NULL) != 0) abort();
  read_stats(&freed);

  printf("CRABC_MI_M7_STATISTICS_REMOTE_NORMAL_TRACE_BEGIN\n");
  printf("profile.level=1\n");
  printf("warm.usable=%zu\n", warm_usable);
  printf("target.usable=%zu\n", target_usable);
  show_normal("allocated", &allocated, &before);
  show_normal("freed", &freed, &before);
  show_worker_binned();
  printf("CRABC_MI_M7_STATISTICS_REMOTE_NORMAL_TRACE_END\n");
  return 0;
}
