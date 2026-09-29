/* One public MI_STAT=1 trace through two real worker owners and process merges. */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mimalloc.h"
#include "mimalloc-stats.h"

static void* blocks[2];
static char worker_rows[2][256];

static void capture(const char* message, void* argument) {
  char* row = (char*)argument;
  const char* found = strstr(message, "  binned");
  if (found == NULL) return;
  const char* end = strchr(found, '\n');
  if (end == NULL || (size_t)(end - found) >= 256) abort();
  memcpy(row, found, (size_t)(end - found));
  row[end - found] = 0;
}

static void* worker(void* argument) {
  const size_t index = (size_t)argument;
  blocks[index] = mi_malloc(index == 0 ? 64 : 128);
  if (blocks[index] == NULL) abort();
  mi_thread_stats_print_out(&capture, worker_rows[index]);
  return NULL;
}

static void show_count(const char* stage, const char* field,
                       const mi_stat_count_t* count) {
  printf("%s.%s=%lld,%lld,%lld\n", stage, field,
         (long long)count->total, (long long)count->peak,
         (long long)count->current);
}

static void show_stage(const char* stage) {
  mi_stats_t_decl(stats);
  if (!mi_stats_get(&stats)) abort();
  show_count(stage, "normal", &stats.malloc_normal);
  show_count(stage, "pages", &stats.pages);
  show_count(stage, "threads", &stats.threads);
  show_count(stage, "theaps", &stats.theaps);
}

static void show_row(const char* stage, const char* row) {
  printf("%s.binned=", stage);
  for (const unsigned char* p = (const unsigned char*)row; *p != 0; p++) {
    printf("%02x", *p);
  }
  printf("\n");
}

int main(void) {
  printf("CRABC_MI_M7_STATISTICS_TWO_OWNER_TRACE_BEGIN\n");
  printf("profile.level=1\n");
  show_stage("before");
  for (size_t index = 0; index < 2; index++) {
    pthread_t thread;
    if (pthread_create(&thread, NULL, worker, (void*)index) != 0 ||
        pthread_join(thread, NULL) != 0) abort();
    if (worker_rows[index][0] == 0) abort();
    show_row(index == 0 ? "worker_first" : "worker_second", worker_rows[index]);
    show_stage(index == 0 ? "merged_first" : "merged_second");
  }
  mi_free(blocks[0]);
  show_stage("freed_first");
  mi_free(blocks[1]);
  show_stage("freed_second");
  printf("CRABC_MI_M7_STATISTICS_TWO_OWNER_TRACE_END\n");
  return 0;
}
