/* SPDX-License-Identifier: MIT
 *
 * Pinned-C half of the native-boundary local trace differential.
 *
 * `compat/allocator/native_local_trace_x86_64.py` compiles this driver with
 * the pinned mimalloc v3.5.0 release source set. It applies one workload
 * through `mi_malloc_aligned(size, 16)` / `mi_zalloc_aligned(size, 16)` /
 * `mi_free` first on the main thread's default Theap and then on one pthread
 * worker's, and after every operation prints the touched page's normalized
 * state and the default Theap's counters. The line format is owned jointly
 * with `crabc-mimalloc/src/native_local_trace.rs`; change both together.
 */
#include "mimalloc.h"
#include "mimalloc/internal.h"
#include "mimalloc/prim-tls.h"

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(__linux__) || !defined(__x86_64__)
#error the native local trace driver requires native Linux/x86_64
#endif
#if MI_BUILD_RELEASE != 1 || MI_DEBUG != 0 || MI_STAT != 0 || MI_SECURE != 0 || MI_GUARDED != 0
#error the native local trace driver requires the fixed release profile
#endif
#if MI_PADDING != 0 || MI_ENCODE_FREELIST != 0
#error the native local trace driver requires unpadded, unencoded release free lists
#endif

#define WORKLOAD_MAGIC "native-local-trace 1"
#define ALIGNMENT 16
#define MAX_PAGES 4096

typedef struct operation_s {
  char kind;
  size_t id;
  size_t size;
  int zero;
} operation_t;

static operation_t* operations;
static size_t operation_count;
static size_t id_count;
static FILE* out;

static void fail(const char* message) {
  fprintf(stderr, "native-local-trace-c: %s\n", message);
  exit(2);
}

static void load(const char* path) {
  FILE* file = fopen(path, "r");
  if (file == NULL) fail("cannot open workload");
  char line[256];
  if (fgets(line, sizeof(line), file) == NULL || strncmp(line, WORKLOAD_MAGIC, strlen(WORKLOAD_MAGIC)) != 0) {
    fail("workload magic");
  }
  size_t capacity = 0;
  while (fgets(line, sizeof(line), file) != NULL) {
    operation_t operation = { 0 };
    if (line[0] == 'a') {
      if (sscanf(line, "a %zu %zu %d", &operation.id, &operation.size, &operation.zero) != 3) fail("bad allocation line");
      operation.kind = 'a';
      if (operation.id + 1 > id_count) id_count = operation.id + 1;
    }
    else if (line[0] == 'f') {
      if (sscanf(line, "f %zu", &operation.id) != 1) fail("bad free line");
      operation.kind = 'f';
    }
    else if (line[0] == '\n') {
      continue;
    }
    else {
      fail("unknown workload operation");
    }
    if (operation_count == capacity) {
      capacity = (capacity == 0 ? 1024 : capacity * 2);
      operations = realloc(operations, capacity * sizeof(operation_t));
      if (operations == NULL) fail("out of workload memory");
    }
    operations[operation_count++] = operation;
  }
  fclose(file);
}

typedef struct tracer_s {
  mi_page_t* pages[MAX_PAGES];
  size_t page_count;
  void** blocks;
  mi_page_t** block_pages;
} tracer_t;

static size_t page_id(tracer_t* tracer, mi_page_t* page) {
  for (size_t index = 0; index < tracer->page_count; index++) {
    if (tracer->pages[index] == page) return index + 1;
  }
  if (tracer->page_count == MAX_PAGES) fail("too many pages");
  tracer->pages[tracer->page_count++] = page;
  return tracer->page_count;
}

static void block_index(char* buffer, size_t size, const mi_page_t* page, const void* block) {
  if (block == NULL) {
    snprintf(buffer, size, "-");
    return;
  }
  const size_t offset = (uintptr_t)block - (uintptr_t)mi_page_start(page);
  const size_t block_size = mi_page_block_size(page);
  if (offset % block_size == 0) {
    snprintf(buffer, size, "%zu", offset / block_size);
  }
  else {
    snprintf(buffer, size, "%zur%zu", offset / block_size, offset % block_size);
  }
}

static void record(tracer_t* tracer, const char* head, void* block, mi_page_t* page) {
  mi_theap_t* theap = _mi_theap_default();
  char index[48], free_index[48], local_index[48];
  block_index(index, sizeof(index), page, block);
  block_index(free_index, sizeof(free_index), page, page->free);
  block_index(local_index, sizeof(local_index), page, page->local_free);
  const size_t block_size = mi_page_block_size(page);
  fprintf(out,
          "%s P%zu i%s | s%zu c%u r%u u%zu f%s l%s x%u z%d n%zu pc%zu gc%ld gcc%ld rmin%zu rmax%zu\n",
          head, page_id(tracer, page), index, block_size, (unsigned)page->capacity,
          (unsigned)page->reserved, (size_t)page->used, free_index, local_index,
          (unsigned)page->retire_expire, page->free_is_zero ? 1 : 0,
          theap->pages[_mi_bin(block_size)].count, theap->page_count, (long)theap->generic_count,
          (long)theap->generic_collect_count, theap->page_retired_min, theap->page_retired_max);
}

static void run(const char* profile) {
  tracer_t* tracer = calloc(1, sizeof(tracer_t));
  if (tracer == NULL) fail("out of tracer memory");
  tracer->blocks = calloc(id_count, sizeof(void*));
  tracer->block_pages = calloc(id_count, sizeof(mi_page_t*));
  if (id_count != 0 && (tracer->blocks == NULL || tracer->block_pages == NULL)) fail("out of id memory");
  fprintf(out, "profile %s\n", profile);
  for (size_t index = 0; index < operation_count; index++) {
    const operation_t* operation = &operations[index];
    char head[96];
    if (operation->kind == 'a') {
      void* block = operation->zero ? mi_zalloc_aligned(operation->size, ALIGNMENT)
                                    : mi_malloc_aligned(operation->size, ALIGNMENT);
      if (block == NULL) fail("allocation failed");
      bool zeroed = false;
      if (operation->zero) {
        zeroed = true;
        for (size_t byte = 0; byte < operation->size; byte++) {
          if (((const unsigned char*)block)[byte] != 0) { zeroed = false; break; }
        }
      }
      memset(block, 0xa5, operation->size);
      mi_page_t* page = _mi_ptr_page(block);
      tracer->blocks[operation->id] = block;
      tracer->block_pages[operation->id] = page;
      snprintf(head, sizeof(head), "a%zu %zu z%d Z%d", operation->id, operation->size,
               operation->zero ? 1 : 0, zeroed ? 1 : 0);
      record(tracer, head, block, page);
    }
    else {
      void* block = tracer->blocks[operation->id];
      mi_page_t* page = tracer->block_pages[operation->id];
      if (block == NULL) fail("free names no live id");
      tracer->blocks[operation->id] = NULL;
      mi_free(block);
      snprintf(head, sizeof(head), "f%zu", operation->id);
      record(tracer, head, block, page);
    }
  }
  for (size_t id = 0; id < id_count; id++) {
    if (tracer->blocks[id] != NULL) fail("the workload leaves a live block");
  }
  free(tracer->blocks);
  free(tracer->block_pages);
  free(tracer);
}

static void* worker(void* argument) {
  (void)argument;
  /* crabc's libc attaches each pthread before its start routine
     (`attach_current_thread`); `mi_thread_init` is the pinned equivalent. */
  mi_thread_init();
  run("worker");
  return NULL;
}

int main(int argc, char** argv) {
  if (argc != 3) fail("usage: native-local-trace-c WORKLOAD OUTPUT");
  load(argv[1]);
  out = fopen(argv[2], "w");
  if (out == NULL) fail("cannot open output");
  run("initial");
  pthread_t thread;
  if (pthread_create(&thread, NULL, worker, NULL) != 0) fail("pthread_create");
  if (pthread_join(thread, NULL) != 0) fail("pthread_join");
  if (fclose(out) != 0) fail("cannot close output");
  return 0;
}
