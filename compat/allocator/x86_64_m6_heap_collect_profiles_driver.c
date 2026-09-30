#define _GNU_SOURCE 1
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mimalloc.h"

#define CLASSES 3
static const size_t sizes[CLASSES] = {80, 256 * 1024 + 17, 10 * 1024 + 1};

typedef struct spans_s { unsigned char* block[CLASSES]; } spans_t;
typedef struct child_s { mi_subproc_id_t id; bool complete; } child_t;

static void require(bool condition) { if (!condition) abort(); }
static void row(const char* stage, bool a, bool b, bool c) {
  printf("collect.%s=%d,%d,%d\n", stage, a, b, c);
  require(a && b && c);
}
static spans_t allocate(mi_heap_t* heap, unsigned char value) {
  spans_t spans;
  for (unsigned i = 0; i < CLASSES; i++) {
    spans.block[i] = i == 2 ? mi_heap_malloc_aligned(heap, sizes[i], 4096)
                           : mi_heap_malloc(heap, sizes[i]);
    require(spans.block[i] != NULL && mi_usable_size(spans.block[i]) >= sizes[i]);
    memset(spans.block[i], value + i, sizes[i]);
  }
  return spans;
}
static bool contents(const spans_t* spans, unsigned char value) {
  for (unsigned i = 0; i < CLASSES; i++)
    for (size_t j = 0; j < sizes[i]; j++)
      if (spans->block[i][j] != (unsigned char)(value + i)) return false;
  return true;
}
static bool owns(mi_heap_t* heap, const spans_t* spans) {
  for (unsigned i = 0; i < CLASSES; i++)
    if (mi_heap_of(spans->block[i]) != heap || !mi_heap_contains(heap, spans->block[i])) return false;
  return true;
}
static bool aligned(const spans_t* spans) { return (uintptr_t)spans->block[2] % 4096 == 0; }
static void release(spans_t* spans) {
  for (unsigned i = 0; i < CLASSES; i++) { mi_free(spans->block[i]); spans->block[i] = NULL; }
}
static void* remote_release(void* argument) { release(argument); return (void*)1; }
static void joined_release(spans_t* spans) {
  pthread_t thread; void* result = NULL;
  require(pthread_create(&thread, NULL, remote_release, spans) == 0);
  require(pthread_join(thread, &result) == 0 && result == (void*)1);
}
static bool in_arena(const spans_t* spans, const void* area, size_t size) {
  for (unsigned i = 0; i < CLASSES; i++) {
    uintptr_t pointer = (uintptr_t)spans->block[i], start = (uintptr_t)area;
    if (pointer < start || pointer - start >= size || sizes[i] > size - (pointer - start)) return false;
  }
  return true;
}

static void retained(void) {
  mi_heap_t* root = mi_heap_main();
  mi_theap_t* default_theap = mi_theap_get_default();
  mi_heap_t* heap = mi_heap_new(); require(heap != NULL && heap != root);
  spans_t live = allocate(heap, 0x31), empty = allocate(heap, 0x51);
  mi_theap_t* theap = mi_heap_theap(heap);
  row("retained_live", contents(&live, 0x31), owns(heap, &live), aligned(&live));
  joined_release(&empty);
  mi_heap_collect(heap, false);
  row("retained_normal", contents(&live, 0x31), owns(heap, &live), mi_heap_theap(heap) == theap);
  mi_heap_collect(heap, true);
  row("retained_forced", contents(&live, 0x31), owns(heap, &live), aligned(&live));
  row("retained_root", mi_heap_main() == root, mi_theap_get_default() == default_theap,
      mi_heap_theap(heap) == theap);
  joined_release(&live);
  mi_heap_collect(heap, false);
  mi_heap_collect(heap, true);
  row("retained_empty", mi_heap_main() == root, mi_heap_theap(heap) == theap,
      mi_theap_get_default() == default_theap);
  spans_t reused = allocate(heap, 0x71);
  row("retained_reuse", contents(&reused, 0x71), owns(heap, &reused), aligned(&reused));
  release(&reused); mi_heap_collect(heap, true); mi_heap_delete(heap);
  row("retained_deleted", mi_heap_main() == root, mi_theap_get_default() == default_theap, true);
}

static void moved(void) {
  mi_heap_t* root = mi_heap_main();
  mi_theap_t* default_theap = mi_theap_get_default();
  mi_heap_t* heap = mi_heap_new(); require(heap != NULL && heap != root);
  spans_t live = allocate(heap, 0x25), remote = allocate(heap, 0x45);
  mi_heap_delete(heap);
  /* The deleted Heap is never queried or collected. Its live pages now
     belong to the subprocess main Heap, which retains their backing. */
  row("moved_live", contents(&live, 0x25), owns(root, &live), owns(root, &remote));
  mi_heap_collect(root, false);
  row("moved_normal", contents(&live, 0x25), owns(root, &live), aligned(&live));
  joined_release(&remote);
  mi_heap_collect(root, true);
  row("moved_forced", contents(&live, 0x25), owns(root, &live), mi_heap_main() == root);
  release(&live); mi_heap_collect(root, false); mi_heap_collect(root, true);
  spans_t reused = allocate(root, 0x65);
  row("moved_reuse", contents(&reused, 0x65), owns(root, &reused), aligned(&reused));
  release(&reused); mi_heap_collect(root, true);
  row("moved_empty", mi_heap_main() == root, mi_theap_get_default() == default_theap, true);
}

static void* child_worker(void* argument) {
  child_t* child = argument; mi_subproc_add_current_thread(child->id);
  mi_heap_t* root = mi_heap_main();
  mi_theap_t* default_theap = mi_theap_get_default();
  require(root != NULL && mi_subproc_current()._mi_subproc_id == child->id._mi_subproc_id);
  mi_arena_id_t id = NULL;
  require(mi_reserve_os_memory_ex(64 * 1024 * 1024, true, false, true, &id) == 0 && id != NULL);
  size_t area_size = 0; void* area = mi_arena_area(id, &area_size); require(area != NULL);
  mi_heap_t* heap = mi_heap_new_in_arena(id); require(heap != NULL && heap != root);
  spans_t live = allocate(heap, 0x13), empty = allocate(heap, 0x33);
  row("child_live", contents(&live, 0x13), owns(heap, &live), in_arena(&live, area, area_size));
  joined_release(&empty); mi_heap_collect(heap, false);
  row("child_normal", contents(&live, 0x13), owns(heap, &live), in_arena(&live, area, area_size));
  mi_heap_collect(heap, true);
  row("child_forced", contents(&live, 0x13), owns(heap, &live), aligned(&live));
  joined_release(&live); mi_heap_collect(heap, false); mi_heap_collect(heap, true);
  row("child_empty", mi_heap_main() == root, mi_theap_get_default() == default_theap,
      mi_subproc_current()._mi_subproc_id == child->id._mi_subproc_id);
  mi_heap_delete(heap);
  mi_heap_t* replacement = mi_heap_new_in_arena(id); require(replacement != NULL);
  spans_t reused = allocate(replacement, 0x53);
  row("child_reuse", contents(&reused, 0x53), owns(replacement, &reused), in_arena(&reused, area, area_size));
  mi_heap_collect(replacement, false); mi_heap_collect(replacement, true);
  row("child_reuse_collect", contents(&reused, 0x53), owns(replacement, &reused), aligned(&reused));
  release(&reused); mi_heap_collect(replacement, true); mi_heap_destroy(replacement);
  child->complete = true; return (void*)1;
}

int main(int argc, char** argv) {
  setvbuf(stdout, NULL, _IONBF, 0);
  require(argc == 2);
  mi_option_set(mi_option_allow_large_os_pages, 0);
  mi_option_set(mi_option_allow_thp, 0);
  mi_option_set(mi_option_purge_delay, 100000);
  puts("CRABC_MI_HEAP_COLLECT_BEGIN");
  if (strcmp(argv[1], "retained") == 0) retained();
  else if (strcmp(argv[1], "moved") == 0) moved();
  else if (strcmp(argv[1], "child") == 0) {
    child_t child = { .id = mi_subproc_new() }; require(child.id._mi_subproc_id != NULL);
    pthread_t thread; void* result = NULL;
    require(pthread_create(&thread, NULL, child_worker, &child) == 0);
    require(pthread_join(thread, &result) == 0 && result == (void*)1 && child.complete);
    mi_subproc_destroy(child.id);
    row("child_joined", mi_subproc_current()._mi_subproc_id == mi_subproc_main()._mi_subproc_id,
        child.complete, true);
  } else return 2;
  puts("CRABC_MI_HEAP_COLLECT_END");
  return 0;
}
