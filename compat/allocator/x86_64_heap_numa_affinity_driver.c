#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <pthread.h>
#include "mimalloc.h"
#ifdef CRABC_NUMA_SOURCE
#include "mimalloc/internal.h"
#endif

/* Only the selected private Heap prefix is observed, never a public ABI. */
typedef struct {
  void* subprocess;
  uintptr_t sequence;
  void* next;
  void* previous;
  uintptr_t theap_slot;
  void* exclusive_arena;
  int numa_node;
} heap_prefix_t;
#ifdef CRABC_NUMA_SOURCE
_Static_assert(offsetof(heap_prefix_t, numa_node) == offsetof(mi_heap_t, numa_node), "Heap NUMA prefix");
#endif
static int node(mi_heap_t* heap) {
  int value;
  memcpy(&value, (char*)heap + offsetof(heap_prefix_t, numa_node), sizeof(value));
  return value;
}
static bool in_area(void* block, void* area, size_t size) {
  return block != NULL && (uintptr_t)block >= (uintptr_t)area && (uintptr_t)block - (uintptr_t)area < size;
}
static bool exercise(const char* label) {
  mi_heap_t* main_heap = mi_heap_main();
  if (main_heap == NULL || mi_heap_theap(main_heap) == NULL) return false;
  printf("%s.initial=%d\n", label, node(main_heap));
  errno = 79;
  mi_heap_set_numa_affinity(NULL, 5);
  printf("%s.null=%d,%d\n", label, node(main_heap), errno == 79);
  mi_heap_set_numa_affinity(main_heap, INT_MIN);
  printf("%s.negative=%d\n", label, node(main_heap));
  mi_heap_set_numa_affinity(main_heap, 0);
  printf("%s.zero=%d\n", label, node(main_heap));
  mi_heap_set_numa_affinity(main_heap, -1);
  void* areas[2]; size_t lengths[2]; mi_arena_id_t ids[2];
  for (int i = 0; i < 2; ++i) {
    size_t size = 64 * 1024 * 1024;
    size_t alignment = mi_arena_min_alignment();
    void* raw = mmap(NULL, size + alignment, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (raw == MAP_FAILED) return false;
    uintptr_t aligned = ((uintptr_t)raw + alignment - 1) & ~(uintptr_t)(alignment - 1);
    size_t prefix = aligned - (uintptr_t)raw;
    size_t suffix = alignment - prefix;
    if (prefix != 0 && munmap(raw, prefix) != 0) return false;
    if (suffix != 0 && munmap((void*)(aligned + size), suffix) != 0) return false;
    void* memory = (void*)aligned;
    if (memory == MAP_FAILED || !mi_manage_os_memory_ex(memory, size, true, false, true, i+1, false, &ids[i])) { fprintf(stderr, "manage%d failed errno%d\n", i, errno); return false; }
    areas[i] = mi_arena_area(ids[i], &lengths[i]);
    if (areas[i] == NULL) return false;
  }
  for (int i = 0; i < 2; ++i) {
    mi_heap_t* heap = mi_heap_new();
    if (heap == NULL) return false;
    printf("%s.new%d=%d\n", label, i, node(heap));
    mi_heap_set_numa_affinity(heap, i+1);
    void* block = mi_heap_malloc(heap, 130007);
    printf("%s.selected%d=%d,%d,%d\n", label, i, node(heap), in_area(block, areas[i], lengths[i]), mi_heap_of(block) == heap);
    if (block == NULL) return false;
    mi_heap_set_numa_affinity(heap, 2-i);
    void* reused = mi_heap_malloc(heap, 130007);
    void* fresh = mi_heap_malloc(heap, 250003);
    printf("%s.changed%d=%d,%d,%d\n", label, i, node(heap),
           in_area(reused, areas[i], lengths[i]), in_area(fresh, areas[1-i], lengths[1-i]));
    if (reused == NULL || fresh == NULL) return false;
    mi_free(reused);
    mi_free(fresh);
    mi_free(block);
    mi_heap_set_numa_affinity(heap, INT_MAX);
    printf("%s.wrapped%d=%d\n", label, i, node(heap));
    mi_heap_set_numa_affinity(heap, -7);
    printf("%s.cleared%d=%d\n", label, i, node(heap));
    mi_heap_destroy(heap);
  }
  mi_heap_set_numa_affinity(NULL, 1);
  void* block = mi_heap_malloc(main_heap, 250003);
  printf("%s.main_selected=%d,%d\n", label, in_area(block, areas[0], lengths[0]), mi_heap_of(block) == main_heap);
  if (block == NULL) return false;
  mi_free(block);
  mi_heap_set_numa_affinity(NULL, -1);
  mi_heap_t* exclusive = mi_heap_new_in_arena(ids[0]);
  if (exclusive == NULL) return false;
  mi_heap_set_numa_affinity(exclusive, 2);
  block = mi_heap_malloc(exclusive, 130007);
  printf("%s.exclusive=%d,%d\n", label, node(exclusive), in_area(block, areas[0], lengths[0]));
  if (block == NULL) return false;
  mi_free(block);
  errno = 0;
  block = mi_heap_malloc(exclusive, 128 * 1024 * 1024);
  printf("%s.refusal=%d,%d,%d\n", label, block == NULL, errno == ENOMEM, node(exclusive));
  if (block != NULL) mi_free(block);
  mi_heap_destroy(exclusive);
  mi_option_set(mi_option_use_numa_nodes, 1);
  mi_heap_set_numa_affinity(NULL, 5);
  printf("%s.cached_count=%d\n", label, node(main_heap));
  mi_heap_set_numa_affinity(NULL, -1);
  return true;
}
typedef struct { mi_subproc_id_t id; bool passed; } child_t;
static void* child_run(void* argument) {
  child_t* child = argument;
  mi_subproc_add_current_thread(child->id);
  child->passed = exercise("child");
  return NULL;
}
int main(void) {
  if (!exercise("main")) return 2;
  child_t child = {mi_subproc_new(), false};
  pthread_t thread;
  if (child.id._mi_subproc_id == NULL || pthread_create(&thread, NULL, child_run, &child) != 0) return 3;
  if (pthread_join(thread, NULL) != 0 || !child.passed) return 4;
  return 0;
}
