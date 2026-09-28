#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "mimalloc.h"
#include "mimalloc-stats.h"
#ifdef CRABC_M6_SOURCE_INTERNAL
#include "mimalloc/internal.h"
#include "mimalloc/prim-tls.h"
#endif

#define MIB ((size_t)1024 * 1024)
#define GIB ((size_t)1024 * MIB)

#ifdef CRABC_M6_SOURCE_INTERNAL
static uintptr_t source_first_theap_address;
#endif

typedef struct population_s {
  size_t areas;
  size_t used;
  size_t small;
  size_t medium;
  size_t huge;
  size_t blocks;
  size_t used_256;
  size_t used_320;
  size_t used_7168;
  size_t used_8192;
  size_t used_163840;
  size_t used_other;
} population_t;

static bool diagnose_population_classes;

typedef struct image_page_s {
  uintptr_t address;
  size_t used;
  int found;
} image_page_t;

static bool observe_image_page(const mi_heap_t* heap, const mi_heap_area_t* area,
                               void* block, size_t block_size, void* argument) {
  (void)heap;
  (void)block_size;
  if (block != NULL) return true;
  image_page_t* value = (image_page_t*)argument;
  uintptr_t start = (uintptr_t)area->blocks;
  uintptr_t end = start + area->committed;
  if (value->address >= start && value->address < end) {
    value->found++;
    value->used = area->used;
  }
  return true;
}

static void print_image_page(const char* step, uintptr_t address) {
  image_page_t value = { address, 0, 0 };
  bool complete = mi_heap_visit_blocks(mi_heap_main(), false, observe_image_page, &value);
  printf("population.image_%s=%d,%d,%zu\n", step, complete, value.found, value.used);
}

static void diagnose_theap(const char* step, mi_heap_t* heap) {
#ifdef CRABC_M6_SOURCE_INTERNAL
  if (heap != NULL) source_first_theap_address = (uintptr_t)heap->theaps;
  if (source_first_theap_address == 0) return;
  mi_page_t* page = _mi_ptr_page((void*)source_first_theap_address);
  fprintf(stderr, "source.theap_%s=%p,%zu,%llu,%zu,%llu\n", step,
          (void*)source_first_theap_address, sizeof(mi_theap_t),
          (unsigned long long)mi_page_thread_id(page), (size_t)page->used,
          (unsigned long long)mi_atomic_load_relaxed(&page->xthread_free));
#else
  (void)step;
  (void)heap;
#endif
}

static bool observe_page(const mi_heap_t* heap, const mi_heap_area_t* area,
                         void* block, size_t block_size, void* argument) {
  (void)heap;
  (void)block_size;
  population_t* value = (population_t*)argument;
  if (block != NULL) {
    value->blocks++;
    return true;
  }
#ifdef CRABC_M6_SOURCE_INTERNAL
  if (source_first_theap_address != 0
      && (uintptr_t)area->blocks == source_first_theap_address) {
    fprintf(stderr, "source.theap_area=%p,%zu,%zu\n", area->blocks,
            area->block_size, area->used);
  }
#endif
  value->areas++;
  value->used += area->used;
  if (area->block_size == 256) value->used_256 += area->used;
  else if (area->block_size == 320) value->used_320 += area->used;
  else if (area->block_size == 7168) value->used_7168 += area->used;
  else if (area->block_size == 8192) value->used_8192 += area->used;
  else if (area->block_size == 163840) value->used_163840 += area->used;
  else value->used_other += area->used;
  if (diagnose_population_classes && area->used > 0
      && area->block_size != 7168 && area->block_size != 8192
      && area->block_size != 163840 && area->block_size != 256) {
    fprintf(stderr, "population.class=%zu,%zu\n", area->block_size, area->used);
  }
  if (area->block_size <= 8192) value->small++;
  else if (area->block_size <= MIB) value->medium++;
  else value->huge++;
  return true;
}

static void print_population(const char* step, bool visit_blocks) {
  population_t value = { 0 };
  bool complete = mi_heap_visit_blocks(mi_heap_main(), visit_blocks, observe_page, &value);
  mi_stats_t stats = { 0 };
  mi_stats_get(&stats);
  printf("population.%s=%d,%zu,%zu,%zu,%zu,%zu,%zu,%lld\n", step, complete,
         value.areas, value.used, value.small, value.medium, value.huge, value.blocks,
         (long long)stats.pages.current);
  printf("population.%s_classes=%zu,%zu,%zu,%zu,%zu,%zu\n", step,
         value.used_256, value.used_320, value.used_7168, value.used_8192,
         value.used_163840, value.used_other);
}

static void run_cycle(bool reserve, int count) {
  mi_heap_t* heaps[1000] = { 0 };
  print_population("before", false);
  if (reserve) {
    int result = mi_reserve_os_memory(16 * GIB, false, true);
    printf("population.reserve=%d\n", result);
    print_population("reserved", false);
  }
  int allocated = 0;
  for (int index = 0; index < count; index++) {
    heaps[index] = mi_heap_new();
    if (heaps[index] == NULL || mi_heap_malloc(heaps[index], 32) == NULL) break;
    allocated++;
  }
  printf("population.allocated=%d\n", allocated);
  printf("population.image_usable=%zu\n", allocated > 0 ? mi_usable_size(heaps[0]) : 0);
  if (count == 1 && allocated > 0) diagnose_theap("live", heaps[0]);
  uintptr_t first_image = allocated > 0 ? (uintptr_t)heaps[0] : 0;
  diagnose_population_classes = count == 100 || count == 1000;
  print_population("live", false);
  diagnose_population_classes = false;
  if (allocated > 0) print_image_page("live", first_image);
  for (int index = 0; index < allocated; index++) mi_heap_destroy(heaps[index]);
  if (count == 1 && allocated > 0) diagnose_theap("destroyed", NULL);
  print_population("destroyed", false);
  if (allocated > 0) print_image_page("destroyed", first_image);
  print_population("visited_blocks", true);
  if (count == 1 && allocated > 0) diagnose_theap("after_visit", NULL);
  print_population("after_visit", false);
  if (allocated > 0) print_image_page("after_visit", first_image);
  mi_collect(true);
  print_population("collected", false);
}

int main(int argc, char** argv) {
  if (argc != 4) return 2;
  bool forked = strcmp(argv[1], "fork") == 0;
  bool direct = strcmp(argv[1], "direct") == 0;
  bool reserve = strcmp(argv[2], "reserve") == 0;
  bool plain = strcmp(argv[2], "plain") == 0;
  char* count_end = NULL;
  long requested = strtol(argv[3], &count_end, 10);
  int count = strcmp(argv[3], "one") == 0 ? 1 :
              strcmp(argv[3], "many") == 0 ? 1000 :
              (count_end != argv[3] && *count_end == '\0' && requested >= 1 && requested <= 1000
                   ? (int)requested : 0);
  if ((!forked && !direct) || (!reserve && !plain) || count == 0) return 2;
  setvbuf(stdout, NULL, _IONBF, 0);
  printf("CRABC_MI_M6_MAIN_POPULATION_TRACE_BEGIN\n");
  if (forked) {
    (void)mi_heap_main();
    pid_t child = fork();
    if (child == 0) {
      run_cycle(reserve, count);
      _exit(0);
    }
    int status = -1;
    bool joined = child > 0 && waitpid(child, &status, 0) == child;
    printf("population.child=%d\n", joined && WIFEXITED(status) && WEXITSTATUS(status) == 0);
  } else {
    run_cycle(reserve, count);
  }
  printf("CRABC_MI_M6_MAIN_POPULATION_TRACE_END\n");
  return 0;
}
