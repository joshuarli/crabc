#define _GNU_SOURCE 1
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include "mimalloc.h"
#include "mimalloc-stats.h"

typedef struct {
  mi_heap_t* heap;
  unsigned char* small;
  unsigned char* medium;
  unsigned char* singleton;
  size_t small_size;
  size_t medium_size;
  unsigned char marker;
} owner_result_t;

typedef struct {
  size_t areas;
  size_t used;
  size_t blocks;
  size_t regular_areas;
  size_t medium_areas;
  size_t large_areas;
  size_t regular_used;
  size_t medium_used;
  size_t large_used;
} population_t;

static bool visit_page(const mi_heap_t* heap, const mi_heap_area_t* area,
                       void* block, size_t block_size, void* argument) {
  (void)heap;
  (void)block_size;
  population_t* value = (population_t*)argument;
  if (block != NULL) {
    value->blocks++;
    return true;
  }
  value->areas++;
  value->used += area->used;
  if (area->block_size <= 8192) {
    value->regular_areas++;
    value->regular_used += area->used;
  } else if (area->block_size <= 1024 * 1024) {
    value->medium_areas++;
    value->medium_used += area->used;
  } else {
    value->large_areas++;
    value->large_used += area->used;
  }
  return true;
}

static void print_population(const char* stage) {
  population_t value = {0};
  bool completed = mi_heap_visit_blocks(mi_heap_main(), true, visit_page, &value);
  mi_stats_t stats = {0};
  mi_stats_get(&stats);
  printf("population.%s=%d,%zu,%zu,%zu,%zu,%zu,%zu,%zu,%zu,%zu,%zu,%lld\n",
         stage, completed, value.areas, value.used, value.blocks,
         value.regular_areas, value.medium_areas, value.large_areas,
         value.regular_used, value.medium_used, value.large_used,
         (size_t)(value.regular_used + value.medium_used + value.large_used),
         (long long)stats.pages.current);
}

static void* owner(void* argument) {
  owner_result_t* result = (owner_result_t*)argument;
  result->heap = mi_heap_new();
  if (result->heap == NULL) return NULL;
  result->small = (unsigned char*)mi_heap_malloc(result->heap, result->small_size);
  result->medium = (unsigned char*)mi_heap_malloc(result->heap, result->medium_size);
  result->singleton = (unsigned char*)mi_heap_zalloc_aligned_at(result->heap, 81, 128, 11);
  if (result->small != NULL) result->small[0] = result->marker;
  if (result->medium != NULL) result->medium[0] = result->marker + 1;
  return NULL;
}

static bool create_owner(owner_result_t* result) {
  pthread_t thread;
  if (pthread_create(&thread, NULL, owner, result) != 0) return false;
  if (pthread_join(thread, NULL) != 0) return false;
  return result->heap != NULL && result->small != NULL &&
         result->medium != NULL && result->singleton != NULL;
}

static void print_membership(const char* stage, const owner_result_t* first,
                             const owner_result_t* second) {
  printf("population.%s_membership=%d,%d,%d,%d,%d,%d\n", stage,
         mi_heap_of(first->small) == first->heap,
         mi_heap_of(first->medium) == first->heap,
         mi_heap_of(first->singleton) == first->heap,
         mi_heap_of(second->small) == second->heap,
         mi_heap_of(second->medium) == second->heap,
         mi_heap_of(second->singleton) == second->heap);
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  mi_option_set(mi_option_arena_reserve, 0);
  puts("CRABC_MI_M6_MAIN_POPULATION_AFTER_OWNER_EXIT_BEGIN");
  print_population("baseline");
  owner_result_t first = { .small_size = 80, .medium_size = 32768, .marker = 0x51 };
  owner_result_t second = { .small_size = 256, .medium_size = 131072, .marker = 0x61 };
  bool created = create_owner(&first) && create_owner(&second);
  printf("population.created=%d\n", created);
  if (!created) _exit(2);
  print_membership("exited", &first, &second);
  printf("population.payload=%d,%d,%d,%d,%d,%d\n",
         first.small[0] == 0x51, first.medium[0] == 0x52,
         first.singleton[0] == 0 && first.singleton[80] == 0,
         second.small[0] == 0x61, second.medium[0] == 0x62,
         second.singleton[0] == 0 && second.singleton[80] == 0);
  print_population("exited");

  uintptr_t first_addresses[3] = {
    (uintptr_t)first.small, (uintptr_t)first.medium, (uintptr_t)first.singleton
  };
  uintptr_t second_addresses[3] = {
    (uintptr_t)second.small, (uintptr_t)second.medium, (uintptr_t)second.singleton
  };
  errno = 37;
  mi_heap_delete(first.heap);
  print_population("deleted");
  printf("population.deleted_membership=%d,%d,%d\n",
         mi_heap_of((void*)first_addresses[0]) == mi_heap_main(),
         mi_heap_of((void*)first_addresses[1]) == mi_heap_main(),
         mi_heap_of((void*)first_addresses[2]) == mi_heap_main());

  mi_heap_destroy(second.heap);
  print_population("destroyed");
  printf("population.destroyed_region=%d,%d,%d\n",
         mi_is_in_heap_region((void*)second_addresses[0]),
         mi_is_in_heap_region((void*)second_addresses[1]),
         mi_is_in_heap_region((void*)second_addresses[2]));

  mi_free(first.small);
  print_population("freed_small");
  mi_free(first.medium);
  print_population("freed_medium");
  mi_free(first.singleton);
  print_population("freed_singleton");
  mi_collect(true);
  print_population("collected");
  printf("population.final=%d,%d,%d,%d\n", errno,
         mi_is_in_heap_region((void*)first_addresses[0]),
         mi_is_in_heap_region((void*)first_addresses[1]),
         mi_is_in_heap_region((void*)first_addresses[2]));
  puts("CRABC_MI_M6_MAIN_POPULATION_AFTER_OWNER_EXIT_END");
  _exit(0);
}
